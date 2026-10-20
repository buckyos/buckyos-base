//! 并发、合并与退避(设计稿 §4、TODO M5)。
//!
//! - `DocLocks`:同键串行锁 `(scope, did, doc_type)`,可取消、受 deadline 约束;
//!   只覆盖"读缓存 / 刷新约束 / 决定查询"与"验证后原子提交"两段,不跨 I/O 持有;
//! - `TaskMerger`:任务合并,键含访问策略;共享任务有自己的有限预算,每个等待者
//!   保留自己的 deadline / 取消,最后一个等待者离开才取消任务;并发数与队列有上限;
//! - `Backoff`:按目标 + 来源 + 访问策略的短期退避,策略拒绝不进共享退避;
//! - `LogThrottle`:错误日志限流。

use super::budget::{erase, Budget};
use super::opts::ResolveOpts;
use super::source::SourceAnswer;
use dashmap::DashMap;
use log::debug;
use name_lib::{NSError, NSResult};
use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{watch, Mutex, OwnedMutexGuard, Semaphore};
use tokio_util::sync::CancellationToken;

#[derive(Debug, Clone)]
pub struct ConcurrencyConfig {
    /// 同时运行的来源查询任务上限。
    pub max_concurrent_queries: usize,
    /// 单个共享任务允许的等待者上限。
    pub max_waiters_per_task: usize,
    /// 共享任务自己的预算上限(与发起者剩余预算取小)。
    pub shared_task_timeout: Duration,
    pub backoff_base: Duration,
    pub backoff_max: Duration,
    pub log_interval: Duration,
}

impl Default for ConcurrencyConfig {
    fn default() -> Self {
        Self {
            max_concurrent_queries: 64,
            max_waiters_per_task: 256,
            shared_task_timeout: Duration::from_secs(30),
            backoff_base: Duration::from_secs(5),
            backoff_max: Duration::from_secs(60),
            log_interval: Duration::from_secs(10),
        }
    }
}

/// 同键串行锁。
#[derive(Default)]
pub struct DocLocks {
    locks: DashMap<String, Arc<Mutex<()>>>,
}

impl DocLocks {
    pub fn new() -> Self {
        Self::default()
    }

    /// 锁等待可取消并受 deadline 约束。
    pub async fn lock(&self, key: &str, budget: &Budget) -> NSResult<OwnedMutexGuard<()>> {
        let mutex = self
            .locks
            .entry(key.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone();
        budget.wait(mutex.lock_owned()).await
    }

    pub fn len(&self) -> usize {
        self.locks.len()
    }
}

struct SharedTask {
    result: watch::Receiver<Option<SourceAnswer>>,
    waiters: AtomicUsize,
    cancel: CancellationToken,
    deadline: Instant,
}

/// 任务合并。
pub struct TaskMerger {
    tasks: DashMap<String, Arc<SharedTask>>,
    permits: Arc<Semaphore>,
    config: ConcurrencyConfig,
}

impl TaskMerger {
    pub fn new(config: ConcurrencyConfig) -> Self {
        Self {
            tasks: DashMap::new(),
            permits: Arc::new(Semaphore::new(config.max_concurrent_queries.max(1))),
            config,
        }
    }

    pub fn running_tasks(&self) -> usize {
        self.tasks.len()
    }

    /// 合并键相同的并发查询共享一个任务。`run` 只在新建任务时执行一次。
    pub async fn merge_or_run<F, Fut>(
        &self,
        key: String,
        opts: &ResolveOpts,
        run: F,
    ) -> NSResult<SourceAnswer>
    where
        F: FnOnce(Budget) -> Fut,
        Fut: Future<Output = SourceAnswer> + Send + 'static,
    {
        let budget = opts.budget().clone();
        budget.check()?;

        // 加入已有任务。
        if let Some(existing) = self.tasks.get(&key).map(|t| t.clone()) {
            if existing.deadline > Instant::now() && !existing.cancel.is_cancelled() {
                let waiters = existing.waiters.fetch_add(1, Ordering::AcqRel) + 1;
                if waiters > self.config.max_waiters_per_task {
                    existing.waiters.fetch_sub(1, Ordering::AcqRel);
                    return Err(NSError::Failed(format!(
                        "resolve queue full for {} ({} waiters)",
                        key, waiters
                    )));
                }
                let outcome = Self::wait_for(&existing, &budget).await;
                Self::leave(&existing);
                return outcome;
            }
            self.tasks.remove(&key);
        }

        // 新建共享任务:自己的有限预算(与发起者剩余预算取小),等待者各自保留 deadline。
        let task_budget = budget.child(self.config.shared_task_timeout);
        let (tx, rx) = watch::channel(None);
        let task = Arc::new(SharedTask {
            result: rx,
            waiters: AtomicUsize::new(1),
            cancel: task_budget.cancel_token(),
            deadline: task_budget.deadline(),
        });
        self.tasks.insert(key.clone(), task.clone());

        let permits = self.permits.clone();
        let fut = run(task_budget.clone());
        let task_key = key.clone();
        let cancel = task_budget.cancel_token();
        tokio::spawn(async move {
            let permit = tokio::select! {
                biased;
                _ = cancel.cancelled() => None,
                permit = permits.acquire_owned() => permit.ok(),
            };
            if permit.is_none() {
                let _ = tx.send(Some(SourceAnswer::unknown(
                    super::source::SourceRef::normal("merger"),
                    format!("shared task {} cancelled before start", task_key),
                    false,
                )));
                return;
            }
            let answer = tokio::select! {
                biased;
                _ = cancel.cancelled() => SourceAnswer::unknown(
                    super::source::SourceRef::normal("merger"),
                    format!("shared task {} cancelled", task_key),
                    false,
                ),
                answer = fut => answer,
            };
            let _ = tx.send(Some(answer));
            drop(permit);
        });

        let outcome = Self::wait_for(&task, &budget).await;
        Self::leave(&task);
        self.tasks.remove_if(&key, |_, t| Arc::ptr_eq(t, &task));
        outcome
    }

    async fn wait_for(task: &Arc<SharedTask>, budget: &Budget) -> NSResult<SourceAnswer> {
        let mut rx = task.result.clone();
        // 装箱:否则深层调用方的 `Send` 证明会溢出(E0275)。
        budget
            .wait(erase(async move {
                loop {
                    if let Some(answer) = rx.borrow().clone() {
                        return answer;
                    }
                    if rx.changed().await.is_err() {
                        return SourceAnswer::unknown(
                            super::source::SourceRef::normal("merger"),
                            "shared task dropped without answer",
                            false,
                        );
                    }
                }
            }))
            .await
    }

    /// 单个等待者离开不取消其它有效等待者的任务;最后一个离开才取消无用任务。
    fn leave(task: &Arc<SharedTask>) {
        if task.waiters.fetch_sub(1, Ordering::AcqRel) == 1 {
            if task.result.borrow().is_none() {
                debug!("last waiter left; cancelling shared resolve task");
                task.cancel.cancel();
            }
        }
    }
}

/// 真实来源 / 传输失败的短期退避。
pub struct Backoff {
    until: DashMap<String, (Instant, u32)>,
    config: ConcurrencyConfig,
}

impl Backoff {
    pub fn new(config: ConcurrencyConfig) -> Self {
        Self {
            until: DashMap::new(),
            config,
        }
    }

    pub fn key(source_id: &str, target: &str, policy_key: &str) -> String {
        format!("{}|{}|{}", source_id, target, policy_key)
    }

    /// 仍在退避期内返回剩余时长。
    pub fn should_skip(&self, key: &str) -> Option<Duration> {
        let entry = self.until.get(key)?;
        let now = Instant::now();
        if entry.0 > now {
            Some(entry.0 - now)
        } else {
            None
        }
    }

    pub fn record_failure(&self, key: String) {
        {
            let mut entry = self.until.entry(key).or_insert((Instant::now(), 0));
            let attempts = entry.1.saturating_add(1);
            let delay = self
                .config
                .backoff_base
                .saturating_mul(1u32 << attempts.min(6).saturating_sub(1))
                .min(self.config.backoff_max);
            *entry = (Instant::now() + delay, attempts);
        }
        // 守卫已释放:len / retain 需要遍历分片,不能与写守卫同时持有。
        if self.until.len() > 4096 {
            let now = Instant::now();
            self.until.retain(|_, (until, _)| *until > now);
        }
    }

    pub fn record_success(&self, key: &str) {
        self.until.remove(key);
    }
}

/// 错误日志限流。
pub struct LogThrottle {
    last: DashMap<String, Instant>,
    interval: Duration,
}

impl LogThrottle {
    pub fn new(interval: Duration) -> Self {
        Self {
            last: DashMap::new(),
            interval,
        }
    }

    pub fn should_log(&self, key: &str) -> bool {
        let now = Instant::now();
        let mut allow = false;
        self.last
            .entry(key.to_string())
            .and_modify(|last| {
                if now.duration_since(*last) >= self.interval {
                    *last = now;
                    allow = true;
                }
            })
            .or_insert_with(|| {
                allow = true;
                now
            });
        if self.last.len() > 4096 {
            let interval = self.interval;
            self.last.retain(|_, last| now.duration_since(*last) < interval);
        }
        allow
    }
}

#[cfg(test)]
mod tests {
    use super::super::source::SourceRef;
    use super::*;
    use std::sync::atomic::AtomicUsize;

    fn opts() -> ResolveOpts {
        ResolveOpts::default().normalize(Duration::from_secs(5))
    }

    #[tokio::test]
    async fn merged_waiters_share_one_run() {
        let merger = Arc::new(TaskMerger::new(ConcurrencyConfig::default()));
        let runs = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();
        for _ in 0..5 {
            let merger = merger.clone();
            let runs = runs.clone();
            handles.push(tokio::spawn(async move {
                merger
                    .merge_or_run("k".to_string(), &opts(), move |_budget| async move {
                        runs.fetch_add(1, Ordering::SeqCst);
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        SourceAnswer::no_answer(SourceRef::normal("x"), "done")
                    })
                    .await
                    .unwrap()
            }));
        }
        for handle in handles {
            handle.await.unwrap();
        }
        assert_eq!(runs.load(Ordering::SeqCst), 1);
        assert_eq!(merger.running_tasks(), 0);
    }

    #[tokio::test]
    async fn single_waiter_cancel_does_not_cancel_others() {
        let merger = Arc::new(TaskMerger::new(ConcurrencyConfig::default()));
        let m1 = merger.clone();
        let slow = tokio::spawn(async move {
            m1.merge_or_run("k".to_string(), &opts(), |_b| async {
                tokio::time::sleep(Duration::from_millis(150)).await;
                SourceAnswer::no_answer(SourceRef::normal("x"), "done")
            })
            .await
        });
        tokio::time::sleep(Duration::from_millis(10)).await;
        let m2 = merger.clone();
        let short_opts = ResolveOpts::default().normalize(Duration::from_millis(30));
        let short = m2
            .merge_or_run("k".to_string(), &short_opts, |_b| async {
                SourceAnswer::no_answer(SourceRef::normal("never"), "never")
            })
            .await;
        assert!(matches!(short, Err(NSError::DeadlineExceeded(_))));
        let answer = slow.await.unwrap().unwrap();
        assert_eq!(answer.reason.as_deref(), Some("done"));
    }

    #[tokio::test]
    async fn lock_wait_is_bounded_by_budget() {
        let locks = Arc::new(DocLocks::new());
        let budget = Budget::new(Duration::from_secs(5));
        let guard = locks.lock("k", &budget).await.unwrap();
        let short = Budget::new(Duration::from_millis(30));
        let err = locks.lock("k", &short).await.unwrap_err();
        assert!(matches!(err, NSError::DeadlineExceeded(_)));
        drop(guard);
        assert!(locks.lock("k", &budget).await.is_ok());
    }

    #[test]
    fn backoff_grows_and_resets() {
        let backoff = Backoff::new(ConcurrencyConfig {
            backoff_base: Duration::from_millis(100),
            backoff_max: Duration::from_millis(250),
            ..Default::default()
        });
        let key = Backoff::key("src", "did:bns:a#zone", "policy");
        assert!(backoff.should_skip(&key).is_none());
        backoff.record_failure(key.clone());
        let first = backoff.should_skip(&key).unwrap();
        backoff.record_failure(key.clone());
        let second = backoff.should_skip(&key).unwrap();
        assert!(second > first);
        assert!(second <= Duration::from_millis(250));
        backoff.record_success(&key);
        assert!(backoff.should_skip(&key).is_none());
        let throttle = LogThrottle::new(Duration::from_secs(10));
        assert!(throttle.should_log("a") && !throttle.should_log("a"));
    }
}
