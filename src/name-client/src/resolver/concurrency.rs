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
use std::time::Duration;
use tokio::time::Instant;
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

impl SharedTask {
    fn usable(&self) -> bool {
        self.deadline > Instant::now() && !self.cancel.is_cancelled()
    }

    /// 尝试加入:任务仍可用且还有等待者时等待者数加一。等待者已归零的任务正被最后一个
    /// 离开者取消,不能再加入。
    fn try_join(&self, max_waiters: usize, key: &str) -> NSResult<bool> {
        if !self.usable() {
            return Ok(false);
        }
        match self
            .waiters
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |w| (w > 0).then_some(w + 1))
        {
            Err(_) => Ok(false),
            Ok(previous) if previous + 1 > max_waiters => {
                self.waiters.fetch_sub(1, Ordering::AcqRel);
                Err(NSError::Failed(format!(
                    "resolve queue full for {} ({} waiters)",
                    key,
                    previous + 1
                )))
            }
            Ok(_) => Ok(true),
        }
    }
}

/// 等待者的成员资格:离开(包括等待 Future 被 drop / abort)时递减;最后一个离开且任务
/// 尚无回答时取消任务并清理登记。
struct Membership<'a> {
    tasks: &'a DashMap<String, Arc<SharedTask>>,
    key: &'a str,
    task: Arc<SharedTask>,
}

impl Drop for Membership<'_> {
    fn drop(&mut self) {
        if self.task.waiters.fetch_sub(1, Ordering::AcqRel) == 1 && self.task.result.borrow().is_none() {
            debug!("last waiter left; cancelling shared resolve task {}", self.key);
            self.task.cancel.cancel();
            self.tasks.remove_if(self.key, |_, t| Arc::ptr_eq(t, &self.task));
        }
    }
}

enum Claim {
    Joined(Arc<SharedTask>),
    Created,
}

/// 任务合并。
pub struct TaskMerger {
    tasks: Arc<DashMap<String, Arc<SharedTask>>>,
    permits: Arc<Semaphore>,
    config: ConcurrencyConfig,
    /// 测试调度钩子:查找未命中之后、取得创建权之前调用。
    #[cfg(test)]
    pub(crate) on_lookup_miss: std::sync::Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
}

impl TaskMerger {
    pub fn new(config: ConcurrencyConfig) -> Self {
        Self {
            tasks: Arc::new(DashMap::new()),
            permits: Arc::new(Semaphore::new(config.max_concurrent_queries.max(1))),
            config,
            #[cfg(test)]
            on_lookup_miss: std::sync::Mutex::new(None),
        }
    }

    pub fn running_tasks(&self) -> usize {
        self.tasks.len()
    }

    /// 某个合并键当前登记的等待者数(诊断用);没有登记的任务时为 0。
    pub fn waiters(&self, key: &str) -> usize {
        self.tasks
            .get(key)
            .map_or(0, |task| task.waiters.load(Ordering::Acquire))
    }

    /// 当前可用的并发许可数(诊断用)。
    pub fn available_permits(&self) -> usize {
        self.permits.available_permits()
    }

    /// 合并键相同的并发查询共享一个任务。`run` 只在新建任务时执行一次。
    ///
    /// 共享任务有自己的有限预算(共享上限与发起者剩余预算取小)和自己的取消信号:发起者
    /// 取消或离开不影响其它等待者;每个等待者按自己的预算等待;登记由任务完成或最后一个
    /// 等待者离开时清理。
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

        // 快路径:加入已有任务。
        let existing = self.tasks.get(&key).map(|t| t.clone());
        if let Some(existing) = existing {
            if existing.try_join(self.config.max_waiters_per_task, &key)? {
                return self.wait_as_member(&key, existing, &budget).await;
            }
        }
        #[cfg(test)]
        {
            // 先取出钩子再调用:`if let` 的临时守卫会活到块尾。
            let hook = self.on_lookup_miss.lock().unwrap().clone();
            if let Some(hook) = hook {
                hook();
            }
        }

        // 原子地取得创建权:同键已有可加入的任务就加入,否则登记新任务。
        let task_budget = Budget::new(self.config.shared_task_timeout.min(budget.remaining()));
        let (tx, rx) = watch::channel(None);
        let task = Arc::new(SharedTask {
            result: rx,
            waiters: AtomicUsize::new(1),
            cancel: task_budget.cancel_token(),
            deadline: task_budget.deadline(),
        });
        let claim = match self.tasks.entry(key.clone()) {
            dashmap::Entry::Occupied(mut occupied) => {
                if occupied.get().try_join(self.config.max_waiters_per_task, &key)? {
                    Claim::Joined(occupied.get().clone())
                } else {
                    occupied.insert(task.clone());
                    Claim::Created
                }
            }
            dashmap::Entry::Vacant(vacant) => {
                vacant.insert(task.clone());
                Claim::Created
            }
        };
        if let Claim::Joined(existing) = claim {
            return self.wait_as_member(&key, existing, &budget).await;
        }

        let permits = self.permits.clone();
        let fut = run(task_budget.clone());
        let task_key = key.clone();
        let cancel = task_budget.cancel_token();
        let deadline = task_budget.deadline();
        let tasks = self.tasks.clone();
        let registered = task.clone();
        tokio::spawn(async move {
            let unknown = |reason: String| {
                SourceAnswer::unknown(super::source::SourceRef::normal("merger"), reason, false)
            };
            let permit = tokio::select! {
                biased;
                _ = cancel.cancelled() => None,
                _ = tokio::time::sleep_until(deadline) => None,
                permit = permits.acquire_owned() => permit.ok(),
            };
            let answer = match permit {
                None => unknown(format!("shared task {} was cancelled or ran out of budget before start", task_key)),
                Some(permit) => {
                    let answer = tokio::select! {
                        biased;
                        _ = cancel.cancelled() => unknown(format!("shared task {} cancelled", task_key)),
                        _ = tokio::time::sleep_until(deadline) => {
                            unknown(format!("shared task {} exceeded its budget", task_key))
                        }
                        answer = fut => answer,
                    };
                    drop(permit);
                    answer
                }
            };
            let _ = tx.send(Some(answer));
            tasks.remove_if(&task_key, |_, t| Arc::ptr_eq(t, &registered));
        });

        self.wait_as_member(&key, task, &budget).await
    }

    async fn wait_as_member(
        &self,
        key: &str,
        task: Arc<SharedTask>,
        budget: &Budget,
    ) -> NSResult<SourceAnswer> {
        let member = Membership {
            tasks: &self.tasks,
            key,
            task,
        };
        let outcome = Self::wait_for(&member.task, budget).await;
        drop(member);
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
