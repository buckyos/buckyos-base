//! 整次调用共用的有限预算(设计稿 §4)。
//!
//! `Budget` 在最外层以 `monotonic_now() + resolve_timeout` 建立绝对 deadline
//! (`tokio::time::Instant`,测试可用 Tokio 虚拟时钟统一推进),
//! 覆盖锁与并发许可等待、缓存 I/O、locker/provider 查询、解析、验签和提交。
//! 副本共享同一 deadline 和取消信号;Owner 递归、fallback 和重试不能续期。
//!
//! - 单个来源超时(`SourceTimeout`)可返回 Unknown 并尝试下个允许来源;
//! - `DeadlineExceeded` / `Cancelled` 终止整次调用,不再 fallback,也不返回旧缓存。

use name_lib::{NSError, NSResult};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

/// 类型擦除的 boxed future。解析主路径嵌套很深,下游 crate 的 `Send` / 类型深度
/// 证明会沿着 `Pin<Box<{async block}>>` 继续展开;只有 `dyn Future` 才能截断。
pub type BoxFut<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

pub fn erase<'a, T>(fut: impl Future<Output = T> + Send + 'a) -> BoxFut<'a, T> {
    Box::pin(fut)
}

/// 单个来源/步骤的超时(不是整次调用的终止)。
#[derive(Debug, Clone)]
pub struct SourceTimeout {
    pub elapsed: Duration,
    pub cap: Duration,
}

impl std::fmt::Display for SourceTimeout {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "source timed out after {}ms (cap {}ms)",
            self.elapsed.as_millis(),
            self.cap.as_millis()
        )
    }
}

/// `Budget::run` 的失败形态:步骤级超时可继续,终止类错误必须向外传播。
#[derive(Debug)]
pub enum BudgetError {
    Timeout(SourceTimeout),
    Terminated(NSError),
}

impl BudgetError {
    pub fn into_ns_error(self) -> NSError {
        match self {
            BudgetError::Timeout(timeout) => NSError::Failed(timeout.to_string()),
            BudgetError::Terminated(err) => err,
        }
    }
}

#[derive(Debug)]
struct BudgetInner {
    started: Instant,
    deadline: Instant,
    cancel: CancellationToken,
    label: String,
}

/// 共享预算句柄。`clone` 得到的是同一份预算。
#[derive(Debug, Clone)]
pub struct Budget {
    inner: Arc<BudgetInner>,
}

impl Budget {
    pub fn new(timeout: Duration) -> Self {
        Self::with_deadline(Instant::now() + timeout)
    }

    pub fn with_deadline(deadline: Instant) -> Self {
        Self {
            inner: Arc::new(BudgetInner {
                started: Instant::now(),
                deadline,
                cancel: CancellationToken::new(),
                label: String::new(),
            }),
        }
    }

    pub fn with_cancel(timeout: Duration, cancel: CancellationToken) -> Self {
        Self {
            inner: Arc::new(BudgetInner {
                started: Instant::now(),
                deadline: Instant::now() + timeout,
                cancel,
                label: String::new(),
            }),
        }
    }

    pub fn labeled(mut self, label: impl Into<String>) -> Self {
        if let Some(inner) = Arc::get_mut(&mut self.inner) {
            inner.label = label.into();
        }
        self
    }

    /// 派生一份更紧的预算:deadline 取两者较早者,取消信号联动(父取消则子取消)。
    /// 用于共享任务自己的有限预算与跨主机传递后的本地收紧。
    pub fn child(&self, cap: Duration) -> Budget {
        let deadline = (Instant::now() + cap).min(self.inner.deadline);
        Budget {
            inner: Arc::new(BudgetInner {
                started: Instant::now(),
                deadline,
                cancel: self.inner.cancel.child_token(),
                label: self.inner.label.clone(),
            }),
        }
    }

    pub fn deadline(&self) -> Instant {
        self.inner.deadline
    }

    pub fn cancel_token(&self) -> CancellationToken {
        self.inner.cancel.clone()
    }

    pub fn cancel(&self) {
        self.inner.cancel.cancel();
    }

    pub fn is_cancelled(&self) -> bool {
        self.inner.cancel.is_cancelled()
    }

    pub fn elapsed(&self) -> Duration {
        self.inner.started.elapsed()
    }

    /// 剩余预算;耗尽为 0。
    pub fn remaining(&self) -> Duration {
        self.inner.deadline.saturating_duration_since(Instant::now())
    }

    /// 剩余预算(毫秒),用于跨主机 locker 传递 `BuckyOS-Resolve-Budget-Ms`。
    pub fn remaining_ms(&self) -> u64 {
        self.remaining().as_millis() as u64
    }

    /// 总 deadline/取消向外传播,不转为可继续回退的 Unknown。
    pub fn check(&self) -> NSResult<()> {
        if self.inner.cancel.is_cancelled() {
            return Err(NSError::Cancelled(self.describe()));
        }
        if Instant::now() >= self.inner.deadline {
            return Err(NSError::DeadlineExceeded(self.describe()));
        }
        Ok(())
    }

    fn describe(&self) -> String {
        if self.inner.label.is_empty() {
            format!("after {}ms", self.elapsed().as_millis())
        } else {
            format!("{} after {}ms", self.inner.label, self.elapsed().as_millis())
        }
    }

    /// 单步上限 = min(配置上限, 剩余预算)。
    pub fn step_cap(&self, configured: Duration) -> Duration {
        configured.min(self.remaining())
    }

    /// 在 `cap`(已与剩余预算取小)内运行一步。步骤超时但总预算仍有余量时返回
    /// `Timeout`,调用方可继续尝试下一个来源;总预算耗尽或被取消返回 `Terminated`。
    pub async fn run<F, T>(&self, cap: Duration, fut: F) -> Result<T, BudgetError>
    where
        F: Future<Output = T>,
    {
        self.check().map_err(BudgetError::Terminated)?;
        let cap = self.step_cap(cap);
        let started = Instant::now();
        tokio::select! {
            biased;
            _ = self.inner.cancel.cancelled() => {
                Err(BudgetError::Terminated(NSError::Cancelled(self.describe())))
            }
            result = tokio::time::timeout(cap, fut) => match result {
                Ok(value) => Ok(value),
                Err(_) => {
                    // 单个步骤超时:若总预算也已到期,必须向外抛终止错误。
                    if let Err(err) = self.check() {
                        return Err(BudgetError::Terminated(err));
                    }
                    Err(BudgetError::Timeout(SourceTimeout {
                        elapsed: started.elapsed(),
                        cap,
                    }))
                }
            }
        }
    }

    /// 在剩余预算内等待一个不可分步的操作(锁、许可、合并任务结果)。
    /// 超时直接按预算耗尽终止。
    pub async fn wait<F, T>(&self, fut: F) -> NSResult<T>
    where
        F: Future<Output = T>,
    {
        self.check()?;
        tokio::select! {
            biased;
            _ = self.inner.cancel.cancelled() => Err(NSError::Cancelled(self.describe())),
            result = tokio::time::timeout(self.remaining(), fut) => {
                result.map_err(|_| NSError::DeadlineExceeded(self.describe()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn step_timeout_keeps_budget_alive_but_exhaustion_terminates() {
        let budget = Budget::new(Duration::from_millis(120));
        let slow = budget
            .run(Duration::from_millis(20), async {
                tokio::time::sleep(Duration::from_millis(80)).await;
            })
            .await;
        assert!(matches!(slow, Err(BudgetError::Timeout(_))));
        assert!(budget.check().is_ok());

        tokio::time::sleep(Duration::from_millis(130)).await;
        assert!(matches!(budget.check(), Err(NSError::DeadlineExceeded(_))));
        let after = budget.run(Duration::from_secs(1), async { 1 }).await;
        assert!(matches!(after, Err(BudgetError::Terminated(_))));
    }

    #[tokio::test]
    async fn child_budget_shares_deadline_and_cancel() {
        let budget = Budget::new(Duration::from_secs(5));
        let child = budget.child(Duration::from_secs(60));
        assert!(child.deadline() <= budget.deadline());
        budget.cancel();
        assert!(matches!(child.check(), Err(NSError::Cancelled(_))));
        assert!(matches!(
            child.run(Duration::from_secs(1), async { 1 }).await,
            Err(BudgetError::Terminated(NSError::Cancelled(_)))
        ));
    }
}
