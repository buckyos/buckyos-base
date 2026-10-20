//! 请求选项(设计稿 §3、§4):来源信任等级与网络访问许可是两个维度。
//!
//! `ResolveOpts` 的 `normalize / with_* / create_get_owner_opts` 都返回副本,
//! 副本共享同一预算、取消信号和本轮 receipt 集合;来源/传输限制只能收紧,
//! Owner 递归、fallback 和重试不能续期或恢复默认值。

use super::budget::Budget;
use super::source::{Operation, SourceAnswer, SourceRef};
use name_lib::{DidDocType, NSError, NSResult, DID};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

/// 信任域标识:普通缓存和本机 locker 属于 Host;Zone locker 的回答携带
/// Zone(zone_did)。它只标识信任域,不授予远程写权限。
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Scope {
    Host,
    Zone(DID),
}

impl Default for Scope {
    fn default() -> Self {
        Self::Host
    }
}

impl Scope {
    pub fn key(&self) -> String {
        match self {
            Self::Host => "host".to_string(),
            Self::Zone(did) => format!("zone:{}", did.to_string()),
        }
    }

    pub fn zone_did(&self) -> Option<&DID> {
        match self {
            Self::Host => None,
            Self::Zone(did) => Some(did),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NetworkSources {
    /// 默认允许查询 authority / trust / normal。
    All,
    /// 仅允许普通 provider 中的 authority 发出网络请求,仍可复用本机材料。
    AuthorityOnly,
}

pub trait TransportPolicyImpl: Send + Sync {
    fn name(&self) -> &str;
    fn permits(&self, source: &SourceRef) -> bool;
}

/// 传输策略:覆盖身份与地址材料获取的每一跳。
#[derive(Clone)]
pub enum TransportPolicy {
    /// 普通传输。
    Default,
    /// 只允许本机可信配置声明且实际保证不依赖目标隧道 / Relay 转发入口的控制
    /// 通道(`SourceRef::independent_control_plane`);未知则拒绝。
    IndependentControlPlane,
    Custom(Arc<dyn TransportPolicyImpl>),
}

impl TransportPolicy {
    pub fn permits(&self, source: &SourceRef) -> bool {
        match self {
            Self::Default => true,
            Self::IndependentControlPlane => source.independent_control_plane,
            Self::Custom(policy) => policy.permits(source),
        }
    }

    pub fn key(&self) -> String {
        match self {
            Self::Default => "default".to_string(),
            Self::IndependentControlPlane => "icp".to_string(),
            Self::Custom(policy) => format!("custom:{}", policy.name()),
        }
    }
}

impl std::fmt::Debug for TransportPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.key())
    }
}

/// 本轮请求上下文中的一条真实回答。按来源 / DID / doc_type / 查询区分,
/// 递归共享;最外层新调用建立新的集合,复用 Opts 配置不能继承上轮 receipt。
#[derive(Debug, Clone)]
pub struct Receipt {
    pub source: SourceRef,
    pub did: DID,
    pub doc_type: DidDocType,
    pub revision_key: String,
    pub answer: SourceAnswer,
    pub recorded_at: Instant,
}

/// 本轮诊断:策略拒绝、超时等未回答记录。
#[derive(Debug, Clone)]
pub struct Unanswered {
    pub source: SourceRef,
    pub operation: Operation,
    pub reason: String,
}

#[derive(Debug, Default)]
pub struct ReceiptSet {
    receipts: Mutex<Vec<Receipt>>,
    unanswered: Mutex<Vec<Unanswered>>,
}

impl ReceiptSet {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn record(
        &self,
        source: &SourceRef,
        did: &DID,
        doc_type: &DidDocType,
        revision_key: &str,
        answer: &SourceAnswer,
    ) {
        if answer.is_unknown() {
            return;
        }
        let mut receipts = self.receipts.lock().unwrap();
        receipts.retain(|r| {
            !(r.source.id == source.id
                && r.did == *did
                && r.doc_type == *doc_type
                && r.revision_key == revision_key)
        });
        receipts.push(Receipt {
            source: source.clone(),
            did: did.clone(),
            doc_type: doc_type.clone(),
            revision_key: revision_key.to_string(),
            answer: answer.clone(),
            recorded_at: Instant::now(),
        });
    }

    /// 只复用本轮精确回答;body 与 publish_info 可共用一次回答。缺少所问内容时
    /// 返回 None,不隐含联网。
    pub fn reusable(
        &self,
        source_id: &str,
        did: &DID,
        doc_type: &DidDocType,
        revision_key: &str,
        operation: Operation,
    ) -> Option<SourceAnswer> {
        let receipts = self.receipts.lock().unwrap();
        receipts
            .iter()
            .find(|r| {
                r.source.id == source_id
                    && r.did == *did
                    && r.doc_type == *doc_type
                    && r.revision_key == revision_key
                    && r.answer.has(operation)
            })
            .map(|r| r.answer.clone())
    }

    /// 本轮真实 authority 回答(供 `select_rtcp_identity` 等证据门禁使用)。
    pub fn authority_receipts(&self, did: &DID, doc_type: &DidDocType) -> Vec<Receipt> {
        let receipts = self.receipts.lock().unwrap();
        receipts
            .iter()
            .filter(|r| {
                r.did == *did
                    && r.doc_type == *doc_type
                    && r.source.is_authority()
                    && !r.source.is_locker()
            })
            .cloned()
            .collect()
    }

    pub fn all(&self) -> Vec<Receipt> {
        self.receipts.lock().unwrap().clone()
    }

    pub fn record_unanswered(&self, source: &SourceRef, operation: Operation, reason: String) {
        self.unanswered.lock().unwrap().push(Unanswered {
            source: source.clone(),
            operation,
            reason,
        });
    }

    pub fn unanswered(&self) -> Vec<Unanswered> {
        self.unanswered.lock().unwrap().clone()
    }
}

/// 一次解析 / 验证调用的控制选项。
#[derive(Clone)]
pub struct ResolveOpts {
    pub scope: Scope,
    pub network_sources: NetworkSources,
    pub allow_request: bool,
    pub allow_local_lock: bool,
    pub allow_zone_lock: bool,
    pub allow_local_cache: bool,
    pub transport_policy: TransportPolicy,
    pub force_authority_query: bool,
    pub connect_timeout: Duration,
    pub request_timeout: Duration,
    /// 最外层建立预算时使用;已有 budget 时忽略。
    pub resolve_timeout: Option<Duration>,
    /// 调用方截止时间:与 `resolve_timeout` 取更早者。
    pub deadline: Option<Instant>,
    pub cancel: Option<CancellationToken>,
    pub max_depth: usize,
    budget: Option<Budget>,
    receipts: Option<Arc<ReceiptSet>>,
    visited: Vec<(DID, DidDocType)>,
}

impl std::fmt::Debug for ResolveOpts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResolveOpts")
            .field("scope", &self.scope)
            .field("network_sources", &self.network_sources)
            .field("allow_request", &self.allow_request)
            .field("allow_local_lock", &self.allow_local_lock)
            .field("allow_zone_lock", &self.allow_zone_lock)
            .field("allow_local_cache", &self.allow_local_cache)
            .field("transport_policy", &self.transport_policy)
            .field("force_authority_query", &self.force_authority_query)
            .field("visited", &self.visited.len())
            .finish()
    }
}

impl Default for ResolveOpts {
    /// 便捷入口默认值:本机 locker + Zone locker + 磁盘缓存 + 联网。
    fn default() -> Self {
        Self {
            scope: Scope::Host,
            network_sources: NetworkSources::All,
            allow_request: true,
            allow_local_lock: true,
            allow_zone_lock: true,
            allow_local_cache: true,
            transport_policy: TransportPolicy::Default,
            force_authority_query: false,
            connect_timeout: Duration::from_secs(5),
            request_timeout: Duration::from_secs(10),
            resolve_timeout: None,
            deadline: None,
            cancel: None,
            max_depth: 8,
            budget: None,
            receipts: None,
            visited: Vec::new(),
        }
    }
}

impl ResolveOpts {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_scope(mut self, scope: Scope) -> Self {
        self.scope = scope;
        self
    }

    pub fn with_network_sources(mut self, sources: NetworkSources) -> Self {
        // 只能收紧:AuthorityOnly 不能再放宽回 All。
        if self.network_sources == NetworkSources::AuthorityOnly {
            return self;
        }
        self.network_sources = sources;
        self
    }

    pub fn authority_only(self) -> Self {
        self.with_network_sources(NetworkSources::AuthorityOnly)
    }

    /// 禁止所有普通 provider 网络查询(包括 authority);递归 Owner 查询继承。
    pub fn not_allow_request(mut self) -> Self {
        self.allow_request = false;
        self
    }

    pub fn without_zone_lock(mut self) -> Self {
        self.allow_zone_lock = false;
        self
    }

    pub fn without_local_lock(mut self) -> Self {
        self.allow_local_lock = false;
        self
    }

    pub fn without_local_cache(mut self) -> Self {
        self.allow_local_cache = false;
        self
    }

    pub fn with_transport_policy(mut self, policy: TransportPolicy) -> Self {
        // 只能收紧:已是受限策略时不能换回 Default。
        if !matches!(self.transport_policy, TransportPolicy::Default)
            && matches!(policy, TransportPolicy::Default)
        {
            return self;
        }
        self.transport_policy = policy;
        self
    }

    pub fn with_force_authority_query(mut self) -> Self {
        self.force_authority_query = true;
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.resolve_timeout = Some(timeout);
        self
    }

    pub fn with_deadline(mut self, deadline: Instant) -> Self {
        self.deadline = Some(match self.deadline {
            Some(existing) => existing.min(deadline),
            None => deadline,
        });
        self
    }

    pub fn with_cancel(mut self, cancel: CancellationToken) -> Self {
        self.cancel = Some(cancel);
        self
    }

    pub fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = self.connect_timeout.min(timeout);
        self
    }

    pub fn with_request_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = self.request_timeout.min(timeout);
        self
    }

    /// 严格不联网:`not_allow_request + without_zone_lock`。
    pub fn strictly_offline(self) -> Self {
        self.not_allow_request().without_zone_lock()
    }

    pub fn allow_request(&self) -> bool {
        self.allow_request
    }

    pub fn allow_zone_lock(&self) -> bool {
        self.allow_zone_lock
    }

    pub fn allow_local_lock(&self) -> bool {
        self.allow_local_lock
    }

    pub fn allow_local_cache(&self) -> bool {
        self.allow_local_cache
    }

    pub fn is_normalized(&self) -> bool {
        self.budget.is_some() && self.receipts.is_some()
    }

    /// 最外层建立有限预算与新的 receipt 集合;已有预算时只继承。
    pub fn normalize(&self, default_timeout: Duration) -> Self {
        let mut opts = self.clone();
        if opts.budget.is_none() {
            let timeout = opts.resolve_timeout.unwrap_or(default_timeout);
            let mut deadline = Instant::now() + timeout;
            if let Some(caller) = opts.deadline {
                deadline = deadline.min(caller);
            }
            let budget = match opts.cancel.clone() {
                Some(cancel) => Budget::with_cancel(
                    deadline.saturating_duration_since(Instant::now()),
                    cancel,
                ),
                None => Budget::with_deadline(deadline),
            };
            opts.budget = Some(budget);
        }
        if opts.receipts.is_none() {
            opts.receipts = Some(ReceiptSet::new());
        }
        opts
    }

    /// 用已有预算 / receipt 构造副本(共享任务、locker 转发等内部用途)。
    pub fn with_budget(mut self, budget: Budget) -> Self {
        self.budget = Some(budget);
        self
    }

    pub fn budget(&self) -> &Budget {
        self.budget
            .as_ref()
            .expect("ResolveOpts must be normalized before use")
    }

    pub fn try_budget(&self) -> Option<&Budget> {
        self.budget.as_ref()
    }

    pub fn receipts(&self) -> &Arc<ReceiptSet> {
        self.receipts
            .as_ref()
            .expect("ResolveOpts must be normalized before use")
    }

    pub fn try_receipts(&self) -> Option<&Arc<ReceiptSet>> {
        self.receipts.as_ref()
    }

    pub fn record_unanswered(&self, source: &SourceRef, operation: Operation, reason: String) {
        if let Some(receipts) = self.receipts.as_ref() {
            receipts.record_unanswered(source, operation, reason);
        }
    }

    /// 本轮可复用的精确回答。
    pub fn reusable_query_answer(
        &self,
        source: &SourceRef,
        did: &DID,
        doc_type: &DidDocType,
        revision_key: &str,
        operation: Operation,
    ) -> Option<SourceAnswer> {
        self.receipts
            .as_ref()?
            .reusable(&source.id, did, doc_type, revision_key, operation)
    }

    pub fn record_query_answer(
        &self,
        source: &SourceRef,
        did: &DID,
        doc_type: &DidDocType,
        revision_key: &str,
        answer: &SourceAnswer,
    ) {
        if let Some(receipts) = self.receipts.as_ref() {
            receipts.record(source, did, doc_type, revision_key, answer);
        }
    }

    /// 访问策略键:任务合并键的一部分,受限请求不加入会访问目标站点的任务。
    pub fn access_policy_key(&self) -> String {
        format!(
            "net={}|req={}|zl={}|ll={}|lc={}|tp={}|faq={}",
            match self.network_sources {
                NetworkSources::All => "all",
                NetworkSources::AuthorityOnly => "authority",
            },
            self.allow_request as u8,
            self.allow_zone_lock as u8,
            self.allow_local_lock as u8,
            self.allow_local_cache as u8,
            self.transport_policy.key(),
            self.force_authority_query as u8
        )
    }

    /// Owner 递归使用的 opts:继承来源 / 传输 / locker 限制、同一预算与取消信号,
    /// 并做环路与深度检查。
    pub fn create_get_owner_opts(&self, owner: &DID) -> NSResult<Self> {
        self.descend(owner, &DidDocType::Owner)
    }

    pub fn descend(&self, did: &DID, doc_type: &DidDocType) -> NSResult<Self> {
        if self.visited.len() >= self.max_depth {
            return Err(NSError::InvalidState(format!(
                "DID resolution recursion depth exceeded at {}#{}",
                did.to_string(),
                doc_type
            )));
        }
        if self
            .visited
            .iter()
            .any(|(visited_did, visited_type)| visited_did == did && visited_type == doc_type)
        {
            return Err(NSError::InvalidState(format!(
                "DID resolution recursion loop at {}#{}",
                did.to_string(),
                doc_type
            )));
        }
        let mut next = self.clone();
        next.visited.push((did.clone(), doc_type.clone()));
        Ok(next)
    }

    /// 标记最外层查询自身,供递归环路检查。
    pub fn mark_visited(&mut self, did: &DID, doc_type: &DidDocType) {
        if !self
            .visited
            .iter()
            .any(|(d, t)| d == did && t == doc_type)
        {
            self.visited.push((did.clone(), doc_type.clone()));
        }
    }

    pub fn depth(&self) -> usize {
        self.visited.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn copies_share_budget_and_only_tighten() {
        let opts = ResolveOpts::default()
            .with_timeout(Duration::from_secs(5))
            .normalize(Duration::from_secs(30));
        let owner = opts
            .create_get_owner_opts(&DID::new("bns", "alice"))
            .unwrap()
            .authority_only()
            .with_network_sources(NetworkSources::All);
        assert_eq!(owner.network_sources, NetworkSources::AuthorityOnly);
        assert_eq!(owner.budget().deadline(), opts.budget().deadline());
        assert!(Arc::ptr_eq(owner.receipts(), opts.receipts()));
        // 再次 normalize 不续期。
        let again = owner.normalize(Duration::from_secs(600));
        assert_eq!(again.budget().deadline(), opts.budget().deadline());
        // 环路检查。
        assert!(owner.create_get_owner_opts(&DID::new("bns", "alice")).is_err());
    }

    #[test]
    fn policy_key_separates_restricted_requests() {
        let a = ResolveOpts::default();
        let b = ResolveOpts::default().authority_only().without_zone_lock();
        assert_ne!(a.access_policy_key(), b.access_policy_key());
        let icp = ResolveOpts::default()
            .with_transport_policy(TransportPolicy::IndependentControlPlane)
            .with_transport_policy(TransportPolicy::Default);
        assert!(!icp
            .transport_policy
            .permits(&SourceRef::provider("x", super::super::source::SourceTier::Authority)));
    }
}
