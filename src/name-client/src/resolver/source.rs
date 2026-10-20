//! 来源模型(设计稿 §2.1、§3):三档来源 authority / trust / normal + locker。
//!
//! 来源等级由本机注册决定,不能采用远端 payload 中的 `trusted / verified` 声明。
//! 统一回答 [`SourceAnswer`] 带 `body / publish_info / reason / cacheable`;
//! 只有可缓存的真实来源回答进入共享查询缓存。

use super::opts::ResolveOpts;
use super::publish_info::{PublishInfo, PublishRecord, PUBLISH_QUERY_TTL_SECS};
use super::revision::{DocRevision, ParsedDocument, Revision};
use async_trait::async_trait;
use buckyos_kit::buckyos_get_unix_timestamp;
use name_lib::{DidDocType, EncodedDocument, DID};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SourceTier {
    /// 确认发布,更新 latest/历史记录;可用文档也参与 best。
    Authority,
    /// 免 Owner 验签,可接受无签名 JSON,参与 best;不设置 is_signed / is_published。
    Trust,
    /// 只贡献候选;按可信 owner 绑定和签名验证后才参与 best。
    Normal,
}

impl SourceTier {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Authority => "authority",
            Self::Trust => "trust",
            Self::Normal => "normal",
        }
    }

    /// normal 必须验签;authority/trust 免 Owner 验签。
    pub fn need_verify(&self) -> bool {
        matches!(self, Self::Normal)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SourceKind {
    Provider,
    LocalLocker,
    ZoneLocker,
    /// 收件箱 / 进程内投递的候选。
    Inbox,
}

/// 一个来源的身份标签;随回答与结果一起保存。
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SourceRef {
    pub id: String,
    pub tier: SourceTier,
    pub kind: SourceKind,
    /// 本机可信配置声明该来源的传输不依赖目标隧道 / Relay 转发入口
    /// (`TransportPolicy::IndependentControlPlane` 只放行这类来源)。
    #[serde(default)]
    pub independent_control_plane: bool,
}

impl SourceRef {
    pub fn provider(id: impl Into<String>, tier: SourceTier) -> Self {
        Self {
            id: id.into(),
            tier,
            kind: SourceKind::Provider,
            independent_control_plane: false,
        }
    }

    pub fn local_locker() -> Self {
        Self {
            id: "local-locker".to_string(),
            tier: SourceTier::Authority,
            kind: SourceKind::LocalLocker,
            independent_control_plane: true,
        }
    }

    pub fn zone_locker(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            tier: SourceTier::Authority,
            kind: SourceKind::ZoneLocker,
            independent_control_plane: false,
        }
    }

    /// 收件箱候选:一律 normal。
    pub fn normal(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            tier: SourceTier::Normal,
            kind: SourceKind::Inbox,
            independent_control_plane: false,
        }
    }

    /// 预装 / 本机配置声明的 trust 候选。只能由进程内配置构造,不能从收件箱或
    /// 远端 payload 产生——这是类型层的提醒,真正的边界在调用入口。
    pub fn configured_trust(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            tier: SourceTier::Trust,
            kind: SourceKind::Inbox,
            independent_control_plane: true,
        }
    }

    pub fn with_independent_control_plane(mut self, independent: bool) -> Self {
        self.independent_control_plane = independent;
        self
    }

    pub fn is_authority(&self) -> bool {
        self.tier == SourceTier::Authority
    }

    pub fn is_zone_locker(&self) -> bool {
        self.kind == SourceKind::ZoneLocker
    }

    pub fn is_locker(&self) -> bool {
        matches!(self.kind, SourceKind::LocalLocker | SourceKind::ZoneLocker)
    }

    pub fn need_verify(&self) -> bool {
        self.tier.need_verify()
    }
}

impl std::fmt::Display for SourceRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}({})", self.id, self.tier.as_str())
    }
}

/// 文档载体:HTTP body / 响应头 / 信封内联 / locker / 推导 / 缓存。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Carrier {
    Body,
    Header,
    Inline,
    Locker,
    Derived,
    Cache,
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    Document,
    PublishInfo,
}

impl Operation {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Document => "document",
            Self::PublishInfo => "publish_info",
        }
    }
}

/// 统一回答。`body` 与 `publish_info` 都为 None 时是 Unknown / NoAnswer,
/// `reason` 保留原因;`cacheable=false` 的回答只记录本次诊断,不进共享缓存。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceAnswer {
    pub body: Option<EncodedDocument>,
    pub publish_info: Option<PublishInfo>,
    pub reason: Option<String>,
    pub cacheable: bool,
    /// 真实来源 / 传输失败(可按目标 + 来源 + 策略短期退避);策略拒绝、调用
    /// 取消或预算不足不设置它。
    #[serde(default)]
    pub failure: bool,
    /// 来源明确表示不支持指定版本 / closest 查询(wire 501)。
    #[serde(default)]
    pub unsupported_history: bool,
    pub carrier: Carrier,
    pub source: SourceRef,
    pub answered_at: u64,
    #[serde(default)]
    pub ttl_secs: Option<u64>,
    /// 实际请求上下文(最终 URL 等),仅诊断。
    #[serde(default)]
    pub context: Option<String>,
}

impl SourceAnswer {
    pub fn new(source: SourceRef) -> Self {
        Self {
            body: None,
            publish_info: None,
            reason: None,
            cacheable: true,
            failure: false,
            unsupported_history: false,
            carrier: Carrier::None,
            source,
            answered_at: buckyos_get_unix_timestamp(),
            ttl_secs: None,
            context: None,
        }
    }

    /// 没有得到回答。`cacheable=false` 用于策略拒绝、本地超时、取消、预算不足;
    /// 真实来源的 NoAnswer / 传输失败用 [`SourceAnswer::failure`]。
    pub fn unknown(source: SourceRef, reason: impl Into<String>, cacheable: bool) -> Self {
        let mut answer = Self::new(source);
        answer.reason = Some(reason.into());
        answer.cacheable = cacheable;
        answer
    }

    /// 真实来源的传输 / 上游失败:不可缓存为负状态,但可短期退避。
    pub fn failure(source: SourceRef, reason: impl Into<String>) -> Self {
        let mut answer = Self::unknown(source, reason, false);
        answer.failure = true;
        answer
    }

    /// 真实来源明确"不适用 / 没有意见"(如 bare 404):可短期缓存为 NoAnswer。
    pub fn no_answer(source: SourceRef, reason: impl Into<String>) -> Self {
        let mut answer = Self::unknown(source, reason, true);
        answer.ttl_secs = Some(PUBLISH_QUERY_TTL_SECS);
        answer
    }

    pub fn with_body(mut self, body: EncodedDocument, carrier: Carrier) -> Self {
        self.body = Some(body);
        self.carrier = carrier;
        self
    }

    pub fn with_publish_info(mut self, info: PublishInfo) -> Self {
        self.publish_info = Some(info);
        self
    }

    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = Some(reason.into());
        self
    }

    pub fn with_context(mut self, context: impl Into<String>) -> Self {
        self.context = Some(context.into());
        self
    }

    pub fn is_unknown(&self) -> bool {
        self.body.is_none() && self.publish_info.is_none()
    }

    pub fn has(&self, operation: Operation) -> bool {
        match operation {
            Operation::Document => self.body.is_some(),
            Operation::PublishInfo => self.publish_info.is_some(),
        }
    }

    pub fn body_revision(&self) -> Option<DocRevision> {
        self.body.as_ref().and_then(DocRevision::of)
    }

    pub fn cache_ttl_secs(&self) -> u64 {
        if let Some(ttl) = self.ttl_secs {
            return ttl;
        }
        match &self.publish_info {
            Some(info) => info.cache_ttl_secs(),
            None => PUBLISH_QUERY_TTL_SECS,
        }
    }

    pub fn reason_text(&self) -> String {
        self.reason
            .clone()
            .unwrap_or_else(|| "no answer".to_string())
    }
}

/// `doc_type = None` 归一的回答(设计稿 §2.4)。
#[derive(Debug, Clone)]
pub enum DefaultDocType {
    Known {
        doc_type: DidDocType,
        reasons: Vec<String>,
    },
    Ambiguous(String),
}

/// 普通来源 / locker 的统一接口。实现接收并执行 `opts`,包含内部解析、每一跳的
/// 传输门禁与剩余预算;不支持传递限制的实现在受限路径必须返回 Unknown(不可缓存)。
#[async_trait]
pub trait Source: Send + Sync + 'static {
    fn id(&self) -> String;

    /// 是否支持 `publish_info` 查询(exact / closest 依赖它)。不支持者在
    /// 非 current 查询上直接得到 Unknown("此来源不支持指定版本/closest 查询")。
    fn supports_publish_info(&self) -> bool {
        false
    }

    /// 取文档。回答可同时带 `publish_info`(一次 HTTP 往返同时回答两列)。
    async fn get_document(
        &self,
        did: &DID,
        doc_type: &DidDocType,
        revision: &Revision,
        opts: &ResolveOpts,
    ) -> SourceAnswer;

    /// 取发布信息。默认复用 `get_document`(同一端点);实现可覆盖。
    async fn get_publish_info(
        &self,
        did: &DID,
        doc_type: &DidDocType,
        revision: &Revision,
        opts: &ResolveOpts,
    ) -> SourceAnswer {
        self.get_document(did, doc_type, revision, opts).await
    }

    /// `doc_type = None` 时按 method / provider 规则选择默认类型。
    /// 默认实现:路径型对象 → `did-object`;其它返回 None 表示该来源无意见。
    async fn default_doc_type(&self, did: &DID, _opts: &ResolveOpts) -> Option<DefaultDocType> {
        if did.id.contains(':') {
            return Some(DefaultDocType::Known {
                doc_type: DidDocType::DidObject,
                reasons: Vec::new(),
            });
        }
        None
    }
}

/// 注册项:来源 + 本机注册决定的等级与传输声明。
#[derive(Clone)]
pub struct RegisteredSource {
    pub source: Arc<dyn Source>,
    pub sref: SourceRef,
    /// 只在 current-zone 自举时可用(DNS TXT 等):`opts.scope == Zone(did)` 且
    /// 请求 DID 等于该 Zone 时才参与。
    pub zone_bootstrap_only: bool,
}

impl RegisteredSource {
    pub fn new(source: Arc<dyn Source>, tier: SourceTier) -> Self {
        let sref = SourceRef::provider(source.id(), tier);
        Self {
            source,
            sref,
            zone_bootstrap_only: false,
        }
    }

    pub fn zone_bootstrap(mut self) -> Self {
        self.zone_bootstrap_only = true;
        self
    }

    pub fn independent_control_plane(mut self, independent: bool) -> Self {
        self.sref.independent_control_plane = independent;
        self
    }

    pub fn is_authority(&self) -> bool {
        self.sref.is_authority()
    }
}

/// 统一归一:回填来源标签;authority 的 current 回答只有 body 没有 publish_info
/// 时,把它登记为"authority 当前发布 = 该 body"(did:web 静态发布面没有独立的
/// 发布状态信道,authority 取回的 current body 就是发布事实)。
pub fn normalize_source_answer(
    mut answer: SourceAnswer,
    sref: &SourceRef,
    did: &DID,
    doc_type: &DidDocType,
    revision: &Revision,
) -> SourceAnswer {
    answer.source = sref.clone();
    if answer.answered_at == 0 {
        answer.answered_at = buckyos_get_unix_timestamp();
    }
    if sref.is_authority()
        && revision.is_current()
        && answer.publish_info.is_none()
        && !answer.source.is_locker()
    {
        if let Some(body) = answer.body.as_ref() {
            if let Ok(parsed) = ParsedDocument::parse(body) {
                if let Some(doc_revision) = parsed.revision() {
                    if parsed.matches(did, doc_type).is_ok() {
                        let info = PublishInfo::new(did.clone(), doc_type.clone(), Revision::current())
                            .with_status(&super::publish_info::DocumentStatus::Active, None, None)
                            .with_record(PublishRecord::published(
                                doc_revision.iat,
                                &doc_revision.hash,
                                true,
                            ))
                            .with_source(sref.id.clone());
                        answer.publish_info = Some(info);
                    }
                }
            }
        }
    }
    if let Some(info) = answer.publish_info.as_mut() {
        if info.source.is_none() {
            info.source = Some(sref.id.clone());
        }
        if info.query != *revision && !info.derived {
            info.query = revision.clone();
        }
    }
    answer
}
