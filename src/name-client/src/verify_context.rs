//! 纯 DID Document verifier 与 freshness 事实类型
//! (doc/verify-did-api-boundary-and-freshness-TODO.md)。
//!
//! 三个动词回答不同问题:`resolve` 负责按指定来源取得证据,`verify`(本模块)
//! 负责用已有证据验证调用方给出的**确切文档**,`add_cache` 负责显式保存证据。
//! 本模块是纯 verify:同步函数,**不联网、不读 provider、不写任何 cache**,
//! 只消费调用方准备好的不可变 [`VerifyContextSnapshot`]。参考 TLS:对端携带
//! 待验证文档(证书链),verifier 用本机 trust store 验它;缺中间材料时返回
//! 结构化 [`VerifyError::MissingDependency`],由调用方决定是否显式 resolve。
//!
//! 结果把"密码学与信任链有效"(validity)和"是不是目前知道的最新版本"
//! (freshness)作为两个独立维度表达;freshness 又区分"本地已知最新"
//! ([`LocalFreshness`],相对某个 local trust scope)与"权威全局最新"
//! ([`AuthorityFreshness`],只能来自本次显式 Remote Authority Resolve)。
//! 是否接受由调用方对事实应用 [`FreshnessRequirement`] 单独决定
//! ([`evaluate_freshness`]),不再压成一个 `CurrentActive` 错误。

use buckyos_kit::buckyos_get_unix_timestamp;
use jsonwebtoken::DecodingKey;
use name_lib::*;
use serde::{Deserialize, Serialize};

use crate::{
    content_hash_matches, document_content_hash, document_iat, is_key_class_method,
    structural_owner, DidDocType, DocumentStatus, ResolveWarning,
};

// ------------------------ revision ------------------------

/// 文档 revision:只以 `iat` 为序,辅以 content hash 判定同一性与冲突。
/// `version_seq` 已整体退出流程(原有字段视作用户自定义扩展,不参与比较)。
///
/// content hash 编码契约见 [`document_content_hash`]。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocumentRevision {
    /// `iat` 直接存在,或由 `exp - DEFAULT_EXPIRE_TIME` 补充推导
    /// (`get_doc_iat` 语义)。iat/exp 皆无的文档没有 revision(InvalidDocument)。
    pub iat: u64,
    pub content_hash: String,
}

impl DocumentRevision {
    /// 计算候选文档的 revision;iat 无法得出时返回 None(文档无效)。
    pub fn of(doc: &EncodedDocument) -> Option<Self> {
        Some(Self {
            iat: document_iat(doc)?,
            content_hash: document_content_hash(doc),
        })
    }
}

// ------------------------ trust scope 与证据来源 ------------------------

/// "本地"是**相对权威 Remote Resolve** 而言的 local trust scope,不等于
/// "只在当前进程内":Zone Resolver 可以代表整个 Zone/集群的生产级已知状态。
/// 一次 snapshot 只选择一个主 scope(Zone 优先于 Host,与现有 L1/L2 层级一致)。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LocalTrustScope {
    Process,
    Host,
    Zone,
    /// 调用方自己的 trust domain / high-water snapshot(RTCP 等上游)。
    Caller(String),
}

impl std::fmt::Display for LocalTrustScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Process => f.write_str("process"),
            Self::Host => f.write_str("host"),
            Self::Zone => f.write_str("zone"),
            Self::Caller(label) => write!(f, "caller:{}", label),
        }
    }
}

/// snapshot 中一份材料的来源(ValidityEvidence 如实记录本次验证依赖了什么)。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceSource {
    /// method 名字结构规则(离线确定,如 did:bns:laptop.alice → did:bns:alice)。
    StructuralRule,
    /// 本次显式 Remote Authority Resolve 的 receipt。
    AuthorityReceipt,
    /// Zone Resolver(shared cache / control plane)的回答。
    ZoneSnapshot,
    /// 本机 `verified/` cache(含装机/激活时种入的种子文档)。
    LocalCache,
    /// 本地 hosts 式 override。
    LocalOverride,
    /// 调用方自备材料。
    Caller,
}

// ------------------------ snapshot ------------------------

/// snapshot 中可作为验签依据的 owner 材料。**必须**具备 Verified/Published/
/// Zone/Authority 级证据;Observed/Unverified 条目不得作为 owner 验签依据
/// (与现有实现一致:owner replay guard 只认 `verified/` 命名空间)。
/// 该门槛由 snapshot 构建方(`build_verify_context` 或调用方)保证——cache 的
/// 信任边界是文件系统 namespace 与写权限,不是 Rust 类型系统(非目标 7)。
#[derive(Debug, Clone)]
pub struct SnapshotOwnerMaterial {
    pub owner: DID,
    pub document: EncodedDocument,
    pub source: EvidenceSource,
}

/// 权威源记录的 owner 绑定及其来源(权威 receipt 或 Zone 回答)。
#[derive(Debug, Clone)]
pub struct SnapshotOwnerBinding {
    pub owner: DID,
    pub source: EvidenceSource,
}

/// 主 scope 中 (did, doc_type) 的 latest-known 基线。"Known"表示已验证/已接受
/// 或由受信 cache/control plane 记录的状态,不表示"网络上随便收到过";
/// Observed/unverified 文件不能推进 baseline。
#[derive(Debug, Clone)]
pub enum SnapshotBaseline {
    /// 本次没有加载该 scope 的基线(cache 关闭、scope 不可达)。
    Unavailable { reason: String },
    /// scope 中没有该 (did, doc_type) 的已接受状态。
    Empty,
    /// scope 中最新已接受的 revision。
    Known(DocumentRevision),
}

/// snapshot 中记忆的 terminal 负状态(Revoked/Tombstoned)。纯 verify 对它硬
/// 失败([`VerifyError::RejectedByNegativeState`]),与现有"负状态屏蔽一切兜底"
/// 语义连续;非 terminal 负状态(Missing/Expired/Migrated)不放这里——它们是
/// freshness/validity 事实(`scope_negative` 或权威 receipt)。
#[derive(Debug, Clone)]
pub struct SnapshotNegativeState {
    pub status: DocumentStatus,
    pub scope: LocalTrustScope,
    /// 记忆来源描述(negative-cache / zone-answer / authority-receipt),诊断用。
    pub origin: String,
}

/// 本次流程中权威渠道的状态。`Receipt` 只能由显式 Remote Authority Resolve
/// (或 `BestAvailable` 明确命中 method authority)产生;local/Zone cache 再强
/// 也不能伪装成 receipt。
#[derive(Debug, Clone)]
pub enum SnapshotAuthorityState {
    /// 本次流程没有(按来源策略也不允许)询问权威渠道。
    NotConsulted,
    /// 该 method 没有注册权威渠道:发布状态与 owner 绑定不可知。
    NoChannel,
    /// 显式要求了权威判断,但权威没有回答(断网/超时)。
    Unreachable {
        attempted_at: u64,
        source: Option<String>,
        detail: String,
    },
    /// 权威渠道的回答。
    Receipt(AuthorityReceipt),
}

/// 本次权威 Remote Resolve 的回答(receipt)。`document_iat` 即 wire 的
/// `documentVersion`(documentVersion = document_iat):权威记录的"文档版本"
/// 就是当前发布文档的 iat,吊销/替换语义与 owner 侧 `valid_iat` 统一在同一条
/// iat 轴上。
#[derive(Debug, Clone)]
pub struct AuthorityReceipt {
    pub status: DocumentStatus,
    /// 权威锚定的当前文档 content hash(wire `docHash`)。
    pub doc_hash: Option<String>,
    /// 权威给出的当前文档 body(内联或读取端取回)。
    pub current_body: Option<EncodedDocument>,
    pub effective_owner: Option<DID>,
    pub authority_seq: Option<u64>,
    /// 权威记录的当前发布文档 iat(wire `documentVersion`)。
    pub document_iat: Option<u64>,
    pub migration_target: Option<DID>,
    pub checked_at: u64,
    pub valid_until: Option<u64>,
    pub source: String,
}

/// 纯 verify 消费的只读 trust snapshot,由调用方显式准备(本机 trust store、
/// local cache、Zone 查询结果、刚完成的 Remote Authority receipt、调用方自己的
/// trust domain)。`NameClient::build_verify_context` 提供按 `ResolveSourcePolicy`
/// 组装的 helper;上游也可以手工拼装(scope 用 `Caller`)。
///
/// snapshot 是不可变值:一次验证只消费一个 generation,避免混用并发更新前后的
/// 证据。
#[derive(Debug, Clone)]
pub struct VerifyContextSnapshot {
    /// 主 scope(一次 snapshot 只选择一个;Zone 优先于 Host)。
    pub scope: LocalTrustScope,
    /// snapshot 构建序号(同一构建方内单调),用于诊断与并发排查。
    pub generation: u64,
    /// snapshot 组装时刻。
    pub checked_at: u64,
    /// snapshot 材料可视为新鲜的截止时刻(来源声明的 validUntil 中最早者)。
    pub valid_until: Option<u64>,
    /// 权威渠道状态(receipt 只能来自本次显式 Remote Resolve)。
    pub authority: SnapshotAuthorityState,
    /// 权威源/Zone 记录的 owner 绑定;候选文档自声明的 owner 说了不算。
    pub owner_binding: Option<SnapshotOwnerBinding>,
    /// expected_owner 的 OwnerDocument 验签材料(证据门槛见类型注释)。
    pub owner_material: Option<SnapshotOwnerMaterial>,
    /// 主 scope 的 latest-known 基线。
    pub baseline: SnapshotBaseline,
    /// terminal 负状态记忆(硬失败)。
    pub negative_state: Option<SnapshotNegativeState>,
    /// 主 scope 源记忆的非 terminal 负状态事实(如 Zone 回答 Missing/Expired),
    /// 进入 ValidityEvidence,由 freshness policy 决定是否接受
    /// (对应未发布 DeviceDocument 的 bootstrap 场景)。
    pub scope_negative: Option<DocumentStatus>,
}

impl VerifyContextSnapshot {
    /// 调用方手工拼装 snapshot 的起点:空材料、指定 scope、当前时刻。
    pub fn empty(scope: LocalTrustScope) -> Self {
        Self {
            scope,
            generation: 0,
            checked_at: buckyos_get_unix_timestamp(),
            valid_until: None,
            authority: SnapshotAuthorityState::NotConsulted,
            owner_binding: None,
            owner_material: None,
            baseline: SnapshotBaseline::Unavailable {
                reason: "caller supplied no baseline".to_string(),
            },
            negative_state: None,
            scope_negative: None,
        }
    }
}

// ------------------------ verify 结果 ------------------------

/// 验证目的。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerifyPurpose {
    /// 默认模式:用于 RTCP、跨 zone 请求、RBAC principal、应用内权限主语。
    /// authority_owner 与 structural_owner 同时存在且不同(detached owner)时
    /// 必须拒绝。
    AuthSubject,
    /// 客体文档解析:允许权威 owner 与结构 owner 不同。调用方不得把结果直接
    /// 作为权限主语使用(`usable_as_authz_subject` 恒为 false)。
    ObjectDocument,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyOptions {
    pub purpose: VerifyPurpose,
}

impl Default for VerifyOptions {
    fn default() -> Self {
        Self {
            purpose: VerifyPurpose::AuthSubject,
        }
    }
}

/// 验证警告沿用 resolver 的警告词表(`SignedByHistoricalKey` 等)。
pub type VerifyWarning = ResolveWarning;

/// 本次验证实际依赖了什么(有效性维度的证据说明)。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidityEvidence {
    /// 本次比较/验签所用 snapshot 的主 scope。
    pub scope: LocalTrustScope,
    pub snapshot_generation: u64,
    /// snapshot 组装时刻(材料新鲜度的读数时刻)。
    pub checked_at: u64,
    pub valid_until: Option<u64>,
    /// expected_owner 的来源;None 表示本次验证没有 expected_owner
    /// (Owner 递归基或无主 ObjectDocument)。
    pub expected_owner_source: Option<EvidenceSource>,
    /// 验签用 OwnerDocument 的来源;未做 owner 验签(membership 路径)为 None。
    pub owner_document_source: Option<EvidenceSource>,
    /// 是否使用 historical key 完成验签。
    pub used_historical_key: bool,
    /// owner replay guard(`valid_iat`)是否执行。
    pub owner_replay_guard_applied: bool,
    /// 权威渠道对 (did, doc_type) 的原始回答状态(本次流程携带 receipt 时)。
    pub authority_status: Option<DocumentStatus>,
    /// 主 scope 源记忆的非 terminal 负状态事实(Missing/Expired/Migrated)。
    /// 是否接受由调用方 freshness policy 决定(bootstrap 场景的显式化)。
    pub scope_negative_status: Option<DocumentStatus>,
    /// 权威 membership 是否成立(候选被证明属于当前发布集合)。
    pub membership_proven: bool,
    /// 权威 owner 绑定与结构 owner 是否分离(仅 ObjectDocument 能带着它成功)。
    pub detached_owner: bool,
}

/// 本地已知 freshness:候选与指定 local trust scope 中已验证/已接受状态的关系。
/// 不同 scope 可以有不同结论;调用方必须知道本次比较使用了哪个 scope,
/// name-client 不替所有应用定义唯一的全局 high-water mark。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LocalFreshness {
    Unknown {
        scope: LocalTrustScope,
        reason: String,
    },
    FirstKnown {
        scope: LocalTrustScope,
        candidate: DocumentRevision,
    },
    SameAsLatestKnown {
        scope: LocalTrustScope,
        revision: DocumentRevision,
    },
    NewerThanLatestKnown {
        scope: LocalTrustScope,
        candidate: DocumentRevision,
        previous: DocumentRevision,
    },
    OlderThanLatestKnown {
        scope: LocalTrustScope,
        candidate: DocumentRevision,
        latest: DocumentRevision,
    },
    ConflictAtSameRevision {
        scope: LocalTrustScope,
        expected: DocumentRevision,
        candidate: DocumentRevision,
    },
}

/// 权威全局 freshness。没有经过权威 Remote Resolve 就是 `NotChecked`;
/// local/Zone cache 再强也属于 `LocalFreshness` 和 `ValidityEvidence` 的来源,
/// 不能仅凭 ZoneHit/Published cache 冒充 `Current`。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthorityFreshness {
    /// 本次没有执行权威 Remote Resolve(含该 method 没有权威渠道)。
    NotChecked,
    /// 本次权威 Remote Resolve 明确证明候选属于当前发布集合(hash/body 绑定)。
    /// 表示 authority 在 `checked_at` 时刻的判断,不是永久当前;没有
    /// `valid_until` 时调用方应通过 freshness policy 限制检查年龄。
    Current {
        authority_seq: Option<u64>,
        /// 权威记录的当前发布文档 iat(wire `documentVersion` 的统一语义)。
        document_iat: Option<u64>,
        checked_at: u64,
        valid_until: Option<u64>,
        source: String,
    },
    /// 本次权威 Remote Resolve 回答了 Active,但没有给出可绑定候选的锚点
    /// (无 doc_hash、无当前 body、无 document_iat 可比较):不是 `Current`
    /// (Current 必须绑定候选),也不是 `NotCurrent`(权威未否定候选)。
    /// 等价于旧流程"权威 Active 下的 NeedProof 候选"档位。
    ActiveUnanchored {
        authority_seq: Option<u64>,
        checked_at: u64,
        source: String,
    },
    /// 本次权威 Remote Resolve 明确说明候选不是当前版本或处于(非 terminal)
    /// 负状态。terminal 负状态不会走到这里——它在纯 verify 中硬失败
    /// (`RejectedByNegativeState`)。
    NotCurrent {
        reason: AuthorityNotCurrentReason,
        authority_seq: Option<u64>,
        /// 权威当前发布文档的 iat;Superseded 时调用方可据此比对 revision。
        current_document_iat: Option<u64>,
        checked_at: u64,
        source: String,
    },
    /// 调用方显式要求 Remote Resolve,但 authority 没有回答。
    Unavailable {
        attempted_at: u64,
        source: Option<String>,
        detail: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthorityNotCurrentReason {
    /// DID 仍 Active,但权威锚定的当前 body/hash 与候选不同。
    DifferentDocument,
    /// 候选 iat 小于权威当前发布文档 iat(wire documentVersion)。
    Superseded,
    /// 权威回答了非 terminal 负状态(Missing/Expired/Migrated)。
    NegativeStatus(DocumentStatus),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FreshnessEvidence {
    pub local: LocalFreshness,
    pub authority: AuthorityFreshness,
}

/// 验证报告(不是 capability):是否有权写 verified cache 由进程/目录权限决定,
/// 不依赖"只有 name-client 能构造这个 Rust 类型"的假设。权限系统只能使用这里
/// 的字段,不得自行从名字截取 owner。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiedDidDocument {
    /// 候选文档证明的主体 DID(已与调用方期望一致)。
    pub subject_did: DID,
    pub doc_type: DidDocType,
    pub document: EncodedDocument,

    /// method 名字结构确定性推出的默认 owner;一级名字为 None。
    pub structural_owner: Option<DID>,
    /// 权威源/Zone 记录的 owner 绑定。
    pub authority_owner: Option<DID>,
    /// 本次验签和 owner replay guard 实际使用的 owner:
    /// `authority_owner.or(structural_owner)`,绝不来自 payload。
    pub expected_owner: Option<DID>,
    /// 候选 payload 自声明的 owner(`get_iss()`);Owner 递归基为 None。
    pub declared_owner: Option<DID>,
    /// 权限系统使用的 owner 维度主体;仅 `usable_as_authz_subject == true` 时
    /// 为 Some(等于 expected_owner)。
    pub authz_owner: Option<DID>,
    /// false 时该结果不得作为权限主语进入 RBAC 或应用内 ACL。
    pub usable_as_authz_subject: bool,

    /// 候选文档的 revision(iat + content hash)。
    pub revision: DocumentRevision,
    /// 有效性维度:本次验证实际依赖的材料与来源。
    pub validity: ValidityEvidence,
    /// freshness 维度:本地已知 + 权威全局两个独立事实。
    pub freshness: FreshnessEvidence,
    pub warnings: Vec<VerifyWarning>,
}

// ------------------------ verify 错误 ------------------------

/// 纯 verify 的结构化失败。注意"缺少 authority-current 证明但密码学/owner 验证
/// 已经完成"**不是** VerifyError——那是 freshness 事实,由
/// [`evaluate_freshness`] 按 policy 决定。
#[derive(Debug, Clone)]
pub enum VerifyError {
    /// 候选不是可识别/自洽的 DID Document(含 iat/exp 皆无推不出 revision、
    /// 文档自声明已过期 `exp <= now`、doc_type 不符、key 类 DID 主体)。
    InvalidDocument { detail: String },
    /// `payload.id != expected_did`。
    DocumentIdMismatch { expected: DID, actual: DID },
    /// declared owner 与 expected_owner 不一致(含未声明 owner)。
    OwnerMismatch {
        expected: DID,
        declared: Option<DID>,
    },
    /// 权威 owner 绑定与结构 owner 分离,而 purpose 为 AuthSubject。
    DetachedOwnerRejected { structural: DID, authority: DID },
    /// 权威渠道已回答(或该 method 没有权威渠道)、也没有结构 owner:
    /// expected_owner 确定性缺失,一级名字没有权威绑定不能作为主体。
    OwnerBindingUnavailable { detail: String },
    /// owner key(含历史 key)验签失败,或候选结构上无法携带签名。
    SignatureRejected { detail: String },
    /// 命中 owner 的 `valid_iat` replay guard(anti-rollback)。
    RevokedByOwnerPolicy { detail: String },
    /// snapshot 中存在该 (did, doc_type) 的 terminal 负状态(Revoked/
    /// Tombstoned),不论它来自本机负缓存记忆、Zone 回答还是本次 Remote receipt。
    RejectedByNegativeState {
        scope: LocalTrustScope,
        status: DocumentStatus,
    },
    /// 缺少完成有效性验证所必需的本地材料,且 verify 没有尝试联网。
    /// 由调用方决定是否显式 resolve 后携带新 snapshot 重试。
    MissingDependency { dependencies: Vec<VerifyDependency> },
}

/// `MissingDependency` 的结构化依赖项。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyDependency {
    /// expected_owner 未知:需要权威 owner 绑定(该 DID 没有结构 owner,
    /// 而 snapshot 未携带权威/Zone 绑定回答)。
    OwnerBinding { did: DID, doc_type: DidDocType },
    /// expected_owner 已知,但 snapshot 缺该 owner 的 OwnerDocument 验签材料。
    OwnerDocument { owner: DID },
    /// 候选没有 owner 信任链可走(Owner 递归基 / 无主 ObjectDocument),
    /// 需要权威 membership 证明,而 snapshot 未携带可绑定的权威回答。
    AuthorityMembership { did: DID, doc_type: DidDocType },
}

impl VerifyError {
    /// 稳定错误码(日志/跨进程传递用;进程内请直接 match 枚举)。
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidDocument { .. } => "InvalidDocument",
            Self::DocumentIdMismatch { .. } => "DocumentIdMismatch",
            Self::OwnerMismatch { .. } => "OwnerMismatch",
            Self::DetachedOwnerRejected { .. } => "DetachedOwnerRejected",
            Self::OwnerBindingUnavailable { .. } => "OwnerBindingUnavailable",
            Self::SignatureRejected { .. } => "SignatureRejected",
            Self::RevokedByOwnerPolicy { .. } => "RevokedByOwnerPolicy",
            Self::RejectedByNegativeState { .. } => "RejectedByNegativeState",
            Self::MissingDependency { .. } => "MissingDependency",
        }
    }
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidDocument { detail } => write!(f, "invalid document: {}", detail),
            Self::DocumentIdMismatch { expected, actual } => write!(
                f,
                "document id {} does not match expected {}",
                actual.to_string(),
                expected.to_string()
            ),
            Self::OwnerMismatch { expected, declared } => write!(
                f,
                "declared owner {} does not match expected owner {}",
                declared
                    .as_ref()
                    .map(|did| did.to_string())
                    .unwrap_or_else(|| "<none>".to_string()),
                expected.to_string()
            ),
            Self::DetachedOwnerRejected {
                structural,
                authority,
            } => write!(
                f,
                "authority owner {} differs from structural owner {}; \
                 detached owner cannot be an auth subject",
                authority.to_string(),
                structural.to_string()
            ),
            Self::OwnerBindingUnavailable { detail } => {
                write!(f, "owner binding unavailable: {}", detail)
            }
            Self::SignatureRejected { detail } => write!(f, "signature rejected: {}", detail),
            Self::RevokedByOwnerPolicy { detail } => {
                write!(f, "revoked by owner policy: {}", detail)
            }
            Self::RejectedByNegativeState { scope, status } => write!(
                f,
                "rejected by terminal negative state {:?} in {} scope",
                status, scope
            ),
            Self::MissingDependency { dependencies } => {
                write!(f, "missing dependencies: {:?}", dependencies)
            }
        }
    }
}

impl std::error::Error for VerifyError {}

// ------------------------ freshness policy ------------------------

/// freshness requirement 是独立 policy:verify 成功只表示候选通过有效性验证并
/// 返回真实 freshness 事实,是否接受由调用方单独应用 requirement。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FreshnessRequirement {
    /// 只要求有效性(签名/owner/负状态),不约束 freshness。
    AnyValid,
    /// 本地防回滚:候选不得旧于指定 scope 的 latest-known(冲突同样拒绝)。
    NotOlderThanLocalLatest { scope: LocalTrustScope },
    /// 必须由本次权威 Remote Resolve 证明候选全局当前;`max_age_secs` 限制
    /// 检查年龄(authority 未提供 valid_until 时的调用方自我约束)。
    RequireAuthorityCurrent { max_age_secs: Option<u64> },
    NotOlderAndAuthorityCurrent {
        scope: LocalTrustScope,
        max_age_secs: Option<u64>,
    },
}

#[derive(Debug, Clone)]
pub enum FreshnessPolicyError {
    /// 候选旧于 scope 的 latest-known。
    OlderThanLocalLatest {
        scope: LocalTrustScope,
        candidate: DocumentRevision,
        latest: DocumentRevision,
    },
    /// 同 iat 不同 hash 的稳定冲突。
    ConflictAtSameRevision {
        scope: LocalTrustScope,
        expected: DocumentRevision,
        candidate: DocumentRevision,
    },
    /// requirement 要求的 scope 与本次比较使用的 scope 不一致,或基线未知,
    /// 无法证明"不旧于"。
    LocalBaselineUnknown {
        requested: LocalTrustScope,
        actual: LocalTrustScope,
        reason: String,
    },
    /// 要求权威当前,但本次没有执行权威 Remote Resolve(或权威没有绑定候选)。
    AuthorityNotChecked { detail: String },
    /// 权威明确否定候选为当前版本。
    AuthorityNotCurrent {
        reason: AuthorityNotCurrentReason,
        current_document_iat: Option<u64>,
    },
    /// 显式要求了权威判断但权威没有回答。
    AuthorityUnavailable { detail: String },
    /// 权威判断超过了 requirement 允许的年龄(max_age_secs 或 valid_until)。
    AuthorityCheckTooOld {
        checked_at: u64,
        limit: String,
    },
}

impl std::fmt::Display for FreshnessPolicyError {
    /// `Display` 走 `Debug`:policy 错误面向日志与上游分支判断。
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for FreshnessPolicyError {}

/// 对 verify 结果的 freshness 事实应用 requirement。
pub fn evaluate_freshness(
    verified: &VerifiedDidDocument,
    requirement: &FreshnessRequirement,
) -> Result<(), FreshnessPolicyError> {
    match requirement {
        FreshnessRequirement::AnyValid => Ok(()),
        FreshnessRequirement::NotOlderThanLocalLatest { scope } => {
            check_not_older(&verified.freshness.local, scope)
        }
        FreshnessRequirement::RequireAuthorityCurrent { max_age_secs } => {
            check_authority_current(&verified.freshness.authority, *max_age_secs)
        }
        FreshnessRequirement::NotOlderAndAuthorityCurrent {
            scope,
            max_age_secs,
        } => {
            check_not_older(&verified.freshness.local, scope)?;
            check_authority_current(&verified.freshness.authority, *max_age_secs)
        }
    }
}

fn check_not_older(
    local: &LocalFreshness,
    requested: &LocalTrustScope,
) -> Result<(), FreshnessPolicyError> {
    let actual = match local {
        LocalFreshness::Unknown { scope, .. }
        | LocalFreshness::FirstKnown { scope, .. }
        | LocalFreshness::SameAsLatestKnown { scope, .. }
        | LocalFreshness::NewerThanLatestKnown { scope, .. }
        | LocalFreshness::OlderThanLatestKnown { scope, .. }
        | LocalFreshness::ConflictAtSameRevision { scope, .. } => scope.clone(),
    };
    if actual != *requested {
        return Err(FreshnessPolicyError::LocalBaselineUnknown {
            requested: requested.clone(),
            actual,
            reason: "freshness was evaluated against a different scope".to_string(),
        });
    }
    match local {
        LocalFreshness::Unknown { scope, reason } => {
            Err(FreshnessPolicyError::LocalBaselineUnknown {
                requested: requested.clone(),
                actual: scope.clone(),
                reason: reason.clone(),
            })
        }
        LocalFreshness::OlderThanLatestKnown {
            scope,
            candidate,
            latest,
        } => Err(FreshnessPolicyError::OlderThanLocalLatest {
            scope: scope.clone(),
            candidate: candidate.clone(),
            latest: latest.clone(),
        }),
        LocalFreshness::ConflictAtSameRevision {
            scope,
            expected,
            candidate,
        } => Err(FreshnessPolicyError::ConflictAtSameRevision {
            scope: scope.clone(),
            expected: expected.clone(),
            candidate: candidate.clone(),
        }),
        LocalFreshness::FirstKnown { .. }
        | LocalFreshness::SameAsLatestKnown { .. }
        | LocalFreshness::NewerThanLatestKnown { .. } => Ok(()),
    }
}

fn check_authority_current(
    authority: &AuthorityFreshness,
    max_age_secs: Option<u64>,
) -> Result<(), FreshnessPolicyError> {
    match authority {
        AuthorityFreshness::Current {
            checked_at,
            valid_until,
            ..
        } => {
            let now = buckyos_get_unix_timestamp();
            if let Some(valid_until) = valid_until {
                if now > *valid_until {
                    return Err(FreshnessPolicyError::AuthorityCheckTooOld {
                        checked_at: *checked_at,
                        limit: format!("validUntil {}", valid_until),
                    });
                }
            }
            if let Some(max_age) = max_age_secs {
                if now.saturating_sub(*checked_at) > max_age {
                    return Err(FreshnessPolicyError::AuthorityCheckTooOld {
                        checked_at: *checked_at,
                        limit: format!("max_age_secs {}", max_age),
                    });
                }
            }
            Ok(())
        }
        AuthorityFreshness::NotChecked => Err(FreshnessPolicyError::AuthorityNotChecked {
            detail: "no authority remote resolve was performed in this flow".to_string(),
        }),
        AuthorityFreshness::ActiveUnanchored { source, .. } => {
            Err(FreshnessPolicyError::AuthorityNotChecked {
                detail: format!(
                    "authority {} answered Active without binding the candidate \
                     (no doc hash/body/document_iat anchor)",
                    source
                ),
            })
        }
        AuthorityFreshness::NotCurrent {
            reason,
            current_document_iat,
            ..
        } => Err(FreshnessPolicyError::AuthorityNotCurrent {
            reason: reason.clone(),
            current_document_iat: *current_document_iat,
        }),
        AuthorityFreshness::Unavailable { detail, .. } => {
            Err(FreshnessPolicyError::AuthorityUnavailable {
                detail: detail.clone(),
            })
        }
    }
}

// ------------------------ 纯 verifier ------------------------

/// 验证调用方给出的确切文档:同步、无网络、无写入,只消费 snapshot。
///
/// 完成:`doc.id == expected_did`、doc type 一致、expected owner 确定与
/// declared owner 一致性、owner key/历史 key 验签、`exp` 有效期、`valid_iat`
/// owner replay guard(`mini_version_seq` 已退役),并根据 snapshot 返回本地
/// freshness 和 authority freshness 事实。
///
/// 缺少完成**有效性**验证所必需的材料时返回
/// [`VerifyError::MissingDependency`];缺少 authority-current 证明但密码学/
/// owner 验证已完成**不是**错误(那是 [`AuthorityFreshness`] 事实)。
pub fn verify_did_document(
    expected_did: &DID,
    doc_type: DidDocType,
    candidate: &EncodedDocument,
    context: &VerifyContextSnapshot,
    options: VerifyOptions,
) -> Result<VerifiedDidDocument, VerifyError> {
    // 硬门禁:key 类 DID 不是名字系统入口。
    if is_key_class_method(&expected_did.method) {
        return Err(VerifyError::InvalidDocument {
            detail: format!(
                "key-class DID {} cannot be a DID Document subject",
                expected_did.to_string()
            ),
        });
    }

    // ---- 1. 归一化解析候选(不信任,只提取字段)----
    let parsed = parse_did_doc(candidate.clone()).map_err(|err| VerifyError::InvalidDocument {
        detail: format!("not a recognizable DID Document: {}", err),
    })?;
    if parsed.get_id() != *expected_did {
        return Err(VerifyError::DocumentIdMismatch {
            expected: expected_did.clone(),
            actual: parsed.get_id(),
        });
    }
    if parsed.get_doc_type() != doc_type {
        return Err(VerifyError::InvalidDocument {
            detail: format!(
                "document body is a {} document, requested doc_type is {}",
                parsed.get_doc_type(),
                doc_type
            ),
        });
    }
    let declared_owner = match parsed.get_iss() {
        None => None,
        Some(iss) => Some(
            DID::from_str(&iss).map_err(|err| VerifyError::InvalidDocument {
                detail: format!("declared owner {} is not a valid DID: {}", iss, err),
            })?,
        ),
    };

    // ---- 2. revision(iat + content hash):iat 推不出的文档无效 ----
    let revision = DocumentRevision::of(candidate).ok_or_else(|| VerifyError::InvalidDocument {
        detail: "document carries neither iat nor exp; revision iat cannot be derived".to_string(),
    })?;

    // ---- 3. 自过期归 validity 失败,不混入 freshness ----
    let now = buckyos_get_unix_timestamp();
    if let Some(exp) = parsed.get_exp() {
        if exp <= now {
            return Err(VerifyError::InvalidDocument {
                detail: format!("document self-expired at {} (now {})", exp, now),
            });
        }
    }

    // ---- 4. terminal 负状态硬失败(负状态屏蔽一切兜底)----
    if let Some(negative) = context.negative_state.as_ref() {
        if negative.status.is_terminal() {
            return Err(VerifyError::RejectedByNegativeState {
                scope: negative.scope.clone(),
                status: negative.status.clone(),
            });
        }
    }
    if let SnapshotAuthorityState::Receipt(receipt) = &context.authority {
        if receipt.status.is_terminal() {
            return Err(VerifyError::RejectedByNegativeState {
                scope: context.scope.clone(),
                status: receipt.status.clone(),
            });
        }
    }

    // ---- 5. 权威 freshness 事实与 membership 判定 ----
    let (authority_freshness, membership_proven, authority_status) =
        authority_facts(&context.authority, candidate, &revision);

    // ---- 6. expected_owner:权威/Zone 绑定 .or 结构规则,绝不来自 payload ----
    let structural = structural_owner(expected_did);
    let binding = context.owner_binding.as_ref();
    let expected_owner = binding
        .map(|binding| binding.owner.clone())
        .or_else(|| structural.clone());
    let expected_owner_source = if binding.is_some() {
        binding.map(|binding| binding.source)
    } else if structural.is_some() {
        Some(EvidenceSource::StructuralRule)
    } else {
        None
    };

    let detached = matches!(
        (structural.as_ref(), binding.map(|binding| &binding.owner)),
        (Some(structural), Some(authority)) if structural != authority
    );
    if options.purpose == VerifyPurpose::AuthSubject {
        if detached {
            return Err(VerifyError::DetachedOwnerRejected {
                structural: structural.clone().unwrap(),
                authority: binding.map(|binding| binding.owner.clone()).unwrap(),
            });
        }
        if expected_owner.is_none() {
            // 权威已回答(或没有权威渠道)且仍无绑定:确定性缺失;
            // 权威没被问到/没回答:是缺依赖,resolve 可能补上绑定。
            match &context.authority {
                SnapshotAuthorityState::Receipt(_) | SnapshotAuthorityState::NoChannel => {
                    return Err(VerifyError::OwnerBindingUnavailable {
                        detail: format!(
                            "no authority owner binding and no structural owner for {}#{}; \
                             a first-level name needs an authority binding to be a subject",
                            expected_did.to_string(),
                            doc_type
                        ),
                    });
                }
                SnapshotAuthorityState::NotConsulted | SnapshotAuthorityState::Unreachable { .. } => {
                    return Err(VerifyError::MissingDependency {
                        dependencies: vec![VerifyDependency::OwnerBinding {
                            did: expected_did.clone(),
                            doc_type,
                        }],
                    });
                }
            }
        }
    }

    // ---- 7. 有效性验证:owner 验签或 membership ----
    let mut warnings: Vec<VerifyWarning> = Vec::new();
    let mut used_historical_key = false;
    let mut owner_replay_guard_applied = false;
    let mut owner_document_source: Option<EvidenceSource> = None;
    let encoded = candidate.to_string();

    if doc_type == DidDocType::Owner {
        // 递归基:OwnerDocument 不能自己给自己作保,可信性只能来自权威
        // membership;文档自带 key 的自签校验只做完整性自检。
        if !membership_proven {
            return Err(owner_membership_gap(expected_did, &doc_type, &context.authority));
        }
        if !candidate.is_proof() {
            return Err(VerifyError::SignatureRejected {
                detail: "owner document candidate is not a signed JWT; \
                         self-signature cannot be verified"
                    .to_string(),
            });
        }
        let Some((self_key, _jwk)) = parsed.get_auth_key(None) else {
            return Err(VerifyError::InvalidDocument {
                detail: "owner document has no usable auth key".to_string(),
            });
        };
        if let Err(err) = decode_json_from_jwt_with_pk(&encoded, &self_key) {
            return Err(VerifyError::SignatureRejected {
                detail: format!("owner document self-signature verification failed: {}", err),
            });
        }
    } else if let Some(expected) = expected_owner.as_ref() {
        // declared_owner 一致性:自声明 owner 必须等于 expected_owner。
        match declared_owner.as_ref() {
            None => {
                return Err(VerifyError::OwnerMismatch {
                    expected: expected.clone(),
                    declared: None,
                });
            }
            Some(declared) if declared != expected => {
                return Err(VerifyError::OwnerMismatch {
                    expected: expected.clone(),
                    declared: Some(declared.clone()),
                });
            }
            _ => {}
        }

        if !candidate.is_proof() {
            return Err(VerifyError::SignatureRejected {
                detail: format!(
                    "{}#{} candidate is not a signed JWT; owner signature cannot be verified",
                    expected_did.to_string(),
                    doc_type
                ),
            });
        }

        // snapshot 必须携带 expected_owner 的 OwnerDocument;缺材料是结构化
        // MissingDependency,由调用方决定是否 resolve。
        let Some(material) = context.owner_material.as_ref() else {
            return Err(VerifyError::MissingDependency {
                dependencies: vec![VerifyDependency::OwnerDocument {
                    owner: expected.clone(),
                }],
            });
        };
        if material.owner != *expected {
            return Err(VerifyError::MissingDependency {
                dependencies: vec![VerifyDependency::OwnerDocument {
                    owner: expected.clone(),
                }],
            });
        }
        let owner_document =
            OwnerDocument::decode(&material.document, None).map_err(|_err| {
                VerifyError::MissingDependency {
                    dependencies: vec![VerifyDependency::OwnerDocument {
                        owner: expected.clone(),
                    }],
                }
            })?;
        owner_document_source = Some(material.source);

        // owner replay guard:valid_iat(anti-rollback)。
        owner_document
            .validate_jwt_revocation(doc_type.as_str(), candidate)
            .map_err(|err| VerifyError::RevokedByOwnerPolicy {
                detail: err.to_string(),
            })?;
        owner_replay_guard_applied = true;

        // 用 owner 默认 key 验签,失败后尝试历史 key。
        let Some((decoding_key, _jwk)) = owner_document.get_auth_key(None) else {
            return Err(VerifyError::MissingDependency {
                dependencies: vec![VerifyDependency::OwnerDocument {
                    owner: expected.clone(),
                }],
            });
        };
        if decode_json_from_jwt_with_pk(&encoded, &decoding_key).is_err() {
            let verified_with_historical_key = owner_document
                .get_historical_keys()
                .into_iter()
                .any(|(_kid, jwk)| match DecodingKey::from_jwk(&jwk) {
                    Ok(historical_key) => {
                        decode_json_from_jwt_with_pk(&encoded, &historical_key).is_ok()
                    }
                    Err(_) => false,
                });
            if !verified_with_historical_key {
                return Err(VerifyError::SignatureRejected {
                    detail: format!(
                        "{}#{} signature verification failed against owner {}",
                        expected_did.to_string(),
                        doc_type,
                        expected.to_string()
                    ),
                });
            }
            used_historical_key = true;
            warnings.push(ResolveWarning::SignedByHistoricalKey);
        }
    } else {
        // expected_owner 推不出(只有 ObjectDocument 能走到):只有权威信道已
        // 证明候选就是当前 body 时,才能返回"非授权主体"结果。
        if !membership_proven {
            match &context.authority {
                SnapshotAuthorityState::Receipt(_) | SnapshotAuthorityState::NoChannel => {
                    return Err(VerifyError::OwnerBindingUnavailable {
                        detail: format!(
                            "no owner binding, no structural owner, and no current-publication \
                             membership proof for {}#{}",
                            expected_did.to_string(),
                            doc_type
                        ),
                    });
                }
                SnapshotAuthorityState::NotConsulted | SnapshotAuthorityState::Unreachable { .. } => {
                    return Err(VerifyError::MissingDependency {
                        dependencies: vec![VerifyDependency::AuthorityMembership {
                            did: expected_did.clone(),
                            doc_type,
                        }],
                    });
                }
            }
        }
    }

    // ---- 8. 本地已知 freshness ----
    let local_freshness = local_facts(&context.baseline, &context.scope, &revision);

    let usable_as_authz_subject =
        options.purpose == VerifyPurpose::AuthSubject && expected_owner.is_some();
    let authz_owner = if usable_as_authz_subject {
        expected_owner.clone()
    } else {
        None
    };

    Ok(VerifiedDidDocument {
        subject_did: expected_did.clone(),
        doc_type,
        document: candidate.clone(),
        structural_owner: structural,
        authority_owner: binding.map(|binding| binding.owner.clone()),
        expected_owner,
        declared_owner,
        authz_owner,
        usable_as_authz_subject,
        revision,
        validity: ValidityEvidence {
            scope: context.scope.clone(),
            snapshot_generation: context.generation,
            checked_at: context.checked_at,
            valid_until: context.valid_until,
            expected_owner_source,
            owner_document_source,
            used_historical_key,
            owner_replay_guard_applied,
            authority_status,
            scope_negative_status: context.scope_negative.clone(),
            membership_proven,
            detached_owner: detached,
        },
        freshness: FreshnessEvidence {
            local: local_freshness,
            authority: authority_freshness,
        },
        warnings,
    })
}

/// Owner 递归基缺 membership 证明时的错误分类:权威已答(Active 无锚点)或无
/// 权威渠道 → 依赖仍然缺失(需要锚定的 membership 证明);没问到/没答上 →
/// 同样是 MissingDependency。统一为结构化缺依赖,调用方可显式 resolve 重试;
/// promote 层会结合 receipt 情况决定删除还是保留候选。
fn owner_membership_gap(
    did: &DID,
    doc_type: &DidDocType,
    _authority: &SnapshotAuthorityState,
) -> VerifyError {
    VerifyError::MissingDependency {
        dependencies: vec![VerifyDependency::AuthorityMembership {
            did: did.clone(),
            doc_type: doc_type.clone(),
        }],
    }
}

/// 权威信道给出的当前 body 与候选是否为同一份文档:编码原文一致,或(权威
/// 内联 JsonLd 时)payload 内容一致。内容一致即视为发布集合成员;普通文档随后
/// 仍要走 owner 验签,签名伪造在验签步骤被拒。
fn same_document(authority_body: &EncodedDocument, external: &EncodedDocument) -> bool {
    if authority_body == external {
        return true;
    }
    match (
        authority_body.clone().to_json_value(),
        external.clone().to_json_value(),
    ) {
        (Ok(authority_value), Ok(external_value)) => authority_value == external_value,
        _ => false,
    }
}

/// 从权威状态推导 authority freshness、membership 与原始回答状态。
fn authority_facts(
    authority: &SnapshotAuthorityState,
    candidate: &EncodedDocument,
    revision: &DocumentRevision,
) -> (AuthorityFreshness, bool, Option<DocumentStatus>) {
    match authority {
        SnapshotAuthorityState::NotConsulted | SnapshotAuthorityState::NoChannel => {
            (AuthorityFreshness::NotChecked, false, None)
        }
        SnapshotAuthorityState::Unreachable {
            attempted_at,
            source,
            detail,
        } => (
            AuthorityFreshness::Unavailable {
                attempted_at: *attempted_at,
                source: source.clone(),
                detail: detail.clone(),
            },
            false,
            None,
        ),
        SnapshotAuthorityState::Receipt(receipt) => {
            let status = Some(receipt.status.clone());
            match &receipt.status {
                // terminal 状态已在 verify 主流程硬失败,这里不会出现;
                // 防御性归入 NotCurrent(NegativeStatus)。
                DocumentStatus::Revoked | DocumentStatus::Tombstoned => (
                    not_current(receipt, AuthorityNotCurrentReason::NegativeStatus(
                        receipt.status.clone(),
                    )),
                    false,
                    status,
                ),
                DocumentStatus::Missing | DocumentStatus::Expired | DocumentStatus::Migrated => (
                    not_current(receipt, AuthorityNotCurrentReason::NegativeStatus(
                        receipt.status.clone(),
                    )),
                    false,
                    status,
                ),
                DocumentStatus::Active => {
                    // 候选 hash/body 绑定成立 → Current。
                    let hash_match = receipt
                        .doc_hash
                        .as_deref()
                        .map(|hash| content_hash_matches(hash, candidate));
                    let body_match = receipt
                        .current_body
                        .as_ref()
                        .map(|body| same_document(body, candidate));
                    if hash_match == Some(true) || (hash_match.is_none() && body_match == Some(true))
                    {
                        return (
                            AuthorityFreshness::Current {
                                authority_seq: receipt.authority_seq,
                                document_iat: receipt.document_iat.or(receipt
                                    .current_body
                                    .as_ref()
                                    .and_then(document_iat)),
                                checked_at: receipt.checked_at,
                                valid_until: receipt.valid_until,
                                source: receipt.source.clone(),
                            },
                            true,
                            status,
                        );
                    }
                    // 锚点存在但不匹配 → 明确不是当前版本。
                    if hash_match == Some(false) || body_match == Some(false) {
                        let current_iat = receipt.document_iat.or(receipt
                            .current_body
                            .as_ref()
                            .and_then(document_iat));
                        let reason = match current_iat {
                            Some(current) if revision.iat < current => {
                                AuthorityNotCurrentReason::Superseded
                            }
                            _ => AuthorityNotCurrentReason::DifferentDocument,
                        };
                        return (
                            AuthorityFreshness::NotCurrent {
                                reason,
                                authority_seq: receipt.authority_seq,
                                current_document_iat: current_iat,
                                checked_at: receipt.checked_at,
                                source: receipt.source.clone(),
                            },
                            false,
                            status,
                        );
                    }
                    // 无 hash/body 锚点:document_iat 仍可判定 Superseded。
                    if let Some(current) = receipt.document_iat {
                        if revision.iat < current {
                            return (
                                AuthorityFreshness::NotCurrent {
                                    reason: AuthorityNotCurrentReason::Superseded,
                                    authority_seq: receipt.authority_seq,
                                    current_document_iat: Some(current),
                                    checked_at: receipt.checked_at,
                                    source: receipt.source.clone(),
                                },
                                false,
                                status,
                            );
                        }
                    }
                    // 权威 Active 但没有可绑定候选的锚点。
                    (
                        AuthorityFreshness::ActiveUnanchored {
                            authority_seq: receipt.authority_seq,
                            checked_at: receipt.checked_at,
                            source: receipt.source.clone(),
                        },
                        false,
                        status,
                    )
                }
            }
        }
    }
}

fn not_current(
    receipt: &AuthorityReceipt,
    reason: AuthorityNotCurrentReason,
) -> AuthorityFreshness {
    AuthorityFreshness::NotCurrent {
        reason,
        authority_seq: receipt.authority_seq,
        current_document_iat: receipt.document_iat,
        checked_at: receipt.checked_at,
        source: receipt.source.clone(),
    }
}

/// 本地已知 freshness:候选 revision 与主 scope 基线的关系。
/// 比较规则(已确认):content hash 相同 → 同一份文档;iat 不同以 iat 决定
/// 新旧;同 iat 不同 hash → 稳定 conflict,不悄悄选一个。
fn local_facts(
    baseline: &SnapshotBaseline,
    scope: &LocalTrustScope,
    revision: &DocumentRevision,
) -> LocalFreshness {
    match baseline {
        SnapshotBaseline::Unavailable { reason } => LocalFreshness::Unknown {
            scope: scope.clone(),
            reason: reason.clone(),
        },
        SnapshotBaseline::Empty => LocalFreshness::FirstKnown {
            scope: scope.clone(),
            candidate: revision.clone(),
        },
        SnapshotBaseline::Known(latest) => {
            if latest.content_hash == revision.content_hash {
                LocalFreshness::SameAsLatestKnown {
                    scope: scope.clone(),
                    revision: revision.clone(),
                }
            } else if revision.iat > latest.iat {
                LocalFreshness::NewerThanLatestKnown {
                    scope: scope.clone(),
                    candidate: revision.clone(),
                    previous: latest.clone(),
                }
            } else if revision.iat < latest.iat {
                LocalFreshness::OlderThanLatestKnown {
                    scope: scope.clone(),
                    candidate: revision.clone(),
                    latest: latest.clone(),
                }
            } else {
                LocalFreshness::ConflictAtSameRevision {
                    scope: scope.clone(),
                    expected: latest.clone(),
                    candidate: revision.clone(),
                }
            }
        }
    }
}
