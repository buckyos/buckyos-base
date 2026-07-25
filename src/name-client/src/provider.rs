use buckyos_kit::buckyos_get_unix_timestamp;
use jsonwebtoken::DecodingKey;
use name_lib::OwnerDocument;
use name_lib::*;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
    sync::{Arc, RwLock},
};

pub use name_lib::{DidDocType, DEFAULT_DID_DOC_TYPE, DOC_TYPE_INFO, DOC_TYPE_OWNER};

/// key 类 DID(did:key / did:dev)不是 `resolve_did` 的合法入参(简化文档第 6 节):
/// 解析的目的是"通过逻辑名字得到当前可信的公钥",而 key 类 DID 的名字就是公钥本身,
/// 解析它没有意义。key 只作为文档内容里的 key 材料和系统内部唯一性标识存在。
pub fn is_key_class_method(method: &str) -> bool {
    matches!(method, "key" | "dev")
}

/// 名字结构推导出的默认 owner(简化文档 2.4 节):二级名字天然自带 owner 假设,
/// `did:bns:app1.alice` 的 expected_owner 就是 `did:bns:alice`——即名字层级
/// 上的上级名字(`DID::upper_did`)。一级名字是根,从结构推不出 owner,绑定
/// 只能来自权威源。其它 method(如 did:web)有名字层级但不定义结构 owner。
pub fn structural_owner(did: &DID) -> Option<DID> {
    match did.method.as_str() {
        "bns" => did.upper_did(),
        _ => None,
    }
}

/// 计算文档 body 的内容哈希(权威源锚定 `doc_hash` 时用来做成员判断,
/// `DocumentRevision::content_hash` 同一契约)。
///
/// 编码契约(doc/verify-did-api-boundary-and-freshness-TODO.md,已确认):
/// - JWT:对 compact artifact **原文**做 sha256;
/// - JsonLd:对 `serde_json::Value` 重序列化结果做 sha256。workspace 不启用
///   serde_json 的 `preserve_order`,`Value` 的 map 是 BTreeMap,序列化天然是
///   "键字典序 + 紧凑分隔符",已消除键序/空白差异(有防护测试锁定该前提);
///   不引入 JCS(RFC 8785)/URDNA2015。
pub fn document_content_hash(doc: &EncodedDocument) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(doc.to_string().as_bytes());
    format!("{:x}", hasher.finalize())
}

/// 文档的 revision `iat`:`iat` 直接存在,或由 `exp - DEFAULT_EXPIRE_TIME`
/// 补充推导(既有 `get_doc_iat` 语义,现为 revision 契约的唯一时间轴)。
/// 两者皆无、无法得出 iat 的文档没有 revision(verify 家族按 InvalidDocument 拒绝)。
pub fn document_iat(doc: &EncodedDocument) -> Option<u64> {
    let value = doc.clone().to_json_value().ok()?;
    if let Some(iat) = value.get("iat").and_then(|ts| ts.as_u64()) {
        return Some(iat);
    }
    value
        .get("exp")
        .and_then(|ts| ts.as_u64())
        .map(|exp| exp.saturating_sub(name_lib::DEFAULT_EXPIRE_TIME))
}

/// 权威源锚定的 hash 与 body 是否匹配。允许 `sha256:` 前缀,大小写不敏感。
pub fn content_hash_matches(expected: &str, doc: &EncodedDocument) -> bool {
    let expected = expected
        .strip_prefix("sha256:")
        .unwrap_or(expected)
        .to_ascii_lowercase();
    document_content_hash(doc) == expected
}

/// 发布状态:权威源对"什么被发布过"的记忆(简化文档第 6 节)。
/// `Missing / Revoked / Tombstoned / Active` 都是权威源给出的**回答**(DR),
/// 与"没有得到回答"(unknown)严格区分。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DocumentStatus {
    Missing,
    Active,
    Revoked,
    Expired,
    Migrated,
    Tombstoned,
}

impl Default for DocumentStatus {
    fn default() -> Self {
        Self::Active
    }
}

impl DocumentStatus {
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Revoked | Self::Tombstoned)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DocumentRef {
    pub uri: Option<String>,
    pub content_hash: Option<String>,
    pub inline_document: Option<EncodedDocument>,
}

impl DocumentRef {
    pub fn inline(document: EncodedDocument) -> Self {
        Self {
            uri: None,
            content_hash: None,
            inline_document: Some(document),
        }
    }
}

/// 权威源对 (did, doc_type) 的完整回答。只保留当前有真实生产者/消费者的字段
/// (简化 TODO T2.1)。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublishedState {
    pub did: DID,
    pub doc_type: String,
    pub document_status: DocumentStatus,
    pub document_ref: Option<DocumentRef>,
    /// 权威记录的"文档版本"= 当前发布文档的 iat(wire `documentVersion` 的统一
    /// 语义,documentVersion = document_iat)。权威侧不引入独立版本序号,吊销/
    /// 替换语义与 owner 侧 `valid_iat` 统一在同一条 iat 轴上:候选 iat 小于它
    /// 即 `Superseded`。
    pub document_version: Option<u64>,
    /// 权威源记录的 owner 绑定。owner 变更/委托只能通过这里生效,
    /// 候选文档自声明的 owner 说了不算(简化文档 2.4 节)。
    pub effective_owner: Option<DID>,
    /// 权威源自身的变更序号(owner binding 变更等),与文档 revision 无关。
    pub authority_seq: Option<u64>,
    pub migration_target: Option<DID>,
    /// 该条目最近一次经权威源确认/写入控制面的时刻(wire `checkedAt`)。
    /// 本机直连权威源时由客户端在收到回答时补记;Zone 控制面转述时来自 wire。
    #[serde(default)]
    pub checked_at: Option<u64>,
    /// 该回答允许消费方视为新鲜的截止时刻(wire `validUntil`);None 表示
    /// 来源没有声明,由调用方 freshness policy 自行限制检查年龄。
    #[serde(default)]
    pub valid_until: Option<u64>,
}

impl PublishedState {
    pub fn active(did: DID, doc_type: String, document: EncodedDocument) -> Self {
        Self {
            did,
            doc_type,
            document_status: DocumentStatus::Active,
            document_ref: Some(DocumentRef::inline(document)),
            document_version: None,
            effective_owner: None,
            authority_seq: None,
            migration_target: None,
            checked_at: None,
            valid_until: None,
        }
    }

    pub fn missing(did: DID, doc_type: String) -> Self {
        Self {
            did,
            doc_type,
            document_status: DocumentStatus::Missing,
            document_ref: None,
            document_version: None,
            effective_owner: None,
            authority_seq: None,
            migration_target: None,
            checked_at: None,
            valid_until: None,
        }
    }
}

/// 文档 body 的证据等级,按**取回信道**和 doc_type 契约打标,永远不看 body 长相
/// (简化文档 2.3 节)。resolver 主流程只认这三档。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BodyEvidence {
    /// 已发布/已锚定:从权威信道取回,need_proof = false。
    Anchored,
    /// 候选文档:从补充信道取回,需要 expected_owner + owner 验签。
    NeedProof,
    /// 免验证的 Info 类:按 method 契约事先声明,不验证、只进入 UnauthenticatedInfoCache。
    UnproofInfo,
}

impl BodyEvidence {
    pub fn as_str(&self) -> &'static str {
        match self {
            BodyEvidence::Anchored => "Anchored",
            BodyEvidence::NeedProof => "NeedProof",
            BodyEvidence::UnproofInfo => "UnproofInfo",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredDocument {
    pub did: DID,
    pub doc_type: Option<DidDocType>,
    pub document: EncodedDocument,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentBody {
    pub document: EncodedDocument,
    pub evidence: BodyEvidence,
    pub resolver_id: Option<String>,
    pub retrieved: Option<u64>,
    #[serde(default)]
    pub discovered_documents: Vec<DiscoveredDocument>,
}

impl DocumentBody {
    pub fn anchored(document: EncodedDocument, resolver_id: Option<String>) -> Self {
        Self::with_evidence(document, BodyEvidence::Anchored, resolver_id)
    }

    pub fn need_proof(document: EncodedDocument, resolver_id: Option<String>) -> Self {
        Self::with_evidence(document, BodyEvidence::NeedProof, resolver_id)
    }

    pub fn unproof_info(document: EncodedDocument, resolver_id: Option<String>) -> Self {
        Self::with_evidence(document, BodyEvidence::UnproofInfo, resolver_id)
    }

    pub(crate) fn with_evidence(
        document: EncodedDocument,
        evidence: BodyEvidence,
        resolver_id: Option<String>,
    ) -> Self {
        Self {
            document,
            evidence,
            resolver_id,
            retrieved: Some(buckyos_get_unix_timestamp()),
            discovered_documents: Vec::new(),
        }
    }

    pub fn with_discovered_documents(
        mut self,
        discovered_documents: Vec<DiscoveredDocument>,
    ) -> Self {
        self.discovered_documents = discovered_documents;
        self
    }
}

/// provider 的归一化回答(简化 TODO T1.1)。`status / owner_binding / doc_hash /
/// migration_target` 只有权威源能填;补充源永远只返回候选 body。
#[derive(Debug, Clone, Default)]
pub struct ProviderAnswer {
    pub status: Option<DocumentStatus>,
    pub owner_binding: Option<DID>,
    pub doc_hash: Option<String>,
    pub migration_target: Option<DID>,
    pub body: Option<DocumentBody>,
    /// 权威源的完整发布状态,只用于结果元数据透传(document_version 等),
    /// 主循环的门禁只看上面的归一化字段。
    pub published: Option<PublishedState>,
}

/// 结果二分法(简化文档 2.1 节):DR = 得到了回答(发布状态是回答的一部分),
/// Unknown = 没有得到回答(断网、超时)。界线是"有没有得到回答",
/// 不是"有没有拿到文档"——Missing 是回答,不是 unknown。
#[derive(Debug)]
pub enum ProviderResolveResult {
    Dr(ProviderAnswer),
    Unknown(NSError),
}

/// 补充源的调用范围。`CurrentZoneBootstrap` 专门用于 DNS TXT 这类只在本机
/// Zone 自举时安全的发现信道:是否允许访问由每次 resolve 的
/// `ResolvePolicy::current_zone_did` 决定,而不是由 provider 自行判断。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupplementScope {
    Always,
    CurrentZoneBootstrap,
}

/// 一个带调用范围的补充源注册项。补充源顺序仍然是显式的 first-win 顺序;
/// scope 只决定当前请求是否跳过该项,不会改变其它补充源的相对顺序。
pub struct RegisteredSupplement {
    pub provider: Box<dyn NsProvider>,
    pub scope: SupplementScope,
}

impl RegisteredSupplement {
    pub fn always(provider: Box<dyn NsProvider>) -> Self {
        Self {
            provider,
            scope: SupplementScope::Always,
        }
    }

    pub fn current_zone_bootstrap(provider: Box<dyn NsProvider>) -> Self {
        Self {
            provider,
            scope: SupplementScope::CurrentZoneBootstrap,
        }
    }

    pub fn is_enabled(&self, did: &DID, policy: &ResolvePolicy) -> bool {
        match self.scope {
            SupplementScope::Always => true,
            SupplementScope::CurrentZoneBootstrap => policy.current_zone_did.as_ref() == Some(did),
        }
    }
}

/// 一个 DID method 的解析注册模型(简化 TODO T2.2):至多一个权威发布渠道 +
/// 显式有序的少数补充源(first-win)。免验证 doc_type 是 method 契约,
/// 不由 provider 运行时协商。
pub struct MethodProviders {
    pub authority: Option<Box<dyn NsProvider>>,
    pub supplements: Vec<RegisteredSupplement>,
    pub no_proof_doc_types: HashSet<DidDocType>,
}

impl MethodProviders {
    pub fn new() -> Self {
        let mut no_proof_doc_types = HashSet::new();
        no_proof_doc_types.insert(DidDocType::Info);
        Self {
            authority: None,
            supplements: Vec::new(),
            no_proof_doc_types,
        }
    }
}

impl Default for MethodProviders {
    fn default() -> Self {
        Self::new()
    }
}

/// 同一权威发布渠道的多个委托读取端(镜像、网关、不同传输),first-win 合并成
/// 一个权威 provider。简化文档 2.2 节:唯一的是"发布渠道",不是"能读到权威数据
/// 的节点数"。Missing 只有在所有读取端都一致回答"没有"时才成立;任何一个读取端
/// 传输失败而其余读取端又给不出 DR 时,整体是 unknown——宁可少回答,不能把
/// "断网"伪装成"从未发布"。
pub struct AuthorityReaders {
    id: String,
    readers: Vec<Box<dyn NsProvider>>,
}

impl AuthorityReaders {
    pub fn new(id: impl Into<String>, readers: Vec<Box<dyn NsProvider>>) -> Self {
        Self {
            id: id.into(),
            readers,
        }
    }
}

#[async_trait::async_trait]
impl NsProvider for AuthorityReaders {
    fn get_id(&self) -> String {
        self.id.clone()
    }

    async fn query(
        &self,
        name: &str,
        record_type: Option<RecordType>,
        from_ip: Option<IpAddr>,
    ) -> NSResult<NameInfo> {
        for reader in &self.readers {
            if let Ok(info) = reader.query(name, record_type, from_ip).await {
                return Ok(info);
            }
        }
        Err(NSError::NotFound(name.to_string()))
    }

    async fn query_did(
        &self,
        did: &DID,
        doc_type: Option<DidDocType>,
        from_ip: Option<IpAddr>,
    ) -> NSResult<EncodedDocument> {
        let mut unknown: Option<NSError> = None;
        let mut not_found: Option<NSError> = None;
        for reader in &self.readers {
            match reader.query_did(did, doc_type.clone(), from_ip).await {
                Ok(doc) => return Ok(doc),
                Err(NSError::Disabled(msg)) => return Err(NSError::Disabled(msg)),
                Err(NSError::NotFound(msg)) => not_found = Some(NSError::NotFound(msg)),
                Err(err) => {
                    if unknown.is_none() {
                        unknown = Some(err);
                    }
                }
            }
        }
        if let Some(err) = unknown {
            return Err(err);
        }
        Err(not_found.unwrap_or_else(|| NSError::NotFound(did.to_string())))
    }

    async fn resolve_published_state(
        &self,
        did: &DID,
        doc_type: &DidDocType,
    ) -> NSResult<Option<PublishedState>> {
        let mut unknown: Option<NSError> = None;
        for reader in &self.readers {
            match reader.resolve_published_state(did, doc_type).await {
                Ok(Some(state)) => return Ok(Some(state)),
                Ok(None) => {}
                Err(NSError::Disabled(msg)) => return Err(NSError::Disabled(msg)),
                Err(err) => {
                    if unknown.is_none() {
                        unknown = Some(err);
                    }
                }
            }
        }
        if let Some(err) = unknown {
            return Err(err);
        }
        Ok(None)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResolveWarning {
    LocalAuthorityOverride,
    UnauthenticatedInfoCache,
    EvidenceContractViolation {
        evidence: String,
        reason: String,
    },
    /// 候选文档自声明的 owner 与 expected_owner 不一致:强攻击信号(owner 冒充,
    /// 或未经权威源发布的 owner 变更),候选作废并打警告(简化文档 2.4 节)。
    OwnerMismatch {
        declared: String,
        expected: String,
    },
    SignedByHistoricalKey,
    CacheFallback,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CacheStatus {
    Disabled,
    Miss,
    Hit,
    Refresh,
    Fallback,
    UnauthenticatedInfoHit,
    /// Zone Resolver(cluster-level L1 cache)明确命中的结果(简化文档第 3 节
    /// 第 0 步)。与本机 cache 的 `Hit` 和 method authority 的 `Miss/Refresh`
    /// 相区分;Zone unknown 会继续落回本机 cache,不会返回 `ZoneHit`。
    ZoneHit,
    /// 宽松模式下返回的 `Unverified` 观察缓存(doc/update-did-cache.md):
    /// lazy verify 因条件不可用没能完成,策略显式允许打标露面。strict 解析
    /// 永远不会产出这个状态。
    ObservedFallback,
}

/// lazy verify 的结果性质(doc/update-did-cache.md"resolve_did_ex 新增
/// metadata 字段")。只在 cache 命中路径上有意义;主循环产出的新鲜结果为 None。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerificationStatus {
    /// 已通过验证(Published 天然满足,或 Verified 已完成 lazy verify)。
    Passed,
    /// 曾尝试 lazy verify,明确失败。
    Failed,
    /// 验证所需条件暂不可用(owner document 拿不到、网络不可达)。
    Unavailable,
    /// 未尝试验证(strict 模式下命中 Unverified 直接当 miss 处理,不返回给调用方,
    /// 因此这个状态只会出现在显式选择宽松模式、且策略决定不触发验证的路径里)。
    NotAttempted,
}

/// Observed 事件的观察来源(doc/update-did-cache.md)。只用于日志、诊断和未来
/// `smart_resolver` 式的动态拓扑记录,绝不参与信任等级判定——判定只看目录位置
/// + 验证结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UpdateSource {
    UdpDiscovery,
    Gossip,
    Push,
    LocalFile,
    Authority,
    ZoneResolver,
}

impl UpdateSource {
    pub fn as_str(&self) -> &'static str {
        match self {
            UpdateSource::UdpDiscovery => "UdpDiscovery",
            UpdateSource::Gossip => "Gossip",
            UpdateSource::Push => "Push",
            UpdateSource::LocalFile => "LocalFile",
            UpdateSource::Authority => "Authority",
            UpdateSource::ZoneResolver => "ZoneResolver",
        }
    }

    /// 从 meta 文件字符串还原;未知值(手工文件乱写)一律当作 None,不报错。
    pub fn from_str(value: &str) -> Option<Self> {
        match value {
            "UdpDiscovery" => Some(UpdateSource::UdpDiscovery),
            "Gossip" => Some(UpdateSource::Gossip),
            "Push" => Some(UpdateSource::Push),
            "LocalFile" => Some(UpdateSource::LocalFile),
            "Authority" => Some(UpdateSource::Authority),
            "ZoneResolver" => Some(UpdateSource::ZoneResolver),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DidResolutionError {
    pub uri: String,
    pub code: String,
    pub title: String,
    pub detail: Option<String>,
}

impl DidResolutionError {
    pub fn new(uri: &str, code: &str, title: &str, detail: Option<String>) -> Self {
        Self {
            uri: uri.to_string(),
            code: code.to_string(),
            title: title.to_string(),
            detail,
        }
    }

    pub fn from_ns_error(err: &NSError) -> Self {
        match err {
            NSError::InvalidDID(detail) => Self::new(
                "https://www.w3.org/ns/did#INVALID_DID",
                "invalidDid",
                "Invalid DID",
                Some(detail.clone()),
            ),
            NSError::NotFound(detail) => Self::new(
                "https://www.w3.org/ns/did#NOT_FOUND",
                "notFound",
                "DID document not found",
                Some(detail.clone()),
            ),
            NSError::Disabled(detail) => Self::new(
                "https://www.w3.org/ns/did#DEACTIVATED",
                "deactivated",
                "DID document deactivated",
                Some(detail.clone()),
            ),
            NSError::InvalidParam(detail) => Self::new(
                "https://www.w3.org/ns/did#INVALID_OPTIONS",
                "invalidOptions",
                "Invalid resolution options",
                Some(detail.clone()),
            ),
            NSError::OwnerConflict(detail) => Self::new(
                "https://www.w3.org/ns/did#INVALID_DID_DOCUMENT",
                "ownerConflict",
                "Document owner conflicts with authority record",
                Some(detail.clone()),
            ),
            _ => Self::new(
                "https://www.w3.org/ns/did#INTERNAL_ERROR",
                "internalError",
                "DID resolution failed",
                Some(err.to_string()),
            ),
        }
    }

    pub fn method_not_supported(method: &str) -> Self {
        Self::new(
            "https://www.w3.org/ns/did#METHOD_NOT_SUPPORTED",
            "methodNotSupported",
            "DID method not supported",
            Some(method.to_string()),
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidResolutionMetadata {
    pub content_type: Option<String>,
    pub retrieved: Option<u64>,
    pub resolver_id: Option<String>,
    /// 结果 body 的证据等级(按取回信道打标,简化文档 2.3 节)。
    pub evidence: Option<BodyEvidence>,
    pub cache_status: Option<CacheStatus>,
    /// lazy verify 的结果性质(doc/update-did-cache.md)。cache 命中路径打标;
    /// 其余路径为 None。
    #[serde(default)]
    pub verification_status: Option<VerificationStatus>,
    /// 结果的观察来源(仅诊断用)。命中 `verified/`/`Published` 结果时通常为
    /// None 或 Authority/ZoneResolver。
    #[serde(default)]
    pub source: Option<UpdateSource>,
    pub warnings: Vec<ResolveWarning>,
    pub error: Option<DidResolutionError>,
}

impl Default for DidResolutionMetadata {
    fn default() -> Self {
        Self {
            content_type: None,
            retrieved: None,
            resolver_id: None,
            evidence: None,
            cache_status: None,
            verification_status: None,
            source: None,
            warnings: Vec::new(),
            error: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuckyOSDocumentMetadata {
    pub doc_type: String,
    pub document_status: Option<DocumentStatus>,
    pub document_version: Option<u64>,
    pub authority_seq: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidDocumentMetadata {
    pub created: Option<u64>,
    pub updated: Option<u64>,
    pub deactivated: Option<bool>,
    pub version_id: Option<String>,
    #[serde(rename = "buckyos")]
    pub buckyos: BuckyOSDocumentMetadata,
}

/// This structure follows the W3C DID Resolution Result standard.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolvedDocument {
    pub document: EncodedDocument,
    pub resolution_metadata: DidResolutionMetadata,
    pub document_metadata: DidDocumentMetadata,
    #[serde(default, skip_serializing, skip_deserializing)]
    pub discovered_documents: Vec<DiscoveredDocument>,
}

impl ResolvedDocument {
    pub fn from_document(
        document: EncodedDocument,
        _did: &DID,
        doc_type: &DidDocType,
        resolver_id: Option<String>,
        evidence: BodyEvidence,
        published: Option<&PublishedState>,
    ) -> Self {
        let doc_value = document.clone().to_json_value().ok();
        let created = doc_value
            .as_ref()
            .and_then(|value| value.get("iat").and_then(|ts| ts.as_u64()));
        let updated = created;

        let document_status = published.map(|state| state.document_status.clone());
        // documentVersion = document_iat:权威没有给出时,兜底为文档自身的
        // revision iat(iat 直接存在或由 exp 推导)。version_seq 已退出流程,
        // 不再参与任何版本语义。
        let document_version = published
            .and_then(|state| state.document_version)
            .or_else(|| document_iat(&document));

        let content_type = match &document {
            EncodedDocument::Jwt(_) => "application/did+jwt",
            EncodedDocument::JsonLd(_) => "application/did+ld+json",
        }
        .to_string();

        Self {
            document,
            discovered_documents: Vec::new(),
            resolution_metadata: DidResolutionMetadata {
                content_type: Some(content_type),
                retrieved: Some(buckyos_get_unix_timestamp()),
                resolver_id,
                evidence: Some(evidence),
                cache_status: Some(CacheStatus::Miss),
                verification_status: None,
                source: None,
                warnings: Vec::new(),
                error: None,
            },
            document_metadata: DidDocumentMetadata {
                created,
                updated,
                deactivated: document_status.as_ref().map(DocumentStatus::is_terminal),
                version_id: document_version.map(|version| version.to_string()),
                buckyos: BuckyOSDocumentMetadata {
                    doc_type: doc_type.to_string(),
                    document_status,
                    document_version,
                    authority_seq: published.and_then(|state| state.authority_seq),
                },
            },
        }
    }

    pub fn from_cache(
        document: EncodedDocument,
        did: &DID,
        doc_type: &DidDocType,
        exp: u64,
        evidence: BodyEvidence,
        cache_status: CacheStatus,
    ) -> Self {
        let mut resolved = Self::from_document(
            document,
            did,
            doc_type,
            Some("did-cache".to_string()),
            evidence,
            None,
        );
        resolved.resolution_metadata.cache_status = Some(cache_status);
        resolved.document_metadata.updated = Some(exp);
        match cache_status {
            CacheStatus::UnauthenticatedInfoHit => {
                resolved
                    .resolution_metadata
                    .warnings
                    .push(ResolveWarning::UnauthenticatedInfoCache);
            }
            CacheStatus::Fallback => {
                resolved
                    .resolution_metadata
                    .warnings
                    .push(ResolveWarning::CacheFallback);
            }
            _ => {}
        }
        resolved
    }

    pub fn from_unauthenticated_info(
        document: EncodedDocument,
        did: &DID,
        doc_type: &DidDocType,
        resolver_id: Option<String>,
    ) -> Self {
        Self::from_document(
            document,
            did,
            doc_type,
            resolver_id,
            BodyEvidence::UnproofInfo,
            None,
        )
    }

    pub fn with_warning(mut self, warning: ResolveWarning) -> Self {
        self.resolution_metadata.warnings.push(warning);
        self
    }

    pub fn with_cache_status(mut self, cache_status: CacheStatus) -> Self {
        self.resolution_metadata.cache_status = Some(cache_status);
        self
    }

    pub fn with_verification_status(mut self, verification_status: VerificationStatus) -> Self {
        self.resolution_metadata.verification_status = Some(verification_status);
        self
    }

    pub fn with_source(mut self, source: Option<UpdateSource>) -> Self {
        self.resolution_metadata.source = source;
        self
    }

    pub fn with_discovered_documents(
        mut self,
        discovered_documents: Vec<DiscoveredDocument>,
    ) -> Self {
        self.discovered_documents = discovered_documents;
        self
    }
}

/// 解析来源范围(doc/verify-did-api-boundary-and-freshness-TODO.md):调用方只看
/// 这个值就能判断一次 resolve 可能访问哪些信道、延迟档位是什么。它与
/// `ResolvePolicy` 其余字段的分工:`source` 决定**哪些信道可访问**;
/// `use_zone_resolver` 是 Zone 信道的额外开关(zone-resolver-server 自递归保护);
/// `allow_self_signed_when_missing` / `allow_stale_cache` /
/// `allow_unverified_cache_when_unavailable` 是候选**准入/兜底策略**;
/// `current_zone_did` 是 current-zone bootstrap supplement 的访问边界;
/// `local_authority_override` / `follow_migration` / `max_depth` 归属解析细节。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResolveSourcePolicy {
    /// 只读进程内/本机文件 cache,不访问 Zone Resolver 和 provider。
    /// 唯一保证无网络 I/O 的档位。
    LocalOnly,
    /// 允许访问 Zone Resolver(即使 endpoint 是 localhost 也是显式允许的 I/O),
    /// 但不访问 method authority remote provider。
    LocalAndZone,
    /// 显式访问 method authority,取得当前权威判断:跳过本机 in-TTL cache 快路径
    /// 与 Zone 快路径,直接进入 resolver 主循环,且不做 stale cache 兜底。
    /// 只有这个档位(或 `BestAvailable` 明确命中 method authority)的结果才有
    /// 资格产生"权威全局当前"receipt。
    RemoteAuthority,
    /// 按 resolver 正常优先级取得当前最佳答案(Zone → 本机 cache → 主循环)。
    BestAvailable,
}

impl Default for ResolveSourcePolicy {
    fn default() -> Self {
        Self::BestAvailable
    }
}

#[derive(Debug, Clone)]
pub struct ResolvePolicy {
    /// 本次解析允许访问的来源范围。resolve 可能读写解析缓存、可能联网,
    /// 由这个字段显式决定(LocalOnly 除外都可能是异步慢操作)。
    pub source: ResolveSourcePolicy,
    pub follow_migration: bool,
    /// 策略点②:权威源明确回答 Missing 时,自签名候选是否有入场资格。
    /// 入场不豁免 expected_owner 一致性与验签。
    pub allow_self_signed_when_missing: bool,
    /// 策略点④:查询没有产出可核实文档、且没有负状态屏蔽时,是否允许用
    /// "过期但未作废"的缓存兜底。兜底对象只有 `Published`/`Verified` 条目,
    /// `Unverified` 观察缓存永远没有兜底资格(doc/update-did-cache.md)。
    pub allow_stale_cache: bool,
    /// 宽松开关(doc/update-did-cache.md,默认 false):命中 `Unverified` 观察
    /// 缓存且 lazy verify 因条件不可用(owner 拿不到、网络不可达)没能完成时,
    /// 是否允许把它以 `cache_status = ObservedFallback` +
    /// `verification_status = Unavailable` 打标返回。strict(默认)等同 miss。
    /// 验证明确失败(Rejected)时不论开关如何都不返回。
    pub allow_unverified_cache_when_unavailable: bool,
    /// 本次解析是否允许走 Zone Resolver cache 快路径(简化文档第 3 节第 0 步)。
    /// 默认允许(是否真的查询还取决于 NameClient 级的启用状态)。设为 false
    /// 的典型调用方是 zone-resolver-server 自己:它的内部实现用 resolve_did
    /// 完成对外查询,若不跳过 zone 快路径,就会查询到自己(127.0.0.1:3180)
    /// 造成自递归。
    pub use_zone_resolver: bool,
    /// 本次调用被确认处于哪个 current-zone 自举上下文。None(默认)表示没有
    /// current-zone 权限,注册为 `CurrentZoneBootstrap` 的补充源会被跳过。
    ///
    /// 这里携带精确 DID 而不是一个 bool:即使 policy 在 migration / owner
    /// 递归中继续传播,也只有对该 DID 本身的查询能使用自举信道,不会把 DNS
    /// TXT 的访问权限扩散到 owner 或其它 zone。
    pub current_zone_did: Option<DID>,
    pub max_depth: usize,
    /// 本地测试/运维显式注入的发布模拟(简化文档第 7 节),类似 hosts 文件。
    /// 挂在 policy 上是为了让它随 `descend()`/`for_authority_lookup()` 一起传播到
    /// owner 递归里——owner 解析同样要能命中 override。
    pub local_authority_override: Option<Arc<LocalAuthorityOverrideStore>>,
    visited: Vec<(DID, DidDocType)>,
}

impl Default for ResolvePolicy {
    fn default() -> Self {
        Self {
            source: ResolveSourcePolicy::BestAvailable,
            follow_migration: true,
            allow_self_signed_when_missing: false,
            allow_stale_cache: true,
            allow_unverified_cache_when_unavailable: false,
            use_zone_resolver: true,
            current_zone_did: None,
            max_depth: 8,
            local_authority_override: None,
            visited: Vec::new(),
        }
    }
}

impl ResolvePolicy {
    pub fn with_source(mut self, source: ResolveSourcePolicy) -> Self {
        self.source = source;
        self
    }

    pub fn with_local_authority_override(
        mut self,
        store: Arc<LocalAuthorityOverrideStore>,
    ) -> Self {
        self.local_authority_override = Some(store);
        self
    }

    /// 跳过 Zone Resolver cache 快路径的 policy。zone-resolver-server 的内部
    /// 实现用它调用 resolve_did 完成对外查询,避免查询到自己(默认 endpoint
    /// 就是本机 3180)造成递归。
    pub fn without_zone_resolver(mut self) -> Self {
        self.use_zone_resolver = false;
        self
    }

    /// 标记本次解析的 current zone。只有请求 DID 与该值完全相同,才会启用
    /// 注册为 `CurrentZoneBootstrap` 的补充源(默认注册中的 DNS TXT)。
    ///
    /// 调用方应只在已经持有该 zone 的本地 OwnerDocument、能够完成后续验签时
    /// 使用；普通跨-zone resolve 保持默认 policy 即会跳过这类信道。
    pub fn with_current_zone(mut self, current_zone_did: DID) -> Self {
        self.current_zone_did = Some(current_zone_did);
        self
    }

    /// owner 递归使用的收紧 policy:owner 文档只信权威渠道,关闭 Missing 自签名
    /// 入场、stale cache 兜底与 Unverified 观察缓存露面。
    pub fn for_authority_lookup(&self) -> Self {
        let mut policy = self.clone();
        policy.allow_self_signed_when_missing = false;
        policy.allow_stale_cache = false;
        policy.allow_unverified_cache_when_unavailable = false;
        policy
    }

    /// owner 材料解析使用的 policy:在 `for_authority_lookup` 之上调整来源范围。
    /// `RemoteAuthority` 只约束**主体** (did, doc_type) 必须取得权威判断;owner
    /// 文档是内部依赖,走正常优先级(含本机 cache 复用,新鲜度由 cache TTL 约束),
    /// 避免每次验证都放大出一次 owner 的权威往返。`LocalOnly` / `LocalAndZone`
    /// 原样传播——这两个档位承诺不访问 method authority,owner 解析同样受约束。
    pub fn for_owner_lookup(&self) -> Self {
        let mut policy = self.for_authority_lookup();
        if policy.source == ResolveSourcePolicy::RemoteAuthority {
            policy.source = ResolveSourcePolicy::BestAvailable;
        }
        policy
    }

    pub fn descend(&self, did: &DID, doc_type: &DidDocType) -> NSResult<Self> {
        if self.visited.len() >= self.max_depth {
            return Err(NSError::InvalidState(format!(
                "DID resolution recursion depth exceeded at {}#{}",
                did.to_string(),
                doc_type
            )));
        }
        if self.visited.iter().any(|(visited_did, visited_doc_type)| {
            visited_did == did && visited_doc_type == doc_type
        }) {
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
}

/// 本地测试/运维显式注入的一条发布模拟记录(简化文档第 7 节)。
#[derive(Debug, Clone)]
struct LocalAuthorityOverrideEntry {
    document: EncodedDocument,
    /// 记录写入者声明的作用域(machine/zone/test-env/CI job),目前只用于日志和
    /// 调试;不参与匹配逻辑。
    #[allow(dead_code)]
    scope: String,
    /// `None` 表示不过期。
    expires_at: Option<u64>,
}

/// hosts 文件式的本地 override 存储:只能被显式写入 API 写入,不参与普通
/// `DIDDocumentCache` 的持久化/淘汰逻辑,默认不导出、不广播、不同步到普通 cache。
#[derive(Debug, Default)]
pub struct LocalAuthorityOverrideStore {
    entries: RwLock<HashMap<(DID, String), LocalAuthorityOverrideEntry>>,
}

impl LocalAuthorityOverrideStore {
    pub fn new() -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
        }
    }

    /// 只应由本地管理员、测试框架或显式运维命令调用。
    pub fn set(
        &self,
        did: DID,
        doc_type: &DidDocType,
        document: EncodedDocument,
        scope: impl Into<String>,
        expires_at: Option<u64>,
    ) {
        let mut entries = self.entries.write().unwrap();
        entries.insert(
            (did, doc_type.to_string()),
            LocalAuthorityOverrideEntry {
                document,
                scope: scope.into(),
                expires_at,
            },
        );
    }

    pub fn clear(&self, did: &DID, doc_type: &DidDocType) {
        let mut entries = self.entries.write().unwrap();
        entries.remove(&(did.clone(), doc_type.to_string()));
    }

    pub fn get(&self, did: &DID, doc_type: &DidDocType) -> Option<EncodedDocument> {
        let entries = self.entries.read().unwrap();
        let entry = entries.get(&(did.clone(), doc_type.to_string()))?;
        if let Some(expires_at) = entry.expires_at {
            if expires_at <= buckyos_get_unix_timestamp() {
                return None;
            }
        }
        Some(entry.document.clone())
    }
}

/// owner 文档声明的验证策略(简化 TODO T2.1:收缩到 `revoke_before_iat`,
/// 其它按 doc_type 的策略等 owner 文档真实声明后再加回)。
#[derive(Debug, Clone, Default)]
pub struct OwnerDocumentPolicy {
    /// 一键否决此时间点(含)之前签发的所有文档,即使签名合法(replay guard)。
    pub revoke_before_iat: Option<u64>,
}

impl OwnerDocumentPolicy {
    pub fn from_owner_document(owner_document: &OwnerDocument) -> Self {
        Self {
            revoke_before_iat: owner_document.valid_iat,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum RecordType {
    A,     // IPv4 address
    AAAA,  // IPv6 address
    CAA,   // Certification Authority Authorization record
    CNAME, // Alias record
    HTTPS, // HTTPS/SVCB service binding record
    TXT,   // Text record
    SRV,   // Service record
    MX,    // Mail exchange record
    NS,    // Name server record
    PTR,   // Pointer record
    SOA,   // Start of authority record
}

impl Default for RecordType {
    fn default() -> Self {
        RecordType::A
    }
}

impl RecordType {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_uppercase().as_str() {
            "A" => Some(RecordType::A),
            "AAAA" => Some(RecordType::AAAA),
            "CAA" => Some(RecordType::CAA),
            "CNAME" => Some(RecordType::CNAME),
            "HTTPS" => Some(RecordType::HTTPS),
            "TXT" => Some(RecordType::TXT),
            "SRV" => Some(RecordType::SRV),
            "MX" => Some(RecordType::MX),
            "NS" => Some(RecordType::NS),
            "PTR" => Some(RecordType::PTR),
            "SOA" => Some(RecordType::SOA),
            _ => None,
        }
    }

    pub fn to_string(&self) -> String {
        match self {
            RecordType::A => "A",
            RecordType::AAAA => "AAAA",
            RecordType::CAA => "CAA",
            RecordType::CNAME => "CNAME",
            RecordType::HTTPS => "HTTPS",
            RecordType::TXT => "TXT",
            RecordType::SRV => "SRV",
            RecordType::MX => "MX",
            RecordType::NS => "NS",
            RecordType::PTR => "PTR",
            RecordType::SOA => "SOA",
        }
        .to_string()
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct EndPointInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    protocol: Option<String>,
    addr: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    port: Option<u16>,
}

// NameInfo的设计
//  这个结构的json未来可以完整的保存在bns的智能合约里
//  向下兼容DNS，因此有DNS里该有的字段 ： DNS Response一定可以转成一个有效的NameInfo ,符合一定约束的NameInfo，可以转成一个合法的DNS Response
//  基于BNS，构造的核心接口是query_did("fragement")
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct NameInfo {
    #[serde(skip_serializing_if = "String::is_empty")]
    #[serde(default)]
    pub name: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    pub address: Vec<IpAddr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cname: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    pub txt: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    pub caa: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    pub ptr_records: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u32>,
    #[serde(default)]
    pub iat: u64,
}

impl Default for NameInfo {
    fn default() -> Self {
        NameInfo {
            name: String::new(),
            address: Vec::new(),
            cname: None,
            txt: Vec::new(),
            caa: Vec::new(),
            ptr_records: Vec::new(),
            iat: 0,
            ttl: None,
        }
    }
}

impl NameInfo {
    pub fn new(domain: &str) -> Self {
        let mut result = Self::default();
        result.name = domain.to_string();
        return result;
    }

    pub fn from_address(name: &str, address: IpAddr) -> Self {
        let ttl = 5 * 60;
        Self {
            name: name.to_string(),
            address: vec![address],
            cname: None,
            txt: Vec::new(),
            caa: Vec::new(),
            ptr_records: Vec::new(),
            iat: 0,
            ttl: Some(ttl),
        }
    }

    pub fn from_address_vec(name: &str, address_vec: Vec<IpAddr>) -> Self {
        let ttl = 5 * 60;
        Self {
            name: name.to_string(),
            address: address_vec,
            cname: None,
            txt: Vec::new(),
            caa: Vec::new(),
            ptr_records: Vec::new(),
            iat: 0,
            ttl: Some(ttl),
        }
    }

    pub fn parse_txt_record_to_did_documents(
        self: &NameInfo,
    ) -> NSResult<HashMap<String, EncodedDocument>> {
        let host_name = self.name.clone();
        let mut did_documents = HashMap::new();
        let mut owner_x = None;
        let mut devices = Vec::new();
        let mut boot_jwt = None;
        let mut zone_document: Option<ZoneDocument> = None;

        for txt in self.txt.iter() {
            debug!("- TXT:{}", txt);
            if txt.starts_with("BOOT=") {
                let boot_payload = txt
                    .trim_start_matches("BOOT=")
                    .trim_end_matches(";")
                    .to_string();
                boot_jwt = Some(boot_payload);
            } else if txt.starts_with("PKX=") {
                let pkx = txt.trim_start_matches("PKX=").trim_end_matches(";");
                owner_x = Some(pkx.to_string());
            } else if txt.starts_with("DEV=") {
                let dev_payload = txt.trim_start_matches("DEV=").trim_end_matches(";");
                devices.push(dev_payload.to_string());
            }
        }

        if owner_x.is_some() {
            let owner_x = owner_x.unwrap();
            let owner_document = OwnerDocument::new_by_pkx(owner_x.as_str(), host_name.as_str())?;
            let public_key_jwk = owner_document.get_default_key().unwrap();
            let owner_public_key = DecodingKey::from_jwk(&public_key_jwk)
                .map_err(|e| NSError::Failed(format!("parse public key failed! {}", e)))?;
            did_documents.insert(
                "owner".to_string(),
                EncodedDocument::JsonLd(serde_json::to_value(&owner_document).unwrap()),
            );
            //verify did_document by pkx_list
            if boot_jwt.is_some() {
                let boot_jwt = boot_jwt.unwrap();
                let mut boot_document =
                    ZoneBootDocument::decode(&EncodedDocument::Jwt(boot_jwt.clone()), None)?;
                boot_document.owner_key = Some(public_key_jwk.clone());
                boot_document.id = Some(DID::from_str(host_name.as_str()).unwrap());
                let real_zone_document = boot_document.to_zone_document(&boot_jwt);
                zone_document = Some(real_zone_document);
                did_documents.insert("boot".to_string(), EncodedDocument::Jwt(boot_jwt));
            }

            if devices.len() > 0 {
                for device_jwt in devices {
                    //用zone_boot_document.owner_key验证device_jwt
                    let device_mini_document =
                        DeviceMiniDocument::from_jwt(&device_jwt, &owner_public_key);
                    if device_mini_document.is_err() {
                        warn!("{} in not device_minit_config jwt", device_jwt);
                        continue;
                    }
                    let device_mini_document = device_mini_document.unwrap();
                    let device_document = DeviceDocument::new_by_mini_document(
                        &device_jwt,
                        &device_mini_document,
                        DID::from_str(host_name.as_str()).unwrap(),
                        DID::from_str(host_name.as_str()).unwrap(),
                    );
                    let device_name = device_document.name.clone();
                    let device_document_json = serde_json::to_value(&device_document).unwrap();
                    did_documents
                        .insert(device_name, EncodedDocument::JsonLd(device_document_json));
                    if zone_document.is_some() {
                        zone_document
                            .as_mut()
                            .unwrap()
                            .mini_device_jwts
                            .insert(device_document.name.clone(), device_jwt);
                        zone_document
                            .as_mut()
                            .unwrap()
                            .devices
                            .insert(device_document.name.clone(), device_document);
                    }
                }
            }

            if zone_document.is_some() {
                let zone_document = zone_document.unwrap();
                let zone_document_json = serde_json::to_value(&zone_document).unwrap();
                did_documents.insert(
                    "zone".to_string(),
                    EncodedDocument::JsonLd(zone_document_json),
                );
            }
        }

        return Ok(did_documents);
    }
}

/// resolver-provider 是内核模型(简化文档 2.2 节):所有 provider 都是内核实现,
/// 可信的是"它如实转述了从哪条信道查到了什么";内容本身可不可信,由主循环的
/// need_proof / verify 判定。provider 只需要诚实回答两件事:
/// - `resolve_published_state`:权威源的发布状态 + owner 绑定(补充源永远返回 `Ok(None)`);
/// - `query_did`:从自己的信道取回文档 body(`NotFound` = 该信道没有,其它错误 = 没得到回答)。
///
/// 证据等级不由 provider 自己声明,而是由注册位置(权威渠道 / 补充源)决定。
#[async_trait::async_trait]
pub trait NsProvider: 'static + Send + Sync {
    fn get_id(&self) -> String;

    /// 该 provider 默认服务的 DID method 列表。仅供 `NameClient::add_provider`
    /// 兼容注册使用;新代码应通过 `set_method_authority` / `add_method_supplement`
    /// 显式注册,不支持 wildcard。
    fn methods(&self) -> Vec<String> {
        Vec::new()
    }

    async fn query(
        &self,
        name: &str,
        record_type: Option<RecordType>,
        from_ip: Option<IpAddr>,
    ) -> NSResult<NameInfo>;

    async fn query_did(
        &self,
        did: &DID,
        doc_type: Option<DidDocType>,
        from_ip: Option<IpAddr>,
    ) -> NSResult<EncodedDocument>;

    async fn query_did_documents(
        &self,
        _did: &DID,
        _from_ip: Option<IpAddr>,
    ) -> NSResult<Option<HashMap<String, EncodedDocument>>> {
        Ok(None)
    }

    async fn resolve_published_state(
        &self,
        _did: &DID,
        _doc_type: &DidDocType,
    ) -> NSResult<Option<PublishedState>> {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use buckyos_kit::buckyos_get_unix_timestamp;
    use jsonwebtoken::{DecodingKey, EncodingKey};
    use serde_json::json;

    // 测试辅助函数：创建测试用的密钥和 ZoneBootDocument
    fn create_test_zone_boot_document() -> (
        EncodingKey,
        DecodingKey,
        jsonwebtoken::jwk::Jwk,
        ZoneBootDocument,
    ) {
        let private_key_pem = r#"
        -----BEGIN PRIVATE KEY-----
        MC4CAQAwBQYDK2VwBCIEIBwApVoYjauZFuKMBRe02wKlKm2B6a1F0/WIPMqDaw5F
        -----END PRIVATE KEY-----
        "#;
        let jwk = json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "qmtOLLWpZeBMzt97lpfj2MxZGWn3QfuDB7Q4uaP3Eok"
        });

        let private_key = EncodingKey::from_ed_pem(private_key_pem.as_bytes()).unwrap();
        let public_key_jwk: jsonwebtoken::jwk::Jwk = serde_json::from_value(jwk).unwrap();
        let public_key = DecodingKey::from_jwk(&public_key_jwk).unwrap();

        let zone_boot_document = ZoneBootDocument {
            id: None,
            oods: vec![
                "ood1".parse().unwrap(),
                "ood2:202.222.122.123".parse().unwrap(),
            ],
            sn: Some("sn.buckyos.io".to_string()),
            exp: buckyos_get_unix_timestamp() + 3600 * 24 * 365,
            owner: None,
            owner_key: None,
            extra_info: HashMap::new(),
        };

        (private_key, public_key, public_key_jwk, zone_boot_document)
    }

    // 测试辅助函数：创建测试用的 DeviceMiniDocument
    fn create_test_device_mini_document(owner_private_key: &EncodingKey) -> String {
        let mini_document = DeviceMiniDocument {
            name: "device1".to_string(),
            x: "5bUuyWLOKyCre9az_IhJVIuOw8bA0gyKjstcYGHbaPE".to_string(),
            rtcp_port: None,
            exp: buckyos_get_unix_timestamp() + 3600 * 24 * 365,
            extra_info: HashMap::new(),
        };

        mini_document.to_jwt(owner_private_key).unwrap()
    }

    #[test]
    fn test_parse_txt_record_to_did_documents() {
        // 准备测试数据
        let (private_key, _public_key, public_key_jwk, zone_boot_document) =
            create_test_zone_boot_document();

        // 编码 ZoneBootDocument 为 JWT
        let boot_jwt = zone_boot_document.encode(Some(&private_key)).unwrap();

        // 创建设备 JWT
        let device_jwt = create_test_device_mini_document(&private_key);

        // 获取 owner key 的 x 值
        let owner_x = get_x_from_jwk(&public_key_jwk).unwrap();

        // 创建包含 TXT 记录的 NameInfo
        let name_info = NameInfo {
            name: "did:bns:testzone".to_string(),
            address: Vec::new(),
            cname: None,
            txt: vec![
                format!("BOOT={};", boot_jwt.to_string()),
                format!("PKX={};", owner_x),
                format!("DEV={};", device_jwt),
                "plain=value".to_string(),
            ],
            caa: Vec::new(),
            ptr_records: Vec::new(),
            iat: buckyos_get_unix_timestamp(),
            ttl: Some(3600),
        };

        // 执行解析
        let result = name_info.parse_txt_record_to_did_documents();
        assert!(
            result.is_ok(),
            "parse_txt_record_to_did_documents should succeed"
        );

        let did_documents = result.unwrap();

        // 验证结果
        assert!(
            did_documents.contains_key("boot"),
            "should contain boot document"
        );
        assert!(
            did_documents.contains_key("zone"),
            "should contain zone document"
        );
        assert!(
            did_documents.contains_key("device1"),
            "should contain device document"
        );

        let zone_boot_document = did_documents.get("zone").unwrap();
        let did_doc = parse_did_doc(zone_boot_document.clone()).unwrap();
        let auth_key = did_doc.get_auth_key(None).unwrap();
        let _auth_key_x = get_x_from_jwk(&auth_key.1).unwrap();
        //assert_eq!(auth_key_x, owner_x);

        println!("✓ test_parse_txt_record_to_did_documents passed");
    }

    #[test]
    fn test_parse_txt_record_without_owner_key() {
        // 测试没有 owner key 的情况
        let name_info = NameInfo {
            name: "did:bns:testzone".to_string(),
            address: Vec::new(),
            cname: None,
            txt: vec!["some-txt=value".to_string()],
            caa: Vec::new(),
            ptr_records: Vec::new(),
            iat: buckyos_get_unix_timestamp(),
            ttl: Some(3600),
        };

        let result = name_info.parse_txt_record_to_did_documents().unwrap();

        assert_eq!(result.len(), 0, "should have no DID documents");
        assert_eq!(name_info.txt.len(), 1, "should preserve original TXT");

        println!("✓ test_parse_txt_record_without_owner_key passed");
    }

    #[test]
    fn test_structural_owner_derivation() {
        // 二级 bns 名字:结构 owner 是去掉第一段后的父名字。
        assert_eq!(
            structural_owner(&DID::new("bns", "app1.alice")),
            Some(DID::new("bns", "alice"))
        );
        assert_eq!(
            structural_owner(&DID::new("bns", "a.b.c")),
            Some(DID::new("bns", "b.c"))
        );
        // 一级名字是根,推不出结构 owner。
        assert_eq!(structural_owner(&DID::new("bns", "alice")), None);
        // did:web 的点号是 DNS 层级,不是 bns 所有权结构。
        assert_eq!(structural_owner(&DID::new("web", "www.example.com")), None);
    }

    #[test]
    fn test_key_class_method_detection() {
        assert!(is_key_class_method("dev"));
        assert!(is_key_class_method("key"));
        assert!(!is_key_class_method("bns"));
        assert!(!is_key_class_method("web"));
    }

    #[test]
    fn test_content_hash_matches() {
        let doc = EncodedDocument::JsonLd(json!({"marker": "hash-me"}));
        let hash = document_content_hash(&doc);
        assert!(content_hash_matches(&hash, &doc));
        assert!(content_hash_matches(&format!("sha256:{}", hash), &doc));
        assert!(content_hash_matches(&hash.to_uppercase(), &doc));
        assert!(!content_hash_matches("deadbeef", &doc));
    }

    /// content hash 编码契约的防护测试(已确认):workspace 不得开启 serde_json
    /// 的 `preserve_order`——`Value` 的 map 必须是 BTreeMap,序列化天然是
    /// "键字典序 + 紧凑分隔符",这是 JsonLd content hash 跨进程稳定的前提。
    /// 若有人打开 preserve_order,本测试会失败。
    #[test]
    fn json_value_serialization_is_key_sorted_and_compact() {
        let value: serde_json::Value =
            serde_json::from_str(r#"{ "zebra": 1, "alpha": {"z": 1, "a": 2}, "mid": [1, 2] }"#)
                .unwrap();
        assert_eq!(
            serde_json::to_string(&value).unwrap(),
            r#"{"alpha":{"a":2,"z":1},"mid":[1,2],"zebra":1}"#
        );

        // 键序/空白差异不影响 JsonLd 的 content hash。
        let reordered: serde_json::Value = serde_json::from_str(
            r#"{"mid":[1,2],  "alpha":{"a":2,"z":1},"zebra":1}"#,
        )
        .unwrap();
        assert_eq!(
            document_content_hash(&EncodedDocument::JsonLd(value)),
            document_content_hash(&EncodedDocument::JsonLd(reordered))
        );
    }

    #[test]
    fn document_iat_derives_from_exp_when_missing() {
        // revision iat 的补充流程(get_doc_iat 语义):iat 直接存在优先;
        // 缺 iat 用 exp - DEFAULT_EXPIRE_TIME;两者皆无 → None(文档无效)。
        let with_iat = EncodedDocument::JsonLd(json!({"iat": 100, "exp": 999_999}));
        assert_eq!(document_iat(&with_iat), Some(100));

        let exp_only = EncodedDocument::JsonLd(json!({"exp": name_lib::DEFAULT_EXPIRE_TIME + 7}));
        assert_eq!(document_iat(&exp_only), Some(7));

        let neither = EncodedDocument::JsonLd(json!({"marker": "no-time"}));
        assert_eq!(document_iat(&neither), None);
    }
}
