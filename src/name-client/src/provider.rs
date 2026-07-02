use buckyos_kit::buckyos_get_unix_timestamp;
use jsonwebtoken::DecodingKey;
use name_lib::OwnerConfig;
use name_lib::*;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, RwLock},
};

pub use name_lib::{DidDocType, DEFAULT_DID_DOC_TYPE, DOC_TYPE_INFO, DOC_TYPE_OWNER};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MethodMatcher {
    Exact(Vec<String>),
    Any,
}

impl MethodMatcher {
    pub fn exact(methods: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self::Exact(methods.into_iter().map(Into::into).collect())
    }

    pub fn matches(&self, method: &str) -> bool {
        match self {
            Self::Exact(methods) => methods.iter().any(|item| item == method),
            Self::Any => true,
        }
    }

    pub fn is_exact_match(&self, method: &str) -> bool {
        match self {
            Self::Exact(methods) => methods.iter().any(|item| item == method),
            Self::Any => false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolverCaps {
    pub published_state: bool,
    pub document_body: bool,
    pub self_signed_candidate: bool,
    pub unauthenticated_info: bool,
    pub negative_state: bool,
}

impl ResolverCaps {
    pub fn legacy_document() -> Self {
        Self {
            published_state: false,
            document_body: true,
            self_signed_candidate: true,
            unauthenticated_info: true,
            negative_state: true,
        }
    }

    pub fn dns_only() -> Self {
        Self {
            published_state: false,
            document_body: false,
            self_signed_candidate: false,
            unauthenticated_info: false,
            negative_state: false,
        }
    }
}

impl Default for ResolverCaps {
    fn default() -> Self {
        Self::legacy_document()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceKind {
    PublishedState,
    AnchoredDocumentBody,
    SelfSignedCandidate,
    UnauthenticatedInfo,
    Negative,
    NotFound,
    TransportError,
}

impl EvidenceKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            EvidenceKind::PublishedState => "PublishedState",
            EvidenceKind::AnchoredDocumentBody => "AnchoredDocumentBody",
            EvidenceKind::SelfSignedCandidate => "SelfSignedCandidate",
            EvidenceKind::UnauthenticatedInfo => "UnauthenticatedInfo",
            EvidenceKind::Negative => "Negative",
            EvidenceKind::NotFound => "NotFound",
            EvidenceKind::TransportError => "TransportError",
        }
    }

    pub fn rank(&self) -> u8 {
        match self {
            EvidenceKind::PublishedState => 0,
            EvidenceKind::AnchoredDocumentBody => 1,
            EvidenceKind::SelfSignedCandidate => 2,
            EvidenceKind::UnauthenticatedInfo => 3,
            EvidenceKind::Negative => 4,
            EvidenceKind::NotFound => 5,
            EvidenceKind::TransportError => 6,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NameStatus {
    Active,
    Missing,
    Expired,
    Tombstoned,
}

impl Default for NameStatus {
    fn default() -> Self {
        Self::Active
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DocumentStatus {
    Missing, //unknown
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OwnerSource {
    MethodAuthority,
    DocumentClaim,
    LocalOverride,
    Unknown,
}

impl Default for OwnerSource {
    fn default() -> Self {
        Self::Unknown
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublishedState {
    pub did: DID,
    pub doc_type: String,
    pub name_status: NameStatus,
    pub document_status: DocumentStatus,
    pub document_ref: Option<DocumentRef>,
    pub document_version: Option<u64>,
    pub previous_version: Option<u64>,
    pub next_version: Option<u64>,
    pub effective_owner: Option<DID>,
    pub owner_source: OwnerSource,
    pub authority_root: Option<String>,
    pub authority_seq: Option<u64>,
    pub lineage_epoch: Option<u64>,
    pub canonical_id: Option<DID>,
    pub equivalent_ids: Vec<DID>,
    pub migration_target: Option<DID>,
}

impl PublishedState {
    pub fn active(did: DID, doc_type: String, document: EncodedDocument) -> Self {
        Self {
            did,
            doc_type,
            name_status: NameStatus::Active,
            document_status: DocumentStatus::Active,
            document_ref: Some(DocumentRef::inline(document)),
            document_version: None,
            previous_version: None,
            next_version: None,
            effective_owner: None,
            owner_source: OwnerSource::Unknown,
            authority_root: None,
            authority_seq: None,
            lineage_epoch: None,
            canonical_id: None,
            equivalent_ids: Vec::new(),
            migration_target: None,
        }
    }

    pub fn missing(did: DID, doc_type: String) -> Self {
        Self {
            did,
            doc_type,
            name_status: NameStatus::Active,
            document_status: DocumentStatus::Missing,
            document_ref: None,
            document_version: None,
            previous_version: None,
            next_version: None,
            effective_owner: None,
            owner_source: OwnerSource::Unknown,
            authority_root: None,
            authority_seq: None,
            lineage_epoch: None,
            canonical_id: None,
            equivalent_ids: Vec::new(),
            migration_target: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentBody {
    pub document: EncodedDocument,
    pub evidence_kind: EvidenceKind,
    pub resolver_id: Option<String>,
    pub retrieved: Option<u64>,
}

impl DocumentBody {
    pub fn anchored(document: EncodedDocument, resolver_id: Option<String>) -> Self {
        Self {
            document,
            evidence_kind: EvidenceKind::AnchoredDocumentBody,
            resolver_id,
            retrieved: Some(buckyos_get_unix_timestamp()),
        }
    }

    pub fn self_signed(document: EncodedDocument, resolver_id: Option<String>) -> Self {
        Self {
            document,
            evidence_kind: EvidenceKind::SelfSignedCandidate,
            resolver_id,
            retrieved: Some(buckyos_get_unix_timestamp()),
        }
    }

    pub fn unauthenticated(document: EncodedDocument, resolver_id: Option<String>) -> Self {
        Self {
            document,
            evidence_kind: EvidenceKind::UnauthenticatedInfo,
            resolver_id,
            retrieved: Some(buckyos_get_unix_timestamp()),
        }
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
    SignedByHistoricalKey,
    KeyRotatedAfterIat,
    PendingActivation {
        pending_version: u64,
        valid_from: u64,
    },
    LegacyResolverEvidence,
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
    pub authority_rank: Option<i32>,
    pub cache_status: Option<CacheStatus>,
    pub warnings: Vec<ResolveWarning>,
    pub error: Option<DidResolutionError>,
}

impl Default for DidResolutionMetadata {
    fn default() -> Self {
        Self {
            content_type: None,
            retrieved: None,
            resolver_id: None,
            authority_rank: None,
            cache_status: None,
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
    pub previous_version: Option<u64>,
    pub lineage_epoch: Option<u64>,
    pub authority_seq: Option<u64>,
    pub proof_root: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidDocumentMetadata {
    pub created: Option<u64>,
    pub updated: Option<u64>,
    pub deactivated: Option<bool>,
    pub version_id: Option<String>,
    pub next_version_id: Option<String>,
    pub canonical_id: Option<DID>,
    pub equivalent_ids: Vec<DID>,
    #[serde(rename = "buckyos")]
    pub buckyos: BuckyOSDocumentMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolvedDocument {
    pub document: EncodedDocument,
    pub resolution_metadata: DidResolutionMetadata,
    pub document_metadata: DidDocumentMetadata,
}

impl ResolvedDocument {
    pub fn from_document(
        document: EncodedDocument,
        _did: &DID,
        doc_type: &DidDocType,
        authority_rank: Option<i32>,
        resolver_id: Option<String>,
        evidence_kind: EvidenceKind,
        published: Option<&PublishedState>,
    ) -> Self {
        let doc_value = document.clone().to_json_value().ok();
        let created = doc_value
            .as_ref()
            .and_then(|value| value.get("iat").and_then(|ts| ts.as_u64()));
        let updated = created;
        let version_seq = doc_value
            .as_ref()
            .and_then(|value| value.get("version_seq").and_then(|ts| ts.as_u64()));

        let document_status = published.map(|state| state.document_status.clone());
        let document_version = published
            .and_then(|state| state.document_version)
            .or(version_seq);
        let previous_version = published.and_then(|state| state.previous_version);
        let next_version = published.and_then(|state| state.next_version);

        let content_type = match &document {
            EncodedDocument::Jwt(_) => "application/did+jwt",
            EncodedDocument::JsonLd(_) => "application/did+ld+json",
        }
        .to_string();

        let mut warnings = Vec::new();
        if evidence_kind == EvidenceKind::AnchoredDocumentBody && published.is_none() {
            warnings.push(ResolveWarning::LegacyResolverEvidence);
        }

        Self {
            document,
            resolution_metadata: DidResolutionMetadata {
                content_type: Some(content_type),
                retrieved: Some(buckyos_get_unix_timestamp()),
                resolver_id,
                authority_rank,
                cache_status: Some(CacheStatus::Miss),
                warnings,
                error: None,
            },
            document_metadata: DidDocumentMetadata {
                created,
                updated,
                deactivated: document_status.as_ref().map(DocumentStatus::is_terminal),
                version_id: document_version.map(|version| version.to_string()),
                next_version_id: next_version.map(|version| version.to_string()),
                canonical_id: published.and_then(|state| state.canonical_id.clone()),
                equivalent_ids: published
                    .map(|state| state.equivalent_ids.clone())
                    .unwrap_or_default(),
                buckyos: BuckyOSDocumentMetadata {
                    doc_type: doc_type.to_string(),
                    document_status,
                    document_version,
                    previous_version,
                    lineage_epoch: published.and_then(|state| state.lineage_epoch),
                    authority_seq: published.and_then(|state| state.authority_seq),
                    proof_root: published.and_then(|state| state.authority_root.clone()),
                },
            },
        }
    }

    pub fn from_cache(
        document: EncodedDocument,
        did: &DID,
        doc_type: &DidDocType,
        exp: u64,
        trust_level: i32,
        cache_status: CacheStatus,
    ) -> Self {
        let mut resolved = Self::from_document(
            document,
            did,
            doc_type,
            Some(trust_level),
            Some("did-cache".to_string()),
            EvidenceKind::AnchoredDocumentBody,
            None,
        );
        resolved.resolution_metadata.cache_status = Some(cache_status);
        resolved.document_metadata.updated = Some(exp);
        let warning = if cache_status == CacheStatus::UnauthenticatedInfoHit {
            ResolveWarning::UnauthenticatedInfoCache
        } else {
            ResolveWarning::CacheFallback
        };
        resolved.resolution_metadata.warnings.push(warning);
        resolved
    }

    pub fn from_unauthenticated_info(
        document: EncodedDocument,
        did: &DID,
        doc_type: &DidDocType,
        authority_rank: Option<i32>,
        resolver_id: Option<String>,
    ) -> Self {
        Self::from_document(
            document,
            did,
            doc_type,
            authority_rank,
            resolver_id,
            EvidenceKind::UnauthenticatedInfo,
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
}

#[derive(Debug, Clone)]
pub struct ResolvePolicy {
    pub follow_migration: bool,
    pub allow_self_signed_when_missing: bool,
    pub allow_cache_when_authority_unavailable: bool,
    pub max_depth: usize,
    /// 本地测试/运维显式注入的发布模拟（设计文档第 7.3 节），类似 hosts 文件。
    /// 挂在 policy 上而不是单独传参，是为了让它随 `descend()`/`for_authority_lookup()`
    /// 一起传播到 owner 递归里——owner 解析同样要能命中 override。
    pub local_authority_override: Option<Arc<LocalAuthorityOverrideStore>>,
    visited: Vec<(DID, DidDocType)>,
}

impl Default for ResolvePolicy {
    fn default() -> Self {
        Self {
            follow_migration: true,
            allow_self_signed_when_missing: false,
            allow_cache_when_authority_unavailable: true,
            max_depth: 8,
            local_authority_override: None,
            visited: Vec::new(),
        }
    }
}

impl ResolvePolicy {
    pub fn with_local_authority_override(
        mut self,
        store: Arc<LocalAuthorityOverrideStore>,
    ) -> Self {
        self.local_authority_override = Some(store);
        self
    }

    pub fn for_authority_lookup(&self) -> Self {
        let mut policy = self.clone();
        policy.allow_self_signed_when_missing = false;
        policy.allow_cache_when_authority_unavailable = false;
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

/// 本地测试/运维显式注入的一条发布模拟记录（设计文档第 7.3 节）。
#[derive(Debug, Clone)]
struct LocalAuthorityOverrideEntry {
    document: EncodedDocument,
    /// 记录写入者声明的作用域（machine/zone/test-env/CI job），目前只用于日志和
    /// 调试；不参与匹配逻辑。
    #[allow(dead_code)]
    scope: String,
    /// `None` 表示不过期。
    expires_at: Option<u64>,
}

/// hosts 文件式的本地 override 存储：只能被显式写入 API 写入，不参与普通
/// `DIDDocumentCache` 的持久化/淘汰逻辑，默认不导出、不广播、不同步到普通 cache。
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

/// Owner 对可达性敏感 doc_type 的发布保护策略。设计文档第 12 节的落点，
/// Phase 1-2 阶段先留空结构，具体规则在后续 Phase 落地。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReachabilityPolicy {}

/// Owner Config 是验证策略源（设计文档第 6 节），不是调用方传入的 `ResolvePolicy`。
/// 它来自递归解析出的 owner 文档本身，而不是调用方配置。
#[derive(Debug, Clone, Default)]
pub struct OwnerDocumentPolicy {
    /// 一键否决此时间点（含）之前签发的所有文档，即使签名合法。
    pub revoke_before_iat: Option<u64>,
    /// 权威发布源返回 Missing 时，是否允许按 doc_type 进入自签名 fallback。
    pub allow_self_signed_when_missing: HashMap<String, bool>,
    /// 权威发布源不可达时，是否允许按 doc_type 使用已验证过的本地结果。
    pub allow_cache_when_authority_unavailable: HashMap<String, bool>,
    /// 可达性敏感 doc_type（zone/device/service 等）的发布保护策略。
    pub reachability_sensitive: HashMap<String, ReachabilityPolicy>,
}

impl OwnerDocumentPolicy {
    /// 从递归解析并验签得到的 owner 文档派生策略。目前只落地 `revoke_before_iat`
    /// （复用 `OwnerConfig::valid_iat` 既有语义），其余字段是尚未被 owner 文档
    /// 显式声明的扩展点，默认空 map 表示"由调用方 ResolvePolicy 兜底"。
    pub fn from_owner_config(owner_config: &OwnerConfig) -> Self {
        Self {
            revoke_before_iat: owner_config.valid_iat,
            allow_self_signed_when_missing: HashMap::new(),
            allow_cache_when_authority_unavailable: HashMap::new(),
            reachability_sensitive: HashMap::new(),
        }
    }
}

/// 递归解析得到的 owner 验证上下文：owner 的 DID、用于验签的 key，以及
/// owner 自己声明的验证策略。
#[derive(Debug, Clone)]
pub struct OwnerContext {
    pub owner_did: DID,
    pub decoding_key: DecodingKey,
    pub public_key: jsonwebtoken::jwk::Jwk,
    pub policy: OwnerDocumentPolicy,
}

/// 验证根：owner 是递归基（`MethodAuthority`），普通文档递归到 owner 文档
/// 拿到 `Owner(OwnerContext)`。参见设计文档第 1.1/9 节。
#[derive(Debug, Clone)]
pub enum VerificationRoot {
    MethodAuthority,
    Owner(OwnerContext),
}

impl VerificationRoot {
    pub fn owner_document_policy(&self) -> OwnerDocumentPolicy {
        match self {
            VerificationRoot::MethodAuthority => OwnerDocumentPolicy::default(),
            VerificationRoot::Owner(ctx) => ctx.policy.clone(),
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
        let mut zone_config: Option<ZoneConfig> = None;

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
            let owner_config = OwnerConfig::new_by_pkx(owner_x.as_str(), host_name.as_str())?;
            let public_key_jwk = owner_config.get_default_key().unwrap();
            let owner_public_key = DecodingKey::from_jwk(&public_key_jwk)
                .map_err(|e| NSError::Failed(format!("parse public key failed! {}", e)))?;
            did_documents.insert(
                "owner".to_string(),
                EncodedDocument::JsonLd(serde_json::to_value(&owner_config).unwrap()),
            );
            //verify did_document by pkx_list
            if boot_jwt.is_some() {
                let boot_jwt = boot_jwt.unwrap();
                let mut boot_config =
                    ZoneBootConfig::decode(&EncodedDocument::Jwt(boot_jwt.clone()), None)?;
                boot_config.owner_key = Some(public_key_jwk.clone());
                boot_config.id = Some(DID::from_str(host_name.as_str()).unwrap());
                let real_zone_config = boot_config.to_zone_config(&boot_jwt);
                zone_config = Some(real_zone_config);
                did_documents.insert("boot".to_string(), EncodedDocument::Jwt(boot_jwt));
            }

            if devices.len() > 0 {
                for device_jwt in devices {
                    //用zone_boot_config.owner_key验证device_jwt
                    let device_mini_config =
                        DeviceMiniConfig::from_jwt(&device_jwt, &owner_public_key);
                    if device_mini_config.is_err() {
                        warn!("{} in not device_minit_config jwt", device_jwt);
                        continue;
                    }
                    let device_mini_config = device_mini_config.unwrap();
                    let device_config = DeviceConfig::new_by_mini_config(
                        &device_jwt,
                        &device_mini_config,
                        DID::from_str(host_name.as_str()).unwrap(),
                        DID::from_str(host_name.as_str()).unwrap(),
                    );
                    let device_name = device_config.name.clone();
                    let device_config_json = serde_json::to_value(&device_config).unwrap();
                    did_documents.insert(device_name, EncodedDocument::JsonLd(device_config_json));
                    if zone_config.is_some() {
                        zone_config
                            .as_mut()
                            .unwrap()
                            .mini_device_jwts
                            .insert(device_config.name.clone(), device_jwt);
                        zone_config
                            .as_mut()
                            .unwrap()
                            .devices
                            .insert(device_config.name.clone(), device_config);
                    }
                }
            }

            if zone_config.is_some() {
                let zone_config = zone_config.unwrap();
                let zone_config_json = serde_json::to_value(&zone_config).unwrap();
                did_documents.insert(
                    "zone".to_string(),
                    EncodedDocument::JsonLd(zone_config_json),
                );
            }
        }

        return Ok(did_documents);
    }
    // pub fn from_zone_config_str(
    //     name: &str,
    //     zone_config_jwt: &str,
    //     zone_config_pkx: &str,
    //     zone_gateway_device_list: &Option<Vec<String>>,
    // ) -> Self {

    //     let ttl = 3600;
    //     let pkx_string = format!("0:{}", zone_config_pkx);
    //     let mut pk_x_list = vec![pkx_string];
    //     if let Some(device_list) = zone_gateway_device_list {
    //         for device_did in device_list {
    //             let device_did = DID::from_str(device_did.as_str());
    //             if device_did.is_ok() {
    //                 let device_did = device_did.unwrap();
    //                 let pkx_string = format!("1:{}", device_did.id);
    //                 pk_x_list.push(pkx_string);
    //             }
    //         }
    //     }

    //     let zone_boot_config_doc = EncodedDocument::from_str(zone_config_jwt.to_string()).unwrap();
    //     Self {
    //         name: name.to_string(),
    //         address: vec![],
    //         cname: None,
    //         txt: Vec::new(),
    //         iat: 0,
    //         ttl: Some(ttl),
    //     }
    // }
}

#[async_trait::async_trait]
pub trait NsProvider: 'static + Send + Sync {
    fn get_id(&self) -> String;

    fn methods(&self) -> MethodMatcher {
        MethodMatcher::Any
    }

    fn caps(&self) -> ResolverCaps {
        ResolverCaps::default()
    }

    fn requires_verification(&self, doc_type: &DidDocType) -> bool {
        doc_type != &DidDocType::Info
    }

    /// 该 (did, doc_type) 是否是 owner 递归的递归基：默认约定是
    /// `doc_type == "owner"`（设计文档第 6.4 节）。method 有自证根
    /// （例如 did:dev 用 DID 自身的 key）时可以覆盖。
    fn is_owner_root(
        &self,
        _did: &DID,
        doc_type: &DidDocType,
        _published: Option<&PublishedState>,
    ) -> bool {
        doc_type == &DidDocType::Owner
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

    async fn resolve_published_state(
        &self,
        _did: &DID,
        _doc_type: &DidDocType,
    ) -> NSResult<Option<PublishedState>> {
        Ok(None)
    }

    async fn fetch_document_body(&self, doc_ref: &DocumentRef) -> NSResult<Option<DocumentBody>> {
        Ok(doc_ref
            .inline_document
            .as_ref()
            .map(|doc| DocumentBody::anchored(doc.clone(), Some(self.get_id()))))
    }

    async fn query_self_signed_candidates(
        &self,
        did: &DID,
        doc_type: &DidDocType,
    ) -> NSResult<Vec<DocumentBody>> {
        let legacy_doc_type = if doc_type == &DidDocType::Zone {
            None
        } else {
            Some(doc_type.clone())
        };
        let doc = self.query_did(did, legacy_doc_type, None).await?;
        Ok(vec![DocumentBody::anchored(doc, Some(self.get_id()))])
    }

    async fn query_unauthenticated_info(
        &self,
        did: &DID,
        doc_type: &DidDocType,
    ) -> NSResult<Vec<DocumentBody>> {
        let doc = self.query_did(did, Some(doc_type.clone()), None).await?;
        Ok(vec![DocumentBody::unauthenticated(
            doc,
            Some(self.get_id()),
        )])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use buckyos_kit::buckyos_get_unix_timestamp;
    use jsonwebtoken::{DecodingKey, EncodingKey};
    use serde_json::json;

    // 测试辅助函数：创建测试用的密钥和 ZoneBootConfig
    fn create_test_zone_boot_config() -> (
        EncodingKey,
        DecodingKey,
        jsonwebtoken::jwk::Jwk,
        ZoneBootConfig,
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

        let zone_boot_config = ZoneBootConfig {
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

        (private_key, public_key, public_key_jwk, zone_boot_config)
    }

    // 测试辅助函数：创建测试用的 DeviceMiniConfig
    fn create_test_device_mini_config(owner_private_key: &EncodingKey) -> String {
        let mini_config = DeviceMiniConfig {
            name: "device1".to_string(),
            x: "5bUuyWLOKyCre9az_IhJVIuOw8bA0gyKjstcYGHbaPE".to_string(),
            rtcp_port: None,
            exp: buckyos_get_unix_timestamp() + 3600 * 24 * 365,
            extra_info: HashMap::new(),
        };

        mini_config.to_jwt(owner_private_key).unwrap()
    }

    #[test]
    fn test_parse_txt_record_to_did_documents() {
        // 准备测试数据
        let (private_key, _public_key, public_key_jwk, zone_boot_config) =
            create_test_zone_boot_config();

        // 编码 ZoneBootConfig 为 JWT
        let boot_jwt = zone_boot_config.encode(Some(&private_key)).unwrap();

        // 创建设备 JWT
        let device_jwt = create_test_device_mini_config(&private_key);

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

        let zone_boot_config = did_documents.get("zone").unwrap();
        let did_doc = parse_did_doc(zone_boot_config.clone()).unwrap();
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
}
