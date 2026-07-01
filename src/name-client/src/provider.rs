use buckyos_kit::buckyos_get_unix_timestamp;
use jsonwebtoken::DecodingKey;
use name_lib::OwnerConfig;
use name_lib::*;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, net::IpAddr};

pub const DEFAULT_DID_DOC_TYPE: &str = "zone";

pub const DOC_TYPE_OWNER: &str = "owner";
pub const DOC_TYPE_INFO: &str = "info";

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
    pub document_status: DocumentStatus,
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
        doc_type: &str,
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

        let document_status = published
            .map(|state| state.document_status.clone())
            .unwrap_or(DocumentStatus::Active);
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
                deactivated: Some(document_status.is_terminal()),
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
        doc_type: &str,
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
        resolved
            .resolution_metadata
            .warnings
            .push(ResolveWarning::CacheFallback);
        resolved
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
    visited: Vec<(DID, String)>,
}

impl Default for ResolvePolicy {
    fn default() -> Self {
        Self {
            follow_migration: true,
            allow_self_signed_when_missing: false,
            allow_cache_when_authority_unavailable: true,
            max_depth: 8,
            visited: Vec::new(),
        }
    }
}

impl ResolvePolicy {
    pub fn for_authority_lookup(&self) -> Self {
        let mut policy = self.clone();
        policy.allow_self_signed_when_missing = false;
        policy.allow_cache_when_authority_unavailable = false;
        policy
    }

    pub fn descend(&self, did: &DID, doc_type: &str) -> NSResult<Self> {
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
        next.visited.push((did.clone(), doc_type.to_string()));
        Ok(next)
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

    fn requires_verification(&self, doc_type: &str) -> bool {
        doc_type != DOC_TYPE_INFO
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
        doc_type: Option<&str>,
        from_ip: Option<IpAddr>,
    ) -> NSResult<EncodedDocument>;

    async fn resolve_published_state(
        &self,
        _did: &DID,
        _doc_type: &str,
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
        doc_type: &str,
    ) -> NSResult<Vec<DocumentBody>> {
        let legacy_doc_type = if doc_type == DEFAULT_DID_DOC_TYPE {
            None
        } else {
            Some(doc_type)
        };
        let doc = self.query_did(did, legacy_doc_type, None).await?;
        Ok(vec![DocumentBody::anchored(doc, Some(self.get_id()))])
    }

    async fn query_unauthenticated_info(
        &self,
        did: &DID,
        doc_type: &str,
    ) -> NSResult<Vec<DocumentBody>> {
        let doc = self.query_did(did, Some(doc_type), None).await?;
        Ok(vec![DocumentBody::unauthenticated(
            doc,
            Some(self.get_id()),
        )])
    }
}

#[async_trait::async_trait]
pub trait NsUpdateProvider: 'static + Send + Sync {
    async fn update(&self, record_type: RecordType, record: NameInfo) -> NSResult<NameInfo>;
    async fn delete(&self, name: &str, record_type: RecordType) -> NSResult<Option<NameInfo>>;
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
