//! HTTP 载体与路由(设计稿 §2.4、§2.5;wire 见 doc/http_did_resolver_api.md)。
//!
//! - `DocumentLocation` / `build_document_request_url`:目录 / 路径 / resolver API /
//!   兼容路由的分类发生在拼 URL 之前,query 不参与目录判断,尾斜杠不被提前抹掉;
//! - `document_answer_from_http`:从 HTTP 状态、信封、裸 body 和
//!   `BuckyOS-DID-Document` 响应头统一提取 [`SourceAnswer`];
//! - 所有读取 / 解码都在同一预算内,取得 header Card 不要求完整下载大业务 body。

use super::budget::Budget;
use super::publish_info::{Boundary, DocumentStatus, PublishInfo, PublishRecord};
use super::revision::{normalize_hash, validate_compact_jwt, DocRevision, ParsedDocument, Revision};
use super::source::{Carrier, SourceAnswer, SourceRef};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use log::{debug, warn};
use name_lib::{DidDocType, EncodedDocument, NSError, NSResult, DID};
use reqwest::header::{HeaderMap, ACCEPT, CONTENT_TYPE};
use reqwest::{redirect, Client, StatusCode, Url};
use serde::Deserialize;
use serde_json::Value;
use std::time::Duration;

pub const DID_DOCUMENT_HEADER: &str = "BuckyOS-DID-Document";
pub const RESOLVE_BUDGET_HEADER: &str = "BuckyOS-Resolve-Budget-Ms";
pub const RESOLVE_NO_ZONE_LOCK_HEADER: &str = "BuckyOS-Resolve-No-Zone-Lock";
pub const DID_RESOLUTION_ACCEPT: &str = "application/did-resolution";
/// 单个响应头值上限:超限按"该来源回答损坏"处理,不视为缺席。
pub const MAX_HEADER_DOCUMENT_BYTES: usize = 16 * 1024;
pub const MAX_HTTP_DID_BODY_BYTES: usize = super::revision::MAX_DOCUMENT_BYTES + 64 * 1024;
pub const MAX_RESOLVER_REDIRECTS: usize = 5;

/// 构造 HTTP 客户端:连接超时、有限重定向、重定向不得从 https 降级到 http。
pub fn build_http_client(connect_timeout: Duration) -> Client {
    let policy = redirect::Policy::custom(|attempt| {
        if attempt.previous().len() > MAX_RESOLVER_REDIRECTS {
            return attempt.error("too many redirects");
        }
        let downgrade = attempt
            .previous()
            .iter()
            .any(|url| url.scheme() == "https")
            && attempt.url().scheme() != "https";
        if downgrade {
            return attempt.error("redirect downgrades https to http");
        }
        attempt.follow()
    });
    Client::builder()
        .redirect(policy)
        .connect_timeout(connect_timeout)
        .build()
        .unwrap_or_else(|err| {
            warn!("build HTTP DID client failed ({}), using default", err);
            Client::new()
        })
}

// ---------- 路由 ----------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocationKind {
    /// `/1.0/identifiers/{did}?type=` resolver API(信封回答)。
    ResolverApi,
    /// 目录型:根域名 well-known 或以 `/` 结尾的 HTTP 目录,补 `did.json`。
    Directory,
    /// 路径型对象 URL:直取原 URL,默认不构造 type 参数。
    ObjectUrl,
    /// 兼容路由:`/{path}/did.json`、`/{path}/{doc_type}.json`。
    LegacyStatic,
}

/// 已知 method / provider 的发布位置,不来自响应中自报的信任字段。
#[derive(Debug, Clone)]
pub struct DocumentLocation {
    pub kind: LocationKind,
    pub url: Url,
    pub did: DID,
    /// 该入口的默认逻辑类型:路径对象为 `did-object`,目录为 `zone`(did.json)。
    pub default_doc_type: DidDocType,
}

impl DocumentLocation {
    pub fn resolver_api(base: Url, did: DID) -> Self {
        Self {
            kind: LocationKind::ResolverApi,
            url: base,
            did,
            default_doc_type: DidDocType::Zone,
        }
    }

    pub fn directory(url: Url, did: DID) -> Self {
        Self {
            kind: LocationKind::Directory,
            url,
            did,
            default_doc_type: DidDocType::Zone,
        }
    }

    pub fn object(url: Url, did: DID) -> Self {
        Self {
            kind: LocationKind::ObjectUrl,
            url,
            did,
            default_doc_type: DidDocType::DidObject,
        }
    }

    pub fn legacy_static(url: Url, did: DID) -> Self {
        Self {
            kind: LocationKind::LegacyStatic,
            url,
            did,
            default_doc_type: DidDocType::Zone,
        }
    }

    /// HTTP Object URL:看 `URL.path` 是否以 `/` 结尾,query 不参与,不 trim。
    pub fn from_object_url(url: &str, did: DID) -> NSResult<Self> {
        let parsed = Url::parse(url)
            .map_err(|err| NSError::InvalidParam(format!("invalid object url {}: {}", url, err)))?;
        if parsed.path().ends_with('/') {
            Ok(Self::directory(parsed, did))
        } else {
            Ok(Self::object(parsed, did))
        }
    }

    pub fn is_directory(&self) -> bool {
        self.kind == LocationKind::Directory
    }

    fn existing_type_selector(&self) -> Option<String> {
        self.url
            .query_pairs()
            .find(|(k, _)| k == "type")
            .map(|(_, v)| v.to_string())
    }

    /// 所有分支先校验原 URL 已有的 `type`:与调用方要求冲突时明确拒绝。
    pub fn check_input_type_selector(&self, doc_type: Option<&DidDocType>) -> NSResult<()> {
        let Some(existing) = self.existing_type_selector() else {
            return Ok(());
        };
        if let Some(requested) = doc_type {
            if existing != requested.as_str() {
                return Err(NSError::InvalidParam(format!(
                    "object url already selects type {} but {} was requested",
                    existing, requested
                )));
            }
        }
        Ok(())
    }

    /// 入口未指定 doc_type 时,从输入 URL 的显式 `type` 归一实际类型。
    pub fn normalized_doc_type(&self, doc_type: Option<&DidDocType>) -> DidDocType {
        doc_type
            .cloned()
            .or_else(|| self.existing_type_selector().map(DidDocType::from))
            .unwrap_or_else(|| self.default_doc_type.clone())
    }

    /// 显式非默认类型才需要选择器。
    pub fn non_default_type_selector(&self, doc_type: Option<&DidDocType>) -> Option<String> {
        let doc_type = doc_type?;
        if *doc_type == self.default_doc_type {
            return None;
        }
        Some(doc_type.as_str().to_string())
    }

    /// 目录规则:默认补 `did.json`;显式类型用 `{doc_type}.json`;保留原 query。
    pub fn directory_document_url(&self, selector: Option<&str>) -> NSResult<Url> {
        let file = match selector {
            Some(selector) => {
                validate_doc_type_segment(selector)?;
                format!("{}.json", selector)
            }
            None => "did.json".to_string(),
        };
        let mut url = self.url.clone();
        let path = format!("{}{}", url.path(), file);
        url.set_path(&path);
        Ok(url)
    }

    pub fn existing_document_url(&self, doc_type: Option<&DidDocType>) -> NSResult<Url> {
        match self.kind {
            LocationKind::ResolverApi => {
                let mut url = self.url.clone();
                let path = format!(
                    "{}/1.0/identifiers/{}",
                    url.path().trim_end_matches('/'),
                    self.did.to_string()
                );
                url.set_path(&path);
                if let Some(doc_type) = doc_type {
                    url.query_pairs_mut().append_pair("type", doc_type.as_str());
                }
                Ok(url)
            }
            LocationKind::LegacyStatic => {
                let stem = match doc_type {
                    Some(DidDocType::Zone) | Some(DidDocType::DidObject) | None => "did".to_string(),
                    Some(other) => {
                        validate_doc_type_segment(other.as_str())?;
                        other.as_str().to_string()
                    }
                };
                let mut url = self.url.clone();
                let path = format!("{}/{}.json", url.path().trim_end_matches('/'), stem);
                url.set_path(&path);
                Ok(url)
            }
            _ => Err(NSError::InvalidState("not a resolver/legacy location".to_string())),
        }
    }
}

fn validate_doc_type_segment(doc_type: &str) -> NSResult<()> {
    if doc_type.is_empty()
        || !doc_type
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-')
    {
        return Err(NSError::InvalidParam(format!(
            "invalid DID document type: {}",
            doc_type
        )));
    }
    Ok(())
}

/// 使用 URL query API 设置 `type`,保留无关参数;与已有 `type` 冲突时拒绝,不重复追加。
pub fn with_document_type_query(url: &Url, selector: &str) -> NSResult<Url> {
    validate_doc_type_segment(selector)?;
    if let Some((_, existing)) = url.query_pairs().find(|(k, _)| k == "type") {
        if existing == selector {
            return Ok(url.clone());
        }
        return Err(NSError::InvalidParam(format!(
            "object url already selects type {} (requested {})",
            existing, selector
        )));
    }
    let mut url = url.clone();
    url.query_pairs_mut().append_pair("type", selector);
    Ok(url)
}

/// 设计稿 §2.4 的 `build_document_request_url`。
pub fn build_document_request_url(
    location: &DocumentLocation,
    doc_type: Option<&DidDocType>,
) -> NSResult<Url> {
    location.check_input_type_selector(doc_type)?;
    match location.kind {
        LocationKind::ResolverApi | LocationKind::LegacyStatic => {
            location.existing_document_url(doc_type)
        }
        LocationKind::Directory => {
            let selector = location.non_default_type_selector(doc_type);
            location.directory_document_url(selector.as_deref())
        }
        LocationKind::ObjectUrl => match location.non_default_type_selector(doc_type) {
            Some(selector) => with_document_type_query(&location.url, &selector),
            None => Ok(location.url.clone()),
        },
    }
}

// ---------- 响应读取 ----------

#[derive(Debug)]
pub struct HttpResponseParts {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub final_url: Option<Url>,
    pub body: Vec<u8>,
    /// body 超限且响应头已携带文档时不再读取 body。
    pub body_skipped: bool,
}

impl HttpResponseParts {
    pub fn for_test(status: StatusCode, headers: HeaderMap, body: &str) -> Self {
        Self {
            status,
            headers,
            final_url: None,
            body: body.as_bytes().to_vec(),
            body_skipped: false,
        }
    }

    pub fn content_type(&self) -> Option<&str> {
        self.headers.get(CONTENT_TYPE).and_then(|v| v.to_str().ok())
    }
}

/// 在预算内读取响应;取得 header Card 不要求完整下载无关的大业务 body。
pub async fn read_response(resp: reqwest::Response, budget: &Budget) -> NSResult<HttpResponseParts> {
    let status = resp.status();
    let headers = resp.headers().clone();
    let final_url = Some(resp.url().clone());
    let has_header_doc = headers.get(DID_DOCUMENT_HEADER).is_some();
    let too_large = resp
        .content_length()
        .is_some_and(|len| len > MAX_HTTP_DID_BODY_BYTES as u64);
    if too_large {
        if has_header_doc {
            return Ok(HttpResponseParts {
                status,
                headers,
                final_url,
                body: Vec::new(),
                body_skipped: true,
            });
        }
        return Err(NSError::Failed(format!(
            "HttpDidBodyTooLarge: response exceeds {} bytes",
            MAX_HTTP_DID_BODY_BYTES
        )));
    }
    let mut resp = resp;
    let mut body = Vec::new();
    let mut skipped = false;
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|err| NSError::Failed(format!("read response failed: {}", err)))?
    {
        budget.check()?;
        if body.len().saturating_add(chunk.len()) > MAX_HTTP_DID_BODY_BYTES {
            if has_header_doc {
                skipped = true;
                body.clear();
                break;
            }
            return Err(NSError::Failed(format!(
                "HttpDidBodyTooLarge: response exceeds {} bytes",
                MAX_HTTP_DID_BODY_BYTES
            )));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(HttpResponseParts {
        status,
        headers,
        final_url,
        body,
        body_skipped: skipped,
    })
}

// ---------- 响应头载体 ----------

/// `BuckyOS-DID-Document: jwt <compact> | json <base64url>`。缺席返回 None;
/// 重复出现、超限、格式错误报错(损坏,不伪装成缺席)。
pub fn decode_declared_document_header(headers: &HeaderMap) -> NSResult<Option<EncodedDocument>> {
    let mut values = headers.get_all(DID_DOCUMENT_HEADER).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(NSError::InvalidData);
    }
    if value.len() > MAX_HEADER_DOCUMENT_BYTES {
        return Err(NSError::Failed(format!(
            "{} exceeds {} bytes",
            DID_DOCUMENT_HEADER, MAX_HEADER_DOCUMENT_BYTES
        )));
    }
    let text = value
        .to_str()
        .map_err(|_| NSError::Failed(format!("{} is not ASCII", DID_DOCUMENT_HEADER)))?
        .trim();
    let (kind, data) = text
        .split_once(' ')
        .ok_or_else(|| NSError::Failed(format!("{} missing kind", DID_DOCUMENT_HEADER)))?;
    let data = data.trim();
    match kind.to_ascii_lowercase().as_str() {
        "jwt" => {
            validate_compact_jwt(data)?;
            Ok(Some(EncodedDocument::Jwt(data.to_string())))
        }
        "json" => {
            let bytes = URL_SAFE_NO_PAD
                .decode(data)
                .map_err(|err| NSError::Failed(format!("{} base64url: {}", DID_DOCUMENT_HEADER, err)))?;
            let value: Value = serde_json::from_slice(&bytes)
                .map_err(|err| NSError::Failed(format!("{} json: {}", DID_DOCUMENT_HEADER, err)))?;
            if !value.is_object() {
                return Err(NSError::Failed(format!("{} is not a JSON object", DID_DOCUMENT_HEADER)));
            }
            Ok(Some(EncodedDocument::JsonLd(value)))
        }
        other => Err(NSError::Failed(format!(
            "{} unsupported kind {}",
            DID_DOCUMENT_HEADER, other
        ))),
    }
}

/// 编码响应头值(服务端 / 测试使用)。
pub fn encode_declared_document_header(document: &EncodedDocument) -> String {
    match document {
        EncodedDocument::Jwt(jwt) => format!("jwt {}", jwt),
        EncodedDocument::JsonLd(value) => {
            format!("json {}", URL_SAFE_NO_PAD.encode(value.to_string().as_bytes()))
        }
    }
}

// ---------- 信封 ----------

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ResolutionMetadataWire {
    #[serde(default)]
    pub content_type: Option<String>,
    #[serde(default)]
    pub error: Option<Value>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SelectedVersionWire {
    #[serde(default)]
    pub iat: Option<u64>,
    #[serde(default)]
    pub doc_hash: Option<String>,
    #[serde(default = "default_published")]
    pub published: bool,
}

fn default_published() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct BuckyOSMetadataWire {
    #[serde(default)]
    pub doc_type: Option<String>,
    #[serde(default)]
    pub document_status: Option<String>,
    #[serde(default)]
    pub document_version: Option<u64>,
    #[serde(default)]
    pub doc_hash: Option<String>,
    #[serde(default)]
    pub latest_iat: Option<u64>,
    #[serde(default)]
    pub selected_version: Option<SelectedVersionWire>,
    #[serde(default)]
    pub boundary_confirmed: Option<bool>,
    #[serde(default)]
    pub effective_owner: Option<String>,
    #[serde(default)]
    pub migration_target: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub checked_at: Option<u64>,
    #[serde(default)]
    pub valid_until: Option<u64>,
    #[serde(default)]
    pub historical_query_supported: Option<bool>,
    #[serde(default)]
    pub authority_seq: Option<u64>,
    #[serde(default)]
    pub registry_version: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct DocumentMetadataWire {
    #[serde(default)]
    pub version_id: Option<Value>,
    #[serde(default)]
    pub deactivated: Option<bool>,
    #[serde(default)]
    pub buckyos: Option<BuckyOSMetadataWire>,
}

/// W3C DID Resolution Result 信封(宽松解析)。
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct DidResolutionEnvelope {
    #[serde(default)]
    pub did_resolution_metadata: Option<ResolutionMetadataWire>,
    #[serde(default)]
    pub did_document: Option<Value>,
    #[serde(default)]
    pub did_document_metadata: Option<DocumentMetadataWire>,
}

impl DidResolutionEnvelope {
    pub fn document(&self) -> NSResult<Option<EncodedDocument>> {
        match self.did_document.as_ref() {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(jwt)) => {
                validate_compact_jwt(jwt)?;
                Ok(Some(EncodedDocument::Jwt(jwt.clone())))
            }
            Some(value) if value.is_object() => Ok(Some(EncodedDocument::JsonLd(value.clone()))),
            Some(_) => Err(NSError::Failed("didDocument is neither object nor JWT".to_string())),
        }
    }

    pub fn error_code(&self) -> Option<String> {
        let error = self.did_resolution_metadata.as_ref()?.error.as_ref()?;
        match error {
            Value::Null => None,
            Value::String(code) => Some(code.clone()),
            Value::Object(map) => map
                .get("code")
                .and_then(|c| c.as_str())
                .map(String::from)
                .or_else(|| Some(error.to_string())),
            other => Some(other.to_string()),
        }
    }

    pub fn buckyos(&self) -> Option<&BuckyOSMetadataWire> {
        self.did_document_metadata.as_ref()?.buckyos.as_ref()
    }
}

enum DetectedBody {
    Empty,
    Envelope(Box<DidResolutionEnvelope>),
    Document(EncodedDocument),
    /// 普通业务内容(HTML / 媒体 / 非文档 JSON)。
    Legacy,
}

fn detect_body(body: &[u8], content_type: Option<&str>) -> DetectedBody {
    let Ok(text) = std::str::from_utf8(body) else {
        return DetectedBody::Legacy;
    };
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return DetectedBody::Empty;
    }
    let looks_json = content_type
        .map(|ct| ct.to_ascii_lowercase())
        .map_or(false, |ct| ct.contains("json") || ct.contains("did"));
    if trimmed.starts_with('{') {
        match serde_json::from_str::<Value>(trimmed) {
            Ok(Value::Object(map)) => {
                let is_envelope = map.contains_key("didDocument")
                    || map.contains_key("didDocumentMetadata")
                    || map.contains_key("didResolutionMetadata");
                if is_envelope {
                    match serde_json::from_value::<DidResolutionEnvelope>(Value::Object(map)) {
                        Ok(envelope) => DetectedBody::Envelope(Box::new(envelope)),
                        Err(_) => DetectedBody::Legacy,
                    }
                } else {
                    DetectedBody::Document(EncodedDocument::JsonLd(Value::Object(map)))
                }
            }
            _ => DetectedBody::Legacy,
        }
    } else if trimmed.starts_with('"') {
        match serde_json::from_str::<Value>(trimmed) {
            Ok(Value::String(jwt)) if validate_compact_jwt(&jwt).is_ok() => {
                DetectedBody::Document(EncodedDocument::Jwt(jwt))
            }
            _ => DetectedBody::Legacy,
        }
    } else if validate_compact_jwt(trimmed).is_ok() && !trimmed.contains(char::is_whitespace) {
        DetectedBody::Document(EncodedDocument::Jwt(trimmed.to_string()))
    } else {
        let _ = looks_json;
        DetectedBody::Legacy
    }
}

/// 从信封建立发布信息。`requested_doc_type` 与 `docType` 冲突视为损坏。
fn publish_info_from_envelope(
    envelope: &DidResolutionEnvelope,
    did: &DID,
    requested_doc_type: &DidDocType,
    revision: &Revision,
    status: StatusCode,
    body_revision: Option<&DocRevision>,
) -> NSResult<Option<PublishInfo>> {
    let Some(buckyos) = envelope.buckyos() else {
        // 没有 buckyos 块:只有 deactivated 标记可用。
        let deactivated = envelope
            .did_document_metadata
            .as_ref()
            .and_then(|m| m.deactivated)
            .unwrap_or(false);
        if deactivated || status == StatusCode::GONE {
            return Ok(Some(
                PublishInfo::new(did.clone(), requested_doc_type.clone(), revision.clone())
                    .with_status(&DocumentStatus::Revoked, None, None),
            ));
        }
        return Ok(None);
    };
    let actual_doc_type = buckyos
        .doc_type
        .as_deref()
        .map(DidDocType::from)
        .unwrap_or_else(|| requested_doc_type.clone());
    if actual_doc_type != *requested_doc_type && !matches!(requested_doc_type, DidDocType::Custom(_)) {
        // 调用方已指定类型时必须一致;None 归一在调用前完成。
        return Err(NSError::Failed(format!(
            "response docType {} does not match requested {}",
            actual_doc_type, requested_doc_type
        )));
    }
    let Some(status_str) = buckyos.document_status.as_deref() else {
        if status == StatusCode::GONE {
            return Ok(Some(
                PublishInfo::new(did.clone(), actual_doc_type, revision.clone())
                    .with_status(&DocumentStatus::Revoked, None, None),
            ));
        }
        if status == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        // 没有 documentStatus 但有 docHash / documentVersion:按 active 处理。
        if buckyos.doc_hash.is_none() && buckyos.document_version.is_none() {
            return Ok(None);
        }
        return build_publish_info(
            buckyos,
            did,
            actual_doc_type,
            revision,
            DocumentStatus::Active,
            body_revision,
        )
        .map(Some);
    };
    let document_status = DocumentStatus::parse(status_str)
        .ok_or_else(|| NSError::Failed(format!("unknown documentStatus {}", status_str)))?;
    // 状态与 HTTP 状态码一致性:revoked / tombstoned 期望 410,missing 期望 404。
    match (&document_status, status) {
        (DocumentStatus::Revoked | DocumentStatus::Tombstoned, s)
            if s != StatusCode::GONE && s != StatusCode::OK => {
            return Err(NSError::Failed(format!(
                "{} answered with HTTP {}",
                document_status, s
            )));
        }
        (DocumentStatus::Missing, s) if s != StatusCode::NOT_FOUND && s != StatusCode::OK => {
            return Err(NSError::Failed(format!("missing answered with HTTP {}", s)));
        }
        (DocumentStatus::Active | DocumentStatus::Invalid | DocumentStatus::Expired | DocumentStatus::Migrated, s)
            if !s.is_success() => {
            return Err(NSError::Failed(format!(
                "{} answered with HTTP {}",
                document_status, s
            )));
        }
        _ => {}
    }
    build_publish_info(buckyos, did, actual_doc_type, revision, document_status, body_revision).map(Some)
}

fn build_publish_info(
    buckyos: &BuckyOSMetadataWire,
    did: &DID,
    doc_type: DidDocType,
    revision: &Revision,
    document_status: DocumentStatus,
    body_revision: Option<&DocRevision>,
) -> NSResult<PublishInfo> {
    let migration_target = buckyos
        .migration_target
        .as_deref()
        .map(DID::from_str)
        .transpose()?;
    if document_status == DocumentStatus::Migrated && migration_target.is_none() {
        return Err(NSError::Failed("migrated response requires migrationTarget".to_string()));
    }
    if document_status == DocumentStatus::Invalid && buckyos.reason.is_none() {
        return Err(NSError::Failed("invalid response requires reason".to_string()));
    }
    let mut info = PublishInfo::new(did.clone(), doc_type, revision.clone()).with_status(
        &document_status,
        buckyos.reason.clone(),
        migration_target,
    );
    info.owner_binding = buckyos
        .effective_owner
        .as_deref()
        .map(DID::from_str)
        .transpose()?;
    info.checked_at = buckyos.checked_at.or(info.checked_at);
    info.valid_until = buckyos.valid_until;
    info.latest_iat = buckyos.latest_iat;

    let described_iat = buckyos
        .document_version
        .or_else(|| body_revision.map(|r| r.iat));
    let described_hash = buckyos
        .doc_hash
        .as_deref()
        .map(normalize_hash)
        .or_else(|| body_revision.map(|r| r.hash.clone()));

    match revision {
        Revision::Current => {
            if document_status == DocumentStatus::Active {
                let (Some(iat), Some(hash)) = (described_iat, described_hash) else {
                    return Err(NSError::Failed(
                        "active response requires a document or docHash".to_string(),
                    ));
                };
                if let Some(latest) = info.latest_iat {
                    if latest != iat {
                        return Err(NSError::Failed(format!(
                            "latestIat {} conflicts with documentVersion {}",
                            latest, iat
                        )));
                    }
                }
                info = info.with_record(PublishRecord::published(iat, hash, true));
            } else if let (Some(iat), Some(hash)) = (described_iat, described_hash) {
                // expired / migrated 等仍可描述最近发布版本(非当前有效)。
                let is_latest = info.latest_iat.map_or(false, |l| l == iat);
                info = info.with_record(PublishRecord::published(iat, hash, is_latest));
            }
        }
        Revision::Exact { iat, .. } => {
            let selected = buckyos.selected_version.as_ref();
            match selected {
                Some(selected) => {
                    let sel_iat = selected.iat.unwrap_or(*iat);
                    if selected.published {
                        let hash = selected.doc_hash.as_deref().ok_or_else(|| {
                            NSError::Failed("selectedVersion.published requires docHash".to_string())
                        })?;
                        let is_latest = info.latest_iat.map_or(false, |l| l == sel_iat);
                        info = info.with_record(PublishRecord::published(sel_iat, hash, is_latest));
                    } else {
                        info.records.push(PublishRecord::not_published(sel_iat));
                    }
                }
                None => {
                    // 旧 resolver 没有 selectedVersion:只能用 current 描述推导。
                    if let (Some(d_iat), Some(hash)) = (described_iat, described_hash) {
                        let is_latest = info.latest_iat.map_or(true, |l| l == d_iat);
                        info = info.with_record(PublishRecord::published(d_iat, hash, is_latest));
                    }
                }
            }
            if let (Some(l_iat), Some(hash)) = (info.latest_iat, buckyos.doc_hash.as_deref()) {
                if buckyos.document_version == Some(l_iat) && info.record_for(l_iat).is_none() {
                    info = info.with_record(PublishRecord::published(l_iat, hash, true));
                }
            }
        }
        Revision::Closest { before_iat } => {
            let confirmed = buckyos.boundary_confirmed.unwrap_or(false);
            let selected = match buckyos.selected_version.as_ref() {
                Some(selected) if selected.published => {
                    let sel_iat = selected.iat.ok_or_else(|| {
                        NSError::Failed("selectedVersion requires iat".to_string())
                    })?;
                    let hash = selected.doc_hash.as_deref().ok_or_else(|| {
                        NSError::Failed("selectedVersion requires docHash".to_string())
                    })?;
                    if sel_iat >= *before_iat {
                        return Err(NSError::Failed(format!(
                            "closest answer {} is not before {}",
                            sel_iat, before_iat
                        )));
                    }
                    let is_latest = info.latest_iat.map_or(false, |l| l == sel_iat);
                    info = info.with_record(PublishRecord::published(sel_iat, hash, is_latest));
                    Some(DocRevision::new(sel_iat, hash))
                }
                _ => None,
            };
            if confirmed || selected.is_some() {
                info.boundary = Some(Boundary {
                    query_iat: *before_iat,
                    selected,
                    confirmed,
                });
            }
            if let (Some(l_iat), Some(hash)) = (info.latest_iat, buckyos.doc_hash.as_deref()) {
                if buckyos.document_version == Some(l_iat) && info.record_for(l_iat).is_none() {
                    info = info.with_record(PublishRecord::published(l_iat, hash, true));
                }
            }
        }
    }
    Ok(info)
}

/// 设计稿 §2.5 `document_answer_from_http`:先处理 HTTP 状态和发布状态信封,
/// 再识别 body / header 文档;body/header 同时提供时必须是同一份文档。
pub fn document_answer_from_http(
    parts: &HttpResponseParts,
    sref: &SourceRef,
    did: &DID,
    doc_type: &DidDocType,
    revision: &Revision,
    allow_legacy_body: bool,
) -> SourceAnswer {
    let context = parts
        .final_url
        .as_ref()
        .map(|u| u.to_string())
        .unwrap_or_default();
    let status = parts.status;

    // 1. 状态分类。
    match status {
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => {
            return SourceAnswer::failure(sref.clone(), format!("HTTP {}", status)).with_context(context);
        }
        StatusCode::NOT_IMPLEMENTED => {
            let mut answer = SourceAnswer::unknown(
                sref.clone(),
                "此来源不支持指定版本/closest 查询",
                false,
            );
            answer.unsupported_history = true;
            return answer.with_context(context);
        }
        StatusCode::BAD_REQUEST => {
            let code = match detect_body(&parts.body, parts.content_type()) {
                DetectedBody::Envelope(envelope) => envelope.error_code(),
                _ => None,
            };
            return SourceAnswer::unknown(
                sref.clone(),
                format!("HTTP 400 {}", code.unwrap_or_default()),
                false,
            )
            .with_context(context);
        }
        s if s.is_server_error() || s == StatusCode::REQUEST_TIMEOUT || s == StatusCode::TOO_MANY_REQUESTS => {
            return SourceAnswer::failure(sref.clone(), format!("HTTP {}", s)).with_context(context);
        }
        s if !(s.is_success() || s == StatusCode::NOT_FOUND || s == StatusCode::GONE) => {
            return SourceAnswer::failure(sref.clone(), format!("unexpected HTTP {}", s)).with_context(context);
        }
        _ => {}
    }

    // 2. 响应头文档(损坏时报来源回答错误,不伪装缺席)。
    let header_doc = match decode_declared_document_header(&parts.headers) {
        Ok(doc) => doc,
        Err(err) => {
            return SourceAnswer::unknown(
                sref.clone(),
                format!("{} corrupt: {}", DID_DOCUMENT_HEADER, err),
                false,
            )
            .with_context(context);
        }
    };

    // 3. body。
    let mut answer = SourceAnswer::new(sref.clone()).with_context(context.clone());
    let detected = if parts.body_skipped {
        DetectedBody::Legacy
    } else {
        detect_body(&parts.body, parts.content_type())
    };
    let mut body_doc: Option<(EncodedDocument, Carrier)> = None;
    match detected {
        DetectedBody::Envelope(envelope) => {
            let doc = match envelope.document() {
                Ok(doc) => doc,
                Err(err) => {
                    return SourceAnswer::unknown(sref.clone(), format!("malformed envelope: {}", err), false)
                        .with_context(context);
                }
            };
            let body_revision = doc.as_ref().and_then(DocRevision::of);
            match publish_info_from_envelope(&envelope, did, doc_type, revision, status, body_revision.as_ref()) {
                Ok(Some(info)) => {
                    if let Some(doc) = doc.as_ref() {
                        if let (Some(rev), Some(record)) = (body_revision.as_ref(), info.record_for(body_revision.as_ref().map_or(0, |r| r.iat))) {
                            if let Some(hash) = record.hash.as_ref() {
                                if record.published && !rev.matches_hash(hash) {
                                    return SourceAnswer::unknown(
                                        sref.clone(),
                                        "inline document does not match docHash",
                                        false,
                                    )
                                    .with_context(context);
                                }
                            }
                        }
                        let _ = doc;
                    }
                    answer = answer.with_publish_info(info);
                }
                Ok(None) => {
                    if status == StatusCode::NOT_FOUND {
                        if envelope.buckyos().map_or(false, |b| b.historical_query_supported == Some(false)) {
                            answer.unsupported_history = true;
                        }
                        return SourceAnswer::no_answer(sref.clone(), "HTTP 404 without documentStatus")
                            .with_context(context);
                    }
                    if let Some(code) = envelope.error_code() {
                        return SourceAnswer::unknown(sref.clone(), format!("resolver error {}", code), false)
                            .with_context(context);
                    }
                    if doc.is_none() {
                        return SourceAnswer::unknown(sref.clone(), "envelope contains no document or status", false)
                            .with_context(context);
                    }
                }
                Err(err) => {
                    return SourceAnswer::unknown(sref.clone(), format!("malformed envelope: {}", err), false)
                        .with_context(context);
                }
            }
            if let Some(doc) = doc {
                body_doc = Some((doc, Carrier::Inline));
            }
        }
        DetectedBody::Document(doc) => {
            if status == StatusCode::NOT_FOUND {
                return SourceAnswer::no_answer(sref.clone(), "HTTP 404").with_context(context);
            }
            if status == StatusCode::GONE {
                answer = answer.with_publish_info(
                    PublishInfo::new(did.clone(), doc_type.clone(), revision.clone())
                        .with_status(&DocumentStatus::Revoked, None, None),
                );
            } else {
                body_doc = Some((doc, Carrier::Body));
            }
        }
        DetectedBody::Empty | DetectedBody::Legacy => {
            if status == StatusCode::NOT_FOUND {
                return SourceAnswer::no_answer(sref.clone(), "HTTP 404").with_context(context);
            }
            if status == StatusCode::GONE {
                answer = answer.with_publish_info(
                    PublishInfo::new(did.clone(), doc_type.clone(), revision.clone())
                        .with_status(&DocumentStatus::Revoked, None, None),
                );
            } else if header_doc.is_none() {
                if !allow_legacy_body || matches!(detected, DetectedBody::Empty) {
                    return SourceAnswer::unknown(sref.clone(), "response carries no DID document", false)
                        .with_context(context);
                }
                return SourceAnswer::unknown(
                    sref.clone(),
                    "business response without DID document or status",
                    false,
                )
                .with_context(context);
            }
        }
    }

    // 4. header 与 body 合并:同一文档幂等;不同文档拒绝该来源回答。
    if let Some(header_doc) = header_doc {
        match body_doc.as_ref() {
            Some((body, _)) => {
                if !same_exact_document(body, &header_doc) {
                    return SourceAnswer::unknown(
                        sref.clone(),
                        "body and header declare different DID documents",
                        false,
                    )
                    .with_context(context);
                }
            }
            None => {
                // 明确负状态不能被 header 覆盖:保留状态,不取 header 文档作为可用版本。
                let negative = answer
                    .publish_info
                    .as_ref()
                    .map_or(false, |info| info.is_disabled() || info.type_state.as_ref().map_or(false, |s| s.is_not_exist()));
                if !negative {
                    body_doc = Some((header_doc, Carrier::Header));
                }
            }
        }
    }

    // 5. 身份 / 类型绑定检查(提取不等于信任)。
    if let Some((doc, carrier)) = body_doc {
        match ParsedDocument::parse(&doc) {
            Ok(parsed) => {
                if let Err(reason) = parsed.matches(did, doc_type) {
                    return SourceAnswer::unknown(sref.clone(), format!("document binding: {}", reason), false)
                        .with_context(context);
                }
                answer = answer.with_body(doc, carrier);
            }
            Err(err) => {
                return SourceAnswer::unknown(sref.clone(), format!("unparsable document: {}", err), false)
                    .with_context(context);
            }
        }
    }
    if answer.is_unknown() {
        answer.reason = Some("response carries no DID document or status".to_string());
        answer.cacheable = false;
    }
    debug!(
        "http answer from {} for {}#{} {}: body={} info={} status={}",
        sref.id,
        did.to_string(),
        doc_type,
        revision,
        answer.body.is_some(),
        answer.publish_info.is_some(),
        status
    );
    answer
}

/// JWT 与 JSON 载体 hash 规则不同,混用视为不一致;JWT 原文不能重序列化后比较。
fn same_exact_document(a: &EncodedDocument, b: &EncodedDocument) -> bool {
    match (a, b) {
        (EncodedDocument::Jwt(x), EncodedDocument::Jwt(y)) => x == y,
        (EncodedDocument::JsonLd(_), EncodedDocument::JsonLd(_)) => {
            DocRevision::of(a) == DocRevision::of(b)
        }
        _ => false,
    }
}

/// 构造 resolver API 请求 URL:`{base}/1.0/identifiers/{did}?type=..[&versionId|&versionTime]`。
pub fn resolver_api_url(base: &str, did: &DID, doc_type: Option<&DidDocType>, revision: &Revision) -> NSResult<Url> {
    let base = base.trim().trim_end_matches('/');
    let base = if base.to_ascii_lowercase().starts_with("http://") || base.to_ascii_lowercase().starts_with("https://") {
        base.to_string()
    } else {
        format!("https://{}", base)
    };
    let mut url = Url::parse(&format!("{}/1.0/identifiers/{}", base, did.to_string()))
        .map_err(|err| NSError::InvalidParam(format!("invalid resolver base {}: {}", base, err)))?;
    {
        let mut query = url.query_pairs_mut();
        if let Some(doc_type) = doc_type {
            query.append_pair("type", doc_type.as_str());
        }
        match revision {
            Revision::Current => {}
            Revision::Exact { iat, .. } => {
                query.append_pair("versionId", &iat.to_string());
            }
            Revision::Closest { before_iat } => {
                query.append_pair("versionTime", &before_iat.to_string());
            }
        }
    }
    Ok(url)
}

pub fn accept_header() -> (reqwest::header::HeaderName, &'static str) {
    (ACCEPT, DID_RESOLUTION_ACCEPT)
}

#[cfg(test)]
mod tests {
    use super::super::source::SourceTier;
    use super::*;
    use reqwest::header::HeaderValue;
    use serde_json::json;

    fn did() -> DID {
        DID::new("web", "example.com")
    }

    fn sref() -> SourceRef {
        SourceRef::provider("test", SourceTier::Authority)
    }

    fn doc_json() -> Value {
        json!({"id": "did:web:example.com", "iat": 1000, "exp": 2_000_000_000, "marker": "x"})
    }

    #[test]
    fn directory_and_object_urls_follow_design_table() {
        let d = DocumentLocation::from_object_url("https://example.com/user/alice/", did()).unwrap();
        assert!(d.is_directory());
        assert_eq!(
            build_document_request_url(&d, None).unwrap().as_str(),
            "https://example.com/user/alice/did.json"
        );
        let q = DocumentLocation::from_object_url("https://example.com/user/alice/?lang=zh", did()).unwrap();
        assert_eq!(
            build_document_request_url(&q, None).unwrap().as_str(),
            "https://example.com/user/alice/did.json?lang=zh"
        );
        let o = DocumentLocation::from_object_url("https://example.com/user/alice", did()).unwrap();
        assert_eq!(
            build_document_request_url(&o, None).unwrap().as_str(),
            "https://example.com/user/alice"
        );
        assert_eq!(
            build_document_request_url(&o, Some(&DidDocType::DidObject)).unwrap().as_str(),
            "https://example.com/user/alice"
        );
        assert_eq!(
            build_document_request_url(&o, Some(&DidDocType::custom("profile"))).unwrap().as_str(),
            "https://example.com/user/alice?type=profile"
        );
        let typed = DocumentLocation::from_object_url("https://example.com/user/alice?type=xxxx&a=1", did()).unwrap();
        assert_eq!(
            build_document_request_url(&typed, Some(&DidDocType::custom("xxxx"))).unwrap().as_str(),
            "https://example.com/user/alice?type=xxxx&a=1"
        );
        assert!(build_document_request_url(&typed, Some(&DidDocType::custom("other"))).is_err());
        assert_eq!(typed.normalized_doc_type(None), DidDocType::custom("xxxx"));
    }

    #[test]
    fn header_carrier_roundtrip_and_corruption() {
        let doc = EncodedDocument::JsonLd(doc_json());
        let mut headers = HeaderMap::new();
        headers.insert(DID_DOCUMENT_HEADER, HeaderValue::from_str(&encode_declared_document_header(&doc)).unwrap());
        assert_eq!(decode_declared_document_header(&headers).unwrap(), Some(doc.clone()));
        headers.append(DID_DOCUMENT_HEADER, HeaderValue::from_static("jwt a.b.c"));
        assert!(decode_declared_document_header(&headers).is_err());
        assert_eq!(decode_declared_document_header(&HeaderMap::new()).unwrap(), None);

        let mut headers = HeaderMap::new();
        headers.insert(DID_DOCUMENT_HEADER, HeaderValue::from_static("jwt not-a-jwt"));
        let parts = HttpResponseParts::for_test(StatusCode::OK, headers, "<html></html>");
        let answer = document_answer_from_http(&parts, &sref(), &did(), &DidDocType::Zone, &Revision::current(), true);
        assert!(answer.is_unknown() && !answer.cacheable);
        assert!(answer.reason.unwrap().contains("corrupt"));
    }

    #[test]
    fn html_body_with_header_card_is_extracted_and_conflict_is_rejected() {
        let doc = EncodedDocument::JsonLd(doc_json());
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("text/html"));
        headers.insert(DID_DOCUMENT_HEADER, HeaderValue::from_str(&encode_declared_document_header(&doc)).unwrap());
        let parts = HttpResponseParts::for_test(StatusCode::OK, headers.clone(), "<html>hi</html>");
        let answer = document_answer_from_http(&parts, &sref(), &did(), &DidDocType::Zone, &Revision::current(), true);
        assert_eq!(answer.body, Some(doc.clone()));
        assert_eq!(answer.carrier, Carrier::Header);

        let same = HttpResponseParts::for_test(StatusCode::OK, headers.clone(), &doc.to_string());
        let answer = document_answer_from_http(&same, &sref(), &did(), &DidDocType::Zone, &Revision::current(), true);
        assert_eq!(answer.body, Some(doc.clone()));
        assert_eq!(answer.carrier, Carrier::Body);

        let other = json!({"id": "did:web:example.com", "iat": 1001, "exp": 2_000_000_000});
        let conflict = HttpResponseParts::for_test(StatusCode::OK, headers, &other.to_string());
        let answer = document_answer_from_http(&conflict, &sref(), &did(), &DidDocType::Zone, &Revision::current(), true);
        assert!(answer.is_unknown());
        assert!(answer.reason.unwrap().contains("different"));

        let plain = HttpResponseParts::for_test(StatusCode::OK, HeaderMap::new(), "<html>hi</html>");
        let answer = document_answer_from_http(&plain, &sref(), &did(), &DidDocType::Zone, &Revision::current(), true);
        assert!(answer.is_unknown() && !answer.cacheable);
    }

    #[test]
    fn envelope_states_map_to_publish_info() {
        let body = json!({
            "didDocument": doc_json(),
            "didDocumentMetadata": {"buckyos": {
                "docType": "zone", "documentStatus": "active", "documentVersion": 1000,
                "docHash": format!("sha256:{}", DocRevision::of(&EncodedDocument::JsonLd(doc_json())).unwrap().hash),
                "latestIat": 1000, "effectiveOwner": "did:web:owner.com"
            }}
        });
        let parts = HttpResponseParts::for_test(StatusCode::OK, HeaderMap::new(), &body.to_string());
        let answer = document_answer_from_http(&parts, &sref(), &did(), &DidDocType::Zone, &Revision::current(), false);
        let info = answer.publish_info.unwrap();
        assert_eq!(info.latest_revision().unwrap().iat, 1000);
        assert_eq!(info.owner_binding, Some(DID::new("web", "owner.com")));
        assert!(answer.body.is_some());

        let invalid = json!({"didDocumentMetadata": {"buckyos": {"documentStatus": "invalid", "reason": "device/zone mismatch"}}});
        let parts = HttpResponseParts::for_test(StatusCode::OK, HeaderMap::new(), &invalid.to_string());
        let answer = document_answer_from_http(&parts, &sref(), &did(), &DidDocType::Device, &Revision::current(), false);
        let info = answer.publish_info.unwrap();
        assert!(info.type_state.as_ref().unwrap().is_not_exist() && !info.is_disabled());
        assert!(!answer.failure && answer.cacheable);

        let missing = json!({"didDocumentMetadata": {"buckyos": {"documentStatus": "missing"}}});
        let parts = HttpResponseParts::for_test(StatusCode::NOT_FOUND, HeaderMap::new(), &missing.to_string());
        let answer = document_answer_from_http(&parts, &sref(), &did(), &DidDocType::Zone, &Revision::current(), false);
        assert!(answer.publish_info.is_some());

        let bare = HttpResponseParts::for_test(StatusCode::NOT_FOUND, HeaderMap::new(), "");
        let answer = document_answer_from_http(&bare, &sref(), &did(), &DidDocType::Zone, &Revision::current(), false);
        assert!(answer.is_unknown() && answer.cacheable && !answer.failure);

        let gone = json!({"didDocumentMetadata": {"deactivated": true, "buckyos": {"documentStatus": "revoked"}}});
        let parts = HttpResponseParts::for_test(StatusCode::GONE, HeaderMap::new(), &gone.to_string());
        let answer = document_answer_from_http(&parts, &sref(), &did(), &DidDocType::Zone, &Revision::current(), false);
        assert!(answer.publish_info.unwrap().is_disabled());

        let not_impl = HttpResponseParts::for_test(StatusCode::NOT_IMPLEMENTED, HeaderMap::new(), r#"{"didDocumentMetadata":{"buckyos":{"historicalQuerySupported":false}}}"#);
        let answer = document_answer_from_http(&not_impl, &sref(), &did(), &DidDocType::Zone, &Revision::closest(5), false);
        assert!(answer.unsupported_history && !answer.cacheable);

        let err = HttpResponseParts::for_test(StatusCode::BAD_GATEWAY, HeaderMap::new(), "boom");
        let answer = document_answer_from_http(&err, &sref(), &did(), &DidDocType::Zone, &Revision::current(), false);
        assert!(answer.failure && !answer.cacheable);
    }

    #[test]
    fn version_queries_parse_selected_version_and_boundary() {
        let exact = json!({"didDocumentMetadata": {"buckyos": {
            "documentStatus": "active", "latestIat": 2000, "documentVersion": 2000, "docHash": "bb",
            "selectedVersion": {"iat": 1000, "docHash": "aa", "published": true}
        }}});
        let parts = HttpResponseParts::for_test(StatusCode::OK, HeaderMap::new(), &exact.to_string());
        let answer = document_answer_from_http(&parts, &sref(), &did(), &DidDocType::Owner, &Revision::exact(1000, "aa"), false);
        let info = answer.publish_info.unwrap();
        assert!(info.satisfies(&Revision::exact(1000, "aa")).is_some());
        assert!(info.satisfies(&Revision::exact(1000, "zz")).is_none());
        assert_eq!(info.latest_revision().unwrap().iat, 2000);

        let closest = json!({"didDocumentMetadata": {"buckyos": {
            "documentStatus": "active", "latestIat": 2000,
            "selectedVersion": {"iat": 1000, "docHash": "aa", "published": true}, "boundaryConfirmed": true
        }}});
        let parts = HttpResponseParts::for_test(StatusCode::OK, HeaderMap::new(), &closest.to_string());
        let answer = document_answer_from_http(&parts, &sref(), &did(), &DidDocType::Owner, &Revision::closest(1500), false);
        let info = answer.publish_info.unwrap();
        assert_eq!(info.satisfies(&Revision::closest(1500)), Some(DocRevision::new(1000, "aa")));

        let empty = json!({"didDocumentMetadata": {"buckyos": {
            "documentStatus": "active", "latestIat": 2000, "selectedVersion": null, "boundaryConfirmed": true
        }}});
        let parts = HttpResponseParts::for_test(StatusCode::OK, HeaderMap::new(), &empty.to_string());
        let answer = document_answer_from_http(&parts, &sref(), &did(), &DidDocType::Owner, &Revision::closest(500), false);
        assert!(answer.publish_info.unwrap().closest_confirmed_empty(500));
    }

    #[test]
    fn resolver_url_carries_version_params() {
        let url = resolver_api_url("resolver.example.com", &DID::new("bns", "alice"), Some(&DidDocType::Owner), &Revision::closest(42)).unwrap();
        assert_eq!(url.as_str(), "https://resolver.example.com/1.0/identifiers/did:bns:alice?type=owner&versionTime=42");
        let url = resolver_api_url("http://127.0.0.1:3180/", &DID::new("bns", "alice"), Some(&DidDocType::Owner), &Revision::exact(7, "x")).unwrap();
        assert_eq!(url.as_str(), "http://127.0.0.1:3180/1.0/identifiers/did:bns:alice?type=owner&versionId=7");
    }
}
