/*
基于https的NsProvider实现
初始化该Provider是，需要传入resolver的hostname
向https://resolver.example.com/1.0/identifiers/did:example:1234#doc_type发送http GET请求，获取did文档
*/

use crate::{
    DidDocType, DocumentRef, DocumentStatus, NameInfo, NsProvider, PublishedState, RecordType,
};
use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use log::{debug, info, warn};
use name_lib::{EncodedDocument, NSError, NSResult, DID};
use reqwest::{redirect, Client, StatusCode, Url};
use serde::Deserialize;
use serde_json::Value;
use std::net::IpAddr;

const DID_RESOLUTION_ACCEPT: &str = "application/did-resolution+json";
const MAX_DID_DOCUMENT_BYTES: usize = 2 * 1024 * 1024;
const MAX_HTTP_DID_BODY_BYTES: usize = MAX_DID_DOCUMENT_BYTES + 64 * 1024;
const MAX_RESOLVER_REDIRECTS: usize = 5;

#[derive(Debug)]
struct HttpDidPayload {
    status: StatusCode,
    content_type: Option<String>,
    final_url: Url,
    body: Vec<u8>,
}

#[derive(Debug)]
enum NormalizedHttpDidResponse {
    Document {
        document: EncodedDocument,
        envelope_metadata: Option<DidDocumentMetadataWire>,
    },
    PublishedState(PublishedState),
    NotApplicable,
    Negative {
        status: DocumentStatus,
        state: Option<PublishedState>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ContentTypeKind {
    Json,
    Jwt,
    Flexible,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DetectedShape {
    JsonDocument,
    JsonStringJwt,
    CompactJwt,
    ResolutionEnvelope,
}

impl DetectedShape {
    fn as_str(self) -> &'static str {
        match self {
            Self::JsonDocument => "json-document",
            Self::JsonStringJwt => "json-string-jwt",
            Self::CompactJwt => "compact-jwt",
            Self::ResolutionEnvelope => "resolution-envelope",
        }
    }

    fn is_json(self) -> bool {
        !matches!(self, Self::CompactJwt)
    }
}

enum DetectedBody {
    Document(EncodedDocument),
    Envelope(Box<DidResolutionResponseWire>),
}

/// Resolve DID documents through an HTTPS resolver endpoint.
pub struct BaseHttpProvider {
    resolver_host: String,
    client: Client,
    scheme: String,
}

impl BaseHttpProvider {
    fn build_client() -> NSResult<Client> {
        let policy = redirect::Policy::custom(|attempt| {
            if let Some(reason) = redirect_violation(attempt.previous(), attempt.url()) {
                return attempt.error(reason);
            }
            attempt.follow()
        });
        Client::builder()
            .redirect(policy)
            .build()
            .map_err(|err| NSError::Failed(format!("build HTTP DID client failed: {}", err)))
    }

    /// Create a provider with default https scheme.
    pub fn new(resolver_host: &str) -> Self {
        Self {
            resolver_host: resolver_host.to_string(),
            client: Self::build_client().expect("default HTTP DID client must be constructible"),
            scheme: "https".to_string(),
        }
    }

    /// Create with config json. Expected keys:
    /// - resolver_host: required, resolver hostname or http(s) base URL.
    /// - scheme: optional, defaults to https.
    pub fn new_with_config(config: Value) -> NSResult<Self> {
        let resolver_host = config
            .get("resolver_host")
            .and_then(|v| v.as_str())
            .ok_or_else(|| NSError::InvalidParam("resolver_host is required".to_string()))?;
        let scheme = config
            .get("scheme")
            .and_then(|v| v.as_str())
            .unwrap_or("https");

        Ok(Self {
            resolver_host: resolver_host.to_string(),
            client: Self::build_client()?,
            scheme: scheme.to_string(),
        })
    }

    fn build_url(&self, did: &DID, doc_type: Option<&DidDocType>) -> String {
        // Encode doc_type as %23doc_type so the resolver can receive it.
        let target = if let Some(doc_type) = doc_type {
            format!("{}?type={}", did.to_string(), doc_type.as_str())
        } else {
            did.to_string()
        };
        let resolver_base = self.resolver_base_url();
        format!("{}/1.0/identifiers/{}", resolver_base, target)
    }

    fn resolver_base_url(&self) -> String {
        let resolver_host = self.resolver_host.trim().trim_end_matches('/');
        let lower = resolver_host.to_ascii_lowercase();

        if lower.starts_with("http://") || lower.starts_with("https://") {
            resolver_host.to_string()
        } else {
            format!("{}://{}", self.scheme, resolver_host)
        }
    }

    fn published_state_request(&self, url: &str) -> reqwest::RequestBuilder {
        self.client
            .get(url)
            .header(reqwest::header::ACCEPT, DID_RESOLUTION_ACCEPT)
    }

    async fn read_payload(mut resp: reqwest::Response) -> NSResult<HttpDidPayload> {
        let status = resp.status();
        let content_type = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let final_url = resp.url().clone();

        if resp
            .content_length()
            .is_some_and(|length| length > MAX_HTTP_DID_BODY_BYTES as u64)
        {
            return Err(NSError::Failed(format!(
                "HttpDidBodyTooLarge: resolver response exceeds {} bytes",
                MAX_HTTP_DID_BODY_BYTES
            )));
        }

        let mut body = Vec::new();
        while let Some(chunk) = resp
            .chunk()
            .await
            .map_err(|err| NSError::Failed(format!("read resolver response failed: {}", err)))?
        {
            if body.len().saturating_add(chunk.len()) > MAX_HTTP_DID_BODY_BYTES {
                return Err(NSError::Failed(format!(
                    "HttpDidBodyTooLarge: resolver response exceeds {} bytes",
                    MAX_HTTP_DID_BODY_BYTES
                )));
            }
            body.extend_from_slice(&chunk);
        }

        Ok(HttpDidPayload {
            status,
            content_type,
            final_url,
            body,
        })
    }

    /// method-agnostic 的 HTTP DID 响应归一:状态码、Content-Type、信封、
    /// 裸 JSON/JWT 及资源限制只在这里处理。
    pub(crate) async fn parse_response(
        did: &DID,
        doc_type: Option<&DidDocType>,
        provider_id: &str,
        resp: reqwest::Response,
    ) -> NSResult<EncodedDocument> {
        let payload = Self::read_payload(resp).await?;
        let normalized = Self::normalize_payload(did, doc_type, provider_id, payload)?;
        Self::document_from_normalized(did, normalized)
    }

    /// 拆成纯函数（接收已经读出来的 status/body）方便直接用字面量测试，
    /// 与 `parse_published_state_body` 同一套路。
    pub(crate) fn parse_response_body(
        did: &DID,
        status: StatusCode,
        body: &str,
    ) -> NSResult<EncodedDocument> {
        let payload = HttpDidPayload::for_test(status, None, body.as_bytes().to_vec());
        let normalized = Self::normalize_payload(did, None, "http-provider-test", payload)?;
        Self::document_from_normalized(did, normalized)
    }

    /// 解析 `resolve_published_state` 的 HTTP 响应。协议见 `doc/http_did_resolver_api.md`：
    /// method-agnostic，任何 did:method 的 HTTP resolver 只要按这份信封应答，都能走这里，
    /// 状态机语义的复杂度在 resolver 那一侧，这里只是老老实实解析一个通用 JSON 信封。
    ///
    /// 拆成纯函数（接收已经读出来的 status/body，而不是 `reqwest::Response`）方便直接用字面量
    /// 状态码和 JSON 字符串写单测，不需要真的发 HTTP 请求。
    fn parse_published_state_body(
        did: &DID,
        doc_type: &DidDocType,
        status: StatusCode,
        body: &str,
    ) -> NSResult<Option<PublishedState>> {
        let payload = HttpDidPayload::for_test(status, None, body.as_bytes().to_vec());
        let normalized =
            Self::normalize_payload(did, Some(doc_type), "http-provider-test", payload)?;
        Self::published_state_from_normalized(did, doc_type, normalized)
    }

    fn normalize_payload(
        did: &DID,
        doc_type: Option<&DidDocType>,
        provider_id: &str,
        payload: HttpDidPayload,
    ) -> NSResult<NormalizedHttpDidResponse> {
        Self::validate_http_status(payload.status)?;
        let body = normalized_text_body(&payload)?;

        if body.is_empty() {
            if payload.status == StatusCode::NOT_FOUND {
                Self::log_response(did, doc_type, provider_id, &payload, "empty-404");
                return Ok(NormalizedHttpDidResponse::NotApplicable);
            }
            return Err(malformed("empty resolver response body"));
        }

        let detected = match detect_body(body) {
            Ok(detected) => detected,
            Err(_err) if payload.status == StatusCode::NOT_FOUND => {
                Self::log_response(did, doc_type, provider_id, &payload, "ordinary-404");
                return Ok(NormalizedHttpDidResponse::NotApplicable);
            }
            Err(err) => return Err(err),
        };
        let shape = match &detected {
            DetectedBody::Document(EncodedDocument::JsonLd(_)) => DetectedShape::JsonDocument,
            DetectedBody::Document(EncodedDocument::Jwt(_)) => {
                if body.starts_with('"') {
                    DetectedShape::JsonStringJwt
                } else {
                    DetectedShape::CompactJwt
                }
            }
            DetectedBody::Envelope(_) => DetectedShape::ResolutionEnvelope,
        };
        Self::warn_content_type_mismatch(&payload, shape);
        Self::log_response(did, doc_type, provider_id, &payload, shape.as_str());

        if payload.status == StatusCode::NOT_FOUND && !matches!(detected, DetectedBody::Envelope(_))
        {
            return Ok(NormalizedHttpDidResponse::NotApplicable);
        }
        if payload.status == StatusCode::GONE && !matches!(detected, DetectedBody::Envelope(_)) {
            return Err(malformed("410 response requires a status envelope"));
        }

        match detected {
            DetectedBody::Document(document) => Ok(NormalizedHttpDidResponse::Document {
                document,
                envelope_metadata: None,
            }),
            DetectedBody::Envelope(response) => {
                Self::normalize_envelope(did, doc_type, payload.status, *response)
            }
        }
    }

    fn normalize_envelope(
        did: &DID,
        requested_doc_type: Option<&DidDocType>,
        http_status: StatusCode,
        response: DidResolutionResponseWire,
    ) -> NSResult<NormalizedHttpDidResponse> {
        let resolution_error = response.resolution_error()?;
        let metadata = response.did_document_metadata.clone();
        let deactivated = metadata.as_ref().and_then(|meta| meta.deactivated);
        let buckyos = metadata.as_ref().and_then(|meta| meta.buckyos.as_ref());
        let status_str = buckyos.and_then(|meta| meta.document_status.as_deref());

        if status_str.is_none() {
            if http_status == StatusCode::NOT_FOUND {
                return Ok(NormalizedHttpDidResponse::NotApplicable);
            }
            if http_status == StatusCode::GONE {
                return Err(malformed(
                    "410 response requires revoked or tombstoned documentStatus",
                ));
            }
            if resolution_error.is_some() {
                return Err(malformed(
                    "successful response conflicts with didResolutionMetadata.error",
                ));
            }
            if deactivated == Some(true) {
                return Ok(NormalizedHttpDidResponse::Negative {
                    status: DocumentStatus::Revoked,
                    state: None,
                });
            }
            let Some(document) = response.document()? else {
                return Err(malformed(
                    "resolution envelope contains no document or status",
                ));
            };
            return Ok(NormalizedHttpDidResponse::Document {
                document,
                envelope_metadata: metadata,
            });
        }

        let document_status = parse_document_status(status_str.unwrap())?;
        validate_status_consistency(http_status, &document_status, deactivated, resolution_error)?;

        let state = Self::published_state_from_wire(
            did,
            requested_doc_type,
            document_status.clone(),
            response,
        )?;
        if matches!(
            document_status,
            DocumentStatus::Missing | DocumentStatus::Revoked | DocumentStatus::Tombstoned
        ) {
            Ok(NormalizedHttpDidResponse::Negative {
                status: document_status,
                state: Some(state),
            })
        } else {
            Ok(NormalizedHttpDidResponse::PublishedState(state))
        }
    }

    fn published_state_from_wire(
        did: &DID,
        requested_doc_type: Option<&DidDocType>,
        document_status: DocumentStatus,
        response: DidResolutionResponseWire,
    ) -> NSResult<PublishedState> {
        let document = response.document()?;
        let metadata = response
            .did_document_metadata
            .ok_or_else(|| malformed("documentStatus requires didDocumentMetadata"))?;
        let buckyos = metadata
            .buckyos
            .ok_or_else(|| malformed("documentStatus requires buckyos metadata"))?;

        if let (Some(requested), Some(actual)) = (requested_doc_type, buckyos.doc_type.as_deref()) {
            if actual != requested.as_str() {
                return Err(malformed("response docType does not match request"));
            }
        }

        if document_status == DocumentStatus::Missing && document.is_some() {
            return Err(malformed("missing response must not contain a document"));
        }

        let mut document_ref = document.map(DocumentRef::inline);
        if let Some(doc_ref) = document_ref.as_mut() {
            doc_ref.content_hash = buckyos.doc_hash.clone();
        } else if let Some(hash) = buckyos.doc_hash.as_ref() {
            document_ref = Some(DocumentRef {
                uri: None,
                content_hash: Some(hash.clone()),
                inline_document: None,
            });
        }
        if document_status == DocumentStatus::Active && document_ref.is_none() {
            return Err(malformed("active response requires a document or docHash"));
        }

        let version_id = metadata
            .version_id
            .as_deref()
            .map(|value| {
                value
                    .parse::<u64>()
                    .map_err(|_| malformed("versionId is not an unsigned integer"))
            })
            .transpose()?;
        if let (Some(version), Some(version_id)) = (buckyos.document_version, version_id) {
            if version != version_id {
                return Err(malformed("documentVersion conflicts with versionId"));
            }
        }
        let document_version = buckyos.document_version.or(version_id);

        let effective_owner = parse_optional_did(
            buckyos.effective_owner.as_deref(),
            "effectiveOwner is not a valid DID",
        )?;
        let migration_target = parse_optional_did(
            buckyos.migration_target.as_deref(),
            "migrationTarget is not a valid DID",
        )?;
        if document_status == DocumentStatus::Migrated && migration_target.is_none() {
            return Err(malformed("migrated response requires migrationTarget"));
        }

        Ok(PublishedState {
            did: did.clone(),
            doc_type: buckyos.doc_type.unwrap_or_else(|| {
                requested_doc_type
                    .map(ToString::to_string)
                    .unwrap_or_default()
            }),
            document_status,
            document_ref,
            document_version,
            effective_owner,
            authority_seq: buckyos.authority_seq,
            migration_target,
        })
    }

    fn document_from_normalized(
        did: &DID,
        normalized: NormalizedHttpDidResponse,
    ) -> NSResult<EncodedDocument> {
        match normalized {
            NormalizedHttpDidResponse::Document {
                document,
                envelope_metadata,
            } => {
                let _ = envelope_metadata;
                Ok(document)
            }
            NormalizedHttpDidResponse::PublishedState(state) => state
                .document_ref
                .and_then(|doc_ref| doc_ref.inline_document)
                .ok_or_else(|| malformed("published-state envelope contains no inline document")),
            NormalizedHttpDidResponse::NotApplicable => Err(NSError::NotFound(did.to_string())),
            NormalizedHttpDidResponse::Negative { status, .. } => match status {
                DocumentStatus::Missing | DocumentStatus::Expired => {
                    Err(NSError::NotFound(did.to_string()))
                }
                DocumentStatus::Revoked | DocumentStatus::Tombstoned | DocumentStatus::Migrated => {
                    Err(NSError::Disabled(format!(
                        "{} is {}",
                        did.to_string(),
                        document_status_name(&status)
                    )))
                }
                DocumentStatus::Active => Err(malformed("invalid negative active response")),
            },
        }
    }

    fn published_state_from_normalized(
        did: &DID,
        doc_type: &DidDocType,
        normalized: NormalizedHttpDidResponse,
    ) -> NSResult<Option<PublishedState>> {
        match normalized {
            NormalizedHttpDidResponse::PublishedState(state) => Ok(Some(state)),
            NormalizedHttpDidResponse::Negative { state, .. } => Ok(state),
            NormalizedHttpDidResponse::NotApplicable => Ok(None),
            NormalizedHttpDidResponse::Document { .. } => {
                warn!(
                    "HttpDidDocumentOnlyPublishedState: did_method={} doc_type={} response has no published state",
                    did.method, doc_type
                );
                Ok(None)
            }
        }
    }

    fn validate_http_status(status: StatusCode) -> NSResult<()> {
        match status {
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => Err(NSError::Forbid),
            StatusCode::REQUEST_TIMEOUT | StatusCode::TOO_MANY_REQUESTS => Err(NSError::Failed(
                format!("HttpDidRetryableStatus: resolver returned {}", status),
            )),
            status if status.is_server_error() => Err(NSError::Failed(format!(
                "HttpDidUpstreamStatus: resolver returned {}",
                status
            ))),
            status
                if status.is_success()
                    || status == StatusCode::NOT_FOUND
                    || status == StatusCode::GONE =>
            {
                Ok(())
            }
            status => Err(NSError::Failed(format!(
                "HttpDidUnexpectedStatus: resolver returned {}",
                status
            ))),
        }
    }

    fn warn_content_type_mismatch(payload: &HttpDidPayload, shape: DetectedShape) {
        let kind = classify_content_type(payload.content_type.as_deref());
        let mismatch = matches!(kind, ContentTypeKind::Json) && !shape.is_json()
            || matches!(kind, ContentTypeKind::Jwt) && shape.is_json();
        if mismatch {
            warn!(
                "HttpDidContentTypeMismatch: status={} content_type={} body_len={} detected_shape={} final_host={}",
                payload.status,
                payload.content_type.as_deref().unwrap_or("<missing>"),
                payload.body.len(),
                shape.as_str(),
                payload.final_url.host_str().unwrap_or("<unknown>")
            );
        }
    }

    fn log_response(
        did: &DID,
        doc_type: Option<&DidDocType>,
        provider_id: &str,
        payload: &HttpDidPayload,
        detected_shape: &str,
    ) {
        debug!(
            "{}",
            response_diagnostics(did, doc_type, provider_id, payload, detected_shape)
        );
    }
}

impl HttpDidPayload {
    fn for_test(status: StatusCode, content_type: Option<&str>, body: Vec<u8>) -> Self {
        Self {
            status,
            content_type: content_type.map(str::to_owned),
            final_url: Url::parse("https://resolver.example.test/1.0/identifiers/test").unwrap(),
            body,
        }
    }
}

fn malformed(detail: &str) -> NSError {
    NSError::Failed(format!("HttpDidMalformedResponse: {}", detail))
}

fn redirect_violation(previous: &[Url], next: &Url) -> Option<&'static str> {
    if previous.len() >= MAX_RESOLVER_REDIRECTS {
        return Some("resolver redirect limit exceeded");
    }
    if previous.iter().any(|previous| previous.scheme() == "https") && next.scheme() != "https" {
        return Some("resolver redirect attempted HTTPS downgrade");
    }
    None
}

fn response_diagnostics(
    did: &DID,
    doc_type: Option<&DidDocType>,
    provider_id: &str,
    payload: &HttpDidPayload,
    detected_shape: &str,
) -> String {
    format!(
        "HTTP DID response: status={} content_type={} body_len={} detected_shape={} final_host={} did_method={} doc_type={} provider_id={}",
        payload.status,
        payload.content_type.as_deref().unwrap_or("<missing>"),
        payload.body.len(),
        detected_shape,
        payload.final_url.host_str().unwrap_or("<unknown>"),
        did.method,
        doc_type.map(DidDocType::as_str).unwrap_or("<unspecified>"),
        provider_id
    )
}

fn normalized_text_body(payload: &HttpDidPayload) -> NSResult<&str> {
    if payload.body.len() > MAX_HTTP_DID_BODY_BYTES {
        return Err(NSError::Failed(format!(
            "HttpDidBodyTooLarge: resolver response exceeds {} bytes",
            MAX_HTTP_DID_BODY_BYTES
        )));
    }
    if payload.body.contains(&0) {
        return Err(malformed("resolver response contains NUL"));
    }
    let text = std::str::from_utf8(&payload.body)
        .map_err(|_| malformed("resolver response is not UTF-8"))?;
    let mut text = text.trim_matches(|ch: char| ch.is_ascii_whitespace());
    if let Some(without_bom) = text.strip_prefix('\u{feff}') {
        text = without_bom.trim_matches(|ch: char| ch.is_ascii_whitespace());
    }
    Ok(text)
}

fn detect_body(body: &str) -> NSResult<DetectedBody> {
    let first = body.as_bytes().first().copied();
    if matches!(first, Some(b'{') | Some(b'[') | Some(b'"')) {
        if let Ok(value) = serde_json::from_str::<Value>(body) {
            return match value {
                Value::Object(map) if is_resolution_envelope(&map) => {
                    let response = serde_json::from_value(Value::Object(map))
                        .map_err(|_| malformed("invalid DID resolution envelope"))?;
                    Ok(DetectedBody::Envelope(Box::new(response)))
                }
                Value::Object(map) => Ok(DetectedBody::Document(EncodedDocument::JsonLd(
                    Value::Object(map),
                ))),
                Value::String(jwt) => {
                    validate_compact_jwt(&jwt)?;
                    Ok(DetectedBody::Document(EncodedDocument::Jwt(jwt)))
                }
                _ => Err(malformed(
                    "JSON response is not a document object or JWT string",
                )),
            };
        }
    }

    validate_compact_jwt(body)?;
    Ok(DetectedBody::Document(EncodedDocument::Jwt(
        body.to_string(),
    )))
}

fn is_resolution_envelope(map: &serde_json::Map<String, Value>) -> bool {
    map.contains_key("didResolutionMetadata")
        || map.contains_key("didDocument")
        || map.contains_key("didDocumentMetadata")
}

fn validate_compact_jwt(jwt: &str) -> NSResult<()> {
    if !jwt.is_ascii() {
        return Err(malformed("compact JWT is not ASCII"));
    }
    let segments: Vec<&str> = jwt.split('.').collect();
    if segments.len() != 3 || segments.iter().any(|segment| segment.is_empty()) {
        return Err(malformed(
            "compact JWT must contain exactly three non-empty segments",
        ));
    }
    if segments.iter().any(|segment| {
        !segment
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    }) {
        return Err(malformed(
            "compact JWT contains invalid base64url characters",
        ));
    }
    let header = URL_SAFE_NO_PAD
        .decode(segments[0])
        .map_err(|_| malformed("compact JWT header is not base64url"))?;
    let payload = URL_SAFE_NO_PAD
        .decode(segments[1])
        .map_err(|_| malformed("compact JWT payload is not base64url"))?;
    if header.is_empty() || payload.is_empty() {
        return Err(malformed(
            "compact JWT header and payload must be non-empty",
        ));
    }
    let header: Value =
        serde_json::from_slice(&header).map_err(|_| malformed("compact JWT header is not JSON"))?;
    if !header.is_object() {
        return Err(malformed("compact JWT header is not a JSON object"));
    }
    Ok(())
}

fn classify_content_type(content_type: Option<&str>) -> ContentTypeKind {
    let Some(content_type) = content_type else {
        return ContentTypeKind::Unknown;
    };
    let media_type = content_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    match media_type.as_str() {
        "application/did-resolution"
        | "application/did-resolution+json"
        | "application/did+json"
        | "application/did+ld+json"
        | "application/json"
        | "application/ld+json" => ContentTypeKind::Json,
        "application/jwt" | "application/did+jwt" | "application/jose" => ContentTypeKind::Jwt,
        "text/plain" | "application/octet-stream" => ContentTypeKind::Flexible,
        other if other.ends_with("+json") => ContentTypeKind::Json,
        _ => ContentTypeKind::Unknown,
    }
}

fn parse_document_status(value: &str) -> NSResult<DocumentStatus> {
    match value {
        "active" => Ok(DocumentStatus::Active),
        "expired" => Ok(DocumentStatus::Expired),
        "missing" => Ok(DocumentStatus::Missing),
        "revoked" => Ok(DocumentStatus::Revoked),
        "tombstoned" => Ok(DocumentStatus::Tombstoned),
        "migrated" => Ok(DocumentStatus::Migrated),
        _ => Err(malformed("unknown documentStatus")),
    }
}

fn validate_status_consistency(
    http_status: StatusCode,
    document_status: &DocumentStatus,
    deactivated: Option<bool>,
    resolution_error: Option<&str>,
) -> NSResult<()> {
    let http_matches = match document_status {
        DocumentStatus::Active | DocumentStatus::Expired | DocumentStatus::Migrated => {
            http_status.is_success()
        }
        DocumentStatus::Missing => http_status == StatusCode::NOT_FOUND,
        DocumentStatus::Revoked | DocumentStatus::Tombstoned => http_status == StatusCode::GONE,
    };
    if !http_matches {
        return Err(malformed("HTTP status conflicts with documentStatus"));
    }

    if deactivated == Some(true)
        && !matches!(
            document_status,
            DocumentStatus::Revoked | DocumentStatus::Tombstoned
        )
    {
        return Err(malformed("deactivated=true conflicts with documentStatus"));
    }
    if deactivated == Some(false)
        && matches!(
            document_status,
            DocumentStatus::Revoked | DocumentStatus::Tombstoned
        )
    {
        return Err(malformed("deactivated=false conflicts with documentStatus"));
    }

    if let Some(error) = resolution_error {
        let compatible = match document_status {
            DocumentStatus::Missing => error.eq_ignore_ascii_case("notFound"),
            DocumentStatus::Revoked | DocumentStatus::Tombstoned => {
                error.eq_ignore_ascii_case("deactivated")
            }
            _ => false,
        };
        if !compatible {
            return Err(malformed(
                "didResolutionMetadata.error conflicts with documentStatus",
            ));
        }
    }
    Ok(())
}

fn parse_optional_did(value: Option<&str>, error: &str) -> NSResult<Option<DID>> {
    value
        .map(|value| {
            let mut parts = value.splitn(3, ':');
            let valid_shape = parts.next() == Some("did")
                && parts.next().is_some_and(|method| !method.is_empty())
                && parts.next().is_some_and(|id| !id.is_empty());
            if !valid_shape {
                return Err(malformed(error));
            }
            DID::from_str(value).map_err(|_| malformed(error))
        })
        .transpose()
}

fn document_status_name(status: &DocumentStatus) -> &'static str {
    match status {
        DocumentStatus::Missing => "missing",
        DocumentStatus::Active => "active",
        DocumentStatus::Revoked => "revoked",
        DocumentStatus::Expired => "expired",
        DocumentStatus::Migrated => "migrated",
        DocumentStatus::Tombstoned => "tombstoned",
    }
}

/// `doc/http_did_resolver_api.md` 第 3 节描述的响应信封，method-agnostic：任何 did:method 的
/// HTTP resolver 都应该按这个形状应答。
#[derive(Clone, Debug, Deserialize)]
struct DidResolutionResponseWire {
    #[serde(rename = "didResolutionMetadata", default)]
    did_resolution_metadata: Option<DidResolutionMetadataWire>,
    #[serde(rename = "didDocument", default)]
    did_document: Option<Value>,
    #[serde(rename = "didDocumentMetadata", default)]
    did_document_metadata: Option<DidDocumentMetadataWire>,
}

impl DidResolutionResponseWire {
    fn document(&self) -> NSResult<Option<EncodedDocument>> {
        match self.did_document.as_ref() {
            None | Some(Value::Null) => Ok(None),
            Some(Value::Object(map)) => {
                Ok(Some(EncodedDocument::JsonLd(Value::Object(map.clone()))))
            }
            Some(Value::String(jwt)) => {
                validate_compact_jwt(jwt)?;
                Ok(Some(EncodedDocument::Jwt(jwt.clone())))
            }
            Some(_) => Err(malformed(
                "didDocument is not a JSON object, compact JWT string, or null",
            )),
        }
    }

    fn resolution_error(&self) -> NSResult<Option<&str>> {
        match self
            .did_resolution_metadata
            .as_ref()
            .and_then(|metadata| metadata.error.as_ref())
        {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(error)) if !error.is_empty() => Ok(Some(error)),
            Some(_) => Err(malformed("didResolutionMetadata.error is not a string")),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
struct DidResolutionMetadataWire {
    #[serde(rename = "contentType", default)]
    _content_type: Option<String>,
    #[serde(default)]
    error: Option<Value>,
}

#[derive(Clone, Debug, Deserialize)]
struct DidDocumentMetadataWire {
    #[serde(rename = "versionId", default)]
    version_id: Option<String>,
    #[serde(default)]
    deactivated: Option<bool>,
    #[serde(default)]
    buckyos: Option<BuckyosMetadataWire>,
}

#[derive(Clone, Debug, Deserialize)]
struct BuckyosMetadataWire {
    #[serde(rename = "docType", default)]
    doc_type: Option<String>,
    #[serde(rename = "documentStatus", default)]
    document_status: Option<String>,
    #[serde(rename = "documentVersion", default)]
    document_version: Option<u64>,
    #[serde(rename = "authoritySeq", default)]
    authority_seq: Option<u64>,
    #[serde(rename = "effectiveOwner", default)]
    effective_owner: Option<String>,
    #[serde(rename = "docHash", default)]
    doc_hash: Option<String>,
    #[serde(rename = "migrationTarget", default)]
    migration_target: Option<String>,
}

#[async_trait]
impl NsProvider for BaseHttpProvider {
    fn get_id(&self) -> String {
        format!("https-resolver:{}", self.resolver_host)
    }

    async fn query(
        &self,
        _name: &str,
        _record_type: Option<RecordType>,
        _from_ip: Option<IpAddr>,
    ) -> NSResult<NameInfo> {
        Err(NSError::NotFound(
            "https provider does not resolve dns records".to_string(),
        ))
    }

    async fn query_did(
        &self,
        did: &DID,
        doc_type: Option<DidDocType>,
        _from_ip: Option<IpAddr>,
    ) -> NSResult<EncodedDocument> {
        let url = self.build_url(did, doc_type.as_ref());
        debug!("https provider querying {}", url);
        let resp = self
            .client
            .get(url.clone())
            .send()
            .await
            .map_err(|e| NSError::Failed(format!("request {} failed: {}", url, e)))?;
        let provider_id = self.get_id();
        BaseHttpProvider::parse_response(did, doc_type.as_ref(), &provider_id, resp).await
    }

    async fn resolve_published_state(
        &self,
        did: &DID,
        doc_type: &DidDocType,
    ) -> NSResult<Option<PublishedState>> {
        let url = self.build_url(did, Some(doc_type));
        info!("https provider querying published state {}", url);
        let resp = self
            .published_state_request(url.as_str())
            .send()
            .await
            .map_err(|e| NSError::Failed(format!("request {} failed: {}", url, e)))?;
        let payload = Self::read_payload(resp).await?;
        let provider_id = self.get_id();
        let normalized = Self::normalize_payload(did, Some(doc_type), &provider_id, payload)?;
        Self::published_state_from_normalized(did, doc_type, normalized)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use name_lib::DID;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn compact_jwt() -> String {
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"EdDSA","typ":"JWT"}"#);
        let payload = URL_SAFE_NO_PAD.encode(br#"{"id":"did:bns:waterflier"}"#);
        let signature = URL_SAFE_NO_PAD.encode(b"test-signature");
        format!("{}.{}.{}", header, payload, signature)
    }

    fn normalize(
        status: StatusCode,
        content_type: Option<&str>,
        body: impl Into<Vec<u8>>,
    ) -> NSResult<NormalizedHttpDidResponse> {
        let did = DID::from_str("did:bns:waterflier").unwrap();
        BaseHttpProvider::normalize_payload(
            &did,
            Some(&DidDocType::Zone),
            "test-provider",
            HttpDidPayload::for_test(status, content_type, body.into()),
        )
    }

    fn parse_document(
        status: StatusCode,
        content_type: Option<&str>,
        body: impl Into<Vec<u8>>,
    ) -> NSResult<EncodedDocument> {
        let did = DID::from_str("did:bns:waterflier").unwrap();
        let normalized = normalize(status, content_type, body)?;
        BaseHttpProvider::document_from_normalized(&did, normalized)
    }

    fn parse_state(
        status: StatusCode,
        content_type: Option<&str>,
        body: impl Into<Vec<u8>>,
    ) -> NSResult<Option<PublishedState>> {
        let did = DID::from_str("did:bns:waterflier").unwrap();
        let normalized = normalize(status, content_type, body)?;
        BaseHttpProvider::published_state_from_normalized(&did, &DidDocType::Zone, normalized)
    }

    #[test]
    fn published_state_request_asks_for_resolution_envelope() {
        let provider = BaseHttpProvider::new("resolver.example.com");
        let request = provider
            .published_state_request(
                "https://resolver.example.com/1.0/identifiers/did:bns:alice?type=zone",
            )
            .build()
            .unwrap();

        assert_eq!(
            request.headers().get(reqwest::header::ACCEPT).unwrap(),
            DID_RESOLUTION_ACCEPT
        );
    }

    #[tokio::test]
    async fn one_client_handles_bare_jwt_and_negotiated_envelope() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let jwt = compact_jwt();
        let server_jwt = jwt.clone();
        let server = tokio::spawn(async move {
            for request_index in 0..3 {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = vec![0u8; 8192];
                let size = stream.read(&mut request).await.unwrap();
                let request = String::from_utf8_lossy(&request[..size]);
                let asks_for_envelope = request.lines().any(|line| {
                    line.eq_ignore_ascii_case(&format!("accept: {}", DID_RESOLUTION_ACCEPT))
                });
                let (content_type, body) = if asks_for_envelope && request_index == 1 {
                    (
                        DID_RESOLUTION_ACCEPT,
                        serde_json::json!({
                            "didDocument": server_jwt,
                            "didDocumentMetadata": {
                                "buckyos": {
                                    "docType": "zone",
                                    "documentStatus": "active"
                                }
                            }
                        })
                        .to_string(),
                    )
                } else {
                    ("application/jwt", server_jwt.clone())
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    content_type,
                    body.len(),
                    body
                );
                stream.write_all(response.as_bytes()).await.unwrap();
            }
        });

        let provider = BaseHttpProvider::new_with_config(serde_json::json!({
            "resolver_host": format!("http://{}", address)
        }))
        .unwrap();
        let did = DID::from_str("did:bns:waterflier").unwrap();
        assert_eq!(
            provider
                .query_did(&did, Some(DidDocType::Zone), None)
                .await
                .unwrap(),
            EncodedDocument::Jwt(jwt.clone())
        );
        let state = provider
            .resolve_published_state(&did, &DidDocType::Zone)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(state.document_status, DocumentStatus::Active);
        assert_eq!(
            state.document_ref.unwrap().inline_document,
            Some(EncodedDocument::Jwt(jwt))
        );
        // 同一 resolver 随后忽略 Accept、退化为裸 JWT：published-state 查询应为
        // NotApplicable，而不是 malformed transport error。
        assert!(provider
            .resolve_published_state(&did, &DidDocType::Zone)
            .await
            .unwrap()
            .is_none());
        server.await.unwrap();
    }

    // ------------------------ query_did 响应解析 ------------------------

    #[test]
    fn parse_response_body_unwraps_envelope_documents_by_shape() {
        let did = DID::from_str("did:web:ood1.example.com").unwrap();
        let jwt = compact_jwt();

        // 信封里的 JSON 文档
        let body = serde_json::json!({
            "didDocument": {"marker": "doc"},
            "didDocumentMetadata": {"buckyos": {"documentStatus": "active"}}
        })
        .to_string();
        let doc = BaseHttpProvider::parse_response_body(&did, StatusCode::OK, &body).unwrap();
        assert_eq!(
            doc,
            EncodedDocument::JsonLd(serde_json::json!({"marker": "doc"}))
        );

        // 信封里的 JWT 文档（字符串形态）必须还原成 Jwt，而不是 JsonLd(String)
        let body = serde_json::json!({
            "didDocument": jwt,
            "didDocumentMetadata": {"buckyos": {"documentStatus": "active"}}
        })
        .to_string();
        let doc = BaseHttpProvider::parse_response_body(&did, StatusCode::OK, &body).unwrap();
        assert_eq!(doc, EncodedDocument::Jwt(jwt.clone()));

        // 裸 JWT body（静态发布面 / 旧形态）仍然可解析
        let doc = BaseHttpProvider::parse_response_body(&did, StatusCode::OK, &jwt).unwrap();
        assert_eq!(doc, EncodedDocument::Jwt(jwt));

        // 裸 JSON 文档（无信封）整体即文档
        let doc =
            BaseHttpProvider::parse_response_body(&did, StatusCode::OK, r#"{"bare":1}"#).unwrap();
        assert_eq!(doc, EncodedDocument::JsonLd(serde_json::json!({"bare": 1})));

        // deactivated 信封仍然拒绝
        let body = serde_json::json!({
            "didDocument": "a.b.c",
            "didDocumentMetadata": {"deactivated": true}
        })
        .to_string();
        assert!(matches!(
            BaseHttpProvider::parse_response_body(&did, StatusCode::OK, &body),
            Err(NSError::Disabled(_))
        ));
    }

    #[test]
    fn document_formats_are_adaptive_for_query_and_published_state() {
        let jwt = compact_jwt();
        let bare_json = r#"{"id":"did:bns:waterflier"}"#.to_string();
        let json_string_jwt = serde_json::to_string(&jwt).unwrap();

        let document_only_cases = [
            (Some("application/json"), bare_json.as_str()),
            (Some("application/jwt"), jwt.as_str()),
            (Some("application/json"), json_string_jwt.as_str()),
            // Content-Type 只作提示：声明与实际形状相反、带参数、缺失都必须可识别。
            (Some("application/json; charset=utf-8"), jwt.as_str()),
            (Some("APPLICATION/JWT"), bare_json.as_str()),
            (Some("text/plain"), jwt.as_str()),
            (Some("application/octet-stream"), bare_json.as_str()),
            (None, jwt.as_str()),
        ];
        for (content_type, body) in document_only_cases {
            assert!(parse_document(StatusCode::OK, content_type, body.as_bytes().to_vec()).is_ok());
            assert!(
                parse_state(StatusCode::OK, content_type, body.as_bytes().to_vec())
                    .unwrap()
                    .is_none()
            );
        }

        for document in [
            serde_json::json!({"id": "did:bns:waterflier"}),
            Value::String(jwt.clone()),
        ] {
            let envelope = serde_json::json!({
                "didResolutionMetadata": {"contentType": "application/did+jwt"},
                "didDocument": document,
                "didDocumentMetadata": {
                    "buckyos": {"docType": "zone", "documentStatus": "active"}
                }
            })
            .to_string();
            assert!(parse_document(
                StatusCode::OK,
                Some("application/did-resolution+json"),
                envelope.as_bytes().to_vec(),
            )
            .is_ok());
            assert_eq!(
                parse_state(
                    StatusCode::OK,
                    Some("application/did-resolution+json"),
                    envelope.as_bytes().to_vec(),
                )
                .unwrap()
                .unwrap()
                .document_status,
                DocumentStatus::Active
            );
        }

        let bom_wrapped = format!("\u{feff}  {}\r\n", bare_json);
        assert!(parse_document(StatusCode::OK, None, bom_wrapped.into_bytes()).is_ok());
    }

    #[test]
    fn bare_jwt_is_not_a_published_state_regression() {
        let jwt = compact_jwt();
        assert!(
            parse_state(StatusCode::OK, Some("application/jwt"), jwt.into_bytes(),)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn content_type_classifier_ignores_case_and_parameters() {
        assert_eq!(
            classify_content_type(Some("Application/Did-Resolution+Json; Charset=UTF-8")),
            ContentTypeKind::Json
        );
        assert_eq!(
            classify_content_type(Some("APPLICATION/DID+JWT; profile=x")),
            ContentTypeKind::Jwt
        );
        assert_eq!(
            classify_content_type(Some("application/octet-stream")),
            ContentTypeKind::Flexible
        );
        assert_eq!(classify_content_type(None), ContentTypeKind::Unknown);
    }

    #[test]
    fn redirects_are_limited_and_never_downgrade_https() {
        let https = Url::parse("https://resolver.example.test/start").unwrap();
        let another_https = Url::parse("https://resolver.example.test/next").unwrap();
        let http = Url::parse("http://resolver.example.test/insecure").unwrap();
        assert_eq!(redirect_violation(&[https.clone()], &another_https), None);
        assert_eq!(
            redirect_violation(&[https], &http),
            Some("resolver redirect attempted HTTPS downgrade")
        );
        assert_eq!(
            redirect_violation(
                &vec![another_https.clone(); MAX_RESOLVER_REDIRECTS],
                &another_https,
            ),
            Some("resolver redirect limit exceeded")
        );
    }

    #[test]
    fn response_diagnostics_never_include_document_or_key_material() {
        let jwt_with_secret = format!("{}.key-material", compact_jwt());
        let payload = HttpDidPayload::for_test(
            StatusCode::OK,
            Some("application/jwt"),
            jwt_with_secret.as_bytes().to_vec(),
        );
        let did = DID::from_str("did:bns:waterflier").unwrap();
        let diagnostics = response_diagnostics(
            &did,
            Some(&DidDocType::Zone),
            "test-provider",
            &payload,
            "compact-jwt",
        );
        assert!(!diagnostics.contains(&jwt_with_secret));
        assert!(!diagnostics.contains("key-material"));
        assert!(diagnostics.contains(&format!("body_len={}", payload.body.len())));
    }

    #[test]
    fn negative_status_matrix_is_fail_closed() {
        let missing = serde_json::json!({
            "didResolutionMetadata": {"error": "notFound"},
            "didDocument": null,
            "didDocumentMetadata": {
                "deactivated": false,
                "buckyos": {"docType": "zone", "documentStatus": "missing"}
            }
        })
        .to_string();
        assert_eq!(
            parse_state(
                StatusCode::NOT_FOUND,
                Some("application/json"),
                missing.as_bytes().to_vec(),
            )
            .unwrap()
            .unwrap()
            .document_status,
            DocumentStatus::Missing
        );
        assert!(matches!(
            parse_document(
                StatusCode::NOT_FOUND,
                Some("application/json"),
                missing.into_bytes(),
            ),
            Err(NSError::NotFound(_))
        ));

        for status_name in ["revoked", "tombstoned"] {
            let body = serde_json::json!({
                "didResolutionMetadata": {"error": "deactivated"},
                "didDocument": null,
                "didDocumentMetadata": {
                    "deactivated": true,
                    "buckyos": {"docType": "zone", "documentStatus": status_name}
                }
            })
            .to_string();
            let state = parse_state(
                StatusCode::GONE,
                Some("application/json"),
                body.as_bytes().to_vec(),
            )
            .unwrap()
            .unwrap();
            assert!(matches!(
                state.document_status,
                DocumentStatus::Revoked | DocumentStatus::Tombstoned
            ));
            assert!(matches!(
                parse_document(
                    StatusCode::GONE,
                    Some("application/json"),
                    body.into_bytes(),
                ),
                Err(NSError::Disabled(_))
            ));
        }

        for (http_status, document_status, deactivated) in [
            (StatusCode::OK, "revoked", true),
            (StatusCode::GONE, "active", false),
            (StatusCode::OK, "active", true),
            (StatusCode::NOT_FOUND, "active", false),
        ] {
            let body = serde_json::json!({
                "didDocument": {"id": "did:bns:waterflier"},
                "didDocumentMetadata": {
                    "deactivated": deactivated,
                    "buckyos": {"docType": "zone", "documentStatus": document_status}
                }
            })
            .to_string();
            assert!(
                parse_state(http_status, Some("application/json"), body.into_bytes(),).is_err()
            );
        }
    }

    #[test]
    fn not_applicable_404_never_becomes_strong_missing() {
        for body in [
            "",
            "not found",
            r#"{"didResolutionMetadata":{"error":"notFound"},"didDocument":null,"didDocumentMetadata":{}}"#,
        ] {
            assert!(parse_state(
                StatusCode::NOT_FOUND,
                Some("text/plain"),
                body.as_bytes().to_vec(),
            )
            .unwrap()
            .is_none());
            assert!(matches!(
                parse_document(
                    StatusCode::NOT_FOUND,
                    Some("text/plain"),
                    body.as_bytes().to_vec(),
                ),
                Err(NSError::NotFound(_))
            ));
        }
    }

    #[test]
    fn malformed_bodies_and_resource_limits_are_rejected_without_echoing_body() {
        let secret = "<html>resolver-secret-token</html>";
        let error = parse_document(
            StatusCode::OK,
            Some("text/html"),
            secret.as_bytes().to_vec(),
        )
        .unwrap_err();
        assert!(!error.to_string().contains("resolver-secret-token"));

        for body in [
            Vec::new(),
            b"abc.def.ghi".to_vec(),
            br#"[1,2,3]"#.to_vec(),
            b"{\"id\":\"did:bns:waterflier\"}\0".to_vec(),
            vec![0xff, 0xfe, 0xfd],
        ] {
            assert!(parse_document(StatusCode::OK, None, body.clone()).is_err());
            assert!(parse_state(StatusCode::OK, None, body).is_err());
        }

        let oversized = vec![b'a'; MAX_HTTP_DID_BODY_BYTES + 1];
        let error = parse_document(StatusCode::OK, Some("application/octet-stream"), oversized)
            .unwrap_err();
        assert!(error.to_string().contains("HttpDidBodyTooLarge"));
    }

    #[test]
    fn transport_and_auth_statuses_do_not_enter_negative_state_parsing() {
        for status in [
            StatusCode::REQUEST_TIMEOUT,
            StatusCode::TOO_MANY_REQUESTS,
            StatusCode::INTERNAL_SERVER_ERROR,
            StatusCode::BAD_GATEWAY,
            StatusCode::SERVICE_UNAVAILABLE,
        ] {
            assert!(matches!(
                parse_state(status, Some("application/json"), b"{}".to_vec()),
                Err(NSError::Failed(_))
            ));
        }
        for status in [StatusCode::UNAUTHORIZED, StatusCode::FORBIDDEN] {
            assert!(matches!(
                parse_state(status, None, Vec::new()),
                Err(NSError::Forbid)
            ));
        }
    }

    #[test]
    fn envelope_fields_are_validated_with_context() {
        let cases = [
            serde_json::json!({
                "didDocument": {"id": "did:bns:waterflier"},
                "didDocumentMetadata": {
                    "versionId": "not-a-number",
                    "buckyos": {"docType": "zone", "documentStatus": "active"}
                }
            }),
            serde_json::json!({
                "didDocument": {"id": "did:bns:waterflier"},
                "didDocumentMetadata": {
                    "versionId": "2",
                    "buckyos": {
                        "docType": "zone", "documentStatus": "active", "documentVersion": 3
                    }
                }
            }),
            serde_json::json!({
                "didDocument": {"id": "did:bns:waterflier"},
                "didDocumentMetadata": {
                    "buckyos": {"docType": "device", "documentStatus": "active"}
                }
            }),
            serde_json::json!({
                "didDocument": null,
                "didDocumentMetadata": {
                    "buckyos": {"docType": "zone", "documentStatus": "migrated"}
                }
            }),
            serde_json::json!({
                "didDocument": {"id": "did:bns:waterflier"},
                "didDocumentMetadata": {
                    "buckyos": {
                        "docType": "zone", "documentStatus": "active",
                        "effectiveOwner": "not-a-did"
                    }
                }
            }),
        ];
        for (index, body) in cases.into_iter().enumerate() {
            assert!(
                parse_state(
                    StatusCode::OK,
                    Some("application/json"),
                    body.to_string().into_bytes(),
                )
                .is_err(),
                "invalid envelope case {} was accepted",
                index
            );
        }

        let unknown_status = serde_json::json!({
            "didDocumentMetadata": {
                "buckyos": {"docType": "zone", "documentStatus": "future-state"}
            }
        })
        .to_string();
        assert!(parse_state(
            StatusCode::OK,
            Some("application/json"),
            unknown_status.into_bytes(),
        )
        .is_err());
    }

    // ------------------------ resolve_published_state 信封解析 ------------------------
    // 按 doc/http_did_resolver_api.md 的信封直接构造字面量 status/body 测试纯解析函数，
    // 不需要真的发 HTTP 请求（也不需要像之前那样搭一套 mock transport trait）。

    #[test]
    fn active_state_maps_document_ref_and_owner() {
        let did = DID::from_str("did:bns:waterflier").unwrap();
        let body = serde_json::json!({
            "didDocument": {"marker": "active"},
            "didDocumentMetadata": {
                "versionId": "3",
                "buckyos": {
                    "docType": "zone",
                    "documentStatus": "active",
                    "documentVersion": 3,
                    "previousVersion": 2,
                    "authoritySeq": 9,
                    "lineageEpoch": 1,
                    "effectiveOwner": "did:bns:waterflier-owner",
                    "ownerSource": "methodAuthority",
                    "authorityRoot": "0xroot"
                }
            }
        })
        .to_string();

        let state = BaseHttpProvider::parse_published_state_body(
            &did,
            &DidDocType::Zone,
            StatusCode::OK,
            &body,
        )
        .unwrap()
        .unwrap();
        assert_eq!(state.document_status, DocumentStatus::Active);
        assert_eq!(state.document_version, Some(3));
        assert_eq!(
            state.effective_owner,
            Some(DID::new("bns", "waterflier-owner"))
        );
        assert_eq!(
            state.document_ref.unwrap().inline_document.unwrap(),
            EncodedDocument::JsonLd(serde_json::json!({"marker": "active"}))
        );
    }

    #[test]
    fn missing_revoked_tombstoned_and_migrated_map_to_terminal_states() {
        let did = DID::from_str("did:bns:waterflier").unwrap();

        let missing_body = serde_json::json!({
            "didDocumentMetadata": {"buckyos": {"documentStatus": "missing"}}
        })
        .to_string();
        let missing = BaseHttpProvider::parse_published_state_body(
            &did,
            &DidDocType::Zone,
            StatusCode::NOT_FOUND,
            &missing_body,
        )
        .unwrap()
        .unwrap();
        assert_eq!(missing.document_status, DocumentStatus::Missing);

        let revoked_body = serde_json::json!({
            "didDocumentMetadata": {"buckyos": {"documentStatus": "revoked"}}
        })
        .to_string();
        let revoked = BaseHttpProvider::parse_published_state_body(
            &did,
            &DidDocType::Zone,
            StatusCode::GONE,
            &revoked_body,
        )
        .unwrap()
        .unwrap();
        assert_eq!(revoked.document_status, DocumentStatus::Revoked);

        let tombstoned_body = serde_json::json!({
            "didDocumentMetadata": {"buckyos": {"documentStatus": "tombstoned"}}
        })
        .to_string();
        let tombstoned = BaseHttpProvider::parse_published_state_body(
            &did,
            &DidDocType::Zone,
            StatusCode::GONE,
            &tombstoned_body,
        )
        .unwrap()
        .unwrap();
        assert_eq!(tombstoned.document_status, DocumentStatus::Tombstoned);

        let migrated_body = serde_json::json!({
            "didDocumentMetadata": {
                "buckyos": {"documentStatus": "migrated", "migrationTarget": "did:bns:waterflier-v2"}
            }
        })
        .to_string();
        let migrated = BaseHttpProvider::parse_published_state_body(
            &did,
            &DidDocType::Zone,
            StatusCode::OK,
            &migrated_body,
        )
        .unwrap()
        .unwrap();
        assert_eq!(migrated.document_status, DocumentStatus::Migrated);
        assert_eq!(
            migrated.migration_target,
            Some(DID::new("bns", "waterflier-v2"))
        );
    }

    #[test]
    fn expired_state_maps_and_preserves_version() {
        let did = DID::from_str("did:bns:waterflier").unwrap();
        let body = serde_json::json!({
            "didDocumentMetadata": {"buckyos": {"documentStatus": "expired", "documentVersion": 5}}
        })
        .to_string();

        let state = BaseHttpProvider::parse_published_state_body(
            &did,
            &DidDocType::Zone,
            StatusCode::OK,
            &body,
        )
        .unwrap()
        .unwrap();
        assert_eq!(state.document_status, DocumentStatus::Expired);
        assert_eq!(state.document_version, Some(5));
    }

    #[test]
    fn bare_404_without_buckyos_extension_is_not_applicable() {
        // 第三方 did:web / did:key resolver（identity.foundation、uniresolver.io 等）根本不
        // 知道这个扩展，普通的 404（甚至没有 JSON body）必须被当成"不适用"，而不是报错。
        let did = DID::from_str("did:web:example.com").unwrap();
        let state = BaseHttpProvider::parse_published_state_body(
            &did,
            &DidDocType::Zone,
            StatusCode::NOT_FOUND,
            "",
        )
        .unwrap();
        assert!(state.is_none());
    }

    #[test]
    fn response_without_buckyos_extension_is_not_applicable() {
        // 200 但响应体里没有 buckyos 扩展块（比如一个不认识这份协议的普通 did:web host），
        // 同样是"不适用"，不是错误、也不是负状态。
        let did = DID::from_str("did:web:example.com").unwrap();
        let body = serde_json::json!({
            "didDocument": {"id": "did:web:example.com"},
            "didDocumentMetadata": {"deactivated": false}
        })
        .to_string();
        let state = BaseHttpProvider::parse_published_state_body(
            &did,
            &DidDocType::Zone,
            StatusCode::OK,
            &body,
        )
        .unwrap();
        assert!(state.is_none());
    }

    // T3.2: transport 错误（5xx/超时/连接失败）必须原样冒泡成 Err，不能被误判成
    // Missing/Revoked 之类的强负状态。
    #[test]
    fn unexpected_status_code_is_transport_error_not_negative_state() {
        let did = DID::from_str("did:bns:waterflier").unwrap();
        let err = BaseHttpProvider::parse_published_state_body(
            &did,
            &DidDocType::Zone,
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal error",
        )
        .unwrap_err();
        assert!(matches!(err, NSError::Failed(_)));
    }

    #[test]
    fn malformed_json_on_200_is_transport_error() {
        let did = DID::from_str("did:bns:waterflier").unwrap();
        let err = BaseHttpProvider::parse_published_state_body(
            &did,
            &DidDocType::Zone,
            StatusCode::OK,
            "not json at all",
        )
        .unwrap_err();
        assert!(matches!(err, NSError::Failed(_)));
    }

    #[test]
    fn build_url_uses_http_base_url_directly() {
        let provider = BaseHttpProvider::new("http://127.0.0.1:3200");
        let did = DID::from_str("did:bns:example").unwrap();

        assert_eq!(
            provider.build_url(&did, Some(&DidDocType::Owner)),
            "http://127.0.0.1:3200/1.0/identifiers/did:bns:example?type=owner"
        );
    }

    #[test]
    fn build_url_keeps_default_https_for_bare_host() {
        let provider = BaseHttpProvider::new("127.0.0.1:3200");
        let did = DID::from_str("did:bns:example").unwrap();

        assert_eq!(
            provider.build_url(&did, None),
            "https://127.0.0.1:3200/1.0/identifiers/did:bns:example"
        );
    }

    #[tokio::test]
    async fn resolve_did_via_identity_foundation() {
        let provider = BaseHttpProvider::new("resolver.identity.foundation");
        // 使用 resolver.identity.foundation 自身的 did:web 作为稳定样例
        let did = DID::from_str("did:web:identity.foundation").unwrap();

        match provider.query_did(&did, None, None).await {
            Ok(doc) => {
                let json = doc.to_json_value().unwrap();
                println!("json: {}", serde_json::to_string_pretty(&json).unwrap());
                assert_eq!(json.get("id").unwrap().as_str().unwrap(), did.to_string());
            }
            Err(NSError::NotFound(_)) => {
                // 公网解析器偶发 404，视为环境性问题，不阻断单测
                println!("skip: resolver returned NotFound for {}", did.to_string());
            }
            Err(e) => panic!("unexpected err: {:?}", e),
        }
    }

    #[tokio::test]
    async fn resolve_did_via_uniresolver() {
        let provider = BaseHttpProvider::new("uniresolver.io");
        // did:key 由密钥直接派生，uniresolver 官方示例，可稳定解析
        let did =
            DID::from_str("did:key:z6Mksw4bDmn77uB5iVbQJBALV4CfqUGNoTCJQwdse1dQcvbK").unwrap();
        // 携带 doc_type，验证 URL 编码（%23）路径能被解析服务接受
        let doc = provider.query_did(&did, None, None).await.unwrap();
        let json = doc.to_json_value().unwrap();
        println!("json: {}", serde_json::to_string_pretty(&json).unwrap());
        assert_eq!(json.get("id").unwrap().as_str().unwrap(), did.to_string());
    }
}
