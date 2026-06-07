use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use http::{header, Method, Response, StatusCode};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use name_lib::DIDObjectCard;
use percent_encoding::percent_decode_str;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{server_err, HttpServer, ServerError, ServerErrorCode, ServerResult, StreamInfo};

pub const DID_OBJECT_CARD_PATH: &str = "did.json";
pub const DID_OBJECT_PROFILE_PATH: &str = "profile.json";
pub const DID_OBJECT_PROPERTY_PREFIX: &str = "props";
pub const DID_OBJECT_ACTION_PREFIX: &str = "methods";
pub const DID_OBJECT_EVENT_PREFIX: &str = "events";

#[derive(Clone, Debug)]
pub struct DIDObjectRequestContext {
    pub stream_info: StreamInfo,
    pub path: String,
    /// The matched object URL for this request, reconstructed from the request origin and object path.
    pub object_url: String,
    /// The path portion of the matched object URL, without the DID Object endpoint suffix.
    pub object_path: String,
    /// Captures extracted from the matched ObjURL pattern.
    pub object_params: HashMap<String, String>,
    /// The DID Object endpoint suffix, such as did.json, profile.json, props/name, or methods/name.
    pub endpoint_path: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DIDObjectUrlMatch {
    pub object_url: String,
    pub object_path: String,
    pub params: HashMap<String, String>,
}

/// Matches the object part of a DID Object URL before the endpoint suffix.
///
/// Patterns may be full URLs or paths. Matching is path-based so deployments behind
/// gateways can use the same handler with different request origins. A segment can
/// be captured with `{name}` or `:name`, and `*` matches the rest of the path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DIDObjectUrlPattern {
    raw: String,
    path: String,
}

impl DIDObjectUrlPattern {
    pub fn new(pattern: impl Into<String>) -> Self {
        let raw = pattern.into();
        let path = normalize_obj_url_path(&raw);
        Self { raw, path }
    }

    pub fn raw(&self) -> &str {
        &self.raw
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn captures(&self, object_path: &str) -> Option<HashMap<String, String>> {
        match_obj_url_path(&self.path, object_path)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct DIDObjectActionRequest {
    pub method: String,
    pub params: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub obj: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub obj_did: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confirm_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    #[serde(flatten)]
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub extra: HashMap<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct DIDObjectActionSuccess {
    pub result: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub meta: Option<Value>,
}

impl DIDObjectActionSuccess {
    pub fn new(result: Value) -> Self {
        Self { result, meta: None }
    }

    pub fn with_meta(result: Value, meta: Value) -> Self {
        Self {
            result,
            meta: Some(meta),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct DIDObjectActionResponse {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub meta: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<DIDObjectError>,
}

impl From<DIDObjectActionSuccess> for DIDObjectActionResponse {
    fn from(value: DIDObjectActionSuccess) -> Self {
        Self {
            result: Some(value.result),
            meta: value.meta,
            error: None,
        }
    }
}

impl From<DIDObjectError> for DIDObjectActionResponse {
    fn from(value: DIDObjectError) -> Self {
        Self {
            result: None,
            meta: None,
            error: Some(value),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct DIDObjectError {
    pub code: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub refresh_hints: Vec<String>,
    #[serde(flatten)]
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub extra: HashMap<String, Value>,
}

impl DIDObjectError {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            details: None,
            retry_after_ms: None,
            refresh_hints: Vec::new(),
            extra: HashMap::new(),
        }
    }

    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new("bad_request", message)
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new("not_found", message)
    }

    pub fn unsupported(message: impl Into<String>) -> Self {
        Self::new("unsupported", message)
    }

    fn status_code(&self) -> StatusCode {
        match self.code.as_str() {
            "bad_request" | "invalid_params" => StatusCode::BAD_REQUEST,
            "permission_denied" => StatusCode::FORBIDDEN,
            "not_found" | "unknown_property" | "unknown_action" | "unknown_event" => {
                StatusCode::NOT_FOUND
            }
            "stale_object" => StatusCode::CONFLICT,
            "unsupported" => StatusCode::NOT_IMPLEMENTED,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

pub type DIDObjectServerResult<T> = Result<T, DIDObjectError>;

#[async_trait]
pub trait DIDObjectServer: Send + Sync + 'static {
    fn object_card(&self) -> &DIDObjectCard;

    fn object_profile(&self) -> &Value;

    async fn object_card_for(
        &self,
        _ctx: DIDObjectRequestContext,
    ) -> DIDObjectServerResult<DIDObjectCard> {
        Ok(self.object_card().clone())
    }

    async fn object_profile_for(
        &self,
        _ctx: DIDObjectRequestContext,
    ) -> DIDObjectServerResult<Value> {
        Ok(self.object_profile().clone())
    }

    async fn read_property(
        &self,
        name: &str,
        ctx: DIDObjectRequestContext,
    ) -> DIDObjectServerResult<Value>;

    async fn invoke_action(
        &self,
        request: DIDObjectActionRequest,
        ctx: DIDObjectRequestContext,
    ) -> DIDObjectServerResult<DIDObjectActionSuccess>;

    async fn handle_event_request(
        &self,
        _event: Option<&str>,
        _ctx: DIDObjectRequestContext,
    ) -> DIDObjectServerResult<Value> {
        Err(DIDObjectError::unsupported(
            "DID Object event WebSocket binding is not implemented by this HTTP adapter",
        ))
    }
}

pub struct DIDObjectHttpServer<T: DIDObjectServer> {
    id: String,
    inner: Arc<T>,
    object_url_patterns: Vec<DIDObjectUrlPattern>,
    http_version: http::Version,
    http3_port: Option<u16>,
}

impl<T: DIDObjectServer> DIDObjectHttpServer<T> {
    pub fn new(id: impl Into<String>, inner: Arc<T>) -> Self {
        let object_url_patterns = inner
            .object_card()
            .object_url()
            .map(|object_url| vec![DIDObjectUrlPattern::new(object_url)])
            .unwrap_or_default();

        Self {
            id: id.into(),
            inner,
            object_url_patterns,
            http_version: http::Version::HTTP_11,
            http3_port: None,
        }
    }

    pub fn with_http_version(mut self, version: http::Version) -> Self {
        self.http_version = version;
        self
    }

    pub fn with_http3_port(mut self, port: Option<u16>) -> Self {
        self.http3_port = port;
        self
    }

    pub fn with_obj_url_pattern(mut self, pattern: impl Into<String>) -> Self {
        self.object_url_patterns.clear();
        self.object_url_patterns
            .push(DIDObjectUrlPattern::new(pattern));
        self
    }

    pub fn with_obj_url_patterns<I, S>(mut self, patterns: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.object_url_patterns = patterns.into_iter().map(DIDObjectUrlPattern::new).collect();
        self
    }

    pub fn add_obj_url_pattern(mut self, pattern: impl Into<String>) -> Self {
        self.object_url_patterns
            .push(DIDObjectUrlPattern::new(pattern));
        self
    }

    pub fn obj_url_patterns(&self) -> &[DIDObjectUrlPattern] {
        &self.object_url_patterns
    }

    fn match_object_url(
        &self,
        req: &http::Request<BoxBody<Bytes, ServerError>>,
        endpoint: &DIDObjectEndpoint,
    ) -> Option<DIDObjectUrlMatch> {
        let object_path = endpoint.object_path.clone();
        let object_url = request_object_url(req, &object_path);

        if self.object_url_patterns.is_empty() {
            return Some(DIDObjectUrlMatch {
                object_url,
                object_path,
                params: HashMap::new(),
            });
        }

        for pattern in &self.object_url_patterns {
            if let Some(params) = pattern.captures(&object_path) {
                return Some(DIDObjectUrlMatch {
                    object_url,
                    object_path,
                    params,
                });
            }
        }

        None
    }

    fn request_context(
        &self,
        path: &str,
        endpoint: &DIDObjectEndpoint,
        object_match: DIDObjectUrlMatch,
        info: StreamInfo,
    ) -> DIDObjectRequestContext {
        DIDObjectRequestContext {
            stream_info: info,
            path: path.to_string(),
            object_url: object_match.object_url,
            object_path: object_match.object_path,
            object_params: object_match.params,
            endpoint_path: endpoint.endpoint_path.clone(),
        }
    }
}

#[async_trait]
impl<T: DIDObjectServer> HttpServer for DIDObjectHttpServer<T> {
    async fn serve_request(
        &self,
        req: http::Request<BoxBody<Bytes, ServerError>>,
        info: StreamInfo,
    ) -> ServerResult<http::Response<BoxBody<Bytes, ServerError>>> {
        let method = req.method().clone();
        let path = normalize_path(req.uri().path());
        let endpoint = match DIDObjectEndpoint::parse(&path) {
            Some(endpoint) => endpoint,
            None => {
                return did_object_error_response(DIDObjectError::not_found(
                    "DID Object endpoint not found",
                ));
            }
        };

        let object_match = match self.match_object_url(&req, &endpoint) {
            Some(object_match) => object_match,
            None => {
                return did_object_error_response(DIDObjectError::not_found(format!(
                    "DID Object URL '{}' is not served by {}",
                    endpoint.object_path, self.id
                )));
            }
        };

        if method == Method::GET && endpoint.kind == DIDObjectEndpointKind::Card {
            let ctx = self.request_context(&path, &endpoint, object_match, info);
            return match self.inner.object_card_for(ctx).await {
                Ok(card) => json_response(StatusCode::OK, &card),
                Err(err) => did_object_error_response(err),
            };
        }

        if method == Method::GET && endpoint.kind == DIDObjectEndpointKind::Profile {
            let ctx = self.request_context(&path, &endpoint, object_match, info);
            return match self.inner.object_profile_for(ctx).await {
                Ok(profile) => json_response(StatusCode::OK, &profile),
                Err(err) => did_object_error_response(err),
            };
        }

        if method == Method::GET && endpoint.kind == DIDObjectEndpointKind::Property {
            let property = endpoint.item.as_deref().unwrap_or_default();
            let ctx = self.request_context(&path, &endpoint, object_match, info);
            return match self.inner.read_property(property, ctx).await {
                Ok(value) => json_response(StatusCode::OK, &value),
                Err(err) => did_object_error_response(err),
            };
        }

        if method == Method::POST && endpoint.kind == DIDObjectEndpointKind::Action {
            let action = endpoint.item.as_deref().unwrap_or_default();
            let body = req.into_body().collect().await.map_err(|e| {
                server_err!(
                    ServerErrorCode::BadRequest,
                    "failed to read DID Object action body: {:?}",
                    e
                )
            })?;
            let request = match serde_json::from_slice::<DIDObjectActionRequest>(&body.to_bytes()) {
                Ok(request) => request,
                Err(err) => {
                    return did_object_action_error_response(DIDObjectError::bad_request(format!(
                        "invalid DID Object action request: {err}"
                    )));
                }
            };

            if request.method != action {
                return did_object_action_error_response(DIDObjectError::bad_request(format!(
                    "action endpoint '{action}' does not match request method '{}'",
                    request.method
                )));
            }

            let ctx = self.request_context(&path, &endpoint, object_match, info);
            return match self.inner.invoke_action(request, ctx).await {
                Ok(success) => {
                    json_response(StatusCode::OK, &DIDObjectActionResponse::from(success))
                }
                Err(err) => {
                    let status = err.status_code();
                    json_response(status, &DIDObjectActionResponse::from(err))
                }
            };
        }

        if endpoint.kind == DIDObjectEndpointKind::Event {
            let ctx = self.request_context(&path, &endpoint, object_match, info);
            return match self
                .inner
                .handle_event_request(endpoint.item.as_deref(), ctx)
                .await
            {
                Ok(value) => json_response(StatusCode::OK, &value),
                Err(err) => did_object_error_response(err),
            };
        }

        did_object_error_response(DIDObjectError::not_found("DID Object endpoint not found"))
    }

    fn id(&self) -> String {
        self.id.clone()
    }

    fn http_version(&self) -> http::Version {
        self.http_version
    }

    fn http3_port(&self) -> Option<u16> {
        self.http3_port
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DIDObjectEndpoint {
    kind: DIDObjectEndpointKind,
    object_path: String,
    endpoint_path: String,
    item: Option<String>,
}

impl DIDObjectEndpoint {
    fn parse(path: &str) -> Option<Self> {
        let segments = path_segments(path);

        if segments.last().copied() == Some(DID_OBJECT_CARD_PATH) {
            return Some(Self::from_parts(
                DIDObjectEndpointKind::Card,
                &segments[..segments.len().saturating_sub(1)],
                &[DID_OBJECT_CARD_PATH],
                None,
            ));
        }

        if segments.last().copied() == Some(DID_OBJECT_PROFILE_PATH) {
            return Some(Self::from_parts(
                DIDObjectEndpointKind::Profile,
                &segments[..segments.len().saturating_sub(1)],
                &[DID_OBJECT_PROFILE_PATH],
                None,
            ));
        }

        Self::parse_named_endpoint(
            &segments,
            DID_OBJECT_PROPERTY_PREFIX,
            DIDObjectEndpointKind::Property,
        )
        .or_else(|| {
            Self::parse_named_endpoint(
                &segments,
                DID_OBJECT_ACTION_PREFIX,
                DIDObjectEndpointKind::Action,
            )
        })
        .or_else(|| {
            Self::parse_optional_named_endpoint(
                &segments,
                DID_OBJECT_EVENT_PREFIX,
                DIDObjectEndpointKind::Event,
            )
        })
    }

    fn parse_named_endpoint(
        segments: &[&str],
        prefix: &'static str,
        kind: DIDObjectEndpointKind,
    ) -> Option<Self> {
        let prefix_index = segments.iter().position(|segment| *segment == prefix)?;
        if segments.len() != prefix_index + 2 {
            return None;
        }

        let item = decode_segment(segments[prefix_index + 1])?;
        Some(Self::from_parts(
            kind,
            &segments[..prefix_index],
            &segments[prefix_index..],
            Some(item),
        ))
    }

    fn parse_optional_named_endpoint(
        segments: &[&str],
        prefix: &'static str,
        kind: DIDObjectEndpointKind,
    ) -> Option<Self> {
        let prefix_index = segments.iter().position(|segment| *segment == prefix)?;
        if segments.len() != prefix_index + 1 && segments.len() != prefix_index + 2 {
            return None;
        }

        let item = if segments.len() == prefix_index + 2 {
            Some(decode_segment(segments[prefix_index + 1])?)
        } else {
            None
        };

        Some(Self::from_parts(
            kind,
            &segments[..prefix_index],
            &segments[prefix_index..],
            item,
        ))
    }

    fn from_parts(
        kind: DIDObjectEndpointKind,
        object_segments: &[&str],
        endpoint_segments: &[&str],
        item: Option<String>,
    ) -> Self {
        Self {
            kind,
            object_path: segments_to_path(object_segments),
            endpoint_path: endpoint_segments.join("/"),
            item,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DIDObjectEndpointKind {
    Card,
    Profile,
    Property,
    Action,
    Event,
}

fn normalize_path(path: &str) -> String {
    let normalized = path.trim_end_matches('/');
    if normalized.is_empty() {
        "/".to_string()
    } else {
        normalized.to_string()
    }
}

fn last_path_segment(path: &str) -> Option<&str> {
    path.rsplit('/').find(|segment| !segment.is_empty())
}

fn path_item_after(path: &str, prefix: &str) -> Option<String> {
    let mut segments = path.split('/').filter(|segment| !segment.is_empty());
    while let Some(segment) = segments.next() {
        if segment == prefix {
            let item = segments.next()?;
            if item.is_empty() || segments.next().is_some() {
                return None;
            }
            return percent_decode_str(item)
                .decode_utf8()
                .ok()
                .map(|s| s.into_owned());
        }
    }
    None
}

fn request_object_url(
    req: &http::Request<BoxBody<Bytes, ServerError>>,
    object_path: &str,
) -> String {
    if let Some(authority) = req
        .uri()
        .authority()
        .map(|authority| authority.as_str())
        .or_else(|| {
            req.headers()
                .get(header::HOST)
                .and_then(|value| value.to_str().ok())
        })
    {
        let scheme = req.uri().scheme_str().unwrap_or("http");
        format!("{scheme}://{authority}{object_path}")
    } else {
        object_path.to_string()
    }
}

fn normalize_obj_url_path(value: &str) -> String {
    let value = value.trim().trim_end_matches('/');
    let path = if let Some(scheme_pos) = value.find("://") {
        let after_authority = &value[scheme_pos + 3..];
        match after_authority.find('/') {
            Some(path_pos) => &after_authority[path_pos..],
            None => "/",
        }
    } else {
        value
    };

    let path = path.split(['?', '#']).next().unwrap_or(path);
    if path.is_empty() {
        "/".to_string()
    } else if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    }
}

fn match_obj_url_path(pattern: &str, object_path: &str) -> Option<HashMap<String, String>> {
    let pattern_segments = path_segments(pattern);
    let object_segments = path_segments(object_path);
    let mut params = HashMap::new();
    let mut object_index = 0;

    for pattern_segment in pattern_segments {
        if pattern_segment == "*" {
            return Some(params);
        }

        let object_segment = object_segments.get(object_index)?;
        if let Some(name) = pattern_param_name(pattern_segment) {
            params.insert(name.to_string(), decode_segment(object_segment)?);
        } else if pattern_segment != *object_segment {
            return None;
        }

        object_index += 1;
    }

    if object_index == object_segments.len() {
        Some(params)
    } else {
        None
    }
}

fn pattern_param_name(segment: &str) -> Option<&str> {
    if segment.starts_with('{') && segment.ends_with('}') && segment.len() > 2 {
        return Some(&segment[1..segment.len() - 1]);
    }

    segment.strip_prefix(':').filter(|name| !name.is_empty())
}

fn path_segments(path: &str) -> Vec<&str> {
    path.split('/')
        .filter(|segment| !segment.is_empty())
        .collect()
}

fn segments_to_path(segments: &[&str]) -> String {
    if segments.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", segments.join("/"))
    }
}

fn decode_segment(segment: &str) -> Option<String> {
    percent_decode_str(segment)
        .decode_utf8()
        .ok()
        .map(|s| s.into_owned())
}

fn did_object_error_response(
    err: DIDObjectError,
) -> ServerResult<Response<BoxBody<Bytes, ServerError>>> {
    json_response(err.status_code(), &err)
}

fn did_object_action_error_response(
    err: DIDObjectError,
) -> ServerResult<Response<BoxBody<Bytes, ServerError>>> {
    let status = err.status_code();
    json_response(status, &DIDObjectActionResponse::from(err))
}

fn json_response<T: Serialize>(
    status: StatusCode,
    value: &T,
) -> ServerResult<Response<BoxBody<Bytes, ServerError>>> {
    let body = serde_json::to_vec(value).map_err(|e| {
        server_err!(
            ServerErrorCode::EncodeError,
            "failed to encode DID Object response: {}",
            e
        )
    })?;

    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(full_body(body))
        .map_err(|e| server_err!(ServerErrorCode::InvalidData, "{}", e))
}

fn full_body(body: impl Into<Bytes>) -> BoxBody<Bytes, ServerError> {
    Full::new(body.into())
        .map_err(|never| match never {})
        .boxed()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_item_after_matches_one_decoded_segment() {
        assert_eq!(
            path_item_after("/devices/cam01/props/brand", "props"),
            Some("brand".to_string())
        );
        assert_eq!(
            path_item_after("/devices/cam01/props/display%20name", "props"),
            Some("display name".to_string())
        );
        assert_eq!(path_item_after("/devices/cam01/props/a/b", "props"), None);
    }

    #[test]
    fn obj_url_pattern_matches_named_segments() {
        let pattern = DIDObjectUrlPattern::new("https://myhome.com/devices/{camera_id}");
        let captures = pattern.captures("/devices/cam%2001").unwrap();
        assert_eq!(captures.get("camera_id").unwrap(), "cam 01");
        assert_eq!(pattern.captures("/devices/cam01/props/brand"), None);

        let colon_pattern = DIDObjectUrlPattern::new("/devices/:camera_id");
        let captures = colon_pattern.captures("/devices/cam02").unwrap();
        assert_eq!(captures.get("camera_id").unwrap(), "cam02");
    }

    #[test]
    fn obj_url_pattern_supports_tail_wildcard() {
        let pattern = DIDObjectUrlPattern::new("/devices/*");
        assert!(pattern.captures("/devices/cam01").is_some());
        assert!(pattern.captures("/devices/room-a/cam01").is_some());
        assert!(pattern.captures("/rooms/room-a/cam01").is_none());
    }
}
