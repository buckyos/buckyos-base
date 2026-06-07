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
    http_version: http::Version,
    http3_port: Option<u16>,
}

impl<T: DIDObjectServer> DIDObjectHttpServer<T> {
    pub fn new(id: impl Into<String>, inner: Arc<T>) -> Self {
        Self {
            id: id.into(),
            inner,
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

    fn request_context(&self, path: &str, info: StreamInfo) -> DIDObjectRequestContext {
        DIDObjectRequestContext {
            stream_info: info,
            path: path.to_string(),
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

        if method == Method::GET && last_path_segment(&path) == Some(DID_OBJECT_CARD_PATH) {
            return json_response(StatusCode::OK, self.inner.object_card());
        }

        if method == Method::GET && last_path_segment(&path) == Some(DID_OBJECT_PROFILE_PATH) {
            return json_response(StatusCode::OK, self.inner.object_profile());
        }

        if method == Method::GET {
            if let Some(property) = path_item_after(&path, DID_OBJECT_PROPERTY_PREFIX) {
                let ctx = self.request_context(&path, info);
                return match self.inner.read_property(&property, ctx).await {
                    Ok(value) => json_response(StatusCode::OK, &value),
                    Err(err) => did_object_error_response(err),
                };
            }
        }

        if method == Method::POST {
            if let Some(action) = path_item_after(&path, DID_OBJECT_ACTION_PREFIX) {
                let body = req.into_body().collect().await.map_err(|e| {
                    server_err!(
                        ServerErrorCode::BadRequest,
                        "failed to read DID Object action body: {:?}",
                        e
                    )
                })?;
                let request =
                    match serde_json::from_slice::<DIDObjectActionRequest>(&body.to_bytes()) {
                        Ok(request) => request,
                        Err(err) => {
                            return did_object_action_error_response(DIDObjectError::bad_request(
                                format!("invalid DID Object action request: {err}"),
                            ));
                        }
                    };

                if request.method != action {
                    return did_object_action_error_response(DIDObjectError::bad_request(format!(
                        "action endpoint '{action}' does not match request method '{}'",
                        request.method
                    )));
                }

                let ctx = self.request_context(&path, info);
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
        }

        if path_item_after(&path, DID_OBJECT_EVENT_PREFIX).is_some()
            || last_path_segment(&path) == Some(DID_OBJECT_EVENT_PREFIX)
        {
            let event = path_item_after(&path, DID_OBJECT_EVENT_PREFIX);
            let ctx = self.request_context(&path, info);
            return match self.inner.handle_event_request(event.as_deref(), ctx).await {
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

fn normalize_path(path: &str) -> String {
    path.trim_end_matches('/').to_string()
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
}
