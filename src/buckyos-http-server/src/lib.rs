#![allow(dead_code)]

use std::net::IpAddr;
use std::sync::Arc;

use ::kRPC::{RPCHandler, RPCRequest, RPCResponse, RPCResult};
use buckyos_kit::AsyncStream;
use http::{Method, Request, Response, StatusCode};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper_util::rt::{TokioExecutor, TokioIo};

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum ServerErrorCode {
    BindFailed,
    NotFound,
    InvalidConfig,
    InvalidParam,
    ProcessChainError,
    StreamError,
    TunnelError,
    InvalidTlsKey,
    InvalidTlsCert,
    InvalidData,
    IOError,
    BadRequest,
    UnknownServerType,
    EncodeError,
    DnsQueryError,
    InvalidDnsOpType,
    InvalidDnsMessageType,
    InvalidDnsRecordType,
    Rejected,
    AlreadyExists,
}

pub type ServerResult<T> = sfo_result::Result<T, ServerErrorCode>;
pub type ServerError = sfo_result::Error<ServerErrorCode>;
pub use sfo_result::err as server_err;
pub use sfo_result::into_err as into_server_err;

#[derive(Default, Debug, Clone)]
pub struct StreamInfo {
    pub src_addr: Option<String>,
    pub dst_addr: Option<String>,
    pub conn_src_addr: Option<String>,
    pub real_src_addr: Option<String>,
    pub source_mac: Option<String>,
    pub source_hostname: Option<String>,
    pub source_online_secs: Option<String>,
}

impl StreamInfo {
    pub fn new(src_addr: String) -> Self {
        Self {
            src_addr: Some(src_addr.clone()),
            dst_addr: None,
            conn_src_addr: Some(src_addr),
            real_src_addr: None,
            source_mac: None,
            source_hostname: None,
            source_online_secs: None,
        }
    }

    pub fn with_addrs(conn_src_addr: Option<String>, real_src_addr: Option<String>) -> Self {
        let src_addr = real_src_addr.clone().or_else(|| conn_src_addr.clone());
        Self {
            src_addr,
            dst_addr: None,
            conn_src_addr,
            real_src_addr,
            source_mac: None,
            source_hostname: None,
            source_online_secs: None,
        }
    }

    pub fn with_device_info(
        mut self,
        source_mac: Option<String>,
        source_hostname: Option<String>,
        source_online_secs: Option<String>,
    ) -> Self {
        self.source_mac = source_mac;
        self.source_hostname = source_hostname;
        self.source_online_secs = source_online_secs;
        self
    }

    pub fn with_dst_addr(mut self, dst_addr: Option<String>) -> Self {
        self.dst_addr = dst_addr;
        self
    }
}

#[async_trait::async_trait]
pub trait HttpServer: Send + Sync + 'static {
    async fn serve_request(
        &self,
        req: http::Request<BoxBody<Bytes, ServerError>>,
        info: StreamInfo,
    ) -> ServerResult<http::Response<BoxBody<Bytes, ServerError>>>;

    fn id(&self) -> String;
    fn http_version(&self) -> http::Version;
    fn http3_port(&self) -> Option<u16>;
}

pub async fn serve_http_by_rpc_handler<T: RPCHandler + Send + Sync + 'static>(
    req: http::Request<BoxBody<Bytes, ServerError>>,
    info: StreamInfo,
    rpc_handler: &T,
) -> ServerResult<http::Response<BoxBody<Bytes, ServerError>>> {
    if req.method() != hyper::Method::POST {
        return Ok(text_response(
            hyper::StatusCode::METHOD_NOT_ALLOWED,
            "Method Not Allowed",
        )?);
    }

    let client_ip = match client_ip(&info) {
        Ok(client_ip) => client_ip,
        Err(resp) => return Ok(resp),
    };

    let body_bytes = match req.collect().await {
        Ok(data) => data.to_bytes(),
        Err(e) => {
            return Ok(text_response(
                hyper::StatusCode::BAD_REQUEST,
                format!("Failed to read body: {:?}", e),
            )?);
        }
    };

    let body_str = match String::from_utf8(body_bytes.to_vec()) {
        Ok(s) => s,
        Err(e) => {
            return Ok(text_response(
                hyper::StatusCode::BAD_REQUEST,
                format!("Failed to convert body to string: {}", e),
            )?);
        }
    };

    log::debug!("|==>recv kRPC req: {}", body_str);

    let rpc_request: RPCRequest = match serde_json::from_str(body_str.as_str()) {
        Ok(rpc_request) => rpc_request,
        Err(e) => {
            return Ok(text_response(
                hyper::StatusCode::BAD_REQUEST,
                format!("Failed to parse request body to RPCRequest: {}", e),
            )?);
        }
    };

    let rpc_seq = rpc_request.seq;
    let rpc_trace_id = rpc_request.trace_id.clone();
    let resp: RPCResponse = match rpc_handler.handle_rpc_call(rpc_request, client_ip).await {
        Ok(resp) => resp,
        Err(e) => {
            log::warn!("Failed to handle rpc call: {}", e);
            RPCResponse {
                result: RPCResult::Failed(e.to_string()),
                seq: rpc_seq,
                trace_id: rpc_trace_id,
            }
        }
    };

    let body_json = serde_json::to_string(&resp).map_err(|e| {
        server_err!(
            ServerErrorCode::EncodeError,
            "Failed to convert response to string: {}",
            e
        )
    })?;

    Ok(Response::builder()
        .body(full_body(body_json))
        .map_err(|e| {
            server_err!(
                ServerErrorCode::InvalidData,
                "Failed to build response: {}",
                e
            )
        })?)
}

pub async fn hyper_serve_http(
    stream: Box<dyn AsyncStream>,
    server: Arc<dyn HttpServer>,
    info: StreamInfo,
) -> ServerResult<()> {
    if server.http_version() <= http::Version::HTTP_11 {
        hyper_serve_http1(stream, server, info).await
    } else if server.http_version() == http::Version::HTTP_3 && server.http3_port().is_some() {
        serve_auto_http(stream, server, info, true).await
    } else {
        serve_auto_http(stream, server, info, false).await
    }
}

pub async fn hyper_serve_http1(
    stream: Box<dyn AsyncStream>,
    server: Arc<dyn HttpServer>,
    info: StreamInfo,
) -> ServerResult<()> {
    hyper::server::conn::http1::Builder::new()
        .serve_connection(
            TokioIo::new(stream),
            hyper::service::service_fn(|req| {
                let server = server.clone();
                let info = info.clone();
                async move { handle_request(req, server, info, false).await }
            }),
        )
        .await
        .map_err(|e| server_err!(ServerErrorCode::StreamError, "{e}"))?;

    Ok(())
}

async fn serve_auto_http(
    stream: Box<dyn AsyncStream>,
    server: Arc<dyn HttpServer>,
    info: StreamInfo,
    add_http3_alt_svc: bool,
) -> ServerResult<()> {
    hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
        .serve_connection(
            TokioIo::new(stream),
            hyper::service::service_fn(|req| {
                let server = server.clone();
                let info = info.clone();
                async move { handle_request(req, server, info, add_http3_alt_svc).await }
            }),
        )
        .await
        .map_err(|e| server_err!(ServerErrorCode::StreamError, "{e}"))?;

    Ok(())
}

async fn handle_request(
    req: hyper::Request<hyper::body::Incoming>,
    server: Arc<dyn HttpServer>,
    info: StreamInfo,
    add_http3_alt_svc: bool,
) -> ServerResult<Response<BoxBody<Bytes, ServerError>>> {
    let (parts, body) = req.into_parts();
    let req = Request::new(BoxBody::new(body))
        .map_err(|e| server_err!(ServerErrorCode::BadRequest, "{}", e))
        .boxed();
    let req = Request::from_parts(parts, req);

    let remote = info
        .src_addr
        .clone()
        .unwrap_or_else(|| "unknown".to_string());
    let method_is_options = req.method() == Method::OPTIONS;
    let method = req.method().to_string();
    let host = req
        .headers()
        .get("host")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("none")
        .to_string();
    let uri = req.uri().to_string();

    log::debug!(
        "recv http request:remote {} method {} host {} path {}",
        remote,
        method,
        host,
        uri,
    );

    match server.serve_request(req, info).await {
        Ok(mut resp) => {
            if add_http3_alt_svc {
                if let Some(http3_port) = server.http3_port() {
                    let value = format!("h3=\":{http3_port}\"; ma=86400");
                    resp.headers_mut().insert(
                        http::header::ALT_SVC,
                        http::HeaderValue::from_str(value.as_str())
                            .map_err(|e| server_err!(ServerErrorCode::InvalidData, "{:?}", e))?,
                    );
                }
            }

            log_forbidden(
                &server,
                resp.status(),
                method_is_options,
                remote,
                method,
                host,
                uri,
            );
            Ok(resp)
        }
        Err(e) => {
            log::error!("http error {}", e);
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(
                    Full::new(Bytes::from(e.msg().to_string()))
                        .map_err(|e| server_err!(ServerErrorCode::BadRequest, "{:?}", e))
                        .boxed(),
                )
                .map_err(|e| server_err!(ServerErrorCode::StreamError, "{:?}", e))
        }
    }
}

fn log_forbidden(
    server: &Arc<dyn HttpServer>,
    status: StatusCode,
    method_is_options: bool,
    remote: String,
    method: String,
    host: String,
    uri: String,
) {
    if status != StatusCode::FORBIDDEN {
        return;
    }

    if method_is_options {
        log::warn!(
            "http_forbidden server={} remote={} method={} host={} uri={}",
            server.id(),
            remote,
            method,
            host,
            uri,
        );
    } else {
        log::debug!(
            "http_forbidden server={} remote={} method={} host={} uri={}",
            server.id(),
            remote,
            method,
            host,
            uri,
        );
    }
}

fn client_ip(info: &StreamInfo) -> Result<IpAddr, http::Response<BoxBody<Bytes, ServerError>>> {
    match info.src_addr.as_ref() {
        Some(addr) => match addr.parse::<std::net::SocketAddr>() {
            Ok(sa) => Ok(sa.ip()),
            Err(e) => {
                log::error!("parse client ip {} err {}", addr, e);
                Err(text_response(hyper::StatusCode::BAD_REQUEST, "Bad Request")
                    .expect("static bad request response should build"))
            }
        },
        None => {
            log::error!("Failed to get client ip");
            Err(text_response(hyper::StatusCode::BAD_REQUEST, "Bad Request")
                .expect("static bad request response should build"))
        }
    }
}

fn text_response(
    status: StatusCode,
    body: impl Into<Bytes>,
) -> ServerResult<Response<BoxBody<Bytes, ServerError>>> {
    Response::builder()
        .status(status)
        .body(full_body(body))
        .map_err(|e| {
            server_err!(
                ServerErrorCode::BadRequest,
                "Failed to build response: {}",
                e
            )
        })
}

fn full_body(body: impl Into<Bytes>) -> BoxBody<Bytes, ServerError> {
    Full::new(body.into())
        .map_err(|never| match never {})
        .boxed()
}

#[cfg(test)]
mod tests {
    use super::*;

    use ::kRPC::RPCErrors;
    use async_trait::async_trait;
    use http_body_util::BodyExt;
    use serde_json::json;

    struct ErrorRpcHandler;

    #[async_trait]
    impl RPCHandler for ErrorRpcHandler {
        async fn handle_rpc_call(
            &self,
            _req: RPCRequest,
            _ip_from: IpAddr,
        ) -> Result<RPCResponse, RPCErrors> {
            Err(RPCErrors::ReasonError("boom".to_string()))
        }
    }

    #[tokio::test]
    async fn serve_http_by_rpc_handler_returns_rpc_error_response() {
        let mut rpc_request = RPCRequest::new("test", json!({ "ok": false }));
        rpc_request.seq = 42;
        rpc_request.trace_id = Some("trace-1".to_string());

        let request = http::Request::builder()
            .method("POST")
            .uri("http://localhost/krpc")
            .body(full_body(serde_json::to_string(&rpc_request).unwrap()))
            .unwrap();

        let response = serve_http_by_rpc_handler(
            request,
            StreamInfo::new("127.0.0.1:12345".to_string()),
            &ErrorRpcHandler,
        )
        .await
        .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let rpc_response: RPCResponse =
            serde_json::from_slice(&response.collect().await.unwrap().to_bytes()).unwrap();

        assert_eq!(
            rpc_response,
            RPCResponse {
                result: RPCResult::Failed("Failed due to reason: boom".to_string()),
                seq: 42,
                trace_id: Some("trace-1".to_string()),
            }
        );
    }
}
