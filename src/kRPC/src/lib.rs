#![allow(dead_code)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
mod example_krpc_client;
mod protocol;
pub mod s2s;
mod session_token;

pub use protocol::*;
pub use session_token::*;

use reqwest::{Client, ClientBuilder};
use s2s::{
    api_name_from_path, S2sClientConfig, S2sClientTransport, S2sError, S2sResponseHeaders,
    S2S_CONTENT_TYPE, S2S_PATH_PREFIX, S2S_PROBE_API,
};
use serde_json::Value;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::sync::RwLock;

//TODO:整体设计基本与jsonrpc2.0一致，要考虑是否完全兼容

#[derive(Error, Debug)]
pub enum RPCErrors {
    #[error("Failed due to reason: {0}")]
    ReasonError(String),
    #[error("Unknown method: {0}")]
    UnknownMethod(String),
    #[error("Invalid token: {0}")]
    InvalidToken(String),
    #[error("Parse Request Error: {0}")]
    ParseRequestError(String),
    #[error("Parse Response Error: {0}")]
    ParserResponseError(String),
    #[error("Token expired:{0}")]
    TokenExpired(String),
    #[error("No permission:{0}")]
    NoPermission(String),
    #[error("Invalid password")]
    InvalidPassword,
    #[error("User Not Found:{0}")]
    UserNotFound(String),
    #[error("Key not exist: {0}")]
    KeyNotExist(String),
    #[error("Service not valid: {0}")]
    ServiceNotValid(String),
    /// S2S transport 永久失败(身份/密钥/配置类):重试无意义,
    /// 必须进入告警或 dead-letter 流程,不能当作临时网络问题吞掉。
    #[error("S2S permanent failure: {0}")]
    S2sPermanentError(String),
    /// S2S transport 临时失败(网络超时、临时不可用):可按业务策略有界重试。
    #[error("S2S transient failure: {0}")]
    S2sTransientError(String),
}
pub type Result<T> = std::result::Result<T, RPCErrors>;
const DEFAULT_KRPC_TIMEOUT_SECS: u64 = 15;

/// 客户端 transport 安全模式(显式配置,不由 URL scheme 猜测;
/// doc/krpc-s2s-payload-encryption-TODO.md §11.1)。
pub enum KrpcTransportSecurity {
    /// 现有明文 JSON 模式(wire 兼容不变)。
    Plaintext,
    /// 强制 https URL 的明文 JSON 模式(wire 兼容不变)。
    Tls,
    /// S2S Payload Protection v1(http URL 上的端到端 Payload 加密)。
    S2sPayloadV1(S2sClientConfig),
    /// TLS 之上叠加 S2S Payload v1(强制 https URL)。
    TlsAndS2sPayloadV1(S2sClientConfig),
}

enum ClientTransport {
    /// Plaintext / Tls:现有 JSON POST。
    PlainJson,
    /// S2S v1:binary body + `KRPC-S2S-*` header。
    S2s {
        transport: S2sClientTransport,
        canonical_api: String,
        /// `/s2s/__probe` 的完整 URL(同 host)。
        probe_url: String,
    },
}

pub struct kRPC {
    client: Client,
    server_url: String,
    protcol_type: RPCProtoclType,
    seq: RwLock<u64>,
    session_token: RwLock<Option<String>>,
    trace_id: RwLock<Option<String>>,
    transport: ClientTransport,
}

impl kRPC {
    pub fn new(url: &str, token: Option<String>) -> Self {
        Self::new_with_timeout_secs(url, token, DEFAULT_KRPC_TIMEOUT_SECS)
    }

    pub fn new_with_timeout_secs(url: &str, token: Option<String>, timeout_secs: u64) -> Self {
        let timeout_secs = timeout_secs.max(1);
        Self::new_with_timeout(url, token, Duration::from_secs(timeout_secs))
    }

    pub fn new_with_timeout(url: &str, token: Option<String>, timeout: Duration) -> Self {
        let client = ClientBuilder::new()
            //.https_only(true)
            .tcp_keepalive(Some(Duration::from_secs(60)))
            .pool_max_idle_per_host(10)
            .timeout(timeout)
            .build()
            .expect("Failed to build reqwest client");

        Self::build(client, url, token, ClientTransport::PlainJson)
    }

    /// 显式 transport 模式构造(§11.1)。
    ///
    /// - `Tls` / `TlsAndS2sPayloadV1` 要求 `https://` URL;
    /// - S2S 模式要求 URL path 为 `/s2s/{api}`,并禁用 HTTP redirect;
    /// - `S2sPayloadV1` 失败后绝不发送明文。
    pub async fn new_with_transport(
        url: &str,
        token: Option<String>,
        transport: KrpcTransportSecurity,
    ) -> Result<Self> {
        Self::new_with_transport_and_timeout(
            url,
            token,
            transport,
            Duration::from_secs(DEFAULT_KRPC_TIMEOUT_SECS),
        )
        .await
    }

    pub async fn new_with_transport_and_timeout(
        url: &str,
        token: Option<String>,
        transport: KrpcTransportSecurity,
        timeout: Duration,
    ) -> Result<Self> {
        let require_tls = matches!(
            transport,
            KrpcTransportSecurity::Tls | KrpcTransportSecurity::TlsAndS2sPayloadV1(_)
        );
        if require_tls && !url.starts_with("https://") {
            return Err(RPCErrors::S2sPermanentError(format!(
                "transport requires https url, got {}",
                url
            )));
        }

        match transport {
            KrpcTransportSecurity::Plaintext | KrpcTransportSecurity::Tls => {
                Ok(Self::new_with_timeout(url, token, timeout))
            }
            KrpcTransportSecurity::S2sPayloadV1(config)
            | KrpcTransportSecurity::TlsAndS2sPayloadV1(config) => {
                let parsed_url: reqwest::Url = url
                    .parse()
                    .map_err(|e| RPCErrors::S2sPermanentError(format!("bad url {}: {}", url, e)))?;
                let canonical_api = api_name_from_path(parsed_url.path())
                    .map_err(|e| RPCErrors::S2sPermanentError(format!("bad s2s url path: {}", e)))?;
                let mut probe_url = parsed_url.clone();
                probe_url.set_path(&format!("{}{}", S2S_PATH_PREFIX, S2S_PROBE_API));

                let transport = S2sClientTransport::new(config)
                    .await
                    .map_err(|e| RPCErrors::S2sPermanentError(e.to_string()))?;

                // S2S 模式:禁用 redirect(§11.1)
                let client = ClientBuilder::new()
                    .tcp_keepalive(Some(Duration::from_secs(60)))
                    .pool_max_idle_per_host(10)
                    .timeout(timeout)
                    .redirect(reqwest::redirect::Policy::none())
                    .build()
                    .expect("Failed to build reqwest client");

                Ok(Self::build(
                    client,
                    url,
                    token,
                    ClientTransport::S2s {
                        transport,
                        canonical_api,
                        probe_url: probe_url.to_string(),
                    },
                ))
            }
        }
    }

    fn build(client: Client, url: &str, token: Option<String>, transport: ClientTransport) -> Self {
        let start = SystemTime::now();
        let since_the_epoch = start
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards");
        let timestamp_millis = since_the_epoch.as_secs() as u64 * 1_000_000;

        kRPC {
            client,
            server_url: url.to_string(),
            protcol_type: RPCProtoclType::HttpPostJson,
            seq: RwLock::new(timestamp_millis),
            session_token: RwLock::new(token),
            trace_id: RwLock::new(None),
            transport,
        }
    }

    pub async fn reset_session_token(&self) {
        let mut session_token = self.session_token.write().await;
        *session_token = None;
    }

    pub async fn get_session_token(&self) -> Option<String> {
        let session_token = self.session_token.read().await;
        session_token.clone()
    }

    pub async fn call(&self, method: &str, params: Value) -> Result<Value> {
        //TODO: do auto-retry by config
        self._call(method, params).await
    }

    /// 加密探测(§13):走与业务请求完全相同的 admission/时间窗/replay 管线,
    /// 验证 endpoint、双方 key、KDF 与 request/response AEAD,但不执行业务 API。
    /// `check_api` 额外验证服务端 registry 中是否存在该 API(受服务端 RBAC 约束)。
    pub async fn probe_s2s(&self, check_api: Option<&str>) -> Result<Value> {
        let ClientTransport::S2s { .. } = &self.transport else {
            return Err(RPCErrors::S2sPermanentError(
                "probe_s2s requires S2S transport mode".to_string(),
            ));
        };
        let params = match check_api {
            Some(api) => serde_json::json!({ "check_api": api }),
            None => serde_json::json!({}),
        };
        self._call_inner(S2S_PROBE_API, "__probe", params, true).await
    }

    pub async fn set_context(&self, context: RPCContext) {
        let mut session_token = self.session_token.write().await;
        *session_token = context.token.clone();
        drop(session_token);

        let mut trace_id = self.trace_id.write().await;
        *trace_id = context.trace_id.clone();
        drop(trace_id);
    }

    async fn _call(&self, method: &str, params: Value) -> Result<Value> {
        self._call_inner("", method, params, false).await
    }

    async fn _call_inner(
        &self,
        api_override: &str,
        method: &str,
        params: Value,
        is_probe: bool,
    ) -> Result<Value> {
        let request_body: Value;
        let current_seq: u64;
        {
            let mut seq = self.seq.write().await;
            *seq += 1;
            current_seq = *seq;
            drop(seq);

            let session_token = self.session_token.read().await;
            let current_session_token = session_token.clone();
            drop(session_token);
            let trace_id = self.trace_id.read().await;
            let current_trace_id = trace_id.clone();
            drop(trace_id);

            let mut request = RPCRequest::new(method, params);
            request.seq = current_seq;
            request.token = current_session_token;
            request.trace_id = current_trace_id;
            request_body = serde_json::to_value(&request).map_err(|err| {
                RPCErrors::ParseRequestError(format!("serialize request failed: {}", err))
            })?;
        }

        match &self.transport {
            ClientTransport::PlainJson => self.post_plain_json(&request_body, current_seq).await,
            ClientTransport::S2s {
                transport,
                canonical_api,
                probe_url,
            } => {
                let (api, url) = if is_probe {
                    (api_override, probe_url.as_str())
                } else {
                    (canonical_api.as_str(), self.server_url.as_str())
                };
                self.post_s2s(transport, api, url, &request_body, current_seq)
                    .await
            }
        }
    }

    async fn post_plain_json(&self, request_body: &Value, current_seq: u64) -> Result<Value> {
        let response = self
            .client
            .post(&self.server_url)
            .json(request_body)
            .send()
            .await
            .map_err(|err| RPCErrors::ReasonError(format!("{}", err)))?;

        if response.status().is_success() {
            let rpc_response: RPCResponse = response
                .json()
                .await
                .map_err(|err| RPCErrors::ParserResponseError(format!("{}", err)))?;

            Self::check_rpc_response(rpc_response, current_seq)
        } else {
            Err(RPCErrors::ReasonError(format!(
                "rpc call error: {}",
                response.status()
            )))
        }
    }

    /// S2S 发送:失败绝不降级明文;解密失败/服务端拒绝时 refresh 目标 key 后
    /// 用新 nonce 有界重试一次(§10.2)。
    async fn post_s2s(
        &self,
        transport: &S2sClientTransport,
        canonical_api: &str,
        url: &str,
        request_body: &Value,
        current_seq: u64,
    ) -> Result<Value> {
        let request_json = serde_json::to_vec(request_body)
            .map_err(|err| RPCErrors::ParseRequestError(format!("{}", err)))?;

        let mut last_err: Option<RPCErrors> = None;
        for attempt in 0..2 {
            let refresh = attempt > 0;
            let now = buckyos_kit::buckyos_get_unix_timestamp();
            let (headers, sealed, pending) = transport
                .seal_request(canonical_api, &request_json, now, refresh)
                .await
                .map_err(map_s2s_error)?;

            let mut header_map = http::HeaderMap::new();
            headers
                .apply(&mut header_map)
                .map_err(map_s2s_error)?;
            header_map.insert(
                http::header::CONTENT_TYPE,
                http::HeaderValue::from_static(S2S_CONTENT_TYPE),
            );

            let response = match self
                .client
                .post(url)
                .headers(header_map)
                .body(sealed)
                .send()
                .await
            {
                Ok(resp) => resp,
                Err(err) => {
                    // 网络类失败:transient,不做 key refresh 重试
                    return Err(RPCErrors::S2sTransientError(format!("{}", err)));
                }
            };

            let status = response.status();
            if !status.is_success() {
                // 服务端在认证响应前失败(统一无细节拒绝):可能是 key/config
                // 漂移,refresh 后重试一次
                last_err = Some(RPCErrors::S2sPermanentError(format!(
                    "s2s transport rejected: {}",
                    status
                )));
                continue;
            }

            let content_type = response
                .headers()
                .get(http::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .map(|v| s2s::parse_media_type(v))
                .flatten();
            if content_type.as_deref() != Some(S2S_CONTENT_TYPE) {
                return Err(RPCErrors::S2sPermanentError(
                    "response is not s2s content type".to_string(),
                ));
            }

            let response_headers = S2sResponseHeaders::parse(response.headers())
                .map_err(map_s2s_error)?;

            if let Some(len) = response.content_length() {
                if len > s2s::S2S_DEFAULT_MAX_BODY_SIZE as u64 {
                    return Err(RPCErrors::S2sPermanentError(
                        "response body too large".to_string(),
                    ));
                }
            }
            let body = response
                .bytes()
                .await
                .map_err(|err| RPCErrors::S2sTransientError(format!("{}", err)))?;
            if body.len() > s2s::S2S_DEFAULT_MAX_BODY_SIZE {
                return Err(RPCErrors::S2sPermanentError(
                    "response body too large".to_string(),
                ));
            }

            let now = buckyos_kit::buckyos_get_unix_timestamp();
            match transport
                .open_response(&pending, &response_headers, &body, now)
                .await
            {
                Ok(plaintext) => {
                    let rpc_response: RPCResponse = serde_json::from_slice(&plaintext)
                        .map_err(|err| RPCErrors::ParserResponseError(format!("{}", err)))?;
                    return Self::check_rpc_response(rpc_response, current_seq);
                }
                Err(S2sError::DecryptFailed) => {
                    // 可能目标 key 轮换:refresh 后新 nonce 重试一次
                    last_err = Some(RPCErrors::S2sPermanentError(
                        "response decrypt failed".to_string(),
                    ));
                    continue;
                }
                Err(err) => return Err(map_s2s_error(err)),
            }
        }
        Err(last_err.unwrap_or_else(|| {
            RPCErrors::S2sPermanentError("s2s call failed".to_string())
        }))
    }

    fn check_rpc_response(rpc_response: RPCResponse, current_seq: u64) -> Result<Value> {
        if rpc_response.seq != current_seq {
            return Err(RPCErrors::ParserResponseError(format!(
                "seq not match: {}!={}",
                rpc_response.seq, current_seq
            )));
        }

        match rpc_response.result {
            RPCResult::Success(value) => Ok(value),
            RPCResult::Failed(err) => {
                Err(RPCErrors::ReasonError(format!("rpc call error: {}", err)))
            }
        }
    }
}

fn map_s2s_error(err: S2sError) -> RPCErrors {
    if err.is_permanent() {
        RPCErrors::S2sPermanentError(err.to_string())
    } else {
        RPCErrors::S2sTransientError(err.to_string())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use serde_json::json;
    #[test]
    fn test_encode_decode() {
        let req = RPCRequest {
            method: "add".to_string(),
            params: json!({"a":1,"b":2}),
            seq: 100,
            token: None,
            trace_id: Some("$trace_id".to_string()),
        };
        let encoded = serde_json::to_string(&req).unwrap();
        println!("req encoded:{}", encoded);

        let decoded: RPCRequest = serde_json::from_str(&encoded).unwrap();
        assert_eq!(req, decoded);

        let resp = RPCResponse {
            result: RPCResult::Success(json!(100)),
            seq: 100,
            trace_id: Some("$trace_id".to_string()),
        };
        let encoded = serde_json::to_string(&resp).unwrap();
        println!("resp encoded:{}", encoded);
        let decoded: RPCResponse = serde_json::from_str(&encoded).unwrap();
        assert_eq!(resp, decoded);

        let resp = RPCResponse {
            result: RPCResult::Failed("game over".to_string()),
            seq: 100,
            trace_id: None,
        };
        let encoded = serde_json::to_string(&resp).unwrap();
        println!("resp encoded:{}", encoded);
        let decoded: RPCResponse = serde_json::from_str(&encoded).unwrap();
        assert_eq!(resp, decoded);
    }
}
