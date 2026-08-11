use crate::RPCErrors;
use async_trait::async_trait;
use buckyos_kit::buckyos_get_unix_timestamp;
use serde::ser::SerializeStruct;
use serde::{Deserialize, Serialize, Serializer};
use serde_json::Value;
use std::net::IpAddr;
pub enum RPCProtoclType {
    HttpPostJson,
}

#[derive(Debug, PartialEq)]
pub struct RPCRequest {
    pub method: String,
    pub params: Value,
    //0: seq,1:token(option),2:trace_id(option)
    //pub sys:  Option<Vec<Value>>,
    pub seq: u64,
    pub token: Option<String>,
    pub trace_id: Option<String>,
}

impl RPCRequest {
    pub fn new(method: &str, params: Value) -> Self {
        RPCRequest {
            method: method.to_string(),
            params: params,
            seq: 0,
            token: None,
            trace_id: None,
        }
    }

    pub fn get_str_param(self: &RPCRequest, key: &str) -> Result<String, RPCErrors> {
        self.params
            .get(key)
            .and_then(|value| value.as_str())
            .map(|value| value.to_string())
            .ok_or(RPCErrors::ParseRequestError(format!(
                "Failed to get {} from params",
                key
            )))
    }
}

impl Serialize for RPCRequest {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("RPCRequest", 2)?;
        state.serialize_field("method", &self.method)?;
        state.serialize_field("params", &self.params)?;
        let mut sys_vec = vec![Value::from(self.seq)];
        if let Some(token) = self.token.as_ref() {
            sys_vec.push(Value::from(token.clone()));
        } else if self.trace_id.is_some() {
            // keep slot for token when trace_id exists
            sys_vec.push(Value::Null);
        }
        if let Some(trace_id) = self.trace_id.as_ref() {
            sys_vec.push(Value::from(trace_id.clone()));
        }
        state.serialize_field("sys", &sys_vec)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for RPCRequest {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let v = Value::deserialize(deserializer)?;
        let method = v
            .get("method")
            .ok_or(serde::de::Error::missing_field("method"))?;
        let method = method
            .as_str()
            .ok_or(serde::de::Error::custom("method is not string"))?;
        let params = v
            .get("params")
            .ok_or(serde::de::Error::missing_field("params"))?;

        let sys = v.get("sys");
        let mut seq: u64 = 0;
        let mut token: Option<String> = None;
        let mut trace_id: Option<String> = None;
        if sys.is_some() {
            let sys = sys
                .unwrap()
                .as_array()
                .ok_or(serde::de::Error::custom("sys is not array"))?;

            if sys.len() > 0 {
                let _seq = sys[0]
                    .as_u64()
                    .ok_or(serde::de::Error::custom("sys[0] seq is not u64"))?;
                seq = _seq;
            }
            if sys.len() > 1 {
                let token_value = &sys[1];
                if !token_value.is_null() {
                    let _token = token_value
                        .as_str()
                        .ok_or(serde::de::Error::custom("sys[1] token is not string"))?;
                    token = Some(_token.to_string());
                }
            }
            if sys.len() > 2 {
                let trace_value = &sys[2];
                if !trace_value.is_null() {
                    let _trace_id = trace_value
                        .as_str()
                        .ok_or(serde::de::Error::custom("sys[2] trace_id is not string"))?;
                    trace_id = Some(_trace_id.to_string());
                }
            }
        }

        Ok(RPCRequest {
            method: method.to_string(),
            params: params.clone(),
            seq,
            token: token,
            trace_id: trace_id,
        })
    }
}

#[derive(Debug, PartialEq)]
pub enum RPCResult {
    Success(Value),
    Failed(String),
}

#[derive(Debug, PartialEq)]
pub struct RPCResponse {
    pub result: RPCResult,

    pub seq: u64,
    pub trace_id: Option<String>,
}

impl RPCResponse {
    pub fn new(result: RPCResult, seq: u64) -> Self {
        RPCResponse {
            result: result,
            seq: seq,
            trace_id: None,
        }
    }

    pub fn create_by_req(result: RPCResult, req: &RPCRequest) -> Self {
        RPCResponse {
            result: result,
            seq: req.seq,
            trace_id: req.trace_id.clone(),
        }
    }
}

impl Serialize for RPCResponse {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match &self.result {
            RPCResult::Success(value) => {
                let mut state: <S as Serializer>::SerializeStruct =
                    serializer.serialize_struct("RPCResponse", 1)?;
                state.serialize_field("result", &value)?;

                let mut sys_vec = vec![Value::from(self.seq)];
                if let Some(trace_id) = self.trace_id.as_ref() {
                    sys_vec.push(Value::from(trace_id.clone()));
                }

                state.serialize_field("sys", &sys_vec)?;

                state.end()
            }
            RPCResult::Failed(err) => {
                let mut state = serializer.serialize_struct("RPCResponse", 1)?;
                state.serialize_field("error", &err)?;
                let mut sys_vec = vec![Value::from(self.seq)];
                if let Some(trace_id) = self.trace_id.as_ref() {
                    sys_vec.push(Value::from(trace_id.clone()));
                }

                state.serialize_field("sys", &sys_vec)?;
                state.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for RPCResponse {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let v = Value::deserialize(deserializer)?;
        let sys = v.get("sys");
        let mut seq: u64 = 0;
        let mut trace_id: Option<String> = None;
        if sys.is_some() {
            let sys = sys
                .unwrap()
                .as_array()
                .ok_or(serde::de::Error::custom("sys is not array"))?;

            if sys.len() > 0 {
                let _seq = sys[0]
                    .as_u64()
                    .ok_or(serde::de::Error::custom("sys[0] seq is not u64"))?;
                seq = _seq;
            }

            if sys.len() > 1 {
                let _trace_id = sys[1]
                    .as_str()
                    .ok_or(serde::de::Error::custom("sys[1] trace_id is not string"))?;
                trace_id = Some(_trace_id.to_string());
            }
        }

        if v.get("error").is_some() {
            Ok(RPCResponse {
                result: RPCResult::Failed(v.get("error").unwrap().as_str().unwrap().to_string()),
                seq: seq,
                trace_id: trace_id,
            })
        } else {
            Ok(RPCResponse {
                result: RPCResult::Success(v.get("result").unwrap().clone()),
                seq: seq,
                trace_id: trace_id,
            })
        }
    }
}

/// 服务端观察到的 transport 安全模式(doc/krpc-s2s-payload-encryption-TODO.md §9.2)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RPCTransportSecurity {
    Plaintext,
    Tls,
    S2sPayloadV1,
    TlsAndS2sPayloadV1,
}

/// dispatch 前由 transport 层构造的 server-side context(§9.2)。
///
/// 必须区分:
/// - `from_ip`:网络观察值,不是密码学身份;
/// - `admitted_by_trusted_network`:只说明 plaintext transport 被放行,
///   不代表 service 身份;
/// - `authenticated_from_service_did`:AEAD 成功后确认的 canonical service DID;
///   plaintext 分支恒为 `None`。
#[derive(Debug, Clone)]
pub struct RPCServerContext {
    pub from_ip: Option<IpAddr>,
    pub source_ip_provenance: Option<crate::s2s::SourceIpProvenance>,
    pub transport_security: RPCTransportSecurity,
    pub admitted_by_trusted_network: bool,
    pub authenticated_from_service_did: Option<name_lib::DID>,
    pub authenticated_from_key_fingerprint: Option<[u8; 32]>,
    pub canonical_api_name: Option<String>,
}

impl RPCServerContext {
    /// 现有明文入口使用的 context(行为与旧 `handle_rpc_call(req, ip)` 一致)。
    pub fn plaintext(from_ip: IpAddr) -> Self {
        Self {
            from_ip: Some(from_ip),
            source_ip_provenance: None,
            transport_security: RPCTransportSecurity::Plaintext,
            admitted_by_trusted_network: false,
            authenticated_from_service_did: None,
            authenticated_from_key_fingerprint: None,
            canonical_api_name: None,
        }
    }
}

//通过RPCContext可以方便跟踪和调试一个长的call chain
//call chain用trace_id来定义
#[derive(Debug, PartialEq, Clone)]
pub struct RPCContext {
    pub seq: u64,
    pub schema: Option<String>,
    pub start_time: u64,
    pub token: Option<String>, //jwt session token
    pub trace_id: Option<String>,
    pub from_ip: Option<IpAddr>, //filled by gateway,client never fill this
    pub from_device: Option<String>, //filled by gateway,client never fill this
    /// S2S 加密验证成功后的 sender service DID(§9.2);plaintext 恒为 None。
    pub authenticated_from_service_did: Option<name_lib::DID>,
    /// 实际参与 DH 的 sender key fingerprint。
    pub authenticated_from_key_fingerprint: Option<[u8; 32]>,
    /// plaintext transport 是否经由可信网段 allowlist 放行(不是身份)。
    pub admitted_by_trusted_network: bool,
}

impl Default for RPCContext {
    fn default() -> Self {
        Self {
            seq: 0,
            schema: None,
            start_time: 0,
            token: None,
            trace_id: None,
            from_ip: None,
            from_device: None,
            authenticated_from_service_did: None,
            authenticated_from_key_fingerprint: None,
            admitted_by_trusted_network: false,
        }
    }
}

impl RPCContext {
    pub fn from_request(req: &RPCRequest, ip_from: IpAddr) -> Self {
        Self {
            seq: req.seq,
            schema: None,
            start_time: buckyos_get_unix_timestamp(),
            token: req.token.clone(),
            trace_id: req.trace_id.clone(),
            from_ip: Some(ip_from),
            from_device: None,
            ..Default::default()
        }
    }

    /// 从 server context 构造(携带 authenticated service identity,
    /// 供 token/RBAC 做一致性检查)。
    pub fn from_server_context(req: &RPCRequest, server_ctx: &RPCServerContext) -> Self {
        Self {
            seq: req.seq,
            schema: None,
            start_time: buckyos_get_unix_timestamp(),
            token: req.token.clone(),
            trace_id: req.trace_id.clone(),
            from_ip: server_ctx.from_ip,
            from_device: None,
            authenticated_from_service_did: server_ctx.authenticated_from_service_did.clone(),
            authenticated_from_key_fingerprint: server_ctx.authenticated_from_key_fingerprint,
            admitted_by_trusted_network: server_ctx.admitted_by_trusted_network,
        }
    }
}

#[async_trait]
pub trait RPCHandler {
    async fn handle_rpc_call(
        &self,
        req: RPCRequest,
        ip_from: IpAddr,
    ) -> Result<RPCResponse, RPCErrors>;
}

/// context-aware handler(§9.2):S2S 入口通过它把 authenticated service
/// identity 传给业务层。
///
/// 所有 `RPCHandler` 实现自动获得 blanket adapter(丢弃额外 context,仅传
/// IP,行为与旧入口一致);需要 authenticated identity 的服务直接实现本
/// trait(不再实现 `RPCHandler`)。
#[async_trait]
pub trait RPCServerHandler: Send + Sync {
    async fn handle_rpc_call_with_context(
        &self,
        req: RPCRequest,
        server_ctx: &RPCServerContext,
    ) -> Result<RPCResponse, RPCErrors>;
}

#[async_trait]
impl<T: RPCHandler + Send + Sync> RPCServerHandler for T {
    async fn handle_rpc_call_with_context(
        &self,
        req: RPCRequest,
        server_ctx: &RPCServerContext,
    ) -> Result<RPCResponse, RPCErrors> {
        let Some(from_ip) = server_ctx.from_ip else {
            return Err(RPCErrors::ReasonError(
                "server context has no source ip".to_string(),
            ));
        };
        self.handle_rpc_call(req, from_ip).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn serialize_request_sys_len_1() {
        let mut req = RPCRequest::new("ping", json!({"k":"v"}));
        req.seq = 7;
        let value = serde_json::to_value(req).expect("serialize request");
        assert_eq!(value.get("sys").unwrap(), &json!([7]));
    }

    #[test]
    fn serialize_request_sys_len_2() {
        let mut req = RPCRequest::new("ping", json!({"k":"v"}));
        req.seq = 8;
        req.token = Some("t1".to_string());
        let value = serde_json::to_value(req).expect("serialize request");
        assert_eq!(value.get("sys").unwrap(), &json!([8, "t1"]));
    }

    #[test]
    fn serialize_request_sys_len_3_with_null_token() {
        let mut req = RPCRequest::new("ping", json!({"k":"v"}));
        req.seq = 9;
        req.trace_id = Some("tr1".to_string());
        let value = serde_json::to_value(req).expect("serialize request");
        assert_eq!(value.get("sys").unwrap(), &json!([9, null, "tr1"]));
    }

    #[test]
    fn deserialize_request_sys_len_1() {
        let value = json!({
            "method": "ping",
            "params": {"k": "v"},
            "sys": [7]
        });
        let req: RPCRequest = serde_json::from_value(value).expect("deserialize request");
        assert_eq!(req.seq, 7);
        assert_eq!(req.token, None);
        assert_eq!(req.trace_id, None);
    }

    #[test]
    fn deserialize_request_sys_len_2() {
        let value = json!({
            "method": "ping",
            "params": {"k": "v"},
            "sys": [7, "t1"]
        });
        let req: RPCRequest = serde_json::from_value(value).expect("deserialize request");
        assert_eq!(req.seq, 7);
        assert_eq!(req.token, Some("t1".to_string()));
        assert_eq!(req.trace_id, None);
    }

    #[test]
    fn deserialize_request_sys_len_3_null_token() {
        let value = json!({
            "method": "ping",
            "params": {"k": "v"},
            "sys": [7, null, "tr1"]
        });
        let req: RPCRequest = serde_json::from_value(value).expect("deserialize request");
        assert_eq!(req.seq, 7);
        assert_eq!(req.token, None);
        assert_eq!(req.trace_id, Some("tr1".to_string()));
    }

    #[test]
    fn deserialize_request_sys_len_3_token_trace() {
        let value = json!({
            "method": "ping",
            "params": {"k": "v"},
            "sys": [7, "t1", "tr1"]
        });
        let req: RPCRequest = serde_json::from_value(value).expect("deserialize request");
        assert_eq!(req.seq, 7);
        assert_eq!(req.token, Some("t1".to_string()));
        assert_eq!(req.trace_id, Some("tr1".to_string()));
    }

    #[test]
    fn deserialize_response_success() {
        let value = json!({
            "result": {"ok": true},
            "sys": [11, "tr1"]
        });
        let resp: RPCResponse = serde_json::from_value(value).expect("deserialize response");
        assert_eq!(resp.seq, 11);
        assert_eq!(resp.trace_id, Some("tr1".to_string()));
        assert_eq!(resp.result, RPCResult::Success(json!({"ok": true})));
    }

    #[test]
    fn deserialize_response_error() {
        let value = json!({
            "error": "boom",
            "sys": [12]
        });
        let resp: RPCResponse = serde_json::from_value(value).expect("deserialize response");
        assert_eq!(resp.seq, 12);
        assert_eq!(resp.trace_id, None);
        assert_eq!(resp.result, RPCResult::Failed("boom".to_string()));
    }
}
