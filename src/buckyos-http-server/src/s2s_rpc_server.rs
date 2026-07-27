//! `serve_http_by_s2s_rpc_handler`(doc/krpc-s2s-payload-encryption-TODO.md §9)。
//!
//! 同一 `/s2s/$apiname` 入口按 policy 接受:
//! - `application/vnd.buckyos.krpc-s2s`:v1 加密 binary body;
//! - `application/json`:仅当显式 plaintext admission(CIDR + API allowlist)
//!   放行时进入现有 `RPCRequest` JSON parser。
//!
//! 安全规则:
//! - encrypted parser 失败后**不会**把同一 Body 重新解释成 plaintext;
//! - plaintext admission 或 encrypted authentication 完成前的错误返回统一、
//!   短小、无敏感细节的 transport failure(内部 metric 记录低基数 reason);
//! - source IP 只用带 provenance 的 resolver(`conn_src_addr` 优先,
//!   `real_src_addr` 只在 socket peer 命中 trusted proxy CIDR 时使用);
//! - 解密失败、replay、admission 失败都不会进入 `RPCHandler`。

use crate::{
    dispatch_rpc_request, full_body, read_body_with_limit, server_err, text_response,
    ServerError, ServerErrorCode, ServerResult, StreamInfo,
};
use ::kRPC::s2s::{
    api_name_from_path, json_value_depth, parse_media_type, resolve_effective_source,
    AuthBindingPolicy, EffectiveSource, PlaintextAuthPolicy, S2sDecryptedRequest, S2sError,
    S2sRequestHeaders, S2sRpcServerContext, S2S_CONTENT_TYPE, S2S_PLAINTEXT_CONTENT_TYPE,
    S2S_PROBE_API, S2S_TAG_LEN,
};
use ::kRPC::{
    RPCRequest, RPCResponse, RPCResult, RPCServerContext, RPCServerHandler, RPCTransportSecurity,
};
use http::{Response, StatusCode};
use http_body_util::combinators::BoxBody;
use hyper::body::Bytes;
use serde_json::Value;

/// 统一、无细节的未认证 transport 拒绝(§9.4)。
fn uniform_reject(reason: &S2sError) -> ServerResult<Response<BoxBody<Bytes, ServerError>>> {
    // 内部记录低基数 reason code;不把细节返回未认证调用方
    log::debug!("s2s transport reject: {}", reason.reason_code());
    text_response(StatusCode::FORBIDDEN, "Forbidden")
}

fn uniform_reject_resp() -> ServerResult<Response<BoxBody<Bytes, ServerError>>> {
    text_response(StatusCode::FORBIDDEN, "Forbidden")
}

/// v1 S2S 入口(命名与现有 `serve_http_by_rpc_handler` 一致)。
///
/// handler 是 [`RPCServerHandler`];所有既有 `RPCHandler` 实现经 blanket
/// adapter 自动可用(只拿到 IP);需要 authenticated service identity 的服务
/// 实现 `RPCServerHandler`。
pub async fn serve_http_by_s2s_rpc_handler<T: RPCServerHandler + Send + Sync + 'static>(
    req: http::Request<BoxBody<Bytes, ServerError>>,
    info: StreamInfo,
    rpc_handler: &T,
    s2s_context: &S2sRpcServerContext,
) -> ServerResult<http::Response<BoxBody<Bytes, ServerError>>> {
    // 一次 request 使用同一 policy snapshot(§11.6)
    let policy = s2s_context.policy_snapshot();

    // ---- 共同前置步骤(§9.3) ----
    if req.method() != hyper::Method::POST {
        return text_response(StatusCode::METHOD_NOT_ALLOWED, "Method Not Allowed");
    }

    // canonical API path
    let canonical_api = match api_name_from_path(req.uri().path()) {
        Ok(api) => api,
        Err(e) => return uniform_reject(&e),
    };

    // source IP:fail closed;不信任普通 forwarded header
    let source = match resolve_effective_source(
        &policy.source_ip,
        info.conn_src_addr.as_deref(),
        info.real_src_addr.as_deref(),
    ) {
        Ok(source) => source,
        Err(e) => return uniform_reject(&e),
    };

    // Content-Length 预检(读取 Body 前)
    if let Some(len) = req
        .headers()
        .get(http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<u64>().ok())
    {
        if len > policy.limits.max_body_size as u64 {
            return uniform_reject(&S2sError::LimitExceeded("body too large".to_string()));
        }
    }

    // Content-Type dispatch(RFC 9110 essence,只比较小写 type/subtype;
    // 缺失/未知拒绝,不做内容嗅探,解析失败不切换模式)
    let media_type = req
        .headers()
        .get(http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(parse_media_type);
    match media_type.as_deref() {
        Some(S2S_CONTENT_TYPE) => {
            serve_encrypted(req, source, canonical_api, rpc_handler, s2s_context).await
        }
        Some(S2S_PLAINTEXT_CONTENT_TYPE) => {
            serve_plaintext(req, source, canonical_api, rpc_handler, s2s_context).await
        }
        _ => uniform_reject(&S2sError::InvalidHeader {
            name: "content-type".to_string(),
            reason: "unsupported media type".to_string(),
        }),
    }
}

/// plaintext 分支(§9.3):admission 在 Body 读取/解析与 dispatch 之前完成。
async fn serve_plaintext<T: RPCServerHandler + Send + Sync + 'static>(
    req: http::Request<BoxBody<Bytes, ServerError>>,
    source: EffectiveSource,
    canonical_api: String,
    rpc_handler: &T,
    s2s_context: &S2sRpcServerContext,
) -> ServerResult<http::Response<BoxBody<Bytes, ServerError>>> {
    let policy = s2s_context.policy_snapshot();

    // 1. effective source IP 与 canonical API 必须同时命中显式 allowlist
    if !policy.admits_plaintext(&source, &canonical_api) {
        return uniform_reject(&S2sError::PolicyViolation(
            "plaintext not admitted".to_string(),
        ));
    }

    // 2. 有界读取并解析完整 RPCRequest JSON
    let body_bytes = match read_body_with_limit(req, policy.limits.max_body_size).await {
        Ok(bytes) => bytes,
        Err(_resp) => return uniform_reject_resp(),
    };
    let Ok(parsed) = serde_json::from_slice::<Value>(&body_bytes) else {
        return uniform_reject_resp();
    };
    if json_value_depth(&parsed) > policy.limits.max_json_depth {
        return uniform_reject(&S2sError::LimitExceeded("json too deep".to_string()));
    }
    let Ok(rpc_request) = serde_json::from_value::<RPCRequest>(parsed) else {
        return uniform_reject_resp();
    };

    // 4. plaintext auth policy:安全默认要求 session token 存在
    if policy.plaintext_auth() == Some(PlaintextAuthPolicy::RequireSessionToken)
        && rpc_request.token.is_none()
    {
        return uniform_reject(&S2sError::PolicyViolation(
            "plaintext requires session token".to_string(),
        ));
    }

    // 3. plaintext 不产生 authenticated service identity
    let server_ctx = RPCServerContext {
        from_ip: Some(source.ip),
        source_ip_provenance: Some(source.provenance),
        transport_security: RPCTransportSecurity::Plaintext,
        admitted_by_trusted_network: true,
        authenticated_from_service_did: None,
        authenticated_from_key_fingerprint: None,
        canonical_api_name: Some(canonical_api),
    };

    // 5. dispatch,生成现有 plaintext RPCResponse JSON
    let resp = dispatch_rpc_request(rpc_handler, rpc_request, &server_ctx).await;
    let body_json = serde_json::to_string(&resp).map_err(|e| {
        server_err!(ServerErrorCode::EncodeError, "encode response: {}", e)
    })?;
    Response::builder()
        .header(http::header::CONTENT_TYPE, S2S_PLAINTEXT_CONTENT_TYPE)
        .body(full_body(body_json))
        .map_err(|e| server_err!(ServerErrorCode::InvalidData, "build response: {}", e))
}

/// encrypted 分支(§9.3 步骤 1–16)。
async fn serve_encrypted<T: RPCServerHandler + Send + Sync + 'static>(
    req: http::Request<BoxBody<Bytes, ServerError>>,
    source: EffectiveSource,
    canonical_api: String,
    rpc_handler: &T,
    s2s_context: &S2sRpcServerContext,
) -> ServerResult<http::Response<BoxBody<Bytes, ServerError>>> {
    let policy = s2s_context.policy_snapshot();
    let now = buckyos_kit::buckyos_get_unix_timestamp();

    // 1. 只解析有界 KRPC-S2S-* Header(不解析加密 Body 内部 JSON)
    let headers = match S2sRequestHeaders::parse(req.headers()) {
        Ok(headers) => headers,
        Err(e) => return uniform_reject(&e),
    };

    // 3. 有界读取 binary Body,基本长度检查
    let body_bytes = match read_body_with_limit(req, policy.limits.max_body_size).await {
        Ok(bytes) => bytes,
        Err(_resp) => return uniform_reject_resp(),
    };
    if body_bytes.len() < S2S_TAG_LEN {
        return uniform_reject(&S2sError::DecryptFailed);
    }

    // 4–12. key selection、AAD、AEAD、时间窗、admission、replay(kRPC 引擎)
    let decrypted: S2sDecryptedRequest = match s2s_context
        .open_request(&headers, &canonical_api, &body_bytes, now)
        .await
    {
        Ok(decrypted) => decrypted,
        Err(e) => return uniform_reject(&e),
    };

    // 13. 解析内部 RPCRequest(depth limit)
    let Ok(parsed) = serde_json::from_slice::<Value>(&decrypted.plaintext) else {
        return uniform_reject_resp();
    };
    if json_value_depth(&parsed) > policy.limits.max_json_depth {
        return uniform_reject(&S2sError::LimitExceeded("json too deep".to_string()));
    }
    let Ok(rpc_request) = serde_json::from_value::<RPCRequest>(parsed) else {
        return uniform_reject_resp();
    };

    // 14. auth binding policy(authenticated identity 已确认,策略可要求 token)
    if policy.auth_binding == AuthBindingPolicy::RequireSessionToken && rpc_request.token.is_none()
    {
        return uniform_reject(&S2sError::PolicyViolation(
            "session token required".to_string(),
        ));
    }

    let server_ctx = RPCServerContext {
        from_ip: Some(source.ip),
        source_ip_provenance: Some(source.provenance),
        transport_security: RPCTransportSecurity::S2sPayloadV1,
        admitted_by_trusted_network: false,
        authenticated_from_service_did: Some(decrypted.authenticated_from_did.clone()),
        authenticated_from_key_fingerprint: Some(decrypted.authenticated_from_fingerprint),
        canonical_api_name: Some(canonical_api.clone()),
    };

    // 15. dispatch(协议保留 API `__probe` 由入口处理,不进业务 handler)
    let resp: RPCResponse = if canonical_api == S2S_PROBE_API {
        handle_probe(&rpc_request, &decrypted, s2s_context)
    } else {
        dispatch_rpc_request(rpc_handler, rpc_request, &server_ctx).await
    };

    // 16. 生成与 request nonce 绑定的加密 response
    let response_json = serde_json::to_vec(&resp).map_err(|e| {
        server_err!(ServerErrorCode::EncodeError, "encode response: {}", e)
    })?;
    let now = buckyos_kit::buckyos_get_unix_timestamp();
    let (response_headers, sealed) = match s2s_context
        .seal_response(&decrypted, &response_json, now)
        .await
    {
        Ok(sealed) => sealed,
        Err(e) => {
            log::warn!("s2s seal response failed: {}", e.reason_code());
            return uniform_reject_resp();
        }
    };

    let mut header_map = http::HeaderMap::new();
    response_headers
        .apply(&mut header_map)
        .map_err(|_| server_err!(ServerErrorCode::EncodeError, "encode s2s headers"))?;

    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header(http::header::CONTENT_TYPE, S2S_CONTENT_TYPE)
        // 防止中间层对 200 响应做启发式缓存(§8.5)
        .header(http::header::CACHE_CONTROL, "no-store");
    if let Some(headers) = builder.headers_mut() {
        headers.extend(header_map);
    }
    builder
        .body(full_body(sealed))
        .map_err(|e| server_err!(ServerErrorCode::InvalidData, "build response: {}", e))
}

/// 加密 `__probe`(§13):走与业务请求完全相同的 admission/时间窗/replay
/// 管线后到达这里;验证双方 key/KDF/AEAD,可选检查 API registry 存在性
/// (`api_visible_to` 由 registry 实现执行 RBAC),但不执行业务 API。
fn handle_probe(
    rpc_request: &RPCRequest,
    decrypted: &S2sDecryptedRequest,
    s2s_context: &S2sRpcServerContext,
) -> RPCResponse {
    let check_api = rpc_request
        .params
        .get("check_api")
        .and_then(Value::as_str);
    let api_exists: Value = match check_api {
        None => Value::Null,
        Some(api) => match ::kRPC::s2s::canonicalize_api_name(api) {
            Err(_) => Value::Bool(false),
            Ok(canonical) => match s2s_context.api_registry() {
                None => Value::Null,
                Some(registry) => Value::Bool(
                    registry.api_visible_to(&canonical, &decrypted.authenticated_from_did),
                ),
            },
        },
    };
    RPCResponse::create_by_req(
        RPCResult::Success(serde_json::json!({
            "probe": "ok",
            "version": ::kRPC::s2s::S2S_PROFILE_VERSION,
            "api_exists": api_exists,
        })),
        rpc_request,
    )
}
