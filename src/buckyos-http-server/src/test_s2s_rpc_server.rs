//! `serve_http_by_s2s_rpc_handler` 安全与兼容测试(Phase 6)。

use crate::{full_body, serve_http_by_s2s_rpc_handler, ServerError, StreamInfo};
use ::kRPC::s2s::*;
use ::kRPC::{
    RPCErrors, RPCRequest, RPCResponse, RPCResult, RPCServerContext, RPCServerHandler,
};
use async_trait::async_trait;
use http::{Request, Response, StatusCode};
use http_body_util::combinators::BoxBody;
use http_body_util::BodyExt;
use hyper::body::Bytes;
use name_lib::DID;
use serde_json::json;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

const CLIENT_SEED: [u8; 32] = [3u8; 32];
const SERVER_SEED: [u8; 32] = [9u8; 32];

fn client_did() -> DID {
    DID::new("web", "event-producer.example.com")
}

fn server_did() -> DID {
    DID::new("web", "event-service.example.com")
}

fn zone_did() -> DID {
    DID::new("web", "example.com")
}

/// 记录 handler 是否被调用 + 捕获 server context。
struct RecordingHandler {
    calls: AtomicUsize,
    last_ctx: std::sync::Mutex<Option<RPCServerContext>>,
}

impl RecordingHandler {
    fn new() -> Self {
        RecordingHandler {
            calls: AtomicUsize::new(0),
            last_ctx: std::sync::Mutex::new(None),
        }
    }

    fn call_count(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    fn last_context(&self) -> Option<RPCServerContext> {
        self.last_ctx.lock().unwrap().clone()
    }
}

#[async_trait]
impl RPCServerHandler for RecordingHandler {
    async fn handle_rpc_call_with_context(
        &self,
        req: RPCRequest,
        server_ctx: &RPCServerContext,
    ) -> std::result::Result<RPCResponse, RPCErrors> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        *self.last_ctx.lock().unwrap() = Some(server_ctx.clone());
        Ok(RPCResponse::create_by_req(
            RPCResult::Success(json!({"echo": req.method})),
            &req,
        ))
    }
}

fn resolver_with_both() -> Arc<StaticPeerKeyResolver> {
    let resolver = Arc::new(StaticPeerKeyResolver::new());
    resolver.insert(
        &client_did(),
        vec![VerifiedPeerKey {
            key_id: None,
            ed25519_public: SecretEd25519Key::from_seed(CLIENT_SEED).public_key(),
        }],
    );
    resolver.insert(
        &server_did(),
        vec![VerifiedPeerKey {
            key_id: None,
            ed25519_public: SecretEd25519Key::from_seed(SERVER_SEED).public_key(),
        }],
    );
    resolver
}

async fn server_context() -> S2sRpcServerContext {
    server_context_with_policy(default_policy()).await
}

fn default_policy() -> S2sServerSecurityPolicy {
    S2sServerSecurityPolicy::builder()
        .peer_admission(PeerAdmissionPolicy::allow_services([client_did()
            .to_string()
            .as_str()]))
        .build()
        .unwrap()
}

async fn server_context_with_policy(policy: S2sServerSecurityPolicy) -> S2sRpcServerContext {
    S2sRpcServerContext::builder("event-service", zone_did())
        .explicit_ed25519_key(SecretEd25519Key::from_seed(SERVER_SEED))
        .peer_key_resolver(resolver_with_both())
        .security_policy(policy)
        .build()
        .await
        .unwrap()
}

async fn client_transport() -> S2sClientTransport {
    let local = S2sLocalIdentityConfig::new(
        "event-producer",
        zone_did(),
        S2sLocalKeySource::ExplicitEd25519 {
            key: SecretEd25519Key::from_seed(CLIENT_SEED),
            key_id: None,
        },
    );
    // 推荐路径:目标 DID + 目标公钥都是确定值(来自 verified descriptor)
    let config = S2sClientConfig::with_pinned_key(
        local,
        server_did(),
        SecretEd25519Key::from_seed(SERVER_SEED).public_key(),
    );
    S2sClientTransport::new(config).await.unwrap()
}

fn rpc_request_bytes(method: &str, token: Option<&str>) -> Vec<u8> {
    let mut req = RPCRequest::new(method, json!({"k": "v"}));
    req.seq = 42;
    req.token = token.map(|t| t.to_string());
    serde_json::to_vec(&serde_json::to_value(&req).unwrap()).unwrap()
}

fn now() -> u64 {
    buckyos_kit::buckyos_get_unix_timestamp()
}

/// 构造一个已加密的 HTTP request。
async fn encrypted_http_request(
    transport: &S2sClientTransport,
    api: &str,
    body_json: &[u8],
) -> (Request<BoxBody<Bytes, ServerError>>, S2sPendingRequest) {
    let (headers, sealed, pending) = transport
        .seal_request(api, body_json, now(), false)
        .await
        .unwrap();
    let mut header_map = http::HeaderMap::new();
    headers.apply(&mut header_map).unwrap();

    let mut builder = Request::builder()
        .method("POST")
        .uri(format!("http://127.0.0.1:18080/s2s/{}", api))
        .header(http::header::CONTENT_TYPE, S2S_CONTENT_TYPE);
    builder.headers_mut().unwrap().extend(header_map);
    let request = builder.body(full_body(sealed)).unwrap();
    (request, pending)
}

fn stream_info() -> StreamInfo {
    StreamInfo::new("203.0.113.7:5555".to_string())
}

async fn read_body(resp: Response<BoxBody<Bytes, ServerError>>) -> Bytes {
    resp.collect().await.unwrap().to_bytes()
}

// ---- 正常路径 ----

#[tokio::test]
async fn encrypted_roundtrip_success_and_identity_passed() {
    let ctx = server_context().await;
    let transport = client_transport().await;
    let handler = RecordingHandler::new();

    let (request, pending) =
        encrypted_http_request(&transport, "event-report-v1", &rpc_request_bytes("report_event", None)).await;
    let response = serve_http_by_s2s_rpc_handler(request, stream_info(), &handler, &ctx)
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(http::header::CONTENT_TYPE).unwrap(),
        S2S_CONTENT_TYPE
    );
    assert_eq!(
        response.headers().get(http::header::CACHE_CONTROL).unwrap(),
        "no-store"
    );

    let response_headers = S2sResponseHeaders::parse(response.headers()).unwrap();
    let body = read_body(response).await;
    let plaintext = transport
        .open_response(&pending, &response_headers, &body, now())
        .await
        .unwrap();
    let rpc_response: RPCResponse = serde_json::from_slice(&plaintext).unwrap();
    assert_eq!(rpc_response.seq, 42);
    assert_eq!(
        rpc_response.result,
        RPCResult::Success(json!({"echo": "report_event"}))
    );

    // handler 收到 authenticated service identity
    assert_eq!(handler.call_count(), 1);
    let server_ctx = handler.last_context().unwrap();
    assert_eq!(server_ctx.authenticated_from_service_did, Some(client_did()));
    assert!(server_ctx.authenticated_from_key_fingerprint.is_some());
    assert!(!server_ctx.admitted_by_trusted_network);
    assert_eq!(
        server_ctx.canonical_api_name.as_deref(),
        Some("event-report-v1")
    );
}

#[tokio::test]
async fn probe_api_works_without_business_handler() {
    let ctx = server_context().await;
    let transport = client_transport().await;
    let handler = RecordingHandler::new();

    let (request, pending) =
        encrypted_http_request(&transport, "__probe", &rpc_request_bytes("__probe", None)).await;
    let response = serve_http_by_s2s_rpc_handler(request, stream_info(), &handler, &ctx)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let response_headers = S2sResponseHeaders::parse(response.headers()).unwrap();
    let body = read_body(response).await;
    let plaintext = transport
        .open_response(&pending, &response_headers, &body, now())
        .await
        .unwrap();
    let rpc_response: RPCResponse = serde_json::from_slice(&plaintext).unwrap();
    let RPCResult::Success(value) = rpc_response.result else {
        panic!("probe failed");
    };
    assert_eq!(value.get("probe").unwrap(), "ok");
    // 无 registry → api_exists null
    assert!(value.get("api_exists").unwrap().is_null());
    // probe 不进业务 handler
    assert_eq!(handler.call_count(), 0);
}

// ---- 篡改与反射 ----

#[tokio::test]
async fn tampering_any_s2s_header_fails_before_handler() {
    let ctx = server_context().await;
    let transport = client_transport().await;

    let tamper_cases: Vec<(&str, &str)> = vec![
        ("krpc-s2s-from", "did:web:attacker.example.com"),
        ("krpc-s2s-to", "did:web:other.example.com"),
        ("krpc-s2s-issued-at", "1"),
        ("krpc-s2s-expires-at", "99999999999"),
        ("krpc-s2s-nonce", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        ("krpc-s2s-version", "2"),
    ];

    for (name, value) in tamper_cases {
        let handler = RecordingHandler::new();
        let (mut request, _pending) =
            encrypted_http_request(&transport, "event-report-v1", &rpc_request_bytes("m", None)).await;
        request.headers_mut().insert(
            http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
            http::HeaderValue::from_str(value).unwrap(),
        );
        let response = serve_http_by_s2s_rpc_handler(request, stream_info(), &handler, &ctx)
            .await
            .unwrap();
        // 统一无细节 transport failure
        assert_ne!(response.status(), StatusCode::OK, "tamper {} accepted", name);
        assert_eq!(read_body(response).await, Bytes::from("Forbidden"));
        assert_eq!(handler.call_count(), 0, "handler ran for tampered {}", name);
    }
}

#[tokio::test]
async fn tampered_body_rejected() {
    let ctx = server_context().await;
    let transport = client_transport().await;
    let handler = RecordingHandler::new();

    let (request, _pending) =
        encrypted_http_request(&transport, "event-report-v1", &rpc_request_bytes("m", None)).await;
    let (parts, body) = request.into_parts();
    let mut body_bytes = body.collect().await.unwrap().to_bytes().to_vec();
    body_bytes[0] ^= 0x01;
    let request = Request::from_parts(parts, full_body(body_bytes));

    let response = serve_http_by_s2s_rpc_handler(request, stream_info(), &handler, &ctx)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(handler.call_count(), 0);
}

#[tokio::test]
async fn cross_api_reflection_rejected() {
    let ctx = server_context().await;
    let transport = client_transport().await;
    let handler = RecordingHandler::new();

    // 密文对 api-a 加密,但发到 api-b 的 path
    let (headers, sealed, _pending) = transport
        .seal_request("api-a", &rpc_request_bytes("m", None), now(), false)
        .await
        .unwrap();
    let mut header_map = http::HeaderMap::new();
    headers.apply(&mut header_map).unwrap();
    let mut builder = Request::builder()
        .method("POST")
        .uri("http://127.0.0.1:18080/s2s/api-b")
        .header(http::header::CONTENT_TYPE, S2S_CONTENT_TYPE);
    builder.headers_mut().unwrap().extend(header_map);
    let request = builder.body(full_body(sealed)).unwrap();

    let response = serve_http_by_s2s_rpc_handler(request, stream_info(), &handler, &ctx)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(handler.call_count(), 0);
}

#[tokio::test]
async fn wrong_target_service_rejected() {
    // 密文加密给另一个服务(To 不同、KDF 不同)→ 转发到本服务必须失败
    let ctx = server_context().await;
    let handler = RecordingHandler::new();

    let other_did = DID::new("web", "other-service.example.com");
    let resolver = resolver_with_both();
    resolver.insert(
        &other_did,
        vec![VerifiedPeerKey {
            key_id: None,
            ed25519_public: SecretEd25519Key::from_seed([7u8; 32]).public_key(),
        }],
    );
    let local = S2sLocalIdentityConfig::new(
        "event-producer",
        zone_did(),
        S2sLocalKeySource::ExplicitEd25519 {
            key: SecretEd25519Key::from_seed(CLIENT_SEED),
            key_id: None,
        },
    );
    let config = S2sClientConfig::with_resolver(local, other_did, resolver);
    let transport_to_other = S2sClientTransport::new(config).await.unwrap();

    let (request, _pending) = encrypted_http_request(
        &transport_to_other,
        "event-report-v1",
        &rpc_request_bytes("m", None),
    )
    .await;
    let response = serve_http_by_s2s_rpc_handler(request, stream_info(), &handler, &ctx)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(handler.call_count(), 0);
}

#[tokio::test]
async fn replayed_request_rejected_and_not_dispatched_twice() {
    let ctx = server_context().await;
    let transport = client_transport().await;
    let handler = RecordingHandler::new();

    let (headers, sealed, _pending) = transport
        .seal_request("event-report-v1", &rpc_request_bytes("m", None), now(), false)
        .await
        .unwrap();

    for attempt in 0..2 {
        let mut header_map = http::HeaderMap::new();
        headers.apply(&mut header_map).unwrap();
        let mut builder = Request::builder()
            .method("POST")
            .uri("http://127.0.0.1:18080/s2s/event-report-v1")
            .header(http::header::CONTENT_TYPE, S2S_CONTENT_TYPE);
        builder.headers_mut().unwrap().extend(header_map);
        let request = builder.body(full_body(sealed.clone())).unwrap();
        let response = serve_http_by_s2s_rpc_handler(request, stream_info(), &handler, &ctx)
            .await
            .unwrap();
        if attempt == 0 {
            assert_eq!(response.status(), StatusCode::OK);
        } else {
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
        }
    }
    assert_eq!(handler.call_count(), 1);
}

// ---- admission / policy ----

#[tokio::test]
async fn unknown_peer_rejected_by_default_deny() {
    // 默认 policy(DenyAll)下即使密钥有效也拒绝
    let ctx = server_context_with_policy(S2sServerSecurityPolicy::public_internet_default()).await;
    let transport = client_transport().await;
    let handler = RecordingHandler::new();

    let (request, _pending) =
        encrypted_http_request(&transport, "event-report-v1", &rpc_request_bytes("m", None)).await;
    let response = serve_http_by_s2s_rpc_handler(request, stream_info(), &handler, &ctx)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(handler.call_count(), 0);
}

#[tokio::test]
async fn default_policy_rejects_all_plaintext() {
    let ctx = server_context().await;
    let handler = RecordingHandler::new();

    let request = Request::builder()
        .method("POST")
        .uri("http://127.0.0.1:18080/s2s/event-report-v1")
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(full_body(rpc_request_bytes("m", Some("token1"))))
        .unwrap();
    let response = serve_http_by_s2s_rpc_handler(request, stream_info(), &handler, &ctx)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(handler.call_count(), 0);
}

#[tokio::test]
async fn plaintext_needs_cidr_and_api_and_token_and_never_gets_identity() {
    let mut policy = S2sServerSecurityPolicy::trusted_network_plaintext(
        parse_cidrs(["203.0.113.0/24"]).unwrap(),
        ["event-report-v1"],
    )
    .unwrap();
    policy.peer_admission = PeerAdmissionPolicy::allow_services([client_did().to_string()]);
    let ctx = server_context_with_policy(policy).await;

    // 命中 CIDR + API + token → 放行
    let handler = RecordingHandler::new();
    let request = Request::builder()
        .method("POST")
        .uri("http://127.0.0.1:18080/s2s/event-report-v1")
        .header(http::header::CONTENT_TYPE, "application/json; charset=utf-8")
        .body(full_body(rpc_request_bytes("m", Some("token1"))))
        .unwrap();
    let response = serve_http_by_s2s_rpc_handler(request, stream_info(), &handler, &ctx)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(handler.call_count(), 1);
    let server_ctx = handler.last_context().unwrap();
    // plaintext 不产生 authenticated identity;只有 trusted-network 标记
    assert_eq!(server_ctx.authenticated_from_service_did, None);
    assert!(server_ctx.admitted_by_trusted_network);

    // 缺 token → 拒绝(默认 RequireSessionToken)
    let handler = RecordingHandler::new();
    let request = Request::builder()
        .method("POST")
        .uri("http://127.0.0.1:18080/s2s/event-report-v1")
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(full_body(rpc_request_bytes("m", None)))
        .unwrap();
    let response = serve_http_by_s2s_rpc_handler(request, stream_info(), &handler, &ctx)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(handler.call_count(), 0);

    // API 不在 allowlist → 拒绝
    let handler = RecordingHandler::new();
    let request = Request::builder()
        .method("POST")
        .uri("http://127.0.0.1:18080/s2s/other-api")
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(full_body(rpc_request_bytes("m", Some("t"))))
        .unwrap();
    let response = serve_http_by_s2s_rpc_handler(request, stream_info(), &handler, &ctx)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(handler.call_count(), 0);

    // CIDR 外来源 → 拒绝
    let handler = RecordingHandler::new();
    let request = Request::builder()
        .method("POST")
        .uri("http://127.0.0.1:18080/s2s/event-report-v1")
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(full_body(rpc_request_bytes("m", Some("t"))))
        .unwrap();
    let response = serve_http_by_s2s_rpc_handler(
        request,
        StreamInfo::new("198.51.100.9:1234".to_string()),
        &handler,
        &ctx,
    )
    .await
    .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(handler.call_count(), 0);
}

#[tokio::test]
async fn forwarded_headers_cannot_bypass_plaintext_policy() {
    // 默认 SocketPeerOnly:实际 socket 在 CIDR 外,伪造各种 forwarded 无效
    let mut policy = S2sServerSecurityPolicy::trusted_network_plaintext(
        parse_cidrs(["10.0.0.0/8"]).unwrap(),
        ["event-report-v1"],
    )
    .unwrap();
    policy.peer_admission = PeerAdmissionPolicy::AnyVerifiedService;
    let ctx = server_context_with_policy(policy).await;
    let handler = RecordingHandler::new();

    let request = Request::builder()
        .method("POST")
        .uri("http://127.0.0.1:18080/s2s/event-report-v1")
        .header(http::header::CONTENT_TYPE, "application/json")
        .header("x-forwarded-for", "10.0.0.7")
        .header("forwarded", "for=10.0.0.7")
        .header("x-real-ip", "10.0.0.7")
        .body(full_body(rpc_request_bytes("m", Some("t"))))
        .unwrap();
    // socket peer 203.0.113.7 不在 10/8;real_src_addr 伪造为 10.0.0.7
    let mut info = StreamInfo::new("203.0.113.7:5555".to_string());
    info.real_src_addr = Some("10.0.0.7:1111".to_string());
    let response = serve_http_by_s2s_rpc_handler(request, info, &handler, &ctx)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(handler.call_count(), 0);
}

#[tokio::test]
async fn trusted_proxy_provenance_enables_real_source() {
    // trusted proxy 模式:socket peer 命中 proxy CIDR 后 real_src_addr 才生效
    let mut policy = S2sServerSecurityPolicy::builder()
        .trusted_proxies(parse_cidrs(["203.0.113.0/24"]).unwrap())
        .plaintext_from(parse_cidrs(["10.0.0.0/8"]).unwrap(), ["event-report-v1"])
        .unwrap()
        .build()
        .unwrap();
    policy.peer_admission = PeerAdmissionPolicy::AnyVerifiedService;
    let ctx = server_context_with_policy(policy).await;
    let handler = RecordingHandler::new();

    let request = Request::builder()
        .method("POST")
        .uri("http://127.0.0.1:18080/s2s/event-report-v1")
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(full_body(rpc_request_bytes("m", Some("t"))))
        .unwrap();
    let mut info = StreamInfo::new("203.0.113.7:5555".to_string());
    info.real_src_addr = Some("10.0.0.7:1111".to_string());
    let response = serve_http_by_s2s_rpc_handler(request, info, &handler, &ctx)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let server_ctx = handler.last_context().unwrap();
    assert_eq!(
        server_ctx.from_ip.unwrap(),
        "10.0.0.7".parse::<std::net::IpAddr>().unwrap()
    );
    assert_eq!(
        server_ctx.source_ip_provenance,
        Some(SourceIpProvenance::TrustedProxyForwarded)
    );
}

#[tokio::test]
async fn encrypted_failure_never_falls_back_to_plaintext_parser() {
    // encrypted content type + 明文 JSON body:必须走 encrypted parser 且失败,
    // 绝不重解释为 plaintext
    let mut policy = S2sServerSecurityPolicy::trusted_network_plaintext(
        parse_cidrs(["203.0.113.0/24"]).unwrap(),
        ["event-report-v1"],
    )
    .unwrap();
    policy.peer_admission = PeerAdmissionPolicy::AnyVerifiedService;
    let ctx = server_context_with_policy(policy).await;
    let handler = RecordingHandler::new();

    let request = Request::builder()
        .method("POST")
        .uri("http://127.0.0.1:18080/s2s/event-report-v1")
        .header(http::header::CONTENT_TYPE, S2S_CONTENT_TYPE)
        .body(full_body(rpc_request_bytes("m", Some("t"))))
        .unwrap();
    let response = serve_http_by_s2s_rpc_handler(request, stream_info(), &handler, &ctx)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(handler.call_count(), 0);
}

#[tokio::test]
async fn unknown_content_type_rejected_without_sniffing() {
    let ctx = server_context().await;
    let handler = RecordingHandler::new();
    for content_type in ["text/plain", "application/octet-stream", ""] {
        let mut builder = Request::builder()
            .method("POST")
            .uri("http://127.0.0.1:18080/s2s/event-report-v1");
        if !content_type.is_empty() {
            builder = builder.header(http::header::CONTENT_TYPE, content_type);
        }
        let request = builder.body(full_body(rpc_request_bytes("m", None))).unwrap();
        let response = serve_http_by_s2s_rpc_handler(request, stream_info(), &handler, &ctx)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
    assert_eq!(handler.call_count(), 0);
}

#[tokio::test]
async fn expired_and_future_requests_rejected() {
    let ctx = server_context().await;
    let transport = client_transport().await;
    let handler = RecordingHandler::new();

    // 手工构造过期请求:seal 时刻 now-1000
    let (headers, sealed, _pending) = transport
        .seal_request(
            "event-report-v1",
            &rpc_request_bytes("m", None),
            now() - 1000,
            false,
        )
        .await
        .unwrap();
    let mut header_map = http::HeaderMap::new();
    headers.apply(&mut header_map).unwrap();
    let mut builder = Request::builder()
        .method("POST")
        .uri("http://127.0.0.1:18080/s2s/event-report-v1")
        .header(http::header::CONTENT_TYPE, S2S_CONTENT_TYPE);
    builder.headers_mut().unwrap().extend(header_map);
    let request = builder.body(full_body(sealed)).unwrap();
    let response = serve_http_by_s2s_rpc_handler(request, stream_info(), &handler, &ctx)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    // iat 在遥远未来
    let (headers, sealed, _pending) = transport
        .seal_request(
            "event-report-v1",
            &rpc_request_bytes("m", None),
            now() + 3000,
            false,
        )
        .await
        .unwrap();
    let mut header_map = http::HeaderMap::new();
    headers.apply(&mut header_map).unwrap();
    let mut builder = Request::builder()
        .method("POST")
        .uri("http://127.0.0.1:18080/s2s/event-report-v1")
        .header(http::header::CONTENT_TYPE, S2S_CONTENT_TYPE);
    builder.headers_mut().unwrap().extend(header_map);
    let request = builder.body(full_body(sealed)).unwrap();
    let response = serve_http_by_s2s_rpc_handler(request, stream_info(), &handler, &ctx)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(handler.call_count(), 0);
}

#[tokio::test]
async fn oversized_body_rejected_cheaply() {
    let ctx = server_context().await;
    let handler = RecordingHandler::new();
    let request = Request::builder()
        .method("POST")
        .uri("http://127.0.0.1:18080/s2s/event-report-v1")
        .header(http::header::CONTENT_TYPE, S2S_CONTENT_TYPE)
        .header(http::header::CONTENT_LENGTH, 10 * 1024 * 1024)
        .body(full_body(vec![0u8; 64]))
        .unwrap();
    let response = serve_http_by_s2s_rpc_handler(request, stream_info(), &handler, &ctx)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(handler.call_count(), 0);
}

// ---- 响应侧(client 校验) ----

#[tokio::test]
async fn client_rejects_response_with_rewritten_key_refs() {
    let ctx = server_context().await;
    let transport = client_transport().await;
    let handler = RecordingHandler::new();

    let (request, pending) =
        encrypted_http_request(&transport, "event-report-v1", &rpc_request_bytes("m", None)).await;
    let response = serve_http_by_s2s_rpc_handler(request, stream_info(), &handler, &ctx)
        .await
        .unwrap();
    let mut response_headers = S2sResponseHeaders::parse(response.headers()).unwrap();
    let body = read_body(response).await;

    // response From 被补全 key id → client 必须拒绝(逐字节回显被破坏)
    response_headers.from =
        ServiceKeyRef::with_key_id(response_headers.from.did.clone(), "key-1").unwrap();
    let err = transport
        .open_response(&pending, &response_headers, &body, now())
        .await
        .unwrap_err();
    assert!(matches!(err, S2sError::WrongPeer(_)));

    // In-Reply-To 不匹配 → 拒绝
    let response_headers2 = S2sResponseHeaders {
        in_reply_to: [0u8; 24],
        ..S2sResponseHeaders::parse(&{
            let mut m = http::HeaderMap::new();
            // 重新构造原始 headers
            let ctx2 = &ctx;
            let _ = ctx2;
            m.insert(
                http::HeaderName::from_static("krpc-s2s-version"),
                http::HeaderValue::from_static("1"),
            );
            m
        })
        .unwrap_or(S2sResponseHeaders {
            version: 1,
            from: ServiceKeyRef::new(server_did()),
            to: ServiceKeyRef::new(client_did()),
            issued_at: now(),
            expires_at: now() + 300,
            in_reply_to: [0u8; 24],
            nonce: [1u8; 24],
        })
    };
    let err = transport
        .open_response(&pending, &response_headers2, &body, now())
        .await
        .unwrap_err();
    assert!(matches!(err, S2sError::WrongKind | S2sError::WrongPeer(_)));
}

// ---- 轮换:grace key 与显式 key id ----

struct TwoKeyProvider {
    active: ExplicitEd25519Provider,
    grace: ExplicitEd25519Provider,
}

#[async_trait]
impl S2sKeyAgreementProvider for TwoKeyProvider {
    async fn local_key_candidates(&self) -> S2sResult<Vec<S2sLocalKeyHandle>> {
        Ok(vec![
            self.active.handle().clone(),
            self.grace.handle().clone(),
        ])
    }

    async fn diffie_hellman(
        &self,
        local_key_fingerprint: &[u8; 32],
        peer_x25519_public: &[u8; 32],
    ) -> S2sResult<Zeroizing<[u8; 32]>> {
        if local_key_fingerprint == &self.active.handle().fingerprint {
            self.active
                .diffie_hellman(local_key_fingerprint, peer_x25519_public)
                .await
        } else {
            self.grace
                .diffie_hellman(local_key_fingerprint, peer_x25519_public)
                .await
        }
    }
}

#[tokio::test]
async fn server_grace_key_still_decrypts_after_rotation() {
    // 服务端 active key 已轮换成 NEW_SEED,旧 key(SERVER_SEED)在 grace 集合;
    // 客户端仍持有旧 verified key → 请求仍可解密
    const NEW_SEED: [u8; 32] = [21u8; 32];
    let provider = TwoKeyProvider {
        active: ExplicitEd25519Provider::new(SecretEd25519Key::from_seed(NEW_SEED), None),
        grace: ExplicitEd25519Provider::new(SecretEd25519Key::from_seed(SERVER_SEED), None),
    };
    let ctx = S2sRpcServerContext::builder("event-service", zone_did())
        .key_agreement_provider(Arc::new(provider))
        .peer_key_resolver(resolver_with_both())
        .security_policy(default_policy())
        .unsafe_skip_local_key_binding_check()
        .build()
        .await
        .unwrap();

    let transport = client_transport().await; // resolver 里仍是旧 server key
    let handler = RecordingHandler::new();
    let (request, pending) =
        encrypted_http_request(&transport, "event-report-v1", &rpc_request_bytes("m", None)).await;
    let response = serve_http_by_s2s_rpc_handler(request, stream_info(), &handler, &ctx)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(handler.call_count(), 1);

    // response 必须沿用实际解密成功的(grace)key pair → client 可解密
    let response_headers = S2sResponseHeaders::parse(response.headers()).unwrap();
    let body = read_body(response).await;
    assert!(transport
        .open_response(&pending, &response_headers, &body, now())
        .await
        .is_ok());
}

// ---- context 构造校验 ----

#[tokio::test]
async fn context_construction_rejects_missing_pieces() {
    // 无 key source
    let err = S2sRpcServerContext::builder("event-service", zone_did())
        .peer_key_resolver(resolver_with_both())
        .build()
        .await;
    assert!(err.is_err());

    // 无 peer resolver
    let err = S2sRpcServerContext::builder("event-service", zone_did())
        .explicit_ed25519_key(SecretEd25519Key::from_seed(SERVER_SEED))
        .build()
        .await;
    assert!(err.is_err());

    // 非法 appid
    let err = S2sRpcServerContext::builder("Bad.Appid", zone_did())
        .explicit_ed25519_key(SecretEd25519Key::from_seed(SERVER_SEED))
        .peer_key_resolver(resolver_with_both())
        .build()
        .await;
    assert!(err.is_err());

    // key binding 不匹配(resolver 中 server did 是另一把 key)
    let resolver = Arc::new(StaticPeerKeyResolver::new());
    resolver.insert(
        &server_did(),
        vec![VerifiedPeerKey {
            key_id: None,
            ed25519_public: SecretEd25519Key::from_seed([100u8; 32]).public_key(),
        }],
    );
    let err = S2sRpcServerContext::builder("event-service", zone_did())
        .explicit_ed25519_key(SecretEd25519Key::from_seed(SERVER_SEED))
        .peer_key_resolver(resolver)
        .build()
        .await;
    assert!(err.is_err());

    // 无效 policy 无法 reload
    let ctx = server_context().await;
    let mut bad = S2sServerSecurityPolicy::public_internet_default();
    bad.message.max_lifetime_secs = 0;
    assert!(ctx.reload_policy(bad).is_err());
}

// ---- 端到端:真实 HTTP server + kRPC 客户端 S2S 模式 ----

use crate::{HttpServer, Runner, ServerResult};
use ::kRPC::{kRPC, KrpcTransportSecurity};
use std::sync::atomic::AtomicBool;

struct S2sHttpServer {
    ctx: Arc<S2sRpcServerContext>,
    handler: Arc<RecordingHandler>,
}

#[async_trait]
impl HttpServer for S2sHttpServer {
    async fn serve_request(
        &self,
        req: http::Request<BoxBody<Bytes, ServerError>>,
        info: StreamInfo,
    ) -> ServerResult<http::Response<BoxBody<Bytes, ServerError>>> {
        serve_http_by_s2s_rpc_handler(req, info, self.handler.as_ref(), &self.ctx).await
    }

    fn id(&self) -> String {
        "s2s-test".to_string()
    }

    fn http_version(&self) -> http::Version {
        http::Version::HTTP_11
    }

    fn http3_port(&self) -> Option<u16> {
        None
    }
}

fn random_loopback_addr() -> std::net::SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap()
}

async fn spawn_s2s_server(
    policy: S2sServerSecurityPolicy,
) -> (std::net::SocketAddr, Arc<RecordingHandler>, tokio::task::JoinHandle<()>) {
    let addr = random_loopback_addr();
    let handler = Arc::new(RecordingHandler::new());
    let ctx = Arc::new(server_context_with_policy(policy).await);
    let server = Arc::new(S2sHttpServer {
        ctx,
        handler: handler.clone(),
    });
    let runner = Runner::with_addr(addr);
    runner.add_http_server("/s2s".to_string(), server).unwrap();
    let task = tokio::spawn(async move {
        let _ = runner.run().await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(80)).await;
    (addr, handler, task)
}

fn client_local_identity() -> S2sLocalIdentityConfig {
    S2sLocalIdentityConfig::new(
        "event-producer",
        zone_did(),
        S2sLocalKeySource::ExplicitEd25519 {
            key: SecretEd25519Key::from_seed(CLIENT_SEED),
            key_id: None,
        },
    )
}

#[tokio::test]
async fn end_to_end_krpc_client_s2s_call_and_probe() {
    let (addr, handler, task) = spawn_s2s_server(default_policy()).await;

    let config = S2sClientConfig::with_pinned_key(
        client_local_identity(),
        server_did(),
        SecretEd25519Key::from_seed(SERVER_SEED).public_key(),
    );
    let client = kRPC::new_with_transport(
        &format!("http://{}/s2s/event-report-v1", addr),
        Some("session-token-1".to_string()),
        KrpcTransportSecurity::S2sPayloadV1(config),
    )
    .await
    .unwrap();

    // 业务调用
    let value = client
        .call("report_event", json!({"level": "info"}))
        .await
        .unwrap();
    assert_eq!(value, json!({"echo": "report_event"}));
    assert_eq!(handler.call_count(), 1);
    let server_ctx = handler.last_context().unwrap();
    assert_eq!(server_ctx.authenticated_from_service_did, Some(client_did()));

    // 加密 probe(不进业务 handler)
    let probe = client.probe_s2s(Some("event-report-v1")).await.unwrap();
    assert_eq!(probe.get("probe").unwrap(), "ok");
    assert_eq!(handler.call_count(), 1);

    task.abort();
    let _ = task.await;
}

/// resolver:refresh 之前返回过期的 server key,refresh 后返回正确 key。
struct StaleThenFreshResolver {
    inner: Arc<StaticPeerKeyResolver>,
    stale_server_key: VerifiedPeerKey,
    refreshed: AtomicBool,
}

#[async_trait]
impl S2sPeerKeyResolver for StaleThenFreshResolver {
    async fn resolve_verified_keys(
        &self,
        service_did: &DID,
        key_id: Option<&str>,
    ) -> S2sResult<Vec<VerifiedPeerKey>> {
        if service_did == &server_did() && !self.refreshed.load(Ordering::SeqCst) {
            return Ok(vec![self.stale_server_key.clone()]);
        }
        self.inner.resolve_verified_keys(service_did, key_id).await
    }

    async fn refresh_verified_keys(
        &self,
        service_did: &DID,
        key_id: Option<&str>,
    ) -> S2sResult<Vec<VerifiedPeerKey>> {
        self.refreshed.store(true, Ordering::SeqCst);
        self.inner.resolve_verified_keys(service_did, key_id).await
    }
}

#[tokio::test]
async fn end_to_end_client_recovers_from_stale_target_key_with_one_refresh_retry() {
    let (addr, handler, task) = spawn_s2s_server(default_policy()).await;

    let resolver = Arc::new(StaleThenFreshResolver {
        inner: resolver_with_both(),
        stale_server_key: VerifiedPeerKey {
            key_id: None,
            ed25519_public: SecretEd25519Key::from_seed([200u8; 32]).public_key(),
        },
        refreshed: AtomicBool::new(false),
    });
    // refresh 重试只在 Resolver 模式存在;Pinned 模式没有可刷新的东西
    let config = S2sClientConfig::with_resolver(client_local_identity(), server_did(), resolver);
    let client = kRPC::new_with_transport(
        &format!("http://{}/s2s/event-report-v1", addr),
        None,
        KrpcTransportSecurity::S2sPayloadV1(config),
    )
    .await
    .unwrap();

    // 第一次 seal 用了过期 key → 服务端 403;客户端 refresh 后新 nonce 重试成功
    let value = client.call("report_event", json!({})).await.unwrap();
    assert_eq!(value, json!({"echo": "report_event"}));
    assert_eq!(handler.call_count(), 1);

    task.abort();
    let _ = task.await;
}

#[tokio::test]
async fn transport_constructor_validations() {
    // Tls 模式拒绝 http URL
    let err = kRPC::new_with_transport(
        "http://127.0.0.1:1/x",
        None,
        KrpcTransportSecurity::Tls,
    )
    .await;
    assert!(err.is_err());

    // S2S 模式拒绝非 /s2s/ path
    let config = S2sClientConfig::with_pinned_key(
        client_local_identity(),
        server_did(),
        SecretEd25519Key::from_seed(SERVER_SEED).public_key(),
    );
    let err = kRPC::new_with_transport(
        "http://127.0.0.1:1/krpc",
        None,
        KrpcTransportSecurity::S2sPayloadV1(config),
    )
    .await;
    assert!(err.is_err());

    // TlsAndS2s 拒绝 http URL
    let config = S2sClientConfig::with_pinned_key(
        client_local_identity(),
        server_did(),
        SecretEd25519Key::from_seed(SERVER_SEED).public_key(),
    );
    let err = kRPC::new_with_transport(
        "http://127.0.0.1:1/s2s/api-a",
        None,
        KrpcTransportSecurity::TlsAndS2sPayloadV1(config),
    )
    .await;
    assert!(err.is_err());

    // probe 只在 S2S 模式可用
    let client = kRPC::new("http://127.0.0.1:1/krpc", None);
    assert!(client.probe_s2s(None).await.is_err());

    // pinned key 在构造时校验:无效/small-order 公钥直接失败,不等到首次 call
    let config = S2sClientConfig::with_pinned_key(
        client_local_identity(),
        server_did(),
        [0u8; 32], // small-order point
    );
    let err = kRPC::new_with_transport(
        "http://127.0.0.1:1/s2s/api-a",
        None,
        KrpcTransportSecurity::S2sPayloadV1(config),
    )
    .await;
    assert!(err.is_err());
}

#[tokio::test]
async fn end_to_end_pinned_wrong_key_fails_closed_no_plaintext() {
    // pinned 了错误的目标公钥:请求确定性失败(服务端解不开→统一 403,
    // 客户端有界重试后返回 permanent),不会降级明文,也不会打到 handler
    let (addr, handler, task) = spawn_s2s_server(default_policy()).await;

    let config = S2sClientConfig::with_pinned_key(
        client_local_identity(),
        server_did(),
        SecretEd25519Key::from_seed([200u8; 32]).public_key(), // 错误 key
    );
    let client = kRPC::new_with_transport(
        &format!("http://{}/s2s/event-report-v1", addr),
        None,
        KrpcTransportSecurity::S2sPayloadV1(config),
    )
    .await
    .unwrap();

    let err = client.call("report_event", json!({})).await.unwrap_err();
    assert!(matches!(err, RPCErrors::S2sPermanentError(_)), "{err}");
    assert_eq!(handler.call_count(), 0);

    task.abort();
    let _ = task.await;
}
