//! `serve_http_by_s2s_rpc_handler` 的 DID-only S2S 安全与集成测试。

use crate::{
    full_body, serve_http_by_s2s_rpc_handler, HttpServer, Runner, ServerError, ServerResult,
    StreamInfo,
};
use ::kRPC::s2s::*;
use ::kRPC::{
    kRPC, KrpcTransportSecurity, RPCErrors, RPCRequest, RPCResponse, RPCResult, RPCServerContext,
    RPCServerHandler,
};
use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::SigningKey;
use http::{Request, Response, StatusCode};
use http_body_util::combinators::BoxBody;
use http_body_util::BodyExt;
use hyper::body::Bytes;
use name_client::{
    CacheBackend, IdentityRoots, NameClient, NameClientConfig, NameInfo, NsProvider, RecordType,
};
use name_lib::{DidDocType, EncodedDocument, NSError, NSResult, DID};
use serde_json::{json, Value};
use std::net::IpAddr;
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

fn public_key(seed: [u8; 32]) -> [u8; 32] {
    SigningKey::from_bytes(&seed).verifying_key().to_bytes()
}

fn identity_document(did: &DID, seed: [u8; 32]) -> Value {
    let x = URL_SAFE_NO_PAD.encode(public_key(seed));
    json!({
        "@context": ["https://www.w3.org/ns/did/v1", "https://buckyos.ai/ns/did/v1"],
        "id": did.to_string(),
        "verificationMethod": [{
            "id": "#main_key",
            "type": "JsonWebKey2020",
            "controller": did.to_string(),
            "publicKeyJwk": {"kty": "OKP", "crv": "Ed25519", "x": x}
        }],
        "authentication": ["#main_key"],
        "service": [{
            "id": "#did-object",
            "type": "DIDObjectService",
            "serviceEndpoint": format!("https://{}/", did.to_raw_host_name()),
            "profile": "https://example.com/service-profile.json"
        }]
    })
}

fn pkcs8_pem(seed: [u8; 32]) -> String {
    let mut der = vec![
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ];
    der.extend_from_slice(&seed);
    format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
        base64::engine::general_purpose::STANDARD.encode(der)
    )
}

fn write_identity(roots: &IdentityRoots, did: &DID, seed: [u8; 32]) {
    let public_dir = roots.public_dir(&did.to_string()).unwrap();
    let security_dir = roots.security_dir(&did.to_string()).unwrap();
    std::fs::create_dir_all(&public_dir).unwrap();
    std::fs::create_dir_all(&security_dir).unwrap();
    std::fs::write(
        public_dir.join("did.json"),
        serde_json::to_vec_pretty(&identity_document(did, seed)).unwrap(),
    )
    .unwrap();
    // 同目录其它 doc_type 文件不得影响 did.json 的选择。
    std::fs::write(public_dir.join("app.json"), b"{}").unwrap();
    std::fs::write(public_dir.join("info.json"), b"{}").unwrap();
    std::fs::write(
        security_dir.join("authentication.private.pem"),
        pkcs8_pem(seed),
    )
    .unwrap();
    assert!(!security_dir.join("authentication.keyref.json").exists());
}

fn memory_name_client() -> Arc<NameClient> {
    Arc::new(NameClient::new(NameClientConfig {
        enable_cache: true,
        cache_backend: CacheBackend::Memory,
        enable_zone_resolver: false,
        ..Default::default()
    }))
}

struct TestFixture {
    roots: IdentityRoots,
    client: Arc<NameClient>,
    runtime: S2sRuntime,
}

impl TestFixture {
    fn new(identities: &[(DID, [u8; 32])]) -> Self {
        let base = tempfile::tempdir().unwrap().keep();
        let roots = IdentityRoots::new(base.join("identity"), base.join("security"));
        let client = memory_name_client();
        for (did, seed) in identities {
            write_identity(&roots, did, *seed);
            client.set_local_authority_override(
                did.clone(),
                DidDocType::Zone,
                EncodedDocument::JsonLd(identity_document(did, *seed)),
                "s2s-test",
                None,
            );
        }
        let runtime = S2sRuntime::new(roots.clone(), client.clone());
        Self {
            roots,
            client,
            runtime,
        }
    }

    fn standard() -> Self {
        Self::new(&[(client_did(), CLIENT_SEED), (server_did(), SERVER_SEED)])
    }

    fn replace_identity(&self, did: &DID, seed: [u8; 32]) {
        write_identity(&self.roots, did, seed);
        self.client.set_local_authority_override(
            did.clone(),
            DidDocType::Zone,
            EncodedDocument::JsonLd(identity_document(did, seed)),
            "s2s-test-rotated",
            None,
        );
    }
}

struct RecordingHandler {
    calls: AtomicUsize,
    last_ctx: std::sync::Mutex<Option<RPCServerContext>>,
}

impl RecordingHandler {
    fn new() -> Self {
        Self {
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

fn default_policy() -> S2sServerSecurityPolicy {
    S2sServerSecurityPolicy::builder()
        .peer_admission(PeerAdmissionPolicy::allow_services([
            client_did().to_string()
        ]))
        .build()
        .unwrap()
}

async fn server_context_with_fixture(
    fixture: &TestFixture,
    policy: S2sServerSecurityPolicy,
) -> S2sRpcServerContext {
    S2sRpcServerContext::builder(server_did())
        .with_runtime(fixture.runtime.clone())
        .security_policy(policy)
        .build()
        .await
        .unwrap()
}

async fn server_context() -> (TestFixture, S2sRpcServerContext) {
    let fixture = TestFixture::standard();
    let context = server_context_with_fixture(&fixture, default_policy()).await;
    (fixture, context)
}

async fn client_transport_with_fixture(fixture: &TestFixture) -> S2sClientTransport {
    S2sClientTransport::new(
        S2sClientConfig::new(client_did(), server_did()).with_runtime(fixture.runtime.clone()),
    )
    .await
    .unwrap()
}

fn rpc_request_bytes(method: &str, token: Option<&str>) -> Vec<u8> {
    let mut req = RPCRequest::new(method, json!({"k": "v"}));
    req.seq = 42;
    req.token = token.map(str::to_string);
    serde_json::to_vec(&req).unwrap()
}

fn now() -> u64 {
    buckyos_kit::buckyos_get_unix_timestamp()
}

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
        .uri(format!("http://127.0.0.1:18080/s2s/{api}"))
        .header(http::header::CONTENT_TYPE, S2S_CONTENT_TYPE);
    builder.headers_mut().unwrap().extend(header_map);
    (builder.body(full_body(sealed)).unwrap(), pending)
}

fn stream_info() -> StreamInfo {
    StreamInfo::new("203.0.113.7:5555".to_string())
}

async fn read_body(resp: Response<BoxBody<Bytes, ServerError>>) -> Bytes {
    resp.collect().await.unwrap().to_bytes()
}

#[tokio::test]
async fn standard_two_file_layout_roundtrips_without_keyref() {
    let (fixture, context) = server_context().await;
    let transport = client_transport_with_fixture(&fixture).await;
    let handler = RecordingHandler::new();
    let (request, pending) = encrypted_http_request(
        &transport,
        "event-report-v1",
        &rpc_request_bytes("report_event", None),
    )
    .await;
    let response = serve_http_by_s2s_rpc_handler(request, stream_info(), &handler, &context)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(http::header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    let response_headers = S2sResponseHeaders::parse(response.headers()).unwrap();
    assert_eq!(response_headers.from, server_did());
    assert_eq!(response_headers.to, client_did());
    let body = read_body(response).await;
    let plaintext = transport
        .open_response(&pending, &response_headers, &body, now())
        .await
        .unwrap();
    let rpc_response: RPCResponse = serde_json::from_slice(&plaintext).unwrap();
    assert_eq!(
        rpc_response.result,
        RPCResult::Success(json!({"echo": "report_event"}))
    );
    assert_eq!(handler.call_count(), 1);
    let rpc_context = handler.last_context().unwrap();
    assert_eq!(
        rpc_context.authenticated_from_service_did,
        Some(client_did())
    );
    assert!(rpc_context.authenticated_from_key_fingerprint.is_some());
}

#[tokio::test]
async fn did_web_and_did_bns_use_the_same_runtime_path() {
    let web_a = DID::new("web", "a.example.com");
    let web_b = DID::new("web", "b.example.com");
    let bns_a = DID::new("bns", "a.alice");
    let bns_b = DID::new("bns", "b.alice");
    for (local, remote) in [(web_a, web_b), (bns_a, bns_b)] {
        let fixture =
            TestFixture::new(&[(local.clone(), CLIENT_SEED), (remote.clone(), SERVER_SEED)]);
        let client = S2sClientTransport::new(
            S2sClientConfig::new(local.clone(), remote.clone())
                .with_runtime(fixture.runtime.clone()),
        )
        .await
        .unwrap();
        let policy = S2sServerSecurityPolicy::builder()
            .peer_admission(PeerAdmissionPolicy::allow_services([local.to_string()]))
            .build()
            .unwrap();
        let server = S2sRpcServerContext::builder(remote)
            .with_runtime(fixture.runtime)
            .security_policy(policy)
            .build()
            .await
            .unwrap();
        let (headers, body, _) = client
            .seal_request("same-loader", &rpc_request_bytes("m", None), now(), false)
            .await
            .unwrap();
        assert!(server
            .open_request(&headers, "same-loader", &body, now())
            .await
            .is_ok());
    }
}

#[tokio::test]
async fn did_fragment_and_malformed_headers_are_rejected_before_handler() {
    let (fixture, context) = server_context().await;
    let transport = client_transport_with_fixture(&fixture).await;
    for (name, value) in [
        ("krpc-s2s-from", "did:web:attacker.example.com"),
        (
            "krpc-s2s-from",
            "did:web:event-producer.example.com#main_key",
        ),
        ("krpc-s2s-to", "did:web:other.example.com"),
        ("krpc-s2s-issued-at", "1"),
        ("krpc-s2s-expires-at", "99999999999"),
        ("krpc-s2s-nonce", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        ("krpc-s2s-version", "2"),
    ] {
        let handler = RecordingHandler::new();
        let (mut request, _) =
            encrypted_http_request(&transport, "event-report-v1", &rpc_request_bytes("m", None))
                .await;
        request.headers_mut().insert(
            http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
            http::HeaderValue::from_str(value).unwrap(),
        );
        let response = serve_http_by_s2s_rpc_handler(request, stream_info(), &handler, &context)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(handler.call_count(), 0);
    }
}

#[tokio::test]
async fn tampered_body_and_cross_api_reflection_are_rejected() {
    let (fixture, context) = server_context().await;
    let transport = client_transport_with_fixture(&fixture).await;
    let handler = RecordingHandler::new();

    let (request, _) =
        encrypted_http_request(&transport, "event-report-v1", &rpc_request_bytes("m", None)).await;
    let (parts, body) = request.into_parts();
    let mut bytes = body.collect().await.unwrap().to_bytes().to_vec();
    bytes[0] ^= 1;
    let response = serve_http_by_s2s_rpc_handler(
        Request::from_parts(parts, full_body(bytes)),
        stream_info(),
        &handler,
        &context,
    )
    .await
    .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let (headers, sealed, _) = transport
        .seal_request("api-a", &rpc_request_bytes("m", None), now(), false)
        .await
        .unwrap();
    let mut map = http::HeaderMap::new();
    headers.apply(&mut map).unwrap();
    let mut builder = Request::builder()
        .method("POST")
        .uri("http://127.0.0.1/s2s/api-b")
        .header(http::header::CONTENT_TYPE, S2S_CONTENT_TYPE);
    builder.headers_mut().unwrap().extend(map);
    let response = serve_http_by_s2s_rpc_handler(
        builder.body(full_body(sealed)).unwrap(),
        stream_info(),
        &handler,
        &context,
    )
    .await
    .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(handler.call_count(), 0);
}

#[tokio::test]
async fn wrong_target_and_replay_are_rejected() {
    let (fixture, context) = server_context().await;
    let other = DID::new("web", "other-service.example.com");
    write_identity(&fixture.roots, &other, [7u8; 32]);
    fixture.client.set_local_authority_override(
        other.clone(),
        DidDocType::Zone,
        EncodedDocument::JsonLd(identity_document(&other, [7u8; 32])),
        "other",
        None,
    );
    let wrong_transport = S2sClientTransport::new(
        S2sClientConfig::new(client_did(), other).with_runtime(fixture.runtime.clone()),
    )
    .await
    .unwrap();
    let handler = RecordingHandler::new();
    let (request, _) = encrypted_http_request(
        &wrong_transport,
        "event-report-v1",
        &rpc_request_bytes("m", None),
    )
    .await;
    let response = serve_http_by_s2s_rpc_handler(request, stream_info(), &handler, &context)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let transport = client_transport_with_fixture(&fixture).await;
    let (headers, body, _) = transport
        .seal_request(
            "event-report-v1",
            &rpc_request_bytes("m", None),
            now(),
            false,
        )
        .await
        .unwrap();
    for expected in [StatusCode::OK, StatusCode::FORBIDDEN] {
        let mut map = http::HeaderMap::new();
        headers.apply(&mut map).unwrap();
        let mut builder = Request::builder()
            .method("POST")
            .uri("http://127.0.0.1/s2s/event-report-v1")
            .header(http::header::CONTENT_TYPE, S2S_CONTENT_TYPE);
        builder.headers_mut().unwrap().extend(map);
        let response = serve_http_by_s2s_rpc_handler(
            builder.body(full_body(body.clone())).unwrap(),
            stream_info(),
            &handler,
            &context,
        )
        .await
        .unwrap();
        assert_eq!(response.status(), expected);
    }
    assert_eq!(handler.call_count(), 1);
}

#[tokio::test]
async fn plaintext_is_fail_closed_unless_cidr_api_and_token_are_admitted() {
    let fixture = TestFixture::standard();
    let default = server_context_with_fixture(&fixture, default_policy()).await;
    let handler = RecordingHandler::new();
    let request = Request::builder()
        .method("POST")
        .uri("http://127.0.0.1/s2s/event-report-v1")
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(full_body(rpc_request_bytes("m", Some("token"))))
        .unwrap();
    assert_eq!(
        serve_http_by_s2s_rpc_handler(request, stream_info(), &handler, &default)
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );

    let mut policy = S2sServerSecurityPolicy::trusted_network_plaintext(
        parse_cidrs(["203.0.113.0/24"]).unwrap(),
        ["event-report-v1"],
    )
    .unwrap();
    policy.peer_admission = PeerAdmissionPolicy::allow_services([client_did().to_string()]);
    let admitted = server_context_with_fixture(&fixture, policy).await;
    for (token, expected) in [
        (Some("token"), StatusCode::OK),
        (None, StatusCode::FORBIDDEN),
    ] {
        let request = Request::builder()
            .method("POST")
            .uri("http://127.0.0.1/s2s/event-report-v1")
            .header(http::header::CONTENT_TYPE, "application/json")
            .body(full_body(rpc_request_bytes("m", token)))
            .unwrap();
        assert_eq!(
            serve_http_by_s2s_rpc_handler(request, stream_info(), &handler, &admitted)
                .await
                .unwrap()
                .status(),
            expected
        );
    }
    assert_eq!(
        handler
            .last_context()
            .unwrap()
            .authenticated_from_service_did,
        None
    );
}

#[tokio::test]
async fn expired_future_and_oversized_requests_fail_before_dispatch() {
    let (fixture, context) = server_context().await;
    let transport = client_transport_with_fixture(&fixture).await;
    let handler = RecordingHandler::new();
    for timestamp in [now() - 1000, now() + 3000] {
        let (headers, body, _) = transport
            .seal_request(
                "event-report-v1",
                &rpc_request_bytes("m", None),
                timestamp,
                false,
            )
            .await
            .unwrap();
        let mut map = http::HeaderMap::new();
        headers.apply(&mut map).unwrap();
        let mut builder = Request::builder()
            .method("POST")
            .uri("http://127.0.0.1/s2s/event-report-v1")
            .header(http::header::CONTENT_TYPE, S2S_CONTENT_TYPE);
        builder.headers_mut().unwrap().extend(map);
        assert_eq!(
            serve_http_by_s2s_rpc_handler(
                builder.body(full_body(body)).unwrap(),
                stream_info(),
                &handler,
                &context,
            )
            .await
            .unwrap()
            .status(),
            StatusCode::FORBIDDEN
        );
    }
    let request = Request::builder()
        .method("POST")
        .uri("http://127.0.0.1/s2s/event-report-v1")
        .header(http::header::CONTENT_TYPE, S2S_CONTENT_TYPE)
        .header(http::header::CONTENT_LENGTH, 10 * 1024 * 1024)
        .body(full_body(vec![0u8; 64]))
        .unwrap();
    assert_eq!(
        serve_http_by_s2s_rpc_handler(request, stream_info(), &handler, &context)
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(handler.call_count(), 0);
}

#[tokio::test]
async fn response_binding_rejects_rewritten_did_and_nonce() {
    let (fixture, context) = server_context().await;
    let transport = client_transport_with_fixture(&fixture).await;
    let handler = RecordingHandler::new();
    let (request, pending) =
        encrypted_http_request(&transport, "event-report-v1", &rpc_request_bytes("m", None)).await;
    let response = serve_http_by_s2s_rpc_handler(request, stream_info(), &handler, &context)
        .await
        .unwrap();
    let mut headers = S2sResponseHeaders::parse(response.headers()).unwrap();
    let body = read_body(response).await;
    headers.from = DID::new("web", "other.example.com");
    assert!(matches!(
        transport
            .open_response(&pending, &headers, &body, now())
            .await,
        Err(S2sError::WrongPeer(_))
    ));
    headers.from = server_did();
    headers.in_reply_to = [0u8; 24];
    assert!(matches!(
        transport
            .open_response(&pending, &headers, &body, now())
            .await,
        Err(S2sError::WrongKind)
    ));
}

#[tokio::test]
async fn reload_uses_new_key_for_new_requests_but_inflight_snapshot_finishes() {
    let fixture = TestFixture::standard();
    let context = server_context_with_fixture(&fixture, default_policy()).await;
    let transport = client_transport_with_fixture(&fixture).await;
    let (headers, body, pending) = transport
        .seal_request(
            "event-report-v1",
            &rpc_request_bytes("m", None),
            now(),
            false,
        )
        .await
        .unwrap();
    let decrypted = context
        .open_request(&headers, "event-report-v1", &body, now())
        .await
        .unwrap();

    fixture.replace_identity(&server_did(), [21u8; 32]);
    assert!(context.reload_local_identity().unwrap());
    let response_json = serde_json::to_vec(&RPCResponse {
        result: RPCResult::Success(json!({"ok": true})),
        seq: 42,
        trace_id: None,
    })
    .unwrap();
    let (response_headers, response_body) = context
        .seal_response(&decrypted, &response_json, now())
        .await
        .unwrap();
    assert!(transport
        .open_response(&pending, &response_headers, &response_body, now())
        .await
        .is_ok());

    // 新 client 解析到新默认 key；新请求由 reload 后 server key 解密。
    let fresh_client = client_transport_with_fixture(&fixture).await;
    let (headers, body, _) = fresh_client
        .seal_request(
            "event-report-v1",
            &rpc_request_bytes("m", None),
            now(),
            false,
        )
        .await
        .unwrap();
    assert!(context
        .open_request(&headers, "event-report-v1", &body, now())
        .await
        .is_ok());
}

struct S2sHttpServer {
    context: Arc<S2sRpcServerContext>,
    handler: Arc<RecordingHandler>,
}

#[async_trait]
impl HttpServer for S2sHttpServer {
    async fn serve_request(
        &self,
        request: http::Request<BoxBody<Bytes, ServerError>>,
        info: StreamInfo,
    ) -> ServerResult<http::Response<BoxBody<Bytes, ServerError>>> {
        serve_http_by_s2s_rpc_handler(request, info, self.handler.as_ref(), &self.context).await
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
    fixture: &TestFixture,
) -> (
    std::net::SocketAddr,
    Arc<RecordingHandler>,
    tokio::task::JoinHandle<()>,
) {
    let addr = random_loopback_addr();
    let handler = Arc::new(RecordingHandler::new());
    let context = Arc::new(server_context_with_fixture(fixture, default_policy()).await);
    let server = Arc::new(S2sHttpServer {
        context,
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

#[tokio::test]
async fn end_to_end_krpc_call_and_probe_are_did_only() {
    let fixture = TestFixture::standard();
    let (addr, handler, task) = spawn_s2s_server(&fixture).await;
    let config =
        S2sClientConfig::new(client_did(), server_did()).with_runtime(fixture.runtime.clone());
    let client = kRPC::new_with_transport(
        &format!("http://{addr}/s2s/event-report-v1"),
        Some("session-token".to_string()),
        KrpcTransportSecurity::S2sPayloadV1(config),
    )
    .await
    .unwrap();
    assert_eq!(
        client
            .call("report_event", json!({"level": "info"}))
            .await
            .unwrap(),
        json!({"echo": "report_event"})
    );
    assert_eq!(client.probe_s2s(None).await.unwrap()["probe"], "ok");
    assert_eq!(handler.call_count(), 1);
    task.abort();
    let _ = task.await;
}

struct RotatingAuthority {
    did: DID,
    stale: EncodedDocument,
    fresh: EncodedDocument,
    calls: AtomicUsize,
}

#[async_trait]
impl NsProvider for RotatingAuthority {
    fn get_id(&self) -> String {
        "rotating-s2s-authority".to_string()
    }

    async fn query(
        &self,
        _name: &str,
        _record_type: Option<RecordType>,
        _from_ip: Option<IpAddr>,
    ) -> NSResult<NameInfo> {
        Err(NSError::NotFound("not a DNS provider".to_string()))
    }

    async fn query_did(
        &self,
        did: &DID,
        _doc_type: Option<DidDocType>,
        _from_ip: Option<IpAddr>,
    ) -> NSResult<EncodedDocument> {
        if did != &self.did {
            return Err(NSError::NotFound(did.to_string()));
        }
        if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
            Ok(self.stale.clone())
        } else {
            Ok(self.fresh.clone())
        }
    }
}

#[tokio::test]
async fn stale_remote_cache_gets_one_authority_refresh_with_fresh_nonce() {
    let server_fixture = TestFixture::standard();
    let (addr, handler, task) = spawn_s2s_server(&server_fixture).await;

    let client_fixture = TestFixture::standard();
    client_fixture
        .client
        .clear_local_authority_override(&server_did(), DidDocType::Zone);
    client_fixture
        .client
        .set_method_authority(
            "web",
            Box::new(RotatingAuthority {
                did: server_did(),
                stale: EncodedDocument::JsonLd(identity_document(&server_did(), [200u8; 32])),
                fresh: EncodedDocument::JsonLd(identity_document(&server_did(), SERVER_SEED)),
                calls: AtomicUsize::new(0),
            }),
        )
        .await;

    let client = kRPC::new_with_transport(
        &format!("http://{addr}/s2s/event-report-v1"),
        None,
        KrpcTransportSecurity::S2sPayloadV1(
            S2sClientConfig::new(client_did(), server_did())
                .with_runtime(client_fixture.runtime.clone()),
        ),
    )
    .await
    .unwrap();
    assert_eq!(
        client.call("report_event", json!({})).await.unwrap(),
        json!({"echo": "report_event"})
    );
    assert_eq!(handler.call_count(), 1);
    task.abort();
    let _ = task.await;
}

#[tokio::test]
async fn server_refreshes_stale_sender_key_once_before_failing_closed() {
    let server_fixture = TestFixture::standard();
    server_fixture
        .client
        .clear_local_authority_override(&client_did(), DidDocType::Zone);
    server_fixture
        .client
        .set_method_authority(
            "web",
            Box::new(RotatingAuthority {
                did: client_did(),
                stale: EncodedDocument::JsonLd(identity_document(&client_did(), [201u8; 32])),
                fresh: EncodedDocument::JsonLd(identity_document(&client_did(), CLIENT_SEED)),
                calls: AtomicUsize::new(0),
            }),
        )
        .await;
    let context = server_context_with_fixture(&server_fixture, default_policy()).await;

    let client_fixture = TestFixture::standard();
    let transport = client_transport_with_fixture(&client_fixture).await;
    let (headers, body, _) = transport
        .seal_request(
            "event-report-v1",
            &rpc_request_bytes("report_event", None),
            now(),
            false,
        )
        .await
        .unwrap();

    let decrypted = context
        .open_request(&headers, "event-report-v1", &body, now())
        .await
        .unwrap();
    assert_eq!(decrypted.authenticated_from_did, client_did());
    assert_eq!(
        decrypted.authenticated_from_fingerprint,
        ed25519_key_fingerprint(&public_key(CLIENT_SEED))
    );
}

#[tokio::test]
async fn invalid_remote_document_fails_closed_without_plaintext_fallback() {
    let server_fixture = TestFixture::standard();
    let (addr, handler, task) = spawn_s2s_server(&server_fixture).await;
    let client_fixture = TestFixture::standard();
    client_fixture.client.set_local_authority_override(
        server_did(),
        DidDocType::Zone,
        EncodedDocument::JsonLd(identity_document(&server_did(), [200u8; 32])),
        "wrong-key",
        None,
    );
    let client = kRPC::new_with_transport(
        &format!("http://{addr}/s2s/event-report-v1"),
        None,
        KrpcTransportSecurity::S2sPayloadV1(
            S2sClientConfig::new(client_did(), server_did())
                .with_runtime(client_fixture.runtime.clone()),
        ),
    )
    .await
    .unwrap();
    let error = client.call("report_event", json!({})).await.unwrap_err();
    assert!(matches!(error, RPCErrors::S2sPermanentError(_)));
    assert_eq!(handler.call_count(), 0);
    task.abort();
    let _ = task.await;
}

#[tokio::test]
async fn transport_constructor_validations_remain_strict() {
    assert!(
        kRPC::new_with_transport("http://127.0.0.1:1/x", None, KrpcTransportSecurity::Tls,)
            .await
            .is_err()
    );
    let fixture = TestFixture::standard();
    let config =
        S2sClientConfig::new(client_did(), server_did()).with_runtime(fixture.runtime.clone());
    assert!(kRPC::new_with_transport(
        "http://127.0.0.1:1/krpc",
        None,
        KrpcTransportSecurity::S2sPayloadV1(config),
    )
    .await
    .is_err());
    let mut bad = S2sServerSecurityPolicy::public_internet_default();
    bad.message.max_lifetime_secs = 0;
    let context = server_context_with_fixture(&fixture, default_policy()).await;
    assert!(context.reload_policy(bad).is_err());
}
