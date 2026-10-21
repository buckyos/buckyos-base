//! Local HTTP regressions for legacy root DID document publication.

use super::*;
use crate::{NameClient, NameClientConfig};
use name_lib::{DeviceDocument, EncodedDocument, OwnerDocument};
use serde_json::json;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Notify;
use tokio::task::{JoinHandle, JoinSet};
use tokio_util::sync::CancellationToken;

const CHILD_HOST: &str = "relay.example.test";
const PARENT_HOST: &str = "example.test";
const DEVICE_PATH: &str = "/.well-known/device.json";
const ROOT_PATH: &str = "/.well-known/did.json";
const PUBLIC_KEY: &str = "T4Quc1L6Ogu4N2tTKOvneV1yYnBcmhP89B_RsuFsJZ8";

#[derive(Clone, Debug)]
struct Request {
    host: String,
    target: String,
}

struct Response {
    status: u16,
    body: String,
    delay: Duration,
}

impl Response {
    fn new(status: u16, body: impl ToString) -> Self {
        Self {
            status,
            body: body.to_string(),
            delay: Duration::ZERO,
        }
    }

    fn document(document: &EncodedDocument) -> Self {
        Self::new(200, document.to_string())
    }

    fn delayed(mut self, delay: Duration) -> Self {
        self.delay = delay;
        self
    }
}

struct HttpSite {
    address: SocketAddr,
    requests: Arc<Mutex<Vec<Request>>>,
    requested: Arc<Notify>,
    task: JoinHandle<()>,
}

impl HttpSite {
    async fn start(handler: impl Fn(&Request) -> Response + Send + Sync + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let requested = Arc::new(Notify::new());
        let recorded = requests.clone();
        let signal = requested.clone();
        let handler = Arc::new(handler);
        let task = tokio::spawn(async move {
            // Dropping the listener task also aborts any delayed connections.
            let mut connections = JoinSet::new();
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let recorded = recorded.clone();
                let signal = signal.clone();
                let handler = handler.clone();
                connections.spawn(async move {
                    let mut input = Vec::new();
                    let mut buffer = [0; 1024];
                    while !input.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                        let count = stream.read(&mut buffer).await.unwrap();
                        if count == 0 {
                            return;
                        }
                        input.extend_from_slice(&buffer[..count]);
                        assert!(input.len() < 16 * 1024);
                    }
                    let input = String::from_utf8(input).unwrap();
                    let request = Request {
                        target: input.lines().next().unwrap().split_whitespace().nth(1).unwrap().to_owned(),
                        host: input.lines().find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.eq_ignore_ascii_case("host").then(|| value.trim().to_owned())
                        }).unwrap(),
                    };
                    recorded.lock().unwrap().push(request.clone());
                    signal.notify_waiters();
                    let response = handler(&request);
                    tokio::time::sleep(response.delay).await;
                    let wire = format!(
                        "HTTP/1.1 {} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        response.status, response.body.len(), response.body
                    );
                    // Cancellation or a shared deadline may close the client first.
                    let _ = stream.write_all(wire.as_bytes()).await;
                });
            }
        });
        Self {
            address,
            requests,
            requested,
            task,
        }
    }

    fn provider(&self) -> Arc<WebProvider> {
        let mut provider = WebProvider::new_with_scheme("http");
        provider.client = Client::builder()
            .no_proxy()
            .resolve(CHILD_HOST, self.address)
            .resolve(PARENT_HOST, self.address)
            .build()
            .unwrap();
        Arc::new(provider)
    }

    fn client(&self) -> NameClient {
        let client = NameClient::new(NameClientConfig::for_test());
        client.set_method_authority("web", self.provider());
        client
    }

    fn targets(&self) -> Vec<String> {
        self.requests
            .lock()
            .unwrap()
            .iter()
            .map(|request| request.target.clone())
            .collect()
    }

    fn assert_no_parent(&self) {
        assert!(self
            .requests
            .lock()
            .unwrap()
            .iter()
            .all(|request| request.host == CHILD_HOST));
    }

    async fn wait_for(&self, target: &str) {
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let notified = self.requested.notified();
                if self.targets().iter().any(|seen| seen == target) {
                    return;
                }
                notified.await;
            }
        })
        .await
        .expect("expected HTTP request was not received");
    }
}

impl Drop for HttpSite {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn did() -> DID {
    DID::new("web", CHILD_HOST)
}

fn device_document(iat: u64) -> EncodedDocument {
    let mut document = DeviceDocument::new("relay", PUBLIC_KEY.into());
    document.id = did();
    document.iat = iat;
    document.exp = iat + 3600;
    EncodedDocument::JsonLd(serde_json::to_value(document).unwrap())
}

fn owner_document(iat: u64) -> EncodedDocument {
    let public_key = serde_json::from_value(json!({
        "kty": "OKP", "crv": "Ed25519", "x": PUBLIC_KEY,
    }))
    .unwrap();
    let mut document = OwnerDocument::new(
        did(),
        "relay".into(),
        "relay@example.test".into(),
        public_key,
    );
    document.iat = iat;
    document.exp = iat + 3600;
    EncodedDocument::JsonLd(serde_json::to_value(document).unwrap())
}

fn opts() -> ResolveOpts {
    ResolveOpts::new().normalize(Duration::from_secs(3))
}

#[tokio::test]
async fn legacy_device_root_resolves_through_name_client_with_explicit_and_default_type() {
    for doc_type in [Some(DidDocType::Device), None] {
        let document = device_document(buckyos_get_unix_timestamp() - 10);
        let served = document.clone();
        let site = HttpSite::start(move |request| match request.target.as_str() {
            ROOT_PATH => Response::document(&served),
            _ => Response::new(404, ""),
        })
        .await;
        let client = site.client();
        assert_eq!(
            client.resolve_did(&did(), doc_type.clone()).await.unwrap(),
            document
        );
        let first_requests = site.targets();
        if doc_type.is_some() {
            assert_eq!(first_requests, [DEVICE_PATH, ROOT_PATH]);
        } else {
            assert_eq!(first_requests, [ROOT_PATH, DEVICE_PATH, ROOT_PATH]);
        }
        assert_eq!(
            client.resolve_did(&did(), doc_type).await.unwrap(),
            document
        );
        assert_eq!(
            site.targets(),
            first_requests,
            "verified result should remain cacheable"
        );
        site.assert_no_parent();
    }
}

#[tokio::test]
async fn forced_authority_refresh_fetches_new_root_body_and_records_receipt() {
    let iat = buckyos_get_unix_timestamp() - 10;
    let published = Arc::new(Mutex::new(device_document(iat)));
    let served = published.clone();
    let site = HttpSite::start(move |request| match request.target.as_str() {
        ROOT_PATH => Response::document(&served.lock().unwrap()),
        _ => Response::new(404, ""),
    })
    .await;
    let client = site.client();
    client.resolve_did(&did(), None).await.unwrap();
    let replacement = device_document(iat + 1);
    *published.lock().unwrap() = replacement.clone();
    let refresh = client
        .default_resolve_opts()
        .with_force_authority_query()
        .normalize(Duration::from_secs(3));
    let result = client
        .resolve_did_ex(&did(), None, Revision::current(), refresh.clone())
        .await
        .unwrap();
    let selected = result.select(&Revision::current()).unwrap();
    assert_eq!(selected.doc, replacement);
    assert_eq!(
        selected.report.authority_receipt.as_deref(),
        Some("web-provider")
    );
    let receipts = refresh
        .receipts()
        .authority_receipts(&did(), &DidDocType::Device);
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].answer.body.as_ref(), Some(&replacement));
    assert_eq!(
        site.targets(),
        [ROOT_PATH, DEVICE_PATH, ROOT_PATH, DEVICE_PATH, ROOT_PATH]
    );
    site.assert_no_parent();
}

#[tokio::test]
async fn root_device_is_not_accepted_as_zone_or_custom_type() {
    for doc_type in [DidDocType::Zone, DidDocType::custom("profile")] {
        let document = device_document(buckyos_get_unix_timestamp() - 10);
        let site = HttpSite::start(move |request| match request.target.as_str() {
            ROOT_PATH => Response::document(&document),
            _ => Response::new(404, ""),
        })
        .await;
        let answer = site
            .provider()
            .get_document(&did(), &doc_type, &Revision::current(), &opts())
            .await;
        assert!(
            answer.body.is_none(),
            "root Device must not satisfy {}",
            doc_type
        );
        assert_eq!(
            site.targets()
                .iter()
                .filter(|target| target.as_str() == ROOT_PATH)
                .count(),
            1
        );
    }
}

#[tokio::test]
async fn fallback_requires_the_requested_identity_and_a_recognized_type() {
    let document = device_document(buckyos_get_unix_timestamp() - 10);
    let mut wrong_id = document.clone().to_json_value().unwrap();
    wrong_id["id"] = json!("did:web:other.example.test");
    let unknown_type = json!({"id": did().to_string(), "iat": buckyos_get_unix_timestamp() - 10});
    for invalid in [wrong_id, unknown_type] {
        let site = HttpSite::start(move |request| match request.target.as_str() {
            ROOT_PATH => Response::new(200, &invalid),
            _ => Response::new(404, ""),
        })
        .await;
        let answer = site
            .provider()
            .get_document(&did(), &DidDocType::Device, &Revision::current(), &opts())
            .await;
        assert!(answer.body.is_none());
    }
}

#[tokio::test]
async fn typed_device_and_owner_paths_have_priority_over_legacy_root() {
    let iat = buckyos_get_unix_timestamp() - 10;
    for (doc_type, path, document) in [
        (DidDocType::Device, DEVICE_PATH, device_document(iat)),
        (
            DidDocType::Owner,
            "/.well-known/owner.json",
            owner_document(iat),
        ),
    ] {
        let served = document.clone();
        let fallback = device_document(iat + 1);
        let site = HttpSite::start(move |request| {
            if request.target == path {
                Response::document(&served)
            } else {
                Response::document(&fallback)
            }
        })
        .await;
        let answer = site
            .provider()
            .get_document(&did(), &doc_type, &Revision::current(), &opts())
            .await;
        assert_eq!(answer.body, Some(document));
        assert_eq!(site.targets(), [path]);
    }
}

#[tokio::test]
async fn typed_negative_status_cannot_be_bypassed_by_root_document() {
    for (status, code) in [("missing", 404), ("invalid", 200), ("revoked", 410)] {
        let fallback = device_document(buckyos_get_unix_timestamp() - 10);
        let site = HttpSite::start(move |request| {
            if request.target == DEVICE_PATH {
                Response::new(code, json!({"didDocumentMetadata": {"buckyos": {
                    "docType": "device", "documentStatus": status, "reason": "test negative state"
                }}}))
            } else {
                Response::document(&fallback)
            }
        }).await;
        let answer = site
            .provider()
            .get_document(&did(), &DidDocType::Device, &Revision::current(), &opts())
            .await;
        assert!(answer.body.is_none());
        assert!(answer.publish_info.unwrap().type_state.is_some());
        assert_eq!(
            site.targets(),
            [DEVICE_PATH],
            "{} must stop fallback",
            status
        );
    }
}

#[tokio::test]
async fn missing_static_documents_fall_back_to_parent_resolver() {
    let document = device_document(buckyos_get_unix_timestamp() - 10);
    let served = document.clone();
    let site = HttpSite::start(move |request| {
        if request.host == PARENT_HOST {
            Response::document(&served)
        } else {
            Response::new(404, "")
        }
    })
    .await;
    assert_eq!(
        site.client()
            .resolve_did(&did(), Some(DidDocType::Device))
            .await
            .unwrap(),
        document
    );
    assert_eq!(
        site.targets(),
        [
            DEVICE_PATH,
            ROOT_PATH,
            "/1.0/identifiers/did:web:relay.example.test?type=device",
        ]
    );
}

#[tokio::test]
async fn historical_queries_use_only_the_parent_api() {
    for revision in [Revision::exact(1000, "aa"), Revision::closest(2000)] {
        let site = HttpSite::start(|_| Response::new(501, "")).await;
        let answer = site
            .provider()
            .get_document(&did(), &DidDocType::Device, &revision, &opts())
            .await;
        assert!(answer.unsupported_history);
        let requests = site.requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].host, PARENT_HOST);
        assert!(requests[0].target.starts_with("/1.0/identifiers/"));
        let query = if revision.is_current() {
            unreachable!()
        } else if matches!(revision, Revision::Exact { .. }) {
            "versionId="
        } else {
            "versionTime="
        };
        assert!(requests[0].target.contains(query));
    }
}

#[tokio::test]
async fn root_fallback_obeys_the_shared_deadline() {
    let site = HttpSite::start(|request| {
        let delay = if request.target == DEVICE_PATH {
            Duration::from_millis(20)
        } else {
            Duration::from_secs(2)
        };
        Response::new(404, "").delayed(delay)
    })
    .await;
    let options = ResolveOpts::new()
        .with_timeout(Duration::from_millis(300))
        .normalize(Duration::from_secs(3));
    let started = Instant::now();
    let answer = site
        .provider()
        .get_document(&did(), &DidDocType::Device, &Revision::current(), &options)
        .await;
    assert!(answer.body.is_none());
    assert!(matches!(
        options.budget().check(),
        Err(NSError::DeadlineExceeded(_))
    ));
    assert!(started.elapsed() < Duration::from_secs(1));
    assert_eq!(site.targets(), [DEVICE_PATH, ROOT_PATH]);
    site.assert_no_parent();
}

#[tokio::test]
async fn cancellation_during_root_fallback_does_not_start_parent_request() {
    let site = HttpSite::start(|request| {
        let response = Response::new(404, "");
        if request.target == ROOT_PATH {
            response.delayed(Duration::from_secs(60))
        } else {
            response
        }
    })
    .await;
    let cancel = CancellationToken::new();
    let options = ResolveOpts::new()
        .with_cancel(cancel.clone())
        .normalize(Duration::from_secs(3));
    let provider = site.provider();
    let requested_did = did();
    let revision = Revision::current();
    let (answer, ()) = tokio::join!(
        provider.get_document(&requested_did, &DidDocType::Device, &revision, &options),
        async {
            site.wait_for(ROOT_PATH).await;
            cancel.cancel();
        },
    );
    assert!(answer.body.is_none());
    assert!(matches!(
        options.budget().check(),
        Err(NSError::Cancelled(_))
    ));
    assert_eq!(site.targets(), [DEVICE_PATH, ROOT_PATH]);
    site.assert_no_parent();
}
