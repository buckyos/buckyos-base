use buckyos_kit::buckyos_get_unix_timestamp;
use name_client::*;
use name_lib::{DidDocType, EncodedDocument, DID};
use serde_json::json;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// 只计数的 Zone locker：每个请求都回答“没有意见”（404 无 documentStatus）。
async fn spawn_counting_zone_locker() -> (String, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = hits.clone();
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            counter.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let _ = stream.read(&mut buf).await;
                let _ = stream
                    .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    .await;
                let _ = stream.shutdown().await;
            });
        }
    });
    (format!("http://{}", addr), hits)
}

async fn resolve(client: &NameClient, did: &DID) -> DocResult {
    let opts = ResolveOpts::default().normalize(Duration::from_secs(5));
    client
        .resolve_did_ex(did, Some(DidDocType::Device), Revision::current(), opts)
        .await
        .unwrap()
}

#[tokio::test]
async fn bypassed_dids_never_reach_the_zone_locker() {
    let (endpoint, hits) = spawn_counting_zone_locker().await;
    let client = NameClient::new(NameClientConfig {
        enable_zone_locker: true,
        zone_locker: ZoneLockerConfig {
            endpoint,
            connect_timeout: Duration::from_millis(500),
            request_timeout: Duration::from_secs(2),
        },
        ..NameClientConfig::for_test()
    });
    let ood1 = DID::from_str("did:bns:ood1.alice").unwrap();
    let ood2 = DID::from_str("did:bns:ood2.alice").unwrap();
    client.set_zone_locker_bypass([ood1.clone()]);
    assert!(client.is_zone_locker_bypassed(&ood1));
    assert!(!client.is_zone_locker_bypassed(&ood2));

    resolve(&client, &ood1).await;
    assert_eq!(hits.load(Ordering::SeqCst), 0, "bypassed DID must not ask the Zone locker");

    resolve(&client, &ood2).await;
    assert!(hits.load(Ordering::SeqCst) > 0, "other DIDs still ask the Zone locker");

    // 例外只跳过 Zone locker：本机 locker 照常生效。
    let now = buckyos_get_unix_timestamp();
    client.lock_document(
        ood1.clone(),
        DidDocType::Device,
        EncodedDocument::JsonLd(json!({"id": ood1.to_string(), "iat": now, "exp": now + 3600})),
        LockOptions::default(),
    );
    let before = hits.load(Ordering::SeqCst);
    assert!(resolve(&client, &ood1).await.locked);
    assert_eq!(hits.load(Ordering::SeqCst), before);

    // 名单整体替换：清空后恢复询问 Zone locker。
    client.unlock_document(&ood1, DidDocType::Device);
    client.set_zone_locker_bypass(Vec::new());
    assert!(!client.is_zone_locker_bypassed(&ood1));
    resolve(&client, &ood1).await;
    assert!(hits.load(Ordering::SeqCst) > before);
}
