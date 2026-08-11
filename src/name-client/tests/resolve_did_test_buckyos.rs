use name_client::{
    CacheBackend, CacheStatus, DidDocType, DnsProvider, NameClient, NameClientConfig, ResolvePolicy,
};
use name_lib::{DIDDocumentTrait, EncodedDocument, ZoneBootDocument, ZoneDocument, DID};

async fn dns_test_client() -> NameClient {
    let client = NameClient::new(NameClientConfig {
        enable_cache: true,
        cache_backend: CacheBackend::Memory,
        // 单机 DNS 解析语义测试:关闭 Zone Resolver,避免命中开发机上真实
        // 运行的 127.0.0.1:3180 服务。
        enable_zone_resolver: false,
        ..Default::default()
    });
    client
        .set_method_authority("web", Box::new(DnsProvider::new(None)))
        .await;
    client
}

#[tokio::test]
async fn resolve_did_test_buckyos_io_returns_boot_and_zone_with_gateway_mini_doc() {
    let client = dns_test_client().await;
    let did = DID::from_str("did:web:test.buckyos.io").unwrap();

    let boot_doc = client
        .resolve_did_ex(&did, Some(DidDocType::Boot), ResolvePolicy::default())
        .await
        .expect("did:web:test.buckyos.io should publish a boot document");
    let boot = ZoneBootDocument::decode(&boot_doc.document, None)
        .expect("boot response should decode as ZoneBootDocument");
    assert_eq!(boot.id.as_ref(), Some(&did));
    assert!(
        boot.device_is_gateway("ood1"),
        "boot document should identify ood1 as a gateway"
    );

    let resolved_zone = client
        .resolve_did_ex(&did, Some(DidDocType::Zone), ResolvePolicy::default())
        .await
        .expect("did:web:test.buckyos.io should resolve to a zone document");
    assert_eq!(
        resolved_zone.resolution_metadata.cache_status,
        Some(CacheStatus::Hit),
        "resolving boot should populate the sibling zone document in cache"
    );
    let zone = ZoneDocument::decode(&resolved_zone.document, None)
        .expect("zone response should decode as ZoneDocument");

    assert_eq!(zone.id, did);
    assert_eq!(zone.get_default_zone_gateway().as_deref(), Some("ood1"));

    let gateway_mini_doc_jwt = zone
        .mini_device_jwts
        .get("ood1")
        .expect("zone document should include the gateway mini doc JWT");
    let gateway_device = zone
        .get_device_document("ood1")
        .expect("zone document should include the gateway device document");

    assert_eq!(gateway_device.name, "ood1");
    assert_eq!(gateway_device.zone_did.as_ref(), Some(&did));
    assert_eq!(gateway_device.owner, did);
    assert_eq!(
        gateway_device.device_mini_document_jwt.as_deref(),
        Some(gateway_mini_doc_jwt.as_str()),
        "gateway device document should preserve the same mini doc JWT published in the zone"
    );

    let gateway_did = DID::from_str("did:web:ood1.test.buckyos.io").unwrap();
    let resolved_gateway = client
        .resolve_did_ex(&gateway_did, None, ResolvePolicy::default())
        .await
        .expect("gateway device should be available from the DID cache after resolving the zone");

    assert_eq!(
        resolved_gateway.resolution_metadata.cache_status,
        Some(CacheStatus::Hit),
        "resolving the gateway child DID should hit the cache populated from DNS zone TXT records"
    );
    assert_eq!(
        resolved_gateway.document,
        EncodedDocument::JsonLd(serde_json::to_value(gateway_device).unwrap())
    );

    let reverse_client = dns_test_client().await;
    let resolved_zone_first = reverse_client
        .resolve_did_ex(&did, Some(DidDocType::Zone), ResolvePolicy::default())
        .await
        .expect("zone document should resolve first");
    assert_eq!(
        resolved_zone_first.resolution_metadata.cache_status,
        Some(CacheStatus::Miss)
    );

    let resolved_boot_after_zone = reverse_client
        .resolve_did_ex(&did, Some(DidDocType::Boot), ResolvePolicy::default())
        .await
        .expect("boot document should be cached after resolving zone");
    assert_eq!(
        resolved_boot_after_zone.resolution_metadata.cache_status,
        Some(CacheStatus::Hit),
        "resolving zone should populate the sibling boot document in cache"
    );
}
