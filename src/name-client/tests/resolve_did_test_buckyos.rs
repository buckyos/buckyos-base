use name_client::{
    CacheBackend, CacheStatus, DidDocType, DnsProvider, NameClient, NameClientConfig, ResolvePolicy,
};
use name_lib::{DIDDocumentTrait, EncodedDocument, ZoneBootDocument, ZoneDocument, DID};

#[tokio::test]
async fn resolve_did_test_buckyos_io_returns_boot_and_zone_with_gateway_mini_doc() {
    let client = NameClient::new(NameClientConfig {
        enable_cache: true,
        cache_backend: CacheBackend::Memory,
        ..Default::default()
    });
    client
        .set_method_authority("web", Box::new(DnsProvider::new(None)))
        .await;

    let did = DID::from_str("did:web:test.buckyos.io").unwrap();

    let boot_doc = client
        .resolve_did(&did, Some(DidDocType::Boot))
        .await
        .expect("did:web:test.buckyos.io should publish a boot document");
    let boot = ZoneBootDocument::decode(&boot_doc, None)
        .expect("boot response should decode as ZoneBootDocument");
    assert_eq!(boot.id.as_ref(), Some(&did));
    assert!(
        boot.device_is_gateway("ood1"),
        "boot document should identify ood1 as a gateway"
    );

    let zone_doc = client
        .resolve_did(&did, Some(DidDocType::Zone))
        .await
        .expect("did:web:test.buckyos.io should resolve to a zone document");
    let zone =
        ZoneDocument::decode(&zone_doc, None).expect("zone response should decode as ZoneDocument");

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
}
