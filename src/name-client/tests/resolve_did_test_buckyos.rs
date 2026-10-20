//! 真实 DNS 的端到端用例(test.buckyos.io 的 TXT 记录),需要网络。
use name_client::{DidDocType, DnsProvider, NameClient, NameClientConfig, Revision};
use name_lib::{DIDDocumentTrait, EncodedDocument, ZoneBootDocument, ZoneDocument, DID};
use std::sync::Arc;

fn dns_test_client() -> NameClient {
    let client = NameClient::new(NameClientConfig::for_test());
    client.set_method_authority("web", Arc::new(DnsProvider::new(None)));
    client
}

#[tokio::test]
#[ignore = "needs network access to test.buckyos.io"]
async fn resolve_did_test_buckyos_io_returns_boot_and_zone_with_gateway_mini_doc() {
    let client = dns_test_client();
    let did = DID::from_str("did:web:test.buckyos.io").unwrap();
    let opts = client.default_resolve_opts();

    let boot = client
        .resolve_did_ex(&did, Some(DidDocType::Boot), Revision::current(), opts.clone())
        .await
        .expect("resolve boot must not terminate");
    let boot_doc = boot
        .select_document(&Revision::current())
        .expect("did:web:test.buckyos.io should publish a boot document");
    let boot = ZoneBootDocument::decode(&boot_doc, None)
        .expect("boot response should decode as ZoneBootDocument");
    assert_eq!(boot.id.as_ref(), Some(&did));
    assert!(boot.device_is_gateway("ood1"));

    let zone = client
        .resolve_did_ex(&did, Some(DidDocType::Zone), Revision::current(), opts.clone())
        .await
        .unwrap();
    let zone_doc = zone
        .select_document(&Revision::current())
        .expect("did:web:test.buckyos.io should resolve to a zone document");
    let zone = ZoneDocument::decode(&zone_doc, None).unwrap();
    assert_eq!(zone.id, did);
    assert_eq!(zone.get_default_zone_gateway().as_deref(), Some("ood1"));
    let gateway_mini_doc_jwt = zone.mini_device_jwts.get("ood1").unwrap();
    let gateway_device = zone.get_device_document("ood1").unwrap();
    assert_eq!(gateway_device.name, "ood1");
    assert_eq!(gateway_device.zone_did.as_ref(), Some(&did));
    assert_eq!(gateway_device.owner, did);
    assert_eq!(
        gateway_device.device_mini_document_jwt.as_deref(),
        Some(gateway_mini_doc_jwt.as_str())
    );

    // 子设备文档来自 zone TXT 的 DEV 记录。
    let gateway_did = DID::from_str("did:web:ood1.test.buckyos.io").unwrap();
    let resolved_gateway = client
        .resolve_did_ex(&gateway_did, Some(DidDocType::Device), Revision::current(), opts)
        .await
        .unwrap();
    assert_eq!(
        resolved_gateway.select_document(&Revision::current()),
        Some(EncodedDocument::JsonLd(serde_json::to_value(gateway_device).unwrap()))
    );
}
