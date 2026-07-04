/*
基于https的NsProvider实现
初始化该Provider是，需要传入resolver的hostname
向https://resolver.example.com/1.0/identifiers/did:example:1234#doc_type发送http GET请求，获取did文档
*/

use crate::{
    DidDocType, DocumentRef, DocumentStatus, NameInfo, NsProvider, PublishedState, RecordType,
};
use async_trait::async_trait;
use log::info;
use name_lib::{EncodedDocument, NSError, NSResult, DID};
use reqwest::{Client, StatusCode};
use serde::Deserialize;
use serde_json::Value;
use std::net::IpAddr;

/// Resolve DID documents through an HTTPS resolver endpoint.
pub struct BaseHttpProvider {
    resolver_host: String,
    client: Client,
    scheme: String,
}

impl BaseHttpProvider {
    /// Create a provider with default https scheme.
    pub fn new(resolver_host: &str) -> Self {
        Self {
            resolver_host: resolver_host.to_string(),
            client: Client::new(),
            scheme: "https".to_string(),
        }
    }

    /// Create with config json. Expected keys:
    /// - resolver_host: required, resolver hostname or http(s) base URL.
    /// - scheme: optional, defaults to https.
    pub fn new_with_config(config: Value) -> NSResult<Self> {
        let resolver_host = config
            .get("resolver_host")
            .and_then(|v| v.as_str())
            .ok_or_else(|| NSError::InvalidParam("resolver_host is required".to_string()))?;
        let scheme = config
            .get("scheme")
            .and_then(|v| v.as_str())
            .unwrap_or("https");

        Ok(Self {
            resolver_host: resolver_host.to_string(),
            client: Client::new(),
            scheme: scheme.to_string(),
        })
    }

    fn build_url(&self, did: &DID, doc_type: Option<&DidDocType>) -> String {
        // Encode doc_type as %23doc_type so the resolver can receive it.
        let target = if let Some(doc_type) = doc_type {
            format!("{}?type={}", did.to_string(), doc_type.as_str())
        } else {
            did.to_string()
        };
        let resolver_base = self.resolver_base_url();
        format!("{}/1.0/identifiers/{}", resolver_base, target)
    }

    fn resolver_base_url(&self) -> String {
        let resolver_host = self.resolver_host.trim().trim_end_matches('/');
        let lower = resolver_host.to_ascii_lowercase();

        if lower.starts_with("http://") || lower.starts_with("https://") {
            resolver_host.to_string()
        } else {
            format!("{}://{}", self.scheme, resolver_host)
        }
    }

    /// method-agnostic 的 HTTP DID 响应归一:状态码映射(404/403/410)、
    /// resolver 信封拆包、JsonLd/Jwt 识别。各 method 的 provider
    /// (如 WebProvider)统一复用,不各自实现。
    pub(crate) async fn parse_response(
        did: &DID,
        resp: reqwest::Response,
    ) -> NSResult<EncodedDocument> {
        let status = resp.status();
        let body = resp
            .text()
            .await
            .map_err(|e| NSError::Failed(format!("read resolver response failed: {}", e)))?;
        Self::parse_response_body(did, status, &body)
    }

    /// 拆成纯函数（接收已经读出来的 status/body）方便直接用字面量测试，
    /// 与 `parse_published_state_body` 同一套路。
    pub(crate) fn parse_response_body(
        did: &DID,
        status: StatusCode,
        body: &str,
    ) -> NSResult<EncodedDocument> {
        if !status.is_success() {
            return match status {
                StatusCode::NOT_FOUND => Err(NSError::NotFound(did.to_string())),
                StatusCode::FORBIDDEN => Err(NSError::Forbid),
                StatusCode::GONE => Err(NSError::Disabled(format!("{} disabled", did.to_string()))),
                _ => Err(NSError::Failed(format!(
                    "https provider returned {}: {}",
                    status, body
                ))),
            };
        }

        if let Ok(value) = serde_json::from_str::<Value>(body) {
            if value
                .get("didDocumentMetadata")
                .and_then(|meta| meta.get("deactivated"))
                .and_then(|v| v.as_bool())
                == Some(true)
            {
                return Err(NSError::Disabled(format!(
                    "{} deactivated",
                    did.to_string()
                )));
            }

            let doc_value = value
                .get("didDocument")
                .cloned()
                .unwrap_or_else(|| value.clone());
            // 信封里的 JWT 文档以字符串形态出现在 didDocument（zone resolver 对
            // boot/device 这类 owner-signed JWT 文档同样返回 resolution 信封），
            // 包成 JsonLd(Value::String) 会让下游 XxxDocument::decode 全部失败。
            return match doc_value {
                Value::String(jwt) => Ok(EncodedDocument::Jwt(jwt)),
                other => Ok(EncodedDocument::JsonLd(other)),
            };
        }

        EncodedDocument::from_str(body.to_string())
            .map_err(|e| NSError::Failed(format!("parse resolver response failed: {}", e)))
    }

    /// 解析 `resolve_published_state` 的 HTTP 响应。协议见 `doc/http_did_resolver_api.md`：
    /// method-agnostic，任何 did:method 的 HTTP resolver 只要按这份信封应答，都能走这里，
    /// 状态机语义的复杂度在 resolver 那一侧，这里只是老老实实解析一个通用 JSON 信封。
    ///
    /// 拆成纯函数（接收已经读出来的 status/body，而不是 `reqwest::Response`）方便直接用字面量
    /// 状态码和 JSON 字符串写单测，不需要真的发 HTTP 请求。
    fn parse_published_state_body(
        did: &DID,
        doc_type: &DidDocType,
        status: StatusCode,
        body: &str,
    ) -> NSResult<Option<PublishedState>> {
        // doc/http_did_resolver_api.md 第 5 节：只有 200/404/410 是这份协议定义的合法状态码，
        // 其它一律当作 transport error，绝不能被误判成 Missing/Revoked 之类的负状态。
        if status != StatusCode::OK && status != StatusCode::NOT_FOUND && status != StatusCode::GONE
        {
            return Err(NSError::Failed(format!(
                "resolver returned unexpected status {} for {}#{}: {}",
                status,
                did.to_string(),
                doc_type,
                body
            )));
        }

        let response = match serde_json::from_str::<DidResolutionResponseWire>(body) {
            Ok(response) => response,
            Err(err) => {
                // 裸 404（没有可解析的 body）视为"这个 resolver 对这个 (did, doc_type) 没有
                // 意见"，不是负状态；200/410 缺了 body 说明响应本身有问题，是真错误。
                if status == StatusCode::NOT_FOUND {
                    return Ok(None);
                }
                return Err(NSError::Failed(format!(
                    "malformed resolver response for {}#{}: {}",
                    did.to_string(),
                    doc_type,
                    err
                )));
            }
        };

        Self::published_state_from_wire(did, doc_type, response)
    }

    fn published_state_from_wire(
        did: &DID,
        doc_type: &DidDocType,
        response: DidResolutionResponseWire,
    ) -> NSResult<Option<PublishedState>> {
        let Some(metadata) = response.did_document_metadata else {
            return Ok(None);
        };
        let Some(buckyos) = metadata.buckyos else {
            return Ok(None);
        };
        let Some(status_str) = buckyos.document_status.as_deref() else {
            // 没有 documentStatus：这个 resolver 明确表示对这个 (did, doc_type) 没有意见
            // （NotApplicable），不是负状态。
            return Ok(None);
        };

        let document_status = match status_str {
            "active" => DocumentStatus::Active,
            "expired" => DocumentStatus::Expired,
            "missing" => DocumentStatus::Missing,
            "revoked" => DocumentStatus::Revoked,
            "tombstoned" => DocumentStatus::Tombstoned,
            "migrated" => DocumentStatus::Migrated,
            other => {
                return Err(NSError::Failed(format!(
                    "unknown documentStatus \"{}\" for {}#{}",
                    other,
                    did.to_string(),
                    doc_type
                )))
            }
        };

        let effective_owner = parse_optional_did(buckyos.effective_owner.as_deref())?;
        let migration_target = parse_optional_did(buckyos.migration_target.as_deref())?;

        let document_ref = response.did_document.map(|value| {
            let document = match value {
                Value::String(jwt) => EncodedDocument::Jwt(jwt),
                other => EncodedDocument::JsonLd(other),
            };
            let mut doc_ref = DocumentRef::inline(document);
            doc_ref.content_hash = buckyos.doc_hash.clone();
            doc_ref
        });
        // 只有锚点没有 body 的回答:doc_hash 单独成为 DocumentRef。
        let document_ref = document_ref.or_else(|| {
            buckyos.doc_hash.as_ref().map(|hash| DocumentRef {
                uri: None,
                content_hash: Some(hash.clone()),
                inline_document: None,
            })
        });

        let document_version = buckyos
            .document_version
            .or_else(|| metadata.version_id.as_deref().and_then(|v| v.parse().ok()));

        Ok(Some(PublishedState {
            did: did.clone(),
            doc_type: buckyos.doc_type.unwrap_or_else(|| doc_type.to_string()),
            document_status,
            document_ref,
            document_version,
            effective_owner,
            authority_seq: buckyos.authority_seq,
            migration_target,
        }))
    }
}

fn parse_optional_did(value: Option<&str>) -> NSResult<Option<DID>> {
    value.map(DID::from_str).transpose()
}

/// `doc/http_did_resolver_api.md` 第 3 节描述的响应信封，method-agnostic：任何 did:method 的
/// HTTP resolver 都应该按这个形状应答。
#[derive(Debug, Deserialize)]
struct DidResolutionResponseWire {
    #[serde(rename = "didDocument", default)]
    did_document: Option<Value>,
    #[serde(rename = "didDocumentMetadata", default)]
    did_document_metadata: Option<DidDocumentMetadataWire>,
}

#[derive(Debug, Deserialize)]
struct DidDocumentMetadataWire {
    #[serde(rename = "versionId", default)]
    version_id: Option<String>,
    #[serde(default)]
    buckyos: Option<BuckyosMetadataWire>,
}

#[derive(Debug, Deserialize)]
struct BuckyosMetadataWire {
    #[serde(rename = "docType", default)]
    doc_type: Option<String>,
    #[serde(rename = "documentStatus", default)]
    document_status: Option<String>,
    #[serde(rename = "documentVersion", default)]
    document_version: Option<u64>,
    #[serde(rename = "authoritySeq", default)]
    authority_seq: Option<u64>,
    #[serde(rename = "effectiveOwner", default)]
    effective_owner: Option<String>,
    #[serde(rename = "docHash", default)]
    doc_hash: Option<String>,
    #[serde(rename = "migrationTarget", default)]
    migration_target: Option<String>,
}

#[async_trait]
impl NsProvider for BaseHttpProvider {
    fn get_id(&self) -> String {
        format!("https-resolver:{}", self.resolver_host)
    }

    async fn query(
        &self,
        _name: &str,
        _record_type: Option<RecordType>,
        _from_ip: Option<IpAddr>,
    ) -> NSResult<NameInfo> {
        Err(NSError::NotFound(
            "https provider does not resolve dns records".to_string(),
        ))
    }

    async fn query_did(
        &self,
        did: &DID,
        doc_type: Option<DidDocType>,
        _from_ip: Option<IpAddr>,
    ) -> NSResult<EncodedDocument> {
        let url = self.build_url(did, doc_type.as_ref());
        debug!("https provider querying {}", url);
        let resp = self
            .client
            .get(url.clone())
            .send()
            .await
            .map_err(|e| NSError::Failed(format!("request {} failed: {}", url, e)))?;
        BaseHttpProvider::parse_response(did, resp).await
    }

    async fn resolve_published_state(
        &self,
        did: &DID,
        doc_type: &DidDocType,
    ) -> NSResult<Option<PublishedState>> {
        let url = self.build_url(did, Some(doc_type));
        info!("https provider querying published state {}", url);
        let resp = self
            .client
            .get(url.clone())
            .send()
            .await
            .map_err(|e| NSError::Failed(format!("request {} failed: {}", url, e)))?;
        let status = resp.status();
        let body = resp
            .text()
            .await
            .map_err(|e| NSError::Failed(format!("read resolver response failed: {}", e)))?;
        Self::parse_published_state_body(did, doc_type, status, &body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use name_lib::DID;

    // ------------------------ query_did 响应解析 ------------------------

    #[test]
    fn parse_response_body_unwraps_envelope_documents_by_shape() {
        let did = DID::from_str("did:web:ood1.example.com").unwrap();

        // 信封里的 JSON 文档
        let body = serde_json::json!({
            "didDocument": {"marker": "doc"},
            "didDocumentMetadata": {"buckyos": {"documentStatus": "active"}}
        })
        .to_string();
        let doc = BaseHttpProvider::parse_response_body(&did, StatusCode::OK, &body).unwrap();
        assert_eq!(
            doc,
            EncodedDocument::JsonLd(serde_json::json!({"marker": "doc"}))
        );

        // 信封里的 JWT 文档（字符串形态）必须还原成 Jwt，而不是 JsonLd(String)
        let body = serde_json::json!({
            "didDocument": "header.payload.sig",
            "didDocumentMetadata": {"buckyos": {"documentStatus": "active"}}
        })
        .to_string();
        let doc = BaseHttpProvider::parse_response_body(&did, StatusCode::OK, &body).unwrap();
        assert_eq!(doc, EncodedDocument::Jwt("header.payload.sig".to_string()));

        // 裸 JWT body（静态发布面 / 旧形态）仍然可解析
        let doc =
            BaseHttpProvider::parse_response_body(&did, StatusCode::OK, "header.payload.sig")
                .unwrap();
        assert_eq!(doc, EncodedDocument::Jwt("header.payload.sig".to_string()));

        // 裸 JSON 文档（无信封）整体即文档
        let doc = BaseHttpProvider::parse_response_body(&did, StatusCode::OK, r#"{"bare":1}"#)
            .unwrap();
        assert_eq!(doc, EncodedDocument::JsonLd(serde_json::json!({"bare": 1})));

        // deactivated 信封仍然拒绝
        let body = serde_json::json!({
            "didDocument": "a.b.c",
            "didDocumentMetadata": {"deactivated": true}
        })
        .to_string();
        assert!(matches!(
            BaseHttpProvider::parse_response_body(&did, StatusCode::OK, &body),
            Err(NSError::Disabled(_))
        ));
    }

    // ------------------------ resolve_published_state 信封解析 ------------------------
    // 按 doc/http_did_resolver_api.md 的信封直接构造字面量 status/body 测试纯解析函数，
    // 不需要真的发 HTTP 请求（也不需要像之前那样搭一套 mock transport trait）。

    #[test]
    fn active_state_maps_document_ref_and_owner() {
        let did = DID::from_str("did:bns:waterflier").unwrap();
        let body = serde_json::json!({
            "didDocument": {"marker": "active"},
            "didDocumentMetadata": {
                "versionId": "3",
                "buckyos": {
                    "docType": "zone",
                    "documentStatus": "active",
                    "documentVersion": 3,
                    "previousVersion": 2,
                    "authoritySeq": 9,
                    "lineageEpoch": 1,
                    "effectiveOwner": "did:bns:waterflier-owner",
                    "ownerSource": "methodAuthority",
                    "authorityRoot": "0xroot"
                }
            }
        })
        .to_string();

        let state = BaseHttpProvider::parse_published_state_body(
            &did,
            &DidDocType::Zone,
            StatusCode::OK,
            &body,
        )
        .unwrap()
        .unwrap();
        assert_eq!(state.document_status, DocumentStatus::Active);
        assert_eq!(state.document_version, Some(3));
        assert_eq!(
            state.effective_owner,
            Some(DID::new("bns", "waterflier-owner"))
        );
        assert_eq!(
            state.document_ref.unwrap().inline_document.unwrap(),
            EncodedDocument::JsonLd(serde_json::json!({"marker": "active"}))
        );
    }

    #[test]
    fn missing_revoked_tombstoned_and_migrated_map_to_terminal_states() {
        let did = DID::from_str("did:bns:waterflier").unwrap();

        let missing_body = serde_json::json!({
            "didDocumentMetadata": {"buckyos": {"documentStatus": "missing"}}
        })
        .to_string();
        let missing = BaseHttpProvider::parse_published_state_body(
            &did,
            &DidDocType::Zone,
            StatusCode::NOT_FOUND,
            &missing_body,
        )
        .unwrap()
        .unwrap();
        assert_eq!(missing.document_status, DocumentStatus::Missing);

        let revoked_body = serde_json::json!({
            "didDocumentMetadata": {"buckyos": {"documentStatus": "revoked"}}
        })
        .to_string();
        let revoked = BaseHttpProvider::parse_published_state_body(
            &did,
            &DidDocType::Zone,
            StatusCode::GONE,
            &revoked_body,
        )
        .unwrap()
        .unwrap();
        assert_eq!(revoked.document_status, DocumentStatus::Revoked);

        let tombstoned_body = serde_json::json!({
            "didDocumentMetadata": {"buckyos": {"documentStatus": "tombstoned"}}
        })
        .to_string();
        let tombstoned = BaseHttpProvider::parse_published_state_body(
            &did,
            &DidDocType::Zone,
            StatusCode::GONE,
            &tombstoned_body,
        )
        .unwrap()
        .unwrap();
        assert_eq!(tombstoned.document_status, DocumentStatus::Tombstoned);

        let migrated_body = serde_json::json!({
            "didDocumentMetadata": {
                "buckyos": {"documentStatus": "migrated", "migrationTarget": "did:bns:waterflier-v2"}
            }
        })
        .to_string();
        let migrated = BaseHttpProvider::parse_published_state_body(
            &did,
            &DidDocType::Zone,
            StatusCode::OK,
            &migrated_body,
        )
        .unwrap()
        .unwrap();
        assert_eq!(migrated.document_status, DocumentStatus::Migrated);
        assert_eq!(
            migrated.migration_target,
            Some(DID::new("bns", "waterflier-v2"))
        );
    }

    #[test]
    fn expired_state_maps_and_preserves_version() {
        let did = DID::from_str("did:bns:waterflier").unwrap();
        let body = serde_json::json!({
            "didDocumentMetadata": {"buckyos": {"documentStatus": "expired", "documentVersion": 5}}
        })
        .to_string();

        let state = BaseHttpProvider::parse_published_state_body(
            &did,
            &DidDocType::Zone,
            StatusCode::OK,
            &body,
        )
        .unwrap()
        .unwrap();
        assert_eq!(state.document_status, DocumentStatus::Expired);
        assert_eq!(state.document_version, Some(5));
    }

    #[test]
    fn bare_404_without_buckyos_extension_is_not_applicable() {
        // 第三方 did:web / did:key resolver（identity.foundation、uniresolver.io 等）根本不
        // 知道这个扩展，普通的 404（甚至没有 JSON body）必须被当成"不适用"，而不是报错。
        let did = DID::from_str("did:web:example.com").unwrap();
        let state = BaseHttpProvider::parse_published_state_body(
            &did,
            &DidDocType::Zone,
            StatusCode::NOT_FOUND,
            "",
        )
        .unwrap();
        assert!(state.is_none());
    }

    #[test]
    fn response_without_buckyos_extension_is_not_applicable() {
        // 200 但响应体里没有 buckyos 扩展块（比如一个不认识这份协议的普通 did:web host），
        // 同样是"不适用"，不是错误、也不是负状态。
        let did = DID::from_str("did:web:example.com").unwrap();
        let body = serde_json::json!({
            "didDocument": {"id": "did:web:example.com"},
            "didDocumentMetadata": {"deactivated": false}
        })
        .to_string();
        let state = BaseHttpProvider::parse_published_state_body(
            &did,
            &DidDocType::Zone,
            StatusCode::OK,
            &body,
        )
        .unwrap();
        assert!(state.is_none());
    }

    // T3.2: transport 错误（5xx/超时/连接失败）必须原样冒泡成 Err，不能被误判成
    // Missing/Revoked 之类的强负状态。
    #[test]
    fn unexpected_status_code_is_transport_error_not_negative_state() {
        let did = DID::from_str("did:bns:waterflier").unwrap();
        let err = BaseHttpProvider::parse_published_state_body(
            &did,
            &DidDocType::Zone,
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal error",
        )
        .unwrap_err();
        assert!(matches!(err, NSError::Failed(_)));
    }

    #[test]
    fn malformed_json_on_200_is_transport_error() {
        let did = DID::from_str("did:bns:waterflier").unwrap();
        let err = BaseHttpProvider::parse_published_state_body(
            &did,
            &DidDocType::Zone,
            StatusCode::OK,
            "not json at all",
        )
        .unwrap_err();
        assert!(matches!(err, NSError::Failed(_)));
    }

    #[test]
    fn build_url_uses_http_base_url_directly() {
        let provider = BaseHttpProvider::new("http://127.0.0.1:3200");
        let did = DID::from_str("did:bns:example").unwrap();

        assert_eq!(
            provider.build_url(&did, Some(&DidDocType::Owner)),
            "http://127.0.0.1:3200/1.0/identifiers/did:bns:example?type=owner"
        );
    }

    #[test]
    fn build_url_keeps_default_https_for_bare_host() {
        let provider = BaseHttpProvider::new("127.0.0.1:3200");
        let did = DID::from_str("did:bns:example").unwrap();

        assert_eq!(
            provider.build_url(&did, None),
            "https://127.0.0.1:3200/1.0/identifiers/did:bns:example"
        );
    }

    #[tokio::test]
    async fn resolve_did_via_identity_foundation() {
        let provider = BaseHttpProvider::new("resolver.identity.foundation");
        // 使用 resolver.identity.foundation 自身的 did:web 作为稳定样例
        let did = DID::from_str("did:web:identity.foundation").unwrap();

        match provider.query_did(&did, None, None).await {
            Ok(doc) => {
                let json = doc.to_json_value().unwrap();
                println!("json: {}", serde_json::to_string_pretty(&json).unwrap());
                assert_eq!(json.get("id").unwrap().as_str().unwrap(), did.to_string());
            }
            Err(NSError::NotFound(_)) => {
                // 公网解析器偶发 404，视为环境性问题，不阻断单测
                println!("skip: resolver returned NotFound for {}", did.to_string());
            }
            Err(e) => panic!("unexpected err: {:?}", e),
        }
    }

    #[tokio::test]
    async fn resolve_did_via_uniresolver() {
        let provider = BaseHttpProvider::new("uniresolver.io");
        // did:key 由密钥直接派生，uniresolver 官方示例，可稳定解析
        let did =
            DID::from_str("did:key:z6Mksw4bDmn77uB5iVbQJBALV4CfqUGNoTCJQwdse1dQcvbK").unwrap();
        // 携带 doc_type，验证 URL 编码（%23）路径能被解析服务接受
        let doc = provider.query_did(&did, None, None).await.unwrap();
        let json = doc.to_json_value().unwrap();
        println!("json: {}", serde_json::to_string_pretty(&json).unwrap());
        assert_eq!(json.get("id").unwrap().as_str().unwrap(), did.to_string());
    }
}
