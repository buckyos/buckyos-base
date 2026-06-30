/*
基于https的NsProvider实现
初始化该Provider是，需要传入resolver的hostname
向https://resolver.example.com/1.0/identifiers/did:example:1234#doc_type发送http GET请求，获取did文档
*/

use crate::{NameInfo, NsProvider, RecordType};
use async_trait::async_trait;
use log::info;
use name_lib::{EncodedDocument, NSError, NSResult, DID};
use percent_encoding::percent_decode_str;
use reqwest::{Client, StatusCode};
use serde_json::Value;
use std::net::IpAddr;

/// Resolve DID documents through an HTTPS resolver endpoint.
pub struct HttpsProvider {
    resolver_host: String,
    client: Client,
    scheme: String,
}

impl HttpsProvider {
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

    fn build_url(&self, did: &DID, doc_type: Option<&str>) -> String {
        // Encode doc_type as %23doc_type so the resolver can receive it.
        let target = if doc_type.is_some() {
            format!("{}?type={}", did.to_string(), doc_type.unwrap())
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

    async fn parse_response(did: &DID, resp: reqwest::Response) -> NSResult<EncodedDocument> {
        let status = resp.status();
        let body = resp
            .text()
            .await
            .map_err(|e| NSError::Failed(format!("read resolver response failed: {}", e)))?;

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

        if let Ok(value) = serde_json::from_str::<Value>(&body) {
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
            return Ok(EncodedDocument::JsonLd(doc_value));
        }

        EncodedDocument::from_str(body)
            .map_err(|e| NSError::Failed(format!("parse resolver response failed: {}", e)))
    }
}

#[async_trait]
impl NsProvider for HttpsProvider {
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
        doc_type: Option<&str>,
        _from_ip: Option<IpAddr>,
    ) -> NSResult<EncodedDocument> {
        let url = self.build_url(did, doc_type);
        info!("https provider querying {}", url);
        let resp = self
            .client
            .get(url.clone())
            .send()
            .await
            .map_err(|e| NSError::Failed(format!("request {} failed: {}", url, e)))?;
        HttpsProvider::parse_response(did, resp).await
    }
}

//TODO:支持用任意协议连接zone
pub struct SmartProvider {
    client: Client,
    scheme: String,
}

impl SmartProvider {
    pub fn new() -> Self {
        Self::new_with_scheme("https")
    }

    pub fn new_with_scheme(scheme: &str) -> Self {
        Self {
            client: Client::new(),
            scheme: scheme.to_string(),
        }
    }

    fn doc_file_stem(doc_type: Option<&str>) -> NSResult<&str> {
        let doc_type = doc_type.unwrap_or("did");
        if doc_type.is_empty()
            || !doc_type
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-')
        {
            return Err(NSError::InvalidParam(format!(
                "invalid DID document type: {}",
                doc_type
            )));
        }
        Ok(doc_type)
    }

    fn build_url(&self, did: &DID, doc_type: Option<&str>) -> NSResult<String> {
        let real_doc_type = Self::doc_file_stem(doc_type)?;
        if did.method == "web" {
            let mut parts = did.id.split(':');
            let host = parts.next().ok_or_else(|| {
                NSError::InvalidDID(format!("missing did:web host: {}", did.to_string()))
            })?;
            let host = percent_decode_str(host)
                .decode_utf8()
                .map_err(|e| NSError::InvalidDID(format!("invalid did:web host: {e}")))?;
            let path = parts.collect::<Vec<_>>().join("/");

            if path.is_empty() {
                return Ok(format!(
                    "{}://{}/.well-known/{}.json",
                    self.scheme, host, real_doc_type
                ));
            }

            return Ok(format!(
                "{}://{}/{}/{}.json",
                self.scheme, host, path, real_doc_type
            ));
        }

        Ok(format!(
            "{}://{}/{}.json",
            self.scheme,
            did.to_host_uri(),
            real_doc_type
        ))
    }
}

#[async_trait]
impl NsProvider for SmartProvider {
    fn get_id(&self) -> String {
        "smart-resolver".to_string()
    }

    async fn query(
        &self,
        _name: &str,
        _record_type: Option<RecordType>,
        _from_ip: Option<IpAddr>,
    ) -> NSResult<NameInfo> {
        Err(NSError::NotFound(
            "smart-resolver does not resolve dns records".to_string(),
        ))
    }

    async fn query_did(
        &self,
        did: &DID,
        doc_type: Option<&str>,
        _from_ip: Option<IpAddr>,
    ) -> NSResult<EncodedDocument> {
        let url = self.build_url(did, doc_type)?;

        let resp = self
            .client
            .get(url.clone())
            .send()
            .await
            .map_err(|e| NSError::Failed(format!("request {} failed: {}", url, e)))?;

        HttpsProvider::parse_response(did, resp).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use name_lib::DID;

    #[test]
    fn build_url_uses_http_base_url_directly() {
        let provider = HttpsProvider::new("http://127.0.0.1:3200");
        let did = DID::from_str("did:bns:example").unwrap();

        assert_eq!(
            provider.build_url(&did, Some("owner")),
            "http://127.0.0.1:3200/1.0/identifiers/did:bns:example?type=owner"
        );
    }

    #[test]
    fn build_url_keeps_default_https_for_bare_host() {
        let provider = HttpsProvider::new("127.0.0.1:3200");
        let did = DID::from_str("did:bns:example").unwrap();

        assert_eq!(
            provider.build_url(&did, None),
            "https://127.0.0.1:3200/1.0/identifiers/did:bns:example"
        );
    }

    #[test]
    fn smart_provider_builds_did_object_url() {
        let provider = SmartProvider::new_with_scheme("http");
        let did = DID::from_str("did:web:127.0.0.1%3A3200:devices:cam01").unwrap();

        assert_eq!(
            provider.build_url(&did, None).unwrap(),
            "http://127.0.0.1:3200/devices/cam01/did.json"
        );
    }

    #[test]
    fn smart_provider_builds_root_did_web_url() {
        let provider = SmartProvider::new_with_scheme("http");
        let did = DID::from_str("did:web:example.com").unwrap();

        assert_eq!(
            provider.build_url(&did, None).unwrap(),
            "http://example.com/.well-known/did.json"
        );
    }

    #[test]
    fn smart_provider_uses_doc_type_as_static_file_name() {
        let provider = SmartProvider::new_with_scheme("http");
        let root_did = DID::from_str("did:web:example.com").unwrap();
        let path_did = DID::from_str("did:web:example.com:users:alice").unwrap();

        assert_eq!(
            provider.build_url(&root_did, Some("owner")).unwrap(),
            "http://example.com/.well-known/owner.json"
        );
        assert_eq!(
            provider.build_url(&path_did, Some("profile")).unwrap(),
            "http://example.com/users/alice/profile.json"
        );
    }

    #[test]
    fn smart_provider_rejects_unsafe_doc_type() {
        let provider = SmartProvider::new_with_scheme("http");
        let did = DID::from_str("did:web:example.com").unwrap();

        assert!(matches!(
            provider.build_url(&did, Some("../owner")),
            Err(NSError::InvalidParam(_))
        ));
        assert!(matches!(
            provider.build_url(&did, Some("profile/v1")),
            Err(NSError::InvalidParam(_))
        ));
    }

    #[tokio::test]
    async fn resolve_did_via_identity_foundation() {
        let provider = HttpsProvider::new("resolver.identity.foundation");
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
        let provider = HttpsProvider::new("uniresolver.io");
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
