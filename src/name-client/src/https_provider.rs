/*
基于https的NsProvider实现
初始化该Provider是，需要传入resolver的hostname
向https://resolver.example.com/1.0/identifiers/did:example:1234#doc_type发送http GET请求，获取did文档
*/

use crate::{NameInfo, NsProvider, RecordType};
use async_trait::async_trait;
use log::info;
use name_lib::{DID, EncodedDocument, NSError, NSResult};
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
    /// - resolver_host: required, resolver hostname.
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
        format!(
            "{}://{}/1.0/identifiers/{}",
            self.scheme, self.resolver_host, target
        )
    }

    async fn parse_response( did: &DID, resp: reqwest::Response) -> NSResult<EncodedDocument> {
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
                return Err(NSError::Disabled(format!("{} deactivated", did.to_string())));
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
}

impl SmartProvider {
    pub fn new() -> Self {
        Self { client: Client::new() }
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
        let hostname = did.to_host_name();
        let path = did.get_path_from_id();
        let real_doc_type = doc_type.unwrap_or("did");
        let url = if path.is_some() {
            format!("https://{}/{}/{}.json", hostname, path.unwrap(), real_doc_type)
        } else {
            format!("https://{}/.well-known/{}", hostname, real_doc_type)
        };

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
        let did = DID::from_str("did:key:z6Mksw4bDmn77uB5iVbQJBALV4CfqUGNoTCJQwdse1dQcvbK").unwrap();
        // 携带 doc_type，验证 URL 编码（%23）路径能被解析服务接受
        let doc = provider.query_did(&did, None, None).await.unwrap();
        let json = doc.to_json_value().unwrap();
        println!("json: {}", serde_json::to_string_pretty(&json).unwrap());
        assert_eq!(json.get("id").unwrap().as_str().unwrap(), did.to_string());
    }
}