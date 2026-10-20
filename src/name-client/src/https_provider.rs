//! HTTP resolver API 来源(`/1.0/identifiers/{did}?type=..[&versionId|&versionTime]`,
//! 协议见 doc/http_did_resolver_api.md)。method-agnostic:BNS 权威 resolver、SN 网关、
//! did:web 上级 resolver 都是它的实例;等级由注册位置决定。

use crate::resolver::{
    accept_header, document_answer_from_http, read_response, resolver_api_url, DefaultDocType,
    ParsedDocument, ResolveOpts, Revision, Source, SourceAnswer, SourceRef, SourceTier,
};
use async_trait::async_trait;
use log::debug;
use name_lib::{DidDocType, NSError, NSResult, DID};
use reqwest::Client;
use serde_json::Value;
use std::time::Duration;

/// 指向一个 HTTP DID resolver 的来源。
pub struct BaseHttpProvider {
    resolver_host: String,
    scheme: String,
    client: Client,
    id: String,
}

impl BaseHttpProvider {
    /// 默认 https;`resolver_host` 可以是 host 或完整 http(s) base URL。
    pub fn new(resolver_host: &str) -> Self {
        Self {
            resolver_host: resolver_host.trim().to_string(),
            scheme: "https".to_string(),
            client: crate::resolver::build_http_client(Duration::from_secs(5)),
            id: format!("http-provider:{}", resolver_host.trim().trim_end_matches('/')),
        }
    }

    /// config keys: `resolver_host`(必填)、`scheme`(可选,默认 https)。
    pub fn new_with_config(config: Value) -> NSResult<Self> {
        let resolver_host = config
            .get("resolver_host")
            .and_then(|v| v.as_str())
            .ok_or_else(|| NSError::InvalidParam("resolver_host is required".to_string()))?;
        let scheme = config
            .get("scheme")
            .and_then(|v| v.as_str())
            .unwrap_or("https");
        let mut provider = Self::new(resolver_host);
        provider.scheme = scheme.to_string();
        Ok(provider)
    }

    pub fn with_id(mut self, id: impl Into<String>) -> Self {
        self.id = id.into();
        self
    }

    pub fn resolver_host(&self) -> &str {
        &self.resolver_host
    }

    pub(crate) fn base_url(&self) -> String {
        let host = self.resolver_host.trim_end_matches('/');
        let lower = host.to_ascii_lowercase();
        if lower.starts_with("http://") || lower.starts_with("https://") {
            host.to_string()
        } else {
            format!("{}://{}", self.scheme, host)
        }
    }

    pub(crate) async fn fetch(
        &self,
        did: &DID,
        doc_type: Option<&DidDocType>,
        revision: &Revision,
        opts: &ResolveOpts,
    ) -> SourceAnswer {
        let sref = SourceRef::provider(self.id.clone(), SourceTier::Authority);
        let url = match resolver_api_url(&self.base_url(), did, doc_type, revision) {
            Ok(url) => url,
            Err(err) => return SourceAnswer::unknown(sref, err.to_string(), false),
        };
        let budget = opts.budget();
        let timeout = budget.step_cap(opts.request_timeout);
        let (accept_name, accept_value) = accept_header();
        debug!("http provider {} querying {}", self.id, url);
        let request = self
            .client
            .get(url.clone())
            .header(accept_name, accept_value)
            .timeout(timeout);
        let response = match budget.run(timeout, request.send()).await {
            Ok(Ok(response)) => response,
            Ok(Err(err)) => {
                return SourceAnswer::failure(sref, format!("request {} failed: {}", url, err));
            }
            Err(err) => return SourceAnswer::unknown(sref, err.into_ns_error().to_string(), false),
        };
        let parts = match read_response(response, budget).await {
            Ok(parts) => parts,
            Err(err) => return SourceAnswer::failure(sref, format!("read {} failed: {}", url, err)),
        };
        let requested = doc_type.cloned().unwrap_or_else(|| DidDocType::custom("*"));
        document_answer_from_http(&parts, &sref, did, &requested, revision, false)
    }
}

#[async_trait]
impl Source for BaseHttpProvider {
    fn id(&self) -> String {
        self.id.clone()
    }

    fn supports_publish_info(&self) -> bool {
        true
    }

    async fn get_document(
        &self,
        did: &DID,
        doc_type: &DidDocType,
        revision: &Revision,
        opts: &ResolveOpts,
    ) -> SourceAnswer {
        self.fetch(did, Some(doc_type), revision, opts).await
    }

    /// 不带 `type` 询问 resolver,由 `buckyos.docType` 或文档内容给出实际类型;
    /// `400 ambiguousDocType` 归一为 Ambiguous。
    async fn default_doc_type(&self, did: &DID, opts: &ResolveOpts) -> Option<DefaultDocType> {
        if did.id.contains(':') {
            return Some(DefaultDocType::Known {
                doc_type: DidDocType::DidObject,
                reasons: Vec::new(),
            });
        }
        let answer = self.fetch(did, None, &Revision::current(), opts).await;
        if let Some(reason) = answer.reason.as_ref() {
            if reason.contains("ambiguousDocType") {
                return Some(DefaultDocType::Ambiguous(reason.clone()));
            }
        }
        if let Some(info) = answer.publish_info.as_ref() {
            if !matches!(info.doc_type, DidDocType::Custom(ref c) if c == "*") {
                return Some(DefaultDocType::Known {
                    doc_type: info.doc_type.clone(),
                    reasons: Vec::new(),
                });
            }
        }
        if let Some(body) = answer.body.as_ref() {
            if let Ok(parsed) = ParsedDocument::parse(body) {
                if let Some(doc_type) = parsed.doc_type {
                    return Some(DefaultDocType::Known {
                        doc_type,
                        reasons: Vec::new(),
                    });
                }
            }
        }
        None
    }
}
