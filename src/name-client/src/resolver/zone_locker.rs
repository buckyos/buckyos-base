//! Zone locker 客户端(设计稿 §2.1、HTTP binding §9):zone-resolver-server 用同一套
//! `/1.0/identifiers/{did}` 信封回答(含版本查询,可在自己的 scope 内模拟发布)。
//! 它不是普通来源:Unknown / 未覆盖继续向后查,显式 missing / invalid / revoked 是
//! 强制回答;结果不写入普通来源缓存。请求附带剩余预算与防自选头。

use super::http_doc::{
    accept_header, build_http_client, document_answer_from_http, read_response, resolver_api_url,
    RESOLVE_BUDGET_HEADER, RESOLVE_NO_ZONE_LOCK_HEADER,
};
use super::opts::ResolveOpts;
use super::revision::Revision;
use super::source::{DefaultDocType, Source, SourceAnswer, SourceRef};
use async_trait::async_trait;
use log::debug;
use name_lib::{DidDocType, DID};
use reqwest::Client;
use std::time::Duration;

pub const DEFAULT_ZONE_LOCKER_ENDPOINT: &str = "http://127.0.0.1:3180";

#[derive(Debug, Clone)]
pub struct ZoneLockerConfig {
    pub endpoint: String,
    pub connect_timeout: Duration,
    pub request_timeout: Duration,
}

impl Default for ZoneLockerConfig {
    fn default() -> Self {
        Self {
            endpoint: DEFAULT_ZONE_LOCKER_ENDPOINT.to_string(),
            connect_timeout: Duration::from_millis(500),
            request_timeout: Duration::from_secs(5),
        }
    }
}

pub struct ZoneLocker {
    config: ZoneLockerConfig,
    client: Client,
}

impl ZoneLocker {
    pub fn new(config: ZoneLockerConfig) -> Self {
        let client = build_http_client(config.connect_timeout);
        Self { config, client }
    }

    pub fn endpoint(&self) -> &str {
        &self.config.endpoint
    }

    pub fn source_ref(&self) -> SourceRef {
        SourceRef::zone_locker(self.id())
    }

    async fn query(
        &self,
        did: &DID,
        doc_type: &DidDocType,
        revision: &Revision,
        opts: &ResolveOpts,
    ) -> SourceAnswer {
        let sref = self.source_ref();
        let url = match resolver_api_url(&self.config.endpoint, did, Some(doc_type), revision) {
            Ok(url) => url,
            Err(err) => return SourceAnswer::unknown(sref, err.to_string(), false),
        };
        let budget = opts.budget();
        let timeout = budget.step_cap(self.config.request_timeout.min(opts.request_timeout));
        let (accept_name, accept_value) = accept_header();
        let request = self
            .client
            .get(url.clone())
            .header(accept_name, accept_value)
            .header(RESOLVE_BUDGET_HEADER, budget.remaining_ms().to_string())
            .header(RESOLVE_NO_ZONE_LOCK_HEADER, "1")
            .timeout(timeout);
        debug!("zone locker querying {}", url);
        let response = match budget.run(timeout, request.send()).await {
            Ok(Ok(response)) => response,
            Ok(Err(err)) => {
                return SourceAnswer::unknown(sref, format!("zone locker {} unreachable: {}", self.config.endpoint, err), false);
            }
            Err(err) => return SourceAnswer::unknown(sref, err.into_ns_error().to_string(), false),
        };
        let parts = match read_response(response, budget).await {
            Ok(parts) => parts,
            Err(err) => return SourceAnswer::unknown(sref, format!("zone locker read failed: {}", err), false),
        };
        let mut answer = document_answer_from_http(&parts, &sref, did, doc_type, revision, false);
        // locker 回答不进普通来源缓存。
        answer.cacheable = false;
        answer.failure = false;
        if let Some(info) = answer.publish_info.as_mut() {
            info.simulated = true;
            info.source = Some(sref.id.clone());
        }
        answer
    }
}

#[async_trait]
impl Source for ZoneLocker {
    fn id(&self) -> String {
        format!("zone-locker:{}", self.config.endpoint)
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
        self.query(did, doc_type, revision, opts).await
    }

    async fn default_doc_type(&self, _did: &DID, _opts: &ResolveOpts) -> Option<DefaultDocType> {
        None
    }
}
