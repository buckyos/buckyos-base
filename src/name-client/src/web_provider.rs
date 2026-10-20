//! 静态发布面 / 对象 URL 来源(设计稿 §2.4):did:web 的域名发布面,以及 did:bns
//! 名字的规范 host 映射(`{name}.{bns_root}`)。
//!
//! 获取规则:
//! - 目录型(无对象子路径):`https://{host}/.well-known/did.json`(默认类型)或
//!   `/.well-known/{doc_type}.json`(显式类型,BuckyOS 扩展);
//! - 路径型对象(`did:web:example.com:user:alice`):直取 `https://example.com/user/alice`,
//!   默认逻辑类型 `did-object`,文档可在 body 或 `BuckyOS-DID-Document` 响应头中;
//!   显式非默认类型用 `?type=` 选择;已配置时再尝试兼容路由 `/{path}/did.json`;
//! - 上级名字(`DID::upper_did`)的 resolver API 作为同一发布渠道的第二信道
//!   (zone gateway 为 zone 内设备提供解析),也是 exact / closest 查询的唯一入口。
//!
//! did:bns 下本来源只能注册为 normal(权威是 BNS 合约 / 网关),did:web 下是 authority。

use crate::bns_provider::bns_web3_bridge_host;
use crate::resolver::{
    accept_header, build_document_request_url, document_answer_from_http, read_response,
    resolver_api_url, DefaultDocType, DocumentLocation, ParsedDocument, ResolveOpts, Revision,
    Source, SourceAnswer, SourceRef, SourceTier,
};
use async_trait::async_trait;
use buckyos_kit::buckyos_get_unix_timestamp;
use log::{debug, info};
use name_lib::{DidDocType, NSError, NSResult, DID};
use percent_encoding::percent_decode_str;
use reqwest::{Client, Url};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

const DEFAULT_TYPE_CACHE_SECS: u64 = 30;

pub struct WebProvider {
    client: Client,
    scheme: String,
    legacy_path_routes: bool,
    default_type_cache: Mutex<HashMap<DID, (DidDocType, u64)>>,
}

impl Default for WebProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl WebProvider {
    /// 规范要求线上必须 https。
    pub fn new() -> Self {
        Self::new_with_scheme("https")
    }

    /// 仅供本地 / 测试环境用 http 连接自建站点。
    pub fn new_with_scheme(scheme: &str) -> Self {
        Self {
            client: crate::resolver::build_http_client(Duration::from_secs(5)),
            scheme: scheme.to_string(),
            legacy_path_routes: true,
            default_type_cache: Mutex::new(HashMap::new()),
        }
    }

    /// 是否对路径型对象保留 `/{path}/did.json`、`/{path}/{doc_type}.json` 兼容路由。
    pub fn with_legacy_path_routes(mut self, enabled: bool) -> Self {
        self.legacy_path_routes = enabled;
        self
    }

    fn decode_host(did: &DID, raw_host: &str) -> NSResult<String> {
        let host = percent_decode_str(raw_host).decode_utf8().map_err(|e| {
            NSError::InvalidDID(format!("invalid did:web host in {}: {}", did.to_string(), e))
        })?;
        let (name, port) = match host.split_once(':') {
            Some((name, port)) => (name, Some(port)),
            None => (host.as_ref(), None),
        };
        let name_is_valid = !name.is_empty()
            && name
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '.' || ch == '-');
        let port_is_valid = match port {
            Some(port) => !port.is_empty() && port.parse::<u16>().is_ok(),
            None => true,
        };
        if !name_is_valid || !port_is_valid {
            return Err(NSError::InvalidDID(format!(
                "invalid did:web host: {}",
                did.to_string()
            )));
        }
        Ok(host.into_owned())
    }

    fn bns_canonical_host(did: &DID, raw_name: &str) -> NSResult<String> {
        let name_is_valid = !raw_name.is_empty()
            && raw_name
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '.' || ch == '-');
        if !name_is_valid {
            return Err(NSError::InvalidDID(format!(
                "invalid did:bns name: {}",
                did.to_string()
            )));
        }
        let bridge = bns_web3_bridge_host()?;
        Ok(format!("{}.{}", raw_name, bridge))
    }

    pub(crate) fn canonical_host(did: &DID, raw_name: &str) -> NSResult<String> {
        match did.method.as_str() {
            "web" => Self::decode_host(did, raw_name),
            "bns" => Self::bns_canonical_host(did, raw_name),
            other => Err(NSError::NotFound(format!(
                "unsupported did method: {}",
                other
            ))),
        }
    }

    fn validate_path_segment(did: &DID, segment: &str) -> NSResult<()> {
        let chars_ok = segment
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_' | '%'));
        if segment.is_empty() || segment == "." || segment == ".." || !chars_ok {
            return Err(NSError::InvalidDID(format!(
                "invalid did:web path segment \"{}\" in {}",
                segment,
                did.to_string()
            )));
        }
        Ok(())
    }

    /// 主入口位置(目录 well-known 或对象 URL)与可选兼容路由。
    pub(crate) fn locations_for(&self, did: &DID) -> NSResult<(DocumentLocation, Option<DocumentLocation>)> {
        let mut segments = did.id.split(':');
        let raw_host = segments.next().unwrap_or_default();
        let host = Self::canonical_host(did, raw_host)?;
        let path_segments: Vec<&str> = segments.collect();
        for segment in &path_segments {
            Self::validate_path_segment(did, segment)?;
        }
        if path_segments.is_empty() {
            let url = Url::parse(&format!("{}://{}/.well-known/", self.scheme, host))
                .map_err(|e| NSError::InvalidDID(format!("{}: {}", did.to_string(), e)))?;
            return Ok((DocumentLocation::directory(url, did.clone()), None));
        }
        let object = Url::parse(&format!(
            "{}://{}/{}",
            self.scheme,
            host,
            path_segments.join("/")
        ))
        .map_err(|e| NSError::InvalidDID(format!("{}: {}", did.to_string(), e)))?;
        let legacy = if self.legacy_path_routes {
            Some(DocumentLocation::legacy_static(object.clone(), did.clone()))
        } else {
            None
        };
        Ok((DocumentLocation::object(object, did.clone()), legacy))
    }

    /// 上级名字的 resolver API base(`{scheme}://{upper_host}`)。
    pub(crate) fn upper_resolver_base(&self, did: &DID) -> Option<String> {
        let upper = did.upper_did()?;
        let host = Self::canonical_host(&upper, &upper.id).ok()?;
        Some(format!("{}://{}", self.scheme, host))
    }

    fn source_ref(&self) -> SourceRef {
        SourceRef::provider(self.id(), SourceTier::Normal)
    }

    async fn fetch_url(
        &self,
        url: Url,
        did: &DID,
        doc_type: &DidDocType,
        revision: &Revision,
        opts: &ResolveOpts,
        allow_legacy_body: bool,
        want_envelope: bool,
    ) -> SourceAnswer {
        let sref = self.source_ref();
        let budget = opts.budget();
        let timeout = budget.step_cap(opts.request_timeout);
        debug!("web provider querying {}", url);
        let mut request = self.client.get(url.clone()).timeout(timeout);
        if want_envelope {
            let (name, value) = accept_header();
            request = request.header(name, value);
        }
        let response = match budget.run(timeout, request.send()).await {
            Ok(Ok(response)) => response,
            Ok(Err(err)) => return SourceAnswer::failure(sref, format!("request {} failed: {}", url, err)),
            Err(err) => return SourceAnswer::unknown(sref, err.into_ns_error().to_string(), false),
        };
        let parts = match read_response(response, budget).await {
            Ok(parts) => parts,
            Err(err) => return SourceAnswer::failure(sref, format!("read {} failed: {}", url, err)),
        };
        document_answer_from_http(&parts, &sref, did, doc_type, revision, allow_legacy_body)
    }

    async fn fetch_upper(
        &self,
        did: &DID,
        doc_type: &DidDocType,
        revision: &Revision,
        opts: &ResolveOpts,
    ) -> Option<SourceAnswer> {
        let base = self.upper_resolver_base(did)?;
        let url = resolver_api_url(&base, did, Some(doc_type), revision).ok()?;
        info!("web provider falling back to upper resolver {}", url);
        Some(self.fetch_url(url, did, doc_type, revision, opts, false, true).await)
    }

    fn answer_is_conclusive(answer: &SourceAnswer) -> bool {
        answer.body.is_some()
            || answer
                .publish_info
                .as_ref()
                .map_or(false, |info| info.is_disabled() || info.type_state.is_some())
    }
}

#[async_trait]
impl Source for WebProvider {
    fn id(&self) -> String {
        "web-provider".to_string()
    }

    /// 上级 resolver API 可回答版本查询;没有上级时在 `get_document` 内归一为不支持。
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
        let sref = self.source_ref();
        if did.method != "web" && did.method != "bns" {
            return SourceAnswer::unknown(sref, format!("unsupported did method: {}", did.method), false);
        }
        // exact / closest 只有 resolver API 能回答。
        if !revision.is_current() {
            return match self.fetch_upper(did, doc_type, revision, opts).await {
                Some(answer) => answer,
                None => {
                    let mut answer = SourceAnswer::unknown(sref, "此来源不支持指定版本/closest 查询", false);
                    answer.unsupported_history = true;
                    answer
                }
            };
        }
        let (primary, legacy) = match self.locations_for(did) {
            Ok(locations) => locations,
            Err(err) => return SourceAnswer::unknown(sref, err.to_string(), false),
        };
        let url = match build_document_request_url(&primary, Some(doc_type)) {
            Ok(url) => url,
            Err(err) => return SourceAnswer::unknown(sref, err.to_string(), false),
        };
        let allow_legacy_body = !primary.is_directory();
        let mut answer = self
            .fetch_url(url, did, doc_type, revision, opts, allow_legacy_body, false)
            .await;
        if Self::answer_is_conclusive(&answer) {
            return answer;
        }
        if let Some(legacy) = legacy {
            if let Ok(url) = build_document_request_url(&legacy, Some(doc_type)) {
                if opts.budget().check().is_ok() {
                    let legacy_answer = self.fetch_url(url, did, doc_type, revision, opts, false, false).await;
                    if Self::answer_is_conclusive(&legacy_answer) {
                        return legacy_answer;
                    }
                    if answer.reason.is_none() {
                        answer = legacy_answer;
                    }
                }
            }
        }
        if opts.budget().check().is_err() {
            return answer;
        }
        if let Some(upper) = self.fetch_upper(did, doc_type, revision, opts).await {
            if Self::answer_is_conclusive(&upper) || upper.failure {
                return upper;
            }
            // 两个信道都"没有":保留 NoAnswer 的可缓存性,unknown 优先于 NotFound。
            if !answer.cacheable {
                return answer;
            }
            return upper;
        }
        answer
    }

    /// 根域名:读 `/.well-known/did.json`,实际类型由文档内容确定;路径型 → did-object。
    async fn default_doc_type(&self, did: &DID, opts: &ResolveOpts) -> Option<DefaultDocType> {
        if did.id.contains(':') {
            return Some(DefaultDocType::Known {
                doc_type: DidDocType::DidObject,
                reasons: Vec::new(),
            });
        }
        let now = buckyos_get_unix_timestamp();
        if let Some((doc_type, until)) = self.default_type_cache.lock().unwrap().get(did).cloned() {
            if until > now {
                return Some(DefaultDocType::Known {
                    doc_type,
                    reasons: Vec::new(),
                });
            }
        }
        let (primary, _) = self.locations_for(did).ok()?;
        let url = build_document_request_url(&primary, None).ok()?;
        let answer = self
            .fetch_url(url, did, &DidDocType::custom("*"), &Revision::current(), opts, false, false)
            .await;
        let doc_type = answer
            .body
            .as_ref()
            .and_then(|body| ParsedDocument::parse(body).ok())
            .and_then(|parsed| parsed.doc_type)?;
        self.default_type_cache
            .lock()
            .unwrap()
            .insert(did.clone(), (doc_type.clone(), now + DEFAULT_TYPE_CACHE_SECS));
        Some(DefaultDocType::Known {
            doc_type,
            reasons: vec![format!("doc_type detected from {}", did.to_string())],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_did_is_directory_and_path_did_is_object() {
        let provider = WebProvider::new();
        let did = DID::from_str("did:web:example.com").unwrap();
        let (primary, legacy) = provider.locations_for(&did).unwrap();
        assert!(primary.is_directory() && legacy.is_none());
        assert_eq!(
            build_document_request_url(&primary, Some(&DidDocType::Zone)).unwrap().as_str(),
            "https://example.com/.well-known/did.json"
        );
        assert_eq!(
            build_document_request_url(&primary, Some(&DidDocType::Owner)).unwrap().as_str(),
            "https://example.com/.well-known/owner.json"
        );

        let did = DID::from_str("did:web:example.com:user:alice").unwrap();
        let (primary, legacy) = provider.locations_for(&did).unwrap();
        assert_eq!(
            build_document_request_url(&primary, Some(&DidDocType::DidObject)).unwrap().as_str(),
            "https://example.com/user/alice"
        );
        assert_eq!(
            build_document_request_url(&primary, Some(&DidDocType::custom("info"))).unwrap().as_str(),
            "https://example.com/user/alice?type=info"
        );
        assert_eq!(
            build_document_request_url(&legacy.unwrap(), Some(&DidDocType::custom("info"))).unwrap().as_str(),
            "https://example.com/user/alice/info.json"
        );
        let did = DID::from_str("did:web:example.com%3A3000").unwrap();
        let (primary, _) = provider.locations_for(&did).unwrap();
        assert_eq!(
            build_document_request_url(&primary, None).unwrap().as_str(),
            "https://example.com:3000/.well-known/did.json"
        );
    }

    #[test]
    fn upper_resolver_base_follows_upper_did() {
        let provider = WebProvider::new();
        assert_eq!(
            provider.upper_resolver_base(&DID::from_str("did:web:ood1.example.com").unwrap()),
            Some("https://example.com".to_string())
        );
        assert_eq!(provider.upper_resolver_base(&DID::from_str("did:web:example.com").unwrap()), None);
    }

    #[test]
    fn rejects_malformed_hosts_and_segments() {
        let provider = WebProvider::new();
        assert!(provider.locations_for(&DID::new("web", "exa mple.com")).is_err());
        assert!(provider.locations_for(&DID::new("web", "example.com:..:x")).is_err());
        assert!(provider.locations_for(&DID::new("key", "abc")).is_err());
    }
}
