//! did:bns 权威渠道的委托读取端:指向 BNS resolver host 的 HTTP resolver API 薄壳,
//! 所有请求 / 响应解析都转发给 `BaseHttpProvider`。协议见 doc/http_did_resolver_api.md。
//!
//! BNS 对 `ood1.<name>` 的设备槽位联合校验挂在 resolver 侧的显式 `device` 类型查询上
//! (TODO D4),本客户端只负责按请求类型发查询。

use crate::resolver::{DefaultDocType, ResolveOpts, Revision, Source, SourceAnswer, SourceRef, SourceTier};
use crate::BaseHttpProvider;
use async_trait::async_trait;
use buckyos_kit::BuckyOSMachineConfig;
use log::info;
use name_lib::{DidDocType, NSError, NSResult, DID};
use serde_json::Value;

/// did:bns 名字的 web3 bridge 映射根(`did:bns:alice` ↔ `alice.{bns_root}`)。
/// 只供 WebProvider 的 did:bns 信道使用,与 BNS 权威 resolver 的 `bns_host` 是
/// 两个独立语义。优先级:全局 `KNOWN_WEB3_BRIDGE_CONFIG` → machine.json → 默认配置。
pub(crate) fn bns_web3_bridge_host() -> NSResult<String> {
    name_lib::KNOWN_WEB3_BRIDGE_CONFIG
        .get()
        .and_then(|m| m.get("bns"))
        .cloned()
        .or_else(|| {
            BuckyOSMachineConfig::load_machine_config()
                .and_then(|mc| mc.web3_bridge.get("bns").cloned())
        })
        .or_else(|| {
            BuckyOSMachineConfig::default()
                .web3_bridge
                .get("bns")
                .cloned()
        })
        .ok_or_else(|| NSError::Failed("web3_bridge.bns not set".to_string()))
}

/// BNS 权威 resolver 的 host:只读取 machine config 的 `bns_host`。
fn bns_resolver_host() -> String {
    BuckyOSMachineConfig::load_machine_config()
        .map(|mc| mc.bns_resolver_host())
        .unwrap_or_else(|| BuckyOSMachineConfig::default().bns_resolver_host())
}

pub struct BnsProvider {
    inner: BaseHttpProvider,
}

impl BnsProvider {
    pub fn new() -> NSResult<Self> {
        let resolver_host = bns_resolver_host();
        info!("bns provider using resolver host: {}", resolver_host);
        Ok(Self::with_resolver_host(&resolver_host))
    }

    pub fn with_resolver_host(resolver_host: &str) -> Self {
        Self {
            inner: BaseHttpProvider::new(resolver_host).with_id("bns-provider"),
        }
    }

    /// 便捷构造:接收 JSON 配置并读取其中的 bns_host。
    pub fn new_with_config(config: Value) -> NSResult<Self> {
        let mc = serde_json::from_value::<BuckyOSMachineConfig>(config).unwrap_or_default();
        Ok(Self::with_resolver_host(&mc.bns_resolver_host()))
    }

    fn source_ref(&self) -> SourceRef {
        SourceRef::provider(self.id(), SourceTier::Authority)
    }
}

#[async_trait]
impl Source for BnsProvider {
    fn id(&self) -> String {
        "bns-provider".to_string()
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
        if did.method != "bns" {
            return SourceAnswer::unknown(
                self.source_ref(),
                format!("unsupported did method: {}", did.to_string()),
                false,
            );
        }
        self.inner.get_document(did, doc_type, revision, opts).await
    }

    async fn default_doc_type(&self, did: &DID, opts: &ResolveOpts) -> Option<DefaultDocType> {
        if did.method != "bns" {
            return None;
        }
        self.inner.default_doc_type(did, opts).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn reject_unsupported_method_without_network() {
        let provider = BnsProvider::with_resolver_host("127.0.0.1:9");
        let opts = ResolveOpts::default().normalize(Duration::from_secs(1));
        let did = DID::from_str("did:web:example.com").unwrap();
        let answer = provider
            .get_document(&did, &DidDocType::Zone, &Revision::current(), &opts)
            .await;
        assert!(answer.is_unknown() && !answer.failure);
        let dev = DID::from_str("did:dev:5bUuyWLOKyCre9az_IhJVIuOw8bA0gyKjstcYGHbaPE").unwrap();
        let answer = provider
            .get_document(&dev, &DidDocType::Zone, &Revision::current(), &opts)
            .await;
        assert!(answer.is_unknown());
    }
}
