/*
实现基于bns合约的NsProvider实现
从接口上是对https_provider的封装
1. 通过输入machine_config的web3网桥配置，得到正确的查询URL
2. 只处理 did method是bns和dev的请求，其它一概返回不支持

`BnsProvider` 就是本文件唯一该有的"Bns"命名：一个指向 web3_bridge.bns host 的薄配置壳。
所有实际的 HTTP 请求/响应解析——包括 `query_did` 和 `resolve_published_state`——都转发给
`HttpsProvider`（见 https_provider.rs），因为那才是真正 method-agnostic 的 HTTP DID resolver
客户端；状态机的复杂度在 resolver-server 那一侧的实现，`BnsProvider` 这里不重新实现一遍。
协议见 doc/http_did_resolver_api.md。
*/

use crate::{
    HttpsProvider, MethodMatcher, NameInfo, NsProvider, PublishedState, RecordType, ResolverCaps,
};
use async_trait::async_trait;
use buckyos_kit::BuckyOSMachineConfig;
use log::info;
use name_lib::{EncodedDocument, NSError, NSResult, DID};
use serde_json::Value;
use std::net::IpAddr;

/// 基于 web3 bridge 的 BNS/DEV DID 解析器，内部完全复用 `HttpsProvider`。
pub struct BnsProvider {
    inner: HttpsProvider,
}

impl BnsProvider {
    /// 使用全局 `KNOWN_WEB3_BRIDGE_CONFIG` 的 bns 网关作为 resolver host。
    /// 若未初始化全局配置，则回退读取 machine.json，再回退默认配置。
    pub fn new() -> NSResult<Self> {
        let host_from_global = name_lib::KNOWN_WEB3_BRIDGE_CONFIG
            .get()
            .and_then(|m| m.get("bns"))
            .cloned();

        let resolver_host = host_from_global
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
            .ok_or_else(|| NSError::Failed("web3_bridge.bns not set".to_string()))?;

        info!("bns provider using resolver host: {}", resolver_host);

        Ok(Self {
            inner: HttpsProvider::new(resolver_host.as_str()),
        })
    }

    /// 便捷构造：接收 JSON 配置，允许外部显式指定 web3 bridge。
    pub fn new_with_config(config: Value) -> NSResult<Self> {
        let mc = serde_json::from_value::<BuckyOSMachineConfig>(config).unwrap_or_default();
        let host = mc
            .web3_bridge
            .get("bns")
            .cloned()
            .ok_or_else(|| NSError::Failed("web3_bridge.bns not set".to_string()))?;
        Ok(Self {
            inner: HttpsProvider::new(host.as_str()),
        })
    }
}

#[async_trait]
impl NsProvider for BnsProvider {
    fn get_id(&self) -> String {
        "bns-provider".to_string()
    }

    fn methods(&self) -> MethodMatcher {
        MethodMatcher::exact(["bns", "dev"])
    }

    fn caps(&self) -> ResolverCaps {
        ResolverCaps {
            published_state: true,
            document_body: true,
            self_signed_candidate: true,
            unauthenticated_info: true,
            negative_state: true,
        }
    }

    async fn query(
        &self,
        _name: &str,
        _record_type: Option<RecordType>,
        _from_ip: Option<IpAddr>,
    ) -> NSResult<NameInfo> {
        Err(NSError::NotFound(
            "bns provider does not resolve dns records".to_string(),
        ))
    }

    async fn query_did(
        &self,
        did: &DID,
        doc_type: Option<&str>,
        _from_ip: Option<IpAddr>,
    ) -> NSResult<EncodedDocument> {
        if did.method != "bns" && did.method != "dev" {
            return Err(NSError::NotFound(format!(
                "unsupported did method: {}",
                did.to_string()
            )));
        }

        info!(
            "bns provider forwarding to https resolver for {}",
            did.to_string()
        );
        self.inner.query_did(did, doc_type, None).await
    }

    async fn resolve_published_state(
        &self,
        did: &DID,
        doc_type: &str,
    ) -> NSResult<Option<PublishedState>> {
        if did.method != "bns" && did.method != "dev" {
            return Ok(None);
        }

        self.inner.resolve_published_state(did, doc_type).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn reject_unsupported_method() {
        let provider = BnsProvider::new().unwrap();
        let did = DID::from_str("did:web:example.com").unwrap();
        let err = provider.query_did(&did, None, None).await.unwrap_err();
        assert!(matches!(err, NSError::NotFound(_)));
    }

    #[tokio::test]
    async fn published_state_rejects_unsupported_method_without_network() {
        // method 校验要在转发给 HttpsProvider 之前做，不支持的 method 直接
        // Ok(None)，不应该发出任何 HTTP 请求。
        let provider = BnsProvider::new().unwrap();
        let did = DID::from_str("did:web:example.com").unwrap();
        let state = provider
            .resolve_published_state(&did, "zone")
            .await
            .unwrap();
        assert!(state.is_none());
    }
}
