/*
实现基于bns合约的NsProvider实现
从接口上是对https_provider的封装
1. 通过输入machine_config的web3网桥配置，得到正确的查询URL
2. 只处理 did method 是 bns 的请求,其它一概返回不支持。
   did:dev 是 key 类 DID,不是 resolve_did 的合法入参(简化文档第 6 节),
   任何 provider 都不再受理它。

`BnsProvider` 就是本文件唯一该有的"Bns"命名：一个指向 BNS resolver host 的薄配置壳。
所有实际的 HTTP 请求/响应解析——包括 `query_did` 和 `resolve_published_state`——都转发给
`HttpsProvider`（见 https_provider.rs），因为那才是真正 method-agnostic 的 HTTP DID resolver
客户端；状态机的复杂度在 resolver-server 那一侧的实现，`BnsProvider` 这里不重新实现一遍。
协议见 doc/http_did_resolver_api.md。
*/

use crate::{BaseHttpProvider, DidDocType, NameInfo, NsProvider, PublishedState, RecordType};
use async_trait::async_trait;
use buckyos_kit::BuckyOSMachineConfig;
use log::info;
use name_lib::{EncodedDocument, NSError, NSResult, DID};
use serde_json::Value;
use std::net::IpAddr;

/// bns 的 web3 bridge 根域。既是 BNS 网关(resolver 接口)的 host,也是
/// did:bns 名字的规范 host 映射根(`did:bns:alice` ↔ `alice.{bns_root}`,
/// 见 doc/已有did-resolver介绍.md 第 1、2 节)——两个用途必须读同一份配置,
/// WebProvider 的 did:bns 信道与 BnsProvider 共用本函数。
/// 优先级:全局 `KNOWN_WEB3_BRIDGE_CONFIG` → machine.json → 默认配置。
/// 默认值为 machine config 的 `bns_host`,当前是 `bns.buckyos.ai`。
pub(crate) fn bns_bridge_host() -> NSResult<String> {
    let host = name_lib::KNOWN_WEB3_BRIDGE_CONFIG
        .get()
        .and_then(|m| m.get("bns"))
        .cloned()
        .or_else(|| BuckyOSMachineConfig::load_machine_config().map(|mc| mc.bns_resolver_host()))
        .unwrap_or_else(|| BuckyOSMachineConfig::default().bns_resolver_host());
    Ok(host)
}

/// 基于 web3 bridge 的 BNS DID 解析器(bns method 的权威渠道委托读取端),
/// 内部完全复用 `HttpsProvider`。
pub struct BnsProvider {
    inner: BaseHttpProvider,
}

impl BnsProvider {
    /// 使用全局 `KNOWN_WEB3_BRIDGE_CONFIG` 的 bns 网关作为 resolver host。
    /// 若未初始化全局配置，则回退读取 machine.json，再回退默认配置。
    pub fn new() -> NSResult<Self> {
        let resolver_host = bns_bridge_host()?;

        info!("bns provider using resolver host: {}", resolver_host);

        Ok(Self {
            inner: BaseHttpProvider::new(resolver_host.as_str()),
        })
    }

    /// 便捷构造：接收 JSON 配置，允许外部显式指定 web3 bridge 或 bns_host。
    pub fn new_with_config(config: Value) -> NSResult<Self> {
        let mc = serde_json::from_value::<BuckyOSMachineConfig>(config).unwrap_or_default();
        let host = mc.bns_resolver_host();
        Ok(Self {
            inner: BaseHttpProvider::new(host.as_str()),
        })
    }
}

#[async_trait]
impl NsProvider for BnsProvider {
    fn get_id(&self) -> String {
        "bns-provider".to_string()
    }

    fn methods(&self) -> Vec<String> {
        vec!["bns".to_string()]
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
        doc_type: Option<DidDocType>,
        _from_ip: Option<IpAddr>,
    ) -> NSResult<EncodedDocument> {
        if did.method != "bns" {
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
        doc_type: &DidDocType,
    ) -> NSResult<Option<PublishedState>> {
        if did.method != "bns" {
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

        // did:dev 不再是任何 provider 的受理对象。
        let dev_did = DID::from_str("did:dev:5bUuyWLOKyCre9az_IhJVIuOw8bA0gyKjstcYGHbaPE").unwrap();
        let err = provider.query_did(&dev_did, None, None).await.unwrap_err();
        assert!(matches!(err, NSError::NotFound(_)));
    }

    #[tokio::test]
    async fn published_state_rejects_unsupported_method_without_network() {
        // method 校验要在转发给 HttpsProvider 之前做，不支持的 method 直接
        // Ok(None)，不应该发出任何 HTTP 请求。
        let provider = BnsProvider::new().unwrap();
        let did = DID::from_str("did:web:example.com").unwrap();
        let state = provider
            .resolve_published_state(&did, &DidDocType::Zone)
            .await
            .unwrap();
        assert!(state.is_none());
    }
}
