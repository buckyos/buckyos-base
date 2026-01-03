/*
实现基于bns合约的NsProvider实现
从接口上是对https_provider的封装
1. 通过输入machine_config的web3网桥配置，得到正确的查询URL
2. 只处理 did method是bns和dev的请求，其它一概返回不支持

*/

use crate::{HttpsProvider, NameInfo, NsProvider, RecordType};
use async_trait::async_trait;
use buckyos_kit::BuckyOSMachineConfig;
use log::info;
use name_lib::{DID, EncodedDocument, NSError, NSResult};
use serde_json::Value;
use std::net::IpAddr;

/// 基于 web3 bridge 的 BNS/DEV DID 解析器，内部复用 `HttpsProvider`。
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
            .or_else(|| BuckyOSMachineConfig::default().web3_bridge.get("bns").cloned())
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
}