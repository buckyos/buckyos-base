//! 已验证对端公钥来源(§6.4)。
//!
//! - key 必须来自经过验证的 DID/name-system evidence,resolver 实现负责
//!   verified freshness policy;
//! - 热路径不得隐式执行无界远程 resolve:resolver 应使用有界、可观测的
//!   verified cache;`refresh_verified_keys` 供客户端在解密失败后显式
//!   重新 resolve 一次(调用方保证有界重试);
//! - 返回顺序固定:active(default)first、grace newest first;调用方
//!   会按 policy 上限截断。

use super::error::S2sResult;
use super::keys::ed25519_key_fingerprint;
use async_trait::async_trait;
use name_lib::DID;
use std::collections::HashMap;
use std::sync::RwLock;

/// 一个经过验证的对端 Ed25519 公钥候选。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedPeerKey {
    /// 显式 key id;`None` 表示默认 active key。
    pub key_id: Option<String>,
    pub ed25519_public: [u8; 32],
}

impl VerifiedPeerKey {
    pub fn fingerprint(&self) -> [u8; 32] {
        ed25519_key_fingerprint(&self.ed25519_public)
    }
}

#[async_trait]
pub trait S2sPeerKeyResolver: Send + Sync {
    /// 返回有界、已验证的候选公钥。
    ///
    /// - `key_id = Some(..)`:只返回该 key(找不到返回空 Vec);
    /// - `key_id = None`:返回 default candidate set,active first、
    ///   grace newest first。
    async fn resolve_verified_keys(
        &self,
        service_did: &DID,
        key_id: Option<&str>,
    ) -> S2sResult<Vec<VerifiedPeerKey>>;

    /// 显式刷新后再 resolve(客户端解密失败后的一次有界重试用)。
    /// 默认实现等价于 `resolve_verified_keys`。
    async fn refresh_verified_keys(
        &self,
        service_did: &DID,
        key_id: Option<&str>,
    ) -> S2sResult<Vec<VerifiedPeerKey>> {
        self.resolve_verified_keys(service_did, key_id).await
    }
}

/// 静态配置的 resolver(测试与固定拓扑部署用)。
///
/// 写入的 key 视为"已验证"——调用方必须保证来源可信。
pub struct StaticPeerKeyResolver {
    keys: RwLock<HashMap<String, Vec<VerifiedPeerKey>>>,
}

impl StaticPeerKeyResolver {
    pub fn new() -> Self {
        StaticPeerKeyResolver {
            keys: RwLock::new(HashMap::new()),
        }
    }

    pub fn insert(&self, service_did: &DID, keys: Vec<VerifiedPeerKey>) {
        self.keys
            .write()
            .unwrap()
            .insert(service_did.to_string(), keys);
    }

    pub fn remove(&self, service_did: &DID) {
        self.keys.write().unwrap().remove(&service_did.to_string());
    }
}

#[async_trait]
impl S2sPeerKeyResolver for StaticPeerKeyResolver {
    async fn resolve_verified_keys(
        &self,
        service_did: &DID,
        key_id: Option<&str>,
    ) -> S2sResult<Vec<VerifiedPeerKey>> {
        let keys = self.keys.read().unwrap();
        let Some(candidates) = keys.get(&service_did.to_string()) else {
            return Ok(Vec::new());
        };
        match key_id {
            Some(kid) => Ok(candidates
                .iter()
                .filter(|k| k.key_id.as_deref() == Some(kid))
                .cloned()
                .collect()),
            None => Ok(candidates.clone()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn static_resolver_filters_by_key_id() {
        let resolver = StaticPeerKeyResolver::new();
        let did = DID::new("web", "svc.example.com");
        resolver.insert(
            &did,
            vec![
                VerifiedPeerKey {
                    key_id: None,
                    ed25519_public: [1u8; 32],
                },
                VerifiedPeerKey {
                    key_id: Some("key-2".to_string()),
                    ed25519_public: [2u8; 32],
                },
            ],
        );

        let all = resolver.resolve_verified_keys(&did, None).await.unwrap();
        assert_eq!(all.len(), 2);

        let one = resolver
            .resolve_verified_keys(&did, Some("key-2"))
            .await
            .unwrap();
        assert_eq!(one.len(), 1);
        assert_eq!(one[0].ed25519_public, [2u8; 32]);

        let none = resolver
            .resolve_verified_keys(&DID::new("web", "other.example.com"), None)
            .await
            .unwrap();
        assert!(none.is_empty());
    }
}
