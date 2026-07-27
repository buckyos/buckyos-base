//! 本地 service 身份(§6.1/§6.3)。
//!
//! 配置侧使用短 `local_service_appid`,密码学身份使用
//! `derive_service_did(appid, current_zone_did)` 派生的 canonical service DID。
//! `service_did` 是构造结果,不是第二个可独立填写的配置源。

use super::error::{S2sError, S2sResult};
use super::keys::{ExplicitEd25519Provider, S2sKeyAgreementProvider, SecretEd25519Key};
use super::peer::S2sPeerKeyResolver;
use super::service_key_ref::derive_service_did;
use name_lib::DID;
use std::sync::Arc;

/// 本地私钥来源(§6.3)。
///
/// Identity Manager 默认路径的实现在 `name-client`
/// (`IdentityManagerS2sKeyProvider`),通过 `Provider` 变体注入——
/// kRPC/HTTP 层不直接读取 security root。
pub enum S2sLocalKeySource {
    /// 显式传入 raw Ed25519 私钥(可选显式 key id)。
    ExplicitEd25519 {
        key: SecretEd25519Key,
        key_id: Option<String>,
    },
    /// key-agreement provider(file、TPM/HSM/TEE 或独立 key agent)。
    Provider {
        provider: Arc<dyn S2sKeyAgreementProvider>,
    },
}

impl std::fmt::Debug for S2sLocalKeySource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            S2sLocalKeySource::ExplicitEd25519 { key_id, .. } => f
                .debug_struct("ExplicitEd25519")
                .field("key_id", key_id)
                .finish_non_exhaustive(),
            S2sLocalKeySource::Provider { .. } => f.write_str("Provider(..)"),
        }
    }
}

/// client/server 共享的本地身份配置(§6.3)。
#[derive(Debug)]
pub struct S2sLocalIdentityConfig {
    pub service_appid: String,
    pub current_zone_did: DID,
    pub key_source: S2sLocalKeySource,
}

/// 本地 key 与派生 service DID 的绑定校验方式。
///
/// web/bns service DID 本身不内嵌公钥,绑定必须经由已验证的
/// DID/name-system evidence 确认;evidence 要么来自 resolver
/// (`VerifyAgainst`),要么由调用方持有的 verified service descriptor
/// 断言(`CallerAsserted`,pinned key 部署)。显式跳过是不安全选项,
/// 只应在测试或 evidence 尚未发布的引导阶段使用。
pub enum LocalKeyBindingCheck<'a> {
    /// 用 resolver 中该 service DID 的 verified keys 校验 provider 的
    /// 默认 key;service DID 无 verified key 或不匹配都失败。
    VerifyAgainst(&'a dyn S2sPeerKeyResolver),
    /// 绑定正确性由调用方提供的 verified descriptor/配置断言
    /// (pinned-key 模式:本地没有可查询的 evidence 源,验证责任在
    /// 产出 descriptor 的服务发现层)。
    CallerAsserted,
    /// 显式跳过(unsafe,测试/引导用)。
    UnsafeSkip,
}

/// 解析完成的本地身份(字段只读)。
#[derive(Clone)]
pub struct S2sLocalIdentity {
    service_appid: String,
    current_zone_did: DID,
    service_did: DID,
    provider: Arc<dyn S2sKeyAgreementProvider>,
}

impl std::fmt::Debug for S2sLocalIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S2sLocalIdentity")
            .field("service_appid", &self.service_appid)
            .field("current_zone_did", &self.current_zone_did.to_string())
            .field("service_did", &self.service_did.to_string())
            .finish_non_exhaustive()
    }
}

impl S2sLocalIdentity {
    pub fn service_appid(&self) -> &str {
        &self.service_appid
    }

    pub fn current_zone_did(&self) -> &DID {
        &self.current_zone_did
    }

    pub fn service_did(&self) -> &DID {
        &self.service_did
    }

    pub fn provider(&self) -> &Arc<dyn S2sKeyAgreementProvider> {
        &self.provider
    }
}

impl S2sLocalIdentityConfig {
    pub fn new(service_appid: impl Into<String>, current_zone_did: DID, key_source: S2sLocalKeySource) -> Self {
        S2sLocalIdentityConfig {
            service_appid: service_appid.into(),
            current_zone_did,
            key_source,
        }
    }

    /// 派生 canonical service DID、包装 provider 并执行 key binding 校验。
    ///
    /// 失败即错(§6.3):显式 key 与派生 service DID 不匹配时不静默回退
    /// 其他 key source。
    pub async fn resolve(self, binding: LocalKeyBindingCheck<'_>) -> S2sResult<S2sLocalIdentity> {
        let service_did = derive_service_did(&self.service_appid, &self.current_zone_did)?;
        let provider: Arc<dyn S2sKeyAgreementProvider> = match self.key_source {
            S2sLocalKeySource::ExplicitEd25519 { key, key_id } => {
                Arc::new(ExplicitEd25519Provider::new(key, key_id))
            }
            S2sLocalKeySource::Provider { provider } => provider,
        };

        let candidates = provider.local_key_candidates().await?;
        if candidates.is_empty() {
            return Err(S2sError::InvalidConfig(
                "local key provider has no key candidates".to_string(),
            ));
        }

        match binding {
            LocalKeyBindingCheck::VerifyAgainst(resolver) => {
                let default_key = &candidates[0];
                let verified = resolver
                    .resolve_verified_keys(&service_did, default_key.key_id.as_deref())
                    .await?;
                let matched = verified
                    .iter()
                    .any(|k| k.ed25519_public == default_key.ed25519_public);
                if !matched {
                    return Err(S2sError::InvalidConfig(format!(
                        "local default key does not match verified keys of {}",
                        service_did.to_string()
                    )));
                }
            }
            LocalKeyBindingCheck::CallerAsserted | LocalKeyBindingCheck::UnsafeSkip => {}
        }

        Ok(S2sLocalIdentity {
            service_appid: self.service_appid,
            current_zone_did: self.current_zone_did,
            service_did,
            provider,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::s2s::peer::{StaticPeerKeyResolver, VerifiedPeerKey};

    fn key(fill: u8) -> SecretEd25519Key {
        SecretEd25519Key::from_seed([fill; 32])
    }

    #[tokio::test]
    async fn resolve_derives_service_did_and_checks_binding() {
        let secret = key(3);
        let public = secret.public_key();
        let zone = DID::new("web", "example.com");
        let expected_did = DID::new("web", "event-service.example.com");

        let resolver = StaticPeerKeyResolver::new();
        resolver.insert(
            &expected_did,
            vec![VerifiedPeerKey {
                key_id: None,
                ed25519_public: public,
            }],
        );

        let config = S2sLocalIdentityConfig::new(
            "event-service",
            zone.clone(),
            S2sLocalKeySource::ExplicitEd25519 {
                key: secret,
                key_id: None,
            },
        );
        let identity = config
            .resolve(LocalKeyBindingCheck::VerifyAgainst(&resolver))
            .await
            .unwrap();
        assert_eq!(identity.service_did(), &expected_did);
        assert_eq!(identity.service_appid(), "event-service");
    }

    #[tokio::test]
    async fn binding_mismatch_fails_construction() {
        let zone = DID::new("web", "example.com");
        let expected_did = DID::new("web", "event-service.example.com");
        let resolver = StaticPeerKeyResolver::new();
        // resolver 里放的是另一把 key
        resolver.insert(
            &expected_did,
            vec![VerifiedPeerKey {
                key_id: None,
                ed25519_public: key(9).public_key(),
            }],
        );

        let config = S2sLocalIdentityConfig::new(
            "event-service",
            zone,
            S2sLocalKeySource::ExplicitEd25519 {
                key: key(3),
                key_id: None,
            },
        );
        let err = config
            .resolve(LocalKeyBindingCheck::VerifyAgainst(&resolver))
            .await
            .unwrap_err();
        assert!(matches!(err, S2sError::InvalidConfig(_)));
    }

    #[tokio::test]
    async fn unknown_service_did_fails_binding_check() {
        let zone = DID::new("web", "example.com");
        let resolver = StaticPeerKeyResolver::new();
        let config = S2sLocalIdentityConfig::new(
            "event-service",
            zone,
            S2sLocalKeySource::ExplicitEd25519 {
                key: key(3),
                key_id: None,
            },
        );
        assert!(config
            .resolve(LocalKeyBindingCheck::VerifyAgainst(&resolver))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn bad_appid_fails() {
        let zone = DID::new("web", "example.com");
        let config = S2sLocalIdentityConfig::new(
            "Bad.Appid",
            zone,
            S2sLocalKeySource::ExplicitEd25519 {
                key: key(3),
                key_id: None,
            },
        );
        assert!(config.resolve(LocalKeyBindingCheck::UnsafeSkip).await.is_err());
    }
}
