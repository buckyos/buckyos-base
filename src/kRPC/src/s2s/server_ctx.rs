//! `S2sRpcServerContext`：服务端 S2S transport 无关引擎。
//!
//! Context accepts only its own complete DID. Remote callers use the shared Provider-first
//! identity cache; each authenticated request/response keeps immutable local and remote state.

use super::aad::{build_request_aad, build_response_aad};
use super::codec::generate_nonce;
use super::error::{S2sError, S2sResult};
use super::headers::{validate_time_window, S2sRequestHeaders, S2sResponseHeaders};
use super::identity::{
    RemoteDefaultKey, S2sLocalIdentity, S2sLocalKeySnapshot, S2sRemoteIdentityMetricsSnapshot,
    S2sRuntime,
};
use super::keys::{
    derive_aead_key, ed25519_pk_to_x25519_pk, DerivedKeyCache, DerivedKeyCacheKey, MessageKind,
};
use super::policy::S2sServerSecurityPolicy;
use super::provider::S2sPublicKeyProvider;
use super::replay::{MemoryReplayStore, ReplayKey, S2sReplayStore};
use super::seal::{aead_open, aead_seal};
use super::S2S_PROFILE_VERSION;
use name_client::ResolveSourcePolicy;
use name_lib::{parse_canonical_did, DID};
use serde_json::Value;
use std::sync::{Arc, RwLock};
use zeroize::Zeroizing;

/// probe 的 API registry 检查。
pub trait S2sApiRegistry: Send + Sync {
    fn api_visible_to(&self, canonical_api: &str, peer_service_did: &DID) -> bool;
}

/// 解密成功后的已认证请求。
#[derive(Debug)]
pub struct S2sDecryptedRequest {
    pub headers: S2sRequestHeaders,
    pub canonical_api: String,
    pub plaintext: Vec<u8>,
    pub authenticated_from_did: DID,
    pub authenticated_from_fingerprint: [u8; 32],
    local_key: S2sLocalKeySnapshot,
    remote_x25519_public: [u8; 32],
}

pub struct S2sRpcServerContext {
    local: S2sLocalIdentity,
    policy: RwLock<Arc<S2sServerSecurityPolicy>>,
    replay_store: Arc<dyn S2sReplayStore>,
    derived_cache: DerivedKeyCache,
    api_registry: Option<Arc<dyn S2sApiRegistry>>,
}

impl S2sRpcServerContext {
    /// Explicit generic/non-cluster construction using system roots and NameClient.
    pub async fn from_did_with_name_client_fallback(local_service_did: DID) -> S2sResult<Self> {
        Self::builder(local_service_did)
            .with_system_name_client_fallback()
            .build()
            .await
    }

    pub fn builder(local_service_did: DID) -> S2sRpcServerContextBuilder {
        S2sRpcServerContextBuilder {
            local_service_did,
            runtime: None,
            public_key_provider: None,
            allow_system_name_client_fallback: false,
            replay_store: None,
            policy: None,
            api_registry: None,
            derived_cache: None,
        }
    }

    /// Strong cluster construction: Provider is installed before the context can be built.
    pub fn cluster_builder(
        local_service_did: DID,
        public_key_provider: Arc<dyn S2sPublicKeyProvider>,
    ) -> S2sRpcServerContextBuilder {
        Self::builder(local_service_did).public_key_provider(public_key_provider)
    }

    pub fn local_service_did(&self) -> &DID {
        self.local.service_did()
    }

    pub fn api_registry(&self) -> Option<&Arc<dyn S2sApiRegistry>> {
        self.api_registry.as_ref()
    }

    pub fn remote_identity_metrics(&self) -> S2sRemoteIdentityMetricsSnapshot {
        self.local.runtime().remote_identity_metrics()
    }

    pub fn policy_snapshot(&self) -> Arc<S2sServerSecurityPolicy> {
        self.policy.read().unwrap().clone()
    }

    pub fn reload_policy(&self, policy: S2sServerSecurityPolicy) -> S2sResult<()> {
        policy.validate()?;
        *self.policy.write().unwrap() = Arc::new(policy);
        Ok(())
    }

    /// 原子 reload 当前默认 local key；旧 key 只由 in-flight request 持有。
    pub fn reload_local_identity(&self) -> S2sResult<bool> {
        if let Some(retired) = self.local.reload()? {
            self.derived_cache.invalidate_fingerprint(&retired);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// 重新读取指定 peer 的 Provider（优先）或 NameClient fallback，并清理
    /// 被替换 fingerprint 的派生密钥缓存。
    pub async fn reload_remote_identity(&self, remote_did: &DID) -> S2sResult<bool> {
        let remote_identity = self.local.runtime().remote_identity_handle(remote_did)?;
        let (changed, retired, _) = remote_identity
            .reload(ResolveSourcePolicy::RemoteAuthority)
            .await?;
        if let Some(retired) = retired {
            self.derived_cache.invalidate_fingerprint(&retired);
        }
        Ok(changed)
    }

    async fn derive_key_cached(
        &self,
        local: &S2sLocalKeySnapshot,
        remote_did: &DID,
        remote_key: &RemoteDefaultKey,
        kind: MessageKind,
        now: u64,
    ) -> S2sResult<Zeroizing<[u8; 32]>> {
        let (from_did, from_fp, to_did, to_fp) = match kind {
            MessageKind::Request => (
                remote_did.to_string(),
                remote_key.fingerprint,
                self.local.service_did().to_string(),
                local.fingerprint,
            ),
            MessageKind::Response => (
                self.local.service_did().to_string(),
                local.fingerprint,
                remote_did.to_string(),
                remote_key.fingerprint,
            ),
        };
        let cache_key = DerivedKeyCacheKey {
            version: S2S_PROFILE_VERSION,
            from_did,
            from_fingerprint: from_fp,
            to_did,
            to_fingerprint: to_fp,
            kind,
        };
        if let Some(key) = self.derived_cache.get(&cache_key, now) {
            return Ok(key);
        }
        let peer_x25519 = ed25519_pk_to_x25519_pk(&remote_key.ed25519_public)?;
        let shared = local.diffie_hellman(&peer_x25519)?;
        let (from, to) = match kind {
            MessageKind::Request => (remote_did, self.local.service_did()),
            MessageKind::Response => (self.local.service_did(), remote_did),
        };
        let key = derive_aead_key(&shared, from, &from_fp, to, &to_fp, kind);
        self.derived_cache.put(cache_key, key.clone(), now);
        Ok(key)
    }

    /// 时间预检 → To 校验 → From admission → 默认 key resolve → AEAD open
    /// → 认证后时间复验 → replay。
    pub async fn open_request(
        &self,
        headers: &S2sRequestHeaders,
        canonical_api: &str,
        body: &[u8],
        now: u64,
    ) -> S2sResult<S2sDecryptedRequest> {
        let policy = self.policy_snapshot();
        validate_time_window(headers.issued_at, headers.expires_at, now, &policy.message)?;

        if &headers.to != self.local.service_did() {
            return Err(S2sError::WrongPeer(format!(
                "request To {} is not this service",
                headers.to.to_string()
            )));
        }
        if !policy.peer_admission.admits(&headers.from) {
            return Err(S2sError::WrongPeer(format!(
                "peer {} not admitted",
                headers.from.to_string()
            )));
        }

        let local_key = self.local.current_key_snapshot();
        let remote_identity = self.local.runtime().remote_identity_handle(&headers.from)?;
        let (mut remote_key, retired) = remote_identity
            .snapshot(ResolveSourcePolicy::BestAvailable)
            .await?;
        if let Some(retired) = retired {
            self.derived_cache.invalidate_fingerprint(&retired);
        }
        let from_wire = headers.from.to_string();
        let to_wire = headers.to.to_string();
        let aad = build_request_aad(
            headers.version,
            &from_wire,
            &to_wire,
            canonical_api,
            headers.issued_at,
            headers.expires_at,
        );
        let key = self
            .derive_key_cached(
                &local_key,
                &headers.from,
                &remote_key,
                MessageKind::Request,
                now,
            )
            .await?;
        let plaintext = match aead_open(&key, &headers.nonce, &aad, body) {
            Ok(plaintext) => plaintext,
            Err(S2sError::DecryptFailed) => {
                // BestAvailable 可能仍持有轮换前的 peer key。只向权威源刷新一次；
                // 认证仍失败就立即 fail closed，不枚举其它候选。
                let Some(refreshed) = remote_identity
                    .refresh_after_failure(remote_key.as_ref())
                    .await?
                else {
                    return Err(S2sError::DecryptFailed);
                };
                self.derived_cache
                    .invalidate_fingerprint(&remote_key.fingerprint);
                let refreshed_key = self
                    .derive_key_cached(
                        &local_key,
                        &headers.from,
                        &refreshed,
                        MessageKind::Request,
                        now,
                    )
                    .await?;
                let plaintext = aead_open(&refreshed_key, &headers.nonce, &aad, body)?;
                remote_key = refreshed;
                plaintext
            }
            Err(err) => return Err(err),
        };

        validate_time_window(headers.issued_at, headers.expires_at, now, &policy.message)?;
        if !policy.peer_admission.admits(&headers.from) {
            return Err(S2sError::WrongPeer(
                "authenticated peer not admitted".to_string(),
            ));
        }
        let replay_key = ReplayKey {
            version: headers.version,
            from_did: from_wire,
            from_fingerprint: remote_key.fingerprint,
            to_did: to_wire,
            to_fingerprint: local_key.fingerprint,
            nonce: headers.nonce,
        };
        let retain_until = headers
            .expires_at
            .saturating_add(policy.message.future_clock_skew_secs);
        if !self
            .replay_store
            .check_and_insert(&replay_key, retain_until)
            .await?
        {
            return Err(S2sError::ReplayDetected);
        }

        Ok(S2sDecryptedRequest {
            headers: headers.clone(),
            canonical_api: canonical_api.to_string(),
            plaintext,
            authenticated_from_did: headers.from.clone(),
            authenticated_from_fingerprint: remote_key.fingerprint,
            local_key,
            remote_x25519_public: ed25519_pk_to_x25519_pk(&remote_key.ed25519_public)?,
        })
    }

    /// response 沿用 request 持有的 local key snapshot，即使 handler 执行期间 reload。
    pub async fn seal_response(
        &self,
        request: &S2sDecryptedRequest,
        response_json: &[u8],
        now: u64,
    ) -> S2sResult<(S2sResponseHeaders, Vec<u8>)> {
        let policy = self.policy_snapshot();
        let issued_at = now;
        let expires_at = now + policy.message.max_lifetime_secs;
        let nonce = generate_nonce();
        let response_headers = S2sResponseHeaders {
            version: S2S_PROFILE_VERSION,
            from: request.headers.to.clone(),
            to: request.headers.from.clone(),
            issued_at,
            expires_at,
            in_reply_to: request.headers.nonce,
            nonce,
        };
        let aad = build_response_aad(
            response_headers.version,
            &response_headers.from.to_string(),
            &response_headers.to.to_string(),
            &request.canonical_api,
            issued_at,
            expires_at,
            &request.headers.nonce,
        );

        let cache_key = DerivedKeyCacheKey {
            version: S2S_PROFILE_VERSION,
            from_did: self.local.service_did().to_string(),
            from_fingerprint: request.local_key.fingerprint,
            to_did: request.authenticated_from_did.to_string(),
            to_fingerprint: request.authenticated_from_fingerprint,
            kind: MessageKind::Response,
        };
        let key = match self.derived_cache.get(&cache_key, now) {
            Some(key) => key,
            None => {
                let shared = request
                    .local_key
                    .diffie_hellman(&request.remote_x25519_public)?;
                let key = derive_aead_key(
                    &shared,
                    self.local.service_did(),
                    &request.local_key.fingerprint,
                    &request.authenticated_from_did,
                    &request.authenticated_from_fingerprint,
                    MessageKind::Response,
                );
                self.derived_cache.put(cache_key, key.clone(), now);
                key
            }
        };
        let sealed = aead_seal(&key, &nonce, &aad, response_json)?;
        Ok((response_headers, sealed))
    }
}

/// JSON 嵌套深度。
pub fn json_value_depth(value: &Value) -> usize {
    match value {
        Value::Array(items) => 1 + items.iter().map(json_value_depth).max().unwrap_or(0),
        Value::Object(map) => 1 + map.values().map(json_value_depth).max().unwrap_or(0),
        _ => 1,
    }
}

pub struct S2sRpcServerContextBuilder {
    local_service_did: DID,
    runtime: Option<S2sRuntime>,
    public_key_provider: Option<Arc<dyn S2sPublicKeyProvider>>,
    allow_system_name_client_fallback: bool,
    replay_store: Option<Arc<dyn S2sReplayStore>>,
    policy: Option<S2sServerSecurityPolicy>,
    api_registry: Option<Arc<dyn S2sApiRegistry>>,
    derived_cache: Option<DerivedKeyCache>,
}

impl S2sRpcServerContextBuilder {
    /// 测试/嵌入场景注入独立 roots 与 NameClient。
    pub fn with_runtime(mut self, runtime: S2sRuntime) -> Self {
        self.runtime = Some(runtime);
        self
    }

    /// 安装查询产品确定性配置 snapshot 的 peer 公钥 Provider。
    pub fn public_key_provider(
        mut self,
        public_key_provider: Arc<dyn S2sPublicKeyProvider>,
    ) -> Self {
        self.public_key_provider = Some(public_key_provider);
        self
    }

    /// Explicit generic/non-cluster mode. This is never selected implicitly.
    pub fn with_system_name_client_fallback(mut self) -> Self {
        self.allow_system_name_client_fallback = true;
        self
    }

    pub fn replay_store(mut self, store: Arc<dyn S2sReplayStore>) -> Self {
        self.replay_store = Some(store);
        self
    }

    pub fn security_policy(mut self, policy: S2sServerSecurityPolicy) -> Self {
        self.policy = Some(policy);
        self
    }

    pub fn api_registry(mut self, registry: Arc<dyn S2sApiRegistry>) -> Self {
        self.api_registry = Some(registry);
        self
    }

    pub fn derived_key_cache(mut self, cache: DerivedKeyCache) -> Self {
        self.derived_cache = Some(cache);
        self
    }

    pub async fn build(self) -> S2sResult<S2sRpcServerContext> {
        parse_canonical_did(&self.local_service_did.to_string())
            .map_err(|err| S2sError::InvalidDid(err.to_string()))?;
        let policy = self.policy.unwrap_or_default();
        policy.validate()?;
        let runtime = match (self.runtime, self.public_key_provider) {
            (Some(runtime), Some(provider)) => runtime.with_public_key_provider(provider),
            (Some(runtime), None) => runtime,
            (None, Some(provider)) => {
                S2sRuntime::system_provider_with_name_client_fallback(provider)?
            }
            (None, None) if self.allow_system_name_client_fallback => {
                S2sRuntime::system_name_client_fallback()?
            }
            (None, None) => {
                return Err(S2sError::InvalidConfig(
                    "S2S server requires a cluster Provider, an injected runtime, or explicit \
                     system NameClient fallback"
                        .to_string(),
                ))
            }
        };
        let local = S2sLocalIdentity::load(self.local_service_did, runtime)?;
        Ok(S2sRpcServerContext {
            local,
            policy: RwLock::new(Arc::new(policy)),
            replay_store: self
                .replay_store
                .unwrap_or_else(|| Arc::new(MemoryReplayStore::with_default_capacity())),
            derived_cache: self
                .derived_cache
                .unwrap_or_else(DerivedKeyCache::with_defaults),
            api_registry: self.api_registry,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn json_depth() {
        assert_eq!(json_value_depth(&json!(1)), 1);
        assert_eq!(json_value_depth(&json!({"a": 1})), 2);
        assert_eq!(json_value_depth(&json!({"a": [1, 2]})), 3);
        assert_eq!(json_value_depth(&json!({"a": {"b": {"c": []}}})), 4);
    }
}
