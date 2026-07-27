//! `S2sRpcServerContext`(§9.1/§11.6):服务端加密分支的 transport 无关引擎。
//!
//! HTTP 入口(`buckyos-http-server::serve_http_by_s2s_rpc_handler`)负责
//! method/path/Content-Type dispatch、Body 上限与响应构造;本引擎负责
//! §9.3 加密分支的 key selection、AAD、AEAD、时间窗口与 replay 验证,
//! 并生成与 request nonce 绑定的加密 response。

use super::aad::{build_request_aad, build_response_aad};
use super::codec::generate_nonce;
use super::error::{S2sError, S2sResult};
use super::headers::{validate_time_window, S2sRequestHeaders, S2sResponseHeaders};
use super::identity::{LocalKeyBindingCheck, S2sLocalIdentity, S2sLocalIdentityConfig, S2sLocalKeySource};
use super::keys::{
    ed25519_pk_to_x25519_pk, derive_aead_key, DerivedKeyCache, DerivedKeyCacheKey, MessageKind,
    S2sKeyAgreementProvider, S2sLocalKeyHandle, SecretEd25519Key,
};
use super::peer::{S2sPeerKeyResolver, VerifiedPeerKey};
use super::policy::S2sServerSecurityPolicy;
use super::replay::{MemoryReplayStore, ReplayKey, S2sReplayStore};
use super::seal::{aead_open, aead_seal};
use super::S2S_PROFILE_VERSION;
use name_lib::DID;
use serde_json::Value;
use std::sync::{Arc, RwLock};
use zeroize::Zeroizing;

/// probe 的 API registry 检查(§13)。
///
/// `api_visible_to` 由实现方执行 RBAC:调用方只能探测自己有权调用的 API,
/// 避免任意已验证 peer 枚举全部 registry。
pub trait S2sApiRegistry: Send + Sync {
    fn api_visible_to(&self, canonical_api: &str, peer_service_did: &DID) -> bool;
}

/// 解密成功后的已认证请求。
#[derive(Debug)]
pub struct S2sDecryptedRequest {
    pub headers: S2sRequestHeaders,
    pub canonical_api: String,
    /// 完整 `RPCRequest` JSON bytes。
    pub plaintext: Vec<u8>,
    /// AEAD 成功后确认的 canonical sender service DID。
    pub authenticated_from_did: DID,
    /// 实际参与 DH 的 sender key fingerprint。
    pub authenticated_from_fingerprint: [u8; 32],
    /// 实际解密成功的本地 key fingerprint(response 必须沿用)。
    pub local_key_fingerprint: [u8; 32],
    /// 实际解密成功的对端 X25519 public key(response 派生复用)。
    remote_x25519_public: [u8; 32],
}

pub struct S2sRpcServerContext {
    local: S2sLocalIdentity,
    policy: RwLock<Arc<S2sServerSecurityPolicy>>,
    peer_resolver: Arc<dyn S2sPeerKeyResolver>,
    replay_store: Arc<dyn S2sReplayStore>,
    derived_cache: DerivedKeyCache,
    api_registry: Option<Arc<dyn S2sApiRegistry>>,
}

impl S2sRpcServerContext {
    pub fn builder(
        local_service_appid: impl Into<String>,
        current_zone_did: DID,
    ) -> S2sRpcServerContextBuilder {
        S2sRpcServerContextBuilder {
            service_appid: local_service_appid.into(),
            current_zone_did,
            key_source: None,
            peer_resolver: None,
            replay_store: None,
            policy: None,
            api_registry: None,
            derived_cache: None,
            skip_local_key_binding_check: false,
        }
    }

    pub fn local_service_did(&self) -> &DID {
        self.local.service_did()
    }

    pub fn local_identity(&self) -> &S2sLocalIdentity {
        &self.local
    }

    pub fn api_registry(&self) -> Option<&Arc<dyn S2sApiRegistry>> {
        self.api_registry.as_ref()
    }

    /// 当前 immutable policy snapshot。一次 request 从 admission 到 dispatch
    /// 必须使用同一 snapshot。
    pub fn policy_snapshot(&self) -> Arc<S2sServerSecurityPolicy> {
        self.policy.read().unwrap().clone()
    }

    /// 原子替换完整 policy snapshot;校验失败保持旧 policy(§11.6)。
    pub fn reload_policy(&self, policy: S2sServerSecurityPolicy) -> S2sResult<()> {
        policy.validate()?;
        *self.policy.write().unwrap() = Arc::new(policy);
        Ok(())
    }

    /// key retire 时主动失效派生 key cache(§6.6)。
    pub fn invalidate_key_fingerprint(&self, fingerprint: &[u8; 32]) {
        self.derived_cache.invalidate_fingerprint(fingerprint);
    }

    async fn derive_key_cached(
        &self,
        local: &S2sLocalKeyHandle,
        remote_did: &DID,
        remote_key: &VerifiedPeerKey,
        remote_fingerprint: &[u8; 32],
        kind: MessageKind,
        now: u64,
    ) -> S2sResult<Zeroizing<[u8; 32]>> {
        // request: from=remote(sender), to=local;response: from=local, to=remote
        let (from_did, from_fp, to_did, to_fp) = match kind {
            MessageKind::Request => (
                remote_did.to_string(),
                *remote_fingerprint,
                self.local.service_did().to_string(),
                local.fingerprint,
            ),
            MessageKind::Response => (
                self.local.service_did().to_string(),
                local.fingerprint,
                remote_did.to_string(),
                *remote_fingerprint,
            ),
        };
        let cache_key = DerivedKeyCacheKey {
            version: S2S_PROFILE_VERSION,
            from_did: from_did.clone(),
            from_fingerprint: from_fp,
            to_did: to_did.clone(),
            to_fingerprint: to_fp,
            kind,
        };
        if let Some(key) = self.derived_cache.get(&cache_key, now) {
            return Ok(key);
        }
        let peer_x25519 = ed25519_pk_to_x25519_pk(&remote_key.ed25519_public)?;
        let shared = self
            .local
            .provider()
            .diffie_hellman(&local.fingerprint, &peer_x25519)
            .await?;
        let (from_did_parsed, to_did_parsed) = match kind {
            MessageKind::Request => (remote_did.clone(), self.local.service_did().clone()),
            MessageKind::Response => (self.local.service_did().clone(), remote_did.clone()),
        };
        let key = derive_aead_key(&shared, &from_did_parsed, &from_fp, &to_did_parsed, &to_fp, kind);
        self.derived_cache.put(cache_key, key.clone(), now);
        Ok(key)
    }

    /// §9.3 加密分支步骤 3–12(header 已由 HTTP 层严格解析):
    /// 时间预检 → To 校验 → From pre-admission → 有界 candidate → AEAD open
    /// → 认证后时间复验 → 最终 peer admission → 原子 replay。
    ///
    /// 成功前的所有错误必须由调用方映射为统一 transport failure。
    pub async fn open_request(
        &self,
        headers: &S2sRequestHeaders,
        canonical_api: &str,
        body: &[u8],
        now: u64,
    ) -> S2sResult<S2sDecryptedRequest> {
        let policy = self.policy_snapshot();

        // 3. 未认证时间预检(廉价拒绝;第 10 步解密后重验)
        validate_time_window(headers.issued_at, headers.expires_at, now, &policy.message)?;

        // 4. To 必须是本服务
        if &headers.to.did != self.local.service_did() {
            return Err(S2sError::WrongPeer(format!(
                "request To {} is not this service",
                headers.to.did.to_string()
            )));
        }
        let mut local_candidates = self.local.provider().local_key_candidates().await?;
        if let Some(kid) = headers.to.key_id.as_deref() {
            local_candidates.retain(|c| c.key_id.as_deref() == Some(kid));
        }
        local_candidates.truncate(policy.limits.max_key_candidates);
        if local_candidates.is_empty() {
            return Err(S2sError::KeyNotFound("no usable local key".to_string()));
        }

        // 6. 对声明的 From 执行廉价 pre-admission,限制无关 peer 的 key lookup 成本
        if !policy.peer_admission.admits(&headers.from.did) {
            return Err(S2sError::WrongPeer(format!(
                "peer {} not admitted",
                headers.from.did.to_string()
            )));
        }

        // 5. 有界、已验证的 sender key candidates
        let mut remote_candidates = self
            .peer_resolver
            .resolve_verified_keys(&headers.from.did, headers.from.key_id.as_deref())
            .await?;
        remote_candidates.truncate(policy.limits.max_key_candidates);
        if remote_candidates.is_empty() {
            return Err(S2sError::KeyNotFound(format!(
                "no verified key for {}",
                headers.from.did.to_string()
            )));
        }

        // 8. AAD 逐字节使用 wire 形式 key ref(不补全 key id)
        let from_wire = headers.from.to_wire_string();
        let to_wire = headers.to.to_wire_string();
        let aad = build_request_aad(
            headers.version,
            &from_wire,
            &to_wire,
            canonical_api,
            headers.issued_at,
            headers.expires_at,
        );

        // 7+9. 逐对 candidate 派生 key 并尝试 AEAD open;错误 candidate 只会
        // 派生出无法解密的 key,不需要 AAD 参与消歧
        let mut opened: Option<(Vec<u8>, S2sLocalKeyHandle, VerifiedPeerKey, [u8; 32])> = None;
        'outer: for local in &local_candidates {
            for remote in &remote_candidates {
                let remote_fp = remote.fingerprint();
                let key = match self
                    .derive_key_cached(local, &headers.from.did, remote, &remote_fp, MessageKind::Request, now)
                    .await
                {
                    Ok(key) => key,
                    Err(S2sError::InvalidKey(_)) => continue,
                    Err(e) => return Err(e),
                };
                if let Ok(plaintext) = aead_open(&key, &headers.nonce, &aad, body) {
                    opened = Some((plaintext, local.clone(), remote.clone(), remote_fp));
                    break 'outer;
                }
            }
        }
        let Some((plaintext, local_key, remote_key, remote_fp)) = opened else {
            return Err(S2sError::DecryptFailed);
        };

        // 10. 重新验证已认证的 iat/exp
        validate_time_window(headers.issued_at, headers.expires_at, now, &policy.message)?;

        // 11. 最终 peer admission(基于 authenticated identity)
        if !policy.peer_admission.admits(&headers.from.did) {
            return Err(S2sError::WrongPeer("authenticated peer not admitted".to_string()));
        }

        // 12. 原子 replay check-and-insert;store 故障 fail closed
        let replay_key = ReplayKey {
            version: headers.version,
            from_key_ref: from_wire,
            from_fingerprint: remote_fp,
            to_key_ref: to_wire,
            to_fingerprint: local_key.fingerprint,
            nonce: headers.nonce,
        };
        let retain_until = headers
            .expires_at
            .saturating_add(policy.message.future_clock_skew_secs);
        let fresh = self.replay_store.check_and_insert(&replay_key, retain_until).await?;
        if !fresh {
            return Err(S2sError::ReplayDetected);
        }

        let remote_x25519_public = ed25519_pk_to_x25519_pk(&remote_key.ed25519_public)?;
        Ok(S2sDecryptedRequest {
            headers: headers.clone(),
            canonical_api: canonical_api.to_string(),
            plaintext,
            authenticated_from_did: headers.from.did.clone(),
            authenticated_from_fingerprint: remote_fp,
            local_key_fingerprint: local_key.fingerprint,
            remote_x25519_public,
        })
    }

    /// 生成与 request nonce 绑定的加密 response(§8.5)。
    ///
    /// - From/To 逐字节回显 request 的 To/From(不补全 key id);
    /// - 沿用本次 request 实际解密成功的 key pair;
    /// - 使用独立 response 派生 key 与新的随机 nonce。
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
            // 逐字节对调回显
            from: request.headers.to.clone(),
            to: request.headers.from.clone(),
            issued_at,
            expires_at,
            in_reply_to: request.headers.nonce,
            nonce,
        };

        let aad = build_response_aad(
            response_headers.version,
            &response_headers.from.to_wire_string(),
            &response_headers.to.to_wire_string(),
            &request.canonical_api,
            issued_at,
            expires_at,
            &request.headers.nonce,
        );

        // response 沿用实际解密成功的 key pair(即使默认 key 在 handler
        // 执行期间发生轮换)
        let local_candidates = self.local.provider().local_key_candidates().await?;
        let local_key = local_candidates
            .iter()
            .find(|c| c.fingerprint == request.local_key_fingerprint)
            .cloned()
            .ok_or_else(|| S2sError::KeyNotFound("local key rotated away mid-request".to_string()))?;

        let cache_key = DerivedKeyCacheKey {
            version: S2S_PROFILE_VERSION,
            from_did: self.local.service_did().to_string(),
            from_fingerprint: local_key.fingerprint,
            to_did: request.authenticated_from_did.to_string(),
            to_fingerprint: request.authenticated_from_fingerprint,
            kind: MessageKind::Response,
        };
        let key = match self.derived_cache.get(&cache_key, now) {
            Some(key) => key,
            None => {
                let shared = self
                    .local
                    .provider()
                    .diffie_hellman(&local_key.fingerprint, &request.remote_x25519_public)
                    .await?;
                let key = derive_aead_key(
                    &shared,
                    self.local.service_did(),
                    &local_key.fingerprint,
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

/// JSON 嵌套深度(§11.5 depth limit 用)。
pub fn json_value_depth(value: &Value) -> usize {
    match value {
        Value::Array(items) => 1 + items.iter().map(json_value_depth).max().unwrap_or(0),
        Value::Object(map) => 1 + map.values().map(json_value_depth).max().unwrap_or(0),
        _ => 1,
    }
}

pub struct S2sRpcServerContextBuilder {
    service_appid: String,
    current_zone_did: DID,
    key_source: Option<S2sLocalKeySource>,
    peer_resolver: Option<Arc<dyn S2sPeerKeyResolver>>,
    replay_store: Option<Arc<dyn S2sReplayStore>>,
    policy: Option<S2sServerSecurityPolicy>,
    api_registry: Option<Arc<dyn S2sApiRegistry>>,
    derived_cache: Option<DerivedKeyCache>,
    skip_local_key_binding_check: bool,
}

impl S2sRpcServerContextBuilder {
    /// 显式传入 Ed25519 私钥(mode=file 场景)。
    pub fn explicit_ed25519_key(mut self, key: SecretEd25519Key) -> Self {
        self.key_source = Some(S2sLocalKeySource::ExplicitEd25519 { key, key_id: None });
        self
    }

    pub fn explicit_ed25519_key_with_id(mut self, key: SecretEd25519Key, key_id: impl Into<String>) -> Self {
        self.key_source = Some(S2sLocalKeySource::ExplicitEd25519 {
            key,
            key_id: Some(key_id.into()),
        });
        self
    }

    /// 注入 key-agreement provider(Identity Manager 实现在 name-client)。
    pub fn key_agreement_provider(mut self, provider: Arc<dyn S2sKeyAgreementProvider>) -> Self {
        self.key_source = Some(S2sLocalKeySource::Provider { provider });
        self
    }

    pub fn peer_key_resolver(mut self, resolver: Arc<dyn S2sPeerKeyResolver>) -> Self {
        self.peer_resolver = Some(resolver);
        self
    }

    /// 覆盖默认的每进程 replay store(多实例生产环境必须换共享 backend)。
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

    /// unsafe:跳过本地 key 与 service DID 的 verified binding 校验
    /// (测试/引导阶段用)。
    pub fn unsafe_skip_local_key_binding_check(mut self) -> Self {
        self.skip_local_key_binding_check = true;
        self
    }

    pub async fn build(self) -> S2sResult<S2sRpcServerContext> {
        let policy = self.policy.unwrap_or_default();
        policy.validate()?;
        let key_source = self.key_source.ok_or_else(|| {
            S2sError::InvalidConfig(
                "encrypted mode requires a local key source (explicit key or provider)".to_string(),
            )
        })?;
        let peer_resolver = self.peer_resolver.ok_or_else(|| {
            S2sError::InvalidConfig("peer key resolver is required".to_string())
        })?;
        // 默认:每进程内存 replay store(单实例)。多实例必须显式注入共享 store。
        let replay_store = self
            .replay_store
            .unwrap_or_else(|| Arc::new(MemoryReplayStore::with_default_capacity()));

        let config = S2sLocalIdentityConfig::new(self.service_appid, self.current_zone_did, key_source);
        let binding = if self.skip_local_key_binding_check {
            LocalKeyBindingCheck::UnsafeSkip
        } else {
            LocalKeyBindingCheck::VerifyAgainst(peer_resolver.as_ref())
        };
        let local = config.resolve(binding).await?;

        Ok(S2sRpcServerContext {
            local,
            policy: RwLock::new(Arc::new(policy)),
            peer_resolver,
            replay_store,
            derived_cache: self.derived_cache.unwrap_or_else(DerivedKeyCache::with_defaults),
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
