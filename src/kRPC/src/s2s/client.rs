//! 客户端 S2S 传输引擎。
//!
//! Local default key comes only from standard IdentityRoots. Remote default key comes from the
//! shared Provider-first cache, with NameClient used only after explicit NotManaged.

use super::aad::{build_request_aad, build_response_aad};
use super::codec::generate_nonce;
use super::error::{S2sError, S2sResult};
use super::headers::{
    validate_time_window, S2sRequestHeaders, S2sResponseHeaders, TimeWindowPolicy,
};
use super::identity::{
    RemoteDefaultKey, RemoteIdentitySnapshot, S2sLocalIdentity, S2sLocalKeySnapshot,
    S2sRemoteIdentityHandle, S2sRemoteIdentityMetricsSnapshot, S2sRuntime,
};
use super::keys::{
    derive_aead_key, ed25519_pk_to_x25519_pk, DerivedKeyCache, DerivedKeyCacheKey, MessageKind,
};
use super::provider::S2sPublicKeyProvider;
use super::{S2S_DEFAULT_MAX_LIFETIME_SECS, S2S_PROFILE_VERSION};
use name_client::ResolveSourcePolicy;
use name_lib::{parse_canonical_did, DID};
use std::sync::Arc;
use zeroize::Zeroizing;

/// 客户端 S2S 配置：只有 local DID 与 remote DID 是身份输入。
pub struct S2sClientConfig {
    pub local_service_did: DID,
    pub remote_service_did: DID,
    runtime: Option<S2sRuntime>,
    public_key_provider: Option<Arc<dyn S2sPublicKeyProvider>>,
    allow_system_name_client_fallback: bool,
    /// 生成的请求 lifetime（秒）；默认 300。
    pub message_lifetime_secs: u64,
    /// 接受响应的时间窗策略。
    pub response_window: TimeWindowPolicy,
}

impl std::fmt::Debug for S2sClientConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S2sClientConfig")
            .field("local_service_did", &self.local_service_did.to_string())
            .field("remote_service_did", &self.remote_service_did.to_string())
            .field("message_lifetime_secs", &self.message_lifetime_secs)
            .finish_non_exhaustive()
    }
}

impl S2sClientConfig {
    pub fn new(local_service_did: DID, remote_service_did: DID) -> Self {
        Self {
            local_service_did,
            remote_service_did,
            runtime: None,
            public_key_provider: None,
            allow_system_name_client_fallback: false,
            message_lifetime_secs: S2S_DEFAULT_MAX_LIFETIME_SECS,
            response_window: TimeWindowPolicy::default(),
        }
    }

    /// 测试/嵌入场景注入独立 roots 与 NameClient。
    pub fn with_runtime(mut self, runtime: S2sRuntime) -> Self {
        self.runtime = Some(runtime);
        self
    }

    /// Strong cluster construction: Provider is installed before any remote key is loaded.
    pub fn for_cluster(
        local_service_did: DID,
        remote_service_did: DID,
        public_key_provider: Arc<dyn S2sPublicKeyProvider>,
    ) -> Self {
        Self::new(local_service_did, remote_service_did)
            .with_public_key_provider(public_key_provider)
    }

    /// Explicit generic/non-cluster mode. This is never selected implicitly.
    pub fn with_system_name_client_fallback(mut self) -> Self {
        self.allow_system_name_client_fallback = true;
        self
    }

    /// 安装按 target DID 查询产品确定性配置 snapshot 的公钥 Provider。
    /// Provider 命中时不会访问 NameClient。
    pub fn with_public_key_provider(
        mut self,
        public_key_provider: Arc<dyn S2sPublicKeyProvider>,
    ) -> Self {
        self.public_key_provider = Some(public_key_provider);
        self
    }
}

/// 一次已发送请求的上下文，响应校验与 in-flight local key snapshot 用。
pub struct S2sPendingRequest {
    pub headers: S2sRequestHeaders,
    pub canonical_api: String,
    local_key: S2sLocalKeySnapshot,
    remote_fingerprint: [u8; 32],
    remote_x25519_public: [u8; 32],
}

impl S2sPendingRequest {
    /// Fingerprint of the remote public key used to seal this request.
    pub fn remote_fingerprint(&self) -> [u8; 32] {
        self.remote_fingerprint
    }
}

#[derive(Clone, Copy)]
enum RemoteKeyRetry {
    None,
    RefreshCurrent,
    FailedFingerprint([u8; 32]),
}

/// 客户端传输引擎（解析后的不可变身份 + 可 reload 当前 local key）。
pub struct S2sClientTransport {
    local: S2sLocalIdentity,
    remote_did: DID,
    remote_identity: S2sRemoteIdentityHandle,
    derived_cache: DerivedKeyCache,
    lifetime_secs: u64,
    response_window: TimeWindowPolicy,
}

impl S2sClientTransport {
    pub async fn new(config: S2sClientConfig) -> S2sResult<Self> {
        if config.message_lifetime_secs == 0
            || config.message_lifetime_secs > super::S2S_HARD_MAX_LIFETIME_SECS
        {
            return Err(S2sError::InvalidConfig(format!(
                "message_lifetime_secs must be 1..={}",
                super::S2S_HARD_MAX_LIFETIME_SECS
            )));
        }
        parse_canonical_did(&config.local_service_did.to_string())
            .map_err(|err| S2sError::InvalidDid(err.to_string()))?;
        parse_canonical_did(&config.remote_service_did.to_string())
            .map_err(|err| S2sError::InvalidDid(err.to_string()))?;

        let runtime = match (config.runtime, config.public_key_provider) {
            (Some(runtime), Some(provider)) => runtime.with_public_key_provider(provider),
            (Some(runtime), None) => runtime,
            (None, Some(provider)) => {
                S2sRuntime::system_provider_with_name_client_fallback(provider)?
            }
            (None, None) if config.allow_system_name_client_fallback => {
                S2sRuntime::system_name_client_fallback()?
            }
            (None, None) => {
                return Err(S2sError::InvalidConfig(
                    "S2S client requires a cluster Provider, an injected runtime, or explicit \
                     system NameClient fallback"
                        .to_string(),
                ))
            }
        };
        // Validate and load local private material before performing any remote lookup.
        let local = S2sLocalIdentity::load(config.local_service_did, runtime.clone())?;
        let remote_identity = runtime.remote_identity_handle(&config.remote_service_did)?;
        // 固定 target 的公钥在 transport 构造阶段只加载一次，request 热路径
        // 只读取内存快照。
        remote_identity
            .snapshot(ResolveSourcePolicy::BestAvailable)
            .await?;
        Ok(Self {
            local,
            remote_did: config.remote_service_did,
            remote_identity,
            derived_cache: DerivedKeyCache::with_defaults(),
            lifetime_secs: config.message_lifetime_secs,
            response_window: config.response_window,
        })
    }

    pub fn local_service_did(&self) -> &DID {
        self.local.service_did()
    }

    pub fn remote_service_did(&self) -> &DID {
        &self.remote_did
    }

    pub async fn remote_identity_snapshot(&self) -> S2sResult<RemoteIdentitySnapshot> {
        let (snapshot, retired) = self
            .remote_identity
            .snapshot(ResolveSourcePolicy::BestAvailable)
            .await?;
        if let Some(retired) = retired {
            self.derived_cache.invalidate_fingerprint(&retired);
        }
        Ok(snapshot.as_ref().clone())
    }

    pub fn remote_identity_metrics(&self) -> S2sRemoteIdentityMetricsSnapshot {
        self.local.runtime().remote_identity_metrics()
    }

    /// 重新读取标准 local identity 文件；新请求只使用新 key。
    pub fn reload_local_identity(&self) -> S2sResult<bool> {
        if let Some(retired) = self.local.reload()? {
            self.derived_cache.invalidate_fingerprint(&retired);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// 重新读取 Provider（优先）或 NameClient fallback，并原子替换 target key。
    pub async fn reload_remote_identity(&self) -> S2sResult<bool> {
        let (changed, retired, _) = self
            .remote_identity
            .reload(ResolveSourcePolicy::RemoteAuthority)
            .await?;
        if let Some(retired) = retired {
            self.derived_cache.invalidate_fingerprint(&retired);
        }
        Ok(changed)
    }

    /// 加密一次请求。refresh=true 只用于 kRPC 的一次有界 authority retry，
    /// 每次调用都会生成 fresh nonce。
    pub async fn seal_request(
        &self,
        canonical_api: &str,
        request_json: &[u8],
        now: u64,
        refresh_remote_key: bool,
    ) -> S2sResult<(S2sRequestHeaders, Vec<u8>, S2sPendingRequest)> {
        let retry = if refresh_remote_key {
            RemoteKeyRetry::RefreshCurrent
        } else {
            RemoteKeyRetry::None
        };
        self.seal_request_inner(canonical_api, request_json, now, retry)
            .await
    }

    /// Retries after a request failed with the exact remote key fingerprint recorded in
    /// `S2sPendingRequest`. A generation update observed before this call already satisfies the
    /// refresh requirement; otherwise the authority is refreshed once.
    pub async fn seal_request_after_remote_key_failure(
        &self,
        canonical_api: &str,
        request_json: &[u8],
        now: u64,
        failed_fingerprint: [u8; 32],
    ) -> S2sResult<(S2sRequestHeaders, Vec<u8>, S2sPendingRequest)> {
        self.seal_request_inner(
            canonical_api,
            request_json,
            now,
            RemoteKeyRetry::FailedFingerprint(failed_fingerprint),
        )
        .await
    }

    async fn seal_request_inner(
        &self,
        canonical_api: &str,
        request_json: &[u8],
        now: u64,
        retry: RemoteKeyRetry,
    ) -> S2sResult<(S2sRequestHeaders, Vec<u8>, S2sPendingRequest)> {
        let (mut remote_key, retired) = self
            .remote_identity
            .snapshot(ResolveSourcePolicy::BestAvailable)
            .await?;
        if let Some(retired) = retired {
            self.derived_cache.invalidate_fingerprint(&retired);
        }

        let failed_fingerprint = match retry {
            RemoteKeyRetry::None => None,
            RemoteKeyRetry::RefreshCurrent => Some(remote_key.fingerprint),
            RemoteKeyRetry::FailedFingerprint(fingerprint) => Some(fingerprint),
        };
        if failed_fingerprint == Some(remote_key.fingerprint) {
            let Some(refreshed) = self
                .remote_identity
                .refresh_after_failure(remote_key.as_ref())
                .await?
            else {
                return Err(S2sError::RemoteKeyUnchanged);
            };
            if Some(refreshed.fingerprint) == failed_fingerprint {
                return Err(S2sError::RemoteKeyUnchanged);
            }
            self.derived_cache
                .invalidate_fingerprint(&remote_key.fingerprint);
            remote_key = refreshed;
        }
        let local_key = self.local.current_key_snapshot();
        let issued_at = now;
        let expires_at = now + self.lifetime_secs;
        let nonce = generate_nonce();
        let headers = S2sRequestHeaders {
            version: S2S_PROFILE_VERSION,
            from: self.local.service_did().clone(),
            to: self.remote_did.clone(),
            issued_at,
            expires_at,
            nonce,
        };

        let aad = build_request_aad(
            headers.version,
            &headers.from.to_string(),
            &headers.to.to_string(),
            canonical_api,
            issued_at,
            expires_at,
        );
        let key = self.request_key(&local_key, &remote_key, now).await?;
        let sealed = super::seal::aead_seal(&key, &nonce, &aad, request_json)?;
        let pending = S2sPendingRequest {
            headers: headers.clone(),
            canonical_api: canonical_api.to_string(),
            local_key,
            remote_fingerprint: remote_key.fingerprint,
            remote_x25519_public: ed25519_pk_to_x25519_pk(&remote_key.ed25519_public)?,
        };
        Ok((headers, sealed, pending))
    }

    async fn request_key(
        &self,
        local_key: &S2sLocalKeySnapshot,
        remote_key: &RemoteDefaultKey,
        now: u64,
    ) -> S2sResult<Zeroizing<[u8; 32]>> {
        let cache_key = DerivedKeyCacheKey {
            version: S2S_PROFILE_VERSION,
            from_did: self.local.service_did().to_string(),
            from_fingerprint: local_key.fingerprint,
            to_did: self.remote_did.to_string(),
            to_fingerprint: remote_key.fingerprint,
            kind: MessageKind::Request,
        };
        if let Some(key) = self.derived_cache.get(&cache_key, now) {
            return Ok(key);
        }
        let peer_x25519 = ed25519_pk_to_x25519_pk(&remote_key.ed25519_public)?;
        let shared = local_key.diffie_hellman(&peer_x25519)?;
        let key = derive_aead_key(
            &shared,
            self.local.service_did(),
            &local_key.fingerprint,
            &self.remote_did,
            &remote_key.fingerprint,
            MessageKind::Request,
        );
        self.derived_cache.put(cache_key, key.clone(), now);
        Ok(key)
    }

    /// 校验并解密响应；From/To 必须逐字节回显 request 的 To/From。
    pub async fn open_response(
        &self,
        pending: &S2sPendingRequest,
        response_headers: &S2sResponseHeaders,
        body: &[u8],
        now: u64,
    ) -> S2sResult<Vec<u8>> {
        if response_headers.from.to_string() != pending.headers.to.to_string() {
            return Err(S2sError::WrongPeer(
                "response From does not echo request To".to_string(),
            ));
        }
        if response_headers.to.to_string() != pending.headers.from.to_string() {
            return Err(S2sError::WrongPeer(
                "response To does not echo request From".to_string(),
            ));
        }
        if response_headers.in_reply_to != pending.headers.nonce {
            return Err(S2sError::WrongKind);
        }
        validate_time_window(
            response_headers.issued_at,
            response_headers.expires_at,
            now,
            &self.response_window,
        )?;
        let aad = build_response_aad(
            response_headers.version,
            &response_headers.from.to_string(),
            &response_headers.to.to_string(),
            &pending.canonical_api,
            response_headers.issued_at,
            response_headers.expires_at,
            &pending.headers.nonce,
        );

        let cache_key = DerivedKeyCacheKey {
            version: S2S_PROFILE_VERSION,
            from_did: self.remote_did.to_string(),
            from_fingerprint: pending.remote_fingerprint,
            to_did: self.local.service_did().to_string(),
            to_fingerprint: pending.local_key.fingerprint,
            kind: MessageKind::Response,
        };
        let key = match self.derived_cache.get(&cache_key, now) {
            Some(key) => key,
            None => {
                let shared = pending
                    .local_key
                    .diffie_hellman(&pending.remote_x25519_public)?;
                let key = derive_aead_key(
                    &shared,
                    &self.remote_did,
                    &pending.remote_fingerprint,
                    self.local.service_did(),
                    &pending.local_key.fingerprint,
                    MessageKind::Response,
                );
                self.derived_cache.put(cache_key, key.clone(), now);
                key
            }
        };
        super::seal::aead_open(&key, &response_headers.nonce, &aad, body)
    }
}
