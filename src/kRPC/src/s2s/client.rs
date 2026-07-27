//! 客户端 S2S 传输引擎(§11.1/Phase 3)。
//!
//! - 发送前取得 verified target key,生成 S2S Header 与 binary Body;
//! - 失败后**绝不**降级明文;
//! - 响应必须通过 From/To 回显、`In-Reply-To`、时间窗、AEAD 与内部 seq 校验;
//! - 解密失败/未知 key 时,调用方(`kRPC`)可显式 refresh key 后用**新 nonce**
//!   重试一次,不做无界重试。

use super::aad::{build_request_aad, build_response_aad};
use super::codec::generate_nonce;
use super::error::{S2sError, S2sResult};
use super::headers::{
    validate_time_window, S2sRequestHeaders, S2sResponseHeaders, TimeWindowPolicy,
};
use super::identity::{LocalKeyBindingCheck, S2sLocalIdentity, S2sLocalIdentityConfig};
use super::keys::{
    derive_aead_key, ed25519_pk_to_x25519_pk, DerivedKeyCache, DerivedKeyCacheKey, MessageKind,
    S2sLocalKeyHandle,
};
use super::peer::S2sPeerKeyResolver;
use super::service_key_ref::ServiceKeyRef;
use super::{S2S_DEFAULT_MAX_LIFETIME_SECS, S2S_PROFILE_VERSION};
use name_lib::DID;
use std::sync::Arc;
use zeroize::Zeroizing;

/// 目标公钥来源。
///
/// 取得 target public key 是关键安全行为。**推荐 `Pinned`**:调用方把
/// verified service descriptor(§12)中已经验证过的
/// `(target_service_did, target_service_public_key)` 作为确定值直接交给
/// transport,发送路径不再有任何隐式解析;验证责任明确落在产出 descriptor
/// 的服务发现层。`Resolver` 保留给确实需要在线轮换发现的动态部署。
pub enum S2sRemoteKeySource {
    /// 确定值:目标 service 的 Ed25519 公钥(32 bytes),与
    /// `remote_service_did` 的绑定由调用方持有的 verified evidence 保证。
    /// 构造 transport 时即校验公钥有效性(无效/small-order 直接失败)。
    Pinned { ed25519_public: [u8; 32] },
    /// 经 `S2sPeerKeyResolver` 动态解析已验证 key(解密失败时支持一次
    /// 显式 refresh 重试)。
    Resolver { resolver: Arc<dyn S2sPeerKeyResolver> },
}

impl std::fmt::Debug for S2sRemoteKeySource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            S2sRemoteKeySource::Pinned { ed25519_public } => f
                .debug_struct("Pinned")
                .field("ed25519_public", &hex::encode(ed25519_public))
                .finish(),
            S2sRemoteKeySource::Resolver { .. } => f.write_str("Resolver(..)"),
        }
    }
}

/// 客户端 S2S 配置。
pub struct S2sClientConfig {
    pub local_identity: S2sLocalIdentityConfig,
    pub remote_service_did: DID,
    /// 显式指定对端 key id(写入 `KRPC-S2S-To` 的 `#key_id`);
    /// `None` 使用默认 active key。
    pub remote_key_id: Option<String>,
    pub remote_key_source: S2sRemoteKeySource,
    /// 生成的请求 lifetime(秒);默认 300。
    pub message_lifetime_secs: u64,
    /// 接受响应的时间窗策略。
    pub response_window: TimeWindowPolicy,
    /// unsafe:跳过本地 key 与派生 service DID 的 verified binding 校验。
    /// 仅 `Resolver` 模式有意义;`Pinned` 模式下双方绑定都由调用方的
    /// verified descriptor 断言(见 `S2sRemoteKeySource::Pinned`)。
    pub unsafe_skip_local_key_binding_check: bool,
}

impl S2sClientConfig {
    /// 推荐构造:目标 DID + 目标公钥都是调用方提供的确定值
    /// (来自 verified service descriptor,§12)。
    pub fn with_pinned_key(
        local_identity: S2sLocalIdentityConfig,
        remote_service_did: DID,
        remote_ed25519_public: [u8; 32],
    ) -> Self {
        Self::build(
            local_identity,
            remote_service_did,
            S2sRemoteKeySource::Pinned {
                ed25519_public: remote_ed25519_public,
            },
        )
    }

    /// 动态部署构造:目标公钥经 resolver 解析(resolver 必须只返回
    /// 已验证 key)。
    pub fn with_resolver(
        local_identity: S2sLocalIdentityConfig,
        remote_service_did: DID,
        peer_key_resolver: Arc<dyn S2sPeerKeyResolver>,
    ) -> Self {
        Self::build(
            local_identity,
            remote_service_did,
            S2sRemoteKeySource::Resolver {
                resolver: peer_key_resolver,
            },
        )
    }

    fn build(
        local_identity: S2sLocalIdentityConfig,
        remote_service_did: DID,
        remote_key_source: S2sRemoteKeySource,
    ) -> Self {
        S2sClientConfig {
            local_identity,
            remote_service_did,
            remote_key_id: None,
            remote_key_source,
            message_lifetime_secs: S2S_DEFAULT_MAX_LIFETIME_SECS,
            response_window: TimeWindowPolicy::default(),
            unsafe_skip_local_key_binding_check: false,
        }
    }
}

/// 一次已发送请求的上下文,响应校验用。
pub struct S2sPendingRequest {
    pub headers: S2sRequestHeaders,
    pub canonical_api: String,
    local_key: S2sLocalKeyHandle,
    remote_fingerprint: [u8; 32],
    remote_x25519_public: [u8; 32],
}

/// 客户端传输引擎(解析后的不可变状态)。
pub struct S2sClientTransport {
    local: S2sLocalIdentity,
    remote_did: DID,
    remote_key_id: Option<String>,
    remote_key_source: S2sRemoteKeySource,
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
        // Pinned key 在构造时即校验有效性(fail early,而不是首次 call 时)
        if let S2sRemoteKeySource::Pinned { ed25519_public } = &config.remote_key_source {
            ed25519_pk_to_x25519_pk(ed25519_public).map_err(|e| {
                S2sError::InvalidConfig(format!(
                    "pinned public key for {} is invalid: {}",
                    config.remote_service_did.to_string(),
                    e
                ))
            })?;
        }
        let binding = match (&config.remote_key_source, config.unsafe_skip_local_key_binding_check)
        {
            // Pinned 模式:双方 (did, key) 绑定都由调用方的 verified
            // descriptor 断言,本地无 evidence 源可查
            (S2sRemoteKeySource::Pinned { .. }, _) => LocalKeyBindingCheck::CallerAsserted,
            (S2sRemoteKeySource::Resolver { .. }, true) => LocalKeyBindingCheck::UnsafeSkip,
            (S2sRemoteKeySource::Resolver { resolver }, false) => {
                LocalKeyBindingCheck::VerifyAgainst(resolver.as_ref())
            }
        };
        let local = config.local_identity.resolve(binding).await?;
        Ok(S2sClientTransport {
            local,
            remote_did: config.remote_service_did,
            remote_key_id: config.remote_key_id,
            remote_key_source: config.remote_key_source,
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

    async fn resolve_remote_default_key(
        &self,
        refresh: bool,
    ) -> S2sResult<super::peer::VerifiedPeerKey> {
        let resolver = match &self.remote_key_source {
            // Pinned:确定值,refresh 无意义(重试仍用同一确定 key)
            S2sRemoteKeySource::Pinned { ed25519_public } => {
                return Ok(super::peer::VerifiedPeerKey {
                    key_id: self.remote_key_id.clone(),
                    ed25519_public: *ed25519_public,
                });
            }
            S2sRemoteKeySource::Resolver { resolver } => resolver,
        };
        let keys = if refresh {
            resolver
                .refresh_verified_keys(&self.remote_did, self.remote_key_id.as_deref())
                .await?
        } else {
            resolver
                .resolve_verified_keys(&self.remote_did, self.remote_key_id.as_deref())
                .await?
        };
        keys.into_iter().next().ok_or_else(|| {
            S2sError::KeyNotFound(format!(
                "no verified key for target {}",
                self.remote_did.to_string()
            ))
        })
    }

    /// 加密一次请求。`refresh_remote_key = true` 时先显式重新 resolve 目标 key
    /// 并失效对应派生 key cache(重试路径;必然使用新 nonce)。
    pub async fn seal_request(
        &self,
        canonical_api: &str,
        request_json: &[u8],
        now: u64,
        refresh_remote_key: bool,
    ) -> S2sResult<(S2sRequestHeaders, Vec<u8>, S2sPendingRequest)> {
        let remote_key = self.resolve_remote_default_key(refresh_remote_key).await?;
        let remote_fp = remote_key.fingerprint();
        if refresh_remote_key {
            self.derived_cache.invalidate_fingerprint(&remote_fp);
        }
        let local_candidates = self.local.provider().local_key_candidates().await?;
        let local_key = local_candidates
            .into_iter()
            .next()
            .ok_or_else(|| S2sError::KeyNotFound("no local key".to_string()))?;

        // 正常情况 Header 只写 service DID;显式 remote_key_id 时带 #key_id
        let from = ServiceKeyRef::new(self.local.service_did().clone());
        let to = match &self.remote_key_id {
            Some(kid) => ServiceKeyRef::with_key_id(self.remote_did.clone(), kid.clone())?,
            None => ServiceKeyRef::new(self.remote_did.clone()),
        };

        let issued_at = now;
        let expires_at = now + self.lifetime_secs;
        let nonce = generate_nonce();
        let headers = S2sRequestHeaders {
            version: S2S_PROFILE_VERSION,
            from,
            to,
            issued_at,
            expires_at,
            nonce,
        };

        let aad = build_request_aad(
            headers.version,
            &headers.from.to_wire_string(),
            &headers.to.to_wire_string(),
            canonical_api,
            issued_at,
            expires_at,
        );

        let key = self
            .request_key(&local_key, &remote_key, &remote_fp, now)
            .await?;
        let sealed = super::seal::aead_seal(&key, &nonce, &aad, request_json)?;

        let remote_x25519_public = ed25519_pk_to_x25519_pk(&remote_key.ed25519_public)?;
        let pending = S2sPendingRequest {
            headers: headers.clone(),
            canonical_api: canonical_api.to_string(),
            local_key,
            remote_fingerprint: remote_fp,
            remote_x25519_public,
        };
        Ok((headers, sealed, pending))
    }

    async fn request_key(
        &self,
        local_key: &S2sLocalKeyHandle,
        remote_key: &super::peer::VerifiedPeerKey,
        remote_fp: &[u8; 32],
        now: u64,
    ) -> S2sResult<Zeroizing<[u8; 32]>> {
        let cache_key = DerivedKeyCacheKey {
            version: S2S_PROFILE_VERSION,
            from_did: self.local.service_did().to_string(),
            from_fingerprint: local_key.fingerprint,
            to_did: self.remote_did.to_string(),
            to_fingerprint: *remote_fp,
            kind: MessageKind::Request,
        };
        if let Some(key) = self.derived_cache.get(&cache_key, now) {
            return Ok(key);
        }
        let peer_x25519 = ed25519_pk_to_x25519_pk(&remote_key.ed25519_public)?;
        let shared = self
            .local
            .provider()
            .diffie_hellman(&local_key.fingerprint, &peer_x25519)
            .await?;
        let key = derive_aead_key(
            &shared,
            self.local.service_did(),
            &local_key.fingerprint,
            &self.remote_did,
            remote_fp,
            MessageKind::Request,
        );
        self.derived_cache.put(cache_key, key.clone(), now);
        Ok(key)
    }

    /// 校验并解密响应(§8.5 客户端接受条件;内部 seq 校验由调用方完成)。
    pub async fn open_response(
        &self,
        pending: &S2sPendingRequest,
        response_headers: &S2sResponseHeaders,
        body: &[u8],
        now: u64,
    ) -> S2sResult<Vec<u8>> {
        // From/To 必须逐字节回显 request 的 To/From(比较 wire 字符串)
        if response_headers.from.to_wire_string() != pending.headers.to.to_wire_string() {
            return Err(S2sError::WrongPeer(
                "response From does not echo request To".to_string(),
            ));
        }
        if response_headers.to.to_wire_string() != pending.headers.from.to_wire_string() {
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
            &response_headers.from.to_wire_string(),
            &response_headers.to.to_wire_string(),
            &pending.canonical_api,
            response_headers.issued_at,
            response_headers.expires_at,
            &pending.headers.nonce,
        );

        // response key:from=remote(responder), to=local(caller)
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
                let shared = self
                    .local
                    .provider()
                    .diffie_hellman(&pending.local_key.fingerprint, &pending.remote_x25519_public)
                    .await?;
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
