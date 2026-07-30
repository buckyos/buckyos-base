//! kRPC S2S 的标准 DID runtime。
//!
//! S2S 不定义 app 身份或 key selector：本地只接收完整 DID，并从
//! `IdentityRoots` 的 exact `did.json + authentication.private.pem` 加载当前
//! 默认 key；远端只通过 `NameClient` 解析 DID document 的默认 authentication
//! Ed25519 key。

use super::error::{S2sError, S2sResult};
use super::keys::ed25519_key_fingerprint;
use name_client::{
    get_name_client, IdentityRoots, LocalEd25519IdentityKey, NameClient, ResolveSourcePolicy,
};
use name_lib::{parse_canonical_did, DID};
use std::sync::{Arc, RwLock};
use zeroize::Zeroizing;

#[derive(Clone)]
enum RuntimeNameClient {
    Global(&'static NameClient),
    Shared(Arc<NameClient>),
}

impl RuntimeNameClient {
    fn as_ref(&self) -> &NameClient {
        match self {
            Self::Global(client) => client,
            Self::Shared(client) => client.as_ref(),
        }
    }
}

/// S2S 运行时依赖。普通调用方使用系统默认 runtime；测试和嵌入场景可注入
/// 独立 `IdentityRoots` 与 `NameClient` instance。
#[derive(Clone)]
pub struct S2sRuntime {
    roots: IdentityRoots,
    name_client: RuntimeNameClient,
}

impl std::fmt::Debug for S2sRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S2sRuntime")
            .field("identity_root", &self.roots.public_root)
            .field("security_root", &self.roots.security_root)
            .finish_non_exhaustive()
    }
}

impl S2sRuntime {
    pub fn system() -> S2sResult<Self> {
        let roots = IdentityRoots::from_env_or_buckyos_root().map_err(map_identity_error)?;
        let name_client = get_name_client().ok_or_else(|| {
            S2sError::InvalidConfig(
                "NameClient is not initialized; initialize name-client before S2S".to_string(),
            )
        })?;
        Ok(Self {
            roots,
            name_client: RuntimeNameClient::Global(name_client),
        })
    }

    pub fn new(roots: IdentityRoots, name_client: Arc<NameClient>) -> Self {
        Self {
            roots,
            name_client: RuntimeNameClient::Shared(name_client),
        }
    }

    fn load_local_key(&self, did: &DID) -> S2sResult<Arc<LocalEd25519IdentityKey>> {
        validate_did(did)?;
        self.roots
            .load_default_ed25519_private_key(did)
            .map(Arc::new)
            .map_err(map_identity_error)
    }

    pub(crate) async fn resolve_remote_key(
        &self,
        did: &DID,
        source: ResolveSourcePolicy,
    ) -> S2sResult<RemoteDefaultKey> {
        validate_did(did)?;
        let ed25519_public = self
            .name_client
            .as_ref()
            .resolve_default_ed25519_key(did, source)
            .await
            .map_err(map_identity_error)?;
        // 在进入 request path 前拒绝无效/small-order key。
        super::keys::ed25519_pk_to_x25519_pk(&ed25519_public)?;
        Ok(RemoteDefaultKey::new(ed25519_public))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RemoteDefaultKey {
    pub ed25519_public: [u8; 32],
    pub fingerprint: [u8; 32],
}

impl RemoteDefaultKey {
    fn new(ed25519_public: [u8; 32]) -> Self {
        Self {
            fingerprint: ed25519_key_fingerprint(&ed25519_public),
            ed25519_public,
        }
    }
}

/// 一次请求持有的本地默认 key 快照。`Arc` 保证 reload 只影响新请求；旧 key
/// 在最后一个 in-flight snapshot 释放时随 `LocalEd25519IdentityKey` 清零。
#[derive(Clone)]
pub(crate) struct S2sLocalKeySnapshot {
    key: Arc<LocalEd25519IdentityKey>,
    pub ed25519_public: [u8; 32],
    pub fingerprint: [u8; 32],
}

impl std::fmt::Debug for S2sLocalKeySnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S2sLocalKeySnapshot")
            .field("fingerprint", &hex::encode(self.fingerprint))
            .finish_non_exhaustive()
    }
}

impl S2sLocalKeySnapshot {
    fn new(key: Arc<LocalEd25519IdentityKey>) -> Self {
        let ed25519_public = key.public_key();
        Self {
            fingerprint: ed25519_key_fingerprint(&ed25519_public),
            ed25519_public,
            key,
        }
    }

    pub fn diffie_hellman(&self, peer_x25519_public: &[u8; 32]) -> S2sResult<Zeroizing<[u8; 32]>> {
        self.key
            .diffie_hellman_x25519(peer_x25519_public)
            .map_err(map_identity_error)
    }
}

struct S2sLocalIdentityInner {
    service_did: DID,
    runtime: S2sRuntime,
    current_key: RwLock<Arc<LocalEd25519IdentityKey>>,
}

/// 已解析的本地普通 DID 身份。
#[derive(Clone)]
pub(crate) struct S2sLocalIdentity {
    inner: Arc<S2sLocalIdentityInner>,
}

impl std::fmt::Debug for S2sLocalIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S2sLocalIdentity")
            .field("service_did", &self.inner.service_did.to_string())
            .finish_non_exhaustive()
    }
}

impl S2sLocalIdentity {
    pub fn load(service_did: DID, runtime: S2sRuntime) -> S2sResult<Self> {
        validate_did(&service_did)?;
        let current_key = runtime.load_local_key(&service_did)?;
        Ok(Self {
            inner: Arc::new(S2sLocalIdentityInner {
                service_did,
                runtime,
                current_key: RwLock::new(current_key),
            }),
        })
    }

    pub fn service_did(&self) -> &DID {
        &self.inner.service_did
    }

    pub fn runtime(&self) -> &S2sRuntime {
        &self.inner.runtime
    }

    pub fn current_key_snapshot(&self) -> S2sLocalKeySnapshot {
        S2sLocalKeySnapshot::new(self.inner.current_key.read().unwrap().clone())
    }

    /// 原子替换当前默认 key。没有 active/grace candidate list；旧 key 只由
    /// 已经开始的请求 snapshot 持有。
    pub fn reload(&self) -> S2sResult<Option<[u8; 32]>> {
        let new_key = self.inner.runtime.load_local_key(self.service_did())?;
        let new_public = new_key.public_key();
        let mut current = self.inner.current_key.write().unwrap();
        if current.public_key() == new_public {
            return Ok(None);
        }
        let retired = ed25519_key_fingerprint(&current.public_key());
        *current = new_key;
        Ok(Some(retired))
    }
}

fn validate_did(did: &DID) -> S2sResult<()> {
    parse_canonical_did(&did.to_string())
        .map(|_| ())
        .map_err(|err| S2sError::InvalidDid(err.to_string()))
}

pub(crate) fn map_identity_error(err: name_lib::NSError) -> S2sError {
    let message = err.to_string();
    if message.contains("KeyAgreementNotSupported") {
        S2sError::KeyAgreementNotSupported(message)
    } else {
        S2sError::InvalidConfig(message)
    }
}
