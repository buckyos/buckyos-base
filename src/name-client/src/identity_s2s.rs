//! Identity Manager 支撑的 kRPC S2S key provider
//! (doc/krpc-s2s-payload-encryption-TODO.md §6.3/§6.6)。
//!
//! 按 `authentication.keyref.json` 协议加载本地 active Ed25519 私钥,并实现
//! kRPC 定义的 `S2sKeyAgreementProvider`:
//!
//! ```text
//! canonical service DID -> IdentityRoots -> security root
//!   -> authentication.keyref.json -> authentication.private.pem  # mode=file
//! ```
//!
//! 校验规则:
//! - keyref 的 `did` 必须等于 canonical service DID;
//! - `usage` 必须是 `authentication`(不得误用 Server 的 TLS key);
//! - `algorithm` 必须是 `Ed25519`;
//! - `public_key_fingerprint` 必须与实际加载的公钥一致
//!   (接受 `sha256:` 前缀,对 raw 32-byte pk 或 SPKI DER 计算,大小写不敏感);
//! - 仅 `mode=file` + `exportable` 的 keyref 能执行 X25519 DH;
//!   signer/remote keyref 只有 sign capability,返回
//!   `KeyAgreementNotSupported`,不导出或伪造私钥。
//!
//! 轮换(§6.6):Identity Manager active path 只保存当前 active material;
//! `reload()` 发现 key 变更时把旧 active key 作为内存 grace candidate 保留到
//! 期限后丢弃(drop 即 zeroize)。进程在 grace period 内重启且 provisioner
//! 未提供旧 key 时,旧请求会失败,client 应 refresh target key 后有界重试。

use crate::identity_mgr::{IdentityMaterial, IdentityRoots, IdentityUsage, KeyAccess};
use async_trait::async_trait;
use kRPC::s2s::{
    ed25519_static_diffie_hellman, S2sError, S2sKeyAgreementProvider, S2sLocalKeyHandle,
    S2sResult, SecretEd25519Key, Zeroizing,
};
use name_lib::{NSError, NSResult, DID};
use sha2::{Digest, Sha256};
use std::sync::{Arc, RwLock};

/// grace key 默认保留时间:覆盖最大 request lifetime(300s)、clock skew(60s)
/// 与一次有界重试窗口。
pub const S2S_DEFAULT_GRACE_PERIOD_SECS: u64 = 600;

struct LoadedS2sKey {
    secret: SecretEd25519Key,
    handle: S2sLocalKeyHandle,
}

struct ProviderState {
    active: Arc<LoadedS2sKey>,
    /// (key, 保留截止时间);newest first。
    grace: Vec<(Arc<LoadedS2sKey>, u64)>,
}

/// Identity Manager file-mode keyref 支撑的 S2S key provider。
pub struct IdentityManagerS2sKeyProvider {
    roots: IdentityRoots,
    service_did: DID,
    grace_period_secs: u64,
    state: RwLock<ProviderState>,
}

impl std::fmt::Debug for IdentityManagerS2sKeyProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdentityManagerS2sKeyProvider")
            .field("service_did", &self.service_did.to_string())
            .finish_non_exhaustive()
    }
}

impl IdentityManagerS2sKeyProvider {
    /// 加载 `service_did` 的 active authentication key。
    pub fn load(roots: IdentityRoots, service_did: DID) -> NSResult<Self> {
        Self::load_with_grace_period(roots, service_did, S2S_DEFAULT_GRACE_PERIOD_SECS)
    }

    pub fn load_with_grace_period(
        roots: IdentityRoots,
        service_did: DID,
        grace_period_secs: u64,
    ) -> NSResult<Self> {
        let active = load_authentication_key(&roots, &service_did)?;
        Ok(IdentityManagerS2sKeyProvider {
            roots,
            service_did,
            grace_period_secs,
            state: RwLock::new(ProviderState {
                active: Arc::new(active),
                grace: Vec::new(),
            }),
        })
    }

    pub fn service_did(&self) -> &DID {
        &self.service_did
    }

    /// active key 的 fingerprint(context/监控用)。
    pub fn active_fingerprint(&self) -> [u8; 32] {
        self.state.read().unwrap().active.handle.fingerprint
    }

    /// 重新加载 active key(Identity Manager 轮换后调用)。
    ///
    /// key 发生变更时,旧 active key 进入内存 grace 集合,保留
    /// `grace_period_secs` 后在下次访问时丢弃(drop 即 zeroize)。
    /// 返回 `(changed, retired_fingerprint)`;调用方应在 retire 时同步失效
    /// 派生 key cache(`S2sRpcServerContext::invalidate_key_fingerprint`)。
    pub fn reload(&self) -> NSResult<(bool, Option<[u8; 32]>)> {
        let new_active = load_authentication_key(&self.roots, &self.service_did)?;
        let now = buckyos_kit::buckyos_get_unix_timestamp();
        let mut state = self.state.write().unwrap();
        if state.active.handle.fingerprint == new_active.handle.fingerprint {
            return Ok((false, None));
        }
        let retired = state.active.clone();
        let retired_fp = retired.handle.fingerprint;
        state
            .grace
            .insert(0, (retired, now + self.grace_period_secs));
        state.active = Arc::new(new_active);
        // 清理已过期 grace key
        state.grace.retain(|(_, until)| *until > now);
        Ok((true, Some(retired_fp)))
    }
}

#[async_trait]
impl S2sKeyAgreementProvider for IdentityManagerS2sKeyProvider {
    async fn local_key_candidates(&self) -> S2sResult<Vec<S2sLocalKeyHandle>> {
        let now = buckyos_kit::buckyos_get_unix_timestamp();
        let state = self.state.read().unwrap();
        // active first、grace newest first(已按插入序保持 newest first)
        let mut candidates = vec![state.active.handle.clone()];
        for (key, until) in &state.grace {
            if *until > now {
                candidates.push(key.handle.clone());
            }
        }
        Ok(candidates)
    }

    async fn diffie_hellman(
        &self,
        local_key_fingerprint: &[u8; 32],
        peer_x25519_public: &[u8; 32],
    ) -> S2sResult<Zeroizing<[u8; 32]>> {
        let now = buckyos_kit::buckyos_get_unix_timestamp();
        let key = {
            let state = self.state.read().unwrap();
            if state.active.handle.fingerprint == *local_key_fingerprint {
                Some(state.active.clone())
            } else {
                state
                    .grace
                    .iter()
                    .find(|(key, until)| {
                        *until > now && key.handle.fingerprint == *local_key_fingerprint
                    })
                    .map(|(key, _)| key.clone())
            }
        };
        let Some(key) = key else {
            return Err(S2sError::KeyNotFound(
                "no active/grace key with this fingerprint".to_string(),
            ));
        };
        ed25519_static_diffie_hellman(&key.secret, peer_x25519_public)
    }
}

/// 按 keyref 协议加载并校验 authentication Ed25519 私钥。
fn load_authentication_key(roots: &IdentityRoots, service_did: &DID) -> NSResult<LoadedS2sKey> {
    let did_str = service_did.to_string();
    let keyref_match = roots.find_security_file(
        &did_str,
        IdentityUsage::Authentication,
        IdentityMaterial::KeyRef,
    )?;
    let keyref = roots.load_keyref(&keyref_match.path)?;

    // §6.3.4:必须校验 did、usage、algorithm 与 public_key_fingerprint
    if keyref.did != did_str {
        return Err(NSError::InvalidState(format!(
            "keyref did {} does not match service did {}",
            keyref.did, did_str
        )));
    }
    if keyref.usage != IdentityUsage::Authentication {
        return Err(NSError::InvalidState(format!(
            "keyref usage {} is not authentication",
            keyref.usage
        )));
    }
    if !keyref.algorithm.eq_ignore_ascii_case("ed25519") {
        return Err(NSError::InvalidState(format!(
            "keyref algorithm {} is not Ed25519",
            keyref.algorithm
        )));
    }

    // §6.3.5/6:仅 file mode 可做 X25519;sign-only keyref 不足以完成 DH
    let key_path = match &keyref.access {
        KeyAccess::File { path, .. } => {
            if !keyref.exportable {
                return Err(NSError::Failed(
                    "PrivateKeyNotUsableForS2s: file keyref is not exportable".to_string(),
                ));
            }
            path.clone()
        }
        KeyAccess::Signer { .. } | KeyAccess::RemoteMeta { .. } => {
            return Err(NSError::Failed(
                "KeyAgreementNotSupported: sign-only keyref cannot perform X25519 key agreement"
                    .to_string(),
            ));
        }
    };

    let pem = std::fs::read_to_string(&key_path).map_err(|err| {
        NSError::ReadLocalFileError(format!(
            "read private key {}: {}",
            key_path.display(),
            err
        ))
    })?;
    let secret = SecretEd25519Key::from_pkcs8_pem(&pem)
        .map_err(|err| NSError::Failed(format!("load private key: {}", err)))?;
    let public = secret.public_key();

    verify_keyref_fingerprint(&keyref.public_key_fingerprint, &public)?;

    let handle = S2sLocalKeyHandle::from_public(None, public);
    Ok(LoadedS2sKey { secret, handle })
}

/// 校验 keyref 声明的 fingerprint 与实际公钥一致。
///
/// 接受 `sha256:<hex>`(大小写不敏感),hash 输入接受两种编码:
/// raw 32-byte public key,或 Ed25519 SPKI DER。
fn verify_keyref_fingerprint(declared: &str, public_key: &[u8; 32]) -> NSResult<()> {
    let declared_hex = declared
        .strip_prefix("sha256:")
        .or_else(|| declared.strip_prefix("SHA256:"))
        .unwrap_or(declared)
        .to_ascii_lowercase();

    let raw_hash = hex::encode(Sha256::digest(public_key));
    // SPKI DER: SEQUENCE { SEQUENCE { OID 1.3.101.112 }, BIT STRING { pk } }
    let mut spki = Vec::with_capacity(44);
    spki.extend_from_slice(&[
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ]);
    spki.extend_from_slice(public_key);
    let spki_hash = hex::encode(Sha256::digest(&spki));

    if declared_hex == raw_hash || declared_hex == spki_hash {
        Ok(())
    } else {
        Err(NSError::InvalidState(format!(
            "keyref public_key_fingerprint mismatch: declared {} but loaded key is sha256:{} (raw) / sha256:{} (spki)",
            declared, raw_hash, spki_hash
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn write_identity(
        tmp: &tempfile::TempDir,
        service_did: &DID,
        seed: [u8; 32],
        fingerprint_style: &str,
    ) -> IdentityRoots {
        let roots = IdentityRoots::new(
            tmp.path().join("local").join("identity"),
            tmp.path().join("security"),
        );
        write_identity_with(&roots, service_did, seed, fingerprint_style, "file", true);
        roots
    }

    fn write_identity_with(
        roots: &IdentityRoots,
        service_did: &DID,
        seed: [u8; 32],
        fingerprint_style: &str,
        mode: &str,
        exportable: bool,
    ) {
        let secret = SecretEd25519Key::from_seed(seed);
        let public = secret.public_key();
        let fingerprint = match fingerprint_style {
            "raw" => format!("sha256:{}", hex::encode(Sha256::digest(&public))),
            "spki" => {
                let mut spki = vec![
                    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
                ];
                spki.extend_from_slice(&public);
                format!("sha256:{}", hex::encode(Sha256::digest(&spki)))
            }
            other => other.to_string(),
        };

        let dir: PathBuf = roots
            .security_dir(&service_did.to_string())
            .unwrap();
        std::fs::create_dir_all(&dir).unwrap();

        // PKCS#8 PEM
        let mut pkcs8 = vec![
            0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22,
            0x04, 0x20,
        ];
        pkcs8.extend_from_slice(&seed);
        let pem = format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &pkcs8)
        );
        let key_path = dir.join("authentication.private.pem");
        std::fs::write(&key_path, pem).unwrap();

        let reference = match mode {
            "file" => serde_json::json!({
                "type": "file",
                "path": key_path.to_string_lossy(),
                "format": "pkcs8-pem",
            }),
            "signer" => serde_json::json!({
                "type": "unix-socket",
                "endpoint": "/tmp/x.sock",
                "protocol": "buckyos-sign-v1",
            }),
            _ => panic!("bad mode"),
        };
        let keyref = serde_json::json!({
            "schema": "buckyos.identity.keyref.v1",
            "kind": "key",
            "did": service_did.to_string(),
            "usage": "authentication",
            "algorithm": "Ed25519",
            "public_key_fingerprint": fingerprint,
            "mode": mode,
            "exportable": exportable,
            "ref": reference,
        });
        std::fs::write(
            dir.join("authentication.keyref.json"),
            serde_json::to_string_pretty(&keyref).unwrap(),
        )
        .unwrap();
    }

    fn service_did() -> DID {
        DID::new("web", "event-service.example.com")
    }

    #[tokio::test]
    async fn load_and_dh_with_raw_and_spki_fingerprints() {
        for style in ["raw", "spki"] {
            let tmp = tempfile::tempdir().unwrap();
            let roots = write_identity(&tmp, &service_did(), [3u8; 32], style);
            let provider =
                IdentityManagerS2sKeyProvider::load(roots, service_did()).unwrap();
            let candidates = provider.local_key_candidates().await.unwrap();
            assert_eq!(candidates.len(), 1);
            assert_eq!(
                candidates[0].ed25519_public,
                SecretEd25519Key::from_seed([3u8; 32]).public_key()
            );

            // DH 正常工作
            let peer = SecretEd25519Key::from_seed([9u8; 32]);
            let peer_x =
                kRPC::s2s::ed25519_pk_to_x25519_pk(&peer.public_key()).unwrap();
            let ss = provider
                .diffie_hellman(&candidates[0].fingerprint, &peer_x)
                .await
                .unwrap();
            assert_ne!(*ss, [0u8; 32]);
        }
    }

    #[tokio::test]
    async fn fingerprint_mismatch_fails_at_load() {
        let tmp = tempfile::tempdir().unwrap();
        let roots = write_identity(&tmp, &service_did(), [3u8; 32], "sha256:deadbeef");
        assert!(IdentityManagerS2sKeyProvider::load(roots, service_did()).is_err());
    }

    #[tokio::test]
    async fn wrong_did_fails_at_load() {
        let tmp = tempfile::tempdir().unwrap();
        let roots = write_identity(&tmp, &service_did(), [3u8; 32], "raw");
        // 目录/文件是 event-service 的,但请求 other-service → NotFound
        assert!(IdentityManagerS2sKeyProvider::load(
            roots,
            DID::new("web", "other-service.example.com")
        )
        .is_err());
    }

    #[tokio::test]
    async fn sign_only_keyref_is_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let roots = IdentityRoots::new(
            tmp.path().join("local").join("identity"),
            tmp.path().join("security"),
        );
        write_identity_with(&roots, &service_did(), [3u8; 32], "raw", "signer", false);
        let err = IdentityManagerS2sKeyProvider::load(roots, service_did()).unwrap_err();
        assert!(err.to_string().contains("KeyAgreementNotSupported"));
    }

    #[tokio::test]
    async fn reload_moves_old_key_to_grace() {
        let tmp = tempfile::tempdir().unwrap();
        let roots = write_identity(&tmp, &service_did(), [3u8; 32], "raw");
        let provider = IdentityManagerS2sKeyProvider::load_with_grace_period(
            roots.clone(),
            service_did(),
            600,
        )
        .unwrap();
        let old_fp = provider.active_fingerprint();

        // 同 key reload → 无变化
        let (changed, retired) = provider.reload().unwrap();
        assert!(!changed);
        assert!(retired.is_none());
        assert_eq!(provider.local_key_candidates().await.unwrap().len(), 1);

        // 轮换成新 key
        write_identity_with(&roots, &service_did(), [7u8; 32], "raw", "file", true);
        let (changed, retired) = provider.reload().unwrap();
        assert!(changed);
        assert_eq!(retired, Some(old_fp));

        let candidates = provider.local_key_candidates().await.unwrap();
        assert_eq!(candidates.len(), 2);
        // active first(新 key),grace 其后(旧 key)
        assert_eq!(
            candidates[0].ed25519_public,
            SecretEd25519Key::from_seed([7u8; 32]).public_key()
        );
        assert_eq!(candidates[1].fingerprint, old_fp);

        // 新旧 key 都能 DH
        let peer = SecretEd25519Key::from_seed([9u8; 32]);
        let peer_x = kRPC::s2s::ed25519_pk_to_x25519_pk(&peer.public_key()).unwrap();
        assert!(provider
            .diffie_hellman(&candidates[0].fingerprint, &peer_x)
            .await
            .is_ok());
        assert!(provider
            .diffie_hellman(&candidates[1].fingerprint, &peer_x)
            .await
            .is_ok());
    }
}
