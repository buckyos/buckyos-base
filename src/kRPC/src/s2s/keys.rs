//! 密钥类型、Ed25519→X25519 转换、fingerprint、HKDF 派生与派生 key cache。
//!
//! 冻结规则(§6.5/§7):
//! - Ed25519 private 输入是 **raw 32-byte seed**(PKCS#8 只作为容器解出 seed;
//!   expanded secret 不作为输入);
//! - seed → X25519 static secret:`SHA-512(seed)[0..32]` 加 clamp
//!   (与 libsodium `crypto_sign_ed25519_sk_to_curve25519` 一致);
//! - Ed25519 public → X25519 public:Edwards 解压 → Montgomery u
//!   (与 libsodium `crypto_sign_ed25519_pk_to_curve25519` 一致);
//!   无效编码与 small-order 公钥拒绝;
//! - X25519 DH 输出必须拒绝 all-zero(non-contributory);
//! - key fingerprint = `SHA-256(encode("buckyos.krpc.s2s.v1/ed25519-key", pk))`;
//! - AEAD key = HKDF-SHA-256,salt/info 绑定 domain、双方 (did, fingerprint)、
//!   方向与 message kind。

use super::codec::{canonical_sort_peers, CanonicalEncoder};
use super::error::{S2sError, S2sResult};
use super::{S2S_DOMAIN_AEAD_KEY, S2S_DOMAIN_ED25519_KEY, S2S_DOMAIN_KDF_SALT};
use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use hkdf::Hkdf;
use name_lib::DID;
use sha2::{Digest, Sha256, Sha512};
use std::collections::HashMap;
use std::collections::VecDeque;
use std::sync::Mutex;
use zeroize::{Zeroize, Zeroizing};

/// request 与 response 使用不同派生 key,防止方向反射(§7.2)。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MessageKind {
    Request,
    Response,
}

impl MessageKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            MessageKind::Request => "request",
            MessageKind::Response => "response",
        }
    }
}

/// raw Ed25519 私钥(32-byte seed)。
///
/// - 不实现 `Debug`(内容)、`Display`、`Serialize`、`Clone`;
/// - drop 时 zeroize。
pub struct SecretEd25519Key {
    seed: [u8; 32],
}

impl Drop for SecretEd25519Key {
    fn drop(&mut self) {
        self.seed.zeroize();
    }
}

impl std::fmt::Debug for SecretEd25519Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretEd25519Key(<redacted>)")
    }
}

impl SecretEd25519Key {
    pub fn from_seed(seed: [u8; 32]) -> Self {
        SecretEd25519Key { seed }
    }

    /// 从 PKCS#8 PEM(`-----BEGIN PRIVATE KEY-----`)解出 Ed25519 seed。
    pub fn from_pkcs8_pem(pem: &str) -> S2sResult<Self> {
        let start = pem.find("-----BEGIN PRIVATE KEY-----");
        let end = pem.find("-----END PRIVATE KEY-----");
        let (Some(start), Some(end)) = (start, end) else {
            return Err(S2sError::PrivateKeyNotUsableForS2s(
                "not a PKCS#8 PRIVATE KEY pem".to_string(),
            ));
        };
        let b64: String = pem[start + "-----BEGIN PRIVATE KEY-----".len()..end]
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        let der = BASE64_STANDARD
            .decode(b64)
            .map_err(|e| S2sError::PrivateKeyNotUsableForS2s(format!("pem base64: {}", e)))?;
        let seed = name_lib::from_pkcs8(&der).map_err(|e| {
            S2sError::PrivateKeyNotUsableForS2s(format!("not an Ed25519 PKCS#8 key: {}", e))
        })?;
        Ok(SecretEd25519Key { seed })
    }

    /// Ed25519 公钥(32 bytes)。
    pub fn public_key(&self) -> [u8; 32] {
        let sk = ed25519_dalek::SigningKey::from_bytes(&self.seed);
        sk.verifying_key().to_bytes()
    }

    /// libsodium 兼容的 X25519 static secret:`SHA-512(seed)[0..32]` + clamp。
    pub(crate) fn x25519_static_secret(&self) -> Zeroizing<[u8; 32]> {
        let mut h = Sha512::digest(&self.seed);
        let mut out = Zeroizing::new([0u8; 32]);
        out.copy_from_slice(&h[..32]);
        out[0] &= 248;
        out[31] &= 127;
        out[31] |= 64;
        h.zeroize();
        out
    }
}

/// Ed25519 public key → X25519 public key(Montgomery u)。
///
/// 拒绝无法解压的编码与 small-order(weak)公钥。
pub fn ed25519_pk_to_x25519_pk(ed25519_public: &[u8; 32]) -> S2sResult<[u8; 32]> {
    let vk = ed25519_dalek::VerifyingKey::from_bytes(ed25519_public)
        .map_err(|_| S2sError::InvalidKey("invalid ed25519 public key encoding".to_string()))?;
    if vk.is_weak() {
        return Err(S2sError::InvalidKey(
            "small-order ed25519 public key".to_string(),
        ));
    }
    Ok(vk.to_montgomery().to_bytes())
}

/// 冻结的 key fingerprint 规则(§7.2):
/// `SHA-256(encode("buckyos.krpc.s2s.v1/ed25519-key", ed25519_public_key))`。
pub fn ed25519_key_fingerprint(ed25519_public: &[u8; 32]) -> [u8; 32] {
    let mut enc = CanonicalEncoder::with_domain(S2S_DOMAIN_ED25519_KEY);
    enc.put_bytes(ed25519_public);
    let digest = Sha256::digest(enc.finish());
    digest.into()
}

/// 用 Ed25519 私钥直接执行 static-static X25519 DH(provider 实现用;
/// 内部先做 libsodium 兼容的 seed→X25519 转换,不导出中间私钥)。
pub fn ed25519_static_diffie_hellman(
    local_key: &SecretEd25519Key,
    peer_x25519_public: &[u8; 32],
) -> S2sResult<Zeroizing<[u8; 32]>> {
    let x_secret = local_key.x25519_static_secret();
    x25519_diffie_hellman(&x_secret, peer_x25519_public)
}

/// X25519 static-static DH,拒绝 all-zero(non-contributory)输出。
pub fn x25519_diffie_hellman(
    local_x25519_secret: &[u8; 32],
    peer_x25519_public: &[u8; 32],
) -> S2sResult<Zeroizing<[u8; 32]>> {
    let secret = x25519_dalek::StaticSecret::from(*local_x25519_secret);
    let public = x25519_dalek::PublicKey::from(*peer_x25519_public);
    let shared = secret.diffie_hellman(&public);
    if !shared.was_contributory() {
        return Err(S2sError::InvalidKey(
            "non-contributory x25519 shared secret".to_string(),
        ));
    }
    Ok(Zeroizing::new(shared.to_bytes()))
}

/// 方向化 AEAD key 派生(§7.2 冻结):
///
/// ```text
/// ordered = canonical_sort((from_did, from_fp), (to_did, to_fp))
/// salt = SHA256(encode("buckyos.krpc.s2s.v1/kdf-salt", ordered...))
/// prk  = HKDF-Extract(salt, shared_secret)
/// key  = HKDF-Expand(prk, encode("buckyos.krpc.s2s.v1/aead-key",
///                    from_did, from_fp, to_did, to_fp, kind), 32)
/// ```
pub fn derive_aead_key(
    shared_secret: &[u8; 32],
    from_service_did: &DID,
    from_key_fingerprint: &[u8; 32],
    to_service_did: &DID,
    to_key_fingerprint: &[u8; 32],
    kind: MessageKind,
) -> Zeroizing<[u8; 32]> {
    let from_did_str = from_service_did.to_string();
    let to_did_str = to_service_did.to_string();

    let (peer_a, peer_b) = canonical_sort_peers(
        (from_did_str.as_str(), from_key_fingerprint),
        (to_did_str.as_str(), to_key_fingerprint),
    );
    let mut salt_enc = CanonicalEncoder::with_domain(S2S_DOMAIN_KDF_SALT);
    salt_enc.put_str(peer_a.0);
    salt_enc.put_bytes(peer_a.1);
    salt_enc.put_str(peer_b.0);
    salt_enc.put_bytes(peer_b.1);
    let salt: [u8; 32] = Sha256::digest(salt_enc.finish()).into();

    let hk = Hkdf::<Sha256>::new(Some(&salt), shared_secret);
    let mut info_enc = CanonicalEncoder::with_domain(S2S_DOMAIN_AEAD_KEY);
    info_enc.put_str(&from_did_str);
    info_enc.put_bytes(from_key_fingerprint);
    info_enc.put_str(&to_did_str);
    info_enc.put_bytes(to_key_fingerprint);
    info_enc.put_str(kind.as_str());
    let info = info_enc.finish();

    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(&info, okm.as_mut())
        .expect("hkdf expand 32 bytes cannot fail");
    okm
}

/// 本地密钥候选(active first,grace newest first;fingerprint 唯一标识)。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct S2sLocalKeyHandle {
    /// 显式 key id;`None` 表示默认 active key。
    pub key_id: Option<String>,
    pub ed25519_public: [u8; 32],
    pub fingerprint: [u8; 32],
}

impl S2sLocalKeyHandle {
    pub fn from_public(key_id: Option<String>, ed25519_public: [u8; 32]) -> Self {
        let fingerprint = ed25519_key_fingerprint(&ed25519_public);
        S2sLocalKeyHandle {
            key_id,
            ed25519_public,
            fingerprint,
        }
    }
}

/// key agreement capability(§6.3):
/// 用指定 local key 与 peer X25519 public key 派生 shared secret。
///
/// - 不向调用方返回 raw private key,兼容 file、TPM/HSM/TEE 或独立 key agent;
/// - 只支持 sign 的 provider 必须返回 `KeyAgreementNotSupported`,
///   不得导出或伪造私钥;
/// - `local_key_candidates` 返回有界候选:active first、grace newest first。
#[async_trait]
pub trait S2sKeyAgreementProvider: Send + Sync {
    async fn local_key_candidates(&self) -> S2sResult<Vec<S2sLocalKeyHandle>>;

    /// 以 fingerprint 指定本地 key(fingerprint 是 KDF/cache 的 key commitment)。
    async fn diffie_hellman(
        &self,
        local_key_fingerprint: &[u8; 32],
        peer_x25519_public: &[u8; 32],
    ) -> S2sResult<Zeroizing<[u8; 32]>>;
}

/// 显式传入 Ed25519 私钥的 provider(mode=file / 测试用)。
pub struct ExplicitEd25519Provider {
    key: SecretEd25519Key,
    handle: S2sLocalKeyHandle,
}

impl ExplicitEd25519Provider {
    pub fn new(key: SecretEd25519Key, key_id: Option<String>) -> Self {
        let public = key.public_key();
        let handle = S2sLocalKeyHandle::from_public(key_id, public);
        ExplicitEd25519Provider { key, handle }
    }

    pub fn handle(&self) -> &S2sLocalKeyHandle {
        &self.handle
    }
}

#[async_trait]
impl S2sKeyAgreementProvider for ExplicitEd25519Provider {
    async fn local_key_candidates(&self) -> S2sResult<Vec<S2sLocalKeyHandle>> {
        Ok(vec![self.handle.clone()])
    }

    async fn diffie_hellman(
        &self,
        local_key_fingerprint: &[u8; 32],
        peer_x25519_public: &[u8; 32],
    ) -> S2sResult<Zeroizing<[u8; 32]>> {
        if local_key_fingerprint != &self.handle.fingerprint {
            return Err(S2sError::KeyNotFound(
                "local key fingerprint does not match".to_string(),
            ));
        }
        let x_secret = self.key.x25519_static_secret();
        x25519_diffie_hellman(&x_secret, peer_x25519_public)
    }
}

/// 派生 key cache 的 key(§6.6:绑定 profile version、双方 did 与实际参与
/// DH 的 key fingerprint、message kind)。
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DerivedKeyCacheKey {
    pub version: u32,
    pub from_did: String,
    pub from_fingerprint: [u8; 32],
    pub to_did: String,
    pub to_fingerprint: [u8; 32],
    pub kind: MessageKind,
}

struct DerivedKeyEntry {
    key: Zeroizing<[u8; 32]>,
    expires_at: u64,
}

struct DerivedKeyCacheInner {
    map: HashMap<DerivedKeyCacheKey, DerivedKeyEntry>,
    order: VecDeque<DerivedKeyCacheKey>,
}

/// 有界、可失效、evict 即 drop(`Zeroizing` 清零)的派生 key cache。
pub struct DerivedKeyCache {
    inner: Mutex<DerivedKeyCacheInner>,
    capacity: usize,
    ttl_secs: u64,
}

pub const S2S_DEFAULT_DERIVED_KEY_CACHE_CAPACITY: usize = 1024;
pub const S2S_DEFAULT_DERIVED_KEY_TTL_SECS: u64 = 3600;

impl DerivedKeyCache {
    pub fn new(capacity: usize, ttl_secs: u64) -> Self {
        DerivedKeyCache {
            inner: Mutex::new(DerivedKeyCacheInner {
                map: HashMap::new(),
                order: VecDeque::new(),
            }),
            capacity: capacity.max(1),
            ttl_secs: ttl_secs.max(1),
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(
            S2S_DEFAULT_DERIVED_KEY_CACHE_CAPACITY,
            S2S_DEFAULT_DERIVED_KEY_TTL_SECS,
        )
    }

    pub fn get(&self, key: &DerivedKeyCacheKey, now: u64) -> Option<Zeroizing<[u8; 32]>> {
        let inner = self.inner.lock().unwrap();
        inner.map.get(key).and_then(|entry| {
            if entry.expires_at > now {
                Some(entry.key.clone())
            } else {
                None
            }
        })
    }

    pub fn put(&self, key: DerivedKeyCacheKey, value: Zeroizing<[u8; 32]>, now: u64) {
        let mut inner = self.inner.lock().unwrap();
        while inner.map.len() >= self.capacity {
            let Some(oldest) = inner.order.pop_front() else {
                break;
            };
            inner.map.remove(&oldest);
        }
        inner.order.push_back(key.clone());
        inner.map.insert(
            key,
            DerivedKeyEntry {
                key: value,
                expires_at: now + self.ttl_secs,
            },
        );
    }

    /// key retire 时按 fingerprint 主动失效(§6.6/§14)。
    pub fn invalidate_fingerprint(&self, fingerprint: &[u8; 32]) {
        let mut inner = self.inner.lock().unwrap();
        inner.map.retain(|k, _| {
            k.from_fingerprint != *fingerprint && k.to_fingerprint != *fingerprint
        });
        let map = &inner.map;
        let retained: VecDeque<DerivedKeyCacheKey> = inner
            .order
            .iter()
            .filter(|k| map.contains_key(*k))
            .cloned()
            .collect();
        inner.order = retained;
    }

    pub fn clear(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.map.clear();
        inner.order.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_seed(fill: u8) -> [u8; 32] {
        [fill; 32]
    }

    #[test]
    fn ed25519_to_x25519_matches_reference_impl() {
        // 独立实现交叉验证:ed25519_to_curve25519 crate(libsodium 语义)
        for fill in [1u8, 7, 42, 200] {
            let seed = test_seed(fill);
            let key = SecretEd25519Key::from_seed(seed);
            let public = key.public_key();

            let ours_sk = key.x25519_static_secret();
            let reference_sk = ed25519_to_curve25519::ed25519_sk_to_curve25519(seed);
            assert_eq!(*ours_sk, reference_sk, "sk conversion mismatch");

            let ours_pk = ed25519_pk_to_x25519_pk(&public).unwrap();
            let reference_pk = ed25519_to_curve25519::ed25519_pk_to_curve25519(public);
            assert_eq!(ours_pk, reference_pk, "pk conversion mismatch");
        }
    }

    #[test]
    fn x25519_static_static_dh_agrees_both_ways() {
        let a = SecretEd25519Key::from_seed(test_seed(3));
        let b = SecretEd25519Key::from_seed(test_seed(9));
        let a_pub_x = ed25519_pk_to_x25519_pk(&a.public_key()).unwrap();
        let b_pub_x = ed25519_pk_to_x25519_pk(&b.public_key()).unwrap();

        let s1 = x25519_diffie_hellman(&a.x25519_static_secret(), &b_pub_x).unwrap();
        let s2 = x25519_diffie_hellman(&b.x25519_static_secret(), &a_pub_x).unwrap();
        assert_eq!(*s1, *s2);
    }

    #[test]
    fn rejects_invalid_and_small_order_public_keys() {
        // 非法编码:y=2 无法解压为曲线点
        let mut invalid = [0u8; 32];
        invalid[0] = 2;
        assert!(ed25519_pk_to_x25519_pk(&invalid).is_err());
        // small-order 点:identity(y=1,order 1)
        let mut small_order = [0u8; 32];
        small_order[0] = 1;
        assert!(ed25519_pk_to_x25519_pk(&small_order).is_err());
        // small-order 点:y=0(order 4)
        let zero = [0u8; 32];
        assert!(ed25519_pk_to_x25519_pk(&zero).is_err());
    }

    #[test]
    fn dh_rejects_non_contributory_all_zero_output() {
        let a = SecretEd25519Key::from_seed(test_seed(3));
        // Montgomery all-zero 公钥 → all-zero shared secret → 必须拒绝
        let zero_public = [0u8; 32];
        let err = x25519_diffie_hellman(&a.x25519_static_secret(), &zero_public).unwrap_err();
        assert!(matches!(err, S2sError::InvalidKey(_)));
    }

    #[test]
    fn fingerprint_is_domain_separated_sha256() {
        let pk = [5u8; 32];
        let fp = ed25519_key_fingerprint(&pk);
        // 独立重算
        let mut manual = Vec::new();
        let domain = S2S_DOMAIN_ED25519_KEY.as_bytes();
        manual.extend_from_slice(&(domain.len() as u32).to_be_bytes());
        manual.extend_from_slice(domain);
        manual.extend_from_slice(&32u32.to_be_bytes());
        manual.extend_from_slice(&pk);
        let expected: [u8; 32] = Sha256::digest(&manual).into();
        assert_eq!(fp, expected);
        // 不等于裸 SHA256(pk)
        let bare: [u8; 32] = Sha256::digest(&pk).into();
        assert_ne!(fp, bare);
    }

    #[test]
    fn derived_keys_are_directional_and_kind_separated() {
        let a = SecretEd25519Key::from_seed(test_seed(3));
        let b = SecretEd25519Key::from_seed(test_seed(9));
        let a_did = DID::new("web", "a.example.com");
        let b_did = DID::new("web", "b.example.com");
        let a_fp = ed25519_key_fingerprint(&a.public_key());
        let b_fp = ed25519_key_fingerprint(&b.public_key());
        let b_pub_x = ed25519_pk_to_x25519_pk(&b.public_key()).unwrap();
        let ss = x25519_diffie_hellman(&a.x25519_static_secret(), &b_pub_x).unwrap();

        let req_ab = derive_aead_key(&ss, &a_did, &a_fp, &b_did, &b_fp, MessageKind::Request);
        let resp_ba = derive_aead_key(&ss, &b_did, &b_fp, &a_did, &a_fp, MessageKind::Response);
        let req_ba = derive_aead_key(&ss, &b_did, &b_fp, &a_did, &a_fp, MessageKind::Request);
        let resp_ab = derive_aead_key(&ss, &a_did, &a_fp, &b_did, &b_fp, MessageKind::Response);

        // request/response 不同;A→B 与 B→A 不同
        assert_ne!(*req_ab, *resp_ba);
        assert_ne!(*req_ab, *req_ba);
        assert_ne!(*resp_ab, *resp_ba);
        assert_ne!(*req_ab, *resp_ab);

        // 双方独立计算一致(B 侧同样输入得到同 key)
        let a_pub_x = ed25519_pk_to_x25519_pk(&a.public_key()).unwrap();
        let ss_b = x25519_diffie_hellman(&b.x25519_static_secret(), &a_pub_x).unwrap();
        let req_ab_from_b =
            derive_aead_key(&ss_b, &a_did, &a_fp, &b_did, &b_fp, MessageKind::Request);
        assert_eq!(*req_ab, *req_ab_from_b);
    }

    #[test]
    fn frozen_test_vector_conversion_and_kdf() {
        // 冻结测试向量(协议 v1;实现变更导致此测试失败 = wire 不兼容):
        // seed_a = 0x01..0x20, seed_b = 0x65..0x84
        let seed: [u8; 32] = (1..=32u8).collect::<Vec<u8>>().try_into().unwrap();
        let key = SecretEd25519Key::from_seed(seed);
        let public = key.public_key();
        assert_eq!(
            hex::encode(public),
            "79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664"
        );
        let x_sk = key.x25519_static_secret();
        assert_eq!(
            hex::encode(*x_sk),
            "70788f1a0cea001a2631dae5d05dbd062008d5b30f50b9e29beb2a7822289044"
        );
        let x_pk = ed25519_pk_to_x25519_pk(&public).unwrap();
        assert_eq!(
            hex::encode(x_pk),
            "4a3807d064d077181cc070989e76891d20dca5559548dc2c77c1a50273882b38"
        );
        let fp = ed25519_key_fingerprint(&public);
        assert_eq!(
            hex::encode(fp),
            "00af8fe7c090e59d3de4b66132bc1eb9dc2985a9a59c2a86911ab0cc91ef5e68"
        );

        // DH + 方向化 KDF 全链路冻结向量
        let seed_b: [u8; 32] = (101..=132u8).collect::<Vec<u8>>().try_into().unwrap();
        let key_b = SecretEd25519Key::from_seed(seed_b);
        let pub_b = key_b.public_key();
        assert_eq!(
            hex::encode(pub_b),
            "da29e95b02e00ffa15645775fb1d2ba222a1943395eea06b94e2c057b7be69d0"
        );
        let fp_b = ed25519_key_fingerprint(&pub_b);
        let x_pk_b = ed25519_pk_to_x25519_pk(&pub_b).unwrap();
        let ss = x25519_diffie_hellman(&key.x25519_static_secret(), &x_pk_b).unwrap();
        assert_eq!(
            hex::encode(*ss),
            "f4220c7019c0ae5bb8011a5058e871f1166b777d2903d5c3a4793d9a9b084940"
        );
        let a_did = DID::new("web", "event-producer.example.com");
        let b_did = DID::new("web", "event-service.example.com");
        let req_key = derive_aead_key(&ss, &a_did, &fp, &b_did, &fp_b, MessageKind::Request);
        assert_eq!(
            hex::encode(*req_key),
            "85f37fd3431b9f0786677071575079edad9c0805a00b6b96806bd302b6f83d12"
        );
        let resp_key = derive_aead_key(&ss, &b_did, &fp_b, &a_did, &fp, MessageKind::Response);
        assert_eq!(
            hex::encode(*resp_key),
            "0d2db6552e77ef21f19d3261ffbec202e883c64baaed7a23ffa9ae8d9ebe4714"
        );
    }

    #[test]
    fn derived_key_cache_bounded_ttl_and_invalidate() {
        let cache = DerivedKeyCache::new(2, 100);
        let mk = |fp: u8, kind: MessageKind| DerivedKeyCacheKey {
            version: 1,
            from_did: "did:web:a".to_string(),
            from_fingerprint: [fp; 32],
            to_did: "did:web:b".to_string(),
            to_fingerprint: [0xbb; 32],
            kind,
        };
        let k1 = mk(1, MessageKind::Request);
        let k2 = mk(2, MessageKind::Request);
        let k3 = mk(3, MessageKind::Request);
        cache.put(k1.clone(), Zeroizing::new([1u8; 32]), 0);
        cache.put(k2.clone(), Zeroizing::new([2u8; 32]), 0);
        assert!(cache.get(&k1, 10).is_some());
        // TTL 过期
        assert!(cache.get(&k1, 101).is_none());
        // 容量驱逐最老
        cache.put(k3.clone(), Zeroizing::new([3u8; 32]), 0);
        assert!(cache.get(&k1, 10).is_none());
        assert!(cache.get(&k2, 10).is_some());
        assert!(cache.get(&k3, 10).is_some());
        // 按 fingerprint 失效
        cache.invalidate_fingerprint(&[2u8; 32]);
        assert!(cache.get(&k2, 10).is_none());
        assert!(cache.get(&k3, 10).is_some());
    }

    #[tokio::test]
    async fn explicit_provider_dh_and_candidates() {
        let key = SecretEd25519Key::from_seed(test_seed(3));
        let peer = SecretEd25519Key::from_seed(test_seed(9));
        let peer_x = ed25519_pk_to_x25519_pk(&peer.public_key()).unwrap();
        let provider = ExplicitEd25519Provider::new(key, None);
        let candidates = provider.local_key_candidates().await.unwrap();
        assert_eq!(candidates.len(), 1);
        let ss = provider
            .diffie_hellman(&candidates[0].fingerprint, &peer_x)
            .await
            .unwrap();
        assert_ne!(*ss, [0u8; 32]);
        // 错误 fingerprint 拒绝
        assert!(provider.diffie_hellman(&[0u8; 32], &peer_x).await.is_err());
    }

    #[test]
    fn pkcs8_pem_roundtrip() {
        let (pem, jwk) = name_lib::generate_ed25519_key_pair();
        let key = SecretEd25519Key::from_pkcs8_pem(&pem).unwrap();
        let x = jwk.get("x").unwrap().as_str().unwrap();
        let expected = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(x)
            .unwrap();
        assert_eq!(key.public_key().to_vec(), expected);
        assert!(SecretEd25519Key::from_pkcs8_pem("not a pem").is_err());
    }
}
