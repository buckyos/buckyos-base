//! canonical length-prefixed encoder(§7.2/§8.4 冻结规则)与 nonce codec。
//!
//! 编码规则(协议的一部分,与测试向量一起冻结):
//! - 字符串与 byte string:`u32 big-endian length || bytes`(字符串取 UTF-8 bytes);
//! - 整数:固定宽度 big-endian,不带长度前缀(`version`=u32,`iat`/`exp`=u64);
//! - `canonical_sort`:按每个 `(service_did, key_fingerprint)` 元组 encode 后的
//!   字节字典序升序排序。
//!
//! 不依赖 JSON field order、调试字符串或平台默认字符编码。

use super::error::{S2sError, S2sResult};
use super::{S2S_NONCE_B64_LEN, S2S_NONCE_LEN};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use rand_core::{OsRng, RngCore};

/// canonical length-prefixed encoder。
pub struct CanonicalEncoder {
    buf: Vec<u8>,
}

impl CanonicalEncoder {
    /// 以 domain separation 字符串开头的 encoder(等价于 `encode(domain, ...)`)。
    pub fn with_domain(domain: &str) -> Self {
        let mut enc = Self::new();
        enc.put_str(domain);
        enc
    }

    pub fn new() -> Self {
        CanonicalEncoder { buf: Vec::new() }
    }

    pub fn put_str(&mut self, s: &str) -> &mut Self {
        self.put_bytes(s.as_bytes())
    }

    pub fn put_bytes(&mut self, b: &[u8]) -> &mut Self {
        debug_assert!(b.len() <= u32::MAX as usize);
        self.buf.extend_from_slice(&(b.len() as u32).to_be_bytes());
        self.buf.extend_from_slice(b);
        self
    }

    /// 固定宽度 u32 big-endian,不带长度前缀。
    pub fn put_u32(&mut self, v: u32) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }

    /// 固定宽度 u64 big-endian,不带长度前缀。
    pub fn put_u64(&mut self, v: u64) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }

    pub fn finish(self) -> Vec<u8> {
        self.buf
    }
}

/// 把一个 `(service_did, key_fingerprint)` 元组 encode 成排序比较用的字节串。
pub fn encode_peer_tuple(service_did: &str, key_fingerprint: &[u8; 32]) -> Vec<u8> {
    let mut enc = CanonicalEncoder::new();
    enc.put_str(service_did);
    enc.put_bytes(key_fingerprint);
    enc.finish()
}

/// `canonical_sort`:按 encode 后字节字典序升序返回两个 peer 元组。
pub fn canonical_sort_peers<'a>(
    a: (&'a str, &'a [u8; 32]),
    b: (&'a str, &'a [u8; 32]),
) -> ((&'a str, &'a [u8; 32]), (&'a str, &'a [u8; 32])) {
    if encode_peer_tuple(a.0, a.1) <= encode_peer_tuple(b.0, b.1) {
        (a, b)
    } else {
        (b, a)
    }
}

/// 从 OS CSPRNG 生成 24-byte nonce(§5.1:不使用用户态自维护 PRNG 状态)。
pub fn generate_nonce() -> [u8; S2S_NONCE_LEN] {
    let mut nonce = [0u8; S2S_NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

/// nonce → Base64URL without padding(24 bytes 恰好 32 chars,无尾随位歧义)。
pub fn encode_nonce(nonce: &[u8; S2S_NONCE_LEN]) -> String {
    URL_SAFE_NO_PAD.encode(nonce)
}

/// Base64URL no-padding → 恰好 24 bytes 的 nonce;其余一律拒绝。
pub fn decode_nonce(s: &str) -> S2sResult<[u8; S2S_NONCE_LEN]> {
    if s.len() != S2S_NONCE_B64_LEN {
        return Err(S2sError::InvalidHeader {
            name: "nonce".to_string(),
            reason: format!("length must be {} chars", S2S_NONCE_B64_LEN),
        });
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(s.as_bytes())
        .map_err(|e| S2sError::InvalidHeader {
            name: "nonce".to_string(),
            reason: format!("invalid base64url: {}", e),
        })?;
    decoded
        .try_into()
        .map_err(|_| S2sError::InvalidHeader {
            name: "nonce".to_string(),
            reason: "decoded length must be 24 bytes".to_string(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_encoder_layout_is_frozen() {
        let mut enc = CanonicalEncoder::with_domain("d");
        enc.put_str("ab");
        enc.put_bytes(&[0xff]);
        enc.put_u32(1);
        enc.put_u64(2);
        let out = enc.finish();
        assert_eq!(
            out,
            vec![
                0, 0, 0, 1, b'd', // domain: len=1 "d"
                0, 0, 0, 2, b'a', b'b', // "ab"
                0, 0, 0, 1, 0xff, // bytes [0xff]
                0, 0, 0, 1, // u32(1) fixed width
                0, 0, 0, 0, 0, 0, 0, 2, // u64(2) fixed width
            ]
        );
    }

    #[test]
    fn canonical_sort_is_byte_lexicographic_on_encoded_tuples() {
        let fp_a = [0u8; 32];
        let fp_b = [1u8; 32];
        // 相同 did,按 fingerprint 排序
        let (first, second) = canonical_sort_peers(("did:web:x", &fp_b), ("did:web:x", &fp_a));
        assert_eq!(first.1, &fp_a);
        assert_eq!(second.1, &fp_b);
        // did 靠长度前缀排序:短 did 的 length 前缀更小
        let (first, _second) =
            canonical_sort_peers(("did:web:bb", &fp_a), ("did:web:a", &fp_b));
        assert_eq!(first.0, "did:web:a");
        // 顺序与参数顺序无关
        let (f1, s1) = canonical_sort_peers(("did:web:a", &fp_a), ("did:web:b", &fp_b));
        let (f2, s2) = canonical_sort_peers(("did:web:b", &fp_b), ("did:web:a", &fp_a));
        assert_eq!((f1.0, s1.0), (f2.0, s2.0));
    }

    #[test]
    fn nonce_roundtrip_and_strictness() {
        let nonce = generate_nonce();
        let encoded = encode_nonce(&nonce);
        assert_eq!(encoded.len(), S2S_NONCE_B64_LEN);
        assert_eq!(decode_nonce(&encoded).unwrap(), nonce);

        // 长度错误
        assert!(decode_nonce("AAAA").is_err());
        // padding 拒绝
        assert!(decode_nonce(&format!("{}==", &encoded[..30])).is_err());
        // 非法字符
        assert!(decode_nonce(&format!("{}+", &encoded[..31])).is_err());

        // 两次生成不同(CSPRNG 冒烟)
        assert_ne!(generate_nonce(), generate_nonce());
    }
}
