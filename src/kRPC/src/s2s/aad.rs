//! request / response AAD 构造(§8.4/§8.5 冻结字段表)。
//!
//! 关键规则:
//! - `canonical_from_key_ref` / `canonical_to_key_ref` **逐字节**使用 wire
//!   Header 规范化后的 `ServiceKeyRef` 字符串;sender 省略 `#key_id` 时 AAD
//!   同样不含 key id,receiver 不得把补全的 key id 写进 AAD;
//! - nonce 作为 AEAD nonce 参数传入,不复制进 AAD;
//! - response 的 from/to 逐字节等于 request 的 to/from;`in_reply_to` 是
//!   request nonce 的 raw 24 bytes(非 Base64URL 字符串);
//! - AAD 不绑定 IP、port、Host 或未知 Header。

use super::codec::CanonicalEncoder;
use super::{S2S_DOMAIN_AAD, S2S_NONCE_LEN};

/// request AAD:
/// `encode(domain, version, "request", "POST", from, to, api, iat, exp)`。
pub fn build_request_aad(
    version: u32,
    canonical_from_key_ref: &str,
    canonical_to_key_ref: &str,
    canonical_api_name: &str,
    issued_at: u64,
    expires_at: u64,
) -> Vec<u8> {
    let mut enc = CanonicalEncoder::with_domain(S2S_DOMAIN_AAD);
    enc.put_u32(version);
    enc.put_str("request");
    enc.put_str("POST");
    enc.put_str(canonical_from_key_ref);
    enc.put_str(canonical_to_key_ref);
    enc.put_str(canonical_api_name);
    enc.put_u64(issued_at);
    enc.put_u64(expires_at);
    enc.finish()
}

/// response AAD:
/// `encode(domain, version, "response", "POST", from, to, api, iat, exp, in_reply_to)`。
pub fn build_response_aad(
    version: u32,
    canonical_from_key_ref: &str,
    canonical_to_key_ref: &str,
    canonical_api_name: &str,
    issued_at: u64,
    expires_at: u64,
    in_reply_to: &[u8; S2S_NONCE_LEN],
) -> Vec<u8> {
    let mut enc = CanonicalEncoder::with_domain(S2S_DOMAIN_AAD);
    enc.put_u32(version);
    enc.put_str("response");
    enc.put_str("POST");
    enc.put_str(canonical_from_key_ref);
    enc.put_str(canonical_to_key_ref);
    enc.put_str(canonical_api_name);
    enc.put_u64(issued_at);
    enc.put_u64(expires_at);
    enc.put_bytes(in_reply_to);
    enc.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_aad_layout_is_frozen() {
        let aad = build_request_aad(1, "did:web:a", "did:web:b", "api-1", 10, 20);
        let mut expected = Vec::new();
        let put_str = |out: &mut Vec<u8>, s: &str| {
            out.extend_from_slice(&(s.len() as u32).to_be_bytes());
            out.extend_from_slice(s.as_bytes());
        };
        put_str(&mut expected, "buckyos.krpc.s2s.v1/aad");
        expected.extend_from_slice(&1u32.to_be_bytes());
        put_str(&mut expected, "request");
        put_str(&mut expected, "POST");
        put_str(&mut expected, "did:web:a");
        put_str(&mut expected, "did:web:b");
        put_str(&mut expected, "api-1");
        expected.extend_from_slice(&10u64.to_be_bytes());
        expected.extend_from_slice(&20u64.to_be_bytes());
        assert_eq!(aad, expected);
    }

    #[test]
    fn any_field_change_changes_aad() {
        let base = build_request_aad(1, "did:web:a", "did:web:b", "api-1", 10, 20);
        assert_ne!(base, build_request_aad(1, "did:web:a#k1", "did:web:b", "api-1", 10, 20));
        assert_ne!(base, build_request_aad(1, "did:web:a", "did:web:c", "api-1", 10, 20));
        assert_ne!(base, build_request_aad(1, "did:web:a", "did:web:b", "api-2", 10, 20));
        assert_ne!(base, build_request_aad(1, "did:web:a", "did:web:b", "api-1", 11, 20));
        assert_ne!(base, build_request_aad(1, "did:web:a", "did:web:b", "api-1", 10, 21));
        // request 与 response AAD 永不相同(kind 字段)
        let resp = build_response_aad(1, "did:web:a", "did:web:b", "api-1", 10, 20, &[0u8; 24]);
        assert_ne!(base, resp);
    }

    #[test]
    fn response_aad_binds_in_reply_to_raw_bytes() {
        let a = build_response_aad(1, "did:web:b", "did:web:a", "api-1", 10, 20, &[1u8; 24]);
        let b = build_response_aad(1, "did:web:b", "did:web:a", "api-1", 10, 20, &[2u8; 24]);
        assert_ne!(a, b);
        // in_reply_to 有长度前缀(24)
        assert!(a
            .windows(4 + 24)
            .any(|w| w[..4] == 24u32.to_be_bytes() && w[4..] == [1u8; 24]));
    }
}
