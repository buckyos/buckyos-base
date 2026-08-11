//! XChaCha20-Poly1305 seal/open(§8.1)。
//!
//! Body 是 AEAD 输出的原始 bytes(`ciphertext || 16-byte Poly1305 tag`),
//! 不做 Base64,也不再包 JSON envelope。

use super::error::{S2sError, S2sResult};
use super::{S2S_NONCE_LEN, S2S_TAG_LEN};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};

/// AEAD seal:返回 `ciphertext || tag`。
pub fn aead_seal(
    key: &[u8; 32],
    nonce: &[u8; S2S_NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> S2sResult<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| S2sError::Internal("aead seal failed".to_string()))
}

/// AEAD open:输入 `ciphertext || tag`;任何失败统一为 `DecryptFailed`,
/// 不区分 tag 错误/密钥不对/截断。
pub fn aead_open(
    key: &[u8; 32],
    nonce: &[u8; S2S_NONCE_LEN],
    aad: &[u8],
    ciphertext_and_tag: &[u8],
) -> S2sResult<Vec<u8>> {
    if ciphertext_and_tag.len() < S2S_TAG_LEN {
        return Err(S2sError::DecryptFailed);
    }
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext_and_tag,
                aad,
            },
        )
        .map_err(|_| S2sError::DecryptFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip_and_tamper_detection() {
        let key = [0x11u8; 32];
        let nonce = [0x22u8; 24];
        let aad = b"aad bytes";
        let plaintext = br#"{"method":"ping","params":{},"sys":[1]}"#;

        let sealed = aead_seal(&key, &nonce, aad, plaintext).unwrap();
        assert_eq!(sealed.len(), plaintext.len() + S2S_TAG_LEN);

        let opened = aead_open(&key, &nonce, aad, &sealed).unwrap();
        assert_eq!(opened, plaintext);

        // 篡改密文任一字节
        let mut tampered = sealed.clone();
        tampered[0] ^= 1;
        assert!(matches!(
            aead_open(&key, &nonce, aad, &tampered),
            Err(S2sError::DecryptFailed)
        ));
        // 篡改 tag
        let mut tampered = sealed.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(aead_open(&key, &nonce, aad, &tampered).is_err());
        // AAD 不一致
        assert!(aead_open(&key, &nonce, b"other aad", &sealed).is_err());
        // nonce 不一致
        assert!(aead_open(&key, &[0x23u8; 24], aad, &sealed).is_err());
        // 错误 key
        assert!(aead_open(&[0x12u8; 32], &nonce, aad, &sealed).is_err());
        // 截断
        assert!(aead_open(&key, &nonce, aad, &sealed[..S2S_TAG_LEN - 1]).is_err());
        assert!(aead_open(&key, &nonce, aad, &[]).is_err());
    }
}
