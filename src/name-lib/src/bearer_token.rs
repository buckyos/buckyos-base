//! One format for the opaque bearer secrets services hand out or accept
//! (bucket capability tokens `bkt_`, AIWorkspace guest tokens `gt_`, exclusive
//! invite secrets `inv_`): `<prefix>_<base64url(32 random bytes)>`. Services
//! keep only `digest(token)` = base64url(sha256(token)) and compare digests in
//! constant time; issuing, recording and revoking stay with each service.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};

pub const SECRET_BYTES: usize = 32;
const SECRET_CHARS: usize = 43;

pub fn issue(prefix: &str) -> String {
    let mut secret = [0u8; SECRET_BYTES];
    OsRng.fill_bytes(&mut secret);
    format!("{prefix}_{}", URL_SAFE_NO_PAD.encode(secret))
}

/// Whether `token` is a `<prefix>_` token of this format.
pub fn has_form(prefix: &str, token: &str) -> bool {
    token
        .strip_prefix(prefix)
        .and_then(|rest| rest.strip_prefix('_'))
        .is_some_and(|secret| secret.len() == SECRET_CHARS && URL_SAFE_NO_PAD.decode(secret).is_ok_and(|b| b.len() == SECRET_BYTES))
}

pub fn digest_bytes(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

/// What a service stores instead of the token.
pub fn digest(token: &str) -> String {
    URL_SAFE_NO_PAD.encode(digest_bytes(token))
}

/// Constant-time comparison of a presented token with a stored digest.
pub fn verify(token: &str, stored_digest: &str) -> bool {
    digests_equal(&digest(token), stored_digest)
}

/// Constant-time comparison of two digests.
pub fn digests_equal(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issued_tokens_have_the_form_and_verify_by_digest() {
        let t = issue("bkt");
        assert!(t.starts_with("bkt_") && has_form("bkt", &t));
        assert!(!has_form("gt", &t));
        assert!(!has_form("bkt", "bkt_short"));
        assert!(!has_form("bkt", &format!("{t}x")));
        assert_ne!(issue("bkt"), t);
        let d = digest(&t);
        assert!(verify(&t, &d));
        assert!(!verify(&issue("bkt"), &d));
        assert!(!verify(&t, &d[1..]));
        assert_eq!(digest("x"), "LXEWQrcmsEQBYnyp-6wy9chTD7GQPMTbAiWHF5IaSIE");
    }
}
