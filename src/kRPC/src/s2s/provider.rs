//! Product-defined S2S remote public-key Provider contract.

use super::error::{S2sError, S2sResult};
use name_lib::DID;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Provider publish generation shared with every S2S runtime that consumes it.
///
/// Reading this token is an in-memory atomic operation. It lets the request path reject a stale
/// cache entry without re-querying the Provider.
#[derive(Clone, Debug)]
pub struct S2sProviderChangeToken {
    generation: Arc<AtomicU64>,
}

impl S2sProviderChangeToken {
    pub fn fixed(generation: u64) -> Self {
        Self {
            generation: Arc::new(AtomicU64::new(generation)),
        }
    }

    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    /// Advances the token after the product has atomically published its own immutable snapshot.
    ///
    /// The product owns the cluster_config schema and the snapshot swap. Calling this before that
    /// swap would expose a generation that `lookup` cannot yet serve.
    pub fn mark_published(&self, generation: u64) -> S2sResult<()> {
        let mut current = self.generation.load(Ordering::Acquire);
        loop {
            if generation <= current {
                return Err(S2sError::InvalidConfig(format!(
                    "S2S Provider generation {} must be greater than {}",
                    generation, current
                )));
            }
            match self.generation.compare_exchange_weak(
                current,
                generation,
                Ordering::Release,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(()),
                Err(observed) => current = observed,
            }
        }
    }
}

/// One Provider-managed default authentication Ed25519 public key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct S2sPeerPublicKey {
    pub ed25519_public: [u8; 32],
    /// Key-specific revision from the product's authoritative snapshot.
    pub revision: u64,
}

impl S2sPeerPublicKey {
    pub fn new(ed25519_public: [u8; 32], revision: u64) -> Self {
        Self {
            ed25519_public,
            revision,
        }
    }
}

/// Explicit Provider lookup semantics.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum S2sProviderLookup {
    /// The Provider is authoritative for this DID. NameClient fallback is forbidden.
    Managed {
        key: S2sPeerPublicKey,
        generation: u64,
    },
    /// The Provider's management domain does not contain this DID.
    NotManaged { generation: u64 },
}

/// Resolves a canonical DID to its unique default authentication Ed25519 public key.
///
/// Implementations must read an already-loaded deterministic snapshot and must not perform
/// network or filesystem I/O. Invalid, missing, disabled, or unavailable managed configuration
/// returns `Err`; only `NotManaged` permits NameClient fallback.
pub trait S2sPublicKeyProvider: Send + Sync {
    fn lookup(&self, target_did: &DID) -> S2sResult<S2sProviderLookup>;

    /// Returns the stable token whose generation changes after every successful atomic publish.
    fn change_token(&self) -> S2sProviderChangeToken;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn change_token_is_monotonic() {
        let token = S2sProviderChangeToken::fixed(7);
        token.mark_published(8).unwrap();
        assert_eq!(token.generation(), 8);
        assert!(matches!(
            token.mark_published(8),
            Err(S2sError::InvalidConfig(_))
        ));
    }
}
