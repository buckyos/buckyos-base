//! kRPC S2S local/remote identity boundary.
//!
//! Local identity loading owns only `IdentityRoots` and private-key binding validation. Remote
//! identity loading owns only Provider/NameClient resolution, provenance, cache lifecycle,
//! singleflight, and bounded refresh. Neither side can call through to the other's data source.

use super::error::{S2sError, S2sResult};
use super::keys::{ed25519_key_fingerprint, ed25519_pk_to_x25519_pk};
use super::provider::{S2sProviderChangeToken, S2sProviderLookup, S2sPublicKeyProvider};
use name_client::{
    get_name_client, IdentityRoots, LocalEd25519IdentityKey, NameClient, ResolveSourcePolicy,
};
use name_lib::{parse_canonical_did, DID};
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use tokio::sync::Mutex as AsyncMutex;
use zeroize::Zeroizing;

pub const S2S_DEFAULT_REMOTE_IDENTITY_CACHE_CAPACITY: usize = 1024;
pub const S2S_DEFAULT_AUTHORITY_REFRESH_COOLDOWN: Duration = Duration::from_secs(30);
const PROVIDER_GENERATION_RACE_RETRIES: usize = 3;

/// The source that authenticated a remote DID snapshot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RemoteKeyProvenance {
    ClusterConfig,
    NameClient,
}

/// Validated immutable remote identity state captured by one protocol operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemoteIdentitySnapshot {
    pub did: DID,
    pub ed25519_public: [u8; 32],
    pub fingerprint: [u8; 32],
    pub provenance: RemoteKeyProvenance,
    pub revision: Option<u64>,
    /// Provider generation observed while loading this snapshot, including a NotManaged result.
    pub source_generation: Option<u64>,
}

impl RemoteIdentitySnapshot {
    fn new(
        did: DID,
        ed25519_public: [u8; 32],
        provenance: RemoteKeyProvenance,
        revision: Option<u64>,
        source_generation: Option<u64>,
    ) -> S2sResult<Self> {
        ed25519_pk_to_x25519_pk(&ed25519_public)?;
        Ok(Self {
            did,
            fingerprint: ed25519_key_fingerprint(&ed25519_public),
            ed25519_public,
            provenance,
            revision,
            source_generation,
        })
    }
}

pub(crate) type RemoteDefaultKey = Arc<RemoteIdentitySnapshot>;

/// Low-cardinality counters for observing the remote identity source without logging key data.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct S2sRemoteIdentityMetricsSnapshot {
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub provider_hits: u64,
    pub provider_not_managed: u64,
    pub provider_errors: u64,
    pub name_client_fallbacks: u64,
    pub refresh_attempts: u64,
    pub fingerprint_changes: u64,
}

#[derive(Default)]
struct S2sRemoteIdentityMetrics {
    cache_hits: AtomicU64,
    cache_misses: AtomicU64,
    provider_hits: AtomicU64,
    provider_not_managed: AtomicU64,
    provider_errors: AtomicU64,
    name_client_fallbacks: AtomicU64,
    refresh_attempts: AtomicU64,
    fingerprint_changes: AtomicU64,
}

impl S2sRemoteIdentityMetrics {
    fn snapshot(&self) -> S2sRemoteIdentityMetricsSnapshot {
        S2sRemoteIdentityMetricsSnapshot {
            cache_hits: self.cache_hits.load(Ordering::Relaxed),
            cache_misses: self.cache_misses.load(Ordering::Relaxed),
            provider_hits: self.provider_hits.load(Ordering::Relaxed),
            provider_not_managed: self.provider_not_managed.load(Ordering::Relaxed),
            provider_errors: self.provider_errors.load(Ordering::Relaxed),
            name_client_fallbacks: self.name_client_fallbacks.load(Ordering::Relaxed),
            refresh_attempts: self.refresh_attempts.load(Ordering::Relaxed),
            fingerprint_changes: self.fingerprint_changes.load(Ordering::Relaxed),
        }
    }
}

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

/// Loader for private capabilities held by the current process.
#[derive(Clone, Debug)]
pub struct S2sLocalIdentityLoader {
    roots: IdentityRoots,
}

impl S2sLocalIdentityLoader {
    pub fn new(roots: IdentityRoots) -> Self {
        Self { roots }
    }

    pub fn roots(&self) -> &IdentityRoots {
        &self.roots
    }

    fn load_key(&self, did: &DID) -> S2sResult<Arc<LocalEd25519IdentityKey>> {
        validate_did(did)?;
        self.roots
            .load_local_default_ed25519_identity(did)
            .map(Arc::new)
            .map_err(map_identity_error)
    }
}

struct RefreshGate {
    last_attempt: Option<Instant>,
}

struct RemoteIdentityEntry {
    did: DID,
    snapshot: RwLock<Option<RemoteDefaultKey>>,
    load_lock: AsyncMutex<()>,
    refresh_gate: AsyncMutex<RefreshGate>,
}

impl RemoteIdentityEntry {
    fn new(did: DID) -> Self {
        Self {
            did,
            snapshot: RwLock::new(None),
            load_lock: AsyncMutex::new(()),
            refresh_gate: AsyncMutex::new(RefreshGate { last_attempt: None }),
        }
    }
}

struct RemoteIdentityCacheInner {
    entries: HashMap<DID, Arc<RemoteIdentityEntry>>,
    order: VecDeque<DID>,
}

struct RemoteIdentityCache {
    inner: Mutex<RemoteIdentityCacheInner>,
    capacity: usize,
}

impl RemoteIdentityCache {
    fn new(capacity: usize) -> Self {
        Self {
            inner: Mutex::new(RemoteIdentityCacheInner {
                entries: HashMap::new(),
                order: VecDeque::new(),
            }),
            capacity: capacity.max(1),
        }
    }

    fn entry(&self, did: &DID) -> Arc<RemoteIdentityEntry> {
        let mut inner = self.inner.lock().unwrap();
        if let Some(entry) = inner.entries.get(did).cloned() {
            touch_lru(&mut inner.order, did);
            return entry;
        }
        while inner.entries.len() >= self.capacity {
            let Some(oldest) = inner.order.pop_front() else {
                break;
            };
            inner.entries.remove(&oldest);
        }
        let entry = Arc::new(RemoteIdentityEntry::new(did.clone()));
        inner.entries.insert(did.clone(), entry.clone());
        inner.order.push_back(did.clone());
        entry
    }

    fn len(&self) -> usize {
        self.inner.lock().unwrap().entries.len()
    }
}

fn touch_lru(order: &mut VecDeque<DID>, did: &DID) {
    if let Some(index) = order.iter().position(|candidate| candidate == did) {
        order.remove(index);
    }
    order.push_back(did.clone());
}

struct S2sRemoteIdentitySource {
    name_client: Option<RuntimeNameClient>,
    provider: Option<Arc<dyn S2sPublicKeyProvider>>,
    provider_token: Option<S2sProviderChangeToken>,
    cache: RemoteIdentityCache,
    refresh_cooldown: Duration,
    metrics: S2sRemoteIdentityMetrics,
}

impl S2sRemoteIdentitySource {
    fn new(
        name_client: Option<RuntimeNameClient>,
        provider: Option<Arc<dyn S2sPublicKeyProvider>>,
        cache_capacity: usize,
        refresh_cooldown: Duration,
    ) -> Self {
        let provider_token = provider.as_ref().map(|provider| provider.change_token());
        Self {
            name_client,
            provider,
            provider_token,
            cache: RemoteIdentityCache::new(cache_capacity),
            refresh_cooldown,
            metrics: S2sRemoteIdentityMetrics::default(),
        }
    }

    fn provider_generation(&self) -> Option<u64> {
        self.provider_token
            .as_ref()
            .map(S2sProviderChangeToken::generation)
    }

    fn is_fresh(&self, snapshot: &RemoteIdentitySnapshot) -> bool {
        snapshot.source_generation == self.provider_generation()
    }

    fn fresh_snapshot(&self, entry: &RemoteIdentityEntry) -> Option<RemoteDefaultKey> {
        entry
            .snapshot
            .read()
            .unwrap()
            .as_ref()
            .filter(|snapshot| self.is_fresh(snapshot))
            .cloned()
    }

    async fn resolve(
        &self,
        entry: &Arc<RemoteIdentityEntry>,
        fallback_source: ResolveSourcePolicy,
    ) -> S2sResult<ResolvedRemote> {
        if let Some(snapshot) = self.fresh_snapshot(entry) {
            self.metrics.cache_hits.fetch_add(1, Ordering::Relaxed);
            return Ok(ResolvedRemote {
                current: snapshot,
                retired: None,
            });
        }
        self.metrics.cache_misses.fetch_add(1, Ordering::Relaxed);
        let _load = entry.load_lock.lock().await;
        if let Some(snapshot) = self.fresh_snapshot(entry) {
            self.metrics.cache_hits.fetch_add(1, Ordering::Relaxed);
            return Ok(ResolvedRemote {
                current: snapshot,
                retired: None,
            });
        }
        let snapshot = self.load(&entry.did, fallback_source).await?;
        Ok(self.replace_snapshot(entry, snapshot))
    }

    async fn reload(
        &self,
        entry: &Arc<RemoteIdentityEntry>,
        fallback_source: ResolveSourcePolicy,
    ) -> S2sResult<RemoteReload> {
        let _load = entry.load_lock.lock().await;
        self.metrics
            .refresh_attempts
            .fetch_add(1, Ordering::Relaxed);
        let snapshot = self.load(&entry.did, fallback_source).await?;
        let previous = entry.snapshot.read().unwrap().clone();
        let resolved = self.replace_snapshot(entry, snapshot);
        let current = resolved.current;
        Ok(RemoteReload { previous, current })
    }

    async fn refresh_after_failure(
        &self,
        entry: &Arc<RemoteIdentityEntry>,
        observed: &RemoteIdentitySnapshot,
    ) -> S2sResult<Option<RemoteDefaultKey>> {
        if let Some(current) = self.fresh_snapshot(entry) {
            if current.fingerprint != observed.fingerprint {
                return Ok(Some(current));
            }
        }

        let provider_changed = observed.source_generation != self.provider_generation();
        if observed.provenance == RemoteKeyProvenance::ClusterConfig && !provider_changed {
            return Ok(None);
        }

        let mut gate = entry.refresh_gate.lock().await;
        if let Some(current) = self.fresh_snapshot(entry) {
            if current.fingerprint != observed.fingerprint {
                return Ok(Some(current));
            }
        }
        let provider_changed = observed.source_generation != self.provider_generation();
        if !provider_changed
            && gate
                .last_attempt
                .is_some_and(|last| last.elapsed() < self.refresh_cooldown)
        {
            return Ok(None);
        }
        gate.last_attempt = Some(Instant::now());

        let reload = self
            .reload(entry, ResolveSourcePolicy::RemoteAuthority)
            .await?;
        if reload.current.fingerprint == observed.fingerprint {
            Ok(None)
        } else {
            Ok(Some(reload.current))
        }
    }

    fn replace_snapshot(
        &self,
        entry: &RemoteIdentityEntry,
        snapshot: RemoteDefaultKey,
    ) -> ResolvedRemote {
        let mut current = entry.snapshot.write().unwrap();
        let retired = current
            .as_ref()
            .filter(|old| old.fingerprint != snapshot.fingerprint)
            .map(|old| old.fingerprint);
        if retired.is_some() {
            self.metrics
                .fingerprint_changes
                .fetch_add(1, Ordering::Relaxed);
        }
        *current = Some(snapshot.clone());
        ResolvedRemote {
            current: snapshot,
            retired,
        }
    }

    async fn load(
        &self,
        did: &DID,
        fallback_source: ResolveSourcePolicy,
    ) -> S2sResult<RemoteDefaultKey> {
        validate_did(did)?;
        if let Some(provider) = self.provider.as_ref() {
            for _ in 0..PROVIDER_GENERATION_RACE_RETRIES {
                let lookup = match provider.lookup(did) {
                    Ok(lookup) => lookup,
                    Err(err) => {
                        self.metrics.provider_errors.fetch_add(1, Ordering::Relaxed);
                        return Err(err);
                    }
                };
                match lookup {
                    S2sProviderLookup::Managed { key, generation } => {
                        if Some(generation) != self.provider_generation() {
                            continue;
                        }
                        self.metrics.provider_hits.fetch_add(1, Ordering::Relaxed);
                        return RemoteIdentitySnapshot::new(
                            did.clone(),
                            key.ed25519_public,
                            RemoteKeyProvenance::ClusterConfig,
                            Some(key.revision),
                            Some(generation),
                        )
                        .map(Arc::new);
                    }
                    S2sProviderLookup::NotManaged { generation } => {
                        if Some(generation) != self.provider_generation() {
                            continue;
                        }
                        self.metrics
                            .provider_not_managed
                            .fetch_add(1, Ordering::Relaxed);
                        let name_client = self.name_client.as_ref().ok_or_else(|| {
                            S2sError::InvalidConfig(format!(
                                "Provider does not manage {} and NameClient fallback is unavailable",
                                did.to_string()
                            ))
                        })?;
                        self.metrics
                            .name_client_fallbacks
                            .fetch_add(1, Ordering::Relaxed);
                        let ed25519_public = name_client
                            .as_ref()
                            .resolve_default_ed25519_key(did, fallback_source)
                            .await
                            .map_err(map_identity_error)?;
                        if Some(generation) != self.provider_generation() {
                            continue;
                        }
                        return RemoteIdentitySnapshot::new(
                            did.clone(),
                            ed25519_public,
                            RemoteKeyProvenance::NameClient,
                            None,
                            Some(generation),
                        )
                        .map(Arc::new);
                    }
                }
            }
            return Err(S2sError::PublicKeyProvider(
                "cluster public-key generation changed repeatedly during lookup".to_string(),
            ));
        }

        let name_client = self.name_client.as_ref().ok_or_else(|| {
            S2sError::InvalidConfig(format!(
                "no remote public-key source configured for {}",
                did.to_string()
            ))
        })?;
        self.metrics
            .name_client_fallbacks
            .fetch_add(1, Ordering::Relaxed);
        let ed25519_public = name_client
            .as_ref()
            .resolve_default_ed25519_key(did, fallback_source)
            .await
            .map_err(map_identity_error)?;
        RemoteIdentitySnapshot::new(
            did.clone(),
            ed25519_public,
            RemoteKeyProvenance::NameClient,
            None,
            None,
        )
        .map(Arc::new)
    }
}

struct RemoteReload {
    previous: Option<RemoteDefaultKey>,
    current: RemoteDefaultKey,
}

struct ResolvedRemote {
    current: RemoteDefaultKey,
    retired: Option<[u8; 32]>,
}

impl RemoteReload {
    fn changed(&self) -> bool {
        self.previous
            .as_ref()
            .is_some_and(|previous| previous.fingerprint != self.current.fingerprint)
    }
}

/// The single authoritative cache entry/handle consumed by client and server code.
#[derive(Clone)]
pub(crate) struct S2sRemoteIdentityHandle {
    source: Arc<S2sRemoteIdentitySource>,
    entry: Arc<RemoteIdentityEntry>,
}

impl S2sRemoteIdentityHandle {
    pub async fn snapshot(
        &self,
        fallback_source: ResolveSourcePolicy,
    ) -> S2sResult<(RemoteDefaultKey, Option<[u8; 32]>)> {
        let resolved = self.source.resolve(&self.entry, fallback_source).await?;
        Ok((resolved.current, resolved.retired))
    }

    pub async fn reload(
        &self,
        fallback_source: ResolveSourcePolicy,
    ) -> S2sResult<(bool, Option<[u8; 32]>, RemoteDefaultKey)> {
        let result = self.source.reload(&self.entry, fallback_source).await?;
        let retired = result
            .previous
            .as_ref()
            .filter(|previous| previous.fingerprint != result.current.fingerprint)
            .map(|previous| previous.fingerprint);
        Ok((result.changed(), retired, result.current))
    }

    pub async fn refresh_after_failure(
        &self,
        observed: &RemoteIdentitySnapshot,
    ) -> S2sResult<Option<RemoteDefaultKey>> {
        self.source
            .refresh_after_failure(&self.entry, observed)
            .await
    }
}

/// Runtime dependency container. Its local loader and remote source are structurally separate.
#[derive(Clone)]
pub struct S2sRuntime {
    local_loader: Arc<S2sLocalIdentityLoader>,
    remote_source: Arc<S2sRemoteIdentitySource>,
}

impl std::fmt::Debug for S2sRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S2sRuntime")
            .field("identity_root", &self.local_loader.roots().public_root)
            .field("security_root", &self.local_loader.roots().security_root)
            .field(
                "has_public_key_provider",
                &self.remote_source.provider.is_some(),
            )
            .field("remote_key_cache_len", &self.remote_source.cache.len())
            .finish_non_exhaustive()
    }
}

impl S2sRuntime {
    /// Explicit generic/non-cluster profile using system roots and NameClient only.
    pub fn system_name_client_fallback() -> S2sResult<Self> {
        let roots = IdentityRoots::from_env_or_buckyos_root().map_err(map_identity_error)?;
        let name_client = get_name_client().ok_or_else(|| {
            S2sError::InvalidConfig(
                "NameClient is not initialized for explicit S2S fallback mode".to_string(),
            )
        })?;
        Ok(Self::build(
            roots,
            Some(RuntimeNameClient::Global(name_client)),
            None,
        ))
    }

    /// System roots plus the cluster Provider. Global NameClient is used only for NotManaged.
    pub fn system_provider_with_name_client_fallback(
        public_key_provider: Arc<dyn S2sPublicKeyProvider>,
    ) -> S2sResult<Self> {
        let roots = IdentityRoots::from_env_or_buckyos_root().map_err(map_identity_error)?;
        Ok(Self::build(
            roots,
            get_name_client().map(RuntimeNameClient::Global),
            Some(public_key_provider),
        ))
    }

    /// Explicit generic/non-cluster profile with an injected NameClient.
    pub fn name_client_fallback(roots: IdentityRoots, name_client: Arc<NameClient>) -> Self {
        Self::build(roots, Some(RuntimeNameClient::Shared(name_client)), None)
    }

    /// Cluster Provider with an explicit NameClient fallback for NotManaged DIDs.
    pub fn provider_with_name_client_fallback(
        roots: IdentityRoots,
        public_key_provider: Arc<dyn S2sPublicKeyProvider>,
        name_client: Arc<NameClient>,
    ) -> Self {
        Self::build(
            roots,
            Some(RuntimeNameClient::Shared(name_client)),
            Some(public_key_provider),
        )
    }

    /// Cluster Provider-only profile. A NotManaged result fails closed.
    pub fn provider_only(
        roots: IdentityRoots,
        public_key_provider: Arc<dyn S2sPublicKeyProvider>,
    ) -> Self {
        Self::build(roots, None, Some(public_key_provider))
    }

    fn build(
        roots: IdentityRoots,
        name_client: Option<RuntimeNameClient>,
        provider: Option<Arc<dyn S2sPublicKeyProvider>>,
    ) -> Self {
        Self {
            local_loader: Arc::new(S2sLocalIdentityLoader::new(roots)),
            remote_source: Arc::new(S2sRemoteIdentitySource::new(
                name_client,
                provider,
                S2S_DEFAULT_REMOTE_IDENTITY_CACHE_CAPACITY,
                S2S_DEFAULT_AUTHORITY_REFRESH_COOLDOWN,
            )),
        }
    }

    /// Installs a Provider before client/server construction and starts with an empty remote cache.
    pub fn with_public_key_provider(
        mut self,
        public_key_provider: Arc<dyn S2sPublicKeyProvider>,
    ) -> Self {
        self.remote_source = Arc::new(S2sRemoteIdentitySource::new(
            self.remote_source.name_client.clone(),
            Some(public_key_provider),
            self.remote_source.cache.capacity,
            self.remote_source.refresh_cooldown,
        ));
        self
    }

    /// Test/embedded tuning for bounded cache and authority refresh protection.
    pub fn with_remote_identity_limits(
        mut self,
        cache_capacity: usize,
        refresh_cooldown: Duration,
    ) -> Self {
        self.remote_source = Arc::new(S2sRemoteIdentitySource::new(
            self.remote_source.name_client.clone(),
            self.remote_source.provider.clone(),
            cache_capacity,
            refresh_cooldown,
        ));
        self
    }

    pub fn remote_identity_metrics(&self) -> S2sRemoteIdentityMetricsSnapshot {
        self.remote_source.metrics.snapshot()
    }

    fn load_local_key(&self, did: &DID) -> S2sResult<Arc<LocalEd25519IdentityKey>> {
        self.local_loader.load_key(did)
    }

    pub(crate) fn remote_identity_handle(&self, did: &DID) -> S2sResult<S2sRemoteIdentityHandle> {
        validate_did(did)?;
        Ok(S2sRemoteIdentityHandle {
            source: self.remote_source.clone(),
            entry: self.remote_source.cache.entry(did),
        })
    }
}

/// One request's local default-key snapshot. Reload only affects later requests.
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

    /// Atomically replaces the local key; in-flight snapshots retain the retired key.
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
