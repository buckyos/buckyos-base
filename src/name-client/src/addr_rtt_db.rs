use dashmap::DashMap;
use redb::{Database, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::time::{Duration, SystemTime};
use thiserror::Error;

pub type LocalIp = IpAddr;
pub type RemoteAddr = SocketAddr;

const ADDRESS_STATS_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("address_stats");
const METADATA_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("metadata");
const SCHEMA_VERSION_KEY: &[u8] = b"schema_version";
const SCHEMA_VERSION: u32 = 1;
const DEFAULT_EWMA_ALPHA: f64 = 0.125;
const DEFAULT_UNKNOWN_BASE_SCORE: f64 = 100.0;

#[derive(Debug, Error)]
pub enum AddrRttDbError {
    #[error("storage error: {0}")]
    Storage(#[from] redb::Error),
    #[error("storage transaction error: {0}")]
    Transaction(#[from] redb::TransactionError),
    #[error("storage table error: {0}")]
    Table(#[from] redb::TableError),
    #[error("storage commit error: {0}")]
    Commit(#[from] redb::CommitError),
    #[error("storage database error: {0}")]
    Database(#[from] redb::DatabaseError),
    #[error("storage access error: {0}")]
    StorageAccess(#[from] redb::StorageError),
    #[error("encode error: {0}")]
    Encode(#[from] bincode::Error),
}

pub type Result<T> = std::result::Result<T, AddrRttDbError>;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct EntryKey {
    pub local: LocalIp,
    pub remote: RemoteAddr,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum MeasurementLayer {
    Tcp,
    Tls,
    Application,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum OutcomeKind {
    Success,
    Timeout,
    Refused,
    Unreachable,
    LocalError,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConnectionOutcome {
    Success {
        rtt: Duration,
        layer: MeasurementLayer,
    },
    Timeout {
        elapsed: Duration,
    },
    Refused,
    Unreachable,
    LocalError,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AddressStats {
    pub samples: u64,
    pub success_count: u64,
    pub rtt_ewma: Option<Duration>,
    pub rtt_variance: Option<Duration>,
    pub last_outcome: Option<OutcomeKind>,
    pub last_success_time: Option<SystemTime>,
    pub last_failure_time: Option<SystemTime>,
    pub consecutive_failures: u32,
    pub measurement_layer: MeasurementLayer,
}

impl Default for AddressStats {
    fn default() -> Self {
        Self {
            samples: 0,
            success_count: 0,
            rtt_ewma: None,
            rtt_variance: None,
            last_outcome: None,
            last_success_time: None,
            last_failure_time: None,
            consecutive_failures: 0,
            measurement_layer: MeasurementLayer::Tcp,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct RankedAddress {
    pub addr: RemoteAddr,
    pub score: f64,
    pub stats: Option<AddressStats>,
    pub rationale: SortRationale,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SortRationale {
    pub reasons: Vec<&'static str>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CleanupReport {
    pub removed_expired: usize,
    pub removed_total: usize,
}

#[derive(Clone, Debug)]
pub struct Config {
    pub max_entries: usize,
    pub max_per_local: usize,
    pub rtt_outlier_factor: f64,
    pub persistence: PersistencePolicy,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            max_entries: 10_000,
            max_per_local: 1_000,
            rtt_outlier_factor: 10.0,
            persistence: PersistencePolicy::None,
        }
    }
}

#[derive(Clone, Debug)]
pub enum PersistencePolicy {
    None,
    Storage {
        path: PathBuf,
        auto_flush_interval: Option<Duration>,
    },
}

#[derive(Clone, Debug)]
pub struct SortPolicy {
    pub max_age: Duration,
    pub prefer_ipv6: bool,
    pub unknown_strategy: UnknownStrategy,
    pub failure_penalty: f64,
    pub blacklist_threshold: u32,
    pub ewma_alpha: f64,
}

impl Default for SortPolicy {
    fn default() -> Self {
        Self {
            max_age: Duration::from_secs(24 * 60 * 60),
            prefer_ipv6: true,
            unknown_strategy: UnknownStrategy::Median,
            failure_penalty: 0.5,
            blacklist_threshold: 5,
            ewma_alpha: DEFAULT_EWMA_ALPHA,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnknownStrategy {
    Optimistic,
    Pessimistic,
    Median,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PersistedEntry {
    stats: AddressStats,
    consecutive_failure_score: f64,
}

#[derive(Clone, Debug)]
struct EntryState {
    stats: AddressStats,
    consecutive_failure_score: f64,
    last_touched_tick: u64,
}

impl EntryState {
    fn new(last_touched_tick: u64) -> Self {
        Self {
            stats: AddressStats::default(),
            consecutive_failure_score: 0.0,
            last_touched_tick,
        }
    }

    fn from_persisted(persisted: PersistedEntry, last_touched_tick: u64) -> Self {
        Self {
            stats: persisted.stats,
            consecutive_failure_score: persisted.consecutive_failure_score,
            last_touched_tick,
        }
    }

    fn to_persisted(&self) -> PersistedEntry {
        PersistedEntry {
            stats: self.stats.clone(),
            consecutive_failure_score: self.consecutive_failure_score,
        }
    }
}

pub struct RttDatabase {
    config: Config,
    entries: DashMap<EntryKey, EntryState>,
    tick: AtomicU64,
}

impl RttDatabase {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            entries: DashMap::new(),
            tick: AtomicU64::new(1),
        }
    }

    pub fn open(path: impl AsRef<Path>, mut config: Config) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        config.persistence = match config.persistence {
            PersistencePolicy::Storage {
                auto_flush_interval,
                ..
            } => PersistencePolicy::Storage {
                path: path.clone(),
                auto_flush_interval,
            },
            PersistencePolicy::None => PersistencePolicy::Storage {
                path: path.clone(),
                auto_flush_interval: None,
            },
        };

        let db = Self::new(config);
        db.load_from_disk(&path)?;
        db.enforce_limits(None);
        Ok(db)
    }

    pub fn record(
        &self,
        local: LocalIp,
        remote: RemoteAddr,
        outcome: ConnectionOutcome,
    ) -> Result<()> {
        if matches!(outcome, ConnectionOutcome::LocalError) {
            return Ok(());
        }

        let now = SystemTime::now();
        let tick = self.next_tick();
        let key = EntryKey { local, remote };
        let mut entry = self
            .entries
            .entry(key.clone())
            .or_insert_with(|| EntryState::new(tick));
        entry.last_touched_tick = tick;

        match outcome {
            ConnectionOutcome::Success { rtt, layer } => {
                let sample =
                    clamp_sample_rtt(entry.stats.rtt_ewma, rtt, self.config.rtt_outlier_factor);
                entry.stats.samples += 1;
                entry.stats.success_count += 1;
                entry.stats.last_outcome = Some(OutcomeKind::Success);
                entry.stats.last_success_time = Some(now);
                entry.stats.consecutive_failures = 0;
                entry.stats.measurement_layer = layer;

                match entry.stats.rtt_ewma {
                    Some(old_ewma) => {
                        let alpha = DEFAULT_EWMA_ALPHA;
                        let new_ewma = duration_weighted_sum(sample, old_ewma, alpha);
                        let diff = abs_duration_diff(sample, old_ewma);
                        let old_var = entry
                            .stats
                            .rtt_variance
                            .unwrap_or_else(|| sample.div_f64(2.0));
                        let new_var = duration_weighted_sum(diff, old_var, alpha);
                        entry.stats.rtt_ewma = Some(new_ewma);
                        entry.stats.rtt_variance = Some(new_var);
                    }
                    None => {
                        entry.stats.rtt_ewma = Some(sample);
                        entry.stats.rtt_variance = Some(sample.div_f64(2.0));
                    }
                }
                entry.consecutive_failure_score = 0.0;
            }
            ConnectionOutcome::Timeout { .. } => {
                entry.stats.samples += 1;
                entry.stats.last_outcome = Some(OutcomeKind::Timeout);
                entry.stats.last_failure_time = Some(now);
                entry.consecutive_failure_score += 1.0;
                entry.stats.consecutive_failures = entry.consecutive_failure_score.ceil() as u32;
            }
            ConnectionOutcome::Refused => {
                entry.stats.samples += 1;
                entry.stats.last_outcome = Some(OutcomeKind::Refused);
                entry.stats.last_failure_time = Some(now);
                entry.consecutive_failure_score += 0.5;
                entry.stats.consecutive_failures = entry.consecutive_failure_score.ceil() as u32;
            }
            ConnectionOutcome::Unreachable => {
                entry.stats.samples += 1;
                entry.stats.last_outcome = Some(OutcomeKind::Unreachable);
                entry.stats.last_failure_time = Some(now);
                entry.consecutive_failure_score += 1.0;
                entry.stats.consecutive_failures = entry.consecutive_failure_score.ceil() as u32;
            }
            ConnectionOutcome::LocalError => {}
        }

        drop(entry);
        self.enforce_limits(Some(local));
        Ok(())
    }

    pub fn rank(
        &self,
        local: LocalIp,
        addresses: &[RemoteAddr],
        policy: &SortPolicy,
    ) -> Vec<RankedAddress> {
        let mut known_base_scores = Vec::new();
        let now = SystemTime::now();
        let mut states = Vec::with_capacity(addresses.len());

        for addr in addresses {
            let key = EntryKey {
                local,
                remote: *addr,
            };
            let state = self.entries.get_mut(&key).map(|mut entry| {
                entry.last_touched_tick = self.next_tick();
                entry.clone()
            });

            if let Some(entry) = state.as_ref() {
                if let Some(rtt) = entry.stats.rtt_ewma {
                    known_base_scores.push(base_score_from_rtt(rtt));
                }
            }
            states.push(state);
        }

        let unknown_base_score = unknown_base_score(&known_base_scores, &policy.unknown_strategy);

        let mut ranked: Vec<(usize, RankedAddress)> = addresses
            .iter()
            .enumerate()
            .map(|(index, addr)| {
                let state = &states[index];
                let (score, rationale, stats) =
                    self.score_address(*addr, state.as_ref(), now, policy, unknown_base_score);
                (
                    index,
                    RankedAddress {
                        addr: *addr,
                        score,
                        stats,
                        rationale,
                    },
                )
            })
            .collect();

        ranked.sort_by(|(left_idx, left), (right_idx, right)| {
            right
                .score
                .partial_cmp(&left.score)
                .unwrap_or(Ordering::Equal)
                .then_with(|| left_idx.cmp(right_idx))
        });

        ranked.into_iter().map(|(_, item)| item).collect()
    }

    pub fn get_stats(&self, local: LocalIp, remote: RemoteAddr) -> Option<AddressStats> {
        let key = EntryKey { local, remote };
        self.entries.get_mut(&key).map(|mut entry| {
            entry.last_touched_tick = self.next_tick();
            entry.stats.clone()
        })
    }

    pub fn cleanup(&self) -> CleanupReport {
        let ttl = SortPolicy::default().max_age.mul_f64(2.0);
        let now = SystemTime::now();
        let mut expired_keys = Vec::new();

        for item in self.entries.iter() {
            let is_expired = latest_observation_time(&item.stats)
                .and_then(|ts| now.duration_since(ts).ok())
                .map(|age| age > ttl)
                .unwrap_or(false);
            if is_expired {
                expired_keys.push(item.key().clone());
            }
        }

        for key in &expired_keys {
            self.entries.remove(key);
        }

        CleanupReport {
            removed_expired: expired_keys.len(),
            removed_total: expired_keys.len(),
        }
    }

    pub fn flush(&self) -> Result<()> {
        let Some(path) = self.persistence_path() else {
            return Ok(());
        };

        self.flush_to_disk(path)
    }

    pub fn forget_local(&self, local: LocalIp) -> usize {
        let keys: Vec<_> = self
            .entries
            .iter()
            .filter(|item| item.key().local == local)
            .map(|item| item.key().clone())
            .collect();

        for key in &keys {
            self.entries.remove(key);
        }

        keys.len()
    }

    pub fn clear(&self) {
        self.entries.clear();
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn dump(&self) -> Vec<(EntryKey, AddressStats)> {
        self.entries
            .iter()
            .map(|item| (item.key().clone(), item.stats.clone()))
            .collect()
    }

    fn score_address(
        &self,
        addr: RemoteAddr,
        state: Option<&EntryState>,
        now: SystemTime,
        policy: &SortPolicy,
        unknown_base_score: f64,
    ) -> (f64, SortRationale, Option<AddressStats>) {
        let mut reasons = Vec::new();
        let family_bonus = if policy.prefer_ipv6 && addr.is_ipv6() {
            reasons.push("ipv6-preferred");
            1.1
        } else {
            1.0
        };

        match state {
            Some(state) => {
                let stats = state.stats.clone();
                let blacklisted = stats.consecutive_failures >= policy.blacklist_threshold;
                if blacklisted {
                    reasons.push("blacklisted");
                }

                let base_score = match stats.rtt_ewma {
                    Some(rtt) => {
                        reasons.push("low-rtt");
                        base_score_from_rtt(rtt)
                    }
                    None => {
                        reasons.push("unknown-rtt");
                        unknown_base_score
                    }
                };

                let freshness_factor = latest_observation_time(&stats)
                    .and_then(|ts| now.duration_since(ts).ok())
                    .map(|age| {
                        let factor =
                            1.0 - (age.as_secs_f64() / policy.max_age.as_secs_f64().max(1.0));
                        if factor > 0.0 {
                            reasons.push("fresh-data");
                        } else {
                            reasons.push("stale-data");
                        }
                        factor.max(0.0)
                    })
                    .unwrap_or_else(|| {
                        reasons.push("fresh-data");
                        1.0
                    });

                let success_factor = if stats.samples == 0 {
                    1.0
                } else {
                    let success_ratio = stats.success_count as f64 / stats.samples as f64;
                    if success_ratio >= 0.8 {
                        reasons.push("high-success-rate");
                    } else if success_ratio > 0.0 {
                        reasons.push("mixed-success-rate");
                    } else {
                        reasons.push("no-success-history");
                    }
                    success_ratio
                };

                let failure_penalty =
                    1.0 / (1.0 + state.consecutive_failure_score * policy.failure_penalty);
                if state.consecutive_failure_score == 0.0 {
                    reasons.push("no-recent-failures");
                } else {
                    reasons.push("recent-failures");
                }

                let score = if blacklisted {
                    f64::NEG_INFINITY
                } else {
                    base_score * freshness_factor * success_factor * failure_penalty * family_bonus
                };

                (score, SortRationale { reasons }, Some(stats))
            }
            None => {
                reasons.push(match policy.unknown_strategy {
                    UnknownStrategy::Optimistic => "unknown-optimistic",
                    UnknownStrategy::Pessimistic => "unknown-pessimistic",
                    UnknownStrategy::Median => "unknown-median",
                });
                (
                    unknown_base_score * family_bonus,
                    SortRationale { reasons },
                    None,
                )
            }
        }
    }

    fn persistence_path(&self) -> Option<&Path> {
        match &self.config.persistence {
            PersistencePolicy::None => None,
            PersistencePolicy::Storage { path, .. } => Some(path.as_path()),
        }
    }

    fn next_tick(&self) -> u64 {
        self.tick.fetch_add(1, AtomicOrdering::Relaxed)
    }

    fn flush_to_disk(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(redb::StorageError::Io)?;
        }

        let db = Database::create(path)?;
        let write_txn = db.begin_write()?;
        {
            let mut table = write_txn.open_table(ADDRESS_STATS_TABLE)?;
            for item in self.entries.iter() {
                let key = bincode::serialize(item.key())?;
                let value = bincode::serialize(&item.to_persisted())?;
                table.insert(key.as_slice(), value.as_slice())?;
            }
        }
        {
            let mut metadata = write_txn.open_table(METADATA_TABLE)?;
            let schema_bytes = SCHEMA_VERSION.to_le_bytes();
            metadata.insert(SCHEMA_VERSION_KEY, schema_bytes.as_slice())?;
        }
        write_txn.commit()?;
        Ok(())
    }

    fn load_from_disk(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(redb::StorageError::Io)?;
        }

        let db = Database::create(path)?;
        self.ensure_storage_schema(&db)?;
        let read_txn = db.begin_read()?;
        let table = read_txn.open_table(ADDRESS_STATS_TABLE)?;

        for row in table.iter()? {
            let (key_guard, value_guard) = row?;
            let key: EntryKey = bincode::deserialize(key_guard.value())?;
            let persisted: PersistedEntry = bincode::deserialize(value_guard.value())?;
            let tick = self.next_tick();
            self.entries
                .insert(key, EntryState::from_persisted(persisted, tick));
        }

        Ok(())
    }

    fn ensure_storage_schema(&self, db: &Database) -> Result<()> {
        let write_txn = db.begin_write()?;
        {
            let _ = write_txn.open_table(ADDRESS_STATS_TABLE)?;
            let mut metadata = write_txn.open_table(METADATA_TABLE)?;
            let schema_bytes = SCHEMA_VERSION.to_le_bytes();
            metadata.insert(SCHEMA_VERSION_KEY, schema_bytes.as_slice())?;
        }
        write_txn.commit()?;
        Ok(())
    }

    fn enforce_limits(&self, local: Option<LocalIp>) {
        if self.config.max_per_local > 0 {
            if let Some(local) = local {
                while self.count_for_local(local) > self.config.max_per_local {
                    let Some(oldest) = self.oldest_key_for_local(local) else {
                        break;
                    };
                    self.entries.remove(&oldest);
                }
            } else {
                for local in self.all_locals() {
                    while self.count_for_local(local) > self.config.max_per_local {
                        let Some(oldest) = self.oldest_key_for_local(local) else {
                            break;
                        };
                        self.entries.remove(&oldest);
                    }
                }
            }
        }

        if self.config.max_entries > 0 {
            while self.entries.len() > self.config.max_entries {
                let Some(oldest) = self.oldest_key_global() else {
                    break;
                };
                self.entries.remove(&oldest);
            }
        }
    }

    fn count_for_local(&self, local: LocalIp) -> usize {
        self.entries
            .iter()
            .filter(|item| item.key().local == local)
            .count()
    }

    fn all_locals(&self) -> HashSet<LocalIp> {
        self.entries.iter().map(|item| item.key().local).collect()
    }

    fn oldest_key_global(&self) -> Option<EntryKey> {
        self.entries
            .iter()
            .min_by_key(|item| item.last_touched_tick)
            .map(|item| item.key().clone())
    }

    fn oldest_key_for_local(&self, local: LocalIp) -> Option<EntryKey> {
        self.entries
            .iter()
            .filter(|item| item.key().local == local)
            .min_by_key(|item| item.last_touched_tick)
            .map(|item| item.key().clone())
    }
}

fn clamp_sample_rtt(ewma: Option<Duration>, sample: Duration, factor: f64) -> Duration {
    if factor <= 0.0 {
        return sample;
    }

    ewma.map(|baseline| {
        let limit = baseline.mul_f64(factor);
        if sample > limit {
            limit
        } else {
            sample
        }
    })
    .unwrap_or(sample)
}

fn duration_weighted_sum(sample: Duration, baseline: Duration, alpha: f64) -> Duration {
    let sample_ms = sample.as_secs_f64() * 1000.0;
    let baseline_ms = baseline.as_secs_f64() * 1000.0;
    Duration::from_secs_f64(((sample_ms * alpha) + (baseline_ms * (1.0 - alpha))) / 1000.0)
}

fn abs_duration_diff(left: Duration, right: Duration) -> Duration {
    left.abs_diff(right)
}

fn base_score_from_rtt(rtt: Duration) -> f64 {
    1000.0 / (rtt.as_secs_f64() * 1000.0).max(1.0)
}

fn latest_observation_time(stats: &AddressStats) -> Option<SystemTime> {
    match (stats.last_success_time, stats.last_failure_time) {
        (Some(success), Some(failure)) => Some(success.max(failure)),
        (Some(success), None) => Some(success),
        (None, Some(failure)) => Some(failure),
        (None, None) => None,
    }
}

fn unknown_base_score(known_scores: &[f64], strategy: &UnknownStrategy) -> f64 {
    if known_scores.is_empty() {
        return DEFAULT_UNKNOWN_BASE_SCORE;
    }

    match strategy {
        UnknownStrategy::Optimistic => {
            known_scores
                .iter()
                .copied()
                .fold(DEFAULT_UNKNOWN_BASE_SCORE, f64::max)
                * 1.05
        }
        UnknownStrategy::Pessimistic => known_scores
            .iter()
            .copied()
            .fold(f64::INFINITY, f64::min)
            .min(DEFAULT_UNKNOWN_BASE_SCORE),
        UnknownStrategy::Median => {
            let mut values = known_scores.to_vec();
            values.sort_by(|left, right| left.partial_cmp(right).unwrap_or(Ordering::Equal));
            values[values.len() / 2]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn test_addr(ip: &str, port: u16) -> SocketAddr {
        SocketAddr::new(ip.parse().unwrap(), port)
    }

    #[test]
    fn record_success_updates_ewma_and_variance() {
        let db = RttDatabase::new(Config::default());
        let local: IpAddr = "10.0.0.1".parse().unwrap();
        let remote = test_addr("192.0.2.10", 443);

        db.record(
            local,
            remote,
            ConnectionOutcome::Success {
                rtt: Duration::from_millis(100),
                layer: MeasurementLayer::Tcp,
            },
        )
        .unwrap();
        db.record(
            local,
            remote,
            ConnectionOutcome::Success {
                rtt: Duration::from_millis(200),
                layer: MeasurementLayer::Application,
            },
        )
        .unwrap();

        let stats = db.get_stats(local, remote).unwrap();
        assert_eq!(stats.samples, 2);
        assert_eq!(stats.success_count, 2);
        assert_eq!(stats.measurement_layer, MeasurementLayer::Application);
        assert!(stats.rtt_ewma.unwrap() > Duration::from_millis(100));
        assert!(stats.rtt_ewma.unwrap() < Duration::from_millis(120));
        assert!(stats.rtt_variance.unwrap() > Duration::from_millis(45));
    }

    #[test]
    fn rank_penalizes_failures_and_keeps_local_isolated() {
        let db = RttDatabase::new(Config::default());
        let local_a: IpAddr = "10.0.0.1".parse().unwrap();
        let local_b: IpAddr = "10.0.0.2".parse().unwrap();
        let fast = test_addr("2001:db8::1", 443);
        let slow = test_addr("192.0.2.20", 443);

        db.record(
            local_a,
            fast,
            ConnectionOutcome::Success {
                rtt: Duration::from_millis(20),
                layer: MeasurementLayer::Tcp,
            },
        )
        .unwrap();
        db.record(
            local_a,
            slow,
            ConnectionOutcome::Success {
                rtt: Duration::from_millis(80),
                layer: MeasurementLayer::Tcp,
            },
        )
        .unwrap();
        for _ in 0..5 {
            db.record(
                local_a,
                fast,
                ConnectionOutcome::Timeout {
                    elapsed: Duration::from_millis(300),
                },
            )
            .unwrap();
        }

        let ranked_a = db.rank(local_a, &[fast, slow], &SortPolicy::default());
        assert_eq!(ranked_a[0].addr, slow);
        assert!(ranked_a[1].score.is_sign_negative());

        let ranked_b = db.rank(local_b, &[fast, slow], &SortPolicy::default());
        assert_eq!(ranked_b[0].addr, fast);
        assert!(ranked_b[0].stats.is_none());
    }

    #[test]
    fn cleanup_removes_expired_entries() {
        let db = RttDatabase::new(Config::default());
        let local: IpAddr = "10.0.0.1".parse().unwrap();
        let remote = test_addr("192.0.2.10", 443);

        db.record(
            local,
            remote,
            ConnectionOutcome::Success {
                rtt: Duration::from_millis(10),
                layer: MeasurementLayer::Tcp,
            },
        )
        .unwrap();

        if let Some(mut entry) = db.entries.get_mut(&EntryKey { local, remote }) {
            entry.stats.last_success_time =
                Some(SystemTime::now() - SortPolicy::default().max_age.mul_f64(3.0));
        }

        let report = db.cleanup();
        assert_eq!(report.removed_expired, 1);
        assert!(db.get_stats(local, remote).is_none());
    }

    #[test]
    fn flush_and_open_round_trip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("addr-rtt.redb");
        let local: IpAddr = "10.0.0.1".parse().unwrap();
        let remote = test_addr("192.0.2.10", 443);
        let config = Config {
            persistence: PersistencePolicy::Storage {
                path: path.clone(),
                auto_flush_interval: None,
            },
            ..Config::default()
        };

        let db = RttDatabase::new(config.clone());
        db.record(
            local,
            remote,
            ConnectionOutcome::Success {
                rtt: Duration::from_millis(25),
                layer: MeasurementLayer::Tls,
            },
        )
        .unwrap();
        db.flush().unwrap();

        let reopened = RttDatabase::open(path, config).unwrap();
        let stats = reopened.get_stats(local, remote).unwrap();
        assert_eq!(stats.success_count, 1);
        assert_eq!(stats.measurement_layer, MeasurementLayer::Tls);
        assert_eq!(stats.rtt_ewma, Some(Duration::from_millis(25)));
    }

    #[test]
    fn per_local_limit_evicts_oldest() {
        let db = RttDatabase::new(Config {
            max_entries: 10,
            max_per_local: 2,
            ..Config::default()
        });
        let local: IpAddr = "10.0.0.1".parse().unwrap();
        let a = test_addr("192.0.2.1", 443);
        let b = test_addr("192.0.2.2", 443);
        let c = test_addr("192.0.2.3", 443);

        for remote in [a, b, c] {
            db.record(
                local,
                remote,
                ConnectionOutcome::Success {
                    rtt: Duration::from_millis(10),
                    layer: MeasurementLayer::Tcp,
                },
            )
            .unwrap();
        }

        assert!(db.get_stats(local, a).is_none());
        assert!(db.get_stats(local, b).is_some());
        assert!(db.get_stats(local, c).is_some());
    }
}
