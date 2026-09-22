//! transport replay 防护(§10.1)。
//!
//! - 在 AEAD 成功之后、handler dispatch 之前执行原子 `put-if-absent`;
//! - entry 至少保留到 `exp + allowed_clock_skew`;
//! - store 故障 fail closed(调用方必须拒绝请求);
//! - 多实例服务必须使用共享 replay store 或等价一致性;
//!   [`MemoryReplayStore`] 是**每进程本地** cache,不能抵御跨实例重放。

use super::error::{S2sError, S2sResult};
use super::S2S_NONCE_LEN;
use async_trait::async_trait;
use std::collections::{BTreeMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// replay key(§10.1 冻结字段)。
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ReplayKey {
    pub version: u32,
    /// wire 形式 canonical From DID。
    pub from_did: String,
    /// AEAD 实际成功的 sender key fingerprint。
    pub from_fingerprint: [u8; 32],
    pub to_did: String,
    pub to_fingerprint: [u8; 32],
    pub nonce: [u8; S2S_NONCE_LEN],
}

#[async_trait]
pub trait S2sReplayStore: Send + Sync {
    /// 原子 put-if-absent。
    ///
    /// - `Ok(true)`:首次出现,已插入;
    /// - `Ok(false)`:已存在(replay),调用方必须拒绝且不 dispatch;
    /// - `Err(..)`:store 故障,调用方必须 fail closed。
    ///
    /// `retain_until` 是 entry 的最小保留时间(unix seconds,应为
    /// `exp + allowed_clock_skew`)。
    async fn check_and_insert(&self, key: &ReplayKey, retain_until: u64) -> S2sResult<bool>;
}

/// 每进程内存 replay store(单实例部署/测试用)。
///
/// **不能抵御跨实例重放**:多实例生产环境必须换成共享 backend,或按 sender
/// 稳定路由到同一实例。容量满且无可清理的过期 entry 时 fail closed。
pub struct MemoryReplayStore {
    inner: Mutex<MemoryReplayState>,
    capacity: usize,
}

#[derive(Default)]
struct MemoryReplayState {
    keys: HashSet<Arc<ReplayKey>>,
    expirations: BTreeMap<u64, Vec<Arc<ReplayKey>>>,
    stats: MemoryReplayStoreStats,
    pressure_reported: bool,
    full_reported: bool,
}

/// 单实例内存 store 的累计计数与最近一次操作后的占用快照。
#[derive(Clone, Copy, Debug, Default)]
pub struct MemoryReplayStoreStats {
    pub capacity: usize,
    pub entries: usize,
    pub high_watermark: usize,
    pub inserted: u64,
    pub replays: u64,
    pub capacity_rejections: u64,
    pub expired_entries: u64,
    pub cleanup_nanos: u64,
}

pub const S2S_DEFAULT_REPLAY_CAPACITY: usize = 100_000;

impl MemoryReplayStore {
    pub fn new_single_instance(capacity: usize) -> Self {
        MemoryReplayStore {
            inner: Mutex::new(MemoryReplayState::default()),
            capacity: capacity.max(16),
        }
    }

    pub fn with_default_capacity() -> Self {
        Self::new_single_instance(S2S_DEFAULT_REPLAY_CAPACITY)
    }

    pub fn stats(&self) -> S2sResult<MemoryReplayStoreStats> {
        let state = self.inner.lock().map_err(|_| {
            S2sError::ReplayStoreUnavailable("poisoned lock".to_string())
        })?;
        Ok(MemoryReplayStoreStats {
            capacity: self.capacity,
            entries: state.keys.len(),
            ..state.stats
        })
    }

    fn sweep_expired(state: &mut MemoryReplayState, now: u64) {
        // 只访问已经到期的桶。满容量且无到期条目时不扫描 nonce 集合。
        if !state.expirations.first_key_value().is_some_and(|(expiry, _)| *expiry <= now) {
            return;
        }
        let started = Instant::now();
        while state.expirations.first_key_value().is_some_and(|(expiry, _)| *expiry <= now) {
            let (_, keys) = state.expirations.pop_first().expect("expiry bucket exists");
            for key in keys {
                state.keys.remove(&key);
                state.stats.expired_entries = state.stats.expired_entries.saturating_add(1);
            }
        }
        state.stats.cleanup_nanos = state.stats.cleanup_nanos.saturating_add(
            started.elapsed().as_nanos().min(u64::MAX as u128) as u64,
        );
    }

    fn check_and_insert_at(&self, key: &ReplayKey, retain_until: u64, now: u64) -> S2sResult<bool> {
        let mut state = self.inner.lock().map_err(|_| {
            S2sError::ReplayStoreUnavailable("poisoned lock".to_string())
        })?;
        Self::sweep_expired(&mut state, now);
        if state.full_reported && state.keys.len() < self.capacity {
            log::info!(
                "s2s replay store recovered: entries={} capacity={} rejected={} expired={} cleanup_nanos={}",
                state.keys.len(), self.capacity, state.stats.capacity_rejections,
                state.stats.expired_entries, state.stats.cleanup_nanos,
            );
            state.full_reported = false;
        }
        if state.keys.len() < self.capacity - self.capacity / 4 {
            state.pressure_reported = false;
        }
        if state.keys.contains(key) {
            state.stats.replays = state.stats.replays.saturating_add(1);
            return Ok(false);
        }
        if state.keys.len() >= self.capacity {
            state.stats.capacity_rejections = state.stats.capacity_rejections.saturating_add(1);
            if !state.full_reported {
                log::warn!(
                    "s2s replay store full: entries={} capacity={} next_expiry={:?}; rejecting encrypted requests",
                    state.keys.len(), self.capacity, state.expirations.first_key_value().map(|(time, _)| time),
                );
                state.full_reported = true;
            }
            return Err(S2sError::ReplayStoreUnavailable("replay store full".to_string()));
        }
        let key = Arc::new(key.clone());
        state.keys.insert(key.clone());
        state.expirations.entry(retain_until).or_default().push(key);
        state.stats.inserted = state.stats.inserted.saturating_add(1);
        state.stats.high_watermark = state.stats.high_watermark.max(state.keys.len());
        if !state.pressure_reported && state.keys.len() >= self.capacity - self.capacity / 5 {
            log::warn!(
                "s2s replay store pressure: entries={} capacity={} high_watermark={}",
                state.keys.len(), self.capacity, state.stats.high_watermark,
            );
            state.pressure_reported = true;
        }
        Ok(true)
    }
}

#[async_trait]
impl S2sReplayStore for MemoryReplayStore {
    async fn check_and_insert(&self, key: &ReplayKey, retain_until: u64) -> S2sResult<bool> {
        self.check_and_insert_at(key, retain_until, buckyos_kit::buckyos_get_unix_timestamp())
    }
}

#[cfg(test)]
#[path = "replay_pressure_tests.rs"]
mod pressure_tests;

#[cfg(test)]
mod tests {
    use super::*;

    fn key(nonce_fill: u8) -> ReplayKey {
        ReplayKey {
            version: 1,
            from_did: "did:web:a.example.com".to_string(),
            from_fingerprint: [1u8; 32],
            to_did: "did:web:b.example.com".to_string(),
            to_fingerprint: [2u8; 32],
            nonce: [nonce_fill; 24],
        }
    }

    #[tokio::test]
    async fn put_if_absent_semantics() {
        let store = MemoryReplayStore::new_single_instance(100);
        let far = buckyos_kit::buckyos_get_unix_timestamp() + 600;
        assert!(store.check_and_insert(&key(1), far).await.unwrap());
        // 同 key 第二次 = replay
        assert!(!store.check_and_insert(&key(1), far).await.unwrap());
        // 不同 nonce 独立
        assert!(store.check_and_insert(&key(2), far).await.unwrap());
        // 不同 sender fingerprint 独立
        let mut other = key(1);
        other.from_fingerprint = [9u8; 32];
        assert!(store.check_and_insert(&other, far).await.unwrap());
    }

    #[tokio::test]
    async fn full_store_fails_closed_but_sweeps_expired() {
        let store = MemoryReplayStore::new_single_instance(16);
        let now = buckyos_kit::buckyos_get_unix_timestamp();
        // 填满(已过期 entry)
        for i in 0..16 {
            assert!(store
                .check_and_insert(&key(i), now.saturating_sub(10))
                .await
                .unwrap());
        }
        // 过期 entry 被清理后可继续插入
        assert!(store.check_and_insert(&key(100), now + 600).await.unwrap());
        // 用未过期 entry 填满 → fail closed
        for i in 101..116 {
            let _ = store.check_and_insert(&key(i), now + 600).await;
        }
        let err = store.check_and_insert(&key(200), now + 600).await;
        assert!(matches!(err, Err(S2sError::ReplayStoreUnavailable(_))));
    }

    #[tokio::test]
    async fn concurrent_same_nonce_only_one_wins() {
        use std::sync::Arc;
        let store = Arc::new(MemoryReplayStore::new_single_instance(1000));
        let far = buckyos_kit::buckyos_get_unix_timestamp() + 600;
        let mut handles = Vec::new();
        for _ in 0..32 {
            let store = store.clone();
            handles.push(tokio::spawn(async move {
                store.check_and_insert(&key(7), far).await.unwrap()
            }));
        }
        let mut winners = 0;
        for h in handles {
            if h.await.unwrap() {
                winners += 1;
            }
        }
        assert_eq!(winners, 1);
    }
}
