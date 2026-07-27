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
use std::collections::HashMap;
use std::sync::Mutex;

/// replay key(§10.1 冻结字段)。
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ReplayKey {
    pub version: u32,
    /// wire 形式 canonical from key ref。
    pub from_key_ref: String,
    /// AEAD 实际成功的 sender key fingerprint。
    pub from_fingerprint: [u8; 32],
    pub to_key_ref: String,
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
    inner: Mutex<HashMap<ReplayKey, u64>>,
    capacity: usize,
}

pub const S2S_DEFAULT_REPLAY_CAPACITY: usize = 100_000;

impl MemoryReplayStore {
    pub fn new_single_instance(capacity: usize) -> Self {
        MemoryReplayStore {
            inner: Mutex::new(HashMap::new()),
            capacity: capacity.max(16),
        }
    }

    pub fn with_default_capacity() -> Self {
        Self::new_single_instance(S2S_DEFAULT_REPLAY_CAPACITY)
    }

    fn sweep_expired(map: &mut HashMap<ReplayKey, u64>, now: u64) {
        map.retain(|_, retain_until| *retain_until > now);
    }
}

#[async_trait]
impl S2sReplayStore for MemoryReplayStore {
    async fn check_and_insert(&self, key: &ReplayKey, retain_until: u64) -> S2sResult<bool> {
        let now = buckyos_kit::buckyos_get_unix_timestamp();
        let mut map = self
            .inner
            .lock()
            .map_err(|_| S2sError::ReplayStoreUnavailable("poisoned lock".to_string()))?;
        if map.contains_key(key) {
            return Ok(false);
        }
        if map.len() >= self.capacity {
            Self::sweep_expired(&mut map, now);
            if map.len() >= self.capacity {
                // 满且不可清理:fail closed,不静默丢弃防护
                return Err(S2sError::ReplayStoreUnavailable(
                    "replay store full".to_string(),
                ));
            }
        }
        map.insert(key.clone(), retain_until);
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(nonce_fill: u8) -> ReplayKey {
        ReplayKey {
            version: 1,
            from_key_ref: "did:web:a.example.com".to_string(),
            from_fingerprint: [1u8; 32],
            to_key_ref: "did:web:b.example.com".to_string(),
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
            assert!(store.check_and_insert(&key(i), now.saturating_sub(10)).await.unwrap());
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
