use super::*;

fn key(id: u64) -> ReplayKey {
    let mut nonce = [0; S2S_NONCE_LEN];
    nonce[..8].copy_from_slice(&id.to_le_bytes());
    ReplayKey {
        version: 1,
        from_did: "did:web:sender.example".into(),
        from_fingerprint: [1; 32],
        to_did: "did:web:receiver.example".into(),
        to_fingerprint: [2; 32],
        nonce,
    }
}

#[test]
fn full_store_recovers_without_restart_and_never_evicts_live_nonces() {
    let store = MemoryReplayStore::new_single_instance(16);
    for id in 0..16 {
        assert!(store.check_and_insert_at(&key(id), 1360, 1000).unwrap());
    }
    for id in 16..1016 {
        assert!(matches!(store.check_and_insert_at(&key(id), 1719, 1359),
            Err(S2sError::ReplayStoreUnavailable(_))));
    }
    let stats = store.stats().unwrap();
    assert_eq!(stats.entries, 16);
    assert_eq!(stats.capacity_rejections, 1000);
    assert_eq!(stats.cleanup_nanos, 0);
    assert_eq!(stats.expired_entries, 0);
    assert!(!store.check_and_insert_at(&key(0), 1720, 1359).unwrap());
    assert!(store.check_and_insert_at(&key(1016), 1720, 1360).unwrap());
    assert!(!store.check_and_insert_at(&key(1016), 1720, 1361).unwrap());
    let stats = store.stats().unwrap();
    assert_eq!(stats.entries, 1);
    assert_eq!(stats.expired_entries, 16);
    assert_eq!(stats.high_watermark, 16);
    assert_eq!(stats.replays, 2);
    assert_eq!(stats.inserted, 17);
}

#[test]
fn expiry_index_handles_out_of_order_lifetimes_and_duplicate_deadlines() {
    let store = MemoryReplayStore::new_single_instance(16);
    for (id, expiry) in [(1, 1500), (2, 1100), (3, 1100), (4, 1400)] {
        assert!(store.check_and_insert_at(&key(id), expiry, 1000).unwrap());
    }
    assert!(!store.check_and_insert_at(&key(2), 1600, 1099).unwrap());
    assert!(store.check_and_insert_at(&key(5), 1600, 1100).unwrap());
    assert_eq!(store.stats().unwrap().expired_entries, 2);
    assert_eq!(store.stats().unwrap().entries, 3);
    assert!(!store.check_and_insert_at(&key(1), 1600, 1100).unwrap());
    let state = store.inner.lock().unwrap();
    assert_eq!(state.expirations.values().map(Vec::len).sum::<usize>(), state.keys.len());
}

#[test]
fn expired_entries_are_cleaned_before_capacity_is_reached() {
    let store = MemoryReplayStore::new_single_instance(100_000);
    assert!(store.check_and_insert_at(&key(1), 10, 1).unwrap());
    assert!(store.check_and_insert_at(&key(2), 20, 10).unwrap());
    assert_eq!(store.stats().unwrap().entries, 1);
    assert_eq!(store.stats().unwrap().expired_entries, 1);
}

#[test]
fn default_capacity_pressure_and_recovery() {
    let store = MemoryReplayStore::with_default_capacity();
    for id in 0..S2S_DEFAULT_REPLAY_CAPACITY as u64 {
        assert!(store.check_and_insert_at(&key(id), 360, 0).unwrap());
    }
    assert!(store.check_and_insert_at(&key(100_001), 360, 0).is_err());
    assert!(store.check_and_insert_at(&key(100_002), 720, 360).unwrap());
    assert_eq!(store.stats().unwrap().expired_entries, 100_000);
}

#[test]
fn poisoned_store_fails_closed() {
    let store = Arc::new(MemoryReplayStore::new_single_instance(16));
    let other = store.clone();
    assert!(std::thread::spawn(move || {
        let _guard = other.inner.lock().unwrap();
        panic!("poison store");
    }).join().is_err());
    assert!(matches!(store.check_and_insert_at(&key(1), 100, 1),
        Err(S2sError::ReplayStoreUnavailable(reason)) if reason == "poisoned lock"));
    assert!(store.stats().is_err());
}
