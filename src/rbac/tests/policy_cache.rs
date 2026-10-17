//! The process enforcer with the cached matcher functions, against plain
//! Casbin on the BuckyOS model and default policy (fixtures copied from
//! buckyos `kernel/buckyos-api/src/rbac_config.rs`).
//!
//! The enforcer and the counters are process-wide, so every test here holds
//! `SERIAL`. `cargo test -p rbac --release --test policy_cache -- --include-ignored --nocapture`
//! runs the full equivalence matrix and prints the benchmark figures.

use casbin::{CoreApi, DefaultModel, Enforcer, MemoryAdapter, MgmtApi};
use lazy_static::lazy_static;
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use tokio::sync::Mutex;

const MODEL: &str = include_str!("fixtures/buckyos_model.conf");
const DEFAULT_POLICY: &str = include_str!("fixtures/buckyos_policy.csv");

/// Zone tail in the shape the scheduler writes it.
const ZONE_TAIL: &str = r#"
g, alice, admin
g, su_alice, su_admin
g, bob, users
g, su_bob, su_users
g, carol, limited
g, ood1, ood
g, node2, node
g, app:notes, app
g, system:workflow, system
g, did:web:xiaobai.test.buckyos.io, agent
g, app:xiaobai.test.buckyos.io, agent_runtime
"#;

lazy_static! {
    static ref SERIAL: Mutex<()> = Mutex::new(());
}

struct CountingAlloc;

static ALLOC_CALLS: AtomicU64 = AtomicU64::new(0);
static ALLOC_BYTES: AtomicU64 = AtomicU64::new(0);

unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOC_CALLS.fetch_add(1, Ordering::Relaxed);
        ALLOC_BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
        System.alloc(layout)
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        ALLOC_CALLS.fetch_add(1, Ordering::Relaxed);
        ALLOC_BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
        System.alloc_zeroed(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout)
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOC_CALLS.fetch_add(1, Ordering::Relaxed);
        ALLOC_BYTES.fetch_add(new_size as u64, Ordering::Relaxed);
        System.realloc(ptr, layout, new_size)
    }
}

#[global_allocator]
static GLOBAL: CountingAlloc = CountingAlloc;

fn policy_with(tail: &str) -> String {
    format!("{}\n{}", DEFAULT_POLICY.trim(), tail.trim())
}

/// Plain Casbin, built the way `rbac` built it before the cached matchers.
async fn reference_enforcer(policy: &str) -> Enforcer {
    let mut e = Enforcer::new(
        DefaultModel::from_str(MODEL).await.unwrap(),
        MemoryAdapter::default(),
    )
    .await
    .unwrap();
    for line in policy.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let rule: Vec<String> = line.split(',').map(|s| s.trim().to_string()).collect();
        if rule[0] == "p" {
            e.add_policy(rule[1..].to_vec()).await.unwrap();
        } else if rule[0] == "g" {
            e.add_grouping_policy(rule[1..].to_vec()).await.unwrap();
        }
    }
    e
}

const SUBJECTS: &[&str] = &[
    "alice",
    "su_alice",
    "bob",
    "su_bob",
    "carol",
    "mallory",
    "ood1",
    "node2",
    "root",
    "app:notes",
    "app:unknown",
    "app:xiaobai.test.buckyos.io",
    "did:web:xiaobai.test.buckyos.io",
    "system:control-panel",
    "system:msg-center",
    "system:scheduler",
    "system:homestation",
    "system:workflow",
    "system:node-daemon",
    "张三",
];

const RESOURCES: &[&str] = &[
    "obj://config/boot/config",
    "obj://config/system/rbac/policy",
    "obj://config/system/content_registry",
    "obj://config/security/alice/key",
    "obj://config/users",
    "obj://config/users/alice",
    "obj://config/users/alice/profile",
    "obj://config/users/alice/settings",
    "obj://config/users/bob/profile",
    "obj://config/users/alice/content_defaults",
    "obj://config/users/alice/apps/notes/settings",
    "obj://config/users/alice/apps/notes/spec",
    "obj://config/users/bob/apps/notes/settings",
    "obj://config/users/alice/agents",
    "obj://config/users/alice/agents/xiaobai.test.buckyos.io/spec",
    "obj://config/users/alice/agents/xiaobai.test.buckyos.io/profile",
    "obj://config/users/bob/agents/xiaobai.test.buckyos.io/settings",
    "obj://config/services/msg-center/info",
    "obj://config/services/msg-center/settings",
    "obj://config/services/notes@alice/instances/ood1",
    "obj://config/services/notes@alice@x/instances/ood1",
    "obj://config/services/workflow/state",
    "obj://msg-center/objects",
    "obj://msg-center/notify",
    "obj://msg-center/group",
    "obj://msg-center/inbox/did:web:alice.test.buckyos.io",
    "obj://msg-center/owners/did:web:xiaobai.test.buckyos.io",
    "obj://task/alice",
    "obj://task/bob",
    "obj://config/users/张三/profile",
    "obj://config/users/a+b/apps/x.y/settings",
    "dfs://homes/alice",
];

const ACTIONS: &[&str] = &[
    "read",
    "write",
    "create",
    "delete",
    "list",
    "all",
    "subscribe",
];

async fn compare_with_casbin(subjects: &[&str], resources: &[&str], actions: &[&str]) {
    let policy = policy_with(ZONE_TAIL);
    let reference = reference_enforcer(&policy).await;
    rbac::create_enforcer(MODEL, &policy).await.unwrap();

    let mut allowed = 0;
    let mut compared = 0;
    for subject in subjects {
        for resource in resources {
            for action in actions {
                let expected = reference.enforce((*subject, *resource, *action)).unwrap();
                // Same subject on the app and user side: one subject's answer.
                let actual = rbac::enforce(subject, subject, resource, action, None).await;
                assert_eq!(actual, expected, "{subject} {action} {resource}");
                allowed += usize::from(expected);
                compared += 1;
            }
        }
    }
    assert!(
        allowed > compared / 10 && allowed < compared * 9 / 10,
        "{allowed}/{compared}"
    );
}

#[tokio::test]
async fn cached_enforcer_matches_casbin_on_buckyos_policy() {
    let _serial = SERIAL.lock().await;
    // Every other subject and resource keeps the debug run short; the full
    // matrix is `full_matrix_matches_casbin`.
    let subjects: Vec<_> = SUBJECTS.iter().copied().step_by(2).collect();
    let resources: Vec<_> = RESOURCES.iter().copied().step_by(2).collect();
    compare_with_casbin(&subjects, &resources, &["read", "write", "all"]).await;
}

#[tokio::test]
#[ignore = "slow in debug builds; run with --release -- --ignored"]
async fn full_matrix_matches_casbin() {
    let _serial = SERIAL.lock().await;
    compare_with_casbin(SUBJECTS, RESOURCES, ACTIONS).await;
}

#[tokio::test]
async fn sudo_and_two_sided_checks_are_unchanged() {
    let _serial = SERIAL.lock().await;
    rbac::create_enforcer(MODEL, &policy_with(ZONE_TAIL))
        .await
        .unwrap();
    let settings = "obj://config/users/bob/apps/notes/settings";
    assert!(rbac::enforce("bob", "app:notes", settings, "write", None).await);
    assert!(!rbac::enforce("alice", "app:notes", settings, "write", None).await);
    assert!(!rbac::enforce("bob", "app:unknown", settings, "read", None).await);
    let profile = "obj://config/users/alice/profile";
    assert!(rbac::enforce("alice", "system:control-panel", profile, "write", None).await);
    assert!(!rbac::enforce("bob", "system:control-panel", profile, "write", None).await);
    assert!(
        rbac::enforce(
            "bob",
            "system:control-panel",
            profile,
            "write",
            Some(rbac::SudoMode::Sudo("su_alice".to_string())),
        )
        .await
    );
}

#[tokio::test]
async fn apply_rebuilds_only_for_changed_policy() {
    let _serial = SERIAL.lock().await;
    let base = policy_with(ZONE_TAIL);
    let probe = "obj://config/users/carol/apps/notes/settings";
    rbac::create_enforcer(MODEL, &base).await.unwrap();
    let builds = rbac::enforcer_build_count();

    // A TTL refresh reads back the same text again and again.
    for _ in 0..50 {
        assert!(!rbac::apply_enforcer_policy(MODEL, &base).await.unwrap());
    }
    assert_eq!(rbac::enforcer_build_count(), builds);
    assert!(!rbac::enforce("carol", "app:notes", probe, "write", None).await);

    // Grant.
    let granted = policy_with(&format!(
        "{ZONE_TAIL}\np, carol, {probe}, read|write, allow"
    ));
    assert!(rbac::apply_enforcer_policy(MODEL, &granted).await.unwrap());
    assert_eq!(rbac::enforcer_build_count(), builds + 1);
    assert!(rbac::enforce("carol", "app:notes", probe, "write", None).await);
    assert!(!rbac::apply_enforcer_policy(MODEL, &granted).await.unwrap());

    // Revocation.
    assert!(rbac::apply_enforcer_policy(MODEL, &base).await.unwrap());
    assert!(!rbac::enforce("carol", "app:notes", probe, "write", None).await);

    // Removed policy tail: the default policy alone.
    let alice_profile = "obj://config/users/alice/profile";
    assert!(
        rbac::enforce(
            "alice",
            "system:control-panel",
            alice_profile,
            "write",
            None
        )
        .await
    );
    assert!(rbac::apply_enforcer_policy(MODEL, DEFAULT_POLICY)
        .await
        .unwrap());
    assert!(
        !rbac::enforce(
            "alice",
            "system:control-panel",
            alice_profile,
            "write",
            None
        )
        .await
    );
    assert_eq!(rbac::enforcer_build_count(), builds + 3);

    // An invalid policy leaves the installed enforcer in place.
    assert!(rbac::apply_enforcer_policy("[matchers]\nm = (", &base)
        .await
        .is_err());
    assert!(
        !rbac::enforce(
            "alice",
            "system:control-panel",
            alice_profile,
            "write",
            None
        )
        .await
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_applies_of_one_policy_build_once() {
    let _serial = SERIAL.lock().await;
    rbac::create_enforcer(MODEL, DEFAULT_POLICY).await.unwrap();
    let builds = rbac::enforcer_build_count();
    let policy = policy_with(ZONE_TAIL);
    let tasks: Vec<_> = (0..16)
        .map(|_| {
            let policy = policy.clone();
            tokio::spawn(async move { rbac::apply_enforcer_policy(MODEL, &policy).await.unwrap() })
        })
        .collect();
    let mut installed = 0;
    for task in tasks {
        installed += usize::from(task.await.unwrap());
    }
    assert_eq!(installed, 1);
    assert_eq!(rbac::enforcer_build_count(), builds + 1);
    assert!(
        rbac::enforce(
            "alice",
            "system:control-panel",
            "obj://config/users/alice/profile",
            "write",
            None
        )
        .await
    );
}

/// A request mix in the shape msg-center and system-config see.
const BENCH_REQUESTS: &[(&str, &str, &str, &str)] = &[
    (
        "alice",
        "system:control-panel",
        "obj://config/users/alice/profile",
        "read",
    ),
    (
        "alice",
        "app:xiaobai.test.buckyos.io",
        "obj://msg-center/inbox/did:web:alice.test.buckyos.io",
        "read",
    ),
    (
        "bob",
        "app:notes",
        "obj://config/users/bob/apps/notes/settings",
        "write",
    ),
    (
        "ood1",
        "system:msg-center",
        "obj://config/users/alice/agents/xiaobai.test.buckyos.io/spec",
        "read",
    ),
    (
        "ood1",
        "system:homestation",
        "obj://msg-center/owners/did:web:alice.test.buckyos.io",
        "read",
    ),
    ("alice", "app:notes", "obj://msg-center/notify", "write"),
    (
        "bob",
        "app:notes",
        "obj://config/users/alice/profile",
        "read",
    ),
];

struct Measure {
    seconds: f64,
    allocs: u64,
    bytes: u64,
}

async fn measure<F, Fut>(rounds: usize, mut run: F) -> Measure
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let calls = ALLOC_CALLS.load(Ordering::Relaxed);
    let bytes = ALLOC_BYTES.load(Ordering::Relaxed);
    let started = Instant::now();
    for _ in 0..rounds {
        run().await;
    }
    Measure {
        seconds: started.elapsed().as_secs_f64(),
        allocs: ALLOC_CALLS.load(Ordering::Relaxed) - calls,
        bytes: ALLOC_BYTES.load(Ordering::Relaxed) - bytes,
    }
}

#[tokio::test]
async fn cached_matchers_stop_recompiling_and_allocating() {
    let _serial = SERIAL.lock().await;
    let policy = policy_with(ZONE_TAIL);
    let reference = reference_enforcer(&policy).await;
    rbac::create_enforcer(MODEL, &policy).await.unwrap();
    let rounds = 20;
    let requests = (rounds * BENCH_REQUESTS.len()) as f64;

    let before = measure(rounds, || async {
        for (user, app, resource, action) in BENCH_REQUESTS {
            let allowed = reference.enforce((*app, *resource, *action)).unwrap()
                && reference.enforce((*user, *resource, *action)).unwrap();
            std::hint::black_box(allowed);
        }
    })
    .await;

    // Warm the pattern caches, then measure.
    for (user, app, resource, action) in BENCH_REQUESTS {
        rbac::enforce(user, app, resource, action, None).await;
    }
    let compiles = rbac::matcher_regex_compile_count();
    let patterns = rbac::matcher_cached_pattern_count();
    let after = measure(rounds, || async {
        for (user, app, resource, action) in BENCH_REQUESTS {
            std::hint::black_box(rbac::enforce(user, app, resource, action, None).await);
        }
    })
    .await;
    assert_eq!(rbac::matcher_regex_compile_count(), compiles);

    // Distinct request paths are inputs, never cached patterns.
    for i in 0..2_000 {
        let inbox = format!("obj://msg-center/inbox/did:web:user{i}.test.buckyos.io");
        let profile = format!("obj://config/users/user{i}/profile");
        rbac::enforce("alice", "app:xiaobai.test.buckyos.io", &inbox, "read", None).await;
        rbac::enforce("alice", "system:control-panel", &profile, "read", None).await;
    }
    assert_eq!(rbac::matcher_regex_compile_count(), compiles);
    assert_eq!(rbac::matcher_cached_pattern_count(), patterns);

    println!(
        "casbin built-ins: {:.1} us/request, {:.0} allocs/request, {:.0} KiB/request",
        before.seconds * 1e6 / requests,
        before.allocs as f64 / requests,
        before.bytes as f64 / requests / 1024.0
    );
    println!(
        "cached matchers:  {:.1} us/request, {:.0} allocs/request, {:.1} KiB/request; {} patterns cached, {} regex compiles in total",
        after.seconds * 1e6 / requests,
        after.allocs as f64 / requests,
        after.bytes as f64 / requests / 1024.0,
        patterns,
        compiles
    );
    assert!(
        after.bytes * 20 < before.bytes,
        "{} vs {}",
        after.bytes,
        before.bytes
    );
}
