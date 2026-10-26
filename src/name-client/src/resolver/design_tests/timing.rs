//! T14 共享任务、T15 回流、T17 预算分层。

use super::fixture::*;
use super::super::*;
use name_lib::{EncodedDocument, NSError, DID};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

fn long_opts() -> ResolveOpts {
    ResolveOpts::default().normalize(Duration::from_secs(60))
}

fn done(reason: &str) -> SourceAnswer {
    no_answer(reason)
}

/// 等到某个合并键登记了 `n` 个等待者(状态观察,不靠耗时阈值)。
async fn wait_waiters(merger: &TaskMerger, key: &str, n: usize) {
    tokio::time::timeout(Duration::from_secs(10), async {
        while merger.waiters(key) != n {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("waiters for {} never reached {} (now {})", key, n, merger.waiters(key)));
}

// ---------- T14 ----------

/// T14:A 创建共享任务、B 加入;取消 A 后 C 再加入。provider 只执行一次,B / C 收到同一回答;
/// A 的取消不传给共享 I/O,A 退出也不删除仍有等待者的登记。
#[tokio::test]
async fn t14_creator_cancel_keeps_joined_waiters_alive() {
    let merger = Arc::new(TaskMerger::new(ConcurrencyConfig::default()));
    let gate = Gate::new();
    let runs = Arc::new(AtomicUsize::new(0));
    let spawn_waiter = |opts: ResolveOpts| {
        let merger = merger.clone();
        let gate = gate.clone();
        let runs = runs.clone();
        tokio::spawn(async move {
            merger
                .merge_or_run("k".into(), &opts, move |_budget| async move {
                    runs.fetch_add(1, Ordering::SeqCst);
                    gate.pass().await;
                    done("shared answer")
                })
                .await
        })
    };

    let cancel_a = CancellationToken::new();
    let a = spawn_waiter(ResolveOpts::default().with_cancel(cancel_a.clone()).normalize(Duration::from_secs(60)));
    gate.wait_entered().await;
    let b = spawn_waiter(long_opts());
    wait_waiters(&merger, "k", 2).await;

    cancel_a.cancel();
    let a = a.await.unwrap();
    assert!(matches!(a, Err(NSError::Cancelled(_))), "{:?}", a);
    assert_eq!(merger.waiters("k"), 1, "A left; B still registered");

    let c = spawn_waiter(long_opts());
    wait_waiters(&merger, "k", 2).await;
    assert_eq!(gate.entries(), 1, "C joined the existing task instead of starting a second one");

    gate.release(8);
    let b = b.await.unwrap().unwrap();
    let c = c.await.unwrap().unwrap();
    assert_eq!(b.reason.as_deref(), Some("shared answer"));
    assert_eq!(c.reason.as_deref(), Some("shared answer"));
    assert_eq!(runs.load(Ordering::SeqCst), 1);
    assert_eq!(gate.dropped(), 0, "creator cancellation must not drop the shared I/O");
    assert_eq!(merger.running_tasks(), 0);
}

/// T14:drop / abort 等待 Future 也要正确离开:最后一个等待者离开时丢弃未完成的 provider
/// Future、释放许可、清理登记;之后同键新请求正常执行。
#[tokio::test]
async fn t14_dropped_waiters_release_membership_and_last_one_cancels_the_task() {
    let merger = Arc::new(TaskMerger::new(ConcurrencyConfig::default()));
    let gate = Gate::new();
    let permits = merger.available_permits();
    let spawn_waiter = |gate: Arc<Gate>| {
        let merger = merger.clone();
        tokio::spawn(async move {
            merger
                .merge_or_run("k".into(), &long_opts(), move |_budget| async move {
                    gate.pass().await;
                    done("answer")
                })
                .await
        })
    };
    let a = spawn_waiter(gate.clone());
    gate.wait_entered().await;
    let b = spawn_waiter(gate.clone());
    wait_waiters(&merger, "k", 2).await;

    b.abort();
    let _ = b.await;
    wait_waiters(&merger, "k", 1).await;
    assert_eq!(gate.dropped(), 0, "one waiter leaving does not cancel the others' task");

    a.abort();
    let _ = a.await;
    tokio::time::timeout(Duration::from_secs(10), async {
        while gate.dropped() == 0 || merger.running_tasks() != 0 || merger.available_permits() != permits {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("last waiter leaving must drop the provider future, free the permit and the registration");

    let fresh = Gate::new();
    let again = spawn_waiter(fresh.clone());
    fresh.wait_entered().await;
    fresh.release(1);
    assert_eq!(again.await.unwrap().unwrap().reason.as_deref(), Some("answer"));
    assert_eq!(merger.running_tasks(), 0);
}

/// T14 首次创建变体:空任务表下两个调用都错过查找,只有一个取得创建权;不同策略键各执行一次。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t14_first_creation_race_yields_a_single_task() {
    async fn race(keys: [&'static str; 2]) -> usize {
        let merger = Arc::new(TaskMerger::new(ConcurrencyConfig::default()));
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let misses = Arc::new(AtomicUsize::new(0));
        {
            let barrier = barrier.clone();
            let misses = misses.clone();
            *merger.on_lookup_miss.lock().unwrap() = Some(Arc::new(move || {
                // 前两次未命中在这里会合,确保两者都越过了查找。
                if misses.fetch_add(1, Ordering::SeqCst) < 2 {
                    barrier.wait();
                }
            }));
        }
        let gate = Gate::new();
        let mut handles = Vec::new();
        for key in keys {
            let merger = merger.clone();
            let gate = gate.clone();
            handles.push(tokio::spawn(async move {
                merger
                    .merge_or_run(key.into(), &long_opts(), move |_budget| async move {
                        gate.pass().await;
                        done("answer")
                    })
                    .await
            }));
        }
        // 两个调用都已登记(加入同一任务,或各自创建了任务)。
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let registered: usize = keys.iter().collect::<std::collections::HashSet<_>>().iter().map(|k| merger.waiters(k)).sum();
                if registered == 2 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("both callers registered");
        gate.release(8);
        for handle in handles {
            handle.await.unwrap().unwrap();
        }
        gate.entries()
    }
    assert_eq!(race(["same", "same"]).await, 1, "same key: exactly one creator");
    assert_eq!(race(["policy-a", "policy-b"]).await, 2, "different keys: separate tasks");
}

/// T14:共享任务的期限不因后加入者延长(任务期限 = min(共享上限, 发起者剩余))。
#[tokio::test(start_paused = true)]
async fn t14_joiners_do_not_extend_the_shared_task_deadline() {
    let merger = Arc::new(TaskMerger::new(ConcurrencyConfig {
        shared_task_timeout: Duration::from_secs(1),
        ..Default::default()
    }));
    let started = tokio::time::Instant::now();
    let spawn_waiter = |secs: u64| {
        let merger = merger.clone();
        tokio::spawn(async move {
            let opts = ResolveOpts::default().normalize(Duration::from_secs(secs));
            merger
                .merge_or_run("k".into(), &opts, move |budget| async move {
                    match budget.run(budget.remaining(), tokio::time::sleep(Duration::from_secs(5))).await {
                        Ok(()) => done("slow answer"),
                        Err(err) => SourceAnswer::unknown(sref("x", SourceTier::Normal), err.into_ns_error().to_string(), false),
                    }
                })
                .await
        })
    };
    let a = spawn_waiter(30);
    wait_waiters(&merger, "k", 1).await;
    let b = spawn_waiter(60);
    wait_waiters(&merger, "k", 2).await;
    let b = b.await.unwrap().unwrap();
    assert!(b.is_unknown() && b.reason.as_deref() != Some("slow answer"));
    assert!(started.elapsed() <= Duration::from_millis(1100), "task ran {:?}", started.elapsed());
    let _ = a.await;
}

// ---------- T15 ----------

/// 预热:trust 提供有效 V1(best);authority 对 zone 不回答,normal 的 V2 停在闸门。
async fn reentrant_fixture() -> (Arc<Fx>, Arc<Gate>, EncodedDocument, EncodedDocument) {
    let fx = Arc::new(Fx::new());
    fx.publish_default_owner();
    let v1 = fx.zone_json(100, "v1");
    let v2 = fx.zone_jwt(200, "v2", &K1);
    fx.trust.add(&zone_did(), &zone(), &v1);
    fx.authority.script(&zone_did(), Some(&zone()), None, vec![Step::Answer(no_answer("not published"))]);
    let warm = fx.resolve(Revision::current(), fx.opts()).await;
    assert_eq!(warm.best.as_ref().unwrap().revision, rev(&v1));
    fx.expire_query_cache(NOW);
    let gate = Gate::new();
    fx.normal.script(&zone_did(), Some(&zone()), None, vec![Step::Gated(gate.clone(), body_only(&v2))]);
    (fx, gate, v1, v2)
}

/// T15:外层停在补充 provider 的 I/O;新的入站调用(独立上下文、同 scope/DID/doc_type、严格离线)
/// 必须在外层 provider 完成前返回。只有观察到内层完成才放行外层。
#[tokio::test]
async fn t15_inbound_resolve_completes_while_outer_waits_in_provider_io() {
    let (fx, gate, v1, v2) = reentrant_fixture().await;
    let outer = {
        let fx = fx.clone();
        tokio::spawn(async move { fx.resolve(Revision::current(), fx.opts()).await })
    };
    gate.wait_entered().await;

    let inner = tokio::time::timeout(
        Duration::from_secs(5),
        fx.client.resolve_did_ex(&zone_did(), Some(zone()), Revision::current(), fx.opts().strictly_offline()),
    )
    .await
    .expect("inner resolve blocked behind the outer provider I/O (lock held across I/O)")
    .unwrap();
    assert_eq!(inner.best.as_ref().unwrap().revision, rev(&v1));
    let inner_exact = tokio::time::timeout(
        Duration::from_secs(5),
        fx.client.resolve_did_ex(
            &zone_did(),
            Some(zone()),
            Revision::exact(rev(&v1).iat, &rev(&v1).hash),
            fx.opts().strictly_offline(),
        ),
    )
    .await
    .expect("inner exact resolve blocked behind the outer provider I/O");
    assert!(inner_exact.is_ok());
    assert_eq!(gate.completed(), 0, "outer provider is still waiting");

    gate.release(1);
    let outer = outer.await.unwrap();
    assert_eq!(outer.best.as_ref().unwrap().revision, rev(&v2));
    fx.finish();
}

/// T15:current / exact / closest 共用 `(scope, DID, doc_type)` 串行锁键,提交段在锁内。
#[tokio::test]
async fn t15_lock_key_ignores_revision_and_commit_runs_inside_the_lock() {
    let (fx, gate, _v1, _v2) = reentrant_fixture().await;
    let probe_opts = fx.client.normalize_opts(fx.opts());
    let guard = fx.client.serialize_document(&zone_did(), &zone(), &probe_opts).await.unwrap();
    for revision in [Revision::exact(1, "aa"), Revision::closest(fx.at(150))] {
        let err = fx
            .client
            .resolve_did_ex(&zone_did(), Some(zone()), revision.clone(), fx.opts().strictly_offline().with_timeout(Duration::from_millis(100)))
            .await
            .unwrap_err();
        assert!(matches!(err, NSError::DeadlineExceeded(_)), "{} must wait on the same lock: {:?}", revision, err);
    }
    drop(guard);

    // 提交段探针:外层在 I/O 中不持锁;放行 provider 时测试持锁,外层提交必须等待。
    let outer = {
        let fx = fx.clone();
        tokio::spawn(async move { fx.resolve(Revision::current(), fx.opts()).await })
    };
    gate.wait_entered().await;
    let guard = fx.client.serialize_document(&zone_did(), &zone(), &probe_opts).await.unwrap();
    gate.release(1);
    for _ in 0..200 {
        tokio::task::yield_now().await;
    }
    assert!(!outer.is_finished(), "commit must wait for the serial lock");
    drop(guard);
    assert!(outer.await.unwrap().best.is_some());
}

// ---------- T17 ----------

fn paused_fx(grace: Duration) -> Fx {
    Fx::with_config(FxConfig {
        resolve_timeout: Duration::from_secs(10),
        request_timeout: Duration::from_secs(2),
        supplement_grace: grace,
        ..Default::default()
    })
}

/// T17:单个来源先超时、总预算仍有余量 → 在剩余预算内继续下一个来源,保留来源原因。
#[tokio::test(start_paused = true)]
async fn t17_source_timeout_moves_on_within_the_remaining_budget() {
    let fx = paused_fx(Duration::from_secs(1));
    fx.publish_default_owner();
    let v2 = fx.zone_jwt(200, "v2", &K1);
    fx.authority.script(&zone_did(), Some(&zone()), None, vec![Step::Sleep(Duration::from_secs(5), no_answer("late"))]);
    fx.normal.add(&zone_did(), &zone(), &v2);
    let started = tokio::time::Instant::now();
    let opts = fx.opts().normalize(Duration::from_secs(10));
    let result = fx.resolve(Revision::current(), opts.clone()).await;
    assert_eq!(result.best.as_ref().unwrap().revision, rev(&v2));
    assert!(result.reason().contains("authority"), "{}", result.reason());
    assert!(
        opts.receipts().unanswered().iter().any(|u| u.source.id == "authority" && u.reason.contains("timed out")),
        "{:?}",
        opts.receipts().unanswered()
    );
    assert!(started.elapsed() < Duration::from_secs(5), "authority step was capped: {:?}", started.elapsed());
    fx.finish();
}

/// T17:authority 本轮给出有效 best,补充源到宽限期未回答 → 返回 authority best,慢源为本轮
/// Unknown,不因宽限期计失败退避(下一轮照常查询)。
#[tokio::test(start_paused = true)]
async fn t17_supplement_grace_is_an_unknown_not_a_backoff() {
    let fx = paused_fx(Duration::from_secs(1));
    fx.publish_default_owner();
    let v1 = fx.zone_jwt(100, "v1", &K1);
    fx.authority.publish(&zone_did(), &zone(), &v1);
    fx.normal.script(
        &zone_did(),
        Some(&zone()),
        None,
        vec![Step::Sleep(Duration::from_secs(1) + Duration::from_millis(500), body_only(&fx.zone_jwt(200, "v2", &K1)))],
    );
    for round in 1..=2 {
        let opts = fx.opts().with_force_authority_query().normalize(Duration::from_secs(10));
        let started = tokio::time::Instant::now();
        let result = fx.resolve(Revision::current(), opts.clone()).await;
        assert_eq!(result.best.as_ref().unwrap().revision, rev(&v1), "round {}", round);
        assert!(started.elapsed() <= Duration::from_millis(1100), "round {} waited {:?}", round, started.elapsed());
        assert!(opts.receipts().unanswered().iter().any(|u| u.source.id == "normal-site"));
        assert_eq!(fx.normal.call_count(), round, "grace expiry does not back the source off");
    }
}

/// T17:旧缓存 best + 本轮 authority Unknown → 不套用"本轮 authority 已成功"的宽限期,
/// 慢补充源在单源上限内回答的较新有效文档可被取得。
#[tokio::test(start_paused = true)]
async fn t17_stale_best_with_unknown_authority_does_not_trigger_the_grace() {
    let fx = paused_fx(Duration::from_secs(1));
    fx.publish_default_owner();
    let v1 = fx.zone_jwt(100, "v1", &K1);
    fx.authority.publish(&zone_did(), &zone(), &v1);
    let warm = fx.resolve(Revision::current(), fx.opts()).await;
    assert_eq!(warm.best.as_ref().unwrap().revision, rev(&v1));
    fx.expire_query_cache(NOW);

    let v2 = fx.zone_jwt(200, "v2", &K1);
    fx.authority.script(&zone_did(), Some(&zone()), Some(&Revision::current()), vec![Step::Answer(failure("HTTP 503"))]);
    fx.normal.script(&zone_did(), Some(&zone()), None, vec![Step::Sleep(Duration::from_millis(1500), body_only(&v2))]);
    let before = fx.authority.calls_for(&zone_did(), &Revision::current());
    let result = fx.resolve(Revision::current(), fx.opts().with_force_authority_query()).await;
    assert_eq!(fx.authority.calls_for(&zone_did(), &Revision::current()), before + 1, "this round really asked the authority");
    assert_eq!(result.best.as_ref().unwrap().revision, rev(&v2), "{}", result.reason());
}

/// T17:总预算耗尽或调用取消 → 整次调用终止,不 fallback 到缓存 best,也不把本地超时写成
/// "不存在 / 禁用 / 撤销";未共享的未完成工作被取消。
#[tokio::test(start_paused = true)]
async fn t17_exhaustion_and_cancellation_terminate_without_writing_negative_state() {
    // 单源上限大于总预算:本例只测总预算耗尽 / 取消。
    let fx = Fx::with_config(FxConfig {
        request_timeout: Duration::from_secs(20),
        ..Default::default()
    });
    fx.publish_default_owner();
    let v1 = fx.zone_jwt(100, "v1", &K1);
    fx.authority.publish(&zone_did(), &zone(), &v1);
    fx.resolve(Revision::current(), fx.opts()).await;
    let gate = Gate::new();
    fx.authority.script(&zone_did(), Some(&zone()), None, vec![Step::Gated(gate.clone(), no_answer("never"))]);

    let err = fx
        .client
        .resolve_did_ex(&zone_did(), Some(zone()), Revision::current(), fx.opts().with_force_authority_query().with_timeout(Duration::from_secs(3)))
        .await
        .unwrap_err();
    assert!(matches!(err, NSError::DeadlineExceeded(_)), "{:?}", err);
    gate.wait_entered().await;

    let cancel = CancellationToken::new();
    let opts = fx.opts().with_force_authority_query().with_cancel(cancel.clone());
    let zone_id = zone_did();
    let (res, _) = tokio::join!(
        fx.client.resolve_did_ex(&zone_id, Some(zone()), Revision::current(), opts),
        async {
            gate.wait_entered().await;
            cancel.cancel();
        }
    );
    assert!(matches!(res, Err(NSError::Cancelled(_))), "{:?}", res);

    tokio::time::timeout(Duration::from_secs(10), async {
        while gate.dropped() < 2 || fx.client.merger.running_tasks() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("unshared provider work is dropped and the registration cleared");

    let stored = fx.stored(&zone_did(), &zone()).unwrap();
    assert!(!stored.is_disabled() && !stored.is_not_exist(), "local timeout is not a negative fact");
    assert_eq!(stored.best.as_ref().unwrap().revision, rev(&v1), "completed commits stay");
}

/// T17:先等锁 / 许可消耗预算,再进入 owner current、closest:每层继承原截止时间。
#[tokio::test(start_paused = true)]
async fn t17_lock_and_permit_waits_consume_the_same_deadline() {
    let fx = Fx::with_config(FxConfig {
        concurrency: ConcurrencyConfig {
            max_concurrent_queries: 1,
            ..Default::default()
        },
        ..Default::default()
    });
    let fx = Arc::new(fx);
    fx.publish_default_owner();
    let v2 = fx.zone_jwt(200, "v2", &K1);
    fx.normal.add(&zone_did(), &zone(), &v2);

    // 另一个 DID 的请求占住唯一许可 2 秒。
    let other = DID::new("bns", "zone2.alice");
    let blocker = Gate::new();
    fx.authority.script(&other, None, None, vec![Step::Gated(blocker.clone(), no_answer("other"))]);
    let hog = {
        let fx = fx.clone();
        let other = other.clone();
        tokio::spawn(async move {
            fx.client.resolve_did_ex(&other, Some(zone()), Revision::current(), fx.opts()).await
        })
    };
    blocker.wait_entered().await;

    let opts = fx.opts().normalize(Duration::from_secs(10));
    let deadline = opts.budget().deadline();
    // 同时持有 zone 的串行锁 1 秒。
    let guard = fx.client.serialize_document(&zone_did(), &zone(), &opts).await.unwrap();
    let main = {
        let fx = fx.clone();
        let opts = opts.clone();
        tokio::spawn(async move { fx.resolve(Revision::current(), opts).await })
    };
    tokio::time::sleep(Duration::from_secs(1)).await;
    drop(guard);
    tokio::time::sleep(Duration::from_secs(1)).await;
    blocker.release(1);
    let result = main.await.unwrap();
    let _ = hog.await;
    assert_eq!(result.best.as_ref().unwrap().revision, rev(&v2), "{}", result.reason());

    let owner_calls: Vec<Call> = fx.authority.calls().into_iter().filter(|c| c.did == owner_did()).collect();
    assert!(owner_calls.iter().any(|c| c.revision.is_current()));
    for call in fx.authority.calls().into_iter().chain(fx.normal.calls()).chain(fx.trust.calls()) {
        if call.did == other {
            continue;
        }
        assert!(call.deadline <= deadline, "{} {} renewed the deadline", call.source, call.revision);
    }
    for call in owner_calls {
        assert_eq!(call.deadline, deadline, "owner {} inherits the outer deadline", call.revision);
        assert!(call.depth > 0, "owner query is a recursion of the outer call");
    }
}

/// T17 跨主机变体:Zone locker 请求带剩余预算毫秒数,不带绝对单调时钟;服务端按本地单调
/// 时钟重建并收紧预算,剩余时间不增加。
#[tokio::test]
async fn t17_zone_locker_sends_remaining_budget_and_no_zone_lock() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut input = Vec::new();
        let mut buf = [0u8; 1024];
        while !input.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = stream.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            input.extend_from_slice(&buf[..n]);
        }
        let _ = stream
            .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await;
        String::from_utf8(input).unwrap()
    });
    let locker = ZoneLocker::new(ZoneLockerConfig {
        endpoint: format!("http://{}", addr),
        ..Default::default()
    });
    let opts = ResolveOpts::default().normalize(Duration::from_secs(5));
    tokio::time::sleep(Duration::from_millis(300)).await;
    let answer = locker.get_document(&zone_did(), &zone(), &Revision::current(), &opts).await;
    assert!(answer.is_unknown() && !answer.cacheable);
    let request = server.await.unwrap().to_ascii_lowercase();
    let budget_ms: u64 = request
        .lines()
        .find_map(|l| l.strip_prefix(&format!("{}:", RESOLVE_BUDGET_HEADER.to_ascii_lowercase())))
        .expect("budget header")
        .trim()
        .parse()
        .unwrap();
    assert!(budget_ms > 0 && budget_ms <= 4_700, "remaining budget {}ms", budget_ms);
    assert!(request.contains(&format!("{}: 1", RESOLVE_NO_ZONE_LOCK_HEADER.to_ascii_lowercase())));

    // 服务端:本地上限 60s,收到 budget_ms;重建后剩余时间不超过收到的值。
    let server_budget = Budget::new(Duration::from_secs(60)).child(Duration::from_millis(budget_ms));
    assert!(server_budget.remaining() <= Duration::from_millis(budget_ms));
}
