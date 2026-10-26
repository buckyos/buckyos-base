//! T07 有效期、T08 负状态范围、T16 提交后重新裁决。

use super::fixture::*;
use super::super::*;
use name_lib::{DidDocType, EncodedDocument, DID};
use std::sync::Arc;

fn persistent(dir: &tempfile::TempDir) -> FxConfig {
    FxConfig {
        persistent_dir: Some(dir.path().to_path_buf()),
        ..Default::default()
    }
}

fn device() -> DidDocType {
    DidDocType::Device
}

// ---------- T07 ----------

/// T07:长来源缓存不能延长文档生命。exp 等号即不可选;离线读取不发任何请求。
#[tokio::test]
async fn t07_document_exp_boundary_is_exact_and_offline() {
    let fx = Fx::new();
    fx.set_now(10_009);
    let d = zone_json(fx.at(100), fx.at(10_010), "short-lived");
    let mut cached = body_only(&d);
    cached.ttl_secs = Some(100);
    fx.trust.script(&zone_did(), Some(&zone()), None, vec![Step::Answer(cached)]);
    fx.authority.script(&zone_did(), Some(&zone()), None, vec![Step::Answer(no_answer("unpublished"))]);
    let warm = fx.resolve(Revision::current(), fx.opts()).await;
    assert_eq!(warm.best.as_ref().unwrap().revision, rev(&d), "exp > now is still selectable");
    let calls = fx.authority.call_count() + fx.trust.call_count() + fx.normal.call_count();

    for t in [10_010, 10_011] {
        fx.set_now(t);
        let result = fx.resolve(Revision::current(), fx.opts().strictly_offline()).await;
        assert!(result.best.is_none(), "now={} reaches exp", t);
        let report = fx.verify(&d, Revision::current(), fx.opts().strictly_offline()).await;
        assert!(report.is_expired && report.validity == Validity::Invalid, "now={}: {:?}", t, report);
        assert_no_selection(&report);
    }
    assert_eq!(fx.authority.call_count() + fx.trust.call_count() + fx.normal.call_count(), calls);
}

fn owner_history(fx: &Fx) -> (EncodedDocument, EncodedDocument) {
    let o1 = owner_doc(fx.at(100), fx.at(EXP * 10), None, &K1);
    let o2 = owner_doc(fx.at(200), fx.at(EXP * 10), None, &K1);
    fx.authority.publish(&owner_did(), &owner_type(), &o1);
    fx.authority.publish(&owner_did(), &owner_type(), &o2);
    (o1, o2)
}

/// T07:body 活着、历史查询依据过期 → 不能直接选该目标;重复读取不刷新原 checked_at。
#[tokio::test]
async fn t07_short_lived_history_evidence_expires_with_its_answer() {
    let fx = Fx::new();
    let (o1, _o2) = owner_history(&fx);
    let closest = Revision::closest(fx.at(150));
    let mut info = PublishInfo::new(owner_did(), owner_type(), closest.clone())
        .with_status(&DocumentStatus::Active, None, None)
        .with_record(PublishRecord::published(rev(&o1).iat, &rev(&o1).hash, false));
    info.boundary = Some(Boundary {
        query_iat: fx.at(150),
        selected: Some(rev(&o1)),
        confirmed: true,
    });
    info.valid_until = Some(fx.at(10_020));
    let checked_at = info.checked_at;
    fx.authority.script(&owner_did(), Some(&owner_type()), Some(&closest), vec![Step::Answer(answer_with(Some(&o1), Some(info)))]);

    let first = fx.resolve_owner(closest.clone(), fx.opts()).await;
    assert_eq!(first.select(&closest).unwrap().revision, rev(&o1));
    let slot = first.slot_for(&closest).unwrap();
    assert!(slot.valid_until <= fx.at(10_020), "slot outlives its evidence: {} > {}", slot.valid_until, fx.at(10_020));

    for t in [10_005, 10_010] {
        fx.set_now(t);
        let again = fx.resolve_owner(closest.clone(), fx.opts().strictly_offline()).await;
        let slot = again.slot_for(&closest).unwrap();
        assert_eq!(Some(slot.evidence.checked_at), checked_at, "reads must not refresh checked_at");
    }

    fx.set_now(10_021);
    let stale = fx.resolve_owner(closest.clone(), fx.opts().strictly_offline()).await;
    assert!(stale.select(&closest).is_none(), "expired history evidence cannot select the target");
    let before = fx.authority.calls_for(&owner_did(), &closest);
    fx.resolve_owner(closest.clone(), fx.opts()).await;
    assert_eq!(fx.authority.calls_for(&owner_did(), &closest), before + 1, "a usable answer must be fetched again");
}

/// T07:缓存命中不能给 current 发布依据续命;旧依据不可复用后,不能再从它推导"新鲜"的
/// closest 回答。
#[tokio::test]
async fn t07_cache_reads_do_not_renew_current_evidence() {
    let fx = Fx::new();
    let (_o1, o2) = owner_history(&fx);
    let current = fx.resolve_owner(Revision::current(), fx.opts()).await;
    assert_eq!(current.latest.as_ref().unwrap().revision, rev(&o2));
    let calls = fx.authority.call_count();

    fx.set_now(10_000 + PUBLISH_QUERY_TTL_SECS - 10);
    fx.resolve_owner(Revision::current(), fx.opts()).await;
    assert_eq!(fx.authority.call_count(), calls, "served from the query cache");

    fx.set_now(10_000 + PUBLISH_QUERY_TTL_SECS + 10);
    let derived = Revision::closest(fx.at(10_000));
    let result = fx.resolve_owner(derived.clone(), fx.opts().strictly_offline()).await;
    assert!(
        result.select(&derived).is_none(),
        "expired current evidence was renewed by a cache read: {:?}",
        result.slot_for(&derived)
    );
}

// ---------- T08 ----------

struct NegFx {
    fx: Fx,
    zone_doc: EncodedDocument,
    device_doc: EncodedDocument,
}

fn neg_fixture(config: FxConfig, base: u64) -> NegFx {
    let fx = Fx::with_base(config, base);
    fx.publish_default_owner();
    let zone_doc = fx.zone_json(100, "zone");
    let device_doc = generic_json(&zone_did(), fx.at(110), fx.at(EXP), "device");
    fx.trust.add(&zone_did(), &zone(), &zone_doc);
    fx.trust.add(&zone_did(), &device(), &device_doc);
    fx.authority.script(&zone_did(), Some(&zone()), None, vec![Step::Answer(no_answer("zone unpublished"))]);
    NegFx { fx, zone_doc, device_doc }
}

async fn warm(n: &NegFx) {
    let z = n.fx.resolve(Revision::current(), n.fx.opts()).await;
    assert_eq!(z.best.as_ref().unwrap().revision, rev(&n.zone_doc));
    let d = resolve_device(&n.fx, n.fx.opts()).await;
    assert_eq!(d.best.as_ref().unwrap().revision, rev(&n.device_doc), "{}", d.reason());
}

async fn resolve_device(fx: &Fx, opts: ResolveOpts) -> DocResult {
    fx.client
        .resolve_did_ex(&zone_did(), Some(device()), Revision::current(), opts)
        .await
        .unwrap()
}

/// T08:device `Invalid(reason)` 是确定回答:保留 reason,不计失败退避,不升级为 DID 禁用,
/// 不影响 zone,也不阻止独立合法候选经 owner 链成为 best。
#[tokio::test]
async fn t08_invalid_is_a_scoped_answer() {
    let n = neg_fixture(FxConfig::default(), real_base());
    warm(&n).await;
    n.fx.authority.set_negative(&zone_did(), &device(), DocumentStatus::Invalid, Some("device/zone mismatch"));
    let signed = generic_jwt(&zone_did(), n.fx.at(120), n.fx.at(EXP), "normal-device", &K1);
    n.fx.normal.add(&zone_did(), &device(), &signed);
    n.fx.expire_query_cache(NOW);
    let result = resolve_device(&n.fx, n.fx.opts().with_force_authority_query()).await;
    assert!(!result.is_disabled() && result.is_not_exist());
    match result.type_state.as_ref() {
        Some(TypeState::Invalid { reason }) => assert!(reason.contains("mismatch")),
        other => panic!("expected invalid state, got {:?}", other),
    }
    assert_eq!(result.best.as_ref().unwrap().revision, rev(&signed), "{}", result.reason());
    let zone_result = n.fx.resolve(Revision::current(), n.fx.opts().strictly_offline()).await;
    assert!(!zone_result.is_disabled() && !zone_result.is_not_exist());
    assert_eq!(zone_result.best.as_ref().unwrap().revision, rev(&n.zone_doc));

    let before = n.fx.authority.calls_for(&zone_did(), &Revision::current());
    resolve_device(&n.fx, n.fx.opts().with_force_authority_query()).await;
    assert!(n.fx.authority.calls_for(&zone_did(), &Revision::current()) > before, "invalid does not back the source off");
}

/// T08:device Revoked 不因 None / Unknown / 来源 NotExist / 旧历史 Active 消失,重启后仍在,
/// 也不禁用 zone;scope A 的已知状态不写进 scope B。
#[tokio::test]
async fn t08_revoked_survives_unknowns_history_and_restart() {
    let dir = tempfile::tempdir().unwrap();
    let base = real_base();
    let n = neg_fixture(persistent(&dir), base);
    warm(&n).await;
    n.fx.authority.set_negative(&zone_did(), &device(), DocumentStatus::Revoked, None);
    let revoked = resolve_device(&n.fx, n.fx.opts().with_force_authority_query()).await;
    assert!(revoked.is_disabled() && revoked.best.is_none());

    let current = Revision::current();
    for step in [no_answer("authority silent"), failure("HTTP 503")] {
        n.fx.authority.script(&zone_did(), Some(&device()), Some(&current), vec![Step::Answer(step)]);
        let after = resolve_device(&n.fx, n.fx.opts().with_force_authority_query()).await;
        assert!(after.is_disabled() && after.best.is_none());
    }
    let exact = Revision::exact(rev(&n.device_doc).iat, &rev(&n.device_doc).hash);
    let mut historical = PublishInfo::new(zone_did(), device(), exact.clone()).with_status(&DocumentStatus::Active, None, None);
    historical = historical.with_record(PublishRecord::published(rev(&n.device_doc).iat, &rev(&n.device_doc).hash, false));
    n.fx.authority.script(&zone_did(), Some(&device()), Some(&exact), vec![Step::Answer(answer_with(Some(&n.device_doc), Some(historical)))]);
    let after = n.fx.client.resolve_did_ex(&zone_did(), Some(device()), exact.clone(), n.fx.opts()).await.unwrap();
    assert!(after.is_disabled() && after.select(&exact).is_none());

    let zone_result = n.fx.resolve(Revision::current(), n.fx.opts().strictly_offline()).await;
    assert!(!zone_result.is_disabled(), "device revocation does not disable zone");
    let other_scope = resolve_device(&n.fx, n.fx.opts().strictly_offline().with_scope(Scope::Zone(DID::new("bns", "zone9.alice")))).await;
    assert!(!other_scope.is_disabled(), "scope A's state is not written into scope B");

    let restarted = neg_fixture(persistent(&dir), base);
    let after = resolve_device(&restarted.fx, restarted.fx.opts().strictly_offline()).await;
    assert!(after.is_disabled() && after.best.is_none(), "revocation survives a restart");
}

/// T08:DID 级 Tombstoned 覆盖该 DID 的各类型(包括已缓存的 zone);只有真实 authority 新的
/// 明确 current 已发布回答才能恢复。
#[tokio::test]
async fn t08_tombstone_covers_every_type_until_a_new_current_answer() {
    let n = neg_fixture(FxConfig::default(), real_base());
    warm(&n).await;
    n.fx.authority.set_negative(&zone_did(), &device(), DocumentStatus::Tombstoned, None);
    let device_result = resolve_device(&n.fx, n.fx.opts().with_force_authority_query()).await;
    assert!(device_result.is_disabled());
    let zone_result = n.fx.resolve(Revision::current(), n.fx.opts().strictly_offline()).await;
    assert!(zone_result.is_disabled(), "a tombstoned DID disables every type");
    assert!(zone_result.select(&Revision::current()).is_none());

    // 恢复:authority 新的明确 current 已发布回答。
    n.fx.authority.clear_negative(&zone_did(), &device());
    let reissued = generic_json(&zone_did(), n.fx.at(500), n.fx.at(EXP), "reissued-device");
    n.fx.authority.publish(&zone_did(), &device(), &reissued);
    let recovered = resolve_device(&n.fx, n.fx.opts().with_force_authority_query()).await;
    assert!(!recovered.is_disabled(), "{}", recovered.reason());
    assert_eq!(recovered.latest.as_ref().unwrap().revision, rev(&reissued));
}

/// T08 删除变体:device 已撤销后删除普通 body,重启再注入旧 body,撤销事实仍在。
#[tokio::test]
async fn t08_removing_bodies_keeps_negative_facts() {
    let dir = tempfile::tempdir().unwrap();
    let base = real_base();
    let n = neg_fixture(persistent(&dir), base);
    warm(&n).await;
    n.fx.authority.set_negative(&zone_did(), &device(), DocumentStatus::Revoked, None);
    resolve_device(&n.fx, n.fx.opts().with_force_authority_query()).await;
    n.fx.client.remove_doc_result(&zone_did(), &device(), n.fx.opts()).await.unwrap();

    let restarted = neg_fixture(persistent(&dir), base);
    restarted
        .fx
        .client
        .commit_candidate_doc(&zone_did(), Some(device()), &n.device_doc, SourceRef::configured_trust("preinstalled"), restarted.fx.opts())
        .await
        .unwrap();
    let after = resolve_device(&restarted.fx, restarted.fx.opts().strictly_offline()).await;
    assert!(after.is_disabled() && after.select(&Revision::current()).is_none());
}

// ---------- T16 ----------

struct Racer {
    fx: Arc<Fx>,
    gate: Arc<Gate>,
}

fn racer(dir: &tempfile::TempDir, base: u64) -> Racer {
    let fx = Fx::with_base(persistent(dir), base);
    fx.publish_default_owner();
    let gate = Gate::new();
    fx.authority.script(&zone_did(), Some(&zone()), None, vec![Step::Answer(no_answer("unpublished"))]);
    fx.authority.script(&zone_did(), Some(&zone()), Some(&Revision::current()), vec![Step::Gated(gate.clone(), no_answer("unpublished"))]);
    Racer { fx: Arc::new(fx), gate }
}

fn spawn_verify(r: &Racer, doc: &EncodedDocument) -> tokio::task::JoinHandle<VerifyResult> {
    let fx = r.fx.clone();
    let doc = doc.clone();
    tokio::spawn(async move { fx.verify(&doc, Revision::current(), fx.opts()).await })
}

/// T16:两个客户端 / 两个 store handle 从同一旧 generation 起步,各自验证同 iat 不同 hash 的
/// 合法文档;先提交者保留,后提交者的最终报告是 invalid(conflict)、选择标志全 false。
/// 两种提交顺序各跑一次,并用新的读取者检查最终存储。
#[tokio::test]
async fn t16_stale_snapshots_cannot_both_report_success() {
    for a_first in [true, false] {
        let dir = tempfile::tempdir().unwrap();
        let base = real_base();
        let a = racer(&dir, base);
        let b = racer(&dir, base);
        let doc_a = a.fx.zone_jwt(200, "a", &K1);
        let doc_b = a.fx.zone_jwt(200, "b", &K1);
        let task_a = spawn_verify(&a, &doc_a);
        a.gate.wait_entered().await;
        let task_b = spawn_verify(&b, &doc_b);
        b.gate.wait_entered().await;

        let (first, second, first_doc) = if a_first { (&a, &b, &doc_a) } else { (&b, &a, &doc_b) };
        let (first_task, second_task) = if a_first { (task_a, task_b) } else { (task_b, task_a) };
        first.gate.release(1);
        let r1 = first_task.await.unwrap();
        assert!(r1.is_valid(), "{}", r1.reason());
        second.gate.release(1);
        let r2 = second_task.await.unwrap();
        assert_eq!(r2.validity, Validity::Invalid, "a_first={}: {}", a_first, r2.reason());
        assert!(r2.reason().contains("conflict"));
        assert_no_selection(&r2);

        let reader = Fx::with_base(persistent(&dir), base);
        let stored = reader.stored(&zone_did(), &zone()).unwrap();
        assert_eq!(stored.best.as_ref().unwrap().revision, rev(first_doc), "a_first={}", a_first);
        let _ = second;
    }
}

/// T16 对照:同 hash 幂等;不同 iat 时最终 best 是较高的有效版本,latest 只由发布依据决定。
#[tokio::test]
async fn t16_same_hash_is_idempotent_and_higher_iat_wins_best() {
    for (iat_a, iat_b) in [(200, 200), (200, 250)] {
        let dir = tempfile::tempdir().unwrap();
        let base = real_base();
        let a = racer(&dir, base);
        let b = racer(&dir, base);
        let doc_a = a.fx.zone_jwt(iat_a, "same", &K1);
        let doc_b = a.fx.zone_jwt(iat_b, "same", &K1);
        let task_a = spawn_verify(&a, &doc_a);
        a.gate.wait_entered().await;
        let task_b = spawn_verify(&b, &doc_b);
        b.gate.wait_entered().await;
        a.gate.release(1);
        assert!(task_a.await.unwrap().is_valid());
        b.gate.release(1);
        let rb = task_b.await.unwrap();
        assert!(rb.is_valid(), "{}", rb.reason());
        let stored = Fx::with_base(persistent(&dir), base).stored(&zone_did(), &zone()).unwrap();
        assert_eq!(stored.best.as_ref().unwrap().revision.iat, a.fx.at(iat_a.max(iat_b)));
        assert!(stored.latest.is_none(), "no publish evidence, no latest");
    }
}

/// T16 撤销交错:B 读到 Active 快照后暂停,A 提交新的撤销事实;B 没有新的 authority current
/// 回答,不能把状态恢复为 Active,返回的报告与 fresh reader 都服从撤销。
#[tokio::test]
async fn t16_stale_snapshot_cannot_resurrect_a_revoked_type() {
    let dir = tempfile::tempdir().unwrap();
    let base = real_base();
    let a = Fx::with_base(persistent(&dir), base);
    a.publish_default_owner();
    let v0 = a.zone_json(100, "published-v0");
    a.authority.publish(&zone_did(), &zone(), &v0);
    let warm = a.resolve(Revision::current(), a.opts()).await;
    assert_eq!(warm.type_state, Some(TypeState::Active));

    let b = racer(&dir, base);
    b.fx.authority.script(
        &zone_did(),
        Some(&zone()),
        Some(&Revision::current()),
        vec![Step::Gated(b.gate.clone(), failure("HTTP 503"))],
    );
    let doc = b.fx.zone_jwt(200, "b", &K1);
    let task = spawn_verify(&b, &doc);
    b.gate.wait_entered().await;

    a.authority.set_negative(&zone_did(), &zone(), DocumentStatus::Revoked, None);
    let revoked = a.resolve(Revision::current(), a.opts().with_force_authority_query()).await;
    assert!(revoked.is_disabled());

    b.gate.release(1);
    let report = task.await.unwrap();
    assert_eq!(report.validity, Validity::Invalid, "stale snapshot must not report success: {}", report.reason());
    assert_no_selection(&report);
    let stored = Fx::with_base(persistent(&dir), base).stored(&zone_did(), &zone()).unwrap();
    assert!(stored.is_disabled(), "stale Active snapshot resurrected the type: {:?}", stored.type_state);
    assert!(stored.best.is_none() || !stored.best.as_ref().unwrap().is_valid());
}
