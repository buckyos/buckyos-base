//! T09 receipt、T10 locker、T11 默认类型、T13 获取策略。

use super::fixture::*;
use super::super::*;
use name_lib::{DidDocType, EncodedDocument, NSError, DID};
use std::sync::Arc;
use std::time::Duration;

fn authority_current(did: &DID, doc_type: &DidDocType, doc: &EncodedDocument) -> Step {
    Step::Answer(answer_with(Some(doc), Some(current_info(did, doc_type, doc))))
}

// ---------- T09 ----------

/// T09:同一份已归一化的 opts 连用两次。第二次最外层调用必须真的发出 authority I/O,
/// 上一轮 receipt 不能短路验证缓存,也不能成为本轮的"权威回答"。
#[tokio::test]
async fn t09_reused_normalized_opts_do_not_reuse_previous_receipts() {
    let fx = Fx::new();
    fx.publish_default_owner();
    let v1 = fx.zone_jwt(100, "v1", &K1);
    let current = Revision::current();
    fx.authority.script(&zone_did(), Some(&zone()), None, vec![Step::Answer(no_answer("no history here"))]);
    fx.authority.script(
        &zone_did(),
        Some(&zone()),
        Some(&current),
        vec![authority_current(&zone_did(), &zone(), &v1), Step::Answer(no_answer("authority has no answer this round"))],
    );
    let opts = fx
        .opts()
        .authority_only()
        .without_local_lock()
        .without_zone_lock()
        .with_force_authority_query()
        .normalize(Duration::from_secs(60));

    let first = fx.resolve(current.clone(), opts.clone()).await;
    assert_eq!(first.latest.as_ref().unwrap().revision, rev(&v1));
    assert_eq!(select_authority_current(&first, opts.receipts()).unwrap().revision, rev(&v1));
    assert_eq!(
        fx.authority.calls_for(&zone_did(), &current),
        1,
        "one round reuses the same answer for document and publish_info"
    );

    let second = fx.resolve(current.clone(), opts.clone()).await;
    let after_second = fx.authority.calls_for(&zone_did(), &current);
    assert!(after_second > 1, "second outer call must really ask the authority");
    assert!(
        select_authority_current(&second, opts.receipts()).is_none(),
        "the previous round's receipt is not this round's authority answer"
    );

    let report = fx.verify(&v1, current.clone(), opts.clone()).await;
    assert!(
        fx.authority.calls_for(&zone_did(), &current) > after_second,
        "an old receipt must not short-circuit the cached report"
    );
    assert_eq!(report.revision, Some(rev(&v1)));

    // 正例:新一轮 authority 再次回答 V1 → 复用已有 body,保留原来源,并有新的 receipt。
    fx.authority.script(&zone_did(), Some(&zone()), Some(&current), vec![authority_current(&zone_did(), &zone(), &v1)]);
    let third = fx.resolve(current.clone(), opts.clone()).await;
    let chosen = select_authority_current(&third, opts.receipts()).unwrap();
    assert_eq!(chosen.revision, rev(&v1));
    assert!(chosen.source.is_authority());
    fx.finish();
}

/// T09 准入探针:本轮 receipt 必须属于同一 DID / 类型 / 查询;更高的 trust best 不能替换
/// receipt 锚定的版本;owner 递归共享本轮上下文。
#[tokio::test]
async fn t09_admission_needs_a_matching_receipt_from_this_round() {
    let fx = Fx::new();
    fx.publish_default_owner();
    let v1 = fx.zone_jwt(100, "v1", &K1);
    let v2 = fx.zone_json(200, "trust-v2");
    let current = Revision::current();
    fx.trust.add(&zone_did(), &zone(), &v2);
    fx.authority.publish(&zone_did(), &zone(), &v1);
    // 先让缓存里有更高的 trust best。
    let warm = fx.resolve(current.clone(), fx.opts()).await;
    assert_eq!(warm.best.as_ref().unwrap().revision, rev(&v2));

    let gate_opts = fx
        .opts()
        .authority_only()
        .without_local_lock()
        .without_zone_lock()
        .with_force_authority_query()
        .normalize(Duration::from_secs(60));
    let result = fx.resolve(current.clone(), gate_opts.clone()).await;
    assert_eq!(result.best.as_ref().unwrap().revision, rev(&v2), "authority_only keeps the cached trust best");
    assert_eq!(
        select_authority_current(&result, gate_opts.receipts()).unwrap().revision,
        rev(&v1),
        "receipt-anchored V1 wins over the higher trust best"
    );

    // 本轮 zone 无回答,只有 owner 的 receipt(验证 normal 候选时取得):不满足 zone 的要求。
    fx.authority.script(&zone_did(), Some(&zone()), Some(&current), vec![Step::Answer(no_answer("gone quiet"))]);
    fx.normal.add(&zone_did(), &zone(), &fx.zone_jwt(300, "normal-v3", &K1));
    fx.expire_query_cache(NOW);
    let round = fx.opts().without_local_lock().without_zone_lock().with_force_authority_query().normalize(Duration::from_secs(60));
    let result = fx.resolve(current.clone(), round.clone()).await;
    assert!(!round.receipts().authority_receipts(&owner_did(), &owner_type()).is_empty());
    assert!(select_authority_current(&result, round.receipts()).is_none());

    // owner 递归共享本轮上下文:验证 normal JWT 时取得的 owner 回答记入同一 receipt 集合。
    let fresh = Fx::new();
    fresh.publish_default_owner();
    let opts = fresh.opts().normalize(Duration::from_secs(60));
    let report = fresh.verify(&fresh.zone_jwt(300, "n", &K1), current.clone(), opts.clone()).await;
    assert!(report.is_signed, "{}", report.reason());
    assert!(!opts.receipts().authority_receipts(&owner_did(), &owner_type()).is_empty());
}

// ---------- T10 ----------

fn locked_v2_fixture() -> (Fx, EncodedDocument, EncodedDocument) {
    let fx = Fx::new();
    fx.publish_default_owner();
    let v1 = fx.zone_jwt(100, "v1", &K1);
    let v2 = fx.zone_json(200, "locked-v2");
    fx.authority.publish(&zone_did(), &zone(), &v1);
    (fx, v1, v2)
}

/// T10:locker 改变 current 的选择,但历史查询不能用锁定文档冒充,验证另一份输入的报告
/// 仍属于该输入。
#[tokio::test]
async fn t10_locker_changes_selection_but_not_the_verified_input() {
    let (fx, v1, v2) = locked_v2_fixture();
    let warm = fx.resolve(Revision::current(), fx.opts()).await;
    assert_eq!(warm.best.as_ref().unwrap().revision, rev(&v1));
    fx.client.lock_document(zone_did(), zone(), v2.clone(), LockOptions::default());
    fx.authority.reset_calls();

    let current = fx.resolve(Revision::current(), fx.opts()).await;
    assert!(current.locked);
    let chosen = current.select(&Revision::current()).unwrap();
    assert_eq!(chosen.revision, rev(&v2));
    assert!(chosen.report.publish_evidence.as_ref().unwrap().simulated);
    assert_eq!(fx.authority.call_count(), 0);

    let other_hash = Revision::exact(rev(&v2).iat, "00ff");
    let exact = fx.resolve(other_hash.clone(), fx.opts()).await;
    assert!(exact.select(&other_hash).is_none(), "locked V2 must not stand in for another exact target");

    let closest = Revision::closest(rev(&v2).iat);
    let result = fx.resolve(closest.clone(), fx.opts()).await;
    assert_ne!(result.select(&closest).map(|c| c.revision.clone()), Some(rev(&v2)));

    let report = fx.verify(&v1, Revision::current(), fx.opts()).await;
    assert_eq!(report.revision, Some(rev(&v1)), "the report belongs to the verified input");
    assert!(!report.success(&Revision::current()));
    assert!(report
        .publish_evidence
        .as_ref()
        .map_or(true, |e| e.record.revision() != Some(rev(&v2))));
}

/// T10:明确不存在是强制回答(不访问后续 Zone locker / provider);解锁后普通缓存里没有
/// 之前的模拟发布事实,从未加锁的 scope 也读不到。
#[tokio::test]
async fn t10_negative_lock_is_forced_and_unlock_leaves_no_simulated_facts() {
    let (fx, v1, v2) = locked_v2_fixture();
    let zone_http = LocalHttp::start(|_| (404, String::new())).await;
    fx.client.set_zone_locker_config(ZoneLockerConfig {
        endpoint: zone_http.url(),
        ..Default::default()
    });
    fx.client.local_locker().lock_negative(zone_did(), &zone(), TypeState::Missing, LockOptions::default());
    let negative = fx.resolve(Revision::current(), fx.opts()).await;
    assert!(negative.locked && negative.is_not_exist() && negative.select(&Revision::current()).is_none());
    assert_eq!(fx.authority.call_count(), 0);
    assert!(zone_http.requests().is_empty(), "forced local answer skips the zone locker");

    // 锁定 V2 后查询一个更晚的 exact:locker 对它模拟"未发布"。
    fx.client.lock_document(zone_did(), zone(), v2.clone(), LockOptions::default());
    let future = Revision::exact(fx.at(300), "abcd");
    fx.resolve(future, fx.opts()).await;
    fx.client.unlock_document(&zone_did(), zone());

    let unlocked = fx.resolve(Revision::current(), fx.opts()).await;
    assert!(!unlocked.locked);
    assert_eq!(unlocked.best.as_ref().unwrap().revision, rev(&v1));
    let stored = fx.stored(&zone_did(), &zone()).unwrap();
    assert!(
        stored.publish_info.as_ref().map_or(true, |info| !info.simulated && info.record_for(rev(&v2).iat).is_none()),
        "simulated publish facts leaked into the normal store: {:?}",
        stored.publish_info
    );
    for choice in stored.verified_choices() {
        assert!(choice.report.publish_evidence.as_ref().map_or(true, |e| !e.simulated));
    }

    let scope_b = Scope::Zone(DID::new("bns", "other-zone"));
    let b = fx.resolve(Revision::current(), fx.opts().with_scope(scope_b.clone())).await;
    assert!(!b.locked);
    assert!(b.publish_info.as_ref().map_or(true, |info| !info.simulated));
}

/// T10:`no_request + allow_zone_lock` 只访问 Zone locker,普通 provider(含 authority)调用为零;
/// `no_request + without_zone_lock` 网络调用全零。
#[tokio::test]
async fn t10_no_request_has_two_network_meanings() {
    let (fx, _v1, _v2) = locked_v2_fixture();
    let zone_http = LocalHttp::start(|_| (404, String::new())).await;
    fx.client.set_zone_locker_config(ZoneLockerConfig {
        endpoint: zone_http.url(),
        ..Default::default()
    });
    fx.client
        .resolve_did_ex(&zone_did(), Some(zone()), Revision::current(), fx.opts().not_allow_request())
        .await
        .unwrap();
    assert!(!zone_http.requests().is_empty(), "zone locker is still consulted");
    assert!(zone_http.requests().iter().all(|r| r.to_ascii_lowercase().contains("buckyos-resolve-no-zone-lock: 1")));
    assert_eq!(fx.authority.call_count() + fx.trust.call_count() + fx.normal.call_count(), 0);

    let before = zone_http.requests().len();
    fx.client
        .resolve_did_ex(&zone_did(), Some(zone()), Revision::current(), fx.opts().strictly_offline())
        .await
        .unwrap();
    assert_eq!(zone_http.requests().len(), before);
    assert_eq!(fx.authority.call_count() + fx.trust.call_count() + fx.normal.call_count(), 0);
}

// ---------- T11 ----------

fn bob() -> DID {
    DID::new("bns", "bob")
}

fn bob_docs(fx: &Fx) -> (EncodedDocument, EncodedDocument) {
    let z = generic_json(&bob(), fx.at(100), fx.at(EXP), "bob-zone");
    let d = generic_json(&bob(), fx.at(110), fx.at(EXP), "bob-device");
    fx.authority.publish(&bob(), &DidDocType::Zone, &z);
    fx.authority.publish(&bob(), &DidDocType::Device, &d);
    (z, d)
}

/// T11:根 `did:bns:bob` 只有 active device → None 在查缓存前归一为 device,不落入 zone 槽。
/// 先显式 zone 预热再请求 None,以及反序,都不能串用。
#[tokio::test]
async fn t11_default_type_is_normalized_before_the_cache_key() {
    for zone_first in [true, false] {
        let fx = Fx::new();
        let (z, d) = bob_docs(&fx);
        fx.authority.set_default_type(Some(DefaultDocType::Known {
            doc_type: DidDocType::Device,
            reasons: Vec::new(),
        }));
        let bob = bob();
        let explicit = || fx.client.resolve_did_ex(&bob, Some(DidDocType::Zone), Revision::current(), fx.opts());
        let default = || fx.client.resolve_did_ex(&bob, None, Revision::current(), fx.opts());
        let (zone_result, default_result) = if zone_first {
            let a = explicit().await.unwrap();
            (a, default().await.unwrap())
        } else {
            let b = default().await.unwrap();
            (explicit().await.unwrap(), b)
        };
        assert_eq!(zone_result.best.as_ref().unwrap().revision, rev(&z));
        assert_eq!(default_result.doc_type, DidDocType::Device);
        assert_eq!(default_result.requested_doc_type, None);
        assert_eq!(default_result.best.as_ref().unwrap().revision, rev(&d), "zone_first={}", zone_first);
        let stored_zone = fx.stored(&bob, &DidDocType::Zone).unwrap();
        assert_eq!(stored_zone.best.as_ref().unwrap().revision, rev(&z));
        fx.finish();
    }
}

/// T11:多 active 类型不含 zone → ambiguity;含 zone → 选 zone 并记录 warn;did:web 根默认
/// 文档实际为 owner → requested=None、actual=owner,不写 zone 槽;路径对象固定为 did-object。
#[tokio::test]
async fn t11_ambiguity_warning_and_actual_type_are_reported() {
    let fx = Fx::new();
    bob_docs(&fx);
    fx.authority.set_default_type(Some(DefaultDocType::Ambiguous("device and user are both active".into())));
    let err = fx.client.resolve_did_ex(&bob(), None, Revision::current(), fx.opts()).await.unwrap_err();
    assert!(matches!(err, NSError::InvalidParam(_)), "{:?}", err);

    fx.authority.set_default_type(Some(DefaultDocType::Known {
        doc_type: DidDocType::Zone,
        reasons: vec!["several active types; chose zone".into()],
    }));
    let warned = fx.client.resolve_did_ex(&bob(), None, Revision::current(), fx.opts()).await.unwrap();
    assert_eq!(warned.doc_type, DidDocType::Zone);
    assert!(warned.reasons.iter().any(|r| r.contains("chose zone")), "{:?}", warned.reasons);

    let web = DID::new("web", "example.com");
    let web_authority = ScriptedSource::authority_model("web-authority");
    let owner = owner_doc(fx.at(100), fx.at(EXP), None, &K1);
    let owner_json = {
        let mut v = json_value(&owner);
        v["id"] = serde_json::json!(web.to_string());
        EncodedDocument::JsonLd(v)
    };
    web_authority.publish(&web, &DidDocType::Owner, &owner_json);
    web_authority.set_default_type(Some(DefaultDocType::Known {
        doc_type: DidDocType::Owner,
        reasons: vec!["doc_type detected from did:web:example.com".into()],
    }));
    fx.client.set_method_authority("web", web_authority.clone());
    let root = fx.client.resolve_did_ex(&web, None, Revision::current(), fx.opts()).await.unwrap();
    assert_eq!(root.doc_type, DidDocType::Owner);
    assert_eq!(root.requested_doc_type, None);
    assert!(root.latest.is_some(), "{}", root.reason());
    assert!(fx.stored(&web, &DidDocType::Zone).is_none(), "owner material is not written into the zone slot");

    let object = DID::new("bns", "alice:obj:a");
    let (doc_type, _) = fx.client.resolve_doc_type(&object, None, &fx.client.normalize_opts(fx.opts())).await.unwrap();
    assert_eq!(doc_type, DidDocType::DidObject);
}

/// T11:显式请求的类型不能被错误类型的响应"偷偷改成功"。
#[tokio::test]
async fn t11_wrong_type_response_does_not_satisfy_an_explicit_request() {
    let fx = Fx::new();
    let owner = owner_doc(fx.at(100), fx.at(EXP), None, &K1);
    let as_zone = {
        let mut v = json_value(&owner);
        v["id"] = serde_json::json!(zone_did().to_string());
        EncodedDocument::JsonLd(v)
    };
    fx.authority.script(&zone_did(), Some(&zone()), None, vec![Step::Answer(body_only(&as_zone))]);
    let result = fx.resolve(Revision::current(), fx.opts()).await;
    assert!(result.select(&Revision::current()).is_none(), "an owner body is not a zone document");
    assert!(result.reason().contains("owner"), "{}", result.reason());
}

// ---------- T13 ----------

/// T13:限制本次获取不删除已取得的信任:热缓存 trust V2 在 authority_only 下仍是 best,
/// trust 网络调用为零;冷缓存则不能新获取 V2。
#[tokio::test]
async fn t13_authority_only_keeps_cached_trust_but_cannot_fetch_it() {
    let fx = Fx::new();
    let v1 = fx.zone_json(100, "authority-v1");
    let v2 = fx.zone_json(200, "trust-v2");
    fx.authority.publish(&zone_did(), &zone(), &v1);
    fx.trust.add(&zone_did(), &zone(), &v2);
    fx.resolve(Revision::current(), fx.opts()).await;
    let trust_calls = fx.trust.call_count();
    let restricted = fx.resolve(Revision::current(), fx.opts().authority_only().with_force_authority_query()).await;
    assert_eq!(restricted.best.as_ref().unwrap().revision, rev(&v2));
    assert_eq!(restricted.latest.as_ref().unwrap().revision, rev(&v1));
    assert_eq!(fx.trust.call_count(), trust_calls);

    let cold = Fx::new();
    cold.authority.publish(&zone_did(), &zone(), &cold.zone_json(100, "authority-v1"));
    cold.trust.add(&zone_did(), &zone(), &cold.zone_json(200, "trust-v2"));
    let result = cold.resolve(Revision::current(), cold.opts().authority_only()).await;
    assert_eq!(marker(&result.best.as_ref().unwrap().doc), "authority-v1");
    assert_eq!(cold.trust.call_count(), 0);
}

/// T13:受限传输策略不加入会访问目标入口的共享任务;authority 等级不能替代通道独立性证明;
/// owner 递归每一跳都受同一限制。
#[tokio::test]
async fn t13_independent_control_plane_is_never_merged_with_default_tasks() {
    let fx = Arc::new(Fx::new());
    fx.publish_default_owner();
    let candidate = fx.zone_jwt(200, "candidate", &K1);
    fx.client
        .commit_candidate_doc(&zone_did(), Some(zone()), &candidate, SourceRef::normal("gossip"), fx.opts())
        .await
        .unwrap();
    let gate = Gate::new();
    fx.trust.script(&zone_did(), Some(&zone()), None, vec![Step::Gated(gate.clone(), no_answer("slow trust"))]);
    let normal = {
        let fx = fx.clone();
        tokio::spawn(async move { fx.resolve(Revision::current(), fx.opts()).await })
    };
    gate.wait_entered().await;
    let owner_calls_before = fx.authority.calls().iter().filter(|c| c.did == owner_did()).count();

    let icp = fx
        .opts()
        .with_transport_policy(TransportPolicy::IndependentControlPlane)
        .normalize(Duration::from_secs(10));
    let restricted = tokio::time::timeout(Duration::from_secs(5), fx.resolve(Revision::current(), icp.clone()))
        .await
        .expect("restricted request must not wait on the default task");
    assert!(restricted.best.is_none(), "no channel-independent source may vouch for the candidate");
    assert_eq!(gate.entries(), 1);
    let refused: Vec<String> = icp.receipts().unanswered().iter().map(|u| u.source.id.clone()).collect();
    assert!(refused.contains(&"authority".to_string()), "authority tier is not a channel proof: {:?}", refused);
    assert!(refused.contains(&"trust-site".to_string()));
    assert_eq!(
        fx.authority.calls().iter().filter(|c| c.did == owner_did()).count(),
        owner_calls_before,
        "owner recursion obeys the same transport restriction"
    );
    gate.release(1);
    normal.await.unwrap();

    // 本机配置声明为独立控制通道的 authority 可以访问。
    let fx2 = Fx::new();
    let independent = ScriptedSource::authority_model("icp-authority");
    let v1 = fx2.zone_json(100, "icp-v1");
    independent.publish(&zone_did(), &zone(), &v1);
    let client = client_with(&FxConfig::default());
    client.register_source("bns", RegisteredSource::new(independent.clone(), SourceTier::Authority).independent_control_plane(true));
    let result = client
        .resolve_did_ex(
            &zone_did(),
            Some(zone()),
            Revision::current(),
            ResolveOpts::default().with_transport_policy(TransportPolicy::IndependentControlPlane),
        )
        .await
        .unwrap();
    assert_eq!(result.best.as_ref().unwrap().revision, rev(&v1));
}

/// T13 污染探针:先策略拒绝,再用允许策略访问同一源 → 真的发起查询(不被负缓存 / 退避
/// 拦住);反向先普通、后受限也不串。
#[tokio::test]
async fn t13_policy_refusal_and_allowed_request_do_not_pollute_each_other() {
    let fx = Fx::new();
    let v1 = fx.zone_json(100, "v1");
    fx.authority.publish(&zone_did(), &zone(), &v1);
    let refused = fx.resolve(Revision::current(), fx.opts().not_allow_request()).await;
    assert!(refused.best.is_none());
    assert_eq!(fx.authority.call_count(), 0);
    let allowed = fx.resolve(Revision::current(), fx.opts()).await;
    assert_eq!(allowed.best.as_ref().unwrap().revision, rev(&v1));
    assert!(fx.authority.call_count() > 0);

    let fx = Fx::new();
    fx.authority.publish(&zone_did(), &zone(), &v1);
    fx.resolve(Revision::current(), fx.opts()).await;
    let calls = fx.authority.call_count();
    let restricted = fx
        .resolve(
            Revision::current(),
            fx.opts().with_transport_policy(TransportPolicy::IndependentControlPlane).with_force_authority_query(),
        )
        .await;
    assert_eq!(fx.authority.call_count(), calls, "restricted request reads the cache but makes no request");
    assert_eq!(restricted.best.as_ref().unwrap().revision, rev(&v1));
}

/// T13:合并键逐项扰动——revision、scope、force 证据要求、访问策略任一不同,任务就分开;
/// 完全相同则合并。
#[tokio::test]
async fn t13_merge_key_fields_each_separate_tasks() {
    async fn concurrent_calls(second: impl FnOnce(&Fx) -> (Revision, ResolveOpts)) -> usize {
        let fx = Arc::new(Fx::new());
        let gate = Gate::new();
        fx.authority.script(&zone_did(), Some(&zone()), None, vec![Step::Gated(gate.clone(), no_answer("held"))]);
        let first = {
            let fx = fx.clone();
            tokio::spawn(async move { fx.resolve(Revision::current(), fx.opts().without_local_lock()).await })
        };
        gate.wait_entered().await;
        let (revision, opts) = second(&fx);
        let second = {
            let fx = fx.clone();
            tokio::spawn(async move {
                fx.client.resolve_did_ex(&zone_did(), Some(zone()), revision, opts).await.unwrap()
            })
        };
        for _ in 0..200 {
            tokio::task::yield_now().await;
        }
        let entries = gate.entries();
        gate.release(16);
        first.await.unwrap();
        second.await.unwrap();
        entries
    }
    assert_eq!(concurrent_calls(|fx| (Revision::current(), fx.opts().without_local_lock())).await, 1, "identical requests merge");
    assert_eq!(
        concurrent_calls(|fx| (Revision::current(), fx.opts().without_local_lock().with_force_authority_query())).await,
        2,
        "force_authority_query"
    );
    assert_eq!(
        concurrent_calls(|fx| (Revision::current(), fx.opts().without_local_lock().with_scope(Scope::Zone(zone_did())))).await,
        2,
        "scope"
    );
    assert_eq!(
        concurrent_calls(|fx| (Revision::exact(fx.at(100), "aa"), fx.opts().without_local_lock())).await,
        2,
        "revision"
    );
    assert_eq!(
        concurrent_calls(|fx| (Revision::current(), fx.opts().without_local_lock().authority_only())).await,
        2,
        "access policy"
    );
}
