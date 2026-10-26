//! T01 版本槽、T02 验证输入、T03 closest 边界、T04 证据维度、T05 历史 key、T06 owner 更新。

use super::fixture::*;
use super::super::*;
use name_lib::{EncodedDocument, DID};
use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::StatusCode;

fn permutations<T: Clone>(items: &[T]) -> Vec<Vec<T>> {
    if items.len() <= 1 {
        return vec![items.to_vec()];
    }
    let mut out = Vec::new();
    for i in 0..items.len() {
        let mut rest = items.to_vec();
        let head = rest.remove(i);
        for mut tail in permutations(&rest) {
            tail.insert(0, head.clone());
            out.push(tail);
        }
    }
    out
}

// ---------- T01 ----------

/// T01:签名错误的高 iat / 同 iat 候选先到,也不能占住合法版本的位置;每种到达顺序都是
/// latest=V1、best=Good,Good 已验签但未发布。
#[tokio::test]
async fn t01_bad_candidates_never_take_the_version_slot_in_any_order() {
    for order in permutations(&["bad-high", "bad-same", "good"]) {
        let fx = Fx::new();
        fx.publish_default_owner();
        let v1 = fx.zone_json(100, "v1");
        fx.authority.publish(&zone_did(), &zone(), &v1);
        let good = fx.zone_jwt(200, "good", &K1);
        for name in &order {
            let doc = match *name {
                "bad-high" => fx.zone_jwt(9000, "bad-high", &KX),
                "bad-same" => fx.zone_jwt(200, "bad-same", &KX),
                _ => good.clone(),
            };
            fx.client
                .commit_candidate_doc(&zone_did(), Some(zone()), &doc, SourceRef::normal("gossip"), fx.opts())
                .await
                .unwrap();
        }
        let result = fx.resolve(Revision::current(), fx.opts()).await;
        assert_eq!(result.latest.as_ref().unwrap().revision, rev(&v1), "{:?}", order);
        let best = result.best.as_ref().unwrap_or_else(|| panic!("{:?}: {}", order, result.reason()));
        assert_eq!(best.revision, rev(&good), "{:?}", order);
        assert!(best.report.is_signed && !best.report.is_published && !best.report.is_latest, "{:?}", order);
        assert!(best.report.conflict.is_none());
        assert!(!result.reason().contains("conflict"), "{:?}: {}", order, result.reason());
        fx.finish();
    }
}

/// T01 对照:两个都有效、同 iat 不同 hash 的文档,先成功提交者保留,后者 conflict;
/// 同 iat 同 hash 重复提交幂等。
#[tokio::test]
async fn t01_first_valid_commit_wins_and_same_hash_is_idempotent() {
    for first_is_a in [true, false] {
        let fx = Fx::new();
        fx.publish_default_owner();
        let a = fx.zone_jwt(200, "a", &K1);
        let b = fx.zone_jwt(200, "b", &K1);
        let (first, second) = if first_is_a { (&a, &b) } else { (&b, &a) };
        let r1 = fx.verify(first, Revision::current(), fx.opts()).await;
        assert!(r1.is_valid() && r1.is_best, "{}", r1.reason());
        let r2 = fx.verify(second, Revision::current(), fx.opts()).await;
        assert_eq!(r2.validity, Validity::Invalid);
        assert_eq!(r2.conflict, Some(rev(first)));
        assert_no_selection(&r2);
        let again = fx.verify(first, Revision::current(), fx.opts()).await;
        assert!(again.is_valid() && again.is_best, "same (iat, hash) is idempotent: {}", again.reason());
        let result = fx.resolve(Revision::current(), fx.opts()).await;
        assert_eq!(result.best.as_ref().unwrap().revision, rev(first));
    }
}

// ---------- T02 ----------

/// T02:有效 V2 已缓存;旧 V1 可以签名正确、valid,但不是 best;同 iat 改内容的 V2' 不能借 V2
/// 的缓存报告成功;错误 DID / 类型在任何来源等级下都失败。
#[tokio::test]
async fn t02_reports_belong_to_the_exact_input() {
    let fx = Fx::new();
    fx.publish_default_owner();
    let v1 = fx.zone_jwt(100, "v1", &K1);
    let v2 = fx.zone_jwt(200, "v2", &K1);
    fx.authority.publish(&zone_did(), &zone(), &v1);
    fx.authority.publish(&zone_did(), &zone(), &v2);
    fx.resolve(Revision::current(), fx.opts()).await;

    let old = fx.verify(&v1, Revision::current(), fx.opts()).await;
    assert!(old.is_signed && old.is_valid(), "{}", old.reason());
    assert_eq!(old.revision, Some(rev(&v1)));
    assert!(!old.is_best && !old.success(&Revision::current()));

    let v2_prime = fx.zone_jwt(200, "v2-prime", &K1);
    let forged = fx.verify(&v2_prime, Revision::current(), fx.opts()).await;
    assert_eq!(forged.validity, Validity::Invalid);
    assert_eq!(forged.revision, Some(rev(&v2_prime)));
    assert!(!forged.success(&Revision::current()));

    let wrong_did = generic_jwt(&DID::new("bns", "zone2.alice"), fx.at(300), fx.at(EXP), "x", &K1);
    let report = fx.verify(&wrong_did, Revision::current(), fx.opts()).await;
    assert_eq!(report.validity, Validity::Invalid);
    let wrong_type = owner_doc(fx.at(300), fx.at(EXP), None, &K1);
    let report = fx
        .client
        .verify_document(&zone_did(), Some(zone()), &wrong_type, Revision::current(), fx.opts())
        .await
        .unwrap();
    assert_eq!(report.validity, Validity::Invalid);

    for tier in [SourceTier::Authority, SourceTier::Trust, SourceTier::Normal] {
        for body in [&wrong_did, &wrong_type] {
            let mut result = DocResult::empty(Scope::Host, zone_did(), zone());
            let answer = SourceAnswer::new(sref("x", tier)).with_body(body.clone(), Carrier::Body);
            result.commit(&answer, &Revision::current(), 0, None);
            assert!(result.best.is_none() && result.latest.is_none() && result.candidates.is_empty(), "{:?}", tier);
        }
    }
}

fn jwt_payload(iat: u64, exp: u64, reorder: bool) -> String {
    let id = zone_did().to_string();
    let owner = owner_did().to_string();
    if reorder {
        format!(r#"{{"owner":"{}","exp":{},"iat":{},"id":"{}","marker":"same-claims"}}"#, owner, exp, iat, id)
    } else {
        format!(r#"{{"id":"{}","iat":{},"exp":{},"owner":"{}","marker":"same-claims"}}"#, id, iat, exp, owner)
    }
}

/// T02:两份 claims 语义相同、键顺序不同、各自正确签名的 JWT,hash 不同;只发布 hash(J1)
/// 时 J2 不能命中 J1 的 exact 或发布记录。JSON 只差空白和键顺序时 hash 相等。
/// J1/J2 分别放进 body / header 时报载体冲突。
#[tokio::test]
async fn t02_equal_claims_are_not_the_same_signed_input() {
    let fx = Fx::new();
    fx.publish_default_owner();
    let j1 = sign_raw_jwt(&jwt_payload(fx.at(200), fx.at(EXP), false), &K1);
    let j2 = sign_raw_jwt(&jwt_payload(fx.at(200), fx.at(EXP), true), &K1);
    assert_eq!(json_value(&j1), json_value(&j2));
    assert_ne!(rev(&j1).hash, rev(&j2).hash);
    fx.authority.publish(&zone_did(), &zone(), &j1);

    let r1 = fx.verify(&j1, Revision::current(), fx.opts()).await;
    assert!(r1.is_valid() && r1.is_published, "{}", r1.reason());
    let r2 = fx.verify(&j2, Revision::current(), fx.opts()).await;
    assert_eq!(r2.validity, Validity::Invalid, "J2 must not borrow J1's publish record");
    assert!(!r2.is_published);
    let exact_j2 = Revision::exact(rev(&j2).iat, &rev(&j2).hash);
    let result = fx.resolve(exact_j2.clone(), fx.opts()).await;
    assert!(result.select(&exact_j2).is_none());
    let exact_j1 = Revision::exact(rev(&j1).iat, &rev(&j1).hash);
    let result = fx.resolve(exact_j1.clone(), fx.opts()).await;
    assert_eq!(result.select(&exact_j1).unwrap().revision, rev(&j1));

    let a: serde_json::Value = serde_json::from_str(r#"{"id":"did:bns:zone1.alice","iat":200,"exp":900}"#).unwrap();
    let b: serde_json::Value = serde_json::from_str("{ \"exp\" : 900,\n \"iat\":200, \"id\":\"did:bns:zone1.alice\" }").unwrap();
    assert_eq!(rev(&EncodedDocument::JsonLd(a)).hash, rev(&EncodedDocument::JsonLd(b)).hash);

    let EncodedDocument::Jwt(j2_raw) = &j2 else { unreachable!() };
    let mut headers = HeaderMap::new();
    headers.insert(DID_DOCUMENT_HEADER, HeaderValue::from_str(&format!("jwt {}", j2_raw)).unwrap());
    let parts = HttpResponseParts::for_test(StatusCode::OK, headers, &j1.to_string());
    let answer = document_answer_from_http(&parts, &sref("site", SourceTier::Normal), &zone_did(), &zone(), &Revision::current(), true);
    assert!(answer.is_unknown(), "body J1 and header J2 are different documents");
}

// ---------- T03 ----------

struct Closest {
    fx: Fx,
    v1: EncodedDocument,
    v2: EncodedDocument,
}

/// authority 历史 V1(100)、V2(200),current V2;normal 另有有效但未发布的 V3(240)。
fn closest_fixture() -> Closest {
    let fx = Fx::new();
    fx.publish_default_owner();
    let v1 = fx.zone_jwt(100, "v1", &K1);
    let v2 = fx.zone_jwt(200, "v2", &K1);
    fx.authority.publish(&zone_did(), &zone(), &v1);
    fx.authority.publish(&zone_did(), &zone(), &v2);
    fx.normal.add(&zone_did(), &zone(), &fx.zone_jwt(240, "v3", &K1));
    Closest { fx, v1, v2 }
}

#[derive(Debug, Clone, Copy)]
enum Probe {
    Closest201,
    Closest200,
    Closest199,
    ExactV2,
    ExactOther,
}

async fn probe(c: &Closest, probe: Probe) {
    let fx = &c.fx;
    let (revision, expected, derived) = match probe {
        Probe::Closest201 => (Revision::closest(fx.at(201)), Some(&c.v2), true),
        Probe::Closest200 => (Revision::closest(fx.at(200)), Some(&c.v1), false),
        Probe::Closest199 => (Revision::closest(fx.at(199)), Some(&c.v1), false),
        Probe::ExactV2 => (Revision::exact(rev(&c.v2).iat, &rev(&c.v2).hash), Some(&c.v2), true),
        Probe::ExactOther => (Revision::exact(rev(&c.v2).iat, "0123abcd"), None, false),
    };
    let before = fx.authority.calls_for(&zone_did(), &revision);
    let result = fx.resolve(revision.clone(), fx.opts()).await;
    let history_calls = fx.authority.calls_for(&zone_did(), &revision) - before;
    match expected {
        Some(doc) => {
            let chosen = result.select(&revision).unwrap_or_else(|| panic!("{:?}: {}", probe, result.reason()));
            assert_eq!(chosen.revision, rev(doc), "{:?}", probe);
            let slot = result.slot_for(&revision).unwrap();
            assert_eq!(slot.query, revision, "{:?} keeps its own full query key", probe);
            assert_eq!(slot.evidence.query, revision);
            assert_eq!(slot.evidence.derived, derived, "{:?}", probe);
            if derived {
                assert_eq!(history_calls, 0, "{:?} is derived from the current answer", probe);
            } else {
                assert_eq!(history_calls, 1, "{:?} needs a real history query", probe);
            }
        }
        None => {
            assert!(result.select(&revision).is_none(), "{:?} must not fall back", probe);
            assert!(result.select(&Revision::current()).is_some(), "current is unaffected");
        }
    }
}

/// T03:先用 closest(201) 预热,再查 200 / 199 / 错误 hash exact;反向再跑一次。
/// 边界差一秒、缓存顺序不同都不能串槽。
#[tokio::test]
async fn t03_closest_boundaries_do_not_share_slots_in_either_order() {
    let forward = [Probe::Closest201, Probe::Closest200, Probe::Closest199, Probe::ExactV2, Probe::ExactOther];
    for order in [forward.to_vec(), forward.iter().rev().cloned().collect::<Vec<_>>()] {
        let c = closest_fixture();
        // 新鲜的 authority current(V2)依据。
        c.fx.resolve(Revision::current(), c.fx.opts()).await;
        for p in order {
            probe(&c, p).await;
        }
        c.fx.finish();
    }
}

/// T03:派生证据指向原 current 回答(来源与检查时刻)。
#[tokio::test]
async fn t03_derived_closest_evidence_points_at_the_current_answer() {
    let c = closest_fixture();
    let current = c.fx.resolve(Revision::current(), c.fx.opts()).await;
    let checked_at = current.latest.as_ref().unwrap().report.publish_evidence.as_ref().unwrap().checked_at;
    let revision = Revision::closest(c.fx.at(201));
    let result = c.fx.resolve(revision.clone(), c.fx.opts()).await;
    let evidence = &result.slot_for(&revision).unwrap().evidence;
    assert!(evidence.derived);
    assert_eq!(evidence.source, "authority");
    assert_eq!(evidence.checked_at, checked_at);
}

fn closest_info(fx: &Fx, before: u64, selected: Option<&EncodedDocument>, confirmed: bool, boundary_iat: u64) -> PublishInfo {
    let mut info = PublishInfo::new(zone_did(), zone(), Revision::closest(fx.at(before)))
        .with_status(&DocumentStatus::Active, None, None);
    if let Some(doc) = selected {
        info = info.with_record(PublishRecord::published(rev(doc).iat, &rev(doc).hash, false));
    }
    info.boundary = Some(Boundary {
        query_iat: fx.at(boundary_iat),
        selected: selected.map(rev),
        confirmed,
    });
    info
}

/// T03:伪造的历史回答(selected.iat == query_iat、未确认边界、边界不匹配、只有发布记录)
/// 都不能产生成功槽。
#[tokio::test]
async fn t03_malformed_history_answers_never_fill_a_slot() {
    let cases: Vec<(&str, u64, Box<dyn Fn(&Closest) -> SourceAnswer>)> = vec![
        ("selected.iat == query_iat", 200, Box::new(|c| answer_with(Some(&c.v2), Some(closest_info(&c.fx, 200, Some(&c.v2), true, 200))))),
        ("boundary not confirmed", 150, Box::new(|c| answer_with(Some(&c.v1), Some(closest_info(&c.fx, 150, Some(&c.v1), false, 150))))),
        ("boundary for another query", 150, Box::new(|c| answer_with(Some(&c.v1), Some(closest_info(&c.fx, 150, Some(&c.v1), true, 160))))),
        ("record without boundary", 150, Box::new(|c| {
            let mut info = closest_info(&c.fx, 150, Some(&c.v1), true, 150);
            info.boundary = None;
            answer_with(Some(&c.v1), Some(info))
        })),
    ];
    for (name, before, answer) in cases {
        let c = closest_fixture();
        c.fx.resolve(Revision::current(), c.fx.opts()).await;
        let revision = Revision::closest(c.fx.at(before));
        c.fx.authority.script(&zone_did(), Some(&zone()), Some(&revision), vec![Step::Answer(answer(&c))]);
        let result = c.fx.resolve(revision.clone(), c.fx.opts()).await;
        assert!(result.select(&revision).is_none(), "{}: must not produce a closest slot", name);
        assert!(result.slot_for(&revision).is_none(), "{}", name);
    }
}

/// T03:只有 trust / normal 的 V3、authority 没有发布回答 → V3 不能成为 closest,也不能充当
/// current 发布证明;authority 确认为空 / 不支持历史 / NoAnswer 都不回退 current 且保留原因。
#[tokio::test]
async fn t03_unpublished_material_and_negative_answers_do_not_fall_back() {
    let fx = Fx::new();
    fx.publish_default_owner();
    let v3 = fx.zone_jwt(240, "v3", &K1);
    fx.normal.add(&zone_did(), &zone(), &v3);
    fx.authority.script(&zone_did(), Some(&zone()), None, vec![Step::Answer(no_answer("authority silent"))]);
    let current = fx.resolve(Revision::current(), fx.opts()).await;
    assert_eq!(current.best.as_ref().unwrap().revision, rev(&v3));
    assert!(current.latest.is_none() && !current.best.as_ref().unwrap().report.is_published);
    let closest = Revision::closest(fx.at(300));
    let result = fx.resolve(closest.clone(), fx.opts()).await;
    assert!(result.select(&closest).is_none());
    assert!(result.reason().contains("authority silent"), "{}", result.reason());

    // 确认为空:有"已回答"的空槽,不回退 current。
    let c = closest_fixture();
    c.fx.resolve(Revision::current(), c.fx.opts()).await;
    let empty = Revision::closest(c.fx.at(50));
    let result = c.fx.resolve(empty.clone(), c.fx.opts()).await;
    assert!(result.select(&empty).is_none());
    assert!(result.satisfies_published_target(&empty), "confirmed-empty is an answer");
    assert_eq!(result.slot_for(&empty).unwrap().revision, None);

    // 不支持历史查询。
    let c = closest_fixture();
    c.fx.resolve(Revision::current(), c.fx.opts()).await;
    c.fx.authority.set_supports_history(false);
    let unsupported = Revision::closest(c.fx.at(150));
    let result = c.fx.resolve(unsupported.clone(), c.fx.opts()).await;
    assert!(result.select(&unsupported).is_none());
    assert!(!result.satisfies_published_target(&unsupported));
    assert!(result.reason().contains("closest"), "{}", result.reason());
}

// ---------- T04 ----------

/// T04:同一份未签名 JSON J,只改证据。normal 提供时无权免签,自报等级 / 发布 / owner 绑定都
/// 不生效;trust 提供时可成为 best,但不设置 is_signed / is_published / is_latest。
#[tokio::test]
async fn t04_source_signature_and_publication_are_independent() {
    let fx = Fx::new();
    fx.publish_default_owner();
    let j = fx.zone_json(200, "json");
    let mallory = DID::new("bns", "mallory");
    let mut boast = current_info(&zone_did(), &zone(), &j);
    boast.owner_binding = Some(mallory.clone());
    let mut claimed = answer_with(Some(&j), Some(boast));
    claimed.source = sref("normal-site", SourceTier::Authority);
    fx.normal.script(&zone_did(), Some(&zone()), None, vec![Step::Answer(claimed)]);
    fx.authority.script(&zone_did(), Some(&zone()), None, vec![Step::Answer(no_answer("unpublished"))]);
    let result = fx.resolve(Revision::current(), fx.opts()).await;
    assert!(result.best.is_none(), "normal JSON cannot skip the signature check");
    assert!(result.latest.is_none());
    assert_ne!(result.owner_binding, Some(mallory.clone()));
    assert!(result.publish_info.as_ref().map_or(true, |i| i.record_for(rev(&j).iat).is_none()));

    let fx = Fx::new();
    fx.trust.add(&zone_did(), &zone(), &j);
    fx.authority.script(&zone_did(), Some(&zone()), Some(&Revision::current()), vec![Step::Answer(no_answer("unpublished"))]);
    let result = fx.resolve(Revision::current(), fx.opts()).await;
    let best = result.best.as_ref().unwrap();
    assert_eq!(best.revision, rev(&j));
    assert!(!best.report.is_signed && !best.report.is_published && !best.report.is_latest);
    assert!(result.latest.is_none());
}

/// T04:trust 缓存了 J 之后,真实 authority 新回答确认 J 的确切 (iat, hash) 为 latest(只回
/// 发布信息、不重发 body):J 复用为已发布 latest,仍不伪造 is_signed;body 来源与发布证据来源
/// 各自保留。
#[tokio::test]
async fn t04_new_authority_evidence_upgrades_the_cached_body() {
    let fx = Fx::new();
    let j = fx.zone_json(200, "json");
    fx.trust.add(&zone_did(), &zone(), &j);
    fx.authority.script(&zone_did(), Some(&zone()), Some(&Revision::current()), vec![Step::Answer(no_answer("unpublished"))]);
    fx.resolve(Revision::current(), fx.opts()).await;

    fx.authority.script(
        &zone_did(),
        Some(&zone()),
        Some(&Revision::current()),
        vec![Step::Answer(answer_with(None, Some(current_info(&zone_did(), &zone(), &j))))],
    );
    let result = fx.resolve(Revision::current(), fx.opts().with_force_authority_query()).await;
    let latest = result.latest.as_ref().unwrap_or_else(|| panic!("J should become the published latest: {}", result.reason()));
    assert_eq!(latest.revision, rev(&j));
    assert!(latest.report.is_published && !latest.report.is_signed);
    assert_eq!(latest.source.tier, SourceTier::Trust, "body keeps its original source");
    assert_eq!(latest.report.publish_evidence.as_ref().unwrap().source, "authority");
    let report = fx.verify(&j, Revision::current(), fx.opts()).await;
    assert!(report.is_latest && report.is_published && !report.is_signed, "{}", report.reason());
}

/// T04:owner 文档只接受 authority / locker 根依据,始终不设置 best。
#[tokio::test]
async fn t04_owner_roots_need_authority_and_never_set_best() {
    let fx = Fx::new();
    let owner = owner_doc(fx.at(100), fx.at(EXP), None, &K1);
    fx.client
        .commit_candidate_doc(&owner_did(), Some(owner_type()), &owner, SourceRef::configured_trust("preinstalled"), fx.opts())
        .await
        .unwrap();
    fx.authority.script(&owner_did(), Some(&owner_type()), None, vec![Step::Answer(no_answer("unpublished"))]);
    let result = fx.resolve_owner(Revision::current(), fx.opts()).await;
    assert!(result.select(&Revision::current()).is_none(), "trust material is not an owner root");
    assert!(result.best.is_none() && result.latest.is_none());

    fx.authority.clear_scripts();
    fx.authority.publish(&owner_did(), &owner_type(), &owner);
    let result = fx.resolve_owner(Revision::current(), fx.opts().with_force_authority_query()).await;
    assert_eq!(result.latest.as_ref().unwrap().revision, rev(&owner));
    assert!(result.best.is_none());
}

// ---------- T05 ----------

struct Rotation {
    fx: Fx,
    o1: EncodedDocument,
}

/// O1:iat=100,K1,exp=400;O2:iat=300,K2,当前。zone 没有可免签锚定的 current 发布记录。
fn rotation(o2_valid_iat: Option<u64>, o1_exp: u64) -> Rotation {
    let fx = Fx::new();
    let o1 = owner_doc(fx.at(100), fx.at(o1_exp), None, &K1);
    let o2 = owner_doc(fx.at(300), fx.at(EXP * 10), o2_valid_iat.map(|v| fx.at(v)), &K2);
    fx.authority.publish(&owner_did(), &owner_type(), &o1);
    fx.authority.publish(&owner_did(), &owner_type(), &o2);
    fx.authority.bind_owner(&zone_did(), &owner_did());
    fx.authority.script(&zone_did(), Some(&zone()), None, vec![Step::Answer(no_answer("not anchored"))]);
    Rotation { fx, o1 }
}

/// T05 步骤 1:当前 owner 没有撤销线 → D 有效;签名依赖是 closest → O1,当前约束依赖是 O2;
/// 今天已过 O1.exp 也不否定它在签发时的用途。
#[tokio::test]
async fn t05_historical_key_signs_current_owner_constrains() {
    let r = rotation(None, 400);
    let d = r.fx.zone_jwt(200, "d", &K1);
    let report = r.fx.verify(&d, Revision::current(), r.fx.opts()).await;
    assert!(report.is_valid() && report.is_signed, "{}", report.reason());
    let signing = report.dependencies.iter().find(|d| d.role == DependencyRole::SigningOwner).unwrap();
    assert_eq!(signing.revision, rev(&r.o1));
    // 冻结稿 §6:签发时 owner 的查询边界是 closest(doc.iat + 1)。
    assert_eq!(signing.query, Revision::closest(r.fx.at(201)));
    let current = report.dependencies.iter().find(|d| d.role == DependencyRole::CurrentOwner).unwrap();
    assert_eq!(current.revision.iat, r.fx.at(300));
    r.fx.finish();
}

/// T05 步骤 2:撤销线 `doc.iat <= valid_iat`:199 不撤销,200 / 201 撤销(签名仍正确)。
#[tokio::test]
async fn t05_valid_iat_boundary_is_inclusive() {
    for (valid_iat, revoked) in [(199, false), (200, true), (201, true)] {
        let r = rotation(Some(valid_iat), 400);
        let d = r.fx.zone_jwt(200, "d", &K1);
        let report = r.fx.verify(&d, Revision::current(), r.fx.opts()).await;
        assert!(report.is_signed, "valid_iat={}: {}", valid_iat, report.reason());
        assert_eq!(report.is_revoked, revoked, "valid_iat={}", valid_iat);
        if revoked {
            assert_eq!(report.validity, Validity::Invalid);
            assert_no_selection(&report);
        } else {
            assert!(report.is_valid(), "{}", report.reason());
        }
    }
}

/// T05 步骤 3:签名 key 由签发时 owner 决定。D.iat 恰好等于 O2.iat 时签发时 owner 是 O2
/// (closest(iat+1),冻结稿 §6),早一秒则是 O1;各用独立 store。
#[tokio::test]
async fn t05_signing_key_follows_the_owner_at_issue_time() {
    for (iat, good, bad) in [(300, &K2, &K1), (299, &K1, &K2)] {
        let r = rotation(None, 400);
        let ok = r.fx.verify(&r.fx.zone_jwt(iat, "ok", good), Revision::current(), r.fx.opts()).await;
        assert!(ok.is_valid() && ok.is_signed, "iat={} key={}: {}", iat, good.name, ok.reason());
        let r = rotation(None, 400);
        let wrong = r.fx.verify(&r.fx.zone_jwt(iat, "wrong", bad), Revision::current(), r.fx.opts()).await;
        assert_eq!(wrong.validity, Validity::Invalid, "iat={} key={}", iat, bad.name);
        assert!(!wrong.is_signed);
    }
}

/// T05 步骤 4:只有当前 O2、没有历史回答 → D unknown,不改用 O2;历史 O1.exp 恰好等于查询
/// 时刻时不能作为有效历史根。
#[tokio::test]
async fn t05_missing_or_expired_history_is_never_replaced_by_current() {
    let r = rotation(None, 400);
    r.fx.authority.set_supports_history(false);
    let d = r.fx.zone_jwt(200, "d", &K1);
    let report = r.fx.verify(&d, Revision::current(), r.fx.opts()).await;
    assert_eq!(report.validity, Validity::Unknown, "{}", report.reason());
    assert!(!report.is_signed);
    assert!(report.missing.iter().any(|m| m.contains("closest")), "{:?}", report.missing);

    for (o1_exp, usable) in [(201, false), (202, true)] {
        let r = rotation(None, o1_exp);
        let report = r.fx.verify(&r.fx.zone_jwt(200, "d", &K1), Revision::current(), r.fx.opts()).await;
        assert_eq!(report.is_signed, usable, "O1.exp={}: {}", o1_exp, report.reason());
        assert_eq!(report.is_valid(), usable, "O1.exp={}", o1_exp);
    }
}

/// T05:外层无论查 current 还是 exact,签名根查询都是同一个 closest 边界。
#[tokio::test]
async fn t05_signing_query_does_not_depend_on_the_outer_revision() {
    let r = rotation(None, 400);
    let d = r.fx.zone_jwt(200, "d", &K1);
    for outer in [Revision::current(), Revision::exact(rev(&d).iat, &rev(&d).hash)] {
        let report = r.fx.verify(&d, outer.clone(), r.fx.opts()).await;
        let signing = report.dependencies.iter().find(|x| x.role == DependencyRole::SigningOwner);
        assert_eq!(signing.map(|s| s.query.clone()), Some(Revision::closest(r.fx.at(201))), "outer {}", outer);
    }
}

// ---------- T06 ----------

/// T06:不改变验证依据的 owner 更新不追溯抹掉 trust 文档;覆盖 U.iat 的新撤销线必须立即
/// 撤掉选择资格(U 没有签名依赖、缓存未到期也不能绕过),严格离线也一样。
#[tokio::test]
async fn t06_owner_update_vs_revocation_for_unsigned_trust_documents() {
    let fx = Fx::new();
    fx.publish_default_owner();
    let u = fx.zone_json(200, "trust-u");
    fx.trust.add(&zone_did(), &zone(), &u);
    let first = fx.resolve(Revision::current(), fx.opts()).await;
    assert_eq!(first.best.as_ref().unwrap().revision, rev(&u));

    // 只换版、不改 key / 撤销线。
    fx.authority.publish(&owner_did(), &owner_type(), &owner_doc(fx.at(300), fx.at(EXP * 10), None, &K1));
    fx.resolve_owner(Revision::current(), fx.opts().with_force_authority_query()).await;
    let kept = fx.resolve(Revision::current(), fx.opts().strictly_offline()).await;
    assert_eq!(kept.best.as_ref().unwrap().revision, rev(&u));
    assert_eq!(kept.best.as_ref().unwrap().source.tier, SourceTier::Trust);

    // 撤销线覆盖 U.iat。
    fx.authority.publish(&owner_did(), &owner_type(), &owner_doc(fx.at(400), fx.at(EXP * 10), Some(fx.at(250)), &K1));
    fx.resolve_owner(Revision::current(), fx.opts().with_force_authority_query()).await;
    let revoked = fx.resolve(Revision::current(), fx.opts().strictly_offline()).await;
    assert!(revoked.best.is_none(), "known revocation applies to unsigned trust documents: {}", revoked.reason());
    let report = fx.verify(&u, Revision::current(), fx.opts().strictly_offline()).await;
    assert!(report.is_revoked && report.validity == Validity::Invalid);
}

/// T06 locker 变体:由 locker 提供的 owner 验证的文档,在 locker 配置改变后必须重判,不能
/// 继续当作已验证文档使用。
#[tokio::test]
async fn t06_locker_change_invalidates_documents_verified_through_locked_material() {
    let fx = Fx::new();
    let locked_owner = owner_doc(fx.at(50), fx.at(EXP * 10), None, &K1);
    fx.client.lock_document(owner_did(), owner_type(), locked_owner, LockOptions::default());
    fx.authority.script(&owner_did(), Some(&owner_type()), None, vec![Step::Answer(no_answer("not published"))]);
    fx.authority.script(&zone_did(), Some(&zone()), None, vec![Step::Answer(no_answer("not published"))]);
    let d = fx.zone_jwt(200, "d", &K1);
    fx.normal.add(&zone_did(), &zone(), &d);
    let with_locker = fx.resolve(Revision::current(), fx.opts()).await;
    assert_eq!(with_locker.best.as_ref().unwrap().revision, rev(&d), "{}", with_locker.reason());

    fx.client.unlock_document(&owner_did(), owner_type());
    let after = fx.resolve(Revision::current(), fx.opts().strictly_offline()).await;
    assert!(
        after.best.is_none(),
        "a document verified through a removed locker root must be re-verified: {:?}",
        after.best.as_ref().map(|b| &b.report)
    );
}
