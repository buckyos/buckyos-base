//! §4 有约束的属性测试:固定种子、独立参考模型,失败时输出种子与操作序列。

use super::fixture::*;
use super::super::*;
use name_lib::{DidDocType, EncodedDocument, DID};
use std::collections::HashSet;

/// SplitMix64:固定种子的可重放随机源。
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }

    fn shuffle<T>(&mut self, items: &mut [T]) {
        for i in (1..items.len()).rev() {
            let j = self.below(i as u64 + 1) as usize;
            items.swap(i, j);
        }
    }
}

/// 属性 1:有效、无冲突的版本集合中插入错误签名 / 错误身份 / 重复候选,再打乱到达顺序,
/// best / latest 不变。期望由生成参数直接算出,不调用被测选择逻辑。
#[tokio::test]
async fn p1_invalid_noise_does_not_change_the_selection() {
    for seed in 0..12u64 {
        let mut rng = Rng::new(seed);
        let fx = Fx::new();
        fx.publish_default_owner();
        let published = fx.zone_json(50, "published");
        fx.authority.publish(&zone_did(), &zone(), &published);
        let mut valid_iats: Vec<u64> = (0..3).map(|i| 100 + i * 100 + rng.below(50)).collect();
        valid_iats.sort();
        let mut arrivals: Vec<(String, EncodedDocument)> = Vec::new();
        for (i, iat) in valid_iats.iter().enumerate() {
            let doc = fx.zone_jwt(*iat, &format!("valid-{}", i), &K1);
            arrivals.push((format!("valid@{}", iat), doc.clone()));
            arrivals.push((format!("dup@{}", iat), doc));
        }
        let noise_iat = valid_iats.last().unwrap() + 1 + rng.below(500);
        arrivals.push((format!("bad-sig@{}", noise_iat), fx.zone_jwt(noise_iat, "bad-sig", &KX)));
        let same = valid_iats[rng.below(3) as usize];
        arrivals.push((format!("bad-sig-same@{}", same), fx.zone_jwt(same, "bad-sig-same", &KX)));
        arrivals.push((
            format!("wrong-id@{}", noise_iat),
            generic_jwt(&DID::new("bns", "zone2.alice"), fx.at(noise_iat), fx.at(EXP), "wrong-id", &K1),
        ));
        rng.shuffle(&mut arrivals);
        let sequence: Vec<&str> = arrivals.iter().map(|(name, _)| name.as_str()).collect();
        for (_, doc) in &arrivals {
            let _ = fx
                .client
                .commit_candidate_doc(&zone_did(), Some(zone()), doc, SourceRef::normal("gossip"), fx.opts())
                .await;
        }
        let result = fx.resolve(Revision::current(), fx.opts()).await;
        let expected_best = fx.at(*valid_iats.last().unwrap());
        assert_eq!(
            result.best.as_ref().map(|b| b.revision.iat),
            Some(expected_best),
            "seed={} arrivals={:?}: {}",
            seed,
            sequence,
            result.reason()
        );
        assert_eq!(result.latest.as_ref().unwrap().revision, rev(&published), "seed={} arrivals={:?}", seed, sequence);
    }
}

/// 属性 2:closest 的参考模型。authority 固定、无冲突的已发布集合 P;对有边界确认的 q,
/// 期望严格为 `max {v ∈ P: v.iat < q}`;包含空集合、等号与相邻时刻。
#[tokio::test]
async fn p2_closest_matches_the_reference_model() {
    for seed in 0..6u64 {
        let mut rng = Rng::new(seed);
        let fx = Fx::new();
        let mut iats: HashSet<u64> = HashSet::new();
        while iats.len() < 4 {
            iats.insert(100 + rng.below(900));
        }
        let mut iats: Vec<u64> = iats.into_iter().collect();
        iats.sort();
        for iat in &iats {
            fx.authority.publish(&owner_did(), &owner_type(), &owner_doc(fx.at(*iat), fx.at(EXP * 10), None, &K1));
        }
        fx.resolve_owner(Revision::current(), fx.opts()).await;
        let mut queries: Vec<u64> = vec![iats[0], iats[0].saturating_sub(1), 50];
        for iat in &iats {
            queries.extend([*iat, iat + 1, iat - 1]);
        }
        queries.push(iats.last().unwrap() + 1 + rng.below(100));
        rng.shuffle(&mut queries);
        for q in &queries {
            let expected = iats.iter().filter(|v| **v < *q).max().map(|v| fx.at(*v));
            let revision = Revision::closest(fx.at(*q));
            let result = fx.resolve_owner(revision.clone(), fx.opts()).await;
            let got = result.select(&revision).map(|c| c.revision.iat);
            assert_eq!(got, expected, "seed={} P={:?} queries={:?} q={}: {}", seed, iats, queries, q, result.reason());
            if expected.is_none() {
                assert!(result.satisfies_published_target(&revision), "empty boundary is an answer (q={})", q);
            }
        }
    }
}

/// 属性 3:只改变 scope / DID / 实际 doc_type / 完整 revision,先前目标槽不可无依据复用;
/// 访问策略不同的 I/O 任务键不同。
#[test]
fn p3_isolation_keys_change_with_every_field() {
    let scopes = [Scope::Host, Scope::Zone(DID::new("bns", "zone1.alice")), Scope::Zone(DID::new("bns", "zone2.alice"))];
    let dids = [DID::new("bns", "zone1.alice"), DID::new("bns", "zone2.alice")];
    let types = [DidDocType::Zone, DidDocType::Device, DidDocType::Owner];
    let revisions = [
        Revision::current(),
        Revision::exact(100, "aa"),
        Revision::exact(100, "ab"),
        Revision::exact(101, "aa"),
        Revision::closest(100),
        Revision::closest(101),
    ];
    let mut result_keys = HashSet::new();
    for scope in &scopes {
        for did in &dids {
            for doc_type in &types {
                assert!(result_keys.insert(DocStore::result_key(scope, did, doc_type)));
            }
        }
    }
    let revision_keys: HashSet<String> = revisions.iter().map(|r| r.cache_key()).collect();
    assert_eq!(revision_keys.len(), revisions.len());

    // 槽按完整查询区分:为一个查询建槽,其它查询看不到它。
    let doc = generic_json(&dids[0], 100, u64::MAX / 2, "slot");
    let r = rev(&doc);
    for (i, target) in revisions.iter().enumerate().skip(1) {
        let mut result = DocResult::empty(Scope::Host, dids[0].clone(), DidDocType::Zone);
        let mut info = PublishInfo::new(dids[0].clone(), DidDocType::Zone, target.clone())
            .with_status(&DocumentStatus::Active, None, None)
            .with_record(PublishRecord::published(r.iat, &r.hash, false));
        info.boundary = match target {
            Revision::Closest { before_iat } => Some(Boundary { query_iat: *before_iat, selected: Some(r.clone()), confirmed: true }),
            _ => None,
        };
        let answer = SourceAnswer::new(sref("authority", SourceTier::Authority)).with_body(doc.clone(), Carrier::Inline).with_publish_info(info);
        result.commit(&answer, target, 0, None);
        for (j, other) in revisions.iter().enumerate().skip(1) {
            if i != j {
                assert!(result.slot_for(other).is_none(), "slot for {} leaked into {}", target, other);
            }
        }
    }

    let variants = [
        ResolveOpts::default(),
        ResolveOpts::default().authority_only(),
        ResolveOpts::default().not_allow_request(),
        ResolveOpts::default().without_zone_lock(),
        ResolveOpts::default().without_local_lock(),
        ResolveOpts::default().without_local_cache(),
        ResolveOpts::default().with_transport_policy(TransportPolicy::IndependentControlPlane),
        ResolveOpts::default().with_force_authority_query(),
    ];
    let policy_keys: HashSet<String> = variants.iter().map(|o| o.access_policy_key()).collect();
    assert_eq!(policy_keys.len(), variants.len());
}

#[derive(Debug, Clone, Copy)]
enum StateOp {
    NoAnswer,
    Failure,
    HistoricalActive,
    DerivedActive,
    SimulatedActive,
    Reverify,
    Restart,
}

/// 属性 4:已知撤销之后,`Unknown → verify → restart` 等短序列不会清除它;没有新的
/// authority current 证据不能恢复可选。
#[test]
fn p4_known_terminal_state_survives_short_sequences() {
    let did = DID::new("bns", "zone1.alice");
    let doc = generic_json(&did, 100, u64::MAX / 2, "body");
    let r = rev(&doc);
    let ops = [
        StateOp::NoAnswer,
        StateOp::Failure,
        StateOp::HistoricalActive,
        StateOp::DerivedActive,
        StateOp::SimulatedActive,
        StateOp::Reverify,
        StateOp::Restart,
    ];
    for seed in 0..64u64 {
        let mut rng = Rng::new(seed);
        let mut result = DocResult::empty(Scope::Host, did.clone(), DidDocType::Device);
        let trust = SourceAnswer::new(sref("trust", SourceTier::Trust)).with_body(doc.clone(), Carrier::Body);
        result.commit(&trust, &Revision::current(), 0, None);
        let revoked = PublishInfo::new(did.clone(), DidDocType::Device, Revision::current()).with_status(&DocumentStatus::Revoked, None, None);
        result.commit(&SourceAnswer::new(sref("authority", SourceTier::Authority)).with_publish_info(revoked), &Revision::current(), 0, None);
        result.refresh_known_constraints(0, None);
        let len = 1 + rng.below(5) as usize;
        let sequence: Vec<StateOp> = (0..len).map(|_| ops[rng.below(ops.len() as u64) as usize]).collect();
        for op in &sequence {
            let authority = sref("authority", SourceTier::Authority);
            match op {
                StateOp::NoAnswer => result.commit(&SourceAnswer::no_answer(authority, "no answer"), &Revision::current(), 0, None),
                StateOp::Failure => result.commit(&SourceAnswer::failure(authority, "503"), &Revision::current(), 0, None),
                StateOp::HistoricalActive => {
                    let exact = Revision::exact(r.iat, &r.hash);
                    let info = PublishInfo::new(did.clone(), DidDocType::Device, exact.clone())
                        .with_status(&DocumentStatus::Active, None, None)
                        .with_record(PublishRecord::published(r.iat, &r.hash, false));
                    result.commit(&SourceAnswer::new(authority).with_body(doc.clone(), Carrier::Inline).with_publish_info(info), &exact, 0, None);
                }
                StateOp::DerivedActive => {
                    let mut info = PublishInfo::new(did.clone(), DidDocType::Device, Revision::current()).with_status(&DocumentStatus::Active, None, None);
                    info.derived = true;
                    result.commit(&SourceAnswer::new(authority).with_publish_info(info), &Revision::current(), 0, None);
                }
                StateOp::SimulatedActive => {
                    // locker 的模拟回答不进入普通结果;这里验证即便误合并,也不当作新的权威证据。
                    let mut info = PublishInfo::new(did.clone(), DidDocType::Device, Revision::closest(r.iat + 10))
                        .with_status(&DocumentStatus::Active, None, None);
                    info.simulated = true;
                    result.apply_publish_info(Some(&info));
                }
                StateOp::Reverify => result.commit(&trust, &Revision::current(), 0, None),
                StateOp::Restart => {
                    let text = serde_json::to_string(&result).unwrap();
                    result = serde_json::from_str(&text).unwrap();
                }
            }
            result.refresh_known_constraints(0, None);
            assert!(result.is_disabled(), "seed={} sequence={:?} cleared the revocation at {:?}", seed, sequence, op);
            assert!(result.select(&Revision::current()).is_none(), "seed={} sequence={:?}", seed, sequence);
        }
        // 正例:新的明确 current 已发布回答恢复可选。
        let fresh = generic_json(&did, 200, u64::MAX / 2, "reissued");
        let fr = rev(&fresh);
        let info = PublishInfo::new(did.clone(), DidDocType::Device, Revision::current())
            .with_status(&DocumentStatus::Active, None, None)
            .with_record(PublishRecord::published(fr.iat, &fr.hash, true));
        result.commit(
            &SourceAnswer::new(sref("authority", SourceTier::Authority)).with_body(fresh.clone(), Carrier::Inline).with_publish_info(info),
            &Revision::current(),
            0,
            None,
        );
        assert!(!result.is_disabled(), "seed={} sequence={:?}", seed, sequence);
        assert_eq!(result.select(&Revision::current()).unwrap().revision, fr);
    }
}

/// 属性 5:无终止状态变化时,同一文档重复提交幂等;无冲突的有效集合按不同顺序提交 / 合并,
/// best 相同。
#[test]
fn p5_merge_is_order_independent_without_terminal_changes() {
    let did = DID::new("bns", "zone1.alice");
    let docs: Vec<EncodedDocument> = (0..5).map(|i| generic_json(&did, 100 + i * 37, u64::MAX / 2, &format!("v{}", i))).collect();
    let expected = docs.iter().map(|d| rev(d).iat).max().unwrap();
    for seed in 0..32u64 {
        let mut rng = Rng::new(seed);
        let mut order: Vec<usize> = (0..docs.len()).collect();
        rng.shuffle(&mut order);
        let mut result = DocResult::empty(Scope::Host, did.clone(), DidDocType::Zone);
        for i in &order {
            let answer = SourceAnswer::new(sref("trust", SourceTier::Trust)).with_body(docs[*i].clone(), Carrier::Body);
            result.commit(&answer, &Revision::current(), 0, None);
            result.commit(&answer, &Revision::current(), 0, None);
        }
        assert_eq!(result.best.as_ref().unwrap().revision.iat, expected, "seed={} order={:?}", seed, order);
        assert!(result.reasons.iter().all(|r| !r.contains("conflict")), "seed={} order={:?}", seed, order);

        // 两个快照按不同顺序合并进存储。
        let split = 1 + rng.below(docs.len() as u64 - 1) as usize;
        let snapshot = |ids: &[usize]| {
            let mut s = DocResult::empty(Scope::Host, did.clone(), DidDocType::Zone);
            for i in ids {
                let answer = SourceAnswer::new(sref("trust", SourceTier::Trust)).with_body(docs[*i].clone(), Carrier::Body);
                s.commit(&answer, &Revision::current(), 0, None);
            }
            s
        };
        let (left, right) = order.split_at(split);
        let (ab, _) = DocResult::merge_into(Some(DocResult::merge_into(None, snapshot(left)).0), snapshot(right));
        let (ba, _) = DocResult::merge_into(Some(DocResult::merge_into(None, snapshot(right)).0), snapshot(left));
        assert_eq!(ab.best.as_ref().unwrap().revision.iat, expected, "seed={} split={:?}", seed, (left, right));
        assert_eq!(ba.best.as_ref().unwrap().revision.iat, expected, "seed={} split={:?}", seed, (right, left));
    }
}
