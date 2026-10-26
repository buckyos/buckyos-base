//! 设计稿 §10 验收场景(doc/resolve-did协议冻结讨论伪代码.md)。函数名前缀标行号。
//! mock authority 实现 current / exact / closest 三种查询、501 分支、负状态覆盖范围
//! 以及可注入的延迟 / 断连(TODO M2)。网络回流、FD 释放类用例见 `#[ignore]` 标记。

use async_trait::async_trait;
use buckyos_kit::buckyos_get_unix_timestamp;
use jsonwebtoken::{jwk::Jwk, EncodingKey};
use name_client::*;
use name_lib::{DIDDocumentTrait, EncodedDocument, NSError, OwnerDocument, ZoneDocument, DID};
use serde_json::json;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

// ---------- 密钥与文档构造 ----------

const OWNER_PRIVATE_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIJBRONAzbwpIOwm0ugIQNyZJrDXxZF7HoPWAZesMedOr\n-----END PRIVATE KEY-----";
const OWNER_PUBLIC_JWK_X: &str = "T4Quc1L6Ogu4N2tTKOvneV1yYnBcmhP89B_RsuFsJZ8";
const MALLORY_PRIVATE_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIAx4nc1H9RY777HF2b55RA5BNlr5d7Brjv9jiHllqMLJ\n-----END PRIVATE KEY-----";
const MALLORY_PUBLIC_JWK_X: &str = "pNq79YSL_EW-oZaHdJ5vU6I_lrl4QssD1joOtlKCLNQ";

fn jwk(x: &str) -> Jwk {
    serde_json::from_value(json!({"kty": "OKP", "crv": "Ed25519", "x": x})).unwrap()
}

fn owner_key() -> (EncodingKey, Jwk) {
    (
        EncodingKey::from_ed_pem(OWNER_PRIVATE_KEY_PEM.as_bytes()).unwrap(),
        jwk(OWNER_PUBLIC_JWK_X),
    )
}

fn mallory_key() -> (EncodingKey, Jwk) {
    (
        EncodingKey::from_ed_pem(MALLORY_PRIVATE_KEY_PEM.as_bytes()).unwrap(),
        jwk(MALLORY_PUBLIC_JWK_X),
    )
}

fn now() -> u64 {
    buckyos_get_unix_timestamp()
}

fn owner_did() -> DID {
    DID::new("bns", "alice")
}

fn zone_did() -> DID {
    DID::new("bns", "zone1.alice")
}

fn build_owner_doc(iat: u64, valid_iat: Option<u64>, key: &EncodingKey, public: Jwk) -> EncodedDocument {
    let mut owner = OwnerDocument::new(owner_did(), "alice".into(), "alice@test".into(), public);
    owner.iat = iat;
    owner.exp = iat + 3600 * 24 * 365;
    owner.valid_iat = valid_iat;
    owner.encode(Some(key)).unwrap()
}

fn owner_doc(iat: u64, valid_iat: Option<u64>) -> EncodedDocument {
    let (key, public) = owner_key();
    build_owner_doc(iat, valid_iat, &key, public)
}

fn zone_doc_signed_by(iat: u64, marker: &str, key: &EncodingKey) -> EncodedDocument {
    let (_, public) = owner_key();
    let mut zone = ZoneDocument::new(zone_did(), owner_did(), public);
    zone.iat = iat;
    zone.exp = iat + 3600 * 24 * 365;
    zone.version_seq = Some(1);
    zone.extra_info.insert("marker".into(), json!(marker));
    zone.encode(Some(key)).unwrap()
}

fn zone_doc(iat: u64, marker: &str) -> EncodedDocument {
    let (key, _) = owner_key();
    zone_doc_signed_by(iat, marker, &key)
}

fn unsigned_zone_doc(iat: u64, marker: &str) -> EncodedDocument {
    let (_, public) = owner_key();
    let mut zone = ZoneDocument::new(zone_did(), owner_did(), public);
    zone.iat = iat;
    zone.exp = iat + 3600 * 24 * 365;
    zone.extra_info.insert("marker".into(), json!(marker));
    EncodedDocument::JsonLd(serde_json::to_value(&zone).unwrap())
}

fn rev(doc: &EncodedDocument) -> DocRevision {
    DocRevision::of(doc).unwrap()
}

// ---------- mock authority ----------

#[derive(Clone, Debug, PartialEq)]
enum Mode {
    Ok,
    /// 传输失败 / 5xx。
    Down,
    /// 挂起指定时长后再回答。
    Hang(Duration),
}

#[derive(Default)]
struct AuthorityState {
    /// (did, doc_type) -> 已发布版本(按 iat)。
    versions: HashMap<(DID, String), Vec<EncodedDocument>>,
    negatives: HashMap<(DID, String), (DocumentStatus, Option<String>)>,
    owner_bindings: HashMap<DID, DID>,
    modes: HashMap<DID, Mode>,
    supports_history: bool,
}

struct MockAuthority {
    id: String,
    state: Mutex<AuthorityState>,
    calls: AtomicUsize,
    history_calls: Mutex<HashMap<DID, usize>>,
}

impl MockAuthority {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            id: "mock-authority".into(),
            state: Mutex::new(AuthorityState {
                supports_history: true,
                ..Default::default()
            }),
            calls: AtomicUsize::new(0),
            history_calls: Mutex::new(HashMap::new()),
        })
    }

    /// 对某个 DID 发出的 exact / closest 查询次数。
    fn history_calls_for(&self, did: &DID) -> usize {
        self.history_calls.lock().unwrap().get(did).copied().unwrap_or(0)
    }

    fn publish(&self, did: &DID, doc_type: &DidDocType, doc: EncodedDocument) {
        let mut state = self.state.lock().unwrap();
        state
            .versions
            .entry((did.clone(), doc_type.to_string()))
            .or_default()
            .push(doc);
    }

    fn set_negative(&self, did: &DID, doc_type: &DidDocType, status: DocumentStatus, reason: Option<&str>) {
        self.state.lock().unwrap().negatives.insert(
            (did.clone(), doc_type.to_string()),
            (status, reason.map(String::from)),
        );
    }

    fn bind_owner(&self, did: &DID, owner: &DID) {
        self.state.lock().unwrap().owner_bindings.insert(did.clone(), owner.clone());
    }

    fn set_mode(&self, did: &DID, mode: Mode) {
        self.state.lock().unwrap().modes.insert(did.clone(), mode);
    }

    fn set_history_support(&self, supported: bool) {
        self.state.lock().unwrap().supports_history = supported;
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl Source for MockAuthority {
    fn id(&self) -> String {
        self.id.clone()
    }

    fn supports_publish_info(&self) -> bool {
        true
    }

    async fn get_document(
        &self,
        did: &DID,
        doc_type: &DidDocType,
        revision: &Revision,
        _opts: &ResolveOpts,
    ) -> SourceAnswer {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if !revision.is_current() {
            *self.history_calls.lock().unwrap().entry(did.clone()).or_insert(0) += 1;
        }
        let sref = SourceRef::provider(self.id.clone(), SourceTier::Authority);
        let mode = self
            .state
            .lock()
            .unwrap()
            .modes
            .get(did)
            .cloned()
            .unwrap_or(Mode::Ok);
        match mode {
            Mode::Ok => {}
            Mode::Down => return SourceAnswer::failure(sref, "HTTP 503"),
            Mode::Hang(delay) => tokio::time::sleep(delay).await,
        }
        let state = self.state.lock().unwrap();
        let key = (did.clone(), doc_type.to_string());
        let mut info = PublishInfo::new(did.clone(), doc_type.clone(), revision.clone()).with_source(self.id.clone());
        info.owner_binding = state.owner_bindings.get(did).cloned();
        if let Some((status, reason)) = state.negatives.get(&key) {
            info = info.with_status(status, reason.clone(), None);
            return SourceAnswer::new(sref).with_publish_info(info);
        }
        let mut versions: Vec<(DocRevision, EncodedDocument)> = state
            .versions
            .get(&key)
            .map(|docs| docs.iter().map(|d| (rev(d), d.clone())).collect())
            .unwrap_or_default();
        versions.sort_by_key(|(r, _)| r.iat);
        let Some((latest_rev, latest_doc)) = versions.last().cloned() else {
            info = info.with_status(&DocumentStatus::Missing, None, None);
            return SourceAnswer::new(sref).with_publish_info(info);
        };
        info = info.with_status(&DocumentStatus::Active, None, None);
        info.latest_iat = Some(latest_rev.iat);
        match revision {
            Revision::Current => {
                info = info.with_record(PublishRecord::published(latest_rev.iat, &latest_rev.hash, true));
                SourceAnswer::new(sref)
                    .with_body(latest_doc, Carrier::Inline)
                    .with_publish_info(info)
            }
            Revision::Exact { iat, .. } => {
                if !state.supports_history {
                    let mut answer = SourceAnswer::unknown(sref, "501 historicalQuerySupported=false", false);
                    answer.unsupported_history = true;
                    return answer;
                }
                match versions.iter().find(|(r, _)| r.iat == *iat) {
                    Some((r, doc)) => {
                        info = info.with_record(PublishRecord::published(r.iat, &r.hash, r.iat == latest_rev.iat));
                        SourceAnswer::new(sref)
                            .with_body(doc.clone(), Carrier::Inline)
                            .with_publish_info(info)
                    }
                    None => {
                        info.records.push(PublishRecord::not_published(*iat));
                        SourceAnswer::new(sref).with_publish_info(info)
                    }
                }
            }
            Revision::Closest { before_iat } => {
                if !state.supports_history {
                    let mut answer = SourceAnswer::unknown(sref, "501 historicalQuerySupported=false", false);
                    answer.unsupported_history = true;
                    return answer;
                }
                let selected = versions.iter().filter(|(r, _)| r.iat < *before_iat).last().cloned();
                match selected {
                    Some((r, doc)) => {
                        info = info.with_record(PublishRecord::published(r.iat, &r.hash, r.iat == latest_rev.iat));
                        info.boundary = Some(Boundary {
                            query_iat: *before_iat,
                            selected: Some(r.clone()),
                            confirmed: true,
                        });
                        SourceAnswer::new(sref)
                            .with_body(doc, Carrier::Inline)
                            .with_publish_info(info)
                    }
                    None => {
                        info.boundary = Some(Boundary {
                            query_iat: *before_iat,
                            selected: None,
                            confirmed: true,
                        });
                        SourceAnswer::new(sref).with_publish_info(info)
                    }
                }
            }
        }
    }
}

/// trust / normal 来源:按 (did, doc_type) 返回固定文档,计数。
struct DocsSource {
    id: String,
    docs: Mutex<HashMap<(DID, String), Vec<EncodedDocument>>>,
    calls: AtomicUsize,
    mode: Mutex<Mode>,
}

impl DocsSource {
    fn new(id: &str) -> Arc<Self> {
        Arc::new(Self {
            id: id.into(),
            docs: Mutex::new(HashMap::new()),
            calls: AtomicUsize::new(0),
            mode: Mutex::new(Mode::Ok),
        })
    }

    fn add(&self, did: &DID, doc_type: &DidDocType, doc: EncodedDocument) {
        self.docs
            .lock()
            .unwrap()
            .entry((did.clone(), doc_type.to_string()))
            .or_default()
            .push(doc);
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl Source for DocsSource {
    fn id(&self) -> String {
        self.id.clone()
    }

    async fn get_document(
        &self,
        did: &DID,
        doc_type: &DidDocType,
        _revision: &Revision,
        _opts: &ResolveOpts,
    ) -> SourceAnswer {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let sref = SourceRef::provider(self.id.clone(), SourceTier::Normal);
        let mode = self.mode.lock().unwrap().clone();
        match mode {
            Mode::Ok => {}
            Mode::Down => return SourceAnswer::failure(sref, "down"),
            Mode::Hang(delay) => tokio::time::sleep(delay).await,
        }
        let docs = self.docs.lock().unwrap();
        match docs.get(&(did.clone(), doc_type.to_string())) {
            // 多份文档时返回最高 iat 的一份(其余由多次查询 / 候选投递覆盖)。
            Some(list) => {
                let doc = list.iter().max_by_key(|d| rev(d).iat).unwrap().clone();
                SourceAnswer::new(sref).with_body(doc, Carrier::Body)
            }
            None => SourceAnswer::no_answer(sref, "not here"),
        }
    }
}

struct Fixture {
    client: NameClient,
    authority: Arc<MockAuthority>,
    trust: Arc<DocsSource>,
    normal: Arc<DocsSource>,
}

fn fixture() -> Fixture {
    let client = NameClient::new(NameClientConfig {
        resolve_timeout: Duration::from_secs(5),
        request_timeout: Duration::from_secs(2),
        ..NameClientConfig::for_test()
    });
    let authority = MockAuthority::new();
    let trust = DocsSource::new("trust-site");
    let normal = DocsSource::new("normal-site");
    client.set_method_authority("bns", authority.clone());
    client.add_method_trust("bns", trust.clone());
    client.add_method_normal("bns", normal.clone());
    Fixture {
        client,
        authority,
        trust,
        normal,
    }
}

fn opts(fx: &Fixture) -> ResolveOpts {
    fx.client.default_resolve_opts()
}

fn marker(doc: &EncodedDocument) -> String {
    doc.clone()
        .to_json_value()
        .unwrap()
        .get("marker")
        .and_then(|m| m.as_str())
        .unwrap_or_default()
        .to_string()
}

// ---------- §10 场景 ----------

/// authority 发布 V1,trust / 合法 normal 提供更高 V2 → latest V1,best V2;
/// 普通 current 不因已有 latest 停止收集。
#[tokio::test]
async fn s11_authority_v1_and_signed_normal_v2_give_latest_v1_best_v2() {
    let fx = fixture();
    let t = now();
    fx.authority.publish(&owner_did(), &DidDocType::Owner, owner_doc(t - 1000, None));
    let v1 = zone_doc(t - 500, "v1");
    let v2 = zone_doc(t - 100, "v2");
    fx.authority.publish(&zone_did(), &DidDocType::Zone, v1.clone());
    fx.normal.add(&zone_did(), &DidDocType::Zone, v2.clone());

    let result = fx
        .client
        .resolve_did_ex(&zone_did(), Some(DidDocType::Zone), Revision::current(), opts(&fx))
        .await
        .unwrap();
    assert_eq!(result.latest.as_ref().unwrap().revision, rev(&v1));
    let best = result.best.as_ref().unwrap();
    assert_eq!(best.revision, rev(&v2));
    assert!(best.report.is_signed && !best.report.is_published);
    assert_eq!(fx.normal.calls(), 1, "normal source is consulted even after authority answered");
    assert_eq!(marker(&fx.client.resolve_did(&zone_did(), Some(DidDocType::Zone)).await.unwrap()), "v2");
}

fn grace_fixture(grace: Duration) -> Fixture {
    let fx = fixture();
    let client = NameClient::new(NameClientConfig {
        resolve_timeout: Duration::from_secs(5),
        request_timeout: Duration::from_secs(2),
        supplement_grace: grace,
        ..NameClientConfig::for_test()
    });
    client.set_method_authority("bns", fx.authority.clone());
    client.add_method_trust("bns", fx.trust.clone());
    client.add_method_normal("bns", fx.normal.clone());
    Fixture { client, ..fx }
}

/// authority 已给出有效 best 时,慢补充来源只等宽限期:按时返回 authority 的文档,
/// 未回答的来源记为 Unknown 且不退避(issue #684)。
#[tokio::test]
async fn s11_slow_supplement_after_valid_authority_is_bounded_by_grace() {
    let fx = grace_fixture(Duration::from_millis(200));
    let t = now();
    fx.authority.publish(&owner_did(), &DidDocType::Owner, owner_doc(t - 1000, None));
    let v1 = zone_doc(t - 500, "v1");
    fx.authority.publish(&zone_did(), &DidDocType::Zone, v1.clone());
    fx.normal.add(&zone_did(), &DidDocType::Zone, zone_doc(t - 100, "v2"));
    *fx.normal.mode.lock().unwrap() = Mode::Hang(Duration::from_secs(3));

    for round in 1..=2 {
        let started = std::time::Instant::now();
        let result = fx
            .client
            .resolve_did_ex(&zone_did(), Some(DidDocType::Zone), Revision::current(), opts(&fx))
            .await
            .unwrap();
        assert!(started.elapsed() < Duration::from_secs(1), "round {} waited {:?}", round, started.elapsed());
        assert_eq!(result.best.as_ref().unwrap().revision, rev(&v1));
        assert_eq!(result.latest.as_ref().unwrap().revision, rev(&v1));
        assert!(result.reason().contains("normal-site"), "{}", result.reason());
        assert_eq!(fx.normal.calls(), round, "grace expiry does not back the source off");
    }
}

/// authority Unknown 时补充来源不受宽限期限制,仍在单源上限内等待回答。
#[tokio::test]
async fn s12_authority_unknown_waits_for_slow_supplement_beyond_grace() {
    let fx = grace_fixture(Duration::from_millis(100));
    let t = now();
    fx.authority.publish(&owner_did(), &DidDocType::Owner, owner_doc(t - 1000, None));
    fx.authority.set_mode(&zone_did(), Mode::Down);
    let v2 = zone_doc(t - 100, "v2");
    fx.normal.add(&zone_did(), &DidDocType::Zone, v2.clone());
    *fx.normal.mode.lock().unwrap() = Mode::Hang(Duration::from_millis(400));

    let result = fx
        .client
        .resolve_did_ex(&zone_did(), Some(DidDocType::Zone), Revision::current(), opts(&fx))
        .await
        .unwrap();
    assert_eq!(result.best.as_ref().unwrap().revision, rev(&v2));
}

/// authority Unknown,补充来源仍可用:继续查询允许来源并按验签规则处理,不把 Unknown 当禁用。
#[tokio::test]
async fn s12_authority_unknown_does_not_stop_supplements() {
    let fx = fixture();
    let t = now();
    fx.authority.publish(&owner_did(), &DidDocType::Owner, owner_doc(t - 1000, None));
    fx.authority.set_mode(&zone_did(), Mode::Down);
    let v2 = zone_doc(t - 100, "v2");
    fx.normal.add(&zone_did(), &DidDocType::Zone, v2.clone());

    let result = fx
        .client
        .resolve_did_ex(&zone_did(), Some(DidDocType::Zone), Revision::current(), opts(&fx))
        .await
        .unwrap();
    assert!(!result.is_disabled());
    assert!(result.latest.is_none());
    assert_eq!(result.best.as_ref().unwrap().revision, rev(&v2));
    assert!(result.best.as_ref().unwrap().report.is_signed);
}

/// trust 提供无签名 JSON → 可成为 best,不自动标 signed / published。
#[tokio::test]
async fn s13_trust_unsigned_json_becomes_best_without_signed_flag() {
    let fx = fixture();
    let t = now();
    let doc = unsigned_zone_doc(t - 100, "trusted");
    fx.trust.add(&zone_did(), &DidDocType::Zone, doc.clone());
    let result = fx
        .client
        .resolve_did_ex(&zone_did(), Some(DidDocType::Zone), Revision::current(), opts(&fx))
        .await
        .unwrap();
    let best = result.best.as_ref().unwrap();
    assert_eq!(best.revision, rev(&doc));
    assert!(!best.report.is_signed && !best.report.is_published);
    assert_eq!(best.source.tier, SourceTier::Trust);
}

/// 验证 V1 时已有更高有效 best V2:报告针对 V1,不回滚 best,不借 V2 成功让 V1 命中 current。
#[tokio::test]
async fn s14_verify_older_v1_does_not_borrow_v2_success() {
    let fx = fixture();
    let t = now();
    fx.authority.publish(&owner_did(), &DidDocType::Owner, owner_doc(t - 1000, None));
    let v1 = zone_doc(t - 500, "v1");
    let v2 = zone_doc(t - 100, "v2");
    fx.authority.publish(&zone_did(), &DidDocType::Zone, v2.clone());
    fx.client
        .resolve_did_ex(&zone_did(), Some(DidDocType::Zone), Revision::current(), opts(&fx))
        .await
        .unwrap();

    let report = fx
        .client
        .verify_document(&zone_did(), Some(DidDocType::Zone), &v1, Revision::current(), opts(&fx))
        .await
        .unwrap();
    assert_eq!(report.validity, Validity::Valid);
    assert!(report.is_signed);
    assert!(!report.is_best && !report.success(&Revision::current()));
    let after = fx
        .client
        .resolve_did_ex(&zone_did(), Some(DidDocType::Zone), Revision::current(), opts(&fx))
        .await
        .unwrap();
    assert_eq!(after.best.unwrap().revision, rev(&v2));
}

/// 同 iat 的坏候选先到、合法候选后到:坏候选不占可信槽;两个已验证不同 hash 才判冲突。
#[tokio::test]
async fn s15_bad_candidate_at_same_iat_does_not_block_good_one() {
    let fx = fixture();
    let t = now();
    fx.authority.publish(&owner_did(), &DidDocType::Owner, owner_doc(t - 1000, None));
    let (mallory, _) = mallory_key();
    let bad = zone_doc_signed_by(t - 100, "bad", &mallory);
    let good = zone_doc(t - 100, "good");
    fx.client
        .commit_candidate_doc(&zone_did(), Some(DidDocType::Zone), &bad, SourceRef::normal("gossip"), opts(&fx))
        .await
        .unwrap();
    fx.client
        .commit_candidate_doc(&zone_did(), Some(DidDocType::Zone), &good, SourceRef::normal("gossip"), opts(&fx))
        .await
        .unwrap();
    let result = fx
        .client
        .resolve_did_ex(&zone_did(), Some(DidDocType::Zone), Revision::current(), opts(&fx))
        .await
        .unwrap();
    assert_eq!(result.best.as_ref().unwrap().revision, rev(&good));

    // 已验证 good 之后,同 iat 不同 hash 的另一份合法签名文档判冲突。
    let other = zone_doc(t - 100, "other");
    let report = fx
        .client
        .verify_document(&zone_did(), Some(DidDocType::Zone), &other, Revision::current(), opts(&fx))
        .await
        .unwrap();
    assert_eq!(report.validity, Validity::Invalid);
    assert!(report.conflict.is_some());
}

/// 输入与同 iat 发布 hash 不同 → invalid;其它 iat 的发布 hash 不否定该输入。
#[tokio::test]
async fn s16_published_hash_mismatch_is_invalid_only_at_same_iat() {
    let fx = fixture();
    let t = now();
    fx.authority.publish(&owner_did(), &DidDocType::Owner, owner_doc(t - 1000, None));
    let published = zone_doc(t - 100, "published");
    fx.authority.publish(&zone_did(), &DidDocType::Zone, published.clone());

    let same_iat = zone_doc(t - 100, "forged");
    let report = fx
        .client
        .verify_document(&zone_did(), Some(DidDocType::Zone), &same_iat, Revision::current(), opts(&fx))
        .await
        .unwrap();
    assert_eq!(report.validity, Validity::Invalid);
    assert!(report.reason().contains("hash"));

    let other_iat = zone_doc(t - 50, "newer-unpublished");
    let report = fx
        .client
        .verify_document(&zone_did(), Some(DidDocType::Zone), &other_iat, Revision::current(), opts(&fx))
        .await
        .unwrap();
    assert_eq!(report.validity, Validity::Valid, "{}", report.reason());
    assert!(report.is_signed && !report.is_published && report.is_best);
}

/// exact hash 不符、closest 无边界回答或 provider 不支持 → 不满足目标并保留原因,不回退 current。
#[tokio::test]
async fn s17_exact_and_closest_never_fall_back_to_current() {
    let fx = fixture();
    let t = now();
    let o1 = owner_doc(t - 2000, None);
    let o2 = owner_doc(t - 1000, None);
    fx.authority.publish(&owner_did(), &DidDocType::Owner, o1.clone());
    fx.authority.publish(&owner_did(), &DidDocType::Owner, o2.clone());

    fx.client
        .resolve_did_ex(&owner_did(), Some(DidDocType::Owner), Revision::current(), opts(&fx))
        .await
        .unwrap();
    let exact = fx
        .client
        .resolve_did_ex(&owner_did(), Some(DidDocType::Owner), Revision::exact(rev(&o1).iat, "deadbeef"), opts(&fx))
        .await
        .unwrap();
    assert!(exact.select(&Revision::exact(rev(&o1).iat, "deadbeef")).is_none());
    assert!(exact.select(&Revision::current()).is_some(), "current slot is unaffected");
    let real = fx
        .client
        .resolve_did_ex(&owner_did(), Some(DidDocType::Owner), Revision::exact(rev(&o1).iat, &rev(&o1).hash), opts(&fx))
        .await
        .unwrap();
    assert_eq!(real.select(&Revision::exact(rev(&o1).iat, &rev(&o1).hash)).unwrap().revision, rev(&o1));

    let closest = fx
        .client
        .resolve_did_ex(&owner_did(), Some(DidDocType::Owner), Revision::closest(t - 1500), opts(&fx))
        .await
        .unwrap();
    assert_eq!(closest.select(&Revision::closest(t - 1500)).unwrap().revision, rev(&o1));

    fx.authority.set_history_support(false);
    let fx2 = fixture();
    fx2.authority.set_history_support(false);
    fx2.authority.publish(&owner_did(), &DidDocType::Owner, o1.clone());
    fx2.authority.publish(&owner_did(), &DidDocType::Owner, o2.clone());
    let unsupported = fx2
        .client
        .resolve_did_ex(&owner_did(), Some(DidDocType::Owner), Revision::closest(t - 1500), opts(&fx2))
        .await
        .unwrap();
    assert!(unsupported.select(&Revision::closest(t - 1500)).is_none());
    assert!(unsupported.reason().contains("closest") || unsupported.reason().contains("501"), "{}", unsupported.reason());
}

/// Owner 历史签名正确,但当前 valid_iat 覆盖子文档 → is_signed、is_revoked、invalid。
#[tokio::test]
async fn s18_signed_but_revoked_by_current_owner_valid_iat() {
    let fx = fixture();
    let t = now();
    let doc = zone_doc(t - 500, "old");
    fx.authority.publish(&owner_did(), &DidDocType::Owner, owner_doc(t - 1000, None));
    fx.authority.publish(&owner_did(), &DidDocType::Owner, owner_doc(t - 200, Some(t - 300)));
    let report = fx
        .client
        .verify_document(&zone_did(), Some(DidDocType::Zone), &doc, Revision::current(), opts(&fx))
        .await
        .unwrap();
    assert!(report.is_signed, "{}", report.reason());
    assert!(report.is_revoked);
    assert_eq!(report.validity, Validity::Invalid);
    assert!(!report.is_best && !report.is_latest);
}

/// 缺历史 Owner,但当前 Owner 有可用 key → 保留缺材料原因,不用当前根替代 closest 发布依据。
#[tokio::test]
async fn s19_missing_historical_owner_is_unknown_not_current_substitute() {
    let fx = fixture();
    let t = now();
    fx.authority.set_history_support(false);
    // 文档 iat 早于当前 owner 发布时间:需要真正的历史查询。
    fx.authority.publish(&owner_did(), &DidDocType::Owner, owner_doc(t - 100, None));
    let doc = zone_doc(t - 500, "older-than-owner");
    let report = fx
        .client
        .verify_document(&zone_did(), Some(DidDocType::Zone), &doc, Revision::current(), opts(&fx))
        .await
        .unwrap();
    assert_eq!(report.validity, Validity::Unknown, "{}", report.reason());
    assert!(!report.is_signed);
    assert!(report.missing.iter().any(|m| m.contains("closest")));
}

/// 缓存命中后 owner 依赖变化(valid_iat)→ 撤掉选择资格,不能靠缓存命中绕过约束。
#[tokio::test]
async fn s20_cached_best_loses_selection_when_owner_constraint_changes() {
    let fx = fixture();
    let t = now();
    fx.authority.publish(&owner_did(), &DidDocType::Owner, owner_doc(t - 1000, None));
    let doc = zone_doc(t - 500, "v1");
    fx.normal.add(&zone_did(), &DidDocType::Zone, doc.clone());
    let first = fx
        .client
        .resolve_did_ex(&zone_did(), Some(DidDocType::Zone), Revision::current(), opts(&fx))
        .await
        .unwrap();
    assert_eq!(first.best.as_ref().unwrap().revision, rev(&doc));

    // owner 换版并设置 valid_iat 覆盖 v1。
    fx.authority.publish(&owner_did(), &DidDocType::Owner, owner_doc(t - 100, Some(t - 300)));
    fx.client
        .remove_doc_result(&owner_did(), &DidDocType::Owner, opts(&fx))
        .await
        .unwrap();
    fx.client
        .resolve_did_ex(&owner_did(), Some(DidDocType::Owner), Revision::current(), opts(&fx))
        .await
        .unwrap();
    let again = fx
        .client
        .resolve_did_ex(&zone_did(), Some(DidDocType::Zone), Revision::current(), opts(&fx))
        .await
        .unwrap();
    assert!(again.best.is_none(), "revoked best must not be selectable: {}", again.reason());
}

/// local locker 覆盖、缺列或明确禁用:本机优先;未覆盖列继续;强制负回答不当 miss。
#[tokio::test]
async fn s21_local_locker_overrides_and_forces_negative_answers() {
    let fx = fixture();
    let t = now();
    fx.authority.publish(&owner_did(), &DidDocType::Owner, owner_doc(t - 1000, None));
    fx.authority.publish(&zone_did(), &DidDocType::Zone, zone_doc(t - 500, "authority"));
    let locked = unsigned_zone_doc(t - 100, "locked");
    fx.client
        .lock_document(zone_did(), DidDocType::Zone, locked.clone(), LockOptions::default());
    let result = fx
        .client
        .resolve_did_ex(&zone_did(), Some(DidDocType::Zone), Revision::current(), opts(&fx))
        .await
        .unwrap();
    assert!(result.locked);
    assert_eq!(result.select(&Revision::current()).unwrap().revision, rev(&locked));
    assert!(result.select(&Revision::current()).unwrap().report.publish_evidence.as_ref().unwrap().simulated);
    assert_eq!(fx.authority.calls(), 0, "locker answers without touching providers");

    fx.client.unlock_document(&zone_did(), DidDocType::Zone);
    fx.client.local_locker().lock_negative(zone_did(), &DidDocType::Zone, TypeState::Missing, LockOptions::default());
    let negative = fx
        .client
        .resolve_did_ex(&zone_did(), Some(DidDocType::Zone), Revision::current(), opts(&fx))
        .await
        .unwrap();
    assert!(negative.locked && negative.select(&Revision::current()).is_none());
    assert!(negative.is_not_exist());

    // locker 缺列(没锁 owner)时 owner 继续向后查。
    let owner = fx
        .client
        .resolve_did_ex(&owner_did(), Some(DidDocType::Owner), Revision::current(), opts(&fx))
        .await
        .unwrap();
    assert!(!owner.locked && owner.select(&Revision::current()).is_some());
}

/// 冷缓存 no_request + without_zone_lock:包括 Owner current / closest 在内均不联网,缺材料明确失败。
#[tokio::test]
async fn s22_strictly_offline_makes_zero_network_calls() {
    let fx = fixture();
    let t = now();
    fx.authority.publish(&owner_did(), &DidDocType::Owner, owner_doc(t - 1000, None));
    fx.authority.publish(&zone_did(), &DidDocType::Zone, zone_doc(t - 500, "v1"));
    let offline = opts(&fx).strictly_offline();
    let result = fx
        .client
        .resolve_did_ex(&zone_did(), Some(DidDocType::Zone), Revision::current(), offline.clone())
        .await
        .unwrap();
    assert!(result.select(&Revision::current()).is_none());
    let report = fx
        .client
        .verify_document(&zone_did(), Some(DidDocType::Zone), &zone_doc(t - 400, "x"), Revision::current(), offline)
        .await
        .unwrap();
    assert_eq!(report.validity, Validity::Unknown);
    assert_eq!(fx.authority.calls(), 0);
    assert_eq!(fx.trust.calls() + fx.normal.calls(), 0);
}

/// RTCP outbound 遇权威 503:authority_only 下 trust / normal 网络调用为 0,在预算内结束。
#[tokio::test]
async fn s23_authority_only_outbound_never_touches_supplements() {
    let fx = fixture();
    fx.authority.set_mode(&zone_did(), Mode::Down);
    fx.normal.add(&zone_did(), &DidDocType::Zone, zone_doc(now() - 100, "v2"));
    let rtcp = opts(&fx).authority_only().without_zone_lock();
    let started = std::time::Instant::now();
    let result = fx
        .client
        .resolve_did_ex(&zone_did(), Some(DidDocType::Zone), Revision::current(), rtcp)
        .await
        .unwrap();
    assert!(result.select(&Revision::current()).is_none());
    assert_eq!(fx.trust.calls() + fx.normal.calls(), 0);
    assert!(started.elapsed() < Duration::from_secs(5));
    // 退避:紧接着的同策略调用不再打 authority;不同策略的调用不受影响。
    let before = fx.authority.calls();
    fx.client
        .resolve_did_ex(&zone_did(), Some(DidDocType::Zone), Revision::current(), opts(&fx).authority_only().without_zone_lock())
        .await
        .unwrap();
    assert_eq!(fx.authority.calls(), before, "failed source backs off");
    fx.client
        .resolve_did_ex(&zone_did(), Some(DidDocType::Zone), Revision::current(), opts(&fx))
        .await
        .unwrap();
    assert!(fx.authority.calls() > before, "other policies keep their own backoff key");
}

/// 锁等待、Owner 递归、多 provider 重试超过总预算或被取消 → 终止整次调用,不返回旧缓存成功。
#[tokio::test]
async fn s25_budget_exhaustion_terminates_without_stale_success() {
    let fx = fixture();
    let t = now();
    fx.authority.publish(&owner_did(), &DidDocType::Owner, owner_doc(t - 1000, None));
    fx.authority.publish(&zone_did(), &DidDocType::Zone, zone_doc(t - 500, "v1"));
    fx.client
        .resolve_did_ex(&zone_did(), Some(DidDocType::Zone), Revision::current(), opts(&fx))
        .await
        .unwrap();
    fx.authority.set_mode(&zone_did(), Mode::Hang(Duration::from_secs(3)));
    let tight = opts(&fx).with_timeout(Duration::from_millis(200)).with_force_authority_query();
    let err = fx
        .client
        .resolve_did_ex(&zone_did(), Some(DidDocType::Zone), Revision::current(), tight)
        .await
        .unwrap_err();
    assert!(matches!(err, NSError::DeadlineExceeded(_)), "{:?}", err);

    let cancel = tokio_util::sync::CancellationToken::new();
    let cancelled = opts(&fx).with_cancel(cancel.clone()).with_force_authority_query();
    let client = &fx.client;
    let zone = zone_did();
    let (res, _) = tokio::join!(
        client.resolve_did_ex(&zone, Some(DidDocType::Zone), Revision::current(), cancelled),
        async {
            tokio::time::sleep(Duration::from_millis(50)).await;
            cancel.cancel();
        }
    );
    assert!(matches!(res.unwrap_err(), NSError::Cancelled(_)));
}

/// 不同访问策略并发不复用网络任务。
#[tokio::test]
async fn s26_different_policies_do_not_share_tasks() {
    let fx = fixture();
    let t = now();
    fx.authority.publish(&owner_did(), &DidDocType::Owner, owner_doc(t - 1000, None));
    fx.authority.publish(&zone_did(), &DidDocType::Zone, zone_doc(t - 500, "v1"));
    fx.authority.set_mode(&zone_did(), Mode::Hang(Duration::from_millis(100)));
    let client = &fx.client;
    let zone = zone_did();
    let (a, b) = tokio::join!(
        client.resolve_did_ex(&zone, Some(DidDocType::Zone), Revision::current(), opts(&fx)),
        client.resolve_did_ex(&zone, Some(DidDocType::Zone), Revision::current(), opts(&fx).authority_only())
    );
    assert!(a.unwrap().select(&Revision::current()).is_some());
    assert!(b.unwrap().select(&Revision::current()).is_some());
    // 两种访问策略各自查询一次 zone(authority 文档免 Owner 验签,不查 owner)。
    assert_eq!(fx.authority.calls(), 2);
}

/// AuthorityCurrent 遇模拟发布、仅 trust best:只接受本轮真实 authority receipt 精确绑定的有效文档。
#[tokio::test]
async fn s27_authority_current_rejects_simulated_and_trust_only() {
    let fx = fixture();
    let t = now();
    fx.trust.add(&zone_did(), &DidDocType::Zone, unsigned_zone_doc(t - 100, "trust"));
    let rtcp = opts(&fx).without_local_lock().without_zone_lock().authority_only().with_force_authority_query();
    let normalized = rtcp.clone().normalize(Duration::from_secs(5));
    let result = fx
        .client
        .resolve_did_ex(&zone_did(), Some(DidDocType::Zone), Revision::current(), normalized.clone())
        .await
        .unwrap();
    assert!(select_authority_current(&result, normalized.receipts()).is_none());

    fx.authority.publish(&owner_did(), &DidDocType::Owner, owner_doc(t - 1000, None));
    let published = zone_doc(t - 50, "published");
    fx.authority.publish(&zone_did(), &DidDocType::Zone, published.clone());
    let normalized = rtcp.normalize(Duration::from_secs(5));
    let result = fx
        .client
        .resolve_did_ex(&zone_did(), Some(DidDocType::Zone), Revision::current(), normalized.clone())
        .await
        .unwrap();
    let chosen = select_authority_current(&result, normalized.receipts()).unwrap();
    assert_eq!(chosen.revision, rev(&published));
}

/// authority 只支持 current,文档 iat 晚于当前 Owner 发布时间:closest 由 current 推出,不发历史查询。
#[tokio::test]
async fn s31_closest_is_derived_from_current_without_history_query() {
    let fx = fixture();
    let t = now();
    fx.authority.set_history_support(false);
    fx.authority.publish(&owner_did(), &DidDocType::Owner, owner_doc(t - 1000, None));
    let doc = zone_doc(t - 100, "after-owner");
    let report = fx
        .client
        .verify_document(&zone_did(), Some(DidDocType::Zone), &doc, Revision::current(), opts(&fx))
        .await
        .unwrap();
    assert_eq!(report.validity, Validity::Valid, "{}", report.reason());
    assert!(report.is_signed);
    assert_eq!(fx.authority.history_calls_for(&owner_did()), 0, "closest derived, no history query");
    assert!(report
        .dependencies
        .iter()
        .any(|d| d.role == DependencyRole::SigningOwner));
}

/// authority 回答 invalid:明确回答、不退避;类型级负状态;normal JWT 仍可经 owner 链成为 best。
#[tokio::test]
async fn s32_invalid_is_an_answer_not_unknown() {
    let fx = fixture();
    let t = now();
    fx.authority.publish(&owner_did(), &DidDocType::Owner, owner_doc(t - 1000, None));
    fx.authority.set_negative(&zone_did(), &DidDocType::Zone, DocumentStatus::Invalid, Some("device/zone mismatch"));
    let signed = zone_doc(t - 100, "normal");
    fx.normal.add(&zone_did(), &DidDocType::Zone, signed.clone());
    let normalized = opts(&fx).normalize(Duration::from_secs(5));
    let result = fx
        .client
        .resolve_did_ex(&zone_did(), Some(DidDocType::Zone), Revision::current(), normalized.clone())
        .await
        .unwrap();
    assert!(!result.is_disabled());
    assert!(result.is_not_exist());
    assert!(result.latest.is_none());
    assert_eq!(result.best.as_ref().unwrap().revision, rev(&signed));
    assert!(select_authority_current(&result, normalized.receipts()).is_none());
    // 不退避:再次调用仍打 authority。
    let before = fx.authority.calls();
    fx.client
        .resolve_did_ex(&zone_did(), Some(DidDocType::Zone), Revision::current(), opts(&fx).with_force_authority_query())
        .await
        .unwrap();
    assert!(fx.authority.calls() > before);
}

/// 默认策略解析在查补充源时请求回流,入站受限策略解析同一键:入站不被串行锁阻塞,
/// 自己查 authority 后在预算内结束(TODO §5 R1)。
#[tokio::test]
async fn s33_inbound_restricted_resolve_is_not_blocked_by_outbound_io() {
    let fx = fixture();
    let t = now();
    fx.authority.publish(&owner_did(), &DidDocType::Owner, owner_doc(t - 1000, None));
    fx.authority.publish(&zone_did(), &DidDocType::Zone, zone_doc(t - 500, "v1"));
    *fx.normal.mode.lock().unwrap() = Mode::Hang(Duration::from_secs(2));
    let client = &fx.client;
    let zone = zone_did();
    let outer = client.resolve_did_ex(&zone, Some(DidDocType::Zone), Revision::current(), opts(&fx));
    let inner = async {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let started = std::time::Instant::now();
        let result = client
            .resolve_did_ex(
                &zone_did(),
                Some(DidDocType::Zone),
                Revision::current(),
                opts(&fx).authority_only().without_zone_lock(),
            )
            .await
            .unwrap();
        (result, started.elapsed())
    };
    let (outer, (inner, inner_elapsed)) = tokio::join!(outer, inner);
    assert!(inner.select(&Revision::current()).is_some());
    assert!(inner_elapsed < Duration::from_secs(1), "inner waited {:?}", inner_elapsed);
    assert!(outer.unwrap().select(&Revision::current()).is_some());
}

/// 两进程提交同 iat 不同 hash:原子裁决并修正本次冲突报告。
#[tokio::test]
async fn s30_two_stores_conflict_at_same_iat() {
    let tmp = tempfile::tempdir().unwrap();
    let make = || {
        let client = NameClient::new(NameClientConfig {
            cache_backend: CacheBackend::Filesystem,
            local_cache_dir: Some(tmp.path().to_string_lossy().to_string()),
            enable_zone_locker: false,
            ..NameClientConfig::default()
        });
        let authority = MockAuthority::new();
        client.set_method_authority("bns", authority.clone());
        (client, authority)
    };
    let t = now();
    let (a, auth_a) = make();
    let (b, auth_b) = make();
    auth_a.publish(&owner_did(), &DidDocType::Owner, owner_doc(t - 1000, None));
    auth_b.publish(&owner_did(), &DidDocType::Owner, owner_doc(t - 1000, None));
    let doc_a = zone_doc(t - 100, "a");
    let doc_b = zone_doc(t - 100, "b");
    let ra = a
        .verify_document(&zone_did(), Some(DidDocType::Zone), &doc_a, Revision::current(), a.default_resolve_opts())
        .await
        .unwrap();
    assert_eq!(ra.validity, Validity::Valid, "{}", ra.reason());
    let rb = b
        .verify_document(&zone_did(), Some(DidDocType::Zone), &doc_b, Revision::current(), b.default_resolve_opts())
        .await
        .unwrap();
    assert_eq!(rb.validity, Validity::Invalid);
    assert!(rb.reason().contains("conflict"));
    // 删除普通 body 不抹负状态、不解锁。
    a.lock_document(zone_did(), DidDocType::Zone, doc_a.clone(), LockOptions::default());
    a.remove_doc_result(&zone_did(), &DidDocType::Zone, a.default_resolve_opts()).await.unwrap();
    let locked = a
        .resolve_did_ex(&zone_did(), Some(DidDocType::Zone), Revision::current(), a.default_resolve_opts())
        .await
        .unwrap();
    assert!(locked.locked);
}

/// 策略拒绝或预算不足后,另一普通调用查询相同来源:前次诊断不污染共享负缓存 / 退避。
#[tokio::test]
async fn s29_policy_refusal_does_not_poison_shared_cache() {
    let fx = fixture();
    let t = now();
    fx.authority.publish(&owner_did(), &DidDocType::Owner, owner_doc(t - 1000, None));
    fx.authority.publish(&zone_did(), &DidDocType::Zone, zone_doc(t - 500, "v1"));
    let refused = fx
        .client
        .resolve_did_ex(&zone_did(), Some(DidDocType::Zone), Revision::current(), opts(&fx).not_allow_request())
        .await
        .unwrap();
    assert!(refused.select(&Revision::current()).is_none());
    let allowed = fx
        .client
        .resolve_did_ex(&zone_did(), Some(DidDocType::Zone), Revision::current(), opts(&fx))
        .await
        .unwrap();
    assert!(allowed.select(&Revision::current()).is_some());
}

/// 同一轮 body / publish_info 复用;新调用不能继承旧 receipt。
#[tokio::test]
async fn s28_receipts_are_per_call() {
    let fx = fixture();
    let t = now();
    fx.authority.publish(&owner_did(), &DidDocType::Owner, owner_doc(t - 1000, None));
    let first = opts(&fx).normalize(Duration::from_secs(5));
    fx.client
        .resolve_did_ex(&owner_did(), Some(DidDocType::Owner), Revision::current(), first.clone())
        .await
        .unwrap();
    assert_eq!(first.receipts().authority_receipts(&owner_did(), &DidDocType::Owner).len(), 1);
    let second = opts(&fx).normalize(Duration::from_secs(5));
    assert!(second.receipts().authority_receipts(&owner_did(), &DidDocType::Owner).is_empty());
}

/// key 类 DID 不是解析入口。
#[tokio::test]
async fn key_class_did_is_rejected() {
    let fx = fixture();
    let did = DID::from_str("did:dev:5bUuyWLOKyCre9az_IhJVIuOw8bA0gyKjstcYGHbaPE").unwrap();
    let err = fx
        .client
        .resolve_did_ex(&did, None, Revision::current(), opts(&fx))
        .await
        .unwrap_err();
    assert!(matches!(err, NSError::InvalidDID(_)));
    assert_eq!(fx.authority.calls(), 0);
}

/// owner 文档不能靠自己签名建立信任:需要 authority / locker 对确切根文档的依据。
#[tokio::test]
async fn self_signed_owner_cannot_bootstrap_trust() {
    let fx = fixture();
    let t = now();
    let (mallory, public) = mallory_key();
    let forged = build_owner_doc(t - 100, None, &mallory, public);
    fx.authority.publish(&owner_did(), &DidDocType::Owner, owner_doc(t - 1000, None));
    let report = fx
        .client
        .verify_document(&owner_did(), Some(DidDocType::Owner), &forged, Revision::current(), opts(&fx))
        .await
        .unwrap();
    assert_ne!(report.validity, Validity::Valid);
    assert!(!report.success(&Revision::current()));
    let real = owner_doc(t - 1000, None);
    let report = fx
        .client
        .verify_document(&owner_did(), Some(DidDocType::Owner), &real, Revision::current(), opts(&fx))
        .await
        .unwrap();
    assert!(report.success(&Revision::current()), "{}", report.reason());
    assert!(report.is_published && report.is_latest);
}

/// Owner 绑定来自 authority,候选自报的 owner 不算。
#[tokio::test]
async fn declared_owner_must_match_binding() {
    let fx = fixture();
    let t = now();
    let (mallory, public) = mallory_key();
    let mallory_did = DID::new("bns", "mallory");
    let mut evil_owner = OwnerDocument::new(mallory_did.clone(), "m".into(), "m".into(), public);
    evil_owner.iat = t - 1000;
    evil_owner.exp = t + 1000;
    fx.authority.publish(&mallory_did, &DidDocType::Owner, evil_owner.encode(Some(&mallory)).unwrap());
    fx.authority.publish(&owner_did(), &DidDocType::Owner, owner_doc(t - 1000, None));
    let (_, owner_public) = owner_key();
    let mut zone = ZoneDocument::new(zone_did(), mallory_did.clone(), owner_public);
    zone.iat = t - 100;
    zone.exp = t + 1000;
    let evil_zone = zone.encode(Some(&mallory)).unwrap();
    let report = fx
        .client
        .verify_document(&zone_did(), Some(DidDocType::Zone), &evil_zone, Revision::current(), opts(&fx))
        .await
        .unwrap();
    assert_eq!(report.validity, Validity::Invalid);
    assert!(report.reason().contains("owner"));
    let _ = DIDDocumentTrait::get_id(&zone);
}
