//! 设计稿 §2 的最小测试装置:`ScriptedSource`、两套独立固定密钥、冻结墙钟、
//! `RequestTrace` 与闸门(屏障)。
//!
//! 时间:真实 JWT 验签按真实时间检查 `exp`,所以夹具时间是"真实当前时刻"的偏移:
//! 设计稿中的墙钟 `now=10_000` 对应 [`Fx::at`]`(10_000)`,解析器墙钟冻结在同一时刻。

use super::super::clock::test_clock;
use super::super::*;
use crate::{NameClient, NameClientConfig};
use async_trait::async_trait;
use jsonwebtoken::{jwk::Jwk, Algorithm, EncodingKey};
use name_lib::{DIDDocumentTrait, DidDocType, EncodedDocument, OwnerDocument, ZoneDocument, DID};
use serde_json::{json, Value};
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::Semaphore;
use tokio::time::Instant;

// ---------- 密钥 ----------

/// 一把固定测试密钥:真实签名、真实验签。
#[derive(Clone)]
pub struct TestKey {
    pub name: &'static str,
    pem: &'static str,
    pub x: &'static str,
}

impl TestKey {
    pub fn encoding(&self) -> EncodingKey {
        EncodingKey::from_ed_pem(self.pem.as_bytes()).unwrap()
    }

    pub fn jwk(&self) -> Jwk {
        serde_json::from_value(json!({"kty": "OKP", "crv": "Ed25519", "x": self.x})).unwrap()
    }
}

/// owner 的第一把 key。
pub const K1: TestKey = TestKey {
    name: "K1",
    pem: "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIJBRONAzbwpIOwm0ugIQNyZJrDXxZF7HoPWAZesMedOr\n-----END PRIVATE KEY-----",
    x: "T4Quc1L6Ogu4N2tTKOvneV1yYnBcmhP89B_RsuFsJZ8",
};

/// owner 换 key 之后的第二把 key(与 K1 独立)。
pub const K2: TestKey = TestKey {
    name: "K2",
    pem: "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIAx4nc1H9RY777HF2b55RA5BNlr5d7Brjv9jiHllqMLJ\n-----END PRIVATE KEY-----",
    x: "pNq79YSL_EW-oZaHdJ5vU6I_lrl4QssD1joOtlKCLNQ",
};

/// 攻击者的 key:从未出现在任何 owner 文档中。
pub const KX: TestKey = TestKey {
    name: "KX",
    pem: "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIEDODzblKEYoy89EBtZA40INlh6tToAQ6/3ifo46GpHL\n-----END PRIVATE KEY-----",
    x: "-uDpBVByjyv8pQ_d3IQC2_l8n6O7OljCp-NYMJazSx8",
};

// ---------- 身份 ----------

pub fn owner_did() -> DID {
    DID::new("bns", "alice")
}

pub fn zone_did() -> DID {
    DID::new("bns", "zone1.alice")
}

pub fn zone() -> DidDocType {
    DidDocType::Zone
}

pub fn owner_type() -> DidDocType {
    DidDocType::Owner
}

// ---------- 文档 ----------

/// 签发 compact JWT;payload 原样使用调用方给出的字节(键顺序 / 空白由调用方决定)。
pub fn sign_raw_jwt(payload: &str, key: &TestKey) -> EncodedDocument {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"EdDSA","typ":"JWT"}"#);
    let body = URL_SAFE_NO_PAD.encode(payload.as_bytes());
    let message = format!("{}.{}", header, body);
    let signature =
        jsonwebtoken::crypto::sign(message.as_bytes(), &key.encoding(), Algorithm::EdDSA).unwrap();
    EncodedDocument::Jwt(format!("{}.{}", message, signature))
}

/// owner 文档:`did:bns:alice`,公钥为 `key`,由 `key` 自签。
pub fn owner_doc(iat: u64, exp: u64, valid_iat: Option<u64>, key: &TestKey) -> EncodedDocument {
    let mut owner = OwnerDocument::new(owner_did(), "alice".into(), "alice@test".into(), key.jwk());
    owner.iat = iat;
    owner.exp = exp;
    owner.valid_iat = valid_iat;
    owner.encode(Some(&key.encoding())).unwrap()
}

/// zone 文档(JWT),声明 owner 为 `did:bns:alice`,由 `signer` 签名。
pub fn zone_jwt(iat: u64, exp: u64, marker: &str, signer: &TestKey) -> EncodedDocument {
    let mut doc = ZoneDocument::new(zone_did(), owner_did(), K1.jwk());
    doc.iat = iat;
    doc.exp = exp;
    doc.version_seq = Some(1);
    doc.extra_info.insert("marker".into(), json!(marker));
    doc.encode(Some(&signer.encoding())).unwrap()
}

/// 未签名 zone 文档(JSON)。
pub fn zone_json(iat: u64, exp: u64, marker: &str) -> EncodedDocument {
    let mut doc = ZoneDocument::new(zone_did(), owner_did(), K1.jwk());
    doc.iat = iat;
    doc.exp = exp;
    doc.extra_info.insert("marker".into(), json!(marker));
    EncodedDocument::JsonLd(serde_json::to_value(&doc).unwrap())
}

/// 不属于已知形态的通用文档(可用于任意 doc_type),JSON。
pub fn generic_json(did: &DID, iat: u64, exp: u64, marker: &str) -> EncodedDocument {
    EncodedDocument::JsonLd(json!({
        "id": did.to_string(),
        "owner": owner_did().to_string(),
        "iat": iat,
        "exp": exp,
        "marker": marker,
    }))
}

/// 通用文档的 JWT 形态,声明 owner 为 `did:bns:alice`。
pub fn generic_jwt(did: &DID, iat: u64, exp: u64, marker: &str, signer: &TestKey) -> EncodedDocument {
    let payload = json!({
        "id": did.to_string(),
        "owner": owner_did().to_string(),
        "iat": iat,
        "exp": exp,
        "marker": marker,
    });
    sign_raw_jwt(&payload.to_string(), signer)
}

pub fn rev(doc: &EncodedDocument) -> DocRevision {
    DocRevision::of(doc).unwrap()
}

pub fn marker(doc: &EncodedDocument) -> String {
    doc.clone()
        .to_json_value()
        .ok()
        .and_then(|v| v.get("marker").and_then(|m| m.as_str()).map(String::from))
        .unwrap_or_default()
}

// ---------- 回答构造 ----------

pub fn sref(id: &str, tier: SourceTier) -> SourceRef {
    SourceRef::provider(id, tier)
}

/// authority 对 current 的回答:body + 当前已发布记录。
pub fn current_info(did: &DID, doc_type: &DidDocType, latest: &EncodedDocument) -> PublishInfo {
    let r = rev(latest);
    let mut info = PublishInfo::new(did.clone(), doc_type.clone(), Revision::current())
        .with_status(&DocumentStatus::Active, None, None)
        .with_record(PublishRecord::published(r.iat, &r.hash, true));
    info.latest_iat = Some(r.iat);
    info
}

pub fn answer_with(body: Option<&EncodedDocument>, info: Option<PublishInfo>) -> SourceAnswer {
    let mut answer = SourceAnswer::new(sref("scripted", SourceTier::Normal));
    if let Some(body) = body {
        answer = answer.with_body(body.clone(), Carrier::Inline);
    }
    if let Some(info) = info {
        answer = answer.with_publish_info(info);
    }
    answer
}

pub fn body_only(body: &EncodedDocument) -> SourceAnswer {
    SourceAnswer::new(sref("scripted", SourceTier::Normal)).with_body(body.clone(), Carrier::Body)
}

pub fn no_answer(reason: &str) -> SourceAnswer {
    SourceAnswer::no_answer(sref("scripted", SourceTier::Normal), reason)
}

pub fn failure(reason: &str) -> SourceAnswer {
    SourceAnswer::failure(sref("scripted", SourceTier::Normal), reason)
}

// ---------- 闸门 ----------

/// 屏障:来源进入时登记 `entered`,等测试 `release` 后才回答;记录 Future 是否被 drop。
pub struct Gate {
    entered: Semaphore,
    release: Semaphore,
    entries: AtomicUsize,
    completed: AtomicUsize,
    dropped: AtomicUsize,
}

impl Gate {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            entered: Semaphore::new(0),
            release: Semaphore::new(0),
            entries: AtomicUsize::new(0),
            completed: AtomicUsize::new(0),
            dropped: AtomicUsize::new(0),
        })
    }

    /// 等待来源进入闸门(第 n 次进入各自消耗一次)。
    pub async fn wait_entered(&self) {
        tokio::time::timeout(Duration::from_secs(10), self.entered.acquire())
            .await
            .expect("source never entered the gate")
            .unwrap()
            .forget();
    }

    pub fn release(&self, n: usize) {
        self.release.add_permits(n);
    }

    pub fn entries(&self) -> usize {
        self.entries.load(Ordering::SeqCst)
    }

    pub fn completed(&self) -> usize {
        self.completed.load(Ordering::SeqCst)
    }

    /// 进入闸门后未完成就被 drop 的来源 Future 数。
    pub fn dropped(&self) -> usize {
        self.dropped.load(Ordering::SeqCst)
    }

    pub async fn pass(&self) {
        struct DropProbe<'a> {
            gate: &'a Gate,
            done: bool,
        }
        impl Drop for DropProbe<'_> {
            fn drop(&mut self) {
                if !self.done {
                    self.gate.dropped.fetch_add(1, Ordering::SeqCst);
                }
            }
        }
        self.entries.fetch_add(1, Ordering::SeqCst);
        self.entered.add_permits(1);
        let mut probe = DropProbe { gate: self, done: false };
        self.release.acquire().await.unwrap().forget();
        probe.done = true;
        self.completed.fetch_add(1, Ordering::SeqCst);
    }
}

// ---------- RequestTrace ----------

#[derive(Clone, Debug)]
pub struct Call {
    pub source: String,
    pub operation: Operation,
    pub did: DID,
    pub doc_type: DidDocType,
    pub revision: Revision,
    pub scope: Scope,
    pub policy: String,
    pub transport: String,
    pub deadline: Instant,
    pub depth: usize,
    pub force: bool,
}

/// 一步脚本回答。
#[derive(Clone)]
pub enum Step {
    Answer(SourceAnswer),
    /// 在闸门处停住,放行后回答。
    Gated(Arc<Gate>, SourceAnswer),
    /// Tokio 时钟上睡眠后回答(虚拟时钟下自动推进)。
    Sleep(Duration, SourceAnswer),
}

struct Rule {
    did: DID,
    doc_type: Option<DidDocType>,
    revision: Option<Revision>,
    steps: VecDeque<Step>,
}

/// authority 的模型回答:已发布版本、负状态、owner 绑定、是否支持历史查询。
#[derive(Default)]
pub struct AuthorityModel {
    pub versions: HashMap<(DID, String), Vec<EncodedDocument>>,
    pub negatives: HashMap<(DID, String), (DocumentStatus, Option<String>)>,
    pub bindings: HashMap<DID, DID>,
    pub no_history: bool,
}

/// trust / normal 的模型回答:固定文档,多份时回答最高 iat 的一份。
#[derive(Default)]
pub struct DocsModel {
    pub docs: HashMap<(DID, String), Vec<EncodedDocument>>,
}

/// 按 `(DID, doc_type, revision)` 配置回答队列的来源;记录每次调用。规则优先,其次
/// 模型;两者都没有的调用记为"未预期"并使 [`Fx::finish`] 失败。
pub struct ScriptedSource {
    pub id: String,
    supports_history: AtomicBool,
    rules: Mutex<Vec<Rule>>,
    calls: Mutex<Vec<Call>>,
    unexpected: Mutex<Vec<Call>>,
    authority: Mutex<Option<AuthorityModel>>,
    docs: Mutex<Option<DocsModel>>,
    default_type: Mutex<Option<DefaultDocType>>,
}

impl ScriptedSource {
    pub fn new(id: &str) -> Arc<Self> {
        Arc::new(Self {
            id: id.to_string(),
            supports_history: AtomicBool::new(true),
            rules: Mutex::new(Vec::new()),
            calls: Mutex::new(Vec::new()),
            unexpected: Mutex::new(Vec::new()),
            authority: Mutex::new(None),
            docs: Mutex::new(None),
            default_type: Mutex::new(None),
        })
    }

    pub fn authority_model(id: &str) -> Arc<Self> {
        let source = Self::new(id);
        *source.authority.lock().unwrap() = Some(AuthorityModel::default());
        source
    }

    /// 静态发布面:不支持版本 / closest 查询。
    pub fn docs_model(id: &str) -> Arc<Self> {
        let source = Self::new(id);
        source.set_supports_history(false);
        *source.docs.lock().unwrap() = Some(DocsModel::default());
        source
    }

    pub fn set_supports_history(&self, supported: bool) {
        self.supports_history.store(supported, Ordering::SeqCst);
    }

    pub fn set_default_type(&self, answer: Option<DefaultDocType>) {
        *self.default_type.lock().unwrap() = answer;
    }

    // ----- 模型 -----

    pub fn publish(&self, did: &DID, doc_type: &DidDocType, doc: &EncodedDocument) {
        let mut model = self.authority.lock().unwrap();
        model
            .as_mut()
            .expect("not an authority model")
            .versions
            .entry((did.clone(), doc_type.to_string()))
            .or_default()
            .push(doc.clone());
    }

    pub fn set_negative(&self, did: &DID, doc_type: &DidDocType, status: DocumentStatus, reason: Option<&str>) {
        self.authority
            .lock()
            .unwrap()
            .as_mut()
            .expect("not an authority model")
            .negatives
            .insert((did.clone(), doc_type.to_string()), (status, reason.map(String::from)));
    }

    pub fn clear_negative(&self, did: &DID, doc_type: &DidDocType) {
        self.authority
            .lock()
            .unwrap()
            .as_mut()
            .expect("not an authority model")
            .negatives
            .remove(&(did.clone(), doc_type.to_string()));
    }

    pub fn bind_owner(&self, did: &DID, owner: &DID) {
        self.authority
            .lock()
            .unwrap()
            .as_mut()
            .expect("not an authority model")
            .bindings
            .insert(did.clone(), owner.clone());
    }

    pub fn add(&self, did: &DID, doc_type: &DidDocType, doc: &EncodedDocument) {
        self.docs
            .lock()
            .unwrap()
            .as_mut()
            .expect("not a docs model")
            .docs
            .entry((did.clone(), doc_type.to_string()))
            .or_default()
            .push(doc.clone());
    }

    pub fn clear_docs(&self) {
        if let Some(model) = self.docs.lock().unwrap().as_mut() {
            model.docs.clear();
        }
    }

    // ----- 脚本 -----

    /// 为 `(did, doc_type, revision)` 追加回答;队列只剩最后一步时重复使用它。
    /// `doc_type` / `revision` 为 None 表示通配。
    pub fn script(&self, did: &DID, doc_type: Option<&DidDocType>, revision: Option<&Revision>, steps: Vec<Step>) {
        self.rules.lock().unwrap().push(Rule {
            did: did.clone(),
            doc_type: doc_type.cloned(),
            revision: revision.cloned(),
            steps: steps.into(),
        });
    }

    pub fn clear_scripts(&self) {
        self.rules.lock().unwrap().clear();
    }

    // ----- 观察 -----

    pub fn calls(&self) -> Vec<Call> {
        self.calls.lock().unwrap().clone()
    }

    pub fn call_count(&self) -> usize {
        self.calls.lock().unwrap().len()
    }

    pub fn calls_for(&self, did: &DID, revision: &Revision) -> usize {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .filter(|c| c.did == *did && c.revision == *revision)
            .count()
    }

    pub fn history_calls_for(&self, did: &DID) -> usize {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .filter(|c| c.did == *did && !c.revision.is_current())
            .count()
    }

    pub fn unexpected(&self) -> Vec<Call> {
        self.unexpected.lock().unwrap().clone()
    }

    pub fn reset_calls(&self) {
        self.calls.lock().unwrap().clear();
    }

    fn take_step(&self, call: &Call) -> Option<Step> {
        let mut rules = self.rules.lock().unwrap();
        // 后添加的规则优先(便于在同一夹具里改写回答)。
        for rule in rules.iter_mut().rev() {
            if rule.did != call.did
                || rule.doc_type.as_ref().map_or(false, |t| *t != call.doc_type)
                || rule.revision.as_ref().map_or(false, |r| *r != call.revision)
            {
                continue;
            }
            if rule.steps.len() > 1 {
                return rule.steps.pop_front();
            }
            return rule.steps.front().cloned();
        }
        None
    }

    fn model_answer(&self, call: &Call) -> Option<SourceAnswer> {
        if let Some(model) = self.authority.lock().unwrap().as_ref() {
            return Some(authority_model_answer(model, call, self.supports_history.load(Ordering::SeqCst)));
        }
        if let Some(model) = self.docs.lock().unwrap().as_ref() {
            return Some(match model.docs.get(&(call.did.clone(), call.doc_type.to_string())) {
                Some(list) if !list.is_empty() => {
                    body_only(list.iter().max_by_key(|d| rev(d).iat).unwrap())
                }
                _ => no_answer("not here"),
            });
        }
        None
    }

    async fn answer(
        &self,
        operation: Operation,
        did: &DID,
        doc_type: &DidDocType,
        revision: &Revision,
        opts: &ResolveOpts,
    ) -> SourceAnswer {
        let call = Call {
            source: self.id.clone(),
            operation,
            did: did.clone(),
            doc_type: doc_type.clone(),
            revision: revision.clone(),
            scope: opts.scope.clone(),
            policy: opts.access_policy_key(),
            transport: opts.transport_policy.key(),
            deadline: opts.budget().deadline(),
            depth: opts.depth(),
            force: opts.force_authority_query,
        };
        self.calls.lock().unwrap().push(call.clone());
        let step = match self.take_step(&call) {
            Some(step) => step,
            None => match self.model_answer(&call) {
                Some(answer) => Step::Answer(answer),
                None => {
                    self.unexpected.lock().unwrap().push(call.clone());
                    return SourceAnswer::unknown(sref(&self.id, SourceTier::Normal), "unexpected call", false);
                }
            },
        };
        match step {
            Step::Answer(answer) => answer,
            Step::Gated(gate, answer) => {
                gate.pass().await;
                answer
            }
            Step::Sleep(delay, answer) => {
                tokio::time::sleep(delay).await;
                answer
            }
        }
    }
}

fn authority_model_answer(model: &AuthorityModel, call: &Call, supports_history: bool) -> SourceAnswer {
    let did = &call.did;
    let doc_type = &call.doc_type;
    let revision = &call.revision;
    let key = (did.clone(), doc_type.to_string());
    let mut info = PublishInfo::new(did.clone(), doc_type.clone(), revision.clone());
    info.owner_binding = model.bindings.get(did).cloned();
    if let Some((status, reason)) = model.negatives.get(&key) {
        info = info.with_status(status, reason.clone(), None);
        return answer_with(None, Some(info));
    }
    let mut versions: Vec<(DocRevision, EncodedDocument)> = model
        .versions
        .get(&key)
        .map(|docs| docs.iter().map(|d| (rev(d), d.clone())).collect())
        .unwrap_or_default();
    versions.sort_by_key(|(r, _)| r.iat);
    let Some((latest_rev, latest_doc)) = versions.last().cloned() else {
        info = info.with_status(&DocumentStatus::Missing, None, None);
        return answer_with(None, Some(info));
    };
    info = info.with_status(&DocumentStatus::Active, None, None);
    info.latest_iat = Some(latest_rev.iat);
    if !revision.is_current() && (!supports_history || model.no_history) {
        let mut answer = SourceAnswer::unknown(sref("scripted", SourceTier::Authority), "501 historicalQuerySupported=false", false);
        answer.unsupported_history = true;
        return answer;
    }
    match revision {
        Revision::Current => {
            info = info.with_record(PublishRecord::published(latest_rev.iat, &latest_rev.hash, true));
            answer_with(Some(&latest_doc), Some(info))
        }
        Revision::Exact { iat, .. } => match versions.iter().find(|(r, _)| r.iat == *iat) {
            Some((r, doc)) => {
                info = info.with_record(PublishRecord::published(r.iat, &r.hash, r.iat == latest_rev.iat));
                answer_with(Some(doc), Some(info))
            }
            None => {
                info.records.push(PublishRecord::not_published(*iat));
                answer_with(None, Some(info))
            }
        },
        Revision::Closest { before_iat } => {
            let selected = versions.iter().filter(|(r, _)| r.iat < *before_iat).last().cloned();
            match selected {
                Some((r, doc)) => {
                    info = info.with_record(PublishRecord::published(r.iat, &r.hash, r.iat == latest_rev.iat));
                    info.boundary = Some(Boundary {
                        query_iat: *before_iat,
                        selected: Some(r.clone()),
                        confirmed: true,
                    });
                    answer_with(Some(&doc), Some(info))
                }
                None => {
                    info.boundary = Some(Boundary {
                        query_iat: *before_iat,
                        selected: None,
                        confirmed: true,
                    });
                    answer_with(None, Some(info))
                }
            }
        }
    }
}

#[async_trait]
impl Source for ScriptedSource {
    fn id(&self) -> String {
        self.id.clone()
    }

    fn supports_publish_info(&self) -> bool {
        self.supports_history.load(Ordering::SeqCst)
    }

    async fn get_document(
        &self,
        did: &DID,
        doc_type: &DidDocType,
        revision: &Revision,
        opts: &ResolveOpts,
    ) -> SourceAnswer {
        self.answer(Operation::Document, did, doc_type, revision, opts).await
    }

    async fn get_publish_info(
        &self,
        did: &DID,
        doc_type: &DidDocType,
        revision: &Revision,
        opts: &ResolveOpts,
    ) -> SourceAnswer {
        self.answer(Operation::PublishInfo, did, doc_type, revision, opts).await
    }

    async fn default_doc_type(&self, did: &DID, _opts: &ResolveOpts) -> Option<DefaultDocType> {
        if did.id.contains(':') {
            return Some(DefaultDocType::Known {
                doc_type: DidDocType::DidObject,
                reasons: Vec::new(),
            });
        }
        self.default_type.lock().unwrap().clone()
    }
}

// ---------- 夹具 ----------

pub struct Fx {
    pub client: NameClient,
    pub authority: Arc<ScriptedSource>,
    pub trust: Arc<ScriptedSource>,
    pub normal: Arc<ScriptedSource>,
    pub base: u64,
    _clock: test_clock::Frozen,
}

pub struct FxConfig {
    pub resolve_timeout: Duration,
    pub request_timeout: Duration,
    pub supplement_grace: Duration,
    pub persistent_dir: Option<std::path::PathBuf>,
    pub concurrency: ConcurrencyConfig,
}

impl Default for FxConfig {
    fn default() -> Self {
        Self {
            resolve_timeout: Duration::from_secs(10),
            request_timeout: Duration::from_secs(2),
            supplement_grace: Duration::from_secs(1),
            persistent_dir: None,
            concurrency: ConcurrencyConfig::default(),
        }
    }
}

/// 设计稿默认墙钟。
pub const NOW: u64 = 10_000;
/// 普通子文档默认 exp。
pub const EXP: u64 = 20_000;

pub fn real_base() -> u64 {
    buckyos_kit::buckyos_get_unix_timestamp() - NOW
}

pub fn client_with(config: &FxConfig) -> NameClient {
    let mut cfg = NameClientConfig {
        resolve_timeout: config.resolve_timeout,
        request_timeout: config.request_timeout,
        supplement_grace: config.supplement_grace,
        concurrency: config.concurrency.clone(),
        ..NameClientConfig::for_test()
    };
    if let Some(dir) = config.persistent_dir.as_ref() {
        cfg.cache_backend = CacheBackend::Filesystem;
        cfg.local_cache_dir = Some(dir.to_string_lossy().to_string());
    }
    NameClient::new(cfg)
}

impl Fx {
    pub fn new() -> Self {
        Self::with_config(FxConfig::default())
    }

    pub fn with_config(config: FxConfig) -> Self {
        let base = real_base();
        Self::with_base(config, base)
    }

    pub fn with_base(config: FxConfig, base: u64) -> Self {
        let clock = test_clock::Frozen::at(base + NOW);
        let client = client_with(&config);
        let authority = ScriptedSource::authority_model("authority");
        let trust = ScriptedSource::docs_model("trust-site");
        let normal = ScriptedSource::docs_model("normal-site");
        client.set_method_authority("bns", authority.clone());
        client.add_method_trust("bns", trust.clone());
        client.add_method_normal("bns", normal.clone());
        Self {
            client,
            authority,
            trust,
            normal,
            base,
            _clock: clock,
        }
    }

    /// 设计稿时刻 → 夹具绝对时刻。
    pub fn at(&self, t: u64) -> u64 {
        self.base + t
    }

    pub fn set_now(&self, t: u64) {
        test_clock::set(self.base + t);
    }

    pub fn opts(&self) -> ResolveOpts {
        self.client.default_resolve_opts()
    }

    /// 默认 owner:iat=50,K1,不过期。
    pub fn publish_default_owner(&self) -> EncodedDocument {
        let owner = owner_doc(self.at(50), self.at(EXP * 10), None, &K1);
        self.authority.publish(&owner_did(), &owner_type(), &owner);
        owner
    }

    pub fn zone_jwt(&self, iat: u64, marker: &str, signer: &TestKey) -> EncodedDocument {
        zone_jwt(self.at(iat), self.at(EXP), marker, signer)
    }

    pub fn zone_json(&self, iat: u64, marker: &str) -> EncodedDocument {
        zone_json(self.at(iat), self.at(EXP), marker)
    }

    pub async fn resolve(&self, revision: Revision, opts: ResolveOpts) -> DocResult {
        self.client
            .resolve_did_ex(&zone_did(), Some(zone()), revision, opts)
            .await
            .unwrap()
    }

    pub async fn resolve_owner(&self, revision: Revision, opts: ResolveOpts) -> DocResult {
        self.client
            .resolve_did_ex(&owner_did(), Some(owner_type()), revision, opts)
            .await
            .unwrap()
    }

    pub async fn verify(&self, doc: &EncodedDocument, revision: Revision, opts: ResolveOpts) -> VerifyResult {
        self.client
            .verify_document(&zone_did(), Some(zone()), doc, revision, opts)
            .await
            .unwrap()
    }

    /// 存储中的结果(不经过解析主路径)。
    pub fn stored(&self, did: &DID, doc_type: &DidDocType) -> Option<DocResult> {
        let use_disk = self.client.store.is_persistent();
        self.client.store.get_doc_result(&Scope::Host, did, doc_type, use_disk)
    }

    /// 推进墙钟越过普通查询回答缓存(预热时缓存的 NoAnswer 不再遮住新回答)。
    pub fn expire_query_cache(&self, from: u64) {
        self.set_now(from + PUBLISH_QUERY_TTL_SECS + 1);
    }

    /// 断言没有未预期的来源调用。
    pub fn finish(&self) {
        for source in [&self.authority, &self.trust, &self.normal] {
            let unexpected = source.unexpected();
            assert!(unexpected.is_empty(), "unexpected calls to {}: {:#?}", source.id, unexpected);
        }
    }
}

// ---------- 报告断言 ----------

pub fn assert_no_selection(report: &VerifyResult) {
    assert!(
        !report.is_best && !report.is_latest && !report.is_exact && !report.is_closest,
        "selection flags must be cleared on {:?}: {:?}",
        report.validity,
        report
    );
}

pub fn json_value(doc: &EncodedDocument) -> Value {
    doc.clone().to_json_value().unwrap()
}

// ---------- 本地 HTTP(Zone locker / provider 组件替身) ----------

/// 极简 HTTP/1.1 服务:每个连接读一个请求头,按 `respond` 回答并记录请求原文。
pub struct LocalHttp {
    pub addr: std::net::SocketAddr,
    requests: Arc<Mutex<Vec<String>>>,
    task: tokio::task::JoinHandle<()>,
}

impl LocalHttp {
    pub async fn start(respond: impl Fn(&str) -> (u16, String) + Send + Sync + 'static) -> Self {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let recorded = requests.clone();
        let respond = Arc::new(respond);
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let recorded = recorded.clone();
                let respond = respond.clone();
                tokio::spawn(async move {
                    let mut input = Vec::new();
                    let mut buf = [0u8; 1024];
                    while !input.windows(4).any(|w| w == b"\r\n\r\n") {
                        match stream.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => input.extend_from_slice(&buf[..n]),
                        }
                    }
                    let request = String::from_utf8_lossy(&input).to_string();
                    recorded.lock().unwrap().push(request.clone());
                    let (status, body) = respond(&request);
                    let wire = format!(
                        "HTTP/1.1 {} Test\r\nContent-Type: application/did-resolution\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        status,
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(wire.as_bytes()).await;
                });
            }
        });
        Self { addr, requests, task }
    }

    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    pub fn requests(&self) -> Vec<String> {
        self.requests.lock().unwrap().clone()
    }
}

impl Drop for LocalHttp {
    fn drop(&mut self) {
        self.task.abort();
    }
}
