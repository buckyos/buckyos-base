use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;
use std::time::UNIX_EPOCH;

use buckyos_kit::{
    buckyos_get_unix_timestamp, get_buckyos_service_local_data_dir, get_buckyos_system_etc_dir,
};
use log::{debug, error, info, warn};
use name_lib::{DIDDocumentTrait, EncodedDocument, OwnerDocument, DID};
use serde::{Deserialize, Serialize};

use crate::{document_content_hash, document_iat, BodyEvidence, DidDocType, DocumentStatus};

/// 负状态条目的重查间隔:in-TTL 内快路径直接报错;过期后允许重新询问权威源
/// (只有权威源的新回答能翻篇),但在权威源没回答时它仍然屏蔽一切兜底。
const NEGATIVE_STATE_TTL_SECS: u64 = 3600;

/// 本机 DID 文档缓存的存储后端。SQL 后端已删除(doc/update-did-cache.md 目标 1):
/// 真正需要结构化查询能力的场景走 zone-did-resolve,本机 `did_cache` 只保留
/// Filesystem(生产默认)与 Memory(测试默认)。
#[derive(Clone, Copy, Debug)]
pub enum CacheBackend {
    Filesystem,
    Memory,
}

/// 缓存条目的证据等级(简化文档第 5 节):已发布/已锚定 > 已验证的自签名 > 未验证。
/// 持久化存储,不再用 trust_level 近似。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CacheEvidence {
    /// 已发布/已锚定:来自权威信道(或其锚定的已发布集合)。
    Published,
    /// 通过了含 expected_owner 一致性在内的完整 verify 的自签名候选。
    Verified,
    /// 未经验证的旁路写入(add_observed_cache / 文件系统协议)。
    Unverified,
}

impl CacheEvidence {
    fn rank(&self) -> u8 {
        match self {
            CacheEvidence::Published => 3,
            CacheEvidence::Verified => 2,
            CacheEvidence::Unverified => 1,
        }
    }

    pub fn to_body_evidence(&self) -> BodyEvidence {
        match self {
            CacheEvidence::Published => BodyEvidence::Anchored,
            CacheEvidence::Verified => BodyEvidence::NeedProof,
            CacheEvidence::Unverified => BodyEvidence::NeedProof,
        }
    }

    pub fn from_body_evidence(evidence: BodyEvidence) -> Self {
        match evidence {
            BodyEvidence::Anchored => CacheEvidence::Published,
            BodyEvidence::NeedProof => CacheEvidence::Verified,
            BodyEvidence::UnproofInfo => CacheEvidence::Unverified,
        }
    }
}

/// 目录即证据(doc/update-did-cache.md):`unverified/` 是任何本机进程都可写的
/// Observed 命名空间,`verified/` 只有 name-client 受控写入。落在 `unverified/`
/// 的条目不论 meta 自称什么证据等级,读出时一律钳制为 `Unverified`;`verified/`
/// 的 meta 才被信任(写权限已经先做了一次身份过滤)。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CacheNamespace {
    Unverified,
    Verified,
}

impl CacheNamespace {
    fn dir_name(&self) -> &'static str {
        match self {
            CacheNamespace::Unverified => "unverified",
            CacheNamespace::Verified => "verified",
        }
    }
}

fn namespace_for_evidence(evidence: CacheEvidence) -> CacheNamespace {
    match evidence {
        CacheEvidence::Unverified => CacheNamespace::Unverified,
        _ => CacheNamespace::Verified,
    }
}

fn default_cache_evidence() -> CacheEvidence {
    // 旧版缓存条目没有证据字段:它们都是老验证路径写入的结果,按已发布档对待,
    // 保持与旧行为最接近的合并偏好(只对 verified/ 命名空间生效)。
    CacheEvidence::Published
}

/// 统一的持久化条目:正条目(带 doc)或负条目(带 negative_status)。
/// 字段全部带 serde default,旧版 meta 文件可以直接读出;未知字段被忽略,
/// 因此外部写入方 meta 里的 `hint_doc_type` 等诊断字段不会破坏解析。
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct StoredMeta {
    #[serde(default = "default_cache_evidence")]
    evidence: CacheEvidence,
    #[serde(default)]
    negative_status: Option<String>,
    #[serde(default)]
    negative_message: Option<String>,
    #[serde(default)]
    exp: Option<u64>,
    #[serde(default)]
    update_from_remote_time: Option<u64>,
    /// Observed 事件的观察来源(doc/update-did-cache.md)。仅诊断用,
    /// 绝不参与信任判定。promote 时原样保留。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    source: Option<String>,
    /// 写入方本地时间戳,仅诊断/排障用。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    observed_at: Option<u64>,
}

impl Default for CacheEvidence {
    fn default() -> Self {
        default_cache_evidence()
    }
}

#[derive(Clone, Debug)]
struct StoredEntry {
    doc: Option<EncodedDocument>,
    meta: StoredMeta,
}

impl StoredEntry {
    fn is_negative(&self) -> bool {
        self.meta.negative_status.is_some()
    }

    fn exp(&self) -> u64 {
        self.meta.exp.unwrap_or(0)
    }
}

/// cache 写入的结构化结果(doc/verify-did-api-boundary-and-freshness-TODO.md
/// Phase 4):写入不能只有 `Ok(())`,调用方必须能区分插入、替换、重复、被更新
/// 内容压制、同 revision 冲突与负状态屏蔽。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CacheWriteOutcome {
    /// 该 key 原本没有条目,已写入。
    Inserted,
    /// 已替换一条更旧(iat 更小)或证据等级更低的条目。
    ReplacedOlder,
    /// 同 iat 同 content hash:同一份编码文档已存在,无需写入。
    AlreadyPresent,
    /// 现有条目更新(iat 更大)或证据等级更高,本次写入被忽略。
    IgnoredOlder,
    /// 同 iat 不同 content hash(同 revision 冲突),或命名对象
    /// (`is_named_obj_id`)的不可替换保护:拒绝写入,不悄悄选一个。
    RejectedConflict,
    /// 该 key 存在负状态记忆(权威源的"回答"),屏蔽本次写入;只有权威源的
    /// 新已发布回答(Published 证据)能翻篇。
    BlockedByNegativeState,
    /// 目标命名空间不可写(文件系统权限/IO 失败)。verified/ 的信任边界正是
    /// 目录写权限,此结果表示调用进程不具备该身份。
    PermissionDenied,
    /// 按既有策略跳过写入(如 detached-owner 的 ObjectDocument 结果:现有
    /// cache 条目无法记录 purpose,固定不落普通 cache)。
    SkippedByPolicy,
}

impl CacheWriteOutcome {
    /// 本次调用后,这份内容是否已存在于目标命名空间(新写入或本就相同)。
    pub fn stored(&self) -> bool {
        matches!(
            self,
            CacheWriteOutcome::Inserted
                | CacheWriteOutcome::ReplacedOlder
                | CacheWriteOutcome::AlreadyPresent
        )
    }
}

/// 统一层的查询结果。负状态"命中"不受 TTL 约束地存在:in_ttl 只影响快路径,
/// 过期的负状态仍然屏蔽兜底,只能被权威源的新回答翻篇。
#[derive(Clone, Debug)]
pub enum CacheLookup {
    Positive {
        doc: EncodedDocument,
        exp: u64,
        evidence: CacheEvidence,
        in_ttl: bool,
        /// Observed 条目的观察来源(仅诊断);verified 命中通常为 None。
        source: Option<String>,
    },
    Negative {
        status: String,
        message: String,
        in_ttl: bool,
    },
}

impl CacheLookup {
    pub fn is_negative(&self) -> bool {
        matches!(self, CacheLookup::Negative { .. })
    }
}

pub struct DIDDocumentCache {
    backend: Backend,
}

enum Backend {
    Fs(FsStore),
    Mem(MemStore),
}

impl DIDDocumentCache {
    /// 默认文件缓存(保持兼容)。
    pub fn new(cache_dir: Option<PathBuf>) -> Self {
        Self {
            backend: Backend::Fs(FsStore::new(cache_dir)),
        }
    }

    /// 显式创建 Memory 缓存(测试用)。进程内用两个命名空间模拟
    /// `unverified/`/`verified/` 目录,行为满足"目录即证据"语义。
    pub fn new_mem() -> Self {
        Self {
            backend: Backend::Mem(MemStore::new()),
        }
    }

    pub fn get_default_cache_dir() -> PathBuf {
        get_buckyos_service_local_data_dir("did_docs")
    }

    pub fn with_default_dir() -> Self {
        Self::new(Some(Self::default_dir()))
    }

    pub fn default_dir() -> PathBuf {
        get_buckyos_system_etc_dir().join("did_docs")
    }

    // ---- 后端 KV 转发(命名空间感知) ----

    fn load_ns(&self, ns: CacheNamespace, key: &str) -> Option<StoredEntry> {
        let mut entry = match &self.backend {
            Backend::Fs(store) => store.load(ns, key),
            Backend::Mem(store) => store.load(ns, key),
        }?;
        if ns == CacheNamespace::Unverified {
            // 目录即证据:unverified/ 里内容自称的证据等级不被信任;
            // 自称的负状态更不被信任(否则任何人放一个 meta 文件就能屏蔽解析)。
            if entry.is_negative() || entry.doc.is_none() {
                return None;
            }
            entry.meta.evidence = CacheEvidence::Unverified;
        }
        Some(entry)
    }

    /// 联合视图:`verified/` 永远优先命中(不论 TTL);没有 verified 条目时才
    /// 露出 unverified 的 Observed 候选。
    fn load_union(&self, key: &str) -> Option<StoredEntry> {
        self.load_ns(CacheNamespace::Verified, key)
            .or_else(|| self.load_ns(CacheNamespace::Unverified, key))
    }

    fn store(&self, key: &str, entry: &StoredEntry) -> bool {
        let ns = if entry.is_negative() {
            CacheNamespace::Verified
        } else {
            namespace_for_evidence(entry.meta.evidence)
        };
        match &self.backend {
            Backend::Fs(store) => store.store(ns, key, entry),
            Backend::Mem(store) => store.store(ns, key, entry),
        }
    }

    fn remove_ns(&self, ns: CacheNamespace, key: &str) {
        match &self.backend {
            Backend::Fs(store) => store.remove(ns, key),
            Backend::Mem(store) => store.remove(ns, key),
        }
    }

    fn remove(&self, key: &str) {
        self.remove_ns(CacheNamespace::Verified, key);
        self.remove_ns(CacheNamespace::Unverified, key);
    }

    fn keys_for_did(&self, did: &DID) -> Vec<String> {
        let did_key = did_cache_key(did);
        let mut keys = match &self.backend {
            Backend::Fs(store) => store.keys_with_prefix(CacheNamespace::Verified, &did_key),
            Backend::Mem(store) => store.keys_with_prefix(CacheNamespace::Verified, &did_key),
        };
        let observed = match &self.backend {
            Backend::Fs(store) => store.keys_with_prefix(CacheNamespace::Unverified, &did_key),
            Backend::Mem(store) => store.keys_with_prefix(CacheNamespace::Unverified, &did_key),
        };
        for key in observed {
            if !keys.contains(&key) {
                keys.push(key);
            }
        }
        keys
    }

    // ---- 统一层逻辑 ----

    /// 查询条目(不做任何删除;过期条目保留给策略点④的 stale 兜底判断)。
    pub fn lookup(&self, did: &DID, doc_type: Option<DidDocType>) -> Option<CacheLookup> {
        let key = combine_key(did, doc_type.as_ref());
        let entry = self.load_union(&key)?;
        let in_ttl = !is_expired(entry.exp());
        if entry.is_negative() {
            let status = entry.meta.negative_status.clone().unwrap_or_default();
            let message = entry.meta.negative_message.clone().unwrap_or_else(|| {
                format!(
                    "{}#{} is {}",
                    did.to_string(),
                    doc_type_str(doc_type.as_ref()),
                    status
                )
            });
            return Some(CacheLookup::Negative {
                status,
                message,
                in_ttl,
            });
        }
        let exp = entry.exp();
        let evidence = entry.meta.evidence;
        let source = entry.meta.source.clone();
        let doc = entry.doc?;
        Some(CacheLookup::Positive {
            doc,
            exp,
            evidence,
            in_ttl,
            source,
        })
    }

    /// 兼容读取:只返回正条目 (doc, exp, evidence_rank)。
    pub fn get(
        &self,
        did: &DID,
        doc_type: Option<DidDocType>,
    ) -> Option<(EncodedDocument, u64, i32)> {
        match self.lookup(did, doc_type)? {
            CacheLookup::Positive {
                doc, exp, evidence, ..
            } => Some((doc, exp, evidence.rank() as i32)),
            CacheLookup::Negative { .. } => None,
        }
    }

    /// 合并写入(简化文档第 5 节的 did_cache_update):
    /// 负状态与本地覆盖屏蔽一切合并写入(本地覆盖根本不进这里);
    /// 先比证据等级,同级只比 revision(iat + content hash,version_seq 已退出流程)。
    ///
    /// `Unverified` 证据的写入走 Observed 旁路语义(doc/update-did-cache.md):
    /// 落 `unverified/` 命名空间,永远压不过 `verified/` 里的条目。
    pub fn update(
        &self,
        did: DID,
        doc_type: Option<DidDocType>,
        doc: EncodedDocument,
        exp: u64,
        evidence: CacheEvidence,
    ) -> CacheWriteOutcome {
        if evidence == CacheEvidence::Unverified {
            return self.update_observed(did, doc_type, doc, exp, None);
        }

        if self
            .validate_owner_revocation(&did, doc_type.clone(), &doc)
            .is_err()
        {
            return CacheWriteOutcome::RejectedConflict;
        }

        let key = combine_key(&did, doc_type.as_ref());
        let verdict = match self.load_union(&key) {
            Some(current) => merge_verdict(&did, doc_type.as_ref(), &current, &doc, evidence),
            None => CacheWriteOutcome::Inserted,
        };
        if !matches!(
            verdict,
            CacheWriteOutcome::Inserted | CacheWriteOutcome::ReplacedOlder
        ) {
            return verdict;
        }
        if !self.write_positive(&did, &key, doc_type.as_ref(), doc, exp, evidence) {
            return CacheWriteOutcome::PermissionDenied;
        }
        verdict
    }

    /// Observed 旁路写入(doc/update-did-cache.md):产物固定落 `unverified/`
    /// 命名空间、证据恒为 `Unverified`,`source` 只做诊断记录。
    ///
    /// 返回的 outcome 描述 Observed 命名空间内部的合并结果;`verified/` 已有同
    /// key 条目时观察仍会被记录(查询永远优先命中 verified/,读侧自然遮蔽)。
    /// 负状态屏蔽一切写入——此时连 unverified 文件都不产生
    /// (`BlockedByNegativeState`)。
    pub fn update_observed(
        &self,
        did: DID,
        doc_type: Option<DidDocType>,
        doc: EncodedDocument,
        exp: u64,
        source: Option<String>,
    ) -> CacheWriteOutcome {
        if self
            .validate_owner_revocation(&did, doc_type.clone(), &doc)
            .is_err()
        {
            return CacheWriteOutcome::RejectedConflict;
        }

        let key = combine_key(&did, doc_type.as_ref());
        if let Some(current) = self.load_ns(CacheNamespace::Verified, &key) {
            if current.is_negative() {
                // 负状态是"回答",Observed 事件翻不了篇,也不值得记录。
                return CacheWriteOutcome::BlockedByNegativeState;
            }
        }

        // Observed 命名空间内部仍按同级 merge 规则去重(iat + content hash)。
        let verdict = match self.load_ns(CacheNamespace::Unverified, &key) {
            Some(current) => merge_verdict(
                &did,
                doc_type.as_ref(),
                &current,
                &doc,
                CacheEvidence::Unverified,
            ),
            None => CacheWriteOutcome::Inserted,
        };
        if !matches!(
            verdict,
            CacheWriteOutcome::Inserted | CacheWriteOutcome::ReplacedOlder
        ) {
            return verdict;
        }

        let entry = StoredEntry {
            doc: Some(doc),
            meta: StoredMeta {
                evidence: CacheEvidence::Unverified,
                negative_status: None,
                negative_message: None,
                exp: Some(exp),
                update_from_remote_time: Some(buckyos_get_unix_timestamp()),
                source,
                observed_at: Some(buckyos_get_unix_timestamp()),
            },
        };
        if !self.store(&key, &entry) {
            return CacheWriteOutcome::PermissionDenied;
        }
        verdict
    }

    /// 无条件写入(种子/测试/本地运维用):跳过合并比较,但 owner replay guard
    /// 与吊销联动清理仍然生效。命名空间由证据等级决定(目录即证据)。
    pub fn insert(
        &self,
        did: DID,
        doc_type: Option<DidDocType>,
        doc: EncodedDocument,
        exp: u64,
        evidence: CacheEvidence,
    ) {
        if self
            .validate_owner_revocation(&did, doc_type.clone(), &doc)
            .is_err()
        {
            return;
        }
        let key = combine_key(&did, doc_type.as_ref());
        self.write_positive(&did, &key, doc_type.as_ref(), doc, exp, evidence);
    }

    fn write_positive(
        &self,
        did: &DID,
        key: &str,
        doc_type: Option<&DidDocType>,
        doc: EncodedDocument,
        exp: u64,
        evidence: CacheEvidence,
    ) -> bool {
        let owner_document = if evidence == CacheEvidence::Unverified {
            // 未验证的 owner 文档没有资格触发吊销联动清理:否则任何人喊一声
            // add_observed_cache 就能用伪造 owner 文档驱逐已验证条目。
            None
        } else {
            parse_owner_document_doc(doc_type, &doc)
        };
        let entry = StoredEntry {
            doc: Some(doc),
            meta: StoredMeta {
                evidence,
                negative_status: None,
                negative_message: None,
                exp: Some(exp),
                update_from_remote_time: Some(buckyos_get_unix_timestamp()),
                source: None,
                observed_at: None,
            },
        };
        if !self.store(key, &entry) {
            return false;
        }

        // 新 owner 文档落地时,联动清理被它的 replay guard 判定吊销的旧文档。
        if let Some(owner_document) = owner_document {
            self.evict_revoked_docs(did, doc_type, &owner_document);
        }
        true
    }

    /// `verified/` 命名空间的受信条目读取(snapshot 构建用):只返回正条目,
    /// 证据必为 Published/Verified。Observed/Unverified 条目**不会**从这里露出
    /// ——它们没有资格作为 owner 验签依据,也不能推进 latest-known baseline。
    pub(crate) fn verified_entry(
        &self,
        did: &DID,
        doc_type: Option<DidDocType>,
    ) -> Option<(EncodedDocument, u64, CacheEvidence)> {
        let key = combine_key(did, doc_type.as_ref());
        let entry = self.load_ns(CacheNamespace::Verified, &key)?;
        if entry.is_negative() {
            return None;
        }
        let exp = entry.exp();
        let evidence = entry.meta.evidence;
        entry.doc.map(|doc| (doc, exp, evidence))
    }

    /// `verified/` 命名空间记忆的负状态(snapshot 构建用)。
    /// 现状负缓存只记录 terminal 状态(Revoked/Tombstoned)。
    pub(crate) fn negative_memory(
        &self,
        did: &DID,
        doc_type: Option<DidDocType>,
    ) -> Option<(String, String)> {
        let key = combine_key(did, doc_type.as_ref());
        let entry = self.load_ns(CacheNamespace::Verified, &key)?;
        if !entry.is_negative() {
            return None;
        }
        let status = entry.meta.negative_status.clone().unwrap_or_default();
        let message = entry.meta.negative_message.clone().unwrap_or_default();
        Some((status, message))
    }

    /// Observed 候选(`unverified/` 命名空间)的原样读取,供 lazy verify 使用。
    /// 不做联合视图:resolve 端必须对这里的内容重新做归一化解析和信任判定。
    pub(crate) fn observed_candidate(
        &self,
        did: &DID,
        doc_type: Option<DidDocType>,
    ) -> Option<(EncodedDocument, u64, Option<String>)> {
        let key = combine_key(did, doc_type.as_ref());
        let entry = self.load_ns(CacheNamespace::Unverified, &key)?;
        let exp = entry.exp();
        let source = entry.meta.source.clone();
        entry.doc.map(|doc| (doc, exp, source))
    }

    /// 验证转正(doc/update-did-cache.md):把 `unverified/` 候选移动进
    /// `verified/`,证据打 `Verified`。文件系统层面是一次原子移动(rename),
    /// 不是读出重写。仍然要过一次 merge_allows(可能撞上已有的 Published/更高
    /// version 的 Verified);移动失败时原 unverified 文件被删除——它已经被
    /// 验证过一次并且证明"验证通过但不是更优版本",没有继续保留的价值。
    ///
    /// 返回 true 表示条目已进入 `verified/`。调用方(verify_and_promote)负责
    /// 在此之前完成真正的验证;本函数只做落盘与合并纪律。
    pub(crate) fn promote_observed(
        &self,
        did: &DID,
        doc_type: Option<DidDocType>,
        exp: u64,
    ) -> bool {
        let key = combine_key(did, doc_type.as_ref());
        let Some(entry) = self.load_ns(CacheNamespace::Unverified, &key) else {
            return false;
        };
        let Some(doc) = entry.doc else {
            self.remove_ns(CacheNamespace::Unverified, &key);
            return false;
        };

        if self
            .validate_owner_revocation(did, doc_type.clone(), &doc)
            .is_err()
        {
            self.remove_ns(CacheNamespace::Unverified, &key);
            return false;
        }
        if let Some(current) = self.load_ns(CacheNamespace::Verified, &key) {
            let verdict = merge_verdict(
                did,
                doc_type.as_ref(),
                &current,
                &doc,
                CacheEvidence::Verified,
            );
            if !matches!(
                verdict,
                CacheWriteOutcome::Inserted | CacheWriteOutcome::ReplacedOlder
            ) {
                self.remove_ns(CacheNamespace::Unverified, &key);
                return false;
            }
        }

        let promoted = StoredEntry {
            doc: Some(doc.clone()),
            meta: StoredMeta {
                evidence: CacheEvidence::Verified,
                negative_status: None,
                negative_message: None,
                exp: Some(exp),
                update_from_remote_time: Some(buckyos_get_unix_timestamp()),
                source: entry.meta.source.clone(),
                observed_at: entry.meta.observed_at,
            },
        };
        let moved = match &self.backend {
            Backend::Fs(store) => store.promote(&key, &promoted),
            Backend::Mem(store) => store.promote(&key, &promoted),
        };
        if !moved {
            return false;
        }

        // 与 write_positive 的联动一致:已验证的 owner 文档落地时清理被吊销文档。
        if let Some(owner_document) = parse_owner_document_doc(doc_type.as_ref(), &doc) {
            self.evict_revoked_docs(did, doc_type.as_ref(), &owner_document);
        }
        true
    }

    /// 删除 Observed 候选(lazy verify 明确失败后调用,避免同一份坏数据反复
    /// 触发验证开销)。
    pub(crate) fn delete_unverified(&self, did: &DID, doc_type: Option<DidDocType>) {
        let key = combine_key(did, doc_type.as_ref());
        self.remove_ns(CacheNamespace::Unverified, &key);
    }

    /// 策略点①的缓存动作:删除 positive、写入负状态条目、屏蔽后续 fallback。
    /// 负状态是"回答",不是 cache miss。同 key 的 Observed 候选一并清理。
    pub fn replace_with_negative(
        &self,
        did: &DID,
        doc_type: Option<DidDocType>,
        status: &DocumentStatus,
        message: &str,
    ) {
        let key = combine_key(did, doc_type.as_ref());
        let entry = StoredEntry {
            doc: None,
            meta: StoredMeta {
                evidence: CacheEvidence::Published,
                negative_status: Some(format!("{:?}", status)),
                negative_message: Some(message.to_string()),
                exp: Some(buckyos_get_unix_timestamp() + NEGATIVE_STATE_TTL_SECS),
                update_from_remote_time: Some(buckyos_get_unix_timestamp()),
                source: None,
                observed_at: None,
            },
        };
        self.store(&key, &entry);
        self.remove_ns(CacheNamespace::Unverified, &key);
    }

    pub fn delete(&self, did: DID, doc_type: Option<DidDocType>) {
        let key = combine_key(&did, doc_type.as_ref());
        self.remove(&key);
    }

    /// 测试辅助:写入一个 TTL 已过期的负状态条目,用于验证"负状态屏蔽兜底
    /// 不受 TTL 约束"的语义。
    #[cfg(test)]
    pub(crate) fn replace_with_negative_expired(
        &self,
        did: &DID,
        doc_type: Option<DidDocType>,
        status: &DocumentStatus,
        message: &str,
    ) {
        let key = combine_key(did, doc_type.as_ref());
        let entry = StoredEntry {
            doc: None,
            meta: StoredMeta {
                evidence: CacheEvidence::Published,
                negative_status: Some(format!("{:?}", status)),
                negative_message: Some(message.to_string()),
                exp: Some(buckyos_get_unix_timestamp().saturating_sub(10)),
                update_from_remote_time: Some(buckyos_get_unix_timestamp()),
                source: None,
                observed_at: None,
            },
        };
        self.store(&key, &entry);
    }

    /// owner 文档声明的 replay guard(valid_iat / mini_version_seq)对读写两侧生效。
    /// guard 的依据只能来自 `verified/` 命名空间的 owner 文档:Observed 命名空间
    /// 里自称的 owner 文档未经验证,没有资格吊销任何条目。
    pub fn validate_owner_revocation(
        &self,
        did: &DID,
        doc_type: Option<DidDocType>,
        doc: &EncodedDocument,
    ) -> name_lib::NSResult<()> {
        if is_owner_doc(doc_type.as_ref(), doc) {
            return Ok(());
        }
        if let Some(owner_document) = self.load_cached_owner_document(did) {
            owner_document.validate_jwt_revocation(doc_type_str(doc_type.as_ref()), doc)?;
        }
        Ok(())
    }

    fn load_cached_owner_document(&self, did: &DID) -> Option<OwnerDocument> {
        let load_positive = |doc_type: Option<&DidDocType>| -> Option<EncodedDocument> {
            let key = combine_key(did, doc_type);
            let entry = self.load_ns(CacheNamespace::Verified, &key)?;
            if entry.is_negative() {
                return None;
            }
            entry.doc
        };
        load_positive(Some(&DidDocType::Owner))
            .and_then(|doc| parse_owner_document_doc(Some(&DidDocType::Owner), &doc))
            .or_else(|| load_positive(None).and_then(|doc| parse_owner_document_doc(None, &doc)))
    }

    fn evict_revoked_docs(
        &self,
        did: &DID,
        owner_doc_type: Option<&DidDocType>,
        owner_document: &OwnerDocument,
    ) {
        let did_key = did_cache_key(did);
        for key in self.keys_for_did(did) {
            let Some(doc_type) = doc_type_from_cache_key(&did_key, &key) else {
                continue;
            };
            if same_doc_type(doc_type.as_ref(), owner_doc_type) {
                continue;
            }
            let Some(entry) = self.load_union(&key) else {
                continue;
            };
            if entry.is_negative() {
                continue;
            }
            let Some(doc) = entry.doc else {
                continue;
            };
            if owner_document
                .validate_jwt_revocation(doc_type_str(doc_type.as_ref()), &doc)
                .is_err()
            {
                self.remove(&key);
            }
        }
    }
}

/// merge 规则(iat-only,doc/verify-did-api-boundary-and-freshness-TODO.md
/// Phase 4;version_seq 已整体退出流程,不参与任何比较):
///
/// 1. 负状态屏蔽一切,只有权威源的新 DR(Published 证据)能翻篇;
/// 2. 更高证据等级直接胜出(权威结果永远能翻案),更低等级被忽略;
/// 3. Info doc_type 的 `update_time` 合并规则独立保留(运行时观察信道,明确
///    排除在 DocumentRevision 契约外);
/// 4. 命名对象(`is_named_obj_id`)同级不可替换:同 hash 视为已存在,不同内容
///    一律冲突;
/// 5. 同级按 revision:`iat` 不同以 iat 决定新旧;同 iat 同 hash 为同一份文档
///    (`AlreadyPresent`);同 iat 不同 hash 为同 revision 冲突
///    (`RejectedConflict`),不悄悄选一个。缺 iat 的文档按 `exp` 补充推导;
///    仍推不出时排在任何带 iat 的文档之前(None < Some)。
fn merge_verdict(
    did: &DID,
    doc_type: Option<&DidDocType>,
    current: &StoredEntry,
    new_doc: &EncodedDocument,
    new_evidence: CacheEvidence,
) -> CacheWriteOutcome {
    if current.is_negative() {
        return if new_evidence == CacheEvidence::Published {
            CacheWriteOutcome::ReplacedOlder
        } else {
            CacheWriteOutcome::BlockedByNegativeState
        };
    }
    let Some(current_doc) = current.doc.as_ref() else {
        return CacheWriteOutcome::Inserted;
    };

    let current_rank = current.meta.evidence.rank();
    let new_rank = new_evidence.rank();
    if new_rank != current_rank {
        return if new_rank > current_rank {
            CacheWriteOutcome::ReplacedOlder
        } else {
            CacheWriteOutcome::IgnoredOlder
        };
    }

    // Info documents carry runtime observations such as DeviceInfo.all_ip with
    // their own update_time axis. Runtime freshness wins before the generic
    // revision merge; the Info channel is outside the DocumentRevision contract.
    if doc_type == Some(&DidDocType::Info) {
        let current_update_time = extract_timestamp(current_doc, "update_time");
        let new_update_time = extract_timestamp(new_doc, "update_time");
        match (current_update_time, new_update_time) {
            (Some(current), Some(new)) => {
                return if new >= current {
                    CacheWriteOutcome::ReplacedOlder
                } else {
                    CacheWriteOutcome::IgnoredOlder
                };
            }
            (None, Some(_)) => return CacheWriteOutcome::ReplacedOlder,
            (Some(_), None) => return CacheWriteOutcome::IgnoredOlder,
            (None, None) => {}
        }
    }

    let same_content = document_content_hash(current_doc) == document_content_hash(new_doc);

    if did.is_named_obj_id() {
        // 命名对象内容即身份:同级永远不可替换。
        return if same_content {
            CacheWriteOutcome::AlreadyPresent
        } else {
            CacheWriteOutcome::RejectedConflict
        };
    }

    let new_iat = document_iat(new_doc);
    let current_iat = document_iat(current_doc);
    if new_iat == current_iat {
        return if same_content {
            CacheWriteOutcome::AlreadyPresent
        } else {
            CacheWriteOutcome::RejectedConflict
        };
    }
    if new_iat > current_iat {
        CacheWriteOutcome::ReplacedOlder
    } else {
        CacheWriteOutcome::IgnoredOlder
    }
}

// ------------------------ 文件系统后端(纯 KV) ------------------------
//
// 磁盘布局(doc/update-did-cache.md"文件系统协议"):
//
// ```text
// {did_cache_root}/
//   unverified/{key}.doc.json + {key}.meta.json   # 任何本机进程可写(Observed)
//   verified/{key}.doc.json + {key}.meta.json     # 只有 name-client 受控写入
// ```
//
// 所有写入都是"写 .tmp/ 临时文件 + rename 进目标目录"的两段式,保证目标目录里
// 出现的文件始终是完整的;promote 对 doc 文件是一次真正的 rename 移动。
// 旧版根目录平铺布局在启动时做一次性迁移(按 meta 证据分流;没有 meta 的
// 手工文件按 Observed 对待)。

static TMP_FILE_SEQ: AtomicU64 = AtomicU64::new(0);

struct FsStore {
    cache_dir: PathBuf,
}

impl FsStore {
    fn new(cache_dir: Option<PathBuf>) -> Self {
        let cache_dir = cache_dir.unwrap_or_else(DIDDocumentCache::get_default_cache_dir);
        info!("doc cache directory: {}", cache_dir.display());
        let store = Self { cache_dir };
        for ns in [CacheNamespace::Unverified, CacheNamespace::Verified] {
            if let Err(err) = fs::create_dir_all(store.tmp_dir(ns)) {
                error!(
                    "Failed to prepare doc cache directory {}: {}",
                    store.ns_dir(ns).display(),
                    err
                );
            }
        }
        store.migrate_legacy_layout();
        store
    }

    fn ns_dir(&self, ns: CacheNamespace) -> PathBuf {
        self.cache_dir.join(ns.dir_name())
    }

    fn tmp_dir(&self, ns: CacheNamespace) -> PathBuf {
        self.ns_dir(ns).join(".tmp")
    }

    fn doc_path(&self, ns: CacheNamespace, key: &str) -> PathBuf {
        self.ns_dir(ns).join(format!("{}.doc.json", key))
    }

    fn meta_path(&self, ns: CacheNamespace, key: &str) -> PathBuf {
        self.ns_dir(ns).join(format!("{}.meta.json", key))
    }

    /// 旧版平铺布局({cache_dir}/{key}.doc.json)一次性迁移到命名空间目录。
    /// meta 声明 Unverified 或根本没有 meta(手工放置)的进 unverified/,
    /// 其余进 verified/。迁移失败只记日志,不阻塞启动。
    fn migrate_legacy_layout(&self) {
        let entries = match fs::read_dir(&self.cache_dir) {
            Ok(entries) => entries,
            Err(_) => return,
        };
        let mut keys = Vec::new();
        for entry in entries.flatten() {
            if !entry.path().is_file() {
                continue;
            }
            let file_name = entry.file_name().to_string_lossy().to_string();
            for suffix in [".doc.json", ".meta.json"] {
                if let Some(key) = file_name.strip_suffix(suffix) {
                    if !keys.contains(&key.to_string()) {
                        keys.push(key.to_string());
                    }
                }
            }
        }
        for key in keys {
            let legacy_meta = self.cache_dir.join(format!("{}.meta.json", key));
            let meta = fs::read_to_string(&legacy_meta)
                .ok()
                .and_then(|content| serde_json::from_str::<StoredMeta>(&content).ok());
            let ns = match &meta {
                Some(meta) if meta.evidence != CacheEvidence::Unverified => {
                    CacheNamespace::Verified
                }
                // Unverified meta 或手工放置(无 meta):按 Observed 对待。
                _ => CacheNamespace::Unverified,
            };
            info!(
                "migrating legacy did cache entry {} to {}/",
                key,
                ns.dir_name()
            );
            for suffix in [".doc.json", ".meta.json"] {
                let from = self.cache_dir.join(format!("{}{}", key, suffix));
                if !from.exists() {
                    continue;
                }
                let to = self.ns_dir(ns).join(format!("{}{}", key, suffix));
                if let Err(err) = fs::rename(&from, &to) {
                    warn!(
                        "migrate legacy did cache file {} failed: {}",
                        from.display(),
                        err
                    );
                }
            }
        }
    }

    /// 两段式原子写:先写同命名空间下 .tmp/ 里的临时文件,再 rename 进目标位置,
    /// 避免并发读者看到半写文件。临时文件名带 PID + 进程内序号,规避并发命名冲突。
    fn write_atomic(&self, ns: CacheNamespace, target: &Path, content: &str) -> std::io::Result<()> {
        let tmp_dir = self.tmp_dir(ns);
        if !tmp_dir.exists() {
            fs::create_dir_all(&tmp_dir)?;
        }
        let file_name = target
            .file_name()
            .map(|name| name.to_string_lossy().to_string())
            .unwrap_or_else(|| "entry".to_string());
        let tmp_path = tmp_dir.join(format!(
            "{}.{}.{}",
            file_name,
            std::process::id(),
            TMP_FILE_SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        fs::write(&tmp_path, content)?;
        match fs::rename(&tmp_path, target) {
            Ok(()) => Ok(()),
            Err(err) => {
                let _ = fs::remove_file(&tmp_path);
                Err(err)
            }
        }
    }

    fn load(&self, ns: CacheNamespace, key: &str) -> Option<StoredEntry> {
        let meta = self.load_meta(ns, key);
        let doc = self.load_doc(ns, key);

        match (doc, meta) {
            (doc, Some(mut meta)) => {
                if meta.negative_status.is_none() && doc.is_none() {
                    return None;
                }
                // 文件系统协议里写入方 meta 只允许 source/observed_at/
                // hint_doc_type,不含 exp:unverified 条目缺 exp 时按文件
                // 修改时间 + 24h 兜底,与 doc-only 手工投递一致。
                if ns == CacheNamespace::Unverified && meta.exp.is_none() && doc.is_some() {
                    meta.exp = fs::metadata(self.doc_path(ns, key))
                        .ok()
                        .and_then(|m| m.modified().ok())
                        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                        .map(|d| d.as_secs() + 3600 * 24);
                }
                Some(StoredEntry { doc, meta })
            }
            (Some(doc), None) => {
                // 手工放置的文件:没有 meta,过期时间退化为文件修改时间 + 24h。
                // 证据等级由命名空间钳制(统一层),这里给出该命名空间的默认档。
                let default_exp = fs::metadata(self.doc_path(ns, key))
                    .ok()
                    .and_then(|m| m.modified().ok())
                    .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                    .map(|d| d.as_secs() + 3600 * 24);
                let evidence = match ns {
                    CacheNamespace::Unverified => CacheEvidence::Unverified,
                    // verified/ 的写权限已经过滤了写者,doc-only 视为受控本地种子。
                    CacheNamespace::Verified => default_cache_evidence(),
                };
                Some(StoredEntry {
                    doc: Some(doc),
                    meta: StoredMeta {
                        evidence,
                        negative_status: None,
                        negative_message: None,
                        exp: default_exp,
                        update_from_remote_time: None,
                        source: None,
                        observed_at: None,
                    },
                })
            }
            (None, None) => None,
        }
    }

    fn load_doc(&self, ns: CacheNamespace, key: &str) -> Option<EncodedDocument> {
        let file_path = self.doc_path(ns, key);
        match fs::read_to_string(&file_path) {
            Ok(content) => match EncodedDocument::from_str(content) {
                Ok(doc) => Some(doc),
                Err(err) => {
                    error!(
                        "parse did doc from local cache failed: {}, {}",
                        file_path.display(),
                        err
                    );
                    None
                }
            },
            Err(err) => {
                debug!(
                    "load did doc from local cache failed: {}, {}",
                    file_path.display(),
                    err
                );
                None
            }
        }
    }

    fn load_meta(&self, ns: CacheNamespace, key: &str) -> Option<StoredMeta> {
        let meta_path = self.meta_path(ns, key);
        match fs::read_to_string(&meta_path) {
            Ok(content) => match serde_json::from_str::<StoredMeta>(&content) {
                Ok(meta) => Some(meta),
                Err(err) => {
                    warn!(
                        "failed to parse did doc meta {}: {}",
                        meta_path.display(),
                        err
                    );
                    None
                }
            },
            Err(err) => {
                if err.kind() != std::io::ErrorKind::NotFound {
                    warn!(
                        "failed to read did doc meta {}: {}",
                        meta_path.display(),
                        err
                    );
                }
                None
            }
        }
    }

    fn store(&self, ns: CacheNamespace, key: &str, entry: &StoredEntry) -> bool {
        let mut ok = true;
        match entry.doc.as_ref() {
            Some(doc) => {
                let file_path = self.doc_path(ns, key);
                if let Err(err) = self.write_atomic(ns, &file_path, &doc.to_string()) {
                    error!(
                        "write did doc to local cache failed: {}, {}",
                        file_path.display(),
                        err
                    );
                    ok = false;
                }
            }
            None => {
                // 负条目没有 doc 文件。
                let _ = fs::remove_file(self.doc_path(ns, key));
            }
        }
        if let Ok(content) = serde_json::to_string(&entry.meta) {
            if let Err(err) = self.write_atomic(ns, &self.meta_path(ns, key), &content) {
                warn!("write did doc meta to local cache failed: {}", err);
                ok = false;
            }
        }
        ok
    }

    fn remove(&self, ns: CacheNamespace, key: &str) {
        for path in [self.doc_path(ns, key), self.meta_path(ns, key)] {
            if let Err(err) = fs::remove_file(&path) {
                if err.kind() != std::io::ErrorKind::NotFound {
                    warn!(
                        "failed to remove did cache file {}: {}",
                        path.display(),
                        err
                    );
                }
            }
        }
    }

    /// promote:doc 文件从 unverified/ rename 到 verified/(本地文件系统上的
    /// 原子移动,不读出重写),meta 由验证结果重新生成后原子写入。
    fn promote(&self, key: &str, entry: &StoredEntry) -> bool {
        let from = self.doc_path(CacheNamespace::Unverified, key);
        let to = self.doc_path(CacheNamespace::Verified, key);
        if let Err(err) = fs::rename(&from, &to) {
            warn!(
                "promote did cache doc {} -> {} failed: {}",
                from.display(),
                to.display(),
                err
            );
            return false;
        }
        match serde_json::to_string(&entry.meta) {
            Ok(content) => {
                if let Err(err) = self.write_atomic(
                    CacheNamespace::Verified,
                    &self.meta_path(CacheNamespace::Verified, key),
                    &content,
                ) {
                    warn!("write promoted did doc meta failed: {}", err);
                }
            }
            Err(err) => {
                warn!("serialize promoted did doc meta failed: {}", err);
            }
        }
        let _ = fs::remove_file(self.meta_path(CacheNamespace::Unverified, key));
        true
    }

    fn keys_with_prefix(&self, ns: CacheNamespace, did_key: &str) -> Vec<String> {
        let entries = match fs::read_dir(self.ns_dir(ns)) {
            Ok(entries) => entries,
            Err(err) => {
                warn!("read did cache directory failed: {}", err);
                return Vec::new();
            }
        };
        let mut keys = Vec::new();
        for entry in entries.flatten() {
            let file_name = entry.file_name().to_string_lossy().to_string();
            for suffix in [".doc.json", ".meta.json"] {
                if let Some(key) = file_name.strip_suffix(suffix) {
                    if (key == did_key || key.starts_with(&format!("{}#", did_key)))
                        && !keys.contains(&key.to_string())
                    {
                        keys.push(key.to_string());
                    }
                }
            }
        }
        keys
    }
}

// ------------------------ 内存后端(纯 KV,测试用) ------------------------
//
// 单机/测试环境不要求两个物理目录:同一进程内用两个命名空间模拟,行为满足
// "目录即证据"的语义(doc/update-did-cache.md 非目标第 6 条)。

struct MemStore {
    unverified: std::sync::Arc<RwLock<HashMap<String, StoredEntry>>>,
    verified: std::sync::Arc<RwLock<HashMap<String, StoredEntry>>>,
}

impl MemStore {
    fn new() -> Self {
        Self {
            unverified: std::sync::Arc::new(RwLock::new(HashMap::new())),
            verified: std::sync::Arc::new(RwLock::new(HashMap::new())),
        }
    }

    fn entries(&self, ns: CacheNamespace) -> &RwLock<HashMap<String, StoredEntry>> {
        match ns {
            CacheNamespace::Unverified => &self.unverified,
            CacheNamespace::Verified => &self.verified,
        }
    }

    fn load(&self, ns: CacheNamespace, key: &str) -> Option<StoredEntry> {
        self.entries(ns).read().ok()?.get(key).cloned()
    }

    fn store(&self, ns: CacheNamespace, key: &str, entry: &StoredEntry) -> bool {
        if let Ok(mut guard) = self.entries(ns).write() {
            guard.insert(key.to_string(), entry.clone());
            return true;
        }
        false
    }

    fn remove(&self, ns: CacheNamespace, key: &str) {
        if let Ok(mut guard) = self.entries(ns).write() {
            guard.remove(key);
        }
    }

    fn promote(&self, key: &str, entry: &StoredEntry) -> bool {
        let removed = match self.entries(CacheNamespace::Unverified).write() {
            Ok(mut guard) => guard.remove(key).is_some(),
            Err(_) => false,
        };
        if !removed {
            return false;
        }
        self.store(CacheNamespace::Verified, key, entry);
        true
    }

    fn keys_with_prefix(&self, ns: CacheNamespace, did_key: &str) -> Vec<String> {
        match self.entries(ns).read() {
            Ok(guard) => guard
                .keys()
                .filter(|key| key.as_str() == did_key || key.starts_with(&format!("{}#", did_key)))
                .cloned()
                .collect(),
            Err(_) => Vec::new(),
        }
    }
}

// ------------------------ unauthenticated info cache ------------------------

#[derive(Clone)]
struct UnauthenticatedInfoEntry {
    doc: EncodedDocument,
    exp: u64,
    source_rank: i32,
}

/// 只保存免验证 Info 类结果(例如 DeviceInfo、运行时地址)。它不参与 owner 验签,
/// 不受 `Missing`/`revoke_before_iat` 等 Document 门禁间接门控,只按 ttl 判断可用性。
/// 这是进程内热缓存;跨进程共享由 `DIDDocumentCache` 的 unverified Info 条目承担。
pub struct UnauthenticatedInfoCache {
    entries: RwLock<HashMap<String, UnauthenticatedInfoEntry>>,
}

impl UnauthenticatedInfoCache {
    pub fn new() -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
        }
    }

    pub fn get(
        &self,
        did: &DID,
        doc_type: Option<DidDocType>,
    ) -> Option<(EncodedDocument, u64, i32)> {
        let key = combine_key(did, doc_type.as_ref());
        let entry = self.entries.read().ok()?.get(&key)?.clone();
        if is_expired(entry.exp) {
            return None;
        }
        Some((entry.doc, entry.exp, entry.source_rank))
    }

    pub fn insert(
        &self,
        did: &DID,
        doc_type: Option<DidDocType>,
        doc: EncodedDocument,
        exp: u64,
        source_rank: i32,
    ) {
        let key = combine_key(did, doc_type.as_ref());
        if let Ok(mut entries) = self.entries.write() {
            entries.insert(
                key,
                UnauthenticatedInfoEntry {
                    doc,
                    exp,
                    source_rank,
                },
            );
        }
    }
}

// ------------------------ 工具函数 ------------------------

fn is_expired(exp_ts: u64) -> bool {
    exp_ts <= buckyos_get_unix_timestamp()
}

fn extract_timestamp(doc: &EncodedDocument, field: &str) -> Option<u64> {
    doc.clone()
        .to_json_value()
        .ok()
        .and_then(|value| value.get(field).and_then(|ts| ts.as_u64()))
}

fn combine_key(did: &DID, doc_type: Option<&DidDocType>) -> String {
    let did_key = did_cache_key(did);
    if let Some(f) = doc_type {
        format!("{}#{}", did_key, f.as_str())
    } else {
        did_key
    }
}

fn doc_type_str(doc_type: Option<&DidDocType>) -> &str {
    doc_type.map(DidDocType::as_str).unwrap_or_default()
}

fn did_cache_key(did: &DID) -> String {
    did.to_filename()
}

fn is_owner_doc(doc_type: Option<&DidDocType>, doc: &EncodedDocument) -> bool {
    doc_type == Some(&DidDocType::Owner)
        || doc.clone().to_json_value().map_or(false, |value| {
            value.get("verificationMethod").is_some()
                && value.get("name").is_some()
                && (value.get("display_name").is_some()
                    || value.get("displayName").is_some()
                    || value.get("full_name").is_some())
        })
}

fn parse_owner_document_doc(
    doc_type: Option<&DidDocType>,
    doc: &EncodedDocument,
) -> Option<OwnerDocument> {
    if !is_owner_doc(doc_type, doc) {
        return None;
    }
    match OwnerDocument::decode(doc, None) {
        Ok(owner_document) => Some(owner_document),
        Err(err) => {
            warn!("parse owner document from did-cache failed: {}", err);
            None
        }
    }
}

fn same_doc_type(left: Option<&DidDocType>, right: Option<&DidDocType>) -> bool {
    doc_type_str(left) == doc_type_str(right)
}

fn doc_type_from_cache_key(did_key: &str, key: &str) -> Option<Option<DidDocType>> {
    if key == did_key {
        return Some(None);
    }
    key.strip_prefix(&format!("{}#", did_key))
        .map(|doc_type| Some(DidDocType::from(doc_type)))
}

// ------------------------ 测试 ------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use name_lib::{DIDDocumentTrait, OwnerDocument, ZoneBootDocument, DEFAULT_EXPIRE_TIME};
    use serde_json::json;
    use std::collections::HashMap;
    use std::fs;
    use tempfile::tempdir;

    const TEST_OWNER_PRIVATE_KEY_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIJBRONAzbwpIOwm0ugIQNyZJrDXxZF7HoPWAZesMedOr
-----END PRIVATE KEY-----"#;

    const TEST_OWNER_PUBLIC_JWK: &str = r#"{
  "kty": "OKP",
  "crv": "Ed25519",
  "x": "T4Quc1L6Ogu4N2tTKOvneV1yYnBcmhP89B_RsuFsJZ8"
}"#;

    fn setup_fs_cache() -> (tempfile::TempDir, DIDDocumentCache, DID) {
        let tmp_dir = tempdir().unwrap();
        let cache = DIDDocumentCache::new(Some(tmp_dir.path().to_path_buf()));
        let did = DID::from_str("did:web:example.com").unwrap();
        (tmp_dir, cache, did)
    }

    fn setup_mem_cache() -> (DIDDocumentCache, DID) {
        let cache = DIDDocumentCache::new_mem();
        let did = DID::from_str("did:web:example.com").unwrap();
        (cache, did)
    }

    fn owner_encoding_key() -> EncodingKey {
        EncodingKey::from_ed_pem(TEST_OWNER_PRIVATE_KEY_PEM.as_bytes()).unwrap()
    }

    fn owner_public_jwk() -> jsonwebtoken::jwk::Jwk {
        serde_json::from_str(TEST_OWNER_PUBLIC_JWK).unwrap()
    }

    fn build_owner_doc_with_revocation(
        did: &DID,
        iat: u64,
        mini_version_seq: Option<u64>,
        valid_iat: Option<u64>,
        marker: &str,
    ) -> EncodedDocument {
        let mut owner_document = OwnerDocument::new(
            did.clone(),
            format!("tester-{marker}"),
            "Tester Example".to_string(),
            owner_public_jwk(),
        );
        owner_document.iat = iat;
        owner_document.exp = iat + DEFAULT_EXPIRE_TIME;
        owner_document.version_seq = Some(1);
        owner_document.mini_version_seq = mini_version_seq;
        owner_document.valid_iat = valid_iat;
        owner_document
            .extra_info
            .insert("marker".to_string(), json!(marker));
        owner_document.encode(Some(&owner_encoding_key())).unwrap()
    }

    fn build_jwt_doc(version_seq: u64, iat: u64, marker: &str) -> EncodedDocument {
        let jwt = encode(
            &Header::new(Algorithm::EdDSA),
            &json!({
                "version_seq": version_seq,
                "iat": iat,
                "exp": iat + DEFAULT_EXPIRE_TIME,
                "marker": marker
            }),
            &owner_encoding_key(),
        )
        .unwrap();
        EncodedDocument::Jwt(jwt)
    }

    fn build_zone_doc(did: &DID, exp: u64, marker: &str) -> EncodedDocument {
        let mut extra_info = HashMap::new();
        extra_info.insert("marker".to_string(), json!(marker));
        let zone_boot_document = ZoneBootDocument {
            id: Some(did.clone()),
            oods: vec!["ood1".parse().unwrap()],
            sn: Some("sn.unit-test.buckyos".to_string()),
            exp,
            owner: None,
            owner_key: None,
            extra_info,
        };
        EncodedDocument::JsonLd(serde_json::to_value(zone_boot_document).unwrap())
    }

    fn positive_doc(cache: &DIDDocumentCache, did: &DID) -> EncodedDocument {
        match cache.lookup(did, None).expect("entry expected") {
            CacheLookup::Positive { doc, .. } => doc,
            CacheLookup::Negative { .. } => panic!("expected positive entry"),
        }
    }

    // ---- 基本读写(两种后端) ----

    fn assert_roundtrip_with_evidence(cache: &DIDDocumentCache, did: &DID) {
        let now = buckyos_get_unix_timestamp();
        let exp = now + DEFAULT_EXPIRE_TIME;
        let doc = build_zone_doc(did, exp, "roundtrip");
        assert_eq!(
            cache.update(did.clone(), None, doc.clone(), exp, CacheEvidence::Verified),
            CacheWriteOutcome::Inserted
        );
        match cache.lookup(did, None).unwrap() {
            CacheLookup::Positive {
                doc: loaded,
                exp: loaded_exp,
                evidence,
                in_ttl,
                ..
            } => {
                assert_eq!(loaded, doc);
                assert_eq!(loaded_exp, exp);
                assert_eq!(evidence, CacheEvidence::Verified);
                assert!(in_ttl);
            }
            other => panic!("unexpected lookup: {:?}", other),
        }
    }

    #[test]
    fn fs_roundtrip_preserves_evidence() {
        let (_tmp, cache, did) = setup_fs_cache();
        assert_roundtrip_with_evidence(&cache, &did);
    }

    #[test]
    fn mem_roundtrip_preserves_evidence() {
        let (cache, did) = setup_mem_cache();
        assert_roundtrip_with_evidence(&cache, &did);
    }

    // ---- T0.5: 负状态条目 ----

    fn assert_negative_state_blocks_and_flips(cache: &DIDDocumentCache, did: &DID) {
        let now = buckyos_get_unix_timestamp();
        let exp = now + DEFAULT_EXPIRE_TIME;
        let doc = build_zone_doc(did, exp, "pre-revoke");
        assert_eq!(
            cache.update(did.clone(), None, doc, exp, CacheEvidence::Published),
            CacheWriteOutcome::Inserted
        );

        cache.replace_with_negative(did, None, &DocumentStatus::Revoked, "revoked by authority");

        // 正条目被替换成负条目。
        match cache.lookup(did, None).unwrap() {
            CacheLookup::Negative { status, in_ttl, .. } => {
                assert_eq!(status, "Revoked");
                assert!(in_ttl);
            }
            other => panic!("expected negative, got {:?}", other),
        }
        assert!(cache.get(did, None).is_none());

        // 负状态屏蔽普通写入(push / 已验证自签名都不行),写入结果结构化区分。
        let newer = build_zone_doc(did, exp + 10, "shadow");
        assert_eq!(
            cache.update(
                did.clone(),
                None,
                newer.clone(),
                exp + 10,
                CacheEvidence::Verified
            ),
            CacheWriteOutcome::BlockedByNegativeState
        );
        assert_eq!(
            cache.update(
                did.clone(),
                None,
                newer.clone(),
                exp + 10,
                CacheEvidence::Unverified
            ),
            CacheWriteOutcome::BlockedByNegativeState
        );
        assert!(cache.lookup(did, None).unwrap().is_negative());
        // Observed 命名空间同样不产生条目(负状态屏蔽一切写入)。
        assert!(cache.observed_candidate(did, None).is_none());

        // 只有权威源的新 DR(Published 证据)能翻篇。
        assert_eq!(
            cache.update(
                did.clone(),
                None,
                newer.clone(),
                exp + 10,
                CacheEvidence::Published
            ),
            CacheWriteOutcome::ReplacedOlder
        );
        assert_eq!(positive_doc(cache, did), newer);
    }

    #[test]
    fn fs_negative_state_blocks_and_flips() {
        let (_tmp, cache, did) = setup_fs_cache();
        assert_negative_state_blocks_and_flips(&cache, &did);
    }

    #[test]
    fn mem_negative_state_blocks_and_flips() {
        let (cache, did) = setup_mem_cache();
        assert_negative_state_blocks_and_flips(&cache, &did);
    }

    // ---- merge:先比证据等级,同级才比 version/iat ----

    #[test]
    fn evidence_rank_beats_freshness() {
        let (cache, did) = setup_mem_cache();
        let now = buckyos_get_unix_timestamp();
        let exp = now + DEFAULT_EXPIRE_TIME;

        let published = build_zone_doc(&did, exp, "published-old");
        assert_eq!(
            cache.update(
                did.clone(),
                None,
                published.clone(),
                exp,
                CacheEvidence::Published
            ),
            CacheWriteOutcome::Inserted
        );

        // 更新鲜的自签名(哪怕 iat 更大)压不过已发布条目。
        let fresher_self_signed = build_zone_doc(&did, exp + 1000, "self-signed-newer");
        assert_eq!(
            cache.update(
                did.clone(),
                None,
                fresher_self_signed,
                exp + 1000,
                CacheEvidence::Verified
            ),
            CacheWriteOutcome::IgnoredOlder
        );
        assert_eq!(positive_doc(&cache, &did), published);

        // 未验证 push 被记录为 Observed(命名空间内 Inserted),但查询仍然
        // 命中 verified 条目(读侧遮蔽)。
        let pushed = build_zone_doc(&did, exp + 2000, "pushed");
        assert_eq!(
            cache.update(
                did.clone(),
                None,
                pushed.clone(),
                exp + 2000,
                CacheEvidence::Unverified
            ),
            CacheWriteOutcome::Inserted
        );
        assert_eq!(positive_doc(&cache, &did), published);
        assert_eq!(cache.observed_candidate(&did, None).unwrap().0, pushed);

        // 同级(已发布)才比新旧。
        let newer_published = build_zone_doc(&did, exp + 3000, "published-new");
        assert_eq!(
            cache.update(
                did.clone(),
                None,
                newer_published.clone(),
                exp + 3000,
                CacheEvidence::Published
            ),
            CacheWriteOutcome::ReplacedOlder
        );
        assert_eq!(positive_doc(&cache, &did), newer_published);
    }

    #[test]
    fn same_rank_compares_iat_only_version_seq_ignored() {
        // revision 只以 iat 为序(方向翻转):version_seq 视作用户自定义扩展,
        // 不参与任何比较——iat 顺序与 version_seq 顺序相反的文档对按 iat 判定
        // (测试要求 12)。
        let (cache, did) = setup_mem_cache();
        let now = buckyos_get_unix_timestamp();

        let doc_v2 = EncodedDocument::JsonLd(json!({
            "version_seq": 2, "iat": now, "exp": now + DEFAULT_EXPIRE_TIME, "marker": "v2"
        }));
        assert_eq!(
            cache.update(
                did.clone(),
                None,
                doc_v2.clone(),
                now + DEFAULT_EXPIRE_TIME,
                CacheEvidence::Verified
            ),
            CacheWriteOutcome::Inserted
        );

        // iat 更新、version_seq 更小:iat 胜出,替换。
        let doc_v1 = EncodedDocument::JsonLd(json!({
            "version_seq": 1, "iat": now + 10_000, "exp": now + DEFAULT_EXPIRE_TIME + 10_000, "marker": "v1"
        }));
        assert_eq!(
            cache.update(
                did.clone(),
                None,
                doc_v1.clone(),
                now + DEFAULT_EXPIRE_TIME + 10_000,
                CacheEvidence::Verified
            ),
            CacheWriteOutcome::ReplacedOlder
        );
        assert_eq!(positive_doc(&cache, &did), doc_v1);

        // iat 更旧、version_seq 更大:仍被忽略。
        let older_bigger_seq = EncodedDocument::JsonLd(json!({
            "version_seq": 9, "iat": now + 5_000, "exp": now + DEFAULT_EXPIRE_TIME + 5_000, "marker": "older"
        }));
        assert_eq!(
            cache.update(
                did.clone(),
                None,
                older_bigger_seq,
                now + DEFAULT_EXPIRE_TIME + 5_000,
                CacheEvidence::Verified
            ),
            CacheWriteOutcome::IgnoredOlder
        );

        // 无 version_seq 的更新文档同样按 iat 胜出。
        let unversioned = EncodedDocument::JsonLd(json!({
            "iat": now + 20_000, "exp": now + DEFAULT_EXPIRE_TIME + 20_000, "marker": "unversioned"
        }));
        assert_eq!(
            cache.update(
                did.clone(),
                None,
                unversioned.clone(),
                now + DEFAULT_EXPIRE_TIME + 20_000,
                CacheEvidence::Verified
            ),
            CacheWriteOutcome::ReplacedOlder
        );
        assert_eq!(positive_doc(&cache, &did), unversioned);
    }

    #[test]
    fn same_iat_distinguishes_already_present_and_conflict() {
        // 同 iat 同 hash → AlreadyPresent;同 iat 不同 hash → RejectedConflict,
        // 不悄悄选一个(测试要求 15)。
        let (cache, did) = setup_mem_cache();
        let now = buckyos_get_unix_timestamp();
        let doc_a = EncodedDocument::JsonLd(json!({
            "iat": now, "exp": now + DEFAULT_EXPIRE_TIME, "marker": "a"
        }));
        assert_eq!(
            cache.update(
                did.clone(),
                None,
                doc_a.clone(),
                now + DEFAULT_EXPIRE_TIME,
                CacheEvidence::Verified
            ),
            CacheWriteOutcome::Inserted
        );
        assert_eq!(
            cache.update(
                did.clone(),
                None,
                doc_a.clone(),
                now + DEFAULT_EXPIRE_TIME,
                CacheEvidence::Verified
            ),
            CacheWriteOutcome::AlreadyPresent
        );
        let doc_b = EncodedDocument::JsonLd(json!({
            "iat": now, "exp": now + DEFAULT_EXPIRE_TIME, "marker": "b"
        }));
        assert_eq!(
            cache.update(
                did.clone(),
                None,
                doc_b,
                now + DEFAULT_EXPIRE_TIME,
                CacheEvidence::Verified
            ),
            CacheWriteOutcome::RejectedConflict
        );
        assert_eq!(positive_doc(&cache, &did), doc_a);
    }

    #[test]
    fn named_obj_is_immutable_at_same_rank() {
        let (cache, _) = setup_mem_cache();
        let did = DID::from_str("did:dev:5bUuyWLOKyCre9az_IhJVIuOw8bA0gyKjstcYGHbaPE").unwrap();
        let now = buckyos_get_unix_timestamp();

        let doc_v1 = EncodedDocument::JsonLd(json!({
            "iat": now, "exp": now + DEFAULT_EXPIRE_TIME, "marker": "v1"
        }));
        cache.insert(
            did.clone(),
            None,
            doc_v1.clone(),
            now + DEFAULT_EXPIRE_TIME,
            CacheEvidence::Verified,
        );

        let doc_v2 = EncodedDocument::JsonLd(json!({
            "iat": now + 1000, "exp": now + DEFAULT_EXPIRE_TIME + 1000, "marker": "v2"
        }));
        assert_eq!(
            cache.update(
                did.clone(),
                None,
                doc_v2,
                now + DEFAULT_EXPIRE_TIME + 1000,
                CacheEvidence::Verified
            ),
            CacheWriteOutcome::RejectedConflict
        );
        assert_eq!(positive_doc(&cache, &did), doc_v1);
    }

    // ---- TTL:过期条目保留,标记 in_ttl=false ----

    #[test]
    fn expired_positive_entry_is_kept_for_stale_fallback() {
        let (cache, did) = setup_mem_cache();
        let past_exp = buckyos_get_unix_timestamp().saturating_sub(10);
        let doc = build_zone_doc(&did, past_exp, "stale");
        cache.insert(
            did.clone(),
            None,
            doc.clone(),
            past_exp,
            CacheEvidence::Published,
        );

        match cache.lookup(&did, None).unwrap() {
            CacheLookup::Positive {
                doc: loaded,
                in_ttl,
                ..
            } => {
                assert_eq!(loaded, doc);
                assert!(!in_ttl);
            }
            other => panic!("unexpected {:?}", other),
        }
    }

    // ---- owner replay guard 联动(保留资产) ----

    fn assert_owner_update_evicts_revoked_docs(cache: &DIDDocumentCache, did: &DID) {
        let base_iat = buckyos_get_unix_timestamp();
        let old_doc = build_jwt_doc(1, base_iat + 10, "old");
        let fresh_doc = build_jwt_doc(2, base_iat + 11, "fresh");
        cache.insert(
            did.clone(),
            None,
            old_doc,
            base_iat + DEFAULT_EXPIRE_TIME,
            CacheEvidence::Verified,
        );
        cache.insert(
            did.clone(),
            Some(DidDocType::Info),
            fresh_doc.clone(),
            base_iat + DEFAULT_EXPIRE_TIME,
            CacheEvidence::Verified,
        );

        let owner_doc =
            build_owner_doc_with_revocation(did, base_iat, Some(1), Some(base_iat + 10), "owner");
        cache.insert(
            did.clone(),
            Some(DidDocType::Owner),
            owner_doc,
            base_iat + DEFAULT_EXPIRE_TIME,
            CacheEvidence::Published,
        );

        assert!(
            cache.get(did, None).is_none(),
            "stale default DID document should be evicted"
        );
        assert_eq!(cache.get(did, Some(DidDocType::Info)).unwrap().0, fresh_doc);
    }

    fn assert_owner_policy_rejects_new_revoked_doc(cache: &DIDDocumentCache, did: &DID) {
        let base_iat = buckyos_get_unix_timestamp();
        let owner_doc =
            build_owner_doc_with_revocation(did, base_iat, Some(1), Some(base_iat + 10), "owner");
        cache.insert(
            did.clone(),
            Some(DidDocType::Owner),
            owner_doc,
            base_iat + DEFAULT_EXPIRE_TIME,
            CacheEvidence::Published,
        );

        let old_doc = build_jwt_doc(1, base_iat + 10, "old");
        cache.insert(
            did.clone(),
            None,
            old_doc,
            base_iat + DEFAULT_EXPIRE_TIME,
            CacheEvidence::Verified,
        );

        assert!(
            cache.get(did, None).is_none(),
            "revoked DID document should not be inserted"
        );
    }

    #[test]
    fn fs_owner_update_evicts_revoked_docs() {
        let (_tmp_dir, cache, did) = setup_fs_cache();
        assert_owner_update_evicts_revoked_docs(&cache, &did);
    }

    #[test]
    fn fs_owner_policy_rejects_new_revoked_doc() {
        let (_tmp_dir, cache, did) = setup_fs_cache();
        assert_owner_policy_rejects_new_revoked_doc(&cache, &did);
    }

    #[test]
    fn mem_owner_update_evicts_revoked_docs() {
        let (cache, did) = setup_mem_cache();
        assert_owner_update_evicts_revoked_docs(&cache, &did);
    }

    #[test]
    fn mem_owner_policy_rejects_new_revoked_doc() {
        let (cache, did) = setup_mem_cache();
        assert_owner_policy_rejects_new_revoked_doc(&cache, &did);
    }

    // ---- 目录即证据(doc/update-did-cache.md) ----

    /// unverified/ 目录下的 meta 自称 Published 也一律按 Unverified 对待。
    #[test]
    fn fs_unverified_dir_clamps_self_claimed_evidence() {
        let (tmp_dir, cache, did) = setup_fs_cache();
        let now = buckyos_get_unix_timestamp();
        let doc = build_zone_doc(&did, now + 1000, "self-claimed");
        let key = did_cache_key(&did);
        let unverified_dir = tmp_dir.path().join("unverified");
        fs::write(
            unverified_dir.join(format!("{}.doc.json", key)),
            doc.to_string(),
        )
        .unwrap();
        fs::write(
            unverified_dir.join(format!("{}.meta.json", key)),
            format!("{{\"evidence\":\"Published\",\"exp\":{}}}", now + 1000),
        )
        .unwrap();

        match cache.lookup(&did, None).unwrap() {
            CacheLookup::Positive { evidence, .. } => {
                assert_eq!(evidence, CacheEvidence::Unverified);
            }
            other => panic!("unexpected {:?}", other),
        }
    }

    /// unverified/ 目录下手工放置的负状态 meta 不被信任(否则任何人都能屏蔽解析)。
    #[test]
    fn fs_unverified_dir_ignores_self_claimed_negative_state() {
        let (tmp_dir, cache, did) = setup_fs_cache();
        let key = did_cache_key(&did);
        fs::write(
            tmp_dir
                .path()
                .join("unverified")
                .join(format!("{}.meta.json", key)),
            "{\"negative_status\":\"Revoked\",\"negative_message\":\"fake\"}",
        )
        .unwrap();
        assert!(cache.lookup(&did, None).is_none());
    }

    /// 手工往 unverified/ 丢一个 doc 文件(无 meta)等价于一次 add_observed_cache:
    /// 可被观察到,证据 Unverified("目录即协议")。
    #[test]
    fn fs_hand_placed_doc_in_unverified_dir_is_observed() {
        let (tmp_dir, cache, did) = setup_fs_cache();
        let now = buckyos_get_unix_timestamp();
        let doc = build_zone_doc(&did, now + 100, "hand-placed");
        fs::write(
            tmp_dir
                .path()
                .join("unverified")
                .join(format!("{}.doc.json", did_cache_key(&did))),
            doc.to_string(),
        )
        .unwrap();

        match cache.lookup(&did, None).unwrap() {
            CacheLookup::Positive {
                doc: loaded,
                evidence,
                in_ttl,
                ..
            } => {
                assert_eq!(loaded, doc);
                assert_eq!(evidence, CacheEvidence::Unverified);
                assert!(in_ttl, "hand-placed file exp derives from mtime + 24h");
            }
            other => panic!("unexpected {:?}", other),
        }
        assert_eq!(cache.observed_candidate(&did, None).unwrap().0, doc);
    }

    /// verified/ 已有 Published 记录时,unverified/ 出现新文件不影响查询结果。
    #[test]
    fn fs_observed_file_never_shadows_verified_entry() {
        let (tmp_dir, cache, did) = setup_fs_cache();
        let now = buckyos_get_unix_timestamp();
        let published = build_zone_doc(&did, now + 1000, "published");
        cache.insert(
            did.clone(),
            None,
            published.clone(),
            now + 1000,
            CacheEvidence::Published,
        );

        let observed = build_zone_doc(&did, now + 5000, "observed-later");
        fs::write(
            tmp_dir
                .path()
                .join("unverified")
                .join(format!("{}.doc.json", did_cache_key(&did))),
            observed.to_string(),
        )
        .unwrap();

        assert_eq!(positive_doc(&cache, &did), published);
        // Observed 候选仍然可见(供 lazy verify / 诊断),但查询永远优先 verified。
        assert_eq!(cache.observed_candidate(&did, None).unwrap().0, observed);
    }

    /// promote:文件从 unverified/ 移动到 verified/,证据打 Verified,source 保留。
    #[test]
    fn fs_promote_moves_files_between_directories() {
        let (tmp_dir, cache, did) = setup_fs_cache();
        let now = buckyos_get_unix_timestamp();
        let doc = build_zone_doc(&did, now + 1000, "to-promote");
        assert_eq!(
            cache.update_observed(
                did.clone(),
                None,
                doc.clone(),
                now + 1000,
                Some("UdpDiscovery".to_string()),
            ),
            CacheWriteOutcome::Inserted
        );
        let key = did_cache_key(&did);
        assert!(tmp_dir
            .path()
            .join("unverified")
            .join(format!("{}.doc.json", key))
            .exists());

        assert!(cache.promote_observed(&did, None, now + 1000));

        assert!(!tmp_dir
            .path()
            .join("unverified")
            .join(format!("{}.doc.json", key))
            .exists());
        assert!(!tmp_dir
            .path()
            .join("unverified")
            .join(format!("{}.meta.json", key))
            .exists());
        assert!(tmp_dir
            .path()
            .join("verified")
            .join(format!("{}.doc.json", key))
            .exists());
        match cache.lookup(&did, None).unwrap() {
            CacheLookup::Positive {
                doc: loaded,
                evidence,
                source,
                ..
            } => {
                assert_eq!(loaded, doc);
                assert_eq!(evidence, CacheEvidence::Verified);
                assert_eq!(source.as_deref(), Some("UdpDiscovery"));
            }
            other => panic!("unexpected {:?}", other),
        }
    }

    /// promote 阶段 merge_allows 失败(verified/ 已有更优记录)时,unverified/
    /// 源文件被清理,不会无限堆积(测试要求 9)。
    fn assert_promote_merge_reject_cleans_observed(cache: &DIDDocumentCache, did: &DID) {
        let now = buckyos_get_unix_timestamp();
        let published = build_zone_doc(did, now + 2000, "published-better");
        cache.insert(
            did.clone(),
            None,
            published.clone(),
            now + 2000,
            CacheEvidence::Published,
        );
        let observed = build_zone_doc(did, now + 1000, "observed-worse");
        cache.update_observed(did.clone(), None, observed, now + 1000, None);
        assert!(cache.observed_candidate(did, None).is_some());

        assert!(!cache.promote_observed(did, None, now + 1000));
        assert!(
            cache.observed_candidate(did, None).is_none(),
            "rejected observed candidate should be cleaned up"
        );
        assert_eq!(positive_doc(cache, did), published);
    }

    #[test]
    fn fs_promote_merge_reject_cleans_observed() {
        let (_tmp, cache, did) = setup_fs_cache();
        assert_promote_merge_reject_cleans_observed(&cache, &did);
    }

    #[test]
    fn mem_promote_merge_reject_cleans_observed() {
        let (cache, did) = setup_mem_cache();
        assert_promote_merge_reject_cleans_observed(&cache, &did);
    }

    // ---- key 布局 ----

    fn assert_path_did_does_not_collide_with_host_did(cache: &DIDDocumentCache) {
        let host_did = DID::from_str("did:web:example.com").unwrap();
        let path_did = DID::from_str("did:web:example.com:abc:bcd").unwrap();
        let now = buckyos_get_unix_timestamp();
        let exp = now + DEFAULT_EXPIRE_TIME;
        let host_doc = build_zone_doc(&host_did, exp, "host");
        let path_doc = build_zone_doc(&path_did, exp, "path");

        cache.insert(
            host_did.clone(),
            None,
            host_doc.clone(),
            exp,
            CacheEvidence::Published,
        );
        cache.insert(
            path_did.clone(),
            None,
            path_doc.clone(),
            exp,
            CacheEvidence::Published,
        );

        assert_eq!(cache.get(&host_did, None).unwrap().0, host_doc);
        assert_eq!(cache.get(&path_did, None).unwrap().0, path_doc);
    }

    #[test]
    fn fs_cache_uses_filename_key_for_path_did() {
        let (tmp_dir, cache, _) = setup_fs_cache();
        assert_path_did_does_not_collide_with_host_did(&cache);

        let path_did = DID::from_str("did:web:example.com:abc:bcd").unwrap();
        assert_eq!(did_cache_key(&path_did), "example.com%2Fabc%2Fbcd");
        assert!(tmp_dir
            .path()
            .join("verified")
            .join(format!("{}.doc.json", did_cache_key(&path_did)))
            .exists());
    }

    #[test]
    fn mem_cache_uses_filename_key_for_path_did() {
        let (cache, _) = setup_mem_cache();
        assert_path_did_does_not_collide_with_host_did(&cache);
    }

    // ---- 兼容:旧平铺布局迁移 ----

    #[test]
    fn fs_legacy_flat_layout_is_migrated_by_meta_evidence() {
        let tmp_dir = tempdir().unwrap();
        let did = DID::from_str("did:web:example.com").unwrap();
        let observed_did = DID::from_str("did:web:observed.example").unwrap();
        let now = buckyos_get_unix_timestamp();

        // 旧版根目录平铺文件:带 Published meta 的、带 Unverified meta 的、
        // 以及没有 meta 的手工种子。
        let published_doc = build_zone_doc(&did, now + 1000, "legacy-published");
        let key = did_cache_key(&did);
        fs::write(
            tmp_dir.path().join(format!("{}.doc.json", key)),
            published_doc.to_string(),
        )
        .unwrap();
        // 旧版 meta 格式:只有 trust_level / exp / update_from_remote_time,
        // 缺证据字段按 serde default(Published)读出。
        fs::write(
            tmp_dir.path().join(format!("{}.meta.json", key)),
            format!(
                "{{\"trust_level\":0,\"exp\":{},\"update_from_remote_time\":{}}}",
                now + 1000,
                now
            ),
        )
        .unwrap();

        let observed_doc = build_zone_doc(&observed_did, now + 1000, "legacy-observed");
        let observed_key = did_cache_key(&observed_did);
        fs::write(
            tmp_dir.path().join(format!("{}.doc.json", observed_key)),
            observed_doc.to_string(),
        )
        .unwrap();

        let cache = DIDDocumentCache::new(Some(tmp_dir.path().to_path_buf()));

        // Published meta → verified/,证据保持 Published。
        assert!(tmp_dir
            .path()
            .join("verified")
            .join(format!("{}.doc.json", key))
            .exists());
        match cache.lookup(&did, None).unwrap() {
            CacheLookup::Positive { evidence, exp, .. } => {
                assert_eq!(evidence, CacheEvidence::Published);
                assert_eq!(exp, now + 1000);
            }
            other => panic!("unexpected {:?}", other),
        }

        // 手工种子(无 meta)→ unverified/,证据钳制为 Unverified。
        assert!(tmp_dir
            .path()
            .join("unverified")
            .join(format!("{}.doc.json", observed_key))
            .exists());
        match cache.lookup(&observed_did, None).unwrap() {
            CacheLookup::Positive { evidence, .. } => {
                assert_eq!(evidence, CacheEvidence::Unverified);
            }
            other => panic!("unexpected {:?}", other),
        }
    }

    /// verified/ 目录里 doc-only(无 meta)按受控本地种子(Published 档)对待:
    /// 能写 verified/ 的都是受控写者,"谁写的"由部署方权限配置负责,
    /// doc_cache 自身不在应用层重新校验(测试要求 8)。
    #[test]
    fn fs_verified_dir_trusts_hand_placed_meta_by_design() {
        let (tmp_dir, cache, did) = setup_fs_cache();
        let now = buckyos_get_unix_timestamp();
        let doc = build_zone_doc(&did, now + 1000, "op-seed");
        let key = did_cache_key(&did);
        let verified_dir = tmp_dir.path().join("verified");
        fs::write(
            verified_dir.join(format!("{}.doc.json", key)),
            doc.to_string(),
        )
        .unwrap();
        fs::write(
            verified_dir.join(format!("{}.meta.json", key)),
            format!("{{\"evidence\":\"Published\",\"exp\":{}}}", now + 1000),
        )
        .unwrap();

        match cache.lookup(&did, None).unwrap() {
            CacheLookup::Positive { evidence, .. } => {
                assert_eq!(evidence, CacheEvidence::Published);
            }
            other => panic!("unexpected {:?}", other),
        }
    }
}
