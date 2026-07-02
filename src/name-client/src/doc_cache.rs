use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::RwLock;
use std::time::UNIX_EPOCH;

use buckyos_kit::{
    buckyos_get_unix_timestamp, get_buckyos_service_local_data_dir, get_buckyos_system_etc_dir,
};
use log::{debug, error, info, warn};
use name_lib::{DIDDocumentTrait, EncodedDocument, OwnerDocument, DEFAULT_EXPIRE_TIME, DID};
use rusqlite::{params, Connection, OpenFlags};
use serde::{Deserialize, Serialize};

use crate::{BodyEvidence, DidDocType, DocumentStatus};

/// 负状态条目的重查间隔:in-TTL 内快路径直接报错;过期后允许重新询问权威源
/// (只有权威源的新回答能翻篇),但在权威源没回答时它仍然屏蔽一切兜底。
const NEGATIVE_STATE_TTL_SECS: u64 = 3600;

/// 支持三种存储后端的 DID 文档缓存。后端只是 KV(load/store/remove/scan),
/// 证据等级、负状态屏蔽、version/iat 比较、owner replay guard 全部在统一层实现
/// (简化 TODO T2.3)。
#[derive(Clone, Copy, Debug)]
pub enum CacheBackend {
    Filesystem,
    Sqlite,
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
    /// 未经验证(push、update_did_cache 等旁路写入)。
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

fn default_cache_evidence() -> CacheEvidence {
    // 旧版缓存条目没有证据字段:它们都是老验证路径写入的结果,按已发布档对待,
    // 保持与旧行为最接近的合并偏好。
    CacheEvidence::Published
}

/// 统一的持久化条目:正条目(带 doc)或负条目(带 negative_status)。
/// 字段全部带 serde default,旧版 meta 文件/表可以直接读出。
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

/// 统一层的查询结果。负状态"命中"不受 TTL 约束地存在:in_ttl 只影响快路径,
/// 过期的负状态仍然屏蔽兜底,只能被权威源的新回答翻篇。
#[derive(Clone, Debug)]
pub enum CacheLookup {
    Positive {
        doc: EncodedDocument,
        exp: u64,
        evidence: CacheEvidence,
        in_ttl: bool,
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
    Db(DbStore),
    Mem(MemStore),
}

impl DIDDocumentCache {
    /// 默认文件缓存(保持兼容)。
    pub fn new(cache_dir: Option<PathBuf>) -> Self {
        Self {
            backend: Backend::Fs(FsStore::new(cache_dir)),
        }
    }

    /// 显式创建 SQLite 缓存。
    pub fn new_db(cache_dir: Option<PathBuf>) -> name_lib::NSResult<Self> {
        Ok(Self {
            backend: Backend::Db(DbStore::new(cache_dir)?),
        })
    }

    /// 显式创建 Memory 缓存(测试用)。
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

    // ---- 后端 KV 转发 ----

    fn load(&self, key: &str) -> Option<StoredEntry> {
        match &self.backend {
            Backend::Fs(store) => store.load(key),
            Backend::Db(store) => store.load(key),
            Backend::Mem(store) => store.load(key),
        }
    }

    fn store(&self, did: &DID, key: &str, entry: &StoredEntry) {
        match &self.backend {
            Backend::Fs(store) => store.store(key, entry),
            Backend::Db(store) => store.store(did, key, entry),
            Backend::Mem(store) => store.store(key, entry),
        }
    }

    fn remove(&self, key: &str) {
        match &self.backend {
            Backend::Fs(store) => store.remove(key),
            Backend::Db(store) => store.remove(key),
            Backend::Mem(store) => store.remove(key),
        }
    }

    fn keys_for_did(&self, did: &DID) -> Vec<String> {
        let did_key = did_cache_key(did);
        match &self.backend {
            Backend::Fs(store) => store.keys_with_prefix(&did_key),
            Backend::Db(store) => store.keys_for_did(&did_key),
            Backend::Mem(store) => store.keys_with_prefix(&did_key),
        }
    }

    // ---- 统一层逻辑 ----

    /// 查询条目(不做任何删除;过期条目保留给策略点④的 stale 兜底判断)。
    pub fn lookup(&self, did: &DID, doc_type: Option<DidDocType>) -> Option<CacheLookup> {
        let key = combine_key(did, doc_type.as_ref());
        let entry = self.load(&key)?;
        let in_ttl = !is_expired(entry.exp());
        if entry.is_negative() {
            let status = entry.meta.negative_status.clone().unwrap_or_default();
            let message = entry
                .meta
                .negative_message
                .clone()
                .unwrap_or_else(|| format!("{}#{} is {}", did.to_string(), doc_type_str(doc_type.as_ref()), status));
            return Some(CacheLookup::Negative {
                status,
                message,
                in_ttl,
            });
        }
        let exp = entry.exp();
        let evidence = entry.meta.evidence;
        let doc = entry.doc?;
        Some(CacheLookup::Positive {
            doc,
            exp,
            evidence,
            in_ttl,
        })
    }

    /// 兼容读取:只返回正条目 (doc, exp, evidence_rank)。
    pub fn get(&self, did: &DID, doc_type: Option<DidDocType>) -> Option<(EncodedDocument, u64, i32)> {
        match self.lookup(did, doc_type)? {
            CacheLookup::Positive { doc, exp, evidence, .. } => {
                Some((doc, exp, evidence.rank() as i32))
            }
            CacheLookup::Negative { .. } => None,
        }
    }

    /// 合并写入(简化文档第 5 节的 did_cache_update):
    /// 负状态与本地覆盖屏蔽一切合并写入(本地覆盖根本不进这里);
    /// 先比证据等级,同级才比 version_seq / iat。
    pub fn update(
        &self,
        did: DID,
        doc_type: Option<DidDocType>,
        doc: EncodedDocument,
        exp: u64,
        evidence: CacheEvidence,
    ) -> bool {
        if self
            .validate_owner_revocation(&did, doc_type.clone(), &doc)
            .is_err()
        {
            return false;
        }

        let key = combine_key(&did, doc_type.as_ref());
        if let Some(current) = self.load(&key) {
            if !merge_allows(&did, &current, &doc, evidence) {
                return false;
            }
        }
        self.write_positive(&did, &key, doc_type.as_ref(), doc, exp, evidence);
        true
    }

    /// 无条件写入(种子/测试/本地运维用):跳过合并比较,但 owner replay guard
    /// 与吊销联动清理仍然生效。
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
    ) {
        let owner_document = parse_owner_document_doc(doc_type, &doc);
        let entry = StoredEntry {
            doc: Some(doc),
            meta: StoredMeta {
                evidence,
                negative_status: None,
                negative_message: None,
                exp: Some(exp),
                update_from_remote_time: Some(buckyos_get_unix_timestamp()),
            },
        };
        self.store(did, key, &entry);

        // 新 owner 文档落地时,联动清理被它的 replay guard 判定吊销的旧文档。
        if let Some(owner_document) = owner_document {
            self.evict_revoked_docs(did, doc_type, &owner_document);
        }
    }

    /// 策略点①的缓存动作:删除 positive、写入负状态条目、屏蔽后续 fallback。
    /// 负状态是"回答",不是 cache miss。
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
            },
        };
        self.store(did, &key, &entry);
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
            },
        };
        self.store(did, &key, &entry);
    }

    /// owner 文档声明的 replay guard(valid_iat / mini_version_seq)对读写两侧生效。
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
            let entry = self.load(&key)?;
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
            let Some(entry) = self.load(&key) else {
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

/// merge 规则(简化文档第 5 节):负状态屏蔽一切,只有权威源的新 DR(Published
/// 证据)能翻篇;否则先比证据等级,同级才比 version_seq / iat。
fn merge_allows(
    did: &DID,
    current: &StoredEntry,
    new_doc: &EncodedDocument,
    new_evidence: CacheEvidence,
) -> bool {
    if current.is_negative() {
        return new_evidence == CacheEvidence::Published;
    }
    let Some(current_doc) = current.doc.as_ref() else {
        return true;
    };

    let current_rank = current.meta.evidence.rank();
    let new_rank = new_evidence.rank();
    if new_rank != current_rank {
        return new_rank > current_rank;
    }

    // 同级:比 version_seq,没有 version_seq 时比 iat(保持既有语义,包括
    // did:dev 命名对象"无版本则不可替换"的保护)。
    let current_version_seq = get_doc_version_seq(current_doc);
    let new_version_seq = get_doc_version_seq(new_doc);
    match (current_version_seq, new_version_seq) {
        (Some(current), Some(new)) => return new > current,
        (Some(_), None) => return false,
        (None, Some(_)) => return true,
        (None, None) => {}
    }

    if did.is_named_obj_id() {
        return false;
    }

    let new_iat = get_doc_iat(new_doc);
    let current_iat = get_doc_iat(current_doc);
    new_iat > current_iat
}

// ------------------------ 文件系统后端(纯 KV) ------------------------
//
// 磁盘布局保持旧格式:`{key}.doc.json` 存文档原文(负条目没有这个文件),
// `{key}.meta.json` 存 StoredMeta。旧版 meta 缺证据字段时按 serde default 读出;
// 只有 doc 文件没有 meta 的手工放置文件按"从未从远端更新过"的本地种子对待。

struct FsStore {
    cache_dir: PathBuf,
}

impl FsStore {
    fn new(cache_dir: Option<PathBuf>) -> Self {
        let cache_dir = cache_dir.unwrap_or_else(DIDDocumentCache::get_default_cache_dir);
        info!("doc cache directory: {}", cache_dir.display());
        if let Err(err) = fs::create_dir_all(&cache_dir) {
            error!(
                "Failed to prepare doc cache directory {}: {}",
                cache_dir.display(),
                err
            );
        }
        Self { cache_dir }
    }

    fn doc_path(&self, key: &str) -> PathBuf {
        self.cache_dir.join(format!("{}.doc.json", key))
    }

    fn meta_path(&self, key: &str) -> PathBuf {
        self.cache_dir.join(format!("{}.meta.json", key))
    }

    fn load(&self, key: &str) -> Option<StoredEntry> {
        let meta = self.load_meta(key);
        let doc = self.load_doc(key);

        match (doc, meta) {
            (doc, Some(meta)) => {
                if meta.negative_status.is_none() && doc.is_none() {
                    return None;
                }
                Some(StoredEntry { doc, meta })
            }
            (Some(doc), None) => {
                // 手工放置的本地种子文件:没有 meta,视为"从未从远端更新过",
                // 过期时间退化为文件修改时间 + 24h。
                let default_exp = fs::metadata(self.doc_path(key))
                    .ok()
                    .and_then(|m| m.modified().ok())
                    .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                    .map(|d| d.as_secs() + 3600 * 24);
                Some(StoredEntry {
                    doc: Some(doc),
                    meta: StoredMeta {
                        evidence: default_cache_evidence(),
                        negative_status: None,
                        negative_message: None,
                        exp: default_exp,
                        update_from_remote_time: None,
                    },
                })
            }
            (None, None) => None,
        }
    }

    fn load_doc(&self, key: &str) -> Option<EncodedDocument> {
        let file_path = self.doc_path(key);
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

    fn load_meta(&self, key: &str) -> Option<StoredMeta> {
        let meta_path = self.meta_path(key);
        match fs::read_to_string(&meta_path) {
            Ok(content) => match serde_json::from_str::<StoredMeta>(&content) {
                Ok(meta) => Some(meta),
                Err(err) => {
                    warn!("failed to parse did doc meta {}: {}", meta_path.display(), err);
                    None
                }
            },
            Err(err) => {
                if err.kind() != std::io::ErrorKind::NotFound {
                    warn!("failed to read did doc meta {}: {}", meta_path.display(), err);
                }
                None
            }
        }
    }

    fn store(&self, key: &str, entry: &StoredEntry) {
        match entry.doc.as_ref() {
            Some(doc) => {
                let file_path = self.doc_path(key);
                if let Err(err) = fs::write(&file_path, doc.to_string()) {
                    error!(
                        "write did doc to local cache failed: {}, {}",
                        file_path.display(),
                        err
                    );
                }
            }
            None => {
                // 负条目没有 doc 文件。
                let _ = fs::remove_file(self.doc_path(key));
            }
        }
        if let Ok(content) = serde_json::to_string(&entry.meta) {
            if let Err(err) = fs::write(self.meta_path(key), content) {
                warn!("write did doc meta to local cache failed: {}", err);
            }
        }
    }

    fn remove(&self, key: &str) {
        for path in [self.doc_path(key), self.meta_path(key)] {
            if let Err(err) = fs::remove_file(&path) {
                if err.kind() != std::io::ErrorKind::NotFound {
                    warn!("failed to remove did cache file {}: {}", path.display(), err);
                }
            }
        }
    }

    fn keys_with_prefix(&self, did_key: &str) -> Vec<String> {
        let entries = match fs::read_dir(&self.cache_dir) {
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

// ------------------------ SQLite 后端(纯 KV) ------------------------

struct DbStore {
    db_path: PathBuf,
}

impl DbStore {
    fn new(cache_dir: Option<PathBuf>) -> name_lib::NSResult<Self> {
        let base_dir = cache_dir.unwrap_or_else(|| get_buckyos_service_local_data_dir("did_docs"));
        if let Err(err) = fs::create_dir_all(&base_dir) {
            return Err(name_lib::NSError::ReadLocalFileError(format!(
                "prepare sqlite cache dir failed: {}",
                err
            )));
        }
        let store = Self {
            db_path: base_dir.join("did_docs.sqlite"),
        };
        store.init_schema()?;
        Ok(store)
    }

    fn open_conn(&self) -> rusqlite::Result<Connection> {
        Connection::open_with_flags(
            &self.db_path,
            OpenFlags::SQLITE_OPEN_CREATE | OpenFlags::SQLITE_OPEN_READ_WRITE,
        )
    }

    fn init_schema(&self) -> name_lib::NSResult<()> {
        let conn = self.open_conn().map_err(|e| {
            name_lib::NSError::ReadLocalFileError(format!("open sqlite failed: {}", e))
        })?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS did_docs (
                doc_key TEXT PRIMARY KEY,
                did TEXT NOT NULL,
                doc_type TEXT NOT NULL,
                doc TEXT NOT NULL,
                exp INTEGER NOT NULL,
                trust_level INTEGER NOT NULL DEFAULT 0,
                update_from_remote_time INTEGER,
                evidence TEXT,
                negative_status TEXT,
                negative_message TEXT
            )",
            [],
        )
        .map_err(|e| {
            name_lib::NSError::ReadLocalFileError(format!("create table failed: {}", e))
        })?;

        // 旧库的 schema 迁移:补齐新列。
        for column in ["update_from_remote_time INTEGER", "evidence TEXT", "negative_status TEXT", "negative_message TEXT"] {
            let column_name = column.split(' ').next().unwrap();
            if !Self::has_column(&conn, column_name).map_err(|e| {
                name_lib::NSError::ReadLocalFileError(format!("inspect table failed: {}", e))
            })? {
                conn.execute(&format!("ALTER TABLE did_docs ADD COLUMN {}", column), [])
                    .map_err(|e| {
                        name_lib::NSError::ReadLocalFileError(format!(
                            "migrate table failed: {}",
                            e
                        ))
                    })?;
            }
        }
        Ok(())
    }

    fn has_column(conn: &Connection, column: &str) -> rusqlite::Result<bool> {
        let mut stmt = conn.prepare("PRAGMA table_info(did_docs)")?;
        let column_iter = stmt.query_map([], |row| row.get::<_, String>(1))?;
        for col_name in column_iter.flatten() {
            if col_name == column {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn load(&self, key: &str) -> Option<StoredEntry> {
        let conn = self.open_conn().ok()?;
        let mut stmt = conn
            .prepare(
                "SELECT doc, exp, update_from_remote_time, evidence, negative_status, negative_message
                 FROM did_docs WHERE doc_key = ?1",
            )
            .ok()?;
        let row = stmt
            .query_row(params![key], |row| {
                let doc_str: String = row.get(0)?;
                let exp: i64 = row.get(1)?;
                let update_from_remote_time: Option<i64> = row.get(2).unwrap_or(None);
                let evidence: Option<String> = row.get(3).unwrap_or(None);
                let negative_status: Option<String> = row.get(4).unwrap_or(None);
                let negative_message: Option<String> = row.get(5).unwrap_or(None);
                Ok((
                    doc_str,
                    exp as u64,
                    update_from_remote_time.map(|v| v as u64),
                    evidence,
                    negative_status,
                    negative_message,
                ))
            })
            .ok()?;

        let (doc_str, exp, update_from_remote_time, evidence, negative_status, negative_message) =
            row;
        let evidence = evidence
            .and_then(|value| serde_json::from_value(serde_json::Value::String(value)).ok())
            .unwrap_or_else(default_cache_evidence);
        let doc = if doc_str.is_empty() {
            None
        } else {
            EncodedDocument::from_str(doc_str).ok()
        };
        if negative_status.is_none() && doc.is_none() {
            return None;
        }
        Some(StoredEntry {
            doc,
            meta: StoredMeta {
                evidence,
                negative_status,
                negative_message,
                exp: Some(exp),
                update_from_remote_time,
            },
        })
    }

    fn store(&self, did: &DID, key: &str, entry: &StoredEntry) {
        let conn = match self.open_conn() {
            Ok(c) => c,
            Err(err) => {
                warn!("open sqlite cache failed: {}", err);
                return;
            }
        };
        let doc_type = key
            .strip_prefix(&format!("{}#", did_cache_key(did)))
            .unwrap_or("")
            .to_string();
        let evidence = serde_json::to_value(entry.meta.evidence)
            .ok()
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .unwrap_or_else(|| "Published".to_string());
        if let Err(err) = conn.execute(
            "INSERT INTO did_docs (doc_key, did, doc_type, doc, exp, trust_level, update_from_remote_time, evidence, negative_status, negative_message)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
             ON CONFLICT(doc_key) DO UPDATE SET doc = excluded.doc, exp = excluded.exp,
                 update_from_remote_time = excluded.update_from_remote_time,
                 evidence = excluded.evidence,
                 negative_status = excluded.negative_status,
                 negative_message = excluded.negative_message",
            params![
                key,
                did_cache_key(did),
                doc_type,
                entry
                    .doc
                    .as_ref()
                    .map(|doc| doc.to_string())
                    .unwrap_or_default(),
                entry.exp() as i64,
                entry.meta.evidence.rank() as i32,
                entry.meta.update_from_remote_time.map(|v| v as i64),
                evidence,
                entry.meta.negative_status,
                entry.meta.negative_message,
            ],
        ) {
            warn!("write did doc sqlite cache failed: {}", err);
        }
    }

    fn remove(&self, key: &str) {
        let conn = match self.open_conn() {
            Ok(c) => c,
            Err(err) => {
                warn!("open sqlite cache failed when delete: {}", err);
                return;
            }
        };
        if let Err(err) = conn.execute("DELETE FROM did_docs WHERE doc_key = ?1", params![key]) {
            warn!("delete did doc sqlite cache failed: {}", err);
        }
    }

    fn keys_for_did(&self, did_key: &str) -> Vec<String> {
        let conn = match self.open_conn() {
            Ok(c) => c,
            Err(_) => return Vec::new(),
        };
        let mut stmt = match conn.prepare("SELECT doc_key FROM did_docs WHERE did = ?1") {
            Ok(stmt) => stmt,
            Err(_) => return Vec::new(),
        };
        let rows = match stmt.query_map(params![did_key], |row| row.get::<_, String>(0)) {
            Ok(rows) => rows,
            Err(_) => return Vec::new(),
        };
        rows.flatten().collect()
    }
}

// ------------------------ 内存后端(纯 KV,测试用) ------------------------

struct MemStore {
    entries: std::sync::Arc<RwLock<HashMap<String, StoredEntry>>>,
}

impl MemStore {
    fn new() -> Self {
        Self {
            entries: std::sync::Arc::new(RwLock::new(HashMap::new())),
        }
    }

    fn load(&self, key: &str) -> Option<StoredEntry> {
        self.entries.read().ok()?.get(key).cloned()
    }

    fn store(&self, key: &str, entry: &StoredEntry) {
        if let Ok(mut guard) = self.entries.write() {
            guard.insert(key.to_string(), entry.clone());
        }
    }

    fn remove(&self, key: &str) {
        if let Ok(mut guard) = self.entries.write() {
            guard.remove(key);
        }
    }

    fn keys_with_prefix(&self, did_key: &str) -> Vec<String> {
        match self.entries.read() {
            Ok(guard) => guard
                .keys()
                .filter(|key| {
                    key.as_str() == did_key || key.starts_with(&format!("{}#", did_key))
                })
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
/// 不受 `Missing`/`revoke_before_iat` 等 Document 门禁间接门控,只按 ttl 判断可用性;
/// 与 `DIDDocumentCache`(verified cache 的角色)完全隔离,不参与它的持久化/合并逻辑。
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

fn get_doc_version_seq(doc: &EncodedDocument) -> Option<u64> {
    extract_timestamp(doc, "version_seq")
}

fn get_doc_iat(doc: &EncodedDocument) -> Option<u64> {
    let iat = extract_timestamp(doc, "iat");
    if iat.is_some() {
        return iat;
    }
    let exp = extract_timestamp(doc, "exp");
    if exp.is_some() {
        let exp_ts = exp.unwrap();
        let iat_ts = exp_ts - DEFAULT_EXPIRE_TIME;
        return Some(iat_ts);
    }
    None
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
    use name_lib::{
        DIDDocumentTrait, NSError, OwnerDocument, ZoneBootDocument, DEFAULT_EXPIRE_TIME,
    };
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

    fn setup_db_cache() -> (tempfile::TempDir, DIDDocumentCache, DID) {
        let tmp_dir = tempdir().unwrap();
        let cache = DIDDocumentCache::new_db(Some(tmp_dir.path().to_path_buf())).unwrap();
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

    // ---- 基本读写(三种后端) ----

    fn assert_roundtrip_with_evidence(cache: &DIDDocumentCache, did: &DID) {
        let now = buckyos_get_unix_timestamp();
        let exp = now + DEFAULT_EXPIRE_TIME;
        let doc = build_zone_doc(did, exp, "roundtrip");
        assert!(cache.update(did.clone(), None, doc.clone(), exp, CacheEvidence::Verified));
        match cache.lookup(did, None).unwrap() {
            CacheLookup::Positive {
                doc: loaded,
                exp: loaded_exp,
                evidence,
                in_ttl,
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
    fn db_roundtrip_preserves_evidence() {
        let (_tmp, cache, did) = setup_db_cache();
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
        assert!(cache.update(did.clone(), None, doc, exp, CacheEvidence::Published));

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

        // 负状态屏蔽普通写入(push / 已验证自签名都不行)。
        let newer = build_zone_doc(did, exp + 10, "shadow");
        assert!(!cache.update(did.clone(), None, newer.clone(), exp + 10, CacheEvidence::Verified));
        assert!(!cache.update(did.clone(), None, newer.clone(), exp + 10, CacheEvidence::Unverified));
        assert!(cache.lookup(did, None).unwrap().is_negative());

        // 只有权威源的新 DR(Published 证据)能翻篇。
        assert!(cache.update(did.clone(), None, newer.clone(), exp + 10, CacheEvidence::Published));
        assert_eq!(positive_doc(cache, did), newer);
    }

    #[test]
    fn fs_negative_state_blocks_and_flips() {
        let (_tmp, cache, did) = setup_fs_cache();
        assert_negative_state_blocks_and_flips(&cache, &did);
    }

    #[test]
    fn db_negative_state_blocks_and_flips() {
        let (_tmp, cache, did) = setup_db_cache();
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
        assert!(cache.update(did.clone(), None, published.clone(), exp, CacheEvidence::Published));

        // 更新鲜的自签名(哪怕 iat 更大)压不过已发布条目。
        let fresher_self_signed = build_zone_doc(&did, exp + 1000, "self-signed-newer");
        assert!(!cache.update(
            did.clone(),
            None,
            fresher_self_signed,
            exp + 1000,
            CacheEvidence::Verified
        ));
        assert_eq!(positive_doc(&cache, &did), published);

        // 未验证 push 更不行。
        let pushed = build_zone_doc(&did, exp + 2000, "pushed");
        assert!(!cache.update(did.clone(), None, pushed, exp + 2000, CacheEvidence::Unverified));

        // 同级(已发布)才比新旧。
        let newer_published = build_zone_doc(&did, exp + 3000, "published-new");
        assert!(cache.update(
            did.clone(),
            None,
            newer_published.clone(),
            exp + 3000,
            CacheEvidence::Published
        ));
        assert_eq!(positive_doc(&cache, &did), newer_published);
    }

    #[test]
    fn same_rank_prefers_version_seq_over_iat() {
        let (cache, did) = setup_mem_cache();
        let now = buckyos_get_unix_timestamp();

        let doc_v2 = EncodedDocument::JsonLd(json!({
            "version_seq": 2, "iat": now, "exp": now + DEFAULT_EXPIRE_TIME, "marker": "v2"
        }));
        assert!(cache.update(did.clone(), None, doc_v2.clone(), now + DEFAULT_EXPIRE_TIME, CacheEvidence::Verified));

        // iat 更新但 version_seq 更小:拒绝。
        let doc_v1 = EncodedDocument::JsonLd(json!({
            "version_seq": 1, "iat": now + 10_000, "exp": now + DEFAULT_EXPIRE_TIME + 10_000, "marker": "v1"
        }));
        assert!(!cache.update(did.clone(), None, doc_v1, now + DEFAULT_EXPIRE_TIME + 10_000, CacheEvidence::Verified));

        // 有版本的条目拒绝无版本的更新。
        let unversioned = EncodedDocument::JsonLd(json!({
            "iat": now + 20_000, "exp": now + DEFAULT_EXPIRE_TIME + 20_000, "marker": "unversioned"
        }));
        assert!(!cache.update(did.clone(), None, unversioned, now + DEFAULT_EXPIRE_TIME + 20_000, CacheEvidence::Verified));

        assert_eq!(positive_doc(&cache, &did), doc_v2);
    }

    #[test]
    fn named_obj_without_version_is_immutable() {
        let (cache, _) = setup_mem_cache();
        let did = DID::from_str("did:dev:5bUuyWLOKyCre9az_IhJVIuOw8bA0gyKjstcYGHbaPE").unwrap();
        let now = buckyos_get_unix_timestamp();

        let doc_v1 = EncodedDocument::JsonLd(json!({
            "iat": now, "exp": now + DEFAULT_EXPIRE_TIME, "marker": "v1"
        }));
        cache.insert(did.clone(), None, doc_v1.clone(), now + DEFAULT_EXPIRE_TIME, CacheEvidence::Verified);

        let doc_v2 = EncodedDocument::JsonLd(json!({
            "iat": now + 1000, "exp": now + DEFAULT_EXPIRE_TIME + 1000, "marker": "v2"
        }));
        assert!(!cache.update(did.clone(), None, doc_v2, now + DEFAULT_EXPIRE_TIME + 1000, CacheEvidence::Verified));
        assert_eq!(positive_doc(&cache, &did), doc_v1);
    }

    // ---- TTL:过期条目保留,标记 in_ttl=false ----

    #[test]
    fn expired_positive_entry_is_kept_for_stale_fallback() {
        let (cache, did) = setup_mem_cache();
        let past_exp = buckyos_get_unix_timestamp().saturating_sub(10);
        let doc = build_zone_doc(&did, past_exp, "stale");
        cache.insert(did.clone(), None, doc.clone(), past_exp, CacheEvidence::Published);

        match cache.lookup(&did, None).unwrap() {
            CacheLookup::Positive { doc: loaded, in_ttl, .. } => {
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
    fn db_owner_update_evicts_revoked_docs() -> Result<(), NSError> {
        let (_tmp_dir, cache, did) = setup_db_cache();
        assert_owner_update_evicts_revoked_docs(&cache, &did);
        Ok(())
    }

    #[test]
    fn db_owner_policy_rejects_new_revoked_doc() -> Result<(), NSError> {
        let (_tmp_dir, cache, did) = setup_db_cache();
        assert_owner_policy_rejects_new_revoked_doc(&cache, &did);
        Ok(())
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

    // ---- key 布局 ----

    fn assert_path_did_does_not_collide_with_host_did(cache: &DIDDocumentCache) {
        let host_did = DID::from_str("did:web:example.com").unwrap();
        let path_did = DID::from_str("did:web:example.com:abc:bcd").unwrap();
        let now = buckyos_get_unix_timestamp();
        let exp = now + DEFAULT_EXPIRE_TIME;
        let host_doc = build_zone_doc(&host_did, exp, "host");
        let path_doc = build_zone_doc(&path_did, exp, "path");

        cache.insert(host_did.clone(), None, host_doc.clone(), exp, CacheEvidence::Published);
        cache.insert(path_did.clone(), None, path_doc.clone(), exp, CacheEvidence::Published);

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
            .join(format!("{}.doc.json", did_cache_key(&path_did)))
            .exists());
    }

    #[test]
    fn db_cache_uses_filename_key_for_path_did() -> Result<(), NSError> {
        let (_tmp_dir, cache, _) = setup_db_cache();
        assert_path_did_does_not_collide_with_host_did(&cache);
        Ok(())
    }

    #[test]
    fn mem_cache_uses_filename_key_for_path_did() {
        let (cache, _) = setup_mem_cache();
        assert_path_did_does_not_collide_with_host_did(&cache);
    }

    // ---- 兼容:手工放置/旧格式 ----

    #[test]
    fn fs_hand_placed_doc_without_meta_is_local_seed() {
        let (tmp_dir, cache, did) = setup_fs_cache();
        let now = buckyos_get_unix_timestamp();
        let doc = build_zone_doc(&did, now + 100, "seed");
        fs::write(
            tmp_dir
                .path()
                .join(format!("{}.doc.json", did_cache_key(&did))),
            doc.to_string(),
        )
        .unwrap();

        match cache.lookup(&did, None).unwrap() {
            CacheLookup::Positive { doc: loaded, evidence, in_ttl, .. } => {
                assert_eq!(loaded, doc);
                assert_eq!(evidence, CacheEvidence::Published);
                assert!(in_ttl, "seed file exp derives from mtime + 24h");
            }
            other => panic!("unexpected {:?}", other),
        }
    }

    #[test]
    fn fs_legacy_meta_without_evidence_defaults_to_published() {
        let (tmp_dir, cache, did) = setup_fs_cache();
        let now = buckyos_get_unix_timestamp();
        let doc = build_zone_doc(&did, now + 1000, "legacy");
        let key = did_cache_key(&did);
        fs::write(
            tmp_dir.path().join(format!("{}.doc.json", key)),
            doc.to_string(),
        )
        .unwrap();
        // 旧版 meta 格式:只有 trust_level / exp / update_from_remote_time。
        fs::write(
            tmp_dir.path().join(format!("{}.meta.json", key)),
            format!(
                "{{\"trust_level\":0,\"exp\":{},\"update_from_remote_time\":{}}}",
                now + 1000,
                now
            ),
        )
        .unwrap();

        match cache.lookup(&did, None).unwrap() {
            CacheLookup::Positive { evidence, exp, .. } => {
                assert_eq!(evidence, CacheEvidence::Published);
                assert_eq!(exp, now + 1000);
            }
            other => panic!("unexpected {:?}", other),
        }
    }
}
