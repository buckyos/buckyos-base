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

use crate::{DidDocType, ROOT_TRUST_LEVEL};

/// 支持两种存储后端的 DID 文档缓存：文件系统和 SQLite。
/// 通过 `CacheBackend` 选择实现，默认推荐 SQLite 以避免大量小文件。
#[derive(Clone, Copy, Debug)]
pub enum CacheBackend {
    Filesystem,
    Sqlite,
    Memory,
}

pub enum DIDDocumentCache {
    Fs(DIDDocumentFsCache),
    Db(DIDDocumentDBCache),
    Mem(DIDDocumentMemCache),
}

impl DIDDocumentCache {
    /// 默认文件缓存（保持兼容）。
    pub fn new(cache_dir: Option<PathBuf>) -> Self {
        Self::Fs(DIDDocumentFsCache::new(cache_dir))
    }

    /// 显式创建 SQLite 缓存。
    pub fn new_db(cache_dir: Option<PathBuf>) -> name_lib::NSResult<Self> {
        Ok(Self::Db(DIDDocumentDBCache::new(cache_dir)?))
    }

    /// 显式创建 Memory 缓存（测试用）。
    pub fn new_mem() -> Self {
        Self::Mem(DIDDocumentMemCache::new())
    }

    pub fn get_default_cache_dir() -> PathBuf {
        DIDDocumentFsCache::get_default_cache_dir()
    }

    pub fn with_default_dir() -> Self {
        Self::Fs(DIDDocumentFsCache::with_default_dir())
    }

    pub fn default_dir() -> PathBuf {
        DIDDocumentFsCache::default_dir()
    }

    pub fn get(
        &self,
        did: &DID,
        doc_type: Option<DidDocType>,
    ) -> Option<(EncodedDocument, u64, i32)> {
        match self {
            Self::Fs(inner) => inner.get(did, doc_type.as_ref()),
            Self::Db(inner) => inner.get(did, doc_type.as_ref()),
            Self::Mem(inner) => inner.get(did, doc_type.as_ref()),
        }
    }

    pub fn update(
        &self,
        did: DID,
        doc_type: Option<DidDocType>,
        doc: EncodedDocument,
        exp: u64,
        trust_level: i32,
    ) -> bool {
        match self {
            Self::Fs(inner) => inner.update(did, doc_type.as_ref(), doc, exp, trust_level),
            Self::Db(inner) => inner.update(did, doc_type.as_ref(), doc, exp, trust_level),
            Self::Mem(inner) => inner.update(did, doc_type.as_ref(), doc, exp, trust_level),
        }
    }

    pub fn validate_owner_revocation(
        &self,
        did: &DID,
        doc_type: Option<DidDocType>,
        doc: &EncodedDocument,
    ) -> name_lib::NSResult<()> {
        match self {
            Self::Fs(inner) => inner.validate_owner_revocation(did, doc_type.as_ref(), doc),
            Self::Db(inner) => inner.validate_owner_revocation(did, doc_type.as_ref(), doc),
            Self::Mem(inner) => inner.validate_owner_revocation(did, doc_type.as_ref(), doc),
        }
    }

    pub fn insert(
        &self,
        did: DID,
        doc_type: Option<DidDocType>,
        doc: EncodedDocument,
        exp: u64,
        trust_level: i32,
    ) {
        match self {
            Self::Fs(inner) => inner.insert(did, doc_type.as_ref(), doc, exp, trust_level),
            Self::Db(inner) => inner.insert(did, doc_type.as_ref(), doc, exp, trust_level),
            Self::Mem(inner) => inner.insert(did, doc_type.as_ref(), doc, exp, trust_level),
        }
    }

    pub fn delete(&self, did: DID, doc_type: Option<DidDocType>) {
        match self {
            Self::Fs(inner) => inner.delete(did, doc_type.as_ref()),
            Self::Db(inner) => inner.delete(did, doc_type.as_ref()),
            Self::Mem(inner) => inner.delete(did, doc_type.as_ref()),
        }
    }
}

// ------------------------ 文件系统实现 ------------------------

#[derive(Clone)]
pub struct DIDDocumentFsCache {
    cache_dir: PathBuf,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct CacheMeta {
    trust_level: i32,
    exp: Option<u64>,
    #[serde(default)]
    update_from_remote_time: Option<u64>,
}

impl DIDDocumentFsCache {
    pub fn new(cache_dir: Option<PathBuf>) -> Self {
        let cache_dir = cache_dir.unwrap_or_else(Self::get_default_cache_dir);
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

    pub fn get_default_cache_dir() -> PathBuf {
        get_buckyos_service_local_data_dir("did_docs")
    }

    pub fn with_default_dir() -> Self {
        Self::new(Some(Self::default_dir()))
    }

    pub fn default_dir() -> PathBuf {
        get_buckyos_system_etc_dir().join("did_docs")
    }

    pub fn get(
        &self,
        did: &DID,
        doc_type: Option<&DidDocType>,
    ) -> Option<(EncodedDocument, u64, i32)> {
        let (doc, meta_fallback) = self.load_from_disk(did, doc_type)?;
        //默认的过期时间，使用磁盘文件的修改时间 + DEFAULT_EXPIRE_TIME
        let meta = self.load_meta(did, doc_type).unwrap_or(meta_fallback);
        let exp = meta
            .exp
            .or_else(|| extract_timestamp(&doc, "exp"))
            .unwrap_or_else(|| buckyos_get_unix_timestamp() + DEFAULT_EXPIRE_TIME);

        let trust_level = meta.trust_level;
        if is_expired(exp) {
            if meta.update_from_remote_time.is_some() {
                self.delete(did.clone(), doc_type);
                return None;
            } else {
                debug!(
                    "doc cache {}#{} expired but kept because never fetched from remote",
                    did.to_string(),
                    doc_type_str(doc_type)
                );
            }
        }
        Some((doc, exp, trust_level))
    }

    pub fn update(
        &self,
        did: DID,
        doc_type: Option<&DidDocType>,
        doc: EncodedDocument,
        exp: u64,
        trust_level: i32,
    ) -> bool {
        if self
            .validate_owner_revocation(&did, doc_type, &doc)
            .is_err()
        {
            return false;
        }

        if let Some((existing, _, current_trust)) = self.get(&did, doc_type) {
            if should_update_cached_doc(&did, &existing, current_trust, &doc, trust_level) {
                self.insert(did, doc_type, doc, exp, trust_level);
                return true;
            }
            return false;
        } else {
            self.insert(did, doc_type, doc, exp, trust_level);
            return true;
        }
    }

    pub fn insert(
        &self,
        did: DID,
        doc_type: Option<&DidDocType>,
        doc: EncodedDocument,
        exp: u64,
        trust_level: i32,
    ) {
        if self
            .validate_owner_revocation(&did, doc_type, &doc)
            .is_err()
        {
            return;
        }

        self.save_to_disk(&did, doc_type, &doc);
        self.save_meta(
            &did,
            doc_type,
            CacheMeta {
                trust_level,
                exp: Some(exp),
                update_from_remote_time: Some(buckyos_get_unix_timestamp()),
            },
        );

        if let Some(owner_document) = parse_owner_document_doc(doc_type, &doc) {
            self.evict_revoked_docs(&did, doc_type, &owner_document);
        }
    }

    pub fn delete(&self, did: DID, doc_type: Option<&DidDocType>) {
        self.delete_local_file(&did, doc_type);
        self.delete_meta(&did, doc_type);
    }

    fn load_from_disk(
        &self,
        did: &DID,
        doc_type: Option<&DidDocType>,
    ) -> Option<(EncodedDocument, CacheMeta)> {
        let file_path = self
            .cache_dir
            .join(format!("{}.doc.json", combine_key(did, doc_type)));

        match fs::read_to_string(&file_path) {
            Ok(content) => match EncodedDocument::from_str(content) {
                Ok(doc) => {
                    let default_exp = fs::metadata(&file_path)
                        .ok()
                        .and_then(|m| m.modified().ok())
                        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                        .map(|d| d.as_secs() + 3600 * 24);
                    let meta = CacheMeta {
                        trust_level: ROOT_TRUST_LEVEL,
                        exp: default_exp,
                        update_from_remote_time: None,
                    };
                    info!(
                        "load did-cache from {} success. meta: {:?}",
                        file_path.display(),
                        meta
                    );
                    Some((doc, meta))
                }
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

    fn save_to_disk(&self, did: &DID, doc_type: Option<&DidDocType>, doc: &EncodedDocument) {
        let file_path = self
            .cache_dir
            .join(format!("{}.doc.json", combine_key(did, doc_type)));
        if let Err(err) = fs::write(&file_path, doc.to_string()) {
            error!(
                "write did doc to local cache failed: {}, {}",
                file_path.display(),
                err
            );
        } else {
            debug!("stored did doc into local cache: {}", file_path.display());
        }
    }

    fn meta_path(&self, did: &DID, doc_type: Option<&DidDocType>) -> PathBuf {
        self.cache_dir
            .join(format!("{}.meta.json", combine_key(did, doc_type)))
    }

    fn save_meta(&self, did: &DID, doc_type: Option<&DidDocType>, meta: CacheMeta) {
        let meta_path = self.meta_path(did, doc_type);
        if let Ok(content) = serde_json::to_string(&meta) {
            if let Err(err) = fs::write(&meta_path, content) {
                warn!(
                    "write did doc meta to local cache failed: {}, {}",
                    meta_path.display(),
                    err
                );
            }
        }
    }

    fn load_meta(&self, did: &DID, doc_type: Option<&DidDocType>) -> Option<CacheMeta> {
        let meta_path = self.meta_path(did, doc_type);
        match fs::read_to_string(&meta_path) {
            Ok(content) => match serde_json::from_str::<CacheMeta>(&content) {
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

    fn delete_meta(&self, did: &DID, doc_type: Option<&DidDocType>) {
        let meta_path = self.meta_path(did, doc_type);
        match fs::remove_file(&meta_path) {
            Ok(_) => debug!("removed did doc meta: {}", meta_path.display()),
            Err(err) => {
                if err.kind() != std::io::ErrorKind::NotFound {
                    warn!(
                        "failed to remove did doc meta {}: {}",
                        meta_path.display(),
                        err
                    );
                }
            }
        }
    }

    fn delete_local_file(&self, did: &DID, doc_type: Option<&DidDocType>) {
        let file_path = self
            .cache_dir
            .join(format!("{}.doc.json", combine_key(did, doc_type)));
        match fs::remove_file(&file_path) {
            Ok(_) => debug!("removed expired did doc: {}", file_path.display()),
            Err(err) => {
                if err.kind() != std::io::ErrorKind::NotFound {
                    warn!("failed to remove did doc {}: {}", file_path.display(), err);
                }
            }
        }
    }

    pub fn validate_owner_revocation(
        &self,
        did: &DID,
        doc_type: Option<&DidDocType>,
        doc: &EncodedDocument,
    ) -> name_lib::NSResult<()> {
        if is_owner_doc(doc_type, doc) {
            return Ok(());
        }

        if let Some(owner_document) = self.load_cached_owner_document(did) {
            owner_document.validate_jwt_revocation(doc_type_str(doc_type), doc)?;
        }
        Ok(())
    }

    fn load_cached_owner_document(&self, did: &DID) -> Option<OwnerDocument> {
        self.load_from_disk(did, Some(&DidDocType::Owner))
            .and_then(|(doc, _)| parse_owner_document_doc(Some(&DidDocType::Owner), &doc))
            .or_else(|| {
                self.load_from_disk(did, None)
                    .and_then(|(doc, _)| parse_owner_document_doc(None, &doc))
            })
    }

    fn evict_revoked_docs(
        &self,
        did: &DID,
        owner_doc_type: Option<&DidDocType>,
        owner_document: &OwnerDocument,
    ) {
        let did_key = did_cache_key(did);
        let entries = match fs::read_dir(&self.cache_dir) {
            Ok(entries) => entries,
            Err(err) => {
                warn!(
                    "read did cache directory for revocation cleanup failed: {}",
                    err
                );
                return;
            }
        };

        for entry in entries.flatten() {
            let file_name = entry.file_name().to_string_lossy().to_string();
            let Some(doc_type) = doc_type_from_cache_file_name(&did_key, &file_name) else {
                continue;
            };
            if same_doc_type(doc_type.as_ref(), owner_doc_type) {
                continue;
            }

            let Some((doc, _)) = self.load_from_disk(did, doc_type.as_ref()) else {
                continue;
            };
            if owner_document
                .validate_jwt_revocation(doc_type_str(doc_type.as_ref()), &doc)
                .is_err()
            {
                self.delete(did.clone(), doc_type.as_ref());
            }
        }
    }
}

// ------------------------ SQLite 实现 ------------------------

pub struct DIDDocumentDBCache {
    db_path: PathBuf,
}

impl DIDDocumentDBCache {
    pub fn new(cache_dir: Option<PathBuf>) -> name_lib::NSResult<Self> {
        let db_path = Self::resolve_db_path(cache_dir)?;
        let cache = Self { db_path };
        cache.init_schema()?;
        Ok(cache)
    }

    pub fn get(
        &self,
        did: &DID,
        doc_type: Option<&DidDocType>,
    ) -> Option<(EncodedDocument, u64, i32)> {
        let conn = self.open_conn().ok()?;
        let mut stmt = conn
            .prepare(
                "SELECT doc, exp, trust_level, update_from_remote_time FROM did_docs WHERE doc_key = ?1",
            )
            .ok()?;
        let row = stmt
            .query_row(params![combine_key(did, doc_type)], |row| {
                let doc_str: String = row.get(0)?;
                let exp: i64 = row.get(1)?;
                let trust_level: i32 = row.get(2)?;
                let update_from_remote_time: Option<i64> = row.get(3).unwrap_or(None);
                Ok((
                    doc_str,
                    exp as u64,
                    trust_level,
                    update_from_remote_time.map(|v| v as u64),
                ))
            })
            .ok();

        let (doc_str, exp, trust_level, update_from_remote_time) = row?;
        let doc = EncodedDocument::from_str(doc_str).ok()?;
        if is_expired(exp) {
            if update_from_remote_time.is_some() {
                self.delete(did.clone(), doc_type);
                return None;
            } else {
                debug!(
                    "db doc cache {}#{} expired but kept because never fetched from remote",
                    did.to_string(),
                    doc_type_str(doc_type)
                );
            }
        }
        Some((doc, exp, trust_level))
    }

    pub fn update(
        &self,
        did: DID,
        doc_type: Option<&DidDocType>,
        doc: EncodedDocument,
        exp: u64,
        trust_level: i32,
    ) -> bool {
        if self
            .validate_owner_revocation(&did, doc_type, &doc)
            .is_err()
        {
            return false;
        }

        if let Some((existing, _, current_trust)) = self.get(&did, doc_type) {
            if should_update_cached_doc(&did, &existing, current_trust, &doc, trust_level) {
                self.insert(did, doc_type, doc, exp, trust_level);
                return true;
            }
            return false;
        } else {
            self.insert(did, doc_type, doc, exp, trust_level);
            return true;
        }
    }

    pub fn insert(
        &self,
        did: DID,
        doc_type: Option<&DidDocType>,
        doc: EncodedDocument,
        exp: u64,
        trust_level: i32,
    ) {
        if self
            .validate_owner_revocation(&did, doc_type, &doc)
            .is_err()
        {
            return;
        }

        let conn = match self.open_conn() {
            Ok(c) => c,
            Err(err) => {
                warn!("open sqlite cache failed: {}", err);
                return;
            }
        };
        if let Err(err) = conn.execute(
            "INSERT INTO did_docs (doc_key, did, doc_type, doc, exp, trust_level, update_from_remote_time) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(doc_key) DO UPDATE SET doc = excluded.doc, exp = excluded.exp, trust_level = excluded.trust_level, update_from_remote_time = excluded.update_from_remote_time",
            params![
                combine_key(&did, doc_type),
                did_cache_key(&did),
                doc_type_str(doc_type),
                doc.to_string(),
                exp as i64,
                trust_level,
                buckyos_get_unix_timestamp() as i64
            ],
        ) {
            warn!("write did doc sqlite cache failed: {}", err);
        }

        if let Some(owner_document) = parse_owner_document_doc(doc_type, &doc) {
            self.evict_revoked_docs(&did, doc_type, &owner_document);
        }
    }

    pub fn delete(&self, did: DID, doc_type: Option<&DidDocType>) {
        let conn = match self.open_conn() {
            Ok(c) => c,
            Err(err) => {
                warn!("open sqlite cache failed when delete: {}", err);
                return;
            }
        };
        if let Err(err) = conn.execute(
            "DELETE FROM did_docs WHERE doc_key = ?1",
            params![combine_key(&did, doc_type)],
        ) {
            warn!("delete did doc sqlite cache failed: {}", err);
        }
    }

    fn resolve_db_path(cache_dir: Option<PathBuf>) -> name_lib::NSResult<PathBuf> {
        let base_dir = cache_dir.unwrap_or_else(|| get_buckyos_service_local_data_dir("did_docs"));
        if let Err(err) = fs::create_dir_all(&base_dir) {
            return Err(name_lib::NSError::ReadLocalFileError(format!(
                "prepare sqlite cache dir failed: {}",
                err
            )));
        }
        Ok(base_dir.join("did_docs.sqlite"))
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
                trust_level INTEGER NOT NULL,
                update_from_remote_time INTEGER
            )",
            [],
        )
        .map_err(|e| {
            name_lib::NSError::ReadLocalFileError(format!("create table failed: {}", e))
        })?;

        // schema migration for existing databases
        ensure_update_from_remote_time_column(&conn).map_err(|e| {
            name_lib::NSError::ReadLocalFileError(format!("migrate table failed: {}", e))
        })?;
        Ok(())
    }

    pub fn validate_owner_revocation(
        &self,
        did: &DID,
        doc_type: Option<&DidDocType>,
        doc: &EncodedDocument,
    ) -> name_lib::NSResult<()> {
        if is_owner_doc(doc_type, doc) {
            return Ok(());
        }

        if let Some(owner_document) = self.load_cached_owner_document(did) {
            owner_document.validate_jwt_revocation(doc_type_str(doc_type), doc)?;
        }
        Ok(())
    }

    fn load_cached_owner_document(&self, did: &DID) -> Option<OwnerDocument> {
        self.get(did, Some(&DidDocType::Owner))
            .and_then(|(doc, _, _)| parse_owner_document_doc(Some(&DidDocType::Owner), &doc))
            .or_else(|| {
                self.get(did, None)
                    .and_then(|(doc, _, _)| parse_owner_document_doc(None, &doc))
            })
    }

    fn evict_revoked_docs(
        &self,
        did: &DID,
        owner_doc_type: Option<&DidDocType>,
        owner_document: &OwnerDocument,
    ) {
        let conn = match self.open_conn() {
            Ok(c) => c,
            Err(err) => {
                warn!("open sqlite cache failed for revocation cleanup: {}", err);
                return;
            }
        };

        let mut stmt = match conn.prepare("SELECT doc_type, doc FROM did_docs WHERE did = ?1") {
            Ok(stmt) => stmt,
            Err(err) => {
                warn!("prepare sqlite revocation cleanup failed: {}", err);
                return;
            }
        };

        let rows = match stmt.query_map(params![did_cache_key(did)], |row| {
            let doc_type: String = row.get(0)?;
            let doc_str: String = row.get(1)?;
            Ok((doc_type, doc_str))
        }) {
            Ok(rows) => rows,
            Err(err) => {
                warn!("query sqlite revocation cleanup failed: {}", err);
                return;
            }
        };

        let mut revoked_doc_types = Vec::new();
        for row in rows.flatten() {
            let doc_type = empty_doc_type_to_option(&row.0);
            if same_doc_type(doc_type.as_ref(), owner_doc_type) {
                continue;
            }
            let Ok(doc) = EncodedDocument::from_str(row.1) else {
                continue;
            };
            if owner_document
                .validate_jwt_revocation(doc_type_str(doc_type.as_ref()), &doc)
                .is_err()
            {
                revoked_doc_types.push(row.0);
            }
        }

        drop(stmt);
        for doc_type in revoked_doc_types {
            let doc_type = empty_doc_type_to_option(&doc_type);
            self.delete(did.clone(), doc_type.as_ref());
        }
    }
}

fn ensure_update_from_remote_time_column(conn: &Connection) -> rusqlite::Result<()> {
    let mut stmt = conn.prepare("PRAGMA table_info(did_docs)")?;
    let mut has_column = false;
    let column_iter = stmt.query_map([], |row| row.get::<_, String>(1))?;
    for col_name in column_iter.flatten() {
        if col_name == "update_from_remote_time" {
            has_column = true;
            break;
        }
    }
    if !has_column {
        conn.execute(
            "ALTER TABLE did_docs ADD COLUMN update_from_remote_time INTEGER",
            [],
        )?;
    }
    Ok(())
}

// ------------------------ 内存实现（测试用） ------------------------

#[derive(Clone)]
pub struct DIDDocumentMemCache {
    entries: std::sync::Arc<RwLock<HashMap<String, MemoryEntry>>>,
}

#[derive(Clone)]
struct MemoryEntry {
    doc: EncodedDocument,
    exp: u64,
    trust_level: i32,
    update_from_remote_time: Option<u64>,
}

impl DIDDocumentMemCache {
    pub fn new() -> Self {
        Self {
            entries: std::sync::Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn get(
        &self,
        did: &DID,
        doc_type: Option<&DidDocType>,
    ) -> Option<(EncodedDocument, u64, i32)> {
        let key = combine_key(did, doc_type);
        let entry = match self.entries.read() {
            Ok(guard) => guard.get(&key).cloned(),
            Err(_) => None,
        }?;
        if is_expired(entry.exp) {
            if entry.update_from_remote_time.is_some() {
                self.delete(did.clone(), doc_type);
                return None;
            } else {
                debug!(
                    "mem doc cache {}#{} expired but kept because never fetched from remote",
                    did.to_string(),
                    doc_type_str(doc_type)
                );
            }
        }
        Some((entry.doc, entry.exp, entry.trust_level))
    }

    pub fn update(
        &self,
        did: DID,
        doc_type: Option<&DidDocType>,
        doc: EncodedDocument,
        exp: u64,
        trust_level: i32,
    ) -> bool {
        if self
            .validate_owner_revocation(&did, doc_type, &doc)
            .is_err()
        {
            return false;
        }

        if let Some((existing, _, current_trust)) = self.get(&did, doc_type) {
            if should_update_cached_doc(&did, &existing, current_trust, &doc, trust_level) {
                self.insert(did, doc_type, doc, exp, trust_level);
                return true;
            }
            return false;
        } else {
            self.insert(did, doc_type, doc, exp, trust_level);
            return true;
        }
    }

    pub fn insert(
        &self,
        did: DID,
        doc_type: Option<&DidDocType>,
        doc: EncodedDocument,
        exp: u64,
        trust_level: i32,
    ) {
        if self
            .validate_owner_revocation(&did, doc_type, &doc)
            .is_err()
        {
            return;
        }

        let owner_document = parse_owner_document_doc(doc_type, &doc);
        let key = combine_key(&did, doc_type);
        if let Ok(mut guard) = self.entries.write() {
            guard.insert(
                key,
                MemoryEntry {
                    doc,
                    exp,
                    trust_level,
                    update_from_remote_time: Some(buckyos_get_unix_timestamp()),
                },
            );
        }

        if let Some(owner_document) = owner_document {
            self.evict_revoked_docs(&did, doc_type, &owner_document);
        }
    }

    pub fn delete(&self, did: DID, doc_type: Option<&DidDocType>) {
        let key = combine_key(&did, doc_type);
        if let Ok(mut guard) = self.entries.write() {
            guard.remove(&key);
        }
    }

    pub fn validate_owner_revocation(
        &self,
        did: &DID,
        doc_type: Option<&DidDocType>,
        doc: &EncodedDocument,
    ) -> name_lib::NSResult<()> {
        if is_owner_doc(doc_type, doc) {
            return Ok(());
        }

        if let Some(owner_document) = self.load_cached_owner_document(did) {
            owner_document.validate_jwt_revocation(doc_type_str(doc_type), doc)?;
        }
        Ok(())
    }

    fn load_cached_owner_document(&self, did: &DID) -> Option<OwnerDocument> {
        self.get(did, Some(&DidDocType::Owner))
            .and_then(|(doc, _, _)| parse_owner_document_doc(Some(&DidDocType::Owner), &doc))
            .or_else(|| {
                self.get(did, None)
                    .and_then(|(doc, _, _)| parse_owner_document_doc(None, &doc))
            })
    }

    fn evict_revoked_docs(
        &self,
        did: &DID,
        owner_doc_type: Option<&DidDocType>,
        owner_document: &OwnerDocument,
    ) {
        let did_key = did_cache_key(did);
        if let Ok(mut guard) = self.entries.write() {
            guard.retain(|key, entry| {
                let doc_type = doc_type_from_cache_key(&did_key, key);
                if doc_type.is_none() {
                    return true;
                }
                let doc_type = doc_type.unwrap();
                if same_doc_type(doc_type.as_ref(), owner_doc_type) {
                    return true;
                }
                owner_document
                    .validate_jwt_revocation(doc_type_str(doc_type.as_ref()), &entry.doc)
                    .is_ok()
            });
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

/// 设计文档第 7.4 节：只保存 `requires_verification(doc_type) == false` 的 Info 类
/// 结果（例如 DeviceInfo、运行时地址）。它不参与 owner 验签，不受
/// `Missing`/`revoke_before_iat` 等 Document 门禁间接门控，只按 `iat/ttl/source_rank`
/// 判断可用性；不与 `DIDDocumentCache`（verified_cache 的角色）混在一起，也不参与
/// 它的持久化/淘汰逻辑。
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

fn should_update_cached_doc(
    did: &DID,
    current_doc: &EncodedDocument,
    current_trust: i32,
    new_doc: &EncodedDocument,
    new_trust: i32,
) -> bool {
    let current_version_seq = get_doc_version_seq(current_doc);
    let new_version_seq = get_doc_version_seq(new_doc);

    match (current_version_seq, new_version_seq) {
        (Some(current), Some(new)) => {
            return new > current || (new == current && new_trust < current_trust);
        }
        (Some(_), None) => return false,
        (None, Some(_)) => return true,
        (None, None) => {}
    }

    if did.is_named_obj_id() {
        return false;
    }

    let new_iat = get_doc_iat(new_doc);
    let current_iat = get_doc_iat(current_doc);
    if new_trust < current_trust {
        return true;
    }
    new_trust == current_trust && new_iat > current_iat
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

fn empty_doc_type_to_option(doc_type: &str) -> Option<DidDocType> {
    if doc_type.is_empty() {
        None
    } else {
        Some(DidDocType::from(doc_type))
    }
}

fn doc_type_from_cache_file_name(did_key: &str, file_name: &str) -> Option<Option<DidDocType>> {
    let suffix = ".doc.json";
    if !file_name.ends_with(suffix) {
        return None;
    }

    let key = file_name.strip_suffix(suffix)?;
    doc_type_from_cache_key(did_key, key)
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
    use crate::DEFAULT_PROVIDER_TRUST_LEVEL;
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use name_lib::{
        DIDDocumentTrait, NSError, OwnerDocument, ZoneBootDocument, DEFAULT_EXPIRE_TIME,
    };
    use rusqlite::{params, Connection};
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

    fn doc_path(base: &tempfile::TempDir, did: &DID) -> PathBuf {
        base.path().join(format!("{}.doc.json", did_cache_key(did)))
    }

    fn meta_path(base: &tempfile::TempDir, did: &DID) -> PathBuf {
        base.path()
            .join(format!("{}.meta.json", did_cache_key(did)))
    }

    fn owner_encoding_key() -> EncodingKey {
        EncodingKey::from_ed_pem(TEST_OWNER_PRIVATE_KEY_PEM.as_bytes()).unwrap()
    }

    fn owner_public_jwk() -> jsonwebtoken::jwk::Jwk {
        serde_json::from_str(TEST_OWNER_PUBLIC_JWK).unwrap()
    }

    fn build_owner_doc(iat: u64, marker: &str) -> EncodedDocument {
        build_owner_doc_with_version(iat, Some(0), marker)
    }

    fn build_owner_doc_with_version(
        iat: u64,
        version_seq: Option<u64>,
        marker: &str,
    ) -> EncodedDocument {
        let mut owner_document = OwnerDocument::new(
            DID::new("bns", "tester"),
            format!("tester-{marker}"),
            "Tester Example".to_string(),
            owner_public_jwk(),
        );
        owner_document.iat = iat;
        owner_document.exp = iat + DEFAULT_EXPIRE_TIME;
        owner_document.version_seq = version_seq;
        owner_document
            .extra_info
            .insert("marker".to_string(), json!(marker));
        owner_document.encode(Some(&owner_encoding_key())).unwrap()
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

    fn assert_owner_update_evicts_revoked_docs(cache: &DIDDocumentCache, did: &DID) {
        let base_iat = buckyos_get_unix_timestamp();
        let old_doc = build_jwt_doc(1, base_iat + 10, "old");
        let fresh_doc = build_jwt_doc(2, base_iat + 11, "fresh");
        cache.insert(
            did.clone(),
            None,
            old_doc,
            base_iat + DEFAULT_EXPIRE_TIME,
            DEFAULT_PROVIDER_TRUST_LEVEL,
        );
        cache.insert(
            did.clone(),
            Some(DidDocType::Info),
            fresh_doc.clone(),
            base_iat + DEFAULT_EXPIRE_TIME,
            DEFAULT_PROVIDER_TRUST_LEVEL,
        );

        let owner_doc =
            build_owner_doc_with_revocation(did, base_iat, Some(1), Some(base_iat + 10), "owner");
        cache.insert(
            did.clone(),
            Some(DidDocType::Owner),
            owner_doc,
            base_iat + DEFAULT_EXPIRE_TIME,
            DEFAULT_PROVIDER_TRUST_LEVEL,
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
            DEFAULT_PROVIDER_TRUST_LEVEL,
        );

        let old_doc = build_jwt_doc(1, base_iat + 10, "old");
        cache.insert(
            did.clone(),
            None,
            old_doc,
            base_iat + DEFAULT_EXPIRE_TIME,
            DEFAULT_PROVIDER_TRUST_LEVEL,
        );

        assert!(
            cache.get(did, None).is_none(),
            "revoked DID document should not be inserted"
        );
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
            DEFAULT_PROVIDER_TRUST_LEVEL,
        );
        cache.insert(
            path_did.clone(),
            None,
            path_doc.clone(),
            exp,
            DEFAULT_PROVIDER_TRUST_LEVEL,
        );

        assert_eq!(cache.get(&host_did, None).unwrap().0, host_doc);
        assert_eq!(cache.get(&path_did, None).unwrap().0, path_doc);
    }

    #[test]
    fn fs_insert_and_get_preserves_document() {
        let (tmp_dir, cache, did) = setup_fs_cache();
        let now = buckyos_get_unix_timestamp();
        let exp = now + DEFAULT_EXPIRE_TIME;
        let doc = build_zone_doc(&did, exp, "json-v1");
        cache.insert(
            did.clone(),
            None,
            doc.clone(),
            exp,
            DEFAULT_PROVIDER_TRUST_LEVEL,
        );

        assert!(doc_path(&tmp_dir, &did).exists());
        let loaded = cache.get(&did, None).expect("doc should be available");
        assert_eq!(loaded.0, doc);
        assert_eq!(loaded.1, exp);
    }

    #[test]
    fn fs_cache_uses_filename_key_for_path_did() {
        let (tmp_dir, cache, _) = setup_fs_cache();
        assert_path_did_does_not_collide_with_host_did(&cache);

        let path_did = DID::from_str("did:web:example.com:abc:bcd").unwrap();
        assert_eq!(did_cache_key(&path_did), "example.com%2Fabc%2Fbcd");
        assert!(doc_path(&tmp_dir, &path_did).exists());
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
    fn fs_get_removes_expired_document() {
        let (tmp_dir, cache, did) = setup_fs_cache();
        let past_exp = buckyos_get_unix_timestamp().saturating_sub(10);
        let doc = build_zone_doc(&did, past_exp, "expired");
        cache.insert(
            did.clone(),
            None,
            doc,
            past_exp,
            DEFAULT_PROVIDER_TRUST_LEVEL,
        );

        assert!(cache.get(&did, None).is_none());
        assert!(
            !doc_path(&tmp_dir, &did).exists(),
            "expired doc file should be removed"
        );
    }

    #[test]
    fn fs_get_keeps_expired_document_without_remote_fetch() {
        let (tmp_dir, cache, did) = setup_fs_cache();
        let past_exp = buckyos_get_unix_timestamp().saturating_sub(10);
        let doc = build_zone_doc(&did, past_exp, "expired-local");

        fs::write(doc_path(&tmp_dir, &did), doc.to_string()).unwrap();
        let meta = CacheMeta {
            trust_level: ROOT_TRUST_LEVEL,
            exp: Some(past_exp),
            update_from_remote_time: None,
        };
        fs::write(
            meta_path(&tmp_dir, &did),
            serde_json::to_string(&meta).unwrap(),
        )
        .unwrap();

        let loaded = cache.get(&did, None).expect("doc should remain available");
        assert_eq!(loaded.0, doc);
        assert!(doc_path(&tmp_dir, &did).exists());
    }

    #[test]
    fn fs_update_prefers_version_seq_over_iat() {
        let (_tmp_dir, cache, did) = setup_fs_cache();
        let now = buckyos_get_unix_timestamp();
        let doc_v1 = build_owner_doc_with_version(now + 1_000, Some(1), "jwt-v1");
        let exp_v1 = doc_v1
            .clone()
            .to_json_value()
            .unwrap()
            .get("exp")
            .unwrap()
            .as_u64()
            .unwrap();
        assert!(cache.update(
            did.clone(),
            None,
            doc_v1.clone(),
            exp_v1,
            DEFAULT_PROVIDER_TRUST_LEVEL
        ));

        let doc_v2 = build_owner_doc_with_version(now, Some(2), "jwt-v2");
        let exp_v2 = doc_v2
            .clone()
            .to_json_value()
            .unwrap()
            .get("exp")
            .unwrap()
            .as_u64()
            .unwrap();
        assert!(cache.update(
            did.clone(),
            None,
            doc_v2.clone(),
            exp_v2,
            DEFAULT_PROVIDER_TRUST_LEVEL
        ));
        assert_eq!(cache.get(&did, None).unwrap().0, doc_v2);

        let older_doc = build_owner_doc_with_version(now + 2_000, Some(1), "jwt-old");
        assert!(!cache.update(
            did.clone(),
            None,
            older_doc,
            now + DEFAULT_EXPIRE_TIME,
            DEFAULT_PROVIDER_TRUST_LEVEL
        ));
        assert_eq!(cache.get(&did, None).unwrap().0, doc_v2);
    }

    #[test]
    fn fs_update_uses_exp_when_iat_missing() {
        let (_tmp_dir, cache, did) = setup_fs_cache();
        let now = buckyos_get_unix_timestamp();
        let exp_v1 = now + (DEFAULT_EXPIRE_TIME * 2);
        let doc_v1 = build_zone_doc(&did, exp_v1, "no-iat-v1");
        assert!(cache.update(
            did.clone(),
            None,
            doc_v1.clone(),
            exp_v1,
            DEFAULT_PROVIDER_TRUST_LEVEL
        ));

        let exp_v2 = exp_v1 + 10;
        let doc_v2 = build_zone_doc(&did, exp_v2, "no-iat-v2");
        assert!(cache.update(
            did.clone(),
            None,
            doc_v2.clone(),
            exp_v2,
            DEFAULT_PROVIDER_TRUST_LEVEL
        ));

        let exp_v3 = exp_v2 - 5;
        let doc_v3 = build_zone_doc(&did, exp_v3, "no-iat-older");
        assert!(!cache.update(
            did.clone(),
            None,
            doc_v3,
            exp_v3,
            DEFAULT_PROVIDER_TRUST_LEVEL
        ));

        assert_eq!(cache.get(&did, None).unwrap().0, doc_v2);
    }

    #[test]
    fn fs_versioned_cache_rejects_unversioned_doc() {
        let (_tmp_dir, cache, did) = setup_fs_cache();
        let now = buckyos_get_unix_timestamp();
        let versioned_doc = EncodedDocument::JsonLd(json!({
            "version_seq": 5,
            "iat": now,
            "exp": now + DEFAULT_EXPIRE_TIME,
            "marker": "versioned"
        }));
        assert!(cache.update(
            did.clone(),
            None,
            versioned_doc.clone(),
            now + DEFAULT_EXPIRE_TIME,
            DEFAULT_PROVIDER_TRUST_LEVEL
        ));

        let unversioned_doc = EncodedDocument::JsonLd(json!({
            "iat": now + 10_000,
            "exp": now + DEFAULT_EXPIRE_TIME + 10_000,
            "marker": "unversioned"
        }));
        assert!(!cache.update(
            did.clone(),
            None,
            unversioned_doc,
            now + DEFAULT_EXPIRE_TIME + 10_000,
            DEFAULT_PROVIDER_TRUST_LEVEL - 10
        ));

        assert_eq!(cache.get(&did, None).unwrap().0, versioned_doc);
    }

    #[test]
    fn mem_version_seq_takes_over_named_obj_cache() {
        let (cache, _) = setup_mem_cache();
        let did = DID::from_str("did:dev:5bUuyWLOKyCre9az_IhJVIuOw8bA0gyKjstcYGHbaPE").unwrap();
        let now = buckyos_get_unix_timestamp();
        let doc_v1 = EncodedDocument::JsonLd(json!({
            "version_seq": 1,
            "iat": now,
            "exp": now + DEFAULT_EXPIRE_TIME,
            "marker": "v1"
        }));
        assert!(cache.update(
            did.clone(),
            None,
            doc_v1,
            now + DEFAULT_EXPIRE_TIME,
            DEFAULT_PROVIDER_TRUST_LEVEL
        ));

        let doc_v2 = EncodedDocument::JsonLd(json!({
            "version_seq": 2,
            "iat": now + 10,
            "exp": now + DEFAULT_EXPIRE_TIME + 10,
            "marker": "v2"
        }));
        assert!(cache.update(
            did.clone(),
            None,
            doc_v2.clone(),
            now + DEFAULT_EXPIRE_TIME + 10,
            DEFAULT_PROVIDER_TRUST_LEVEL
        ));

        assert_eq!(cache.get(&did, None).unwrap().0, doc_v2);
    }

    #[test]
    fn db_version_seq_rejects_lower_sequence() -> Result<(), NSError> {
        let (_tmp_dir, cache, did) = setup_db_cache();
        let now = buckyos_get_unix_timestamp();
        let doc_v2 = EncodedDocument::JsonLd(json!({
            "version_seq": 2,
            "iat": now,
            "exp": now + DEFAULT_EXPIRE_TIME,
            "marker": "v2"
        }));
        assert!(cache.update(
            did.clone(),
            None,
            doc_v2.clone(),
            now + DEFAULT_EXPIRE_TIME,
            DEFAULT_PROVIDER_TRUST_LEVEL
        ));

        let doc_v1 = EncodedDocument::JsonLd(json!({
            "version_seq": 1,
            "iat": now + 10_000,
            "exp": now + DEFAULT_EXPIRE_TIME + 10_000,
            "marker": "v1"
        }));
        assert!(!cache.update(
            did.clone(),
            None,
            doc_v1,
            now + DEFAULT_EXPIRE_TIME + 10_000,
            DEFAULT_PROVIDER_TRUST_LEVEL - 10
        ));

        assert_eq!(cache.get(&did, None).unwrap().0, doc_v2);
        Ok(())
    }

    #[test]
    fn fs_get_handles_missing_meta_file() {
        let (tmp_dir, cache, did) = setup_fs_cache();
        let now = buckyos_get_unix_timestamp();
        let exp = now + DEFAULT_EXPIRE_TIME;
        let doc = build_zone_doc(&did, exp, "missing-meta");
        cache.insert(
            did.clone(),
            None,
            doc.clone(),
            exp,
            DEFAULT_PROVIDER_TRUST_LEVEL,
        );

        // Simulate meta file being deleted/corrupted
        std::fs::remove_file(meta_path(&tmp_dir, &did)).unwrap();

        let (loaded_doc, _loaded_exp, trust) =
            cache.get(&did, None).expect("doc should still load");
        assert_eq!(loaded_doc, doc);
        assert_eq!(trust, ROOT_TRUST_LEVEL);
    }

    #[test]
    fn db_roundtrip() -> Result<(), NSError> {
        let (_tmp_dir, cache, did) = setup_db_cache();
        let now = buckyos_get_unix_timestamp();
        let exp = now + DEFAULT_EXPIRE_TIME;
        let doc = build_zone_doc(&did, exp, "db");
        assert!(cache.update(
            did.clone(),
            None,
            doc.clone(),
            exp,
            DEFAULT_PROVIDER_TRUST_LEVEL
        ));
        let loaded = cache.get(&did, None).expect("doc should be available");
        assert_eq!(loaded.0, doc);
        Ok(())
    }

    #[test]
    fn db_cache_uses_filename_key_for_path_did() -> Result<(), NSError> {
        let (_tmp_dir, cache, _) = setup_db_cache();
        assert_path_did_does_not_collide_with_host_did(&cache);
        Ok(())
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
    fn mem_roundtrip() {
        let (cache, did) = setup_mem_cache();
        let now = buckyos_get_unix_timestamp();
        let exp = now + DEFAULT_EXPIRE_TIME;
        let doc = build_zone_doc(&did, exp, "mem");
        assert!(cache.update(
            did.clone(),
            None,
            doc.clone(),
            exp,
            DEFAULT_PROVIDER_TRUST_LEVEL
        ));
        let loaded = cache.get(&did, None).expect("doc should be available");
        assert_eq!(loaded.0, doc);
    }

    #[test]
    fn mem_cache_uses_filename_key_for_path_did() {
        let (cache, _) = setup_mem_cache();
        assert_path_did_does_not_collide_with_host_did(&cache);
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

    #[test]
    fn mem_get_removes_expired_document() {
        let (cache, did) = setup_mem_cache();
        let past_exp = buckyos_get_unix_timestamp().saturating_sub(10);
        let doc = build_zone_doc(&did, past_exp, "mem-expired");
        cache.insert(
            did.clone(),
            None,
            doc,
            past_exp,
            DEFAULT_PROVIDER_TRUST_LEVEL,
        );

        assert!(cache.get(&did, None).is_none());
    }

    #[test]
    fn mem_get_keeps_expired_document_without_remote_fetch() {
        let (cache, did) = setup_mem_cache();
        let past_exp = buckyos_get_unix_timestamp().saturating_sub(10);
        let doc = build_zone_doc(&did, past_exp, "mem-expired-local");

        let mem_cache = match &cache {
            DIDDocumentCache::Mem(inner) => inner,
            _ => unreachable!(),
        };

        if let Ok(mut guard) = mem_cache.entries.write() {
            guard.insert(
                combine_key(&did, None),
                MemoryEntry {
                    doc: doc.clone(),
                    exp: past_exp,
                    trust_level: DEFAULT_PROVIDER_TRUST_LEVEL,
                    update_from_remote_time: None,
                },
            );
        }

        let loaded = cache.get(&did, None).expect("doc should remain available");
        assert_eq!(loaded.0, doc);
    }

    #[test]
    fn db_get_keeps_expired_document_without_remote_fetch() -> Result<(), NSError> {
        let (_tmp_dir, cache, did) = setup_db_cache();
        let past_exp = buckyos_get_unix_timestamp().saturating_sub(10);
        let doc = build_zone_doc(&did, past_exp, "db-expired-local");

        let db_cache = match &cache {
            DIDDocumentCache::Db(inner) => inner,
            _ => unreachable!(),
        };

        let conn = Connection::open(&db_cache.db_path).unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO did_docs (doc_key, did, doc_type, doc, exp, trust_level, update_from_remote_time)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL)",
            params![
                combine_key(&did, None),
                did_cache_key(&did),
                "",
                doc.to_string(),
                past_exp as i64,
                DEFAULT_PROVIDER_TRUST_LEVEL
            ],
        )
        .unwrap();

        let loaded = cache.get(&did, None).expect("doc should remain available");
        assert_eq!(loaded.0, doc);
        Ok(())
    }

    #[test]
    fn fs_update_does_not_replace_named_obj() {
        let (_tmp_dir, cache, _) = setup_fs_cache();
        let did = DID::from_str("did:dev:5bUuyWLOKyCre9az_IhJVIuOw8bA0gyKjstcYGHbaPE").unwrap();
        let now = buckyos_get_unix_timestamp();

        let doc_v1 = EncodedDocument::JsonLd(json!({
            "iat": now,
            "exp": now + DEFAULT_EXPIRE_TIME,
            "marker": "v1"
        }));
        cache.insert(
            did.clone(),
            None,
            doc_v1.clone(),
            now + DEFAULT_EXPIRE_TIME,
            DEFAULT_PROVIDER_TRUST_LEVEL,
        );

        let doc_v2 = EncodedDocument::JsonLd(json!({
            "iat": now + 1000,
            "exp": now + DEFAULT_EXPIRE_TIME + 1000,
            "marker": "v2"
        }));
        let updated = cache.update(
            did.clone(),
            None,
            doc_v2.clone(),
            now + DEFAULT_EXPIRE_TIME + 1000,
            DEFAULT_PROVIDER_TRUST_LEVEL - 10,
        );
        assert!(!updated);

        let loaded = cache.get(&did, None).unwrap();
        assert_eq!(loaded.0, doc_v1);
    }
}
