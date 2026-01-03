use std::fs;
use std::path::PathBuf;

use buckyos_kit::{
    buckyos_get_unix_timestamp, get_buckyos_service_local_data_dir, get_buckyos_system_etc_dir,
};
use log::{debug, error, info, warn};
use name_lib::{EncodedDocument, DEFAULT_EXPIRE_TIME, DID};
use rusqlite::{params, Connection, OpenFlags};
use serde::{Deserialize, Serialize};

/// 支持两种存储后端的 DID 文档缓存：文件系统和 SQLite。
/// 通过 `CacheBackend` 选择实现，默认推荐 SQLite 以避免大量小文件。
#[derive(Clone, Copy, Debug)]
pub enum CacheBackend {
    Filesystem,
    Sqlite,
}

pub enum DIDDocumentCache {
    Fs(DIDDocumentFsCache),
    Db(DIDDocumentDBCache),
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

    pub fn get_default_cache_dir() -> PathBuf {
        DIDDocumentFsCache::get_default_cache_dir()
    }

    pub fn with_default_dir() -> Self {
        Self::Fs(DIDDocumentFsCache::with_default_dir())
    }

    pub fn default_dir() -> PathBuf {
        DIDDocumentFsCache::default_dir()
    }

    pub fn get(&self, did: &DID, doc_type: Option<&str>) -> Option<(EncodedDocument, u64, i32)> {
        match self {
            Self::Fs(inner) => inner.get(did, doc_type),
            Self::Db(inner) => inner.get(did, doc_type),
        }
    }

    pub fn update(
        &self,
        did: DID,
        doc_type: Option<&str>,
        doc: EncodedDocument,
        exp: u64,
        trust_level: i32,
    ) -> bool {
        match self {
            Self::Fs(inner) => inner.update(did, doc_type, doc, exp, trust_level),
            Self::Db(inner) => inner.update(did, doc_type, doc, exp, trust_level),
        }
    }

    pub fn insert(
        &self,
        did: DID,
        doc_type: Option<&str>,
        doc: EncodedDocument,
        exp: u64,
        trust_level: i32,
    ) {
        match self {
            Self::Fs(inner) => inner.insert(did, doc_type, doc, exp, trust_level),
            Self::Db(inner) => inner.insert(did, doc_type, doc, exp, trust_level),
        }
    }

    pub fn delete(&self, did: DID, doc_type: Option<&str>) {
        match self {
            Self::Fs(inner) => inner.delete(did, doc_type),
            Self::Db(inner) => inner.delete(did, doc_type),
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
        get_buckyos_service_local_data_dir("did_docs", None)
    }

    pub fn with_default_dir() -> Self {
        Self::new(Some(Self::default_dir()))
    }

    pub fn default_dir() -> PathBuf {
        get_buckyos_system_etc_dir().join("did_docs")
    }

    pub fn get(&self, did: &DID, doc_type: Option<&str>) -> Option<(EncodedDocument, u64, i32)> {
        let doc = self.load_from_disk(did, doc_type)?;
        let meta = self.load_meta(did, doc_type);
        let exp = meta
            .as_ref()
            .and_then(|m| m.exp)
            .or_else(|| extract_timestamp(&doc, "exp"))
            .unwrap_or_else(|| buckyos_get_unix_timestamp() + DEFAULT_EXPIRE_TIME);
        if is_expired(exp) {
            warn!("did doc is expired, delete it: {}", did.to_raw_host_name());
            self.delete(did.clone(), doc_type);
            return None;
        }
        let trust_level = meta.map(|m| m.trust_level).unwrap_or(i32::MAX);
        Some((doc, exp, trust_level))
    }

    pub fn update(
        &self,
        did: DID,
        doc_type: Option<&str>,
        doc: EncodedDocument,
        exp: u64,
        trust_level: i32,
    ) -> bool {
        if let Some((existing, _, current_trust)) = self.get(&did, doc_type) {
            let mut need_update = false;
            if did.is_named_obj_id() {
                need_update = false;
            } else {
                let new_iat = get_doc_iat(&doc);
                let current_iat = get_doc_iat(&existing);
                if trust_level < current_trust {
                    need_update = true;
                } else if trust_level == current_trust && new_iat > current_iat {
                    need_update = true;
                }
            }

            if need_update {
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
        doc_type: Option<&str>,
        doc: EncodedDocument,
        exp: u64,
        trust_level: i32,
    ) {
        self.save_to_disk(&did, doc_type, &doc);
        self.save_meta(&did, doc_type, CacheMeta {
            trust_level,
            exp: Some(exp),
        });
    }

    pub fn delete(&self, did: DID, doc_type: Option<&str>) {
        self.delete_local_file(&did, doc_type);
        self.delete_meta(&did, doc_type);
    }

    fn load_from_disk(&self, did: &DID, doc_type: Option<&str>) -> Option<EncodedDocument> {
        let file_path = self
            .cache_dir
            .join(format!("{}.doc.json", combine_key(did, doc_type)));

        match fs::read_to_string(&file_path) {
            Ok(content) => match EncodedDocument::from_str(content) {
                Ok(doc) => {
                    debug!("load did doc from local cache: {}", file_path.display());
                    Some(doc)
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

    fn save_to_disk(&self, did: &DID, doc_type: Option<&str>, doc: &EncodedDocument) {
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

    fn meta_path(&self, did: &DID, doc_type: Option<&str>) -> PathBuf {
        self.cache_dir
            .join(format!("{}.meta.json", combine_key(did, doc_type)))
    }

    fn save_meta(&self, did: &DID, doc_type: Option<&str>, meta: CacheMeta) {
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

    fn load_meta(&self, did: &DID, doc_type: Option<&str>) -> Option<CacheMeta> {
        let meta_path = self.meta_path(did, doc_type);
        match fs::read_to_string(&meta_path) {
            Ok(content) => serde_json::from_str::<CacheMeta>(&content).ok(),
            Err(_) => None,
        }
    }

    fn delete_meta(&self, did: &DID, doc_type: Option<&str>) {
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

    fn delete_local_file(&self, did: &DID, doc_type: Option<&str>) {
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

    pub fn get(&self, did: &DID, doc_type: Option<&str>) -> Option<(EncodedDocument, u64, i32)> {
        let conn = self.open_conn().ok()?;
        let mut stmt = conn
            .prepare("SELECT doc, exp, trust_level FROM did_docs WHERE doc_key = ?1")
            .ok()?;
        let row = stmt
            .query_row(params![combine_key(did, doc_type)], |row| {
                let doc_str: String = row.get(0)?;
                let exp: i64 = row.get(1)?;
                let trust_level: i32 = row.get(2)?;
                Ok((doc_str, exp as u64, trust_level))
            })
            .ok();

        let (doc_str, exp, trust_level) = row?;
        let doc = EncodedDocument::from_str(doc_str).ok()?;
        if is_expired(exp) {
            self.delete(did.clone(), doc_type);
            return None;
        }
        Some((doc, exp, trust_level))
    }

    pub fn update(
        &self,
        did: DID,
        doc_type: Option<&str>,
        doc: EncodedDocument,
        exp: u64,
        trust_level: i32,
    ) -> bool {
        if let Some((existing, _, current_trust)) = self.get(&did, doc_type) {
            let mut need_update = false;
            let new_iat = get_doc_iat(&doc);
            let current_iat = get_doc_iat(&existing);
            if trust_level < current_trust {
                need_update = true;
            } else if trust_level == current_trust && new_iat > current_iat {
                need_update = true;
            }
            if need_update {
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
        doc_type: Option<&str>,
        doc: EncodedDocument,
        exp: u64,
        trust_level: i32,
    ) {
        let conn = match self.open_conn() {
            Ok(c) => c,
            Err(err) => {
                warn!("open sqlite cache failed: {}", err);
                return;
            }
        };
        if let Err(err) = conn.execute(
            "INSERT INTO did_docs (doc_key, did, doc_type, doc, exp, trust_level) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(doc_key) DO UPDATE SET doc = excluded.doc, exp = excluded.exp, trust_level = excluded.trust_level",
            params![
                combine_key(&did, doc_type),
                did.to_raw_host_name(),
                doc_type.unwrap_or_default(),
                doc.to_string(),
                exp as i64,
                trust_level
            ],
        ) {
            warn!("write did doc sqlite cache failed: {}", err);
        }
    }

    pub fn delete(&self, did: DID, doc_type: Option<&str>) {
        let conn = match self.open_conn() {
            Ok(c) => c,
            Err(err) => {
                warn!("open sqlite cache failed when delete: {}", err);
                return;
            }
        };
        if let Err(err) = conn.execute("DELETE FROM did_docs WHERE doc_key = ?1", params![combine_key(&did, doc_type)]) {
            warn!("delete did doc sqlite cache failed: {}", err);
        }
    }

    fn resolve_db_path(cache_dir: Option<PathBuf>) -> name_lib::NSResult<PathBuf> {
        let base_dir = cache_dir.unwrap_or_else(|| get_buckyos_service_local_data_dir("did_docs", None));
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
        let conn = self
            .open_conn()
            .map_err(|e| name_lib::NSError::ReadLocalFileError(format!("open sqlite failed: {}", e)))?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS did_docs (
                doc_key TEXT PRIMARY KEY,
                did TEXT NOT NULL,
                doc_type TEXT NOT NULL,
                doc TEXT NOT NULL,
                exp INTEGER NOT NULL,
                trust_level INTEGER NOT NULL
            )",
            [],
        )
        .map_err(|e| name_lib::NSError::ReadLocalFileError(format!("create table failed: {}", e)))?;
        Ok(())
    }
}

// ------------------------ 工具函数 ------------------------

fn is_expired(exp_ts: u64) -> bool {
    exp_ts <= buckyos_get_unix_timestamp()
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

fn combine_key(did: &DID, doc_type: Option<&str>) -> String {
    if let Some(f) = doc_type {
        format!("{}#{}", did.to_raw_host_name(), f)
    } else {
        did.to_raw_host_name()
    }
}

// ------------------------ 测试 ------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::EncodingKey;
    use name_lib::{DIDDocumentTrait, OwnerConfig, ZoneBootConfig, DEFAULT_EXPIRE_TIME, NSError};
    use serde_json::json;
    use std::collections::HashMap;
    use tempfile::tempdir;
    use crate::DEFAULT_PROVIDER_TRUST_LEVEL;

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

    fn doc_path(base: &tempfile::TempDir, did: &DID) -> PathBuf {
        base.path().join(format!("{}.doc.json", did.to_raw_host_name()))
    }

    fn owner_encoding_key() -> EncodingKey {
        EncodingKey::from_ed_pem(TEST_OWNER_PRIVATE_KEY_PEM.as_bytes()).unwrap()
    }

    fn owner_public_jwk() -> jsonwebtoken::jwk::Jwk {
        serde_json::from_str(TEST_OWNER_PUBLIC_JWK).unwrap()
    }

    fn build_owner_doc(iat: u64, marker: &str) -> EncodedDocument {
        let mut owner_config = OwnerConfig::new(
            DID::new("bns", "tester"),
            format!("tester-{marker}"),
            "Tester Example".to_string(),
            owner_public_jwk(),
        );
        owner_config.iat = iat;
        owner_config.exp = iat + DEFAULT_EXPIRE_TIME;
        owner_config
            .extra_info
            .insert("marker".to_string(), json!(marker));
        owner_config.encode(Some(&owner_encoding_key())).unwrap()
    }

    fn build_zone_doc(did: &DID, exp: u64, marker: &str) -> EncodedDocument {
        let mut extra_info = HashMap::new();
        extra_info.insert("marker".to_string(), json!(marker));
        let zone_boot_config = ZoneBootConfig {
            id: Some(did.clone()),
            oods: vec!["ood1".parse().unwrap()],
            sn: Some("sn.unit-test.buckyos".to_string()),
            exp,
            owner: None,
            owner_key: None,
            devices: HashMap::new(),
            extra_info,
        };
        EncodedDocument::JsonLd(serde_json::to_value(zone_boot_config).unwrap())
    }

    #[test]
    fn fs_insert_and_get_preserves_document() {
        let (tmp_dir, cache, did) = setup_fs_cache();
        let now = buckyos_get_unix_timestamp();
        let exp = now + DEFAULT_EXPIRE_TIME;
        let doc = build_zone_doc(&did, exp, "json-v1");
        cache.insert(did.clone(), None, doc.clone(), exp, DEFAULT_PROVIDER_TRUST_LEVEL);

        assert!(doc_path(&tmp_dir, &did).exists());
        let loaded = cache.get(&did, None).expect("doc should be available");
        assert_eq!(loaded.0, doc);
        assert_eq!(loaded.1, exp);
    }

    #[test]
    fn fs_get_removes_expired_document() {
        let (tmp_dir, cache, did) = setup_fs_cache();
        let past_exp = buckyos_get_unix_timestamp().saturating_sub(10);
        let doc = build_zone_doc(&did, past_exp, "expired");
        cache.insert(did.clone(), None, doc, past_exp, DEFAULT_PROVIDER_TRUST_LEVEL);

        assert!(cache.get(&did, None).is_none());
        assert!(
            !doc_path(&tmp_dir, &did).exists(),
            "expired doc file should be removed"
        );
    }

    #[test]
    fn fs_update_only_writes_when_newer_iat_or_higher_trust() {
        let (_tmp_dir, cache, did) = setup_fs_cache();
        let now = buckyos_get_unix_timestamp();
        let doc_v1 = build_owner_doc(now, "jwt-v1");
        let exp_v1 = doc_v1.clone().to_json_value().unwrap().get("exp").unwrap().as_u64().unwrap();
        assert!(cache.update(did.clone(), None, doc_v1.clone(), exp_v1, DEFAULT_PROVIDER_TRUST_LEVEL));

        let doc_v2 = build_owner_doc(now + 1_000, "jwt-v2");
        let exp_v2 = doc_v2.clone().to_json_value().unwrap().get("exp").unwrap().as_u64().unwrap();
        assert!(cache.update(did.clone(), None, doc_v2.clone(), exp_v2, DEFAULT_PROVIDER_TRUST_LEVEL));
        assert_eq!(cache.get(&did, None).unwrap().0, doc_v2);

        let older_doc = build_owner_doc(now + 500, "jwt-old");
        assert!(!cache.update(did.clone(), None, older_doc, now + DEFAULT_EXPIRE_TIME, DEFAULT_PROVIDER_TRUST_LEVEL));
        assert_eq!(cache.get(&did, None).unwrap().0, doc_v2);
    }

    #[test]
    fn fs_update_uses_exp_when_iat_missing() {
        let (_tmp_dir, cache, did) = setup_fs_cache();
        let now = buckyos_get_unix_timestamp();
        let exp_v1 = now + (DEFAULT_EXPIRE_TIME * 2);
        let doc_v1 = build_zone_doc(&did, exp_v1, "no-iat-v1");
        assert!(cache.update(did.clone(), None, doc_v1.clone(), exp_v1, DEFAULT_PROVIDER_TRUST_LEVEL));

        let exp_v2 = exp_v1 + 10;
        let doc_v2 = build_zone_doc(&did, exp_v2, "no-iat-v2");
        assert!(cache.update(did.clone(), None, doc_v2.clone(), exp_v2, DEFAULT_PROVIDER_TRUST_LEVEL));

        let exp_v3 = exp_v2 - 5;
        let doc_v3 = build_zone_doc(&did, exp_v3, "no-iat-older");
        assert!(!cache.update(did.clone(), None, doc_v3, exp_v3, DEFAULT_PROVIDER_TRUST_LEVEL));

        assert_eq!(cache.get(&did, None).unwrap().0, doc_v2);
    }

    #[test]
    fn db_roundtrip() -> Result<(), NSError> {
        let (_tmp_dir, cache, did) = setup_db_cache();
        let now = buckyos_get_unix_timestamp();
        let exp = now + DEFAULT_EXPIRE_TIME;
        let doc = build_zone_doc(&did, exp, "db");
        assert!(cache.update(did.clone(), None, doc.clone(), exp, DEFAULT_PROVIDER_TRUST_LEVEL));
        let loaded = cache.get(&did, None).expect("doc should be available");
        assert_eq!(loaded.0, doc);
        Ok(())
    }
}
