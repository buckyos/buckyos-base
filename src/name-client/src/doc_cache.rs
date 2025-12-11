use std::fs;
use std::path::PathBuf;

use buckyos_kit::{
    buckyos_get_unix_timestamp, get_buckyos_service_local_data_dir, get_buckyos_system_etc_dir,
};
use log::{debug, error, warn};
use name_lib::{EncodedDocument, DEFAULT_EXPIRE_TIME, DID};

/// Handles DID document caching backed solely by the filesystem.
pub struct DIDDocumentCache {
    cache_dir: PathBuf,
}

impl DIDDocumentCache {
    /// Create a new DIDDocumentCache with the given cache directory.
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

    pub fn get(&self, did: &DID) -> Option<EncodedDocument> {
        let doc = self.load_from_disk(did)?;
        if Self::is_doc_expired(&doc) {
            warn!("did doc is expired, delete it: {}", did.to_raw_host_name());
            self.delete_local_file(did);
            return None;
        }
        Some(doc)
    }

    pub fn update(&self, did: DID, doc: EncodedDocument) -> bool {
        let new_iat = Self::get_doc_iat(&doc);
        if let Some(existing) = self.get(&did) {
            let current_iat = Self::get_doc_iat(&existing);
            if Self::should_skip_update(new_iat, current_iat, &doc, &existing) {
                return false;
            }
        }

        self.insert(did, doc);
        true
    }

    pub fn insert(&self, did: DID, doc: EncodedDocument) {
        self.save_to_disk(&did, &doc);
    }

    fn should_skip_update(
        new_iat: Option<u64>,
        current_iat: Option<u64>,
        new_doc: &EncodedDocument,
        current_doc: &EncodedDocument,
    ) -> bool {
        match (new_iat, current_iat) {
            (Some(new_iat), Some(current_iat)) => new_iat <= current_iat,
            _ => new_doc == current_doc,
        }
    }

    fn load_from_disk(&self, did: &DID) -> Option<EncodedDocument> {
        let file_path = self
            .cache_dir
            .join(format!("{}.doc.json", did.to_raw_host_name()));

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

    fn save_to_disk(&self, did: &DID, doc: &EncodedDocument) {
        let file_path = self
            .cache_dir
            .join(format!("{}.doc.json", did.to_raw_host_name()));
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

    fn delete_local_file(&self, did: &DID) {
        let file_path = self
            .cache_dir
            .join(format!("{}.doc.json", did.to_raw_host_name()));
        match fs::remove_file(&file_path) {
            Ok(_) => debug!("removed expired did doc: {}", file_path.display()),
            Err(err) => {
                if err.kind() != std::io::ErrorKind::NotFound {
                    warn!("failed to remove did doc {}: {}", file_path.display(), err);
                }
            }
        }
    }

    fn is_doc_expired(doc: &EncodedDocument) -> bool {
        match Self::extract_timestamp(doc, "exp") {
            Some(exp_ts) => exp_ts <= buckyos_get_unix_timestamp(),
            None => false,
        }
    }

    fn get_doc_iat(doc: &EncodedDocument) -> Option<u64> {
        let iat = Self::extract_timestamp(doc, "iat");
        if iat.is_some() {
            return iat;
        }
        let exp = Self::extract_timestamp(doc, "exp");
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::EncodingKey;
    use name_lib::{DIDDocumentTrait, OwnerConfig, ZoneBootConfig};
    use serde_json::json;
    use std::collections::HashMap;
    use tempfile::tempdir;

    const TEST_OWNER_PRIVATE_KEY_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIJBRONAzbwpIOwm0ugIQNyZJrDXxZF7HoPWAZesMedOr
-----END PRIVATE KEY-----"#;

    const TEST_OWNER_PUBLIC_JWK: &str = r#"{
  "kty": "OKP",
  "crv": "Ed25519",
  "x": "T4Quc1L6Ogu4N2tTKOvneV1yYnBcmhP89B_RsuFsJZ8"
}"#;

    fn setup_cache() -> (tempfile::TempDir, DIDDocumentCache, DID) {
        let tmp_dir = tempdir().unwrap();
        let cache = DIDDocumentCache::new(Some(tmp_dir.path().to_path_buf()));
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
    fn insert_and_get_preserves_document() {
        let (tmp_dir, cache, did) = setup_cache();
        let now = buckyos_get_unix_timestamp();
        let exp = now + DEFAULT_EXPIRE_TIME;
        let doc = build_zone_doc(&did, exp, "json-v1");
        cache.insert(did.clone(), doc.clone());

        assert!(doc_path(&tmp_dir, &did).exists());
        let loaded = cache.get(&did).expect("doc should be available");
        assert_eq!(loaded, doc);
    }

    #[test]
    fn get_removes_expired_document() {
        let (tmp_dir, cache, did) = setup_cache();
        let past_exp = buckyos_get_unix_timestamp().saturating_sub(10);
        let doc = build_zone_doc(&did, past_exp, "expired");
        cache.insert(did.clone(), doc);

        assert!(cache.get(&did).is_none());
        assert!(
            !doc_path(&tmp_dir, &did).exists(),
            "expired doc file should be removed"
        );
    }

    #[test]
    fn update_only_writes_when_newer_iat() {
        let (tmp_dir, cache, did) = setup_cache();
        let now = buckyos_get_unix_timestamp();
        let doc_v1 = build_owner_doc(now, "jwt-v1");
        assert!(cache.update(did.clone(), doc_v1.clone()));

        let doc_v2 = build_owner_doc(now + 1_000, "jwt-v2");
        assert!(cache.update(did.clone(), doc_v2.clone()));
        assert_eq!(cache.get(&did).unwrap(), doc_v2);

        let older_doc = build_owner_doc(now + 500, "jwt-old");
        assert!(!cache.update(did.clone(), older_doc));
        assert_eq!(cache.get(&did).unwrap(), doc_v2);
        assert!(doc_path(&tmp_dir, &did).exists());
    }

    #[test]
    fn update_uses_exp_when_iat_missing() {
        let (_tmp_dir, cache, did) = setup_cache();
        let now = buckyos_get_unix_timestamp();
        let exp_v1 = now + (DEFAULT_EXPIRE_TIME * 2);
        let doc_v1 = build_zone_doc(&did, exp_v1, "no-iat-v1");
        assert!(cache.update(did.clone(), doc_v1.clone()));

        let exp_v2 = exp_v1 + 10;
        let doc_v2 = build_zone_doc(&did, exp_v2, "no-iat-v2");
        assert!(cache.update(did.clone(), doc_v2.clone()));

        let exp_v3 = exp_v2 - 5;
        let doc_v3 = build_zone_doc(&did, exp_v3, "no-iat-older");
        assert!(!cache.update(did.clone(), doc_v3));

        assert_eq!(cache.get(&did).unwrap(), doc_v2);
    }
}
