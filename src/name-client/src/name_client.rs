#![allow(unused)]

use crate::addr_rtt_db::{
    AutoFlushHandle, CleanupReport, Config as AddrRttDbConfig, ConnectionOutcome,
    PersistencePolicy, RankedAddress, RttDatabase, SortPolicy,
};
use crate::dns_provider::DnsProvider;
use crate::doc_cache::{CacheBackend, DIDDocumentCache, UnauthenticatedInfoCache};
use crate::name_query::NameQuery;
use crate::provider::RecordType;
use crate::{
    CacheStatus, LocalAuthorityOverrideStore, NameInfo, NsProvider, ResolvePolicy, ResolveWarning,
    ResolvedDocument, DEFAULT_DID_DOC_TYPE, DOC_TYPE_INFO,
};
use buckyos_kit::{buckyos_get_unix_timestamp, get_buckyos_system_etc_dir};
use core::error;
use name_lib::DEFAULT_EXPIRE_TIME;
use name_lib::*;

use log::*;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, RwLock as StdRwLock};
use tokio::sync::RwLock;

pub const DEFAULT_PROVIDER_TRUST_LEVEL: i32 = 100;
pub const ROOT_TRUST_LEVEL: i32 = 0;
pub const DNS_TRUST_LEVEL: i32 = 16;
const MAX_CACHED_LOCAL_IPS: usize = 8;

#[derive(Clone)]
pub struct NameClientConfig {
    pub enable_cache: bool,
    pub local_cache_dir: Option<String>,
    pub cache_backend: CacheBackend,
    pub rtt_db_config: AddrRttDbConfig,
}

impl Default for NameClientConfig {
    fn default() -> Self {
        Self {
            enable_cache: true,
            local_cache_dir: None,
            cache_backend: CacheBackend::Filesystem,
            rtt_db_config: AddrRttDbConfig::default(),
        }
    }
}
pub struct NameClient {
    name_query: NameQuery,
    config: NameClientConfig,
    doc_cache: DIDDocumentCache,
    addr_rtt_db: Arc<RttDatabase>,
    _addr_rtt_auto_flush: Option<AutoFlushHandle>,
    cached_local_ips: StdRwLock<Vec<IpAddr>>,
    nameinfo_cache: Option<std::sync::Arc<RwLock<HashMap<String, NameInfo>>>>,
    local_authority_overrides: Arc<LocalAuthorityOverrideStore>,
    unauthenticated_info_cache: UnauthenticatedInfoCache,
}

impl NameClient {
    pub fn new(config: NameClientConfig) -> Self {
        let mut name_query = NameQuery::new();
        //name_query.add_provider(Box::new(DnsProvider::new(None)));
        //name_query.add_provider(Box::new(ZoneProvider::new()));

        let doc_cache_dir = config
            .local_cache_dir
            .as_ref()
            .map(|dir| PathBuf::from(dir));

        let doc_cache = match config.cache_backend {
            CacheBackend::Sqlite => {
                DIDDocumentCache::new_db(doc_cache_dir.clone()).unwrap_or_else(|e| {
                    warn!("init sqlite cache failed ({}), fallback to fs cache", e);
                    DIDDocumentCache::new(doc_cache_dir.clone())
                })
            }
            CacheBackend::Filesystem => DIDDocumentCache::new(doc_cache_dir),
            CacheBackend::Memory => DIDDocumentCache::new_mem(),
        };

        let nameinfo_cache = match config.cache_backend {
            CacheBackend::Memory => Some(std::sync::Arc::new(RwLock::new(HashMap::new()))),
            _ => None,
        };

        let addr_rtt_db = Arc::new(Self::build_rtt_db(
            config.rtt_db_config.clone(),
            config.local_cache_dir.as_deref(),
        ));
        let addr_rtt_auto_flush = addr_rtt_db.spawn_auto_flush();

        Self {
            name_query,
            config: config,
            doc_cache,
            addr_rtt_db,
            _addr_rtt_auto_flush: addr_rtt_auto_flush,
            cached_local_ips: StdRwLock::new(Vec::new()),
            nameinfo_cache,
            local_authority_overrides: Arc::new(LocalAuthorityOverrideStore::new()),
            unauthenticated_info_cache: UnauthenticatedInfoCache::new(),
        }
    }

    /// 写入本地测试/运维 override（设计文档第 7.3 节，类似 hosts 文件）。只应由本地
    /// 管理员、测试框架或显式运维命令调用；不会进入普通 `doc_cache`，也不会被导出。
    pub fn set_local_authority_override(
        &self,
        did: DID,
        doc_type: &str,
        document: EncodedDocument,
        scope: impl Into<String>,
        expires_at: Option<u64>,
    ) {
        self.local_authority_overrides
            .set(did, doc_type, document, scope, expires_at);
    }

    pub fn clear_local_authority_override(&self, did: &DID, doc_type: &str) {
        self.local_authority_overrides.clear(did, doc_type);
    }

    fn build_rtt_db(config: AddrRttDbConfig, local_cache_dir: Option<&str>) -> RttDatabase {
        match &config.persistence {
            PersistencePolicy::Storage { path, .. } => RttDatabase::open(path, config.clone())
                .unwrap_or_else(|e| {
                    warn!("open addr-rtt-db failed ({}), fallback to in-memory db", e);
                    RttDatabase::new(AddrRttDbConfig {
                        persistence: PersistencePolicy::None,
                        ..config
                    })
                }),
            PersistencePolicy::None => {
                if let Some(cache_dir) = local_cache_dir {
                    let path = PathBuf::from(cache_dir).join("addr-rtt.redb");
                    let storage_config = AddrRttDbConfig {
                        persistence: PersistencePolicy::Storage {
                            path,
                            auto_flush_interval: None,
                        },
                        ..config.clone()
                    };
                    let storage_path = match &storage_config.persistence {
                        PersistencePolicy::Storage { path, .. } => path.clone(),
                        PersistencePolicy::None => unreachable!(),
                    };
                    RttDatabase::open(storage_path, storage_config).unwrap_or_else(|e| {
                        warn!(
                            "init addr-rtt-db at cache dir failed ({}), fallback to in-memory db",
                            e
                        );
                        RttDatabase::new(config)
                    })
                } else {
                    RttDatabase::new(config)
                }
            }
        }
    }

    pub async fn add_provider(&self, provider: Box<dyn NsProvider>, trust_level: Option<i32>) {
        let trust_level = trust_level.unwrap_or(DEFAULT_PROVIDER_TRUST_LEVEL);
        self.name_query.add_provider(provider, trust_level).await;
    }

    pub fn update_did_cache(
        &self,
        did: DID,
        doc_type: Option<&str>,
        doc: EncodedDocument,
    ) -> NSResult<()> {
        let exp = Self::extract_exp(&doc)
            .unwrap_or_else(|| buckyos_get_unix_timestamp() + DEFAULT_EXPIRE_TIME);
        self.doc_cache
            .update(did, doc_type, doc, exp, DEFAULT_PROVIDER_TRUST_LEVEL);
        Ok(())
    }

    pub fn invalidate_did_cache(&self, did: DID, doc_type: Option<&str>) {
        if self.config.enable_cache {
            self.doc_cache.delete(did, doc_type);
        }
    }

    //only for test
    pub async fn add_nameinfo_cache(&self, name: &str, info: NameInfo) -> NSResult<()> {
        let cache = match &self.nameinfo_cache {
            Some(cache) => cache,
            None => return Ok(()),
        };

        let mut real_name = name.to_string();
        if name.starts_with("did") {
            if let Ok(name_did) = DID::from_str(name) {
                if name_did.method.as_str() == "web" {
                    real_name = name_did.id.clone();
                }
            }
        }

        //let mut cache = cache.blocking_write();
        cache.write().await.insert(real_name, info);
        Ok(())
    }

    pub async fn resolve(&self, name: &str, record_type: Option<RecordType>) -> NSResult<NameInfo> {
        let mut real_name = name.to_string();
        if name.starts_with("did") {
            let name_did = DID::from_str(name);
            if name_did.is_ok() {
                let name_did = name_did.unwrap();
                if name_did.method.as_str() == "web" {
                    info!(
                        "resolve did:web is some as resolve host: {}",
                        name_did.id.as_str()
                    );
                    real_name = name_did.id.clone();
                }
            }
        }

        if let Some(cache) = &self.nameinfo_cache {
            let cache = cache.read().await;
            if let Some(info) = cache.get(real_name.as_str()) {
                if Self::nameinfo_matches_record_type(record_type, info) {
                    return Ok(info.clone());
                }
            }
        }

        let name_info = self
            .name_query
            .query(real_name.as_str(), record_type)
            .await?;
        return Ok(name_info);
    }

    pub async fn resolve_ip(&self, name: &str) -> NSResult<IpAddr> {
        self.resolve_ips(name)
            .await?
            .into_iter()
            .next()
            .ok_or_else(|| NSError::NotFound("A record not found".to_string()))
    }

    pub async fn resolve_ips(&self, name: &str) -> NSResult<Vec<IpAddr>> {
        if let Some(ips) = self.resolve_signed_device_document_ips(name).await? {
            return self.sort_resolved_ips(&ips);
        }

        let mut merged_ips = Vec::new();
        let mut first_error = None;

        match self.resolve(name, None).await {
            Ok(name_info) => Self::merge_unique_ips(&mut merged_ips, &name_info.address),
            Err(err) => first_error = Some(err),
        }

        match self.resolve_device_info_ips(name).await {
            Ok(device_info_ips) => Self::merge_unique_ips(&mut merged_ips, &device_info_ips),
            Err(err) => {
                if first_error.is_none() {
                    first_error = Some(err);
                }
            }
        }

        if !merged_ips.is_empty() {
            return self.sort_resolved_ips(&merged_ips);
        }

        Err(first_error.unwrap_or_else(|| NSError::NotFound("A record not found".to_string())))
    }

    pub async fn resolve_with_local_ip(
        &self,
        name: &str,
        record_type: Option<RecordType>,
        local_ip: IpAddr,
        port: u16,
        policy: Option<&SortPolicy>,
    ) -> NSResult<NameInfo> {
        self.remember_local_ip(local_ip);
        let mut name_info = self.resolve(name, record_type).await?;
        if name_info.address.len() <= 1 {
            return Ok(name_info);
        }

        name_info.address = self.rank_ip_addrs(local_ip, &name_info.address, port, policy);
        Ok(name_info)
    }

    pub fn rank_ip_addrs(
        &self,
        local_ip: IpAddr,
        addresses: &[IpAddr],
        port: u16,
        policy: Option<&SortPolicy>,
    ) -> Vec<IpAddr> {
        let socket_addrs: Vec<_> = addresses
            .iter()
            .copied()
            .map(|addr| SocketAddr::new(addr, port))
            .collect();
        self.rank_socket_addrs(local_ip, &socket_addrs, policy)
            .into_iter()
            .map(|item| item.addr.ip())
            .collect()
    }

    pub fn rank_socket_addrs(
        &self,
        local_ip: IpAddr,
        addresses: &[SocketAddr],
        policy: Option<&SortPolicy>,
    ) -> Vec<RankedAddress> {
        let default_policy;
        let policy = match policy {
            Some(policy) => policy,
            None => {
                default_policy = SortPolicy::default();
                &default_policy
            }
        };
        self.addr_rtt_db.rank(local_ip, addresses, policy)
    }

    pub fn get_address_stats(
        &self,
        local_ip: IpAddr,
        remote: SocketAddr,
    ) -> Option<crate::AddressStats> {
        self.addr_rtt_db.get_stats(local_ip, remote)
    }

    pub fn record_connection_outcome(
        &self,
        local_ip: IpAddr,
        remote: SocketAddr,
        outcome: ConnectionOutcome,
    ) -> NSResult<()> {
        self.remember_local_ip(local_ip);
        self.addr_rtt_db
            .record(local_ip, remote, outcome)
            .map_err(|e| NSError::Failed(format!("record addr-rtt outcome failed: {}", e)))
    }

    pub fn flush_rtt_db(&self) -> NSResult<()> {
        self.addr_rtt_db
            .flush()
            .map_err(|e| NSError::Failed(format!("flush addr-rtt-db failed: {}", e)))
    }

    pub fn cleanup_rtt_db(&self) -> CleanupReport {
        self.addr_rtt_db.cleanup()
    }

    pub fn cleanup_rtt_db_with_policy(&self, policy: &SortPolicy) -> CleanupReport {
        self.addr_rtt_db.cleanup_with_policy(policy)
    }

    pub fn forget_local_rtt(&self, local_ip: IpAddr) -> usize {
        self.addr_rtt_db.forget_local(local_ip)
    }

    fn sort_resolved_ips(&self, addresses: &[IpAddr]) -> NSResult<Vec<IpAddr>> {
        if addresses.is_empty() {
            return Err(NSError::NotFound("A record not found".to_string()));
        }
        if addresses.len() == 1 {
            return Ok(addresses.to_vec());
        }

        let local_ips = self.cached_local_ips();
        if local_ips.is_empty() {
            return Ok(addresses.to_vec());
        }

        let policy = SortPolicy::default();
        let ranked = self.addr_rtt_db.rank_ips(&local_ips, addresses, &policy);
        Ok(ranked.into_iter().map(|item| item.ip).collect())
    }

    async fn resolve_signed_device_document_ips(
        &self,
        name: &str,
    ) -> NSResult<Option<Vec<IpAddr>>> {
        let did = DID::from_str(name)?;
        let doc = match self.resolve_did(&did, None).await {
            Ok(doc) => doc,
            Err(NSError::NotFound(_)) => return Ok(None),
            Err(err) => return Err(err),
        };
        Self::extract_signed_device_document_ips(doc)
    }

    async fn resolve_device_info_ips(&self, name: &str) -> NSResult<Vec<IpAddr>> {
        let did = DID::from_str(name)?;
        let doc = self.resolve_did(&did, Some("info")).await?;
        Self::extract_device_info_ips(doc)
    }

    fn extract_signed_device_document_ips(doc: EncodedDocument) -> NSResult<Option<Vec<IpAddr>>> {
        if !doc.is_proof() {
            return Ok(None);
        }

        let value = doc.to_json_value()?;
        if value.get("device_type").is_none() {
            return Ok(None);
        }

        let device_config = serde_json::from_value::<DeviceConfig>(value).map_err(|e| {
            NSError::Failed(format!(
                "parse device config from DID document failed: {}",
                e
            ))
        })?;
        if device_config.ips.is_empty() {
            return Err(NSError::NotFound(
                "device document does not contain ips".to_string(),
            ));
        }
        Ok(Some(device_config.ips))
    }

    fn extract_device_info_ips(doc: EncodedDocument) -> NSResult<Vec<IpAddr>> {
        let value = doc.to_json_value()?;
        let device_info = serde_json::from_value::<DeviceInfo>(value).map_err(|e| {
            NSError::Failed(format!("parse device info from DID document failed: {}", e))
        })?;
        let ips = device_info.merged_ips();
        if ips.is_empty() {
            return Err(NSError::NotFound(
                "device info does not contain ips".to_string(),
            ));
        }
        Ok(ips)
    }

    fn merge_unique_ips(ips: &mut Vec<IpAddr>, new_ips: &[IpAddr]) {
        for ip in new_ips {
            if !ips.contains(ip) {
                ips.push(*ip);
            }
        }
    }

    fn remember_local_ip(&self, local_ip: IpAddr) {
        let Ok(mut cached) = self.cached_local_ips.write() else {
            return;
        };

        if let Some(pos) = cached.iter().position(|ip| *ip == local_ip) {
            cached.remove(pos);
        }
        cached.insert(0, local_ip);
        cached.truncate(MAX_CACHED_LOCAL_IPS);
    }

    fn cached_local_ips(&self) -> Vec<IpAddr> {
        self.cached_local_ips
            .read()
            .map(|cached| cached.clone())
            .unwrap_or_default()
    }

    fn nameinfo_matches_record_type(record_type: Option<RecordType>, info: &NameInfo) -> bool {
        match record_type {
            None => true,
            Some(RecordType::A) => info.address.iter().any(|ip| ip.is_ipv4()),
            Some(RecordType::AAAA) => info.address.iter().any(|ip| ip.is_ipv6()),
            Some(RecordType::CAA) => !info.caa.is_empty() || !info.name.is_empty(),
            Some(RecordType::CNAME) => info.cname.is_some(),
            Some(RecordType::HTTPS) => !info.name.is_empty(),
            Some(RecordType::TXT) => !info.txt.is_empty(),
            Some(RecordType::PTR) => !info.ptr_records.is_empty(),
            _ => false,
        }
    }

    fn validate_doc_replay_guard(
        &self,
        did: &DID,
        doc_type: Option<&str>,
        doc: &EncodedDocument,
    ) -> NSResult<()> {
        if self.config.enable_cache {
            self.doc_cache
                .validate_owner_revocation(did, doc_type, doc)?;
        }
        Ok(())
    }

    fn is_expired(&self, exp: u64) -> bool {
        exp <= buckyos_get_unix_timestamp()
    }

    fn extract_exp(doc: &EncodedDocument) -> Option<u64> {
        doc.clone()
            .to_json_value()
            .ok()
            .and_then(|value| value.get("exp").and_then(|ts| ts.as_u64()))
    }

    pub async fn resolve_did_ex(
        &self,
        did: &DID,
        doc_type: Option<&str>,
        policy: ResolvePolicy,
    ) -> NSResult<ResolvedDocument> {
        let policy = policy.with_local_authority_override(self.local_authority_overrides.clone());
        let canonical_doc_type = doc_type.unwrap_or(DEFAULT_DID_DOC_TYPE);
        let is_unauthenticated_info = canonical_doc_type == DOC_TYPE_INFO;
        let mut cached_trust_level: i32 = i32::MAX;
        let mut cached_result: Option<(EncodedDocument, u64, i32)> = None;
        if self.config.enable_cache {
            // unauthenticated_info_cache 和 doc_cache（verified_cache 的角色）是两个
            // 独立的存储：Info 类结果只按 iat/ttl 判断可用性，不做 owner replay guard。
            cached_result = if is_unauthenticated_info {
                self.unauthenticated_info_cache.get(did, doc_type)
            } else {
                self.doc_cache.get(did, doc_type)
            };
            if let Some((_, exp, trust_level)) = cached_result.as_ref() {
                if !self.is_expired(*exp) {
                    info!(
                        "cached did:{}#{} is not expired, trust_level set to: {}",
                        did.to_string(),
                        doc_type.unwrap_or(""),
                        trust_level
                    );
                    cached_trust_level = *trust_level;
                }
            }
            if !is_unauthenticated_info {
                if let Some((doc, _, _)) = cached_result.as_ref() {
                    if let Err(err) = self.validate_doc_replay_guard(did, doc_type, doc) {
                        info!(
                            "cached did:{}#{} rejected by owner replay guard: {}",
                            did.to_string(),
                            doc_type.unwrap_or(""),
                            err
                        );
                        self.doc_cache.delete(did.clone(), doc_type);
                        cached_result = None;
                        cached_trust_level = i32::MAX;
                    }
                }
            }
        }

        let max_trust_level = if is_unauthenticated_info {
            None
        } else {
            Some(cached_trust_level)
        };
        let reslove_result = self
            .name_query
            .query_did_ex(did, Some(canonical_doc_type), max_trust_level, policy)
            .await;

        match reslove_result {
            Ok(mut resolved) => {
                let exp = Self::extract_exp(&resolved.document)
                    .unwrap_or_else(|| buckyos_get_unix_timestamp() + DEFAULT_EXPIRE_TIME);
                let result_trust_level = resolved
                    .resolution_metadata
                    .authority_rank
                    .unwrap_or(DEFAULT_PROVIDER_TRUST_LEVEL);
                info!(
                    "resolve did:{}#{} success, exp:{}",
                    did.to_string(),
                    canonical_doc_type,
                    exp
                );
                // local_authority_override 命中的结果不受普通验证/缓存规则约束：
                // 它不应该反过来污染普通 doc_cache（设计文档第 7.3 节第 3 条），
                // 也不需要走 owner replay guard（override 本身就是最高优先级）。
                let is_local_override = resolved
                    .resolution_metadata
                    .warnings
                    .contains(&ResolveWarning::LocalAuthorityOverride);
                if !is_unauthenticated_info && !is_local_override {
                    self.validate_doc_replay_guard(did, doc_type, &resolved.document)?;
                }
                if self.config.enable_cache {
                    if is_unauthenticated_info {
                        self.unauthenticated_info_cache.insert(
                            did,
                            doc_type,
                            resolved.document.clone(),
                            exp,
                            result_trust_level,
                        );
                    } else if !is_local_override {
                        self.doc_cache.update(
                            did.clone(),
                            doc_type,
                            resolved.document.clone(),
                            exp,
                            result_trust_level,
                        );
                    }
                }
                resolved.resolution_metadata.cache_status = Some(if cached_result.is_some() {
                    CacheStatus::Refresh
                } else {
                    CacheStatus::Miss
                });
                Ok(resolved)
            }
            Err(result_error) => match result_error {
                NSError::Disabled(msg) => {
                    info!("{}'s doc disabled, delete cache", did.to_string());
                    if self.config.enable_cache {
                        self.doc_cache.delete(did.clone(), doc_type);
                    }
                    Err(NSError::Disabled(msg))
                }
                _ => {
                    if let Some((doc, exp, trust_level)) = cached_result {
                        info!(
                            "resolve did:{}#{} by cache success, exp:{}",
                            did.to_string(),
                            canonical_doc_type,
                            exp
                        );
                        let cache_status = if is_unauthenticated_info {
                            CacheStatus::UnauthenticatedInfoHit
                        } else {
                            CacheStatus::Fallback
                        };
                        return Ok(ResolvedDocument::from_cache(
                            doc,
                            did,
                            canonical_doc_type,
                            exp,
                            trust_level,
                            cache_status,
                        ));
                    }
                    Err(result_error)
                }
            },
        }
    }

    pub async fn resolve_did(
        &self,
        did: &DID,
        doc_type: Option<&str>,
    ) -> NSResult<EncodedDocument> {
        Ok(self
            .resolve_did_ex(did, doc_type, ResolvePolicy::default())
            .await?
            .document)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::Duration;

    use crate::{init_name_lib_ex, resolve_did};

    use super::*;
    use async_trait::async_trait;
    use buckyos_kit::init_logging;
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use tempfile::tempdir;
    use tokio::sync::Mutex;

    const TEST_OWNER_PRIVATE_KEY_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIJBRONAzbwpIOwm0ugIQNyZJrDXxZF7HoPWAZesMedOr
-----END PRIVATE KEY-----"#;

    fn make_doc(iat: u64, exp: u64, marker: &str) -> EncodedDocument {
        EncodedDocument::JsonLd(serde_json::json!({
            "iat": iat,
            "exp": exp,
            "marker": marker
        }))
    }

    // 构造一个自持有（owner == 自己）的 zone 文档 + 对应 owner 文档，两者都用同一把
    // 测试 key 签名，用来在需要真实 owner 验签的 resolve 路径测试里替代裸的 JsonLd
    // 占位文档。
    fn build_self_owned_zone_and_owner(
        did: &DID,
        iat: u64,
        marker: &str,
    ) -> (EncodedDocument, EncodedDocument) {
        let private_key = EncodingKey::from_ed_pem(TEST_OWNER_PRIVATE_KEY_PEM.as_bytes()).unwrap();
        let jwk = test_owner_public_jwk();

        let mut owner = OwnerConfig::new(
            did.clone(),
            "owner".to_string(),
            "owner@test".to_string(),
            jwk.clone(),
        );
        owner.version_seq = Some(0);
        let owner_doc = owner.encode(Some(&private_key)).unwrap();

        let mut zone = ZoneConfig::new(did.clone(), did.clone(), jwk);
        zone.iat = iat;
        zone.exp = iat + 3600 * 24 * 365;
        zone.version_seq = Some(1);
        zone.extra_info
            .insert("marker".to_string(), serde_json::json!(marker));
        let zone_doc = zone.encode(Some(&private_key)).unwrap();

        (zone_doc, owner_doc)
    }

    #[test]
    fn test_nameinfo_matches_record_type_for_caa() {
        let mut info = NameInfo::new("web3.buckyos.ai");
        assert!(NameClient::nameinfo_matches_record_type(
            Some(RecordType::CAA),
            &info
        ));

        info.caa.push("0 issue \"letsencrypt.org\"".to_string());
        assert!(NameClient::nameinfo_matches_record_type(
            Some(RecordType::CAA),
            &info
        ));

        let empty = NameInfo::default();
        assert!(!NameClient::nameinfo_matches_record_type(
            Some(RecordType::CAA),
            &empty
        ));
    }

    #[test]
    fn test_record_type_from_str_and_to_string_for_caa() {
        assert_eq!(RecordType::from_str("CAA"), Some(RecordType::CAA));
        assert_eq!(RecordType::CAA.to_string(), "CAA");
    }

    #[test]
    fn test_nameinfo_matches_record_type_for_https() {
        let info = NameInfo::new("web3.buckyos.ai");
        assert!(NameClient::nameinfo_matches_record_type(
            Some(RecordType::HTTPS),
            &info
        ));

        let empty = NameInfo::default();
        assert!(!NameClient::nameinfo_matches_record_type(
            Some(RecordType::HTTPS),
            &empty
        ));
    }

    #[test]
    fn test_record_type_from_str_and_to_string_for_https() {
        assert_eq!(RecordType::from_str("HTTPS"), Some(RecordType::HTTPS));
        assert_eq!(RecordType::HTTPS.to_string(), "HTTPS");
    }

    #[derive(Clone, Copy)]
    enum MockErr {
        NotFound,
        Disabled,
    }

    struct MockProvider {
        doc: Option<EncodedDocument>,
        owner_doc: Option<EncodedDocument>,
        err: Option<MockErr>,
    }

    impl MockProvider {
        fn ok(doc: EncodedDocument) -> Self {
            Self {
                doc: Some(doc),
                owner_doc: None,
                err: None,
            }
        }

        fn err(err: MockErr) -> Self {
            Self {
                doc: None,
                owner_doc: None,
                err: Some(err),
            }
        }

        // 让同一个 provider 也能在 doc_type == "owner" 时返回一份不同的文档，
        // 用来搭建"文档 -> owner 递归验签"需要的最小可验证链路。
        fn with_owner_doc(mut self, owner_doc: EncodedDocument) -> Self {
            self.owner_doc = Some(owner_doc);
            self
        }
    }

    #[async_trait]
    impl NsProvider for MockProvider {
        fn get_id(&self) -> String {
            "mock".to_string()
        }

        async fn query(
            &self,
            _name: &str,
            _record_type: Option<RecordType>,
            _from_ip: Option<std::net::IpAddr>,
        ) -> NSResult<NameInfo> {
            Err(NSError::NotFound("mock".into()))
        }

        async fn query_did(
            &self,
            _did: &DID,
            doc_type: Option<&str>,
            _from_ip: Option<std::net::IpAddr>,
        ) -> NSResult<EncodedDocument> {
            if doc_type == Some("owner") {
                if let Some(owner_doc) = self.owner_doc.as_ref() {
                    return Ok(owner_doc.clone());
                }
            }
            match self.err {
                Some(MockErr::NotFound) => Err(NSError::NotFound("mock notfound".into())),
                Some(MockErr::Disabled) => Err(NSError::Disabled("mock disabled".into())),
                None => Ok(self.doc.as_ref().unwrap().clone()),
            }
        }
    }

    struct ReplayGuardProvider {
        owner_doc: EncodedDocument,
        fresh_doc: EncodedDocument,
    }

    #[async_trait]
    impl NsProvider for ReplayGuardProvider {
        fn get_id(&self) -> String {
            "replay-guard-provider".to_string()
        }

        async fn query(
            &self,
            _name: &str,
            _record_type: Option<RecordType>,
            _from_ip: Option<std::net::IpAddr>,
        ) -> NSResult<NameInfo> {
            Err(NSError::NotFound("not implemented".into()))
        }

        async fn query_did(
            &self,
            _did: &DID,
            doc_type: Option<&str>,
            _from_ip: Option<std::net::IpAddr>,
        ) -> NSResult<EncodedDocument> {
            if doc_type == Some("owner") {
                return Ok(self.owner_doc.clone());
            }
            Ok(self.fresh_doc.clone())
        }
    }

    struct NameMockProvider {
        called_name: Arc<Mutex<Option<String>>>,
    }

    #[async_trait]
    impl NsProvider for NameMockProvider {
        fn get_id(&self) -> String {
            "name-mock".to_string()
        }

        async fn query(
            &self,
            name: &str,
            _record_type: Option<RecordType>,
            _from_ip: Option<std::net::IpAddr>,
        ) -> NSResult<NameInfo> {
            let mut guard = self.called_name.lock().await;
            *guard = Some(name.to_string());
            Ok(NameInfo::new(name))
        }

        async fn query_did(
            &self,
            _did: &DID,
            _doc_type: Option<&str>,
            _from_ip: Option<std::net::IpAddr>,
        ) -> NSResult<EncodedDocument> {
            Err(NSError::NotFound("not implemented".into()))
        }
    }

    fn client_with_temp_cache(cache_backend: CacheBackend) -> NameClient {
        let tmp = tempdir().unwrap().keep(); // 持久化临时目录，避免 drop 后被删除
        let cfg = NameClientConfig {
            enable_cache: true,
            local_cache_dir: Some(tmp.to_string_lossy().to_string()),
            cache_backend,
            ..Default::default()
        };
        NameClient::new(cfg)
    }

    fn get_default_web3_bridge_config() -> HashMap<String, String> {
        let mut config = HashMap::new();
        config.insert("bns".to_string(), "web3.buckyos.ai".to_string());

        config
    }

    fn test_owner_public_jwk() -> jsonwebtoken::jwk::Jwk {
        serde_json::from_value(serde_json::json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "T4Quc1L6Ogu4N2tTKOvneV1yYnBcmhP89B_RsuFsJZ8"
        }))
        .unwrap()
    }

    fn make_jwt_doc(version_seq: u64, iat: u64, marker: &str) -> EncodedDocument {
        let private_key = EncodingKey::from_ed_pem(TEST_OWNER_PRIVATE_KEY_PEM.as_bytes()).unwrap();
        let jwt = encode(
            &Header::new(Algorithm::EdDSA),
            &serde_json::json!({
                "version_seq": version_seq,
                "iat": iat,
                "exp": iat + DEFAULT_EXPIRE_TIME,
                "marker": marker
            }),
            &private_key,
        )
        .unwrap();
        EncodedDocument::Jwt(jwt)
    }

    #[tokio::test]
    async fn prefer_higher_trust_provider_over_cached() {
        let mut client = client_with_temp_cache(CacheBackend::Filesystem);
        let did = DID::from_str("did:web:example.com").unwrap();
        let now = buckyos_get_unix_timestamp();
        let cached = make_doc(now, now + 1000, "cached");
        // "fresh" 走真正需要验证的 zone doc_type，必须是一份能通过 owner 递归验签的
        // 真实文档；未验证签名的裸 JsonLd 现在会被拒绝，从而错误地退回到 cache。
        let (fresh, owner_doc) = build_self_owned_zone_and_owner(&did, now + 10, "fresh");

        // 先写入低优先级缓存
        client
            .doc_cache
            .insert(did.clone(), None, cached.clone(), now + 1000, 50);

        // 高优先级 provider
        client
            .add_provider(
                Box::new(MockProvider::ok(fresh.clone()).with_owner_doc(owner_doc)),
                Some(10),
            )
            .await;

        let resolved = client.resolve_did(&did, None).await.unwrap();
        assert_eq!(resolved, fresh);
    }

    #[tokio::test]
    async fn fallback_to_cache_on_error() {
        let mut client = client_with_temp_cache(CacheBackend::Filesystem);
        let did = DID::from_str("did:web:example.com").unwrap();
        let now = buckyos_get_unix_timestamp();
        let cached = make_doc(now, now + 1000, "cached");

        client
            .doc_cache
            .insert(did.clone(), None, cached.clone(), now + 1000, 50);

        // 高优先级 provider 返回 NotFound
        client
            .add_provider(Box::new(MockProvider::err(MockErr::NotFound)), Some(10))
            .await;

        let resolved = client.resolve_did(&did, None).await.unwrap();
        assert_eq!(resolved, cached);
    }

    #[tokio::test]
    async fn local_authority_override_wins_over_provider_and_skips_normal_cache() {
        // T4.1: override 命中时优先级高于任何 provider 返回的结果，带
        // LocalAuthorityOverride warning，且不会被写入普通 doc_cache。
        let mut client = client_with_temp_cache(CacheBackend::Filesystem);
        let did = DID::from_str("did:web:example.com").unwrap();
        let now = buckyos_get_unix_timestamp();
        let (provider_doc, owner_doc) = build_self_owned_zone_and_owner(&did, now, "from-provider");
        let override_doc = make_doc(now, now + 1000, "from-override");

        client
            .add_provider(
                Box::new(MockProvider::ok(provider_doc.clone()).with_owner_doc(owner_doc)),
                Some(0),
            )
            .await;
        client.set_local_authority_override(
            did.clone(),
            "zone",
            override_doc.clone(),
            "test-env",
            None,
        );

        let resolved = client
            .resolve_did_ex(&did, None, ResolvePolicy::default())
            .await
            .unwrap();
        assert_eq!(resolved.document, override_doc);
        assert!(resolved
            .resolution_metadata
            .warnings
            .contains(&ResolveWarning::LocalAuthorityOverride));

        // override 不应该泄漏进普通 doc_cache。
        assert!(client.doc_cache.get(&did, None).is_none());

        // 清除 override 后应该正常回落到 provider 的结果。
        client.clear_local_authority_override(&did, "zone");
        let resolved_after_clear = client.resolve_did(&did, None).await.unwrap();
        assert_eq!(resolved_after_clear, provider_doc);
    }

    struct FlakyInfoProvider {
        doc: EncodedDocument,
        calls: std::sync::atomic::AtomicUsize,
    }

    #[async_trait]
    impl NsProvider for FlakyInfoProvider {
        fn get_id(&self) -> String {
            "flaky-info".to_string()
        }

        async fn query(
            &self,
            _name: &str,
            _record_type: Option<RecordType>,
            _from_ip: Option<std::net::IpAddr>,
        ) -> NSResult<NameInfo> {
            Err(NSError::NotFound("not implemented".into()))
        }

        async fn query_did(
            &self,
            _did: &DID,
            _doc_type: Option<&str>,
            _from_ip: Option<std::net::IpAddr>,
        ) -> NSResult<EncodedDocument> {
            let call = self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if call == 0 {
                Ok(self.doc.clone())
            } else {
                Err(NSError::NotFound("provider gone".into()))
            }
        }
    }

    #[tokio::test]
    async fn unauthenticated_info_cache_serves_as_fallback_when_provider_goes_away() {
        // T4.2: unauthenticated_info_cache 是独立于 doc_cache 的存储，Info 结果第一次
        // 解析成功后应该被缓存下来；provider 之后失效时能从这个独立 cache 回落。
        let client = NameClient::new(NameClientConfig {
            enable_cache: true,
            cache_backend: CacheBackend::Memory,
            ..Default::default()
        });
        let did = DID::from_str("did:web:flaky.example").unwrap();
        let now = buckyos_get_unix_timestamp();
        let doc = make_doc(now, now + 1000, "flaky-info");

        client
            .add_provider(
                Box::new(FlakyInfoProvider {
                    doc: doc.clone(),
                    calls: std::sync::atomic::AtomicUsize::new(0),
                }),
                Some(10),
            )
            .await;

        let first = client.resolve_did(&did, Some("info")).await.unwrap();
        assert_eq!(first, doc);

        // provider 从第二次调用起总是失败，只有 unauthenticated_info_cache 命中才能
        // 让这次解析成功。
        let second = client
            .resolve_did_ex(&did, Some("info"), ResolvePolicy::default())
            .await
            .unwrap();
        assert_eq!(second.document, doc);
        assert_eq!(
            second.resolution_metadata.cache_status,
            Some(CacheStatus::UnauthenticatedInfoHit)
        );
        assert!(second
            .resolution_metadata
            .warnings
            .contains(&ResolveWarning::UnauthenticatedInfoCache));

        // 这个 cache 完全独立于普通 doc_cache（verified_cache 的角色）。
        assert!(client.doc_cache.get(&did, Some("info")).is_none());
    }

    #[tokio::test]
    async fn owner_replay_guard_rejects_cached_stale_jwt_and_resolves_again() {
        let client = NameClient::new(NameClientConfig {
            enable_cache: true,
            cache_backend: CacheBackend::Memory,
            ..Default::default()
        });
        let did = DID::from_str("did:web:example.com").unwrap();
        let now = buckyos_get_unix_timestamp();
        let owner_valid_iat = now + 200;
        let private_key = EncodingKey::from_ed_pem(TEST_OWNER_PRIVATE_KEY_PEM.as_bytes()).unwrap();

        // old/fresh 现在必须是真实可验证的 zone 文档（owner 递归 + 签名校验），
        // 不能再用裸 JWT payload 占位——不然会在新验证路径里被当成
        // "不可识别的文档" 直接拒绝，而不是走到 replay guard 这一层的判断。
        let mut old_zone = ZoneConfig::new(did.clone(), did.clone(), test_owner_public_jwk());
        old_zone.iat = now + 150;
        old_zone.exp = old_zone.iat + DEFAULT_EXPIRE_TIME;
        old_zone.version_seq = Some(1);
        let old_doc = old_zone.encode(Some(&private_key)).unwrap();

        let mut fresh_zone = ZoneConfig::new(did.clone(), did.clone(), test_owner_public_jwk());
        fresh_zone.iat = now + 300;
        fresh_zone.exp = fresh_zone.iat + DEFAULT_EXPIRE_TIME;
        fresh_zone.version_seq = Some(2);
        let fresh_doc = fresh_zone.encode(Some(&private_key)).unwrap();

        let mut owner_config = OwnerConfig::new(
            did.clone(),
            "example".to_string(),
            "example@example.com".to_string(),
            test_owner_public_jwk(),
        );
        owner_config.version_seq = Some(0);
        owner_config.mini_version_seq = Some(1);
        owner_config.valid_iat = Some(owner_valid_iat);
        let owner_doc = owner_config.encode(Some(&private_key)).unwrap();

        client.doc_cache.insert(
            did.clone(),
            None,
            old_doc,
            now + DEFAULT_EXPIRE_TIME,
            DEFAULT_PROVIDER_TRUST_LEVEL,
        );
        client.doc_cache.insert(
            did.clone(),
            Some("owner"),
            owner_doc.clone(),
            now + DEFAULT_EXPIRE_TIME,
            DEFAULT_PROVIDER_TRUST_LEVEL,
        );
        client
            .add_provider(
                Box::new(ReplayGuardProvider {
                    owner_doc,
                    fresh_doc: fresh_doc.clone(),
                }),
                Some(DEFAULT_PROVIDER_TRUST_LEVEL),
            )
            .await;

        let resolved = client.resolve_did(&did, None).await.unwrap();
        assert_eq!(resolved, fresh_doc);
    }

    #[tokio::test]
    async fn disabled_removes_cache() {
        let tmp_dir = tempdir().unwrap().keep();
        let did = DID::from_str("did:web:example.com").unwrap();
        let now = buckyos_get_unix_timestamp();
        let cached = make_doc(now, now + 1000, "cached");

        let mut client = NameClient::new(NameClientConfig {
            enable_cache: true,
            local_cache_dir: Some(tmp_dir.to_string_lossy().to_string()),
            cache_backend: CacheBackend::Filesystem,
            ..Default::default()
        });

        client
            .doc_cache
            .insert(did.clone(), None, cached.clone(), now + 1000, 50);

        client
            .add_provider(Box::new(MockProvider::err(MockErr::Disabled)), Some(10))
            .await;

        let err = client.resolve_did(&did, None).await.unwrap_err();
        assert!(matches!(err, NSError::Disabled(_)));
        assert!(client.doc_cache.get(&did, None).is_none());
    }

    #[tokio::test]
    async fn cache_from_high_priority_works_when_only_low_priority_available() {
        // 第一次客户端：有高优先级 provider，生成缓存
        let tmp_dir = tempdir().unwrap().keep();
        let did = DID::from_str("did:web:example.com").unwrap();
        let now = buckyos_get_unix_timestamp();
        let (high_doc, owner_doc) = build_self_owned_zone_and_owner(&did, now, "high");

        let mut client_high = NameClient::new(NameClientConfig {
            enable_cache: true,
            local_cache_dir: Some(tmp_dir.to_string_lossy().to_string()),
            cache_backend: CacheBackend::Filesystem,
            ..Default::default()
        });

        client_high
            .add_provider(
                Box::new(MockProvider::ok(high_doc.clone()).with_owner_doc(owner_doc)),
                Some(10),
            )
            .await;

        let resolved_first = client_high.resolve_did(&did, None).await.unwrap();
        assert_eq!(resolved_first, high_doc);

        // 第二次客户端：只配置低优先级 provider（会返回 NotFound），但使用同一缓存目录
        let mut client_low_only = NameClient::new(NameClientConfig {
            enable_cache: true,
            local_cache_dir: Some(tmp_dir.to_string_lossy().to_string()),
            cache_backend: CacheBackend::Filesystem,
            ..Default::default()
        });

        client_low_only
            .add_provider(Box::new(MockProvider::err(MockErr::NotFound)), Some(50))
            .await;

        // 期望通过已有缓存成功返回
        let resolved_again = client_low_only.resolve_did(&did, None).await.unwrap();
        assert_eq!(resolved_again, high_doc);
    }

    #[tokio::test]
    async fn resolve_from_default_cache_without_providers() {
        // 使用默认的 NameClient 配置，但指定临时缓存目录，模拟默认 did-cache 行为
        let tmp_dir = tempdir().unwrap().keep();
        let did = DID::from_str("did:web:cache.only").unwrap();
        let now = buckyos_get_unix_timestamp();
        let cached_doc = make_doc(now, now + 1800, "cache-only");

        let mut client = NameClient::new(NameClientConfig {
            enable_cache: true,
            local_cache_dir: Some(tmp_dir.to_string_lossy().to_string()),
            cache_backend: CacheBackend::Filesystem,
            ..Default::default()
        });

        client.doc_cache.insert(
            did.clone(),
            None,
            cached_doc.clone(),
            now + 1800,
            DEFAULT_PROVIDER_TRUST_LEVEL,
        );

        // 未配置任何 provider，仍应直接从缓存返回
        let resolved = client.resolve_did(&did, None).await.unwrap();
        assert_eq!(resolved, cached_doc);
    }

    #[tokio::test]
    async fn resolve_via_init_name_lib_with_mock_provider() {
        init_logging("test-name-client", false);
        let now = buckyos_get_unix_timestamp();
        let doc = make_doc(now, now + 600, "init-mock");
        let did = DID::from_str("did:web:mock.example").unwrap();

        if crate::GLOBAL_NAME_CLIENT.get().is_none() {
            let tmp_dir = tempdir().unwrap().keep();
            let mut client = NameClient::new(NameClientConfig {
                enable_cache: true,
                local_cache_dir: Some(tmp_dir.to_string_lossy().to_string()),
                cache_backend: CacheBackend::Filesystem,
                ..Default::default()
            });
            client
                .add_provider(Box::new(MockProvider::err(MockErr::NotFound)), Some(10))
                .await;
            let _ = crate::GLOBAL_NAME_CLIENT.set(client);
            let _ = crate::IS_NAME_LIB_INITED.set(true);
        }

        crate::update_did_cache(did.clone(), None, doc.clone())
            .await
            .unwrap();
        let resolved = resolve_did(&did, None).await.unwrap();
        assert_eq!(resolved, doc);
    }

    #[tokio::test]
    async fn resolve_did_web_normalizes_to_host_name() {
        let called_name = Arc::new(Mutex::new(None));
        let provider = NameMockProvider {
            called_name: called_name.clone(),
        };
        let tmp_dir = tempdir().unwrap().keep();
        let client = NameClient::new(NameClientConfig {
            enable_cache: false,
            local_cache_dir: Some(tmp_dir.to_string_lossy().to_string()),
            cache_backend: CacheBackend::Filesystem,
            ..Default::default()
        });
        client
            .add_provider(Box::new(provider), Some(DEFAULT_PROVIDER_TRUST_LEVEL))
            .await;

        let result = client.resolve("did:web:example.com", None).await.unwrap();
        assert_eq!(result.name, "example.com".to_string());

        let observed = called_name.lock().await.clone().unwrap();
        assert_eq!(observed, "example.com".to_string());
    }

    #[tokio::test]
    async fn resolve_with_local_ip_reorders_addresses_by_rtt_history() {
        struct AddressProvider;

        #[async_trait]
        impl NsProvider for AddressProvider {
            fn get_id(&self) -> String {
                "address-provider".to_string()
            }

            async fn query(
                &self,
                _name: &str,
                _record_type: Option<RecordType>,
                _from_ip: Option<std::net::IpAddr>,
            ) -> NSResult<NameInfo> {
                Ok(NameInfo::from_address_vec(
                    "example.com",
                    vec![
                        "192.0.2.10".parse().unwrap(),
                        "2001:db8::1".parse().unwrap(),
                    ],
                ))
            }

            async fn query_did(
                &self,
                _did: &DID,
                _doc_type: Option<&str>,
                _from_ip: Option<std::net::IpAddr>,
            ) -> NSResult<EncodedDocument> {
                Err(NSError::NotFound("not implemented".into()))
            }
        }

        let local_ip: IpAddr = "10.0.0.1".parse().unwrap();
        let ipv4_remote: SocketAddr = "192.0.2.10:443".parse().unwrap();
        let ipv6_remote: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        let client = NameClient::new(NameClientConfig {
            cache_backend: CacheBackend::Memory,
            ..Default::default()
        });
        client
            .add_provider(
                Box::new(AddressProvider),
                Some(DEFAULT_PROVIDER_TRUST_LEVEL),
            )
            .await;

        client
            .record_connection_outcome(
                local_ip,
                ipv4_remote,
                ConnectionOutcome::Success {
                    rtt: Duration::from_millis(120),
                    layer: crate::MeasurementLayer::Tcp,
                },
            )
            .unwrap();
        client
            .record_connection_outcome(
                local_ip,
                ipv6_remote,
                ConnectionOutcome::Success {
                    rtt: Duration::from_millis(20),
                    layer: crate::MeasurementLayer::Tcp,
                },
            )
            .unwrap();

        let resolved = client
            .resolve_with_local_ip("example.com", Some(RecordType::A), local_ip, 443, None)
            .await
            .unwrap();
        assert_eq!(
            resolved.address[0],
            "2001:db8::1".parse::<IpAddr>().unwrap()
        );
    }

    #[tokio::test]
    async fn resolve_ip_uses_cached_local_ip_and_rtt_history() {
        struct AddressProvider;

        #[async_trait]
        impl NsProvider for AddressProvider {
            fn get_id(&self) -> String {
                "address-provider".to_string()
            }

            async fn query(
                &self,
                _name: &str,
                _record_type: Option<RecordType>,
                _from_ip: Option<std::net::IpAddr>,
            ) -> NSResult<NameInfo> {
                Ok(NameInfo::from_address_vec(
                    "example.com",
                    vec!["192.0.2.10".parse().unwrap(), "192.0.2.20".parse().unwrap()],
                ))
            }

            async fn query_did(
                &self,
                _did: &DID,
                _doc_type: Option<&str>,
                _from_ip: Option<std::net::IpAddr>,
            ) -> NSResult<EncodedDocument> {
                Err(NSError::NotFound("not implemented".into()))
            }
        }

        let local_ip: IpAddr = "10.0.0.1".parse().unwrap();
        let slow_remote: SocketAddr = "192.0.2.10:443".parse().unwrap();
        let fast_remote: SocketAddr = "192.0.2.20:8443".parse().unwrap();
        let client = NameClient::new(NameClientConfig {
            cache_backend: CacheBackend::Memory,
            ..Default::default()
        });
        client
            .add_provider(
                Box::new(AddressProvider),
                Some(DEFAULT_PROVIDER_TRUST_LEVEL),
            )
            .await;

        client
            .record_connection_outcome(
                local_ip,
                slow_remote,
                ConnectionOutcome::Success {
                    rtt: Duration::from_millis(120),
                    layer: crate::MeasurementLayer::Tcp,
                },
            )
            .unwrap();
        client
            .record_connection_outcome(
                local_ip,
                fast_remote,
                ConnectionOutcome::Success {
                    rtt: Duration::from_millis(20),
                    layer: crate::MeasurementLayer::Tcp,
                },
            )
            .unwrap();

        let resolved = client.resolve_ip("example.com").await.unwrap();
        assert_eq!(resolved, "192.0.2.20".parse::<IpAddr>().unwrap());
    }

    #[tokio::test]
    async fn resolve_ips_returns_ranked_ipv4_and_ipv6_addresses() {
        struct AddressProvider;

        #[async_trait]
        impl NsProvider for AddressProvider {
            fn get_id(&self) -> String {
                "address-provider".to_string()
            }

            async fn query(
                &self,
                _name: &str,
                _record_type: Option<RecordType>,
                _from_ip: Option<std::net::IpAddr>,
            ) -> NSResult<NameInfo> {
                Ok(NameInfo::from_address_vec(
                    "example.com",
                    vec![
                        "192.0.2.10".parse().unwrap(),
                        "2001:db8::1".parse().unwrap(),
                    ],
                ))
            }

            async fn query_did(
                &self,
                _did: &DID,
                _doc_type: Option<&str>,
                _from_ip: Option<std::net::IpAddr>,
            ) -> NSResult<EncodedDocument> {
                Err(NSError::NotFound("not implemented".into()))
            }
        }

        let local_ip: IpAddr = "10.0.0.1".parse().unwrap();
        let ipv4_remote: SocketAddr = "192.0.2.10:443".parse().unwrap();
        let ipv6_remote: SocketAddr = "[2001:db8::1]:8443".parse().unwrap();
        let client = NameClient::new(NameClientConfig {
            cache_backend: CacheBackend::Memory,
            ..Default::default()
        });
        client
            .add_provider(
                Box::new(AddressProvider),
                Some(DEFAULT_PROVIDER_TRUST_LEVEL),
            )
            .await;

        client
            .record_connection_outcome(
                local_ip,
                ipv4_remote,
                ConnectionOutcome::Success {
                    rtt: Duration::from_millis(120),
                    layer: crate::MeasurementLayer::Tcp,
                },
            )
            .unwrap();
        client
            .record_connection_outcome(
                local_ip,
                ipv6_remote,
                ConnectionOutcome::Success {
                    rtt: Duration::from_millis(20),
                    layer: crate::MeasurementLayer::Tcp,
                },
            )
            .unwrap();

        let resolved = client.resolve_ips("example.com").await.unwrap();
        assert_eq!(
            resolved,
            vec![
                "2001:db8::1".parse::<IpAddr>().unwrap(),
                "192.0.2.10".parse::<IpAddr>().unwrap(),
            ]
        );
    }

    #[tokio::test]
    async fn resolve_ips_prefers_signed_device_document_over_unverified_ips() {
        struct MixedProvider {
            signed_doc: EncodedDocument,
            info_doc: EncodedDocument,
            owner_doc: EncodedDocument,
        }

        #[async_trait]
        impl NsProvider for MixedProvider {
            fn get_id(&self) -> String {
                "mixed-provider".to_string()
            }

            async fn query(
                &self,
                _name: &str,
                _record_type: Option<RecordType>,
                _from_ip: Option<std::net::IpAddr>,
            ) -> NSResult<NameInfo> {
                Ok(NameInfo::from_address_vec(
                    "ood1.example",
                    vec!["192.0.2.30".parse().unwrap()],
                ))
            }

            async fn query_did(
                &self,
                _did: &DID,
                doc_type: Option<&str>,
                _from_ip: Option<std::net::IpAddr>,
            ) -> NSResult<EncodedDocument> {
                match doc_type {
                    Some("info") => Ok(self.info_doc.clone()),
                    Some("owner") => Ok(self.owner_doc.clone()),
                    None => Ok(self.signed_doc.clone()),
                    _ => Err(NSError::NotFound("not implemented".into())),
                }
            }
        }

        let owner_private_key_pem = r#"
        -----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIJBRONAzbwpIOwm0ugIQNyZJrDXxZF7HoPWAZesMedOr
        -----END PRIVATE KEY-----
        "#;
        let owner_private_key = EncodingKey::from_ed_pem(owner_private_key_pem.as_bytes()).unwrap();
        let device_did = DID::from_str("did:web:ood1.example").unwrap();

        // 设备文档必须能递归解析到一个真实可验证的 owner，这里让设备"自持有"，
        // 用同一把 key 签发 owner 文档。
        let mut owner_config = OwnerConfig::new(
            device_did.clone(),
            "ood1-owner".to_string(),
            "ood1-owner@test".to_string(),
            test_owner_public_jwk(),
        );
        owner_config.version_seq = Some(0);
        let owner_doc = owner_config.encode(Some(&owner_private_key)).unwrap();

        let mut signed_device_config = DeviceConfig::new(
            "ood1",
            "5bUuyWLOKyCre9az_IhJVIuOw8bA0gyKjstcYGHbaPE".to_string(),
        );
        signed_device_config.owner = device_did.clone();
        signed_device_config.ips = vec!["192.0.2.10".parse().unwrap()];
        let signed_doc = signed_device_config
            .encode(Some(&owner_private_key))
            .unwrap();

        let mut info_config = signed_device_config.clone();
        info_config.ips = vec!["192.0.2.20".parse().unwrap()];
        let mut device_info = DeviceInfo::from_device_doc(&info_config);
        device_info.all_ip = vec!["192.0.2.40".parse().unwrap()];
        let info_doc = EncodedDocument::JsonLd(serde_json::to_value(&device_info).unwrap());

        let client = NameClient::new(NameClientConfig {
            enable_cache: false,
            cache_backend: CacheBackend::Memory,
            ..Default::default()
        });
        client
            .add_provider(
                Box::new(MixedProvider {
                    signed_doc,
                    info_doc,
                    owner_doc,
                }),
                Some(DEFAULT_PROVIDER_TRUST_LEVEL),
            )
            .await;

        let resolved = client.resolve_ips("did:web:ood1.example").await.unwrap();
        assert_eq!(resolved, vec!["192.0.2.10".parse::<IpAddr>().unwrap()]);
    }

    #[tokio::test]
    async fn resolve_ips_merges_nameinfo_and_device_info_ips() {
        struct MergeProvider {
            info_doc: EncodedDocument,
        }

        #[async_trait]
        impl NsProvider for MergeProvider {
            fn get_id(&self) -> String {
                "merge-provider".to_string()
            }

            async fn query(
                &self,
                _name: &str,
                _record_type: Option<RecordType>,
                _from_ip: Option<std::net::IpAddr>,
            ) -> NSResult<NameInfo> {
                Ok(NameInfo::from_address_vec(
                    "ood1.example",
                    vec!["192.0.2.10".parse().unwrap(), "192.0.2.20".parse().unwrap()],
                ))
            }

            async fn query_did(
                &self,
                _did: &DID,
                doc_type: Option<&str>,
                _from_ip: Option<std::net::IpAddr>,
            ) -> NSResult<EncodedDocument> {
                match doc_type {
                    Some("info") => Ok(self.info_doc.clone()),
                    _ => Err(NSError::NotFound("not implemented".into())),
                }
            }
        }

        let mut device_config = DeviceConfig::new(
            "ood1",
            "5bUuyWLOKyCre9az_IhJVIuOw8bA0gyKjstcYGHbaPE".to_string(),
        );
        device_config.ips = vec![
            "192.0.2.20".parse().unwrap(),
            "2001:db8::1".parse().unwrap(),
        ];
        let mut device_info = DeviceInfo::from_device_doc(&device_config);
        device_info.all_ip = vec!["192.0.2.30".parse().unwrap()];
        let info_doc = EncodedDocument::JsonLd(serde_json::to_value(&device_info).unwrap());

        let client = NameClient::new(NameClientConfig {
            enable_cache: false,
            cache_backend: CacheBackend::Memory,
            ..Default::default()
        });
        client
            .add_provider(
                Box::new(MergeProvider { info_doc }),
                Some(DEFAULT_PROVIDER_TRUST_LEVEL),
            )
            .await;

        let resolved = client.resolve_ips("did:web:ood1.example").await.unwrap();
        assert_eq!(
            resolved,
            vec![
                "192.0.2.10".parse::<IpAddr>().unwrap(),
                "192.0.2.20".parse::<IpAddr>().unwrap(),
                "2001:db8::1".parse::<IpAddr>().unwrap(),
                "192.0.2.30".parse::<IpAddr>().unwrap(),
            ]
        );
    }

    #[tokio::test]
    async fn resolve_ips_falls_back_to_device_info_ips() {
        let mut device_config = DeviceConfig::new(
            "ood1",
            "5bUuyWLOKyCre9az_IhJVIuOw8bA0gyKjstcYGHbaPE".to_string(),
        );
        device_config.ips = vec![
            "192.0.2.10".parse().unwrap(),
            "2001:db8::1".parse().unwrap(),
        ];
        let mut device_info = DeviceInfo::from_device_doc(&device_config);
        device_info.all_ip = vec!["192.0.2.10".parse().unwrap(), "192.0.2.20".parse().unwrap()];
        let doc = EncodedDocument::JsonLd(serde_json::to_value(&device_info).unwrap());

        let client = NameClient::new(NameClientConfig {
            enable_cache: false,
            cache_backend: CacheBackend::Memory,
            ..Default::default()
        });
        client
            .add_provider(
                Box::new(MockProvider::ok(doc)),
                Some(DEFAULT_PROVIDER_TRUST_LEVEL),
            )
            .await;

        let resolved = client.resolve_ips("did:web:ood1.example").await.unwrap();
        assert_eq!(
            resolved,
            vec![
                "192.0.2.10".parse::<IpAddr>().unwrap(),
                "2001:db8::1".parse::<IpAddr>().unwrap(),
                "192.0.2.20".parse::<IpAddr>().unwrap(),
            ]
        );
    }
}
