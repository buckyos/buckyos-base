#![allow(unused)]

use crate::addr_rtt_db::{
    AutoFlushHandle, CleanupReport, Config as AddrRttDbConfig, ConnectionOutcome,
    PersistencePolicy, RankedAddress, RttDatabase, SortPolicy,
};
use crate::dns_provider::DnsProvider;
use crate::doc_cache::{CacheBackend, DIDDocumentCache};
use crate::name_query::NameQuery;
use crate::provider::RecordType;
use crate::{NameInfo, NsProvider};
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
        }
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
        let name_info = self.resolve(name, None).await?;
        self.sort_resolved_ips(&name_info.address)
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
            Some(RecordType::TXT) => !info.txt.is_empty() || !info.did_documents.is_empty(),
            Some(RecordType::PTR) => !info.ptr_records.is_empty(),
            _ => false,
        }
    }

    fn is_doc_type_is_owner(&self, doc_type: Option<&str>) -> bool {
        if doc_type.is_some() {
            let doc_type = doc_type.unwrap();
            if doc_type == "owner" {
                return true;
            }
        }
        return false;
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

    pub async fn resolve_did(
        &self,
        did: &DID,
        doc_type: Option<&str>,
    ) -> NSResult<EncodedDocument> {
        let mut cached_trust_level: i32 = i32::MAX;
        let mut cached_result: Option<(EncodedDocument, u64, i32)> = None;
        if self.config.enable_cache {
            cached_result = self.doc_cache.get(did, doc_type);
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
        }

        let reslove_result = self
            .name_query
            .query_did(did, doc_type, Some(cached_trust_level))
            .await;

        match reslove_result {
            Ok((did_doc, exp, result_trust_level)) => {
                info!(
                    "resolve did:{}#{} success, exp:{}",
                    did.to_string(),
                    doc_type.unwrap_or(""),
                    exp
                );
                if self.config.enable_cache {
                    self.doc_cache.update(
                        did.clone(),
                        doc_type,
                        did_doc.clone(),
                        exp,
                        result_trust_level,
                    );
                }
                Ok(did_doc)
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
                    if let Some((doc, exp, _)) = cached_result {
                        info!(
                            "resolve did:{}#{} by cache success, exp:{}",
                            did.to_string(),
                            doc_type.unwrap_or(""),
                            exp
                        );
                        return Ok(doc.clone());
                    }
                    Err(result_error)
                }
            },
        }
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
    use tempfile::tempdir;
    use tokio::sync::Mutex;

    fn make_doc(iat: u64, exp: u64, marker: &str) -> EncodedDocument {
        EncodedDocument::JsonLd(serde_json::json!({
            "iat": iat,
            "exp": exp,
            "marker": marker
        }))
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
        err: Option<MockErr>,
    }

    impl MockProvider {
        fn ok(doc: EncodedDocument) -> Self {
            Self {
                doc: Some(doc),
                err: None,
            }
        }

        fn err(err: MockErr) -> Self {
            Self {
                doc: None,
                err: Some(err),
            }
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
            _doc_type: Option<&str>,
            _from_ip: Option<std::net::IpAddr>,
        ) -> NSResult<EncodedDocument> {
            match self.err {
                Some(MockErr::NotFound) => Err(NSError::NotFound("mock notfound".into())),
                Some(MockErr::Disabled) => Err(NSError::Disabled("mock disabled".into())),
                None => Ok(self.doc.as_ref().unwrap().clone()),
            }
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

    #[tokio::test]
    async fn prefer_higher_trust_provider_over_cached() {
        let mut client = client_with_temp_cache(CacheBackend::Filesystem);
        let did = DID::from_str("did:web:example.com").unwrap();
        let now = buckyos_get_unix_timestamp();
        let cached = make_doc(now, now + 1000, "cached");
        let fresh = make_doc(now + 10, now + 2000, "fresh");

        // 先写入低优先级缓存
        client
            .doc_cache
            .insert(did.clone(), None, cached.clone(), now + 1000, 50);

        // 高优先级 provider
        client
            .add_provider(Box::new(MockProvider::ok(fresh.clone())), Some(10))
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
        let high_doc = make_doc(now, now + 2000, "high");

        let mut client_high = NameClient::new(NameClientConfig {
            enable_cache: true,
            local_cache_dir: Some(tmp_dir.to_string_lossy().to_string()),
            cache_backend: CacheBackend::Filesystem,
            ..Default::default()
        });

        client_high
            .add_provider(Box::new(MockProvider::ok(high_doc.clone())), Some(10))
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
}
