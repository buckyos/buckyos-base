#![allow(unused)]

use crate::addr_rtt_db::{
    AutoFlushHandle, CleanupReport, Config as AddrRttDbConfig, ConnectionOutcome,
    PersistencePolicy, RankedAddress, RttDatabase, SortPolicy,
};
use crate::dns_provider::DnsProvider;
use crate::doc_cache::{
    CacheBackend, CacheEvidence, CacheLookup, DIDDocumentCache, UnauthenticatedInfoCache,
};
use crate::name_query::{NameQuery, ResolveOutcome};
use crate::provider::RecordType;
use crate::{
    is_key_class_method, BodyEvidence, CacheStatus, DidDocType, DocumentStatus,
    LocalAuthorityOverrideStore, NameInfo, NsProvider, ResolvePolicy, ResolveWarning,
    ResolvedDocument,
};
use buckyos_kit::{buckyos_get_unix_timestamp, get_buckyos_system_etc_dir};
use core::error;
use name_lib::DEFAULT_EXPIRE_TIME;
use name_lib::*;

use log::*;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, RwLock as StdRwLock};
use tokio::sync::RwLock;

/// 旧注册接口的 trust_level 常量。method registry(T2.2)之后 trust_level 不再
/// 参与解析决策,保留常量只为兼容旧调用方的传参。
pub const DEFAULT_PROVIDER_TRUST_LEVEL: i32 = 100;
pub const ROOT_TRUST_LEVEL: i32 = 0;
pub const DNS_TRUST_LEVEL: i32 = 16;
pub const DEFAULT_DEVICE_INFO_CACHE_TTL_SECS: u64 = 3600 * 24 * 7;
/// 已验证文档缓存的 TTL 上限:文档自身的 exp 可能长达数年,但缓存快路径会在
/// TTL 内完全跳过权威源查询,吊销可见性 ≤ TTL,所以要单独封顶。
pub const DOC_CACHE_TTL_SECS: u64 = 3600;
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
        let name_query = NameQuery::new();

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

    /// 写入本地测试/运维 override(简化文档第 7 节,类似 hosts 文件)。只应由本地
    /// 管理员、测试框架或显式运维命令调用;不会进入普通 `doc_cache`,也不会被导出。
    pub fn set_local_authority_override(
        &self,
        did: DID,
        doc_type: DidDocType,
        document: EncodedDocument,
        scope: impl Into<String>,
        expires_at: Option<u64>,
    ) {
        self.local_authority_overrides
            .set(did, &doc_type, document, scope, expires_at);
    }

    pub fn clear_local_authority_override(&self, did: &DID, doc_type: DidDocType) {
        self.local_authority_overrides.clear(did, &doc_type);
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

    // ---- provider 注册(T2.2 method registry) ----

    /// 注册某 method 的权威发布渠道(一个 method 至多一个)。
    pub async fn set_method_authority(
        &self,
        method: impl Into<String>,
        provider: Box<dyn NsProvider>,
    ) {
        self.name_query.set_method_authority(method, provider).await;
    }

    /// 追加某 method 的补充源(显式有序,first-win)。
    pub async fn add_method_supplement(
        &self,
        method: impl Into<String>,
        provider: Box<dyn NsProvider>,
    ) {
        self.name_query
            .add_method_supplement(method, provider)
            .await;
    }

    /// 注册当前 zone 的权威读取端(zone_resolver,介绍文档第 5、7 节)。
    /// buckyos 启动后调用,provider 通常是指向 zone 内服务的
    /// `BaseHttpProvider`(如 `http://127.0.0.1:3180`)。只受理同 zone did
    /// 的查询,对这些 did 排在 method 权威读取端之前(同一发布渠道的
    /// 另一个读取端)。同一 zone_did 重复注册时取代旧读取端。
    pub async fn set_zone_authority(&self, zone_did: DID, provider: Box<dyn NsProvider>) {
        self.name_query.set_zone_authority(zone_did, provider).await;
    }

    /// 注销某 zone 的权威读取端(zone 迁移/退出时)。
    pub async fn clear_zone_authority(&self, zone_did: &DID) {
        self.name_query.clear_zone_authority(zone_did).await;
    }

    /// 覆盖某 method 的免验证 doc_type 契约(默认只有 `info`)。
    pub async fn set_no_proof_doc_types(&self, method: &str, doc_types: HashSet<DidDocType>) {
        self.name_query
            .set_no_proof_doc_types(method, doc_types)
            .await;
    }

    /// 注册普通名字解析(DNS 语义)的 provider。
    pub async fn add_dns_provider(&self, provider: Box<dyn NsProvider>) {
        self.name_query.add_dns_provider(provider).await;
    }

    /// 兼容旧注册接口:trust_level 已不再参与解析决策。按 provider 自声明的
    /// method 注册(首个注册者成为权威渠道);不声明 method 的 provider 只服务
    /// 普通名字解析。新代码请使用显式注册接口。
    pub async fn add_provider(&self, provider: Box<dyn NsProvider>, trust_level: Option<i32>) {
        self.name_query.add_provider(provider, trust_level).await;
    }

    // ---- 缓存旁路写入 ----

    /// push / 社交网络等旁路拿到的文档从这里进入缓存,证据等级按"未验证"对待:
    /// 它压不过已发布/已验证条目,也翻不了负状态(简化文档第 5 节)。
    pub fn update_did_cache(
        &self,
        did: DID,
        doc_type: Option<DidDocType>,
        doc: EncodedDocument,
    ) -> NSResult<()> {
        let exp = Self::cache_ttl_exp(&doc);
        self.doc_cache
            .update(did, doc_type, doc, exp, CacheEvidence::Unverified);
        Ok(())
    }

    pub fn add_device_info_cache(&self, did: DID, device_info: DeviceInfo) -> NSResult<()> {
        self.add_device_info_cache_with_ttl(did, device_info, DEFAULT_DEVICE_INFO_CACHE_TTL_SECS)
    }

    pub fn add_device_info_cache_with_ttl(
        &self,
        did: DID,
        device_info: DeviceInfo,
        ttl_secs: u64,
    ) -> NSResult<()> {
        if ttl_secs == 0 {
            return Err(NSError::InvalidParam(
                "device info cache ttl must be greater than zero".to_string(),
            ));
        }
        let doc =
            EncodedDocument::JsonLd(serde_json::to_value(&device_info).map_err(|e| {
                NSError::Failed(format!("serialize device info cache failed: {}", e))
            })?);
        let seen_at = if device_info.update_time == 0 {
            buckyos_get_unix_timestamp()
        } else {
            device_info.update_time
        };
        let exp = seen_at.saturating_add(ttl_secs);
        self.unauthenticated_info_cache.insert(
            &did,
            Some(DidDocType::Info),
            doc,
            exp,
            DEFAULT_PROVIDER_TRUST_LEVEL,
        );
        Ok(())
    }

    pub fn invalidate_did_cache(&self, did: DID, doc_type: Option<DidDocType>) {
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
        if let Some(ips) = self.resolve_device_document_ips(name).await? {
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

    async fn resolve_device_document_ips(&self, name: &str) -> NSResult<Option<Vec<IpAddr>>> {
        let did = DID::from_str(name)?;
        let doc = match self.resolve_did(&did, None).await {
            Ok(doc) => doc,
            Err(NSError::NotFound(_)) => return Ok(None),
            // key 类 DID 不是解析入口:让 resolve_ips 继续走 nameinfo / device-info 路径。
            Err(NSError::InvalidDID(_)) => return Ok(None),
            Err(err) => return Err(err),
        };
        Self::extract_device_document_ips(doc)
    }

    async fn resolve_device_info_ips(&self, name: &str) -> NSResult<Vec<IpAddr>> {
        let did = DID::from_str(name)?;
        let doc = self.resolve_did(&did, Some(DidDocType::Info)).await?;
        Self::extract_device_info_ips(doc)
    }

    fn extract_device_document_ips(doc: EncodedDocument) -> NSResult<Option<Vec<IpAddr>>> {
        let value = doc.to_json_value()?;
        if value.get("device_type").is_none() {
            return Ok(None);
        }

        let device_document = serde_json::from_value::<DeviceDocument>(value).map_err(|e| {
            NSError::Failed(format!(
                "parse device document from DID document failed: {}",
                e
            ))
        })?;
        Ok((!device_document.ips.is_empty()).then_some(device_document.ips))
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
        doc_type: Option<DidDocType>,
        doc: &EncodedDocument,
    ) -> NSResult<()> {
        if self.config.enable_cache {
            self.doc_cache
                .validate_owner_revocation(did, doc_type, doc)?;
        }
        Ok(())
    }

    fn extract_exp(doc: &EncodedDocument) -> Option<u64> {
        doc.clone()
            .to_json_value()
            .ok()
            .and_then(|value| value.get("exp").and_then(|ts| ts.as_u64()))
    }

    /// 缓存条目的 TTL:文档自身 exp 与 `DOC_CACHE_TTL_SECS` 取小。TTL 只决定
    /// 快路径的新鲜度,不代表文档作废时间。
    fn cache_ttl_exp(doc: &EncodedDocument) -> u64 {
        let now = buckyos_get_unix_timestamp();
        let doc_exp = Self::extract_exp(doc).unwrap_or_else(|| now + DEFAULT_EXPIRE_TIME);
        doc_exp.min(now + DOC_CACHE_TTL_SECS)
    }

    /// 文档自身是否已作废(自声明的 exp 已过)。stale cache 兜底只对"TTL 过期
    /// 但文档未作废"的条目开放(策略点④)。
    fn doc_self_expired(doc: &EncodedDocument) -> bool {
        match Self::extract_exp(doc) {
            Some(exp) => exp <= buckyos_get_unix_timestamp(),
            None => false,
        }
    }

    /// resolve_did 外层(简化文档第 3 节第 0/2 步):
    /// 1. 本地覆盖快路径(hosts 语义);
    /// 2. in-TTL positive cache 快路径(`CacheStatus::Hit`);
    /// 3. in-TTL negative cache 快路径(直接报错);
    /// 4. 进入 resolver 主循环;
    /// 5. 只有主循环没产出可核实文档、且没有负状态屏蔽、权威源也没回答 Missing
    ///    时,才按策略用"过期但未作废"的缓存兜底。
    pub async fn resolve_did_ex(
        &self,
        did: &DID,
        doc_type: Option<DidDocType>,
        policy: ResolvePolicy,
    ) -> NSResult<ResolvedDocument> {
        // 硬门禁(T0.1):key 类 DID 不是解析入口,也不查任何缓存。
        if is_key_class_method(&did.method) {
            return Err(NSError::InvalidDID(format!(
                "key-class DID {} is not a legal resolve_did input; keys only appear inside documents",
                did.to_string()
            )));
        }

        let policy = policy.with_local_authority_override(self.local_authority_overrides.clone());
        let allow_stale_cache = policy.allow_stale_cache;
        let doc_type_c = doc_type.clone().unwrap_or_default();

        // Info 契约走独立轻量路径 + UnauthenticatedInfoCache 隔离。
        if self
            .name_query
            .is_no_proof_doc_type(&did.method, &doc_type_c)
            .await
        {
            return self
                .resolve_unproof_info_with_cache(did, doc_type, &doc_type_c, policy)
                .await;
        }

        // 0. 本地覆盖快路径:短路在一切缓存与查询之前,显式打标。
        if let Some(document) = self.local_authority_overrides.get(did, &doc_type_c) {
            return Ok(ResolvedDocument::from_document(
                document,
                did,
                &doc_type_c,
                Some("local-authority-override".to_string()),
                BodyEvidence::Anchored,
                None,
            )
            .with_warning(ResolveWarning::LocalAuthorityOverride));
        }

        let mut cached = if self.config.enable_cache {
            self.doc_cache.lookup(did, doc_type.clone())
        } else {
            None
        };

        // 1. 负状态快路径:负状态是"回答",命中返回错误,不是"查不到"。
        if let Some(CacheLookup::Negative {
            message,
            in_ttl: true,
            ..
        }) = &cached
        {
            return Err(NSError::Disabled(message.clone()));
        }

        // 2. in-TTL positive 快路径。owner replay guard 对缓存命中同样生效。
        if let Some(CacheLookup::Positive {
            doc,
            exp,
            evidence,
            in_ttl: true,
        }) = &cached
        {
            match self.validate_doc_replay_guard(did, doc_type.clone(), doc) {
                Ok(()) => {
                    return Ok(ResolvedDocument::from_cache(
                        doc.clone(),
                        did,
                        &doc_type_c,
                        *exp,
                        evidence.to_body_evidence(),
                        CacheStatus::Hit,
                    ));
                }
                Err(err) => {
                    info!(
                        "cached did:{}#{} rejected by owner replay guard: {}",
                        did.to_string(),
                        doc_type_c,
                        err
                    );
                    self.doc_cache.delete(did.clone(), doc_type.clone());
                    cached = None;
                }
            }
        }

        // 3. resolver 主循环。
        let had_cache = cached.is_some();
        let outcome = self
            .name_query
            .query_did_outcome(did, doc_type.clone(), policy)
            .await?;

        match outcome {
            ResolveOutcome::Resolved(mut resolved) => {
                // 负状态记忆只能被权威源的新"已发布"回答(Anchored 证据)翻篇。
                // Missing + 策略放行的自签名候选是 fallback 路径,不许越过吊销记忆
                // (速查规则 1:吊销之后不允许任何 fallback)。
                if let Some(CacheLookup::Negative { message, .. }) = &cached {
                    if resolved.resolution_metadata.evidence != Some(BodyEvidence::Anchored) {
                        return Err(NSError::Disabled(message.clone()));
                    }
                }
                let is_local_override = resolved
                    .resolution_metadata
                    .warnings
                    .contains(&ResolveWarning::LocalAuthorityOverride);
                if !is_local_override {
                    self.validate_doc_replay_guard(did, doc_type.clone(), &resolved.document)?;
                    if self.config.enable_cache {
                        let evidence = match resolved.resolution_metadata.evidence {
                            Some(BodyEvidence::Anchored) => CacheEvidence::Published,
                            Some(BodyEvidence::NeedProof) => CacheEvidence::Verified,
                            _ => CacheEvidence::Unverified,
                        };
                        let exp = Self::cache_ttl_exp(&resolved.document);
                        self.doc_cache.update(
                            did.clone(),
                            doc_type.clone(),
                            resolved.document.clone(),
                            exp,
                            evidence,
                        );
                    }
                }
                resolved.resolution_metadata.cache_status = Some(if had_cache {
                    CacheStatus::Refresh
                } else {
                    CacheStatus::Miss
                });
                Ok(resolved)
            }
            ResolveOutcome::Negative { status, message } => {
                // 策略点①的缓存动作:吊销删除 positive、写入负状态本身;
                // Migrated 只删除 positive(不是可缓存的终态否决)。
                if self.config.enable_cache {
                    match status {
                        DocumentStatus::Revoked | DocumentStatus::Tombstoned => {
                            self.doc_cache.replace_with_negative(
                                did,
                                doc_type.clone(),
                                &status,
                                &message,
                            );
                        }
                        _ => {
                            self.doc_cache.delete(did.clone(), doc_type.clone());
                        }
                    }
                }
                Err(NSError::Disabled(message))
            }
            ResolveOutcome::NoAnswer {
                authority_missing,
                last_error,
                ..
            } => {
                // 负状态记忆屏蔽一切兜底,且不受 TTL 约束:过期的"已吊销"也只能
                // 被权威源的新回答翻篇。
                if let Some(CacheLookup::Negative { message, .. }) = &cached {
                    return Err(NSError::Disabled(message.clone()));
                }
                // 权威源明确 Missing:旧的 positive cache 与权威答复矛盾,不兜底。
                if authority_missing {
                    return Err(last_error.unwrap_or_else(|| {
                        NSError::NotFound(format!(
                            "{}#{} missing in method authority",
                            did.to_string(),
                            doc_type_c
                        ))
                    }));
                }
                // 策略点④:过期但未作废的缓存兜底。
                if allow_stale_cache {
                    if let Some(CacheLookup::Positive {
                        doc, exp, evidence, ..
                    }) = cached
                    {
                        if !Self::doc_self_expired(&doc) {
                            info!(
                                "resolve did:{}#{} falls back to stale cache",
                                did.to_string(),
                                doc_type_c
                            );
                            return Ok(ResolvedDocument::from_cache(
                                doc,
                                did,
                                &doc_type_c,
                                exp,
                                evidence.to_body_evidence(),
                                CacheStatus::Fallback,
                            ));
                        }
                    }
                }
                Err(last_error.unwrap_or_else(|| NSError::NotFound(did.to_host_name())))
            }
        }
    }

    /// Info 契约的轻量路径:in-TTL 命中 UnauthenticatedInfoCache 即返回,否则查询
    /// 后写回。该缓存与 doc_cache(verified cache)完全隔离。
    async fn resolve_unproof_info_with_cache(
        &self,
        did: &DID,
        doc_type: Option<DidDocType>,
        doc_type_c: &DidDocType,
        policy: ResolvePolicy,
    ) -> NSResult<ResolvedDocument> {
        if self.config.enable_cache {
            if let Some((doc, exp, _rank)) =
                self.unauthenticated_info_cache.get(did, doc_type.clone())
            {
                return Ok(ResolvedDocument::from_cache(
                    doc,
                    did,
                    doc_type_c,
                    exp,
                    BodyEvidence::UnproofInfo,
                    CacheStatus::UnauthenticatedInfoHit,
                ));
            }
        }

        match self
            .name_query
            .query_did_outcome(did, doc_type.clone(), policy)
            .await?
        {
            ResolveOutcome::Resolved(resolved) => {
                if self.config.enable_cache {
                    let now = buckyos_get_unix_timestamp();
                    let exp = Self::extract_exp(&resolved.document)
                        .unwrap_or_else(|| now + DEFAULT_EXPIRE_TIME);
                    self.unauthenticated_info_cache.insert(
                        did,
                        doc_type,
                        resolved.document.clone(),
                        exp,
                        DEFAULT_PROVIDER_TRUST_LEVEL,
                    );
                }
                Ok(resolved)
            }
            ResolveOutcome::Negative { message, .. } => Err(NSError::Disabled(message)),
            ResolveOutcome::NoAnswer { last_error, .. } => Err(last_error.unwrap_or_else(|| {
                NSError::NotFound(format!(
                    "unauthenticated info not found: {}#{}",
                    did.to_string(),
                    doc_type_c
                ))
            })),
        }
    }

    pub async fn resolve_did(
        &self,
        did: &DID,
        doc_type: Option<DidDocType>,
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
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    use crate::{resolve_did, DocumentRef, PublishedState};

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

    /// 没有自声明 exp 的文档:TTL 过期后仍"未作废",是 stale 兜底的合法对象。
    fn make_doc_without_exp(marker: &str) -> EncodedDocument {
        EncodedDocument::JsonLd(serde_json::json!({
            "marker": marker
        }))
    }

    fn test_owner_public_jwk() -> jsonwebtoken::jwk::Jwk {
        serde_json::from_value(serde_json::json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "T4Quc1L6Ogu4N2tTKOvneV1yYnBcmhP89B_RsuFsJZ8"
        }))
        .unwrap()
    }

    // 构造一个自持有(owner == 自己)的 zone 文档 + 对应 owner 文档。
    fn build_self_owned_zone_and_owner(
        did: &DID,
        iat: u64,
        marker: &str,
    ) -> (EncodedDocument, EncodedDocument) {
        let private_key = EncodingKey::from_ed_pem(TEST_OWNER_PRIVATE_KEY_PEM.as_bytes()).unwrap();
        let jwk = test_owner_public_jwk();

        let mut owner = OwnerDocument::new(
            did.clone(),
            "owner".to_string(),
            "owner@test".to_string(),
            jwk.clone(),
        );
        owner.version_seq = Some(0);
        let owner_doc = owner.encode(Some(&private_key)).unwrap();

        let mut zone = ZoneDocument::new(did.clone(), did.clone(), jwk);
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

    /// 可切换行为的权威源 mock:Ok(doc) / NotFound(=Missing) / Failed(=unknown)
    /// / Disabled(=负状态)。
    #[derive(Clone, Copy, PartialEq)]
    enum AuthorityMode {
        Ok,
        Missing,
        Down,
        Disabled,
    }

    struct MockAuthority {
        doc: Option<EncodedDocument>,
        owner_doc: Option<EncodedDocument>,
        mode: Arc<std::sync::Mutex<AuthorityMode>>,
        calls: AtomicUsize,
    }

    impl MockAuthority {
        fn ok(doc: EncodedDocument) -> Self {
            Self {
                doc: Some(doc),
                owner_doc: None,
                mode: Arc::new(std::sync::Mutex::new(AuthorityMode::Ok)),
                calls: AtomicUsize::new(0),
            }
        }

        fn with_mode(mode: AuthorityMode) -> Self {
            Self {
                doc: None,
                owner_doc: None,
                mode: Arc::new(std::sync::Mutex::new(mode)),
                calls: AtomicUsize::new(0),
            }
        }

        /// 返回可在注册后继续切换行为的句柄,模拟"权威源先回答、后断网"。
        fn mode_handle(&self) -> Arc<std::sync::Mutex<AuthorityMode>> {
            self.mode.clone()
        }

        fn with_owner_doc(mut self, owner_doc: EncodedDocument) -> Self {
            self.owner_doc = Some(owner_doc);
            self
        }
    }

    #[async_trait]
    impl NsProvider for MockAuthority {
        fn get_id(&self) -> String {
            "mock-authority".to_string()
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
            doc_type: Option<DidDocType>,
            _from_ip: Option<std::net::IpAddr>,
        ) -> NSResult<EncodedDocument> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if doc_type == Some(DidDocType::Owner) {
                if let Some(owner_doc) = self.owner_doc.as_ref() {
                    return Ok(owner_doc.clone());
                }
            }
            match *self.mode.lock().unwrap() {
                AuthorityMode::Ok => self
                    .doc
                    .clone()
                    .ok_or_else(|| NSError::NotFound("no doc".into())),
                AuthorityMode::Missing => Err(NSError::NotFound("mock missing".into())),
                AuthorityMode::Down => Err(NSError::Failed("mock network down".into())),
                AuthorityMode::Disabled => Err(NSError::Disabled("mock disabled".into())),
            }
        }
    }

    fn client_with_temp_cache(cache_backend: CacheBackend) -> NameClient {
        let tmp = tempdir().unwrap().keep();
        let cfg = NameClientConfig {
            enable_cache: true,
            local_cache_dir: Some(tmp.to_string_lossy().to_string()),
            cache_backend,
            ..Default::default()
        };
        NameClient::new(cfg)
    }

    fn mem_client() -> NameClient {
        NameClient::new(NameClientConfig {
            enable_cache: true,
            cache_backend: CacheBackend::Memory,
            ..Default::default()
        })
    }

    // ---- T0.1: key 类 DID 入参门禁 ----

    #[tokio::test]
    async fn key_class_did_rejected_before_cache_and_providers() {
        let client = mem_client();
        let authority = Box::new(MockAuthority::ok(make_doc(0, 10, "dev-doc")));
        let calls_probe = &authority.calls as *const AtomicUsize;
        client.set_method_authority("dev", authority).await;

        let did = DID::from_str("did:dev:5bUuyWLOKyCre9az_IhJVIuOw8bA0gyKjstcYGHbaPE").unwrap();
        let err = client.resolve_did(&did, None).await.unwrap_err();
        assert!(matches!(err, NSError::InvalidDID(_)));
        // Info 路径同样被门禁拦住。
        let err = client
            .resolve_did(&did, Some(DidDocType::Info))
            .await
            .unwrap_err();
        assert!(matches!(err, NSError::InvalidDID(_)));
        // 没有任何 provider 被触碰。
        assert_eq!(unsafe { (*calls_probe).load(Ordering::SeqCst) }, 0);
    }

    // ---- T0.6: in-TTL 快路径 ----

    #[tokio::test]
    async fn in_ttl_cache_hit_short_circuits_providers() {
        let client = mem_client();
        let did = DID::from_str("did:web:example.com").unwrap();
        let now = buckyos_get_unix_timestamp();
        let cached = make_doc(now, now + 1000, "cached");
        client.doc_cache.insert(
            did.clone(),
            None,
            cached.clone(),
            now + 1000,
            CacheEvidence::Published,
        );

        let authority = MockAuthority::ok(make_doc(now + 10, now + 2000, "fresh"));
        client
            .set_method_authority("web", Box::new(authority))
            .await;

        let resolved = client
            .resolve_did_ex(&did, None, ResolvePolicy::default())
            .await
            .unwrap();
        assert_eq!(resolved.document, cached);
        assert_eq!(
            resolved.resolution_metadata.cache_status,
            Some(CacheStatus::Hit)
        );
        assert!(!resolved
            .resolution_metadata
            .warnings
            .contains(&ResolveWarning::CacheFallback));
    }

    #[tokio::test]
    async fn resolve_from_cache_without_any_provider() {
        let client = client_with_temp_cache(CacheBackend::Filesystem);
        let did = DID::from_str("did:web:cache.only").unwrap();
        let now = buckyos_get_unix_timestamp();
        let cached_doc = make_doc(now, now + 1800, "cache-only");

        client.doc_cache.insert(
            did.clone(),
            None,
            cached_doc.clone(),
            now + 1800,
            CacheEvidence::Published,
        );

        let resolved = client.resolve_did(&did, None).await.unwrap();
        assert_eq!(resolved, cached_doc);
    }

    // ---- T0.5 / T0.4: 负状态与 Missing / unknown ----

    #[tokio::test]
    async fn disabled_authority_answer_writes_negative_and_removes_positive() {
        let client = mem_client();
        let did = DID::from_str("did:web:example.com").unwrap();
        let now = buckyos_get_unix_timestamp();
        // 植入一个已过期的 positive(避免 TTL 快路径直接短路)。
        client.doc_cache.insert(
            did.clone(),
            None,
            make_doc_without_exp("stale"),
            now.saturating_sub(10),
            CacheEvidence::Published,
        );

        client
            .set_method_authority(
                "web",
                Box::new(MockAuthority::with_mode(AuthorityMode::Disabled)),
            )
            .await;

        let err = client.resolve_did(&did, None).await.unwrap_err();
        assert!(matches!(err, NSError::Disabled(_)));

        // positive 被负状态条目取代。
        assert!(client.doc_cache.get(&did, None).is_none());
        assert!(client.doc_cache.lookup(&did, None).unwrap().is_negative());
    }

    #[tokio::test]
    async fn negative_state_survives_authority_unknown_and_blocks_stale_fallback() {
        let client = mem_client();
        let did = DID::from_str("did:web:revoked.example").unwrap();

        let authority = MockAuthority::with_mode(AuthorityMode::Disabled);
        let mode = authority.mode_handle();
        client
            .set_method_authority("web", Box::new(authority))
            .await;

        // 第一次:拿到 Revoked,写入负状态。
        let err = client.resolve_did(&did, None).await.unwrap_err();
        assert!(matches!(err, NSError::Disabled(_)));

        // 权威源转为断网(unknown):负状态记忆仍然屏蔽一切,不返回 NotFound、
        // 不做 stale 兜底(in-TTL 时由负状态快路径直接命中)。
        *mode.lock().unwrap() = AuthorityMode::Down;
        let err = client.resolve_did(&did, None).await.unwrap_err();
        assert!(matches!(err, NSError::Disabled(_)));
    }

    #[tokio::test]
    async fn expired_negative_state_blocks_verified_candidate_under_missing() {
        // 吊销记忆存在时,即使权威源后来回答 Missing、策略放行自签名候选、候选
        // 也通过了完整 verify,它仍然是 fallback,不许越过负状态;只有权威源的
        // 新"已发布"回答能翻篇。
        let app_did = DID::new("bns", "app1.alice");
        let owner_did = DID::new("bns", "alice");
        let private_key = EncodingKey::from_ed_pem(TEST_OWNER_PRIVATE_KEY_PEM.as_bytes()).unwrap();

        let mut owner = OwnerDocument::new(
            owner_did.clone(),
            "alice".to_string(),
            "alice@test".to_string(),
            test_owner_public_jwk(),
        );
        owner.version_seq = Some(0);
        let owner_doc = owner.encode(Some(&private_key)).unwrap();

        let now = buckyos_get_unix_timestamp();
        let mut zone =
            ZoneDocument::new(app_did.clone(), owner_did.clone(), test_owner_public_jwk());
        zone.iat = now;
        zone.exp = now + 3600 * 24;
        zone.version_seq = Some(1);
        let candidate_doc = zone.encode(Some(&private_key)).unwrap();

        let client = mem_client();
        client.doc_cache.replace_with_negative_expired(
            &app_did,
            None,
            &DocumentStatus::Revoked,
            "revoked long ago",
        );
        // 权威源:zone 回答 Missing,owner 文档正常可取(anchored)。
        client
            .set_method_authority(
                "bns",
                Box::new(
                    MockAuthority::with_mode(AuthorityMode::Missing).with_owner_doc(owner_doc),
                ),
            )
            .await;
        // 补充源提供签名合法的候选。
        client
            .add_method_supplement("bns", Box::new(MockAuthority::ok(candidate_doc)))
            .await;

        let mut policy = ResolvePolicy::default();
        policy.allow_self_signed_when_missing = true;
        let err = client
            .resolve_did_ex(&app_did, None, policy)
            .await
            .unwrap_err();
        assert!(matches!(err, NSError::Disabled(_)));
        // 负状态记忆原样保留。
        assert!(client
            .doc_cache
            .lookup(&app_did, None)
            .unwrap()
            .is_negative());
    }

    #[tokio::test]
    async fn expired_negative_state_still_blocks_fallback_when_authority_unknown() {
        // 负状态屏蔽兜底不受 TTL 约束:TTL 过期只允许重新询问权威源;权威源
        // 没回答时,过期的"已吊销"记忆仍然优先于一切 fallback。
        let client = mem_client();
        let did = DID::from_str("did:web:revoked-stale.example").unwrap();
        client.doc_cache.replace_with_negative_expired(
            &did,
            None,
            &DocumentStatus::Revoked,
            "revoked long ago",
        );

        client
            .set_method_authority(
                "web",
                Box::new(MockAuthority::with_mode(AuthorityMode::Down)),
            )
            .await;

        let err = client.resolve_did(&did, None).await.unwrap_err();
        assert!(matches!(err, NSError::Disabled(_)));
    }

    #[tokio::test]
    async fn negative_state_blocks_push_into_cache() {
        let client = mem_client();
        let did = DID::from_str("did:web:revoked2.example").unwrap();
        client
            .set_method_authority(
                "web",
                Box::new(MockAuthority::with_mode(AuthorityMode::Disabled)),
            )
            .await;
        let _ = client.resolve_did(&did, None).await.unwrap_err();
        assert!(client.doc_cache.lookup(&did, None).unwrap().is_negative());

        // push(update_did_cache)写不进去,负状态仍在。
        let now = buckyos_get_unix_timestamp();
        client
            .update_did_cache(did.clone(), None, make_doc(now, now + 1000, "pushed"))
            .unwrap();
        assert!(client.doc_cache.lookup(&did, None).unwrap().is_negative());
        assert!(client.doc_cache.get(&did, None).is_none());
    }

    #[tokio::test]
    async fn authority_missing_does_not_fallback_to_stale_positive_cache() {
        let client = mem_client();
        let did = DID::from_str("did:web:gone.example").unwrap();
        let now = buckyos_get_unix_timestamp();
        // 过期(TTL)但未作废的 positive:若权威源 unknown 本可兜底,但 Missing 不行。
        client.doc_cache.insert(
            did.clone(),
            None,
            make_doc_without_exp("stale"),
            now.saturating_sub(10),
            CacheEvidence::Published,
        );

        client
            .set_method_authority(
                "web",
                Box::new(MockAuthority::with_mode(AuthorityMode::Missing)),
            )
            .await;

        let err = client.resolve_did(&did, None).await.unwrap_err();
        assert!(matches!(err, NSError::NotFound(_)));
    }

    #[tokio::test]
    async fn authority_unknown_uses_stale_cache_when_policy_allows() {
        let client = mem_client();
        let did = DID::from_str("did:web:down.example").unwrap();
        let now = buckyos_get_unix_timestamp();
        let stale_doc = make_doc_without_exp("stale-but-usable");
        client.doc_cache.insert(
            did.clone(),
            None,
            stale_doc.clone(),
            now.saturating_sub(10),
            CacheEvidence::Published,
        );

        client
            .set_method_authority(
                "web",
                Box::new(MockAuthority::with_mode(AuthorityMode::Down)),
            )
            .await;

        // 默认策略允许 stale 兜底。
        let resolved = client
            .resolve_did_ex(&did, None, ResolvePolicy::default())
            .await
            .unwrap();
        assert_eq!(resolved.document, stale_doc);
        assert_eq!(
            resolved.resolution_metadata.cache_status,
            Some(CacheStatus::Fallback)
        );
        assert!(resolved
            .resolution_metadata
            .warnings
            .contains(&ResolveWarning::CacheFallback));

        // 策略关闭时不得兜底。
        let mut policy = ResolvePolicy::default();
        policy.allow_stale_cache = false;
        let err = client.resolve_did_ex(&did, None, policy).await.unwrap_err();
        assert!(matches!(err, NSError::Failed(_)));
    }

    #[tokio::test]
    async fn self_expired_doc_is_not_used_for_stale_fallback() {
        let client = mem_client();
        let did = DID::from_str("did:web:expired.example").unwrap();
        let now = buckyos_get_unix_timestamp();
        // 文档自声明的 exp 已过:它已"作废",不是策略点④的兜底对象。
        let dead_doc = make_doc(now.saturating_sub(100), now.saturating_sub(10), "dead");
        client.doc_cache.insert(
            did.clone(),
            None,
            dead_doc,
            now.saturating_sub(10),
            CacheEvidence::Published,
        );

        client
            .set_method_authority(
                "web",
                Box::new(MockAuthority::with_mode(AuthorityMode::Down)),
            )
            .await;

        let err = client.resolve_did(&did, None).await.unwrap_err();
        assert!(matches!(err, NSError::Failed(_)));
    }

    // ---- 解析成功路径与缓存回写 ----

    #[tokio::test]
    async fn resolved_document_is_cached_and_served_from_ttl_fast_path() {
        let client = mem_client();
        let did = DID::from_str("did:web:example.com").unwrap();
        let now = buckyos_get_unix_timestamp();
        let (zone_doc, owner_doc) = build_self_owned_zone_and_owner(&did, now, "fresh");

        let authority = MockAuthority::ok(zone_doc.clone()).with_owner_doc(owner_doc);
        client
            .set_method_authority("web", Box::new(authority))
            .await;

        let first = client
            .resolve_did_ex(&did, None, ResolvePolicy::default())
            .await
            .unwrap();
        assert_eq!(first.document, zone_doc);
        assert_eq!(
            first.resolution_metadata.cache_status,
            Some(CacheStatus::Miss)
        );

        // 第二次命中 TTL 快路径,不再触发查询。
        let second = client
            .resolve_did_ex(&did, None, ResolvePolicy::default())
            .await
            .unwrap();
        assert_eq!(second.document, zone_doc);
        assert_eq!(
            second.resolution_metadata.cache_status,
            Some(CacheStatus::Hit)
        );
    }

    #[tokio::test]
    async fn local_authority_override_wins_over_provider_and_skips_normal_cache() {
        let client = client_with_temp_cache(CacheBackend::Filesystem);
        let did = DID::from_str("did:web:example.com").unwrap();
        let now = buckyos_get_unix_timestamp();
        let (provider_doc, owner_doc) = build_self_owned_zone_and_owner(&did, now, "from-provider");
        let override_doc = make_doc(now, now + 1000, "from-override");

        client
            .set_method_authority(
                "web",
                Box::new(MockAuthority::ok(provider_doc.clone()).with_owner_doc(owner_doc)),
            )
            .await;
        client.set_local_authority_override(
            did.clone(),
            DidDocType::Zone,
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
        client.clear_local_authority_override(&did, DidDocType::Zone);
        let resolved_after_clear = client.resolve_did(&did, None).await.unwrap();
        assert_eq!(resolved_after_clear, provider_doc);
    }

    struct FlakyInfoProvider {
        doc: EncodedDocument,
        calls: AtomicUsize,
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
            _doc_type: Option<DidDocType>,
            _from_ip: Option<std::net::IpAddr>,
        ) -> NSResult<EncodedDocument> {
            let call = self.calls.fetch_add(1, Ordering::SeqCst);
            if call == 0 {
                Ok(self.doc.clone())
            } else {
                Err(NSError::NotFound("provider gone".into()))
            }
        }
    }

    #[tokio::test]
    async fn unauthenticated_info_cache_serves_and_stays_isolated() {
        let client = mem_client();
        let did = DID::from_str("did:web:flaky.example").unwrap();
        let now = buckyos_get_unix_timestamp();
        let doc = make_doc(now, now + 1000, "flaky-info");

        client
            .set_method_authority(
                "web",
                Box::new(FlakyInfoProvider {
                    doc: doc.clone(),
                    calls: AtomicUsize::new(0),
                }),
            )
            .await;

        let first = client
            .resolve_did_ex(&did, Some(DidDocType::Info), ResolvePolicy::default())
            .await
            .unwrap();
        assert_eq!(first.document, doc);
        assert_eq!(first.document_metadata.buckyos.document_status, None);
        assert_eq!(first.document_metadata.deactivated, None);

        // provider 从第二次调用起总是失败;这一次由 UnauthenticatedInfoCache 命中。
        let second = client
            .resolve_did_ex(&did, Some(DidDocType::Info), ResolvePolicy::default())
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

        // Info 结果只进入 UnauthenticatedInfoCache,与 doc_cache 完全隔离。
        assert!(client.doc_cache.get(&did, Some(DidDocType::Info)).is_none());
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
            doc_type: Option<DidDocType>,
            _from_ip: Option<std::net::IpAddr>,
        ) -> NSResult<EncodedDocument> {
            if doc_type == Some(DidDocType::Owner) {
                return Ok(self.owner_doc.clone());
            }
            Ok(self.fresh_doc.clone())
        }
    }

    #[tokio::test]
    async fn owner_replay_guard_rejects_cached_stale_jwt_and_resolves_again() {
        let client = mem_client();
        let did = DID::from_str("did:web:example.com").unwrap();
        let now = buckyos_get_unix_timestamp();
        let owner_valid_iat = now + 200;
        let private_key = EncodingKey::from_ed_pem(TEST_OWNER_PRIVATE_KEY_PEM.as_bytes()).unwrap();

        let mut old_zone = ZoneDocument::new(did.clone(), did.clone(), test_owner_public_jwk());
        old_zone.iat = now + 150;
        old_zone.exp = old_zone.iat + DEFAULT_EXPIRE_TIME;
        old_zone.version_seq = Some(1);
        let old_doc = old_zone.encode(Some(&private_key)).unwrap();

        let mut fresh_zone = ZoneDocument::new(did.clone(), did.clone(), test_owner_public_jwk());
        fresh_zone.iat = now + 300;
        fresh_zone.exp = fresh_zone.iat + DEFAULT_EXPIRE_TIME;
        fresh_zone.version_seq = Some(2);
        let fresh_doc = fresh_zone.encode(Some(&private_key)).unwrap();

        let mut owner_document = OwnerDocument::new(
            did.clone(),
            "example".to_string(),
            "example@example.com".to_string(),
            test_owner_public_jwk(),
        );
        owner_document.version_seq = Some(0);
        owner_document.mini_version_seq = Some(1);
        owner_document.valid_iat = Some(owner_valid_iat);
        let owner_doc = owner_document.encode(Some(&private_key)).unwrap();

        // 缓存里是 owner replay guard 判定作废的旧 JWT(in-TTL,快路径会先命中它,
        // 但 replay guard 把它踢出去并继续真正的解析)。
        client.doc_cache.insert(
            did.clone(),
            None,
            old_doc,
            now + DOC_CACHE_TTL_SECS,
            CacheEvidence::Published,
        );
        client.doc_cache.insert(
            did.clone(),
            Some(DidDocType::Owner),
            owner_doc.clone(),
            now + DOC_CACHE_TTL_SECS,
            CacheEvidence::Published,
        );
        client
            .set_method_authority(
                "web",
                Box::new(ReplayGuardProvider {
                    owner_doc,
                    fresh_doc: fresh_doc.clone(),
                }),
            )
            .await;

        let resolved = client.resolve_did(&did, None).await.unwrap();
        assert_eq!(resolved, fresh_doc);
    }

    // ---- 普通名字解析路径 ----

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
            _doc_type: Option<DidDocType>,
            _from_ip: Option<std::net::IpAddr>,
        ) -> NSResult<EncodedDocument> {
            Err(NSError::NotFound("not implemented".into()))
        }
    }

    #[tokio::test]
    async fn resolve_did_web_normalizes_to_host_name() {
        let called_name = Arc::new(Mutex::new(None));
        let provider = NameMockProvider {
            called_name: called_name.clone(),
        };
        let client = NameClient::new(NameClientConfig {
            enable_cache: false,
            cache_backend: CacheBackend::Memory,
            ..Default::default()
        });
        client.add_dns_provider(Box::new(provider)).await;

        let result = client.resolve("did:web:example.com", None).await.unwrap();
        assert_eq!(result.name, "example.com".to_string());

        let observed = called_name.lock().await.clone().unwrap();
        assert_eq!(observed, "example.com".to_string());
    }

    // ---- add_provider 兼容注册 ----

    struct WebDeclaredProvider {
        doc: EncodedDocument,
    }

    #[async_trait]
    impl NsProvider for WebDeclaredProvider {
        fn get_id(&self) -> String {
            "web-declared".to_string()
        }

        fn methods(&self) -> Vec<String> {
            vec!["web".to_string()]
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
            _doc_type: Option<DidDocType>,
            _from_ip: Option<std::net::IpAddr>,
        ) -> NSResult<EncodedDocument> {
            Ok(self.doc.clone())
        }
    }

    #[tokio::test]
    async fn add_provider_compat_registers_declared_method_as_authority() {
        let client = NameClient::new(NameClientConfig {
            enable_cache: false,
            cache_backend: CacheBackend::Memory,
            ..Default::default()
        });
        let did = DID::from_str("did:web:compat.example").unwrap();
        let now = buckyos_get_unix_timestamp();
        let doc = make_doc(now, now + 600, "compat");

        client
            .add_provider(Box::new(WebDeclaredProvider { doc: doc.clone() }), Some(0))
            .await;

        let resolved = client.resolve_did(&did, None).await.unwrap();
        assert_eq!(resolved, doc);
    }

    // ---- resolve_ips 路径 ----

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
                _doc_type: Option<DidDocType>,
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
        client.add_dns_provider(Box::new(AddressProvider)).await;

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

    struct DeviceDocumentProvider {
        device_doc: EncodedDocument,
        info_doc: EncodedDocument,
        name_info: NameInfo,
    }

    #[async_trait]
    impl NsProvider for DeviceDocumentProvider {
        fn get_id(&self) -> String {
            "device-document-provider".to_string()
        }

        async fn query(
            &self,
            _name: &str,
            _record_type: Option<RecordType>,
            _from_ip: Option<std::net::IpAddr>,
        ) -> NSResult<NameInfo> {
            Ok(self.name_info.clone())
        }

        async fn query_did(
            &self,
            _did: &DID,
            doc_type: Option<DidDocType>,
            _from_ip: Option<std::net::IpAddr>,
        ) -> NSResult<EncodedDocument> {
            match doc_type {
                Some(DidDocType::Info) => Ok(self.info_doc.clone()),
                None => Ok(self.device_doc.clone()),
                _ => Err(NSError::NotFound("not implemented".into())),
            }
        }
    }

    fn build_device_provider(
        device_ips: Vec<IpAddr>,
        info_ips: Vec<IpAddr>,
        name_ips: Vec<IpAddr>,
    ) -> DeviceDocumentProvider {
        let device_did = DID::from_str("did:web:ood1.example").unwrap();
        let mut device_document = DeviceDocument::new(
            "ood1",
            "5bUuyWLOKyCre9az_IhJVIuOw8bA0gyKjstcYGHbaPE".to_string(),
        );
        device_document.id = device_did.clone();
        device_document.owner = device_did.clone();
        device_document.ips = device_ips;
        let device_doc = EncodedDocument::JsonLd(serde_json::to_value(&device_document).unwrap());

        let mut info_config = device_document.clone();
        let mut device_info = DeviceInfo::from_device_doc(&info_config);
        device_info.all_ip = info_ips;
        let info_doc = EncodedDocument::JsonLd(serde_json::to_value(&device_info).unwrap());

        DeviceDocumentProvider {
            device_doc,
            info_doc,
            name_info: NameInfo::from_address_vec("ood1.example", name_ips),
        }
    }

    #[tokio::test]
    async fn resolve_ips_prefers_device_document_ips() {
        let client = NameClient::new(NameClientConfig {
            enable_cache: false,
            cache_backend: CacheBackend::Memory,
            ..Default::default()
        });
        let provider = build_device_provider(
            vec!["192.0.2.10".parse().unwrap()],
            vec!["192.0.2.40".parse().unwrap()],
            vec!["192.0.2.30".parse().unwrap()],
        );
        client.set_method_authority("web", Box::new(provider)).await;

        let resolved = client.resolve_ips("did:web:ood1.example").await.unwrap();
        assert_eq!(resolved, vec!["192.0.2.10".parse::<IpAddr>().unwrap()]);
    }

    #[tokio::test]
    async fn resolve_ips_falls_back_when_device_document_has_no_fixed_ips() {
        let client = NameClient::new(NameClientConfig {
            enable_cache: false,
            cache_backend: CacheBackend::Memory,
            ..Default::default()
        });
        let provider = build_device_provider(
            Vec::new(),
            vec!["192.0.2.30".parse().unwrap()],
            vec!["192.0.2.10".parse().unwrap()],
        );
        // 同一个 provider 同时服务 DID 管线与普通名字解析。
        let provider2 = build_device_provider(
            Vec::new(),
            vec!["192.0.2.30".parse().unwrap()],
            vec!["192.0.2.10".parse().unwrap()],
        );
        client.set_method_authority("web", Box::new(provider)).await;
        client.add_dns_provider(Box::new(provider2)).await;

        let resolved = client.resolve_ips("did:web:ood1.example").await.unwrap();
        assert_eq!(
            resolved,
            vec![
                "192.0.2.10".parse::<IpAddr>().unwrap(),
                "192.0.2.30".parse::<IpAddr>().unwrap(),
            ]
        );
    }

    #[tokio::test]
    async fn resolve_ips_uses_cached_finder_device_info_after_discovery() {
        let client = mem_client();
        client
            .set_method_authority(
                "web",
                Box::new(MockAuthority::with_mode(AuthorityMode::Missing)),
            )
            .await;

        let device_did = DID::from_str("did:web:ood1.example").unwrap();
        let before_cache = client.resolve_ips("did:web:ood1.example").await;
        assert!(before_cache.is_err());

        let endpoint_ip: IpAddr = "192.168.1.20".parse().unwrap();
        let mut discovered_doc = DeviceDocument::new(
            "ood1",
            "5bUuyWLOKyCre9az_IhJVIuOw8bA0gyKjstcYGHbaPE".to_string(),
        );
        discovered_doc.id = device_did.clone();
        discovered_doc.zone_did = Some(DID::new("bns", "alice"));
        discovered_doc.owner = DID::new("bns", "alice");
        discovered_doc.ips.push(endpoint_ip);

        let mut device_info = DeviceInfo::from_device_doc(&discovered_doc);
        device_info.arch.clear();
        device_info.os.clear();
        device_info.update_time = buckyos_get_unix_timestamp();
        device_info.all_ip.push(endpoint_ip);

        client
            .add_device_info_cache(device_did.clone(), device_info)
            .unwrap();

        let resolved = client.resolve_ips("did:web:ood1.example").await.unwrap();
        assert_eq!(resolved, vec![endpoint_ip]);
        assert!(client
            .doc_cache
            .get(&device_did, Some(DidDocType::Info))
            .is_none());
    }
}
