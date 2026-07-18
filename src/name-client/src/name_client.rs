#![allow(unused)]

use crate::addr_rtt_db::{
    AutoFlushHandle, CleanupReport, Config as AddrRttDbConfig, ConnectionOutcome,
    PersistencePolicy, RankedAddress, RttDatabase, SortPolicy,
};
use crate::dns_provider::DnsProvider;
use crate::doc_cache::{
    CacheBackend, CacheEvidence, CacheLookup, CacheWriteOutcome, DIDDocumentCache,
    UnauthenticatedInfoCache,
};
use crate::name_query::{NameQuery, ResolveOutcome};
use crate::provider::RecordType;
use crate::verify::VerifyPromoteOutcome;
use crate::zone_resolver::{ZoneLookup, ZoneResolverClient, ZoneResolverConfig};
use crate::{
    is_key_class_method, BodyEvidence, CacheStatus, DidDocType, DiscoveredDocument, DocumentStatus,
    LocalAuthorityOverrideStore, NameInfo, NsProvider, ResolvePolicy, ResolveSourcePolicy,
    ResolveWarning, ResolvedDocument, UpdateSource, VerificationStatus,
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
    /// Zone Resolver L1 cache(cluster-level cache,简化文档第 3 节第 0 步)。
    /// 默认启用:明确回答时命中;返回 unknown 或传输失败时落回本机 cache
    /// 与 resolver core。单元测试、离线工具应显式关闭,避免打到开发机上
    /// 真实运行的 zone 服务。
    pub enable_zone_resolver: bool,
    pub zone_resolver: ZoneResolverConfig,
}

impl Default for NameClientConfig {
    fn default() -> Self {
        Self {
            enable_cache: true,
            local_cache_dir: None,
            cache_backend: CacheBackend::Filesystem,
            rtt_db_config: AddrRttDbConfig::default(),
            enable_zone_resolver: true,
            zone_resolver: ZoneResolverConfig::default(),
        }
    }
}

pub struct NameClient {
    pub(crate) name_query: NameQuery,
    pub(crate) config: NameClientConfig,
    pub(crate) doc_cache: DIDDocumentCache,
    addr_rtt_db: Arc<RttDatabase>,
    _addr_rtt_auto_flush: Option<AutoFlushHandle>,
    cached_local_ips: StdRwLock<Vec<IpAddr>>,
    nameinfo_cache: Option<std::sync::Arc<RwLock<HashMap<String, NameInfo>>>>,
    local_authority_overrides: Arc<LocalAuthorityOverrideStore>,
    unauthenticated_info_cache: UnauthenticatedInfoCache,
    /// Zone Resolver cache 客户端(T5.5):cluster-level cache,不是 NsProvider,
    /// 不进入 NameQuery 的 provider 管线。None = 已关闭。
    zone_resolver: StdRwLock<Option<Arc<ZoneResolverClient>>>,
}

impl NameClient {
    pub fn new(config: NameClientConfig) -> Self {
        let name_query = NameQuery::new();

        let doc_cache_dir = config
            .local_cache_dir
            .as_ref()
            .map(|dir| PathBuf::from(dir));

        let doc_cache = match config.cache_backend {
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

        let zone_resolver = if config.enable_zone_resolver {
            Some(Arc::new(ZoneResolverClient::new(
                config.zone_resolver.clone(),
            )))
        } else {
            None
        };

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
            zone_resolver: StdRwLock::new(zone_resolver),
        }
    }

    // ---- Zone Resolver cache(T5.1:启用与配置)----

    /// 关闭 Zone Resolver cache 快路径,退回单机 cache + resolver 流程。
    /// 非 BuckyOS 环境、单元测试、离线工具使用。
    pub fn disable_zone_resolver(&self) {
        if let Ok(mut zone) = self.zone_resolver.write() {
            *zone = None;
        }
    }

    /// 设置 Zone Resolver endpoint 并启用(timeout 沿用构造配置)。
    pub fn set_zone_resolver_endpoint(&self, endpoint: impl Into<String>) {
        let mut config = self.config.zone_resolver.clone();
        config.endpoint = endpoint.into();
        self.set_zone_resolver_config(config);
    }

    /// 设置完整 Zone Resolver 配置(endpoint / timeout)并启用。
    pub fn set_zone_resolver_config(&self, config: ZoneResolverConfig) {
        if let Ok(mut zone) = self.zone_resolver.write() {
            *zone = Some(Arc::new(ZoneResolverClient::new(config)));
        }
    }

    pub(crate) fn zone_resolver_snapshot(&self) -> Option<Arc<ZoneResolverClient>> {
        self.zone_resolver.read().ok().and_then(|zone| zone.clone())
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

    // ---- add_cache:显式保存证据(doc/verify-did-api-boundary-and-freshness-TODO.md Phase 4)----

    /// add_cache 动词的 Observed 入口:UDP 发现、gossip、push、文件投递拿到的
    /// 文档从这里进入 `unverified` cache。这是 Observed 事件,不是信任入口:
    /// 产物恒为 `CacheEvidence::Unverified`,落 `unverified/` 命名空间;它压
    /// 不过已发布/已验证条目,也翻不了负状态。strict 解析在首次使用时做
    /// lazy verify(verify_and_promote),验证通过才会返回给调用方。
    ///
    /// 本函数只是文件系统旁路协议的薄封装(省一次文件 IO,语义完全等价,不享受
    /// 任何额外信任):写入前做一次快速校验(本地解析,不联网),校验不过不
    /// 产生任何写入。`source` 只描述链路来源(诊断用),不接受写入方自报的
    /// 信任等级。
    pub fn add_observed_cache(
        &self,
        did: DID,
        doc_type: Option<DidDocType>,
        doc: EncodedDocument,
        source: Option<UpdateSource>,
    ) -> NSResult<CacheWriteOutcome> {
        Self::quick_check_observed_document(&did, &doc)?;
        let exp = Self::cache_ttl_exp(&doc);
        Ok(self.doc_cache.update_observed(
            did,
            doc_type,
            doc,
            exp,
            source.map(|s| s.as_str().to_string()),
        ))
    }

    /// add_cache 动词的 Verified 入口:把一份**调用方已完成验证与最终接受**的
    /// 文档显式写入 `verified/` 命名空间(证据 `Verified`)。安全边界不在这个
    /// 函数:是否有权写 verified 命名空间由目标目录的 OS 权限与进程身份保证,
    /// 直接按文件系统协议写入与调用本函数具有相同语义。
    ///
    /// verify 家族**不会**隐式调用它——是否保存、何时保存(在持钥证明/授权/
    /// 锁管理之后)由完成"最终接受"动作的上游显式决定。组合便捷入口见
    /// `resolve_verify_and_cache_did_document`。
    pub fn add_verified_cache(
        &self,
        did: DID,
        doc_type: Option<DidDocType>,
        doc: EncodedDocument,
    ) -> NSResult<CacheWriteOutcome> {
        Self::quick_check_observed_document(&did, &doc)?;
        let exp = Self::cache_ttl_exp(&doc);
        Ok(self
            .doc_cache
            .update(did, doc_type, doc, exp, CacheEvidence::Verified))
    }

    /// 写入 `unverified/` 前的快速校验(doc/update-did-cache.md"写入协议"):
    /// **不是**完整验证——不检查签名、不检查 owner、不提升信任等级,只挡住
    /// 格式明显损坏或张冠李戴的数据:
    /// - JWT 形式必须能被 `parse_did_doc` 归一化解析(内含"JWT 必须带
    ///   version_seq"的现有硬规则),且解析出的 id 与调用方声明的 did 一致;
    /// - JsonLd 形式若自带 `id` 字段,必须与声明的 did 一致。
    fn quick_check_observed_document(did: &DID, doc: &EncodedDocument) -> NSResult<()> {
        match doc {
            EncodedDocument::Jwt(_) => {
                let parsed = parse_did_doc(doc.clone()).map_err(|err| {
                    NSError::UnverifiedCacheWriteRejected(format!(
                        "document is not a recognizable DID document: {}",
                        err
                    ))
                })?;
                if parsed.get_id() != *did {
                    return Err(NSError::UnverifiedCacheWriteRejected(format!(
                        "document id {} does not match declared did {}",
                        parsed.get_id().to_string(),
                        did.to_string()
                    )));
                }
            }
            EncodedDocument::JsonLd(value) => {
                if let Some(id_value) = value.get("id").and_then(|v| v.as_str()) {
                    let doc_id = DID::from_str(id_value).map_err(|err| {
                        NSError::UnverifiedCacheWriteRejected(format!(
                            "document id {} is not a valid DID: {}",
                            id_value, err
                        ))
                    })?;
                    if doc_id != *did {
                        return Err(NSError::UnverifiedCacheWriteRejected(format!(
                            "document id {} does not match declared did {}",
                            doc_id.to_string(),
                            did.to_string()
                        )));
                    }
                }
            }
        }
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
        Self::quick_check_observed_document(&did, &doc)?;
        let seen_at = if device_info.update_time == 0 {
            buckyos_get_unix_timestamp()
        } else {
            device_info.update_time
        };
        let exp = seen_at.saturating_add(ttl_secs);
        self.unauthenticated_info_cache.insert(
            &did,
            Some(DidDocType::Info),
            doc.clone(),
            exp,
            DEFAULT_PROVIDER_TRUST_LEVEL,
        );
        if self.config.enable_cache {
            self.doc_cache
                .update_observed(did, Some(DidDocType::Info), doc, exp, None);
        }
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
        // Document 固定 IP 只是优先级最高的一条信道:它解析失败(权威渠道断网、
        // 网关返回损坏内容等)不能终结整个 resolve_ips,nameinfo / device-info
        // 仍可能给出可用地址。该错误只在所有信道都落空时作为兜底错误报出。
        let device_document_error = match self.resolve_device_document_ips(name).await {
            Ok(Some(ips)) => return self.sort_resolved_ips(&ips),
            Ok(None) => None,
            Err(err) => {
                debug!(
                    "resolve_ips({}): device document channel failed, \
                     falling back to nameinfo/device-info: {}",
                    name, err
                );
                Some(err)
            }
        };

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

        Err(first_error
            .or(device_document_error)
            .unwrap_or_else(|| NSError::NotFound("A record not found".to_string())))
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

    fn extract_update_time(doc: &EncodedDocument) -> Option<u64> {
        doc.clone()
            .to_json_value()
            .ok()
            .and_then(|value| value.get("update_time").and_then(|ts| ts.as_u64()))
    }

    fn info_doc_is_at_least_as_fresh(
        candidate: &EncodedDocument,
        current: &EncodedDocument,
    ) -> bool {
        match (
            Self::extract_update_time(candidate),
            Self::extract_update_time(current),
        ) {
            (Some(candidate), Some(current)) => candidate >= current,
            (Some(_), None) => true,
            (None, Some(_)) => false,
            (None, None) => true,
        }
    }

    /// 缓存条目的 TTL:文档自身 exp 与 `DOC_CACHE_TTL_SECS` 取小。TTL 只决定
    /// 快路径的新鲜度,不代表文档作废时间。
    pub(crate) fn cache_ttl_exp(doc: &EncodedDocument) -> u64 {
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

    fn zone_child_did(zone_did: &DID, device_name: &str) -> Option<DID> {
        if device_name.is_empty() {
            return None;
        }
        match zone_did.method.as_str() {
            "web" | "bns" => Some(DID::new(
                &zone_did.method,
                &format!("{}.{}", device_name, zone_did.id),
            )),
            _ => None,
        }
    }

    fn cache_embedded_zone_devices(
        &self,
        doc_type: &DidDocType,
        zone_doc: &EncodedDocument,
        evidence: CacheEvidence,
    ) {
        if *doc_type != DidDocType::Zone {
            return;
        }

        let Ok(zone) = ZoneDocument::decode(zone_doc, None) else {
            return;
        };

        for (device_name, device_document) in zone.devices.iter() {
            let Some(device_did) = Self::zone_child_did(&zone.id, device_name) else {
                continue;
            };
            let Ok(device_doc) = serde_json::to_value(device_document)
                .map(EncodedDocument::JsonLd)
                .map_err(|err| {
                    warn!(
                        "failed to encode embedded device document {} in {}: {}",
                        device_name,
                        zone.id.to_string(),
                        err
                    )
                })
            else {
                continue;
            };
            let exp = Self::cache_ttl_exp(&device_doc);
            self.doc_cache
                .update(device_did, None, device_doc, exp, evidence);
        }
    }

    fn cache_discovered_documents(
        &self,
        discovered_documents: &[DiscoveredDocument],
        evidence: CacheEvidence,
    ) {
        for discovered in discovered_documents {
            let exp = Self::cache_ttl_exp(&discovered.document);
            self.doc_cache.update(
                discovered.did.clone(),
                discovered.doc_type.clone(),
                discovered.document.clone(),
                exp,
                evidence,
            );

            if discovered.doc_type == Some(DidDocType::Zone) {
                self.doc_cache.update(
                    discovered.did.clone(),
                    None,
                    discovered.document.clone(),
                    exp,
                    evidence,
                );
                self.cache_embedded_zone_devices(&DidDocType::Zone, &discovered.document, evidence);
            }
        }
    }

    /// resolve_did 外层(简化文档第 3 节第 0/2 步)。来源范围由
    /// `policy.source`(`ResolveSourcePolicy`)显式决定:
    /// - `LocalOnly`:只走本机 cache 快路径与 stale 判定,零网络;
    /// - `LocalAndZone`:Zone 快路径 + 本机 cache,不进 resolver 主循环;
    /// - `RemoteAuthority`:跳过 Zone 与本机 in-TTL 快路径,直接进主循环取得
    ///   权威判断;不做 stale cache 兜底;
    /// - `BestAvailable`(默认):完整正常优先级——
    ///   0. Zone Resolver L1 cache 快路径(明确回答即命中,unknown 继续 L2);
    ///   1. 本地覆盖快路径(hosts 语义);
    ///   2. in-TTL positive cache 快路径(`CacheStatus::Hit`);
    ///   3. in-TTL negative cache 快路径(直接报错);
    ///   4. 进入 resolver 主循环;
    ///   5. 只有主循环没产出可核实文档、且没有负状态屏蔽、权威源也没回答
    ///      Missing 时,才按策略用"过期但未作废"的缓存兜底。
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
        let source = policy.source;
        let allow_stale_cache = policy.allow_stale_cache;
        let doc_type_c = doc_type.clone().unwrap_or_default();

        // 0. Zone Resolver L1 cache 快路径(T5.2):明确回答时命中
        // (`CacheStatus::ZoneHit`),local override、本机 cache、method authority、
        // supplements 都不参与;Missing / 负状态是回答。Zone 返回 unknown
        // 时按 L1 miss 继续 L2 本机 cache 与 resolver core。Zone 结果不回写
        // 本机 cache(避免两级 cache entry 合并)。不做 did_in_zone 客户端过滤:
        // 覆盖范围由 Zone Resolver 服务内部策略决定(T5.3)。
        // 来源门禁:LocalOnly(零网络)与 RemoteAuthority(显式权威判断)不走
        // Zone;policy 也可按调用关闭(`use_zone_resolver = false`):
        // zone-resolver-server 内部用 resolve_did 完成对外查询,必须跳过这里,
        // 否则查询到自己造成递归。
        let zone_allowed = matches!(
            source,
            ResolveSourcePolicy::LocalAndZone | ResolveSourcePolicy::BestAvailable
        ) && policy.use_zone_resolver;
        if zone_allowed {
            if let Some(zone) = self.zone_resolver_snapshot() {
                let no_proof = self
                    .name_query
                    .is_no_proof_doc_type(&did.method, &doc_type_c)
                    .await;
                match zone.lookup(did, &doc_type_c, no_proof).await {
                    ZoneLookup::Answered(answer) => return answer.result,
                    ZoneLookup::Unknown(err) => {
                        debug!(
                            "zone resolver unknown for {}#{}, falling back to local cache: {}",
                            did.to_string(),
                            doc_type_c,
                            err
                        );
                    }
                }
            }
        }

        // Info 契约走独立轻量路径:进程内热缓存 + 本机 unverified 持久化观察。
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

        // RemoteAuthority:显式要求本次取得权威判断,跳过一切 in-TTL 快路径
        // (负状态记忆仍在主循环后置门禁里生效:非权威已发布结果翻不了它)。
        let fast_path_allowed = source != ResolveSourcePolicy::RemoteAuthority;

        // 1. 负状态快路径:负状态是"回答",命中返回错误,不是"查不到"。
        if fast_path_allowed {
            if let Some(CacheLookup::Negative {
                message,
                in_ttl: true,
                ..
            }) = &cached
            {
                return Err(NSError::Disabled(message.clone()));
            }
        }

        // 2. in-TTL positive 快路径。owner replay guard 对缓存命中同样生效。
        //    读路径按证据等级分流(doc/update-did-cache.md):Published/Verified
        //    直接返回;Unverified(Observed)必须先过一次 lazy verify——系统
        //    收到过 != 系统信任它,resolver 的默认返回不能不问出处。
        if fast_path_allowed {
            if let Some(CacheLookup::Positive {
                doc,
                exp,
                evidence,
                in_ttl: true,
                source: entry_source,
            }) = &cached
            {
                let doc = doc.clone();
                let exp = *exp;
                let evidence = *evidence;
                let entry_source = entry_source.as_deref().and_then(UpdateSource::from_str);
                match evidence {
                    CacheEvidence::Published | CacheEvidence::Verified => {
                        match self.validate_doc_replay_guard(did, doc_type.clone(), &doc) {
                            Ok(()) => {
                                return Ok(ResolvedDocument::from_cache(
                                    doc,
                                    did,
                                    &doc_type_c,
                                    exp,
                                    evidence.to_body_evidence(),
                                    CacheStatus::Hit,
                                )
                                .with_verification_status(VerificationStatus::Passed));
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
                    CacheEvidence::Unverified
                        if source == ResolveSourcePolicy::BestAvailable =>
                    {
                        // 首次使用时 lazy verify(需要权威往返,只有
                        // BestAvailable 允许)。Rejected(候选已删除)与 strict
                        // 下的 Unavailable 都等同 cache miss 继续主循环,与
                        // owner replay guard 失败的处理方式完全对称。
                        match self.verify_and_promote(did, doc_type.clone(), &policy).await {
                            Ok(VerifyPromoteOutcome::Promoted(promoted_doc)) => {
                                return Ok(ResolvedDocument::from_cache(
                                    promoted_doc,
                                    did,
                                    &doc_type_c,
                                    exp,
                                    CacheEvidence::Verified.to_body_evidence(),
                                    CacheStatus::Hit,
                                )
                                .with_verification_status(VerificationStatus::Passed)
                                .with_source(entry_source));
                            }
                            Ok(VerifyPromoteOutcome::Rejected(err)) => {
                                info!(
                                    "observed did:{}#{} rejected by lazy verify: {}",
                                    did.to_string(),
                                    doc_type_c,
                                    err
                                );
                                cached = None;
                            }
                            Ok(VerifyPromoteOutcome::Unavailable(err)) => {
                                if policy.allow_unverified_cache_when_unavailable
                                    && self
                                        .validate_doc_replay_guard(did, doc_type.clone(), &doc)
                                        .is_ok()
                                {
                                    // 显式宽松模式:打标露面,绝不冒充已验证结果。
                                    info!(
                                        "observed did:{}#{} served as ObservedFallback \
                                         (verification unavailable): {}",
                                        did.to_string(),
                                        doc_type_c,
                                        err
                                    );
                                    return Ok(ResolvedDocument::from_cache(
                                        doc,
                                        did,
                                        &doc_type_c,
                                        exp,
                                        CacheEvidence::Unverified.to_body_evidence(),
                                        CacheStatus::ObservedFallback,
                                    )
                                    .with_verification_status(VerificationStatus::Unavailable)
                                    .with_source(entry_source));
                                }
                                debug!(
                                    "observed did:{}#{} lazy verify unavailable, \
                                     strict resolve treats it as cache miss: {}",
                                    did.to_string(),
                                    doc_type_c,
                                    err
                                );
                                cached = None;
                            }
                            Err(err) => {
                                debug!(
                                    "lazy verify for observed did:{}#{} failed to run: {}",
                                    did.to_string(),
                                    doc_type_c,
                                    err
                                );
                                cached = None;
                            }
                        }
                    }
                    CacheEvidence::Unverified => {
                        // LocalOnly / LocalAndZone:来源策略不允许 lazy verify
                        // 的权威往返。宽松模式下打标露面(verification 未尝试),
                        // strict 等同 miss。
                        if policy.allow_unverified_cache_when_unavailable
                            && self
                                .validate_doc_replay_guard(did, doc_type.clone(), &doc)
                                .is_ok()
                        {
                            return Ok(ResolvedDocument::from_cache(
                                doc,
                                did,
                                &doc_type_c,
                                exp,
                                CacheEvidence::Unverified.to_body_evidence(),
                                CacheStatus::ObservedFallback,
                            )
                            .with_verification_status(VerificationStatus::NotAttempted)
                            .with_source(entry_source));
                        }
                        cached = None;
                    }
                }
            }
        }

        // LocalOnly / LocalAndZone:不进 resolver 主循环。负状态(不论 TTL)
        // 屏蔽;否则按策略用"过期但未作废"的 Published/Verified 条目兜底。
        if matches!(
            source,
            ResolveSourcePolicy::LocalOnly | ResolveSourcePolicy::LocalAndZone
        ) {
            if let Some(CacheLookup::Negative { message, .. }) = &cached {
                return Err(NSError::Disabled(message.clone()));
            }
            if allow_stale_cache {
                if let Some(CacheLookup::Positive {
                    doc, exp, evidence, ..
                }) = cached
                {
                    if evidence != CacheEvidence::Unverified && !Self::doc_self_expired(&doc) {
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
            return Err(NSError::NotFound(format!(
                "{}#{} not available from {:?} sources",
                did.to_string(),
                doc_type_c,
                source
            )));
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
                        self.cache_embedded_zone_devices(&doc_type_c, &resolved.document, evidence);
                        self.cache_discovered_documents(&resolved.discovered_documents, evidence);
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
                // 策略点④:过期但未作废的缓存兜底。兜底资格只属于
                // Published/Verified 条目:Unverified 观察缓存从未通过验证,
                // 连降级露面都必须走显式的 ObservedFallback 打标路径
                // (doc/update-did-cache.md),不能混进普通 stale 兜底。
                // RemoteAuthority 来源策略显式要求权威判断,不做任何兜底。
                if allow_stale_cache && source == ResolveSourcePolicy::BestAvailable {
                    if let Some(CacheLookup::Positive {
                        doc, exp, evidence, ..
                    }) = cached
                    {
                        if evidence != CacheEvidence::Unverified && !Self::doc_self_expired(&doc) {
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

    /// Info 契约的轻量路径:先查进程内 UnauthenticatedInfoCache,再查本机
    /// `did_cache/unverified` 的跨进程观察结果,否则查询后写回进程内缓存。
    async fn resolve_unproof_info_with_cache(
        &self,
        did: &DID,
        doc_type: Option<DidDocType>,
        doc_type_c: &DidDocType,
        policy: ResolvePolicy,
    ) -> NSResult<ResolvedDocument> {
        if self.config.enable_cache {
            let mut selected = self
                .unauthenticated_info_cache
                .get(did, doc_type.clone())
                .map(|(doc, exp, _rank)| (doc, exp, false));

            if let Some(CacheLookup::Positive {
                doc,
                exp,
                in_ttl: true,
                ..
            }) = self.doc_cache.lookup(did, doc_type.clone())
            {
                let use_persisted = selected
                    .as_ref()
                    .map(|(current_doc, _, _)| {
                        Self::info_doc_is_at_least_as_fresh(&doc, current_doc)
                    })
                    .unwrap_or(true);
                if use_persisted {
                    selected = Some((doc, exp, true));
                }
            }

            if let Some((doc, exp, from_persisted)) = selected {
                if from_persisted {
                    self.unauthenticated_info_cache.insert(
                        did,
                        doc_type.clone(),
                        doc.clone(),
                        exp,
                        DEFAULT_PROVIDER_TRUST_LEVEL,
                    );
                }
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

        // LocalOnly / LocalAndZone:info 契约同样不进 provider 查询
        // (Zone 快路径已在外层按来源门禁执行过)。
        if matches!(
            policy.source,
            ResolveSourcePolicy::LocalOnly | ResolveSourcePolicy::LocalAndZone
        ) {
            return Err(NSError::NotFound(format!(
                "unauthenticated info not cached: {}#{}",
                did.to_string(),
                doc_type_c
            )));
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
            // 单机语义测试:显式关闭 Zone Resolver,避免命中开发机上真实
            // 运行的 127.0.0.1:3180 服务。
            enable_zone_resolver: false,
            ..Default::default()
        };
        NameClient::new(cfg)
    }

    fn mem_client() -> NameClient {
        NameClient::new(NameClientConfig {
            enable_cache: true,
            cache_backend: CacheBackend::Memory,
            enable_zone_resolver: false,
            ..Default::default()
        })
    }

    // ---- T5: Zone Resolver cache 层(zone_resolver.rs + resolve_did_ex 第 0 步) ----

    /// 极小的 zone resolver HTTP stub:对任意请求返回固定 status + body,
    /// 记录请求次数。返回 (endpoint, hits)。
    async fn spawn_zone_stub(
        status_line: &'static str,
        body: String,
    ) -> (String, Arc<AtomicUsize>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let hits = Arc::new(AtomicUsize::new(0));
        let hits_in_task = hits.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                hits_in_task.fetch_add(1, Ordering::SeqCst);
                // 读到请求头结束(GET 无 body)。
                let mut buf = Vec::new();
                let mut chunk = [0u8; 1024];
                loop {
                    match stream.read(&mut chunk).await {
                        Ok(0) => break,
                        Ok(n) => {
                            buf.extend_from_slice(&chunk[..n]);
                            if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
                let response = format!(
                    "HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    status_line,
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            }
        });
        (format!("http://{}", addr), hits)
    }

    /// 拿一个当前没有监听者的本机端口(bind 后立即释放)。
    async fn free_endpoint() -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        format!("http://{}", addr)
    }

    fn zone_doc_body(marker: &str) -> String {
        serde_json::json!({
            "didDocument": {"marker": marker},
            "didDocumentMetadata": {
                "buckyos": {"documentStatus": "active", "documentVersion": 3}
            }
        })
        .to_string()
    }

    #[tokio::test]
    async fn zone_answer_short_circuits_local_cache_and_providers() {
        // T5.6:Zone Resolver 成功返回时,不调用 local cache、local override、
        // method authority 或 supplements;结果打 ZoneHit,且不回写本机 cache。
        let (endpoint, hits) = spawn_zone_stub("200 OK", zone_doc_body("zone-answer")).await;
        let client = mem_client();
        client.set_zone_resolver_endpoint(&endpoint);

        let did = DID::from_str("did:web:example.com").unwrap();
        let now = buckyos_get_unix_timestamp();
        // in-TTL local positive cache 与 local override 都在场,但都不参与。
        let cached = make_doc(now, now + 1000, "local-cache");
        client.doc_cache.insert(
            did.clone(),
            None,
            cached.clone(),
            now + 1000,
            CacheEvidence::Published,
        );
        client.set_local_authority_override(
            did.clone(),
            DidDocType::Zone,
            make_doc(now, now + 1000, "local-override"),
            "test-env",
            None,
        );
        let authority = MockAuthority::ok(make_doc(now, now + 2000, "from-authority"));
        let calls_probe = &authority.calls as *const AtomicUsize;
        client
            .set_method_authority("web", Box::new(authority))
            .await;

        let resolved = client
            .resolve_did_ex(&did, None, ResolvePolicy::default())
            .await
            .unwrap();
        assert_eq!(
            resolved.document,
            EncodedDocument::JsonLd(serde_json::json!({"marker": "zone-answer"}))
        );
        assert_eq!(
            resolved.resolution_metadata.cache_status,
            Some(CacheStatus::ZoneHit)
        );
        assert_eq!(resolved.document_metadata.buckyos.document_version, Some(3));
        assert!(resolved
            .resolution_metadata
            .resolver_id
            .as_deref()
            .unwrap()
            .starts_with("zone-resolver:"));
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        assert_eq!(unsafe { (*calls_probe).load(Ordering::SeqCst) }, 0);
        // zone 结果不回写 local cache:原缓存条目原样保留。
        assert_eq!(client.doc_cache.get(&did, None).unwrap().0, cached);
    }

    #[tokio::test]
    async fn zone_disabled_falls_back_to_single_node_flow() {
        // T5.6:disable_zone_resolver() 后不查询 Zone Resolver,退回单机
        // cache + resolver 流程。
        let (endpoint, hits) = spawn_zone_stub("200 OK", zone_doc_body("zone-answer")).await;
        let client = mem_client();
        client.set_zone_resolver_endpoint(&endpoint);
        client.disable_zone_resolver();

        let did = DID::from_str("did:web:example.com").unwrap();
        let now = buckyos_get_unix_timestamp();
        let cached = make_doc(now, now + 1000, "local-cache");
        client.doc_cache.insert(
            did.clone(),
            None,
            cached.clone(),
            now + 1000,
            CacheEvidence::Published,
        );

        let resolved = client
            .resolve_did_ex(&did, None, ResolvePolicy::default())
            .await
            .unwrap();
        assert_eq!(resolved.document, cached);
        assert_eq!(
            resolved.resolution_metadata.cache_status,
            Some(CacheStatus::Hit)
        );
        assert_eq!(hits.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn policy_without_zone_resolver_skips_zone_for_this_call_only() {
        // ResolvePolicy::use_zone_resolver = false 是按调用的旁路:
        // zone-resolver-server 内部用 resolve_did 向外查询时靠它避免自递归;
        // 同一 client 上使用默认 policy 的调用不受影响。
        let (endpoint, hits) = spawn_zone_stub("200 OK", zone_doc_body("zone-answer")).await;
        let client = mem_client();
        client.set_zone_resolver_endpoint(&endpoint);

        let did = DID::from_str("did:web:example.com").unwrap();
        let now = buckyos_get_unix_timestamp();
        let cached = make_doc(now, now + 1000, "local-cache");
        client.doc_cache.insert(
            did.clone(),
            None,
            cached.clone(),
            now + 1000,
            CacheEvidence::Published,
        );

        // 关闭 zone 的调用:不触碰 stub,走本机 cache。
        let resolved = client
            .resolve_did_ex(&did, None, ResolvePolicy::default().without_zone_resolver())
            .await
            .unwrap();
        assert_eq!(resolved.document, cached);
        assert_eq!(
            resolved.resolution_metadata.cache_status,
            Some(CacheStatus::Hit)
        );
        assert_eq!(hits.load(Ordering::SeqCst), 0);

        // 默认 policy 的调用仍优先命中 Zone L1。
        let resolved = client
            .resolve_did_ex(&did, None, ResolvePolicy::default())
            .await
            .unwrap();
        assert_eq!(
            resolved.resolution_metadata.cache_status,
            Some(CacheStatus::ZoneHit)
        );
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn zone_unavailable_falls_back_to_local_cache_hit() {
        // T5.6:服务不可用(connection refused)是 Zone unknown,落回 local cache,
        // 命中返回原有 CacheStatus::Hit。
        let client = mem_client();
        client.set_zone_resolver_endpoint(free_endpoint().await);

        let did = DID::from_str("did:web:example.com").unwrap();
        let now = buckyos_get_unix_timestamp();
        let cached = make_doc(now, now + 1000, "local-cache");
        client.doc_cache.insert(
            did.clone(),
            None,
            cached.clone(),
            now + 1000,
            CacheEvidence::Published,
        );

        let resolved = client
            .resolve_did_ex(&did, None, ResolvePolicy::default())
            .await
            .unwrap();
        assert_eq!(resolved.document, cached);
        assert_eq!(
            resolved.resolution_metadata.cache_status,
            Some(CacheStatus::Hit)
        );
    }

    #[tokio::test]
    async fn zone_unknown_answer_falls_back_to_local_cache_hit() {
        // 裸 404 表示 Zone L1 cache 不知道,继续走 L2 本机 cache。
        let (endpoint, hits) = spawn_zone_stub("404 Not Found", String::new()).await;
        let client = mem_client();
        client.set_zone_resolver_endpoint(&endpoint);

        let did = DID::from_str("did:web:example.com").unwrap();
        let now = buckyos_get_unix_timestamp();
        let cached = make_doc(now, now + 1000, "local-cache");
        client.doc_cache.insert(
            did.clone(),
            None,
            cached.clone(),
            now + 1000,
            CacheEvidence::Published,
        );
        let authority = MockAuthority::ok(make_doc(now, now + 2000, "from-authority"));
        let calls_probe = &authority.calls as *const AtomicUsize;
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
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        assert_eq!(unsafe { (*calls_probe).load(Ordering::SeqCst) }, 0);
    }

    #[tokio::test]
    async fn zone_negative_answer_blocks_local_positive_and_authority() {
        // T5.6:Zone 返回 Revoked 时,local positive cache 和外部 authority
        // 都不得绕过;负状态是回答,不是 miss。zone 回答也不改写本机 cache。
        let body = serde_json::json!({
            "didDocumentMetadata": {"buckyos": {"documentStatus": "revoked"}}
        })
        .to_string();
        let (endpoint, _hits) = spawn_zone_stub("410 Gone", body).await;
        let client = mem_client();
        client.set_zone_resolver_endpoint(&endpoint);

        let did = DID::from_str("did:web:example.com").unwrap();
        let now = buckyos_get_unix_timestamp();
        let cached = make_doc(now, now + 1000, "local-cache");
        client.doc_cache.insert(
            did.clone(),
            None,
            cached.clone(),
            now + 1000,
            CacheEvidence::Published,
        );
        let authority = MockAuthority::ok(make_doc(now, now + 2000, "from-authority"));
        let calls_probe = &authority.calls as *const AtomicUsize;
        client
            .set_method_authority("web", Box::new(authority))
            .await;

        let err = client.resolve_did(&did, None).await.unwrap_err();
        let NSError::Disabled(msg) = err else {
            panic!("expected disabled, got {:?}", err);
        };
        assert!(msg.contains("zone resolver"));
        assert_eq!(unsafe { (*calls_probe).load(Ordering::SeqCst) }, 0);
        // zone 的负状态回答不写本机 negative cache(不回写纪律)。
        assert_eq!(client.doc_cache.get(&did, None).unwrap().0, cached);
    }

    #[tokio::test]
    async fn zone_missing_answer_blocks_local_cache_and_external_resolvers() {
        // T5.6:Zone 明确返回 Missing 时,不查 local cache,也不查外部 resolver。
        let body = serde_json::json!({
            "didDocumentMetadata": {"buckyos": {"documentStatus": "missing"}}
        })
        .to_string();
        let (endpoint, hits) = spawn_zone_stub("404 Not Found", body).await;
        let client = mem_client();
        client.set_zone_resolver_endpoint(&endpoint);

        let did = DID::from_str("did:web:example.com").unwrap();
        let now = buckyos_get_unix_timestamp();
        client.doc_cache.insert(
            did.clone(),
            None,
            make_doc(now, now + 1000, "local-cache"),
            now + 1000,
            CacheEvidence::Published,
        );
        let authority = MockAuthority::ok(make_doc(now, now + 2000, "from-authority"));
        let calls_probe = &authority.calls as *const AtomicUsize;
        client
            .set_method_authority("web", Box::new(authority))
            .await;

        let err = client.resolve_did(&did, None).await.unwrap_err();
        let NSError::NotFound(msg) = err else {
            panic!("expected not-found, got {:?}", err);
        };
        assert!(msg.contains("zone resolver"));
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        assert_eq!(unsafe { (*calls_probe).load(Ordering::SeqCst) }, 0);
    }

    #[tokio::test]
    async fn add_observed_cache_writes_local_only_and_zone_still_wins() {
        // T5.6:`update DID cache` 只影响 local cache;Zone Resolver 可用时
        // Zone 结果仍优先。
        let (endpoint, _hits) = spawn_zone_stub("200 OK", zone_doc_body("zone-answer")).await;
        let client = mem_client();
        client.set_zone_resolver_endpoint(&endpoint);

        let did = DID::from_str("did:web:example.com").unwrap();
        let now = buckyos_get_unix_timestamp();
        let pushed = make_doc(now, now + 1000, "pushed");
        client
            .add_observed_cache(did.clone(), None, pushed.clone(), None)
            .unwrap();
        // push 进的是本机 cache。
        assert_eq!(client.doc_cache.get(&did, None).unwrap().0, pushed);

        let resolved = client
            .resolve_did_ex(&did, None, ResolvePolicy::default())
            .await
            .unwrap();
        assert_eq!(
            resolved.resolution_metadata.cache_status,
            Some(CacheStatus::ZoneHit)
        );
        assert_eq!(
            resolved.document,
            EncodedDocument::JsonLd(serde_json::json!({"marker": "zone-answer"}))
        );
        // 本机 cache 不受 zone 回答影响。
        assert_eq!(client.doc_cache.get(&did, None).unwrap().0, pushed);
    }

    #[tokio::test]
    async fn zone_covers_any_did_without_client_side_zone_filter() {
        // T5.6:`did_in_zone` 过滤已移除——Zone Resolver 可覆盖任意 DID,
        // 包括未注册 method 的 DID;覆盖范围由服务内部策略决定。
        let (endpoint, hits) = spawn_zone_stub("200 OK", zone_doc_body("zone-any")).await;
        let client = mem_client();
        client.set_zone_resolver_endpoint(&endpoint);

        // 未注册任何 method provider。
        for did_str in ["did:web:other.com", "did:bns:alice"] {
            let did = DID::from_str(did_str).unwrap();
            let resolved = client
                .resolve_did_ex(&did, None, ResolvePolicy::default())
                .await
                .unwrap();
            assert_eq!(
                resolved.resolution_metadata.cache_status,
                Some(CacheStatus::ZoneHit)
            );
        }
        assert_eq!(hits.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn zone_serves_info_doc_type_with_unproof_evidence() {
        // Info 契约的请求同样可由 Zone L1 明确命中,证据按契约打 UnproofInfo,
        // 且不写 UnauthenticatedInfoCache(zone 结果不回写任何本机缓存)。
        let body = serde_json::json!({"didDocument": {"info": "zone-info"}}).to_string();
        let (endpoint, _hits) = spawn_zone_stub("200 OK", body).await;
        let client = mem_client();
        client.set_zone_resolver_endpoint(&endpoint);

        let did = DID::from_str("did:web:dev1.example.com").unwrap();
        let resolved = client
            .resolve_did_ex(&did, Some(DidDocType::Info), ResolvePolicy::default())
            .await
            .unwrap();
        assert_eq!(
            resolved.resolution_metadata.cache_status,
            Some(CacheStatus::ZoneHit)
        );
        assert_eq!(
            resolved.resolution_metadata.evidence,
            Some(BodyEvidence::UnproofInfo)
        );
        assert!(client
            .unauthenticated_info_cache
            .get(&did, Some(DidDocType::Info))
            .is_none());
    }

    #[tokio::test]
    async fn key_class_did_rejected_before_zone_lookup() {
        // key 类 DID 的硬门禁仍然排在 Zone 快路径之前。
        let (endpoint, hits) = spawn_zone_stub("200 OK", zone_doc_body("zone-answer")).await;
        let client = mem_client();
        client.set_zone_resolver_endpoint(&endpoint);

        let did = DID::from_str("did:dev:5bUuyWLOKyCre9az_IhJVIuOw8bA0gyKjstcYGHbaPE").unwrap();
        let err = client.resolve_did(&did, None).await.unwrap_err();
        assert!(matches!(err, NSError::InvalidDID(_)));
        assert_eq!(hits.load(Ordering::SeqCst), 0);
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

        // push(add_observed_cache)写不进去,负状态仍在。
        let now = buckyos_get_unix_timestamp();
        client
            .add_observed_cache(
                did.clone(),
                None,
                make_doc(now, now + 1000, "pushed"),
                Some(UpdateSource::Push),
            )
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

        // provider 返回的 Info 结果只进入 UnauthenticatedInfoCache,不回写 doc_cache。
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
            enable_zone_resolver: false,
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
            enable_zone_resolver: false,
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
            enable_zone_resolver: false,
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
            enable_zone_resolver: false,
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
            enable_zone_resolver: false,
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
    async fn resolve_ips_falls_back_when_device_document_resolution_fails() {
        // 权威读取端拿回损坏内容(如网关把错误页当文档返回)时,resolve_did
        // 以非 NotFound 错误落空。这只作废 Document 固定 IP 信道,不能终结
        // resolve_ips:nameinfo 信道仍要照常给出地址。
        struct GarbageAuthority;

        #[async_trait]
        impl NsProvider for GarbageAuthority {
            fn get_id(&self) -> String {
                "garbage-authority".to_string()
            }

            async fn query(
                &self,
                _name: &str,
                _record_type: Option<RecordType>,
                _from_ip: Option<std::net::IpAddr>,
            ) -> NSResult<NameInfo> {
                Err(NSError::NotFound("no nameinfo".into()))
            }

            async fn query_did(
                &self,
                _did: &DID,
                _doc_type: Option<DidDocType>,
                _from_ip: Option<std::net::IpAddr>,
            ) -> NSResult<EncodedDocument> {
                Err(NSError::DecodeJWTError(
                    "Failed: parts.len != 3".to_string(),
                ))
            }
        }

        let client = NameClient::new(NameClientConfig {
            enable_cache: false,
            cache_backend: CacheBackend::Memory,
            enable_zone_resolver: false,
            ..Default::default()
        });
        client
            .set_method_authority("web", Box::new(GarbageAuthority))
            .await;
        let name_provider = build_device_provider(
            Vec::new(),
            Vec::new(),
            vec!["192.0.2.10".parse().unwrap()],
        );
        client.add_dns_provider(Box::new(name_provider)).await;

        let resolved = client.resolve_ips("did:web:ood1.example").await.unwrap();
        assert_eq!(resolved, vec!["192.0.2.10".parse::<IpAddr>().unwrap()]);
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
            .is_some());
    }

    fn build_discovered_device_info(
        device_did: &DID,
        endpoint_ip: IpAddr,
        update_time: u64,
    ) -> DeviceInfo {
        let mut discovered_doc = DeviceDocument::new(
            "ood1",
            "5bUuyWLOKyCre9az_IhJVIuOw8bA0gyKjstcYGHbaPE".to_string(),
        );
        discovered_doc.id = device_did.clone();
        discovered_doc.zone_did = Some(DID::new("bns", "alice"));
        discovered_doc.owner = DID::new("bns", "alice");

        let mut device_info = DeviceInfo::from_device_doc(&discovered_doc);
        device_info.arch.clear();
        device_info.os.clear();
        device_info.update_time = update_time;
        device_info.all_ip.push(endpoint_ip);
        device_info
    }

    #[tokio::test]
    async fn device_info_cache_is_shared_across_processes() {
        let tmp_dir = tempdir().unwrap();
        let cache_dir = tmp_dir.path().to_string_lossy().to_string();
        let new_client = || {
            NameClient::new(NameClientConfig {
                enable_cache: true,
                local_cache_dir: Some(cache_dir.clone()),
                cache_backend: CacheBackend::Filesystem,
                enable_zone_resolver: false,
                ..Default::default()
            })
        };
        let writer = new_client();
        let reader = new_client();

        let device_did = DID::from_str("did:web:ood1.example").unwrap();
        let now = buckyos_get_unix_timestamp();
        let first_ip: IpAddr = "192.168.1.20".parse().unwrap();
        let first_info = build_discovered_device_info(&device_did, first_ip, now);
        let first_doc = EncodedDocument::JsonLd(serde_json::to_value(&first_info).unwrap());
        writer
            .add_observed_cache(
                device_did.clone(),
                Some(DidDocType::Info),
                first_doc,
                Some(UpdateSource::UdpDiscovery),
            )
            .unwrap();

        let first_resolved = reader.resolve_ips("did:web:ood1.example").await.unwrap();
        assert_eq!(first_resolved, vec![first_ip]);

        let second_ip: IpAddr = "192.168.1.21".parse().unwrap();
        let second_info = build_discovered_device_info(&device_did, second_ip, now + 1);
        writer
            .add_device_info_cache(device_did.clone(), second_info)
            .unwrap();

        let second_resolved = reader.resolve_ips("did:web:ood1.example").await.unwrap();
        assert_eq!(second_resolved, vec![second_ip]);

        let resolved_info = reader
            .resolve_did_ex(
                &device_did,
                Some(DidDocType::Info),
                ResolvePolicy::default(),
            )
            .await
            .unwrap();
        assert_eq!(
            resolved_info.resolution_metadata.cache_status,
            Some(CacheStatus::UnauthenticatedInfoHit)
        );
        assert!(resolved_info
            .resolution_metadata
            .warnings
            .contains(&ResolveWarning::UnauthenticatedInfoCache));
    }

    // ---- doc/update-did-cache.md 测试要求:Observed / lazy verify / promote ----

    /// bns 二级名字的可验证候选链:owner alice + 由 alice 签名、声明 owner 为
    /// alice 的 app zone 文档。
    fn build_owned_zone_and_owner(
        app_did: &DID,
        owner_did: &DID,
        iat: u64,
        marker: &str,
    ) -> (EncodedDocument, EncodedDocument) {
        let private_key = EncodingKey::from_ed_pem(TEST_OWNER_PRIVATE_KEY_PEM.as_bytes()).unwrap();
        let jwk = test_owner_public_jwk();

        let mut owner = OwnerDocument::new(
            owner_did.clone(),
            "alice".to_string(),
            "alice@test".to_string(),
            jwk.clone(),
        );
        owner.version_seq = Some(0);
        let owner_doc = owner.encode(Some(&private_key)).unwrap();

        let mut zone = ZoneDocument::new(app_did.clone(), owner_did.clone(), jwk);
        zone.iat = iat;
        zone.exp = iat + 3600 * 24 * 365;
        zone.version_seq = Some(1);
        zone.extra_info
            .insert("marker".to_string(), serde_json::json!(marker));
        let zone_doc = zone.encode(Some(&private_key)).unwrap();

        (zone_doc, owner_doc)
    }

    // 测试要求 3:Observed 候选通过 verify_and_promote 后,原条目从 unverified
    // 消失、verified 出现对应条目(证据 Verified);第二次 resolve_did 是普通
    // cache hit,不再重复触发验证(权威源零调用)。
    #[tokio::test]
    async fn lazy_verify_promotes_observed_candidate_then_plain_hit() {
        let app_did = DID::new("bns", "app1.alice");
        let now = buckyos_get_unix_timestamp();
        let (zone_doc, owner_doc) =
            build_owned_zone_and_owner(&app_did, &DID::new("bns", "alice"), now, "observed");

        let client = mem_client();
        let authority = MockAuthority::ok(zone_doc.clone()).with_owner_doc(owner_doc);
        let calls_probe = &authority.calls as *const AtomicUsize;
        client
            .set_method_authority("bns", Box::new(authority))
            .await;

        client
            .add_observed_cache(
                app_did.clone(),
                None,
                zone_doc.clone(),
                Some(UpdateSource::UdpDiscovery),
            )
            .unwrap();
        match client.doc_cache.lookup(&app_did, None).unwrap() {
            CacheLookup::Positive { evidence, .. } => {
                assert_eq!(evidence, CacheEvidence::Unverified)
            }
            other => panic!("unexpected {:?}", other),
        }

        // 首次 resolve:触发 lazy verify,promote 成功。
        let first = client
            .resolve_did_ex(&app_did, None, ResolvePolicy::default())
            .await
            .unwrap();
        assert_eq!(first.document, zone_doc);
        assert_eq!(
            first.resolution_metadata.cache_status,
            Some(CacheStatus::Hit)
        );
        assert_eq!(
            first.resolution_metadata.verification_status,
            Some(VerificationStatus::Passed)
        );
        assert_eq!(
            first.resolution_metadata.source,
            Some(UpdateSource::UdpDiscovery)
        );

        // 条目已从 unverified 移动到 verified,证据为 Verified。
        assert!(client.doc_cache.observed_candidate(&app_did, None).is_none());
        match client.doc_cache.lookup(&app_did, None).unwrap() {
            CacheLookup::Positive { evidence, .. } => {
                assert_eq!(evidence, CacheEvidence::Verified)
            }
            other => panic!("unexpected {:?}", other),
        }

        // 第二次 resolve:普通 cache hit,不再触发任何权威源调用。
        let calls_before = unsafe { (*calls_probe).load(Ordering::SeqCst) };
        let second = client
            .resolve_did_ex(&app_did, None, ResolvePolicy::default())
            .await
            .unwrap();
        assert_eq!(second.document, zone_doc);
        assert_eq!(
            second.resolution_metadata.cache_status,
            Some(CacheStatus::Hit)
        );
        assert_eq!(unsafe { (*calls_probe).load(Ordering::SeqCst) }, calls_before);
    }

    // 测试要求 4:lazy verify 明确失败(owner 冒充)时,unverified 条目被删除,
    // 不会反复触发验证开销。
    #[tokio::test]
    async fn lazy_verify_rejects_owner_impersonation_and_deletes_candidate() {
        let app_did = DID::new("bns", "app1.alice");
        let bob = DID::new("bns", "bob");
        let now = buckyos_get_unix_timestamp();
        // 候选由 bob 签名、声明 owner 为 bob,但名字结构决定 expected_owner
        // 是 alice —— owner 冒充。
        let (impersonated_doc, _bob_owner) =
            build_owned_zone_and_owner(&app_did, &bob, now, "impersonated");
        let (_zone, alice_owner_doc) = build_owned_zone_and_owner(
            &app_did,
            &DID::new("bns", "alice"),
            now,
            "alice-owner",
        );

        let client = mem_client();
        // 权威源:把这份冒充文档当作当前 body 返回(membership 满足),让验证
        // 走到 declared_owner 一致性检查;owner 文档正常可取。
        client
            .set_method_authority(
                "bns",
                Box::new(MockAuthority::ok(impersonated_doc.clone()).with_owner_doc(alice_owner_doc)),
            )
            .await;

        client
            .add_observed_cache(app_did.clone(), None, impersonated_doc, Some(UpdateSource::Gossip))
            .unwrap();
        assert!(client.doc_cache.observed_candidate(&app_did, None).is_some());

        let outcome = client
            .verify_and_promote(&app_did, None, &ResolvePolicy::default())
            .await
            .unwrap();
        match outcome {
            VerifyPromoteOutcome::Rejected(NSError::VerifyAndPromoteRejected { code, .. }) => {
                assert_eq!(code, "OwnerMismatch");
            }
            other => panic!("expected rejected, got {:?}", other),
        }
        // 候选已删除:第二次调用没有可验证对象,不会重复烧验证成本。
        assert!(client.doc_cache.observed_candidate(&app_did, None).is_none());
        assert!(client
            .verify_and_promote(&app_did, None, &ResolvePolicy::default())
            .await
            .is_err());
    }

    // 测试要求 5:验证条件不可用(权威源断网)时,strict 视为 miss;显式宽松
    // 模式返回 evidence=Unverified(NeedProof)+ verification_status=Unavailable
    // 的打标结果,且 unverified 条目保留。
    #[tokio::test]
    async fn lazy_verify_unavailable_strict_miss_lax_tagged_result() {
        let app_did = DID::new("bns", "app1.alice");
        let now = buckyos_get_unix_timestamp();
        let (zone_doc, _owner_doc) =
            build_owned_zone_and_owner(&app_did, &DID::new("bns", "alice"), now, "unavailable");

        let client = mem_client();
        client
            .set_method_authority(
                "bns",
                Box::new(MockAuthority::with_mode(AuthorityMode::Down)),
            )
            .await;

        client
            .add_observed_cache(app_did.clone(), None, zone_doc.clone(), Some(UpdateSource::Push))
            .unwrap();

        // strict(默认):等同 cache miss,主循环也拿不到结果时报错,但绝不把
        // 未验证文档返回给调用方。
        let err = client
            .resolve_did_ex(&app_did, None, ResolvePolicy::default())
            .await
            .unwrap_err();
        assert!(matches!(err, NSError::Failed(_)));
        // Unavailable 不删除候选。
        assert!(client.doc_cache.observed_candidate(&app_did, None).is_some());

        // 显式宽松模式:打标露面。
        let mut lax = ResolvePolicy::default();
        lax.allow_unverified_cache_when_unavailable = true;
        let resolved = client
            .resolve_did_ex(&app_did, None, lax)
            .await
            .unwrap();
        assert_eq!(resolved.document, zone_doc);
        assert_eq!(
            resolved.resolution_metadata.cache_status,
            Some(CacheStatus::ObservedFallback)
        );
        assert_eq!(
            resolved.resolution_metadata.verification_status,
            Some(VerificationStatus::Unavailable)
        );
        assert_eq!(
            resolved.resolution_metadata.evidence,
            Some(BodyEvidence::NeedProof)
        );
        assert_eq!(resolved.resolution_metadata.source, Some(UpdateSource::Push));
        // 候选仍保留在 unverified,等待条件恢复后真正验证。
        assert!(client.doc_cache.observed_candidate(&app_did, None).is_some());
    }

    // 测试要求 1 + 7:手工往 unverified/ 目录放文件与调用 add_observed_cache 完全
    // 等价("目录即协议");格式合法但验证不过的文件,strict resolve 不返回它、
    // 也不因它报错——视为 miss 继续主循环,拿到权威源结果。
    #[tokio::test]
    async fn hand_placed_unverified_file_is_miss_not_error_for_strict_resolve() {
        let tmp = tempdir().unwrap();
        let client = NameClient::new(NameClientConfig {
            enable_cache: true,
            local_cache_dir: Some(tmp.path().to_string_lossy().to_string()),
            cache_backend: CacheBackend::Filesystem,
            enable_zone_resolver: false,
            ..Default::default()
        });

        let did = DID::from_str("did:web:example.com").unwrap();
        let now = buckyos_get_unix_timestamp();
        let (authority_doc, owner_doc) = build_self_owned_zone_and_owner(&did, now, "authority");
        client
            .set_method_authority(
                "web",
                Box::new(MockAuthority::ok(authority_doc.clone()).with_owner_doc(owner_doc)),
            )
            .await;

        // 手工投递:格式合法(可解析)但未经验证、与权威结果不同的文档。
        let key = did.to_filename();
        let hand_placed = make_doc(now, now + 1000, "hand-placed");
        let unverified_doc_path = tmp
            .path()
            .join("unverified")
            .join(format!("{}.doc.json", key));
        std::fs::write(&unverified_doc_path, hand_placed.to_string()).unwrap();
        // 与 add_observed_cache 等价:立即被观察到。
        assert!(client.doc_cache.observed_candidate(&did, None).is_some());

        // strict resolve:不返回手工文件、不报错,继续主循环拿权威结果。
        let resolved = client
            .resolve_did_ex(&did, None, ResolvePolicy::default())
            .await
            .unwrap();
        assert_eq!(resolved.document, authority_doc);
        // 明确失败的候选被清理,不会反复触发验证。
        assert!(!unverified_doc_path.exists());
        assert!(client.doc_cache.observed_candidate(&did, None).is_none());
    }

    // 测试要求 7(promote 形态):手工放进 unverified/ 的可验证候选与
    // add_observed_cache 行为一致——resolve 时被 lazy verify 转正,文件物理移动
    // 到 verified/;meta 自称的 evidence 不被信任。
    #[tokio::test]
    async fn hand_placed_verifiable_file_promotes_like_add_observed_cache() {
        let tmp = tempdir().unwrap();
        let client = NameClient::new(NameClientConfig {
            enable_cache: true,
            local_cache_dir: Some(tmp.path().to_string_lossy().to_string()),
            cache_backend: CacheBackend::Filesystem,
            enable_zone_resolver: false,
            ..Default::default()
        });

        let app_did = DID::new("bns", "app1.alice");
        let now = buckyos_get_unix_timestamp();
        let (zone_doc, owner_doc) =
            build_owned_zone_and_owner(&app_did, &DID::new("bns", "alice"), now, "hand-promote");
        client
            .set_method_authority(
                "bns",
                Box::new(MockAuthority::ok(zone_doc.clone()).with_owner_doc(owner_doc)),
            )
            .await;

        // 手工写 doc + meta(meta 自称 Published,必须被忽略;source 仅诊断)。
        let key = app_did.to_filename();
        let unverified_dir = tmp.path().join("unverified");
        std::fs::write(
            unverified_dir.join(format!("{}.doc.json", key)),
            zone_doc.to_string(),
        )
        .unwrap();
        std::fs::write(
            unverified_dir.join(format!("{}.meta.json", key)),
            "{\"evidence\":\"Published\",\"source\":\"LocalFile\"}",
        )
        .unwrap();

        // 自称的 Published 不被信任:读出即 Unverified。
        match client.doc_cache.lookup(&app_did, None).unwrap() {
            CacheLookup::Positive { evidence, .. } => {
                assert_eq!(evidence, CacheEvidence::Unverified)
            }
            other => panic!("unexpected {:?}", other),
        }

        let resolved = client
            .resolve_did_ex(&app_did, None, ResolvePolicy::default())
            .await
            .unwrap();
        assert_eq!(resolved.document, zone_doc);
        assert_eq!(
            resolved.resolution_metadata.verification_status,
            Some(VerificationStatus::Passed)
        );
        assert_eq!(
            resolved.resolution_metadata.source,
            Some(UpdateSource::LocalFile)
        );

        // 文件已物理移动:unverified/ 清空,verified/ 出现对应文件。
        assert!(!unverified_dir.join(format!("{}.doc.json", key)).exists());
        assert!(tmp
            .path()
            .join("verified")
            .join(format!("{}.doc.json", key))
            .exists());
        match client.doc_cache.lookup(&app_did, None).unwrap() {
            CacheLookup::Positive { evidence, .. } => {
                assert_eq!(evidence, CacheEvidence::Verified)
            }
            other => panic!("unexpected {:?}", other),
        }
    }

    // 测试要求 2:verified/ 已有 Published 记录时,unverified/ 出现新文件不
    // 影响 resolve_did 的返回结果(也不触发验证)。
    #[tokio::test]
    async fn observed_file_does_not_affect_resolve_when_published_exists() {
        let client = mem_client();
        let did = DID::from_str("did:web:example.com").unwrap();
        let now = buckyos_get_unix_timestamp();
        let published = make_doc(now, now + 1000, "published");
        client.doc_cache.insert(
            did.clone(),
            None,
            published.clone(),
            now + 1000,
            CacheEvidence::Published,
        );

        // Observed 事件被记录,但查询永远优先命中 verified。
        client
            .add_observed_cache(
                did.clone(),
                None,
                make_doc(now + 10, now + 5000, "observed-later"),
                Some(UpdateSource::Push),
            )
            .unwrap();
        assert!(client.doc_cache.observed_candidate(&did, None).is_some());

        let resolved = client
            .resolve_did_ex(&did, None, ResolvePolicy::default())
            .await
            .unwrap();
        assert_eq!(resolved.document, published);
        assert_eq!(
            resolved.resolution_metadata.cache_status,
            Some(CacheStatus::Hit)
        );
        assert_eq!(
            resolved.resolution_metadata.verification_status,
            Some(VerificationStatus::Passed)
        );
    }

    // 测试要求 6:快速校验——声明 did:web:a 但文档 id 是 did:web:b 时,
    // unverified/ 目录不产生任何文件。
    #[tokio::test]
    async fn quick_check_rejects_mismatched_document_id_without_writing() {
        let tmp = tempdir().unwrap();
        let client = NameClient::new(NameClientConfig {
            enable_cache: true,
            local_cache_dir: Some(tmp.path().to_string_lossy().to_string()),
            cache_backend: CacheBackend::Filesystem,
            enable_zone_resolver: false,
            ..Default::default()
        });

        let declared = DID::from_str("did:web:a").unwrap();
        let mismatched = EncodedDocument::JsonLd(serde_json::json!({
            "id": "did:web:b",
            "exp": buckyos_get_unix_timestamp() + 1000,
        }));
        let err = client
            .add_observed_cache(declared.clone(), None, mismatched, Some(UpdateSource::Push))
            .unwrap_err();
        assert!(matches!(err, NSError::UnverifiedCacheWriteRejected(_)));

        // 目录里没有任何文件。
        let entries: Vec<_> = std::fs::read_dir(tmp.path().join("unverified"))
            .unwrap()
            .flatten()
            .filter(|entry| entry.path().is_file())
            .collect();
        assert!(entries.is_empty(), "no file should be written: {:?}", entries);
        assert!(client.doc_cache.observed_candidate(&declared, None).is_none());
    }

    // 补充:Unverified 观察缓存没有 stale 兜底资格——TTL 过期的 Observed 条目
    // 在权威源 unknown 时不能冒充 CacheFallback 结果。
    #[tokio::test]
    async fn expired_observed_entry_is_not_stale_fallback_material() {
        let client = mem_client();
        let did = DID::from_str("did:web:observed-stale.example").unwrap();
        let now = buckyos_get_unix_timestamp();
        // 直接以过期 exp 写入 Observed 条目(绕过 add_observed_cache 的 TTL 计算)。
        client.doc_cache.update_observed(
            did.clone(),
            None,
            make_doc_without_exp("observed-stale"),
            now.saturating_sub(10),
            None,
        );

        client
            .set_method_authority(
                "web",
                Box::new(MockAuthority::with_mode(AuthorityMode::Down)),
            )
            .await;

        // 默认策略允许 stale 兜底,但 Unverified 没有兜底资格。
        let err = client.resolve_did(&did, None).await.unwrap_err();
        assert!(matches!(err, NSError::Failed(_)));
    }
}
