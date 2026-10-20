#![allow(unused)]

use crate::addr_rtt_db::{
    AutoFlushHandle, CleanupReport, Config as AddrRttDbConfig, ConnectionOutcome,
    PersistencePolicy, RankedAddress, RttDatabase, SortPolicy,
};
use crate::name_query::NameQuery;
use crate::provider::RecordType;
use crate::resolver::{
    select_or_error, Backoff, CacheBackend, ConcurrencyConfig, DocLocks, DocStore, InfoCache,
    LocalLocker, LockOptions, LogThrottle, RegisteredSource, ResolveOpts, Revision, Scope, Source,
    SourceRegistry, TaskMerger, ZoneLocker, ZoneLockerConfig,
};
use crate::{is_key_class_method, DidDocType, NameInfo, NsProvider};
use buckyos_kit::buckyos_get_unix_timestamp;
use name_lib::*;

use log::*;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, RwLock as StdRwLock};
use std::time::{Duration, Instant};
use tokio::sync::RwLock;


/// 地址解析目标的可信类型判断。该值只用于收紧 Info 访问范围和审计日志，
/// 不从待解析目标的自声明文档推导。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolveIpTargetKind {
    Device,
    Zone,
    Sn,
    Owner,
    Unknown,
}

impl ResolveIpTargetKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Device => "device",
            Self::Zone => "zone",
            Self::Sn => "sn",
            Self::Owner => "owner",
            Self::Unknown => "unknown",
        }
    }
}

/// 地址解析目标与本机 zone 的可信关系判断。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolveIpZoneRelation {
    SameZone,
    CrossZone,
    Unknown,
}

impl ResolveIpZoneRelation {
    fn as_str(self) -> &'static str {
        match self {
            Self::SameZone => "same_zone",
            Self::CrossZone => "cross_zone",
            Self::Unknown => "unknown",
        }
    }
}

/// same-zone 事实的权威生产者。不能使用 DNS、名字形状、目标自声明字段或 Info
/// 查询结果作为 evidence。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SameZoneEvidenceSource {
    LocalZoneConfiguration,
    VerifiedOwnerZoneDeviceRelation,
    VerifiedHandshakeIdentity,
}

impl SameZoneEvidenceSource {
    fn as_str(self) -> &'static str {
        match self {
            Self::LocalZoneConfiguration => "local_zone_configuration",
            Self::VerifiedOwnerZoneDeviceRelation => "verified_owner_zone_device_relation",
            Self::VerifiedHandshakeIdentity => "verified_handshake_identity",
        }
    }
}

/// 已由调用方可信上下文证明的 same-zone device 关系。evidence 绑定精确目标 DID，
/// 避免把一个 tunnel/身份验证结果复用于其它目标。调用方应在本机 zone 配置或已验证
/// 身份关系变化时丢弃并重新生成该值。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedSameZoneDevice {
    target_did: DID,
    zone_did: DID,
    source: SameZoneEvidenceSource,
}

impl VerifiedSameZoneDevice {
    /// 只能在 `target_did` 的 device 类型及其 `zone_did` 关系均已由可信上下文验证后调用。
    pub fn from_verified_relation(
        target_did: DID,
        zone_did: DID,
        source: SameZoneEvidenceSource,
    ) -> Self {
        Self {
            target_did,
            zone_did,
            source,
        }
    }

    pub fn target_did(&self) -> &DID {
        &self.target_did
    }

    pub fn zone_did(&self) -> &DID {
        &self.zone_did
    }

    pub fn source(&self) -> SameZoneEvidenceSource {
        self.source
    }
}

/// DeviceInfo 的地址解析访问策略。启用分支要求携带绑定到目标的可信 evidence，
/// 避免 `include_info: bool` 这类无法审计来源的开关。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceInfoPolicy {
    Disabled,
    VerifiedSameZone(VerifiedSameZoneDevice),
}

/// 一次地址解析的可信作用域。默认是 unknown + InfoDisabled（fail closed）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolveIpOptions {
    target_kind: ResolveIpTargetKind,
    zone_relation: ResolveIpZoneRelation,
    device_info_policy: DeviceInfoPolicy,
}

impl ResolveIpOptions {
    /// 为 cross-zone、non-device 或关系未知目标构造显式的 no-Info 策略。
    pub fn without_device_info(
        target_kind: ResolveIpTargetKind,
        zone_relation: ResolveIpZoneRelation,
    ) -> Self {
        Self {
            target_kind,
            zone_relation,
            device_info_policy: DeviceInfoPolicy::Disabled,
        }
    }

    /// 为已验证的 same-zone device 构造唯一允许读取 Info 的一致策略。
    pub fn verified_same_zone_device(evidence: VerifiedSameZoneDevice) -> Self {
        Self {
            target_kind: ResolveIpTargetKind::Device,
            zone_relation: ResolveIpZoneRelation::SameZone,
            device_info_policy: DeviceInfoPolicy::VerifiedSameZone(evidence),
        }
    }

    pub fn target_kind(&self) -> ResolveIpTargetKind {
        self.target_kind
    }

    pub fn zone_relation(&self) -> ResolveIpZoneRelation {
        self.zone_relation
    }

    pub fn device_info_policy(&self) -> &DeviceInfoPolicy {
        &self.device_info_policy
    }
}

impl Default for ResolveIpOptions {
    fn default() -> Self {
        Self::without_device_info(ResolveIpTargetKind::Unknown, ResolveIpZoneRelation::Unknown)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeviceInfoSkipReason {
    PolicyDisabled,
    TargetNotDevice,
    ZoneNotSame,
    InvalidTargetDid,
    EvidenceTargetMismatch,
    UnsupportedTargetMethod,
    FixedDeviceDocumentAddress,
}

impl DeviceInfoSkipReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::PolicyDisabled => "policy_disabled",
            Self::TargetNotDevice => "target_not_device",
            Self::ZoneNotSame => "zone_not_same",
            Self::InvalidTargetDid => "invalid_target_did",
            Self::EvidenceTargetMismatch => "evidence_target_mismatch",
            Self::UnsupportedTargetMethod => "unsupported_target_method",
            Self::FixedDeviceDocumentAddress => "fixed_device_document_address",
        }
    }
}

enum DeviceInfoDecision<'a> {
    Disabled(DeviceInfoSkipReason),
    Enabled(&'a VerifiedSameZoneDevice),
}

#[cfg(feature = "metrics")]
fn metrics_resolve_ip_scope(
    target_kind: &'static str,
    zone_relation: &'static str,
    info_policy: &'static str,
    skip_reason: &'static str,
) {
    metrics::counter!(
        "name_client.resolve_ips.scope_total",
        "target_kind" => target_kind,
        "zone_relation" => zone_relation,
        "info_policy" => info_policy,
        "skip_reason" => skip_reason,
    )
    .increment(1);
}

#[cfg(not(feature = "metrics"))]
fn metrics_resolve_ip_scope(
    _target_kind: &'static str,
    _zone_relation: &'static str,
    _info_policy: &'static str,
    _skip_reason: &'static str,
) {
}

#[cfg(feature = "metrics")]
fn metrics_resolve_ip_channel(channel: &'static str, outcome: &'static str, duration: Duration) {
    metrics::counter!(
        "name_client.resolve_ips.channel_total",
        "channel" => channel,
        "outcome" => outcome,
    )
    .increment(1);
    metrics::histogram!(
        "name_client.resolve_ips.channel_duration_seconds",
        "channel" => channel,
        "outcome" => outcome,
    )
    .record(duration.as_secs_f64());
}

#[cfg(not(feature = "metrics"))]
fn metrics_resolve_ip_channel(_channel: &'static str, _outcome: &'static str, _duration: Duration) {
}

/// Info 类文档(设备 Info 等)进程内缓存的默认 TTL。
pub const DEFAULT_DEVICE_INFO_CACHE_TTL_SECS: u64 = 3600 * 24 * 7;
/// 同 zone 私有 Info 信道的默认总 deadline。它只在调用方显式提供
/// `VerifiedSameZoneDevice` evidence 后生效;默认地址解析不会发起 Info 查询。
pub const DEFAULT_DEVICE_INFO_RESOLVE_TIMEOUT: Duration = Duration::from_secs(2);
/// 整次 resolve / verify 调用的默认有限预算(设计稿 §4 `config.resolve_timeout`)。
pub const DEFAULT_RESOLVE_TIMEOUT: Duration = Duration::from_secs(20);
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_CACHED_LOCAL_IPS: usize = 8;

#[derive(Clone)]
pub struct NameClientConfig {
    /// 是否使用普通结果缓存(磁盘 / 内存后端由 `cache_backend` 决定)。
    pub enable_cache: bool,
    pub local_cache_dir: Option<String>,
    pub cache_backend: CacheBackend,
    pub rtt_db_config: AddrRttDbConfig,
    /// Zone locker(zone-resolver-server,默认本机 `http://127.0.0.1:3180`)。
    /// 单元测试、离线工具应显式关闭,避免打到开发机上真实运行的 zone 服务。
    pub enable_zone_locker: bool,
    pub zone_locker: ZoneLockerConfig,
    /// 已验证 same-zone device 的 Info 查询总 deadline。
    pub device_info_timeout: Duration,
    /// 最外层调用的默认预算;调用方可用 `ResolveOpts::with_timeout / with_deadline` 收紧。
    pub resolve_timeout: Duration,
    pub connect_timeout: Duration,
    pub request_timeout: Duration,
    /// 并发、合并、退避与日志限流参数。
    pub concurrency: ConcurrencyConfig,
    /// 默认 scope(Zone 内进程可设为 `Scope::Zone(zone_did)`,启用 current-zone 自举来源)。
    pub default_scope: Option<Scope>,
}

impl Default for NameClientConfig {
    fn default() -> Self {
        Self {
            enable_cache: true,
            local_cache_dir: None,
            cache_backend: CacheBackend::Filesystem,
            rtt_db_config: AddrRttDbConfig::default(),
            enable_zone_locker: true,
            zone_locker: ZoneLockerConfig::default(),
            device_info_timeout: DEFAULT_DEVICE_INFO_RESOLVE_TIMEOUT,
            resolve_timeout: DEFAULT_RESOLVE_TIMEOUT,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            concurrency: ConcurrencyConfig::default(),
            default_scope: None,
        }
    }
}

impl NameClientConfig {
    /// 测试 / 离线工具配置:内存缓存、关闭 Zone locker。
    pub fn for_test() -> Self {
        Self {
            enable_cache: true,
            cache_backend: CacheBackend::Memory,
            enable_zone_locker: false,
            ..Default::default()
        }
    }
}

pub struct NameClient {
    pub(crate) name_query: NameQuery,
    pub(crate) config: NameClientConfig,
    pub(crate) store: Arc<DocStore>,
    pub(crate) registry: SourceRegistry,
    pub(crate) local_locker: Arc<LocalLocker>,
    pub(crate) zone_locker: StdRwLock<Option<Arc<ZoneLocker>>>,
    pub(crate) locks: DocLocks,
    pub(crate) merger: TaskMerger,
    pub(crate) backoff: Backoff,
    pub(crate) throttle: LogThrottle,
    pub(crate) info_cache: InfoCache,
    addr_rtt_db: Arc<RttDatabase>,
    _addr_rtt_auto_flush: Option<AutoFlushHandle>,
    cached_local_ips: StdRwLock<Vec<IpAddr>>,
    nameinfo_cache: Option<std::sync::Arc<RwLock<HashMap<String, NameInfo>>>>,
}

impl NameClient {
    pub fn new(config: NameClientConfig) -> Self {
        let name_query = NameQuery::new();
        let cache_dir = config.local_cache_dir.as_ref().map(PathBuf::from);
        let store = DocStore::new(config.cache_backend, cache_dir);

        let nameinfo_cache = match config.cache_backend {
            CacheBackend::Memory => Some(std::sync::Arc::new(RwLock::new(HashMap::new()))),
            _ => None,
        };

        let addr_rtt_db = Arc::new(Self::build_rtt_db(
            config.rtt_db_config.clone(),
            config.local_cache_dir.as_deref(),
        ));
        let addr_rtt_auto_flush = addr_rtt_db.spawn_auto_flush();

        let zone_locker = if config.enable_zone_locker {
            Some(Arc::new(ZoneLocker::new(config.zone_locker.clone())))
        } else {
            None
        };

        Self {
            name_query,
            store,
            registry: SourceRegistry::new(),
            local_locker: Arc::new(LocalLocker::new()),
            zone_locker: StdRwLock::new(zone_locker),
            locks: DocLocks::new(),
            merger: TaskMerger::new(config.concurrency.clone()),
            backoff: Backoff::new(config.concurrency.clone()),
            throttle: LogThrottle::new(config.concurrency.log_interval),
            info_cache: InfoCache::default(),
            config,
            addr_rtt_db,
            _addr_rtt_auto_flush: addr_rtt_auto_flush,
            cached_local_ips: StdRwLock::new(Vec::new()),
            nameinfo_cache,
        }
    }

    pub fn config(&self) -> &NameClientConfig {
        &self.config
    }

    // ---- Zone locker ----

    /// 关闭 Zone locker,退回本机 locker + 缓存 + provider 流程。
    pub fn disable_zone_locker(&self) {
        if let Ok(mut zone) = self.zone_locker.write() {
            *zone = None;
        }
    }

    pub fn set_zone_locker_endpoint(&self, endpoint: impl Into<String>) {
        let mut config = self.config.zone_locker.clone();
        config.endpoint = endpoint.into();
        self.set_zone_locker_config(config);
    }

    pub fn set_zone_locker_config(&self, config: ZoneLockerConfig) {
        if let Ok(mut zone) = self.zone_locker.write() {
            *zone = Some(Arc::new(ZoneLocker::new(config)));
        }
    }

    // ---- 本机 locker ----

    pub fn local_locker(&self) -> &Arc<LocalLocker> {
        &self.local_locker
    }

    /// 锁定一份文档(hosts 语义,模拟发布)。只应由本地管理员、测试框架或显式运维
    /// 命令调用;不进入普通来源缓存。
    pub fn lock_document(
        &self,
        did: DID,
        doc_type: DidDocType,
        document: EncodedDocument,
        options: LockOptions,
    ) {
        self.local_locker.lock_document(did, &doc_type, document, options);
    }

    pub fn unlock_document(&self, did: &DID, doc_type: DidDocType) {
        self.local_locker.unlock(did, &doc_type);
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

    // ---- 来源注册:显式 (method, tier, source) ----

    pub fn registry(&self) -> &SourceRegistry {
        &self.registry
    }

    /// 注册某 method 的 authority(一个 method 至多一个)。
    pub fn set_method_authority(&self, method: impl Into<String>, source: Arc<dyn Source>) {
        self.registry.set_method_authority(method, source);
    }

    /// 追加某 method 的 trust 来源(免 Owner 验签,参与 best)。
    pub fn add_method_trust(&self, method: impl Into<String>, source: Arc<dyn Source>) {
        self.registry.add_method_trust(method, source);
    }

    /// 追加某 method 的 normal 来源(只贡献候选)。
    pub fn add_method_normal(&self, method: impl Into<String>, source: Arc<dyn Source>) {
        self.registry.add_method_normal(method, source);
    }

    /// 只在 current-zone 自举(`opts.scope == Zone(did)` 且请求 DID 为该 Zone)时
    /// 可用的 normal 来源(DNS TXT 等)。
    pub fn add_zone_bootstrap_normal(&self, method: impl Into<String>, source: Arc<dyn Source>) {
        self.registry.add_zone_bootstrap_normal(method, source);
    }

    /// 显式注册项(可声明 `independent_control_plane` 等传输属性)。
    pub fn register_source(&self, method: impl Into<String>, registered: RegisteredSource) {
        self.registry.register(method, registered);
    }

    /// 覆盖某 method 的免验证 doc_type 契约(默认只有 `info`)。
    pub fn set_no_proof_doc_types(&self, method: &str, doc_types: HashSet<DidDocType>) {
        self.registry.set_no_proof_doc_types(method, doc_types);
    }

    /// 注册普通名字解析(DNS 语义)的 provider。
    pub async fn add_dns_provider(&self, provider: Box<dyn NsProvider>) {
        self.name_query.add_dns_provider(provider).await;
    }

    // ---- Info 缓存(免验证,Zone 内共享) ----

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
        let doc = EncodedDocument::JsonLd(serde_json::to_value(&device_info).map_err(|e| {
            NSError::Failed(format!("serialize device info cache failed: {}", e))
        })?);
        let seen_at = if device_info.update_time == 0 {
            buckyos_get_unix_timestamp()
        } else {
            device_info.update_time
        };
        let exp = seen_at.saturating_add(ttl_secs);
        self.info_cache.insert(&did, &DidDocType::Info, doc, exp);
        Ok(())
    }

    /// 删除普通文档缓存(不解锁、不抹负状态)。
    pub async fn invalidate_did_cache(&self, did: &DID, doc_type: &DidDocType) -> NSResult<()> {
        self.remove_doc_result(did, doc_type, self.default_resolve_opts())
            .await
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
                real_name = name_did.to_host_name();
            }
        }

        cache.write().await.insert(real_name, info);
        Ok(())
    }

    pub async fn resolve(&self, name: &str, record_type: Option<RecordType>) -> NSResult<NameInfo> {
        let mut real_name = name.to_string();
        if name.starts_with("did") {
            if let Ok(name_did) = DID::from_str(name) {
                real_name = name_did.to_host_name();
                info!("resolve {} as host: {}", name, real_name);
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
        self.resolve_ip_with_options(name, ResolveIpOptions::default())
            .await
    }

    pub async fn resolve_ip_with_options(
        &self,
        name: &str,
        options: ResolveIpOptions,
    ) -> NSResult<IpAddr> {
        self.resolve_ips_with_options(name, options)
            .await?
            .into_iter()
            .next()
            .ok_or_else(|| NSError::NotFound("A record not found".to_string()))
    }

    /// 无可信 zone 上下文的通用地址解析。默认 fail closed，不读取 DeviceInfo。
    pub async fn resolve_ips(&self, name: &str) -> NSResult<Vec<IpAddr>> {
        self.resolve_ips_with_options(name, ResolveIpOptions::default())
            .await
    }

    /// 按可信目标类型 / zone 关系解析地址。只有携带精确目标绑定 evidence 的
    /// `VerifiedSameZone` 策略才会读取 Info；该查询只允许 LocalAndZone 来源。
    pub async fn resolve_ips_with_options(
        &self,
        name: &str,
        options: ResolveIpOptions,
    ) -> NSResult<Vec<IpAddr>> {
        let info_decision = Self::device_info_decision(name, &options);
        let (info_policy, skip_reason, evidence_source) = match &info_decision {
            DeviceInfoDecision::Disabled(reason) => ("disabled", reason.as_str(), "none"),
            DeviceInfoDecision::Enabled(evidence) => {
                ("verified_same_zone", "none", evidence.source().as_str())
            }
        };
        info!(
            "resolve_ips_scope target={} target_kind={} zone_relation={} \
             info_policy={} info_skip_reason={} info_evidence={}",
            name,
            options.target_kind.as_str(),
            options.zone_relation.as_str(),
            info_policy,
            skip_reason,
            evidence_source,
        );
        metrics_resolve_ip_scope(
            options.target_kind.as_str(),
            options.zone_relation.as_str(),
            info_policy,
            skip_reason,
        );

        // Document 固定 IP 只是优先级最高的一条信道:它解析失败(权威渠道断网、
        // 网关返回损坏内容等)不能终结整个 resolve_ips,nameinfo / device-info
        // 仍可能给出可用地址。该错误只在所有信道都落空时作为兜底错误报出。
        let document_started = Instant::now();
        let device_document_error = match self.resolve_device_document_ips(name).await {
            Ok(Some(ips)) => {
                Self::log_resolve_ip_channel(
                    name,
                    "device_document",
                    "success",
                    document_started.elapsed(),
                    ips.len(),
                );
                if matches!(&info_decision, DeviceInfoDecision::Enabled(_)) {
                    debug!(
                        "resolve_ips_info target={} outcome=skipped skip_reason={}",
                        name,
                        DeviceInfoSkipReason::FixedDeviceDocumentAddress.as_str()
                    );
                    metrics_resolve_ip_channel("device_info", "skipped", Duration::ZERO);
                }
                return self.sort_resolved_ips(&ips);
            }
            Ok(None) => {
                Self::log_resolve_ip_channel(
                    name,
                    "device_document",
                    "empty",
                    document_started.elapsed(),
                    0,
                );
                None
            }
            Err(err) => {
                Self::log_resolve_ip_channel(
                    name,
                    "device_document",
                    "error",
                    document_started.elapsed(),
                    0,
                );
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

        let nameinfo_started = Instant::now();
        match self.resolve(name, None).await {
            Ok(name_info) => {
                let count = name_info.address.len();
                Self::merge_unique_ips(&mut merged_ips, &name_info.address);
                Self::log_resolve_ip_channel(
                    name,
                    "name_info",
                    if count == 0 { "empty" } else { "success" },
                    nameinfo_started.elapsed(),
                    count,
                );
            }
            Err(err) => {
                Self::log_resolve_ip_channel(
                    name,
                    "name_info",
                    "error",
                    nameinfo_started.elapsed(),
                    0,
                );
                first_error = Some(err);
            }
        }

        match info_decision {
            DeviceInfoDecision::Disabled(reason) => {
                debug!(
                    "resolve_ips_info target={} outcome=skipped skip_reason={}",
                    name,
                    reason.as_str()
                );
                metrics_resolve_ip_channel("device_info", "skipped", Duration::ZERO);
            }
            DeviceInfoDecision::Enabled(evidence) => {
                let info_started = Instant::now();
                let info_result = tokio::time::timeout(
                    self.config.device_info_timeout,
                    self.resolve_device_info_ips_from_private_sources(name),
                )
                .await;
                match info_result {
                    Ok(Ok(device_info_ips)) => {
                        let count = device_info_ips.len();
                        Self::merge_unique_ips(&mut merged_ips, &device_info_ips);
                        Self::log_resolve_ip_channel(
                            name,
                            "device_info",
                            "success",
                            info_started.elapsed(),
                            count,
                        );
                    }
                    Ok(Err(err)) => {
                        Self::log_resolve_ip_channel(
                            name,
                            "device_info",
                            "error",
                            info_started.elapsed(),
                            0,
                        );
                        debug!(
                            "resolve_ips_info target={} evidence={} outcome=error error={}",
                            name,
                            evidence.source().as_str(),
                            err
                        );
                        if first_error.is_none() {
                            first_error = Some(err);
                        }
                    }
                    Err(_) => {
                        Self::log_resolve_ip_channel(
                            name,
                            "device_info",
                            "timeout",
                            info_started.elapsed(),
                            0,
                        );
                        let err = NSError::Failed(format!(
                            "same-zone device info query exceeded {:?} deadline for {}",
                            self.config.device_info_timeout, name
                        ));
                        if first_error.is_none() {
                            first_error = Some(err);
                        }
                    }
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

    fn device_info_decision<'a>(
        name: &str,
        options: &'a ResolveIpOptions,
    ) -> DeviceInfoDecision<'a> {
        let DeviceInfoPolicy::VerifiedSameZone(evidence) = &options.device_info_policy else {
            return DeviceInfoDecision::Disabled(DeviceInfoSkipReason::PolicyDisabled);
        };
        if options.target_kind != ResolveIpTargetKind::Device {
            return DeviceInfoDecision::Disabled(DeviceInfoSkipReason::TargetNotDevice);
        }
        if options.zone_relation != ResolveIpZoneRelation::SameZone {
            return DeviceInfoDecision::Disabled(DeviceInfoSkipReason::ZoneNotSame);
        }
        let Ok(target_did) = DID::from_str(name) else {
            return DeviceInfoDecision::Disabled(DeviceInfoSkipReason::InvalidTargetDid);
        };
        if is_key_class_method(&target_did.method) {
            return DeviceInfoDecision::Disabled(DeviceInfoSkipReason::UnsupportedTargetMethod);
        }
        if target_did != *evidence.target_did() {
            return DeviceInfoDecision::Disabled(DeviceInfoSkipReason::EvidenceTargetMismatch);
        }
        DeviceInfoDecision::Enabled(evidence)
    }

    fn log_resolve_ip_channel(
        target: &str,
        channel: &'static str,
        outcome: &'static str,
        duration: Duration,
        candidate_count: usize,
    ) {
        debug!(
            "resolve_ips_channel target={} channel={} outcome={} elapsed_ms={} candidate_count={}",
            target,
            channel,
            outcome,
            duration.as_millis(),
            candidate_count,
        );
        metrics_resolve_ip_channel(channel, outcome, duration);
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

    async fn resolve_device_info_ips_from_private_sources(
        &self,
        name: &str,
    ) -> NSResult<Vec<IpAddr>> {
        let did = DID::from_str(name)?;
        // Info 只走 locker(本机 / Zone)与进程内 Info 缓存,不访问公网 provider。
        let result = self
            .resolve_did_ex(
                &did,
                Some(DidDocType::Info),
                Revision::current(),
                self.default_resolve_opts().not_allow_request(),
            )
            .await?;
        let doc = select_or_error(&result, &Revision::current())?;
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


    fn extract_exp(doc: &EncodedDocument) -> Option<u64> {
        doc.clone()
            .to_json_value()
            .ok()
            .and_then(|value| value.get("exp").and_then(|ts| ts.as_u64()))
    }

    fn zone_child_did(zone_did: &DID, device_name: &str) -> Option<DID> {
        name_lib::zone_child_did(zone_did, device_name).ok()
    }

    /// 解析指定 DID document 的默认 authentication Ed25519 公钥。
    ///
    /// 不识别 device/zone/app 等 document shape,也不接受调用方指定 kid:
    /// document id 必须精确匹配请求 DID,默认 key 必须是 Ed25519。
    pub async fn resolve_default_ed25519_key(
        &self,
        did: &DID,
        opts: ResolveOpts,
    ) -> NSResult<[u8; 32]> {
        let result = self
            .resolve_did_ex(did, None, Revision::current(), opts)
            .await?;
        let document = select_or_error(&result, &Revision::current())?;
        let document = parse_did_doc(document).map_err(|err| {
            NSError::InvalidParam(format!(
                "invalid DID document for {}: {err}",
                did.to_string()
            ))
        })?;
        if document.get_id() != *did {
            return Err(NSError::InvalidState(format!(
                "DID document id {} does not match requested {}",
                document.get_id().to_string(),
                did.to_string()
            )));
        }
        let (_, jwk) = document.get_auth_key(None).ok_or_else(|| {
            NSError::NotFound(format!(
                "default authentication Ed25519 key in {} (missing or invalid)",
                did.to_string()
            ))
        })?;
        jwk_to_ed25519_pk(&jwk)
    }
}
