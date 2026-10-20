#![allow(dead_code)]

mod addr_rtt_db;
mod bns_provider;
mod did_obj_client;
mod dns_provider;
mod https_provider;
mod identity_mgr;
mod local_ns_provider;
mod name_client;
mod name_query;
mod profile_resolver;
mod provider;
mod resolver;
mod utility;
mod web_provider;

pub use addr_rtt_db::*;
pub use bns_provider::*;
pub use did_obj_client::*;
pub use dns_provider::*;
pub use https_provider::*;
pub use identity_mgr::*;
use jsonwebtoken::DecodingKey;
pub use local_ns_provider::*;
pub use name_client::*;
pub use name_query::*;
pub use profile_resolver::*;
pub use provider::*;
pub use resolver::*;
pub use utility::*;
pub use web_provider::*;

use buckyos_kit::BuckyOSMachineConfig;
use log::*;
use name_lib::*;
use once_cell::sync::OnceCell;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

#[macro_use]
extern crate log;
//TODO 首次初始化的BOOT NAME CLIENT 可以为系统的名字解析提供一个保底
pub static GLOBAL_BOOT_NAME_CLIENT: OnceCell<NameClient> = OnceCell::new();
pub static GLOBAL_NAME_CLIENT: OnceCell<NameClient> = OnceCell::new();
pub static IS_NAME_LIB_INITED: OnceCell<bool> = OnceCell::new();
//串行化首次初始化，避免并发调用 init_name_lib_ex 时重复构建 NameClient
static NAME_LIB_INIT_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// 默认 web3 bridge 配置。键的含义:
/// - "bns":did:bns 名字的规范 host 映射根
///   (`did:bns:alice` ↔ `alice.{bns_root}`)。它与 BNS 权威 resolver 使用
///   的 `bns_host` 是两个独立配置。
/// - "sn":可选,SN 网关 host,配置后注册为两个 method 的 normal 来源。
pub fn get_default_web3_bridge_config() -> HashMap<String, String> {
    BuckyOSMachineConfig::default().web3_bridge
}

//name lib 是系统最基础的库，应尽量在进程启动时完成初始化
pub async fn init_name_lib(web3_bridge_config: &HashMap<String, String>) -> NSResult<()> {
    init_name_lib_ex(web3_bridge_config, NameClientConfig::default()).await
}

pub async fn init_name_lib_for_test(web3_bridge_config: &HashMap<String, String>) -> NSResult<()> {
    // 测试环境:内存缓存并关闭 Zone locker(开发机上可能真的跑着 127.0.0.1:3180)。
    init_name_lib_ex(web3_bridge_config, NameClientConfig::for_test()).await
}

pub async fn init_name_lib_ex(
    web3_bridge_config: &HashMap<String, String>,
    config: NameClientConfig,
) -> NSResult<()> {
    if IS_NAME_LIB_INITED.get().is_some() {
        return Ok(());
    }
    let _init_guard = NAME_LIB_INIT_LOCK.lock().await;
    if IS_NAME_LIB_INITED.get().is_some() {
        return Ok(());
    }
    if GLOBAL_NAME_CLIENT.get().is_some() {
        let _ = IS_NAME_LIB_INITED.set(true);
        return Ok(());
    }

    let set_result = KNOWN_WEB3_BRIDGE_CONFIG.set(web3_bridge_config.clone());
    if set_result.is_err() && KNOWN_WEB3_BRIDGE_CONFIG.get().is_none() {
        return Err(NSError::Failed(
            "Failed to set KNOWN_WEB3_BRIDGE_CONFIG".to_string(),
        ));
    }

    let client = NameClient::new(config);
    register_default_sources(&client, web3_bridge_config)?;
    client
        .add_dns_provider(Box::new(DnsProvider::new(None)))
        .await;

    if GLOBAL_NAME_CLIENT.set(client).is_err() && GLOBAL_NAME_CLIENT.get().is_none() {
        return Err(NSError::Failed(
            "Failed to set GLOBAL_NAME_CLIENT".to_string(),
        ));
    }
    let _ = IS_NAME_LIB_INITED.set(true);
    Ok(())
}

/// 默认来源注册(设计稿 §2.1 三档来源):每个 method 至多一个 authority,
/// 其后是 trust / normal。
///
/// - did:bns —— authority:BNS 智能合约,`BnsProvider` 是它的委托读取端;
///   normal:`WebProvider`(名字的规范 host 映射 `alice.{bns_root}` 上的静态发布面
///   与上级 resolver);zone-bootstrap normal:`DnsProvider`(TXT,只在 current-zone
///   自举时可用)。
/// - did:web —— authority:`WebProvider`(域名 HTTPS 站点的静态发布面 + 上级 resolver);
///   zone-bootstrap normal:`DnsProvider`。
/// - "sn" 网关(web3 bridge 配置)注册为两个 method 的末位 normal 来源。
/// - did:dev / did:key 不注册任何来源:key 类 DID 不是解析入口。
pub fn register_default_sources(
    client: &NameClient,
    web3_bridge_config: &HashMap<String, String>,
) -> NSResult<()> {
    let bns_provider: Arc<dyn Source> = Arc::new(BnsProvider::new()?);
    client.set_method_authority("bns", bns_provider);
    client.add_method_normal("bns", Arc::new(WebProvider::new()));
    client.add_zone_bootstrap_normal("bns", Arc::new(DnsProvider::new(None)));

    client.set_method_authority("web", Arc::new(WebProvider::new()));
    client.add_zone_bootstrap_normal("web", Arc::new(DnsProvider::new(None)));

    if let Some(sn_host) = web3_bridge_config.get("sn") {
        let sn: Arc<dyn Source> = Arc::new(BaseHttpProvider::new(sn_host).with_id("sn-resolver"));
        client.add_method_normal("web", sn.clone());
        client.add_method_normal("bns", sn);
    }
    Ok(())
}

pub async fn resolve_ip(name: &str) -> NSResult<IpAddr> {
    let client = get_name_client().ok_or_else(|| NSError::NotFound("Name client not init yet".to_string()))?;
    client.resolve_ip(name).await
}

pub async fn resolve_ip_with_options(name: &str, options: ResolveIpOptions) -> NSResult<IpAddr> {
    let client = get_name_client().ok_or_else(|| NSError::NotFound("Name client not init yet".to_string()))?;
    client.resolve_ip_with_options(name, options).await
}

pub async fn resolve_ips(name: &str) -> NSResult<Vec<IpAddr>> {
    let client = get_name_client().ok_or_else(|| NSError::NotFound("Name client not init yet".to_string()))?;
    client.resolve_ips(name).await
}

pub async fn resolve_ips_with_options(
    name: &str,
    options: ResolveIpOptions,
) -> NSResult<Vec<IpAddr>> {
    let client = get_name_client().ok_or_else(|| NSError::NotFound("Name client not init yet".to_string()))?;
    client.resolve_ips_with_options(name, options).await
}

pub fn get_name_client() -> Option<&'static NameClient> {
    GLOBAL_NAME_CLIENT.get()
}

pub async fn resolve(name: &str, record_type: Option<RecordType>) -> NSResult<NameInfo> {
    let client = get_name_client().ok_or_else(|| NSError::NotFound("Name client not init yet".to_string()))?;
    client.resolve(name, record_type).await
}

pub async fn resolve_with_local_ip(
    name: &str,
    record_type: Option<RecordType>,
    local_ip: IpAddr,
    port: u16,
    policy: Option<&SortPolicy>,
) -> NSResult<NameInfo> {
    let client = get_name_client().ok_or_else(|| NSError::NotFound("Name client not init yet".to_string()))?;
    client
        .resolve_with_local_ip(name, record_type, local_ip, port, policy)
        .await
}

pub fn rank_socket_addrs(
    local_ip: IpAddr,
    addresses: &[SocketAddr],
    policy: Option<&SortPolicy>,
) -> NSResult<Vec<RankedAddress>> {
    let client = get_name_client().ok_or_else(|| NSError::NotFound("Name client not init yet".to_string()))?;
    Ok(client.rank_socket_addrs(local_ip, addresses, policy))
}

pub fn record_connection_outcome(
    local_ip: IpAddr,
    remote: SocketAddr,
    outcome: ConnectionOutcome,
) -> NSResult<()> {
    let client = get_name_client().ok_or_else(|| NSError::NotFound("Name client not init yet".to_string()))?;
    client.record_connection_outcome(local_ip, remote, outcome)
}

/// 解析这个 DID **自己**的 auth key。
///
/// 注意:它不能用于 DID Document JWT 的 owner binding 验证——不要用
/// `payload.owner` / `payload.iss` 调本函数来验一份外部 DID Document JWT,
/// 那只能证明"JWT 能被它自己声明的 owner 验过"。权限主体认证场景必须使用
/// `verify_document`。
pub async fn resolve_auth_key(did: &DID, kid: Option<&str>) -> NSResult<DecodingKey> {
    if let Some(ed25519_auth_key) = did.get_ed25519_auth_key() {
        return ed25519_to_decoding_key(&ed25519_auth_key);
    }
    let client = get_name_client().ok_or_else(|| {
        let msg = "Name client not init yet".to_string();
        error!("{}", msg);
        NSError::InvalidState(msg)
    })?;
    let did_doc = client.resolve_did(did, None).await?;
    let did_doc = parse_did_doc(did_doc)?;
    match did_doc.get_auth_key(kid) {
        Some((key, _)) => Ok(key),
        None => Err(NSError::NotFound("Invalid kid".to_string())),
    }
}

/// 日常解析:普通文档选择 best,owner 选择 latest。
pub async fn resolve_did(did: &DID, doc_type: Option<DidDocType>) -> NSResult<EncodedDocument> {
    let client = get_name_client().ok_or_else(|| NSError::NotFound("Name client not found".to_string()))?;
    client.resolve_did(did, doc_type).await
}

/// 精确版本或严格早于指定时间的最近已发布版本。
pub async fn resolve_did_revision(
    did: &DID,
    doc_type: Option<DidDocType>,
    revision: Revision,
) -> NSResult<EncodedDocument> {
    let client = get_name_client().ok_or_else(|| NSError::NotFound("Name client not found".to_string()))?;
    client.resolve_did_revision(did, doc_type, revision).await
}

/// 获取完整结果及原因,控制来源、传输、缓存、locker 和预算。
pub async fn resolve_did_ex(
    did: &DID,
    doc_type: Option<DidDocType>,
    revision: Revision,
    opts: ResolveOpts,
) -> NSResult<DocResult> {
    let client = get_name_client().ok_or_else(|| NSError::NotFound("Name client not found".to_string()))?;
    client.resolve_did_ex(did, doc_type, revision, opts).await
}

/// 始终验证收到的确切文档;允许按 opts 补材料并更新解析缓存。
/// 入站握手等攻击者可触发的路径必须传 `ResolveOpts::not_allow_request()`。
pub async fn verify_document(
    did: &DID,
    doc_type: Option<DidDocType>,
    body: &EncodedDocument,
    revision: Revision,
    opts: ResolveOpts,
) -> NSResult<VerifyResult> {
    let client = get_name_client().ok_or_else(|| NSError::NotFound("Name client not found".to_string()))?;
    client.verify_document(did, doc_type, body, revision, opts).await
}

pub async fn resolve_owner_document(did: &DID) -> NSResult<OwnerDocument> {
    let client = get_name_client().ok_or_else(|| NSError::NotFound("Name client not found".to_string()))?;
    client.resolve_owner_document(did).await
}

pub async fn resolve_user_profile(
    did: &DID,
    opts: ProfileResolveOptions,
) -> NSResult<MergedProfile> {
    let client = get_name_client().ok_or_else(|| NSError::NotFound("Name client not found".to_string()))?;
    client.resolve_user_profile(did, opts).await
}

pub async fn owner_is_bound_to_zone(did: &DID, zone_did: &DID) -> NSResult<bool> {
    let client = get_name_client().ok_or_else(|| NSError::NotFound("Name client not found".to_string()))?;
    client.owner_is_bound_to_zone(did, zone_did).await
}

/// 收件箱路径:投递一份候选文档(UDP 发现 / gossip / push……拿到的文档)。
/// 它只是候选,按 normal 来源进入验证;不等于发布或成功选择。
pub async fn commit_candidate_doc(
    did: &DID,
    doc_type: Option<DidDocType>,
    doc: &EncodedDocument,
    source: SourceRef,
) -> NSResult<()> {
    let client = get_name_client().ok_or_else(|| NSError::NotFound("Name client not found".to_string()))?;
    client
        .commit_candidate_doc(did, doc_type, doc, source, client.default_resolve_opts())
        .await
}

/// 删除普通文档 body;不解锁、不抹掉已知禁用 / 撤销。
pub async fn remove_doc_result(did: &DID, doc_type: &DidDocType) -> NSResult<()> {
    let client = get_name_client().ok_or_else(|| NSError::NotFound("Name client not found".to_string()))?;
    client
        .remove_doc_result(did, doc_type, client.default_resolve_opts())
        .await
}

pub async fn add_device_info_cache(did: DID, device_info: DeviceInfo) -> NSResult<()> {
    let client = get_name_client().ok_or_else(|| NSError::NotFound("Name client not found".to_string()))?;
    client.add_device_info_cache(did, device_info)
}

pub async fn add_device_info_cache_with_ttl(
    did: DID,
    device_info: DeviceInfo,
    ttl_secs: u64,
) -> NSResult<()> {
    let client = get_name_client().ok_or_else(|| NSError::NotFound("Name client not found".to_string()))?;
    client.add_device_info_cache_with_ttl(did, device_info, ttl_secs)
}

pub async fn add_nameinfo_cache(hostname: &str, info: NameInfo) -> NSResult<()> {
    let client = get_name_client().ok_or_else(|| NSError::NotFound("Name client not found".to_string()))?;
    client.add_nameinfo_cache(hostname, info).await
}
