#![allow(dead_code)]

mod addr_rtt_db;
mod bns_provider;
mod did_obj_client;
mod dns_provider;
mod doc_cache;
mod https_provider;
mod identity_mgr;
mod local_ns_provider;
mod name_client;
mod name_query;
mod profile_resolver;
mod provider;
mod utility;
mod verify;
mod verify_context;
mod web_provider;
mod zone_resolver;

pub use addr_rtt_db::*;
pub use bns_provider::*;
pub use did_obj_client::*;
pub use dns_provider::*;
pub use doc_cache::*;
pub use https_provider::*;
pub use identity_mgr::*;
use jsonwebtoken::DecodingKey;
pub use local_ns_provider::*;
pub use name_client::*;
pub use name_query::*;
pub use profile_resolver::*;
pub use provider::*;
pub use utility::*;
pub use verify::*;
pub use verify_context::*;
pub use web_provider::*;
pub use zone_resolver::*;

use buckyos_kit::BuckyOSMachineConfig;
use log::*;
use name_lib::*;
use once_cell::sync::OnceCell;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

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
/// - "sn":可选,SN 网关 host,配置后注册 sn_resolver 补充源(第 4 节)。
pub fn get_default_web3_bridge_config() -> HashMap<String, String> {
    BuckyOSMachineConfig::default().web3_bridge
}

//name lib 是系统最基础的库，应尽量在进程启动时完成初始化
pub async fn init_name_lib(web3_bridge_config: &HashMap<String, String>) -> NSResult<()> {
    init_name_lib_ex(web3_bridge_config, NameClientConfig::default()).await
}

pub async fn init_name_lib_for_test(web3_bridge_config: &HashMap<String, String>) -> NSResult<()> {
    let mut config = NameClientConfig::default();
    config.cache_backend = CacheBackend::Memory;
    // 测试环境关闭 Zone Resolver cache:开发机上可能真的跑着 127.0.0.1:3180
    // 服务,默认启用会让测试命中它。
    config.enable_zone_resolver = false;
    init_name_lib_ex(web3_bridge_config, config).await
}

pub async fn init_name_lib_ex(
    web3_bridge_config: &HashMap<String, String>,
    config: NameClientConfig,
) -> NSResult<()> {
    //init web3 bridge config
    if IS_NAME_LIB_INITED.get().is_some() {
        return Ok(());
    }
    let _init_guard = NAME_LIB_INIT_LOCK.lock().await;
    //拿到锁后重新检查：可能已被先拿到锁的调用者（或直接设置 statics 的测试代码）初始化
    if IS_NAME_LIB_INITED.get().is_some() {
        return Ok(());
    }
    if GLOBAL_NAME_CLIENT.get().is_some() {
        let _ = IS_NAME_LIB_INITED.set(true);
        return Ok(());
    }

    let set_result = KNOWN_WEB3_BRIDGE_CONFIG.set(web3_bridge_config.clone());
    if set_result.is_err() {
        if KNOWN_WEB3_BRIDGE_CONFIG.get().is_none() {
            return Err(NSError::Failed(
                "Failed to set KNOWN_WEB3_BRIDGE_CONFIG".to_string(),
            ));
        }
    }

    let client = NameClient::new(config);
    // 注册模型与顺序见 doc/已有did-resolver介绍.md 第 7 节:每个 method
    // 第一个总是权威源,补充源按注册顺序即优先级(first-win)。

    // did:bns —— 权威渠道:BNS 智能合约,bns_resolver 是它的委托读取端
    // (web3 bridge 的 BNS 网关)。补充源:web_resolver(名字的规范 host 映射
    // alice.{bns_root} 上的 well-known / uppername 双信道)→ dns_resolver
    // (同一映射 host 上的 TXT 记录,need_proof 候选)。DNS TXT 只用于
    // current-zone boot:普通 resolve 默认跳过,调用方须通过
    // ResolvePolicy::with_current_zone 显式给出相同的 zone DID。
    let bns_provider = BnsProvider::new()?;
    client
        .set_method_authority("bns", Box::new(bns_provider))
        .await;
    client
        .add_method_supplement("bns", Box::new(WebProvider::new()))
        .await;
    client
        .add_current_zone_bootstrap_supplement("bns", Box::new(DnsProvider::new(None)))
        .await;

    // did:web —— 权威发布面就是该域名 HTTPS 站点的固定路径,web_resolver 是
    // 这个 canonical endpoint 的读取端(先查 W3C well-known 静态 URL,未命中
    // 再回退 uppername 的 resolver 接口,见 web_provider.rs)。dns_resolver
    // 降为补充源:DNS 信道本身没有认证能力,它取回的一切都只是 need_proof
    // 候选("英雄不问出处,但要验证",介绍文档第 3 节),并同样只在
    // current-zone bootstrap policy 下启用。
    client
        .set_method_authority("web", Box::new(WebProvider::new()))
        .await;
    client
        .add_current_zone_bootstrap_supplement("web", Box::new(DnsProvider::new(None)))
        .await;

    // sn_resolver(介绍文档第 4 节)—— 补充源,走 resolver 接口,支持跨 NAT
    // 组网阶段取回 DeviceDocument / DeviceInfo。web3 bridge 配置里声明了
    // "sn" 网关时注册为两个 method 的末位补充源;默认配置不含 sn,即默认不注册。
    if let Some(sn_host) = web3_bridge_config.get("sn") {
        client
            .add_method_supplement("web", Box::new(BaseHttpProvider::new(sn_host)))
            .await;
        client
            .add_method_supplement("bns", Box::new(BaseHttpProvider::new(sn_host)))
            .await;
    }

    // zone_resolver(介绍文档第 5 节)不是 provider,不在这里注册:它是
    // cluster-level cache,`NameClientConfig::enable_zone_resolver` 默认启用,
    // 默认指向本机 `http://127.0.0.1:3180`(zone_resolver.rs)。

    // 普通名字解析(resolve / resolve_ip)与 DID 管线独立注册。
    client
        .add_dns_provider(Box::new(DnsProvider::new(None)))
        .await;
    // did:dev / did:key 不注册任何 provider:key 类 DID 不是解析入口(简化文档第 6 节)。
    let set_result = GLOBAL_NAME_CLIENT.set(client);
    if set_result.is_err() {
        if GLOBAL_NAME_CLIENT.get().is_none() {
            return Err(NSError::Failed(
                "Failed to set GLOBAL_BOOT_NAME_CLIENT".to_string(),
            ));
        }
    }
    //set 失败说明已被其他路径置位，全局状态有效，与 GLOBAL_NAME_CLIENT.set 一样容忍
    let _ = IS_NAME_LIB_INITED.set(true);
    Ok(())
}

pub async fn resolve_ip(name: &str) -> NSResult<IpAddr> {
    let client = get_name_client();
    if client.is_none() {
        return Err(NSError::NotFound("Name client not init yet".to_string()));
    }
    let client = client.unwrap();
    client.resolve_ip(name).await
}

pub async fn resolve_ips(name: &str) -> NSResult<Vec<IpAddr>> {
    let client = get_name_client();
    if client.is_none() {
        return Err(NSError::NotFound("Name client not init yet".to_string()));
    }
    let client = client.unwrap();
    client.resolve_ips(name).await
}

pub fn get_name_client() -> Option<&'static NameClient> {
    let client = GLOBAL_NAME_CLIENT.get();
    return client;
}

pub async fn resolve(name: &str, record_type: Option<RecordType>) -> NSResult<NameInfo> {
    let client = get_name_client();
    if client.is_none() {
        return Err(NSError::NotFound("Name client not init yet".to_string()));
    }
    let client = client.unwrap();
    client.resolve(name, record_type).await
}

pub async fn resolve_with_local_ip(
    name: &str,
    record_type: Option<RecordType>,
    local_ip: IpAddr,
    port: u16,
    policy: Option<&SortPolicy>,
) -> NSResult<NameInfo> {
    let client = get_name_client();
    if client.is_none() {
        return Err(NSError::NotFound("Name client not init yet".to_string()));
    }
    let client = client.unwrap();
    client
        .resolve_with_local_ip(name, record_type, local_ip, port, policy)
        .await
}

pub fn rank_socket_addrs(
    local_ip: IpAddr,
    addresses: &[SocketAddr],
    policy: Option<&SortPolicy>,
) -> NSResult<Vec<RankedAddress>> {
    let client = get_name_client();
    if client.is_none() {
        return Err(NSError::NotFound("Name client not init yet".to_string()));
    }
    let client = client.unwrap();
    Ok(client.rank_socket_addrs(local_ip, addresses, policy))
}

pub fn record_connection_outcome(
    local_ip: IpAddr,
    remote: SocketAddr,
    outcome: ConnectionOutcome,
) -> NSResult<()> {
    let client = get_name_client();
    if client.is_none() {
        return Err(NSError::NotFound("Name client not init yet".to_string()));
    }
    let client = client.unwrap();
    client.record_connection_outcome(local_ip, remote, outcome)
}

/// 解析这个 DID **自己**的 auth key。
///
/// 注意:它不能用于 DID Document JWT 的 owner binding 验证——不要用
/// `payload.owner` / `payload.iss` 调本函数来验一份外部 DID Document JWT,
/// 那只能证明"JWT 能被它自己声明的 owner 验过"。权限主体认证场景必须使用
/// verify 家族(`resolve_and_verify_did_document_jwt`,doc/verify-did-document-jwt.md)。
pub async fn resolve_auth_key(did: &DID, kid: Option<&str>) -> NSResult<DecodingKey> {
    let ed25519_auth_key = did.get_ed25519_auth_key();
    if ed25519_auth_key.is_some() {
        let auth_key = ed25519_to_decoding_key(&ed25519_auth_key.unwrap())?;
        return Ok(auth_key);
    }

    let client = get_name_client();
    if client.is_none() {
        let msg = "Name client not init yet".to_string();
        error!("{}", msg);
        return Err(NSError::InvalidState(msg));
    }
    let did_doc = client.unwrap().resolve_did(did, None).await?;
    let did_doc = parse_did_doc(did_doc)?;
    let auth_key = did_doc.get_auth_key(kid);
    if auth_key.is_some() {
        let auth_key = auth_key.unwrap();
        return Ok(auth_key.0);
    }
    return Err(NSError::NotFound("Invalid kid".to_string()));
}

pub async fn resolve_did(did: &DID, doc_type: Option<DidDocType>) -> NSResult<EncodedDocument> {
    let client = get_name_client();
    if client.is_none() {
        return Err(NSError::NotFound("Name client not found".to_string()));
    }
    let client = client.unwrap();
    client.resolve_did(did, doc_type).await
}

pub async fn resolve_did_ex(
    did: &DID,
    doc_type: Option<DidDocType>,
    policy: ResolvePolicy,
) -> NSResult<ResolvedDocument> {
    let client = get_name_client();
    if client.is_none() {
        return Err(NSError::NotFound("Name client not found".to_string()));
    }
    let client = client.unwrap();
    client.resolve_did_ex(did, doc_type, policy).await
}

/// 组合便捷 API:resolve(按 `options.policy` 的来源范围)+ 纯 verify 一份
/// 外部传入的 DID Document JWT(doc/verify-did-document-jwt.md)。**不写 cache**。
/// 权限主体认证场景必须用 verify 家族,不要用 `payload.owner`/`payload.iss` 调
/// `resolve_auth_key` 验 DID Document JWT——那只能证明"JWT 能被它自己声明的
/// owner 验过"。
pub async fn resolve_and_verify_did_document_jwt(
    did: &DID,
    doc_type: DidDocType,
    jwt: &str,
    options: &ResolveVerifyOptions,
) -> std::result::Result<VerifiedDidDocument, ResolveVerifyError> {
    let client = get_name_client().ok_or_else(|| {
        ResolveVerifyError::Resolve(NSError::NotFound("Name client not found".to_string()))
    })?;
    client
        .resolve_and_verify_did_document_jwt(did, doc_type, jwt, options)
        .await
}

/// `resolve_and_verify_did_document_jwt` 的 DeviceDocument typed wrapper
/// (RTCP 迁移入口)。
pub async fn resolve_and_verify_device_document_jwt(
    did: &DID,
    jwt: &str,
    options: &ResolveVerifyOptions,
) -> std::result::Result<(DeviceDocument, VerifiedDidDocument), ResolveVerifyError> {
    let client = get_name_client().ok_or_else(|| {
        ResolveVerifyError::Resolve(NSError::NotFound("Name client not found".to_string()))
    })?;
    client
        .resolve_and_verify_device_document_jwt(did, jwt, options)
        .await
}

/// 组合便捷 API:resolve + verify + 显式写 verified cache
/// (`resolve_verify_and_cache_did_document` 的全局包装)。
pub async fn resolve_verify_and_cache_did_document(
    did: &DID,
    doc_type: DidDocType,
    candidate: &EncodedDocument,
    options: &ResolveVerifyOptions,
) -> std::result::Result<(VerifiedDidDocument, CacheWriteOutcome), ResolveVerifyError> {
    let client = get_name_client().ok_or_else(|| {
        ResolveVerifyError::Resolve(NSError::NotFound("Name client not found".to_string()))
    })?;
    client
        .resolve_verify_and_cache_did_document(did, doc_type, candidate, options)
        .await
}

pub async fn resolve_owner_document(did: &DID) -> NSResult<OwnerDocument> {
    let client = get_name_client();
    if client.is_none() {
        return Err(NSError::NotFound("Name client not found".to_string()));
    }
    client.unwrap().resolve_owner_document(did).await
}

pub async fn resolve_user_profile(
    did: &DID,
    opts: ProfileResolveOptions,
) -> NSResult<MergedProfile> {
    let client = get_name_client();
    if client.is_none() {
        return Err(NSError::NotFound("Name client not found".to_string()));
    }
    client.unwrap().resolve_user_profile(did, opts).await
}

pub async fn owner_is_bound_to_zone(did: &DID, zone_did: &DID) -> NSResult<bool> {
    let client = get_name_client();
    if client.is_none() {
        return Err(NSError::NotFound("Name client not found".to_string()));
    }
    client.unwrap().owner_is_bound_to_zone(did, zone_did).await
}

/// add_cache 动词的 Observed 入口(doc/update-did-cache.md):旁路的
/// **未验证**缓存写入(`CacheEvidence::Unverified`,落 `unverified/` 目录),
/// 不能提升文档信任等级。它是文件系统旁路协议的进程内薄封装——任何人往
/// `unverified/` 目录里放约定格式的文件,效果与调用本函数完全等价。
/// 快速操作:本地解析 + id 一致性检查,**不**触发联网 resolve;深度验证留给
/// resolve 时的 lazy verify(`verify_and_promote`)。
///
/// `source` 描述观察链路(UDP 发现 / gossip / push……),仅诊断用。应用层完成
/// 验证与最终接受后要保存"已验证文档",用组合 API
/// `resolve_verify_and_cache_did_document`(或受控进程内的 `add_verified_cache`),
/// 不要再经过 Observed 旁路。
pub fn add_observed_cache(
    did: DID,
    doc_type: Option<DidDocType>,
    doc: EncodedDocument,
    source: Option<UpdateSource>,
) -> NSResult<CacheWriteOutcome> {
    let client = get_name_client();
    if client.is_none() {
        return Err(NSError::NotFound("Name client not found".to_string()));
    }
    let client = client.unwrap();
    client.add_observed_cache(did, doc_type, doc, source)
}

pub async fn add_device_info_cache(did: DID, device_info: DeviceInfo) -> NSResult<()> {
    let client = get_name_client();
    if client.is_none() {
        return Err(NSError::NotFound("Name client not found".to_string()));
    }
    let client = client.unwrap();
    client.add_device_info_cache(did, device_info)
}

pub async fn add_device_info_cache_with_ttl(
    did: DID,
    device_info: DeviceInfo,
    ttl_secs: u64,
) -> NSResult<()> {
    let client = get_name_client();
    if client.is_none() {
        return Err(NSError::NotFound("Name client not found".to_string()));
    }
    let client = client.unwrap();
    client.add_device_info_cache_with_ttl(did, device_info, ttl_secs)
}

pub async fn add_nameinfo_cache(hostname: &str, info: NameInfo) -> NSResult<()> {
    let client = get_name_client();
    if client.is_none() {
        return Err(NSError::NotFound("Name client not found".to_string()));
    }
    let client = client.unwrap();
    client.add_nameinfo_cache(hostname, info).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use buckyos_kit::buckyos_get_unix_timestamp;
    use name_lib::NSError;
    use tempfile::tempdir;

    struct MockProvider {
        name: String,
        doc: EncodedDocument,
    }

    #[async_trait]
    impl NsProvider for MockProvider {
        fn get_id(&self) -> String {
            "mock".to_string()
        }

        async fn query(
            &self,
            name: &str,
            _record_type: Option<RecordType>,
            _from_ip: Option<std::net::IpAddr>,
        ) -> NSResult<NameInfo> {
            if name == self.name {
                Ok(NameInfo::new(name))
            } else {
                Err(NSError::NotFound("mock notfound".into()))
            }
        }

        async fn query_did(
            &self,
            did: &DID,
            _doc_type: Option<DidDocType>,
            _from_ip: Option<std::net::IpAddr>,
        ) -> NSResult<EncodedDocument> {
            if did.to_string() == self.name {
                Ok(self.doc.clone())
            } else {
                Err(NSError::NotFound("mock notfound".into()))
            }
        }
    }

    #[tokio::test]
    async fn test_add_observed_cache_is_observed_not_trusted() {
        // doc/update-did-cache.md 核心原则:系统收到过 != 系统信任它。
        // add_observed_cache 只产生 Observed 事件;strict 的 resolve_did 不能把
        // 未通过验证的旁路文档当成解析结果返回。
        let did = DID::from_str("did:web:example.com").unwrap();
        let doc = EncodedDocument::JsonLd(serde_json::json!({
            "exp": buckyos_get_unix_timestamp() + 600,
            "marker": "mock-doc"
        }));

        if GLOBAL_NAME_CLIENT.get().is_none() {
            let tmp = tempdir().unwrap().keep();
            let client = NameClient::new(NameClientConfig {
                enable_cache: true,
                local_cache_dir: Some(tmp.to_string_lossy().to_string()),
                cache_backend: CacheBackend::Filesystem,
                enable_zone_resolver: false,
                ..Default::default()
            });
            client
                .add_provider(
                    Box::new(MockProvider {
                        name: did.to_string(),
                        doc: doc.clone(),
                    }),
                    Some(DEFAULT_PROVIDER_TRUST_LEVEL),
                )
                .await;
            let _ = GLOBAL_NAME_CLIENT.set(client);
            let _ = IS_NAME_LIB_INITED.set(true);
        }

        add_observed_cache(did.clone(), None, doc.clone(), Some(UpdateSource::Push)).unwrap();
        // 观察缓存里可见(Unverified)。
        let client = GLOBAL_NAME_CLIENT.get().unwrap();
        assert!(client.doc_cache.get(&did, None).is_some());

        // strict resolve:lazy verify 无法把这份无签名 JsonLd 变成可信文档,
        // 视为 cache miss 继续主循环;没有权威渠道兜底时解析失败,而不是把
        // 未验证内容返回给调用方。
        let result = resolve_did(&did, None).await;
        assert!(result.is_err(), "unverified push must not resolve: {:?}", result);
    }
}
