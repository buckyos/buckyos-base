#![allow(dead_code)]

mod local_ns_provider;
mod dns_provider;
mod doc_cache;
mod bns_provider;
mod https_provider;
mod name_client;
mod name_query;
mod provider;
mod utility;

pub use local_ns_provider::*;
pub use dns_provider::*;
pub use doc_cache::*;
pub use bns_provider::*;
pub use https_provider::*;
use jsonwebtoken::DecodingKey;
pub use name_client::*;
pub use name_query::*;
pub use provider::*;
pub use utility::*;

use cfg_if::cfg_if;
cfg_if! {
    if #[cfg(feature = "cloudflare")] {
        mod cloudflare;
        pub use cloudflare::*;
    }
}

use log::*;
use name_lib::*;
use once_cell::sync::OnceCell;
use std::collections::HashMap;
use std::net::IpAddr;

#[macro_use]
extern crate log;
//TODO 首次初始化的BOOT NAME CLIENT 可以为系统的名字解析提供一个保底
pub static GLOBAL_BOOT_NAME_CLIENT: OnceCell<NameClient> = OnceCell::new();
pub static GLOBAL_NAME_CLIENT: OnceCell<NameClient> = OnceCell::new();
pub static IS_NAME_LIB_INITED: OnceCell<bool> = OnceCell::new();

pub fn get_default_web3_bridge_config() -> HashMap<String, String> {
    let mut web3_bridge_config = HashMap::new();
    web3_bridge_config.insert("bns".to_string(), "web3.buckyos.ai".to_string());
    web3_bridge_config
}

//name lib 是系统最基础的库，应尽量在进程启动时完成初始化
pub async fn init_name_lib(web3_bridge_config: &HashMap<String, String>) -> NSResult<()> {
    init_name_lib_ex(web3_bridge_config, NameClientConfig::default()).await
}

pub async fn init_name_lib_for_test(web3_bridge_config: &HashMap<String, String>) -> NSResult<()> {
    let mut config = NameClientConfig::default();
    config.cache_backend = CacheBackend::Memory;
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
    let bns_provider = BnsProvider::new()?;
    client
        .add_provider(Box::new(bns_provider), Some(ROOT_TRUST_LEVEL))
        .await;
    client.add_provider(Box::new(DnsProvider::new(None)), Some(DNS_TRUST_LEVEL)).await;
    //基于当前zone创建https provider?
    client.add_provider(Box::new(SmartProvider::new()), Some(DEFAULT_PROVIDER_TRUST_LEVEL)).await;
    let set_result = GLOBAL_NAME_CLIENT.set(client);
    if set_result.is_err() {
        if GLOBAL_NAME_CLIENT.get().is_none() {
            return Err(NSError::Failed(
                "Failed to set GLOBAL_BOOT_NAME_CLIENT".to_string(),
            ));
        }
    }
    let set_result = IS_NAME_LIB_INITED.set(true);
    if set_result.is_err() {
        panic!("Failed to set IS_NAME_LIB_INITED");
    }
    Ok(())
}

pub async fn resolve_ip(name: &str) -> NSResult<IpAddr> {
    let name_info = resolve(name, None).await?;
    if name_info.address.is_empty() {
        return Err(NSError::NotFound("A record not found".to_string()));
    }
    let result_ip = name_info.address[0];
    Ok(result_ip)
}

fn get_name_client() -> Option<&'static NameClient> {
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

pub async fn resolve_ed25519_exchange_key(remote_did: &DID) -> NSResult<[u8; 32]> {
    //return #auth-key
    if let Some(auth_key) = remote_did.get_ed25519_auth_key() {
        return Ok(auth_key);
    }

    let client = get_name_client();
    if client.is_none() {
        let msg = "Name client not init yet".to_string();
        error!("{}", msg);
        return Err(NSError::InvalidState(msg));
    }
    let client = client.unwrap();
    let did_doc = client.resolve_did(remote_did, None).await?;
    let did_doc = parse_did_doc(did_doc)?;
    let exchange_key = did_doc.get_exchange_key(None);
    if exchange_key.is_some() {
        let exchange_key = exchange_key.unwrap();
        let exchange_key = jwk_to_ed25519_pk(&exchange_key.1)?;
        return Ok(exchange_key);
    }
    return Err(NSError::NotFound("Invalid did document".to_string()));
}

pub async fn resolve_did(did: &DID, doc_type: Option<&str>) -> NSResult<EncodedDocument> {
    let client = get_name_client();
    if client.is_none() {
        return Err(NSError::NotFound("Name client not found".to_string()));
    }
    let client = client.unwrap();
    client.resolve_did(did, doc_type).await
}

pub async fn update_did_cache(
    did: DID,
    doc_type: Option<&str>,
    doc: EncodedDocument,
) -> NSResult<()> {
    let client = get_name_client();
    if client.is_none() {
        return Err(NSError::NotFound("Name client not found".to_string()));
    }
    let client = client.unwrap();
    client.update_did_cache(did, doc_type, doc)
}

pub async fn add_nameinfo_cache(hostname: &str, info: NameInfo) -> NSResult<()> {
    let client = get_name_client();
    if client.is_none() {
        return Err(NSError::NotFound("Name client not found".to_string()));
    }
    let client = client.unwrap();
    client.add_nameinfo_cache(hostname, info)
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
            _doc_type: Option<&str>,
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
    async fn test_resolve_did_nameinfo() {
        let did = DID::from_str("did:web:example.com").unwrap();
        let doc = EncodedDocument::JsonLd(serde_json::json!({
            "exp": buckyos_get_unix_timestamp() + 600,
            "marker": "mock-doc"
        }));

        if GLOBAL_NAME_CLIENT.get().is_none() {
            let tmp = tempdir().unwrap().keep();
            let mut client = NameClient::new(NameClientConfig {
                enable_cache: true,
                local_cache_dir: Some(tmp.to_string_lossy().to_string()),
                cache_backend: CacheBackend::Filesystem,
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

        update_did_cache(did.clone(), None, doc.clone()).await.unwrap();
        let did_doc = resolve_did(&did, None).await.unwrap();
        assert_eq!(did_doc, doc);
    }
}
