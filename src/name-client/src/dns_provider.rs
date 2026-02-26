#![allow(unused)]

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

use buckyos_kit::buckyos_get_unix_timestamp;
use hickory_resolver::proto::xfer::Protocol;
use hickory_resolver::config::*;
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::TokioResolver;
use jsonwebtoken::DecodingKey;
use serde_json::json;

use crate::{DEFAULT_DID_DOC_TYPE, NameInfo, NsProvider, RecordType};
use name_lib::*;
pub struct DnsProvider {
    dns_server: Option<String>,
}

impl DnsProvider {
    pub fn new(dns_server: Option<String>) -> Self {
        Self { dns_server }
    }

    pub fn new_with_config(config: serde_json::Value) -> NSResult<Self> {
        let dns_server = config.get("dns_server");
        if dns_server.is_some() {
            let dns_server = dns_server.unwrap().as_str();
            return Ok(Self {
                dns_server: dns_server.map(|s| s.to_string()),
            });
        }
        Ok(Self { dns_server: None })
    }
}

#[async_trait::async_trait]
impl NsProvider for DnsProvider {
    fn get_id(&self) -> String {
        return "dns provider".to_string();
    }

    async fn query(
        &self,
        name: &str,
        record_type: Option<RecordType>,
        from_ip: Option<IpAddr>,
    ) -> NSResult<NameInfo> {
        let mut server_config = ResolverConfig::default();
        let resolver;
        if self.dns_server.is_some() {
            let dns_server = self.dns_server.clone().unwrap();
            let dns_ip_addr = if let Ok(ip) = IpAddr::from_str(&dns_server) {
                SocketAddr::new(ip, 53)
            } else {
                let dns_ip_addr = SocketAddr::from_str(&dns_server).map_err(|e| {
                    NSError::ReadLocalFileError(format!("Invalid dns server: {}", e))
                })?;
                dns_ip_addr
            };
            let name_server_configs = vec![NameServerConfig::new(dns_ip_addr, Protocol::Udp)];
            server_config = ResolverConfig::from_parts(None, vec![], name_server_configs);
            resolver = TokioResolver::builder_with_config(server_config, TokioConnectionProvider::default())
                .build();
        } else {
            resolver = TokioResolver::builder_tokio()
                .map_err(|e| NSError::Failed(format!("create system resolver failed! {}", e)))?
                .build();
        }
       
        match record_type.unwrap_or(RecordType::A) {
            RecordType::TXT => {
                //TODO: 这里似乎有崩溃bug，需要排查
                info!("dns query TXT: {}", name);
                let response = resolver.txt_lookup(name).await;
                if response.is_err() {
                    let err = response.err().unwrap();
                    warn!("lookup txt failed! {}", err.to_string());
                    return Err(NSError::Failed(format!(
                        "lookup txt failed! {}",
                        err
                    )));
                }

                let response = response.unwrap();
                let mut txt_vec = Vec::new();
                for record in response.iter() {
                    let txt = record
                        .txt_data()
                        .iter()
                        .map(|s| -> String {
                            String::from_utf8_lossy(s).to_string()
                        })
                        .collect::<Vec<String>>()
                        .join("");
                    txt_vec.push(txt);
                }

                info!("lookup txt success! {}", name);
                let ttl = response.as_lookup().record_iter().next().map(|r| r.ttl()).unwrap_or(300);
                let name_info = NameInfo {
                    name: name.to_string(),
                    address: Vec::new(),
                    cname: None,
                    txt: txt_vec,
                    ptr_records: Vec::new(),
                    did_documents: HashMap::new(),
                    iat: buckyos_get_unix_timestamp(),
                    ttl: Some(ttl),
                };
                return Ok(name_info);
            }
            RecordType::A | RecordType::AAAA => {
                info!("dns query ip: {}", name);
                let response = resolver.lookup_ip(name).await;
                if response.is_err() {
                    return Err(NSError::Failed(format!(
                        "lookup ip failed! {}",
                        response.err().unwrap()
                    )));
                }
                let response = response.unwrap();
                let mut addrs = Vec::new();
                for ip in response.iter() {
                    addrs.push(ip);
                }
                let ttl = response.as_lookup().record_iter().next().map(|r| r.ttl()).unwrap_or(0);
                let name_info = NameInfo {
                    name: name.to_string(),
                    address: addrs,
                    cname: None,
                    txt: Vec::new(),
                    ptr_records: Vec::new(),
                    did_documents: HashMap::new(),
                    iat: buckyos_get_unix_timestamp(),
                    ttl: Some(ttl),
                };
                return Ok(name_info);
            }
            RecordType::PTR => {
                info!("dns query PTR: {}", name);

                let ip = IpAddr::from_str(name).map_err(|e| {
                    NSError::InvalidParam(format!(
                        "PTR query requires IP input, got '{}': {}",
                        name, e
                    ))
                })?;
                let response = resolver.reverse_lookup(ip).await.map_err(|e| {
                    NSError::Failed(format!("reverse lookup failed! {}", e))
                })?;

                let mut ptr_records = Vec::new();
                for ptr in response.iter() {
                    ptr_records.push(ptr.to_utf8());
                }
                let ttl = response
                    .as_lookup()
                    .record_iter()
                    .next()
                    .map(|r| r.ttl())
                    .unwrap_or(0);

                let name_info = NameInfo {
                    name: name.to_string(),
                    address: Vec::new(),
                    cname: None,
                    txt: Vec::new(),
                    ptr_records,
                    did_documents: HashMap::new(),
                    iat: buckyos_get_unix_timestamp(),
                    ttl: Some(ttl),
                };
                return Ok(name_info);
            }
            _ => {
                return Err(NSError::Failed(format!(
                    "Invalid record type: {:?}",
                    record_type
                )));
            }
        }
    }

    async fn query_did(
        &self,
        did: &DID,
        doc_type: Option<&str>,
        from_ip: Option<IpAddr>,
    ) -> NSResult<EncodedDocument> {
        info!("NsProvider query did: {} ...", did.to_host_name());
        
        let name_info = self
            .query(&did.to_host_name(), Some(RecordType::TXT), None)
            .await?;

        //info!("NsProvicer will parse_txt_record_to_did_document... for {}",did.to_host_name());

        //识别TXT记录中的特殊记录
        let new_name_info = name_info.parse_txt_record_to_did_document()?;

        let doc_type = doc_type.unwrap_or(DEFAULT_DID_DOC_TYPE);
        let did_document = new_name_info.get_did_document(doc_type);
        if did_document.is_some() {
            info!("NsProvider::query_did{}: DID Document found: {}", did.to_host_name(), doc_type);
            return Ok(did_document.unwrap().clone());
        }
        warn!("NsProvider::query_did{}: DID Document not found: {}", did.to_host_name(), doc_type);
        return Err(NSError::NotFound(format!("DID Document not found: {}", doc_type)));
    }
}


#[cfg(test)]
mod tests {
    use buckyos_kit::init_logging;

    use super::*;

    #[tokio::test]
    async fn test_dns_provider() {
        init_logging("test_dns_provider", false);
        let dns_provider = DnsProvider::new(None);
        let result = dns_provider.query("test.buckyos.io", None, None).await;
        assert!(result.is_ok(), "query should succeed");
        let result = result.unwrap();
        assert!(result.address.len() > 0, "address should not be empty");

        let result = dns_provider.query_did(&DID::from_str("did:web:test.buckyos.io").unwrap(), None, None).await;
        assert!(result.is_ok(), "query_did should succeed");
        let result = result.unwrap();
        let result_str = result.to_string();
        println!("* result_str: {}", result_str);


        let result = dns_provider.query_did(&DID::from_str("did:web:test.buckyos.io").unwrap(), Some("boot"), None).await;
        assert!(result.is_ok(), "query_did should succeed");
        let result = result.unwrap();
        let result_str = result.to_string();
        println!("* result_str: {}", result_str);

        let result = dns_provider.query_did(&DID::from_str("did:web:test.buckyos.io").unwrap(), Some("owner"), None).await;
        assert!(result.is_ok(), "query_did should succeed");
        let result = result.unwrap();
        let result_str = result.to_string();
        println!("* result_str: {}", result_str);

        let result = dns_provider.query_did(&DID::from_str(" filebrowser.buckyos.web3.devtests.org").unwrap(), None, None).await;
        if result.is_err() {
            let err = result.err().unwrap();
            warn!("query_did failed! {}", err.to_string());
        }

       

        println!("✓ test_dns_provider passed");
    }
}
