#![allow(unused)]

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

use buckyos_kit::buckyos_get_unix_timestamp;
use hickory_resolver::proto::rr::record_type;
use hickory_resolver::TokioAsyncResolver;
use hickory_resolver::{config::*, Resolver};
use jsonwebtoken::DecodingKey;
use serde_json::json;

use crate::{DEFAULT_FRAGMENT, NameInfo, NsProvider, RecordType};
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

    

    // fn parse_dns_response(resp: DnsResponse) -> NSResult<NameInfo> {
    //     let mut txt_list = Vec::new();
    //     for record in resp.answers() {
    //         if record.record_type() == RecordType::TXT {
    //             let data = record.data();
    //             if data.is_some() {
    //                 let data = data.unwrap();
    //                 if let RData::TXT(txt) = data {
    //                     for txt in txt.txt_data() {
    //                         let txt = String::from_utf8_lossy(txt).to_string();
    //                         txt_list.push(txt);
    //                     }
    //                 }

    //             }
    //         }
    //     }
    //     if txt_list.len() == 0 {
    //         return Err(ns_err!(NSErrorCode::NotFound, "txt data is empty"));
    //     }

    //     let txt = DnsTxtCodec::decode(txt_list)?;
    //     return Ok(serde_json::from_str(txt.as_str()).map_err(into_ns_err!(NSErrorCode::InvalidData, "Failed to parse txt {}", txt))?);
    // }
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
            resolver = TokioAsyncResolver::tokio(server_config, ResolverOpts::default());
        } else {
            let system_resolver = TokioAsyncResolver::tokio_from_system_conf();
            if system_resolver.is_err() {
                return Err(NSError::Failed(format!(
                    "create system resolver failed! {}",
                    system_resolver.err().unwrap()
                )));
            }
            resolver = system_resolver.unwrap();
        }
        info!("dns query: {}", name);
        //resolver.lookup(name, record_type)
        //for dns proivder,default record type is A.
        let record_type_str = record_type
            .map(|rt| rt.to_string())
            .unwrap_or_else(|| "A".to_string());

        match record_type.unwrap_or(RecordType::A) {
            RecordType::TXT => {
                let response = resolver.txt_lookup(name).await;
                if response.is_err() {
                    return Err(NSError::Failed(format!(
                        "lookup txt failed! {}",
                        response.err().unwrap()
                    )));
                }
                let response = response.unwrap();
                let mut txt_vec = Vec::new();
                for record in response.iter() {
                    let txt = record
                        .txt_data()
                        .iter()
                        .map(|s| -> String {
                            let byte_slice: &[u8] = &s;
                            return String::from_utf8_lossy(byte_slice).to_string();
                        })
                        .collect::<Vec<String>>()
                        .join("");
                    txt_vec.push(txt);
                }

                let ttl = response.as_lookup().record_iter().next().map(|r| r.ttl()).unwrap_or(0);
                let name_info = NameInfo {
                    name: name.to_string(),
                    address: Vec::new(),
                    cname: None,
                    txt: txt_vec,
                    did_documents: HashMap::new(),
                    iat: buckyos_get_unix_timestamp(),
                    ttl: Some(ttl),
                };
                return Ok(name_info);
            }
            RecordType::A | RecordType::AAAA => {
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
        
        let name_info = self
            .query(&did.to_host_name(), Some(RecordType::TXT), None)
            .await?;

        info!("NsProvicer will parse_txt_record_to_did_document... for {}",did.to_host_name());

        //识别TXT记录中的特殊记录
        let new_name_info = name_info.parse_txt_record_to_did_document()?;

        let doc_type = doc_type.unwrap_or(DEFAULT_FRAGMENT);
        let did_document = new_name_info.get_did_document(doc_type);
        if did_document.is_some() {
            return Ok(did_document.unwrap().clone());
        }
        warn!("NsProvider::query_did{}: DID Document not found: {}", did.to_host_name(), doc_type);
        return Err(NSError::NotFound(format!("DID Document not found: {}", doc_type)));
    }
}
