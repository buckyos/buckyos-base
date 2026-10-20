#![allow(unused)]

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

use buckyos_kit::buckyos_get_unix_timestamp;
use hickory_resolver::config::*;
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::proto::rr::{RData, RecordType as HickoryRecordType};
use hickory_resolver::proto::xfer::Protocol;
use hickory_resolver::TokioResolver;
use jsonwebtoken::DecodingKey;
use serde_json::json;

use crate::resolver::{Carrier, ResolveOpts, Revision, Source, SourceAnswer, SourceRef, SourceTier};
use crate::{DidDocType, NameInfo, NsProvider, RecordType};
use std::collections::HashMap as StdHashMap;
use name_lib::*;
pub struct DnsProvider {
    dns_server: Option<String>,
    /// 一次 TXT 查询解析出的全部文档(owner / boot / zone / device)短期缓存,
    /// 避免同一名字的多种类型查询重复发 DNS。
    txt_cache: std::sync::Mutex<StdHashMap<String, (StdHashMap<String, EncodedDocument>, u64)>>,
}

const TXT_DOCS_CACHE_SECS: u64 = 30;

impl DnsProvider {
    pub fn new(dns_server: Option<String>) -> Self {
        Self {
            dns_server,
            txt_cache: std::sync::Mutex::new(StdHashMap::new()),
        }
    }

    pub fn new_with_config(config: serde_json::Value) -> NSResult<Self> {
        let dns_server = config
            .get("dns_server")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        Ok(Self::new(dns_server))
    }

    fn build_resolver(&self) -> NSResult<TokioResolver> {
        let mut builder = if let Some(dns_server) = &self.dns_server {
            let dns_ip_addr = if let Ok(ip) = IpAddr::from_str(dns_server) {
                SocketAddr::new(ip, 53)
            } else {
                SocketAddr::from_str(dns_server).map_err(|e| {
                    NSError::ReadLocalFileError(format!("Invalid dns server: {}", e))
                })?
            };
            let name_server_configs = vec![
                NameServerConfig::new(dns_ip_addr, Protocol::Udp),
                NameServerConfig::new(dns_ip_addr, Protocol::Tcp),
            ];
            let server_config = ResolverConfig::from_parts(None, vec![], name_server_configs);
            TokioResolver::builder_with_config(server_config, TokioConnectionProvider::default())
        } else {
            TokioResolver::builder_tokio()
                .map_err(|e| NSError::Failed(format!("create system resolver failed! {}", e)))?
        };

        let resolver_opts = builder.options_mut();
        resolver_opts.edns0 = true;
        resolver_opts.try_tcp_on_error = true;

        Ok(builder.build())
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
        let resolver = self.build_resolver()?;

        match record_type.unwrap_or(RecordType::A) {
            RecordType::TXT => {
                //TODO: 这里似乎有崩溃bug，需要排查
                debug!("dns query TXT: {}", name);
                let response = resolver.txt_lookup(name).await;
                if response.is_err() {
                    let err = response.err().unwrap();
                    // NoRecordsFound/NXDOMAIN 是 DNS 渠道的权威回答("没有"),
                    // 必须与传输失败(没得到回答)区分:前者是 NotFound,
                    // 后者才是 Failed(设计稿 §2.2:NoAnswer 与"没有文档"的二分)。
                    if err.is_no_records_found() {
                        return Err(NSError::NotFound(format!("no TXT record for {}", name)));
                    }
                    warn!("lookup txt failed! {}", err.to_string());
                    return Err(NSError::Failed(format!("lookup txt failed! {}", err)));
                }

                let response = response.unwrap();
                let mut txt_vec = Vec::new();
                for record in response.iter() {
                    let txt = record
                        .txt_data()
                        .iter()
                        .map(|s| -> String { String::from_utf8_lossy(s).to_string() })
                        .collect::<Vec<String>>()
                        .join("");
                    txt_vec.push(txt);
                }

                debug!("lookup txt success! {}", name);
                let ttl = response
                    .as_lookup()
                    .record_iter()
                    .next()
                    .map(|r| r.ttl())
                    .unwrap_or(300);
                let name_info = NameInfo {
                    name: name.to_string(),
                    address: Vec::new(),
                    cname: None,
                    txt: txt_vec,
                    caa: Vec::new(),
                    ptr_records: Vec::new(),
                    iat: buckyos_get_unix_timestamp(),
                    ttl: Some(ttl),
                };
                return Ok(name_info);
            }
            RecordType::CAA => {
                debug!("dns query CAA: {}", name);
                let response = resolver.lookup(name, HickoryRecordType::CAA).await;
                if response.is_err() {
                    let err = response.err().unwrap();
                    warn!("lookup caa failed! {}", err);
                    return Err(NSError::Failed(format!("lookup caa failed! {}", err)));
                }

                let response = response.unwrap();
                let ttl = response
                    .record_iter()
                    .next()
                    .map(|r| r.ttl())
                    .unwrap_or(300);
                let caa = response
                    .iter()
                    .filter_map(|rdata| match rdata {
                        RData::CAA(caa) => Some(caa.to_string()),
                        _ => None,
                    })
                    .collect::<Vec<_>>();
                let name_info = NameInfo {
                    name: name.to_string(),
                    address: Vec::new(),
                    cname: None,
                    txt: Vec::new(),
                    caa,
                    ptr_records: Vec::new(),
                    iat: buckyos_get_unix_timestamp(),
                    ttl: Some(ttl),
                };
                return Ok(name_info);
            }
            RecordType::HTTPS => {
                let mut name_info = NameInfo::new(name);
                name_info.ttl = Some(300);
                return Ok(name_info);
            }
            RecordType::A | RecordType::AAAA => {
                debug!("dns query ip: {}", name);
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
                let ttl = response
                    .as_lookup()
                    .record_iter()
                    .next()
                    .map(|r| r.ttl())
                    .unwrap_or(0);
                let name_info = NameInfo {
                    name: name.to_string(),
                    address: addrs,
                    cname: None,
                    txt: Vec::new(),
                    caa: Vec::new(),
                    ptr_records: Vec::new(),
                    iat: buckyos_get_unix_timestamp(),
                    ttl: Some(ttl),
                };
                return Ok(name_info);
            }
            RecordType::PTR => {
                debug!("dns query PTR: {}", name);

                let ip = IpAddr::from_str(name).map_err(|e| {
                    NSError::InvalidParam(format!(
                        "PTR query requires IP input, got '{}': {}",
                        name, e
                    ))
                })?;
                let response = resolver
                    .reverse_lookup(ip)
                    .await
                    .map_err(|e| NSError::Failed(format!("reverse lookup failed! {}", e)))?;

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
                    caa: Vec::new(),
                    ptr_records,
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

}


impl DnsProvider {
    /// 从 TXT 记录解析出该名字下的全部 DID 文档(owner / boot / zone / device)。
    pub async fn query_did_documents(
        &self,
        did: &DID,
        from_ip: Option<IpAddr>,
    ) -> NSResult<StdHashMap<String, EncodedDocument>> {
        let host = did.to_host_name();
        let now = buckyos_get_unix_timestamp();
        if let Some((docs, until)) = self.txt_cache.lock().unwrap().get(&host).cloned() {
            if until > now {
                return Ok(docs);
            }
        }
        let name_info = self.query(&host, Some(RecordType::TXT), from_ip).await?;
        let docs = name_info.parse_txt_record_to_did_documents()?;
        let mut cache = self.txt_cache.lock().unwrap();
        if cache.len() > 256 {
            cache.retain(|_, (_, until)| *until > now);
        }
        cache.insert(host, (docs.clone(), now + TXT_DOCS_CACHE_SECS));
        Ok(docs)
    }
}

/// DNS TXT 只用于 current-zone 自举(注册为 zone-bootstrap normal 来源):
/// 没有发布状态机和负状态信令,只贡献候选。
#[async_trait::async_trait]
impl Source for DnsProvider {
    fn id(&self) -> String {
        "dns-provider".to_string()
    }

    async fn get_document(
        &self,
        did: &DID,
        doc_type: &DidDocType,
        _revision: &Revision,
        _opts: &ResolveOpts,
    ) -> SourceAnswer {
        let sref = SourceRef::provider(self.id(), SourceTier::Normal);
        let own = match self.query_did_documents(did, None).await {
            Ok(documents) => match documents.get(doc_type.as_str()) {
                Some(doc) => return SourceAnswer::new(sref).with_body(doc.clone(), Carrier::Body),
                None => SourceAnswer::no_answer(sref.clone(), format!("no {} document in TXT", doc_type)),
            },
            Err(NSError::NotFound(msg)) => SourceAnswer::no_answer(sref.clone(), msg),
            Err(err) => SourceAnswer::failure(sref.clone(), err.to_string()),
        };
        // zone 的 TXT 里用 `DEV=` 携带子设备文档:`{device}.{zone}` 的 device 文档
        // 在上级名字的记录中按设备名查找。
        if matches!(doc_type, DidDocType::Device | DidDocType::Zone) {
            if let Some(upper) = did.upper_did() {
                let device_name = did.id.split('.').next().unwrap_or_default().to_string();
                if !device_name.is_empty() {
                    if let Ok(documents) = self.query_did_documents(&upper, None).await {
                        if let Some(doc) = documents.get(&device_name) {
                            return SourceAnswer::new(sref).with_body(doc.clone(), Carrier::Body);
                        }
                    }
                }
            }
        }
        own
    }
}

#[cfg(test)]
mod tests {
    use buckyos_kit::init_logging;

    use super::*;
    use hickory_resolver::proto::xfer::Protocol;
    use std::time::Duration;

    #[test]
    fn test_custom_dns_resolver_enables_edns0_and_tcp_fallback() {
        let dns_provider = DnsProvider::new(Some("1.1.1.1".to_string()));
        let resolver = dns_provider
            .build_resolver()
            .expect("resolver should build");

        assert!(resolver.options().edns0, "edns0 should be enabled");
        assert!(
            resolver.options().try_tcp_on_error,
            "tcp fallback should be enabled"
        );

        let protocols = resolver
            .config()
            .name_servers()
            .iter()
            .map(|server| server.protocol)
            .collect::<Vec<_>>();
        assert!(protocols.contains(&Protocol::Udp));
        assert!(protocols.contains(&Protocol::Tcp));
    }

    #[tokio::test]
    async fn test_dns_provider() {
        init_logging("test_dns_provider", false);
        let dns_provider = DnsProvider::new(None);
        let result = dns_provider.query("test.buckyos.io", None, None).await;
        assert!(result.is_ok(), "query should succeed");
        let result = result.unwrap();
        assert!(result.address.len() > 0, "address should not be empty");

        let answer = dns_provider
            .get_document(
                &DID::from_str("did:web:test.buckyos.io").unwrap(),
                &DidDocType::Zone,
                &Revision::current(),
                &ResolveOpts::default().normalize(Duration::from_secs(10)),
            )
            .await;
        assert!(answer.body.is_some(), "get_document should succeed: {:?}", answer.reason);
        println!("* result_str: {}", answer.body.unwrap().to_string());

        let answer = dns_provider
            .get_document(
                &DID::from_str("did:web:test.buckyos.io").unwrap(),
                &DidDocType::Boot,
                &Revision::current(),
                &ResolveOpts::default().normalize(Duration::from_secs(10)),
            )
            .await;
        assert!(answer.body.is_some(), "get_document should succeed: {:?}", answer.reason);
        println!("* result_str: {}", answer.body.unwrap().to_string());

        let answer = dns_provider
            .get_document(
                &DID::from_str("did:web:test.buckyos.io").unwrap(),
                &DidDocType::Owner,
                &Revision::current(),
                &ResolveOpts::default().normalize(Duration::from_secs(10)),
            )
            .await;
        assert!(answer.body.is_some(), "get_document should succeed: {:?}", answer.reason);
        println!("* result_str: {}", answer.body.unwrap().to_string());

        if let Ok(did) = DID::from_str("filebrowser.buckyos.web3.devtests.org") {
            let answer = dns_provider
                .get_document(
                    &did,
                    &DidDocType::Zone,
                    &Revision::current(),
                    &ResolveOpts::default().normalize(Duration::from_secs(10)),
                )
                .await;
            if answer.body.is_none() {
                warn!("get_document failed! {:?}", answer.reason);
            }
        }

        println!("✓ test_dns_provider passed");
    }
}
