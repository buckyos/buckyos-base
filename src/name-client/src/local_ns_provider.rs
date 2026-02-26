use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::io::Result;
use std::net::IpAddr;
use std::path::Path;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use crate::DEFAULT_DID_DOC_TYPE;
use crate::{NSResult, NameInfo, NsProvider, RecordType};
use name_lib::*;

/* config file example (toml):

[www.example.com]
ttl=1800
address=["192.168.1.102","192.168.1.103"]
txt=["THIS_IS_TXT_RECORD"]

["*.example.com"]
A=["192.168.1.104","192.168.1.105"]
TXT="THIS_IS_TXT_RECORD"


[mail.example.com]
A=["192.168.1.106"]
MX=["mail.example.com"]


*/


#[derive(Debug, Serialize, Deserialize, Clone)]
pub(crate) struct DnsLocalConfig {
    #[serde(flatten)]
    pub domains: HashMap<String, NameInfo>,
}

pub struct LocalConfigDnsProvider {
    inner: Arc<Mutex<ConfigProviderInner>>,
}

struct ConfigProviderInner {
    config: DnsLocalConfig,
    ptr_index: HashMap<IpAddr, Vec<String>>,
    config_path: PathBuf,
    last_modified: SystemTime,
}

impl LocalConfigDnsProvider {
    pub fn new(config_path: &Path) -> NSResult<Self> {
        let mut file = File::open(config_path)
            .map_err(|e| NSError::ReadLocalFileError(format!("load config error:{}", e)))?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)
            .map_err(|e| NSError::ReadLocalFileError(format!("load config error:{}", e)))?;

        let config: DnsLocalConfig = toml::from_str(&contents)
            .map_err(|e| NSError::ReadLocalFileError(format!("load config error:{}", e)))?;

        let metadata = file
            .metadata()
            .map_err(|_e| NSError::ReadLocalFileError("Failed to get metadata".to_string()))?;
        let last_modified = metadata
            .modified()
            .map_err(|_e| NSError::ReadLocalFileError("Failed to get modified time".to_string()))?;

        let inner = ConfigProviderInner {
            ptr_index: Self::build_ptr_index(&config),
            config,
            config_path: config_path.to_path_buf(),
            last_modified,
        };

        Ok(LocalConfigDnsProvider {
            inner: Arc::new(Mutex::new(inner)),
        })
    }

    pub fn new_with_config(config: serde_json::Value) -> NSResult<Self> {
        let config_path_str = config.get("path");
        if config_path_str.is_none() {
            return Err(NSError::ReadLocalFileError(
                "config path is not set".to_string(),
            ));
        }
        let config_path_str = config_path_str.unwrap();
        let config_path_str = config_path_str.as_str();
        if config_path_str.is_none() {
            return Err(NSError::ReadLocalFileError(
                "config path is not a string".to_string(),
            ));
        }
        let config_path_str = config_path_str.unwrap();
        let config_path = Path::new(config_path_str);
        Self::new(config_path)
    }

    fn check_and_reload_config(inner: &mut ConfigProviderInner) -> Result<bool> {
        let metadata = std::fs::metadata(&inner.config_path)?;
        let current_modified = metadata.modified()?;

        if current_modified > inner.last_modified {
            let mut file = File::open(&inner.config_path)?;
            let mut contents = String::new();
            file.read_to_string(&mut contents)?;

            let new_config: DnsLocalConfig = toml::from_str(&contents)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

            inner.config = new_config;
            inner.ptr_index = Self::build_ptr_index(&inner.config);
            inner.last_modified = current_modified;
            info!("Config file reloaded successfully");
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn matches_wildcard(pattern: &str, name: &str) -> bool {
        if pattern == "*" {
            return true;
        }

        let pattern_parts: Vec<&str> = pattern.split('.').collect();
        let name_parts: Vec<&str> = name.split('.').collect();

        if pattern_parts.len() != name_parts.len() {
            return false;
        }

        pattern_parts
            .iter()
            .zip(name_parts.iter())
            .all(|(p, n)| *p == "*" || *p == *n)
    }

    fn build_ptr_index(config: &DnsLocalConfig) -> HashMap<IpAddr, Vec<String>> {
        let mut ptr_index: HashMap<IpAddr, Vec<String>> = HashMap::new();

        for (domain, name_info) in &config.domains {
            let mut ptr_values = name_info.ptr_records.clone();
            if ptr_values.is_empty() && !domain.contains('*') {
                ptr_values.push(domain.clone());
            }

            if ptr_values.is_empty() {
                continue;
            }

            for ip in &name_info.address {
                let records = ptr_index.entry(*ip).or_default();
                for ptr in &ptr_values {
                    if !records.contains(ptr) {
                        records.push(ptr.clone());
                    }
                }
            }
        }

        ptr_index
    }

    // fn convert_domain_config_to_records(
    //     domain: &str,
    //     config: &DomainConfig,
    //     record_type: RecordType,
    // ) -> NSResult<NameInfo> {
    //     let default_ttl = config.ttl;
    //     let mut name_info = NameInfo {
    //         name: domain.to_string(),
    //         address: Vec::new(),
    //         cname: None,
    //         txt: Vec::new(),
    //         did_documents: HashMap::new(),
    //         iat: 0,
    //         ttl: Some(default_ttl),
    //     };

    //     match record_type {
    //         RecordType::A => {
    //             name_info.address = config
    //                 .a
    //                 .iter()
    //                 .filter_map(|addr| IpAddr::from_str(addr).ok())
    //                 .filter(|addr| addr.is_ipv4())
    //                 .collect();
    //             if name_info.address.len() < 1 {
    //                 return Err(NSError::InvalidData);
    //             }
    //         }
    //         RecordType::AAAA => {
    //             name_info.address = config
    //                 .aaaa
    //                 .iter()
    //                 .filter_map(|addr| IpAddr::from_str(addr).ok())
    //                 .filter(|addr| addr.is_ipv6())
    //                 .collect();
    //             if name_info.address.len() < 1 {
    //                 return Err(NSError::InvalidData);
    //             }
    //         }
    //         RecordType::CNAME => {
    //             if config.cname.is_some() {
    //                 name_info.cname = config.cname.clone();
    //             } else {
    //                 return Err(NSError::InvalidData);
    //             }
    //         }
    //         RecordType::TXT => {
    //             name_info.txt = config.txt.clone();
    //             if config.did.is_some() {
    //                 let doc_doc_str = config.did.clone().unwrap();
    //                 let did_doc = EncodedDocument::from_str(doc_doc_str)?;
    //                 name_info.did_document = Some(did_doc);
    //             }
    //             if !config.pkx.is_empty() {
    //                 name_info._pk_x_list = Some(config.pkx.clone());
    //             }
    //         }
    //         _ => {
    //             warn!(
    //                 "record type {} not support in dns local file config provider",
    //                 record_type.to_string()
    //             );
    //             return Err(NSError::InvalidData);
    //         }
    //     }

    //     Ok(name_info)
    // }

    pub fn get_all_domains(&self) -> Vec<String> {
        let inner = self.inner.lock().unwrap();
        inner.config.domains.keys().cloned().collect()
    }

    pub fn get_name_info(&self, host_name: &str) -> NSResult<NameInfo> {
        let mut inner = self.inner.lock().unwrap();

        // TODO:每次请求都加载文件，可能有性能问题，应该由外部触发reload
        if let Err(e) = Self::check_and_reload_config(&mut inner) {
            warn!("Failed to reload config: {},still use old config", e);
        }

        // First check for exact match
        let config = inner.config.domains.get(host_name);
        if config.is_none() {
            for (pattern, config) in &inner.config.domains {
                if pattern.contains('*') {
                    if Self::matches_wildcard(pattern, host_name) {
                        debug!("{} found in matches_wildcard {}", host_name, pattern);
                        return Ok(config.clone());
                    }
                }
            }
            return Err(NSError::NotFound(host_name.to_string()));
        }
        debug!("{} found in dns-local-config!", host_name);
        let config = config.unwrap();
        return Ok(config.clone());
    }
}

#[async_trait::async_trait]
impl NsProvider for LocalConfigDnsProvider {
    fn get_id(&self) -> String {
        "local dns-record-config provider".to_string()
    }

    async fn query(
        &self,
        domain: &str,
        record_type: Option<RecordType>,
        _from_ip: Option<IpAddr>,
    ) -> NSResult<NameInfo> {
        let mut domain = domain.to_string();
        if domain.ends_with(".") {
            domain = domain.trim_end_matches('.').to_string();
        }

        if matches!(record_type, Some(RecordType::PTR)) {
            let ip = domain.parse::<IpAddr>().map_err(|e| {
                NSError::InvalidParam(format!(
                    "PTR query requires IP input, got '{}': {}",
                    domain, e
                ))
            })?;

            let mut inner = self.inner.lock().unwrap();
            if let Err(e) = Self::check_and_reload_config(&mut inner) {
                warn!("Failed to reload config: {},still use old config", e);
            }

            let ptr_records = inner
                .ptr_index
                .get(&ip)
                .cloned()
                .ok_or_else(|| NSError::NotFound(domain.clone()))?;

            return Ok(NameInfo {
                name: domain,
                address: Vec::new(),
                cname: None,
                txt: Vec::new(),
                ptr_records,
                ttl: None,
                did_documents: HashMap::new(),
                iat: 0,
            });
        }

        let mut name_info = self.get_name_info(&domain)?;
        //name_info.ttl = Some(300);
        name_info.name = domain.to_string();
        return Ok(name_info);
    }

    async fn query_did(
        &self,
        did: &DID,
        doc_type: Option<&str>,
        _from_ip: Option<IpAddr>,
    ) -> NSResult<EncodedDocument> {
        let host_name = did.to_host_name();
        let name_info = self.get_name_info(&host_name)?; 
        let new_name_info = name_info.parse_txt_record_to_did_document()?;
        let doc_type = doc_type.unwrap_or(DEFAULT_DID_DOC_TYPE);
        let did_document = new_name_info.get_did_document(doc_type);
        if did_document.is_some() {
            return Ok(did_document.unwrap().clone());
        }
        return Err(NSError::NotFound(format!("DID Document not found: {}", doc_type)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use buckyos_kit::init_logging;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn create_test_config() -> NamedTempFile {
        init_logging("config-provider-test", false);
        let config_content = r#"
["www.example.com"]
ttl = 300
address = ["192.168.1.1"]
txt = [
"THISISATEST",
"BOOT=eyJhbGciOiJFZERTQSJ9.eyJvb2RzIjpbInNuIl0sImV4cCI6MjA1ODgzODkzOX0.SGem2FBRB0H2TcRWBRJCsCg5PYXzHW9X9853UChV_qzWHHhKxunZ-emotSnr9HufjL7avGEos1ifRjl9KTrzBg;",
"PKX=qJdNEtscIYwTo-I0K7iPEt_UZdBDRd4r16jdBfNR0tM;",
"DEV=eyJhbGciOiJFZERTQSJ9.eyJuIjoic24iLCJ4IjoiRlB2WTNXWFB4dVdQWUZ1d09ZMFFiaDBPNy1oaEtyNnRhMWpUY1g5T1JQSSIsImV4cCI6MjA1ODgzODkzOX0._YKR0y6E4JQJXDEG12WWFfY1pXyxtdSuigERZQXphnQAarDM02JIoXLNtad80U7T7lO_A4z_HbNDRJ9hMGKhCA;"
]

["*.example.com"]
ttl = 300
address = ["192.168.1.2"]

["*.sub.example.com"]
ttl = 300
address = ["192.168.1.3"]

["mail.example.com"]
ttl = 300
address = ["2600:1700:1150:9440:5cbb:f6ff:fe9e:eefa"]

["reverse.example.com"]
ttl = 300
address = ["192.168.1.10"]
ptr_records = ["node1.example.com", "node1-alt.example.com"]
"#;

        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(config_content.as_bytes()).unwrap();
        temp_file
    }

    #[test]
    fn test_wildcard_matching() {
        assert!(LocalConfigDnsProvider::matches_wildcard("*", "www"));
        assert!(LocalConfigDnsProvider::matches_wildcard(
            "*.example.com",
            "www.example.com"
        ));
        assert!(LocalConfigDnsProvider::matches_wildcard(
            "*.example.com",
            "mail.example.com"
        ));
        assert!(!LocalConfigDnsProvider::matches_wildcard(
            "*.example.com",
            "example.com"
        ));
        assert!(!LocalConfigDnsProvider::matches_wildcard(
            "*.example.com",
            "sub.www.example.com"
        ));
    }

    #[tokio::test]
    async fn test_local_ns_provider() {
        let temp_file = create_test_config();
        let provider = LocalConfigDnsProvider::new(temp_file.path()).unwrap();
        // Test exact domain match
        let result = provider
            .query("www.example.com.", Some(RecordType::A), None)
            .await
            .unwrap();
        assert_eq!(result.name, "www.example.com");
        assert_eq!(result.ttl.unwrap(), 300);
        assert_eq!(result.address.len(), 1);
        assert_eq!(result.address[0].to_string(), "192.168.1.1");

        let result = provider
            .query_did(&DID::new("web", "www.example.com"), None, None)
            .await
            .unwrap();

        let _boot_config = ZoneBootConfig::decode(&result, None).unwrap();
        let result = provider
            .query_did(&DID::new("web", "www.example.com"), Some("boot"), None)
            .await
            .unwrap();
        let boot_jwt = result.to_string();
        assert_eq!(boot_jwt.as_str(),"eyJhbGciOiJFZERTQSJ9.eyJvb2RzIjpbInNuIl0sImV4cCI6MjA1ODgzODkzOX0.SGem2FBRB0H2TcRWBRJCsCg5PYXzHW9X9853UChV_qzWHHhKxunZ-emotSnr9HufjL7avGEos1ifRjl9KTrzBg");
 
        let result = provider
            .query("www.example.com", Some(RecordType::TXT), None)
            .await
            .unwrap();
        assert_eq!(result.name, "www.example.com");
        assert_eq!(result.ttl.unwrap(), 300);

        // Test wildcard domain match
        let result = provider
            .query("test.example.com", Some(RecordType::A), None)
            .await
            .unwrap();
        assert_eq!(result.name, "test.example.com");
        assert_eq!(result.ttl.unwrap(), 300);

        // Test nested wildcard domain match
        let result = provider
            .query("foo.sub.example.com", Some(RecordType::A), None)
            .await
            .unwrap();
        assert_eq!(result.name, "foo.sub.example.com");
        assert_eq!(result.ttl.unwrap(), 300);

        let result = provider.query("mail.example.com", Some(RecordType::AAAA), None)
            .await
            .unwrap();
        assert_eq!(result.name, "mail.example.com");
        assert_eq!(result.address.len(), 1);
        assert_eq!(result.address[0].to_string(), "2600:1700:1150:9440:5cbb:f6ff:fe9e:eefa");

        let result = provider
            .query("192.168.1.1", Some(RecordType::PTR), None)
            .await
            .unwrap();
        assert_eq!(result.name, "192.168.1.1");
        assert!(result.ptr_records.contains(&"www.example.com".to_string()));

        let result = provider
            .query("192.168.1.10", Some(RecordType::PTR), None)
            .await
            .unwrap();
        assert!(result.ptr_records.contains(&"node1.example.com".to_string()));
        assert!(result.ptr_records.contains(&"node1-alt.example.com".to_string()));

        let result = provider
            .query("192.168.1.254", Some(RecordType::PTR), None)
            .await;
        assert!(result.is_err());

        // Test non-existent domain
        let result = provider
            .query("nonexistent.com", Some(RecordType::A), None)
            .await;
        assert!(result.is_err());
    }
}
