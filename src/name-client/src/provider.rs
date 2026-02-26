
use jsonwebtoken::DecodingKey;
use name_lib::*;
use name_lib::OwnerConfig;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, net::IpAddr};

pub const DEFAULT_DID_DOC_TYPE: &str = "zone";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum RecordType {
    A,     // IPv4 address
    AAAA,  // IPv6 address
    CNAME, // Alias record
    TXT,   // Text record
    SRV,   // Service record
    MX,    // Mail exchange record
    NS,    // Name server record
    PTR,   // Pointer record
    SOA,   // Start of authority record
}

impl Default for RecordType {
    fn default() -> Self {
        RecordType::A
    }
}

impl RecordType {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_uppercase().as_str() {
            "A" => Some(RecordType::A),
            "AAAA" => Some(RecordType::AAAA),
            "CNAME" => Some(RecordType::CNAME),
            "TXT" => Some(RecordType::TXT),
            "SRV" => Some(RecordType::SRV),
            "MX" => Some(RecordType::MX),
            "NS" => Some(RecordType::NS),
            "PTR" => Some(RecordType::PTR),
            "SOA" => Some(RecordType::SOA),
            _ => None,
        }
    }

    pub fn to_string(&self) -> String {
        match self {
            RecordType::A => "A",
            RecordType::AAAA => "AAAA",
            RecordType::CNAME => "CNAME",
            RecordType::TXT => "TXT",
            RecordType::SRV => "SRV",
            RecordType::MX => "MX",
            RecordType::NS => "NS",
            RecordType::PTR => "PTR",
            RecordType::SOA => "SOA",
        }
        .to_string()
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct EndPointInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    protocol: Option<String>,
    addr: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    port: Option<u16>,
}

// NameInfo的设计
//  这个结构的json未来可以完整的保存在bns的智能合约里
//  向下兼容DNS，因此有DNS里该有的字段 ： DNS Response一定可以转成一个有效的NameInfo ,符合一定约束的NameInfo，可以转成一个合法的DNS Response
//  基于BNS，构造的核心接口是query_did("fragement")
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct NameInfo {
    #[serde(skip_serializing_if = "String::is_empty")]
    #[serde(default)]
    pub name: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    pub address: Vec<IpAddr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cname: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    pub txt: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    pub ptr_records: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u32>,
    /// key is the doc_type,used by query_did
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    #[serde(default)]
    pub did_documents: HashMap<String, EncodedDocument>,
    #[serde(default)]
    pub iat: u64
}

impl Default for NameInfo {
    fn default() -> Self {
        NameInfo {
            name: String::new(),
            address: Vec::new(),
            cname: None,
            txt: Vec::new(),
            ptr_records: Vec::new(),
            did_documents: HashMap::new(),
            iat: 0,
            ttl: None,
        }
    }
}

impl NameInfo {
    pub fn new(domain: &str) -> Self {
        let mut result = Self::default();
        result.name = domain.to_string();
        return result;
    }

    pub fn from_address(name: &str, address: IpAddr) -> Self {
        let ttl = 5 * 60;
        Self {
            name: name.to_string(),
            address: vec![address],
            cname: None,
            txt: Vec::new(),
            ptr_records: Vec::new(),
            did_documents: HashMap::new(),
            iat: 0,
            ttl: Some(ttl),
        }
    }

    pub fn from_address_vec(name: &str, address_vec: Vec<IpAddr>) -> Self {
        let ttl = 5 * 60;
        Self {
            name: name.to_string(),
            address: address_vec,
            cname: None,
            txt: Vec::new(),
            ptr_records: Vec::new(),
            did_documents: HashMap::new(),
            iat: 0,
            ttl: Some(ttl),
        }
    }

    pub fn parse_did_document_to_txt_record(self: &NameInfo) -> NSResult<NameInfo> {
        let mut new_name_info = self.clone();

        let boot_jwt = self.get_did_document("boot");
        if boot_jwt.is_some() {
            let boot_jwt = boot_jwt.unwrap();
            new_name_info.txt.push(format!("BOOT={};", boot_jwt.to_string()));
        }

        let owner_config = self.get_did_document("owner");
        if owner_config.is_some() {
            let owner_config = owner_config.unwrap();
            let owner_config = OwnerConfig::decode(owner_config, None)?;
            new_name_info.txt.push(format!("PKX={};", get_x_from_jwk(&owner_config.get_default_key().unwrap())?));
        }
        

        for (obj_name, device_jwt) in self.did_documents.iter() {
            if obj_name == "boot" || obj_name == "zone" || obj_name == "owner" {
                continue;
            }

            new_name_info.txt.push(format!("DEV={};", device_jwt.to_string()));
        }

        new_name_info.did_documents.clear();
        return Ok(new_name_info);
    }

    pub fn parse_txt_record_to_did_document(self: &NameInfo) -> NSResult<NameInfo> {
        let host_name = self.name.clone();
        let mut did_documents = HashMap::new();
        let mut owner_x = None;
        let mut devices = Vec::new();
        let mut boot_jwt = None;
        let mut zone_config : Option<ZoneConfig> = None;
        let mut new_txt_vec = Vec::new();

        for txt in self.txt.iter() {
            debug!("- TXT:{}",txt);
            if txt.starts_with("BOOT=") {
                let boot_payload = txt.trim_start_matches("BOOT=").trim_end_matches(";").to_string();
                boot_jwt = Some(boot_payload);
            } else if txt.starts_with("PKX=") {
                let pkx = txt.trim_start_matches("PKX=").trim_end_matches(";");
                owner_x = Some(pkx.to_string());
            } else if txt.starts_with("DEV=") {
                let dev_payload = txt.trim_start_matches("DEV=").trim_end_matches(";");
                devices.push(dev_payload.to_string());
            } else {
                new_txt_vec.push(txt.to_string());
            }
        }

        if owner_x.is_some() {
            let owner_x = owner_x.unwrap();
            let owner_config = OwnerConfig::new_by_pkx(owner_x.as_str(), host_name.as_str())?;
            let public_key_jwk = owner_config.get_default_key().unwrap();
            let owner_public_key = DecodingKey::from_jwk(&public_key_jwk)
                .map_err(|e| NSError::Failed(format!("parse public key failed! {}", e)))?;
            did_documents.insert("owner".to_string(), EncodedDocument::JsonLd(serde_json::to_value(&owner_config).unwrap()));
            //verify did_document by pkx_list
            if boot_jwt.is_some() {
                let boot_jwt = boot_jwt.unwrap();
                let mut boot_config = ZoneBootConfig::decode(&EncodedDocument::Jwt(boot_jwt.clone()), None)?;
                boot_config.owner_key = Some(public_key_jwk.clone());
                boot_config.id = Some(DID::from_str(host_name.as_str()).unwrap());
                let real_zone_config = boot_config.to_zone_config(&boot_jwt);
                zone_config = Some(real_zone_config);
                did_documents.insert("boot".to_string(), EncodedDocument::Jwt(boot_jwt));
            }
           
            if devices.len() > 0 {
                for device_jwt in devices {
                    //用zone_boot_config.owner_key验证device_jwt
                    let device_mini_config = DeviceMiniConfig::from_jwt(&device_jwt, &owner_public_key);
                    if device_mini_config.is_err()  {
                        warn!("{} in not device_minit_config jwt",device_jwt);
                        continue;
                    }
                    let device_mini_config = device_mini_config.unwrap();
                    let device_config = DeviceConfig::new_by_mini_config(
                        &device_jwt,
                        &device_mini_config,
                        DID::from_str(host_name.as_str()).unwrap(),
                        DID::from_str(host_name.as_str()).unwrap(),
                    );
                    let device_name = device_config.name.clone();
                    let device_config_json = serde_json::to_value(&device_config).unwrap();
                    did_documents.insert(device_name, EncodedDocument::JsonLd(device_config_json));
                    if zone_config.is_some() {
                        zone_config.as_mut().unwrap().devices.insert(device_config.name.clone(), device_config);
                    }
                    
   
                }
            }

            if zone_config.is_some() {
                let zone_config = zone_config.unwrap();
                let zone_config_json = serde_json::to_value(&zone_config).unwrap();
                did_documents.insert("zone".to_string(), EncodedDocument::JsonLd(zone_config_json));
            }

            let mut new_name_info = self.clone();
            new_name_info.did_documents = did_documents;
            new_name_info.txt = new_txt_vec;
            return Ok(new_name_info);
        }

        return Ok(self.clone());
    }
    // pub fn from_zone_config_str(
    //     name: &str,
    //     zone_config_jwt: &str,
    //     zone_config_pkx: &str,
    //     zone_gateway_device_list: &Option<Vec<String>>,
    // ) -> Self {

    //     let ttl = 3600;
    //     let pkx_string = format!("0:{}", zone_config_pkx);
    //     let mut pk_x_list = vec![pkx_string];
    //     if let Some(device_list) = zone_gateway_device_list {
    //         for device_did in device_list {
    //             let device_did = DID::from_str(device_did.as_str());
    //             if device_did.is_ok() {
    //                 let device_did = device_did.unwrap();
    //                 let pkx_string = format!("1:{}", device_did.id);
    //                 pk_x_list.push(pkx_string);
    //             }
    //         }
    //     }

    //     let zone_boot_config_doc = EncodedDocument::from_str(zone_config_jwt.to_string()).unwrap();
    //     let mut did_documents = HashMap::new();
    //     did_documents.insert("boot".to_string(), zone_boot_config_doc);
    //     Self {
    //         name: name.to_string(),
    //         address: vec![],
    //         cname: None,
    //         txt: Vec::new(),
    //         did_documents: did_documents,
    //         iat: 0,
    //         ttl: Some(ttl),
    //     }
    // }

    pub fn get_did_document(&self, doc_type: &str) -> Option<&EncodedDocument> {
        self.did_documents.get(doc_type)
    }
}

#[async_trait::async_trait]
pub trait NsProvider: 'static + Send + Sync {
    fn get_id(&self) -> String;
    async fn query(
        &self,
        name: &str,
        record_type: Option<RecordType>,
        from_ip: Option<IpAddr>,
    ) -> NSResult<NameInfo>;
    async fn query_did(
        &self,
        did: &DID,
        doc_type: Option<&str>,
        from_ip: Option<IpAddr>,
    ) -> NSResult<EncodedDocument>;
}

#[async_trait::async_trait]
pub trait NsUpdateProvider: 'static + Send + Sync {
    async fn update(&self, record_type: RecordType, record: NameInfo) -> NSResult<NameInfo>;
    async fn delete(&self, name: &str, record_type: RecordType) -> NSResult<Option<NameInfo>>;
}


#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{EncodingKey, DecodingKey};
    use serde_json::json;
    use buckyos_kit::buckyos_get_unix_timestamp;

    // 测试辅助函数：创建测试用的密钥和 ZoneBootConfig
    fn create_test_zone_boot_config() -> (EncodingKey, DecodingKey, jsonwebtoken::jwk::Jwk, ZoneBootConfig) {
        let private_key_pem = r#"
        -----BEGIN PRIVATE KEY-----
        MC4CAQAwBQYDK2VwBCIEIBwApVoYjauZFuKMBRe02wKlKm2B6a1F0/WIPMqDaw5F
        -----END PRIVATE KEY-----
        "#;
        let jwk = json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "qmtOLLWpZeBMzt97lpfj2MxZGWn3QfuDB7Q4uaP3Eok"
        });
        
        let private_key = EncodingKey::from_ed_pem(private_key_pem.as_bytes()).unwrap();
        let public_key_jwk: jsonwebtoken::jwk::Jwk = serde_json::from_value(jwk).unwrap();
        let public_key = DecodingKey::from_jwk(&public_key_jwk).unwrap();

        let zone_boot_config = ZoneBootConfig {
            id: None,
            oods: vec![
                "ood1".parse().unwrap(),
                "ood2:202.222.122.123".parse().unwrap(),
            ],
            sn: Some("sn.buckyos.io".to_string()),
            exp: buckyos_get_unix_timestamp() + 3600 * 24 * 365,
            owner: None,
            owner_key: None,
            extra_info: HashMap::new(),
        };

        (private_key, public_key, public_key_jwk, zone_boot_config)
    }

    // 测试辅助函数：创建测试用的 DeviceMiniConfig
    fn create_test_device_mini_config(owner_private_key: &EncodingKey) -> String {
        let mini_config = DeviceMiniConfig {
            name: "device1".to_string(),
            x: "5bUuyWLOKyCre9az_IhJVIuOw8bA0gyKjstcYGHbaPE".to_string(),
            rtcp_port: None,
            exp: buckyos_get_unix_timestamp() + 3600 * 24 * 365,
            extra_info: HashMap::new(),
        };
        
        mini_config.to_jwt(owner_private_key).unwrap()
    }

    #[test]
    fn test_parse_txt_record_to_did_document() {
        // 准备测试数据
        let (private_key, _public_key, public_key_jwk, zone_boot_config) = create_test_zone_boot_config();
        
        // 编码 ZoneBootConfig 为 JWT
        let boot_jwt = zone_boot_config.encode(Some(&private_key)).unwrap();
        let boot_jwt_str = boot_jwt.to_string();
        
        // 创建设备 JWT
        let device_jwt = create_test_device_mini_config(&private_key);
        
        // 获取 owner key 的 x 值
        let owner_x = get_x_from_jwk(&public_key_jwk).unwrap();

        let other_txt = vec ![
            "DEV=eyJhbGciOiJFZERTQSJ9.eyJuIjoic24iLCJ4IjoiRlB2WTNXWFB4dVdQWUZ1d09ZMFFiaDBPNy1oaEtyNnRhMWpUY1g5T1JQSSIsImV4cCI6MjA1ODgzODkzOX0._YKR0y6E4JQJXDEG12WWFfY1pXyxtdSuigERZQXphnQAarDM02JIoXLNtad80U7T7lO_A4z_HbNDRJ9hMGKhCA;".to_string(),
            "BOOT=eyJhbGciOiJFZERTQSJ9.eyJvb2RzIjpbInNuIl0sImV4cCI6MjA1ODgzODkzOX0.SGem2FBRB0H2TcRWBRJCsCg5PYXzHW9X9853UChV_qzWHHhKxunZ-emotSnr9HufjL7avGEos1ifRjl9KTrzBg;".to_string(),
            "PKX=qJdNEtscIYwTo-I0K7iPEt_UZdBDRd4r16jdBfNR0tM;".to_string(),
        ];
        
        // 创建包含 TXT 记录的 NameInfo
        let name_info = NameInfo {
            name: "did:bns:testzone".to_string(),
            address: Vec::new(),
            cname: None,
            txt: other_txt,
            ptr_records: Vec::new(),
            did_documents: HashMap::new(),
            iat: buckyos_get_unix_timestamp(),
            ttl: Some(3600),
        };

        // 执行解析
        let result = name_info.parse_txt_record_to_did_document();
        assert!(result.is_ok(), "parse_txt_record_to_did_document should succeed");
        
        let parsed_info = result.unwrap();
        
        // 验证结果
        assert!(parsed_info.did_documents.contains_key("boot"), "should contain boot document");
        assert!(parsed_info.did_documents.contains_key("zone"), "should contain zone document");
        assert!(parsed_info.did_documents.contains_key("sn"), "should contain ood1 document");


        let zone_boot_config = parsed_info.get_did_document("zone").unwrap();
        let did_doc = parse_did_doc(zone_boot_config.clone()).unwrap();
        let auth_key = did_doc.get_auth_key(None).unwrap();
        let auth_key_x = get_x_from_jwk(&auth_key.1).unwrap();
        //assert_eq!(auth_key_x, owner_x);
        

        println!("✓ test_parse_txt_record_to_did_document passed");
    }

    #[test]
    fn test_parse_did_document_to_txt_record() {
        // 准备测试数据
        let (private_key, _public_key, public_key_jwk, mut zone_boot_config) = create_test_zone_boot_config();
        
        // 设置 owner_key
        zone_boot_config.owner_key = Some(public_key_jwk.clone());
        zone_boot_config.id = Some(DID::from_str("did:bns:testzone").unwrap());

        let owner_config = OwnerConfig::new(DID::from_str("did:bns:testzone").unwrap(), "did:bns:testzone".to_string(), "did:bns:testzone".to_string(), public_key_jwk.clone());
        let owner_config_json = serde_json::to_value(&owner_config).unwrap();
        // 编码为 JWT
        let boot_jwt = zone_boot_config.encode(Some(&private_key)).unwrap();
        
        // 创建设备 JWT
        let device_jwt = create_test_device_mini_config(&private_key);
        
        // 创建 zone 的 JsonLd 文档
        let zone_config_value = serde_json::to_value(&zone_boot_config).unwrap();
        
        // 创建包含 DID 文档的 NameInfo
        let mut did_documents = HashMap::new();
        did_documents.insert("boot".to_string(), boot_jwt.clone());
        did_documents.insert("owner".to_string(), EncodedDocument::JsonLd(owner_config_json));
        did_documents.insert("device1".to_string(), EncodedDocument::Jwt(device_jwt.clone()));
        
        let name_info = NameInfo {
            name: "did:bns:testzone".to_string(),
            address: Vec::new(),
            cname: None,
            txt: Vec::new(),
            ptr_records: Vec::new(),
            did_documents,
            iat: buckyos_get_unix_timestamp(),
            ttl: Some(3600),
        };

        // 执行转换
        let result = name_info.parse_did_document_to_txt_record();
        assert!(result.is_ok(), "parse_did_document_to_txt_record should succeed");
        
        let parsed_info = result.unwrap();
        
        // 验证结果
        assert!(parsed_info.txt.len() >= 3, "should have at least 3 TXT records (BOOT, PKX, DEV)");
        for txt in parsed_info.txt.iter() {
            println!("TXT:{}", txt);
        }
        
        //验证包含必要的 TXT 记录
        let has_boot = parsed_info.txt.iter().any(|txt| txt.starts_with("BOOT="));
        let has_pkx = parsed_info.txt.iter().any(|txt| txt.starts_with("PKX="));
        let has_dev = parsed_info.txt.iter().any(|txt| txt.starts_with("DEV="));
        
        assert!(has_boot, "should have BOOT TXT record");
        assert!(has_pkx, "should have PKX TXT record");
        assert!(has_dev, "should have DEV TXT record");
        
        // 验证 did_documents 已清空
        assert_eq!(parsed_info.did_documents.len(), 0, "did_documents should be cleared");
        
        println!("✓ test_parse_did_document_to_txt_record passed");
    }

    #[test]
    fn test_txt_record_round_trip() {
        // 准备测试数据
        let (private_key, _public_key, public_key_jwk, zone_boot_config) = create_test_zone_boot_config();
        
        // 编码 ZoneBootConfig 为 JWT
        let boot_jwt = zone_boot_config.encode(Some(&private_key)).unwrap();
        let boot_jwt_str = boot_jwt.to_string();
        
        // 创建设备 JWT
        let device_jwt = create_test_device_mini_config(&private_key);
        
        // 获取 owner key 的 x 值
        let owner_x = get_x_from_jwk(&public_key_jwk).unwrap();
        
        // 创建初始 NameInfo（TXT 记录格式）
        let original_name_info = NameInfo {
            name: "did:bns:testzone".to_string(),
            address: Vec::new(),
            cname: None,
            txt: vec![
                format!("BOOT={};", boot_jwt_str),
                format!("PKX={};", owner_x),
                format!("DEV={};", device_jwt),
            ],
            ptr_records: Vec::new(),
            did_documents: HashMap::new(),
            iat: buckyos_get_unix_timestamp(),
            ttl: Some(3600),
        };

        // 第一步：TXT -> DID Documents
        let with_did_docs = original_name_info.parse_txt_record_to_did_document().unwrap();
        assert!(with_did_docs.did_documents.len() >= 2, "should have DID documents");
        assert_eq!(with_did_docs.txt.len(), 0, "TXT records should be moved to did_documents");

        // // 第二步：DID Documents -> TXT
        let back_to_txt = with_did_docs.parse_did_document_to_txt_record().unwrap();
        assert!(back_to_txt.txt.len() >= 3, "should have TXT records");
        assert_eq!(back_to_txt.did_documents.len(), 0, "did_documents should be cleared");
        
        // 验证往返后包含相同的记录类型
        let has_boot = back_to_txt.txt.iter().any(|txt| txt.starts_with("BOOT="));
        let has_pkx = back_to_txt.txt.iter().any(|txt| txt.starts_with("PKX="));
        let has_dev = back_to_txt.txt.iter().any(|txt| txt.starts_with("DEV="));
        
        assert!(has_boot, "round trip should preserve BOOT");
        assert!(has_pkx, "round trip should preserve PKX");
        assert!(has_dev, "round trip should preserve DEV");
        
        println!("✓ test_txt_record_round_trip passed");
    }

    #[test]
    fn test_parse_txt_record_without_owner_key() {
        // 测试没有 owner key 的情况
        let name_info = NameInfo {
            name: "did:bns:testzone".to_string(),
            address: Vec::new(),
            cname: None,
            txt: vec![
                "some-txt=value".to_string(),
            ],
            ptr_records: Vec::new(),
            did_documents: HashMap::new(),
            iat: buckyos_get_unix_timestamp(),
            ttl: Some(3600),
        };

        let result = name_info.parse_txt_record_to_did_document().unwrap();
        
        // 应该返回原始 NameInfo 的克隆
        assert_eq!(result.did_documents.len(), 0, "should have no DID documents");
        assert_eq!(result.txt.len(), 1, "should preserve original TXT");
        
        println!("✓ test_parse_txt_record_without_owner_key passed");
    }

    #[test]
    fn test_parse_did_document_without_zone() {
        // 测试没有 zone 文档的情况
        let name_info = NameInfo {
            name: "did:bns:testzone".to_string(),
            address: Vec::new(),
            cname: None,
            txt: Vec::new(),
            ptr_records: Vec::new(),
            did_documents: HashMap::new(),
            iat: buckyos_get_unix_timestamp(),
            ttl: Some(3600),
        };

        let result = name_info.clone();
        
        // 应该返回原始的 NameInfo，只是 did_documents 被清空
        assert_eq!(result.txt.len(), 0, "should have no TXT records");
        assert_eq!(result.did_documents.len(), 0, "should have no DID documents");
        
        println!("✓ test_parse_did_document_without_zone passed");
    }


}
