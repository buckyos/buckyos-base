use std::collections::HashMap;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;

use crate::DEFUALT_EXPIRE_TIME;
use crate::get_x_from_jwk;

use crate::DID;
use crate::{DeviceConfig, DeviceInfo};
use buckyos_kit::*;
use jsonwebtoken::jwk::Jwk;
use jsonwebtoken::{encode, Algorithm, DecodingKey, EncodingKey, Header};
use log::*;
use once_cell::sync::OnceCell;
use rand::seq::SliceRandom;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::json;

use crate::{
    decode_json_from_jwt_with_default_pk, decode_json_from_jwt_with_pk,
    decode_jwt_claim_without_verify,
};
use crate::{DIDDocumentTrait, EncodedDocument};
use crate::{NSError, NSResult};

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub(crate) struct VerificationMethodNode {
    #[serde(rename = "type")]
    pub key_type: String,
    #[serde(rename = "id")]
    pub key_id: String,
    #[serde(rename = "controller")]
    pub key_controller: String,
    #[serde(rename = "publicKeyJwk")]
    pub public_key: Jwk,
    #[serde(flatten)]
    pub extra_info: HashMap<String, serde_json::Value>,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub(crate) struct ServiceNode {
    pub id: String,
    #[serde(rename = "type")]
    pub service_type: String,
    #[serde(rename = "serviceEndpoint")]
    pub service_endpoint: String,
}

pub(crate) fn default_context() -> String {
    "https://www.w3.org/ns/did/v1".to_string()
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub enum DeviceNodeType {
    OOD,     //ood and gateway
    Gateway, //gateway only
    OODOnly, //not gateway
    Server,
    Device,//normal client device
    Sensor,//sensor,
    IoTController,//iot controller
    UnknownClient(String),
}


impl Default for DeviceNodeType {
    fn default() -> Self {
        DeviceNodeType::Device
    }
}

impl DeviceNodeType {
    pub fn is_allow_in_oods(&self) -> bool {
        match self {
            DeviceNodeType::OOD => true,
            DeviceNodeType::Gateway => true,
            DeviceNodeType::OODOnly => true,
            _ => false,
        }
    }

    pub fn is_ood(&self) -> bool {
        return self == &DeviceNodeType::OOD || self == &DeviceNodeType::OODOnly;
    }

    pub fn is_gateway(&self) -> bool {
        return self == &DeviceNodeType::Gateway || self == &DeviceNodeType::OOD;
    }
}



//OODDescriptionString is a string that describes the OOD
// ood1@lan1
// ood1@wan
// ood1:210.35.234.21
// ood1:192.168.1.100@lan1
// #gate1:210.35.22 // gateway device that is not OOD
// $ood1:210.35.234.21 // OOD device that is not gateway
#[derive(Clone, Debug, PartialEq)]
pub struct OODDescriptionString {
    pub name: String,
    pub node_type: DeviceNodeType,
    pub net_id: Option<String>,
    pub ip: Option<IpAddr>,

}

impl OODDescriptionString {
    pub fn new(
        name: String,
        node_type: DeviceNodeType,
        net_id: Option<String>,
        ip: Option<IpAddr>,
    ) -> Self {
        let mut final_net_id = net_id;
        // If IP is present but net_id is not, automatically set to wan
        if ip.is_some() && final_net_id.is_none() {
            final_net_id = Some("wan".to_string());
        }
        OODDescriptionString {
            name,
            node_type,
            net_id: final_net_id,
            ip,
        }
    }

    pub fn to_string(&self) -> NSResult<String> {
        let mut result = String::new();
        match self.node_type {
            DeviceNodeType::OOD => {
                result = self.name.clone();
            }
            DeviceNodeType::Gateway => {
                result = format!("#{}", self.name);
            }
            DeviceNodeType::OODOnly => {
                result = format!("${}", self.name);
            }
            _ => {
                return Err(NSError::InvalidParam(
                    "Node type is not allow in oods".to_string(),
                ));
            }
        }

        if self.ip.is_some() {
            result += &format!(":{}", self.ip.as_ref().unwrap());
            if self.net_id.is_some() {
                if self.net_id.as_ref().unwrap() != "wan" {
                    result += &format!("@{}", self.net_id.as_ref().unwrap());
                }
            } 
            // If IP is present but net_id is not, return directly (allow this case for backward compatibility)
            return Ok(result);
        }

        if self.net_id.is_some() {
            result += &format!("@{}", self.net_id.as_ref().unwrap());
        }

        return Ok(result);
    }
}

impl FromStr for OODDescriptionString {
    type Err = NSError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // s examples: "ood1"  "#ood1"  "$ood1"   "ood1:192.168.1.8@lan"  "#ood1:192.168.1.8@lan" "$ood1:1.2.3.4@lan"  "ood1@wan"  "ood1:192.168.1.8@wan"
        // Rules can refer to to_string
        let mut node_type = DeviceNodeType::OOD;
        let mut rest = s;

        // Process prefix to determine NodeType
        if let Some(stripped) = s.strip_prefix('#') {
            node_type = DeviceNodeType::Gateway;
            rest = stripped;
        } else if let Some(stripped) = s.strip_prefix('$') {
            node_type = DeviceNodeType::OODOnly;
            rest = stripped;
        }

        let mut name = "";
        let mut ip: Option<IpAddr> = None;
        let mut net_id: Option<String> = None;

        // Find '@' to separate net_id
        let (before_netid, after_netid_opt) = {
            if let Some(idx) = rest.rfind('@') {
                (&rest[..idx], Some(&rest[idx + 1..]))
            } else {
                (rest, None)
            }
        };

        // If after_netid_opt has content, it means net_id is present
        if let Some(netid) = after_netid_opt {
            net_id = Some(netid.to_string());
        }

        // Find ':' to separate ip
        let (name_part, ip_part_opt) = {
            if let Some(idx) = before_netid.find(':') {
                (&before_netid[..idx], Some(&before_netid[idx + 1..]))
            } else {
                (before_netid, None)
            }
        };

        name = name_part;

        // IP part
        if let Some(ipstr) = ip_part_opt {
            match ipstr.parse::<IpAddr>() {
                Ok(ipaddr) => ip = Some(ipaddr),
                Err(_) => return Err(NSError::InvalidParam(format!("Invalid ip addr: {}", ipstr))),
            }
        }

        // Record whether net_id is explicitly specified by user
        let net_id_explicit = net_id.is_some();

        // If IP is present but net_id is not, automatically set to wan
        if ip.is_some() && net_id.is_none() {
            net_id = Some("wan".to_string());
        }

        // Name cannot be empty
        if name.is_empty() {
            return Err(NSError::InvalidParam(
                "Name in OODDescriptionString is empty".to_string(),
            ));
        }

        Ok(OODDescriptionString {
            name: name.to_string(),
            node_type,
            net_id,
            ip,
        })
    }
}

impl Serialize for OODDescriptionString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let s = self.to_string().map_err(|e| {
            serde::ser::Error::custom(format!("Failed to serialize OODDescriptionString: {}", e))
        })?;
        serializer.serialize_str(&s)
    }
}

impl<'de> Deserialize<'de> for OODDescriptionString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(|e| {
            serde::de::Error::custom(format!("Failed to deserialize OODDescriptionString: {}", e))
        })
    }
}

//this config is store at DNS TXT record,and can be used to boot up the zone
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct ZoneBootConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<DID>,
    pub oods: Vec<OODDescriptionString>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sn: Option<String>,
    pub exp: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<DID>,
    #[serde(flatten)]
    pub extra_info: HashMap<String, serde_json::Value>,
    //------- The following fields are not serialized, but stored separately in TXT Records ------------

    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_key: Option<Jwk>, //PKX=0:xxxxxxx;

    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    //已经过时，但为了向下兼容，保留该字段
    pub gateway_devs: Vec<DID>,
    #[serde(skip_serializing)]
    #[serde(default)]
    //device name -> device config jwt,
    pub devices:HashMap<String, DeviceConfig>,
}

impl ZoneBootConfig {
    pub fn to_zone_config(&self) -> ZoneConfig {
        let mut result = ZoneConfig::new(
            self.id.clone().unwrap(),
            self.owner.clone().unwrap(),
            self.owner_key.clone().unwrap(),
        );
        result.init_by_boot_config(self);
        return result;
    }

    pub fn device_is_ood(&self,device_name: &str) -> bool {
        for ood in self.oods.iter() {
            if ood.name == device_name {
                if ood.node_type.is_ood() {
                    return true;
                }
            }
        }
        return false;
    }

    pub fn device_is_gateway(&self,device_name: &str) -> bool {
        for ood in self.oods.iter() {
            if ood.name == device_name {
                if ood.node_type.is_gateway() {
                    return true;
                }
            }
        }
        return false;
    }
    
    pub fn get_gateway_name(&self) -> String {
        for ood in self.oods.iter() {
            if ood.node_type.is_gateway() {
                return ood.name.clone();
            }
        }
        return "".to_string();
    }

    pub fn get_device_config(&self,device_name: &str) -> Option<&DeviceConfig> {
        return self.devices.get(device_name);
    }
    
}

impl DIDDocumentTrait for ZoneBootConfig {
    fn get_id(&self) -> DID {
        if self.id.is_some() {
            return self.id.clone().unwrap();
        }
        return DID::undefined();
    }

    fn get_auth_key(&self, kid: Option<&str>) -> Option<(DecodingKey, Jwk)> {
        if kid.is_none() {
            if self.owner_key.is_none() {
                return None;
            }
            let owner_key = self.owner_key.as_ref().unwrap().clone();
            let result_key = DecodingKey::from_jwk(&owner_key);
            if result_key.is_err() {
                error!(
                    "Failed to decode owner key: {:?}",
                    result_key.err().unwrap()
                );
                return None;
            }
            return Some((result_key.unwrap(), owner_key));
        }
        return None;
    }

    fn get_exchange_key(&self, kid: Option<&str>) -> Option<(DecodingKey, Jwk)> {
        let gateway_name = self.get_gateway_name();
        let device_config = self.devices.get(&gateway_name);
        if device_config.is_some() {
            let device_config = device_config.unwrap();
            return device_config.get_exchange_key(None);
        }
        
        if self.gateway_devs.is_empty() {
            return None;
        }
        warn!("get_exchange_key: use pkx1 to get exchange key,this is deprecated.please add device_config_jwt to your TXT record!");
        let did = self.gateway_devs[0].clone();
        let key = did.get_auth_key();
        if key.is_none() {
            return None;
        }
        return Some(key.unwrap());
    }

    fn get_iss(&self) -> Option<String> {
        return None;
    }

    fn get_exp(&self) -> Option<u64> {
        return Some(self.exp);
    }

    fn get_iat(&self) -> Option<u64> {
        return Some(self.exp - DEFUALT_EXPIRE_TIME);
    }

    fn encode(&self, key: Option<&EncodingKey>) -> NSResult<EncodedDocument> {
        if key.is_none() {
            return Err(NSError::Failed("No key provided".to_string()));
        }
        let key = key.unwrap();
        let mut header = Header::new(Algorithm::EdDSA);
        header.typ = None; // Default is JWT, set to None to save space
        let token = encode(&header, self, key).map_err(|error| {
            NSError::Failed(format!("Failed to encode zone boot config:{}", error))
        })?;
        return Ok(EncodedDocument::Jwt(token));
    }

    fn decode(doc: &EncodedDocument, key: Option<&DecodingKey>) -> NSResult<Self>
    where
        Self: Sized,
    {
        match doc {
            EncodedDocument::Jwt(jwt_str) => {
                let json_result: serde_json::Value;
                if key.is_none() {
                    json_result = decode_jwt_claim_without_verify(jwt_str)?;
                } else {
                    json_result = decode_json_from_jwt_with_pk(jwt_str, key.unwrap())?;
                }
                let result: ZoneBootConfig =
                    serde_json::from_value(json_result).map_err(|error| {
                        NSError::Failed(format!("Failed to decode device config:{}", error))
                    })?;
                return Ok(result);
            }
            EncodedDocument::JsonLd(json_value) => {
                let result: ZoneBootConfig =
                    serde_json::from_value(json_value.clone()).map_err(|error| {
                        NSError::Failed(format!("Failed to decode zone boot config:{}", error))
                    })?;
                return Ok(result);
            }
        }
    }
}

/*
How to use OODInfo & ZoneBootInfo

Before Node Boot(first time connected to system_config_service),ZoneBootInfo will help Node connect to system_config_service
Search in the following order, return the first found:
orders:
- looking for same LAN ood by udp broadcast
- looking for same LAN ood by tcp-scan (ipv4, Class C addresses, try up to 254 addresses)

After connection, obtain complete ZoneBootInfo by reading system_config (by integrating OOD's DeviceInfo)
Node Daemon will periodically refresh ZoneBootInfo. When unable to connect to any ood for a long time, it will return to the search process

Why don't others except node_daemon search for zone-boot-info?
    Fundamentally to control performance
    node_daemon passes the latest version of zone-boot-info it has to each service via environment variables at startup
    Each service periodically communicates with system_config to refresh the latest version of zone-boot-info
    If a service cannot connect to system_config for a long time, it should actively terminate the process to let node_daemon restart it

*/

pub struct OODInfo {
    pub address: Option<IpAddr>,
    pub net_id: Option<String>,
    pub last_connected_time: Option<u64>, //linux time stamp
}
pub struct ZoneBootInfo {
    //pub zone_boot_config: ZoneBootConfig,
    // oodid -> address
    pub ood_info: HashMap<String, OODInfo>,
}

impl ZoneBootInfo {
    pub fn new_by_boot_config(boot_config: &ZoneBootConfig) -> Self {
        ZoneBootInfo {
            ood_info: HashMap::new(),
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct VerifyHubInfo {
    pub port: u16,
    pub node_name: String,
    pub public_key: Jwk,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct ZoneConfig {
    #[serde(rename = "@context", default = "default_context")]
    pub context: String,
    pub id: DID,
    #[serde(rename = "verificationMethod")]
    verification_method: Vec<VerificationMethodNode>,
    authentication: Vec<String>,
    #[serde(rename = "assertionMethod")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    assertion_method: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    service: Vec<ServiceNode>,
    pub exp: u64,
    pub iat: u64,
    #[serde(flatten)]
    pub extra_info: HashMap<String, serde_json::Value>,

    //--------------------------------
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<DID>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>, //zone short name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_list: Option<HashMap<String, DID>>, //gateway device did list
    //ood server endpoints,can be ["ood1","ood2@192.168.32.1","ood3#vlan1]
    pub oods: Vec<String>,
    pub zone_gateway: Vec<String>,
    // Since all Gateways on Nodes are homogeneous, this may not need to be configured? The Gateway on whichever Node the DNS record resolves to is the ZoneGateway
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sn: Option<String>, //
    #[serde(skip_serializing_if = "Option::is_none")]
    pub docker_repo_base_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verify_hub_info: Option<VerifyHubInfo>,
}

impl ZoneConfig {
    pub fn new(id: DID, owner_did: DID, public_key: Jwk) -> Self {
        let id2 = id.clone();
        ZoneConfig {
            context: default_context(),
            id: id2,
            verification_method: vec![VerificationMethodNode {
                key_type: "Ed25519VerificationKey2020".to_string(),
                key_id: "#main_key".to_string(),
                key_controller: owner_did.to_string(),
                public_key: public_key,
                extra_info: HashMap::new(),
            }],
            authentication: vec!["#main_key".to_string()],
            assertion_method: vec!["#main_key".to_string()],
            service: vec![ServiceNode {
                id: format!("{}#lastDoc", id.to_string()),
                service_type: "DIDDoc".to_string(),
                service_endpoint: format!("https://{}/resolve/this_zone", id.to_host_name()),
            }],
            exp: buckyos_get_unix_timestamp() + 3600 * 24 * 365 * 10,
            iat: buckyos_get_unix_timestamp(),
            extra_info: HashMap::new(),
            owner: Some(owner_did),
            name: None,
            device_list: None,
            oods: vec![],
            zone_gateway: vec![],
            sn: None,
            docker_repo_base_url: None,
            verify_hub_info: None,
        }
    }

    pub fn load_zone_config(file_path: &PathBuf) -> NSResult<ZoneConfig> {
        let contents = std::fs::read_to_string(file_path.clone()).map_err(|err| {
            error!("read {} failed! {}", file_path.to_string_lossy(), err);
            return NSError::ReadLocalFileError(format!(
                "read {} failed! {}",
                file_path.to_string_lossy(),
                err
            ));
        })?;
        let config: ZoneConfig = serde_json::from_str(&contents).map_err(|err| {
            error!("parse {} failed! {}", file_path.to_string_lossy(), err);
            return NSError::ReadLocalFileError(format!(
                "Failed to parse ZoneConfig json: {}",
                err
            ));
        })?;
        Ok(config)
    }

    pub fn get_default_zone_gateway(&self) -> Option<String> {
        if self.zone_gateway.is_empty() {
            return None;
        }
        return Some(self.zone_gateway[0].clone());
    }

    pub fn init_by_boot_config(&mut self, boot_config: &ZoneBootConfig) {
        self.id = boot_config.id.clone().unwrap();
        self.oods = boot_config
            .oods
            .iter()
            .map(|ood| ood.to_string().unwrap_or_default())
            .collect();
        self.zone_gateway = boot_config
            .oods
            .iter()
            .map(|ood| ood.to_string().unwrap_or_default())
            .collect();
        self.sn = boot_config.sn.clone();
        self.exp = boot_config.exp;
        self.iat = self.exp - DEFUALT_EXPIRE_TIME;

        if boot_config.owner.is_some() {
            self.owner = Some(boot_config.owner.clone().unwrap());
        }
        if boot_config.owner_key.is_some() {
            self.verification_method[0].public_key = boot_config.owner_key.clone().unwrap();
        }
        self.extra_info.extend(boot_config.extra_info.clone());
    }

    pub fn get_zone_short_name(&self) -> String {
        if self.name.is_some() {
            return self.name.clone().unwrap();
        }
        let host_name = self.id.to_host_name();
        let short_name = host_name.split('.').next().unwrap();
        return short_name.to_string();
    }

    pub fn get_node_host_name(&self, node_name: &str) -> String {
        let zone_short_name = self.get_zone_short_name();
        let host_name = format!("{}-{}", zone_short_name, node_name);
        return host_name;
    }

    // OOD needs this information to establish connections with other OODs in the zone
    pub fn get_ood_desc_string(&self, node_name: &str) -> Option<String> {
        for ood in self.oods.iter() {
            if ood.starts_with(node_name) {
                return Some(ood.clone());
            }
        }
        return None;
    }

    pub fn select_same_subnet_ood(&self, device_info: &DeviceInfo) -> Option<String> {
        let mut ood_list = self.oods.clone();
        ood_list.shuffle(&mut rand::thread_rng());

        for ood in ood_list.iter() {
            let (device_name, net_id, ip) = DeviceInfo::get_net_info_from_ood_desc_string(ood);
            if net_id == device_info.net_id {
                return Some(ood.clone());
            }
        }

        return None;
    }

    pub fn select_wan_ood(&self) -> Option<String> {
        let mut ood_list = self.oods.clone();
        ood_list.shuffle(&mut rand::thread_rng());
        for ood in self.oods.iter() {
            let (device_name, net_id, ip) = DeviceInfo::get_net_info_from_ood_desc_string(ood);
            if net_id.is_some() {
                if net_id.as_ref().unwrap().starts_with("wan") {
                    return Some(ood.clone());
                }
            }
        }
        return None;
    }

    pub fn get_sn_api_url(&self) -> Option<String> {
        if self.sn.is_some() {
            return Some(format!("https://{}/kapi/sn", self.sn.as_ref().unwrap()));
        }
        return None;
    }

    fn get_default_service_port(&self, service_name: &str) -> Option<u16> {
        if service_name.starts_with("http") {
            return Some(80);
        } else if service_name.starts_with("https") {
            return Some(443);
        }
        return None;
    }

    pub fn get_default_key(&self) -> Option<Jwk> {
        for method in self.verification_method.iter() {
            if method.key_id == "#main_key" {
                return Some(method.public_key.clone());
            }
        }
        return None;
    }
}

impl DIDDocumentTrait for ZoneConfig {
    fn get_id(&self) -> DID {
        return self.id.clone();
    }

    fn get_auth_key(&self, kid: Option<&str>) -> Option<(DecodingKey, Jwk)> {
        if self.verification_method.is_empty() {
            return None;
        }
        if kid.is_none() {
            let decoding_key = DecodingKey::from_jwk(&self.verification_method[0].public_key);
            if decoding_key.is_err() {
                error!(
                    "Failed to decode auth key: {:?}",
                    decoding_key.err().unwrap()
                );
                return None;
            }
            return Some((
                decoding_key.unwrap(),
                self.verification_method[0].public_key.clone(),
            ));
        }
        let kid = kid.unwrap();
        for method in self.verification_method.iter() {
            if method.key_id == kid {
                let decoding_key = DecodingKey::from_jwk(&method.public_key);
                if decoding_key.is_err() {
                    error!(
                        "Failed to decode auth key: {:?}",
                        decoding_key.err().unwrap()
                    );
                    return None;
                }
                return Some((decoding_key.unwrap(), method.public_key.clone()));
            }
        }
        return None;
    }

    fn get_exchange_key(&self, kid: Option<&str>) -> Option<(DecodingKey, Jwk)> {
        if self.device_list.is_some() {
            let device_list = self.device_list.as_ref().unwrap();
            let did = device_list.get("gateway");
            if did.is_some() {
                let did = did.unwrap();
                let key = did.get_auth_key();
                return key;
            }
        }
        return None;
    }

    fn get_iss(&self) -> Option<String> {
        if self.owner.is_some() {
            return Some(self.owner.as_ref().unwrap().to_string());
        }
        return None;
    }
    fn get_exp(&self) -> Option<u64> {
        return Some(self.exp);
    }

    fn get_iat(&self) -> Option<u64> {
        return Some(self.iat);
    }

    fn encode(&self, key: Option<&EncodingKey>) -> NSResult<EncodedDocument> {
        if key.is_none() {
            return Err(NSError::Failed("No key provided".to_string()));
        }
        let key = key.unwrap();
        let mut header = Header::new(Algorithm::EdDSA);
        header.typ = None; // Default is JWT, set to None to save space
        let token = encode(&header, self, key)
            .map_err(|error| NSError::Failed(format!("Failed to encode zone config:{}", error)))?;
        return Ok(EncodedDocument::Jwt(token));
    }

    fn decode(doc: &EncodedDocument, key: Option<&DecodingKey>) -> NSResult<Self>
    where
        Self: Sized,
    {
        match doc {
            EncodedDocument::Jwt(jwt_str) => {
                let json_result: serde_json::Value;
                if key.is_none() {
                    json_result = decode_jwt_claim_without_verify(jwt_str)?;
                } else {
                    json_result = decode_json_from_jwt_with_pk(jwt_str, key.unwrap())?;
                }
                let result: ZoneConfig = serde_json::from_value(json_result).map_err(|error| {
                    NSError::Failed(format!("Failed to decode zone config:{}", error))
                })?;
                return Ok(result);
            }
            EncodedDocument::JsonLd(json_value) => {
                let result: ZoneConfig =
                    serde_json::from_value(json_value.clone()).map_err(|error| {
                        NSError::Failed(format!("Failed to decode zone config:{}", error))
                    })?;
                return Ok(result);
            }
        }
    }
    // async fn decode_with_load_key<'a, F, Fut>(doc: &'a EncodedDocument,loader:F) -> NSResult<Self>
    //     where Self: Sized,
    //           F: Fn(&'a str) -> Fut,
    //           Fut: std::future::Future<Output = NSResult<DecodingKey>> {
    //     unimplemented!()
    // }
}


#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct OwnerConfig {
    #[serde(rename = "@context", default = "default_context")]
    pub context: String,
    pub id: DID,
    #[serde(rename = "verificationMethod")]
    verification_method: Vec<VerificationMethodNode>,
    authentication: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    assertion_method: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    service: Vec<ServiceNode>,
    pub exp: u64,
    pub iat: u64,
    #[serde(flatten)]
    pub extra_info: HashMap<String, serde_json::Value>,

    //--------------------------------
    pub name: String,
    pub full_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_zone_did: Option<DID>,
}

impl OwnerConfig {
    pub fn new(id: DID, name: String, full_name: String, public_key: Jwk) -> Self {
        let verification_method = vec![VerificationMethodNode {
            key_type: "Ed25519VerificationKey2020".to_string(),
            key_id: "#main_key".to_string(),
            key_controller: id.to_string(),
            public_key: public_key,
            extra_info: HashMap::new(),
        }];

        OwnerConfig {
            context: default_context(),
            id: id,
            name: name,
            full_name: full_name,
            verification_method: verification_method,
            authentication: vec!["#main_key".to_string()],
            assertion_method: vec!["#main_key".to_string()],
            default_zone_did: None,
            exp: buckyos_get_unix_timestamp() + 3600 * 24 * 365 * 10,
            iat: buckyos_get_unix_timestamp(),
            extra_info: HashMap::new(),
            service: vec![],
        }
    }

    pub fn set_default_zone_did(&mut self, default_zone_did: DID) {
        self.default_zone_did = Some(default_zone_did.clone());
        self.service.push(ServiceNode {
            id: format!("{}#lastDoc", self.id.to_string()),
            service_type: "DIDDoc".to_string(),
            service_endpoint: format!(
                "https://{}/resolve/{}",
                default_zone_did.to_host_name(),
                self.id.to_string()
            ),
        });
    }

    pub fn load_owner_config(file_path: &PathBuf) -> NSResult<OwnerConfig> {
        let contents = std::fs::read_to_string(file_path.clone()).map_err(|err| {
            error!("read {} failed! {}", file_path.to_string_lossy(), err);
            return NSError::ReadLocalFileError(format!(
                "read {} failed! {}",
                file_path.to_string_lossy(),
                err
            ));
        })?;
        let config: OwnerConfig = serde_json::from_str(&contents).map_err(|err| {
            error!("parse {} failed! {}", file_path.to_string_lossy(), err);
            return NSError::ReadLocalFileError(format!(
                "Failed to parse OwnerConfig json: {}",
                err
            ));
        })?;
        Ok(config)
    }

    pub fn get_default_zone_did(&self) -> Option<DID> {
        return self.default_zone_did.clone();
    }

    pub fn get_default_key(&self) -> Option<Jwk> {
        for method in self.verification_method.iter() {
            if method.key_id == "#main_key" {
                return Some(method.public_key.clone());
            }
        }
        return None;
    }
}

impl DIDDocumentTrait for OwnerConfig {
    fn get_id(&self) -> DID {
        return self.id.clone();
    }
    fn get_auth_key(&self, kid: Option<&str>) -> Option<(DecodingKey, Jwk)> {
        if self.verification_method.is_empty() {
            return None;
        }
        if kid.is_none() {
            let decoding_key = DecodingKey::from_jwk(&self.verification_method[0].public_key);
            if decoding_key.is_err() {
                error!(
                    "Failed to decode auth key: {:?}",
                    decoding_key.err().unwrap()
                );
                return None;
            }
            return Some((
                decoding_key.unwrap(),
                self.verification_method[0].public_key.clone(),
            ));
        }
        let kid = kid.unwrap();
        for method in self.verification_method.iter() {
            if method.key_id == kid {
                let decoding_key = DecodingKey::from_jwk(&method.public_key);
                if decoding_key.is_err() {
                    error!(
                        "Failed to decode auth key: {:?}",
                        decoding_key.err().unwrap()
                    );
                    return None;
                }
                return Some((decoding_key.unwrap(), method.public_key.clone()));
            }
        }
        return None;
    }

    fn get_exchange_key(&self, kid: Option<&str>) -> Option<(DecodingKey, Jwk)> {
        //return default zone's exchange key
        return None;
    }

    fn get_iss(&self) -> Option<String> {
        return None;
    }
    fn get_exp(&self) -> Option<u64> {
        return Some(self.exp);
    }
    fn get_iat(&self) -> Option<u64> {
        return Some(self.iat);
    }

    fn encode(&self, key: Option<&EncodingKey>) -> NSResult<EncodedDocument> {
        if key.is_none() {
            return Err(NSError::Failed("No key provided".to_string()));
        }
        let key = key.unwrap();
        let mut header = Header::new(Algorithm::EdDSA);
        header.typ = None; // Default is JWT, set to None to save space
        let token = encode(&header, self, key)
            .map_err(|error| NSError::Failed(format!("Failed to encode OwnerConfig :{}", error)))?;
        return Ok(EncodedDocument::Jwt(token));
    }

    fn decode(doc: &EncodedDocument, key: Option<&DecodingKey>) -> NSResult<Self>
    where
        Self: Sized,
    {
        match doc {
            EncodedDocument::Jwt(jwt_str) => {
                let json_result: serde_json::Value;
                if key.is_none() {
                    json_result = decode_jwt_claim_without_verify(jwt_str)?;
                } else {
                    json_result = decode_json_from_jwt_with_pk(jwt_str, key.unwrap())?;
                }
                let result: OwnerConfig = serde_json::from_value(json_result).map_err(|error| {
                    NSError::Failed(format!("Failed to decode owner config:{}", error))
                })?;
                return Ok(result);
            }
            EncodedDocument::JsonLd(json_value) => {
                let result: OwnerConfig =
                    serde_json::from_value(json_value.clone()).map_err(|error| {
                        NSError::Failed(format!("Failed to decode owner config:{}", error))
                    })?;
                return Ok(result);
            }
        }
    }
    // async fn decode_with_load_key<'a, F, Fut>(doc: &'a EncodedDocument,loader:F) -> NSResult<Self>
    //     where Self: Sized,
    //           F: Fn(&'a str) -> Fut,
    //           Fut: std::future::Future<Output = NSResult<DecodingKey>> {
    //     unimplemented!()
    // }
}



// unit tests that depend on external crates are behind an opt-in feature

mod tests {
    use super::super::*;
    use super::*;

    use serde::de;
    use serde_json::json;
    use std::{
        alloc::System,
        hash::Hash,
        time::{SystemTime, UNIX_EPOCH},
    };

    //     #[tokio::test]
    //     async fn test_all_dev_env_configs() {
    //         let tmp_dir = std::env::temp_dir().join(".buckycli");
    //         std::fs::create_dir_all(tmp_dir.clone()).unwrap();
    //         println!(
    //             "# all BuckyOS dev test config files will be saved in: {:?}",
    //             tmp_dir
    //         );
    //         // This test will create all test files for the development environment in the tmp directory and output DNS record information to the console.
    //         let now = 1743478939; //2025-04-01
    //         let exp = now + 3600 * 24 * 365 * 10; //2035-04-01
    //         let owner_private_key_pem = r#"
    // -----BEGIN PRIVATE KEY-----
    // MC4CAQAwBQYDK2VwBCIEIJBRONAzbwpIOwm0ugIQNyZJrDXxZF7HoPWAZesMedOr
    // -----END PRIVATE KEY-----
    //         "#;
    //         let user_key_path = tmp_dir.join("user_private_key.pem");
    //         std::fs::write(user_key_path.clone(), owner_private_key_pem).unwrap();
    //         println!(
    //             "# user private key write to file: {}",
    //             user_key_path.to_string_lossy()
    //         );
    //         let owner_jwk = json!(
    //             {
    //                 "kty": "OKP",
    //                 "crv": "Ed25519",
    //                 "x": "T4Quc1L6Ogu4N2tTKOvneV1yYnBcmhP89B_RsuFsJZ8"
    //             }
    //         );
    //         let owner_jwk: jsonwebtoken::jwk::Jwk = serde_json::from_value(owner_jwk.clone()).unwrap();
    //         let owner_private_key: EncodingKey =
    //             EncodingKey::from_ed_pem(owner_private_key_pem.as_bytes()).unwrap();

    //         let mut owner_config = OwnerConfig::new(
    //             DID::new("bns", "devtest"),
    //             "devtest".to_string(),
    //             "zhicong liu".to_string(),
    //             owner_jwk.clone(),
    //         );
    //         let owner_config_json_str = serde_json::to_string_pretty(&owner_config).unwrap();
    //         let owner_config_path = tmp_dir.join("user_config.json");
    //         std::fs::write(owner_config_path.clone(), owner_config_json_str.clone()).unwrap();
    //         println!("owner config: {}", owner_config_json_str);
    //         println!(
    //             "# owner config write to file: {}",
    //             owner_config_path.to_string_lossy()
    //         );

    //         let device_private_key_pem = r#"
    // -----BEGIN PRIVATE KEY-----
    // MC4CAQAwBQYDK2VwBCIEIMDp9endjUnT2o4ImedpgvhVFyZEunZqG+ca0mka8oRp
    // -----END PRIVATE KEY-----
    //         "#;
    //         let private_key_path = tmp_dir.join("node_private_key.pem");
    //         std::fs::write(private_key_path.clone(), device_private_key_pem).unwrap();
    //         println!(
    //             "# device ood1 private key write to file: {}",
    //             private_key_path.to_string_lossy()
    //         );
    //         let ood1_jwk = json!(
    //             {
    //                 "kty": "OKP",
    //                 "crv": "Ed25519",
    //                 "x": "gubVIszw-u_d5PVTh-oc8CKAhM9C-ne5G_yUK5BDaXc"
    //               }
    //         );
    //         let ood1_jwk: jsonwebtoken::jwk::Jwk = serde_json::from_value(ood1_jwk.clone()).unwrap();
    //         let mut ood1_device_config = DeviceConfig::new_by_jwk("ood1", ood1_jwk.clone());

    //         ood1_device_config.support_container = true;
    //         // #[cfg(all(target_os = "linux"))]
    //         // {
    //         //     ood1_device_config.support_container = true;
    //         // }

    //         ood1_device_config.iss = "did:bns:devtest".to_string();
    //         let ood1_device_config_json_str =
    //             serde_json::to_string_pretty(&ood1_device_config).unwrap();
    //         println!("ood1 device config: {}", ood1_device_config_json_str);
    //         let device_jwt = ood1_device_config.encode(Some(&owner_private_key)).unwrap();
    //         println!("ood1 device jwt: {}", device_jwt.to_string());
    //         let deocode_key = DecodingKey::from_jwk(&owner_jwk).unwrap();
    //         let decode_ood_config = DeviceConfig::decode(&device_jwt, Some(&deocode_key)).unwrap();
    //         assert_eq!(ood1_device_config, decode_ood_config);

    //         let encode_key = EncodingKey::from_ed_pem(device_private_key_pem.as_bytes()).unwrap();
    //         let decode_key = DecodingKey::from_jwk(&ood1_jwk).unwrap();
    //         let ood_jwt2 = ood1_device_config.encode(Some(&encode_key)).unwrap();
    //         let decode_ood_config = DeviceConfig::decode(&ood_jwt2, Some(&decode_key)).unwrap();
    //         assert_eq!(ood1_device_config, decode_ood_config);

    //         let zone_boot_config = ZoneBootConfig {
    //             id: None,
    //             oods: vec!["ood1".to_string()],
    //             sn: None,
    //             exp: exp,
    //             iat: now as u32,
    //             owner: None,
    //             owner_key: None,
    //             gateway_devs: vec![],
    //             extra_info: HashMap::new(),
    //         };
    //         let zone_boot_config_json_str = serde_json::to_string_pretty(&zone_boot_config).unwrap();
    //         println!("zone boot config: {}", zone_boot_config_json_str.as_str());

    //         let zone_boot_config_path = tmp_dir.join(format!(
    //             "{}.zone.json",
    //             DID::new("web", "test.buckyos.io").to_host_name()
    //         ));
    //         std::fs::write(
    //             zone_boot_config_path.clone(),
    //             zone_boot_config_json_str.clone(),
    //         )
    //         .unwrap();
    //         println!(
    //             "# zone boot config write to file: {}",
    //             zone_boot_config_path.to_string_lossy()
    //         );
    //         let zone_boot_config_jwt = zone_boot_config.encode(Some(&owner_private_key)).unwrap();

    //         let mut zone_config = ZoneConfig::new(
    //             DID::new("web", "test.buckyos.io"),
    //             DID::new("bns", "devtest"),
    //             owner_jwk.clone(),
    //         );
    //         zone_config.init_by_boot_config(&zone_boot_config);
    //         let zone_config_json_str = serde_json::to_string_pretty(&zone_config).unwrap();
    //         println!("zone config: {}", zone_config_json_str.as_str());
    //         let zone_config_path = tmp_dir.join("zone_config.json");
    //         std::fs::write(zone_config_path.clone(), zone_config_json_str.clone()).unwrap();
    //         println!(
    //             " zone config write to file: {}",
    //             zone_config_path.to_string_lossy()
    //         );
    //         println!(
    //             "# zone config generated by zone boot config will store at {}",
    //             zone_config_path.to_string_lossy()
    //         );

    //         let node_identity_config = NodeIdentityConfig {
    //             zone_did: DID::new("web", "test.buckyos.io"),
    //             owner_public_key: owner_jwk.clone(),
    //             owner_did: DID::new("bns", "devtest"),
    //             device_doc_jwt: device_jwt.to_string(),
    //             zone_iat: now as u32,
    //         };
    //         let node_identity_config_json_str =
    //             serde_json::to_string_pretty(&node_identity_config).unwrap();
    //         println!(
    //             "node identity config: {}",
    //             node_identity_config_json_str.as_str()
    //         );
    //         let node_identity_config_path = tmp_dir.join("node_identity.json");
    //         std::fs::write(
    //             node_identity_config_path.clone(),
    //             node_identity_config_json_str.clone(),
    //         )
    //         .unwrap();
    //         println!(
    //             "# node identity config will store at {}",
    //             node_identity_config_path.to_string_lossy()
    //         );

    //         //build start_config.json
    //         let start_config = json!(
    //             {
    //                 "admin_password_hash":"o8XyToejrbCYou84h/VkF4Tht0BeQQbuX3XKG+8+GQ4=",//bucky2025
    //                 "device_private_key":device_private_key_pem,
    //                 "device_public_key":ood1_jwk,
    //                 "friend_passcode":"sdfsdfsdf",
    //                 "gateway_type":"PortForward",
    //                 "guest_access":true,
    //                 "private_key":owner_private_key_pem,
    //                 "public_key":owner_jwk,
    //                 "user_name":"devtest",
    //                 "zone_name":"test.buckyos.io",
    //                 "BUCKYOS_ROOT":"/opt/buckyos"
    //             }
    //         );
    //         let start_config_json_str = serde_json::to_string_pretty(&start_config).unwrap();
    //         println!("start config: {}", start_config_json_str.as_str());
    //         let start_config_path = tmp_dir.join("start_config.json");
    //         std::fs::write(start_config_path.clone(), start_config_json_str.clone()).unwrap();
    //         println!(
    //             "# start_config will store at {}",
    //             start_config_path.to_string_lossy()
    //         );

    //         println!(
    //             "# test.buckyos.io TXT Record: DID={};",
    //             zone_boot_config_jwt.to_string()
    //         );
    //         let owner_x = get_x_from_jwk(&owner_jwk).unwrap();
    //         let ood_x = get_x_from_jwk(&ood1_jwk).unwrap();
    //         println!(
    //             "# test.buckyos.io TXT Record: PKX=0:{};",
    //             owner_x.to_string()
    //         );
    //         println!("# test.buckyos.io TXT Record: PKX=1:{};", ood_x.to_string());
    //     }

    async fn create_test_zone_config(
        user_did: DID,
        username: &str,
        owner_private_key_pem: &str,
        owner_jwk: serde_json::Value,
        zone_did: DID,
        sn_host: Option<String>,
    ) -> String {
        let tmp_dir = std::env::temp_dir()
            .join("buckyos_dev_configs")
            .join(username.to_string());
        std::fs::create_dir_all(tmp_dir.clone()).unwrap();
        println!(
            "# all BuckyOS dev test config files will be saved in: {:?}",
            tmp_dir
        );
        // This test will create all test files for the development environment in the tmp directory and output DNS record information to the console.
        let now = 1743478939; //2025-04-01
        let exp = now + 3600 * 24 * 365 * 10; //2035-04-01

        let user_key_path = tmp_dir.join("user_private_key.pem");
        std::fs::write(user_key_path.clone(), owner_private_key_pem).unwrap();
        println!(
            "# user private key write to file: {}",
            user_key_path.to_string_lossy()
        );

        let owner_jwk: jsonwebtoken::jwk::Jwk = serde_json::from_value(owner_jwk.clone()).unwrap();
        let owner_private_key: EncodingKey =
            EncodingKey::from_ed_pem(owner_private_key_pem.as_bytes()).unwrap();

        let mut owner_config = OwnerConfig::new(
            user_did.clone(),
            username.to_string(),
            username.to_string(),
            owner_jwk.clone(),
        );
        let owner_config_json_str = serde_json::to_string_pretty(&owner_config).unwrap();
        let owner_config_path = tmp_dir.join("user_config.json");
        std::fs::write(owner_config_path.clone(), owner_config_json_str.clone()).unwrap();
        println!("{}'s owner config: {}", username, owner_config_json_str);
        println!(
            "# owner config write to file: {}",
            owner_config_path.to_string_lossy()
        );

        let zone_boot_config = ZoneBootConfig {
            id: None,
            oods: vec!["ood1".parse().unwrap()],
            sn: sn_host,
            exp: exp,
            owner: None,
            owner_key: None,
            devices: HashMap::new(),
            gateway_devs: vec![],
            extra_info: HashMap::new(),
        };
        let zone_boot_config_json_str = serde_json::to_string_pretty(&zone_boot_config).unwrap();
        println!("zone boot config: {}", zone_boot_config_json_str.as_str());

        let zone_boot_config_path = tmp_dir.join(format!("{}.zone.json", zone_did.to_host_name()));
        std::fs::write(
            zone_boot_config_path.clone(),
            zone_boot_config_json_str.clone(),
        )
        .unwrap();
        println!(
            "# zone boot config write to file: {}",
            zone_boot_config_path.to_string_lossy()
        );
        let zone_boot_config_jwt = zone_boot_config.encode(Some(&owner_private_key)).unwrap();

        let zone_host_name = zone_did.to_host_name();
        println!(
            "# {} TXT Record: DID={};",
            zone_host_name,
            zone_boot_config_jwt.to_string()
        );
        let owner_x = get_x_from_jwk(&owner_jwk).unwrap();
        //let ood_x = get_x_from_jwk(&ood1_jwk).unwrap();
        println!(
            "# {} TXT Record: PKX=0:{};",
            zone_host_name,
            owner_x.to_string()
        );
        return zone_boot_config_jwt.to_string();
        //println!("# {} TXT Record: PKX=1:{};",zone_host_name,ood_x.to_string());
    }

    async fn create_test_node_config(
        user_did: DID,
        username: &str,
        owner_private_key_pem: &str,
        owner_jwk: serde_json::Value,
        zone_did: DID,
        device_name: &str,
        device_private_key_pem: &str,
        device_public_key: serde_json::Value,
        is_wan: bool,
    ) -> String {
        let now = 1743478939; //2025-04-01
        let exp = now + 3600 * 24 * 365 * 10; //2035-04-01
        let owner_private_key: EncodingKey =
            EncodingKey::from_ed_pem(owner_private_key_pem.as_bytes()).unwrap();
        let owner_jwk: jsonwebtoken::jwk::Jwk = serde_json::from_value(owner_jwk.clone()).unwrap();

        let tmp_dir = std::env::temp_dir()
            .join("buckyos_dev_configs")
            .join(username)
            .join(device_name.to_string());
        std::fs::create_dir_all(tmp_dir.clone()).unwrap();
        println!(
            "# all BuckyOS dev test config files will be saved in: {:?}",
            tmp_dir
        );

        let private_key_path = tmp_dir.join("node_private_key.pem");
        std::fs::write(private_key_path.clone(), device_private_key_pem).unwrap();
        println!(
            "# device {} private key write to file: {}",
            device_name,
            private_key_path.to_string_lossy()
        );

        let device_jwk: jsonwebtoken::jwk::Jwk =
            serde_json::from_value(device_public_key.clone()).unwrap();
        let mut device_config = DeviceConfig::new_by_jwk(device_name, device_jwk.clone());

        device_config.support_container = true;
        if is_wan {
            device_config.net_id = Some("wan".to_string());
        }

        device_config.iss = user_did.to_string();
        let device_config_json_str = serde_json::to_string_pretty(&device_config).unwrap();
        println!("device config: {}", device_config_json_str);

        let device_jwt = device_config.encode(Some(&owner_private_key)).unwrap();
        println!(" device {} jwt: {}", device_name, device_jwt.to_string());

        let encode_key = EncodingKey::from_ed_pem(owner_private_key_pem.as_bytes()).unwrap();
        let decode_key = DecodingKey::from_jwk(&owner_jwk).unwrap();
        let device_jwt2 = device_config.encode(Some(&encode_key)).unwrap();
        let decode_device_config = DeviceConfig::decode(&device_jwt2, Some(&decode_key)).unwrap();
        assert_eq!(device_config, decode_device_config);

        let node_identity_config = NodeIdentityConfig {
            zone_did: zone_did.clone(),
            owner_public_key: owner_jwk.clone(),
            owner_did: user_did,
            device_doc_jwt: device_jwt.to_string(),
            zone_iat: now as u32,
        };
        let node_identity_config_json_str =
            serde_json::to_string_pretty(&node_identity_config).unwrap();
        println!(
            "node identity config: {}",
            node_identity_config_json_str.as_str()
        );
        let node_identity_config_path = tmp_dir.join("node_identity.json");
        std::fs::write(
            node_identity_config_path.clone(),
            node_identity_config_json_str.clone(),
        )
        .unwrap();
        println!(
            "# node identity config will store at {}",
            node_identity_config_path.to_string_lossy()
        );

        //build start_config.json
        if device_name.starts_with("ood") {
            let start_config = json!(
                {
                    "admin_password_hash":"o8XyToejrbCYou84h/VkF4Tht0BeQQbuX3XKG+8+GQ4=",//bucky2025
                    "device_private_key":device_private_key_pem,
                    "device_public_key":device_jwk,
                    "friend_passcode":"sdfsdfsdf",
                    "gateway_type":"PortForward",
                    "guest_access":true,
                    "private_key":owner_private_key_pem,
                    "public_key":owner_jwk,
                    "user_name":username,
                    "zone_name":zone_did.to_host_name(),
                    "BUCKYOS_ROOT":"/opt/buckyos"
                }
            );
            let start_config_json_str = serde_json::to_string_pretty(&start_config).unwrap();
            println!("start config: {}", start_config_json_str.as_str());
            let start_config_path = tmp_dir.join("start_config.json");
            std::fs::write(start_config_path.clone(), start_config_json_str.clone()).unwrap();
            println!(
                "# start_config will store at {}",
                start_config_path.to_string_lossy()
            );
        }

        return device_jwt2.to_string();
    }

    //     async fn create_test_sn_config() {
    //         let sn_server_ip = "192.168.1.188";
    //         let sn_server_host = "buckyos.io";
    //         let now = 1743478939; //2025-04-01
    //         let exp = now + 3600 * 24 * 365 * 10; //2035-04-01
    //         let tmp_dir = std::env::temp_dir()
    //             .join("buckyos_dev_configs")
    //             .join("sn_server");
    //         std::fs::create_dir_all(tmp_dir.clone()).unwrap();
    //         //create test sn zone_boot_config
    //         let test_sn_zone_owner_private_key = r#"
    // -----BEGIN PRIVATE KEY-----
    // MC4CAQAwBQYDK2VwBCIEIH3hgzhuE0wuR+OEz0Bx6I+YrJDtS0OIajH1rNkEfxnl
    // -----END PRIVATE KEY-----
    //         "#;
    //         let test_sn_zone_owner_public_key = json!({
    //             "crv":"Ed25519",
    //             "kty":"OKP",
    //             "x":"qJdNEtscIYwTo-I0K7iPEt_UZdBDRd4r16jdBfNR0tM"
    //         });
    //         let owner_private_key: EncodingKey =
    //             EncodingKey::from_ed_pem(test_sn_zone_owner_private_key.as_bytes()).unwrap();
    //         let x_str = test_sn_zone_owner_public_key.get("x").unwrap().as_str();
    //         //create test sn device_key_pair

    //         let test_sn_device_private_key = r#"
    // -----BEGIN PRIVATE KEY-----
    // MC4CAQAwBQYDK2VwBCIEIBvnIIa1Tx45SjRu9kBZuMgusP5q762SvojXZ4scFxVD
    // -----END PRIVATE KEY-----
    //         "#;
    //         let test_sn_device_public_key = json!({
    //             "crv":"Ed25519",
    //             "kty":"OKP",
    //             "x":"FPvY3WXPxuWPYFuwOY0Qbh0O7-hhKr6ta1jTcX9ORPI"
    //         });
    //         let private_key_path = tmp_dir.join("device_key.pem");
    //         std::fs::write(private_key_path.clone(), test_sn_device_private_key).unwrap();
    //         println!(
    //             "# device key write to file: {}",
    //             private_key_path.to_string_lossy()
    //         );
    //         let zone_boot_config = ZoneBootConfig {
    //             id: None,
    //             oods: vec!["ood1".to_string()],
    //             sn: None,
    //             exp: exp,
    //             iat: now as u32,
    //             owner: None,
    //             owner_key: None,
    //             gateway_devs: vec![],
    //             extra_info: HashMap::new(),
    //         };
    //         let zone_boot_config_json_str = serde_json::to_string_pretty(&zone_boot_config).unwrap();
    //         //println!("zone boot config: {}",zone_boot_config_json_str.as_str());

    //         let zone_boot_config_jwt = zone_boot_config.encode(Some(&owner_private_key)).unwrap();
    //         let zone_boot_config_jwt_str = zone_boot_config_jwt.to_string();
    //         let config = json!({
    //             "device_name":"web3_gateway",
    //             "device_key_path":"/opt/web3_bridge/device_key.pem",
    //             "inner_services":{
    //                 "main_sn" : {
    //                     "type" : "cyfs-sn",
    //                     "host":format!("web3.{}",sn_server_host),
    //                     "aliases":vec![format!("sn.{}",sn_server_host)],
    //                     "ip":sn_server_ip,
    //                     "zone_config_jwt":zone_boot_config_jwt_str,
    //                     "zone_config_pkx":x_str

    //                 },
    //                 "zone_provider" : {
    //                     "type" : "zone-provider"
    //                 }
    //             },
    //             "servers":{
    //                 "main_http_server":{
    //                     "type":"cyfs-warp",
    //                     "bind":"0.0.0.0",
    //                     "http_port":80,
    //                     "tls_port":443,
    //                     "default_tls_host":format!("*.{}",sn_server_host),
    //                     "hosts": {
    //                         format!("web3.{}",sn_server_host): {
    //                             "tls": {
    //                                 "disable_tls": true,
    //                                 "enable_acme": false
    //                             },
    //                             "enable_cors":true,
    //                             "routes": {
    //                                 "/kapi/sn":{
    //                                     "inner_service":"main_sn"
    //                                 }
    //                             }
    //                         },
    //                         format!("*.web3.{}",sn_server_host): {
    //                             "tls": {
    //                                 "disable_tls": true
    //                             },
    //                             "routes": {
    //                                 "/":{
    //                                     "tunnel_selector":"main_sn"
    //                                 }
    //                             }
    //                         },
    //                         "*":{
    //                             "routes": {
    //                                 "/":{
    //                                     "tunnel_selector":"main_sn"
    //                                 },
    //                                 "/resolve":{
    //                                     "inner_service":"zone_provider"
    //                                 }
    //                             }
    //                         }
    //                     }
    //                 },
    //                 "main_dns_server":{
    //                     "type":"cyfs-dns",
    //                     "bind":"0.0.0.0",
    //                     "port":53,
    //                     "this_name":format!("sn.{}",sn_server_host),
    //                     "resolver_chain": [
    //                         {
    //                           "type": "SN",
    //                           "server_id": "main_sn"
    //                         },
    //                         {
    //                             "type": "dns",
    //                             "cache": true
    //                         }
    //                     ],
    //                     "fallback": ["8.8.8.8","6.6.6.6"]
    //                 }
    //             },

    //             "dispatcher" : {
    //                 "udp://0.0.0.0:53":{
    //                     "type":"server",
    //                     "id":"main_dns_server"
    //                 },
    //                 "tcp://0.0.0.0:80":{
    //                     "type":"server",
    //                     "id":"main_http_server"
    //                 },
    //                 "tcp://0.0.0.0:443":{
    //                     "type":"server",
    //                     "id":"main_http_server"
    //                 }
    //             }
    //         });

    //         let config_path = tmp_dir.join("web3_gateway.json");
    //         let config_str = serde_json::to_string_pretty(&config).unwrap();
    //         println!("# web3 gateway config: {}", config_str.as_str());
    //         std::fs::write(config_path.clone(), config_str.as_str()).unwrap();
    //         println!(
    //             "# web3 gateway config write to file: {}",
    //             config_path.to_string_lossy()
    //         );
    //     }

    //     #[tokio::test]
    //     async fn create_test_env_configs() {
    //         let mut test_web3_bridge = HashMap::new();
    //         test_web3_bridge.insert("bns".to_string(), "web3.buckyos.io".to_string());
    //         KNOWN_WEB3_BRIDGE_CONFIG.set(test_web3_bridge.clone());

    //         let devtest_private_key_pem = r#"
    // -----BEGIN PRIVATE KEY-----
    // MC4CAQAwBQYDK2VwBCIEIJBRONAzbwpIOwm0ugIQNyZJrDXxZF7HoPWAZesMedOr
    // -----END PRIVATE KEY-----
    //         "#;

    //         let devtest_owner_jwk = json!(
    //             {
    //                 "kty": "OKP",
    //                 "crv": "Ed25519",
    //                 "x": "T4Quc1L6Ogu4N2tTKOvneV1yYnBcmhP89B_RsuFsJZ8"
    //             }
    //         );

    //         let devtest_node1_private_key = r#"
    // -----BEGIN PRIVATE KEY-----
    // MC4CAQAwBQYDK2VwBCIEICwMZt1W7P/9v3Iw/rS2RdziVkF7L+o5mIt/WL6ef/0w
    // -----END PRIVATE KEY-----"#;
    //         let devtest_node1_public_key = json!(
    //             {
    //                 "crv":"Ed25519",
    //                 "kty":"OKP",
    //                 "x":"Bb325f2ed0XSxrPS5sKQaX7ylY9Jh9rfevXiidKA1zc"
    //             }
    //         );

    //         create_test_node_config(
    //             DID::new("bns", "devtest"),
    //             "devtest",
    //             devtest_private_key_pem,
    //             devtest_owner_jwk.clone(),
    //             DID::new("bns", "devtest"),
    //             "node1",
    //             devtest_node1_private_key,
    //             devtest_node1_public_key,
    //             false,
    //         )
    //         .await;

    //         //create bob (nodeB1) config
    //         let bob_private_key = r#"
    // -----BEGIN PRIVATE KEY-----
    // MC4CAQAwBQYDK2VwBCIEILQLoUZt2okCht0UVhsf4UlGAV9h3BoliwZQN5zBO1G+
    // -----END PRIVATE KEY-----"#;
    //         let bob_public_key = json!(
    //             {
    //                 "crv":"Ed25519",
    //                 "kty":"OKP",
    //                 "x":"y-kuJcQ0doFpdNXf4HI8E814lK8MB3-t4XjDRcR_QCU"
    //             }
    //         );
    //         let bob_public_key_str = serde_json::to_string(&bob_public_key).unwrap();

    //         let bob_zone_jwt = create_test_zone_config(
    //             DID::new("bns", "bobdev"),
    //             "bobdev",
    //             bob_private_key,
    //             bob_public_key.clone(),
    //             DID::new("bns", "bob"),
    //             Some("sn.buckyos.io".to_string()),
    //         )
    //         .await;
    //         let bob_ood1_private_key = r#"
    // -----BEGIN PRIVATE KEY-----
    // MC4CAQAwBQYDK2VwBCIEIADmO0+u/gcmStDsHZOZCM5gxNYlQmP6jpMo279TQE75
    // -----END PRIVATE KEY-----"#;
    //         let bob_ood1_public_key = json!(
    //             {
    //                 "crv":"Ed25519",
    //                 "kty":"OKP",
    //                 "x":"iSMKakFEGzGAxLTlaB5TkqZ6d4wurObr-BpaQleoE2M"
    //             }
    //         );
    //         let bob_ood1_did = DID::new("dev", "iSMKakFEGzGAxLTlaB5TkqZ6d4wurObr-BpaQleoE2M");
    //         let bob_ood1_device_jwt = create_test_node_config(
    //             DID::new("bns", "bobdev"),
    //             "bobdev",
    //             bob_private_key,
    //             bob_public_key.clone(),
    //             DID::new("bns", "bob"),
    //             "ood1",
    //             bob_ood1_private_key,
    //             bob_ood1_public_key,
    //             false,
    //         )
    //         .await;

    //         //create sn db
    //         create_test_sn_config().await;

    //         let tmp_dir = std::env::temp_dir().join("buckyos_dev_configs");

    //         let sn_db_path = tmp_dir.join("sn_db.sqlite3");
    //         //delete first
    //         if sn_db_path.exists() {
    //             std::fs::remove_file(sn_db_path.clone()).unwrap();
    //         }

    //         let db = SnDB::new_by_path(sn_db_path.to_str().unwrap()).unwrap();
    //         db.initialize_database();
    //         db.insert_activation_code("test-active-sn-code-bob")
    //             .unwrap();
    //         db.insert_activation_code("11111").unwrap();
    //         db.insert_activation_code("22222").unwrap();
    //         db.insert_activation_code("33333").unwrap();
    //         db.insert_activation_code("44444").unwrap();
    //         db.insert_activation_code("55555").unwrap();
    //         db.register_user(
    //             "test-active-sn-code-bob",
    //             "bob",
    //             bob_public_key_str.as_str(),
    //             bob_zone_jwt.as_str(),
    //             None,
    //         )
    //         .unwrap();

    //         let mut device_info = DeviceInfo::new("ood1", bob_ood1_did.clone());
    //         device_info.auto_fill_by_system_info().await.unwrap();
    //         let device_info_json = serde_json::to_string_pretty(&device_info).unwrap();

    //         db.register_device(
    //             "bob",
    //             "ood1",
    //             bob_ood1_did.to_string().as_str(),
    //             "192.168.100.100",
    //             device_info_json.as_str(),
    //         )
    //         .unwrap();

    //         println!("# sn_db already create at {}", sn_db_path.to_string_lossy());
    //     }

    #[test]
    fn test_ood_description_string_from_str_ood() {
        // Test various formats of OOD type
        let cases = vec![
            ("ood1", DeviceNodeType::OOD, None, None),
            ("ood1@wan", DeviceNodeType::OOD, Some("wan".to_string()), None),
            ("ood1@lan1", DeviceNodeType::OOD, Some("lan1".to_string()), None),
            ("ood1@lan", DeviceNodeType::OOD, Some("lan".to_string()), None),
            (
                "ood1:192.168.1.8",
                DeviceNodeType::OOD,
                Some("wan".to_string()),
                Some("192.168.1.8".parse().unwrap()),
            ),
            (
                "ood1:192.168.1.8@lan",
                DeviceNodeType::OOD,
                Some("lan".to_string()),
                Some("192.168.1.8".parse().unwrap()),
            ),
            (
                "ood1:192.168.1.8",
                DeviceNodeType::OOD,
                Some("wan".to_string()),
                Some("192.168.1.8".parse().unwrap()),
            ),
            (
                "ood1:192.168.1.8@lan1",
                DeviceNodeType::OOD,
                Some("lan1".to_string()),
                Some("192.168.1.8".parse().unwrap()),
            ),
            (
                "ood1:210.35.234.21",
                DeviceNodeType::OOD,
                Some("wan".to_string()),
                Some("210.35.234.21".parse().unwrap()),
            ),
            (
                "ood1:192.168.1.100@lan1",
                DeviceNodeType::OOD,
                Some("lan1".to_string()),
                Some("192.168.1.100".parse().unwrap()),
            ),
            (
                "ood1:2001:db8::1",
                DeviceNodeType::OOD,
                Some("wan".to_string()),
                Some("2001:db8::1".parse().unwrap()),
            ),
            (
                "ood1:2001:db8::1",
                DeviceNodeType::OOD,
                Some("wan".to_string()),
                Some("2001:db8::1".parse().unwrap()),
            ),
        ];

        for (input, expected_type, expected_net_id, expected_ip) in cases {
            let result: OODDescriptionString = input.parse().unwrap();
            assert_eq!(
                result.node_type, expected_type,
                "Failed for input: {}",
                input
            );
            assert_eq!(
                result.name,
                input.split(['@', ':', '#', '$']).next().unwrap(),
                "Failed for input: {}",
                input
            );
            assert_eq!(
                result.net_id, expected_net_id,
                "Failed for input: {}",
                input
            );
            assert_eq!(result.ip, expected_ip, "Failed for input: {}", input);
            let result_string = result.to_string().unwrap();
            assert_eq!(result_string, input, "Failed for input: {}", input);
        }
    }

    #[test]
    fn test_ood_description_string_from_str_gateway() {
        // Test various formats of Gateway type
        let cases = vec![
            ("#gate1", DeviceNodeType::Gateway, None, None),
            (
                "#gate1@wan",
                DeviceNodeType::Gateway,
                Some("wan".to_string()),
                None,
            ),
            (
                "#gate1@lan1",
                DeviceNodeType::Gateway,
                Some("lan1".to_string()),
                None,
            ),
            (
                "#gate1:210.35.22.1",
                DeviceNodeType::Gateway,
                Some("wan".to_string()),
                Some("210.35.22.1".parse().unwrap()),
            ),
            (
                "#gate1:192.168.1.8@lan",
                DeviceNodeType::Gateway,
                Some("lan".to_string()),
                Some("192.168.1.8".parse().unwrap()),
            ),
            (
                "#gate1:192.168.1.8",
                DeviceNodeType::Gateway,
                Some("wan".to_string()),
                Some("192.168.1.8".parse().unwrap()),
            ),
            (
                "#gateway1:10.0.0.1@lan2",
                DeviceNodeType::Gateway,
                Some("lan2".to_string()),
                Some("10.0.0.1".parse().unwrap()),
            ),
        ];

        for (input, expected_type, expected_net_id, expected_ip) in cases {
            let result: OODDescriptionString = input.parse().unwrap();
            assert_eq!(
                result.node_type, expected_type,
                "Failed for input: {}",
                input
            );
            let name = input
                .strip_prefix('#')
                .unwrap()
                .split(['@', ':'])
                .next()
                .unwrap();
            assert_eq!(result.name, name, "Failed for input: {}", input);
            assert_eq!(
                result.net_id, expected_net_id,
                "Failed for input: {}",
                input
            );
            assert_eq!(result.ip, expected_ip, "Failed for input: {}", input);
            let result_string = result.to_string().unwrap();
            assert_eq!(result_string, input, "Failed for input: {}", input);
        }
    }

    #[test]
    fn test_ood_description_string_from_str_ood_only() {
        // Test various formats of OODOnly type
        let cases = vec![
            ("$ood1", DeviceNodeType::OODOnly, None, None),
            (
                "$ood1@wan",
                DeviceNodeType::OODOnly,
                Some("wan".to_string()),
                None,
            ),
            (
                "$ood1@lan1",
                DeviceNodeType::OODOnly,
                Some("lan1".to_string()),
                None,
            ),
            (
                "$ood1:210.35.234.21",
                DeviceNodeType::OODOnly,
                Some("wan".to_string()),
                Some("210.35.234.21".parse().unwrap()),
            ),
            (
                "$ood1:1.2.3.4@lan",
                DeviceNodeType::OODOnly,
                Some("lan".to_string()),
                Some("1.2.3.4".parse().unwrap()),
            ),
            (
                "$ood1:192.168.1.8@wan",
                DeviceNodeType::OODOnly,
                Some("wan".to_string()),
                Some("192.168.1.8".parse().unwrap()),
            ),
        ];

        for (input, expected_type, expected_net_id, expected_ip) in cases {
            let result: OODDescriptionString = input.parse().unwrap();
            assert_eq!(
                result.node_type, expected_type,
                "Failed for input: {}",
                input
            );
            let name = input
                .strip_prefix('$')
                .unwrap()
                .split(['@', ':'])
                .next()
                .unwrap();
            assert_eq!(result.name, name, "Failed for input: {}", input);
            assert_eq!(
                result.net_id, expected_net_id,
                "Failed for input: {}",
                input
            );
            assert_eq!(result.ip, expected_ip, "Failed for input: {}", input);
        }
    }

    #[test]
    fn test_ood_description_string_from_str_error_cases() {
        // Test error cases
        let error_cases = vec![
            "",                     // Empty string
            "#",                    // Only prefix
            "$",                    // Only prefix
            ":",                    // Only colon
            "@",                    // Only @
            ":192.168.1.1",         // No name
            "@wan",                 // No name
            "ood1:invalid_ip",      // Invalid IP
            "ood1:999.999.999.999", // Invalid IP
        ];

        for input in error_cases {
            let result: Result<OODDescriptionString, _> = input.parse();
            assert!(
                result.is_err(),
                "Expected error for input: '{}', but got: {:?}",
                input,
                result
            );
        }
    }

    #[test]
    fn test_ood_description_string_to_string() {
        // Test to_string() method
        let test_cases = vec![
            (
                OODDescriptionString::new("ood1".to_string(), DeviceNodeType::OOD, None, None),
                "ood1",
            ),
            (
                OODDescriptionString::new(
                    "ood1".to_string(),
                    DeviceNodeType::OOD,
                    Some("wan".to_string()),
                    None,
                ),
                "ood1@wan",
            ),
            (
                OODDescriptionString::new(
                    "ood1".to_string(),
                    DeviceNodeType::OOD,
                    Some("lan1".to_string()),
                    None,
                ),
                "ood1@lan1",
            ),
            (
                OODDescriptionString::new(
                    "ood1".to_string(),
                    DeviceNodeType::OOD,
                    None,
                    Some("192.168.1.8".parse().unwrap()),
                ),
                "ood1:192.168.1.8",
            ),
            (
                OODDescriptionString::new(
                    "ood1".to_string(),
                    DeviceNodeType::OOD,
                    Some("lan".to_string()),
                    Some("192.168.1.8".parse().unwrap()),
                ),
                "ood1:192.168.1.8@lan",
            ),
            (
                OODDescriptionString::new(
                    "ood1".to_string(),
                    DeviceNodeType::OOD,
                    Some("wan".to_string()),
                    Some("192.168.1.8".parse().unwrap()),
                ),
                "ood1:192.168.1.8",
            ),
            (
                OODDescriptionString::new(
                    "ood1".to_string(),
                    DeviceNodeType::OOD,
                    Some("lan1".to_string()),
                    Some("192.168.1.8".parse().unwrap()),
                ),
                "ood1:192.168.1.8@lan1", // lan1 will be simplified to lan
            ),
            (
                OODDescriptionString::new("gate1".to_string(), DeviceNodeType::Gateway, None, None),
                "#gate1",
            ),
            (
                OODDescriptionString::new(
                    "gate1".to_string(),
                    DeviceNodeType::Gateway,
                    Some("wan".to_string()),
                    None,
                ),
                "#gate1@wan",
            ),
            (
                OODDescriptionString::new(
                    "gate1".to_string(),
                    DeviceNodeType::Gateway,
                    Some("wan".to_string()),
                    Some("210.35.22.1".parse().unwrap()),
                ),
                "#gate1:210.35.22.1",
            ),
            (
                OODDescriptionString::new("ood1".to_string(), DeviceNodeType::OODOnly, None, None),
                "$ood1",
            ),
            (
                OODDescriptionString::new(
                    "ood1".to_string(),
                    DeviceNodeType::OODOnly,
                    Some("wan".to_string()),
                    None,
                ),
                "$ood1@wan",
            ),
            (
                OODDescriptionString::new(
                    "ood1".to_string(),
                    DeviceNodeType::OODOnly,
                    Some("lan".to_string()),
                    Some("1.2.3.4".parse().unwrap()),
                ),
                "$ood1:1.2.3.4@lan",
            ),
        ];

        for (input, expected) in test_cases {
            let result = input.to_string().unwrap();
            assert_eq!(result, expected, "Failed for input: {:?}", input);
        }
    }

    #[test]
    fn test_ood_description_string_to_string_error_cases() {
        // Test error cases of to_string() (unsupported NodeType)
        let error_cases = vec![
            DeviceNodeType::Device,
            DeviceNodeType::Sensor,
            DeviceNodeType::IoTController,
        ];

        for node_type in error_cases {
            let ood = OODDescriptionString::new("test".to_string(), node_type.clone(), None, None);
            let result = ood.to_string();
            assert!(
                result.is_err(),
                "Expected error for NodeType: {:?}",
                node_type
            );
        }
    }

    #[test]
    fn test_ood_description_string_round_trip() {
        // Test round-trip: parse from string, then convert back to string
        let test_strings = vec![
            "ood1",
            "ood1@wan",
            "ood1@lan1",
            "ood1:192.168.1.8",
            "ood1:192.168.1.8@lan",
            "ood1:192.168.1.8@wan",
            "ood1:192.168.1.8@lan1",
            "#gate1",
            "#gate1@wan",
            "#gate1:210.35.22.1",
            "#gate1:192.168.1.8@lan",
            "$ood1",
            "$ood1@wan",
            "$ood1:1.2.3.4@lan",
        ];

        for input_str in test_strings {
            let parsed: OODDescriptionString = input_str.parse().unwrap();
            let serialized = parsed.to_string().unwrap();
            // Note: Due to special handling of lan, output may be slightly different in some cases
            // For example, "ood1@lan1" will become "ood1:ip@lan" when serialized with IP
            // So we need to re-parse to verify
            let reparsed: OODDescriptionString = serialized.parse().unwrap();
            assert_eq!(
                parsed.name, reparsed.name,
                "Name mismatch for input: {}",
                input_str
            );
            assert_eq!(
                parsed.node_type, reparsed.node_type,
                "NodeType mismatch for input: {}",
                input_str
            );
            assert_eq!(
                parsed.ip, reparsed.ip,
                "IP mismatch for input: {}",
                input_str
            );
            // net_id may differ slightly due to special handling of lan, so only check if both exist or both don't exist
            assert_eq!(
                parsed.net_id.is_some(),
                reparsed.net_id.is_some(),
                "NetId presence mismatch for input: {}",
                input_str
            );
        }
    }

    #[test]
    fn test_ood_description_string_serialize() {
        // Test serialization (should serialize to string)
        let ood = OODDescriptionString::new(
            "ood1".to_string(),
            DeviceNodeType::OOD,
            Some("wan".to_string()),
            None,
        );
        let json = serde_json::to_string(&ood).unwrap();
        assert_eq!(
            json, "\"ood1@wan\"",
            "Serialization should produce a string"
        );

        let ood2 = OODDescriptionString::new(
            "gate1".to_string(),
            DeviceNodeType::Gateway,
            None,
            Some("192.168.1.8".parse().unwrap()),
        );
        let json2 = serde_json::to_string(&ood2).unwrap();
        assert_eq!(
            json2, "\"#gate1:192.168.1.8\"",
            "Serialization should produce a string"
        );

        let ood3 = OODDescriptionString::new(
            "ood1".to_string(),
            DeviceNodeType::OODOnly,
            Some("lan".to_string()),
            Some("1.2.3.4".parse().unwrap()),
        );
        let json3 = serde_json::to_string(&ood3).unwrap();
        assert_eq!(
            json3, "\"$ood1:1.2.3.4@lan\"",
            "Serialization should produce a string"
        );
    }

    #[test]
    fn test_ood_description_string_deserialize() {
        // Test deserialization (deserialize from string)
        let json = "\"ood1@wan\"";
        let ood: OODDescriptionString = serde_json::from_str(json).unwrap();
        assert_eq!(ood.name, "ood1");
        assert_eq!(ood.node_type, DeviceNodeType::OOD);
        assert_eq!(ood.net_id, Some("wan".to_string()));
        assert_eq!(ood.ip, None);

        let json2 = "\"#gate1:192.168.1.8\"";
        let ood2: OODDescriptionString = serde_json::from_str(json2).unwrap();
        assert_eq!(ood2.name, "gate1");
        assert_eq!(ood2.node_type, DeviceNodeType::Gateway);
        assert_eq!(ood2.net_id, Some("wan".to_string())); // Automatically set to wan
        assert_eq!(ood2.ip, Some("192.168.1.8".parse().unwrap()));

        let json3 = "\"$ood1:1.2.3.4@lan\"";
        let ood3: OODDescriptionString = serde_json::from_str(json3).unwrap();
        assert_eq!(ood3.name, "ood1");
        assert_eq!(ood3.node_type, DeviceNodeType::OODOnly);
        assert_eq!(ood3.net_id, Some("lan".to_string()));
        assert_eq!(ood3.ip, Some("1.2.3.4".parse().unwrap()));
    }

    #[test]
    fn test_ood_description_string_serialize_deserialize_round_trip() {
        // Test serialize/deserialize round-trip
        let test_cases = vec![
            OODDescriptionString::new("ood1".to_string(), DeviceNodeType::OOD, None, None),
            OODDescriptionString::new(
                "ood1".to_string(),
                DeviceNodeType::OOD,
                Some("wan".to_string()),
                None,
            ),
            OODDescriptionString::new(
                "ood1".to_string(),
                DeviceNodeType::OOD,
                Some("lan1".to_string()),
                None,
            ),
            OODDescriptionString::new(
                "ood1".to_string(),
                DeviceNodeType::OOD,
                None,
                Some("192.168.1.8".parse().unwrap()),
            ),
            OODDescriptionString::new(
                "ood1".to_string(),
                DeviceNodeType::OOD,
                Some("lan".to_string()),
                Some("192.168.1.8".parse().unwrap()),
            ),
            OODDescriptionString::new("gate1".to_string(), DeviceNodeType::Gateway, None, None),
            OODDescriptionString::new(
                "gate1".to_string(),
                DeviceNodeType::Gateway,
                Some("wan".to_string()),
                None,
            ),
            OODDescriptionString::new("ood1".to_string(), DeviceNodeType::OODOnly, None, None),
            OODDescriptionString::new(
                "ood1".to_string(),
                DeviceNodeType::OODOnly,
                Some("lan".to_string()),
                Some("1.2.3.4".parse().unwrap()),
            ),
        ];

        for original in test_cases {
            let json = serde_json::to_string(&original).unwrap();
            let deserialized: OODDescriptionString = serde_json::from_str(&json).unwrap();
            assert_eq!(original.name, deserialized.name);
            assert_eq!(original.node_type, deserialized.node_type);
            assert_eq!(original.net_id, deserialized.net_id);
            assert_eq!(original.ip, deserialized.ip);
        }
    }

    #[test]
    fn test_ood_description_string_ipv6() {
        // Test IPv6 addresses
        let ipv6_str = "2001:db8::1";
        let ood_str = format!("ood1:{}", ipv6_str);
        let ood: OODDescriptionString = ood_str.parse().unwrap();
        assert_eq!(ood.ip, Some(ipv6_str.parse().unwrap()));

        let serialized = ood.to_string().unwrap();
        assert!(serialized.contains(ipv6_str));

        // Test IPv6 with net_id
        let ood_str2 = format!("ood1:{}@wan", ipv6_str);
        let ood2: OODDescriptionString = ood_str2.parse().unwrap();
        assert_eq!(ood2.ip, Some(ipv6_str.parse().unwrap()));
        assert_eq!(ood2.net_id, Some("wan".to_string()));
    }

    #[test]
    fn test_ood_description_string_lan_special_case() {
        // Test special handling of lan (if net_id starts with "lan" and has IP, serialize as "@lan")
        let ood = OODDescriptionString::new(
            "ood1".to_string(),
            DeviceNodeType::OOD,
            Some("lan1".to_string()),
            Some("192.168.1.8".parse().unwrap()),
        );
        let serialized = ood.to_string().unwrap();
        assert_eq!(
            serialized, "ood1:192.168.1.8@lan1",
            "lan net_id should be simplified to 'lan' when IP is present"
        );

        // Test lan2 case (only "lan" or "lan1" are simplified to "lan", "lan2" remains unchanged)
        let ood2 = OODDescriptionString::new(
            "ood1".to_string(),
            DeviceNodeType::OOD,
            Some("lan2".to_string()),
            Some("192.168.1.8".parse().unwrap()),
        );
        let serialized2 = ood2.to_string().unwrap();
        assert_eq!(
            serialized2, "ood1:192.168.1.8@lan2",
            "lan2 should keep full name"
        );
    }

    #[test]
    fn test_ood_description_string_in_vec() {
        // Test serialization in Vec
        let oods: Vec<OODDescriptionString> = vec![
            "ood1".parse().unwrap(),
            "ood2@wan".parse().unwrap(),
            "#gate1:192.168.1.8".parse().unwrap(),
            "$ood1:1.2.3.4@lan".parse().unwrap(),
        ];

        let json = serde_json::to_string(&oods).unwrap();
        let deserialized: Vec<OODDescriptionString> = serde_json::from_str(&json).unwrap();
        assert_eq!(oods.len(), deserialized.len());
        for (original, deserialized_item) in oods.iter().zip(deserialized.iter()) {
            assert_eq!(original.name, deserialized_item.name);
            assert_eq!(original.node_type, deserialized_item.node_type);
            assert_eq!(original.net_id, deserialized_item.net_id);
            assert_eq!(original.ip, deserialized_item.ip);
        }
    }

    #[test]
    fn test_zone_boot_config() {
        let private_key_pem = r#"
        -----BEGIN PRIVATE KEY-----
        MC4CAQAwBQYDK2VwBCIEIBwApVoYjauZFuKMBRe02wKlKm2B6a1F0/WIPMqDaw5F
        -----END PRIVATE KEY-----
        "#;
        let jwk = json!(
            {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": "qmtOLLWpZeBMzt97lpfj2MxZGWn3QfuDB7Q4uaP3Eok"
            }
        );
        let private_key: EncodingKey =
            EncodingKey::from_ed_pem(private_key_pem.as_bytes()).unwrap();
        let public_key_jwk: jsonwebtoken::jwk::Jwk = serde_json::from_value(jwk).unwrap();
        let public_key = DecodingKey::from_jwk(&public_key_jwk).unwrap();

        let mut extera_info = HashMap::new();
        // extera_info.insert(
        //     "x".to_string(),
        //     json!("qmtOLLWpZeBMzt97lpfj2MxZGWn3QfuDB7Q4uaP3Eok"),
        // );

        let zone_boot_config = ZoneBootConfig {
            id: None,
            oods: vec![
                "ood1".parse().unwrap(),
                "ood2:202.222.122.123".parse().unwrap(),
                "ood3".parse().unwrap(),
            ],
            sn: Some("sn.buckyos.io".to_string()),
            exp: buckyos_get_unix_timestamp() + DEFUALT_EXPIRE_TIME,
            owner: None,
            owner_key: None,
            devices: HashMap::new(),
            gateway_devs: vec![],
            extra_info: extera_info,
        };


        let json_str = serde_json::to_string(&zone_boot_config).unwrap();
        println!("zone_boot_config: {:?}", json_str);

        let zone_boot_config_jwt = zone_boot_config.encode(Some(&private_key)).unwrap();
        let txt_record = format!("DID={};", zone_boot_config_jwt.to_string());
        println!("zone_boot_config_jwt:{} {}", &txt_record, txt_record.len());

        //decode
        let zone_boot_config_decoded =
            ZoneBootConfig::decode(&zone_boot_config_jwt, Some(&public_key)).unwrap();
        println!("zone_boot_config_decoded: {:?}", zone_boot_config_decoded);

        assert_eq!(zone_boot_config, zone_boot_config_decoded);
    }

    #[test]
    fn test_zone_config() {
        let private_key_pem = r#"
        -----BEGIN PRIVATE KEY-----
        MC4CAQAwBQYDK2VwBCIEIJBRONAzbwpIOwm0ugIQNyZJrDXxZF7HoPWAZesMedOr
        -----END PRIVATE KEY-----
        "#;
        let jwk = json!(
            {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": "T4Quc1L6Ogu4N2tTKOvneV1yYnBcmhP89B_RsuFsJZ8"
            }
        );
        let public_key_jwk: jsonwebtoken::jwk::Jwk = serde_json::from_value(jwk).unwrap();
        let private_key: EncodingKey =
            EncodingKey::from_ed_pem(private_key_pem.as_bytes()).unwrap();
        let public_key = DecodingKey::from_jwk(&public_key_jwk).unwrap();

        let zone_config = ZoneConfig::new(
            DID::new("web", "test.buckyos.io"),
            DID::new("bns", "devtest"),
            public_key_jwk,
        );

        let json_str = serde_json::to_string(&zone_config).unwrap();
        println!("json_str: {:?}", json_str);

        let encoded = zone_config.encode(Some(&private_key)).unwrap();
        println!("encoded: {:?}", encoded);

        let decoded = ZoneConfig::decode(&encoded, Some(&public_key)).unwrap();
        println!("decoded: {:?}", serde_json::to_string(&decoded).unwrap());
        let token2 = decoded.encode(Some(&private_key)).unwrap();

        assert_eq!(zone_config, decoded);
        assert_eq!(encoded, token2);
    }

   
    #[test]
    fn test_owner_config() {
        let private_key_pem = r#"
        -----BEGIN PRIVATE KEY-----
        MC4CAQAwBQYDK2VwBCIEIJBRONAzbwpIOwm0ugIQNyZJrDXxZF7HoPWAZesMedOr
        -----END PRIVATE KEY-----
        "#;
        let jwk = json!(
            {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": "T4Quc1L6Ogu4N2tTKOvneV1yYnBcmhP89B_RsuFsJZ8"
            }
        );
        let public_key_jwk: jsonwebtoken::jwk::Jwk = serde_json::from_value(jwk).unwrap();
        let private_key: EncodingKey =
            EncodingKey::from_ed_pem(private_key_pem.as_bytes()).unwrap();
        let public_key = DecodingKey::from_jwk(&public_key_jwk).unwrap();

        let mut owner_config = OwnerConfig::new(
            DID::new("bns", "lzc"),
            "lzc".to_string(),
            "zhicong liu".to_string(),
            public_key_jwk,
        );

        owner_config.set_default_zone_did(DID::new("bns", "waterflier"));

        let json_str = serde_json::to_string_pretty(&owner_config).unwrap();
        println!("json_str: {}", json_str.as_str());

        let encoded = owner_config.encode(Some(&private_key)).unwrap();
        println!("encoded: {:?}", encoded);

        let decoded = OwnerConfig::decode(&encoded, Some(&public_key)).unwrap();
        println!(
            "decoded: {}",
            serde_json::to_string_pretty(&decoded).unwrap()
        );
        let token2 = decoded.encode(Some(&private_key)).unwrap();

        assert_eq!(owner_config, decoded);
        assert_eq!(encoded, token2);
    }
}
