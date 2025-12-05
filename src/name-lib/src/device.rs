use buckyos_kit::*;
use jsonwebtoken::jwk::Jwk;
use jsonwebtoken::{encode, Algorithm, DecodingKey, EncodingKey, Header};
use log::error;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::net::ToSocketAddrs;
use std::net::{IpAddr, Ipv6Addr};
use std::ops::Deref;
use std::str::FromStr;
use thiserror::Error;
use tokio::net::UdpSocket;

use crate::config::{default_context, ServiceNode, VerificationMethodNode};
use crate::{
    decode_json_from_jwt_with_pk, decode_jwt_claim_without_verify, get_x_from_jwk,
    DIDDocumentTrait, EncodedDocument, NSError, NSResult, DEFAULT_EXPIRE_TIME, DID,
};
use nvml_wrapper::enum_wrappers::device::Clock;
use nvml_wrapper::*;
use sysinfo::{Components, Disks, Networks, System};

pub enum DeviceType {
    OOD,    //run system config service
    Node,   //run other service
    Device, //client device
    Sensor,
    Browser,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct DeviceMiniConfig {
    #[serde(rename = "n")]
    pub name: String,
    pub x: String,
    //rtcp port
    #[serde(rename = "p")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rtcp_port: Option<u32>,
    pub exp: u64,
    #[serde(flatten)]
    pub extra_info: HashMap<String, serde_json::Value>,
}

impl DeviceMiniConfig {
    pub fn to_jwt(&self, owner_private_key: &EncodingKey) -> NSResult<String> {
        let mut header = Header::new(Algorithm::EdDSA);
        header.typ = None; // Default is JWT, set to None to save space

        let token = encode(&header, self, owner_private_key).map_err(|error| {
            NSError::Failed(format!("Failed to encode device mini config:{}", error))
        })?;
        return Ok(token);
    }

    pub fn from_jwt(jwt: &str, key: &DecodingKey) -> NSResult<Self> {
        let json_result = decode_json_from_jwt_with_pk(jwt, key)?;
        let result: DeviceMiniConfig = serde_json::from_value(json_result).map_err(|error| {
            NSError::Failed(format!("Failed to decode device mini config:{}", error))
        })?;
        return Ok(result);
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct DeviceConfig {
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
    pub device_type: String, //[ood,server,sensor
    pub name: String,        //short name,like ood1
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rtcp_port: Option<u32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<IpAddr>, //main_ip
    #[serde(skip_serializing_if = "Option::is_none")]
    pub net_id: Option<String>, // lan1 | wan, when None it represents lan0
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ddns_sn_url: Option<String>,
    #[serde(skip_serializing_if = "is_true", default = "bool_default_true")]
    pub support_container: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zone_did: Option<DID>, // The zone did where the Device is located
    pub iss: String,
}

impl DeviceConfig {
    pub fn new_by_jwk(name: &str, pk: Jwk) -> Self {
        let x = get_x_from_jwk(&pk).unwrap();
        return DeviceConfig::new(name, x);
    }

    pub fn new_by_mini_config(
        mini_config: DeviceMiniConfig,
        zone_did: DID,
        owner_did: DID,
    ) -> Self {
        let did = format!("did:dev:{}", mini_config.x);
        let jwk = json!(
            {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": mini_config.x
            }
        );
        let public_key_jwk: jsonwebtoken::jwk::Jwk = serde_json::from_value(jwk).unwrap();
        DeviceConfig {
            context: default_context(),
            id: DID::from_str(&did).unwrap(),
            name: mini_config.name.clone(),
            device_type: "ood".to_string(),
            ip: None,
            net_id: None,
            ddns_sn_url: None,
            rtcp_port: mini_config.rtcp_port,
            verification_method: vec![VerificationMethodNode {
                key_type: "Ed25519VerificationKey2020".to_string(),
                key_id: "#main_key".to_string(),
                key_controller: did.clone(),
                public_key: public_key_jwk,
                extra_info: HashMap::new(),
            }],
            authentication: vec!["#main_key".to_string()],
            assertion_method: vec!["#main_key".to_string()],
            service: vec![],
            support_container: true,
            zone_did: Some(zone_did.clone()),
            iss: owner_did.to_string(),
            exp: mini_config.exp,
            iat: mini_config.exp - DEFAULT_EXPIRE_TIME,
            extra_info: mini_config.extra_info,
        }
    }

    pub fn new(name: &str, pkx: String) -> Self {
        let did = format!("did:dev:{}", pkx);
        let jwk = json!(
            {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": pkx
            }
        );

        let public_key_jwk: jsonwebtoken::jwk::Jwk = serde_json::from_value(jwk).unwrap();
        DeviceConfig {
            context: default_context(),
            id: DID::from_str(&did).unwrap(),
            name: name.to_string(),
            device_type: "ood".to_string(),
            ip: None,
            net_id: None,
            ddns_sn_url: None,
            rtcp_port: None,
            verification_method: vec![VerificationMethodNode {
                key_type: "Ed25519VerificationKey2020".to_string(),
                key_id: "#main_key".to_string(),
                key_controller: did.clone(),
                public_key: public_key_jwk,
                extra_info: HashMap::new(),
            }],
            authentication: vec!["#main_key".to_string()],
            assertion_method: vec!["#main_key".to_string()],
            service: vec![],
            support_container: true,
            zone_did: None,
            iss: "".to_string(),
            exp: buckyos_get_unix_timestamp() + DEFAULT_EXPIRE_TIME,
            iat: buckyos_get_unix_timestamp() as u64,
            extra_info: HashMap::new(),
        }
    }

    pub fn get_default_key(&self) -> Option<Jwk> {
        for method in self.verification_method.iter() {
            if method.key_id == "#main_key" {
                return Some(method.public_key.clone());
            }
        }
        return None;
    }

    pub fn set_zone_did(&mut self, zone_did: DID) {
        self.zone_did = Some(zone_did.clone());
        self.service.push(ServiceNode {
            id: format!("{}#lastDoc", self.id.to_string()),
            service_type: "DIDDoc".to_string(),
            service_endpoint: format!(
                "https://{}/resolve/{}",
                zone_did.to_host_name(),
                self.id.to_string()
            ),
        });
    }
}

impl DIDDocumentTrait for DeviceConfig {
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
        return self.get_auth_key(kid);
    }

    fn get_iss(&self) -> Option<String> {
        return Some(self.iss.clone());
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
                let result: DeviceConfig =
                    serde_json::from_value(json_result).map_err(|error| {
                        NSError::Failed(format!("Failed to decode device config:{}", error))
                    })?;
                return Ok(result);
            }
            EncodedDocument::JsonLd(json_value) => {
                let result: DeviceConfig =
                    serde_json::from_value(json_value.clone()).map_err(|error| {
                        NSError::Failed(format!("Failed to decode device config:{}", error))
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

// describe a device runtime info
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct DeviceInfo {
    #[serde(flatten)]
    pub device_doc: DeviceConfig,
    pub arch: String,
    pub os: String, //linux,windows,apple
    pub update_time: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub sys_hostname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_os_info: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_info: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_num: Option<u32>, //cpu核心数
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_mhz: Option<u32>, //cpu的最大性能,单位是MHZ
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_ratio: Option<f32>, //cpu的性能比率
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_usage: Option<f32>, //类似top里的load,0 -- core

    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_mem: Option<u64>, //单位是bytes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mem_usage: Option<u64>, //单位是bytes

    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_space: Option<u64>, //单位是bytes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disk_usage: Option<u64>, //单位是bytes

    #[serde(skip_serializing_if = "Option::is_none")]
    pub gpu_info: Option<String>, //gpu信息
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gpu_tflops: Option<f32>, //gpu的算力,单位是TFLOPS
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gpu_total_mem: Option<u64>, //gpu总内存,单位是bytes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gpu_used_mem: Option<u64>, //gpu已用内存,单位是bytes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gpu_load: Option<f32>, //gpu负载
}

impl Deref for DeviceInfo {
    type Target = DeviceConfig;

    fn deref(&self) -> &Self::Target {
        &self.device_doc
    }
}

impl DeviceInfo {
    pub fn from_device_doc(device_doc: &DeviceConfig) -> Self {
        let os_type = Self::get_os_type();

        #[cfg(all(target_arch = "x86_64"))]
        let arch = "amd64";
        #[cfg(all(target_arch = "aarch64"))]
        let arch = "aarch64";

        let result_info = DeviceInfo {
            device_doc: device_doc.clone(),
            arch: arch.to_string(),
            os: os_type.to_string(),
            update_time: buckyos_get_unix_timestamp(),
            state: None,
            sys_hostname: None,
            base_os_info: None,
            cpu_info: None,
            cpu_num: None,
            cpu_mhz: None,
            cpu_ratio: None,
            cpu_usage: None,
            total_mem: None,
            mem_usage: None,
            total_space: None,
            disk_usage: None,
            gpu_info: None,
            gpu_tflops: None,
            gpu_total_mem: None,
            gpu_used_mem: None,
            gpu_load: None,
        };

        return result_info;
    }

    //return (short_name,net_id,ip_addr)
    pub fn get_net_info_from_ood_desc_string(
        ood_desc_string: &str,
    ) -> (String, Option<String>, Option<IpAddr>) {
        let ip: Option<IpAddr>;
        let net_id: Option<String>;

        let parts: Vec<&str> = ood_desc_string.split('@').collect();
        let hostname = parts[0];
        if parts.len() > 1 {
            let ip_str = parts[1];
            let ip_result = IpAddr::from_str(ip_str);
            if ip_result.is_ok() {
                ip = Some(ip_result.unwrap());
            } else {
                ip = None;
            }
        } else {
            ip = None;
        }

        let parts: Vec<&str> = ood_desc_string.split('#').collect();
        if parts.len() == 2 {
            net_id = Some(parts[1].to_string());
        } else {
            net_id = None;
        }
        return (hostname.to_string(), net_id, ip);
    }

    pub fn new(ood_string: &str, did: DID) -> Self {
        //device_string format: hostname@[ip]#[netid]
        let (hostname, net_id, ip) = Self::get_net_info_from_ood_desc_string(ood_string);

        let os_type = Self::get_os_type();

        #[cfg(all(target_arch = "x86_64"))]
        let arch = "amd64";
        #[cfg(all(target_arch = "aarch64"))]
        let arch = "aarch64";

        let mut config = DeviceConfig::new(hostname.as_str(), did.id.to_string());
        config.ip = ip;
        config.net_id = net_id;
        config.device_type = "ood".to_string();

        DeviceInfo {
            device_doc: config,
            state: Some("Ready".to_string()),
            arch: arch.to_string(),
            os: os_type.to_string(),
            update_time: buckyos_get_unix_timestamp(),
            base_os_info: None,
            cpu_info: None,
            cpu_num: None,
            cpu_mhz: None,
            cpu_ratio: None,
            cpu_usage: None,
            total_mem: None,
            mem_usage: None,
            total_space: None,
            disk_usage: None,
            sys_hostname: None,
            gpu_info: None,
            gpu_tflops: None,
            gpu_total_mem: None,
            gpu_used_mem: None,
            gpu_load: None,
        }
    }

    pub async fn auto_fill_by_system_info(&mut self) -> NSResult<()> {
        let mut sys = System::new_all();
        sys.refresh_all();

        let test_socket = UdpSocket::bind("0.0.0.0:0").await;
        if test_socket.is_ok() {
            let test_socket = test_socket.unwrap();
            test_socket.connect("8.8.8.8:80").await;
            let local_addr = test_socket.local_addr().unwrap();
            self.device_doc.ip = Some(local_addr.ip());
        }

        // Get OS information
        self.base_os_info = Some(format!(
            "{} {} {}",
            System::name().unwrap_or_default(),
            System::os_version().unwrap_or_default(),
            System::kernel_version().unwrap_or_default()
        ));
        // Get CPU information
        let mut cpu_usage = 0.0;
        let mut cpu_mhz: u32 = 0;
        let mut cpu_mhz_last: u32 = 0;
        let mut cpu_brand: String = "Unknown".to_string();
        self.cpu_ratio = Some(1.0);
        for cpu in sys.cpus() {
            cpu_brand = cpu.brand().to_string();
            cpu_usage += cpu.cpu_usage();
            cpu_mhz += cpu.frequency() as u32;
            cpu_mhz_last = cpu.frequency() as u32;
        }
        if cpu_mhz < 1000 {
            cpu_mhz = 2000 * sys.cpus().len() as u32;
            cpu_mhz_last = 2000;
        }
        self.cpu_info = Some(format!(
            "{} @ {} MHz,({} cores)",
            cpu_brand,
            cpu_mhz_last,
            sys.cpus().len()
        ));
        self.cpu_num = Some(sys.cpus().len() as u32);
        self.cpu_mhz = Some(cpu_mhz);
        self.cpu_usage = Some(cpu_usage);
        // Get memory information
        self.total_mem = Some(sys.total_memory());
        self.mem_usage = Some(sys.used_memory());
        // Get hostname if not already set
        self.sys_hostname = Some(System::host_name().unwrap_or_default());

        // First try NVIDIA GPU
        let nvidia_info = match nvml_wrapper::Nvml::init() {
            Ok(nvml) => {
                if let Ok(device) = nvml.device_by_index(0) {
                    // Get GPU name
                    let name = device.name().ok();
                    let memory = device.memory_info().ok();
                    let utilization = device.utilization_rates().ok();
                    let clock = device.clock_info(Clock::Graphics).ok();
                    let cuda_cores = device.num_cores().ok();

                    Some((name, memory, utilization, clock, cuda_cores))
                } else {
                    None
                }
            }
            Err(_) => None,
        };

        if let Some((name, memory, utilization, clock, cuda_cores)) = nvidia_info {
            // NVIDIA GPU found
            self.gpu_info = name.map(|n| format!("NVIDIA {}", n));
            if let Some(mem) = memory {
                self.gpu_total_mem = Some(mem.total);
                self.gpu_used_mem = Some(mem.used);
            }
            if let Some(util) = utilization {
                self.gpu_load = Some(util.gpu as f32);
            }
            if let (Some(clock), Some(cores)) = (clock, cuda_cores) {
                let tflops = (clock as f32 * cores as f32 * 2.0) / 1_000_000.0;
                self.gpu_tflops = Some(tflops);
            }
        } else {
            // Try to get basic GPU info from system
            #[cfg(target_os = "linux")]
            {
                use std::fs;
                use std::path::Path;

                let gpu_dir = Path::new("/sys/class/drm");
                if gpu_dir.exists() {
                    if let Ok(entries) = fs::read_dir(gpu_dir) {
                        for entry in entries.flatten() {
                            let path = entry.path();
                            if let Some(name) = path.file_name() {
                                if name.to_string_lossy().starts_with("card") {
                                    // Try to read vendor name
                                    if let Ok(vendor) =
                                        fs::read_to_string(path.join("device/vendor"))
                                    {
                                        let vendor = vendor.trim();
                                        let gpu_type = match vendor {
                                            "0x1002" => "AMD",
                                            "0x8086" => "Intel",
                                            _ => "Unknown",
                                        };

                                        // Try to read device name
                                        if let Ok(device) =
                                            fs::read_to_string(path.join("device/device"))
                                        {
                                            self.gpu_info = Some(format!(
                                                "{} GPU (Device ID: {})",
                                                gpu_type,
                                                device.trim()
                                            ));
                                        } else {
                                            self.gpu_info = Some(format!("{} GPU", gpu_type));
                                        }
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // If no GPU info was found
        if self.gpu_info.is_none() {
            self.gpu_info = Some("No GPU detected or unable to get GPU information".to_string());
        }

        Ok(())
    }

    pub fn is_wan_device(&self) -> bool {
        if self.net_id.is_some() {
            let net_id = self.net_id.as_ref().unwrap();
            if net_id.starts_with("wan") {
                return true;
            }
        }
        return false;
    }

    fn get_os_type() -> String {
        #[cfg(all(target_os = "macos"))]
        let os_type = "apple";
        #[cfg(all(target_os = "linux"))]
        let os_type = "linux";
        #[cfg(all(target_os = "windows"))]
        let os_type = "windows";
        #[cfg(all(target_os = "android"))]
        let os_type = "android";
        #[cfg(all(target_os = "ios"))]
        let os_type = "ios";
        os_type.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_device_info() {
        let mut device_info = DeviceInfo::new("ood1@192.168.1.1#wan1", DID::new("bns", "ood1"));
        device_info.auto_fill_by_system_info().await.unwrap();
        let device_info_json = serde_json::to_string_pretty(&device_info).unwrap();
        println!("{}", device_info_json);
    }

    #[test]
    fn test_device_mini_config() {
        let owner_private_key_pem = r#"
        -----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIJBRONAzbwpIOwm0ugIQNyZJrDXxZF7HoPWAZesMedOr
        -----END PRIVATE KEY-----
        "#;
        let owner_jwk: Jwk = serde_json::from_value(json!(
            {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": "T4Quc1L6Ogu4N2tTKOvneV1yYnBcmhP89B_RsuFsJZ8"
            }
        ))
        .unwrap();
        let owner_private_key: EncodingKey =
            EncodingKey::from_ed_pem(owner_private_key_pem.as_bytes()).unwrap();
        let owner_public_key = DecodingKey::from_jwk(&owner_jwk).unwrap();

        let now = buckyos_get_unix_timestamp();
        let exp: u64 = now + 3600 * 24 * 365 * 5;

        let mini_config = DeviceMiniConfig {
            name: "ood1".to_string(),
            x: "5bUuyWLOKyCre9az_IhJVIuOw8bA0gyKjstcYGHbaPE".to_string(),
            rtcp_port: None,
            exp: exp,
            extra_info: HashMap::new(),
        };

        let mini_json = serde_json::to_string_pretty(&mini_config).unwrap();
        println!("json {}", mini_json);

        let mini_jwt = mini_config.to_jwt(&owner_private_key).unwrap();
        let txt_record = format!("DEV={};", mini_jwt);
        println!("mini_jwt:{} {}", &txt_record, txt_record.len());

        let mini_config_from_jwt =
            DeviceMiniConfig::from_jwt(&mini_jwt, &owner_public_key).unwrap();
        let mini_config_from_jwt_json =
            serde_json::to_string_pretty(&mini_config_from_jwt).unwrap();
        println!("jwt decoded json: {}", mini_config_from_jwt_json);

        let device_config = DeviceConfig::new_by_mini_config(
            mini_config,
            DID::new("bns", "ood1"),
            DID::new("bns", "lzc"),
        );
        let device_config_json = serde_json::to_string_pretty(&device_config).unwrap();
        println!("{}", device_config_json);
    }

    #[tokio::test]
    async fn test_device_config() {
        let owner_private_key_pem = r#"
        -----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIJBRONAzbwpIOwm0ugIQNyZJrDXxZF7HoPWAZesMedOr
        -----END PRIVATE KEY-----
        "#;
        let owner_jwk = json!(
            {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": "T4Quc1L6Ogu4N2tTKOvneV1yYnBcmhP89B_RsuFsJZ8"
            }
        );
        let public_key_jwk: jsonwebtoken::jwk::Jwk = serde_json::from_value(owner_jwk).unwrap();
        let owner_private_key: EncodingKey =
            EncodingKey::from_ed_pem(owner_private_key_pem.as_bytes()).unwrap();
        let public_key = DecodingKey::from_jwk(&public_key_jwk).unwrap();

        //ood1 privete key:

        let ood_public_key = json!(
            {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": "5bUuyWLOKyCre9az_IhJVIuOw8bA0gyKjstcYGHbaPE"
            }
        );
        let ood_key_jwk: jsonwebtoken::jwk::Jwk = serde_json::from_value(ood_public_key).unwrap();
        let mut device_config = DeviceConfig::new(
            "ood1",
            "5bUuyWLOKyCre9az_IhJVIuOw8bA0gyKjstcYGHbaPE".to_string(),
        );
        device_config.iss = "did:bns:lzc".to_string();

        let json_str = serde_json::to_string(&device_config).unwrap();
        println!("ood json_str: {}", json_str);

        let encoded = device_config.encode(Some(&owner_private_key)).unwrap();
        println!("ood encoded: {:?}", encoded);

        let decoded = DeviceConfig::decode(&encoded, Some(&public_key)).unwrap();
        println!(
            "ood decoded: {:?}",
            serde_json::to_string(&decoded).unwrap()
        );
        let token2 = decoded.encode(Some(&owner_private_key)).unwrap();

        let mut device_info_ood = DeviceInfo::from_device_doc(&decoded);
        device_info_ood.auto_fill_by_system_info().await;
        let device_info_str = serde_json::to_string(&device_info_ood).unwrap();
        println!("ood device_info: {}", device_info_str);

        assert_eq!(device_config, decoded);
        assert_eq!(encoded, token2);

        // Public Key (JWK base64URL):
        //  M3-pAdhs0uFkWmmjdHLBfs494R91QmQeXzCEhEHP-tI
        // Private Key (DER):
        //-----BEGIN PRIVATE KEY-----
        // MC4CAQAwBQYDK2VwBCIEIGdfBOWv07OemQY4BGe7LYqDOVY+qvwpcbAeI1d1VRBo
        // -----END PRIVATE KEY-----
        let gateway_public_key = json!(
            {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": "M3-pAdhs0uFkWmmjdHLBfs494R91QmQeXzCEhEHP-tI"
            }
        );
        let gateway_key_jwk: jsonwebtoken::jwk::Jwk =
            serde_json::from_value(gateway_public_key).unwrap();
        let device_config = DeviceConfig::new(
            "gateway",
            "M3-pAdhs0uFkWmmjdHLBfs494R91QmQeXzCEhEHP-tI".to_string(),
        );

        let json_str = serde_json::to_string(&device_config).unwrap();
        println!("gateway json_str: {:?}", json_str);

        let encoded = device_config.encode(Some(&owner_private_key)).unwrap();
        println!("gateway encoded: {:?}", encoded);

        let decoded = DeviceConfig::decode(&encoded, Some(&public_key)).unwrap();
        println!(
            "gateway decoded: {:?}",
            serde_json::to_string(&decoded).unwrap()
        );
        let token2 = decoded.encode(Some(&owner_private_key)).unwrap();

        assert_eq!(device_config, decoded);
        assert_eq!(encoded, token2);

        //Public Key (JWK base64URL): LBgzvFCD4VqQxTsO2LCZjs9FPVaQV2Dt0Q5W_lr4mr0
        //Private Key (DER):
        //-----BEGIN PRIVATE KEY-----
        //MC4CAQAwBQYDK2VwBCIEIHb18syrSj0BELLwDLJKugmj+63JUzDPIay6gZqUaBeM
        //-----END PRIVATE KEY-----
        let server_public_key = json!(
            {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": "LBgzvFCD4VqQxTsO2LCZjs9FPVaQV2Dt0Q5W_lr4mr0"
            }
        );
        let server_key_jwk: jsonwebtoken::jwk::Jwk =
            serde_json::from_value(server_public_key).unwrap();
        let mut device_config = DeviceConfig::new(
            "server1",
            "LBgzvFCD4VqQxTsO2LCZjs9FPVaQV2Dt0Q5W_lr4mr0".to_string(),
        );
        device_config.iss = "did:bns:waterflier".to_string();
        device_config.ip = None;
        device_config.net_id = None;

        let json_str = serde_json::to_string(&device_config).unwrap();
        println!("server json_str: {:?}", json_str);

        let encoded = device_config.encode(Some(&owner_private_key)).unwrap();
        println!("server encoded: {:?}", encoded);

        let decoded = DeviceConfig::decode(&encoded, Some(&public_key)).unwrap();
        println!(
            "server decoded: {:?}",
            serde_json::to_string(&decoded).unwrap()
        );
        let token2 = decoded.encode(Some(&owner_private_key)).unwrap();

        assert_eq!(device_config, decoded);
        assert_eq!(encoded, token2);
    }
}
