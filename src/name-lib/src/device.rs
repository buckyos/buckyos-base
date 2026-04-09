use buckyos_kit::*;
use jsonwebtoken::jwk::Jwk;
use jsonwebtoken::{encode, Algorithm, DecodingKey, EncodingKey, Header};
use log::error;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ops::Deref;
use std::process::Command;
use std::str::FromStr;
use thiserror::Error;

use crate::zone::{default_context, ServiceNode, VerificationMethodNode};
use crate::{
    decode_json_from_jwt_with_pk, decode_jwt_claim_without_verify, get_x_from_jwk,
    DIDDocumentTrait, EncodedDocument, NSError, NSResult, OODDescriptionString,
    DEFAULT_EXPIRE_TIME, DID,
};
use nvml_wrapper::enum_wrappers::device::Clock;
use nvml_wrapper::*;
use sysinfo::{Disks, Networks, System};

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
    pub fn new_by_device_config(device_config: &DeviceConfig) -> Self {
        let default_key = device_config.get_default_key().unwrap();
        let x = get_x_from_jwk(&default_key).unwrap();
        Self {
            name: device_config.name.clone(),
            x,
            rtcp_port: device_config.rtcp_port.clone(),
            exp: device_config.exp,
            extra_info: HashMap::new(),
        }
    }

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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zone_did: Option<DID>, // The zone did where the Device is located
    pub owner: DID, //owner did，原则上应该与zone的owner相同

    pub device_type: String, //[ood,server,sensor
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub device_mini_config_jwt: Option<String>,
    pub name: String, //short name,like ood1
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rtcp_port: Option<u32>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub ips: Vec<IpAddr>, //main_ip
    #[serde(skip_serializing_if = "Option::is_none")]
    pub net_id: Option<String>, // lan1 | wan, when None it represents lan0
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ddns_sn_url: Option<String>,

    #[serde(skip_serializing_if = "is_true", default = "bool_default_true")]
    pub support_container: bool,
    #[serde(default)]
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub capbilities: HashMap<String, i64>, //capbility id -> resource value (like memory size, cpu core count, etc.)
}

impl DeviceConfig {
    pub fn new_by_jwk(name: &str, pk: Jwk) -> Self {
        let x = get_x_from_jwk(&pk).unwrap();
        return DeviceConfig::new(name, x);
    }

    pub fn new_by_mini_config(
        mini_config_jwt: &String,
        mini_config: &DeviceMiniConfig,
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
            device_mini_config_jwt: Some(mini_config_jwt.clone()),
            context: default_context(),
            id: DID::from_str(&did).unwrap(),
            name: mini_config.name.clone(),
            device_type: "ood".to_string(),
            ips: vec![],
            net_id: None,
            ddns_sn_url: None,
            rtcp_port: mini_config.rtcp_port,
            verification_method: vec![VerificationMethodNode {
                key_type: "Ed25519VerificationKey2020".to_string(),
                key_id: "#main_key".to_string(),
                key_controller: did.clone(),
                public_key: public_key_jwk,
            }],
            authentication: vec!["#main_key".to_string()],
            assertion_method: vec!["#main_key".to_string()],
            service: vec![],
            support_container: true,
            zone_did: Some(zone_did.clone()),
            owner: owner_did,
            capbilities: HashMap::new(),
            exp: mini_config.exp,
            iat: mini_config.exp - DEFAULT_EXPIRE_TIME,
            extra_info: HashMap::new(),
        }
    }

    pub fn new_by_ood_desc_string(ood_desc_string: &OODDescriptionString) -> Self {
        unimplemented!()
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
            ips: vec![],
            net_id: None,
            ddns_sn_url: None,
            rtcp_port: None,
            verification_method: vec![VerificationMethodNode {
                key_type: "Ed25519VerificationKey2020".to_string(),
                key_id: "#main_key".to_string(),
                key_controller: did.clone(),
                public_key: public_key_jwk,
            }],
            authentication: vec!["#main_key".to_string()],
            assertion_method: vec!["#main_key".to_string()],
            service: vec![],
            support_container: true,
            zone_did: None,
            owner: DID::undefined(),
            device_mini_config_jwt: None,
            capbilities: HashMap::new(),
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
        // self.service.push(ServiceNode {
        //     id: format!("{}#lastDoc", self.id.to_string()),
        //     service_type: "DIDDoc".to_string(),
        //     service_endpoint: format!(
        //         "https://{}/resolve/{}",
        //         zone_did.to_host_name(),
        //         self.id.to_string()
        //     ),
        // });
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
        return Some(self.owner.to_string());
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

    #[serde(default)]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub all_ip: Vec<IpAddr>,

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
            all_ip: vec![],
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
            //extra_info: HashMap::new(),
        };

        return result_info;
    }

    // //return (short_name,net_id,ip_addr)
    // pub fn get_net_info_from_ood_desc_string(
    //     ood_desc_string: &str,
    // ) -> (String, Option<String>, Option<IpAddr>) {
    //     let ip: Option<IpAddr>;
    //     let net_id: Option<String>;

    //     let parts: Vec<&str> = ood_desc_string.split('@').collect();
    //     let hostname = parts[0];
    //     if parts.len() > 1 {
    //         let ip_str = parts[1];
    //         let ip_result = IpAddr::from_str(ip_str);
    //         if ip_result.is_ok() {
    //             ip = Some(ip_result.unwrap());
    //         } else {
    //             ip = None;
    //         }
    //     } else {
    //         ip = None;
    //     }

    //     let parts: Vec<&str> = ood_desc_string.split('#').collect();
    //     if parts.len() == 2 {
    //         net_id = Some(parts[1].to_string());
    //     } else {
    //         net_id = None;
    //     }
    //     return (hostname.to_string(), net_id, ip);
    // }

    pub fn new(ood_string: &OODDescriptionString, did: DID) -> Self {
        //device_string format: hostname@[ip]#[netid]
        let device_name = ood_string.name.clone();
        let net_id = ood_string.net_id.clone();
        let ip = ood_string.ip.clone();
        let os_type = Self::get_os_type();

        #[cfg(all(target_arch = "x86_64"))]
        let arch = "amd64";
        #[cfg(all(target_arch = "aarch64"))]
        let arch = "aarch64";

        let mut config = DeviceConfig::new(device_name.as_str(), did.id.to_string());
        if ip.is_some() {
            config.ips.push(ip.unwrap());
        }
        config.net_id = net_id;
        config.device_type = "ood".to_string();

        DeviceInfo {
            device_doc: config,
            state: Some("Ready".to_string()),
            arch: arch.to_string(),
            os: os_type.to_string(),
            update_time: buckyos_get_unix_timestamp(),
            base_os_info: None,
            all_ip: vec![],
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
            //extra_info: HashMap::new(),
        }
    }

    pub async fn auto_fill_by_system_info(&mut self) -> NSResult<()> {
        let mut sys = System::new_all();
        sys.refresh_all();

        let discovered_ips = collect_reachable_ip_addrs();
        self.all_ip = discovered_ips.clone();
        for ip in discovered_ips {
            push_unique_ip(&mut self.device_doc.ips, ip);
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
        // Get disk space information
        let mut total_space = 0u64;
        let mut used_space = 0u64;
        let disks = Disks::new_with_refreshed_list();
        for disk in disks.list() {
            let total = disk.total_space();
            let available = disk.available_space();
            total_space += total;
            used_space += total.saturating_sub(available);
        }
        self.total_space = Some(total_space);
        self.disk_usage = Some(used_space);
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

fn push_unique_ip(ips: &mut Vec<IpAddr>, ip: IpAddr) {
    if !ips.contains(&ip) {
        ips.push(ip);
    }
}

fn collect_reachable_ip_addrs() -> Vec<IpAddr> {
    let mut ips = collect_reachable_ip_addrs_from_command()
        .filter(|ips| !ips.is_empty())
        .unwrap_or_else(collect_reachable_ip_addrs_from_sysinfo);
    ips.retain(|ip| should_collect_ip(*ip));

    let mut deduped = Vec::with_capacity(ips.len());
    for ip in ips {
        push_unique_ip(&mut deduped, ip);
    }
    deduped
}

fn collect_reachable_ip_addrs_from_sysinfo() -> Vec<IpAddr> {
    let networks = Networks::new_with_refreshed_list();
    let mut ips = Vec::new();
    for (_, network) in &networks {
        for ip_network in network.ip_networks() {
            if should_collect_ip(ip_network.addr) {
                push_unique_ip(&mut ips, ip_network.addr);
            }
        }
    }
    ips
}

fn collect_reachable_ip_addrs_from_command() -> Option<Vec<IpAddr>> {
    #[cfg(target_os = "linux")]
    {
        let output = run_command_stdout("ip", &["-j", "addr", "show"])?;
        return Some(parse_linux_ip_addr_output(&output));
    }

    #[cfg(target_os = "macos")]
    {
        let output = run_command_stdout("ifconfig", &[])?;
        return Some(parse_macos_ifconfig_output(&output));
    }

    #[cfg(target_os = "windows")]
    {
        let powershell_args = [
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Get-NetIPAddress | Select-Object IPAddress,AddressFamily,InterfaceOperationalStatus,SkipAsSource,AddressState,Type,PrefixOrigin,SuffixOrigin,@{Name='AddressOrigin';Expression={ if ($_.PSObject.Properties['AddressOrigin']) { $_.AddressOrigin } else { $_.PrefixOrigin } }} | ConvertTo-Json -Depth 3",
        ];
        let output = run_command_stdout("powershell.exe", &powershell_args)
            .or_else(|| run_command_stdout("powershell", &powershell_args))?;
        return Some(parse_windows_net_ip_address_output(&output));
    }

    #[allow(unreachable_code)]
    None
}

fn run_command_stdout(command: &str, args: &[&str]) -> Option<String> {
    let mut cmd = Command::new(command);
    cmd.args(args);

    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(windows_hidden_process_creation_flags());
    }

    let output = cmd.output().ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8(output.stdout).ok()
}

#[cfg(target_os = "windows")]
fn windows_hidden_process_creation_flags() -> u32 {
    const DETACHED_PROCESS: u32 = 0x0000_0008;
    const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW
}

fn parse_linux_ip_addr_output(output: &str) -> Vec<IpAddr> {
    let mut ips = Vec::new();
    let interfaces: serde_json::Value = match serde_json::from_str(output) {
        Ok(value) => value,
        Err(_) => return ips,
    };

    let Some(interfaces) = interfaces.as_array() else {
        return ips;
    };

    for interface in interfaces {
        let is_up = interface
            .get("operstate")
            .and_then(|value| value.as_str())
            .map(|state| matches!(state, "UP" | "UNKNOWN"))
            .unwrap_or(true);
        if !is_up {
            continue;
        }

        let Some(addr_infos) = interface
            .get("addr_info")
            .and_then(|value| value.as_array())
        else {
            continue;
        };

        for addr_info in addr_infos {
            let Some(local) = addr_info.get("local").and_then(|value| value.as_str()) else {
                continue;
            };

            let scope = addr_info
                .get("scope")
                .and_then(|value| value.as_str())
                .unwrap_or_default();
            if matches!(scope, "host" | "nowhere") {
                continue;
            }

            if linux_addr_is_ephemeral(addr_info) {
                continue;
            }

            let Ok(ip) = local.parse::<IpAddr>() else {
                continue;
            };

            if ip.is_ipv6() && scope != "global" {
                continue;
            }

            if should_collect_ip(ip) {
                push_unique_ip(&mut ips, ip);
            }
        }
    }

    ips
}

fn linux_addr_is_ephemeral(addr_info: &serde_json::Value) -> bool {
    if addr_info
        .get("ifa_flags")
        .and_then(|value| value.as_u64())
        .map(|flags| (flags & 0x01) != 0)
        .unwrap_or(false)
    {
        return true;
    }

    if addr_info
        .get("temporary")
        .and_then(|value| value.as_bool())
        .unwrap_or(false)
    {
        return true;
    }

    if addr_info
        .get("deprecated")
        .and_then(|value| value.as_bool())
        .unwrap_or(false)
    {
        return true;
    }

    let Some(flags) = addr_info.get("flags").and_then(|value| value.as_array()) else {
        return false;
    };

    flags.iter().filter_map(|value| value.as_str()).any(|flag| {
        matches!(
            flag,
            "temporary" | "deprecated" | "tentative" | "dadfailed" | "optimistic"
        )
    })
}

fn parse_macos_ifconfig_output(output: &str) -> Vec<IpAddr> {
    #[derive(Default)]
    struct InterfaceBlock {
        is_up: bool,
        is_running: bool,
        is_active: Option<bool>,
        addrs: Vec<IpAddr>,
    }

    let mut ips = Vec::new();
    let mut current_name: Option<String> = None;
    let mut current_block = InterfaceBlock::default();

    let mut flush_current = |ips: &mut Vec<IpAddr>,
                             current_name: &mut Option<String>,
                             current_block: &mut InterfaceBlock| {
        if current_name.is_some()
            && current_block.is_up
            && current_block.is_running
            && current_block.is_active.unwrap_or(true)
        {
            for ip in current_block.addrs.drain(..) {
                push_unique_ip(ips, ip);
            }
        } else {
            current_block.addrs.clear();
        }
        *current_name = None;
        *current_block = InterfaceBlock::default();
    };

    for line in output.lines() {
        let starts_with_whitespace = line
            .chars()
            .next()
            .map(|ch| ch.is_whitespace())
            .unwrap_or(false);
        if !starts_with_whitespace {
            flush_current(&mut ips, &mut current_name, &mut current_block);
            current_name = line
                .split_once(':')
                .map(|(name, _)| name.trim().to_string())
                .filter(|name| !name.is_empty());

            let flags = line
                .split_once('<')
                .and_then(|(_, rest)| rest.split_once('>'))
                .map(|(flags, _)| flags)
                .unwrap_or_default();
            current_block.is_up = flags.split(',').any(|flag| flag == "UP");
            current_block.is_running = flags.split(',').any(|flag| flag == "RUNNING");
            continue;
        }

        let trimmed = line.trim();
        if let Some(status) = trimmed.strip_prefix("status:") {
            current_block.is_active = Some(status.trim() == "active");
            continue;
        }

        let tokens: Vec<&str> = trimmed.split_whitespace().collect();
        if tokens.len() < 2 {
            continue;
        }

        let family = tokens[0];
        if family != "inet" && family != "inet6" {
            continue;
        }

        let addr_token = tokens[1];
        let attrs = &tokens[2..];

        if macos_addr_is_ephemeral(family, attrs) {
            continue;
        }

        let addr_without_zone = addr_token.split('%').next().unwrap_or(addr_token);
        let Ok(ip) = addr_without_zone.parse::<IpAddr>() else {
            continue;
        };

        if should_collect_ip(ip) {
            current_block.addrs.push(ip);
        }
    }

    flush_current(&mut ips, &mut current_name, &mut current_block);
    ips
}

fn parse_windows_net_ip_address_output(output: &str) -> Vec<IpAddr> {
    let mut ips = Vec::new();
    let json: serde_json::Value = match serde_json::from_str(output) {
        Ok(value) => value,
        Err(_) => return ips,
    };

    let entries: Vec<&serde_json::Value> = match &json {
        serde_json::Value::Array(items) => items.iter().collect(),
        serde_json::Value::Object(_) => vec![&json],
        _ => return ips,
    };

    for entry in entries {
        if entry
            .get("InterfaceOperationalStatus")
            .and_then(|value| value.as_str())
            .map(|status| status != "Up")
            .unwrap_or(false)
        {
            continue;
        }

        if entry
            .get("SkipAsSource")
            .and_then(|value| value.as_bool())
            .unwrap_or(false)
        {
            continue;
        }

        if entry
            .get("Type")
            .and_then(|value| value.as_str())
            .map(|addr_type| addr_type != "Unicast")
            .unwrap_or(false)
        {
            continue;
        }

        if entry
            .get("AddressState")
            .and_then(|value| value.as_str())
            .map(|state| state != "Preferred")
            .unwrap_or(false)
        {
            continue;
        }

        let Some(ip_str) = entry.get("IPAddress").and_then(|value| value.as_str()) else {
            continue;
        };
        let Ok(ip) = ip_str.parse::<IpAddr>() else {
            continue;
        };

        if windows_addr_is_ephemeral(entry, ip) {
            continue;
        }

        if !windows_address_family_matches(entry, ip) {
            continue;
        }

        if should_collect_ip(ip) {
            push_unique_ip(&mut ips, ip);
        }
    }

    ips
}

fn windows_addr_is_ephemeral(entry: &serde_json::Value, ip: IpAddr) -> bool {
    if !ip.is_ipv6() {
        return false;
    }

    if entry
        .get("AddressOrigin")
        .and_then(|value| value.as_str())
        .or_else(|| entry.get("PrefixOrigin").and_then(|value| value.as_str()))
        .map(|origin| !matches!(origin, "Dhcp" | "Manual"))
        .unwrap_or(false)
    {
        return true;
    }

    if entry
        .get("SuffixOrigin")
        .and_then(|value| value.as_str())
        .map(|origin| origin == "Random")
        .unwrap_or(false)
    {
        return true;
    }

    entry
        .get("AddressState")
        .and_then(|value| value.as_str())
        .map(|state| matches!(state, "Deprecated" | "Tentative" | "Duplicate" | "Invalid"))
        .unwrap_or(false)
}

fn windows_address_family_matches(entry: &serde_json::Value, ip: IpAddr) -> bool {
    match entry.get("AddressFamily") {
        Some(serde_json::Value::String(family)) => {
            matches!(
                (family.as_str(), ip),
                ("IPv4", IpAddr::V4(_)) | ("IPv6", IpAddr::V6(_))
            )
        }
        Some(serde_json::Value::Number(family)) => {
            matches!(
                (family.as_u64(), ip),
                (Some(2), IpAddr::V4(_)) | (Some(23), IpAddr::V6(_))
            )
        }
        _ => true,
    }
}

fn macos_addr_is_ephemeral(family: &str, attrs: &[&str]) -> bool {
    if family != "inet6" {
        return false;
    }

    attrs.iter().any(|attr| {
        matches!(
            *attr,
            "temporary" | "deprecated" | "tentative" | "duplicated" | "detached"
        )
    })
}

fn should_collect_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => should_collect_ipv4(ipv4),
        IpAddr::V6(ipv6) => should_collect_ipv6(ipv6),
    }
}

fn should_collect_ipv4(ip: Ipv4Addr) -> bool {
    if ip.is_loopback()
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_unspecified()
    {
        return false;
    }

    true
}

fn should_collect_ipv6(ip: Ipv6Addr) -> bool {
    if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() || ip.is_unicast_link_local() {
        return false;
    }

    let segments = ip.segments();
    if (segments[0] & 0xfe00) == 0xfc00 {
        return false;
    }

    if segments[0] == 0x2001 && segments[1] == 0x0db8 {
        return false;
    }

    if segments[0] == 0x2002 {
        return false;
    }

    if segments[0] == 0x2001 && segments[1] == 0x0000 {
        return false;
    }

    if segments[0] == 0x0064 && segments[1] == 0xff9b && segments[2] == 0 && segments[3] == 0 {
        return false;
    }

    if segments[0] == 0
        && segments[1] == 0
        && segments[2] == 0
        && segments[3] == 0
        && segments[4] == 0
        && segments[5] == 0xffff
    {
        return false;
    }

    true
}

//DeviceMiniInfo 用于激活协议，或向非Zone内用户展示设备信息的场景。不包含敏感信息。
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct DeviceMiniInfo {
    pub hostname: String, //hostname of the device
    pub device_type: String,
    pub arch: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_os_info: Option<String>,
    pub state: String, //actived,inactive,error
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_url: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_info: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_num: Option<u32>, //cpu核心数
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_mhz: Option<u32>, //cpu的最大性能,单位是MHZ
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_ratio: Option<f32>, //cpu的性能比率

    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_mem: Option<u64>, //单位是bytes

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
    #[serde(flatten)]
    pub extra_info: HashMap<String, serde_json::Value>,
}

impl Default for DeviceMiniInfo {
    fn default() -> Self {
        Self {
            hostname: System::host_name().unwrap_or_default(),
            device_type: "ood".to_string(),
            arch: "".to_string(),
            state: "inactive".to_string(),
            active_url: None,
            cpu_info: None,
            cpu_num: None,
            cpu_mhz: None,
            cpu_ratio: None,
            total_mem: None,
            total_space: None,
            disk_usage: None,
            gpu_info: None,
            gpu_tflops: None,
            gpu_total_mem: None,
            gpu_used_mem: None,
            gpu_load: None,
            base_os_info: None,
            extra_info: HashMap::new(),
        }
    }
}

impl DeviceMiniInfo {
    pub async fn auto_fill_by_system_info(&mut self) -> NSResult<()> {
        let mut sys = System::new_all();
        sys.refresh_all();

        self.arch = System::cpu_arch().unwrap_or_default();
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

        // Get memory information
        self.total_mem = Some(sys.total_memory());

        // Get disk space information
        let mut total_space = 0u64;
        let mut used_space = 0u64;
        let disks = Disks::new_with_refreshed_list();
        for disk in disks.list() {
            let total = disk.total_space();
            let available = disk.available_space();
            total_space += total;
            used_space += total.saturating_sub(available);
        }
        self.total_space = Some(total_space);
        self.disk_usage = Some(used_space);

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
}
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_device_mini_info() {
        let mut device_mini_info = DeviceMiniInfo::default();
        device_mini_info.auto_fill_by_system_info().await.unwrap();

        device_mini_info.active_url = Some("./index.html".to_string());
        let device_mini_info_json = serde_json::to_string_pretty(&device_mini_info).unwrap();
        println!("{}", device_mini_info_json);
    }

    #[tokio::test]
    async fn test_device_info() {
        let ood_string = OODDescriptionString::from_str("ood1@192.168.1.1#wan1").unwrap();
        let mut device_info = DeviceInfo::new(&ood_string, DID::new("bns", "ood1"));
        device_info.auto_fill_by_system_info().await.unwrap();
        let device_info_json = serde_json::to_string_pretty(&device_info).unwrap();
        println!("{}", device_info_json);
    }

    #[test]
    fn test_filter_collectable_ip_addresses() {
        assert!(should_collect_ip(
            "2600:1700:1150:9440::27".parse().unwrap()
        ));
        assert!(!should_collect_ip("fd00::1".parse().unwrap()));
        assert!(should_collect_ip("192.168.1.1".parse().unwrap()));
        assert!(should_collect_ip("169.254.1.1".parse().unwrap()));
        assert!(!should_collect_ip("fe80::1".parse().unwrap()));
        assert!(!should_collect_ip("2002:c000:0204::1".parse().unwrap()));
        assert!(!should_collect_ip(
            "2001:0000:4136:e378:8000:63bf:3fff:fdd2".parse().unwrap()
        ));
        assert!(!should_collect_ip("64:ff9b::c000:0204".parse().unwrap()));
        assert!(!should_collect_ip("::ffff:192.0.2.128".parse().unwrap()));
        assert!(!should_collect_ip("::1".parse().unwrap()));
        assert!(!should_collect_ip("127.0.0.1".parse().unwrap()));
        assert!(!should_collect_ip("224.0.0.1".parse().unwrap()));
        assert!(!should_collect_ip("ff02::1".parse().unwrap()));
    }

    #[test]
    fn test_parse_macos_ifconfig_output() {
        let output = r#"en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
	inet6 fe80::c20:e642:71ec:a899%en0 prefixlen 64 secured scopeid 0xd
	inet6 fd42:7582::10 prefixlen 64 autoconf secured
	inet6 2600:1700:1150:9440:8a6:5e43:a1f2:980d prefixlen 64 autoconf secured
	inet6 2600:1700:1150:9440:2011:5273:b721:1b9 prefixlen 64 deprecated autoconf temporary
	inet6 2600:1700:1150:9440::27 prefixlen 64 dynamic
	inet 192.168.1.143 netmask 0xffffff00 broadcast 192.168.1.255
	status: active
en5: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
	inet6 2600:1700:1150:9440:71e1:db03:2c35:ffc1 prefixlen 64 autoconf temporary
	status: inactive
"#;

        let ips = parse_macos_ifconfig_output(output);
        assert_eq!(
            ips,
            vec![
                "2600:1700:1150:9440:8a6:5e43:a1f2:980d"
                    .parse::<IpAddr>()
                    .unwrap(),
                "2600:1700:1150:9440::27".parse::<IpAddr>().unwrap(),
                "192.168.1.143".parse::<IpAddr>().unwrap(),
            ]
        );
    }

    #[test]
    fn test_parse_linux_ip_addr_output() {
        let output = r#"[
  {
    "ifname": "eth0",
    "operstate": "UP",
    "addr_info": [
      { "family": "inet", "local": "192.168.1.143", "scope": "global" },
      { "family": "inet6", "local": "fe80::1", "scope": "link" },
      { "family": "inet6", "local": "fd42:7582::10", "scope": "global" },
      { "family": "inet6", "local": "2404:6800:4008:80b::200d", "scope": "global", "ifa_flags": 1 },
      { "family": "inet6", "local": "2404:6800:4008:80b::200e", "scope": "global" },
      { "family": "inet6", "local": "2404:6800:4008:80b::200f", "scope": "global", "temporary": true },
      { "family": "inet6", "local": "2404:6800:4008:80b::2010", "scope": "global", "flags": ["deprecated"] }
    ]
  },
  {
    "ifname": "eth1",
    "operstate": "DOWN",
    "addr_info": [
      { "family": "inet6", "local": "2001:db8::1", "scope": "global" }
    ]
  }
]"#;

        let ips = parse_linux_ip_addr_output(output);
        assert_eq!(
            ips,
            vec![
                "192.168.1.143".parse::<IpAddr>().unwrap(),
                "2404:6800:4008:80b::200e".parse::<IpAddr>().unwrap(),
            ]
        );
    }

    #[test]
    fn test_parse_windows_net_ip_address_output() {
        let output = r#"[
  {
    "IPAddress": "192.168.1.143",
    "AddressFamily": "IPv4",
    "InterfaceOperationalStatus": "Up",
    "SkipAsSource": false,
    "AddressState": "Preferred",
    "Type": "Unicast"
  },
  {
    "IPAddress": "fd42:7582::10",
    "AddressFamily": "IPv6",
    "InterfaceOperationalStatus": "Up",
    "SkipAsSource": false,
    "AddressState": "Preferred",
    "Type": "Unicast",
    "AddressOrigin": "Manual",
    "SuffixOrigin": "Manual"
  },
  {
    "IPAddress": "2600:1700:1150:9440::27",
    "AddressFamily": "IPv6",
    "InterfaceOperationalStatus": "Up",
    "SkipAsSource": false,
    "AddressState": "Preferred",
    "Type": "Unicast",
    "AddressOrigin": "Dhcp",
    "SuffixOrigin": "Link"
  },
  {
    "IPAddress": "2600:1700:1150:9440:71e1:db03:2c35:ffc1",
    "AddressFamily": "IPv6",
    "InterfaceOperationalStatus": "Up",
    "SkipAsSource": false,
    "AddressState": "Preferred",
    "Type": "Unicast",
    "AddressOrigin": "Dhcp",
    "SuffixOrigin": "Random"
  },
  {
    "IPAddress": "2600:1700:1150:9440::88",
    "AddressFamily": "IPv6",
    "InterfaceOperationalStatus": "Up",
    "SkipAsSource": false,
    "AddressState": "Preferred",
    "Type": "Unicast",
    "AddressOrigin": "RouterAdvertisement",
    "SuffixOrigin": "Link"
  },
  {
    "IPAddress": "2600:1700:1150:9440::99",
    "AddressFamily": "IPv6",
    "InterfaceOperationalStatus": "Down",
    "SkipAsSource": false,
    "AddressState": "Preferred",
    "Type": "Unicast",
    "AddressOrigin": "Dhcp",
    "SuffixOrigin": "Link"
  }
]"#;

        let ips = parse_windows_net_ip_address_output(output);
        assert_eq!(
            ips,
            vec![
                "192.168.1.143".parse::<IpAddr>().unwrap(),
                "2600:1700:1150:9440::27".parse::<IpAddr>().unwrap(),
            ]
        );
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
            &mini_jwt,
            &mini_config,
            DID::new("bns", "ood1"),
            DID::new("bns", "lzc"),
        );
        let device_config_json = serde_json::to_string_pretty(&device_config).unwrap();
        println!("{}", device_config_json);

        let device_mini_config = DeviceMiniConfig::new_by_device_config(&device_config);
        assert_eq!(mini_config, device_mini_config);
        let device_mini_config_json = serde_json::to_string_pretty(&device_mini_config).unwrap();
        println!("{}", device_mini_config_json);

        let device_mini_config_jwt = device_mini_config.to_jwt(&owner_private_key).unwrap();
        println!("device mini config jwt: {}", device_mini_config_jwt);
        assert_eq!(mini_jwt, device_mini_config_jwt);
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
        device_config.owner = DID::new("bns", "lzc");

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

        let device_info2 = serde_json::from_str::<DeviceInfo>(&device_info_str).unwrap();
        let device_info2_str = serde_json::to_string(&device_info2).unwrap();
        println!("ood device_info2: {}", device_info2_str);
        let device_info3 = serde_json::from_str::<DeviceInfo>(&device_info2_str).unwrap();

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
        device_config.owner = DID::new("bns", "waterflier");
        device_config.ips = Vec::new();
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
