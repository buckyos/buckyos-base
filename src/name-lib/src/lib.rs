#![allow(dead_code)]
#![allow(unused)]

mod zone;
mod device;
mod agent;
mod did;
mod utility;
mod user;

pub use zone::*;
pub use device::*;
pub use agent::*;
pub use did::*;
use serde::{Deserialize, Serialize};
pub use utility::*;
pub use user::OwnerConfig;

use log::*;
use once_cell::sync::Lazy;
use once_cell::sync::OnceCell;
use std::env;
use std::net::IpAddr;
use std::path::PathBuf;
use tokio::sync::Mutex;

pub static CURRENT_DEVICE_CONFIG: OnceCell<DeviceConfig> = OnceCell::new();
pub const DEFAULT_EXPIRE_TIME: u64 = 3600 * 24 * 365 * 5;

pub fn try_load_current_device_config_from_env() -> NSResult<()> {
    let device_doc = env::var("BUCKYOS_THIS_DEVICE");
    if device_doc.is_err() {
        return Err(NSError::NotFound("BUCKY_DEVICE_DOC not set".to_string()));
    }
    let device_doc = device_doc.unwrap();

    let device_config = serde_json::from_str(device_doc.as_str());
    if device_config.is_err() {
        warn!("parse device_doc format error");
        return Err(NSError::Failed("device_doc format error".to_string()));
    }
    let device_config: DeviceConfig = device_config.unwrap();
    let set_result = CURRENT_DEVICE_CONFIG.set(device_config);
    if set_result.is_err() {
        warn!("Failed to set CURRENT_DEVICE_CONFIG");
        return Err(NSError::Failed(
            "Failed to set CURRENT_DEVICE_CONFIG".to_string(),
        ));
    }
    Ok(())
}

//NodeIdentity from ood active progress ，move to buckyos
#[derive(Deserialize, Debug, Serialize)]
pub struct NodeIdentityConfig {
    pub zone_did: DID,                            // $name.buckyos.org or did:ens:$name
    pub owner_public_key: jsonwebtoken::jwk::Jwk, //owner is zone_owner, must same as zone_config.default_auth_key
    pub owner_did: DID,                           //owner's did
    pub device_doc_jwt: String,                   //device document,jwt string,siged by owner
    pub device_mini_doc_jwt: String,               //device mini document,jwt string,siged by owner
    pub zone_iat: u32,
    
    //device_private_key: ,storage in partical file
}

impl NodeIdentityConfig {
    pub fn load_node_identity_config(file_path: &PathBuf) -> NSResult<(NodeIdentityConfig)> {
        let contents = std::fs::read_to_string(file_path.clone()).map_err(|err| {
            error!("read {} failed! {}", file_path.to_string_lossy(), err);
            return NSError::ReadLocalFileError(format!(
                "read {} failed! {}",
                file_path.to_string_lossy(),
                err
            ));
        })?;

        let config: NodeIdentityConfig = serde_json::from_str(&contents).map_err(|err| {
            error!("parse {} failed! {}", file_path.to_string_lossy(), err);
            return NSError::ReadLocalFileError(format!(
                "Failed to parse NodeIdentityConfig JSON: {}",
                err
            ));
        })?;

        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zone::OODDescriptionString;
    use std::str::FromStr;
    #[test]
    fn test_utility() {
        assert_eq!(is_did("did:example:123456789abcdefghi"), true);
        assert_eq!(is_did("www.buckyos.org"), false);
    }

    #[test]
    fn test_is_valid_name() {
        // length must be > 6
        assert!(!is_valid_name("short", NameType::User));
        assert!(!is_valid_name("abc123", NameType::Device)); // len 6, need > 6
        assert!(is_valid_name("mydevice", NameType::Device));
        assert!(is_valid_name("waterflier", NameType::User));
        assert!(is_valid_name("myagent1", NameType::Agent));

        // valid DNS: lowercase, letter start, no hyphen at end
        assert!(!is_valid_name("MyDevice", NameType::Device)); // uppercase
        assert!(!is_valid_name("1device", NameType::Device)); // start with digit
        assert!(!is_valid_name("device-", NameType::Device)); // hyphen at end
        assert!(is_valid_name("my-device", NameType::Device));
        assert!(is_valid_name("sub.domain", NameType::User));

        // App: username-appname, both parts valid and length > 6
        assert!(is_valid_name("waterflier-myapp12", NameType::App)); // user 10, app 8
        assert!(!is_valid_name("waterflier-myapp", NameType::App)); // app "myapp" len 5
        assert!(!is_valid_name("user-app", NameType::App)); // user len 4, app len 3
        assert!(!is_valid_name("user123-app", NameType::App)); // app len 3
        assert!(!is_valid_name("user123-app456", NameType::App)); // app456 len 6
        assert!(is_valid_name("user1234-app4567", NameType::App));
        assert!(!is_valid_name("no-hyphen-here", NameType::App)); // splitn(2,'-') gives ["no","hyphen-here"], user "no" len 2

        // blacklist (exact match on each label)
        assert!(!is_valid_name("administrator", NameType::User)); // in blacklist
        assert!(!is_valid_name("localhost", NameType::Device)); // in blacklist
        assert!(!is_valid_name("sub.admin.domain", NameType::User)); // label "admin" blacklisted
        assert!(!is_valid_name("administrator-myapp123", NameType::App)); // username blacklisted
        assert!(!is_valid_name("user12345-administrator", NameType::App)); // appname blacklisted
    }

    #[tokio::test]
    async fn test_get_device_info() {
        let ood_string = OODDescriptionString::from_str("ood1").unwrap();
        let mut device_info = DeviceInfo::new(&ood_string, DID::new("bns", "ood1"));
        device_info.auto_fill_by_system_info().await.unwrap();
        println!("device_info: {:?}", device_info);
    }
}
