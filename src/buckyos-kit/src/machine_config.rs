use crate::get_buckyos_system_etc_dir;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;

const DEFAULT_SN_HOST: &str = "buckyos.ai";

#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
pub struct BuckyOSMachineConfig {
    #[serde(default)]
    pub web3_bridge: HashMap<String, String>,
    #[serde(default = "default_trust_did")]
    pub trust_did: Vec<String>, //did
    #[serde(default = "default_force_https")]
    pub force_https: bool,
    #[serde(default)]
    pub sn_host: Option<String>,

    #[serde(flatten)]
    pub extra_info: HashMap<String, serde_json::Value>,
}

fn default_force_https() -> bool {
    true
}

fn default_trust_did() -> Vec<String> {
    vec![
        "did:web:buckyos.org".to_string(),
        "did:web:buckyos.ai".to_string(),
        "did:web:buckyos.io".to_string(),
    ]
}

fn default_bns_resolver_host(sn_host: &str) -> String {
    format!("bns.{}", sn_host.trim())
}

impl Default for BuckyOSMachineConfig {
    fn default() -> Self {
        let sn_host = DEFAULT_SN_HOST.to_string();
        let mut web3_bridge = HashMap::new();
        web3_bridge.insert("bns".to_string(), default_bns_resolver_host(&sn_host));

        Self {
            web3_bridge,
            trust_did: default_trust_did(),
            force_https: default_force_https(),
            sn_host: Some(sn_host),
            extra_info: HashMap::new(),
        }
    }
}

impl BuckyOSMachineConfig {
    pub fn sn_host_or_default(&self) -> &str {
        self.sn_host
            .as_deref()
            .map(str::trim)
            .filter(|host| !host.is_empty())
            .unwrap_or(DEFAULT_SN_HOST)
    }

    pub fn default_bns_resolver_host(&self) -> String {
        default_bns_resolver_host(self.sn_host_or_default())
    }

    pub fn bns_resolver_host(&self) -> String {
        self.web3_bridge
            .get("bns")
            .map(String::as_str)
            .map(str::trim)
            .filter(|host| !host.is_empty())
            .map(ToString::to_string)
            .unwrap_or_else(|| self.default_bns_resolver_host())
    }

    pub fn load_machine_config() -> Option<Self> {
        let machine_config_path = get_buckyos_system_etc_dir().join("machine.json");
        let machine_config_file = File::open(machine_config_path);
        if machine_config_file.is_err() {
            return None;
        }
        let machine_config = serde_json::from_reader(machine_config_file.unwrap());
        if machine_config.is_err() {
            return None;
        }
        info!("load machine config from machine.json success.");
        return Some(machine_config.unwrap());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn default_bns_resolver_uses_default_sn_host() {
        let config = BuckyOSMachineConfig::default();

        assert_eq!(config.sn_host.as_deref(), Some("buckyos.ai"));
        assert_eq!(config.bns_resolver_host(), "bns.buckyos.ai");
        assert_eq!(
            config.web3_bridge.get("bns").map(String::as_str),
            Some("bns.buckyos.ai")
        );
    }

    #[test]
    fn bns_resolver_falls_back_to_sn_host_when_bridge_missing() {
        let mut config = BuckyOSMachineConfig::default();
        config.web3_bridge.remove("bns");
        config.sn_host = Some("example.org".to_string());

        assert_eq!(config.bns_resolver_host(), "bns.example.org");
    }

    #[test]
    fn explicit_bns_bridge_overrides_sn_host_default() {
        let mut config = BuckyOSMachineConfig::default();
        config
            .web3_bridge
            .insert("bns".to_string(), "resolver.example.org".to_string());
        config.sn_host = Some("example.org".to_string());

        assert_eq!(config.bns_resolver_host(), "resolver.example.org");
    }

    #[test]
    fn partial_machine_config_can_set_sn_host_only() {
        let config = serde_json::from_value::<BuckyOSMachineConfig>(json!({
            "sn_host": "example.org"
        }))
        .unwrap();

        assert_eq!(config.bns_resolver_host(), "bns.example.org");
        assert!(config.force_https);
        assert_eq!(config.trust_did, default_trust_did());
    }
}
