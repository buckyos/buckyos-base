use crate::get_buckyos_system_etc_dir;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;

const DEFAULT_BNS_HOST: &str = "bns.buckyos.ai";

#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
pub struct BuckyOSMachineConfig {
    #[serde(default)]
    pub web3_bridge: HashMap<String, String>,
    #[serde(default = "default_trust_did")]
    pub trust_did: Vec<String>, //did
    #[serde(default = "default_force_https")]
    pub force_https: bool,
    #[serde(default)]
    pub bns_host: Option<String>,

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

impl Default for BuckyOSMachineConfig {
    fn default() -> Self {
        let bns_host = DEFAULT_BNS_HOST.to_string();
        let mut web3_bridge = HashMap::new();
        web3_bridge.insert("bns".to_string(), bns_host.clone());

        Self {
            web3_bridge,
            trust_did: default_trust_did(),
            force_https: default_force_https(),
            bns_host: Some(bns_host),
            extra_info: HashMap::new(),
        }
    }
}

impl BuckyOSMachineConfig {
    pub fn bns_host_or_default(&self) -> &str {
        self.bns_host
            .as_deref()
            .map(str::trim)
            .filter(|host| !host.is_empty())
            .unwrap_or(DEFAULT_BNS_HOST)
    }

    pub fn default_bns_resolver_host(&self) -> String {
        self.bns_host_or_default().to_string()
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
    fn default_bns_resolver_uses_default_bns_host() {
        let config = BuckyOSMachineConfig::default();

        assert_eq!(config.bns_host.as_deref(), Some("bns.buckyos.ai"));
        assert_eq!(config.bns_resolver_host(), "bns.buckyos.ai");
        assert_eq!(
            config.web3_bridge.get("bns").map(String::as_str),
            Some("bns.buckyos.ai")
        );
    }

    #[test]
    fn bns_resolver_falls_back_to_bns_host_when_bridge_missing() {
        let mut config = BuckyOSMachineConfig::default();
        config.web3_bridge.remove("bns");
        config.bns_host = Some("resolver.example.org".to_string());

        assert_eq!(config.bns_resolver_host(), "resolver.example.org");
    }

    #[test]
    fn explicit_bns_bridge_overrides_bns_host_default() {
        let mut config = BuckyOSMachineConfig::default();
        config
            .web3_bridge
            .insert("bns".to_string(), "resolver.example.org".to_string());
        config.bns_host = Some("bns.example.org".to_string());

        assert_eq!(config.bns_resolver_host(), "resolver.example.org");
    }

    #[test]
    fn partial_machine_config_can_set_bns_host_only() {
        let config = serde_json::from_value::<BuckyOSMachineConfig>(json!({
            "bns_host": "resolver.example.org"
        }))
        .unwrap();

        assert_eq!(config.bns_resolver_host(), "resolver.example.org");
        assert!(config.force_https);
        assert_eq!(config.trust_did, default_trust_did());
    }
}
