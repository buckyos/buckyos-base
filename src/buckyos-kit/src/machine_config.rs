use crate::get_buckyos_system_etc_dir;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;

// BNS 权威解析器与 DID -> hostname 的 bridge 是独立配置，不能共用默认值。
const DEFAULT_BNS_RESOLVER_HOST: &str = "bns.buckyos.ai";
const DEFAULT_BNS_BRIDGE_HOST: &str = "web3.buckyos.ai";

#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
pub struct BuckyOSMachineConfig {
    /// DID method 到 Web3 bridge 根域名的映射，仅影响 DID -> hostname。
    /// 例如 bns = web3.buckyos.ai 将 did:bns:alice 映射为 alice.web3.buckyos.ai。
    /// 它不是 BNS 权威解析器地址；已发布 Zone 的访问域名以 ZoneDocument.hostname 为准。
    #[serde(default)]
    pub web3_bridge: HashMap<String, String>,
    #[serde(default = "default_trust_did")]
    pub trust_did: Vec<String>, //did
    #[serde(default = "default_force_https")]
    pub force_https: bool,
    /// BNS 权威解析器的服务域名，用于查询 DID 文档，例如 bns.buckyos.ai。
    /// 不参与 DID -> hostname 映射；修改解析器地址时不能同步改写 web3_bridge.bns。
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
        let mut web3_bridge = HashMap::new();
        web3_bridge.insert("bns".to_string(), DEFAULT_BNS_BRIDGE_HOST.to_string());

        Self {
            web3_bridge,
            trust_did: default_trust_did(),
            force_https: default_force_https(),
            bns_host: Some(DEFAULT_BNS_RESOLVER_HOST.to_string()),
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
            .unwrap_or(DEFAULT_BNS_RESOLVER_HOST)
    }

    pub fn bns_resolver_host(&self) -> String {
        self.bns_host_or_default().to_string()
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
    fn default_bns_resolver_and_bridge_have_distinct_hosts() {
        let config = BuckyOSMachineConfig::default();

        assert_eq!(config.bns_host.as_deref(), Some("bns.buckyos.ai"));
        assert_eq!(config.bns_resolver_host(), "bns.buckyos.ai");
        assert_eq!(
            config.web3_bridge.get("bns").map(String::as_str),
            Some("web3.buckyos.ai")
        );
    }

    #[test]
    fn bns_resolver_uses_configured_bns_host() {
        let mut config = BuckyOSMachineConfig::default();
        config.bns_host = Some("resolver.example.org".to_string());

        assert_eq!(config.bns_resolver_host(), "resolver.example.org");
        assert_eq!(
            config.web3_bridge.get("bns").map(String::as_str),
            Some("web3.buckyos.ai")
        );
    }

    #[test]
    fn bns_bridge_does_not_override_bns_host() {
        let mut config = BuckyOSMachineConfig::default();
        config
            .web3_bridge
            .insert("bns".to_string(), "bridge.example.org".to_string());

        assert_eq!(config.bns_resolver_host(), "bns.buckyos.ai");
        assert_eq!(
            config.web3_bridge.get("bns").map(String::as_str),
            Some("bridge.example.org")
        );
    }

    #[test]
    fn missing_or_blank_bns_host_does_not_use_bridge_as_resolver() {
        for bns_host in [None, Some(""), Some("   ")] {
            let config = serde_json::from_value::<BuckyOSMachineConfig>(json!({
                "bns_host": bns_host,
                "web3_bridge": {"bns": "bridge.example.org"}
            }))
            .unwrap();

            assert_eq!(config.bns_resolver_host(), "bns.buckyos.ai");
            assert_eq!(
                config.web3_bridge.get("bns").map(String::as_str),
                Some("bridge.example.org")
            );
        }
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
