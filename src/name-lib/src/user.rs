use std::collections::HashMap;
use std::path::PathBuf;
use std::str::FromStr;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use buckyos_kit::buckyos_get_unix_timestamp;
use jsonwebtoken::{encode, jwk::Jwk, Algorithm, DecodingKey, EncodingKey, Header};
use log::error;
use serde::{Deserialize, Serialize};

use crate::{
    create_jwt_by_x, decode_json_from_jwt_with_pk, decode_jwt_claim_without_verify,
    default_owner_context, ensure_version_seq_for_jwt, DIDContext, DIDDocumentTrait,
    EncodedDocument, NSError, NSResult, ServiceNode, VerificationMethodNode, DID,
};

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct OwnerWallet {
    #[serde(rename = "type")]
    pub wallet_type: String,
    pub address: String,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct OwnerConfig {
    #[serde(rename = "@context", default = "default_owner_context")]
    pub context: DIDContext,
    pub id: DID,
    #[serde(rename = "verificationMethod")]
    verification_method: Vec<VerificationMethodNode>,
    authentication: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    assertion_method: Vec<String>,
    #[serde(rename = "capabilityInvocation")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    capability_invocation: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    service: Vec<ServiceNode>,
    pub exp: u64,
    pub iat: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub version_seq: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub mini_version_seq: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub valid_iat: Option<u64>,
    #[serde(flatten)]
    pub extra_info: HashMap<String, serde_json::Value>,

    //--------------------------------
    #[serde(rename = "keyScope", alias = "buckyos:scopes")]
    #[serde(default)]
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub key_scope: HashMap<String, Vec<String>>,
    pub name: String,
    #[serde(alias = "full_name", alias = "displayName")]
    pub display_name: String, //display name
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar: Option<String>, //avatar url (http url or cyfs url) or object id
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub meta: Option<serde_json::Value>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub binded_zone_list: Vec<DID>,
    #[serde(default)]
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub wallets: HashMap<String, OwnerWallet>,
}

impl OwnerConfig {
    fn validate_pkx_x(x: &str) -> NSResult<()> {
        let decoded = URL_SAFE_NO_PAD
            .decode(x)
            .map_err(|_| NSError::InvalidDID("Invalid pkx: x must be base64url".to_string()))?;
        if decoded.len() != 32 {
            return Err(NSError::InvalidDID(format!(
                "Invalid pkx: x length must be 32 bytes, got {}",
                decoded.len()
            )));
        }
        Ok(())
    }

    pub fn new_by_pkx(pkx: &str, hostname: &str) -> NSResult<Self> {
        //pkx like "qJdNEtscIYwTo-I0K7iPEt_UZdBDRd4r16jdBfNR0tM[:bns:waterflier];"
        let parts = pkx.split(":").collect::<Vec<&str>>();
        if parts.is_empty() || parts[0].is_empty() {
            return Err(NSError::InvalidDID("Invalid pkx: empty x".to_string()));
        }
        Self::validate_pkx_x(parts[0])?;
        let jwk: Jwk = create_jwt_by_x(parts[0])?;
        if parts.len() == 1 {
            let owenr_did = DID::from_str(hostname)?;
            let owner_name = owenr_did.id.clone();
            let full_name = format!("{}@{}", owner_name, hostname);

            return Ok(OwnerConfig::new(
                owenr_did,
                owner_name.clone(),
                full_name,
                jwk,
            ));
        }

        if parts.len() >= 3 {
            let owner_did = DID::new(parts[1], parts[2]);
            let owner_name = parts[2].to_string();
            let full_name = format!("{}@{}", owner_name, hostname);
            return Ok(OwnerConfig::new(
                owner_did,
                owner_name.clone(),
                full_name,
                jwk,
            ));
        }

        return Err(NSError::InvalidDID(format!("Invalid pkx:{}", pkx)));
    }

    pub fn new(id: DID, name: String, full_name: String, public_key: Jwk) -> Self {
        let verification_method = vec![VerificationMethodNode {
            key_type: "Ed25519VerificationKey2020".to_string(),
            key_id: "#main_key".to_string(),
            key_controller: id.to_string(),
            public_key: public_key,
        }];

        OwnerConfig {
            context: default_owner_context(),
            id: id,
            name: name,
            display_name: full_name,
            verification_method: verification_method,
            authentication: vec!["#main_key".to_string()],
            assertion_method: vec!["#main_key".to_string()],
            capability_invocation: vec!["#main_key".to_string()],
            binded_zone_list: Vec::new(),
            exp: buckyos_get_unix_timestamp() + 3600 * 24 * 365 * 10,
            iat: buckyos_get_unix_timestamp(),
            version_seq: Some(0),
            mini_version_seq: None,
            valid_iat: None,
            avatar: None,
            meta: None,
            wallets: HashMap::new(),
            key_scope: HashMap::new(),
            extra_info: HashMap::new(),
            service: vec![],
        }
    }

    pub fn set_default_zone_did(&mut self, default_zone_did: DID) {
        self.binded_zone_list
            .retain(|zone_did| zone_did != &default_zone_did);
        self.binded_zone_list.insert(0, default_zone_did.clone());

        let last_doc_service_id = format!("{}#lastDoc", self.id.to_string());
        self.service
            .retain(|service| service.id != last_doc_service_id);
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
        self.binded_zone_list.first().cloned()
    }

    pub fn is_bound_to_zone(&self, zone_did: &DID) -> bool {
        self.binded_zone_list
            .iter()
            .any(|binded_zone_did| binded_zone_did == zone_did)
    }

    pub fn get_default_key(&self) -> Option<Jwk> {
        for method in self.verification_method.iter() {
            if method.key_id == "#main_key" {
                return Some(method.public_key.clone());
            }
        }
        return None;
    }

    /// 除默认 key（`#main_key`）之外的历史 key，供调用方在默认 key 验签失败时
    /// 做 fallback 验证（例如刚发生过 key rotation，旧文档仍用旧 key 签名）。
    pub fn get_historical_keys(&self) -> Vec<(String, Jwk)> {
        self.verification_method
            .iter()
            .filter(|method| method.key_id != "#main_key")
            .map(|method| (method.key_id.clone(), method.public_key.clone()))
            .collect()
    }

    pub fn validate_jwt_revocation(&self, doc_type: &str, doc: &EncodedDocument) -> NSResult<()> {
        if self.mini_version_seq.is_none() && self.valid_iat.is_none() {
            return Ok(());
        }

        if !doc.is_proof() {
            return Ok(());
        }

        let doc_value = doc.clone().to_json_value()?;
        if let Some(mini_version_seq) = self.mini_version_seq {
            let version_seq = doc_value
                .get("version_seq")
                .and_then(|value| value.as_u64())
                .ok_or_else(|| {
                    NSError::Failed(format!(
                        "{} JWT missing version_seq required by owner revocation policy",
                        doc_type
                    ))
                })?;
            if version_seq <= mini_version_seq {
                return Err(NSError::Failed(format!(
                    "{} JWT version_seq {} is not greater than owner mini_version_seq {}",
                    doc_type, version_seq, mini_version_seq
                )));
            }
        }

        if let Some(valid_iat) = self.valid_iat {
            let iat = doc_value
                .get("iat")
                .and_then(|value| value.as_u64())
                .ok_or_else(|| {
                    NSError::Failed(format!(
                        "{} JWT missing iat required by owner revocation policy",
                        doc_type
                    ))
                })?;
            if iat <= valid_iat {
                return Err(NSError::Failed(format!(
                    "{} JWT iat {} is not greater than owner valid_iat {}",
                    doc_type, iat, valid_iat
                )));
            }
        }

        Ok(())
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

    fn get_key_ids_by_scope(&self, scope: &str) -> Option<&[String]> {
        self.key_scope.get(scope).map(Vec::as_slice)
    }

    fn has_key_scope(&self) -> bool {
        !self.key_scope.is_empty()
    }

    fn get_standard_scope_key_ids(&self) -> Option<&[String]> {
        if !self.capability_invocation.is_empty() {
            Some(self.capability_invocation.as_slice())
        } else if !self.authentication.is_empty() {
            Some(self.authentication.as_slice())
        } else {
            None
        }
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
    fn get_version_seq(&self) -> Option<u64> {
        return self.version_seq;
    }

    fn encode(&self, key: Option<&EncodingKey>) -> NSResult<EncodedDocument> {
        if key.is_none() {
            return Err(NSError::Failed("No key provided".to_string()));
        }
        ensure_version_seq_for_jwt("OwnerConfig", self.version_seq)?;
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
                ensure_version_seq_for_jwt("OwnerConfig", result.version_seq)?;
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
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

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

    #[test]
    fn owner_config_serializes_wallets_by_name() {
        let public_key_jwk: jsonwebtoken::jwk::Jwk = serde_json::from_value(json!(
            {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": "T4Quc1L6Ogu4N2tTKOvneV1yYnBcmhP89B_RsuFsJZ8"
            }
        ))
        .unwrap();
        let mut owner_config = OwnerConfig::new(
            DID::new("bns", "lzc"),
            "lzc".to_string(),
            "zhicong liu".to_string(),
            public_key_jwk,
        );

        owner_config.wallets.insert(
            "main".to_string(),
            OwnerWallet {
                wallet_type: "eth".to_string(),
                address: "0x1234".to_string(),
            },
        );

        let json_value = serde_json::to_value(&owner_config).unwrap();
        assert_eq!(
            json_value["wallets"]["main"],
            json!({
                "type": "eth",
                "address": "0x1234"
            })
        );

        let decoded: OwnerConfig = serde_json::from_value(json_value).unwrap();
        assert_eq!(
            decoded.wallets.get("main").unwrap(),
            &OwnerWallet {
                wallet_type: "eth".to_string(),
                address: "0x1234".to_string(),
            }
        );
    }

    #[test]
    fn owner_config_serializes_key_scope_by_scope_name() {
        let public_key_jwk: jsonwebtoken::jwk::Jwk = serde_json::from_value(json!(
            {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": "T4Quc1L6Ogu4N2tTKOvneV1yYnBcmhP89B_RsuFsJZ8"
            }
        ))
        .unwrap();
        let mut owner_config = OwnerConfig::new(
            DID::new("bns", "lzc"),
            "lzc".to_string(),
            "zhicong liu".to_string(),
            public_key_jwk,
        );

        let empty_json_value = serde_json::to_value(&owner_config).unwrap();
        assert!(empty_json_value.get("keyScope").is_none());
        assert!(owner_config.is_key_allowed_in_scope(crate::key_scope::CONTENT_CREATE, "#main_key"));
        assert_eq!(
            owner_config
                .get_key_by_scope(crate::key_scope::CONTENT_CREATE)
                .map(|(key_id, _, _)| key_id),
            Some("#main_key".to_string())
        );

        let main_key_id = format!("{}#main_key", owner_config.id.to_string());
        owner_config.key_scope.insert(
            crate::key_scope::MANUAL.to_string(),
            vec![main_key_id.clone()],
        );
        assert!(
            !owner_config.is_key_allowed_in_scope(crate::key_scope::CONTENT_CREATE, "#main_key")
        );
        assert!(owner_config
            .get_key_by_scope(crate::key_scope::CONTENT_CREATE)
            .is_none());

        let json_value = serde_json::to_value(&owner_config).unwrap();
        assert_eq!(
            json_value["keyScope"][crate::key_scope::MANUAL],
            json!([main_key_id])
        );

        let decoded: OwnerConfig = serde_json::from_value(json_value).unwrap();
        assert_eq!(
            decoded.key_scope.get(crate::key_scope::MANUAL).unwrap(),
            &vec![main_key_id.clone()]
        );
        assert!(decoded.is_key_allowed_in_scope(crate::key_scope::MANUAL, "#main_key"));
        assert!(decoded.is_key_allowed_in_scope(crate::key_scope::MANUAL, &main_key_id));
        assert_eq!(
            decoded
                .get_key_by_scope(crate::key_scope::MANUAL)
                .map(|(key_id, _, _)| key_id),
            Some(main_key_id)
        );
    }

    #[test]
    fn owner_config_accepts_buckyos_scopes_alias() {
        let public_key_jwk: jsonwebtoken::jwk::Jwk = serde_json::from_value(json!(
            {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": "T4Quc1L6Ogu4N2tTKOvneV1yYnBcmhP89B_RsuFsJZ8"
            }
        ))
        .unwrap();
        let owner_config = OwnerConfig::new(
            DID::new("bns", "lzc"),
            "lzc".to_string(),
            "zhicong liu".to_string(),
            public_key_jwk,
        );
        let mut json_value = serde_json::to_value(&owner_config).unwrap();
        let json_object = json_value.as_object_mut().unwrap();
        json_object.insert(
            "buckyos:scopes".to_string(),
            json!({
                crate::key_scope::CONTENT_CREATE: ["did:bucky:lzc#identity-cold"]
            }),
        );

        let decoded: OwnerConfig = serde_json::from_value(json_value).unwrap();
        assert_eq!(
            decoded
                .key_scope
                .get(crate::key_scope::CONTENT_CREATE)
                .unwrap(),
            &vec!["did:bucky:lzc#identity-cold".to_string()]
        );
        assert!(!decoded.extra_info.contains_key("buckyos:scopes"));
    }

    #[test]
    fn owner_config_jwt_requires_version_seq() {
        let private_key_pem = r#"
        -----BEGIN PRIVATE KEY-----
        MC4CAQAwBQYDK2VwBCIEIJBRONAzbwpIOwm0ugIQNyZJrDXxZF7HoPWAZesMedOr
        -----END PRIVATE KEY-----
        "#;
        let public_key_jwk: jsonwebtoken::jwk::Jwk = serde_json::from_value(json!(
            {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": "T4Quc1L6Ogu4N2tTKOvneV1yYnBcmhP89B_RsuFsJZ8"
            }
        ))
        .unwrap();
        let private_key = EncodingKey::from_ed_pem(private_key_pem.as_bytes()).unwrap();
        let mut owner_config = OwnerConfig::new(
            DID::new("bns", "lzc"),
            "lzc".to_string(),
            "zhicong liu".to_string(),
            public_key_jwk,
        );

        owner_config.version_seq = None;

        let err = owner_config.encode(Some(&private_key)).unwrap_err();
        assert!(matches!(err, NSError::Failed(_)));
    }

    #[test]
    fn owner_config_replay_guard_rejects_stale_jwt() {
        let private_key_pem = r#"
        -----BEGIN PRIVATE KEY-----
        MC4CAQAwBQYDK2VwBCIEIJBRONAzbwpIOwm0ugIQNyZJrDXxZF7HoPWAZesMedOr
        -----END PRIVATE KEY-----
        "#;
        let private_key = EncodingKey::from_ed_pem(private_key_pem.as_bytes()).unwrap();

        let mut owner_config = OwnerConfig::new(
            DID::new("bns", "lzc"),
            "lzc".to_string(),
            "zhicong liu".to_string(),
            serde_json::from_value(json!({
                "kty": "OKP",
                "crv": "Ed25519",
                "x": "T4Quc1L6Ogu4N2tTKOvneV1yYnBcmhP89B_RsuFsJZ8"
            }))
            .unwrap(),
        );
        owner_config.mini_version_seq = Some(3);
        owner_config.valid_iat = Some(100);

        let fresh_jwt = encode(
            &Header::new(Algorithm::EdDSA),
            &json!({
                "version_seq": 4,
                "iat": 101,
                "exp": 1000
            }),
            &private_key,
        )
        .unwrap();
        owner_config
            .validate_jwt_revocation("ZoneConfig", &EncodedDocument::Jwt(fresh_jwt))
            .unwrap();

        let stale_version_jwt = encode(
            &Header::new(Algorithm::EdDSA),
            &json!({
                "version_seq": 3,
                "iat": 101,
                "exp": 1000
            }),
            &private_key,
        )
        .unwrap();
        assert!(owner_config
            .validate_jwt_revocation("ZoneConfig", &EncodedDocument::Jwt(stale_version_jwt))
            .is_err());

        let stale_iat_jwt = encode(
            &Header::new(Algorithm::EdDSA),
            &json!({
                "version_seq": 4,
                "iat": 100,
                "exp": 1000
            }),
            &private_key,
        )
        .unwrap();
        assert!(owner_config
            .validate_jwt_revocation("ZoneConfig", &EncodedDocument::Jwt(stale_iat_jwt))
            .is_err());
    }

    #[test]
    fn new_by_pkx_accepts_single_part_pkx() {
        let pkx = "T4Quc1L6Ogu4N2tTKOvneV1yYnBcmhP89B_RsuFsJZ8"; // valid base64url(32 bytes)
        let hostname = "did:web:example.com";

        let cfg = OwnerConfig::new_by_pkx(pkx, hostname).expect("should build owner config");

        assert_eq!(cfg.id.method, "web");
        assert_eq!(cfg.id.id, "example.com");
        assert_eq!(cfg.name, "example.com");
        assert_eq!(cfg.display_name, "example.com@did:web:example.com");
    }

    #[test]
    fn new_by_pkx_accepts_three_part_pkx() {
        let pkx = "T4Quc1L6Ogu4N2tTKOvneV1yYnBcmhP89B_RsuFsJZ8:bns:user1:xxxx";
        let hostname = "bridge.buckyos.org";

        let cfg = OwnerConfig::new_by_pkx(pkx, hostname).expect("should build owner config");

        assert_eq!(cfg.id.method, "bns");
        assert_eq!(cfg.id.id, "user1");
        assert_eq!(cfg.name, "user1");
        assert_eq!(cfg.display_name, "user1@bridge.buckyos.org");
    }

    #[test]
    fn new_by_pkx_rejects_two_part_pkx() {
        let pkx = "abc123:onlytwo";
        let hostname = "did:web:example.com";

        let err = OwnerConfig::new_by_pkx(pkx, hostname).unwrap_err();
        assert!(matches!(err, NSError::InvalidDID(_)));
    }

    #[test]
    fn new_by_pkx_rejects_non_base64_x() {
        let pkx = "not_base64!:bns:user1";
        let hostname = "bridge.buckyos.org";

        let err = OwnerConfig::new_by_pkx(pkx, hostname).unwrap_err();
        assert!(matches!(err, NSError::InvalidDID(_)));
    }

    #[test]
    fn new_by_pkx_rejects_wrong_length_x() {
        // base64url for 1 byte ("AQ") -> decodes to len 1
        let pkx = "AQ:bns:user1";
        let hostname = "bridge.buckyos.org";

        let err = OwnerConfig::new_by_pkx(pkx, hostname).unwrap_err();
        assert!(matches!(err, NSError::InvalidDID(_)));
    }
}
