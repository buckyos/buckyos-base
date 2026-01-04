
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
    default_context, EncodedDocument, NSError, NSResult, DID, DIDDocumentTrait, ServiceNode,
    VerificationMethodNode,
};

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
    #[serde(default)]
    pub meta: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_zone_did: Option<DID>,
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

    pub fn new_by_pkx(pkx: &str,hostname: &str) -> NSResult<Self> {
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
            public_key: public_key
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
            meta: None,
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
    fn new_by_pkx_accepts_single_part_pkx() {
        let pkx = "T4Quc1L6Ogu4N2tTKOvneV1yYnBcmhP89B_RsuFsJZ8"; // valid base64url(32 bytes)
        let hostname = "did:web:example.com";

        let cfg = OwnerConfig::new_by_pkx(pkx, hostname).expect("should build owner config");

        assert_eq!(cfg.id.method, "web");
        assert_eq!(cfg.id.id, "example.com");
        assert_eq!(cfg.name, "example.com");
        assert_eq!(cfg.full_name, "example.com@did:web:example.com");
    }

    #[test]
    fn new_by_pkx_accepts_three_part_pkx() {
        let pkx = "T4Quc1L6Ogu4N2tTKOvneV1yYnBcmhP89B_RsuFsJZ8:bns:user1:xxxx";
        let hostname = "bridge.buckyos.org";

        let cfg = OwnerConfig::new_by_pkx(pkx, hostname).expect("should build owner config");

        assert_eq!(cfg.id.method, "bns");
        assert_eq!(cfg.id.id, "user1");
        assert_eq!(cfg.name, "user1");
        assert_eq!(cfg.full_name, "user1@bridge.buckyos.org");
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