use std::collections::HashMap;
use std::path::PathBuf;

use buckyos_kit::buckyos_get_unix_timestamp;
use jsonwebtoken::jwk::Jwk;
use jsonwebtoken::{encode, Algorithm, DecodingKey, EncodingKey, Header};
use log::error;
use serde::{Deserialize, Serialize};

use crate::{
    decode_json_from_jwt_with_pk, decode_jwt_claim_without_verify, default_context,
    DIDDocumentTrait, EncodedDocument, NSError, NSResult, ServiceNode, VerificationMethodNode, DID,
};

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Default)]
pub struct AgentContactInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub telegram: Option<String>,
    #[serde(flatten)]
    #[serde(default)]
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub extra_info: HashMap<String, String>,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Default)]
pub struct AgentHttpServicePorts {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub send_msg: Option<u16>,
    #[serde(flatten)]
    #[serde(default)]
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub extra_ports: HashMap<String, u16>,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct AgentDocument {
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
    #[serde(default)]
    pub support_public_access: bool,
    #[serde(default)]
    pub contact: AgentContactInfo,
    pub owner: DID,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub eth_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub public_description: Option<String>,
    #[serde(rename = "httpServicePorts")]
    #[serde(default)]
    pub http_service_ports: AgentHttpServicePorts,
}

impl AgentDocument {
    pub fn new(id: DID, owner: DID, public_key: Jwk) -> Self {
        let verification_method = vec![VerificationMethodNode {
            key_type: "Ed25519VerificationKey2020".to_string(),
            key_id: "#main_key".to_string(),
            key_controller: id.to_string(),
            public_key,
        }];

        Self {
            context: default_context(),
            id,
            verification_method,
            authentication: vec!["#main_key".to_string()],
            assertion_method: vec!["#main_key".to_string()],
            service: vec![],
            exp: buckyos_get_unix_timestamp() + 3600 * 24 * 365 * 10,
            iat: buckyos_get_unix_timestamp(),
            extra_info: HashMap::new(),
            support_public_access: false,
            contact: AgentContactInfo::default(),
            owner,
            eth_address: None,
            public_description: None,
            http_service_ports: AgentHttpServicePorts::default(),
        }
    }

    pub fn get_default_key(&self) -> Option<Jwk> {
        for method in self.verification_method.iter() {
            if method.key_id == "#main_key" {
                return Some(method.public_key.clone());
            }
        }
        None
    }

    pub fn set_send_msg_port(&mut self, port: u16) {
        self.http_service_ports.send_msg = Some(port);
    }

    pub fn set_http_service_port(&mut self, service: &str, port: u16) {
        if service == "send_msg" {
            self.http_service_ports.send_msg = Some(port);
            return;
        }
        self.http_service_ports
            .extra_ports
            .insert(service.to_string(), port);
    }

    pub fn get_http_service_port(&self, service: &str) -> Option<u16> {
        if service == "send_msg" {
            return self.http_service_ports.send_msg;
        }
        self.http_service_ports.extra_ports.get(service).copied()
    }

    pub fn load_agent_document(file_path: &PathBuf) -> NSResult<AgentDocument> {
        let contents = std::fs::read_to_string(file_path.clone()).map_err(|err| {
            error!("read {} failed! {}", file_path.to_string_lossy(), err);
            NSError::ReadLocalFileError(format!(
                "read {} failed! {}",
                file_path.to_string_lossy(),
                err
            ))
        })?;
        let config: AgentDocument = serde_json::from_str(&contents).map_err(|err| {
            error!("parse {} failed! {}", file_path.to_string_lossy(), err);
            NSError::ReadLocalFileError(format!("Failed to parse AgentDocument json: {}", err))
        })?;
        Ok(config)
    }
}

impl DIDDocumentTrait for AgentDocument {
    fn get_id(&self) -> DID {
        self.id.clone()
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
        None
    }

    fn get_exchange_key(&self, kid: Option<&str>) -> Option<(DecodingKey, Jwk)> {
        self.get_auth_key(kid)
    }

    fn get_iss(&self) -> Option<String> {
        Some(self.owner.to_string())
    }

    fn get_exp(&self) -> Option<u64> {
        Some(self.exp)
    }

    fn get_iat(&self) -> Option<u64> {
        Some(self.iat)
    }

    fn encode(&self, key: Option<&EncodingKey>) -> NSResult<EncodedDocument> {
        if key.is_none() {
            return Err(NSError::Failed("No key provided".to_string()));
        }
        let key = key.unwrap();
        let mut header = Header::new(Algorithm::EdDSA);
        header.typ = None;
        let token = encode(&header, self, key).map_err(|error| {
            NSError::Failed(format!("Failed to encode AgentDocument :{}", error))
        })?;
        Ok(EncodedDocument::Jwt(token))
    }

    fn decode(doc: &EncodedDocument, key: Option<&DecodingKey>) -> NSResult<Self>
    where
        Self: Sized,
    {
        match doc {
            EncodedDocument::Jwt(jwt_str) => {
                let json_result = if key.is_none() {
                    decode_jwt_claim_without_verify(jwt_str)?
                } else {
                    decode_json_from_jwt_with_pk(jwt_str, key.unwrap())?
                };
                let result: AgentDocument =
                    serde_json::from_value(json_result).map_err(|error| {
                        NSError::Failed(format!("Failed to decode agent doc:{}", error))
                    })?;
                Ok(result)
            }
            EncodedDocument::JsonLd(json_value) => {
                let result: AgentDocument =
                    serde_json::from_value(json_value.clone()).map_err(|error| {
                        NSError::Failed(format!("Failed to decode agent doc:{}", error))
                    })?;
                Ok(result)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn test_agent_document_encode_decode() {
        let private_key_pem = r#"
        -----BEGIN PRIVATE KEY-----
        MC4CAQAwBQYDK2VwBCIEIJBRONAzbwpIOwm0ugIQNyZJrDXxZF7HoPWAZesMedOr
        -----END PRIVATE KEY-----
        "#;
        let jwk = json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "T4Quc1L6Ogu4N2tTKOvneV1yYnBcmhP89B_RsuFsJZ8"
        });
        let public_key_jwk: Jwk = serde_json::from_value(jwk).unwrap();
        let private_key: EncodingKey =
            EncodingKey::from_ed_pem(private_key_pem.as_bytes()).unwrap();
        let public_key = DecodingKey::from_jwk(&public_key_jwk).unwrap();

        let mut doc = AgentDocument::new(
            DID::new("bns", "agent.alice"),
            DID::new("bns", "alice"),
            public_key_jwk,
        );
        doc.support_public_access = true;
        doc.contact.telegram = Some("@alice_agent".to_string());
        doc.eth_address = Some("0x1234567890123456789012345678901234567890".to_string());
        doc.public_description = Some("Public AI assistant for demo use".to_string());
        doc.set_send_msg_port(8081);
        doc.set_http_service_port("status", 8082);

        // JSON serialize -> deserialize -> serialize -> deserialize
        let json1 = serde_json::to_string(&doc).unwrap();
        let json_decoded1: AgentDocument = serde_json::from_str(&json1).unwrap();
        let json2 = serde_json::to_string(&json_decoded1).unwrap();
        let json_decoded2: AgentDocument = serde_json::from_str(&json2).unwrap();

        assert_eq!(doc, json_decoded1);
        assert_eq!(json_decoded1, json_decoded2);

        // JWT serialize -> deserialize -> serialize -> deserialize
        let encoded1 = doc.encode(Some(&private_key)).unwrap();
        let decoded1 = AgentDocument::decode(&encoded1, Some(&public_key)).unwrap();
        let encoded2 = decoded1.encode(Some(&private_key)).unwrap();
        let decoded2 = AgentDocument::decode(&encoded2, Some(&public_key)).unwrap();

        assert_eq!(
            decoded2.public_description.as_deref(),
            Some("Public AI assistant for demo use")
        );
        assert_eq!(decoded2.get_http_service_port("send_msg"), Some(8081));
        assert_eq!(decoded2.get_http_service_port("status"), Some(8082));
        assert_eq!(doc, decoded1);
        assert_eq!(decoded1, decoded2);
    }

    #[test]
    fn test_agent_document_parse_from_raw_json_string() {
        let raw_json = r##"{
            "@context": "https://www.w3.org/ns/did/v1",
            "id": "did:bns:agent.alice",
            "verificationMethod": [{
                "type": "Ed25519VerificationKey2020",
                "id": "#main_key",
                "controller": "did:bns:agent.alice",
                "publicKeyJwk": {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": "T4Quc1L6Ogu4N2tTKOvneV1yYnBcmhP89B_RsuFsJZ8"
                }
            }],
            "authentication": ["#main_key"],
            "assertion_method": ["#main_key"],
            "service": [],
            "exp": 2200000000,
            "iat": 1700000000,
            "support_public_access": true,
            "contact": {
                "telegram": "@alice_agent",
                "email": "alice@example.com"
            },
            "owner": "did:bns:alice",
            "eth_address": "0x1234567890123456789012345678901234567890",
            "public_description": "Public AI assistant for demo use",
            "httpServicePorts": {
                "send_msg": 8081,
                "status": 8082
            },
            "customFlag": true
        }"##;

        let parsed_by_serde: AgentDocument = serde_json::from_str(raw_json).unwrap();
        assert_eq!(parsed_by_serde.id, DID::new("bns", "agent.alice"));
        assert_eq!(parsed_by_serde.owner, DID::new("bns", "alice"));
        assert_eq!(
            parsed_by_serde.public_description.as_deref(),
            Some("Public AI assistant for demo use")
        );
        assert_eq!(
            parsed_by_serde.contact.telegram.as_deref(),
            Some("@alice_agent")
        );
        assert_eq!(
            parsed_by_serde.contact.extra_info.get("email").map(|v| v.as_str()),
            Some("alice@example.com")
        );
        assert_eq!(parsed_by_serde.get_http_service_port("send_msg"), Some(8081));
        assert_eq!(parsed_by_serde.get_http_service_port("status"), Some(8082));
        assert_eq!(
            parsed_by_serde
                .extra_info
                .get("customFlag")
                .and_then(|v| v.as_bool()),
            Some(true)
        );

        let encoded_doc = EncodedDocument::from_str(raw_json.to_string()).unwrap();
        let parsed_by_decode = AgentDocument::decode(&encoded_doc, None).unwrap();
        assert_eq!(parsed_by_serde, parsed_by_decode);
    }
}
