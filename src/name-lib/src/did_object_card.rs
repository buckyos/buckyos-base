use std::collections::HashMap;

use jsonwebtoken::jwk::Jwk;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    decode_jwt_claim_without_verify, DIDContext, DIDDocumentTrait, DidDocType, EncodedDocument,
    NSError, NSResult, DID, DID_CORE_CONTEXT, DID_OBJECT_CONTEXT,
};

pub const DID_OBJECT_SERVICE_TYPE: &str = "DIDObjectService";
pub const DID_OBJECT_SERVICE_ID: &str = "#did-object";

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct DIDObjectCard {
    #[serde(rename = "@context", default = "default_did_object_context")]
    pub context: DIDContext,
    pub id: DID,
    #[serde(rename = "alsoKnownAs")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    pub also_known_as: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub controller: Option<DID>,
    #[serde(rename = "verificationMethod")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    pub verification_method: Vec<DIDObjectVerificationMethod>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    pub authentication: Vec<String>,
    #[serde(rename = "assertionMethod")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    pub assertion_method: Vec<String>,
    #[serde(rename = "capabilityInvocation")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    pub capability_invocation: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    pub service: Vec<DIDObjectService>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub exp: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub iat: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub version_seq: Option<u64>,
    #[serde(rename = "keyScope", alias = "buckyos:scopes")]
    #[serde(default)]
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub key_scope: HashMap<String, Vec<String>>,
    #[serde(flatten)]
    #[serde(default)]
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub extra: HashMap<String, Value>,
}

impl DIDObjectCard {
    pub fn new(
        id: DID,
        object_url: impl Into<String>,
        controller: Option<DID>,
        profile: impl Into<String>,
        kind: Option<impl Into<String>>,
    ) -> Self {
        let object_url = object_url.into();
        let service_endpoint = object_url.trim_end_matches('/').to_string();

        Self {
            context: default_did_object_context(),
            id,
            also_known_as: vec![service_endpoint.clone()],
            controller,
            verification_method: Vec::new(),
            authentication: Vec::new(),
            assertion_method: Vec::new(),
            capability_invocation: Vec::new(),
            service: vec![DIDObjectService::new(
                DID_OBJECT_SERVICE_ID,
                service_endpoint,
                profile,
                kind,
            )],
            exp: None,
            iat: None,
            version_seq: None,
            key_scope: HashMap::new(),
            extra: HashMap::new(),
        }
    }

    pub fn from_json_str(card: &str) -> NSResult<Self> {
        let card = serde_json::from_str(card)
            .map_err(|err| NSError::InvalidParam(format!("invalid did object card json: {err}")))?;
        Ok(card)
    }

    pub fn from_value(value: Value) -> NSResult<Self> {
        let card = serde_json::from_value(value)
            .map_err(|err| NSError::InvalidParam(format!("invalid did object card json: {err}")))?;
        Ok(card)
    }

    pub fn validate(&self) -> NSResult<()> {
        if !self.context.contains(DID_CORE_CONTEXT) {
            return Err(NSError::InvalidParam(format!(
                "DID Object Card @context must contain {DID_CORE_CONTEXT}"
            )));
        }
        if !self.id.is_valid() {
            return Err(NSError::InvalidDID(
                "DID Object Card id cannot be undefined".to_string(),
            ));
        }
        if self.did_object_services().is_empty() {
            return Err(NSError::InvalidParam(
                "DID Object Card must contain a DIDObjectService".to_string(),
            ));
        }
        for service in self.did_object_services() {
            service.validate()?;
        }
        for method in &self.verification_method {
            method.validate()?;
        }
        Ok(())
    }

    pub fn primary_service(&self) -> NSResult<&DIDObjectService> {
        self.did_object_services()
            .into_iter()
            .next()
            .ok_or_else(|| NSError::NotFound("DIDObjectService".to_string()))
    }

    pub fn did_object_services(&self) -> Vec<&DIDObjectService> {
        self.service
            .iter()
            .filter(|service| service.service_type == DID_OBJECT_SERVICE_TYPE)
            .collect()
    }

    pub fn service_endpoint(&self) -> NSResult<&str> {
        Ok(self.primary_service()?.service_endpoint.as_str())
    }

    pub fn profile(&self) -> NSResult<&str> {
        Ok(self.primary_service()?.profile.as_str())
    }

    pub fn kind(&self) -> Option<&str> {
        self.primary_service()
            .ok()
            .and_then(|service| service.kind.as_deref())
    }

    pub fn object_url(&self) -> Option<&str> {
        self.also_known_as.first().map(String::as_str).or_else(|| {
            self.primary_service()
                .ok()
                .map(|item| item.service_endpoint.as_str())
        })
    }

    pub fn default_card_url(object_url: &str) -> String {
        format!("{}/did.json", object_url.trim_end_matches('/'))
    }

    pub fn get_default_key(&self) -> Option<Jwk> {
        self.verification_method
            .first()
            .map(|method| method.public_key.clone())
    }

    fn get_key_by_id(&self, kid: Option<&str>) -> Option<(DecodingKey, Jwk)> {
        if self.verification_method.is_empty() {
            return None;
        }

        let method = if let Some(kid) = kid {
            let local_kid = self.normalize_key_id_for_local_lookup(kid);
            self.verification_method
                .iter()
                .find(|method| method.key_id == local_kid || method.key_id == kid)?
        } else {
            &self.verification_method[0]
        };

        DecodingKey::from_jwk(&method.public_key)
            .ok()
            .map(|key| (key, method.public_key.clone()))
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct DIDObjectService {
    pub id: String,
    #[serde(rename = "type")]
    pub service_type: String,
    #[serde(rename = "serviceEndpoint")]
    pub service_endpoint: String,
    pub profile: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(flatten)]
    #[serde(default)]
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub extra: HashMap<String, Value>,
}

impl DIDObjectService {
    pub fn new(
        id: impl Into<String>,
        service_endpoint: impl Into<String>,
        profile: impl Into<String>,
        kind: Option<impl Into<String>>,
    ) -> Self {
        Self {
            id: id.into(),
            service_type: DID_OBJECT_SERVICE_TYPE.to_string(),
            service_endpoint: service_endpoint.into(),
            profile: profile.into(),
            kind: kind.map(Into::into),
            extra: HashMap::new(),
        }
    }

    pub fn validate(&self) -> NSResult<()> {
        if self.id.trim().is_empty() {
            return Err(NSError::InvalidParam(
                "DIDObjectService id cannot be empty".to_string(),
            ));
        }
        if self.service_type != DID_OBJECT_SERVICE_TYPE {
            return Err(NSError::InvalidParam(format!(
                "DIDObjectService type must be {DID_OBJECT_SERVICE_TYPE}"
            )));
        }
        if self.service_endpoint.trim().is_empty() {
            return Err(NSError::InvalidParam(
                "DIDObjectService serviceEndpoint cannot be empty".to_string(),
            ));
        }
        if self.profile.trim().is_empty() {
            return Err(NSError::InvalidParam(
                "DIDObjectService profile cannot be empty".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct DIDObjectVerificationMethod {
    #[serde(rename = "type")]
    pub key_type: String,
    #[serde(rename = "id")]
    pub key_id: String,
    #[serde(rename = "controller")]
    pub key_controller: String,
    #[serde(rename = "publicKeyJwk")]
    pub public_key: Jwk,
    #[serde(flatten)]
    #[serde(default)]
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub extra: HashMap<String, Value>,
}

impl DIDObjectVerificationMethod {
    pub fn validate(&self) -> NSResult<()> {
        if self.key_id.trim().is_empty() {
            return Err(NSError::InvalidParam(
                "verificationMethod id cannot be empty".to_string(),
            ));
        }
        if self.key_type.trim().is_empty() {
            return Err(NSError::InvalidParam(
                "verificationMethod type cannot be empty".to_string(),
            ));
        }
        if self.key_controller.trim().is_empty() {
            return Err(NSError::InvalidParam(
                "verificationMethod controller cannot be empty".to_string(),
            ));
        }
        Ok(())
    }
}

impl DIDDocumentTrait for DIDObjectCard {
    fn get_id(&self) -> DID {
        self.id.clone()
    }

    fn get_owner_did(&self) -> Option<DID> {
        self.controller.clone()
    }

    fn get_doc_type(&self) -> DidDocType {
        DidDocType::DidObject
    }

    fn get_auth_key(&self, kid: Option<&str>) -> Option<(DecodingKey, Jwk)> {
        self.get_key_by_id(kid)
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
        } else if !self.assertion_method.is_empty() {
            Some(self.assertion_method.as_slice())
        } else {
            None
        }
    }

    fn get_iss(&self) -> Option<String> {
        self.controller.as_ref().map(DID::to_string)
    }

    fn get_exp(&self) -> Option<u64> {
        self.exp
    }

    fn get_iat(&self) -> Option<u64> {
        self.iat
    }

    fn get_version_seq(&self) -> Option<u64> {
        self.version_seq
    }

    fn encode(&self, key: Option<&EncodingKey>) -> NSResult<EncodedDocument> {
        if let Some(key) = key {
            crate::ensure_jwt_iat_derivable("DIDObjectCard", self.iat, self.exp)?;
            let mut header = Header::new(Algorithm::EdDSA);
            header.typ = None;
            let token = encode(&header, self, key)
                .map_err(|err| NSError::Failed(format!("Failed to encode DIDObjectCard: {err}")))?;
            Ok(EncodedDocument::Jwt(token))
        } else {
            let value = serde_json::to_value(self).map_err(|err| {
                NSError::Failed(format!("Failed to encode DIDObjectCard as JSON-LD: {err}"))
            })?;
            Ok(EncodedDocument::JsonLd(value))
        }
    }

    fn decode(doc: &EncodedDocument, key: Option<&DecodingKey>) -> NSResult<Self>
    where
        Self: Sized,
    {
        let value = match doc {
            EncodedDocument::Jwt(jwt_str) => {
                if let Some(key) = key {
                    let mut validation = Validation::new(Algorithm::EdDSA);
                    validation.validate_exp = false;
                    decode::<Value>(jwt_str, key, &validation)
                        .map_err(|err| {
                            NSError::DecodeJWTError(format!(
                                "Failed to decode DIDObjectCard jwt: {err}"
                            ))
                        })?
                        .claims
                } else {
                    decode_jwt_claim_without_verify(jwt_str)?
                }
            }
            EncodedDocument::JsonLd(json_value) => json_value.clone(),
        };

        let card: DIDObjectCard = serde_json::from_value(value)
            .map_err(|err| NSError::Failed(format!("Failed to decode DIDObjectCard: {err}")))?;
        if matches!(doc, EncodedDocument::Jwt(_)) {
            crate::ensure_jwt_iat_derivable("DIDObjectCard", card.iat, card.exp)?;
        }
        Ok(card)
    }
}

pub(crate) fn default_did_object_context() -> DIDContext {
    DIDContext::Array(vec![
        DID_CORE_CONTEXT.to_string(),
        DID_OBJECT_CONTEXT.to_string(),
    ])
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn parse_and_validate_card_example() {
        let card = DIDObjectCard::from_value(json!({
            "@context": [
                "https://www.w3.org/ns/did/v1",
                "https://buckyos.org/ns/did-object/v1"
            ],
            "id": "did:web:myhome.com:devices:cam01",
            "alsoKnownAs": ["https://myhome.com/devices/cam01"],
            "controller": "did:web:myhome.com",
            "service": [
                {
                    "id": "#did-object",
                    "type": "DIDObjectService",
                    "serviceEndpoint": "https://myhome.com/devices/cam01",
                    "profile": "https://buckyos.org/profiles/web-camera@1",
                    "kind": "web.camera"
                }
            ]
        }))
        .unwrap();

        card.validate().unwrap();
        assert_eq!(
            card.service_endpoint().unwrap(),
            "https://myhome.com/devices/cam01"
        );
        assert_eq!(
            card.profile().unwrap(),
            "https://buckyos.org/profiles/web-camera@1"
        );
        assert_eq!(card.kind(), Some("web.camera"));
        assert_eq!(
            DIDObjectCard::default_card_url("https://myhome.com/devices/cam01/"),
            "https://myhome.com/devices/cam01/did.json"
        );
    }

    #[test]
    fn validation_rejects_missing_did_object_service() {
        let card = DIDObjectCard::from_value(json!({
            "@context": "https://www.w3.org/ns/did/v1",
            "id": "did:web:myhome.com:devices:cam01",
            "service": []
        }))
        .unwrap();

        assert!(card.validate().is_err());
    }

    #[test]
    fn generic_did_parser_accepts_did_object_card() {
        let card = DIDObjectCard::new(
            DID::new("web", "myhome.com:devices:cam01"),
            "https://myhome.com/devices/cam01",
            Some(DID::new("web", "myhome.com")),
            "https://buckyos.org/profiles/web-camera@1",
            Some("web.camera"),
        );
        let doc = EncodedDocument::JsonLd(serde_json::to_value(&card).unwrap());

        let parsed = crate::parse_did_doc(doc).unwrap();

        assert_eq!(parsed.get_id(), DID::new("web", "myhome.com:devices:cam01"));
    }
}
