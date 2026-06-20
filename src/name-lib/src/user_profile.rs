use std::collections::HashMap;

use jsonwebtoken::DecodingKey;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    decode_json_from_jwt_with_pk, decode_jwt_claim_without_verify, ensure_version_seq_for_jwt,
    EncodedDocument, NSError, NSResult, DID,
};

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct ProfileLink {
    pub label: String,
    pub url: String,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct ProfileContact {
    pub kind: String,
    pub value: String,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct UserProfile {
    #[serde(alias = "id")]
    pub did: DID,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub avatar: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub headline: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub bio: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub location: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub organization: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub links: Vec<ProfileLink>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub public_contacts: Vec<ProfileContact>,
    #[serde(default)]
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

impl UserProfile {
    pub fn decode(doc: &EncodedDocument, key: Option<&DecodingKey>) -> NSResult<Self> {
        let profile_value = match doc {
            EncodedDocument::Jwt(jwt_str) => {
                let value = if let Some(key) = key {
                    decode_json_from_jwt_with_pk(jwt_str, key)?
                } else {
                    decode_jwt_claim_without_verify(jwt_str)?
                };
                ensure_version_seq_for_jwt(
                    "UserProfile",
                    value.get("version_seq").and_then(|value| value.as_u64()),
                )?;
                value
            }
            EncodedDocument::JsonLd(json_value) => json_value.clone(),
        };

        serde_json::from_value(profile_value)
            .map_err(|error| NSError::Failed(format!("Failed to decode user profile: {}", error)))
    }
}
