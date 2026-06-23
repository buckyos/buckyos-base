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
#[serde(rename_all = "snake_case")]
pub enum ProfileContactPlatform {
    Email,
    Phone,
    Telegram,
    Matrix,
    Discord,
    Wechat,
    Whatsapp,
    Signal,
    X,
    Github,
    Linkedin,
    Facebook,
    Instagram,
    Tiktok,
    Reddit,
    Mastodon,
    Bluesky,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProfileContact {
    #[serde(alias = "kind")]
    pub platform: ProfileContactPlatform,
    #[serde(alias = "value")]
    pub account_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub display_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub tunnel_id: Option<DID>,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct UserProfile {
    #[serde(alias = "id")]
    pub did: DID,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(alias = "displayName")]
    pub display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub avatar: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub meta: Option<Value>,
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
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub links: HashMap<String, ProfileLink>,
    #[serde(default)]
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub public_contacts: HashMap<String, ProfileContact>,
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn profile_contact_accepts_known_platforms_and_legacy_field_aliases() {
        let telegram: ProfileContact = serde_json::from_value(json!({
            "platform": "telegram",
            "account_id": "user:5397330802",
            "display_id": "wacer2026",
            "tunnel_id": "did:web:tg-tunnel.test.buckyos.io"
        }))
        .unwrap();

        assert_eq!(telegram.platform, ProfileContactPlatform::Telegram);
        assert_eq!(telegram.account_id, "user:5397330802");
        assert_eq!(telegram.display_id.as_deref(), Some("wacer2026"));
        assert_eq!(
            telegram.tunnel_id.as_ref().map(DID::to_string).as_deref(),
            Some("did:web:tg-tunnel.test.buckyos.io")
        );

        let legacy_email: ProfileContact = serde_json::from_value(json!({
            "kind": "email",
            "value": "alice@example.com"
        }))
        .unwrap();

        assert_eq!(legacy_email.platform, ProfileContactPlatform::Email);
        assert_eq!(legacy_email.account_id, "alice@example.com");
    }

    #[test]
    fn profile_contact_rejects_unknown_platform_or_fields() {
        assert!(serde_json::from_value::<ProfileContact>(json!({
            "platform": "custom-chat",
            "account_id": "alice"
        }))
        .is_err());

        assert!(serde_json::from_value::<ProfileContact>(json!({
            "platform": "telegram",
            "account_id": "user:5397330802",
            "custom_field": "not allowed"
        }))
        .is_err());
    }
}
