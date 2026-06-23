use std::collections::HashMap;

use jsonwebtoken::DecodingKey;
use serde::{de::Error as DeError, Deserialize, Deserializer, Serialize};
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

#[derive(Clone, Serialize, Debug, PartialEq, Eq)]
#[serde(tag = "platform", rename_all = "snake_case")]
pub enum ProfileContact {
    Email(EmailContact),
    Phone(PhoneContact),
    Telegram(TelegramContact),
    Matrix(MatrixContact),
    Discord(DiscordContact),
    Wechat(WechatContact),
    Whatsapp(WhatsappContact),
    Signal(SignalContact),
    X(XContact),
    Github(GithubContact),
    Linkedin(LinkedinContact),
    Facebook(FacebookContact),
    Instagram(InstagramContact),
    Tiktok(TiktokContact),
    Reddit(RedditContact),
    Mastodon(MastodonContact),
    Bluesky(BlueskyContact),
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EmailContact {
    pub address: String,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PhoneContact {
    pub e164: String,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TelegramContact {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub account_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub display_id: Option<String>,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MatrixContact {
    pub user_id: String,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DiscordContact {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub user_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub username: Option<String>,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WechatContact {
    pub wechat_id: String,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WhatsappContact {
    pub phone_e164: String,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignalContact {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub phone_e164: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub username: Option<String>,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct XContact {
    pub username: String,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GithubContact {
    pub username: String,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LinkedinContact {
    pub public_id: String,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FacebookContact {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub profile_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub username: Option<String>,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct InstagramContact {
    pub username: String,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TiktokContact {
    pub username: String,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RedditContact {
    pub username: String,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MastodonContact {
    pub handle: String,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BlueskyContact {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub did: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub handle: Option<String>,
}

impl<'de> Deserialize<'de> for ProfileContact {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(tag = "platform", rename_all = "snake_case")]
        enum ProfileContactDef {
            Email(EmailContact),
            Phone(PhoneContact),
            Telegram(TelegramContact),
            Matrix(MatrixContact),
            Discord(DiscordContact),
            Wechat(WechatContact),
            Whatsapp(WhatsappContact),
            Signal(SignalContact),
            X(XContact),
            Github(GithubContact),
            Linkedin(LinkedinContact),
            Facebook(FacebookContact),
            Instagram(InstagramContact),
            Tiktok(TiktokContact),
            Reddit(RedditContact),
            Mastodon(MastodonContact),
            Bluesky(BlueskyContact),
        }

        let contact = match ProfileContactDef::deserialize(deserializer)? {
            ProfileContactDef::Email(contact) => Self::Email(contact),
            ProfileContactDef::Phone(contact) => Self::Phone(contact),
            ProfileContactDef::Telegram(contact) => Self::Telegram(contact),
            ProfileContactDef::Matrix(contact) => Self::Matrix(contact),
            ProfileContactDef::Discord(contact) => Self::Discord(contact),
            ProfileContactDef::Wechat(contact) => Self::Wechat(contact),
            ProfileContactDef::Whatsapp(contact) => Self::Whatsapp(contact),
            ProfileContactDef::Signal(contact) => Self::Signal(contact),
            ProfileContactDef::X(contact) => Self::X(contact),
            ProfileContactDef::Github(contact) => Self::Github(contact),
            ProfileContactDef::Linkedin(contact) => Self::Linkedin(contact),
            ProfileContactDef::Facebook(contact) => Self::Facebook(contact),
            ProfileContactDef::Instagram(contact) => Self::Instagram(contact),
            ProfileContactDef::Tiktok(contact) => Self::Tiktok(contact),
            ProfileContactDef::Reddit(contact) => Self::Reddit(contact),
            ProfileContactDef::Mastodon(contact) => Self::Mastodon(contact),
            ProfileContactDef::Bluesky(contact) => Self::Bluesky(contact),
        };
        contact.validate().map_err(D::Error::custom)?;
        Ok(contact)
    }
}

impl ProfileContact {
    pub fn validate(&self) -> Result<(), &'static str> {
        match self {
            Self::Telegram(contact) => validate_at_least_one(
                "telegram contact requires account_id or display_id",
                [&contact.account_id, &contact.display_id],
            ),
            Self::Discord(contact) => validate_at_least_one(
                "discord contact requires user_id or username",
                [&contact.user_id, &contact.username],
            ),
            Self::Signal(contact) => validate_at_least_one(
                "signal contact requires phone_e164 or username",
                [&contact.phone_e164, &contact.username],
            ),
            Self::Facebook(contact) => validate_at_least_one(
                "facebook contact requires profile_id or username",
                [&contact.profile_id, &contact.username],
            ),
            Self::Bluesky(contact) => validate_at_least_one(
                "bluesky contact requires did or handle",
                [&contact.did, &contact.handle],
            ),
            _ => Ok(()),
        }
    }
}

fn validate_at_least_one<const N: usize>(
    error: &'static str,
    values: [&Option<String>; N],
) -> Result<(), &'static str> {
    if values.iter().any(|value| {
        value
            .as_deref()
            .map(|value| !value.trim().is_empty())
            .unwrap_or(false)
    }) {
        Ok(())
    } else {
        Err(error)
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProfileVisibility {
    Public,
    Private,
    Contacts,
    Zone,
    Custom,
}

impl Default for ProfileVisibility {
    fn default() -> Self {
        Self::Public
    }
}

impl ProfileVisibility {
    fn is_public(&self) -> bool {
        matches!(self, Self::Public)
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct ProfilePrivacyRule {
    pub visibility: ProfileVisibility,
    #[serde(default)]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub allow: Vec<DID>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub deny: Vec<DID>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<String>,
}

impl ProfilePrivacyRule {
    pub fn public() -> Self {
        Self::new(ProfileVisibility::Public)
    }

    pub fn private() -> Self {
        Self::new(ProfileVisibility::Private)
    }

    pub fn new(visibility: ProfileVisibility) -> Self {
        Self {
            visibility,
            allow: Vec::new(),
            deny: Vec::new(),
            groups: Vec::new(),
        }
    }

    fn is_public(&self) -> bool {
        self.visibility.is_public()
    }
}

impl Default for ProfilePrivacyRule {
    fn default() -> Self {
        Self::public()
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq, Default)]
pub struct UserProfilePrivacy {
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_visibility: Option<ProfilePrivacyRule>,
    #[serde(default)]
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub fields: HashMap<String, ProfilePrivacyRule>,
    #[serde(default)]
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub links: HashMap<String, ProfilePrivacyRule>,
    #[serde(default)]
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub contacts: HashMap<String, ProfilePrivacyRule>,
}

impl UserProfilePrivacy {
    pub fn is_empty(&self) -> bool {
        self.default_visibility.is_none()
            && self.fields.is_empty()
            && self.links.is_empty()
            && self.contacts.is_empty()
    }

    fn default_is_public(&self) -> bool {
        self.default_visibility
            .as_ref()
            .map(ProfilePrivacyRule::is_public)
            .unwrap_or(true)
    }

    fn is_public_field(&self, field_name: &str) -> bool {
        self.fields
            .get(field_name)
            .map(ProfilePrivacyRule::is_public)
            .unwrap_or_else(|| self.default_is_public())
    }

    fn is_public_link(&self, link_name: &str) -> bool {
        self.links
            .get(link_name)
            .map(ProfilePrivacyRule::is_public)
            .unwrap_or_else(|| self.is_public_field("links"))
    }

    fn is_public_contact(&self, contact_name: &str) -> bool {
        self.contacts
            .get(contact_name)
            .map(ProfilePrivacyRule::is_public)
            .unwrap_or_else(|| self.is_public_field("public_contacts"))
    }
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

/// Local-only superset of UserProfile. Do not publish it as a DID document.
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct UserPrivateProfile {
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
    #[serde(skip_serializing_if = "UserProfilePrivacy::is_empty")]
    pub privacy: UserProfilePrivacy,
    #[serde(default)]
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub private_contacts: HashMap<String, ProfileContact>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub private_meta: Option<Value>,
    #[serde(default)]
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub private_extra: HashMap<String, Value>,
    #[serde(default)]
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

impl UserPrivateProfile {
    pub fn to_user_profile(&self) -> UserProfile {
        self.to_public_profile()
    }

    pub fn to_public_profile(&self) -> UserProfile {
        UserProfile {
            did: self.did.clone(),
            name: self.public_option("name", &self.name),
            display_name: self.public_option("display_name", &self.display_name),
            avatar: self.public_option("avatar", &self.avatar),
            meta: self.public_option("meta", &self.meta),
            headline: self.public_option("headline", &self.headline),
            bio: self.public_option("bio", &self.bio),
            location: self.public_option("location", &self.location),
            organization: self.public_option("organization", &self.organization),
            title: self.public_option("title", &self.title),
            links: self
                .links
                .iter()
                .filter(|(name, _)| self.privacy.is_public_link(name))
                .map(|(name, link)| (name.clone(), link.clone()))
                .collect(),
            public_contacts: self
                .public_contacts
                .iter()
                .filter(|(name, _)| self.privacy.is_public_contact(name))
                .map(|(name, contact)| (name.clone(), contact.clone()))
                .collect(),
            extra: self
                .extra
                .iter()
                .filter(|(field_name, _)| self.privacy.is_public_field(field_name))
                .map(|(field_name, field_value)| (field_name.clone(), field_value.clone()))
                .collect(),
        }
    }

    fn public_option<T: Clone>(&self, field_name: &str, value: &Option<T>) -> Option<T> {
        if self.privacy.is_public_field(field_name) {
            value.clone()
        } else {
            None
        }
    }
}

impl From<UserProfile> for UserPrivateProfile {
    fn from(profile: UserProfile) -> Self {
        Self {
            did: profile.did,
            name: profile.name,
            display_name: profile.display_name,
            avatar: profile.avatar,
            meta: profile.meta,
            headline: profile.headline,
            bio: profile.bio,
            location: profile.location,
            organization: profile.organization,
            title: profile.title,
            links: profile.links,
            public_contacts: profile.public_contacts,
            privacy: UserProfilePrivacy::default(),
            private_contacts: HashMap::new(),
            private_meta: None,
            private_extra: HashMap::new(),
            extra: profile.extra,
        }
    }
}

impl From<&UserPrivateProfile> for UserProfile {
    fn from(profile: &UserPrivateProfile) -> Self {
        profile.to_user_profile()
    }
}

impl From<UserPrivateProfile> for UserProfile {
    fn from(profile: UserPrivateProfile) -> Self {
        profile.to_user_profile()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn profile_contact_accepts_platform_specific_shapes() {
        let telegram: ProfileContact = serde_json::from_value(json!({
            "platform": "telegram",
            "account_id": "user:5397330802",
            "display_id": "wacer2026"
        }))
        .unwrap();

        assert_eq!(
            telegram,
            ProfileContact::Telegram(TelegramContact {
                account_id: Some("user:5397330802".to_string()),
                display_id: Some("wacer2026".to_string()),
            })
        );

        let email: ProfileContact = serde_json::from_value(json!({
            "platform": "email",
            "address": "alice@example.com"
        }))
        .unwrap();
        assert_eq!(
            email,
            ProfileContact::Email(EmailContact {
                address: "alice@example.com".to_string()
            })
        );

        let bluesky: ProfileContact = serde_json::from_value(json!({
            "platform": "bluesky",
            "handle": "alice.bsky.social"
        }))
        .unwrap();
        assert_eq!(
            bluesky,
            ProfileContact::Bluesky(BlueskyContact {
                did: None,
                handle: Some("alice.bsky.social".to_string()),
            })
        );
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
            "tunnel_id": "did:web:tg-tunnel.test.buckyos.io"
        }))
        .is_err());

        assert!(serde_json::from_value::<ProfileContact>(json!({
            "platform": "telegram"
        }))
        .is_err());

        assert!(serde_json::from_value::<ProfileContact>(json!({
            "platform": "matrix",
            "account_id": "@alice:example.com"
        }))
        .is_err());
    }

    #[test]
    fn private_profile_derives_public_profile_with_privacy_controls() {
        let mut privacy = UserProfilePrivacy::default();
        privacy
            .fields
            .insert("bio".to_string(), ProfilePrivacyRule::private());
        privacy
            .links
            .insert("private_site".to_string(), ProfilePrivacyRule::private());
        privacy
            .contacts
            .insert("telegram".to_string(), ProfilePrivacyRule::private());

        let private_profile = UserPrivateProfile {
            did: DID::new("bns", "alice"),
            name: Some("alice".to_string()),
            display_name: Some("Alice".to_string()),
            avatar: Some("https://example.com/alice.png".to_string()),
            meta: None,
            headline: Some("Builder".to_string()),
            bio: Some("private long-form biography".to_string()),
            location: Some("Wonderland".to_string()),
            organization: None,
            title: None,
            links: HashMap::from([
                (
                    "website".to_string(),
                    ProfileLink {
                        label: "Website".to_string(),
                        url: "https://alice.example.com".to_string(),
                    },
                ),
                (
                    "private_site".to_string(),
                    ProfileLink {
                        label: "Private".to_string(),
                        url: "https://private.example.com".to_string(),
                    },
                ),
            ]),
            public_contacts: HashMap::from([
                (
                    "email".to_string(),
                    ProfileContact::Email(EmailContact {
                        address: "alice@example.com".to_string(),
                    }),
                ),
                (
                    "telegram".to_string(),
                    ProfileContact::Telegram(TelegramContact {
                        account_id: Some("user:5397330802".to_string()),
                        display_id: Some("alice".to_string()),
                    }),
                ),
            ]),
            privacy,
            private_contacts: HashMap::from([(
                "phone".to_string(),
                ProfileContact::Phone(PhoneContact {
                    e164: "+15555550100".to_string(),
                }),
            )]),
            private_meta: Some(json!({ "birthday": "1990-01-01" })),
            private_extra: HashMap::from([("note".to_string(), json!("local only"))]),
            extra: HashMap::from([("pronouns".to_string(), json!("she/her"))]),
        };

        let public_profile = private_profile.to_user_profile();

        assert_eq!(public_profile.did, DID::new("bns", "alice"));
        assert_eq!(public_profile.name.as_deref(), Some("alice"));
        assert_eq!(public_profile.bio, None);
        assert!(public_profile.links.contains_key("website"));
        assert!(!public_profile.links.contains_key("private_site"));
        assert!(public_profile.public_contacts.contains_key("email"));
        assert!(!public_profile.public_contacts.contains_key("telegram"));
        assert_eq!(
            public_profile.extra.get("pronouns"),
            Some(&json!("she/her"))
        );

        let public_value = serde_json::to_value(public_profile).unwrap();
        assert!(public_value.get("privacy").is_none());
        assert!(public_value.get("private_contacts").is_none());
        assert!(public_value.get("private_meta").is_none());
        assert!(public_value.get("private_extra").is_none());
    }

    #[test]
    fn private_profile_can_round_trip_from_user_profile() {
        let public_profile = UserProfile {
            did: DID::new("bns", "alice"),
            name: Some("alice".to_string()),
            display_name: Some("Alice".to_string()),
            avatar: None,
            meta: Some(json!({ "identity": "public" })),
            headline: Some("Builder".to_string()),
            bio: None,
            location: None,
            organization: None,
            title: None,
            links: HashMap::from([(
                "website".to_string(),
                ProfileLink {
                    label: "Website".to_string(),
                    url: "https://alice.example.com".to_string(),
                },
            )]),
            public_contacts: HashMap::new(),
            extra: HashMap::from([("pronouns".to_string(), json!("she/her"))]),
        };

        let private_profile = UserPrivateProfile::from(public_profile.clone());

        assert_eq!(private_profile.to_user_profile(), public_profile);
    }

    #[test]
    fn private_profile_default_private_requires_explicit_public_fields() {
        let mut privacy = UserProfilePrivacy::default();
        privacy.default_visibility = Some(ProfilePrivacyRule::private());
        privacy
            .fields
            .insert("name".to_string(), ProfilePrivacyRule::public());
        privacy
            .contacts
            .insert("email".to_string(), ProfilePrivacyRule::public());

        let private_profile = UserPrivateProfile {
            did: DID::new("bns", "alice"),
            name: Some("alice".to_string()),
            display_name: Some("Alice".to_string()),
            avatar: None,
            meta: None,
            headline: Some("Builder".to_string()),
            bio: None,
            location: None,
            organization: None,
            title: None,
            links: HashMap::from([(
                "website".to_string(),
                ProfileLink {
                    label: "Website".to_string(),
                    url: "https://alice.example.com".to_string(),
                },
            )]),
            public_contacts: HashMap::from([(
                "email".to_string(),
                ProfileContact::Email(EmailContact {
                    address: "alice@example.com".to_string(),
                }),
            )]),
            privacy,
            private_contacts: HashMap::new(),
            private_meta: None,
            private_extra: HashMap::new(),
            extra: HashMap::from([("pronouns".to_string(), json!("she/her"))]),
        };

        let public_profile = private_profile.to_user_profile();

        assert_eq!(public_profile.name.as_deref(), Some("alice"));
        assert_eq!(public_profile.display_name, None);
        assert_eq!(public_profile.headline, None);
        assert!(public_profile.links.is_empty());
        assert!(public_profile.public_contacts.contains_key("email"));
        assert!(!public_profile.extra.contains_key("pronouns"));
    }
}
