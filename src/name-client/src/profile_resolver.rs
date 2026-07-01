use std::collections::HashMap;

use jsonwebtoken::DecodingKey;
use name_lib::{DIDDocumentTrait, EncodedDocument, NSError, NSResult};
use name_lib::{OwnerConfig, UserProfile, DID};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::NameClient;

pub const OWNER_DOC_TYPE: &str = "owner";
pub const USER_PROFILE_DOC_TYPE: &str = "user";

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProfileResolveOptions {
    #[serde(default)]
    pub force_refresh: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProfileSource {
    Profile,
    OwnerConfig,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct MergedProfile {
    pub did: DID,
    pub profile: UserProfile,
    pub field_sources: HashMap<String, ProfileSource>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_zone_did: Option<DID>,
}

impl NameClient {
    pub async fn resolve_owner_config(&self, did: &DID) -> NSResult<OwnerConfig> {
        self.resolve_owner_config_with_options(did, false).await
    }

    pub async fn resolve_owner_config_with_options(
        &self,
        did: &DID,
        force_refresh: bool,
    ) -> NSResult<OwnerConfig> {
        if force_refresh {
            self.invalidate_did_cache(did.clone(), Some(OWNER_DOC_TYPE));
        }
        let owner_doc = self.resolve_did(did, Some(OWNER_DOC_TYPE)).await?;
        decode_owner_config(did, &owner_doc)
    }

    pub async fn resolve_user_profile(
        &self,
        did: &DID,
        opts: ProfileResolveOptions,
    ) -> NSResult<MergedProfile> {
        let (owner_did, _) = split_bns_user_zone_did(did);
        let owner_config = self
            .resolve_owner_config_with_options(&owner_did, opts.force_refresh)
            .await?;
        let profile = self
            .resolve_profile_source(did, &owner_config, opts.force_refresh)
            .await?;
        let profile_source = profile.as_ref().map(|_| ProfileSource::Profile);

        merge_profile_with_owner_config(
            did.clone(),
            profile,
            profile_source,
            &owner_config,
            owner_config.get_default_zone_did(),
        )
    }

    pub async fn owner_is_bound_to_zone(&self, did: &DID, zone_did: &DID) -> NSResult<bool> {
        let owner_config = self.resolve_owner_config(did).await?;
        Ok(owner_config.is_bound_to_zone(zone_did))
    }

    async fn resolve_profile_source(
        &self,
        profile_did: &DID,
        owner_config: &OwnerConfig,
        force_refresh: bool,
    ) -> NSResult<Option<UserProfile>> {
        if force_refresh {
            self.invalidate_did_cache(profile_did.clone(), Some(USER_PROFILE_DOC_TYPE));
        }

        let profile_doc = match self
            .resolve_did(profile_did, Some(USER_PROFILE_DOC_TYPE))
            .await
        {
            Ok(profile_doc) => profile_doc,
            Err(NSError::Disabled(msg)) => return Err(NSError::Disabled(msg)),
            Err(_) => return Ok(None),
        };

        let profile = decode_user_profile(owner_config, &profile_doc)?;
        Ok(Some(profile))
    }
}

fn decode_owner_config(did: &DID, owner_doc: &EncodedDocument) -> NSResult<OwnerConfig> {
    let unverified_owner_config = OwnerConfig::decode(owner_doc, None)?;
    if unverified_owner_config.id != *did {
        return Err(NSError::InvalidDID(format!(
            "owner-config id {} does not match requested {}",
            unverified_owner_config.id.to_string(),
            did.to_string()
        )));
    }

    if !owner_doc.is_proof() {
        return Ok(unverified_owner_config);
    }

    let owner_public_key = unverified_owner_config
        .get_default_key()
        .ok_or_else(|| NSError::NotFound("owner-config default key not found".to_string()))?;
    let owner_public_key = DecodingKey::from_jwk(&owner_public_key).map_err(|err| {
        NSError::DecodeJWTError(format!("owner public key decode failed: {}", err))
    })?;
    let verified_owner_config = OwnerConfig::decode(owner_doc, Some(&owner_public_key))?;
    if verified_owner_config.id != *did {
        return Err(NSError::InvalidDID(format!(
            "verified owner-config id {} does not match requested {}",
            verified_owner_config.id.to_string(),
            did.to_string()
        )));
    }
    Ok(verified_owner_config)
}

fn decode_user_profile(
    owner_config: &OwnerConfig,
    profile_doc: &EncodedDocument,
) -> NSResult<UserProfile> {
    owner_config.validate_jwt_revocation(USER_PROFILE_DOC_TYPE, profile_doc)?;

    if !profile_doc.is_proof() {
        return UserProfile::decode(profile_doc, None);
    }

    let owner_public_key = owner_config
        .get_default_key()
        .ok_or_else(|| NSError::NotFound("owner-config default key not found".to_string()))?;
    let owner_public_key = DecodingKey::from_jwk(&owner_public_key).map_err(|err| {
        NSError::DecodeJWTError(format!("owner public key decode failed: {}", err))
    })?;
    UserProfile::decode(profile_doc, Some(&owner_public_key))
}

fn split_bns_user_zone_did(did: &DID) -> (DID, Option<DID>) {
    if did.method != "bns" {
        return (did.clone(), None);
    }

    if let Some((user_name, zone_name)) = did.id.split_once('.') {
        if !user_name.is_empty() && !zone_name.is_empty() {
            return (DID::new("bns", user_name), Some(DID::new("bns", zone_name)));
        }
    }

    (did.clone(), None)
}

fn merge_profile_with_owner_config(
    requested_did: DID,
    profile: Option<UserProfile>,
    profile_source: Option<ProfileSource>,
    owner_config: &OwnerConfig,
    default_zone_did: Option<DID>,
) -> NSResult<MergedProfile> {
    let mut merged = Map::new();
    let mut field_sources = HashMap::new();

    if let Some(profile_source) = profile_source {
        merge_profile_source(&mut merged, &mut field_sources, profile, profile_source)?;
    }

    merge_owner_config_identity(&mut merged, &mut field_sources, owner_config);

    merged.insert(
        "did".to_string(),
        serde_json::to_value(&requested_did).unwrap(),
    );
    field_sources.remove("did");

    let profile = serde_json::from_value::<UserProfile>(Value::Object(merged))
        .map_err(|err| NSError::Failed(format!("failed to build merged user profile: {}", err)))?;

    Ok(MergedProfile {
        did: requested_did,
        profile,
        field_sources,
        default_zone_did,
    })
}

fn merge_owner_config_identity(
    merged: &mut Map<String, Value>,
    field_sources: &mut HashMap<String, ProfileSource>,
    owner_config: &OwnerConfig,
) {
    insert_owner_config_field(
        merged,
        field_sources,
        "name",
        Value::String(owner_config.name.clone()),
    );
    insert_owner_config_field(
        merged,
        field_sources,
        "display_name",
        Value::String(owner_config.display_name.clone()),
    );
    if let Some(avatar) = owner_config.avatar.as_ref() {
        insert_owner_config_field(
            merged,
            field_sources,
            "avatar",
            Value::String(avatar.clone()),
        );
    }
    if let Some(meta) = owner_config.meta.as_ref() {
        insert_owner_config_field(merged, field_sources, "meta", meta.clone());
        merge_owner_config_meta_overlay(merged, field_sources, meta);
    }

    for (field_name, field_value) in owner_config.extra_info.iter() {
        if field_name == "did" || field_name == "id" || field_value.is_null() {
            continue;
        }
        insert_owner_config_path(merged, field_sources, field_name, field_value.clone());
    }
}

fn insert_owner_config_field(
    merged: &mut Map<String, Value>,
    field_sources: &mut HashMap<String, ProfileSource>,
    field_name: &str,
    field_value: Value,
) {
    if field_value.is_null() {
        return;
    }
    merged.insert(field_name.to_string(), field_value);
    field_sources.insert(field_name.to_string(), ProfileSource::OwnerConfig);
}

fn merge_owner_config_meta_overlay(
    merged: &mut Map<String, Value>,
    field_sources: &mut HashMap<String, ProfileSource>,
    meta: &Value,
) {
    let Some(meta_object) = meta.as_object() else {
        return;
    };

    for (field_path, field_value) in meta_object {
        if field_path == "meta" || field_value.is_null() {
            continue;
        }
        insert_owner_config_path(merged, field_sources, field_path, field_value.clone());
    }
}

fn insert_owner_config_path(
    merged: &mut Map<String, Value>,
    field_sources: &mut HashMap<String, ProfileSource>,
    field_path: &str,
    field_value: Value,
) {
    let path = field_path.strip_prefix("$.").unwrap_or(field_path);
    let parts: Vec<&str> = path.split('.').filter(|part| !part.is_empty()).collect();

    let Some(first_part) = parts.first().copied() else {
        return;
    };
    if first_part == "did" || first_part == "id" || field_value.is_null() {
        return;
    }

    if parts.len() == 1 {
        let target = merged.entry(first_part.to_string()).or_insert(Value::Null);
        merge_json_value(target, field_value);
    } else {
        let target = merged
            .entry(first_part.to_string())
            .or_insert_with(|| Value::Object(Map::new()));
        merge_json_path(target, &parts[1..], field_value);
    }
    field_sources.insert(first_part.to_string(), ProfileSource::OwnerConfig);
}

fn merge_json_path(target: &mut Value, path: &[&str], value: Value) {
    if path.is_empty() {
        merge_json_value(target, value);
        return;
    }

    if !target.is_object() {
        *target = Value::Object(Map::new());
    }
    let target_object = target.as_object_mut().unwrap();
    let next = target_object
        .entry(path[0].to_string())
        .or_insert(Value::Null);
    merge_json_path(next, &path[1..], value);
}

fn merge_json_value(target: &mut Value, value: Value) {
    match (target, value) {
        (Value::Object(target_object), Value::Object(value_object)) => {
            for (key, value) in value_object {
                let target_value = target_object.entry(key).or_insert(Value::Null);
                merge_json_value(target_value, value);
            }
        }
        (target, value) => {
            *target = value;
        }
    }
}

fn merge_profile_source(
    merged: &mut Map<String, Value>,
    field_sources: &mut HashMap<String, ProfileSource>,
    profile: Option<UserProfile>,
    source: ProfileSource,
) -> NSResult<()> {
    let Some(profile) = profile else {
        return Ok(());
    };

    let value = serde_json::to_value(profile)
        .map_err(|err| NSError::Failed(format!("failed to serialize profile: {}", err)))?;
    let Some(profile_object) = value.as_object() else {
        return Err(NSError::Failed(
            "serialized user profile is not a JSON object".to_string(),
        ));
    };

    for (field_name, field_value) in profile_object {
        if field_name == "did" || field_value.is_null() {
            continue;
        }
        merged.insert(field_name.clone(), field_value.clone());
        field_sources.insert(field_name.clone(), source.clone());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{NameInfo, NsProvider, RecordType};
    use async_trait::async_trait;
    use buckyos_kit::buckyos_get_unix_timestamp;
    use jsonwebtoken::{encode, jwk::Jwk, Algorithm, EncodingKey, Header};
    use name_lib::{EmailContact, MatrixContact, ProfileContact};
    use serde_json::json;

    const TEST_OWNER_PRIVATE_KEY_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIJBRONAzbwpIOwm0ugIQNyZJrDXxZF7HoPWAZesMedOr
-----END PRIVATE KEY-----"#;

    fn owner_public_jwk() -> Jwk {
        serde_json::from_value(json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "T4Quc1L6Ogu4N2tTKOvneV1yYnBcmhP89B_RsuFsJZ8"
        }))
        .unwrap()
    }

    fn owner_private_key() -> EncodingKey {
        EncodingKey::from_ed_pem(TEST_OWNER_PRIVATE_KEY_PEM.as_bytes()).unwrap()
    }

    fn owner_doc(owner_did: DID, zone_did: Option<DID>) -> EncodedDocument {
        let mut owner_config = OwnerConfig::new(
            owner_did,
            "alice".to_string(),
            "Alice Document".to_string(),
            owner_public_jwk(),
        );
        owner_config.avatar = Some("https://example.com/alice.png".to_string());
        owner_config.meta = Some(json!({
            "identity": "owner-config",
            "headline": "from owner meta",
            "links": {
                "github": {
                    "label": "GitHub",
                    "url": "https://github.com/alice-owner"
                }
            },
            "$.public_contacts.email": {
                "platform": "email",
                "address": "owner@example.com"
            }
        }));
        owner_config
            .extra_info
            .insert("title".to_string(), json!("Owner Title"));
        if let Some(zone_did) = zone_did {
            owner_config.set_default_zone_did(zone_did);
        }
        owner_config.encode(Some(&owner_private_key())).unwrap()
    }

    fn profile_doc(did: DID, version_seq: u64, fields: Value) -> EncodedDocument {
        let mut profile = fields.as_object().unwrap().clone();
        profile.insert("did".to_string(), serde_json::to_value(did).unwrap());
        profile.insert("version_seq".to_string(), json!(version_seq));
        profile.insert("iat".to_string(), json!(buckyos_get_unix_timestamp()));
        profile.insert(
            "exp".to_string(),
            json!(buckyos_get_unix_timestamp() + 3600),
        );

        let jwt = encode(
            &Header::new(Algorithm::EdDSA),
            &Value::Object(profile),
            &owner_private_key(),
        )
        .unwrap();
        EncodedDocument::Jwt(jwt)
    }

    struct ProfileMockProvider {
        docs: HashMap<(String, String), EncodedDocument>,
    }

    #[async_trait]
    impl NsProvider for ProfileMockProvider {
        fn get_id(&self) -> String {
            "profile-mock".to_string()
        }

        // "user" 文档不是自声明 owner 字段的通用 Document 类型：它的归属由请求 DID
        // 的命名结构（`split_bns_user_zone_did`）决定，而不是文档内容自身。它的真实性
        // 由 `decode_user_profile` 用调用方已解析出的 owner key 单独验证，因此这里
        // 声明成免验证，交给 resolve_profile_source 自己的验签逻辑处理，避免走进
        // 通用递归验证管线（那条管线无法从文档内容推断出这个 owner 关系）。
        fn requires_verification(&self, doc_type: &str) -> bool {
            doc_type != USER_PROFILE_DOC_TYPE
        }

        async fn query(
            &self,
            _name: &str,
            _record_type: Option<RecordType>,
            _from_ip: Option<std::net::IpAddr>,
        ) -> NSResult<NameInfo> {
            Err(NSError::NotFound("not implemented".to_string()))
        }

        async fn query_did(
            &self,
            did: &DID,
            doc_type: Option<&str>,
            _from_ip: Option<std::net::IpAddr>,
        ) -> NSResult<EncodedDocument> {
            let key = (did.to_string(), doc_type.unwrap_or_default().to_string());
            self.docs
                .get(&key)
                .cloned()
                .ok_or_else(|| NSError::NotFound(format!("missing {}", did.to_string())))
        }
    }

    #[tokio::test]
    async fn resolve_user_profile_uses_standard_did_resolution_then_owner_config_overrides_identity_fields(
    ) {
        let owner_did = DID::new("bns", "alice");
        let zone_did = DID::new("bns", "home");

        let mut high_priority_docs = HashMap::new();
        high_priority_docs.insert(
            (owner_did.to_string(), OWNER_DOC_TYPE.to_string()),
            owner_doc(owner_did.clone(), Some(zone_did.clone())),
        );
        high_priority_docs.insert(
            (owner_did.to_string(), USER_PROFILE_DOC_TYPE.to_string()),
            profile_doc(
                owner_did.clone(),
                2,
                json!({
                    "display_name": "Alice Profile",
                    "avatar": "https://example.com/profile.png",
                    "headline": "from selected profile",
                    "title": "Profile Title",
                    "links": {
                        "blog": {
                            "label": "Blog",
                            "url": "https://blog.example.com/alice"
                        },
                        "github": {
                            "label": "GitHub",
                            "url": "https://github.com/alice-profile"
                        }
                    },
                    "public_contacts": {
                        "email": {
                            "platform": "email",
                            "address": "profile@example.com"
                        },
                        "matrix": {
                            "platform": "matrix",
                            "user_id": "@alice:example.com"
                        }
                    }
                }),
            ),
        );

        let mut low_priority_docs = HashMap::new();
        low_priority_docs.insert(
            (owner_did.to_string(), USER_PROFILE_DOC_TYPE.to_string()),
            profile_doc(
                owner_did.clone(),
                1,
                json!({
                    "display_name": "Alice Low Priority",
                    "bio": "from low priority profile",
                    "location": "Low Priority City"
                }),
            ),
        );

        let client = NameClient::new(crate::NameClientConfig {
            enable_cache: false,
            cache_backend: crate::CacheBackend::Memory,
            ..Default::default()
        });
        client
            .add_provider(
                Box::new(ProfileMockProvider {
                    docs: low_priority_docs,
                }),
                Some(50),
            )
            .await;
        client
            .add_provider(
                Box::new(ProfileMockProvider {
                    docs: high_priority_docs,
                }),
                Some(10),
            )
            .await;

        let merged = client
            .resolve_user_profile(&owner_did, ProfileResolveOptions::default())
            .await
            .unwrap();

        assert_eq!(merged.default_zone_did, Some(zone_did));
        assert_eq!(merged.profile.name.as_deref(), Some("alice"));
        assert_eq!(
            merged.profile.display_name.as_deref(),
            Some("Alice Document")
        );
        assert_eq!(
            merged.profile.avatar.as_deref(),
            Some("https://example.com/alice.png")
        );
        assert_eq!(
            merged
                .profile
                .meta
                .as_ref()
                .and_then(|meta| meta.get("identity")),
            Some(&json!("owner-config"))
        );
        assert_eq!(merged.profile.bio.as_deref(), None);
        assert_eq!(merged.profile.location.as_deref(), None);
        assert_eq!(merged.profile.headline.as_deref(), Some("from owner meta"));
        assert_eq!(merged.profile.title.as_deref(), Some("Owner Title"));
        assert_eq!(
            merged.profile.extra.get("identity"),
            Some(&json!("owner-config"))
        );
        assert_eq!(
            merged
                .profile
                .links
                .get("blog")
                .map(|link| link.url.as_str()),
            Some("https://blog.example.com/alice")
        );
        assert_eq!(
            merged
                .profile
                .links
                .get("github")
                .map(|link| link.url.as_str()),
            Some("https://github.com/alice-owner")
        );
        assert_eq!(
            merged
                .profile
                .public_contacts
                .get("email")
                .and_then(|contact| match contact {
                    ProfileContact::Email(EmailContact { address }) => Some(address.as_str()),
                    _ => None,
                }),
            Some("owner@example.com")
        );
        assert_eq!(
            merged
                .profile
                .public_contacts
                .get("matrix")
                .and_then(|contact| match contact {
                    ProfileContact::Matrix(MatrixContact { user_id }) => Some(user_id.as_str()),
                    _ => None,
                }),
            Some("@alice:example.com")
        );
        assert_eq!(
            merged.field_sources.get("display_name"),
            Some(&ProfileSource::OwnerConfig)
        );
        assert_eq!(
            merged.field_sources.get("avatar"),
            Some(&ProfileSource::OwnerConfig)
        );
        assert_eq!(
            merged.field_sources.get("headline"),
            Some(&ProfileSource::OwnerConfig)
        );
        assert_eq!(
            merged.field_sources.get("links"),
            Some(&ProfileSource::OwnerConfig)
        );
        assert_eq!(
            merged.field_sources.get("public_contacts"),
            Some(&ProfileSource::OwnerConfig)
        );
        assert!(!merged.field_sources.contains_key("bio"));
    }

    #[tokio::test]
    async fn explicit_bns_zone_did_resolves_profile_for_requested_did_and_owner_doc_for_owner() {
        let requested_did = DID::new("bns", "alice.home");
        let owner_did = DID::new("bns", "alice");

        let mut docs = HashMap::new();
        docs.insert(
            (owner_did.to_string(), OWNER_DOC_TYPE.to_string()),
            owner_doc(owner_did.clone(), None),
        );
        docs.insert(
            (requested_did.to_string(), USER_PROFILE_DOC_TYPE.to_string()),
            profile_doc(
                requested_did.clone(),
                1,
                json!({
                    "display_name": "Alice In Home",
                    "location": "Home"
                }),
            ),
        );

        let client = NameClient::new(crate::NameClientConfig {
            enable_cache: false,
            cache_backend: crate::CacheBackend::Memory,
            ..Default::default()
        });
        client
            .add_provider(Box::new(ProfileMockProvider { docs }), Some(10))
            .await;

        let merged = client
            .resolve_user_profile(&requested_did, ProfileResolveOptions::default())
            .await
            .unwrap();

        assert_eq!(merged.did, requested_did);
        assert_eq!(merged.default_zone_did, None);
        assert_eq!(merged.profile.did, DID::new("bns", "alice.home"));
        assert_eq!(
            merged.profile.display_name.as_deref(),
            Some("Alice Document")
        );
        assert_eq!(merged.profile.location.as_deref(), Some("Home"));
        assert_eq!(
            merged.field_sources.get("display_name"),
            Some(&ProfileSource::OwnerConfig)
        );
        assert_eq!(
            merged.field_sources.get("location"),
            Some(&ProfileSource::Profile)
        );
    }

    #[tokio::test]
    async fn resolve_user_profile_returns_owner_config_identity_without_profile_doc() {
        let owner_did = DID::new("bns", "alice");

        let mut docs = HashMap::new();
        docs.insert(
            (owner_did.to_string(), OWNER_DOC_TYPE.to_string()),
            owner_doc(owner_did.clone(), None),
        );

        let client = NameClient::new(crate::NameClientConfig {
            enable_cache: false,
            cache_backend: crate::CacheBackend::Memory,
            ..Default::default()
        });
        client
            .add_provider(Box::new(ProfileMockProvider { docs }), Some(10))
            .await;

        let merged = client
            .resolve_user_profile(&owner_did, ProfileResolveOptions::default())
            .await
            .unwrap();

        assert_eq!(merged.did, owner_did);
        assert_eq!(merged.default_zone_did, None);
        assert_eq!(merged.profile.name.as_deref(), Some("alice"));
        assert_eq!(
            merged.profile.display_name.as_deref(),
            Some("Alice Document")
        );
        assert_eq!(
            merged.profile.avatar.as_deref(),
            Some("https://example.com/alice.png")
        );
        assert_eq!(merged.profile.title.as_deref(), Some("Owner Title"));
        assert_eq!(
            merged.field_sources.get("display_name"),
            Some(&ProfileSource::OwnerConfig)
        );
    }

    #[tokio::test]
    async fn owner_is_bound_to_zone_uses_binded_zone_list() {
        let owner_did = DID::new("bns", "alice");
        let zone_did = DID::new("bns", "home");
        let mut docs = HashMap::new();
        docs.insert(
            (owner_did.to_string(), OWNER_DOC_TYPE.to_string()),
            owner_doc(owner_did.clone(), Some(zone_did.clone())),
        );

        let client = NameClient::new(crate::NameClientConfig {
            enable_cache: false,
            cache_backend: crate::CacheBackend::Memory,
            ..Default::default()
        });
        client
            .add_provider(Box::new(ProfileMockProvider { docs }), Some(10))
            .await;

        assert!(client
            .owner_is_bound_to_zone(&owner_did, &zone_did)
            .await
            .unwrap());
        assert!(!client
            .owner_is_bound_to_zone(&owner_did, &DID::new("bns", "other"))
            .await
            .unwrap());
    }
}
