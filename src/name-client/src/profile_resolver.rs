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
    #[serde(default)]
    pub require_bns: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProfileSource {
    Zone,
    Bns,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct MergedProfile {
    pub did: DID,
    pub profile: UserProfile,
    pub field_sources: HashMap<String, ProfileSource>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_zone_did: Option<DID>,
}

#[derive(Clone, Debug)]
struct ProfileRoute {
    requested_did: DID,
    owner_did: DID,
    bns_profile_did: DID,
    zone_profile_did: Option<DID>,
    default_zone_did: Option<DID>,
    route_error: Option<String>,
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
        let route = self.resolve_profile_route(did, opts.force_refresh).await?;
        let owner_config = self
            .resolve_owner_config_with_options(&route.owner_did, opts.force_refresh)
            .await?;

        let zone_profile = match route.zone_profile_did.as_ref() {
            Some(zone_profile_did) => {
                self.resolve_profile_source(
                    zone_profile_did,
                    &owner_config,
                    opts.force_refresh,
                    false,
                )
                .await?
            }
            None => None,
        };

        let bns_profile = self
            .resolve_profile_source(
                &route.bns_profile_did,
                &owner_config,
                opts.force_refresh,
                opts.require_bns,
            )
            .await?;

        if opts.require_bns && bns_profile.is_none() {
            return Err(NSError::NotFound(format!(
                "BNS user profile not found: {}",
                route.bns_profile_did.to_string()
            )));
        }

        if zone_profile.is_none() && bns_profile.is_none() {
            if let Some(route_error) = route.route_error {
                return Err(NSError::NotFound(route_error));
            }
            return Err(NSError::NotFound(format!(
                "user profile not found: {}",
                did.to_string()
            )));
        }

        merge_profiles(
            route.requested_did,
            zone_profile,
            bns_profile,
            route.default_zone_did,
        )
    }

    pub async fn owner_is_bound_to_zone(&self, did: &DID, zone_did: &DID) -> NSResult<bool> {
        let owner_config = self.resolve_owner_config(did).await?;
        Ok(owner_config.is_bound_to_zone(zone_did))
    }

    async fn resolve_profile_route(
        &self,
        did: &DID,
        force_refresh: bool,
    ) -> NSResult<ProfileRoute> {
        let (owner_did, explicit_zone_did) = split_bns_user_zone_did(did);
        let bns_profile_did = owner_did.clone();
        let mut default_zone_did = explicit_zone_did;
        let mut route_error = None;

        if default_zone_did.is_none() {
            match self
                .resolve_owner_config_with_options(&owner_did, force_refresh)
                .await
            {
                Ok(owner_config) => {
                    default_zone_did = owner_config.get_default_zone_did();
                    if default_zone_did.is_none() {
                        route_error = Some(format!(
                            "{} owner-config binded_zone_list is empty",
                            owner_did.to_string()
                        ));
                    }
                }
                Err(err) => {
                    route_error = Some(format!(
                        "resolve {} owner-config failed: {}",
                        owner_did.to_string(),
                        err
                    ));
                }
            }
        }

        let zone_profile_did = default_zone_did
            .as_ref()
            .map(|zone_did| zone_hosted_user_did(&owner_did, zone_did));

        Ok(ProfileRoute {
            requested_did: did.clone(),
            owner_did,
            bns_profile_did,
            zone_profile_did,
            default_zone_did,
            route_error,
        })
    }

    async fn resolve_profile_source(
        &self,
        profile_did: &DID,
        owner_config: &OwnerConfig,
        force_refresh: bool,
        require_source: bool,
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
            Err(err) => {
                if require_source {
                    return Err(err);
                }
                return Ok(None);
            }
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

fn zone_hosted_user_did(owner_did: &DID, zone_did: &DID) -> DID {
    let user_name = owner_did
        .id
        .split(':')
        .next()
        .unwrap_or(owner_did.id.as_str());
    match zone_did.method.as_str() {
        "bns" => DID::new("bns", &format!("{}.{}", user_name, zone_did.id)),
        "web" => DID::new("web", &format!("{}:users:{}", zone_did.id, user_name)),
        _ => DID::new(&zone_did.method, &format!("{}.{}", user_name, zone_did.id)),
    }
}

fn merge_profiles(
    requested_did: DID,
    zone_profile: Option<UserProfile>,
    bns_profile: Option<UserProfile>,
    default_zone_did: Option<DID>,
) -> NSResult<MergedProfile> {
    let mut merged = Map::new();
    let mut field_sources = HashMap::new();

    merge_profile_source(
        &mut merged,
        &mut field_sources,
        zone_profile,
        ProfileSource::Zone,
    )?;
    merge_profile_source(
        &mut merged,
        &mut field_sources,
        bns_profile,
        ProfileSource::Bns,
    )?;

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
            "Alice".to_string(),
            owner_public_jwk(),
        );
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
    async fn resolve_user_profile_merges_zone_and_bns_with_bns_precedence() {
        let owner_did = DID::new("bns", "alice");
        let zone_did = DID::new("bns", "home");
        let zone_profile_did = DID::new("bns", "alice.home");

        let mut docs = HashMap::new();
        docs.insert(
            (owner_did.to_string(), OWNER_DOC_TYPE.to_string()),
            owner_doc(owner_did.clone(), Some(zone_did.clone())),
        );
        docs.insert(
            (
                zone_profile_did.to_string(),
                USER_PROFILE_DOC_TYPE.to_string(),
            ),
            profile_doc(
                owner_did.clone(),
                1,
                json!({
                    "display_name": "Alice Zone",
                    "bio": "from zone",
                    "location": "Zone City"
                }),
            ),
        );
        docs.insert(
            (owner_did.to_string(), USER_PROFILE_DOC_TYPE.to_string()),
            profile_doc(
                owner_did.clone(),
                2,
                json!({
                    "display_name": "Alice BNS",
                    "headline": "from bns"
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
            .resolve_user_profile(&owner_did, ProfileResolveOptions::default())
            .await
            .unwrap();

        assert_eq!(merged.default_zone_did, Some(zone_did));
        assert_eq!(merged.profile.display_name.as_deref(), Some("Alice BNS"));
        assert_eq!(merged.profile.bio.as_deref(), Some("from zone"));
        assert_eq!(merged.profile.headline.as_deref(), Some("from bns"));
        assert_eq!(
            merged.field_sources.get("display_name"),
            Some(&ProfileSource::Bns)
        );
        assert_eq!(merged.field_sources.get("bio"), Some(&ProfileSource::Zone));
    }

    #[tokio::test]
    async fn explicit_bns_zone_did_skips_default_zone_lookup() {
        let requested_did = DID::new("bns", "alice.home");
        let owner_did = DID::new("bns", "alice");
        let zone_profile_did = DID::new("bns", "alice.home");

        let mut docs = HashMap::new();
        docs.insert(
            (owner_did.to_string(), OWNER_DOC_TYPE.to_string()),
            owner_doc(owner_did.clone(), None),
        );
        docs.insert(
            (
                zone_profile_did.to_string(),
                USER_PROFILE_DOC_TYPE.to_string(),
            ),
            profile_doc(
                owner_did.clone(),
                1,
                json!({
                    "display_name": "Alice In Home"
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
        assert_eq!(merged.default_zone_did, Some(DID::new("bns", "home")));
        assert_eq!(merged.profile.did, DID::new("bns", "alice.home"));
        assert_eq!(
            merged.profile.display_name.as_deref(),
            Some("Alice In Home")
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
