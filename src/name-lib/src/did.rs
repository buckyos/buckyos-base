use std::collections::HashMap;

use crate::agent::AgentDocument;
use crate::did_object_card::{DIDObjectCard, DID_OBJECT_SERVICE_TYPE};
use crate::user::OwnerDocument;
use crate::zone::{ZoneBootDocument, ZoneDocument};
use crate::DeviceDocument;
use crate::{decode_jwt_claim_without_verify, NSError, NSResult};
use async_trait::async_trait;
use base64::{
    engine::general_purpose::STANDARD, engine::general_purpose::URL_SAFE_NO_PAD, Engine as _,
};
use jsonwebtoken::{jwk::Jwk, DecodingKey, EncodingKey};
use log::{debug, info};
use once_cell::sync::OnceCell;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{json, Value};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DidDocType {
    Zone,
    Owner,
    Info,
    Boot,
    User,
    Device,
    DidObject,
    Custom(String),
}

impl DidDocType {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Zone => "zone",
            Self::Owner => "owner",
            Self::Info => "info",
            Self::Boot => "boot",
            Self::User => "user",
            Self::Device => "device",
            Self::DidObject => "did-object",
            Self::Custom(doc_type) => doc_type.as_str(),
        }
    }

    pub fn custom(doc_type: impl Into<String>) -> Self {
        Self::from(doc_type.into())
    }
}

impl Default for DidDocType {
    fn default() -> Self {
        Self::Zone
    }
}

impl std::fmt::Display for DidDocType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl AsRef<str> for DidDocType {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl From<&str> for DidDocType {
    fn from(value: &str) -> Self {
        match value {
            "zone" => Self::Zone,
            "owner" => Self::Owner,
            "info" => Self::Info,
            "boot" => Self::Boot,
            "user" => Self::User,
            "device" => Self::Device,
            "did-object" => Self::DidObject,
            _ => Self::Custom(value.to_string()),
        }
    }
}

impl From<String> for DidDocType {
    fn from(value: String) -> Self {
        match value.as_str() {
            "zone" => Self::Zone,
            "owner" => Self::Owner,
            "info" => Self::Info,
            "boot" => Self::Boot,
            "user" => Self::User,
            "device" => Self::Device,
            "did-object" => Self::DidObject,
            _ => Self::Custom(value),
        }
    }
}

impl Serialize for DidDocType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for DidDocType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Ok(Self::from(value))
    }
}

pub const DEFAULT_DID_DOC_TYPE: DidDocType = DidDocType::Zone;

pub const DOC_TYPE_OWNER: DidDocType = DidDocType::Owner;
pub const DOC_TYPE_INFO: DidDocType = DidDocType::Info;
#[derive(Clone, Debug, PartialEq, Hash, Eq, PartialOrd, Ord)]
pub struct DID {
    pub method: String,
    pub id: String,
}

pub const DID_DOC_AUTHKEY: &str = "#auth-key";

impl Default for DID {
    fn default() -> Self {
        Self {
            method: "undefined".to_string(),
            id: "undefined".to_string(),
        }
    }
}

impl DID {
    pub fn new(method: &str, id: &str) -> Self {
        DID {
            method: method.to_string(),
            id: id.to_string(),
        }
    }

    pub fn undefined() -> Self {
        DID {
            method: "undefined".to_string(),
            id: "undefined".to_string(),
        }
    }

    pub fn is_undefined(&self) -> bool {
        self.method == "undefined"
    }

    pub fn is_valid(&self) -> bool {
        self.method != "undefined"
    }

    pub fn get_ed25519_auth_key(&self) -> Option<[u8; 32]> {
        if self.method == "dev" {
            let auth_key = URL_SAFE_NO_PAD.decode(self.id.as_str()).unwrap();
            return Some(auth_key.try_into().unwrap());
        }
        None
    }

    pub fn get_auth_key(&self) -> Option<(DecodingKey, Jwk)> {
        if self.method == "dev" {
            let jwk = json!({
             "kty": "OKP",
             "crv": "Ed25519",
             "x": self.id,
            });
            let jwk = serde_json::from_value(jwk);
            if jwk.is_err() {
                return None;
            }
            let jwk: Jwk = jwk.unwrap();
            return Some((DecodingKey::from_jwk(&jwk).unwrap(), jwk));
        }
        None
    }

    pub fn is_named_obj_id(&self) -> bool {
        self.method == "dev"
    }

    pub fn get_path_from_id(&self) -> Option<String> {
        let parts: Vec<&str> = self.id.split(':').collect();
        if parts.len() > 1 {
            return Some(parts[1..].join("/"));
        }
        None
    }

    /// 名字层级上的上级名字(uppername):去掉名字最左边一个 label,得到上级
    /// 名字的 DID。名字之外的部分不参与层级、也不被上级继承:did:web 的
    /// %3A 编码端口和路径段都会被去掉。上级必须仍是可独立查询的名字,
    /// 否则返回 None:
    ///
    ///   did:web:ood1.example.com            => Some(did:web:example.com)
    ///   did:web:ood1.example.com%3A8080     => Some(did:web:example.com)
    ///   did:web:ood1.example.com:devices:c1 => Some(did:web:example.com)
    ///   did:web:example.com                 => None(域名默认至少有一个点,
    ///                                         上级只剩顶级域,不可能向它查询)
    ///   did:web:127.0.0.1                   => None(IP 没有名字层级)
    ///   did:bns:app1.alice                  => Some(did:bns:alice)
    ///   did:bns:alice                       => None(一级名字是根)
    ///   did:dev / did:key                   => None(key 类 DID 没有名字层级)
    pub fn upper_did(&self) -> Option<DID> {
        // 名字部分:id 的第一段(web 的路径段以 ':' 分隔),再去掉 %3A 编码的
        // 端口(hostname 合法字符不需要 pct-encode,'%' 只会出现在端口编码里)。
        let name = self.id.split(':').next().unwrap_or_default();
        let name = name.split('%').next().unwrap_or_default();
        match self.method.as_str() {
            "web" => {
                if name.parse::<std::net::IpAddr>().is_ok() {
                    return None;
                }
                let (_, upper) = name.split_once('.')?;
                // 域名默认至少有一个点:上级只剩单 label(com 这类顶级域)时,
                // 不可能向它查询,视为没有 upper。
                if !upper.contains('.') {
                    return None;
                }
                Some(DID::new("web", upper))
            }
            "bns" => {
                let (_, upper) = name.split_once('.')?;
                Some(DID::new("bns", upper))
            }
            _ => None,
        }
    }

    pub fn from_str(did: &str) -> NSResult<Self> {
        let parts: Vec<&str> = did.split(':').collect();
        if parts[0] != "did" {
            //this is a host name
            let result = Self::from_host_name(did);
            if result.is_some() {
                return Ok(result.unwrap());
            }
            return Err(NSError::InvalidDID(format!("invalid did {}", did)));
        }
        let id = parts[2..].join(":");
        Ok(DID {
            method: parts[1].to_string(),
            id,
        })
    }

    /// 将用户输入的友好名字推断为完整 DID。
    ///
    /// 未带 `did:` 前缀时，单段或两段名字按 BNS 处理，三段及以上名字按
    /// Web 域名处理：
    ///
    /// - `app1.owner` -> `did:bns:app1.owner`
    /// - `app1.example.com` -> `did:web:app1.example.com`
    ///
    /// 已经是完整 DID 的输入会被严格校验后原样返回。该 helper 只用于用户
    /// 输入边界；协议层仍应直接使用 canonical DID。
    pub fn from_friendly_name(input: &str) -> NSResult<Self> {
        let value = input.trim();
        if value.starts_with("did:") {
            return parse_canonical_did(value);
        }
        if value.is_empty() {
            return Err(NSError::InvalidDID(
                "friendly DID name cannot be empty".to_string(),
            ));
        }

        let labels: Vec<&str> = value.split('.').collect();
        if labels.iter().any(|label| label.is_empty()) {
            return Err(NSError::InvalidDID(format!(
                "friendly DID name {value:?} contains an empty label"
            )));
        }

        let method = if labels.len() >= 3 { "web" } else { "bns" };
        parse_canonical_did(&format!("did:{method}:{value}"))
    }

    pub fn to_string(&self) -> String {
        format!("did:{}:{}", self.method, self.id)
    }

    pub fn to_raw_host_name(&self) -> String {
        let real_id = self.id.split(':').nth(0).unwrap();
        if self.method == "web" {
            return real_id.to_string();
        }
        format!("{}.{}.did", real_id, self.method)
    }

    pub fn to_host_name_by_bridge(&self, bridge_base_hostname: &str) -> String {
        let real_id = self.id.split(':').nth(0).unwrap();
        if self.method == "web" {
            return real_id.to_string();
        }
        return format!("{}.{}", real_id, bridge_base_hostname);
    }

    pub fn from_host_name_by_bridge(
        host_name: &str,
        method: &str,
        bridge_base_hostname: &str,
    ) -> Option<Self> {
        loop {
            if host_name.ends_with(bridge_base_hostname) {
                if host_name == bridge_base_hostname {
                    break;
                }
                let id = host_name[..host_name.len() - bridge_base_hostname.len() - 1].to_string();
                return Some(DID::new(method, &id));
            }
            break;
        }

        if host_name.ends_with(".did") {
            let parts: Vec<&str> = host_name.split('.').collect();
            if parts.len() == 3 {
                return Some(DID::new(parts[1].to_string().as_str(), parts[0]));
            }
        }

        return Some(DID::new("web", host_name.to_string().as_str()));
    }

    pub fn to_host_name(&self) -> String {
        let real_id = self.id.split(':').nth(0).unwrap();
        if self.method == "web" {
            return real_id.to_string();
        }

        let web3_bridge_config = KNOWN_WEB3_BRIDGE_CONFIG.get();
        if web3_bridge_config.is_some() {
            let web3_bridge_config = web3_bridge_config.unwrap();
            let bridge_base_hostname = web3_bridge_config.get(self.method.as_str());
            if bridge_base_hostname.is_some() {
                return format!("{}.{}", real_id, bridge_base_hostname.unwrap());
            }
        }
        //todo: find web3 bridge config
        format!("{}.{}.did", real_id, self.method)
    }

    /// Returns `host/path` for DIDs that carry a sub-path (e.g. did:web with extra segments),
    /// or just `host` when there is no path.
    ///
    /// Examples:
    ///   did:web:example.com              → "example.com"
    ///   did:web:example.com:user:alice   → "example.com/user/alice"
    ///   did:bns:waterflier               → "waterflier.web3.buckyos.io"
    pub fn to_host_uri(&self) -> String {
        let hostname = self.to_host_name();
        match self.get_path_from_id() {
            Some(path) => format!("{}/{}", hostname, path),
            None => hostname,
        }
    }

    pub fn to_raw_host_uri(&self) -> String {
        let raw_hostname = self.to_raw_host_name();
        match self.get_path_from_id() {
            Some(path) => format!("{}/{}", raw_hostname, path),
            None => raw_hostname,
        }
    }

    pub fn to_filename(&self) -> String {
        const HEX: &[u8; 16] = b"0123456789ABCDEF";

        let raw_host_uri = self.to_raw_host_uri();
        let mut filename = String::with_capacity(raw_host_uri.len());
        for byte in raw_host_uri.bytes() {
            match byte {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-' => {
                    filename.push(byte as char);
                }
                _ => {
                    filename.push('%');
                    filename.push(HEX[(byte >> 4) as usize] as char);
                    filename.push(HEX[(byte & 0x0f) as usize] as char);
                }
            }
        }
        filename
    }

    fn from_host_name(host_name: &str) -> Option<Self> {
        if host_name.ends_with(".did") {
            let parts: Vec<&str> = host_name.split('.').collect();
            if parts.len() == 3 {
                return Some(DID::new(parts[1].to_string().as_str(), parts[0]));
            }
        }

        let web3_bridge_config = KNOWN_WEB3_BRIDGE_CONFIG.get();
        if web3_bridge_config.is_some() {
            let web3_bridge_config = web3_bridge_config.unwrap();
            for (method, bridge_base_hostname) in web3_bridge_config.iter() {
                if host_name.ends_with(bridge_base_hostname) {
                    if host_name == bridge_base_hostname {
                        break;
                    }
                    let id =
                        host_name[..host_name.len() - bridge_base_hostname.len() - 1].to_string();
                    return Some(DID::new(method, &id));
                }
            }
        }

        return Some(DID::new("web", host_name.to_string().as_str()));
    }

    pub fn is_did(did: &str) -> bool {
        did.starts_with("did:")
    }
}

/// 名字类 DID(`did:web` / `did:bns`)的 child 派生共享规则:
/// `did:{method}:{child_label}.{zone_id}`。
///
/// 这是 provisioning / app runtime 在进入协议层之前使用的二级名字 helper，
/// 同时供 name resolution 与 identity path 复用。kRPC S2S 只接收这里已经
/// 形成的完整 DID，不参与 appid + zone DID 的拼装。
///
/// `child_label` 必须是合法的单级 DNS-safe label:
/// 仅 `[a-z0-9-]`、长度 1..=63、不以 `-` 开头/结尾、不含 `.`。
/// zone DID method 不支持 child 派生(非 web/bns)时直接报错,不猜测其他规则。
pub fn zone_child_did(zone_did: &DID, child_label: &str) -> NSResult<DID> {
    validate_zone_child_label(child_label)?;
    match zone_did.method.as_str() {
        "web" | "bns" => {
            // zone id 携带 path/端口段(`:` 分段)时,child 不继承这些段
            let zone_name = zone_did.id.split(':').next().unwrap_or_default();
            if zone_name.is_empty() {
                return Err(NSError::InvalidDID(format!(
                    "zone did {} has empty name part",
                    zone_did.to_string()
                )));
            }
            if zone_name.contains('%') {
                // %3A 编码端口:带端口的 zone 名字不参与 child 派生
                return Err(NSError::InvalidDID(format!(
                    "zone did {} carries an encoded port; cannot derive child did",
                    zone_did.to_string()
                )));
            }
            Ok(DID::new(
                &zone_did.method,
                &format!("{}.{}", child_label, zone_name),
            ))
        }
        other => Err(NSError::InvalidDID(format!(
            "zone did method {} does not support child derivation",
            other
        ))),
    }
}

/// `zone_child_did` 的 label 校验,独立导出便于调用方在配置阶段提前检查。
pub fn validate_zone_child_label(label: &str) -> NSResult<()> {
    if label.is_empty() || label.len() > 63 {
        return Err(NSError::InvalidParam(format!(
            "invalid zone child label {:?}: length must be 1..=63",
            label
        )));
    }
    if label.starts_with('-') || label.ends_with('-') {
        return Err(NSError::InvalidParam(format!(
            "invalid zone child label {:?}: must not start or end with '-'",
            label
        )));
    }
    if !label
        .bytes()
        .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'-'))
    {
        return Err(NSError::InvalidParam(format!(
            "invalid zone child label {:?}: only [a-z0-9-] allowed",
            label
        )));
    }
    Ok(())
}

/// 严格解析可用于 wire/config 边界的 canonical DID。
///
/// 当前 canonical 形式只接受可见 ASCII、`did:` 前缀、全小写字母数字 method
/// 和非空 id；fragment (`#kid`) 不是 DID 身份的一部分，必须由 document 内部
/// 的 verification method 语义处理，不能出现在此边界。
pub fn parse_canonical_did(value: &str) -> NSResult<DID> {
    if value.is_empty() || !value.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
        return Err(NSError::InvalidDID(
            "canonical DID must contain only visible ASCII".to_string(),
        ));
    }
    if value.contains('#') {
        return Err(NSError::InvalidDID(
            "DID fragments are not accepted at this identity boundary".to_string(),
        ));
    }
    let Some(rest) = value.strip_prefix("did:") else {
        return Err(NSError::InvalidDID(
            "canonical DID must start with 'did:'".to_string(),
        ));
    };
    let Some((method, id)) = rest.split_once(':') else {
        return Err(NSError::InvalidDID(
            "canonical DID must include method and id".to_string(),
        ));
    };
    if method.is_empty()
        || !method
            .bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9'))
    {
        return Err(NSError::InvalidDID(format!(
            "invalid canonical DID method {method:?}"
        )));
    }
    if id.is_empty() {
        return Err(NSError::InvalidDID(
            "canonical DID id cannot be empty".to_string(),
        ));
    }
    let mut index = 0;
    let bytes = id.as_bytes();
    while index < bytes.len() {
        match bytes[index] {
            b'a'..=b'z'
            | b'A'..=b'Z'
            | b'0'..=b'9'
            | b'.'
            | b'-'
            | b'_'
            | b':' => index += 1,
            b'%' if index + 2 < bytes.len()
                && bytes[index + 1].is_ascii_hexdigit()
                && bytes[index + 2].is_ascii_hexdigit() =>
            {
                index += 3;
            }
            _ => {
                return Err(NSError::InvalidDID(
                    "canonical DID id contains an invalid character or percent escape".to_string(),
                ));
            }
        }
    }
    if id.ends_with(':') {
        return Err(NSError::InvalidDID(
            "canonical DID id cannot end with ':'".to_string(),
        ));
    }
    let did = DID::new(method, id);
    if did.to_string() != value {
        return Err(NSError::InvalidDID(
            "DID is not in canonical form".to_string(),
        ));
    }
    Ok(did)
}

impl Serialize for DID {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for DID {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let result = Self::from_str(&s);
        if result.is_err() {
            return Err(serde::de::Error::custom(format!("invalid did: {}", s)));
        }
        Ok(result.unwrap())
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub enum EncodedDocument {
    JsonLd(Value),
    Jwt(String),
}

impl EncodedDocument {
    pub fn is_proof(&self) -> bool {
        match self {
            EncodedDocument::Jwt(_jwt) => true,
            _ => false,
        }
    }

    // pub fn get_prover_kid(&self) -> Option<String> {
    //     match self {
    //         EncodedDocument::Jwt(jwt) => {
    //             //return jwt header kid
    //             let header = decode_jwt_header_without_verify(jwt.as_str()).unwrap();
    //             header.kid
    //         }
    //         _ => None,
    //     }
    // }

    pub fn to_string(&self) -> String {
        match self {
            EncodedDocument::Jwt(jwt) => jwt.clone(),
            EncodedDocument::JsonLd(value) => serde_json::to_string(value).unwrap(),
        }
    }

    pub fn from_str(doc_str: String) -> NSResult<Self> {
        if doc_str.starts_with("{") || doc_str.starts_with("[") {
            let real_value = serde_json::from_str(&doc_str)
                .map_err(|e| NSError::DecodeJWTError(e.to_string()))?;
            return Ok(EncodedDocument::JsonLd(real_value));
        }
        return Ok(EncodedDocument::Jwt(doc_str));
    }

    pub fn to_json_value(self) -> NSResult<Value> {
        match self {
            EncodedDocument::Jwt(jwt_str) => {
                let claims = decode_jwt_claim_without_verify(jwt_str.as_str())
                    .map_err(|e| NSError::DecodeJWTError(e.to_string()))?;
                Ok(claims)
            }
            EncodedDocument::JsonLd(value) => Ok(value),
        }
    }
}

#[async_trait]
pub trait DIDDocumentTrait: Send + Sync {
    fn get_id(&self) -> DID;

    fn get_owner_did(&self) -> Option<DID>;

    fn get_doc_type(&self) -> DidDocType;

    //key id is none means the default key
    fn get_auth_key(&self, kid: Option<&str>) -> Option<(DecodingKey, Jwk)>;
    //TODO 该方法变成DeviceDocument的特殊方法
    //fn get_exchange_key(&self, kid: Option<&str>) -> Option<(DecodingKey, Jwk)>;

    fn get_key_ids_by_scope(&self, _scope: &str) -> Option<&[String]> {
        None
    }

    fn has_key_scope(&self) -> bool {
        false
    }

    fn get_standard_scope_key_ids(&self) -> Option<&[String]> {
        None
    }

    fn get_key_by_scope(&self, scope: &str) -> Option<(String, DecodingKey, Jwk)> {
        if let Some(key_ids) = self.get_key_ids_by_scope(scope) {
            return self.get_key_from_key_ids(key_ids);
        }
        if self.has_key_scope() {
            return None;
        }
        self.get_standard_scope_key_ids()
            .and_then(|key_ids| self.get_key_from_key_ids(key_ids))
            .or_else(|| {
                self.get_auth_key(None)
                    .map(|(decoding_key, jwk)| ("".to_string(), decoding_key, jwk))
            })
    }

    fn get_key_from_key_ids(&self, key_ids: &[String]) -> Option<(String, DecodingKey, Jwk)> {
        for key_id in key_ids {
            let local_key_id = self.normalize_key_id_for_local_lookup(key_id);
            if let Some((decoding_key, jwk)) = self.get_auth_key(Some(&local_key_id)) {
                return Some((key_id.clone(), decoding_key, jwk));
            }
        }
        None
    }

    fn is_key_allowed_in_scope(&self, scope: &str, key_id: &str) -> bool {
        if let Some(key_ids) = self.get_key_ids_by_scope(scope) {
            return key_ids
                .iter()
                .any(|allowed_key_id| self.is_same_document_key_id(allowed_key_id, key_id));
        }
        if self.has_key_scope() {
            return false;
        }
        self.get_standard_scope_key_ids()
            .map(|key_ids| {
                key_ids
                    .iter()
                    .any(|allowed_key_id| self.is_same_document_key_id(allowed_key_id, key_id))
            })
            .unwrap_or_else(|| {
                let local_key_id = self.normalize_key_id_for_local_lookup(key_id);
                self.get_auth_key(Some(&local_key_id)).is_some()
            })
    }

    fn normalize_key_id_for_local_lookup(&self, key_id: &str) -> String {
        let document_id = self.get_id().to_string();
        if let Some(local_key_id) = key_id.strip_prefix(&document_id) {
            if local_key_id.starts_with('#') {
                return local_key_id.to_string();
            }
        }
        key_id.to_string()
    }

    fn expand_local_key_id(&self, key_id: &str) -> String {
        if key_id.starts_with('#') {
            return format!("{}{}", self.get_id().to_string(), key_id);
        }
        key_id.to_string()
    }

    fn is_same_document_key_id(&self, left: &str, right: &str) -> bool {
        left == right
            || self.normalize_key_id_for_local_lookup(left)
                == self.normalize_key_id_for_local_lookup(right)
            || self.expand_local_key_id(left) == self.expand_local_key_id(right)
    }

    fn get_iss(&self) -> Option<String>;
    fn get_exp(&self) -> Option<u64>;
    fn get_iat(&self) -> Option<u64>;
    fn get_version_seq(&self) -> Option<u64>;

    fn encode(&self, key: Option<&EncodingKey>) -> NSResult<EncodedDocument>;
    fn decode(doc: &EncodedDocument, key: Option<&DecodingKey>) -> NSResult<Self>
    where
        Self: Sized;
    // async fn decode_with_load_key<'a, F, Fut>(doc: &'a EncodedDocument,loader:F) -> NSResult<Self>
    //     where Self: Sized,
    //           F: Fn(&'a str) -> Fut,
    //           Fut: std::future::Future<Output = NSResult<DecodingKey>>;

    //JSON-LD
    //fn to_json_value(&self) -> Value;
    //fn from_json_value(value: &Value) -> Self;
}

pub static KNOWN_WEB3_BRIDGE_CONFIG: OnceCell<HashMap<String, String>> = OnceCell::new();

/// JWT 形式 DID Document 的硬规则(doc/verify-did-api-boundary-and-freshness-TODO.md):
/// 必须能得出 revision `iat`——`iat` 直接存在,或可由 `exp - DEFAULT_EXPIRE_TIME`
/// 补充推导(`get_doc_iat` 语义)。两者皆无、无法得出 iat 的文档无效。
///
/// 旧的"JWT 必须带 version_seq"强制项已随 version_seq 整体退出流程:
/// `version_seq` 字段视作用户自定义扩展原样透传,不参与任何比较、guard 与强制项。
pub(crate) fn ensure_jwt_iat_derivable(
    doc_type: &str,
    iat: Option<u64>,
    exp: Option<u64>,
) -> NSResult<()> {
    if iat.is_none() && exp.is_none() {
        return Err(NSError::Failed(format!(
            "{} JWT carries neither iat nor exp; revision iat cannot be derived",
            doc_type
        )));
    }
    Ok(())
}

pub fn parse_did_doc(doc: EncodedDocument) -> NSResult<Box<dyn DIDDocumentTrait + Send + Sync>> {
    let is_jwt = matches!(&doc, EncodedDocument::Jwt(_));
    let doc_value = doc.to_json_value()?;
    debug!(
        "parse_did_doc: doc_value: {}",
        serde_json::to_string_pretty(&doc_value).unwrap()
    );

    if doc_value.get("verificationMethod").is_some()
        && doc_value.get("name").is_some()
        && (doc_value.get("display_name").is_some()
            || doc_value.get("displayName").is_some()
            || doc_value.get("full_name").is_some())
    {
        let owner_document = serde_json::from_value::<OwnerDocument>(doc_value)
            .map_err(|e| NSError::Failed(format!("parse owner document failed: {}", e)))?;
        if is_jwt {
            ensure_jwt_iat_derivable("OwnerDocument", owner_document.get_iat(), owner_document.get_exp())?;
        }
        return Ok(Box::new(owner_document));
    }
    if doc_value.get("httpServicePorts").is_some() {
        let agent_document = serde_json::from_value::<AgentDocument>(doc_value)
            .map_err(|e| NSError::Failed(format!("parse agent document failed: {}", e)))?;
        if is_jwt {
            ensure_jwt_iat_derivable("AgentDocument", agent_document.get_iat(), agent_document.get_exp())?;
        }
        return Ok(Box::new(agent_document));
    }
    if doc_value.get("device_type").is_some() {
        let device_document = serde_json::from_value::<DeviceDocument>(doc_value)
            .map_err(|e| NSError::Failed(format!("parse device document failed: {}", e)))?;
        if is_jwt {
            ensure_jwt_iat_derivable("DeviceDocument", device_document.get_iat(), device_document.get_exp())?;
        }
        return Ok(Box::new(device_document));
    }

    if doc_value.get("oods").is_some() {
        let zone_document = serde_json::from_value::<ZoneDocument>(doc_value)
            .map_err(|e| NSError::Failed(format!("parse zone document failed: {}", e)))?;
        if is_jwt {
            ensure_jwt_iat_derivable("ZoneDocument", zone_document.get_iat(), zone_document.get_exp())?;
        }
        return Ok(Box::new(zone_document));
    }

    if doc_value
        .get("service")
        .and_then(Value::as_array)
        .map(|services| {
            services.iter().any(|service| {
                service
                    .get("type")
                    .and_then(Value::as_str)
                    .map(|service_type| service_type == DID_OBJECT_SERVICE_TYPE)
                    .unwrap_or(false)
            })
        })
        .unwrap_or(false)
    {
        let did_object_card = serde_json::from_value::<DIDObjectCard>(doc_value)
            .map_err(|e| NSError::Failed(format!("parse DID Object Card failed: {}", e)))?;
        if is_jwt {
            ensure_jwt_iat_derivable("DIDObjectCard", did_object_card.get_iat(), did_object_card.get_exp())?;
        }
        return Ok(Box::new(did_object_card));
    }

    Err(NSError::Failed("unknown did document".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_upper_did() {
        let upper = |s: &str| DID::from_str(s).unwrap().upper_did();

        assert_eq!(
            upper("did:web:ood1.example.com"),
            Some(DID::new("web", "example.com"))
        );
        assert_eq!(
            upper("did:web:a.b.example.com"),
            Some(DID::new("web", "b.example.com"))
        );
        // 端口与路径不参与名字层级,也不被上级继承
        assert_eq!(
            upper("did:web:ood1.example.com%3A8080"),
            Some(DID::new("web", "example.com"))
        );
        assert_eq!(
            upper("did:web:ood1.example.com:devices:cam01"),
            Some(DID::new("web", "example.com"))
        );
        // 域名默认至少有一个点:上级只剩顶级域(com)时没有 upper
        assert_eq!(upper("did:web:example.com"), None);
        // IP 没有名字层级
        assert_eq!(upper("did:web:127.0.0.1"), None);
        assert_eq!(upper("did:web:127.0.0.1%3A3200"), None);
        // bns 的名字层级:一级名字是根
        assert_eq!(
            upper("did:bns:app1.alice"),
            Some(DID::new("bns", "alice"))
        );
        assert_eq!(upper("did:bns:alice"), None);
        // key 类 DID 没有名字层级
        assert_eq!(
            upper("did:dev:5bUuyWLOKyCre9az_IhJVIuOw8bA0gyKjstcYGHbaPE"),
            None
        );
    }

    #[test]
    fn test_did_from_str() {
        let did = DID::from_str("did:bns:waterflier").unwrap();
        assert_eq!(did.method, "bns");
        assert_eq!(did.id, "waterflier");

        let did = DID::from_str("did:bns:waterflier:sssn.did").unwrap();
        assert_eq!(did.method, "bns");
        assert_eq!(did.id, "waterflier:sssn.did");

        let mut web3_bridge_config = HashMap::new();
        web3_bridge_config.insert("bns".to_string(), "web3.buckyos.io".to_string());
        let _ = KNOWN_WEB3_BRIDGE_CONFIG.set(web3_bridge_config);

        let did = DID::from_str("web3.buckyos.io").unwrap();
        assert_eq!(did.method, "web");
        assert_eq!(did.id, "web3.buckyos.io");

        let did = DID::from_str("did:web:web3.buckyos.io:users:bob").unwrap();
        assert_eq!(did.method, "web");
        assert_eq!(did.id, "web3.buckyos.io:users:bob");
        let host_name = did.to_host_name();
        assert_eq!(host_name, "web3.buckyos.io");
        let path = did.get_path_from_id();
        assert_eq!(path, Some("users/bob".to_string()));
        let uri = did.to_host_uri();
        assert_eq!(uri, "web3.buckyos.io/users/bob");

        let did = DID::from_str("did:web:example.com:user:alice").unwrap();
        assert_eq!(did.to_host_name(), "example.com");
        assert_eq!(did.get_path_from_id(), Some("user/alice".to_string()));
        assert_eq!(did.to_host_uri(), "example.com/user/alice");

        let did = DID::from_str("did:web:example.com").unwrap();
        assert_eq!(did.to_host_uri(), "example.com");

        let did = DID::from_host_name("waterflier.web3.buckyos.io").unwrap();
        assert_eq!(did.method, "bns");
        assert_eq!(did.id, "waterflier");
        let host_name = did.to_host_name();
        assert_eq!(host_name, "waterflier.web3.buckyos.io");

        let did = DID::from_host_name("zhicong.me").unwrap();
        assert_eq!(did.method, "web");
        assert_eq!(did.id, "zhicong.me");

        let did = DID::from_str("buckyos.ai").unwrap();
        assert_eq!(did.method, "web");
        assert_eq!(did.id, "buckyos.ai");
        let host_name = did.to_host_name();
        assert_eq!(host_name, "buckyos.ai");
        let did_str = did.to_string();
        assert_eq!(did_str, "did:web:buckyos.ai");

        let did = DID::from_str("did:web:buckyos.ai").unwrap();
        let host_name = did.to_host_name();
        assert_eq!(host_name, "buckyos.ai");
        let did_str = did.to_string();
        assert_eq!(did_str, "did:web:buckyos.ai");

        let did = DID::from_str("abcdef.dev.did").unwrap();
        assert_eq!(did.method, "dev");
        assert_eq!(did.id, "abcdef");
        let did_str = did.to_string();
        assert_eq!(did_str, "did:dev:abcdef");

        let did = DID::from_str("did:bns:app1.waterflier").unwrap();
        assert_eq!(did.method, "bns");
        assert_eq!(did.id, "app1.waterflier");
        let did_str = did.to_string();
        assert_eq!(did_str, "did:bns:app1.waterflier");
        let host_name = did.to_host_name();
        assert_eq!(host_name, "app1.waterflier.web3.buckyos.io");

        let did = DID::from_host_name_by_bridge(
            "app1.waterflier.web3.buckyos.io",
            "bns",
            "web3.buckyos.io",
        )
        .unwrap();
        assert_eq!(did.method, "bns");
        assert_eq!(did.id, "app1.waterflier");
        let did_str = did.to_string();
        assert_eq!(did_str, "did:bns:app1.waterflier");
        let host_name = did.to_host_name_by_bridge("web3.buckyos.io");
        assert_eq!(host_name, "app1.waterflier.web3.buckyos.io");
        let did = DID::from_host_name_by_bridge("waterflier.buckyos.io", "bns", "web3.buckyos.io")
            .unwrap();
        assert_eq!(did.method, "web");
        assert_eq!(did.id, "waterflier.buckyos.io");
        let did_str = did.to_string();
        assert_eq!(did_str, "did:web:waterflier.buckyos.io");
        let host_name = did.to_host_name_by_bridge("web3.buckyos.io");
        assert_eq!(host_name, "waterflier.buckyos.io");
    }

    #[test]
    fn test_did_from_friendly_name() {
        assert_eq!(
            DID::from_friendly_name("app1.owner").unwrap(),
            DID::new("bns", "app1.owner")
        );
        assert_eq!(
            DID::from_friendly_name("app1.example.com").unwrap(),
            DID::new("web", "app1.example.com")
        );
        assert_eq!(
            DID::from_friendly_name(" did:web:app1.example.com ").unwrap(),
            DID::new("web", "app1.example.com")
        );

        assert!(DID::from_friendly_name("").is_err());
        assert!(DID::from_friendly_name("app1..example.com").is_err());
        assert!(DID::from_friendly_name("did:web:").is_err());
    }

    #[test]
    fn test_zone_child_did() {
        let zone = DID::new("web", "example.com");
        assert_eq!(
            zone_child_did(&zone, "event-service").unwrap(),
            DID::new("web", "event-service.example.com")
        );
        let zone = DID::new("bns", "alice");
        assert_eq!(
            zone_child_did(&zone, "app1").unwrap(),
            DID::new("bns", "app1.alice")
        );
        // path 段不被 child 继承
        let zone = DID::new("web", "example.com:user:alice");
        assert_eq!(
            zone_child_did(&zone, "svc").unwrap(),
            DID::new("web", "svc.example.com")
        );
        // 编码端口的 zone 不支持派生
        let zone = DID::new("web", "example.com%3A8080");
        assert!(zone_child_did(&zone, "svc").is_err());
        // method 不支持
        let zone = DID::new("dev", "5bUuyWLOKyCre9az_IhJVIuOw8bA0gyKjstcYGHbaPE");
        assert!(zone_child_did(&zone, "svc").is_err());
        // 非法 label
        let zone = DID::new("web", "example.com");
        assert!(zone_child_did(&zone, "").is_err());
        assert!(zone_child_did(&zone, "Upper").is_err());
        assert!(zone_child_did(&zone, "a.b").is_err());
        assert!(zone_child_did(&zone, "-bad").is_err());
        assert!(zone_child_did(&zone, "bad-").is_err());
        assert!(zone_child_did(&zone, &"a".repeat(64)).is_err());
        assert!(zone_child_did(&zone, &"a".repeat(63)).is_ok());
    }

    #[test]
    fn canonical_did_parser_rejects_fragments_and_noncanonical_values() {
        assert_eq!(
            parse_canonical_did("did:bns:event-service.alice").unwrap(),
            DID::new("bns", "event-service.alice")
        );
        assert_eq!(
            parse_canonical_did("did:web:event-service.example.com").unwrap(),
            DID::new("web", "event-service.example.com")
        );
        for bad in [
            "",
            "event-service.example.com",
            "did:WEB:event-service.example.com",
            "did:web:",
            "did:web:event-service.example.com#main_key",
            "did:web:event service.example.com",
            "did:web:event-service.example.com/path",
            "did:web:event-service.example.com%ZZ",
            "did:web:event-service.example.com:",
        ] {
            assert!(parse_canonical_did(bad).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn test_did_to_filename() {
        let did = DID::from_str("did:web:node1.example.com").unwrap();
        assert_eq!(did.to_raw_host_uri(), "node1.example.com");
        assert_eq!(did.to_filename(), "node1.example.com");

        let did = DID::from_str("did:web:example.com:user:alice").unwrap();
        assert_eq!(did.to_raw_host_uri(), "example.com/user/alice");
        assert_eq!(did.to_filename(), "example.com%2Fuser%2Falice");

        let did = DID::from_str("did:web:example.com%3A3000:user:alice").unwrap();
        assert_eq!(did.to_raw_host_uri(), "example.com%3A3000/user/alice");
        assert_eq!(did.to_filename(), "example.com%253A3000%2Fuser%2Falice");

        let did = DID::new("web", "example.com:user:\u{00E9}");
        assert_eq!(did.to_raw_host_uri(), "example.com/user/\u{00E9}");
        assert_eq!(did.to_filename(), "example.com%2Fuser%2F%C3%A9");

        let did = DID::from_str("did:bns:waterflier").unwrap();
        assert_eq!(did.to_raw_host_uri(), "waterflier.bns.did");
        assert_eq!(did.to_filename(), "waterflier.bns.did");
    }

    #[test]
    fn test_encoded_document_from_str_detects_format() {
        let json_doc = EncodedDocument::from_str("{\"a\":1}".to_string()).unwrap();
        assert!(matches!(json_doc, EncodedDocument::JsonLd(_)));

        let jwt_doc = EncodedDocument::from_str("header.payload.signature".to_string()).unwrap();
        assert!(matches!(jwt_doc, EncodedDocument::Jwt(_)));
    }

    #[test]
    fn test_parse_did_doc_routes_by_shape() {
        let owner_jwk: Jwk = serde_json::from_value(json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "T4Quc1L6Ogu4N2tTKOvneV1yYnBcmhP89B_RsuFsJZ8"
        }))
        .unwrap();

        let owner = OwnerDocument::new(
            DID::new("bns", "alice"),
            "alice".to_string(),
            "alice@bns".to_string(),
            owner_jwk.clone(),
        );
        let owner_doc = EncodedDocument::JsonLd(serde_json::to_value(&owner).unwrap());
        let owner_parsed = parse_did_doc(owner_doc).unwrap();
        assert_eq!(owner_parsed.get_id(), owner.id);

        let mut agent = AgentDocument::new(
            DID::new("bns", "agent.alice"),
            DID::new("bns", "alice"),
            owner_jwk.clone(),
        );
        agent.support_public_access = true;
        agent.set_send_msg_port(8081);
        let agent_doc = EncodedDocument::JsonLd(serde_json::to_value(&agent).unwrap());
        let agent_parsed = parse_did_doc(agent_doc).unwrap();
        assert_eq!(agent_parsed.get_id(), agent.id);

        let device = DeviceDocument::new(
            "ood1",
            "5bUuyWLOKyCre9az_IhJVIuOw8bA0gyKjstcYGHbaPE".to_string(),
        );
        let device_doc = EncodedDocument::JsonLd(serde_json::to_value(&device).unwrap());
        let device_parsed = parse_did_doc(device_doc).unwrap();
        assert_eq!(device_parsed.get_id(), device.id);

        let mut zone = ZoneDocument::new(
            DID::new("bns", "zone1"),
            DID::new("bns", "alice"),
            owner_jwk,
        );
        zone.oods = vec!["ood1".parse().unwrap()];
        let zone_doc = EncodedDocument::JsonLd(serde_json::to_value(&zone).unwrap());
        let zone_parsed = parse_did_doc(zone_doc).unwrap();
        assert_eq!(zone_parsed.get_id(), zone.id);
    }
}
