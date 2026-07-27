//! `ServiceKeyRef := canonical_service_did [ "#" key_id ]`(§6.2 冻结)。
//!
//! - canonical service DID 必须以 `did:` 开头,method 只允许 `[a-z0-9]+`,
//!   id 非空且只含可见 ASCII(不含 `#`、空白、控制字符);
//! - 解析后 `DID::from_str(..).to_string()` 必须逐字节等于输入(canonical form);
//! - key id 只允许 `[A-Za-z0-9._-]{1,64}`;
//! - 省略 `#key_id` 表示该 service DID 的默认 active key。

use super::error::{S2sError, S2sResult};
use super::{S2S_MAX_KEY_ID_LEN, S2S_MAX_KEY_REF_LEN};
use name_lib::DID;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ServiceKeyRef {
    pub did: DID,
    pub key_id: Option<String>,
}

impl ServiceKeyRef {
    pub fn new(did: DID) -> Self {
        ServiceKeyRef { did, key_id: None }
    }

    pub fn with_key_id(did: DID, key_id: impl Into<String>) -> S2sResult<Self> {
        let key_id = key_id.into();
        validate_key_id(&key_id)?;
        Ok(ServiceKeyRef {
            did,
            key_id: Some(key_id),
        })
    }

    /// 严格解析 wire 形式并校验 canonical form。
    pub fn parse(s: &str) -> S2sResult<Self> {
        if s.is_empty() || s.len() > S2S_MAX_KEY_REF_LEN {
            return Err(S2sError::InvalidServiceKeyRef(format!(
                "length must be 1..={}",
                S2S_MAX_KEY_REF_LEN
            )));
        }
        // 只允许可见 ASCII(0x21..=0x7e):控制字符、空白、非 ASCII 一律拒绝
        if !s.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
            return Err(S2sError::InvalidServiceKeyRef(
                "only visible ascii allowed".to_string(),
            ));
        }
        let (did_part, key_id) = match s.split_once('#') {
            Some((did_part, key_part)) => {
                if key_part.contains('#') {
                    return Err(S2sError::InvalidServiceKeyRef(
                        "more than one '#'".to_string(),
                    ));
                }
                validate_key_id(key_part)?;
                (did_part, Some(key_part.to_string()))
            }
            None => (s, None),
        };

        let did = parse_canonical_service_did(did_part)?;
        Ok(ServiceKeyRef { did, key_id })
    }

    /// canonical wire 形式(Header 与 AAD 逐字节使用该形式)。
    pub fn to_wire_string(&self) -> String {
        match &self.key_id {
            Some(kid) => format!("{}#{}", self.did.to_string(), kid),
            None => self.did.to_string(),
        }
    }
}

impl std::fmt::Display for ServiceKeyRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_wire_string())
    }
}

/// 解析并校验 canonical service DID(wire 形式必须与 `DID::to_string()` 逐字节一致)。
pub fn parse_canonical_service_did(s: &str) -> S2sResult<DID> {
    if !s.starts_with("did:") {
        return Err(S2sError::InvalidServiceKeyRef(
            "service did must start with 'did:'".to_string(),
        ));
    }
    let did = DID::from_str(s)
        .map_err(|e| S2sError::InvalidServiceKeyRef(format!("invalid did: {}", e)))?;
    if did.method.is_empty()
        || !did
            .method
            .bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9'))
    {
        return Err(S2sError::InvalidServiceKeyRef(format!(
            "invalid did method: {}",
            did.method
        )));
    }
    if did.id.is_empty() {
        return Err(S2sError::InvalidServiceKeyRef("empty did id".to_string()));
    }
    if did.to_string() != s {
        return Err(S2sError::InvalidServiceKeyRef(
            "did is not in canonical form".to_string(),
        ));
    }
    Ok(did)
}

fn validate_key_id(key_id: &str) -> S2sResult<()> {
    if key_id.is_empty() || key_id.len() > S2S_MAX_KEY_ID_LEN {
        return Err(S2sError::InvalidServiceKeyRef(format!(
            "key id length must be 1..={}",
            S2S_MAX_KEY_ID_LEN
        )));
    }
    if !key_id
        .bytes()
        .all(|b| matches!(b, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'.' | b'_' | b'-'))
    {
        return Err(S2sError::InvalidServiceKeyRef(
            "key id allows only [A-Za-z0-9._-]".to_string(),
        ));
    }
    Ok(())
}

/// `local_service_appid + current_zone_did -> canonical service DID`(§6.1)。
///
/// 通过 name-lib 共享 `zone_child_did` 派生;appid 必须是合法单级 service
/// label,Zone DID method 不支持 child derivation 时直接失败,不猜测其他规则。
pub fn derive_service_did(local_service_appid: &str, current_zone_did: &DID) -> S2sResult<DID> {
    name_lib::zone_child_did(current_zone_did, local_service_appid).map_err(|e| {
        S2sError::InvalidConfig(format!(
            "cannot derive service did from appid {:?} + zone {}: {}",
            local_service_appid,
            current_zone_did.to_string(),
            e
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_wire_roundtrip() {
        let r = ServiceKeyRef::parse("did:web:event-service.example.com").unwrap();
        assert_eq!(r.did, DID::new("web", "event-service.example.com"));
        assert_eq!(r.key_id, None);
        assert_eq!(r.to_wire_string(), "did:web:event-service.example.com");

        let r = ServiceKeyRef::parse("did:web:event-service.example.com#key-42").unwrap();
        assert_eq!(r.key_id.as_deref(), Some("key-42"));
        assert_eq!(
            r.to_wire_string(),
            "did:web:event-service.example.com#key-42"
        );

        let r = ServiceKeyRef::parse("did:bns:app1.alice").unwrap();
        assert_eq!(r.did, DID::new("bns", "app1.alice"));
    }

    #[test]
    fn parse_rejects_bad_refs() {
        // 非 did
        assert!(ServiceKeyRef::parse("example.com").is_err());
        // 空
        assert!(ServiceKeyRef::parse("").is_err());
        // 空 key id / 双 #
        assert!(ServiceKeyRef::parse("did:web:x.com#").is_err());
        assert!(ServiceKeyRef::parse("did:web:x.com#a#b").is_err());
        // 控制字符/空白
        assert!(ServiceKeyRef::parse("did:web:x.com \t").is_err());
        assert!(ServiceKeyRef::parse("did:web:x\u{0}.com").is_err());
        // method 大写
        assert!(ServiceKeyRef::parse("did:WEB:x.com").is_err());
        // key id 非法字符
        assert!(ServiceKeyRef::parse("did:web:x.com#k$1").is_err());
        // 超长
        let long = format!("did:web:{}.com", "a".repeat(600));
        assert!(ServiceKeyRef::parse(&long).is_err());
    }

    #[test]
    fn derive_service_did_rules() {
        let zone = DID::new("web", "example.com");
        assert_eq!(
            derive_service_did("event-service", &zone).unwrap(),
            DID::new("web", "event-service.example.com")
        );
        let zone = DID::new("bns", "alice");
        assert_eq!(
            derive_service_did("event-service", &zone).unwrap(),
            DID::new("bns", "event-service.alice")
        );
        // 非法 appid
        assert!(derive_service_did("Bad", &zone).is_err());
        assert!(derive_service_did("a.b", &zone).is_err());
        assert!(derive_service_did("", &zone).is_err());
        // 不支持的 zone method
        let zone = DID::new("dev", "xxxx");
        assert!(derive_service_did("svc", &zone).is_err());
    }
}
