//! 版本模型(设计稿 §1):`Revision` 是**查询条件**,`DocRevision` 是**文档身份**
//! `(iat, content_hash)`,两者不能混用。版本只按 `iat` 比较;同 iat 同 hash 幂等,
//! 同 iat 不同 hash 才在通过验证后判冲突。

use name_lib::{parse_did_doc, DidDocType, EncodedDocument, NSError, NSResult, DID};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// 单份 DID Document 的输入上限(JWT compact 原文或 JSON 序列化后的字节数)。
/// 同步解析受此上限约束,不能只依赖异步超时(设计稿 §4)。
pub const MAX_DOCUMENT_BYTES: usize = 2 * 1024 * 1024;

/// 查询条件。`None` 等价于 `Current`。
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Revision {
    /// 普通文档同时获取 latest 与 best(默认选 best);owner 只取 latest。
    Current,
    /// 指定的已发布版本:精确匹配 iat/hash,且有该查询的发布依据。
    Exact { iat: u64, hash: String },
    /// 已发布版本中最大的 `document.iat < before_iat`。
    Closest { before_iat: u64 },
}

impl Default for Revision {
    fn default() -> Self {
        Self::Current
    }
}

impl Revision {
    pub fn current() -> Self {
        Self::Current
    }

    /// `hash` 允许 `sha256:` 前缀与大写,归一后保存。
    pub fn exact(iat: u64, hash: impl AsRef<str>) -> Self {
        Self::Exact {
            iat,
            hash: normalize_hash(hash.as_ref()),
        }
    }

    pub fn closest(before_iat: u64) -> Self {
        Self::Closest { before_iat }
    }

    pub fn is_current(&self) -> bool {
        matches!(self, Self::Current)
    }

    /// 查询的时间参数:exact 是指定 iat,closest 是边界 iat。
    pub fn query_iat(&self) -> Option<u64> {
        match self {
            Self::Current => None,
            Self::Exact { iat, .. } => Some(*iat),
            Self::Closest { before_iat } => Some(*before_iat),
        }
    }

    /// 按完整查询分槽的缓存键;exact/closest 不能串用。
    pub fn cache_key(&self) -> String {
        match self {
            Self::Current => "current".to_string(),
            Self::Exact { iat, hash } => format!("exact:{}:{}", iat, hash),
            Self::Closest { before_iat } => format!("closest:{}", before_iat),
        }
    }

    /// `Revision::exact` 要求同时给出 iat 与 hash,空 hash 视为非法查询。
    pub fn validate(&self) -> NSResult<()> {
        if let Self::Exact { hash, .. } = self {
            if hash.is_empty() {
                return Err(NSError::InvalidParam(
                    "Revision::exact requires both iat and content hash".to_string(),
                ));
            }
        }
        Ok(())
    }
}

impl std::fmt::Display for Revision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.cache_key())
    }
}

/// 文档身份 `(iat, content_hash)`。hash 规则沿用 [`document_content_hash`]:
/// JWT 对 compact 原文取 sha256,JSON 对规范化序列化结果取 sha256。
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DocRevision {
    pub iat: u64,
    pub hash: String,
}

impl DocRevision {
    pub fn new(iat: u64, hash: impl AsRef<str>) -> Self {
        Self {
            iat,
            hash: normalize_hash(hash.as_ref()),
        }
    }

    /// 计算文档的 revision;iat 无法得出时返回 None(文档无效)。
    pub fn of(doc: &EncodedDocument) -> Option<Self> {
        Some(Self {
            iat: document_iat(doc)?,
            hash: document_content_hash(doc),
        })
    }

    pub fn matches_hash(&self, expected: &str) -> bool {
        self.hash == normalize_hash(expected)
    }

    pub fn matches_exact(&self, revision: &Revision) -> bool {
        match revision {
            Revision::Exact { iat, hash } => self.iat == *iat && self.hash == *hash,
            _ => false,
        }
    }
}

impl std::fmt::Display for DocRevision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}@{}", self.iat, &self.hash[..self.hash.len().min(12)])
    }
}

/// 去掉 `sha256:` 前缀并小写化。
pub fn normalize_hash(value: &str) -> String {
    value
        .trim()
        .strip_prefix("sha256:")
        .or_else(|| value.trim().strip_prefix("SHA256:"))
        .unwrap_or(value.trim())
        .to_ascii_lowercase()
}

/// 计算文档 body 的内容哈希(权威源锚定 `docHash` 时用来做成员判断)。
///
/// 编码契约:
/// - JWT:对 compact artifact **原文**做 sha256;
/// - JsonLd:对 `serde_json::Value` 重序列化结果做 sha256。workspace 不启用
///   serde_json 的 `preserve_order`,`Value` 的 map 是 BTreeMap,序列化天然是
///   "键字典序 + 紧凑分隔符",已消除键序/空白差异(有防护测试锁定该前提);
///   不引入 JCS(RFC 8785)/URDNA2015。
pub fn document_content_hash(doc: &EncodedDocument) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(doc.to_string().as_bytes());
    format!("{:x}", hasher.finalize())
}

/// 文档的 revision `iat`:`iat` 直接存在,或由 `exp - DEFAULT_EXPIRE_TIME`
/// 补充推导。两者皆无、无法得出 iat 的文档没有 revision。
pub fn document_iat(doc: &EncodedDocument) -> Option<u64> {
    let value = doc.clone().to_json_value().ok()?;
    if let Some(iat) = value.get("iat").and_then(|ts| ts.as_u64()) {
        return Some(iat);
    }
    value
        .get("exp")
        .and_then(|ts| ts.as_u64())
        .map(|exp| exp.saturating_sub(name_lib::DEFAULT_EXPIRE_TIME))
}

/// 权威源锚定的 hash 与 body 是否匹配。允许 `sha256:` 前缀,大小写不敏感。
pub fn content_hash_matches(expected: &str, doc: &EncodedDocument) -> bool {
    document_content_hash(doc) == normalize_hash(expected)
}

/// key 类 DID(did:key / did:dev)不是 `resolve_did` 的合法入参:解析的目的是
/// "通过逻辑名字得到当前可信的公钥",而 key 类 DID 的名字就是公钥本身。
pub fn is_key_class_method(method: &str) -> bool {
    matches!(method, "key" | "dev")
}

/// 名字结构推导出的默认 owner:`did:bns:app1.alice` 的 expected_owner 就是
/// `did:bns:alice`(名字层级上的上级名字)。一级名字是根,推不出 owner;
/// 其它 method 有名字层级但不定义结构 owner。
pub fn structural_owner(did: &DID) -> Option<DID> {
    match did.method.as_str() {
        "bns" => {
            if did.id.contains(':') {
                // 路径型 DID Object:controller/Owner 链须先形成可信绑定,
                // 不把截掉对象路径当成信任证明(设计稿 §6)。
                return None;
            }
            did.upper_did()
        }
        _ => None,
    }
}

/// 解析后(未信任)的文档视图:只提取身份、类型、owner 与时间字段,
/// 提取不等于信任。
#[derive(Clone, Debug)]
pub struct ParsedDocument {
    pub document: EncodedDocument,
    pub claims: Value,
    pub id: Option<DID>,
    pub doc_type: Option<DidDocType>,
    pub owner: Option<DID>,
    pub iat: Option<u64>,
    pub exp: Option<u64>,
    pub revision: Option<DocRevision>,
    /// name-lib 能把它识别成已知文档形态(owner/zone/device/...)。
    pub recognized: bool,
}

impl ParsedDocument {
    /// 标准 JSON/JWT 解析;受输入上限约束。JWT 只解 claims,不验签。
    pub fn parse(document: &EncodedDocument) -> NSResult<Self> {
        let raw_len = match document {
            EncodedDocument::Jwt(jwt) => jwt.len(),
            EncodedDocument::JsonLd(value) => value.to_string().len(),
        };
        if raw_len > MAX_DOCUMENT_BYTES {
            return Err(NSError::InvalidParam(format!(
                "document exceeds {} bytes",
                MAX_DOCUMENT_BYTES
            )));
        }
        if let EncodedDocument::Jwt(jwt) = document {
            validate_compact_jwt(jwt)?;
        }
        let claims = document.clone().to_json_value()?;
        if !claims.is_object() {
            return Err(NSError::InvalidParam(
                "document body is not a JSON object".to_string(),
            ));
        }

        let mut parsed = Self {
            document: document.clone(),
            id: claims
                .get("id")
                .and_then(|v| v.as_str())
                .and_then(|s| DID::from_str(s).ok()),
            doc_type: None,
            owner: None,
            iat: claims.get("iat").and_then(|v| v.as_u64()),
            exp: claims.get("exp").and_then(|v| v.as_u64()),
            revision: None,
            recognized: false,
            claims: Value::Null,
        };
        if parsed.iat.is_none() {
            parsed.iat = parsed
                .exp
                .map(|exp| exp.saturating_sub(name_lib::DEFAULT_EXPIRE_TIME));
        }
        parsed.revision = parsed.iat.map(|iat| DocRevision {
            iat,
            hash: document_content_hash(document),
        });

        // owner:JWT 的 iss 优先,其次文档自报的 owner 字段;两者都只是自报。
        parsed.owner = claims
            .get("iss")
            .and_then(|v| v.as_str())
            .or_else(|| claims.get("owner").and_then(|v| v.as_str()))
            .and_then(|s| DID::from_str(s).ok());

        if let Ok(known) = parse_did_doc(document.clone()) {
            parsed.recognized = true;
            parsed.doc_type = Some(known.get_doc_type());
            if parsed.id.is_none() {
                parsed.id = Some(known.get_id());
            }
            if parsed.owner.is_none() {
                parsed.owner = known
                    .get_iss()
                    .and_then(|iss| DID::from_str(&iss).ok())
                    .or_else(|| known.get_owner_did());
            }
        }
        parsed.claims = claims;
        Ok(parsed)
    }

    pub fn is_jwt(&self) -> bool {
        matches!(self.document, EncodedDocument::Jwt(_))
    }

    /// 身份与类型检查。文档自报 id 时必须与请求一致;name-lib 识别出的文档
    /// 类型与请求类型都是内置类型时必须一致;iat 必须可得出。
    pub fn matches(&self, did: &DID, doc_type: &DidDocType) -> Result<(), String> {
        if let Some(id) = &self.id {
            if id != did {
                return Err(format!(
                    "document id {} does not match requested {}",
                    id.to_string(),
                    did.to_string()
                ));
            }
        }
        if let Some(actual) = &self.doc_type {
            // 只有两边都是强形态(owner / zone / device / boot / user)且不同才算类型
            // 不符;`did-object` / custom 是泛化形态,由注册方 / 调用方决定其类型。
            let strong = |t: &DidDocType| {
                matches!(
                    t,
                    DidDocType::Owner
                        | DidDocType::Zone
                        | DidDocType::Device
                        | DidDocType::Boot
                        | DidDocType::User
                )
            };
            if strong(actual) && strong(doc_type) && actual != doc_type {
                return Err(format!(
                    "document body is a {} document, requested {}",
                    actual, doc_type
                ));
            }
        }
        if self.iat.is_none() {
            return Err("document carries neither iat nor exp".to_string());
        }
        Ok(())
    }

    pub fn revision(&self) -> Option<&DocRevision> {
        self.revision.as_ref()
    }
}

/// compact JWT 的形状检查:三段、非空、base64url 字符集。
pub fn validate_compact_jwt(jwt: &str) -> NSResult<()> {
    let segments: Vec<&str> = jwt.split('.').collect();
    if segments.len() != 3 || segments.iter().any(|s| s.is_empty()) {
        return Err(NSError::DecodeJWTError(
            "JWT must have three non-empty segments".to_string(),
        ));
    }
    if !jwt
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'='))
    {
        return Err(NSError::DecodeJWTError(
            "JWT contains characters outside base64url".to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn revision_cache_keys_are_distinct_per_query() {
        assert_eq!(Revision::current().cache_key(), "current");
        assert_eq!(Revision::exact(5, "SHA256:ABC").cache_key(), "exact:5:abc");
        assert_eq!(Revision::closest(9).cache_key(), "closest:9");
        assert!(Revision::exact(1, "").validate().is_err());
    }

    #[test]
    fn content_hash_matches_accepts_prefix_and_case() {
        let doc = EncodedDocument::JsonLd(json!({"marker": "hash-me"}));
        let hash = document_content_hash(&doc);
        assert!(content_hash_matches(&hash, &doc));
        assert!(content_hash_matches(&format!("sha256:{}", hash), &doc));
        assert!(content_hash_matches(&hash.to_uppercase(), &doc));
        assert!(!content_hash_matches("deadbeef", &doc));
    }

    /// content hash 编码契约的防护测试:workspace 不得开启 serde_json 的
    /// `preserve_order`——`Value` 的 map 必须是 BTreeMap,序列化天然是
    /// "键字典序 + 紧凑分隔符",这是 JsonLd content hash 跨进程稳定的前提。
    #[test]
    fn json_value_serialization_is_key_sorted_and_compact() {
        let value: serde_json::Value =
            serde_json::from_str(r#"{ "zebra": 1, "alpha": {"z": 1, "a": 2}, "mid": [1, 2] }"#)
                .unwrap();
        assert_eq!(
            serde_json::to_string(&value).unwrap(),
            r#"{"alpha":{"a":2,"z":1},"mid":[1,2],"zebra":1}"#
        );
        let reordered: serde_json::Value =
            serde_json::from_str(r#"{"mid":[1,2],  "alpha":{"a":2,"z":1},"zebra":1}"#).unwrap();
        assert_eq!(
            document_content_hash(&EncodedDocument::JsonLd(value)),
            document_content_hash(&EncodedDocument::JsonLd(reordered))
        );
    }

    #[test]
    fn document_iat_derives_from_exp_when_missing() {
        let with_iat = EncodedDocument::JsonLd(json!({"iat": 100, "exp": 999_999}));
        assert_eq!(document_iat(&with_iat), Some(100));
        let exp_only = EncodedDocument::JsonLd(json!({"exp": name_lib::DEFAULT_EXPIRE_TIME + 7}));
        assert_eq!(document_iat(&exp_only), Some(7));
        let neither = EncodedDocument::JsonLd(json!({"marker": "no-time"}));
        assert_eq!(document_iat(&neither), None);
    }

    #[test]
    fn structural_owner_derivation() {
        assert_eq!(
            structural_owner(&DID::new("bns", "app1.alice")),
            Some(DID::new("bns", "alice"))
        );
        assert_eq!(structural_owner(&DID::new("bns", "alice")), None);
        assert_eq!(structural_owner(&DID::new("bns", "alice:obj:a")), None);
        assert_eq!(structural_owner(&DID::new("web", "www.example.com")), None);
    }

    #[test]
    fn parsed_document_checks_identity_and_iat() {
        let did = DID::new("web", "example.com");
        let doc = EncodedDocument::JsonLd(json!({"id": "did:web:example.com", "iat": 10, "exp": 20}));
        let parsed = ParsedDocument::parse(&doc).unwrap();
        assert!(parsed.matches(&did, &DidDocType::Zone).is_ok());
        assert!(parsed
            .matches(&DID::new("web", "other.com"), &DidDocType::Zone)
            .is_err());
        let no_time = EncodedDocument::JsonLd(json!({"id": "did:web:example.com"}));
        let parsed = ParsedDocument::parse(&no_time).unwrap();
        assert!(parsed.matches(&did, &DidDocType::Zone).is_err());
        assert!(is_key_class_method("dev") && !is_key_class_method("bns"));
    }
}
