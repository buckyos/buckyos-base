//! S2S Header DTO 与严格解析(§8.2/§8.3/§8.5)。
//!
//! HTTP Header name 大小写不敏感,但 AAD 不使用原始 Header bytes:parser 先
//! 得到结构化值再按协议规范化。同名 S2S Header 出现多次直接拒绝;前后 OWS
//! 移除;内部空白与控制字符拒绝;未识别的 `krpc-s2s-*` Header 默认拒绝。

use super::codec::{decode_nonce, encode_nonce};
use super::error::{S2sError, S2sResult};
use super::service_key_ref::ServiceKeyRef;
use super::{
    HEADER_S2S_EXPIRES_AT, HEADER_S2S_FROM, HEADER_S2S_IN_REPLY_TO, HEADER_S2S_ISSUED_AT,
    HEADER_S2S_NONCE, HEADER_S2S_PREFIX, HEADER_S2S_TO, HEADER_S2S_VERSION,
    S2S_DEFAULT_MAX_HEADER_VALUE_LEN, S2S_NONCE_LEN, S2S_PROFILE_VERSION,
};
use http::HeaderMap;

/// request 侧结构化 S2S Header。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct S2sRequestHeaders {
    pub version: u32,
    pub from: ServiceKeyRef,
    pub to: ServiceKeyRef,
    pub issued_at: u64,
    pub expires_at: u64,
    pub nonce: [u8; S2S_NONCE_LEN],
}

/// response 侧结构化 S2S Header。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct S2sResponseHeaders {
    pub version: u32,
    pub from: ServiceKeyRef,
    pub to: ServiceKeyRef,
    pub issued_at: u64,
    pub expires_at: u64,
    pub in_reply_to: [u8; S2S_NONCE_LEN],
    pub nonce: [u8; S2S_NONCE_LEN],
}

const REQUEST_ALLOWED: [&str; 6] = [
    HEADER_S2S_VERSION,
    HEADER_S2S_FROM,
    HEADER_S2S_TO,
    HEADER_S2S_ISSUED_AT,
    HEADER_S2S_EXPIRES_AT,
    HEADER_S2S_NONCE,
];

const RESPONSE_ALLOWED: [&str; 7] = [
    HEADER_S2S_VERSION,
    HEADER_S2S_FROM,
    HEADER_S2S_TO,
    HEADER_S2S_ISSUED_AT,
    HEADER_S2S_EXPIRES_AT,
    HEADER_S2S_NONCE,
    HEADER_S2S_IN_REPLY_TO,
];

fn invalid(name: &str, reason: impl Into<String>) -> S2sError {
    S2sError::InvalidHeader {
        name: name.to_string(),
        reason: reason.into(),
    }
}

/// 取唯一 Header 值:重复、缺失、超长、非可见 ASCII、内部空白一律拒绝。
fn get_single(headers: &HeaderMap, name: &str, max_len: usize) -> S2sResult<String> {
    let mut iter = headers.get_all(name).iter();
    let Some(first) = iter.next() else {
        return Err(invalid(name, "missing"));
    };
    if iter.next().is_some() {
        return Err(invalid(name, "duplicated header"));
    }
    let raw = first
        .to_str()
        .map_err(|_| invalid(name, "non-ascii header value"))?;
    // 按 HTTP 规则移除前后 OWS(space / htab)
    let trimmed = raw.trim_matches(|c| c == ' ' || c == '\t');
    if trimmed.is_empty() {
        return Err(invalid(name, "empty"));
    }
    if trimmed.len() > max_len {
        return Err(invalid(name, format!("value longer than {}", max_len)));
    }
    // 内部空白与控制字符拒绝(S2S 字段全部是 token 型)
    if !trimmed.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
        return Err(invalid(name, "control char or whitespace inside value"));
    }
    Ok(trimmed.to_string())
}

/// 拒绝未识别的 `krpc-s2s-*` Header(避免实现间安全语义漂移)。
fn reject_unknown_s2s_headers(headers: &HeaderMap, allowed: &[&str]) -> S2sResult<()> {
    for name in headers.keys() {
        let lower = name.as_str(); // http crate 存储即小写
        if lower.starts_with(HEADER_S2S_PREFIX) && !allowed.contains(&lower) {
            return Err(invalid(lower, "unrecognized krpc-s2s-* header"));
        }
    }
    Ok(())
}

fn parse_version(headers: &HeaderMap) -> S2sResult<u32> {
    let value = get_single(headers, HEADER_S2S_VERSION, 10)?;
    let version: u32 = parse_decimal_u64(HEADER_S2S_VERSION, &value)?
        .try_into()
        .map_err(|_| invalid(HEADER_S2S_VERSION, "version out of range"))?;
    if version != S2S_PROFILE_VERSION {
        return Err(S2sError::UnknownVersion(value));
    }
    Ok(version)
}

/// 严格十进制无符号整数:只允许 ASCII digits,无符号、无前导 0(除单个 "0")。
fn parse_decimal_u64(name: &str, s: &str) -> S2sResult<u64> {
    if s.is_empty() || s.len() > 20 {
        return Err(invalid(name, "bad integer length"));
    }
    if !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(invalid(name, "not a decimal integer"));
    }
    if s.len() > 1 && s.starts_with('0') {
        return Err(invalid(name, "leading zero"));
    }
    s.parse::<u64>().map_err(|_| invalid(name, "integer overflow"))
}

fn parse_key_ref(headers: &HeaderMap, name: &str, max_len: usize) -> S2sResult<ServiceKeyRef> {
    let value = get_single(headers, name, max_len)?;
    ServiceKeyRef::parse(&value)
        .map_err(|e| invalid(name, format!("{}", e)))
}

fn parse_nonce_header(headers: &HeaderMap, name: &str) -> S2sResult<[u8; S2S_NONCE_LEN]> {
    let value = get_single(headers, name, 64)?;
    decode_nonce(&value).map_err(|e| invalid(name, format!("{}", e)))
}

impl S2sRequestHeaders {
    /// 从 HTTP HeaderMap 严格解析(不含时间窗校验——那是 policy 的事)。
    pub fn parse(headers: &HeaderMap) -> S2sResult<Self> {
        reject_unknown_s2s_headers(headers, &REQUEST_ALLOWED)?;
        let version = parse_version(headers)?;
        let from = parse_key_ref(headers, HEADER_S2S_FROM, S2S_DEFAULT_MAX_HEADER_VALUE_LEN)?;
        let to = parse_key_ref(headers, HEADER_S2S_TO, S2S_DEFAULT_MAX_HEADER_VALUE_LEN)?;
        let issued_at =
            parse_decimal_u64(HEADER_S2S_ISSUED_AT, &get_single(headers, HEADER_S2S_ISSUED_AT, 20)?)?;
        let expires_at = parse_decimal_u64(
            HEADER_S2S_EXPIRES_AT,
            &get_single(headers, HEADER_S2S_EXPIRES_AT, 20)?,
        )?;
        let nonce = parse_nonce_header(headers, HEADER_S2S_NONCE)?;
        Ok(S2sRequestHeaders {
            version,
            from,
            to,
            issued_at,
            expires_at,
            nonce,
        })
    }

    /// 写入 HTTP HeaderMap(客户端发送用)。
    pub fn apply(&self, headers: &mut HeaderMap) -> S2sResult<()> {
        put_header(headers, HEADER_S2S_VERSION, &self.version.to_string())?;
        put_header(headers, HEADER_S2S_FROM, &self.from.to_wire_string())?;
        put_header(headers, HEADER_S2S_TO, &self.to.to_wire_string())?;
        put_header(headers, HEADER_S2S_ISSUED_AT, &self.issued_at.to_string())?;
        put_header(headers, HEADER_S2S_EXPIRES_AT, &self.expires_at.to_string())?;
        put_header(headers, HEADER_S2S_NONCE, &encode_nonce(&self.nonce))?;
        Ok(())
    }
}

impl S2sResponseHeaders {
    pub fn parse(headers: &HeaderMap) -> S2sResult<Self> {
        reject_unknown_s2s_headers(headers, &RESPONSE_ALLOWED)?;
        let version = parse_version(headers)?;
        let from = parse_key_ref(headers, HEADER_S2S_FROM, S2S_DEFAULT_MAX_HEADER_VALUE_LEN)?;
        let to = parse_key_ref(headers, HEADER_S2S_TO, S2S_DEFAULT_MAX_HEADER_VALUE_LEN)?;
        let issued_at =
            parse_decimal_u64(HEADER_S2S_ISSUED_AT, &get_single(headers, HEADER_S2S_ISSUED_AT, 20)?)?;
        let expires_at = parse_decimal_u64(
            HEADER_S2S_EXPIRES_AT,
            &get_single(headers, HEADER_S2S_EXPIRES_AT, 20)?,
        )?;
        let in_reply_to = parse_nonce_header(headers, HEADER_S2S_IN_REPLY_TO)?;
        let nonce = parse_nonce_header(headers, HEADER_S2S_NONCE)?;
        Ok(S2sResponseHeaders {
            version,
            from,
            to,
            issued_at,
            expires_at,
            in_reply_to,
            nonce,
        })
    }

    pub fn apply(&self, headers: &mut HeaderMap) -> S2sResult<()> {
        put_header(headers, HEADER_S2S_VERSION, &self.version.to_string())?;
        put_header(headers, HEADER_S2S_FROM, &self.from.to_wire_string())?;
        put_header(headers, HEADER_S2S_TO, &self.to.to_wire_string())?;
        put_header(headers, HEADER_S2S_ISSUED_AT, &self.issued_at.to_string())?;
        put_header(headers, HEADER_S2S_EXPIRES_AT, &self.expires_at.to_string())?;
        put_header(
            headers,
            HEADER_S2S_IN_REPLY_TO,
            &encode_nonce(&self.in_reply_to),
        )?;
        put_header(headers, HEADER_S2S_NONCE, &encode_nonce(&self.nonce))?;
        Ok(())
    }
}

fn put_header(headers: &mut HeaderMap, name: &'static str, value: &str) -> S2sResult<()> {
    let value = http::HeaderValue::from_str(value)
        .map_err(|e| invalid(name, format!("cannot encode: {}", e)))?;
    headers.insert(
        http::HeaderName::from_static(name),
        value,
    );
    Ok(())
}

/// 时间窗策略(§8.2):
/// `exp > iat`、`exp - iat <= max_lifetime`、`iat <= now + future_clock_skew`、
/// `exp > now`;任何一条不满足即拒绝。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimeWindowPolicy {
    pub max_lifetime_secs: u64,
    pub future_clock_skew_secs: u64,
}

impl Default for TimeWindowPolicy {
    fn default() -> Self {
        TimeWindowPolicy {
            max_lifetime_secs: super::S2S_DEFAULT_MAX_LIFETIME_SECS,
            future_clock_skew_secs: super::S2S_DEFAULT_FUTURE_CLOCK_SKEW_SECS,
        }
    }
}

pub fn validate_time_window(
    issued_at: u64,
    expires_at: u64,
    now: u64,
    policy: &TimeWindowPolicy,
) -> S2sResult<()> {
    if expires_at <= issued_at {
        return Err(S2sError::ExpiredMessage("exp <= iat".to_string()));
    }
    if expires_at - issued_at > policy.max_lifetime_secs {
        return Err(S2sError::ExpiredMessage("lifetime too long".to_string()));
    }
    if issued_at > now.saturating_add(policy.future_clock_skew_secs) {
        return Err(S2sError::ExpiredMessage("iat in the future".to_string()));
    }
    if expires_at <= now {
        return Err(S2sError::ExpiredMessage("expired".to_string()));
    }
    Ok(())
}

/// 按 RFC 9110 解析 Content-Type 后只比较小写 `type/subtype`,忽略参数;
/// 无法解析返回 None(调用方拒绝,不做内容嗅探)。
pub fn parse_media_type(content_type: &str) -> Option<String> {
    let essence = content_type.split(';').next()?.trim();
    if essence.is_empty() || !essence.contains('/') {
        return None;
    }
    if !essence
        .bytes()
        .all(|b| (0x21..=0x7e).contains(&b))
    {
        return None;
    }
    Some(essence.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    use name_lib::DID;

    fn sample() -> S2sRequestHeaders {
        S2sRequestHeaders {
            version: 1,
            from: ServiceKeyRef::new(DID::new("web", "a.example.com")),
            to: ServiceKeyRef::new(DID::new("web", "b.example.com")),
            issued_at: 1785100000,
            expires_at: 1785100300,
            nonce: [7u8; 24],
        }
    }

    #[test]
    fn request_headers_roundtrip() {
        let mut map = HeaderMap::new();
        sample().apply(&mut map).unwrap();
        let parsed = S2sRequestHeaders::parse(&map).unwrap();
        assert_eq!(parsed, sample());
    }

    #[test]
    fn rejects_duplicate_and_unknown_and_bad_values() {
        let mut map = HeaderMap::new();
        sample().apply(&mut map).unwrap();
        // 重复 Header
        map.append(
            http::HeaderName::from_static(HEADER_S2S_NONCE),
            http::HeaderValue::from_static("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        );
        assert!(S2sRequestHeaders::parse(&map).is_err());

        // 未识别 krpc-s2s-*
        let mut map = HeaderMap::new();
        sample().apply(&mut map).unwrap();
        map.insert(
            http::HeaderName::from_static("krpc-s2s-extra"),
            http::HeaderValue::from_static("x"),
        );
        assert!(S2sRequestHeaders::parse(&map).is_err());

        // 普通 HTTP Header 不影响解析
        let mut map = HeaderMap::new();
        sample().apply(&mut map).unwrap();
        map.insert(
            http::HeaderName::from_static("x-custom"),
            http::HeaderValue::from_static("anything"),
        );
        assert!(S2sRequestHeaders::parse(&map).is_ok());

        // 版本错误:不降级
        let mut map = HeaderMap::new();
        sample().apply(&mut map).unwrap();
        map.insert(
            http::HeaderName::from_static(HEADER_S2S_VERSION),
            http::HeaderValue::from_static("2"),
        );
        assert!(matches!(
            S2sRequestHeaders::parse(&map),
            Err(S2sError::UnknownVersion(_))
        ));

        // timestamp 带符号/前导零拒绝
        for bad in ["+1", "01", "1.0", "-5", ""] {
            let mut map = HeaderMap::new();
            sample().apply(&mut map).unwrap();
            map.insert(
                http::HeaderName::from_static(HEADER_S2S_ISSUED_AT),
                http::HeaderValue::from_str(bad).unwrap(),
            );
            assert!(S2sRequestHeaders::parse(&map).is_err(), "should reject {:?}", bad);
        }

        // OWS 移除后可解析
        let mut map = HeaderMap::new();
        sample().apply(&mut map).unwrap();
        map.insert(
            http::HeaderName::from_static(HEADER_S2S_ISSUED_AT),
            http::HeaderValue::from_static(" 1785100000\t"),
        );
        assert!(S2sRequestHeaders::parse(&map).is_ok());

        // 缺失字段
        let mut map = HeaderMap::new();
        sample().apply(&mut map).unwrap();
        map.remove(HEADER_S2S_FROM);
        assert!(S2sRequestHeaders::parse(&map).is_err());
    }

    #[test]
    fn time_window_rules() {
        let policy = TimeWindowPolicy {
            max_lifetime_secs: 300,
            future_clock_skew_secs: 60,
        };
        let now = 1000;
        // 正常
        assert!(validate_time_window(now, now + 300, now, &policy).is_ok());
        // exp <= iat
        assert!(validate_time_window(now, now, now, &policy).is_err());
        // lifetime 超限
        assert!(validate_time_window(now, now + 301, now, &policy).is_err());
        // iat 超前超出 skew
        assert!(validate_time_window(now + 61, now + 200, now, &policy).is_err());
        assert!(validate_time_window(now + 60, now + 200, now, &policy).is_ok());
        // 已过期
        assert!(validate_time_window(now - 300, now - 1, now, &policy).is_err());
    }

    #[test]
    fn media_type_parsing() {
        assert_eq!(
            parse_media_type("application/vnd.buckyos.krpc-s2s"),
            Some("application/vnd.buckyos.krpc-s2s".to_string())
        );
        assert_eq!(
            parse_media_type("Application/JSON; charset=utf-8"),
            Some("application/json".to_string())
        );
        assert_eq!(parse_media_type(""), None);
        assert_eq!(parse_media_type("nonsense"), None);
    }

    #[test]
    fn response_headers_roundtrip() {
        let resp = S2sResponseHeaders {
            version: 1,
            from: ServiceKeyRef::new(DID::new("web", "b.example.com")),
            to: ServiceKeyRef::new(DID::new("web", "a.example.com")),
            issued_at: 1785100001,
            expires_at: 1785100301,
            in_reply_to: [7u8; 24],
            nonce: [9u8; 24],
        };
        let mut map = HeaderMap::new();
        resp.apply(&mut map).unwrap();
        let parsed = S2sResponseHeaders::parse(&map).unwrap();
        assert_eq!(parsed, resp);
    }
}
