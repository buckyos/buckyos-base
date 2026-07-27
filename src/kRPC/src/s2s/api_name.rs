//! canonical API name(Phase 0 冻结规则)。
//!
//! 规则:
//! - 输入是 `/s2s/` 之后的单个 path 段(允许 percent-encoding,先解码);
//! - 解码后必须精确匹配:首字符 `[a-z0-9_]`,其余 `[a-z0-9._-]`;
//! - 拒绝大写(canonical form 只有一种 wire 形式,不做大小写折叠);
//! - 拒绝 `..` 子串、拒绝 `/`(不存在多级 API path);
//! - 长度 1..=128;
//! - `__` 前缀保留给协议自身:目前只接受 `__probe`,其余 `_` 开头一律拒绝。

use super::error::{S2sError, S2sResult};
use super::{S2S_MAX_API_NAME_LEN, S2S_PATH_PREFIX, S2S_PROBE_API};
use percent_encoding::percent_decode_str;

/// 把原始 path 段规范化为 canonical API name。
pub fn canonicalize_api_name(raw_segment: &str) -> S2sResult<String> {
    if raw_segment.is_empty() {
        return Err(S2sError::InvalidApiName("empty api name".to_string()));
    }
    // 防御性上限:percent 解码前的长度不超过 3x 上限
    if raw_segment.len() > S2S_MAX_API_NAME_LEN * 3 {
        return Err(S2sError::InvalidApiName("api name too long".to_string()));
    }
    let decoded = percent_decode_str(raw_segment)
        .decode_utf8()
        .map_err(|_| S2sError::InvalidApiName("invalid percent encoding".to_string()))?;
    let name = decoded.as_ref();

    if name.is_empty() || name.len() > S2S_MAX_API_NAME_LEN {
        return Err(S2sError::InvalidApiName(format!(
            "api name length must be 1..={}",
            S2S_MAX_API_NAME_LEN
        )));
    }
    let bytes = name.as_bytes();
    if !matches!(bytes[0], b'a'..=b'z' | b'0'..=b'9' | b'_') {
        return Err(S2sError::InvalidApiName(
            "api name must start with [a-z0-9_]".to_string(),
        ));
    }
    if !bytes
        .iter()
        .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-'))
    {
        return Err(S2sError::InvalidApiName(
            "api name allows only [a-z0-9._-]".to_string(),
        ));
    }
    if name.contains("..") {
        return Err(S2sError::InvalidApiName(
            "api name must not contain '..'".to_string(),
        ));
    }
    if name.starts_with('_') && name != S2S_PROBE_API {
        return Err(S2sError::InvalidApiName(
            "'_' prefix is reserved for the protocol".to_string(),
        ));
    }
    Ok(name.to_string())
}

/// 从 HTTP path 提取 canonical API name。path 必须是 `/s2s/{api}`,
/// 不允许额外的 `/` 层级或空段。
pub fn api_name_from_path(path: &str) -> S2sResult<String> {
    let segment = path
        .strip_prefix(S2S_PATH_PREFIX)
        .ok_or_else(|| S2sError::InvalidApiName(format!("path must start with {}", S2S_PATH_PREFIX)))?;
    if segment.contains('/') {
        return Err(S2sError::InvalidApiName(
            "api path must be a single segment".to_string(),
        ));
    }
    canonicalize_api_name(segment)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_api_names() {
        assert_eq!(canonicalize_api_name("event-report-v1").unwrap(), "event-report-v1");
        assert_eq!(canonicalize_api_name("a.b_c-d1").unwrap(), "a.b_c-d1");
        assert_eq!(canonicalize_api_name("__probe").unwrap(), "__probe");
        // percent-encoding 解码后校验
        assert_eq!(canonicalize_api_name("event%2Dreport").unwrap(), "event-report");

        assert!(canonicalize_api_name("").is_err());
        assert!(canonicalize_api_name("Upper").is_err());
        assert!(canonicalize_api_name("has/slash").is_err());
        assert!(canonicalize_api_name("%2F").is_err()); // decoded '/'
        assert!(canonicalize_api_name("a..b").is_err());
        assert!(canonicalize_api_name("..").is_err());
        assert!(canonicalize_api_name("__other").is_err()); // 保留前缀
        assert!(canonicalize_api_name("_x").is_err());
        assert!(canonicalize_api_name(&"a".repeat(129)).is_err());
        assert!(canonicalize_api_name(&"a".repeat(128)).is_ok());
        assert!(canonicalize_api_name("-lead").is_err());
        assert!(canonicalize_api_name("空格 x").is_err());
    }

    #[test]
    fn api_name_from_path_rules() {
        assert_eq!(api_name_from_path("/s2s/event-report-v1").unwrap(), "event-report-v1");
        assert!(api_name_from_path("/s2s/").is_err());
        assert!(api_name_from_path("/s2s/a/b").is_err());
        assert!(api_name_from_path("/other/a").is_err());
        assert!(api_name_from_path("/s2s/a%2Fb").is_err());
    }
}
