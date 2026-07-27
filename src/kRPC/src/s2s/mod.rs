//! kRPC S2S Payload Protection v1
//!
//! 实现 doc/krpc-s2s-payload-encryption-TODO.md 定义的可选 S2S Payload 加密
//! Profile:双方使用已验证的 Ed25519/DID 身份密钥在本地完成
//! Ed25519→X25519 static-static DH + HKDF-SHA-256 派生,对每个 kRPC JSON
//! Payload 独立执行 XChaCha20-Poly1305 AEAD。没有在线握手,也没有加密 session。
//!
//! 本模块只定义协议基元与 trait(codec、密钥、AAD、seal/open、policy、
//! replay、context);HTTP 入口在 `buckyos-http-server` 的
//! `serve_http_by_s2s_rpc_handler`。

mod aad;
mod api_name;
mod client;
mod codec;
mod error;
mod headers;
mod identity;
mod keys;
mod peer;
mod policy;
mod replay;
mod seal;
mod server_ctx;
mod service_key_ref;

pub use aad::*;
pub use api_name::*;
pub use client::*;
pub use codec::*;
pub use error::*;
pub use headers::*;
pub use identity::*;
pub use keys::*;
pub use peer::*;
pub use policy::*;
pub use replay::*;
pub use seal::*;
pub use server_ctx::*;
pub use service_key_ref::*;

/// `S2sKeyAgreementProvider` 返回值用的 zeroize-on-drop 容器(re-export,
/// 便于下游实现 provider trait)。
pub use zeroize::Zeroizing;

/// v1 唯一版本号。版本号唯一决定算法套件,不做协商。
pub const S2S_PROFILE_VERSION: u32 = 1;

/// 加密请求/响应的 media type(parser dispatch 依据,参数被忽略)。
pub const S2S_CONTENT_TYPE: &str = "application/vnd.buckyos.krpc-s2s";
/// 明文 kRPC 的 media type。
pub const S2S_PLAINTEXT_CONTENT_TYPE: &str = "application/json";

/// S2S 调用的 HTTP path 前缀:`POST /s2s/$apiname`。
pub const S2S_PATH_PREFIX: &str = "/s2s/";
/// 协议保留的加密探测 API(`POST /s2s/__probe`)。
pub const S2S_PROBE_API: &str = "__probe";

// ---- Header 名称(http crate 要求小写;HTTP header name 大小写不敏感) ----
pub const HEADER_S2S_VERSION: &str = "krpc-s2s-version";
pub const HEADER_S2S_FROM: &str = "krpc-s2s-from";
pub const HEADER_S2S_TO: &str = "krpc-s2s-to";
pub const HEADER_S2S_ISSUED_AT: &str = "krpc-s2s-issued-at";
pub const HEADER_S2S_EXPIRES_AT: &str = "krpc-s2s-expires-at";
pub const HEADER_S2S_NONCE: &str = "krpc-s2s-nonce";
pub const HEADER_S2S_IN_REPLY_TO: &str = "krpc-s2s-in-reply-to";
/// 所有 `krpc-s2s-*` 前缀 Header 属于协议命名空间;未识别的默认拒绝。
pub const HEADER_S2S_PREFIX: &str = "krpc-s2s-";

// ---- domain separation 常量(冻结,不可变更) ----
pub const S2S_DOMAIN_AAD: &str = "buckyos.krpc.s2s.v1/aad";
pub const S2S_DOMAIN_KDF_SALT: &str = "buckyos.krpc.s2s.v1/kdf-salt";
pub const S2S_DOMAIN_AEAD_KEY: &str = "buckyos.krpc.s2s.v1/aead-key";
pub const S2S_DOMAIN_ED25519_KEY: &str = "buckyos.krpc.s2s.v1/ed25519-key";

// ---- wire 常量 ----
/// XChaCha20-Poly1305 nonce 长度(CSPRNG 随机,Base64URL no-padding 放入 Header)。
pub const S2S_NONCE_LEN: usize = 24;
/// Poly1305 tag 长度(附加在密文尾部)。
pub const S2S_TAG_LEN: usize = 16;
/// 24 字节 nonce 的 Base64URL no-padding 编码长度。
pub const S2S_NONCE_B64_LEN: usize = 32;

// ---- 默认限制(§11.5;放宽必须显式,且不能超过 hard cap) ----
pub const S2S_DEFAULT_MAX_LIFETIME_SECS: u64 = 300;
pub const S2S_DEFAULT_FUTURE_CLOCK_SKEW_SECS: u64 = 60;
pub const S2S_DEFAULT_MAX_BODY_SIZE: usize = 1024 * 1024;
pub const S2S_DEFAULT_MAX_JSON_DEPTH: usize = 64;
pub const S2S_DEFAULT_MAX_KEY_CANDIDATES: usize = 2;
/// 单个 S2S Header value 的默认长度上限。
pub const S2S_DEFAULT_MAX_HEADER_VALUE_LEN: usize = 1024;

// ---- library hard caps(显式配置也不能超过) ----
pub const S2S_HARD_MAX_LIFETIME_SECS: u64 = 3600;
pub const S2S_HARD_MAX_FUTURE_CLOCK_SKEW_SECS: u64 = 600;
pub const S2S_HARD_MAX_BODY_SIZE: usize = 64 * 1024 * 1024;
pub const S2S_HARD_MAX_KEY_CANDIDATES: usize = 8;

/// ServiceKeyRef wire 形式的长度上限(canonical did + 可选 `#key_id`)。
pub const S2S_MAX_KEY_REF_LEN: usize = 512;
/// key id 的长度上限。
pub const S2S_MAX_KEY_ID_LEN: usize = 64;
/// canonical API name 的长度上限。
pub const S2S_MAX_API_NAME_LEN: usize = 128;
