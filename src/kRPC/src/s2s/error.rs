//! S2S 结构化错误。
//!
//! 注意:这些错误用于服务内部诊断与 metric reason code;发给**未认证**对端的
//! HTTP 响应必须使用统一、无细节的 transport failure(见 server 侧
//! `uniform reject`),不得把这里的信息直接返回。

use thiserror::Error;

#[derive(Debug, Error)]
pub enum S2sError {
    /// 未识别的 profile 版本。不尝试 v0/plaintext。
    #[error("unknown s2s version: {0}")]
    UnknownVersion(String),
    /// Header 缺失、重复、超长、含控制字符或无法解析。
    #[error("invalid s2s header {name}: {reason}")]
    InvalidHeader { name: String, reason: String },
    #[error("invalid canonical DID: {0}")]
    InvalidDid(String),
    #[error("invalid api name: {0}")]
    InvalidApiName(String),
    /// 时间窗口校验失败(`exp<=iat`、超过 max lifetime、iat 超前、已过期)。
    #[error("message outside allowed time window: {0}")]
    ExpiredMessage(String),
    /// `To` 不是本服务,或 peer admission 拒绝。
    #[error("wrong peer: {0}")]
    WrongPeer(String),
    /// message kind (request/response) 不匹配。
    #[error("wrong message kind")]
    WrongKind,
    /// API 与密文绑定不一致。
    #[error("wrong api")]
    WrongApi,
    /// AEAD open 失败。刻意不区分 tag 错误/密钥不对/密文截断。
    #[error("decrypt failed")]
    DecryptFailed,
    #[error("replay detected")]
    ReplayDetected,
    /// replay store 故障。fail closed:必须拒绝请求。
    #[error("replay store unavailable: {0}")]
    ReplayStoreUnavailable(String),
    /// provider 只支持签名,不支持 X25519 key agreement。
    #[error("key agreement not supported: {0}")]
    KeyAgreementNotSupported(String),
    #[error("private key not usable for s2s: {0}")]
    PrivateKeyNotUsableForS2s(String),
    /// 找不到指定 key(本地或对端)。
    #[error("key not found: {0}")]
    KeyNotFound(String),
    /// 产品 Provider 管理状态错误、禁用、损坏或暂时不可用。
    #[error("s2s public-key provider failed: {0}")]
    PublicKeyProvider(String),
    /// 有界 refresh 没有得到不同的可信 fingerprint，因此不应重发密文。
    #[error("remote key did not change after bounded refresh")]
    RemoteKeyUnchanged,
    /// 无效 Ed25519 公钥或 non-contributory(all-zero)DH 输出。
    #[error("invalid or non-contributory key: {0}")]
    InvalidKey(String),
    #[error("policy violation: {0}")]
    PolicyViolation(String),
    /// context 构造/reload 时的配置不变量违反。
    #[error("invalid s2s config: {0}")]
    InvalidConfig(String),
    #[error("resource limit exceeded: {0}")]
    LimitExceeded(String),
    /// 网络/HTTP transport 层失败(客户端侧,可能 transient)。
    #[error("s2s transport error: {0}")]
    Transport(String),
    #[error("s2s internal error: {0}")]
    Internal(String),
}

impl S2sError {
    /// 客户端重试分类:permanent 错误重试无意义,必须进入告警/DLQ 流程,
    /// 不能被 best-effort 逻辑静默吞掉。
    pub fn is_permanent(&self) -> bool {
        match self {
            S2sError::Transport(_)
            | S2sError::ReplayStoreUnavailable(_)
            | S2sError::Internal(_) => false,
            _ => true,
        }
    }

    /// 低基数 metric reason code(不含动态内容)。
    pub fn reason_code(&self) -> &'static str {
        match self {
            S2sError::UnknownVersion(_) => "unknown_version",
            S2sError::InvalidHeader { .. } => "invalid_header",
            S2sError::InvalidDid(_) => "invalid_did",
            S2sError::InvalidApiName(_) => "invalid_api_name",
            S2sError::ExpiredMessage(_) => "expired",
            S2sError::WrongPeer(_) => "wrong_peer",
            S2sError::WrongKind => "wrong_kind",
            S2sError::WrongApi => "wrong_api",
            S2sError::DecryptFailed => "decrypt_failed",
            S2sError::ReplayDetected => "replay",
            S2sError::ReplayStoreUnavailable(_) => "replay_store_unavailable",
            S2sError::KeyAgreementNotSupported(_) => "key_agreement_not_supported",
            S2sError::PrivateKeyNotUsableForS2s(_) => "private_key_not_usable",
            S2sError::KeyNotFound(_) => "key_not_found",
            S2sError::PublicKeyProvider(_) => "public_key_provider",
            S2sError::RemoteKeyUnchanged => "remote_key_unchanged",
            S2sError::InvalidKey(_) => "invalid_key",
            S2sError::PolicyViolation(_) => "policy_violation",
            S2sError::InvalidConfig(_) => "invalid_config",
            S2sError::LimitExceeded(_) => "limit_exceeded",
            S2sError::Transport(_) => "transport",
            S2sError::Internal(_) => "internal",
        }
    }
}

pub type S2sResult<T> = std::result::Result<T, S2sError>;
