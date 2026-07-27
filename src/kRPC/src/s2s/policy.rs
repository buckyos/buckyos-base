//! 服务端安全策略模型(§11)。
//!
//! 基础库提供完整 policy evaluation;应用不通过自拼 boolean 重做安全判断。
//! 安全默认 fail closed:`/s2s/` 只接受加密请求、不信任 forwarded source、
//! 不允许任意 peer,并强制时间窗口、replay 和资源上限。

use super::api_name::canonicalize_api_name;
use super::error::{S2sError, S2sResult};
use super::headers::TimeWindowPolicy;
use super::{
    S2S_DEFAULT_MAX_BODY_SIZE, S2S_DEFAULT_MAX_HEADER_VALUE_LEN, S2S_DEFAULT_MAX_JSON_DEPTH,
    S2S_DEFAULT_MAX_KEY_CANDIDATES, S2S_HARD_MAX_BODY_SIZE, S2S_HARD_MAX_FUTURE_CLOCK_SKEW_SECS,
    S2S_HARD_MAX_KEY_CANDIDATES, S2S_HARD_MAX_LIFETIME_SECS,
};
use ipnet::IpNet;
use name_lib::DID;
use std::collections::HashSet;
use std::net::IpAddr;
use std::str::FromStr;

/// source IP 的 provenance(§9.2/§11.3)。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceIpProvenance {
    /// TCP/QUIC connection 的直接 peer address。
    SocketPeer,
    /// socket peer 命中 trusted proxy allowlist 后,可信 lower layer 提供的
    /// real source。
    TrustedProxyForwarded,
}

/// source IP policy(§11.3)。
#[derive(Clone, Debug)]
pub enum SourceIpPolicy {
    /// 安全默认:只使用 connection 的直接 peer address(`conn_src_addr`)。
    SocketPeerOnly,
    /// 只有 socket peer 命中 `trusted_proxy_cidrs`,才接受 lower layer 提供的
    /// `real_src_addr`。普通 HTTP `Forwarded` / `X-Forwarded-For` 永远忽略。
    TrustedProxy { trusted_proxy_cidrs: Vec<IpNet> },
}

/// 带 provenance 的 effective source。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EffectiveSource {
    pub ip: IpAddr,
    pub provenance: SourceIpProvenance,
}

/// IPv4-mapped IPv6 归一化到 IPv4,保证 CIDR 匹配一致。
pub fn canonical_ip(ip: IpAddr) -> IpAddr {
    ip.to_canonical()
}

fn parse_addr_ip(addr: &str) -> Option<IpAddr> {
    if let Ok(sa) = addr.parse::<std::net::SocketAddr>() {
        return Some(canonical_ip(sa.ip()));
    }
    addr.parse::<IpAddr>().ok().map(canonical_ip)
}

fn ip_in_cidrs(ip: IpAddr, cidrs: &[IpNet]) -> bool {
    let ip = canonical_ip(ip);
    cidrs.iter().any(|net| net.contains(&ip))
}

/// 从 `StreamInfo` 的地址字段解析 effective source(fail closed)。
///
/// - `conn_src_addr` 缺失或非法 → 错误;
/// - `SocketPeerOnly` → 永远返回 socket peer;
/// - `TrustedProxy` → socket peer 命中 proxy CIDR 且 `real_src_addr` 可解析时
///   返回 forwarded source,否则返回 socket peer。
pub fn resolve_effective_source(
    policy: &SourceIpPolicy,
    conn_src_addr: Option<&str>,
    real_src_addr: Option<&str>,
) -> S2sResult<EffectiveSource> {
    let conn_addr = conn_src_addr
        .ok_or_else(|| S2sError::PolicyViolation("missing conn_src_addr".to_string()))?;
    let conn_ip = parse_addr_ip(conn_addr)
        .ok_or_else(|| S2sError::PolicyViolation(format!("bad conn_src_addr: {}", conn_addr)))?;

    match policy {
        SourceIpPolicy::SocketPeerOnly => Ok(EffectiveSource {
            ip: conn_ip,
            provenance: SourceIpProvenance::SocketPeer,
        }),
        SourceIpPolicy::TrustedProxy { trusted_proxy_cidrs } => {
            if trusted_proxy_cidrs.is_empty() {
                // proxy allowlist 为空:配置校验会拒绝;运行时同样 fail closed
                return Err(S2sError::PolicyViolation(
                    "trusted proxy policy with empty cidr list".to_string(),
                ));
            }
            if ip_in_cidrs(conn_ip, trusted_proxy_cidrs) {
                if let Some(real) = real_src_addr {
                    let real_ip = parse_addr_ip(real).ok_or_else(|| {
                        S2sError::PolicyViolation(format!("bad real_src_addr: {}", real))
                    })?;
                    return Ok(EffectiveSource {
                        ip: real_ip,
                        provenance: SourceIpProvenance::TrustedProxyForwarded,
                    });
                }
                Ok(EffectiveSource {
                    ip: conn_ip,
                    provenance: SourceIpProvenance::SocketPeer,
                })
            } else {
                Ok(EffectiveSource {
                    ip: conn_ip,
                    provenance: SourceIpProvenance::SocketPeer,
                })
            }
        }
    }
}

/// canonical API allowlist。
#[derive(Clone, Debug, Default)]
pub struct ApiAllowlist {
    apis: HashSet<String>,
}

impl ApiAllowlist {
    /// 每个名字都会先 canonical 化;非法名字直接报错。
    pub fn new<I, S>(names: I) -> S2sResult<Self>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut apis = HashSet::new();
        for name in names {
            apis.insert(canonicalize_api_name(name.as_ref())?);
        }
        Ok(ApiAllowlist { apis })
    }

    pub fn is_empty(&self) -> bool {
        self.apis.is_empty()
    }

    pub fn contains(&self, canonical_api: &str) -> bool {
        self.apis.contains(canonical_api)
    }
}

/// plaintext 请求的鉴权策略(§11.4)。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlaintextAuthPolicy {
    /// 安全默认:要求 session token 存在并进入正常 verifier/RBAC 流程。
    RequireSessionToken,
    /// 显式不安全选项:只依赖网络隔离,不要求 token。
    UnsafeNetworkOnly,
}

/// transport admission(§11.4)。
#[derive(Clone, Debug)]
pub enum S2sTransportAdmission {
    /// 安全默认:`/s2s/` 只接受加密请求。
    EncryptedOnly,
    /// 显式配置的可信网段 + API 才能使用明文。
    /// CIDR 允许明文 transport,但**不产生** authenticated service DID。
    EncryptedOrPlaintext {
        plaintext_source_cidrs: Vec<IpNet>,
        plaintext_apis: ApiAllowlist,
        plaintext_auth: PlaintextAuthPolicy,
    },
}

/// peer admission(§11.5)。
#[derive(Clone, Debug)]
pub enum PeerAdmissionPolicy {
    /// 安全默认。
    DenyAll,
    /// 显式 service DID allowlist(canonical did 字符串)。
    AllowServices(HashSet<String>),
    /// 任何 key 验证通过的 service。必须显式开启。
    AnyVerifiedService,
}

impl PeerAdmissionPolicy {
    pub fn allow_services<I, S>(dids: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        PeerAdmissionPolicy::AllowServices(
            dids.into_iter().map(|d| d.as_ref().to_string()).collect(),
        )
    }

    pub fn admits(&self, service_did: &DID) -> bool {
        match self {
            PeerAdmissionPolicy::DenyAll => false,
            PeerAdmissionPolicy::AllowServices(set) => set.contains(&service_did.to_string()),
            PeerAdmissionPolicy::AnyVerifiedService => true,
        }
    }
}

/// token 与 authenticated identity 的绑定策略(§11.5)。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthBindingPolicy {
    /// 由 handler 侧的 token/RBAC 流程处理(authenticated identity 已注入
    /// `RPCServerContext`,handler 可做 subject/audience 一致性检查)。
    HandlerManaged,
    /// 加密请求也必须携带 session token,缺失即拒绝(dispatch 之前)。
    RequireSessionToken,
}

/// 资源限制(§11.5/§14)。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct S2sResourceLimits {
    pub max_body_size: usize,
    pub max_header_value_len: usize,
    pub max_json_depth: usize,
    /// 省略 key id 时 active/grace candidate 尝试上限(本地与对端各自适用)。
    pub max_key_candidates: usize,
}

impl Default for S2sResourceLimits {
    fn default() -> Self {
        S2sResourceLimits {
            max_body_size: S2S_DEFAULT_MAX_BODY_SIZE,
            max_header_value_len: S2S_DEFAULT_MAX_HEADER_VALUE_LEN,
            max_json_depth: S2S_DEFAULT_MAX_JSON_DEPTH,
            max_key_candidates: S2S_DEFAULT_MAX_KEY_CANDIDATES,
        }
    }
}

/// 未认证错误的响应方式(§9.4:统一、短小、无敏感细节)。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RejectionPolicy {
    /// 默认:统一无细节短 403。
    GenericShort403,
}

/// 服务端安全策略(不可缺省;`Default` 等价 `public_internet_default()`)。
#[derive(Clone, Debug)]
pub struct S2sServerSecurityPolicy {
    pub source_ip: SourceIpPolicy,
    pub transport: S2sTransportAdmission,
    pub peer_admission: PeerAdmissionPolicy,
    pub auth_binding: AuthBindingPolicy,
    pub message: TimeWindowPolicy,
    pub limits: S2sResourceLimits,
    pub rejection: RejectionPolicy,
    /// 显式 unsafe 标记:允许 `0.0.0.0/0` / `::/0` 之类的全网 plaintext CIDR。
    /// 默认 false;validate 会拒绝未标记的全网段配置。
    pub unsafe_allow_full_network_plaintext: bool,
}

impl S2sServerSecurityPolicy {
    /// 公网安全默认(§11.6):EncryptedOnly、SocketPeerOnly、peer fail closed、
    /// replay/time/resource limits 必开、generic rejection、不信任 forwarded。
    pub fn public_internet_default() -> Self {
        S2sServerSecurityPolicy {
            source_ip: SourceIpPolicy::SocketPeerOnly,
            transport: S2sTransportAdmission::EncryptedOnly,
            peer_admission: PeerAdmissionPolicy::DenyAll,
            auth_binding: AuthBindingPolicy::HandlerManaged,
            message: TimeWindowPolicy::default(),
            limits: S2sResourceLimits::default(),
            rejection: RejectionPolicy::GenericShort403,
            unsafe_allow_full_network_plaintext: false,
        }
    }

    /// 在公网默认值上只增加指定 CIDR/API 的 plaintext admission,
    /// 保留 token/RBAC、Body limit 与审计。
    pub fn trusted_network_plaintext<I, S>(cidrs: Vec<IpNet>, apis: I) -> S2sResult<Self>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut policy = Self::public_internet_default();
        policy.transport = S2sTransportAdmission::EncryptedOrPlaintext {
            plaintext_source_cidrs: cidrs,
            plaintext_apis: ApiAllowlist::new(apis)?,
            plaintext_auth: PlaintextAuthPolicy::RequireSessionToken,
        };
        policy.validate()?;
        Ok(policy)
    }

    pub fn builder() -> S2sServerSecurityPolicyBuilder {
        S2sServerSecurityPolicyBuilder {
            policy: Self::public_internet_default(),
        }
    }

    /// 校验不变量(§11.6);context 构造与 reload 都必须调用,
    /// 失败返回错误而不是运行时静默修正。
    pub fn validate(&self) -> S2sResult<()> {
        if let S2sTransportAdmission::EncryptedOrPlaintext {
            plaintext_source_cidrs,
            plaintext_apis,
            ..
        } = &self.transport
        {
            if plaintext_source_cidrs.is_empty() {
                return Err(S2sError::InvalidConfig(
                    "EncryptedOrPlaintext requires non-empty plaintext_source_cidrs".to_string(),
                ));
            }
            if plaintext_apis.is_empty() {
                return Err(S2sError::InvalidConfig(
                    "EncryptedOrPlaintext requires non-empty plaintext_apis".to_string(),
                ));
            }
            if !self.unsafe_allow_full_network_plaintext {
                for net in plaintext_source_cidrs {
                    if net.prefix_len() == 0 {
                        return Err(S2sError::InvalidConfig(format!(
                            "full-network plaintext cidr {} requires unsafe_allow_full_network_plaintext",
                            net
                        )));
                    }
                }
            }
        }
        if let SourceIpPolicy::TrustedProxy { trusted_proxy_cidrs } = &self.source_ip {
            if trusted_proxy_cidrs.is_empty() {
                return Err(S2sError::InvalidConfig(
                    "TrustedProxy requires non-empty trusted_proxy_cidrs".to_string(),
                ));
            }
        }
        if self.message.max_lifetime_secs == 0
            || self.message.max_lifetime_secs > S2S_HARD_MAX_LIFETIME_SECS
        {
            return Err(S2sError::InvalidConfig(format!(
                "max_lifetime_secs must be 1..={}",
                S2S_HARD_MAX_LIFETIME_SECS
            )));
        }
        if self.message.future_clock_skew_secs > S2S_HARD_MAX_FUTURE_CLOCK_SKEW_SECS {
            return Err(S2sError::InvalidConfig(format!(
                "future_clock_skew_secs must be <= {}",
                S2S_HARD_MAX_FUTURE_CLOCK_SKEW_SECS
            )));
        }
        if self.limits.max_body_size == 0 || self.limits.max_body_size > S2S_HARD_MAX_BODY_SIZE {
            return Err(S2sError::InvalidConfig(format!(
                "max_body_size must be 1..={}",
                S2S_HARD_MAX_BODY_SIZE
            )));
        }
        if self.limits.max_key_candidates == 0
            || self.limits.max_key_candidates > S2S_HARD_MAX_KEY_CANDIDATES
        {
            return Err(S2sError::InvalidConfig(format!(
                "max_key_candidates must be 1..={}",
                S2S_HARD_MAX_KEY_CANDIDATES
            )));
        }
        if self.limits.max_json_depth == 0 || self.limits.max_header_value_len == 0 {
            return Err(S2sError::InvalidConfig(
                "json depth / header value limits must be non-zero".to_string(),
            ));
        }
        Ok(())
    }

    /// plaintext admission 判定(§11.4):必须同时命中 source CIDR 与 API
    /// allowlist。在读取/解析 Body 之前调用。
    pub fn admits_plaintext(&self, source: &EffectiveSource, canonical_api: &str) -> bool {
        match &self.transport {
            S2sTransportAdmission::EncryptedOnly => false,
            S2sTransportAdmission::EncryptedOrPlaintext {
                plaintext_source_cidrs,
                plaintext_apis,
                ..
            } => {
                ip_in_cidrs(source.ip, plaintext_source_cidrs)
                    && plaintext_apis.contains(canonical_api)
            }
        }
    }

    pub fn plaintext_auth(&self) -> Option<PlaintextAuthPolicy> {
        match &self.transport {
            S2sTransportAdmission::EncryptedOnly => None,
            S2sTransportAdmission::EncryptedOrPlaintext { plaintext_auth, .. } => {
                Some(*plaintext_auth)
            }
        }
    }
}

impl Default for S2sServerSecurityPolicy {
    /// 与 `public_internet_default()` 相同;禁止 derive 出 allow-all 默认。
    fn default() -> Self {
        Self::public_internet_default()
    }
}

/// builder(字段级 setter,最后 `build()` 校验不变量)。
pub struct S2sServerSecurityPolicyBuilder {
    policy: S2sServerSecurityPolicy,
}

impl S2sServerSecurityPolicyBuilder {
    pub fn source_ip(mut self, policy: SourceIpPolicy) -> Self {
        self.policy.source_ip = policy;
        self
    }

    pub fn trusted_proxies(mut self, cidrs: Vec<IpNet>) -> Self {
        self.policy.source_ip = SourceIpPolicy::TrustedProxy {
            trusted_proxy_cidrs: cidrs,
        };
        self
    }

    pub fn transport(mut self, admission: S2sTransportAdmission) -> Self {
        self.policy.transport = admission;
        self
    }

    pub fn plaintext_from<I, S>(mut self, cidrs: Vec<IpNet>, apis: I) -> S2sResult<Self>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.policy.transport = S2sTransportAdmission::EncryptedOrPlaintext {
            plaintext_source_cidrs: cidrs,
            plaintext_apis: ApiAllowlist::new(apis)?,
            plaintext_auth: PlaintextAuthPolicy::RequireSessionToken,
        };
        Ok(self)
    }

    pub fn peer_admission(mut self, policy: PeerAdmissionPolicy) -> Self {
        self.policy.peer_admission = policy;
        self
    }

    pub fn auth_binding(mut self, policy: AuthBindingPolicy) -> Self {
        self.policy.auth_binding = policy;
        self
    }

    pub fn message_window(mut self, window: TimeWindowPolicy) -> Self {
        self.policy.message = window;
        self
    }

    pub fn limits(mut self, limits: S2sResourceLimits) -> Self {
        self.policy.limits = limits;
        self
    }

    /// 显式 unsafe:允许全网段 plaintext CIDR。
    pub fn unsafe_allow_full_network_plaintext(mut self) -> Self {
        self.policy.unsafe_allow_full_network_plaintext = true;
        self
    }

    pub fn build(self) -> S2sResult<S2sServerSecurityPolicy> {
        self.policy.validate()?;
        Ok(self.policy)
    }
}

/// 便捷 CIDR 解析。
pub fn parse_cidrs<I, S>(cidrs: I) -> S2sResult<Vec<IpNet>>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    cidrs
        .into_iter()
        .map(|s| {
            IpNet::from_str(s.as_ref())
                .map_err(|e| S2sError::InvalidConfig(format!("bad cidr {}: {}", s.as_ref(), e)))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_policy_is_fail_closed() {
        let policy = S2sServerSecurityPolicy::default();
        policy.validate().unwrap();
        assert!(matches!(policy.transport, S2sTransportAdmission::EncryptedOnly));
        assert!(matches!(policy.peer_admission, PeerAdmissionPolicy::DenyAll));
        assert!(matches!(policy.source_ip, SourceIpPolicy::SocketPeerOnly));
        let src = EffectiveSource {
            ip: "127.0.0.1".parse().unwrap(),
            provenance: SourceIpProvenance::SocketPeer,
        };
        // loopback 也不放行 plaintext(不自动信任 RFC1918/loopback)
        assert!(!policy.admits_plaintext(&src, "any-api"));
        assert!(!policy.peer_admission.admits(&DID::new("web", "x.example.com")));
    }

    #[test]
    fn plaintext_requires_cidr_and_api_hit() {
        let policy = S2sServerSecurityPolicy::trusted_network_plaintext(
            parse_cidrs(["10.1.0.0/16"]).unwrap(),
            ["event-report-v1"],
        )
        .unwrap();

        let inside = EffectiveSource {
            ip: "10.1.2.3".parse().unwrap(),
            provenance: SourceIpProvenance::SocketPeer,
        };
        let outside = EffectiveSource {
            ip: "10.2.2.3".parse().unwrap(),
            provenance: SourceIpProvenance::SocketPeer,
        };
        assert!(policy.admits_plaintext(&inside, "event-report-v1"));
        assert!(!policy.admits_plaintext(&inside, "other-api"));
        assert!(!policy.admits_plaintext(&outside, "event-report-v1"));
        // IPv4-mapped IPv6 命中 IPv4 CIDR
        let mapped = EffectiveSource {
            ip: "::ffff:10.1.2.3".parse().unwrap(),
            provenance: SourceIpProvenance::SocketPeer,
        };
        assert!(policy.admits_plaintext(&mapped, "event-report-v1"));
    }

    #[test]
    fn invalid_configs_rejected() {
        // 空 CIDR
        assert!(S2sServerSecurityPolicy::trusted_network_plaintext::<_, &str>(vec![], ["a"]).is_err());
        // 空 API
        assert!(S2sServerSecurityPolicy::trusted_network_plaintext::<_, &str>(
            parse_cidrs(["10.0.0.0/8"]).unwrap(),
            Vec::<&str>::new()
        )
        .is_err());
        // 全网段默认拒绝
        assert!(S2sServerSecurityPolicy::trusted_network_plaintext(
            parse_cidrs(["0.0.0.0/0"]).unwrap(),
            ["a"]
        )
        .is_err());
        // 显式 unsafe 才允许全网段
        let policy = S2sServerSecurityPolicy::builder()
            .plaintext_from(parse_cidrs(["0.0.0.0/0"]).unwrap(), ["a"])
            .unwrap()
            .unsafe_allow_full_network_plaintext()
            .build();
        assert!(policy.is_ok());
        // trusted proxy 无 CIDR
        let policy = S2sServerSecurityPolicy::builder()
            .trusted_proxies(vec![])
            .build();
        assert!(policy.is_err());
        // 超出 hard cap
        let mut limits = S2sResourceLimits::default();
        limits.max_key_candidates = 100;
        assert!(S2sServerSecurityPolicy::builder().limits(limits).build().is_err());
        let mut window = TimeWindowPolicy::default();
        window.max_lifetime_secs = 24 * 3600;
        assert!(S2sServerSecurityPolicy::builder().message_window(window).build().is_err());
    }

    #[test]
    fn effective_source_resolution() {
        // SocketPeerOnly:忽略 real_src_addr
        let src = resolve_effective_source(
            &SourceIpPolicy::SocketPeerOnly,
            Some("203.0.113.7:5555"),
            Some("198.51.100.9:1111"),
        )
        .unwrap();
        assert_eq!(src.ip, "203.0.113.7".parse::<IpAddr>().unwrap());
        assert_eq!(src.provenance, SourceIpProvenance::SocketPeer);

        // 缺失 conn_src_addr → fail closed
        assert!(resolve_effective_source(&SourceIpPolicy::SocketPeerOnly, None, None).is_err());

        let proxy_policy = SourceIpPolicy::TrustedProxy {
            trusted_proxy_cidrs: parse_cidrs(["203.0.113.0/24"]).unwrap(),
        };
        // socket peer 命中 proxy → 用 real source(provenance 标记 forwarded)
        let src = resolve_effective_source(
            &proxy_policy,
            Some("203.0.113.7:5555"),
            Some("198.51.100.9:1111"),
        )
        .unwrap();
        assert_eq!(src.ip, "198.51.100.9".parse::<IpAddr>().unwrap());
        assert_eq!(src.provenance, SourceIpProvenance::TrustedProxyForwarded);

        // socket peer 不在 proxy CIDR → 伪造 real_src_addr 无效
        let src = resolve_effective_source(
            &proxy_policy,
            Some("198.51.100.20:5555"),
            Some("10.0.0.1:1111"),
        )
        .unwrap();
        assert_eq!(src.ip, "198.51.100.20".parse::<IpAddr>().unwrap());
        assert_eq!(src.provenance, SourceIpProvenance::SocketPeer);

        // IPv4-mapped IPv6 socket peer 命中 IPv4 proxy CIDR
        let src = resolve_effective_source(
            &proxy_policy,
            Some("[::ffff:203.0.113.7]:5555"),
            Some("198.51.100.9"),
        )
        .unwrap();
        assert_eq!(src.provenance, SourceIpProvenance::TrustedProxyForwarded);
    }

    #[test]
    fn peer_admission_rules() {
        let deny = PeerAdmissionPolicy::DenyAll;
        assert!(!deny.admits(&DID::new("web", "a.example.com")));
        let allow = PeerAdmissionPolicy::allow_services(["did:web:a.example.com"]);
        assert!(allow.admits(&DID::new("web", "a.example.com")));
        assert!(!allow.admits(&DID::new("web", "b.example.com")));
        let any = PeerAdmissionPolicy::AnyVerifiedService;
        assert!(any.admits(&DID::new("web", "b.example.com")));
    }
}
