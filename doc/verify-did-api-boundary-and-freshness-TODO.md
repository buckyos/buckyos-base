# Verify DID API 边界与最新性 TODO

> 状态：讨论中，未执行。
>
> 本 TODO 根据 RTCP 等上游的实际使用经验，重新固定 name-client 的 API 心智模型：
> `resolve` 负责取得证据，`verify` 负责使用已有证据验证调用方给出的确切文档，
> `add_cache` 负责显式保存证据。

## 核心心智模型：参考 TLS，而不是把所有事情塞进 verify

DID Document 验证可以参考 TLS 证书验证的分层方式：

1. 对端可以直接携带待验证的文档，类似 TLS peer 携带证书链。
2. verifier 使用调用方已准备好的 trust material 验证这份**确切文档**，类似使用本机
   trust store 验证 peer certificate；默认不应因为 `verify` 这个动作隐式联网。
3. 如果本地缺少 owner binding、OwnerDocument、authority state 等材料，调用方可以显式
   `resolve`，类似显式取得缺失的中间证书、发布状态或在线状态证明。
4. 验证或解析得到的材料是否保存，由调用方显式 `add_cache`，不能成为 verify 的隐藏副作用。
5. “密码学与信任链有效”和“是不是目前知道的最新版本”是两个维度。DID 比普通 TLS
   证书多出文档更新、未公开发布 DeviceDocument、本地 anti-rollback 等使用场景，因此必须
   结构化返回 freshness 事实，而不是把它们继续混在 `CurrentActive` 中。

这三个动词回答不同问题：

| 动词 | 回答的问题 | 允许联网 | 允许写 cache |
| --- | --- | --- | --- |
| `resolve` | 关于这个 DID，我按指定来源目前能取得什么证据？ | 由 options 明确决定 | 可回填解析缓存 |
| `verify` | 调用方给我的这一份文档，能否被已有 trust material 验证？ | 默认不允许 | 不允许 |
| `add_cache` | 是否把这份证据显式保存到指定 cache namespace？ | 不需要 | 是 |

组合 API 可以存在，但名字必须显式暴露组合了哪些动作。

## 背景与现状

当前 `verify_did_document_jwt` 已经同时承担了三个动词：

1. 查询 method authority provider，可能产生 Remote Resolve 网络 I/O。
2. 为取得 expected owner 的 OwnerDocument 递归调用 `resolve_did_ex`。
3. `cache_result = true` 时写入正缓存；此外还有**不受 `cache_result` 控制**的写副作用
   （只受 `enable_cache` 约束）：权威负状态触发 negative cache 写入、Migrated 触发条目
   删除、in-TTL 快路径 replay-guard 失败触发条目删除。
4. 返回值能表达签名、owner、authority status 和 evidence，但不能稳定回答：
   - 候选文档在已有 trust material 下是否有效；
   - 它与某个本地/Zone 作用域已经接受的版本相比是什么关系；
   - 是否刚刚经过权威 Remote Resolve，并被权威源明确确认为全局当前版本。

这让调用者无法从函数名判断延迟、副作用和安全语义，也容易在握手、登录等攻击者可触发的
路径里意外引入查询放大。

RTCP 是最早暴露这个问题的上游之一，但 RTCP 只用于说明使用背景。RTCP 自己必须负责握手
阶段的锁、并发、session 状态和 high-water mark 原子推进；这些正确性责任不属于本仓库。
name-client 的责任是提供边界清楚、事实充分的基础 API，让 RTCP 可以正确组合它们。

## 目标

1. 固定 `resolve / verify / add_cache` 三个动词的 API 边界。
2. verify 默认无网络、无写入副作用；它可以消费调用方准备好的本机/Zone trust snapshot。
3. verify 结果把“有效性”和“最新性”作为两个独立维度表达。
4. 最新性至少区分：
   - **本地已知最新**：候选与指定 local trust scope 中已验证/已接受状态的关系；
   - **权威全局最新**：本次流程经过权威 Remote Resolve，且权威明确证明候选属于当前发布集合。
5. Zone Resolver 作为生产级 shared cache/control-plane cache，能力高于普通文件 cache；
   两者都能参与本地已知状态判断，但不能仅凭“cache 命中”冒充权威 Remote Resolve。
6. 缺少完成有效性验证所需的依赖时，返回结构化 `MissingDependency`，由调用方决定是否 resolve。
7. cache 信任边界继续由文件系统 namespace 和写权限保证，不把
   `VerifiedDidDocument` 设计成不可伪造 capability。
8. revision 比较只使用 `iat`（辅以 content hash 判定同一性与冲突）。`version_seq` 整体退出
   流程：使用者不再构造它，原有字段视作用户自定义扩展，任何比较、guard、强制项都不再读取；
   `mini_version_seq` owner replay guard 随之退役，anti-rollback 由 `valid_iat` 承担。
   权威侧同样统一到 iat 轴：documentVersion = document_iat（权威记录的"文档版本"就是
   当前发布文档的 iat），吊销/替换语义用一个准确的 iat 表达。

## 非目标

1. 不要求所有应用都强制使用最新 DeviceDocument。
2. 不把某个 Gateway/RTCP 的 anti-rollback 策略上升为所有 DID method 的全局规则。
3. 不用文档 freshness 替代 RTCP 的 Hello nonce、token expiry、key confirmation 或锁管理。
4. 不要求 verify 在没有本地 trust material 时偷偷补齐网络依赖。
5. 不在本 TODO 中定义 RTCP high-water mark 的持久化、CAS 或 session 提交算法。
6. 不把普通 local file cache 扩展成 Zone Resolver 的完整替代品。
7. 不在 Rust DTO 类型层面建立 verified cache 的安全边界；真正边界是进程是否有权限写
   verified namespace。

## 三个动词的契约

### 1. resolve：按指定来源取得证据

目标接口形态：

```rust
pub async fn resolve_did(
    did: &DID,
    doc_type: Option<DidDocType>,
    options: ResolveOptions,
) -> NSResult<ResolvedDocument>;
```

`ResolveOptions` 至少要明确来源范围：

```rust
pub enum ResolveSourcePolicy {
    /// 只读进程内/本机文件 cache，不访问 Zone Resolver 和 provider。
    LocalOnly,
    /// 允许访问 Zone Resolver，但不访问 method authority remote provider。
    LocalAndZone,
    /// 显式访问 method authority，取得当前权威判断。
    RemoteAuthority,
    /// 按 resolver 正常优先级取得当前最佳答案。
    BestAvailable,
}
```

语义约束：

- 调用方应预期除 `LocalOnly` 外都可能是异步慢操作。
- Zone Resolver 即使 endpoint 是 localhost，也属于显式允许的 I/O，不能隐藏在纯 verify 中。
- timeout、并发、provider 范围和是否允许 supplement 必须可配置。
- 返回文档之外，还应返回 source、evidence、authority status、cache status、retrieved/checked time。
- 只有 `RemoteAuthority`，或 `BestAvailable` 明确命中 method authority 的结果，才有资格产生
  “权威全局当前”的 receipt。
- resolver 内部回填解析缓存可以保留为实现细节，但文档和类型必须让调用者知道 resolve
  可能读写 cache、可能联网。

`resolve` 回答的是“按指定来源，我现在能取得什么证据”，不是验证调用方手中某一份外部
文档的便捷替代品。

### 2. verify：使用只读 snapshot 验证确切证据

目标接口形态：

```rust
pub fn verify_did_document(
    expected_did: &DID,
    doc_type: DidDocType,
    candidate: &EncodedDocument,
    context: &VerifyContextSnapshot,
    options: VerifyOptions,
) -> Result<VerifiedDidDocument, VerifyError>;
```

`VerifyContextSnapshot` 由调用方显式准备，可以来自：

- 本机 trust store / local override；
- local file cache；
- Zone Resolver 查询结果形成的 Zone snapshot；
- 刚刚完成的 Remote Authority Resolve receipt；
- 调用方自己的 trust domain / high-water snapshot。

纯 verifier 只消费这个不可变 snapshot，不自己读取 provider、不递归 resolve、不写 cache。这样
既能保证无隐式网络，也能用 snapshot generation 避免一次验证混用并发更新前后的证据。

snapshot 中可作为验签依据的 owner 材料（OwnerDocument/key）必须具备 Verified/Published/
Zone/Authority 级证据；Observed/Unverified 条目不得作为 owner 验签依据（与现有实现一致：
owner replay guard 只认 `verified/` 命名空间）。snapshot 中的负状态材料按“负状态的处理规则”
（见 VerifyError 一节）分 terminal / 非 terminal 处理。

verify 必须完成：

- `doc.id == expected_did`；
- 实际 doc type 与期望一致；
- expected owner 的确定与 declared owner 一致性；
- owner key/历史 key 验签；
- `exp` 等有效期检查；
- `valid_iat` owner replay guard（`mini_version_seq` 随 version_seq 退出流程，兼容期只警告不执行）；
- 根据 snapshot 返回本地 freshness 和 authority freshness 事实。

建议错误至少区分：

```rust
pub enum VerifyError {
    InvalidDocument { detail: String },
    DocumentIdMismatch { expected: DID, actual: DID },
    OwnerMismatch { expected: DID, declared: Option<DID> },
    SignatureRejected { detail: String },
    RevokedByOwnerPolicy { detail: String },
    /// snapshot 中存在该 (did, doc_type) 的 terminal 负状态（Revoked/Tombstoned），
    /// 不论它来自本机负缓存记忆、Zone 回答还是本次 Remote receipt。
    RejectedByNegativeState { scope: LocalTrustScope, status: DocumentStatus },
    MissingDependency { dependencies: Vec<VerifyDependency> },
}
```

`MissingDependency` 只表示“缺少完成有效性验证所必需的本地材料，且 verify 没有尝试联网”。
缺少 authority-current 证明但密码学/owner 验证已经完成，不一定是 VerifyError；是否必须权威
当前由后续 freshness policy 决定。

负状态的处理规则（已确认）：terminal 状态（`Revoked` / `Tombstoned`）在纯 verify 中硬失败，
返回 `RejectedByNegativeState`，与现有“负状态屏蔽一切兜底”的语义连续（现状负缓存也只记
terminal 状态）；非 terminal 负状态（`Missing` / `Expired` / `Migrated`）不构成 VerifyError——
来自本次 Remote Authority receipt 的进入 `AuthorityFreshness::NotCurrent { reason:
NegativeStatus(..) }`，来自 Zone 回答的作为 Zone scope 事实进入 ValidityEvidence，是否接受由
freshness policy 决定（对应未发布 DeviceDocument 的 bootstrap 场景，即现有策略点②
`allow_self_signed_when_missing` 的显式化）。

### 3. add_cache：显式保存证据

`add_cache` 是文件系统 cache 协议的函数封装，不是 Rust 类型 capability。现有目录语义继续成立：

```text
unverified/  普通 producer 可写，只表示 Observed
verified/    只有受控进程/服务可写，表示该 producer 有权写入 Verified/Published evidence
```

可以提供语义更清晰的函数：

```rust
pub fn add_observed_cache(entry: CacheEntry) -> CacheWriteOutcome;
pub fn add_verified_cache(entry: CacheEntry) -> CacheWriteOutcome;
```

但两者的安全差异来自目标目录的 OS 权限和进程身份，不来自 `CacheEntry` 或
`VerifiedDidDocument` 是否可构造。直接按文件系统协议写入与调用函数必须具有相同语义。

cache 写入结果不能只有 `Ok(())`：

```rust
pub enum CacheWriteOutcome {
    Inserted,
    ReplacedOlder,
    AlreadyPresent,
    IgnoredOlder,
    RejectedConflict,
    BlockedByNegativeState,
    PermissionDenied,
}
```

verify 不调用 add_cache。组合 API 或上层应用在拿到验证结果后，显式决定写哪个 namespace。

## 证据来源分层与 Zone Resolver

现有两级 cache 不能被抽象成完全相同的能力：

| 来源 | 当前能力 | 在新模型中的作用 | 能否单独证明权威全局当前 |
| --- | --- | --- | --- |
| local file cache | document、evidence、exp、source、负状态 | 本机历史、快速复用、local freshness | 否 |
| Zone Resolver | shared cache/control plane；wire 可携带 body、status、document iat（`documentVersion` 字段）、authority seq、effective owner，但当前 `ResolvedDocument` 只保留其中一部分 | Zone trust scope 中更强的本地证据与最新已知状态 | 当前默认否 |
| method authority Remote Resolve | 权威发布状态、owner binding、当前 body/hash | 产生本次权威全局当前/非当前判断 | 是 |

这里的“本地”是**相对于权威 Remote Resolve**而言的 local trust scope，不等于“只在当前
进程内”。Zone Resolver 可以代表整个 Zone/集群的生产级已知状态，因此它通常比 local file
cache 更强、更完整，但仍是缓存/控制面视图。

整合原则：

1. local file cache 与 Zone Resolver 不强行压成同一种 StoredMeta；通过统一的
   `VerifyContextSnapshot` 消费它们已经具备的字段。
2. snapshot 中必须保留 source 和 scope，返回值明确说明判断来自 Process/Host/Zone/Caller。
3. Zone Resolver 查询属于 resolve 的 `LocalAndZone` 路径；纯 verify 不主动访问它。
4. Zone Resolver 命中可以推进或比较 Zone scope 的“本地已知最新”，但不能仅凭 `ZoneHit`
   返回 `AuthorityFreshness::Current`。
5. 如果未来 Zone Resolver 能转发仍在有效期内、可验证的 authority-signed attestation，
   可以像 TLS stapled OCSP 一样单独定义 receipt；在该协议落地前不做这种推断。
6. 当前 local file cache 不保存 effective owner、authority seq、checked_at/valid_until 等完整
   metadata。不要为了统一接口伪造这些字段，缺什么就结构化表达缺什么。
7. 旧 cache 中的 `Published/Anchored` 只说明 body evidence 等级，不能自动升级成
   “本次已经 Remote Resolve 并确认全局当前”。
8. 负状态对称规则：Zone/local 记忆的负状态同样不产生 `AuthorityFreshness::NotCurrent`
   （NotCurrent 只来自本次 Remote Resolve）。terminal 负状态在纯 verify 中按
   `RejectedByNegativeState { scope, .. }` 硬失败；Missing/Expired 作为 scope 事实交给
   freshness policy。

## Verify 结果：分别说明有效性和真实 freshness

### VerifiedDidDocument 是报告，不是 capability

```rust
pub struct VerifiedDidDocument {
    pub subject_did: DID,
    pub doc_type: DidDocType,
    pub document: EncodedDocument,
    pub structural_owner: Option<DID>,
    pub authority_owner: Option<DID>,
    pub expected_owner: Option<DID>,
    pub declared_owner: Option<DID>,
    pub authz_owner: Option<DID>,
    pub usable_as_authz_subject: bool,
    pub revision: DocumentRevision,
    pub validity: ValidityEvidence,
    pub freshness: FreshnessEvidence,
    pub warnings: Vec<VerifyWarning>,
}
```

它可以继续作为普通 DTO 使用。是否有权写 verified cache 由进程/目录权限决定，不能依赖
“只有 name-client 能构造这个 Rust 类型”的假设。

`ValidityEvidence` 应说明本次验证实际依赖了什么：

- expected owner 来自 structural rule、local override、local cache、Zone snapshot，还是
  Remote Authority receipt；
- OwnerDocument/key 的来源；
- 是否使用 historical key；
- owner replay guard 是否执行；
- snapshot scope、generation、checked_at 和可用的 valid_until。

### revision：只以 iat 为序，version_seq 退出流程

```rust
pub struct DocumentRevision {
    pub iat: u64,
    pub content_hash: String,
}
```

比较规则（已确认）：

1. `content_hash` 相同表示同一份编码文档（`SameAsLatestKnown` / `AlreadyPresent`）。
2. `iat` 不同时，以 `iat` 决定新旧。
3. `iat` 相同、hash 不同时，返回同 revision conflict（`ConflictAtSameRevision` /
   `RejectedConflict`），不悄悄选一个。
4. `iat` 是 revision 的必备字段：文档缺 `iat` 时沿用现有补充流程
   （`exp - DEFAULT_EXPIRE_TIME` 推导，`get_doc_iat` 语义保持）；`iat` 和 `exp` 都没有、
   无法得出 iat 的文档无效（`InvalidDocument`）。
5. `version_seq` 不参与任何比较：使用者不再构造它，原有字段视作用户自定义扩展原样保留；
   JWT 强制项从 `ensure_version_seq_for_jwt` 改为“必须能得出 iat”。`mini_version_seq`
   owner replay guard 随之退役（兼容期读到时打 deprecation warning，不执行），
   anti-rollback 由 `valid_iat` 承担。iat 与 version_seq 顺序矛盾的
   `InconsistentRevision` 情形不复存在。

content hash 编码契约（已确认）：JWT 对 compact artifact 原文做 sha256；JsonLd 对
`serde_json::Value` 重序列化结果做 sha256——workspace 不启用 serde_json 的
`preserve_order`，`Value` 序列化天然是“键字典序 + 紧凑分隔符”，该前提需用防护测试固定；
不引入 JCS（RFC 8785）/URDNA2015。

### 本地已知 freshness

```rust
pub struct FreshnessEvidence {
    pub local: LocalFreshness,
    pub authority: AuthorityFreshness,
}

pub enum LocalTrustScope {
    Process,
    Host,
    Zone,
    Caller(String),
}

pub enum LocalFreshness {
    Unknown {
        scope: LocalTrustScope,
        reason: String,
    },
    FirstKnown {
        scope: LocalTrustScope,
        candidate: DocumentRevision,
    },
    SameAsLatestKnown {
        scope: LocalTrustScope,
        revision: DocumentRevision,
    },
    NewerThanLatestKnown {
        scope: LocalTrustScope,
        candidate: DocumentRevision,
        previous: DocumentRevision,
    },
    OlderThanLatestKnown {
        scope: LocalTrustScope,
        candidate: DocumentRevision,
        latest: DocumentRevision,
    },
    ConflictAtSameRevision {
        scope: LocalTrustScope,
        expected: DocumentRevision,
        candidate: DocumentRevision,
    },
}
```

“Known”表示在指定 scope 中已经验证/接受或由受信 cache/control plane 记录的状态，不表示
“网络上随便收到过”。Observed/unverified 文件不能推进 latest-known baseline。

不同 scope 可以有不同结论：同一候选可能是 Host scope 的 `FirstKnown`，同时是 Zone scope 的
`OlderThanLatestKnown`。调用方必须知道本次比较使用了哪个 scope，name-client 不替所有应用
定义唯一的全局 high-water mark。

### 权威全局 freshness

```rust
pub enum AuthorityFreshness {
    /// 本次没有执行权威 Remote Resolve。
    NotChecked,
    /// 本次权威 Remote Resolve 明确证明候选属于当前发布集合。
    Current {
        authority_seq: Option<u64>,
        /// 权威记录的当前发布文档 iat（wire `documentVersion` 的统一语义）。
        document_iat: Option<u64>,
        checked_at: u64,
        valid_until: Option<u64>,
        source: String,
    },
    /// 本次权威 Remote Resolve 明确说明候选不是当前版本或处于负状态。
    NotCurrent {
        reason: AuthorityNotCurrentReason,
        authority_seq: Option<u64>,
        /// 权威当前发布文档的 iat；Superseded 时调用方可据此比对 revision。
        current_document_iat: Option<u64>,
        checked_at: u64,
        source: String,
    },
    /// 调用方显式要求 Remote Resolve，但 authority 没有回答。
    Unavailable {
        attempted_at: u64,
        source: Option<String>,
        detail: String,
    },
}

pub enum AuthorityNotCurrentReason {
    DifferentDocument,
    Superseded,
    NegativeStatus(DocumentStatus),
}
```

规则：

- 没有经过权威 Remote Resolve，就返回 `NotChecked`；local/Zone cache 再强，也属于
  `LocalFreshness` 和 `ValidityEvidence` 的来源。
- `Current` 必须绑定候选 hash/body，不能只因为 authority 对该 DID 返回 `Active` 就成立。
- `document_iat` 即 wire 的 `documentVersion`（documentVersion = document_iat）：权威侧不引入
  独立版本序号，"当前发布文档的 iat"就是版本。候选 `iat` 小于它即 `Superseded`——吊销/替换
  语义与 owner 侧 `valid_iat` 统一在同一条 iat 轴上。
- `Current` 表示 authority 在 `checked_at` 时刻给出的判断，不表示永久当前；authority 没有
  提供 `valid_until` 时，调用方应通过 freshness policy 限制可接受的检查年龄。
- `NotCurrent` 必须区分“DID 仍 Active，但当前 body 已不同”和 revoked/missing 等负状态。
- 如果未来支持带签名和有效期的可转交 authority attestation，再单独扩展 receipt 语义。

### freshness requirement 是独立 policy

```rust
pub enum FreshnessRequirement {
    AnyValid,
    NotOlderThanLocalLatest { scope: LocalTrustScope },
    RequireAuthorityCurrent { max_age_secs: Option<u64> },
    NotOlderAndAuthorityCurrent {
        scope: LocalTrustScope,
        max_age_secs: Option<u64>,
    },
}

pub fn evaluate_freshness(
    verified: &VerifiedDidDocument,
    requirement: &FreshnessRequirement,
) -> Result<(), FreshnessPolicyError>;
```

verify 成功表示候选通过有效性验证，并返回真实 freshness 事实；是否接受由调用方单独应用
policy。这样不会再把“签名失败”“本地比它新”“没有联网查 authority”“authority 明确否定”
压成同一个 `CurrentActive` 错误。

## RTCP 使用背景（非本仓库正确性责任）

对于非 `did:dev` 的逻辑设备名，RTCP 可以按以下方式组合基础 API：

```text
Hello 携带 DeviceDocument
        ↓
RTCP 做廉价格式/大小检查与候选 key 的持钥过滤
        ↓
verify_did_document(candidate, prepared local/zone snapshot)
        ↓
RTCP 对返回的 LocalFreshness 应用自己的 high-water policy
        ↓
RTCP 完成持钥证明、授权、锁管理和原子状态推进
        ↓
按配置显式 add_cache
```

`MissingDependency` 时，RTCP 可以默认拒绝，也可以进入自己受限流保护的显式 slow path：先
resolve，再构造新的 snapshot 重试 verify。name-client 不在 verify 内替 RTCP 做这个决定。

本 TODO 只保证：

- 常规 verify 不隐式联网；
- 更旧/冲突/未知等事实可以被 RTCP 可靠识别；
- Remote Authority Current 只能由显式 resolve 路径产生；
- verify 不隐式推进任何 RTCP high-water mark。

RTCP 的 per-DID lock、并发 session、CAS、nonce、key confirmation 和 high-water 持久化测试
属于 RTCP 仓库。

## 组合便捷 API

三动词边界固定后，可以提供便捷组合：

```rust
pub async fn resolve_and_verify_did_document(...)
    -> Result<VerifiedDidDocument, ResolveVerifyError>;

pub async fn resolve_verify_and_cache_did_document(...)
    -> Result<(VerifiedDidDocument, CacheWriteOutcome), ResolveVerifyCacheError>;
```

组合 API 必须在 options/名字中暴露：

- 使用 `LocalOnly / LocalAndZone / RemoteAuthority / BestAvailable` 中哪种 resolve policy；
- 是否写 cache、写哪个 namespace；
- 返回的 authority freshness 是否来自本次 Remote Authority Resolve。

当前 `verify_did_document_jwt` 可以重命名为组合入口，或在兼容期 deprecated。不能继续让
`VerifyOptions { cache_result, ... }` 把纯 verify 和 resolve/cache 组合在同一个函数名下。

## 实现阶段

### Phase 0：固化术语和 API 契约

- [ ] 给所有 name-client DID verify/resolve/cache 入口列出 I/O、副作用和 cache 行为。
      清单必须包含 verify 中不受 `cache_result` 控制的写入：权威负状态写入 negative cache、
      Migrated 触发删除、in-TTL 快路径 replay-guard 失败触发删除。
- [ ] 固定 `ResolveSourcePolicy`，特别是 LocalOnly、LocalAndZone、RemoteAuthority 的边界。
- [ ] 明确 `VerifiedDidDocument` 是验证报告，不是 cache capability。
- [ ] 明确 authority current 只来自本次 Remote Authority Resolve；现有 cache hit 不自动升级。
- [ ] 明确通用 `verify-jwt` 是否在范围内；默认只改 DID Document verify 家族。

### Phase 1：整理 local file cache 与 Zone Resolver 的证据能力

- [ ] 列出现有 local file StoredMeta 能提供和不能提供的字段。
- [ ] 列出现有 Zone Resolver wire metadata 能提供和不能提供的字段。
- [ ] 引入统一只读 `VerifyContextSnapshot`，但不强行统一两种存储后端。
- [ ] snapshot 携带 source、scope、generation、checked_at 和可用的 valid_until。
- [ ] Zone 客户端停止丢弃 wire 已定义的 `docHash` / `migrationTarget`
      （`published_state_from_envelope` 当前将两者置 None），保留进 snapshot 供
      candidate hash 绑定与 freshness 比较使用。
- [ ] 扩展 `http_did_resolver_api.md` 的 `buckyos` 块：新增 `checkedAt` / `validUntil`
      时间维度字段（需 resolver/zone server 侧配合，先固定协议字段再排实现）。
- [ ] 固定 wire `documentVersion` 的取值语义 = 当前发布文档的 iat（documentVersion =
      document_iat），同步修订 `http_did_resolver_api.md` 与 resolver/zone server 侧实现。
- [ ] ZoneHit 只进入 Zone local freshness/validity evidence，不返回 AuthorityCurrent。
- [ ] 旧 Published/Anchored cache 只保留 body evidence 含义。

### Phase 2：拆出真正的本地 verifier

- [ ] 从现有 `verify_did_document_jwt` 拆出无网络、无写入、只消费 snapshot 的核心。
- [ ] 保留 expected owner、签名、historical key、exp、valid_iat 规则；`mini_version_seq`
      guard 退役（兼容期只警告）。
- [ ] 把现有 verify 路径的写副作用移出纯 verify：权威负状态学习归 resolve 的缓存回填，
      Migrated / replay-guard 触发的条目删除归 cache 层读写卫生或 resolve 路径。
- [ ] 新增 `VerifyError::RejectedByNegativeState { scope, status }`：terminal 负状态硬失败；
      Missing/Expired/Migrated 不进 VerifyError，转为 freshness/validity 事实。
- [ ] 自过期（`exp <= now`）归入 validity 失败（`InvalidDocument`），不再混入
      `NotCurrentActive` 一类 freshness 语义。
- [ ] snapshot 的 owner 材料证据门槛：Observed/Unverified 不得作为验签依据。
- [ ] 提供 snapshot 构建 helper（从 local cache / Zone 查询 / Remote receipt 组装），
      上游不必手工拼装。
- [ ] 重构 `verify_and_promote` 为“按 resolve policy 构建 snapshot → 纯 verify → promote
      落盘”，对外行为等价；它属于 resolve 的缓存回填路径，不违反 verify 无写入边界。
- [ ] 增加 provider/Zone spy，断言纯 verify 永远不发起查询。
- [ ] 断言纯 verify 不修改 verified、unverified 和 negative cache（含负状态/replay-guard
      触发的删除）。

### Phase 3：返回 validity、revision 和 freshness 事实

- [ ] 引入 `ValidityEvidence`、`DocumentRevision`、`LocalFreshness` 和
  `AuthorityFreshness`。
- [ ] revision 只用 `iat` + content hash；同 iat 不同 hash 表达为稳定 conflict。
- [ ] `version_seq` 退出流程：JWT 强制项从 `ensure_version_seq_for_jwt` 改为“必须能得出
      iat（iat 直接存在，或由 exp 补充推导）”；原有 version_seq 字段按用户自定义扩展
      原样透传，不参与比较与 guard。
- [ ] 固定 JWT/JsonLd content hash 契约（serde_json 键字典序序列化；加防护测试锁定
      workspace 不启用 `preserve_order`）。
- [ ] `AuthorityFreshness` 携带 `document_iat`（= wire `documentVersion`）；候选 iat 小于
      权威当前发布 iat 判定为 `NotCurrent(Superseded)`。`PublishedState.document_version`
      与 `ResolvedDocument` 的 version_id / buckyos.document_version 语义同步为文档 iat
      （`from_document` 的 `.or(version_seq)` 兜底相应改为 `.or(doc.iat)`）。
- [ ] 所有 DID Document verify 成功结果携带 validity/freshness。
- [ ] 增加独立 `evaluate_freshness` policy，不把 freshness rejection 混入 VerifyError。

### Phase 4：固定 add_cache 与文件系统协议

- [ ] 将现有 `update_did_cache` 的公开语义统一为 add observed。
- [ ] 明确函数写入与直接文件投递具有相同 namespace 语义。
- [ ] verified/Published 写入权限由目录权限和受控进程保证。
- [ ] cache 写入返回结构化 `CacheWriteOutcome`。
- [ ] `merge_allows` 从现状“version_seq 优先、iat 兜底”迁移为 iat-only 规则（**方向翻转**，
      需评估旧条目兼容）：同证据级比 iat；同 iat 同 hash → `AlreadyPresent`；同 iat 不同
      hash → `RejectedConflict`；更高证据等级仍按 rank 直接胜出（权威结果永远能翻案）。
- [ ] 在 iat-only 规则下保留命名对象（`is_named_obj_id`）“不可替换”保护的等价语义。
- [ ] Info doc_type 的 `update_time` 合并规则独立保留，明确排除在 DocumentRevision 契约外
      （Info 走 UnproofInfo/免验证信道，不属于 verify 家族）。

### Phase 5：组合 API 与兼容迁移

- [ ] 将当前隐式 resolve/cache 的 verify 入口重命名或 deprecated。
- [ ] 增加显式 `resolve_and_verify` 和 `resolve_verify_and_cache`。
- [ ] 移除或废弃 `VerifyDidDocumentJwtOptions.cache_result`。
- [ ] 明确 `ResolveSourcePolicy` 与现有 `ResolvePolicy` 字段（use_zone_resolver /
      allow_stale_cache / allow_self_signed_when_missing / local_authority_override /
      follow_migration / max_depth）的映射与归属，避免两套 policy 长期并行。
- [ ] 把 `CurrentActive` 拆成 validity evidence、freshness facts 和 requirement。
- [ ] 更新 `verify-did-document-jwt.md`、`update-did-cache.md` 和 resolve-did 文档
      （含 version_seq / mini_version_seq 退役的同步修订）。
- [ ] 给 RTCP 等上游提供组合示例，但不在本仓库实现其锁/high-water 逻辑。

## 测试要求

至少覆盖：

1. 纯 verify 在 snapshot 命中、缺依赖、验证失败时都不调用 provider/Zone Resolver。
2. 纯 verify 不写任何 cache。
3. local file snapshot 依赖齐全时返回正确 ValidityEvidence 和 expected owner。
4. Zone snapshot 返回 Zone scope 的 LocalFreshness，并保留 source/authority_seq 等已有字段。
5. ZoneHit 不返回 `AuthorityFreshness::Current`。
6. 显式 RemoteAuthority resolve 且 candidate hash/body 匹配时返回 AuthorityCurrent。
7. RemoteAuthority 明确 Active 但 current body 不同时返回 NotCurrent(DifferentDocument)。
8. 没有 Remote Resolve 时，即使命中 Published local cache，authority 仍为 NotChecked。
9. latest-known iat 为 N 时，候选 N-1 返回 OlderThanLatestKnown。
10. 同 iat、同 hash 返回 SameAsLatestKnown。
11. 同 iat、不同 hash 返回 ConflictAtSameRevision。
12. 携带 version_seq 的旧文档仍可解析，但 version_seq 不影响任何比较结果（含 iat 顺序与
    version_seq 顺序相反的文档对）；`mini_version_seq` 不再 enforce，兼容期只产生警告。
13. Observed/unverified entry 不能推进 latest-known baseline。
14. add observed 不能覆盖 verified/negative entry。
15. cache 写入能区分 Inserted、IgnoredOlder、RejectedConflict 和 BlockedByNegativeState。
16. 组合 resolve_and_verify 可以按 policy 访问 Zone/Remote；纯 verify 永远不访问。
17. snapshot 含 terminal 负状态（负缓存记忆或 Zone 负回答）时，纯 verify 返回
    `RejectedByNegativeState` 且不发起任何查询、不做任何 cache 写删。
18. 权威 Missing/Expired 不构成 VerifyError；作为事实返回后可由 `evaluate_freshness`
    按 policy 拒绝。
19. 缺 iat 但有 exp 的 JWT 按补充流程得出 iat；iat/exp 皆无时返回 InvalidDocument。
20. 候选 iat 小于权威当前发布文档 iat（wire documentVersion）时返回
    NotCurrent(Superseded)，并携带权威 `current_document_iat`。

RTCP 的并发 high-water/session 授权测试不属于本仓库验收范围。

## 待确认问题

- LocalFreshness 是否允许同时返回多个 scope 的结论，还是一次 snapshot 只选择一个主 scope？
> 只选择一个主 scope
- Host local file cache 与 Zone snapshot 同时存在时，默认选择规则是 Zone 优先，还是返回两份事实？
> Zone 优先，仍只返回一个主 scope（与上一问一致）。这与现有实现的层级一致：Zone Resolver 是
> L1、本机 did_cache 是 L2，`resolve_did_ex` 第 0 步 ZoneHit 直接短路本机 cache。Zone 无回答
> （Unknown）时才降级以 Host 作为主 scope；ValidityEvidence 如实记录本次实际使用的 scope 与来源。
- Zone Resolver 当前 wire metadata 还需要补哪些 retrieved/checked_at/valid_until 字段？
> 现有 wire（`didDocumentMetadata.buckyos`）只有 docType / documentStatus / documentVersion /
> authoritySeq / effectiveOwner / docHash / migrationTarget，没有任何时间维度字段；`retrieved`
> 一直是客户端收到回答时本地打的时间戳。需要补：`checkedAt`（该条目最近一次经权威源确认/写入
> Zone control plane 的时刻）与 `validUntil`（Zone 允许消费方视为新鲜的截止时刻）；可选补 Zone
> 自身的 snapshot generation（与权威源的 authoritySeq 区分）。另外客户端目前丢弃了 wire 已定义
> 的 `docHash` / `migrationTarget`（`zone_resolver.rs` 的 `published_state_from_envelope`），
> candidate hash 绑定与 freshness 比较需要把 docHash 保留进 snapshot。
- Zone Resolver 未来是否需要支持 authority-signed、可转交的 freshness attestation？
> 短期不需要，不排期。Zone Resolver 的信任边界就是 zone 部署边界，zone 内消费者本就信任其控制面
> 回答，签名不增加安全性；维持整合原则第 5 条"协议落地前不做 stapled 推断"。触发条件：出现需要
> 把 freshness 判断转交给不信任 Zone control plane 的消费方（跨 zone、离线转交）时，再按
> TLS stapled OCSP 模式单独定义 receipt。
- `iat` 相同而只有一边带 version_seq 时，默认应视为 conflict 还是 incomparable？
> 发生这种情况时直接算验证失败
> （已被后续"version_seq 整体退出流程"的决定覆盖：该情形不复存在；同 iat 不同 hash 一律
> ConflictAtSameRevision，效果等价于验证失败。）
- 纯 verify 遇到 snapshot 中的负状态材料时，硬失败还是作为事实返回？
> terminal（Revoked/Tombstoned）硬失败，返回 `RejectedByNegativeState { scope, status }`，
> 与现有"负状态屏蔽一切兜底"语义连续（现状负缓存只记 terminal）；Missing/Expired/Migrated
> 作为 freshness/validity 事实由 freshness policy 决定（呼应 bootstrap 答案与现有策略点②）。
- `version_seq` 在 revision 比较中的地位？
> 整体退出流程：使用者不再构造，原有字段视作用户自定义扩展，不参与任何比较与 guard；
> JWT 强制项从 `ensure_version_seq_for_jwt` 改为"必须能得出 iat"——缺 iat 沿用
> `exp - DEFAULT_EXPIRE_TIME` 补充流程（`get_doc_iat` 语义保持），iat/exp 皆无则文档无效；
> `mini_version_seq` replay guard 随之退役，anti-rollback 由 `valid_iat` 承担。
- 权威侧 `documentVersion` 与文档 iat 的关系？
> documentVersion = document_iat：权威源记录/返回的"文档版本"就是当前发布文档的 iat，不引入
> 独立版本序号，吊销/替换语义统一到 iat 轴——owner 侧 `valid_iat`（小于该值全部作废）与权威侧
> 当前发布 iat（小于它即 Superseded）用同一把尺子。`authoritySeq` 保留为权威源自身的变更序号
> （owner binding 变更等），与文档 revision 无关。

- JsonLd content hash 采用哪种 canonicalization？
> 沿用现有 `document_content_hash` 的事实契约：JWT 对 compact 原文做 sha256；JsonLd 对
> `serde_json::Value` 重序列化结果做 sha256。workspace 未启用 serde_json 的 preserve_order，
> `Value` 的 map 是 BTreeMap，序列化天然是"键字典序 + 紧凑分隔符"，已消除键序/空白差异；
> 不引入 JCS（RFC 8785）/URDNA2015。需把"不得开启 preserve_order"固定为契约并加防护测试；
> 出现非 serde_json 实现的跨实现一致性需求时再升级 JCS。
- owner binding 合法变化时，local latest-known baseline 如何分 epoch；由具体上游还是通用 helper 处理？
> 事实归通用层，策略归上游。通用层在 freshness 事实中如实返回断点信号（baseline 与本次的
> expected_owner 不一致；未来权威源提供 lineageEpoch/authoritySeq 变化时透传），唯一硬规则沿用
> resolve_did重构.md 7.1 节第 4 条：lineageEpoch 变化是信任断点，旧世代 baseline 不自动沿用到
> 新世代。是否清 baseline、如何跨 epoch 迁移由具体上游决定。注意 AuthSubject 下 detached owner
> 直接拒绝，epoch 问题实际只影响一级名字转让与 ObjectDocument 场景。
- 首次见到未公网发布的逻辑 DeviceDocument 时，bootstrap trust snapshot 从哪里来？
> 信任根是 owner 链，不需要 device 自身的发布记录：expected_owner 由 method 结构规则离线给出
> （did:bns:laptop.alice → did:bns:alice）；验签材料是 expected_owner 的 OwnerDocument——owner
> 是公网已发布的一级名字，经显式 resolve（RemoteAuthority/LocalAndZone）取得，或来自装机/激活时
> 种进 verified/ 的种子文档（现有 `insert()`/文件系统协议），zone 内亦可由 Zone Resolver 回答。
> 权威源对 device 槽位回答 Missing 属于 authority freshness 事实（现有策略点②
> `allow_self_signed_when_missing` 的显式化），是否接受由调用方 freshness policy 决定；首次接受
> 后由上游显式 add_cache 建立 FirstKnown baseline。
- 已验证但未被上游最终接受的文档是否进入 verified cache，由哪个上游策略决定？
> 由完成"最终接受"动作、显式调用 add_cache 的那一层上游决定；name-client 只保证纯 verify 不写、
> add_cache 显式、写权限由 verified/ 目录 OS 权限约束。本文 RTCP 流程已体现该答案：add_cache 排
> 在持钥证明、授权、锁管理、原子状态推进之后。对比现状：`verify_did_document_jwt` 默认
> `cache_result=true` 会在上游最终接受之前写入 Verified/Published，这正是 Phase 5 要废弃的行为。

## 验收标准

- [ ] 调用者只看函数名、options 和类型，就能判断是否可能访问 Zone/Remote、是否写 cache。
- [ ] verify 无网络、无写入，只验证调用方给出的确切文档和 snapshot。
- [ ] 返回值分别表达 validity、本地已知 freshness 和 Remote Authority freshness。
- [ ] 没有显式 Remote Authority Resolve 时，结果不会声称 authority current。
- [ ] local file cache 与 Zone Resolver 的能力差异被保留并结构化表达。
- [ ] revision 只以 iat + content hash 判定，version_seq 不参与流程，同 iat 冲突不会被隐藏。
- [ ] 应用可以独立选择 AnyValid、本地防回滚或权威当前性策略。
- [ ] add_cache 是显式动作，安全边界与文件系统 namespace 权限一致。
- [ ] 任意外部输入不能通过纯 verify 自动触发 authority 查询。
- [ ] 组合便捷 API 保留，但名字/options 明确暴露 resolve/cache 行为。
- [ ] RTCP 等上游能用这些事实实现自己的握手锁、high-water 和授权策略，而 name-client
  不越权承担这些状态机责任。

## 相关文档与实现

- [`verify-did-document-jwt.md`](./verify-did-document-jwt.md)
- [`update-did-cache.md`](./update-did-cache.md)
- [`简单介绍resolve-did.md`](./简单介绍resolve-did.md)
- [`resolve_did简化_TODO.md`](./resolve_did简化_TODO.md)
- [`src/name-client/src/verify_did_jwt.rs`](../src/name-client/src/verify_did_jwt.rs)
- [`src/name-client/src/name_client.rs`](../src/name-client/src/name_client.rs)
- [`src/name-client/src/doc_cache.rs`](../src/name-client/src/doc_cache.rs)
- [`src/name-client/src/name_query.rs`](../src/name-client/src/name_query.rs)
- [`src/name-client/src/zone_resolver.rs`](../src/name-client/src/zone_resolver.rs)
