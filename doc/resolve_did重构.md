# resolve_did 重构设计

本文描述 `resolve_did(did, doc_type)` 的新流程。目标是把早期“多个 provider 返回 DID Document，再按 trust level / iat 选一个”的模型，升级为可以表达 BNS Registry、Document tombstone/revoke、自签名文档扩散、method-scoped resolver 的统一解析框架。

## 0. 文档定位与体系升级意图

本文是一份**工程指导文档**，目标是配合 BNS 合约上线，重新梳理现有 `resolve_did` 实现的目标与边界。它聚焦解析引擎本身，不重复 `resolve-did.md` 里的基础设施愿景与 URL 体系。待 BNS 合约上线、本文描述的实现落地后，本文应与 `resolve-did.md` 合并为一份统一文档。

`resolve_did` 不是孤立的解析函数，它是 BuckyOS 去中心基础设施三项升级的交汇点：

1. **DNS 升级体系**：用 `did:bns` 解析取代 DNS 根解析，提供可扩展的根信任；`did:web` / DNS TXT 作为过渡与兼容层。
2. **CA 升级体系**：用 owner / authority 锚定的 DID Document 验证取代 CA 证书链，配合 RTCP 让可信连接不再依赖 CA 证书。
3. **核心三件套**：**BNS**（名字与发布的权威源）、**DID Document 体系**（可验证的内容与配置）、**RTCP 协议**（可信连接）。三者协同：BNS 解出 DID Document，Document 里的 key 支撑 RTCP，RTCP 取代 TLS+CA。

因此 `resolve_did` 的设计目标不只是“拿到一份文档”，而是同时承担**取代 DNS 的寻址**和**取代 CA 的信任根**两件事。本文后续的状态机、权威源、owner 递归都服务于这个目标。

## 1. 核心目标

新的解析流程需要同时解决五件事：

1. `did:method` 必须参与 resolver 选择。一个 resolver 注册时应声明自己支持哪些 DID method，只有匹配时才会被调用。
2. `trust_level` 表达 method 内的权威等级。`trust_level = 0` 是该 method 的最权威源，例如 BNS Registry 对 `did:bns`。
3. BNS 的 `resolveDocument` 结果不是简单的“有没有文档”，而是包含 `Missing / Active / Revoked / Tombstoned / Migrated / Expired` 等状态。
4. 已发布结果和未发布的自签名候选要分开。未发布文档不能覆盖正常环境中的已发布结果。
5. 测试“发布后效果”应使用本地 authority override cache，类似 `hosts` 文件，而不是放宽正常解析规则。

### 1.1 结构原则：解析是递归的，owner 是递归基

`resolve_did` 是整个系统最核心的流程，它的结构必须简单优雅：**只有一条解析流程，靠递归表达所有层级，而不是为不同 doc_type 设计不同的特殊流程。**

核心观察：任何一份文档都需要回答「用什么来验证它」。

- 普通文档 `X`：先确定该文档的 owner，再用 **owner 文档**作为验证策略源。owner 可能来自权威发布源的 `effective_owner`，也可能只来自文档自声明。要拿到 owner 文档，就是对 owner DID 递归调用 `resolve_did_document(owner_did, "owner")`。这是**递归步**。
- owner 文档：不能再回头解析另一个 owner（否则无限递归，也会产生第 6 节描述的循环信任）。它的信任根**直接来自该 DID method 的 authority**（`did:bns` 来自 Registry 的 `PublishedState`，`did:key` / `did:dev` 来自 DID 自身的自证 key）。这是**递归基**。

因此 owner 解析不是另一条流程，而是同一个 `resolve_did_document` 的递归终止条件。除了「用什么验证」这一个分叉点之外，owner 文档和普通文档共享完全相同的解析流程（查发布状态 → 取 body → hash 校验 → 验签 → 选最优 → 缓存）。下文第 9 节的伪代码据此组织。

### 1.2 为什么解析的基本单元是 `(did, doc_type)`

一个名字（Name）主要用于**内容发布**。同一个名字支持多个 doc_type，本质是「**用同一个名字发表不同类型的内容**」——同一个 `alice` 可以既是一个移动 App，又是一个网站，还可以是一个 Zone、一个用户身份。这就是为什么解析的基本单元是 `(did, doc_type)`，而不是一个 DID 对应唯一一份文档。

doc_type 解决两件事：

1. **名字权益的可扩展性**。一个名字承载的权益不是一次性定死的，而是通过不断新增 doc_type 来扩展。新增一种内容类型 = 在同一名字下新增一个 doc_type，而不是让用户为每种内容重新申请名字。
2. **以“名字”为核心的信用体系**。我们坚持把信用建立在名字上，而不是建立在每一份具体内容上——用户不必为每个内容单独选名字。在某个领域通过该名字积累的信用，有机会被带到该名字下的新类型内容上。

这与 W3C「一个 DID 解析出唯一一份 DID Document、文档内部用 `service` 数组区分用途」的取舍不同：BuckyOS 把同一名字下的不同 doc_type 当成**平级、可独立发布、共享名字信用**的多份文档。代价是各 doc_type 的版本与撤销相互独立（见第 7 节缓存规则），收益是名字权益与信用可持续扩展。

### 1.3 Document 与 Info 的分离，以及 IP 解析的演进

一个 DID 的解析结果分成两部分：

- **Document**：需要签名、参与权威发布与验证的部分（owner / zone / device / service 等配置）。本文的状态机、权威源、缓存规则都是针对 Document 的。
- **Info**：实时、易变的信息（如 DeviceInfo、运行时地址）。Info 通常**不需要签名**；链上一般**不存储** Info（个别组织可能选择存储）。

实现上，这个边界必须由 `DidResolver::requires_verification(doc_type)` 显式落地：声明为免验证的 Info 类 `doc_type` 不进入 `PublishedState / DocumentStatus` 状态机，不触发 owner 递归，也不受 `Missing / Revoked / Tombstoned` 这类 Document 门禁约束。它仍然使用第 3 节的 method-scoped resolver 选择，避免 wildcard resolver 覆盖具体 DID method，但解析结果只能作为非权威实时信息使用。

**IP 解析的演进目标**：随着 IPv6 普及、每个节点都能拥有公网固定 IP，Zone document / device document 里会直接带上固定 IP。那时 **resolve Document 就等同于 resolve IP**，不再需要独立的地址解析流程。（当前实现里地址提取的顺序和位置还不一定对，属于待校正项，也回应了 review 中提到的 “resolve-ip 流程是否纳入统一递归” 的问题。）

**过渡期**：当节点位于 NAT 后、无公网 IP、或公网 IP 动态可变时，固定 IP 假设不成立。此时仍需依赖传统的 SN（Super Node）服务作为过渡，由 SN / DNS 承担动态地址的发现与中转。因此 SN 返回的地址不改变 Document 的权威性。

### 1.4 与 W3C DID Core / DID Resolution 的术语对齐

本次重构是 breaking change，应尽量把对外名词对齐到 W3C DID Core 和 DID Resolution，方便未来和通用 DID 工具、DIF Universal Resolver、HTTP binding 互操作。但这里要保留一个边界：W3C DID Core 的默认模型是 `resolve(did, resolutionOptions) -> (didResolutionMetadata, didDocument, didDocumentMetadata)`，一个 DID 解析出一份 DID Document；BuckyOS 的核心模型是 `(did, doc_type)`，同一个名字下可以有多份平级、独立版本和独立撤销的文档。

因此对齐策略是：

1. **对外结果结构采用 W3C 三段式 metadata**。`resolve_did_ex` 返回的 `ResolvedDocument` 应显式拆成 `resolution_metadata`、`document`、`document_metadata` 三层。当前散落的 `warnings`、resolver 选择、cache 使用、authority 证明、transport 信息属于 `resolution_metadata`；document status、version、canonical/alias、deactivation、method proof 属于 `document_metadata`。
2. **`doc_type` 是 BuckyOS 扩展语义**。默认 DID Document 可按 W3C `didDocument` 暴露；其它 `doc_type` 可以理解成 BuckyOS 的 resolution option（例如 `buckyos:docType`），或在 HTTP 互操作层映射成 DID URL dereferencing 返回的 resource。不要在文档里声称所有 `doc_type` 都是 W3C DID Core 意义上的同一份 DID Document。
3. **method-scoped resolver 对齐 DID method resolver / driver 模型**。`MethodMatcher::Exact(["bns"])` 可以类比 DIF Universal Resolver 的 per-method driver 注册；W3C 规范要求 resolver 至少支持一个 DID method，但不规定本地 driver registry 形态。
4. **错误与负状态优先使用 W3C error vocabulary**。内部仍可保留 `ResolveError` enum，但要能稳定投影到 W3C DID Resolution v0.3 的 error URI；兼容老 DID Core 1.0 文档时，可同时保留 camelCase alias。

推荐的 typed result 形态：

```rust
struct ResolvedDocument {
    document: EncodedDocument,
    resolution_metadata: DidResolutionMetadata,
    document_metadata: DidDocumentMetadata,
}

struct DidResolutionMetadata {
    content_type: Option<String>,
    retrieved: Option<u64>,
    resolver_id: Option<String>,
    authority_rank: Option<i32>,
    cache_status: Option<CacheStatus>,
    warnings: Vec<ResolveWarning>,
    error: Option<DidResolutionError>,
}

struct DidDocumentMetadata {
    created: Option<u64>,
    updated: Option<u64>,
    deactivated: Option<bool>,
    version_id: Option<String>,
    next_version_id: Option<String>,
    canonical_id: Option<DID>,
    equivalent_ids: Vec<DID>,

    // BuckyOS 扩展字段，避免把 per-doc_type 状态误写成 DID-level 状态。
    buckyos: BuckyOSDocumentMetadata,
}

struct BuckyOSDocumentMetadata {
    doc_type: String,
    document_status: Option<DocumentStatus>,
    document_version: Option<u64>,
    previous_version: Option<u64>,
    lineage_epoch: Option<u64>,
    authority_seq: Option<u64>,
    proof_root: Option<Hash>,
}
```

关键映射规则：

| BuckyOS 概念 | W3C/DIF 对齐 | 注意事项 |
| --- | --- | --- |
| `resolve_did_ex` | DID Resolution `resolve()` result | 返回结构按 `didResolutionMetadata / didDocument / didDocumentMetadata` 三段式组织。 |
| `MethodMatcher::Exact(["bns"])` | per DID method resolver / Universal Resolver driver | 这是工程注册模型，不是 W3C Core 数据模型的一部分。 |
| `warnings` | `didResolutionMetadata` | 例如 `LocalAuthorityOverride`、`SignedByHistoricalKey`、`PendingActivation` 都是解析过程信息。 |
| `Missing` | `https://www.w3.org/ns/did#NOT_FOUND` / `notFound` | 只能用于权威源确认不存在；transport error 不能伪装成 Missing。 |
| `resolvers.is_empty()` | `https://www.w3.org/ns/did#METHOD_NOT_SUPPORTED` / `methodNotSupported` | 如果没有支持该 DID method 的 resolver，不应返回普通 NotFound。 |
| `canonicalize_did` 失败 | `https://www.w3.org/ns/did#INVALID_DID` / `invalidDid` | 这是输入 DID 语法或 canonical form 错误。 |
| body 格式或签名结构非法 | `https://www.w3.org/ns/did#INVALID_DID_DOCUMENT` | 包括解析出非 DID Document 或关键字段不满足约束。 |
| `Tombstoned` / `Revoked` | `didDocumentMetadata.deactivated = true` 或 BuckyOS extension | 只有当状态表示整个 DID/name 被停用时才映射为 W3C `deactivated`；如果只是某个 `doc_type` 的终止状态，应放在 `buckyos.document_status`，避免污染 DID-level 语义。 |
| `document_status = None` | 无 DID Resolution 标准状态；BuckyOS extension 明确置空 | 表示这个结果没有经过 `PublishedState / DocumentStatus` 状态机，典型场景是第 9 节 `resolve_unauthenticated_info`。调用方不能把它当作 `Active`；Info 消费方应改看 Info 自身字段，例如 `iat`、`ttl`、`source_rank`、`resolver_id` 和 `cache_status`。 |
| `Migrated` / alias | `canonicalId` / `equivalentId` | 只有同一 DID method 内、由 method 规范保证逻辑等价时才能使用。跨 method 迁移或弱别名应使用 BuckyOS extension，或在 DID Document 中使用 `alsoKnownAs`。 |
| `document_version` | `versionId` | W3C 要求 ASCII string，对外可把 `u64` 渲染成字符串。 |
| `previous_version` | BuckyOS `previousVersionId` extension | W3C `nextVersionId` 表示“当前解析版本之后的下一版”，不是 previous；解析历史版本时，如果 Registry 能证明后一版，才填 `nextVersionId`。 |

参考规范：

- [W3C DID Resolution v0.3](https://www.w3.org/TR/did-resolution/)
- [W3C DID Core 1.0](https://www.w3.org/TR/did-1.0/)
- [DIF Universal Resolver](https://github.com/decentralized-identity/universal-resolver)

## 2. trust_level 语义

沿用当前代码的排序语义：

```text
trust_level 数字越小越权威。
0 是当前 did:method 的 method authority。
更大的数字表示更弱的权威或更普通的候选传播源。
```

建议在新代码中把内部概念命名为 `authority_rank` 或 `resolver_rank`，避免“等级越高越权威”和当前数字排序产生歧义。

推荐分层：

```rust
enum AuthorityRank {
    MethodAuthority = 0,        // BNS Registry, did:web canonical endpoint
    MethodDelegated = 16,       // method 明确授权的辅助 resolver
    OwnerAuthorized = 64,       // owner/zone/SN 授权源
    SelfSignedGossip = 128,     // SN/DHT/cache/relay 传播自签名候选文档
    LocalHint = 256,            // 本地 hint、历史 cache
}
```

`trust_level` 只在同一个 DID method 的解析空间内比较。不同 method 的 resolver 不应互相竞争。

## 3. Resolver 注册模型

当前 `NsProvider::query_did` 只接收 DID 并返回 `EncodedDocument`，无法表达 method 匹配和状态语义。新的注册模型应显式声明能力：

```rust
struct ResolverRegistration {
    id: String,
    methods: MethodMatcher,
    trust_level: i32,
    caps: ResolverCaps,
    resolver: Box<dyn DidResolver>,
}

enum MethodMatcher {
    Exact(Vec<String>),     // ["bns"], ["web"], ["dev"]
    Any,                   // 只允许纯传输/候选源使用
}

struct ResolverCaps {
    published_state: bool,      // 能返回发布状态，如 BNS ResolveResult
    document_body: bool,        // 能根据 DocumentRef 拉取文档原文
    self_signed_candidate: bool,// 能返回自签名候选文档
    unauthenticated_info: bool, // 能返回不参与 owner 信任链的 Info 类内容
    negative_state: bool,       // 能表达 Revoked/Tombstoned/Missing
}
```

匹配规则：

```rust
fn match_resolvers(did: &DID, doc_type: &str) -> Vec<ResolverRegistration> {
    registry
        .iter()
        .filter(|r| r.methods.matches(&did.method))
        .sorted_by_key(|r| r.trust_level)
        .collect()
}
```

## 4. Resolver 返回语义

resolver 不应只返回 `EncodedDocument`。它应返回“证据”：

```rust
enum ResolveEvidence {
    PublishedState(PublishedState),
    AnchoredDocumentBody(DocumentBody),
    SelfSignedCandidate(DocumentBody),
    UnauthenticatedInfo(DocumentBody),
    Negative(NegativeState),
    NotFound, // 只表示当前 resolver 未找到；权威 Missing 才能映射到 W3C NOT_FOUND。
    TransportError(ResolveTransportError),
}
```

`UnauthenticatedInfo` 用于 method resolver 显式声明为“不参与 owner 信任链”的 `doc_type`，典型例子是 DeviceInfo 或运行时地址信息。这类证据允许 body 使用 `EncodedDocument::JsonLd` 编码，不要求、也不会尝试 owner-key 验签；上层调用者（例如 `resolve_ips` 的地址合并逻辑）可以自行决定如何使用它，但这不改变该内容“不是权威 Document 来源”的性质。

其中 BNS 的发布状态可以映射为：

```rust
struct PublishedState {
    did: DID,
    doc_type: String,

    name_status: NameStatus,
    document_status: DocumentStatus,

    document_ref: Option<DocumentRef>,
    document_version: u64,
    previous_version: Option<u64>,
    next_version: Option<u64>,

    effective_owner: Principal,
    owner_source: OwnerSource,
    authority_root: Hash,
    authority_seq: u64,

    effective_controller: Option<Principal>,
    lineage_epoch: u64,
    proof_root: Option<Hash>,

    canonical_id: Option<DID>,
    equivalent_ids: Vec<DID>,
    migration_target: Option<DID>,
}

enum DocumentStatus {
    Missing,
    Active,
    Revoked,
    Expired,
    Migrated,
    Tombstoned,
}
```

`PublishedState` 需要能回答 `effective_owner_at(iat)`。对 BNS 这类 Registry，可以通过当前状态、历史版本或事件日志计算签发时刻的 owner；如果某个 method 无法提供历史 owner，只能退化为使用当前 owner 或拒绝需要历史一致性校验的文档。

`Revoked` 和 `Tombstoned` 是强负状态。它们不是普通 `NotFound`，不能被 cache、SN 或自签名文档绕过。

把 `PublishedState` 转成对外 `DidDocumentMetadata` 时要遵循第 1.4 节的边界：`document_version` 渲染为 W3C `versionId`，`next_version` 只有在确实知道后继版本时才渲染为 `nextVersionId`，`previous_version` 保留为 BuckyOS extension；`canonical_id / equivalent_ids` 只有在同 method 强等价时才填入 W3C `canonicalId / equivalentId`，否则保留在 BuckyOS metadata 或 `migration_target` 中。

## 5. 发布语义与权威源

权威源的核心意义不是“它的文档签名更真”，而是“它承载了发布动作”。DID Document 的构造和发布是两个不同动作：

```text
构造 Document
  -> 使用 DID/Owner 协议中的签名 key
  -> 证明这份内容由 owner 授权生成

发布 Document
  -> 使用目标 resolver / 平台要求的发布权限
  -> 区块链可能是 EVM 签名，中心化平台可能是账号/session/服务端认证
  -> 证明这份内容已经进入该 resolver 的公开结果
```

发布权限应当大于等于构造权限。一个签名合法的 Document，如果没有发布到使用者当前信任的 resolver 中，在正常环境里不应覆盖该 resolver 已发布的结果。

因此：

1. 上链不是特殊的验证规则，而是一种强发布路径。
2. BNS Registry、did:web canonical endpoint、SN authority service、中心化 resolver 都可以是发布路径。
3. `trust_level = 0` 表示当前 `did:method` 的最高等级发布源。
4. 如果某个 `(did, doc_type)` 已经在某个权威源发布过，后续更新原则上也应发布到同一语义层级的源，才能对正常使用者生效。
5. 未发布的签名文档主要用于 staging、测试、离线交换或没有权威发布记录时的 fallback。

这可以避免测试环境中的签名 Document 意外流出后，在正常环境中生效。

### 5.1 Owner 判定规则

给定一份 DID Document，确定其 owner 有两个来源：

1. 文档内部的 owner/controller/issuer 等自声明。
2. DID method 的权威发布源。如果该 DID 存在权威验证源，例如 BNS Registry，则权威源可以直接返回该 DID 的 `effective_owner`、`owner_source`、`authority_root`。

二者不能冲突。通用规则是：

```text
if method authority can resolve owner(did, iat):
    owner_from_authority = authority.effective_owner_at(iat)
    owner_from_document = document.declared_owner()
    require owner_from_document == owner_from_authority
    owner = owner_from_authority
else:
    owner = owner_from_document
```

这里的比较点是文档的 `iat`。文档在签发时刻声明的 owner，必须和该时刻权威源记录的 owner 一致；否则该文档非法。BNS 文档中的 owner/controller 字段也遵循这个原则：文档内部声明不能反向改变 Registry owner，只能被 resolver 用来校验它是否写对。

因此，解析普通文档时不能机械地解析“同一个 DID 的 owner 文档”。正确流程是先根据发布状态和文档声明确定 owner DID，再递归解析该 owner DID 的 owner 文档。

## 6. Owner Config 是验证策略源

Owner Config 不属于普通传播路径。它是后续 DID Document 是否可接受的验证策略源，因此必须从该 DID method 的权威源取得，或由权威源明确 anchor。

Owner Config 至少应能表达：

```rust
struct OwnerDocumentPolicy {
    // 一键否决此时间点之前签发的所有文档。
    revoke_before_iat: Option<u64>,

    // 如果权威发布源返回 Missing，是否允许进入自签名 fallback。
    allow_self_signed_when_missing: HashMap<String, bool>,

    // 如果权威发布源不可达，是否允许使用已经验证过的本地结果。
    allow_cache_when_authority_unavailable: HashMap<String, bool>,

    // 对可达性敏感文档的发布保护。
    reachability_sensitive: HashMap<String, ReachabilityPolicy>,
}
```

基本语义：

1. Owner Config 自身的获取不能依赖普通候选传播路径，否则会出现用未验证策略决定后续验证规则的循环信任。在递归模型里，这一约束不是一段散文，而是递归调用 owner 时收紧的 policy（见第 9 节 `policy.for_authority_lookup()`）：禁止 self-signed / gossip fallback，只接受 `trust_level = 0` 的权威发布源或权威 anchor。
2. `revoke_before_iat` 是 owner 级全局撤销门槛。候选文档的 `iat <= revoke_before_iat` 时，即使签名曾经合法，也不得作为当前有效文档返回。
3. Owner 正常 key rotation 不会自动否决旧 key 在历史上合法签发的文档。若 owner 要否决旧文档，应通过 `revoke_before_iat` 或更具体的 revocation policy 表达。
4. owner 解析是递归基：解析 `doc_type = "owner"` 时不再回头取 owner_ctx，而是直接用 method authority 作为验证根。`effective_owner` 指向另一个 Principal 时会继续递归到该 Principal 的 owner 文档，因此需要带 `(did, doc_type)` 访问集和深度上限防环路，`did == owner` 的自指情况直接落到递归基。

## 7. Cache 规则

cache 分四类：

```rust
struct DidCacheEntry {
    // 来自真实发布源的状态，例如 BNS ResolveResult。
    published_state: Option<CachedPublishedState>,

    // 已验证过、可作为 fallback 的普通缓存。
    verified_cache: Vec<CachedVerifiedDocument>,

    // 不参与 owner 验证链的实时 Info 缓存，只能服务免验证路径。
    unauthenticated_info_cache: Vec<CachedUnauthenticatedInfo>,

    // 本地测试或运维显式注入的发布模拟。
    local_authority_override: Option<LocalAuthorityOverride>,
}
```

### 7.1 published_state cache

保存 BNS `ResolveResult`、document status、version、contentHash、owner resolution、proofRoot。

规则：

1. `Revoked / Tombstoned` 可以缓存，并且会屏蔽旧 positive cache。
2. `Active + contentHash` 可以缓存。返回 body 前仍需确认 body hash 匹配。
3. 更高版本的 `DocumentState.version` 覆盖低版本。
4. `lineageEpoch` 变化是信任断点。旧世代的 positive cache 不能自动沿用到新世代。
5. Owner Config policy 和 `revoke_before_iat` 应独立缓存，并参与所有文档的重新验证。

### 7.2 verified_cache

保存已经通过 owner key 验签的文档。它只能在没有权威发布结果，或权威发布源不可达且 policy 明确允许时使用。

规则：

1. 如果权威源返回 `Active / Revoked / Tombstoned / Migrated`，普通 verified cache 不得覆盖。
2. 如果权威源返回 `Missing`，是否允许使用 verified cache 由 Owner Config 决定。
3. 如果权威源只是网络不可达，是否允许使用 verified cache 由 strictness policy 和 Owner Config 决定。
4. 如果 owner authority key 变化，依赖旧 key 验证的缓存需要根据历史 key 状态和当前 revoke policy 重新验证。

### 7.3 local_authority_override

`local_authority_override` 用于测试和运维，类似传统系统的 `hosts` 文件。它是环境本地的 Document 发布模拟，不是协议传播路径，也不用于 Info 轻量路径；Info 的本地覆盖应表现为本地 info resolver 或 `unauthenticated_info_cache`。

规则：

1. 只能由本地管理员、测试框架或显式运维命令写入。
2. 必须带有 scope，例如 machine、zone、test-env、CI job。
3. 默认不得导出、广播或同步到普通 cache。
4. 可以设置不过期，或设置比普通 cache 更长的测试 TTL。
5. resolver 返回时必须带 `LocalAuthorityOverride` warning，方便 UI 和日志识别。
6. 在测试环境中，它可以被当作该环境的最高优先级发布结果。

通过这种方式，可以在上线前把新 Document 写入测试环境 cache，模拟“已经从权威源发布”的效果。测试通过后，再执行真正的链上或平台发布。

### 7.4 unauthenticated_info_cache

`unauthenticated_info_cache` 只保存 `requires_verification(doc_type) == false` 的 Info 类结果，例如 DeviceInfo 或运行时地址。它不参与 owner 验签，不得提升为 `verified_cache`，也不得用于 Document fallback。

规则：

1. 只按 Info 自身协议字段判断可用性，例如 `iat / ttl / source_rank`。
2. 不能被 `PublishedState::Missing`、Owner Config fallback policy 或 `revoke_before_iat` 间接门控。
3. 如果实时 resolver 可达，应优先使用实时返回；cache 只作为离线重连或短 TTL 加速手段。
4. 返回 cache 命中时必须在 `resolution_metadata.warnings` 或 `cache_status` 中标明它是 unauthenticated info cache。

## 8. 文档选择规则

对需要验证的 Document，正常环境的选择顺序：

```text
1. local_authority_override
   -> 仅限本地测试/运维显式启用的环境。

2. 最高 trust_level 的匹配发布源
   -> 返回 Active/Revoked/Tombstoned/Migrated/Missing 等状态。

3. verified_cache / self-signed fallback
   -> 只在权威源 Missing 或不可达且 policy 允许时使用。
```

在同一个发布源内部，如果同时拿到多个合法 body，使用稳定排序：

```rust
fn compare_published_body(a: &VerifiedDocument, b: &VerifiedDocument) -> Ordering {
    cmp_evidence_rank(a.evidence_kind, b.evidence_kind)
        .then_with(|| cmp_optional_version_seq(a.version_seq, b.version_seq))
        .then_with(|| cmp_optional_iat(a.iat, b.iat))
        .then_with(|| a.content_hash.cmp(&b.content_hash))
}
```

`cmp_evidence_rank` 必须优先于 `version_seq / iat`。同一个发布源内部，`AnchoredDocumentBody` 的真实性来自权威源的写入权限保证和 `content_hash` 锚定，`SelfSignedCandidate` 只能靠自身签名自证，因此排序应满足 `AnchoredDocumentBody > SelfSignedCandidate`。否则在“不同 resolver 对同一 `(did, doc_type)` 一个返回已锚定 body、一个返回自签名候选”的混合场景里，合并结果会被 `version_seq / iat` 打平后变成未定义。

普通 self-signed fallback 也可以按同样规则在候选之间选择，但它不能覆盖已发布结果。

免验证 Info 不使用本节的 Document 发布源排序和 `compare_published_body`，它走第 9 节 `resolve_unauthenticated_info` 的轻量选择规则。

签名合法性的判断点是文档的 `iat`：

```text
document.iat = T
  -> 查询 T 时刻 owner authority key 是否有效
  -> 验证签名是否由当时有效 key 产生
  -> 再应用当前 Owner Config 的 revoke_before_iat / lineage / doc_type policy
```

resolver 可以把 `SignedByHistoricalKey`、`KeyRotatedAfterIat` 等信息放进 `resolution_metadata.warnings`，供上层 UI 或业务策略决定是否提示或拒绝。

## 9. 核心伪代码

对需要验证的 Document，整个流程只有一条路径。owner 和普通文档共用它，区别只在第 1 步「确定验证根」的那个分叉：owner 走递归基（method authority），其它 doc_type 走递归步（递归解析 owner 文档）。除此之外，从查发布状态到选最优文档完全一致。

声明为免验证的 Info 类 `doc_type` 是这条 Document 流程的前置分流：它不属于第 1.3 节定义的状态机范围，必须在查询 `PublishedState` 之前跳到轻量路径。

```rust
async fn resolve_did_document(
    did: DID,
    doc_type: Option<&str>,
    policy: ResolvePolicy,
) -> Result<ResolvedDocument, ResolveError> {
    let did = canonicalize_did(did)?;
    let doc_type = canonicalize_doc_type(doc_type)?;
    let cache_entry = cache.load(&did, &doc_type);

    let resolvers = resolver_registry.match_method(&did.method);
    if resolvers.is_empty() {
        return Err(ResolveError::MethodNotSupported {
            method: did.method.clone(),
        });
    }
    let method_resolver = method_resolver(&did.method);
    let needs_verification = method_resolver.requires_verification(&doc_type);

    if !needs_verification {
        // Info 类内容不属于 Document 状态机范围：不查 PublishedState，
        // 不要求 owner 递归，不受 Missing/Revoked/Tombstoned 门禁约束。
        // 仍然使用 method-scoped resolver 选择，只是跳过验证/权威链。
        return resolve_unauthenticated_info(
            &did,
            &doc_type,
            &resolvers,
            &cache_entry,
            &policy,
        ).await;
    }

    // 0. 本地测试/运维覆盖，语义类似 hosts 文件。只对 Document 路径生效，对 owner 同样适用。
    if let Some(local) = cache_entry.local_authority_override {
        let resolved = verify_local_authority_override(&did, &doc_type, local).await?;
        return Ok(resolved.with_warning(ResolveWarning::LocalAuthorityOverride));
    }

    // 1. 以下只对需要验证的 doc_type 执行。
    // 查询最高等级的发布源。发布源返回的是状态，而不是普通候选。
    let published = resolve_published_state(
        &did,
        &doc_type,
        &resolvers,
        cache_entry.published_state.as_ref(),
        &policy,
    ).await;

    match published {
        Ok(state) => match state.document_status {
            DocumentStatus::Revoked | DocumentStatus::Tombstoned => {
                cache.store_published_state(&did, &doc_type, &state);
                cache.evict_positive_documents(&did, &doc_type);
                return Err(ResolveError::TerminalDocumentState(state));
            }

            DocumentStatus::Migrated => {
                cache.store_published_state(&did, &doc_type, &state);
                if policy.follow_migration {
                    return resolve_did_document(state.alias_target_did()?, Some(&doc_type), policy).await;
                }
                return Err(ResolveError::Migrated(state));
            }

            DocumentStatus::Active => {
                let doc_ref = state.document_ref
                    .as_ref()
                    .ok_or(ResolveError::InvalidAuthorityState("active without document_ref"))?;

                let bodies = fetch_document_bodies(
                    doc_ref,
                    &did,
                    &doc_type,
                    &resolvers,
                    &cache_entry,
                ).await;

                let mut verified = Vec::new();
                let mut warnings = Vec::new();
                for body in bodies {
                    if hash(&body.bytes) != doc_ref.content_hash {
                        continue;
                    }

                    match body.evidence_kind() {
                        EvidenceKind::AnchoredDocumentBody => {
                            // 已被 PublishedState.document_ref.content_hash 锚定，写入权限由权威源保证。
                            // 签名校验是否强制由 policy 决定；JsonLd / Jwt 均可作为合法编码。
                        }
                        EvidenceKind::SelfSignedCandidate => {
                            // self-signed 语义上必须能验证，即 doc.is_proof() == true。
                            // JsonLd 结构上不可能携带签名，属于证据契约违规。
                            if !body.doc.is_proof() {
                                warnings.push(ResolveWarning::EvidenceContractViolation {
                                    evidence: "SelfSignedCandidate",
                                    reason: "unsigned JsonLd body",
                                });
                                continue;
                            }
                        }
                        EvidenceKind::UnauthenticatedInfo => {
                            warnings.push(ResolveWarning::EvidenceContractViolation {
                                evidence: "UnauthenticatedInfo",
                                reason: "doc_type requires verification",
                            });
                            continue;
                        }
                        _ => {}
                    }

                    // 唯一的分叉点在这里：确定“用什么验证这份具体文档”。
                    // 对普通文档，先从 body 自声明和 PublishedState 的 owner-at-iat
                    // 一致性检查得到 owner，再递归解析该 owner 的 owner 文档。
                    // 对 owner 文档，resolve_verification_root_for_document 会落到 method authority。
                    let parsed = parse_document_claims(&body.bytes)?;
                    let verifier = resolve_verification_root_for_document(
                        &did,
                        &doc_type,
                        &parsed,
                        Some(&state),
                        &policy,
                    ).await?;
                    let owner_policy = verifier.owner_document_policy();

                    if let Ok(doc) = verify_document_body(
                        &did,
                        &doc_type,
                        &body.bytes,
                        &verifier,
                        &owner_policy,
                    ) {
                        verified.push(VerifiedDocument::from_published_body(doc, body, &state));
                    }
                }

                let best = verified
                    .into_iter()
                    .max_by(compare_published_body)
                    .ok_or(ResolveError::PublishedBodyNotFound(state.clone()))?;

                cache.store_published_document(&did, &doc_type, &state, &best);
                return Ok(ResolvedDocument::from_verified(did, doc_type, best, Some(state))
                    .with_warnings(warnings));
            }

            DocumentStatus::Missing => {
                cache.store_published_state(&did, &doc_type, &state);
                let fallback_policy = resolve_fallback_policy_from_published_owner(
                    &did,
                    &doc_type,
                    Some(&state),
                    &policy,
                ).await?;
                if !fallback_policy.allow_self_signed_when_missing(&doc_type, &policy) {
                    return Err(ResolveError::Missing(state));
                }
            }

            DocumentStatus::Expired => {
                cache.store_published_state(&did, &doc_type, &state);
                let fallback_policy = resolve_fallback_policy_from_published_owner(
                    &did,
                    &doc_type,
                    Some(&state),
                    &policy,
                ).await?;
                if !fallback_policy.allow_cache_when_expired(&doc_type, &policy) {
                    return Err(ResolveError::Expired(state));
                }
            }
        },

        Err(ResolveError::AuthorityUnavailable(err)) => {
            let fallback_policy = resolve_fallback_policy_from_published_owner(
                &did,
                &doc_type,
                None,
                &policy,
            ).await?;
            if !fallback_policy.allow_cache_when_authority_unavailable(&doc_type, &policy) {
                return Err(ResolveError::AuthorityUnavailable(err));
            }
        }

        Err(err) => return Err(err),
    }

    // 3. 只有在 Missing/Expired/AuthorityUnavailable 且 policy 允许时，
    // 才进入普通 verified cache / self-signed fallback。
    let candidates = collect_verified_fallback_candidates(
        &did,
        &doc_type,
        &resolvers,
        &cache_entry,
    ).await;

    let best = choose_best_verified_fallback(
        &did,
        &doc_type,
        candidates,
        &policy,
    )?;

    cache.store_verified_cache(&did, &doc_type, &best);
    Ok(ResolvedDocument::from_verified(did, doc_type, best, None))
}
```

免验证 Info 的轻量路径只处理 `UnauthenticatedInfo` 证据。它不读取 `PublishedState`，不进入 `DocumentStatus::Missing` 分支，不调用 `resolve_fallback_policy_from_published_owner`，也不使用第 7.2 节的 `verified_cache` 池：

```rust
async fn resolve_unauthenticated_info(
    did: &DID,
    doc_type: &str,
    resolvers: &[ResolverRegistration],
    cache_entry: &DidCacheEntry,
    policy: &ResolvePolicy,
) -> Result<ResolvedDocument, ResolveError> {
    let mut warnings = Vec::new();

    for group in group_by_trust_level(resolvers) {
        let info_resolvers = group
            .iter()
            .filter(|r| r.caps.unauthenticated_info)
            .collect::<Vec<_>>();

        if info_resolvers.is_empty() {
            continue;
        }

        let results = query_unauthenticated_info_group_concurrently(
            info_resolvers,
            did,
            doc_type,
        ).await;

        let mut group_candidates = Vec::new();
        for body in results.bodies {
            if body.evidence_kind() != EvidenceKind::UnauthenticatedInfo {
                warnings.push(ResolveWarning::EvidenceContractViolation {
                    evidence: body.evidence_kind().as_str(),
                    reason: "unauthenticated info path only accepts UnauthenticatedInfo",
                });
                continue;
            }
            group_candidates.push(UnauthenticatedDocument::from_body(body));
        }

        if let Some(best) = choose_best_unauthenticated_info(group_candidates, policy) {
            return Ok(ResolvedDocument::from_unauthenticated_info(did, doc_type, best)
                .with_warnings(warnings));
        }
    }

    if let Some(cached) = cache_entry.usable_unauthenticated_info(doc_type, policy) {
        return Ok(ResolvedDocument::from_unauthenticated_info(did, doc_type, cached)
            .with_warning(ResolveWarning::UnauthenticatedInfoCache));
    }

    Err(ResolveError::InfoNotFound {
        did: did.clone(),
        doc_type: doc_type.to_string(),
    })
}
```

`choose_best_unauthenticated_info` 可以按 Info 自身协议字段排序，例如 `iat / ttl / source_rank / content_hash`，但不能复用 `compare_published_body`，因为它不比较 Document 证据等级，也不表示 owner 授权。

`ResolvedDocument::from_unauthenticated_info` 必须把 `document_metadata.buckyos.document_status` 填为 `None`，同时不要把 `didDocumentMetadata.deactivated` 强行写成 `false`。`None` 是对外契约的一部分：它表示调用方拿到的是未经过 Document 状态机的 Info 结果，不能按 `DocumentStatus::Active` 处理。

验证根用一个枚举统一表达，递归基和递归步只是它的两个变体：

```rust
enum VerificationRoot {
    // 递归基：信任根来自 method authority，由 PublishedState / 自证 key 提供。
    MethodAuthority,
    // 递归步：信任根来自递归解析得到的 owner 文档。
    Owner(OwnerContext),
}

impl VerificationRoot {
    fn owner_document_policy(&self) -> OwnerDocumentPolicy { /* ... */ }
}

async fn resolve_verification_root_for_document(
    did: &DID,
    doc_type: &str,
    claims: &DocumentClaims,
    published: Option<&PublishedState>,
    policy: &ResolvePolicy,
) -> Result<VerificationRoot, ResolveError> {
    if method_resolver(did.method).is_owner_root(did, doc_type, published) {
        return Ok(VerificationRoot::MethodAuthority);
    }

    let declared_owner = claims.owner_did()?;

    if let Some(state) = published {
        let owner_at_iat = state.effective_owner_at(claims.iat)?;
        if declared_owner != owner_at_iat {
            return Err(ResolveError::OwnerConflict {
                declared_owner,
                authority_owner: owner_at_iat,
                iat: claims.iat,
            });
        }
    }

    let owner = resolve_did_document(
        declared_owner.clone(),
        Some("owner"),
        policy
            .for_authority_lookup()
            .descend(&declared_owner, "owner")?,
    ).await?;

    Ok(VerificationRoot::Owner(owner.into_owner_context()))
}
```

这样原设计里的 `resolve_owner_context_from_authority` 和 `resolve_owner_document_policy` 两个独立函数都不再需要：前者被 `resolve_did_document` 的递归取代，后者从递归返回的 owner 文档里直接得到。

## 10. 发布状态查询伪代码

```rust
async fn resolve_published_state(
    did: &DID,
    doc_type: &str,
    resolvers: &[ResolverRegistration],
    cached_published: Option<&CachedPublishedState>,
    policy: &ResolvePolicy,
) -> Result<PublishedState, ResolveError> {
    let mut transport_errors = Vec::new();

    for group in group_by_trust_level(resolvers) {
        let published_resolvers = group
            .iter()
            .filter(|r| r.caps.published_state)
            .collect::<Vec<_>>();

        if published_resolvers.is_empty() {
            continue;
        }

        let results = query_group_concurrently(published_resolvers, did, doc_type).await;

        if let Some(state) = choose_published_state(results.published_states) {
            return Ok(merge_with_cached_published(cached_published, state)?);
        }

        if let Some(negative) = choose_negative_state(results.negatives) {
            return Ok(published_state_from_negative(negative));
        }

        transport_errors.extend(results.transport_errors);

        // 如果本 trust group 明确 NotFound，但不是强负发布状态，继续查更低 rank。
    }

    if let Some(cached) = cached_published {
        if cached.is_usable_under(policy) {
            return Ok(cached.to_published_state());
        }
    }

    if policy.allow_self_signed_when_authority_unavailable {
        return Ok(PublishedState::unavailable_fallback_allowed(did, doc_type));
    }

    Err(ResolveError::AuthorityUnavailable {
        did: did.clone(),
        doc_type: doc_type.to_string(),
        transport_errors,
    })
}
```

## 11. 与当前实现的迁移建议

### 11.1 保留兼容 API

当前 API：

```rust
pub async fn resolve_did(did: &DID, doc_type: Option<&str>) -> NSResult<EncodedDocument>
```

可以保留为兼容层：

```rust
pub async fn resolve_did(did: &DID, doc_type: Option<&str>) -> NSResult<EncodedDocument> {
    let result = resolve_did_ex(did, doc_type, ResolvePolicy::default()).await?;
    Ok(result.document)
}
```

新增 typed API：

```rust
pub async fn resolve_did_ex(
    did: &DID,
    doc_type: Option<&str>,
    policy: ResolvePolicy,
) -> NSResult<ResolvedDocument>
```

`resolve_did_ex` 是对外入口，内部直接调用第 9 节的递归函数 `resolve_did_document`。外部调用者不需要、也不应该单独解析 owner —— owner 解析是 `resolve_did_document` 在 `doc_type = "owner"` 时的递归层，由内部自动完成。

`ResolvedDocument` 不应只是 `EncodedDocument` 的薄包装。它是第 1.4 节定义的三段式结果：`resolution_metadata` 记录解析过程、warning、cache/local override、resolver id、W3C error；`document` 是最终选中的文档；`document_metadata` 记录状态、version、deactivation、canonical/alias 和 BuckyOS 扩展 metadata。`document_metadata.buckyos.document_status` 只有在结果确实来自 `PublishedState / DocumentStatus` 状态机时才是 `Some(..)`；免验证 Info 必须是 `None`。兼容 API `resolve_did` 会丢弃 metadata，因此只适合旧调用方和明确不关心解析 provenance 的场景。

`ResolveError` 也应提供稳定的标准投影：

```rust
impl ResolveError {
    fn to_did_resolution_error(&self) -> DidResolutionError { /* W3C error URI + title/detail */ }
}
```

这样内部可以继续用有业务语义的 enum，例如 `TerminalDocumentState`、`OwnerConflict`、`AuthorityUnavailable`；对外 HTTP binding 或跨语言 SDK 则输出 W3C DID Resolution 的 `didResolutionMetadata.error`。

`ResolvePolicy` 需要承载递归所需的两点：

```rust
impl ResolvePolicy {
    // 递归解析 owner 文档时收紧的 policy：
    // 关闭 self-signed / gossip fallback，只接受 trust_level 0 的权威源或权威 anchor。
    fn for_authority_lookup(&self) -> ResolvePolicy { /* ... */ }

    // 递归保护：携带 (did, doc_type) 访问集与剩余深度，防止 owner 链成环。
    fn descend(&self, did: &DID, doc_type: &str) -> Result<ResolvePolicy, ResolveError>;
}
```

### 11.2 拆分 provider trait

旧 trait：

```rust
async fn query_did(&self, did: &DID, doc_type: Option<&str>) -> NSResult<EncodedDocument>;
```

建议演进为：

```rust
#[async_trait]
trait DidResolver {
    fn id(&self) -> &str;
    fn methods(&self) -> MethodMatcher;
    fn trust_level(&self) -> i32;
    fn caps(&self) -> ResolverCaps;

    async fn resolve_published_state(
        &self,
        did: &DID,
        doc_type: &str,
    ) -> NSResult<Option<PublishedState>>;

    async fn fetch_document_body(
        &self,
        doc_ref: &DocumentRef,
    ) -> NSResult<Option<DocumentBody>>;

    async fn query_self_signed_candidates(
        &self,
        did: &DID,
        doc_type: &str,
    ) -> NSResult<Vec<DocumentBody>>;

    async fn query_unauthenticated_info(
        &self,
        did: &DID,
        doc_type: &str,
    ) -> NSResult<Vec<DocumentBody>>;

    // 声明某个 doc_type 是否需要走 owner 验证链，默认 true。
    // Info 类 doc_type（如 "info"）的 resolver 应返回 false。
    fn requires_verification(&self, doc_type: &str) -> bool { true }
}
```

`requires_verification(doc_type)` 是 resolver 与 `doc_type` 的显式契约。解析器不能通过 `EncodedDocument` 编码形态或验证失败来反推“是否需要签名”：声明为免验证的 `doc_type` 进入 `query_unauthenticated_info` / `UnauthenticatedInfo` 轻量路径；未声明免验证的 `doc_type` 即使 body 是 `JsonLd`，也仍按需要验证的 Document 处理，验证失败就是失败。

### 11.3 BNS provider 的定位

BNS provider 不应再只是 `HttpsProvider` wrapper。它应负责：

1. `did:bns:$name` 到 canonical BNS name 的转换。
2. 调用 BNS `resolveDocument(name, docType)` 或 RPC 等价接口。
3. 返回 `PublishedState`，包含 document status、version、contentHash、owner resolution、proof root。
4. 对 inline document 可以直接返回 body。
5. 对外链 document ref，可以交给通用 body resolver 拉取。

### 11.4 SN provider 的定位

SN 不应作为 `did:bns` 的 method authority。它可以承担：

1. 自签名候选文档传播。
2. owner/zone 授权后的候选文档索引。
3. document body cache。
4. 运行时信息，例如 `info` 类文档或设备在线信息。

SN 返回的文档必须经过 owner key 验签，不能因为来自 SN 就直接成为权威文档。

## 12. 可达性敏感 Document 的安全发布

有些 DID Document 承担的职责类似传统系统里的 `ipconfig`、DNS zone file 或服务发现配置。例如：

```text
boot
zone
device
service
dns_a / dns_aaaa / dns_srv
```

这类文档一旦写错并成为权威 current version，可能导致机器、Zone 或服务无法再被访问，从而失去在线修复通道。测试期间如果自动化发布链路过于激进，这个问题会被放大。

### 12.1 基本原则

可达性敏感文档不能按普通内容文档处理。它的发布流程应满足：

1. 上链是强传播和强公告路径，不应承担首次验证新网络配置是否可用的职责。
2. 新文档发布到目标发布源或大范围广播之前，应先作为自签名候选文档在 SN / cache / staging resolver 中传播和验证。
3. 发布者必须能通过不依赖目标新配置的通道完成回滚。
4. Registry authority key 不能只存在于待更新文档里，否则错误文档会同时破坏访问通道和授权通道。
5. 错误配置的修复必须是发布一个更高版本，而不是回滚 current pointer 到旧版本。

### 12.2 推荐发布流程

```rust
async fn publish_reachability_sensitive_document(
    did: DID,
    doc_type: String,
    candidate: EncodedDocument,
    owner_key: OwnerSigningKey,
) -> Result<PublishReceipt, PublishError> {
    // 1. 本地静态校验。
    validate_schema(&candidate)?;
    validate_document_subject(&candidate, &did, &doc_type)?;
    validate_no_obvious_lockout(&candidate)?;

    // 2. 用 owner key 生成自签名候选版本，但先不正式发布。
    let signed_candidate = sign_document(candidate, owner_key)?;
    let candidate_hash = hash_document(&signed_candidate);

    // 3. 发布到 staging/self-signed 传播层，例如 SN、DHT、临时 HTTPS。
    staging_publish(&did, &doc_type, &signed_candidate).await?;

    // 4. 从多个视角解析候选文档，确认候选能被 resolver 找到并通过验签。
    let staged = resolve_self_signed_candidate(&did, &doc_type, candidate_hash).await?;
    verify_document_signature(&staged, owner_key.public_context())?;

    // 5. 做可达性探测。探测必须从当前机器以外的视角执行。
    let probe_result = probe_reachability_from_independent_points(&staged).await?;
    if !probe_result.satisfies_minimum_policy() {
        return Err(PublishError::PreflightReachabilityFailed(probe_result));
    }

    // 6. 设置延迟生效时间，给旧版本保留一个明确的恢复窗口。
    //    目标发布源可以是 BNS 链、did:web endpoint、中心化 resolver 或 SN authority service。
    let update = DocumentUpdate {
        document_ref: DocumentRef::from_staged_document(&signed_candidate),
        valid_from: now() + ACTIVATION_DELAY,
        expire_at: staged_expire_at(&staged),
        expected_version: current_document_version(&did, &doc_type).await?,
    };

    // 7. 正式发布只提交 hash/ref/version，不依赖目标机器的新网络配置。
    let receipt = publish_document_to_target_resolver(&did, &doc_type, update, owner_key).await?;

    // 8. 激活窗口内继续探测。失败则发布一个更高版本恢复到 last-known-good。
    schedule_activation_monitor(did, doc_type, receipt.version, candidate_hash);

    Ok(receipt)
}
```

### 12.3 Resolver 激活规则

`DocumentState.validFrom` 应参与 resolver 判断。对于可达性敏感文档：

```rust
fn select_reachability_document(
    current: PublishedState,
    previous: Option<PublishedState>,
    policy: ReachabilityPolicy,
) -> Result<PublishedState, ResolveError> {
    if current.document_status.is_terminal() {
        return Err(ResolveError::TerminalDocumentState(current));
    }

    if current.valid_from > now() {
        // 这是显式延迟生效，不是静默 fallback。
        // 只允许使用 Registry previousVersion 指向的旧 Active 文档。
        if let Some(prev) = previous {
            if prev.is_active() && !prev.is_expired() {
                return Ok(prev.with_warning(ResolveWarning::PendingActivation {
                    pending_version: current.document_version,
                    valid_from: current.valid_from,
                }));
            }
        }
    }

    Ok(current)
}
```

这个规则必须是显式的、受 `validFrom / previousVersion / policy` 约束的恢复窗口。不能把它实现成普通的“新文档不可达就随便用旧 cache”，否则会重新引入 revoke/tombstone 绕过问题。

### 12.4 Last-known-good 与回滚

对可达性敏感文档，cache 可以保存 last-known-good，但使用范围必须很窄：

1. 只能在 `validFrom` 延迟激活窗口或明确的 rollback grace 窗口内使用。
2. 只能使用 Registry 可追溯的 `previousVersion`，不能使用任意历史 cache。
3. 如果 current 是 `Revoked / Tombstoned / Migrated`，last-known-good 不得返回。
4. 回滚必须通过发布新版本完成，例如 `Active v3 bad -> Active v4 old_content_hash`。
5. last-known-good 只能帮助客户端保持连接，不应改变 Registry current state。

### 12.5 防 lockout 校验

发布工具在提交可达性敏感文档前，至少应检查：

1. 文档包含至少一个可独立访问的管理通道，或保留当前已验证可用的管理通道。
2. 新配置不会把所有 gateway / SN / resolver endpoint 同时替换成未验证地址。
3. 新文档的 owner/controller 声明不与 Registry effective owner/controller 冲突。
4. 新文档的 `version_seq / iat` 单调递增。
5. 新文档的过期时间、TTL、activation delay 不会导致立即过期或立即切断旧配置。
6. 对 Zone/device/service 文档，至少从一个外部探测点完成连接测试。

这类检查应放在发布工具和 CI 中，而不只放在 resolver 中。resolver 只能决定是否接受和如何选择文档，不能替发布者判断一组网络配置是否一定可用。

## 13. 必须避免的行为

1. `Revoked / Tombstoned` 后 fallback 到旧 cache。
2. `did:bns` 被 `did:web` 或 wildcard resolver 返回的文档覆盖。
3. 让未发布的自签名文档覆盖正常环境中已经发布的结果。
4. provider transport error 被误解释为 `Missing` 或 `Revoked`。
5. 文档内部声明的 owner/controller 反向改变 Registry owner。
6. cache 只按 `exp` 判断可用，而忽略 `DocumentState.version`、`lineageEpoch`、`authoritySeq`。
7. 可达性敏感文档没有 staging、activation delay 或 last-known-good 窗口就直接替换 current。
8. 回滚流程依赖已经被新文档配置影响的机器本身。
9. 从普通传播路径获取 Owner Config，再用它决定后续文档验证策略。在递归模型里，等价于解析 `doc_type = "owner"` 时没有用 `policy.for_authority_lookup()` 收紧、放任 self-signed / gossip fallback 进入递归基。
10. 把 owner 解析实现成一条独立于 `resolve_did_document` 的特殊流程。owner 只是递归基，不应该有自己的取文档、验签、选优逻辑。
11. 把“验证失败”和“证据契约违规”混为一谈：`SelfSignedCandidate` 携带结构上不可验证的 `JsonLd` body，应作为契约违规直接丢弃并记录 warning，不能被误判为该 resolver 没有候选（`NotFound`），也不能悄悄进入 `compare_published_body` 参与排序。
12. 让声明为免验证的 `doc_type`（如 Info）落到第 9 节默认的递归验证路径里。必须通过 `requires_verification(doc_type)` 在查询 `PublishedState` 之前显式豁免，不能先走 `Missing / Expired / owner fallback policy / verified_cache` 再靠验证失败静默退化；后者会让“这个 `doc_type` 本来就不需要验证”和“这个 `doc_type` 应该验证但验证失败了”在结果上无法区分。
