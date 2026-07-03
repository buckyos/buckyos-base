# resolve_did 简化 TODO

> **状态:已完成(2026-07-02)。** P0-P4 全部落地于 `src/name-client`
> (provider.rs / name_query.rs / doc_cache.rs / name_client.rs 及各 provider),
> workspace 测试全绿。本文件保留作为这轮简化的任务记录;实现语义以
> [简单介绍resolve-did.md](./简单介绍resolve-did.md) 为准。
> 实现层面在 TODO 之外补充的两个决定:
> ① 已验证文档缓存 TTL 上限 1 小时(`DOC_CACHE_TTL_SECS`,快路径的吊销盲区 ≤ TTL);
> ② did:web 的权威渠道 = DNS TXT + `.well-known` 两个委托读取端的 first-win 合并
> (`AuthorityReaders`,Missing 需两者一致,任一传输失败按 unknown 处理)。
>
> **新增(2026-07-03):** P5 记录 Zone Resolver 从 provider / authority
> 读取端迁移到 cache 层的待办。P0-P4 的 resolver core 已完成,但当前
> `zone_resolver` 的定位仍需按 P5 调整。

目标：以 [简单介绍resolve-did.md](./简单介绍resolve-did.md) 为准，把现有 `name-client`
里的 DID 解析逻辑先修正确，再收敛成一条可读的主循环。

本 TODO 暂时不要求完成 resolver-provider 的真实后端实现；provider 可以先用 mock /
adapter 表达正确语义。优先级是：

1. 先保证安全语义正确，尤其是 Missing / unknown、expected_owner、负状态和 cache fallback；
2. 再删除多余抽象，把实现改到和简化文档的伪代码一致。

范围：`src/name-client` 的 `resolve_did / resolve_did_ex / NameQuery` 路径。
不包含 DNS 普通 `resolve(name)`、`resolve_ip` 的行为重做。

## 0. 当前实现的主要偏差

- `verify_owned_candidate` 仍先读取候选文档自声明 owner，再递归解析这个 owner。只有权威源返回
  `effective_owner` 时才做冲突校验；没有权威 owner 绑定、也没有结构默认 owner 时，攻击者仍可能让
  resolver 去验证攻击者自己声明的 owner。
- 验证逻辑没有统一检查 `doc.id == did`，也没有把权威源锚定的 `content_hash` 作为硬约束。
- 权威源查询失败和权威源明确 Missing 还没有清晰分开；当前若 published-state 查询出错，容易继续落到候选查询或 cache fallback。
- `Disabled` 只删除正缓存，不缓存负状态；权威源下一次不可达时，旧缓存或候选仍可能绕过“吊销屏蔽一切 fallback”的语义。
- cache merge 仍靠 `trust_level` 和 `iat/version_seq`，没有持久化“已发布 / 已验证自签 / 未验证 / 负状态”这些证据等级。
- `did:dev` 仍被 `BnsProvider` 接受，`DID::is_named_obj_id()` 也把 `dev` 纳入 resolve/cache 逻辑；这和简化文档“key 类 DID 不作为 `resolve_did` 入参”不一致。
- `NameQuery` 里存在多套并行概念：`trust_level`、`ResolverCaps`、`MethodMatcher`、`PublishedState`、`DocumentBody`、`EvidenceKind`，主流程被拆成三个类似循环，不容易对照简化文档检查。

## P0. 正确性优先

### T0.1 拒绝 key 类 DID 作为 resolve_did 入参

- 在 `NameClient::resolve_did_ex` 或更靠内的统一入口增加硬门禁：`did:key` / `did:dev` 返回 `InvalidDID` 或 `NotFound`，不进入 provider 管线。
- `did:dev` 仍可作为文档内容里的 key/id 材料存在，但不作为解析入口。
- 先保留内部对象里的 `did:dev` 字段，不做全仓模型迁移。

验收：

- 新增测试：`resolve_did(did:dev:...)` 不调用 provider，直接失败。
- 现有设备文档、DeviceInfo、resolve_ip 测试仍通过。

### T0.2 引入 expected_owner，禁止用候选文档自证 owner

- 新增 `expected_owner_for(did, authority_owner_binding) -> Option<DID>`：
  - 权威源 owner 绑定优先；
  - method 结构能确定 owner 时使用结构默认值，例如 `did:bns:app1.alice -> did:bns:alice`；
  - 一级名字推不出 owner 时返回 `None`。
- `verify_owned_candidate` 改为：
  - 先解析候选文档里的 `id` 和 `owner`；
  - 要求 `doc.id == did`；
  - 要求 `expected_owner.is_some()`；
  - 要求 `doc.owner == expected_owner`；
  - 递归解析 `expected_owner#owner`，而不是递归解析候选文档自声明 owner。
- owner 变更 / 委托只能通过权威源 owner 绑定生效。

验收：

- 新增攻击测试：候选文档声明 `owner = did:bns:mallory` 并由 mallory key 签名，若请求 DID 的 expected_owner 不是 mallory，必须拒绝。
- 新增测试：一级名字没有权威 owner 绑定时，自签名候选不能通过。
- 新增测试：二级名字结构 owner 与候选 owner 不一致时拒绝。

### T0.3 补齐 verify 的硬约束

- `verify` 必须同时检查：
  - `doc.id == did`；
  - `doc.owner == expected_owner`；
  - 若权威源给出 `content_hash` / `doc_hash`，body hash 必须匹配；
  - JWT 用 owner document 的 key 验签；
  - owner 文档策略，例如 `revoke_before_iat`。
- 一份坏 body 只作废自己，继续尝试后续候选。

验收：

- 新增测试：body 内容与权威 hash 不匹配时拒绝。
- 新增测试：文档 id 与请求 did 不一致时拒绝。

### T0.4 明确 DR / unknown，不让断网变成 Missing

- 在 resolver core 内部引入明确结果：

  ```rust
  enum ProviderResolveResult {
      Dr(ProviderAnswer),
      Unknown(NSError),
  }
  ```

- `Missing / Revoked / Tombstoned / Active` 都必须是 DR 的状态，不用普通 `NSError::NotFound` 表达。
- 权威源 `Unknown` 时：
  - 不允许候选进入“已验证”结果；
  - 默认不实现 unproof 返回；
  - 直接进入缓存兜底判断。
- 权威源 `Missing` 时：
  - 只按策略决定是否允许自签名候选入场；
  - 不允许用已有已发布缓存覆盖 Missing。

验收：

- 新增测试：权威源 unknown + 补充源返回合法自签名候选，默认不得返回候选。
- 新增测试：权威源 Missing + 策略不允许自签名时，不得 fallback 到旧 positive cache。
- 新增测试：权威源 Missing + 策略允许时，候选仍必须通过 expected_owner 和验签。

### T0.5 落地负状态缓存

- 增加负状态 cache entry：`Revoked / Tombstoned` 是“回答”，不是 cache miss。
- 命中负状态时直接返回错误，不受普通 TTL 过期影响。
- 权威源返回负状态时：
  - 删除 positive cache；
  - 写入 negative cache；
  - 终止查询。
- merge 时负状态屏蔽普通候选和 stale cache；只能被权威源新的 DR 翻篇。

验收：

- 新增测试：先拿到 Revoked，再让权威源 unknown，解析仍返回 Revoked，不返回旧缓存。
- 新增测试：负状态存在时，push / self-signed candidate 不得写入普通 cache。

### T0.6 统一 cache fallback 策略

- `NameClient` 外层改成简化文档的形状：
  1. local override 快路径；
  2. in-TTL positive cache 快路径；
  3. negative cache 快路径；
  4. 进入 resolver 主循环；
  5. 只有 resolver 没产出可核实文档、且没有负状态屏蔽时，才按策略使用 stale cache。
- 删除“任何 provider 错误都 fallback 到 cache”的泛化逻辑。
- `max_trust_level` 不再作为 cache 命中后的 provider 剪枝机制。

验收：

- cache hit 返回 `CacheStatus::Hit`，不是错误兜底路径里的 `Fallback`。
- authority Missing 不使用旧 positive cache。
- authority unknown 且 stale cache 策略允许时才使用 stale cache。

## P1. 收敛 resolver 主循环

### T1.1 定义内部最小模型

先不重写 provider 后端，只在 `NameQuery` 内部用 adapter 归一成简化文档需要的模型：

```rust
struct ProviderAnswer {
    status: Option<DocumentStatus>,       // 只有权威源能填
    owner_binding: Option<DID>,           // 只有权威源能填
    doc_hash: Option<String>,             // 只有权威源能填
    body: Option<DocumentBody>,
}

enum BodyEvidence {
    Anchored,      // 已发布 / 已锚定，不需要额外 proof
    NeedProof,     // 候选文档，需要 expected_owner + owner_doc 验证
    UnproofInfo,   // 明确免验证的 info 类
}
```

`EvidenceKind` 可先保留兼容，但 resolver 主流程只认这三档。

### T1.2 重写 `NameQuery::query_did_ex` 为一条路径

目标结构和 `简单介绍resolve-did.md` 第 3 节一致：

- 先拿 method authority，再按顺序查询 supplements；
- 权威源只负责 `status / owner_binding / doc_hash`；
- `Revoked / Tombstoned` 立即返回负状态；
- `Missing` 只发放自签名候选入场资格；
- `Active` 可只带锚点，body 由后续补充源提供；
- `need_proof` 统一走 expected_owner + owner recursion + verify；
- owner doc 只是 `doc_type=owner` 的权威结果，不单写另一套流程。

验收：

- 主循环代码能逐段标注简化文档四个策略点。
- 删除 `resolve_from_published_state / resolve_from_document_candidates / resolve_unauthenticated_info` 三个互相绕的循环，或至少把它们降为内部小 helper。

### T1.3 保留现有正确资产

重写时不能丢：

- `LocalAuthorityOverrideStore`：打标、带 scope、不进普通 cache；
- Info 类免验证路径和 `UnauthenticatedInfoCache` 隔离；
- `CandidateRejection`：契约违规只作废单个 body；
- owner 递归 `descend()` 防环 / 深度限制；
- 历史 key 验签和 `SignedByHistoricalKey` warning；
- `revoke_before_iat` replay guard。

## P2. 简化类型和注册模型

### T2.1 删除或收缩没有当前使用者的抽象

- 删除 `VerificationRoot` / `OwnerContext`，当前主流程没有使用。
- 删除空的 `ReachabilityPolicy`。
- `OwnerDocumentPolicy` 先收缩到 `revoke_before_iat`；其它按 doc_type 的策略等 owner 文档真实声明后再加回。
- 删除 `NameQuery::query_did_from_providers`。
- `EvidenceKind` 收缩到 resolver 实际使用的三档。
- `PublishedState` 裁剪到当前需要字段：`did / doc_type / document_status / document_ref/doc_hash / document_version / effective_owner / authority_seq / migration_target`。

### T2.2 把 `trust_level + caps + matcher` 换成 method registry

目标模型：

```rust
struct MethodProviders {
    authority: Option<Box<dyn NsProvider>>,
    supplements: Vec<Box<dyn NsProvider>>,
    no_proof_doc_types: HashSet<DidDocType>,
}
```

- 一个 method 至多一个 authority；
- supplements 是显式有序列表，first-win；
- 不再让 app 任意注册 wildcard provider；
- `Info` 等免验证 doc_type 是 method 契约，不由 provider 运行时协商。

provider 后端可先用现有 `NsProvider` adapter 包住，不要求一次改完所有 provider。

### T2.3 doc_cache 后端退化为 KV，merge 上提

- Fs / Db / Mem 只负责 `get / put / delete`。
- 证据等级、负状态屏蔽、version/iat 比较、owner replay guard 在统一层实现。
- cache entry 持久化证据等级，不能继续用 `trust_level` 近似。

验收：

- `doc_cache.rs` 三个后端不再复制 update/insert/evict 逻辑。
- merge 规则为：负状态屏蔽一切；否则先比证据等级，同级才比 `version_seq / iat`。

## P3. 测试清单

优先新增这些测试，再开始大改：

- `did:dev` / `did:key` 作为 `resolve_did` 入参被拒绝。
- 一级 DID 无权威 owner 绑定时，自签名候选不能通过。
- 二级 DID 的结构 owner 与候选 owner 不一致时拒绝。
- 候选文档自声明 mallory owner 且用 mallory key 签名，不能通过。
- 文档 `id` 与请求 DID 不一致时拒绝。
- 权威 `doc_hash` 与 body 不一致时拒绝。
- 权威 unknown 时不接受自签名候选。
- 权威 Missing 时不 fallback 到旧 positive cache。
- Revoked / Tombstoned 写负状态 cache，并在权威 unknown 时继续屏蔽 fallback。
- in-TTL cache 命中走快路径，返回 `CacheStatus::Hit`。
- Info 类仍走免验证路径，并只进入 `UnauthenticatedInfoCache`。

## P4. 文档同步

- [简单介绍resolve-did.md](./简单介绍resolve-did.md) 作为主规范保留。
- [resolve_did重构.md](./resolve_did重构.md) 头部加说明：旧文档中的 trust-level、多 provider 并发、复杂状态机字段以简化文档为准。
- [http_did_resolver_api.md](./http_did_resolver_api.md) 随 `PublishedState` 裁剪同步字段。
- 本 TODO 完成后，可以删除旧的“重构 TODO”引用，避免两套任务列表同时指导实现。

## P5. Zone Resolver cache 层化

背景：当前实现把 `zone_resolver` 通过 `NameClient::set_zone_authority`
注册成 zone 内的权威读取端，并和 method authority 做同一发布渠道的
first-win 合并。新的定位是：`zone_resolver` 不是 resolver provider，
而是 cluster-level shared cache / control-plane cache。它的管理面可以由
BuckyOS 或其它私有 cluster 实现，但 `name-client` 只能假设存在一个可选的本机
HTTP cache 服务，不能假设 cluster 一定是 BuckyOS。

目标：当 Zone Resolver 启用且服务可用时，`resolve_did` 的结果只从它返回，
相当于一次 cache 命中；只有 Zone Resolver 服务不可用时，才回落到本机
local cache 和后续 resolver 流程。这样避免同时合并 zone cache 与 local cache。

### T5.1 启用与配置

- 默认启用 Zone Resolver，默认地址沿用现有本机服务：
  `http://127.0.0.1:3180/1.0/identifiers/{did}?type={doc_type}`。
- 增加显式关闭接口，例如 `NameClient::disable_zone_resolver()`；
  非 BuckyOS 环境、单元测试、离线工具可以关闭它。
- 增加可配置 endpoint / timeout，例如 `set_zone_resolver_endpoint(...)`。
- 连接失败、connection refused、超时、明确的 service unavailable 才表示
  `ZoneUnavailable`；语义上的 `Missing / Revoked / Tombstoned / Unknown`
  都是 Zone Resolver 的回答，不触发 local cache fallback。
- 默认启用不能引入明显延迟：本机连接和读取 timeout 必须很短；是否需要短期
  circuit breaker 可以单独评估，但首版语义仍是“Zone 可用则优先且独占”。

### T5.2 查询顺序

目标查询顺序：

```text
if zone_resolver.enabled:
    zone = query_zone_resolver(did, doc_type)
    if zone.service_available:
        return zone.answer as CacheStatus::ZoneHit

local cache / local override fast path
resolver core(authority + supplements)
stale local cache fallback
```

- Zone Resolver 可用时，local cache、local override、method authority、
  supplements 都不参与本次解析。
- 只有 Zone Resolver 服务不可用时，才使用原有本机 cache 快路径和 resolver core。
- `update DID cache` 的旧语义保持不变：只写本机 local cache，不写 Zone Resolver。
- Zone Resolver 返回的结果默认不回写 local cache；否则又会引入两层 cache 合并问题。
- 关闭 Zone Resolver 后，行为退回当前单机模式。

### T5.3 语义边界与 metadata

- Zone Resolver 是 cache / control-plane 来源，不是全局权威源。它可以返回
  已发布文档、已验证文档、Info、`Missing`、`Revoked`、`Tombstoned`、
  `Unknown`，但这些只表达“当前 Zone 内的解析结果”。
- 解析结果需要明确 provenance：例如新增 `CacheStatus::ZoneHit`、
  `ResolveWarning::ZoneResolverOverride` 或等价 metadata，避免 UI / 日志把它误判成
  method authority 的直接回答。
- `Revoked / Tombstoned` 这类 Zone 内负状态是回答，不是 miss；只要 Zone Resolver
  可用，本机 local cache 和外部 authority 都不能绕过它。
- `Missing` 也必须是回答：如果 Zone Resolver 明确说某 DID/doc_type 不存在，
  不再查 local cache，也不再查外部 resolver。若 Zone 实现希望“没有命中时继续向外查”，
  应由 Zone Resolver 自己完成外部查询或返回明确的 resolver 结果。
- `did_in_zone` 过滤不应继续放在 `name-client` 侧。作为 cluster cache，Zone Resolver
  可以覆盖任意 DID；哪些 DID 属于本 Zone、哪些需要短路、哪些允许出 Zone，应由
  Zone Resolver 服务内部策略决定。

### T5.4 Cluster 管理与开发旁路

- Zone Resolver 可以承载原先通过 local cache 实现的开发旁路：在集群级注入
  Document / Info / 负状态，而不是在每台机器上分别写本机 cache。
- 这类 cluster-level override 必须由 Zone Resolver 的私有管理接口控制；
  `name-client` 只消费解析接口，不定义管理 API。
- 与传统 `hosts` 文件相比，Zone Resolver 使用完整 resolver 接口，因此能覆盖
  DID Document、Info、状态和 metadata，不只模拟 IP 解析。
- Zone Resolver 可以实现 Zone 内短路：只要它持续返回某个 DID 的结果或负状态，
  Zone 内客户端就不会把该 DID 请求发送到 Zone 外。
- 例如 Zone 内“吊销”：即使全局权威源没有真正吊销，只要 Zone Resolver 持续返回
  `Revoked / Tombstoned`，Zone 内就视为已吊销；metadata 必须表明这是 Zone 内控制结果。

### T5.5 实现步骤

- 新增 `ZoneResolverCache` / `ClusterCache` 客户端抽象，不再把 Zone Resolver 实现成
  `NsProvider`。
- 在 `NameClient::resolve_did_ex` 或统一入口接入 Zone Resolver cache 快路径；
  `NameQuery` 只保留 resolver core，不再感知 zone reader。
- 废弃或迁移 `set_zone_authority / clear_zone_authority`；若需要兼容旧调用方，
  先提供 deprecated wrapper，语义改为配置 Zone Resolver cache endpoint / enable 状态。
- 删除 `merged_authority_answer` 中为 `zone_resolver` 做的 authority-reader 合并逻辑。
- 更新 `doc/简单介绍resolve-did.md` 第 3、5、7 节：本地覆盖不再是唯一旁路，
  还存在默认启用的 Zone cache / cluster override 层。
- 更新 `doc/已有did-resolver介绍.md`：把“zone 内权威源”改成“cluster-level cache /
  control-plane resolver”。

### T5.6 测试清单

- 默认配置会先查询 `http://127.0.0.1:3180`，Zone Resolver 成功返回时不调用
  local cache、local override、method authority 或 supplements。
- `disable_zone_resolver()` 后不查询 Zone Resolver，退回当前单机 cache + resolver 流程。
- Zone Resolver 服务不可用时，才落回 local cache；local cache 命中返回原有
  `CacheStatus::Hit`。
- Zone Resolver 返回 `Revoked / Tombstoned` 时，local positive cache 和外部 authority
  都不得绕过。
- Zone Resolver 返回 `Missing` 时，不查 local cache，也不查外部 resolver。
- `update DID cache` 只影响 local cache；当 Zone Resolver 可用时，Zone 结果仍优先。
- Zone Resolver 可覆盖非本 zone DID；`name-client` 不再用 `did_in_zone` 阻止查询。
- Zone 结果的 metadata / warning 能区分 `ZoneHit`、`ZoneOverride`、普通 local cache
  hit 和 method authority 结果。
