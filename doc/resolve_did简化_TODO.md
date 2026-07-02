# resolve_did 简化 TODO：向《简单介绍resolve-did》模型收敛

> 上一轮工作（[resolve_did重构_TODO.md](./resolve_did重构_TODO.md)，Phase 0-5 已完成）把 [resolve_did重构.md](./resolve_did重构.md)（下称 **A**）的设计落了地。本文件规划下一轮：以 [简单介绍resolve-did.md](./简单介绍resolve-did.md)（下称 **B**）为规范文档，把实现从"面面俱到"收敛到"简单易懂"。
>
> 范围：`name-client` 的 DID 解析路径（`resolve_did / resolve_did_ex`）。DNS 老路径（`resolve(name) / NameInfo / resolve_ip`）不在本轮范围。

## 0. 为什么简化，简化什么

团队反馈"A 看完了像没看懂"。对照代码盘点后，原因可以定位得很具体：**A 的机制约九成已经落地，但其中相当一部分是没有使用者的抽象**——

- `VerificationRoot` / `OwnerContext` 定义了但引擎从未使用（引擎实际用 `is_owner_root` 布尔值）；
- `OwnerDocumentPolicy` 4 个字段里 3 个永远是空 map；`ReachabilityPolicy` 是空结构体；
- `EvidenceKind` 7 个变体只有 3 个真正作为证据出现；
- `PublishedState` 16 个字段约一半没有生产者也没有消费者；
- `ResolverCaps` 5 个能力标志 + `MethodMatcher` + `trust_level` 三套机制共同表达的东西，B 用"一个权威渠道 + 有序补充源"一句话就说清了。

读者要理解的概念数量是实际语义的两倍以上——这就是"看不懂"的来源。简化的本质是**把概念数量砍回语义数量**。

### 三条原则

1. **概念预算**：解析主流程中出现的概念必须 ⊆ B 的词表——DR/unknown、权威渠道/补充源、need_proof（按信道打标）、证据三档、四个策略点、owner 递归基、负状态、本地覆盖。不在词表里的概念，要么删掉，要么改名对齐。
2. **删推测性通用性**：没有第二个使用者的扩展点一律删。要用时从 git 历史里找回来，比让每个读者都为它付理解成本便宜。
3. **简化不越红线**：B §8 的 8 条规则（owner 一致性已于 2026-07-02 写入 B 并加强为 expected_owner 规则），加上代码已做对、B 还没写进去的 info 前置分流，是资产不是负担。第 4 节有"勿回退清单"，每个 P 阶段验收时对照。

### 顺带修复的三个语义缺口

简化过程恰好经过三处现存问题，一并修掉（不是新增功能，是补红线）：

1. **权威源 unknown 时自签名候选无门禁**：transport error 被静默吞掉（[name_query.rs:324](../src/name-client/src/name_query.rs:324)）后无条件落到候选查询（[name_query.rs:175](../src/name-client/src/name_query.rs:175)），等于"断你的网 = Missing 放行"，违反 B §2.1 / A 红线 13.3。→ P2/T2.1
2. **负状态不缓存**：`Disabled` 只删正缓存（[name_client.rs:659](../src/name-client/src/name_client.rs:659)），"吊销屏蔽一切 fallback"只在权威源在线时成立。→ P3/T3.1
3. **wildcard provider 活着**：`SmartProvider` 以 `MethodMatcher::Any` + trust 100 注册（[lib.rs:100](../src/name-client/src/lib.rs:100)），正是 A 红线 13.2 警告的形态。→ P1 结构性消灭

## 1. 现状 → 目标 总表

| 现状机制（A 概念） | 位置 | B 模型对应 | 处置 |
| --- | --- | --- | --- |
| `MethodMatcher::Exact/Any` | [provider.rs:116](../src/name-client/src/provider.rs:116) | method 注册表的 key；Any 不存在 | P1 删 |
| `ResolverCaps` 5 个标志 | [provider.rs:142](../src/name-client/src/provider.rs:142) | 角色即能力（authority / supplement） | P1 删 |
| `trust_level: i32`（0/16/100） | [name_client.rs:27](../src/name-client/src/name_client.rs:27) | authority 永远第一 + 补充源列表顺序 | P1 删 |
| `EvidenceKind` 7 档 | [provider.rs:179](../src/name-client/src/provider.rs:179) | 证据三档 rank（已发布锚定 > 已验证自签 > 未验证） | P0 收缩为 3 |
| `PublishedState` 16 字段 | [provider.rs:283](../src/name-client/src/provider.rs:283) | DR 的状态部分（status / hash / version / owner） | P0 裁到 ~8 |
| `NameStatus`（独立于 DocumentStatus） | [provider.rs:216](../src/name-client/src/provider.rs:216) | 无——per doc_type 负状态足够 | P0 删 |
| `VerificationRoot` / `OwnerContext` | [provider.rs:828](../src/name-client/src/provider.rs:828) | —（死代码） | P0 删 |
| `OwnerDocumentPolicy` 4 字段 | [provider.rs:800](../src/name-client/src/provider.rs:800) | owner 策略 = `revoke_before_iat` 一项 | P0 收缩 |
| `ReachabilityPolicy` 空结构 | [provider.rs:795](../src/name-client/src/provider.rs:795) | —（A §12 未实现，实现时再回来） | P0 删 |
| `NsProvider` 5 async + 5 配置方法 | [provider.rs:1126](../src/name-client/src/provider.rs:1126) | `resolve_did()` 单入口返回 DR\|unknown | P1 收缩 |
| 三个 trust-group 游标循环 | [name_query.rs:188](../src/name-client/src/name_query.rs:188) / :370 / :430 | 一条 first-win 循环 + 四个策略点 | P2 合并 |
| 组内 `join_all` 并发（3 处） | [name_query.rs:304](../src/name-client/src/name_query.rs:304) 等 | 无——镜像并发是 provider 内部实现细节 | P2 删 |
| `max_trust_level` 贯穿参数 | [name_query.rs:89](../src/name-client/src/name_query.rs:89), [name_client.rs:590](../src/name-client/src/name_client.rs:590) | 无——真快路径取代 | P3 删 |
| 缓存"错误兜底"迂回 | [name_client.rs:659-690](../src/name-client/src/name_client.rs:659) | 快路径（步骤 0）+ 策略点④ | P3 重写 |
| doc_cache 三后端各复制一份 merge/校验 | [doc_cache.rs](../src/name-client/src/doc_cache.rs) | 单一 merge（先 rank 后 version/iat），后端纯 KV | P3 |
| W3C 三段式 `ResolvedDocument` | [provider.rs:530](../src/name-client/src/provider.rs:530) | （B 未覆盖，对外契约） | **保留**，裁 buckyos 扩展字段 |
| 验证核（验签/OwnerConflict/revoke_before_iat/历史key/防环） | [name_query.rs:550-839](../src/name-client/src/name_query.rs:550) | B §2.3 verify + §2.4 递归基 | **原样保留** |
| `LocalAuthorityOverrideStore` | [provider.rs:744](../src/name-client/src/provider.rs:744) | B §7 hosts 语义 | **原样保留** |
| info 免验证前置分流 | [name_query.rs:144](../src/name-client/src/name_query.rs:144) | B §2.3 契约打标 | **保留**，循环体简化 |
| `UnauthenticatedInfoCache` 独立池 | [doc_cache.rs:931](../src/name-client/src/doc_cache.rs:931) | 未验证档缓存 | **保留** |

## 2. 决策点（开工前拍板）

- [ ] **D1：unproof（B 策略点③）不实现。** 代码从未有过这条路径，A 也不允许；B 引入它是一处放宽。建议：B 里标注"设计保留，当前不实现、默认关闭"，代码不加。
- [ ] **D2：did:dev 的归位。** `BnsProvider` 现在 match `["bns","dev"]`。B 的退化梯子里 did:dev 是生成式（权威 = 自证 key，无发布渠道）。建议：dev 无 authority，web3 桥作为补充源——状态门禁自动不触发，自然退化成"自签名候选 + 自证 key 验证"（B §6）。备选：桥继续当 dev 的 authority（则 dev 获得 Missing 门禁，语义更强但依赖桥在线）。
- [ ] **D3：真快路径的取舍确认。** in-TTL 正缓存直接返回（`Hit`），吊销可见性最多滞后一个 TTL，由负状态缓存（T3.1）+ 读时 replay guard 缓解。当前实现是"命中缓存仍查更权威 provider"的折中（代价：每次解析都可能打权威源，且真命中被标成 `Fallback`）。这是信任模型级别的改变，需要明确拍板并写进 B（T4.1）。
- [ ] **D4：did:web 的 authority 定谁。** 按 did:web 规范应是 canonical endpoint（`SmartProvider` 的 `.well-known` 路径）；DNS TXT（`DnsProvider`，现 trust 16 排在前面）按 A §0 的定位是"过渡与兼容层"，应降为补充源。注意行为变化：TXT 来源的文档从今天的 Anchored 证据（见 T1.2 的"证据谎言"）降为诚实的 SelfSignedCandidate，需过 owner 验签。

## 3. 分阶段任务

阶段顺序有依赖：先删（P0）让重写少碰死代码；trait 与主循环（P1+P2）建议连续落地（一到两个 PR）；缓存（P3）依赖新循环的错误分类；文档（P4）中 B 的伪代码补丁与 T2.1 同步。

### P0 —— 纯删除与收缩（无行为变化，规模 S，~1-2 天）

- [ ] **T0.1** 删 `VerificationRoot` / `OwnerContext` / `owner_document_policy()`（[provider.rs:826-850](../src/name-client/src/provider.rs:826)）。引擎实际用 `is_owner_root` 布尔（[name_query.rs:559](../src/name-client/src/name_query.rs:559)），这些类型零使用者。
- [ ] **T0.2** 删 `ReachabilityPolicy`（provider.rs:795）；`OwnerDocumentPolicy`（provider.rs:800）收缩——3 个永远为空的 HashMap 删除，`revoke_before_iat` 直接内联到 `verify_owned_candidate`（[name_query.rs:773](../src/name-client/src/name_query.rs:773)）从 `OwnerConfig::valid_iat` 读。
- [ ] **T0.3** 删 `NameQuery::query_did_from_providers`（[name_query.rs:868-932](../src/name-client/src/name_query.rs:868)，无调用者）。
- [ ] **T0.4** 删 `GLOBAL_BOOT_NAME_CLIENT`（lib.rs，声明后从未使用）。
- [ ] **T0.5** `EvidenceKind` 7 → 3（provider.rs:179）：`Negative / NotFound / TransportError / PublishedState` 从未作为 `DocumentBody` 证据出现。剩下三档的 `rank()` 与 B §5 的证据等级一一对应。
- [ ] **T0.6** `PublishedState` 裁剪（provider.rs:283）：删 `lineage_epoch / canonical_id / equivalent_ids / next_version / previous_version / owner_source / authority_root / name_status`（无生产者或无消费者），保留 `did / doc_type / document_status / document_ref / document_version / effective_owner / authority_seq / migration_target`。联动修改：`HttpsProvider` 的 wire 解析、`BuckyOSDocumentMetadata`（provider.rs:506）、[http_did_resolver_api.md](./http_did_resolver_api.md)。**服务端尚未实现，现在裁协议字段是零迁移成本，越晚越贵。** lineage/owner-at-iat 历史校验记入"待 BNS 合约上线"backlog（T4.2）。

验收：`cargo test` 全绿；provider.rs 预计 -300 行。影响测试：构造 `PublishedState` 的用例改字段即可。

### P1 —— Provider 模型：注册表 → 每 method「一个权威 + 有序补充源」（规模 M，~2-3 天）

- [ ] **T1.1** 用 `MethodRegistry` 取代 `Vec<(Box<dyn NsProvider>, i32)>`：

  ```rust
  struct MethodProviders {
      authority: Option<Box<dyn NsProvider>>,   // 每个 method 至多一个权威发布渠道
      supplements: Vec<Box<dyn NsProvider>>,    // 有序补充源，first-win
      no_proof_doc_types: HashSet<DidDocType>,  // method 级契约，默认 {Info}
  }
  // NameQuery { registry: HashMap<String /*method*/, MethodProviders> }
  ```

  随之删除：`MethodMatcher`、`ResolverCaps`、`provider_supports_did`（name_query.rs:179）、`requires_verification` 的跨 provider `.any()` 协商（[name_query.rs:135-142](../src/name-client/src/name_query.rs:135)——"是否免验证"是 method 的声明，收到注册表一处，不再是运行时协商）、per-provider `is_owner_root`（保留 `doc_type == Owner` 的全局约定即可）。

- [ ] **T1.2** `NsProvider` trait 收缩（[provider.rs:1126-1206](../src/name-client/src/provider.rs:1126)）：

  ```rust
  #[async_trait]
  trait NsProvider {
      fn get_id(&self) -> String;
      // DNS 老路径，保留不动
      async fn query(&self, name, record_type, from_ip) -> NSResult<NameInfo>;
      // B 的单一入口：Ok(DR) 或 Err(unknown)。约定：Err 只表示"没得到回答"
      // （断网/超时）；"回答了没有/没了"用 DR 的 status 表达。
      async fn resolve_did(&self, did: &DID, doc_type: &DidDocType) -> NSResult<ProviderAnswer>;
      // 可选：按外链 doc_ref 取 body（BNS 合约只存 hash 的场景）
      async fn fetch_document_body(&self, doc_ref: &DocumentRef) -> NSResult<Option<DocumentBody>> { ... }
  }

  // B 的 DR：状态归状态、body 归 body，但属于同一个结果。
  struct ProviderAnswer {
      status: Option<DocumentStatus>,  // 只有权威渠道会填
      doc_ref: Option<DocumentRef>,    // hash 锚定 / inline
      bodies: Vec<DocumentBody>,       // 证据档按取回信道如实打标
  }
  ```

  顺带修正默认实现的**证据谎言**：现在 `query_self_signed_candidates` 的默认实现把 `query_did` 结果包装成 `AnchoredDocumentBody`（[provider.rs:1181-1193](../src/name-client/src/provider.rs:1181)），让老 provider 的候选冒充锚定证据、在排序中越级。新 trait 下补充源的 bodies 必须按真实信道打 `SelfSignedCandidate` / `UnauthenticatedInfo`——B §2.3"need_proof 按取回信道打标，永远不看 body 长相"的落点。

- [ ] **T1.3** 现有 provider 归位（改造 [lib.rs:92-105](../src/name-client/src/lib.rs:92) 的注册代码）：

  | method | authority | supplements | 备注 |
  | --- | --- | --- | --- |
  | `bns` | `BnsProvider`（内部走 `HttpsProvider` 打 web3 桥） | —（未来：SN） | 现状即是，只是显式化 |
  | `web` | `SmartProvider`（`.well-known` canonical endpoint，仅 Missing/Active 两态） | `DnsProvider`（TXT）、`LocalConfigDnsProvider` | 按 D4 决策 |
  | `dev` | 无（生成式，权威 = 自证 key） | web3 桥 | 按 D2 决策；状态门禁自动不触发 |

  `SmartProvider` 的 wildcard 形态（`Any` + trust 100）随 per-method 注册结构性消失。外部唯一的 `add_provider` 调用点在 `buckyos-http-server/src/test_did_obj_server.rs`，同步改签名。

验收：注册处一眼能看出谁是权威、谁是补充；"wildcard 压过具体 method"在类型上不可能（对应测试 `method_scoped_resolver_filters_wrong_method_*` 转为注册表单元测试）。

### P2 —— 主循环：三个游标循环 → 一条 first-win 循环 + 四个策略点（规模 M，~2-3 天，核心）

- [ ] **T2.1** 重写 `NameQuery::query_did_ex`：合并 `resolve_from_published_state` / `resolve_from_document_candidates` / `resolve_unauthenticated_info` 三个结构雷同的游标循环（[name_query.rs:188](../src/name-client/src/name_query.rs:188) / :370 / :430）为 B §3 形状的一条流程，**显式携带入场状态**：

  ```rust
  enum AuthorityAnswer {
      NoAuthority,          // 该 method 没有权威渠道（did:dev）→ 候选即正路
      Unknown,              // 权威渠道没回答（断网/超时）→ 跳过候选，交给缓存兜底（策略点④）
      MissingAllowed,       // 权威回答 Missing 且策略放行 → 候选入场（策略点②）
      Active(PublishedState), // 锚定 hash，body 缺失时向补充源取
      // Revoked/Tombstoned/Migrated/Missing-不放行 在权威分支内直接 return（策略点①/②）
  }
  ```

  **这是语义修复，不只是重构**：现状把"权威源 transport error"（[name_query.rs:324](../src/name-client/src/name_query.rs:324) 静默吞掉）和"权威源明确 Missing 且放行"折叠成同一条 fall-through（[name_query.rs:168-176](../src/name-client/src/name_query.rs:168)），自签名候选在断网时无门禁入场——B §2.1 的原话："谁能断你的网，谁就能给你塞文档"。B 的伪代码缺口已于 2026-07-02 修复（B §3：`authority_unknown` 候选门禁 + ③ 的零记忆前提 + 循环尾负状态屏蔽），实现以 B 为准。同一处门禁还要落 B §2.4 的 expected_owner 硬规则：候选先过 `doc.owner == expected_owner`（权威源 owner 绑定 > 名字结构默认值），推不出 expected_owner 的候选直接出局（不进③）；权威源没回答时，验签通过的候选也最多以 unproof 露面。

- [ ] **T2.2** 删三处组内 `join_all` 并发。"同一渠道多个读取端"（镜像、网关）的并发是 provider 内部实现细节（`HttpsProvider` 可对多 gateway 并发），不是解析引擎的结构。
- [ ] **T2.3** `Expired` 分支现在被 `allow_cache_when_authority_unavailable` 门控（[name_query.rs:259-268](../src/name-client/src/name_query.rs:259)），名实不符。改为：`Expired` 返回专门错误；"是否用过期缓存兜底"统一收到 NameClient 的策略点④（P3）。`ResolvePolicy` 相应收缩：保留 `follow_migration / allow_self_signed_when_missing / max_depth + visited / local_authority_override`，删 `allow_cache_when_authority_unavailable`（语义移到 NameClient 层的 `allow_stale_cache`）。
- [ ] **T2.4** 验证核**零改动搬运**：`verify_and_select_document` / `verify_document_candidate` / `verify_owner_root_candidate` / `verify_owned_candidate`（[name_query.rs:550-839](../src/name-client/src/name_query.rs:550)）整体保留。见第 4 节清单。

验收：主循环单函数可通读（目标 ≤120 行），B 的四个策略点能在注释里逐一指认；name_query 的 18 个测试只改 mock 搭建方式（authority/supplement 两类），断言不变。mock 重写时注意保持真实签名链（历史教训：收紧验证后，走捷径的 fixture 会成批爆掉）。

### P3 —— 缓存层：负状态 + 真快路径 + 单一 merge（规模 M，~2 天）

- [ ] **T3.1**【补缺】**负状态缓存**：现状 `Disabled` 只删正缓存不存负状态（[name_client.rs:659-666](../src/name-client/src/name_client.rs:659)）。按 B §2/策略点①：负状态写入缓存条目；快路径命中负状态返回错误而不是"没命中"，**TTL 过期不使其失效**；merge 对负状态条目拒写，只有权威源的新状态能翻篇。
- [ ] **T3.2** **真快路径**（按 D3 决策）：in-TTL 正缓存直接返回 `CacheStatus::Hit`。删掉现在的迂回——命中缓存后仍带 `max_trust_level` 查更权威 provider、失败后经错误兜底路径把真命中标成 `Fallback`（[name_client.rs:543-594](../src/name-client/src/name_client.rs:543) + :667-690）。`max_trust_level` 参数从 `query_did / query_did_ex` 签名中移除。B §5 的对应表述："进入解析流程，就意味着缓存已经失效"。
- [ ] **T3.3** `doc_cache.rs`（1827 行）瘦身：Fs/Db/Mem 三个后端各复制了一份 update/insert/撤销校验逻辑，上提到 `DIDDocumentCache` 一层，后端退化为纯 KV。merge 规则同时对齐 B §5：**先证据档、同档才比 version/iat**——现状用 `trust_level` 充当 rank 代理（[doc_cache.rs:983](../src/name-client/src/doc_cache.rs:983)），改为持久化证据档（三档）。
- [ ] **T3.4** owner 撤销校验现有**三处**：NameQuery 验证时（revoke_before_iat）、NameClient 读缓存的 replay guard、`doc_cache` insert 时的 `validate_owner_revocation`。收敛为两处：读时 guard 保留（防"缓存之后 owner 才声明吊销"），写入校验留一处（NameClient 写前与 cache insert 二选一，删掉另一份）。

验收：doc_cache.rs 目标 -40% 行数；新增负状态测试：吊销 → 权威源断网 → 解析仍返回吊销错误（而不是 fallback 到旧缓存）。

### P4 —— 文档归一（规模 S，~0.5 天）

- [ ] **T4.1** 给 B 打 5 个补丁（与代码改动同步，其中 1 随 T2.1 落地）：
  1. **已于 2026-07-02 完成**：B §3 伪代码已带候选入场门禁（`authority_unknown` → 候选最多以 unproof 露面，且要求本地对该 (did, doc_type) 零记忆、策略放行）与循环尾负状态屏蔽（不受 TTL 约束）。实现随 T2.1 落地（AuthorityAnswer 入场状态即此语义）；
  2. **已于 2026-07-02 完成，并加强为 expected_owner 硬规则**（B §2.2/§2.4/§3/§4/§8-5）：验签用的 owner 只能来自权威源 owner 绑定（可不带文档单独返回；owner 变更/委托的唯一发布口）或名字结构默认值（`app1.alice → alice`；自证 DID → 自身；一级名字推不出），`doc.owner` 不一致直接拒绝。代码现状只有“权威源在线给出 effective_owner”这一半的 OwnerConflict（[name_query.rs:719](../src/name-client/src/name_query.rs:719)）；实现缺口并入 T2.1：结构默认值推导、验签递归目标改用 expected_owner（而非候选自声明 owner）、推不出 expected_owner 的候选直接出局；
  3. §2.3 注明 info 类 doc_type 的分流发生在查发布状态**之前**，不受 Missing/负状态门禁影响（代码已实现：[name_query.rs:144](../src/name-client/src/name_query.rs:144)）;
  4. 新增一小节：TTL 快路径的显式取舍（吊销可见性最多滞后一个 TTL）+ 负状态缓存不受 TTL 约束的语义；
  5. 策略点③（unproof）标注"设计保留，当前不实现、默认关闭"（D1）。
- [ ] **T4.2** [resolve_did重构.md](./resolve_did重构.md) 头部加声明：§2（trust_level 分层）、§3（注册表/caps）、§10（组内并发查询）已被 B 的"单权威 + 补充源"模型取代，以 B 为准；§5.1/§6/§8 的验证语义与 §12 可达性敏感发布保留为参考；`lineage_epoch` / owner-at-iat 历史校验 / `validFrom` 延迟激活移入"待 BNS 合约上线"backlog。按 A §0 原计划，最终与 [resolve-did.md](./resolve-did.md) 合并。
- [ ] **T4.3** [http_did_resolver_api.md](./http_did_resolver_api.md) 随 T0.6 同步裁字段。
- [ ] **T4.4** [resolve_did重构_TODO.md](./resolve_did重构_TODO.md) 标记完结，指向本文件。

## 4. 简化中不能弄丢的资产（勿回退清单）

以下均已实现且正确，是红线的落点。P1/P2 重写时逐条对照：

1. **OwnerConflict 校验**（[name_query.rs:717-731](../src/name-client/src/name_query.rs:717)）：文档自声明 owner ≠ 权威源 `effective_owner` 时拒绝——A 红线 13.5。B 已于 2026-07-02 补上并加强为 expected_owner 硬规则（B §2.4/§4）：新增名字结构默认值兜底、“推不出 expected_owner 就不得用自声明 owner 验签”，实现随 T2.1 落地。
2. **info 前置分流**（[name_query.rs:140-148](../src/name-client/src/name_query.rs:140)）：免验证 doc_type 在查发布状态之前豁免，不进状态机——A 红线 13.12。
3. **契约违规 ≠ 验证失败**（`CandidateRejection`，[name_query.rs:19-22](../src/name-client/src/name_query.rs:19)）：无签名的 SelfSigned JsonLd 记 warning 丢弃，一份坏 body 只作废它自己——A 红线 13.11 / B 规则 6。
4. **历史 key 验签 + `SignedByHistoricalKey` warning**（[name_query.rs:794-823](../src/name-client/src/name_query.rs:794)）：正常 key rotation 不否决旧文档。
5. **owner 递归收紧 + 防环**（[name_query.rs:736-739](../src/name-client/src/name_query.rs:736)）：`for_authority_lookup()` 关闭 fallback + `descend()` 访问集/深度上限。B 说一跳约定下防环"天然不需要"，但 20 行的保险防的是 method 声明错误，保留。
6. **`Disabled` 短路语义**：负状态终止解析、不被同组/低优先级成功结果掩盖（`stop_on_disabled_error` 等测试）。
7. **本地覆盖纪律**（[provider.rs:744](../src/name-client/src/provider.rs:744), [name_client.rs:619-625](../src/name-client/src/name_client.rs:619)）:打标、带 scope、不进普通缓存、不参与合并。
8. **`UnauthenticatedInfoCache` 与 doc_cache 隔离**：info 只按 iat/ttl 判可用，不做 owner replay guard，不得提升为已验证档。

## 5. 验收标准："简单了"的可度量定义

- `NsProvider` trait：10 个方法 → 4 个（`get_id / query / resolve_did / fetch_document_body`）。
- provider.rs 对外类型：~25 个 → ~12 个；解析路径总行数（name_query + provider 类型部分）预期 -40%。
- 解析主流程 = NameQuery 一个函数 + NameClient 一个函数，与 B §3 伪代码逐段对应，合计 ≤250 行。
- 概念核对：代码中出现的解析概念 ⊆ B 词表（DR/unknown、权威渠道/补充源、证据三档、四个策略点、owner 递归基、负状态、本地覆盖）。
- **新人测试**（最终判据）：一个没读过 A 的工程师，只读 B（约 240 行）+ 上述两个函数，能正确回答三个问题——"吊销之后 fallback 会发生什么？""权威源断网时会发生什么？""Missing 时自签名文档什么时候能用？"

## 6. 对外兼容性

- `lib.rs` 全局函数（`resolve_did / resolve_did_ex / resolve_owner_config / resolve_auth_key / ...`）与 `ResolvedDocument` 三段式结构签名不变——仓库外（buckyos 主仓）的调用方不感知本轮改动。
- `NameClient::add_provider(provider, trust_level)` 签名改为按角色注册；仓库内唯一外部调用点在 `buckyos-http-server/src/test_did_obj_server.rs`。
- `NameQuery::query_did` 返回值中的 `trust_level` 失去原语义，兼容层返回证据档或 0；确认调用方后可整体废弃。
- 测试规模预估：全仓 108 个相关测试，约 60 个需机械性改造（mock 从 trust_level/caps 改为 authority/supplement 声明），断言语义不变。
