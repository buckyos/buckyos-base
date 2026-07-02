# resolve_did 重构 TODO

本文档给执行实现的 Code Agent 使用。背景：[resolve_did重构.md](./resolve_did重构.md) 是设计文档；`c961267 "upgrade did-resolve"` 是第一版实现提交，范围限定在 `src/name-client/`。对照设计文档做过一轮 review，结论是：**类型体系和兼容 API 已经落地，但设计文档反复强调的核心机制——owner 递归验证、BNS PublishedState 状态机——基本没有接入实际解析路径**。当前 `resolve_did` 在生产路径上的行为和重构前基本一致（选 trust_level 最高、version/iat 最新的自签名候选），签名验证、owner 一致性校验、Revoked/Tombstoned 状态目前都不会真正生效。

**执行原则**：
- 每个任务给出问题定位（file:line）、要做什么、验收标准（要跑通的测试/新增测试）。开工前先用 `grep`/`Read` 核对文件当前内容，行号可能已随其它改动漂移。
- 任务按依赖顺序分了 Phase，同一 Phase 内的任务原则上可以并行，但 Phase 之间有依赖，不要跳跃。
- 每完成一个任务，跑 `cd src && cargo test -p name-client --lib` 确认不引入回归，再继续下一个。
- 不要为了让测试通过而放宽正常环境的解析规则（设计文档第 13 节"必须避免的行为"，这是硬约束）。

---

## Phase 0 — 修复现有实现里的假活/死代码（无外部依赖，可立即开工）

### T0.1 修复 `DocumentStatus::Migrated` 分支的假递归

- **位置**：`src/name-client/src/name_query.rs:196-212`（`resolve_from_published_state` 内）
- **问题**：无论 `policy.follow_migration` 是 true 还是 false，代码都直接 `return Err(...)`，从未真正解析 migration target，和设计文档第 9 节伪代码（`return resolve_did_document(state.alias_target_did()?, ...)`）矛盾。
- **要做的事**：
  - 当 `policy.follow_migration == true` 且 `state.migration_target` 存在时，应该真正递归调用解析（当前 `NameQuery::query_did_ex` 不是 `&self` 递归安全的 async fn boundary 问题需要处理——用 `Box::pin` 包一层或者把递归入口放在 `NameClient::resolve_did_ex` 层，取决于 T1.x 完成后的递归结构，建议和 T1.1 一起做，避免实现两套递归框架）。
  - 递归调用前必须走 `policy.descend(target_did, doc_type)`（见 T0.2）做环路/深度检查。
  - `follow_migration == false` 或没有 `migration_target` 时，保留现有的 `Err(NSError::Disabled(...))` 语义。
- **验收**：新增测试，mock provider 返回 `PublishedState { document_status: Migrated, migration_target: Some(other_did), .. }`，验证 `follow_migration=true` 时最终解析到 target 的文档；`follow_migration=false` 时返回 Disabled 错误。

### T0.2 把 `ResolvePolicy::descend()` / `for_authority_lookup()` 接入真实调用路径

- **位置**：定义在 `src/name-client/src/provider.rs:559-587`；目前全仓库没有调用点。
- **问题**：这两个方法是文档第 9/11.1 节要求的递归防护（环路检测、深度上限、递归 owner 时收紧 policy），现在是死代码。
- **要做的事**：
  - 在 T1.1（owner 递归）和 T0.1（migration 递归）里，每次进入下一层递归解析前必须调用 `policy.descend(&did, doc_type)?`，深度超限或成环要返回明确错误（不要静默截断）。
  - 解析 owner 文档时必须用 `policy.for_authority_lookup()` 收紧后的 policy（关闭 self-signed/gossip fallback）。
- **验收**：构造一个人为的 owner 循环引用（A 的 owner 是 B，B 的 owner 是 A）的测试，确认在 `max_depth` 内报错而不是死循环/栈溢出。

### T0.3 修正 `requires_verification` 的聚合逻辑

- **位置**：`src/name-client/src/name_query.rs:125-127`
- **问题**：`matched.iter().all(|(provider, _)| provider.requires_verification(doc_type))`——只要一个 provider 认为该 doc_type 免验证，就会把所有匹配的 provider（包括认为需要验证的）一起降级进 unauthenticated 路径。这和设计文档第 1.3 节"`requires_verification(doc_type)` 是该 DID method 的显式声明"不符——应该是同一 method 内所有 resolver 对同一 doc_type 有一致声明，而不是取并集里最弱的那个。
- **要做的事**：
  - 改为以 `did.method` 为单位取"该 method 的权威声明"，而不是对 `matched` 里所有 provider 做布尔聚合。具体做法：优先找 `trust_level` 最小（最权威）的 provider 的 `requires_verification(doc_type)` 结果作为该 method 的判定；如果实现上暂时无法确定"谁是权威"，至少改成 `.any()`（任一 provider 认为需要验证就应该走验证路径），避免"一个不严谨的 provider 就能让所有 provider 一起被降级"的安全隐患。
  - 补充一条注释或文档说明这是"同一 doc_type 在同一 method 内的解析器必须对是否需要验证达成一致"这个契约的假设，而不是运行时协商。
- **验收**：新增测试，同一 method 下注册两个 provider，一个 `requires_verification("zone") == false`、一个默认 `true`，确认修复后仍然按验证路径处理（不会被错误 provider 拖到 unauthenticated 路径）。

---

## Phase 1 — Owner 递归验证（设计文档第 5/6/9 节，整个重构的核心）

> 这是最大的缺口：目前 `query_did_ex` 是单层扁平调用，从不为 owner 递归；`choose_best_body`（`name_query.rs:484`）只检查 `body.document.is_proof()`（即"是不是 JWT 格式"，`is_proof()` 定义见 `src/name-lib/src/did.rs:281`，纯格式判断，不做签名验证），没有任何针对 owner key 的签名校验。resolve 目前不是信任边界。

### T1.1 引入 `VerificationRoot` 枚举和 `resolve_verification_root_for_document`

- **参考**：设计文档第 9 节 `VerificationRoot` / `resolve_verification_root_for_document` 伪代码。
- **要做的事**：
  - 在 `provider.rs` 新增：
    ```rust
    pub enum VerificationRoot {
        MethodAuthority,
        Owner(OwnerContext), // OwnerContext 至少要能拿到 owner 的公钥材料
    }
    ```
  - 明确"谁是递归基"：为 `did method` 增加一个判定点（可以是 `NsProvider` 新增方法 `fn is_owner_root(&self, did: &DID, doc_type: &str, published: Option<&PublishedState>) -> bool`，默认对 `doc_type == "owner"` 返回 true），对应设计文档第 6.4 条"owner 解析是递归基"。
  - 在 `NameQuery`（或新建的递归入口，建议命名贴近设计文档的 `resolve_did_document` 以便未来对照）里，对每一份候选 body：
    1. 解析出文档自声明的 owner（`declared_owner`）。
    2. 如果是递归基（`doc_type == "owner"` 或 `is_owner_root` 为 true），直接用 method authority 校验（当前 method 自证 key，例如 `did:dev` 用 DID 自身的 key）。
    3. 否则递归调用解析 `declared_owner` 的 `"owner"` 文档（套用 T0.2 的 `descend`/`for_authority_lookup`），拿到 owner 文档后作为验证根。
- **验收**：新增集成测试，构造一个两层链路（普通 zone 文档 -> 递归解析其 owner 文档 -> owner 文档的验证根落到 method authority），验证能正确递归拿到 owner 公钥。

### T1.2 补上真正的签名验证

- **问题**：目前全仓库没有在 resolve 路径里对 JWT 类型的候选文档做"用 owner key 验证签名"这一步，`is_proof()` 只是格式判断。
- **要做的事**：
  - 检查 `name-lib` 里现有的 JWT 解码/校验能力（例如 `OwnerDocument::decode`、`jsonwebtoken::decode` 的现有用法，参考 `src/name-lib` 里已有的 owner/device 文档校验代码作为起点，不要重新发明）。
  - 在拿到 `VerificationRoot`（T1.1）之后，新增一步：用 verification root 提供的公钥，对候选文档执行真正的 JWT 签名验证；验证失败的候选要被丢弃（不能进入 `compare_document_body` 参与排序）。
  - 区分"验证失败"和"证据契约违规"（设计文档第 13 节第 11 条）：结构上不可能验证的（如 `SelfSignedCandidate` 但是 `JsonLd` 编码）算契约违规，直接丢弃并记 `ResolveWarning::EvidenceContractViolation`；能验证但签名不对的，算验证失败。
- **验收**：新增测试，构造一份用错误私钥签名的候选文档，确认它不会被选中；用正确私钥签名的能被选中。

### T1.3 owner 一致性校验（`OwnerConflict`）

- **参考**：设计文档第 5.1 节。
- **要做的事**：
  - 当存在权威发布源的 `effective_owner`/`effective_owner_at(iat)` 时，检查文档自声明的 owner 和权威源记录的 owner 是否一致；不一致要拒绝该文档（新增 `ResolveError`/`NSError` 变体，比如 `OwnerConflict { declared_owner, authority_owner, iat }`）。
  - 目前 `PublishedState::effective_owner` 字段已经存在（`provider.rs:190`）但从未被赋值或读取过，这一步要把它真正用起来。
- **依赖**：这一条依赖 Phase 2 的 BNS `PublishedState` 才有真实数据源，如果 BNS 部分还没做，先用 mock provider 覆盖测试逻辑，接口和校验逻辑先写好。
- **验收**：mock 一个 published_state provider 返回 `effective_owner = X`，候选文档自声明 owner 是 `Y`，确认解析报错；两者一致时正常通过。

---

## Phase 2 — OwnerDocumentPolicy（设计文档第 6 节）

### T2.1 引入 `OwnerDocumentPolicy` 结构体，替换 `ResolvePolicy` 里的扁平布尔值

- **位置**：`src/name-client/src/provider.rs:539-588`（现有 `ResolvePolicy` 只有 `allow_self_signed_when_missing: bool` / `allow_cache_when_authority_unavailable: bool` 两个全局布尔值，不是按 doc_type 区分的）。
- **要做的事**：
  - 新增：
    ```rust
    pub struct OwnerDocumentPolicy {
        pub revoke_before_iat: Option<u64>,
        pub allow_self_signed_when_missing: HashMap<String, bool>,
        pub allow_cache_when_authority_unavailable: HashMap<String, bool>,
        pub reachability_sensitive: HashMap<String, ReachabilityPolicy>, // ReachabilityPolicy 可以先留空 struct，Phase 4 之外的内容
    }
    ```
  - 这个 policy 应该来自 T1.1 递归解析出的 owner 文档（`VerificationRoot::Owner(ctx).owner_document_policy()`），不是像现在这样挂在调用方传入的 `ResolvePolicy` 上。`ResolvePolicy`（进程级/调用级配置：`follow_migration`、`max_depth` 等）和 `OwnerDocumentPolicy`（owner 自己声明的、随 owner 文档一起解析出来的策略）要分清楚，不要合并成一个结构体。
  - `revoke_before_iat`：候选文档 `iat <= revoke_before_iat` 时即使签名合法也要拒绝，在 T1.2 验证通过之后、加入候选集之前做这个检查。
- **验收**：测试 owner 文档声明 `revoke_before_iat = 1000`，一份 `iat = 900` 的合法签名文档被拒绝，`iat = 1100` 的正常通过。

---

## Phase 3 — BNS PublishedState 接入（设计文档第 4/5/8/10/11.3 节）

> 这是让新状态机在生产环境"活起来"的关键一步。目前 `BnsProvider::caps()`（`src/name-client/src/bns_provider.rs:75-83`）里 `published_state: false`，`query_did` 直接转发给 `HttpsProvider`，`resolve_from_published_state`（`name_query.rs:155`）对 BNS 永远拿不到状态。**这一 Phase 依赖 BNS 合约/RPC 接口实际可用，如果合约还没上线，先把接口和数据映射写好，用假的/mock 的 RPC 响应跑通单测，等合约就绪后替换真实调用即可。**

### T3.1 实现 `BnsProvider::resolve_published_state`

- **要做的事**：
  - 调用 BNS 的 `resolveDocument(name, docType)`（或对应 RPC），把返回结果映射成 `PublishedState`（`provider.rs:180-198`），正确填充 `document_status`、`document_ref`、`document_version`、`effective_owner`、`owner_source`、`authority_root`、`authority_seq`、`canonical_id`/`migration_target`（如适用）。
  - 更新 `BnsProvider::caps()`，把 `published_state` 改成 `true`。
  - 注意设计文档第 11.3 节的定位：BNS provider 不应该只是 `HttpsProvider` 的薄封装，`resolve_published_state` 要有自己独立的状态解析逻辑，`fetch_document_body` 可以继续复用通用 HTTP 拉取。
- **验收**：用一个假的 BNS RPC mock（或本地 HTTP mock server），覆盖 `Active`/`Missing`/`Revoked`/`Tombstoned`/`Migrated`/`Expired` 六种状态，确认 `NameQuery::resolve_from_published_state` 对每种状态的分支行为符合设计文档第 9 节（尤其是 Revoked/Tombstoned 必须硬拒绝，不能被后续 fallback 绕过）。

### T3.2 补充 `Negative` 证据的处理

- **位置**：`choose_negative_state` 在设计文档第 10 节伪代码里存在，当前实现完全没有对应函数。
- **要做的事**：当 published_state 查询本身不返回状态但返回强负证据（比如 transport 层明确拒绝、而不是网络错误）时，要能正确映射成 `DocumentStatus::Missing`/`Tombstoned` 而不是被误判成普通 `NotFound`（对应设计文档第 13 节第 4 条"provider transport error 不能被误解释为 Missing 或 Revoked"，注意这条是反过来也要防：真正的强负状态不能被误判成普通网络错误而被后续 fallback 悄悄绕过）。

---

## Phase 4 — Cache 四分结构与 local_authority_override（设计文档第 7 节）

> 优先级低于 Phase 1-3：如果 BNS 合约上线前需要在测试环境模拟"已发布"效果，这一 Phase 就要提前；否则可以放在 Phase 3 之后再做。

### T4.1 local_authority_override（hosts 文件式测试覆盖）

- **要做的事**：
  - 在 cache 层（`src/name-client/src/doc_cache.rs`，当前是扁平 `(EncodedDocument, exp, trust_level)` 结构）新增一个独立的 override 存储，不要和普通 cache 混在一起（设计文档第 7.3 节明确要求"默认不得导出、广播或同步到普通 cache"）。
  - 提供显式写入 API（只能由本地管理员/测试框架调用，不能通过普通 resolve 流程写入）。
  - 解析主流程（T1.1 递归函数）里，在查 `PublishedState` 之前先检查这个 override，命中则直接返回并打上 `ResolveWarning::LocalAuthorityOverride`（这个枚举值已存在于 `provider.rs:283`，目前从未被构造过）。
- **验收**：测试里写入一个 override，确认它的优先级高于任何 provider 返回的结果，且带有 `LocalAuthorityOverride` warning；确认它不会被序列化进普通 cache 文件。

### T4.2 verified_cache / unauthenticated_info_cache 分离

- **要做的事**：把现有 `doc_cache.rs` 的单一缓存拆分成设计文档第 7.2/7.4 节描述的两类，行为差异点：
  - `verified_cache` 只能在权威源 Missing/不可达且 policy 允许时使用，且要能标注 `CacheFallback`。
  - `unauthenticated_info_cache` 不受 `Missing`/`revoke_before_iat` 等 Document 门禁影响，只按 `iat/ttl/source_rank` 判断可用性。
  - 现有的 `validate_owner_revocation`/`evict_revoked_docs` 机制（`doc_cache.rs:388-453`）先保留，作为 `verified_cache` 淘汰逻辑的一部分整合进去，不要重复造一遍。

---

## Phase 5 — 收尾/一致性清理

### T5.1 让已定义但从未构造的 `ResolveWarning` 变体真正被使用

- 涉及：`EvidenceContractViolation`（`provider.rs:285`）、`SignedByHistoricalKey`、`KeyRotatedAfterIat`（`provider.rs:289-290`）、`PendingActivation`（`provider.rs:291`）。
- 在 T1.2（签名验证失败/契约违规）、T3.1（Owner key 历史轮换场景）分别接入对应位置，跑一遍全仓库 grep 确认每个变体至少有一处构造点和一处测试断言。

### T5.2（可选，低优先级）`ResolverRegistration` 结构体整合

- 当前 provider 注册是 `Vec<(Box<dyn NsProvider>, i32)>` 元组列表（`name_query.rs:15`），trust_level/caps/id 散落在不同地方。设计文档建议统一成 `ResolverRegistration { id, methods, trust_level, caps, resolver }`。
- 这是纯重构、不改变行为，优先级最低，建议放在 Phase 1-3 落地、行为稳定之后再做，避免和行为变更的 diff 混在一起导致 review 困难。

---

## 执行前的一个开放问题（需要人确认，不要自行假设）

Phase 3（BNS PublishedState）依赖 BNS 合约的 `resolveDocument` 接口是否已经有可调用的 RPC/ABI。如果合约还没上线，Phase 3 只能先写接口和映射逻辑、用 mock 数据跑测试，**不要**为了"能跑通"而放宽正常路径的判定规则（比如让 `resolve_published_state` 在拿不到真实数据时静默返回 `Active` 之类）。如果不确定合约当前状态，先去确认，而不是假设一个默认行为。
