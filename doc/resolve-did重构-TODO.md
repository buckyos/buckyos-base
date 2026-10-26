# resolve-did 重构 TODO

> 状态：M0–M6 已实施（2026-10-20；name-client 内 `cargo test -p name-lib -p name-client -p kRPC -p buckyos-http-server` 通过，buckyos / cyfs-gateway / cyfs-ndn 用本地 patch 编译并通过相关测试，三个仓库均未提交）；真实 Zone 验收未做。§5 是与 cyfs-gateway#207 的对照，由此新增 R1、R2 两处设计调整。
> 设计依据：[resolve-did.py](./resolve-did.py) 与 [resolve-did 协议冻结讨论](./resolve-did协议冻结讨论伪代码.md)（下称“设计稿”）。两份文件是本次重构的唯一设计来源；与 doc 目录下其它 resolve-did 文档冲突时以设计稿为准。
> 本文只记录：开工前必须补定的裁决、最小协议补丁、旧 API 到新 API 的映射、阶段切分、验收方式，以及重构后要清理的文档。不重复设计稿已经写清的语义。
> 标 **[已定]** 的条目原为建议裁决，2026-10-20 用户确认按建议执行；未标的是从设计稿直接推出的结论。

## 0. 为什么还要这份 TODO

设计稿在版本模型、三档来源 + locker、验证报告、Owner 双查询、请求门禁与预算这五块已经写到可以直接翻译成代码。但有四处缺口不是 wire 细节，而是决定代码结构的：

1. 普通 JWT 验签依赖 `Revision.closest(doc.iat)` 的 Owner，而现有 resolver 协议没有版本化查询；不补规则，重构后所有普通来源验证都会退化成 unknown。
2. `scope`、缓存后端、trust 来源的写入边界、核心类型没有定义。
3. 设计稿推翻了 2026-07-17 已实施的 `resolve / verify / add_cache` 三动词模型，但没有对照表；buckyos、cyfs-gateway、cyfs-ndn 共 17 个文件在用旧 API。
4. `doc_type = None` 的语义和验证依赖集合没有定，而它们决定缓存键和 `refresh_known_constraints` 的检查范围。

另外设计稿没有“实现迁移顺序”一节，doc 目录下多数 resolve-did 文档仍描述现有实现，重构后会整体过时。

## 1. 开工前裁决

### D1. publish_info 版本化查询与 closest 推导规则

**问题。** 现有 `PublishedState` 只有当前状态和 `document_version`（= 当前发布 iat），`NsProvider::resolve_published_state` 不接受版本参数。设计稿要求 exact 回答带该 iat 的实际发布 hash，closest 回答还要确认查询边界内没有更高版本，并明确禁止“缺历史材料时用当前 Owner 冒充”。[http_did_resolver_api.md §7](./http_did_resolver_api.md) 现行规则是 resolver 返回 501 时“退化为使用当前 owner”，与设计稿直接冲突。

**裁决 1a：closest 可由 current 回答推出（写入设计稿 §1 与 §6）。**

设 authority（或 locker 模拟发布）对 `(owner_did, "owner")` 的 current 回答为 L = (iat_L, hash_L, body_L)。因为 L 是 latest，区间 (iat_L, +∞) 内不存在已发布版本，所以：

- 对任意 `query_iat > iat_L`，`closest(query_iat) = L`，边界条件自动成立；
- 对 `exact(iat, hash)`，当 `iat == iat_L && hash == hash_L` 时直接命中；
- `query_iat <= iat_L` 时必须走真正的历史查询，推导不适用。

推出的 closest/exact 回答按完整查询分槽缓存，证据指向产生它的 current receipt，TTL 与该 receipt 相同；trust/normal 来源的 body 不能用于推导。这条规则让“签发时间晚于当前 Owner 发布时间”的文档（绝大多数设备/应用文档）在现有协议下就能完成验签，只有 Owner 换版之后仍在流通的旧文档需要历史查询。

**裁决 1b：最小 wire 补丁（落在 http_did_resolver_api.md，M0 完成）。** 在现有 `GET /1.0/identifiers/{did}?type=...` 上增加可选参数，不新开端点：

| 参数 | 语义 | 回答必须包含 |
| --- | --- | --- |
| 无 | current（现有行为） | 现有信封；`docHash` 从可选改为 Active 时必填 |
| `versionId=<iat>` | exact | 该 iat 的 `{iat, docHash, status: published / notPublished}`；当前 `latestIat` |
| `versionTime=<iat>` | closest，**严格早于** | 选中版本 `{iat, docHash}`，`latestIat`，`boundaryConfirmed: true` |

- 不支持历史查询的 resolver 返回 501 + `historicalQuerySupported: false`；客户端归一为 `Unknown("此来源不支持指定版本/closest 查询")`，**不**回退 current。§7 的退化规则废除。
- `documentStatus` 负状态保留现有覆盖范围说明：DID 级 / 类型级 / 版本级分别标注，对应设计稿 §2.2“负状态只覆盖它明确声明的范围”。
- 新增类型级负状态 `documentStatus: "invalid"` + `reason`：authority 对该 `(did, doc_type)` 做过确定性校验且拒绝（如 BNS 的 device/zone 身份不一致）。它是**明确回答**而不是 Unknown：HTTP 200，可缓存（短 TTL），选择时等同 NotExist，不升级为 DID 禁用，不阻止 trust/normal 候选按 owner 链验签。只有真正的瞬时错误（上游 RPC 失败、投影变更）才用 5xx。来源：#207 评论 C1，见 §5 R2。
- **[已定]** `versionTime` 沿用 W3C DID Resolution 的参数名，binding 里写死“严格早于”语义（W3C 原义是 `iat <= T`），不另造 `beforeIat`。
- Zone locker（zone-resolver-server）同一套参数，在自己的 scope 内可模拟回答；body 与 publish_info 分列回答。
- 测试用 mock authority 必须实现全部三种查询和 501 分支，否则 §10 验收表里 exact/closest 的用例无法执行。

### D2. 数据模型

**裁决 2a：scope。** **[已定]** 定义为 `enum Scope { Host, Zone(DID) }`。普通缓存和本机 locker 属于 Host；Zone locker 的回答携带 Zone(zone_did)；缓存键、串行锁键、任务合并键里的 scope 就是这个值。它只标识信任域，不授予远程写权限。

**裁决 2b：缓存后端。** **[已定]** 设计稿写 sqlite，[update-did-cache.md](./update-did-cache.md) 记录的决定是“SQL 后端已删除、目录即证据”。两者冲突，按下面方案：

- doc_result / publish_info / 查询回答 / receipt 用嵌入式 KV 或 SQL 单文件存储，需要跨进程原子合并（同 iat 不同 hash 的裁决靠 rename 做不到）。workspace 已有 `redb` 依赖（`persistence` feature），优先评估复用，不够再引 sqlite。
  **M3 评估结论：** `redb` 是单进程独占打开（第二个进程打开同一文件得到 `DatabaseAlreadyOpen`），而同一主机上 node_daemon、cyfs-gateway、各服务进程都持有自己的 NameClient 并共享同一缓存目录，不满足跨进程合并；sqlite 需新增依赖。最终采用"每键一个 JSON 结果文件 + 同名 `.lock` 文件上的 OS 文件锁（`std::fs::File::lock`，rustc ≥ 1.89）"做读-改-写：段 2 在锁内重读存储最新结果再合并，不持锁等待任何网络 I/O；内存后端提供同样的串行语义。查询回答与 receipt 只在进程内存中，不落盘。落点 `resolver/store.rs`。
- 现有 `verified/` 与 `unverified/` 目录的安全边界用另一种方式保留：数据库文件只有 name-client 特权进程可写；其它本机进程投递候选只能经一个“收件箱”目录（即今天的 `unverified/`），收件箱里的文档一律按 `Source.normal()` 进入 candidates。`Source.configured_trust(...)` 只能由进程内配置（预装、本机 locker 配置）构造，不能从收件箱或任何远端 payload 产生。
- `allow_local_cache=false` 时用内存后端，语义不变。

**裁决 2c：核心类型草图（M1 落地，命名以 Rust 为准，不再沿用伪代码拼写 `revesion`）。**

```rust
pub enum Revision { Current, Exact { iat: u64, hash: ContentHash }, Closest { before_iat: u64 } }
pub struct DocRevision { iat: u64, hash: ContentHash }               // 文档身份

pub struct ResolveOpts {                                              // 伪代码 Opts
    scope: Scope, network_sources: NetworkSources, allow_request: bool,
    allow_local_lock: bool, allow_zone_lock: bool, allow_local_cache: bool,
    transport_policy: TransportPolicy, force_authority_query: bool,
    budget: Arc<Budget>, cancel: CancellationToken, receipts: Arc<ReceiptSet>,
    visited: Vec<(DID, DidDocType)>, connect_timeout, request_timeout,
}
pub enum SourceTier { Authority, Trust, Normal }
pub struct SourceAnswer { body: Option<ExactDocument>, publish_info: Option<PublishInfo>,
                          reason: Option<String>, cacheable: bool, carrier: Carrier, source: SourceRef }
pub struct PublishInfo { did_state, type_state, owner_binding: Option<DID>,
                         records: Vec<PublishRecord>, latest_iat: Option<u64>, boundary: Option<Boundary> }
pub struct VerifyResult { validity, is_signed, is_published, is_revoked, is_expired, is_disabled,
                          is_best, is_latest, is_exact, is_closest, reasons, missing,
                          dependencies: Vec<Dependency>, locker_version }
pub struct DocResult { state, latest, best, history, candidates, slots: HashMap<Revision, Slot>, query_answers }
```

- `ExactDocument` 保留 JWT compact 原文或 JSON 规范化序列化，hash 规则沿用 `document_content_hash`，并保留“不得开启 serde_json preserve_order”的防护测试。
- Owner 撤销线使用 name-lib 现有字段 `OwnerDocument.valid_iat`；伪代码的 `mini_iat` 不另起名。`mini_version_seq` 随本次删除。

### D3. 与已实施三动词模型的对照

**裁决 3a：verify_document 的默认 opts。** **[已定]** 设计稿明确 verify 可按 opts 取材料并写缓存。默认 opts 与 `resolve_did` 便捷入口一致（本机 locker + Zone locker + 磁盘缓存 + 联网），只保留一套默认值；但 2026-07 模型的理由（握手等攻击者可触发路径的查询放大）仍然成立，因此下列入站路径在迁移时**必须**显式传 `not_allow_request()`，并在 M6 用测试断言网络调用为 0：

- cyfs-gateway `rtcp.rs` 入站 hello 与 `rtcp_stack.rs` 的对端文档处理；
- cyfs-gateway `bns-server` 对外查询入口；
- buckyos-base kRPC S2S 入站身份校验（若经 name-client fallback）。

未采用的替代方案是 verify 默认离线、resolve 默认联网：两套默认值更安全，但调用方更容易在“为什么 unknown”上踩坑。

**裁决 3b：旧 API 映射（M6 一次性 breaking，不留兼容层，与 2026-07 重构做法一致）。**

| 现有 | 去向 |
| --- | --- |
| `resolve_did(did, Option<DidDocType>)` | 保留签名；`None` 按 D4 归一后进入 `resolve_did_ex` |
| `resolve_did_ex(did, doc_type, ResolvePolicy)` | `resolve_did_ex(did, doc_type, Revision, ResolveOpts) -> DocResult` |
| `ResolvePolicy.source: ResolveSourcePolicy` | 拆为 `allow_request` + `network_sources` + `allow_zone_lock` + `allow_local_lock`。LocalOnly = `not_allow_request().without_zone_lock()`；LocalAndZone = `not_allow_request()`；RemoteAuthority = `with_network_sources(AuthorityOnly).with_force_authority_query()`；BestAvailable = 默认 |
| `use_zone_resolver` | `allow_zone_lock` |
| `local_authority_override` / `LocalAuthorityOverrideStore` | 本机 locker（`local_locked`），配置版本进入 `locker_version` |
| `allow_self_signed_when_missing` | 删除。普通 JWT 有可信 owner 绑定且验签通过即 valid，authority Missing 只影响 `is_published`；RTCP 未发布设备准入因此从 opt-in 变为默认允许，上游若要收紧改用 `success(Revision::Current)` 之外的业务门禁 |
| `allow_stale_cache` / `allow_unverified_cache_when_unavailable` | 删除。best 在 exp 内始终可选；候选未验证通过不返回 |
| `follow_migration` / `DocumentStatus::Migrated` | **[已定]** 保留 Migrated 为 publish_info 的 DID 级负状态并携带 target，resolver 对该 DID 返回 disabled + reason，不自动跟随；是否跟随由调用方决定 |
| `current_zone_did` / `add_current_zone_bootstrap_supplement` | **[已定]** 保留为 Normal 档 provider，仅当 `opts.scope == Zone(did)` 且请求 DID 等于该 Zone 时可用；不再挂在 policy 上 |
| `verify_did_document(.., &VerifyContextSnapshot, VerifyOptions)` / `build_verify_context` | `verify_document(did, doc_type, body, Revision, ResolveOpts) -> VerifyResult`；snapshot 类型删除 |
| `resolve_and_verify_did_document*` / `resolve_verify_and_cache_did_document` / `verify_and_promote` | 删除；语义等于 `verify_document` 默认 opts |
| `FreshnessRequirement` / `evaluate_freshness` / `LocalFreshness` / `AuthorityFreshness` / `AuthorityReceipt` | 删除；对应 `VerifyResult` 的选择标志 + `success(Revision)` + 本轮 receipt 集合；RTCP `AuthorityCurrent` 用 `select_rtcp_identity` 的 receipt 检查 |
| `VerifiedDidDocument` / `ValidityEvidence` / `VerifyError` / `VerifyDependency` | 合并进 `VerifyResult`（validity / reasons / missing / dependencies） |
| `add_observed_cache` | `commit_candidate_doc(.., Source::normal())`（收件箱路径） |
| `add_verified_cache` | 删除。业务准入通过后的“保存”在新模型里是 `verify_document` 的 valid 结果自动推进 best；需要固定某一份文档的场景用本机 locker |
| `CacheWriteOutcome` | 删除；冲突体现在 `VerifyResult.validity = invalid(conflict)` |
| `invalidate_did_cache` | `remove_doc_result`（不解锁、不抹负状态） |
| `set_method_authority` / `add_method_supplement` / `add_provider(.., trust_level)` | 显式注册 `(method, SourceTier, provider)`；`trust_level` 参数删除（核对文档 D6） |
| `NsProvider::query_did / resolve_published_state` | `get_document(did, doc_type, revision, opts)` / `get_publish_info(did, doc_type, revision, opts)`，都接收 opts 并在每一跳执行 `transport_policy` 与剩余预算；不支持者在受限路径返回 Unknown(不可缓存) |
| `PublishedState` | `PublishInfo`；`documentVersion` 仍 = iat，`registryVersion` 不消费 |
| `resolve_default_ed25519_key` / `resolve_auth_key` | 保留，内部改走新 `resolve_did_ex`；kRPC S2S 公钥 provider 契约不变（核对文档 N5） |

上游受影响文件（2026-10-20 统计，只算 `use name_client` 的生产代码）：buckyos 9 个、cyfs-gateway 7 个、cyfs-ndn 1 个，共 17 个。其中 `rtcp.rs` 同时用到 add_observed_cache / add_verified_cache / resolve_and_verify / ResolveSourcePolicy，是迁移最重的一处。

### D4. 默认 doc_type 与依赖集合

**裁决 4a：`doc_type=None` 归一发生在缓存键之前。** 并入 [resolve_did_default_doc_type_TODO.md](./resolve_did_default_doc_type_TODO.md) 的结论：`None` 表示接受 method/provider 定义的默认类型，不是 `zone` 的别名。归一规则表放在设计稿 §2.4，按输入形态：

- 路径型 DID Object / Object URL：`did-object`（设计稿已定）；
- 无对象子路径的 `did:bns:<name>`：由 BNS provider 在合约/indexer 的 active 类型集合里选择，有且仅有一个时取它，多个且无显式默认值时返回 ambiguity 错误；**[已定]** 保留“多个且含 zone 时取 zone 并 warn”的兼容分支，warn 进结果 reasons，不静默；
- BNS 对 `ood1.<name>` 的设备槽位联合校验（核对文档 N3）只挂在显式 `device` 类型查询上，不再挂在默认查询上；RTCP 等要设备文档的调用方必须传 `device`（#207 现场正是 `None` 被默认成 `zone`）；
- `did:web` 根域名：读取 `/.well-known/did.json`，实际类型由文档内容确定；
- 现有 Zone 分支 Device → Agent → Owner 的“取任意身份文档”探测（核对文档 D7）**删除**，调用方要类型就传类型。

归一之后缓存键、串行锁、验证都用真实类型；结果携带 `requested_doc_type` 与 `actual_doc_type` 供诊断。

**裁决 4b：依赖集合泛化，第一期只填 owner。** `VerifyResult.dependencies: Vec<Dependency { did, doc_type, revision, role }>`，`refresh_known_constraints` 遍历依赖而不是只看 owner revision。第一期只写入 `role = current_owner / signing_owner`；Zone membership 等关系依赖（核对文档 N3）不进 name-client，由 bns-server 等上游在自己的联合校验里处理。这样后续要加依赖不改 schema。

## 2. 阶段切分

每阶段结束要求 `cargo test -p name-client -p name-lib` 通过，且 `cargo check` 覆盖 workspace。M1 到 M5 在 name-client 内完成，旧 API 在 M6 前保持可编译但可以标 deprecated；M6 一次性切换上游。

### M0 裁决落地与协议文档同步（已完成，2026-10-20）

- 设计稿 .md 与 .py 已回写：closest 推导规则（§1、§6）、`Invalid` 负状态（§2.2）、`doc_type=None` 归一表（§2.4）、串行锁只包读缓存段与提交段（§4、§5、§7，伪代码 `_get_document` / `update_doc_result` / `verify_document` 相应改写，`get_document_by_provider` 经 `merge_or_run`）、§10 新增 4 行验收场景。
- http_did_resolver_api.md 重写：`versionId` / `versionTime`（严格早于）/ `latestIat` / `selectedVersion` / `boundaryConfirmed`；`docHash` 在 active 与版本查询中必填；`invalid` 状态（200 + reason，不得报 5xx）；501 归一 Unknown 不回退当前 owner；§7.3 客户端推导规则；§8 响应头 binding：`BuckyOS-DID-Document: jwt <compact> | json <base64url>`，单值 16 KiB，重复或超限视为损坏；§9 Zone locker 请求头 `BuckyOS-Resolve-Budget-Ms`、`BuckyOS-Resolve-No-Zone-Lock`；`type` 缺省不再约定为 zone，无法唯一确定时 `400 ambiguousDocType`；删除指向已删文档的链接。
- did-object-protocol.md §4 / §5.3 / §6.1 / §6.3：路径型对象直取原 URL，目录型补 did.json，非默认类型 `?type=`，`{object_url}/did.json` 降为兼容路由，响应头承载 Card，Card 版本与业务 ETag 分开。
- 已删除 resolve-did.md、resolve_did_default_doc_type_TODO.md；http-provider自适应响应解析-TODO.md 与 简单介绍resolve-did.md 的失效链接已改指设计稿。

### M1 核心类型与预算（已完成，2026-10-20）

- 落点：`name-client/src/resolver/{revision.rs, opts.rs, budget.rs, verify_result.rs, source.rs, publish_info.rs}`（整个重构放在 `resolver/` 子模块，`lib.rs` 全量 re-export）。
- 实际命名：`Revision { Current, Exact{iat,hash}, Closest{before_iat} }`、`DocRevision`、`ParsedDocument`（解析不等于信任）、`Budget`（tokio-util `CancellationToken` + 单调 deadline；`run(cap, fut)` 区分步骤超时与终止）、`ResolveOpts`（`normalize` 建预算与 `ReceiptSet`，`with_*` 只收紧）、`SourceTier/SourceRef/SourceAnswer/Source`、`PublishInfo { did_state, type_state, owner_binding, records, latest_iat, boundary }` + `derive_for`（D1 推导）。
- name-lib `NSError` 新增 `DeadlineExceeded` / `Cancelled`（`is_termination()`），删除 `VerifyAndPromote*`。
- `Budget`：单调 deadline、取消、`run(f, connect_timeout, request_timeout)`、`check()` 抛 `ResolutionDeadlineExceeded / ResolutionCancelled`；同步解析分片检查。
- `ResolveOpts::normalize / with_* / create_get_owner_opts` 只收紧不放宽；最外层新建 receipt 集合。
- 测试：预算耗尽不回退、副本共享 deadline、owner opts 继承限制。

### M2 来源层（已完成，2026-10-20）

- `Source` trait（`resolver/source.rs`）替换 `NsProvider` 的 DID 部分（`NsProvider` 只剩 `get_id` + `query`）；`request_source` / `gate` 统一门禁在 `resolver/resolve.rs`；`normalize_source_answer` 把 authority 的 current 裸 body 登记为发布事实（did:web 静态发布面）。
- `resolver/http.rs`：`DocumentLocation` + `build_document_request_url`（目录/路径/resolver API/兼容路由）、`document_answer_from_http`（信封、裸 body、`BuckyOS-DID-Document` 头、冲突拒绝、状态码矩阵）、`read_response`（预算内读取，头载体时不下载大 body）。
- `https_provider.rs`（`BaseHttpProvider` = resolver API 来源，`default_doc_type` 不带 type 询问）、`web_provider.rs`（目录 well-known / 对象 URL 直取 / `legacy_path_routes` 兼容 / 上级 resolver 作为版本查询入口）、`bns_provider.rs`、`dns_provider.rs`（TXT 文档缓存 + 子设备从 zone TXT 的 `DEV=` 取，注册为 zone-bootstrap normal）、`local_ns_provider.rs` 实现 `Source`。
- mock authority 在 `tests/resolve_did_scenarios.rs`：三种查询 + 501 + 负状态 + 延迟/断连注入。
- HTTP provider：`build_document_request_url`（目录/路径/旧路由分类，query 安全合并）、`document_answer_from_http`（body/header 双载体、同文档比对、大 body 不下载）、`versionId / versionTime` 查询。
- mock authority（tests 内）：三种查询 + 501 + 负状态覆盖范围 + 可注入延迟/断连。
- 落点：`https_provider.rs`、`web_provider.rs`、`bns_provider.rs` 重写；`http-provider自适应响应解析` 的逻辑被 `decode_http_source_answer` 取代。
- 测试：设计稿 §10 目录/路径/header 相关 9 行。

### M3 缓存、locker 与提交（已完成，2026-10-20）

- `resolver/doc_result.rs`：`DocResult { latest, best, history, candidates, slots, rejected, publish_info, locked }`、`commit` / `accept_verified` / `candidates_for` / `select` / `satisfies_published_target` / `refresh_known_constraints` / `merge_into`（存储代际未变则整体替换，否则按同键合并；本地已确定拒绝的版本不复活）、`locked_from`、`fill_slot_from_known`。
- `resolver/store.rs`：`DocStore`（文件 + flock / 内存；`allow_local_cache=false` 用独立内存表）、收件箱 `unverified/`（旧文件名协议兼容）+ `inbox/`、进程内查询回答缓存。
- `resolver/local_locker.rs`（`LocalLocker`，配置文件 + 版本号，模拟发布，负状态锁定）、`resolver/zone_locker.rs`（`ZoneLocker`，`BuckyOS-Resolve-Budget-Ms` / `-No-Zone-Lock` 头）。旧 `doc_cache.rs` / `zone_resolver.rs` / `verify_context.rs` / 旧 `verify.rs` 已删除。
- 本机 locker（替代 `LocalAuthorityOverrideStore`，配置文件 + 版本号）与 Zone locker 客户端（替代 `zone_resolver.rs` 快路径），顺序本机 > Zone；Unknown 放行、显式负回答强制。
- 收件箱与 `commit_candidate_doc`、`remove_doc_result`、预装 trust 候选。
- 落点：`doc_cache.rs` 重写为 `doc_store.rs`；`zone_resolver.rs` → `zone_locker.rs`；新增 `local_locker.rs`。
- 测试：同 iat 不同 hash 两进程提交、删除不解锁、locker 缺列继续查、预装被更高 iat 替代。

### M4 解析与验证主路径（已完成，2026-10-20）

- `resolver/resolve.rs`：`resolve_did_ex` / `resolve_did` / `resolve_did_revision` / `resolve_doc_type`（D4 归一）/ `get_document` / `get_publish_info` / `get_document_by_provider` / `request_source` / `select_authority_current`（RTCP AuthorityCurrent 门禁）；`resolver/verify.rs`：`verify_document` / `verify_document_ex` / `get_expected_owner` / `commit_candidate_doc` / `remove_doc_result`。Info 类型只走 locker 与进程内 `InfoCache`。
- 与伪代码的差异：owner / exact / closest 的发布目标一旦由本轮（含推导）发布依据满足就不再发来源请求；`refresh_known_constraints` 把确定撤销/过期/禁用的版本写入 `rejected`，提交合并时不复活。
- `serialize_document` 按 §5 R1 收窄：只包“读缓存并决定要发哪些查询”和“验证结果提交”两段，provider/locker I/O 阶段不持锁，去重交给 M5 的任务合并。
- Owner 双查询含 D1 推导；`finish` 优先级；选择标志针对收到的输入重算。
- 落点：`name_client.rs` 的 DID 部分拆到 `resolve.rs` / `verify.rs`，`verify_context.rs` 删除。
- 测试：§10 版本/验证相关 11 行，特别是“authority V1 + 合法 normal V2 → latest V1 / best V2”“历史签名正确但当前 valid_iat 覆盖 → is_signed 且 invalid”“缺历史 Owner 不用当前根替代”。

### M5 并发、合并与退避（已完成，2026-10-20）

- `resolver/concurrency.rs`：`DocLocks`（可取消、受 deadline 约束的同键锁，只包段 1 / 段 2）、`TaskMerger::merge_or_run`（键含访问策略；共享任务自己的预算；最后等待者离开才取消；并发 `Semaphore` + 等待队列上限）、`Backoff`（目标 + 来源 + 策略键；只对真实失败退避）、`LogThrottle`。坑：DashMap 的 `get` / `entry` 守卫不能跨 `await` 或与 `len/retain` 同时持有（曾两次死锁）。
- Zone locker 传剩余预算（`BuckyOS-Resolve-Budget-Ms`）；服务端收紧由 zone-resolver-server 实现（上游待做）。
- Zone locker 传剩余预算；服务端收紧。
- 测试：不同访问策略并发不复用网络任务；单等待者取消不影响其它等待者；RTCP outbound 场景 trust/normal 网络调用为 0、FD 在预算内释放（隔离环境）；#207 回流复现：外层默认策略解析在 I/O 中，内层受限策略同键解析不被阻塞、各自在预算内结束。

### M6 上游迁移、验收与清理（进行中，2026-10-20）

- 本仓库内：kRPC s2s（`ResolveSourcePolicy` → `ResolveOpts`，RemoteAuthority = `with_force_authority_query()`）、buckyos-http-server 测试（`set_local_authority_override` → `lock_document`，mock authority 实现 `Source`，夹具补 iat/exp）已迁移并通过测试。
- cyfs-ndn：`ndn-toolkit` 只用 `resolve_did(did, Some(Zone))`，签名不变，`cargo check` 通过（用本地 patch 编译）。
- 上游编译方法：不改上游 Cargo.toml，用 `cargo check --config <patch.toml>`，patch 文件把 `https://github.com/buckyos/buckyos-base.git` 的 name-client / name-lib / kRPC / buckyos-kit / buckyos-http-server / rbac / buckyos-tracing 指向本地路径。正式上线仍是推 buckyos-base main 后在上游 `cargo update -p name-client`。
- 按 D3 映射表迁移 buckyos、cyfs-gateway 的文件（记录见下）；入站路径加 `not_allow_request()` 并加零网络断言。
- **buckyos（已迁移，未提交，用本地 patch 编译）**：node_daemon zone_boot_resolve / active_server / finder / node_daemon、control_panel app_installer / app_install_resolver、msg_center group_publication、scheduler 测试。映射：`add_verified_cache` → `commit_candidate_doc(.., configured_trust(..))`（接纳 / 激活的 Zone 文档成为 trust 候选，影响 best 不影响 latest）；`add_observed_cache` → `commit_candidate_doc(.., SourceRef::normal("udp-discovery"))`；`set_local_authority_override` → `lock_document`；`set_zone_resolver_endpoint` → `set_zone_locker_endpoint`；RemoteAuthority + Anchored 检查 → `authority_only().without_local_lock().without_zone_lock().with_force_authority_query()` + `select_authority_current`；app_install_resolver 不再有 unverified / self-signed / stale 开关，`DidResolutionSnapshot` 由 `DocResult` 派生（`invalid` 映射 Missing，locker 命中报 cache Hit）。通过:node_daemon zone_boot_resolve(7)/finder(14)/active_server(11)、control_panel app_install_resolver(6)。
  - 由此修正 name-client:大状态机装箱(`resolve_did_ex` / `get_document` / `verify_document` 等为 `Box::pin` 薄包装,`TaskMerger::wait_for` 内部 future 与任务闭包同样装箱;否则下游 `queries overflow the depth limit`、debug 栈溢出与 `E0275` Send 证明溢出);新增 `LockOptions::simulate_history`:锁定文档视为 scope 内完整历史,Root Trust 合成 Owner(`install_local_owner_trust`)用它为更早签发的设备 / Zone 文档充当签发时 owner,boot 全程不在线解析 Owner。复验:workspace depth-limit 错误消失,scheduler 69+21 通过,node_daemon 25 通过,无临时 `recursion_limit`。
  - zone-resolver-server 尚未读 `BuckyOS-Resolve-Budget-Ms` / `-No-Zone-Lock` 头(服务端待做)。
- **cyfs-gateway(已迁移,未提交,用本地 patch 编译)**:`rtcp.rs` outbound 按 requirement 构造 opts(AuthorityCurrent = `authority_only().without_local_lock().without_zone_lock().with_force_authority_query()` + `select_authority_current(result, receipts)`;TrustedSnapshot = `not_allow_request()` + `select(current)`),Device 优先、Zone 兜底;入站 hello = `verify_document(.., not_allow_request())`,准入 = `success(current)`,`Invalid` 为确定拒绝、`Unknown` 才允许匿名 KeyDid;权威确认 / Negative 恢复用 AuthorityCurrent opts + 本轮 `authority_receipts` 判 Confirmed / Negative / Unavailable;`add_verified_cache` / `CacheWriteOutcome` 删除(`verify_document` 已推进 best),隧道索引只保留本地 `VerifiedCommitOutcome`;`rtcp_stack.rs` 测试 44 处 `add_observed_cache` → `commit_candidate_doc`;`gateway.rs` 动态 provider 注册为 web / bns 的 normal 来源;`local_dns.rs` 走 `Source::get_document`。新增零网络断言 `inbound_hello_verification_never_queries_sources`(D3 入站要求已落实)。验证:`cargo check --workspace` 0 错,rtcp 137 通过 / 1 ignored(需 BNS fixture),rtcp_stack 47 通过。`TransportPolicy::IndependentControlPlane` 未启用(来源尚未声明 `independent_control_plane`,留 TODO,§6)。
  - 由此修正 name-client:`resolver::http` 改名 `http_doc`(glob 导出曾遮蔽 http crate);签发时 owner 查询改为 `closest(doc.iat + 1)`(同秒激活并签发的设备文档也能命中当前 owner,设计稿 §6 已注明);`VerifyResult.owner_binding` 携带本次使用的可信 owner 绑定。
- 删除旧 API、deprecated 标记、`verify_context.rs`、`doc_cache.rs` 旧实现。
- 清理源码里对旧文档的引用（`grep -rn "doc/verify-did-api-boundary\|doc/update-did-cache\|简化文档\|verify-did-document-jwt\|已有did-resolver介绍\|简单介绍resolve-did\|resolve_did重构\|resolve-did.md" src`，2026-10-20 共 14 个文件 67 处，`provider.rs` 22 处、`doc_cache.rs` 13 处最多）。
- 执行 §4 文档清理。
- **合入后的上游测试遗留（2026-10-20 修复，未提交）**：cyfs-gateway main 上 bns-server、cyfs-sn 测试编译不过，`test_control_server`、`test_dns_over_tcp` 失败。处理结果：
  - name-client 修正两处：① `get_document` 在本轮发布信息让结果 disabled 后提前返回时，没有执行 `refresh_known_constraints`，revoked 之后旧 best 仍会被 `select` 返回（违反设计稿“已知禁用 / 撤销撤掉选择资格”），现在返回前先刷新；② `PublishInfo::merge` 原来任何非禁用回答都覆盖不了已知禁用，撤销过的设备重新签发后也永远恢复不了。**[已定，2026-10-20 用户裁决]** 新的、非推导的 current 明确回答可以翻篇；None、历史版本回答、推导回答仍不能覆盖（单测 `merge_keeps_known_negative_state` 已改写）。
  - **[已定，2026-10-20 用户裁决]** authority 回答的类型级 `expired`（文档自身、owner 或 zone 过期）不撤掉选择资格：本机已验证、自身 exp 未到的 best 仍可选。这和重构前“过期即报错”不同；bns-server 的 `did_resolver_owner_policy_revokes_device_and_expiry_keeps_verified_best` 按此断言。
  - bns-server：显式 `type=device` 也走设备槽位投影，回答的 `docType` 就是 `device`（D4；此前只有缺省 / `type=zone` 会投影，新客户端按 D4 传 `device` 时拿到 missing，buckyos `active_server` 的设备门禁因此不可用）。缺省 / `type=zone` 的旧投影保留给旧客户端，待旧客户端退场后按 D4 / N3 删除。测试里设备 DID 改为显式传 `DidDocType::Device`，夹具文档补 iat。
  - cyfs-sn：SN 对未在 BNS 发布 zone 文档的用户返回 `auth_db_projection`（`SNUserInfo` 投影，无 iat、无签名），Zone locker 按 Unknown 处理。**[已定，2026-10-20 用户裁决]** 接受这一行为；locker 互通改为在 `test_sn_bns_proxy_rpc_paths` 末尾，用已发布签名 zone JWT 的用户断言。
  - `test_control_server`：provider id 前缀随重构由 `https-resolver:` 改为 `http-provider:`，只改期望值（id 只在回包里回显）。`test_dns_over_tcp`：与 resolve-did 无关，测试没设控制服务端口，本机运行 gateway 时 13451 冲突，改为随机端口。
  - 合入顺序：bns-server 的 owner_policy 测试依赖上面两处 name-client 修正，须先推 buckyos-base main，cyfs-gateway 再提交；其余测试对 base main 原样即可通过。
- **未做**：真实 Zone 验收（bns-server 升级 versionId / versionTime / `invalid` 后，devnet 跑 §10 的 exact / closest 行与 RTCP 两个场景）；zone-resolver-server 读 `BuckyOS-Resolve-*` 头；N1–N7 上游 issue（§7）；三个上游仓库与本仓库的改动都未提交，上线顺序：先推 buckyos-base main，再在 buckyos / cyfs-gateway / cyfs-ndn `cargo update -p name-client -p name-lib -p kRPC -p buckyos-http-server` 并提交迁移。

## 3. 验收

- 设计稿 §10 的每一行对应一个测试函数名，放在 `name-client/tests/resolve_did_scenarios.rs`，函数名前缀标行号（`s11_`…`s33_`，25 个用例已通过）；目录/路径/header 的 9 行在 `resolver/http.rs` 与 `web_provider.rs` 的单测中。
- 网络回流、FD 释放、预算耗尽的用例用 `#[ignore]` + 隔离环境运行，CI 只跑无网络部分。
- 上游零网络断言：mock Source 计数器，入站路径 `trust/normal` 请求数为 0。
- #207 验收清单逐项对应（见 §5 表），另加评论里建议的两条：“BNS 对健康 Zone 返回 503”“BNS 不响应”，断言 Relay 对自身 443 的连接数不随时间增长、第二个合法 Zone 持续可用。
- 命令：

```bash
cd buckyos-base && cargo test -p name-lib -p name-client
cd buckyos-base && cargo test -p name-client --test resolve_did_scenarios -- --ignored   # 隔离环境
cd buckyos && cargo check --workspace
cd cyfs-gateway && cargo check --workspace
```

## 4. 文档清理

原则：协议文档保留并修订；描述现有实现的文档在 M6 删除，不留 legacy 版本；被删除文档里仍有价值的内容先并入设计稿或本 TODO，再删。

| 文档 | 性质 | 处置 | 时机 |
| --- | --- | --- | --- |
| resolve-did.py / resolve-did协议冻结讨论伪代码.md | 新设计 | 保留。helper 名已回写为实际 Rust 名（`revision` / `ResolveOpts` / `DocStore` / `LocalLocker` 等），免责语已去 | 已完成 |
| resolve-did重构-TODO.md（本文） | 实施记录 | 保留；§5 的 R1/R2 已回写设计稿 §4/§2.2，本文保留对照 | 持续 |
| http_did_resolver_api.md | wire 协议 | 保留并按 M0 修订；删除指向 resolve_did重构.md、简单介绍resolve-did.md、resolve-did.md 的链接 | M0 |
| did-object-protocol.md | 协议 | 保留并按 M0 修订发现路由 | M0 |
| bns.md | method 介绍 | 保留 | 无 |
| did_profile_resolution_protocol.md | 需求/协议 | 保留；§2“现状”已改引新 API | 已完成 |
| cyfs-trust-verification-flow.md | 概念背景 | 保留；文首已加“获取与验证流程以设计稿为准” | 已完成 |
| did-identity-certificate-manager.md | 本地身份材料协议 | 保留，与 resolver 正交 | 无 |
| resolve_did_default_doc_type_TODO.md | 讨论稿 | 结论并入 D4 后删除 | M0 已删 |
| resolve-did.md（9 月“设计冻结”） | 被替换的旧设计 | 删除。其 §9 场景已被设计稿 §10 吸收；§7 场景简化方案不再成立 | M0 已删 |
| resolve-did组件与使用模式核对.md | 对现有实现的静态核对 | 已删除；D1–D7 结论在本 TODO，N1–N7 摘要见 §7（issue 待开） | 已删除 |
| verify-did-api-boundary-and-freshness-TODO.md | 已实施的旧模型 | 已删除 | 已删除 |
| verify-did-document-jwt.md | 旧 API 需求 | 已删除 | 已删除 |
| update-did-cache.md | 旧缓存设计 | 已删除；收件箱协议（`unverified/{did}.doc.json` 或 `{did}.{doc_type}.doc.json`，一律按 normal 候选）写在 `resolver/store.rs` 模块注释 | 已删除 |
| http-provider自适应响应解析-TODO.md | 旧 provider TODO | 已删除，逻辑由 `document_answer_from_http` 承接 | 已删除 |
| 已有did-resolver介绍.md、简单介绍resolve-did.md | 基于现有实现的介绍 | 已删除；介绍由设计稿承担 | 已删除 |
| test-design-name-system.md | 旧测试设计 | 已删除；测试清单即设计稿 §10 | 已删除 |
| addr-rtt-db.md、krpc-s2s-*.md、krpc_s2s_review.md | 其它组件 | 保留，不属本次范围；krpc S2S 公钥 provider 与新 resolver 的关系见 D3 最后一行 | 无 |

## 5. 与 cyfs-gateway#207 的对照

[#207](https://github.com/buckyos/cyfs-gateway/issues/207)：日本 SN Relay 上，一个 Zone 的 ZoneDocument owner 为 `did:undefined:undefined`，BNS 对 `ood1.<bad-zone>` 返回 502；name-client 记为 authority_unknown 后仍查 WebProvider，`*.web3.<sn-host>` 的 DNS 指回同一 Relay，每次回退都变成新的入站 HTTPS → RTCP → 解析，无超时、无合并、无退避，约 28k 条自连接打满临时端口，连带健康 Zone 的 TLS 握手超时。评论里的修复方案是 A（name-client 止血）、B（RTCP 隔离）、C（BNS 回答形态）三层补丁；用户决定不打补丁，直接做本次重构。下面逐条反推设计稿和 D1–D4 是否覆盖了 #207 的根因，以及还剩什么。

### 5.1 根因对照

| #207 根因 / 补丁 | 设计稿与本 TODO 的对应 | 结论 |
| --- | --- | --- |
| 根因 1：authority Unknown 后仍查补充源，且补充源结果必被拒 | RTCP outbound 用 `network_sources=authority_only` + `transport_policy=independent_control_plane` + `without_zone_lock`（设计稿 §8.1）；这是补丁 A2 的正式形态。补丁 A1（authority Unknown 时全局跳过补充源）**有意不采纳**：新模型下 normal JWT 经 owner 链验签即可成为 valid best，补充源查询对默认调用方不再是“必被拒”，所以不能全局跳过 | 覆盖，A1 被更强的语义取代 |
| 根因 2：全链无 connect/total timeout，每层挂在下一层 TLS 握手上 | §4 单一有限预算，每跳 `min(配置上限, 剩余预算)`，`ResolutionDeadlineExceeded` 不回退；入站握手自建预算且不接受对端期限（§8.2）。对应补丁 A3、B1 | 覆盖 |
| 根因 2 附带：同 DID 并发不合并、失败无退避 | §4 任务合并（键含访问策略）、按目标 + 来源 + 策略短期退避、并发与队列上限、日志限流。对应补丁 B2–B5 | 覆盖，但见 R1 |
| 根因 3：BNS 把确定性校验失败报成 502/Transport，客户端分不清“权威说不对”和“权威没回答” | 设计稿只有 NoAnswer / NotExist / 禁用 / 撤销，没有“权威确定拒绝”的状态。补丁 C1 提议 `DocumentStatus::Invalid` | **缺口**，见 R2 |
| 单次解析的 visited / max_depth 挡不住跨入站请求的递归 | 设计稿 §4 明说 visited、同键串行、原子合并都不能代替网络门禁，门禁在 `request_source` 每跳执行 | 覆盖，但同键锁本身会制造等待环，见 R1 |
| 现场默认类型 `None` 被当成 `zone`，`?type=device` 不是等价复现 | D4：None 在缓存键前归一，Zone 分支探测删除；BNS 设备槽位联合校验只挂显式 `device`；RTCP 传 `device` | 覆盖 |
| 评论第 4 点：AuthorityCurrent 下每次 create_tunnel 都同步查 BNS，Relay 可用性与 BNS 强绑定 | 设计稿有意如此：AuthorityCurrent 要求本轮真实 receipt，`force_authority_query` 跳过查询缓存。成功侧不缓存是 RTCP 自己的 requirement 选择 | 不是缺口，见 R3 |

### 5.2 由对照产生的调整

**R1. 串行锁不能跨 provider I/O 持有（设计调整，进 M4/M5）。** 伪代码 `resolve_did_ex` 在 `serialize_document(did, doc_type)` 内调用 `_get_document`，锁跨越全部网络 I/O，锁键 `(scope, did, doc_type)` 不含访问策略。把 #207 的回流套进去：Relay 上一个默认策略的解析持锁查 WebProvider，请求绕回 Relay 变成入站 RTCP，RTCP 用 authority_only 解析同一 `(Host, ood1.X, device)`，在同一把锁上等外层，外层又在等这个入站的 TLS 握手。§4 任务合并键含访问策略，本意就是让受限请求不加入会访问目标站点的任务，但串行锁把它们又绑在一起了。结果虽然有界（锁等待可取消、受预算约束），但每次都要烧满整份预算才失败，而且健康场景下入站并发查询也要等出站 I/O。调整：锁只覆盖“读缓存、刷新约束、决定要发哪些查询”与“验证并原子提交”两段，I/O 阶段释放；跨请求去重交给任务合并（键含策略）；两段之间提交时按 §7 的原子合并裁决冲突。设计稿 §7“不同 revesion 仍可能更新同一 best，不能分别加锁”在提交段仍然成立。

**R2. 新增 `invalid` 类型级负状态（协议调整，已写入 D1 wire 表）。** 这是 #207 补丁 C1 的归宿。要点：它是 authority 的明确回答，不触发退避；可缓存短 TTL；选择时等同 NotExist；不升级为 DID 禁用，也不阻止 trust/normal 候选经 owner 链验签成为 best（设备文档本身是对的，坏的是 ZoneDocument）。RTCP AuthorityCurrent 因为拿不到 receipt 仍会拒绝，这正是 issue 要求的“保留所有拒绝”。bns-server 侧 `validate_device_slot` 失败改为返回这个状态，`BNS projection changed` 这类瞬时错误保持 5xx。

**R3. Relay 与 BNS 的耦合是 RTCP 的 requirement 选择，不是 resolver 问题。** 设计稿 §8.1 给了 `AuthorityCurrent` 和 `TrustedSnapshot` 两档。Relay 转发场景是否该用 TrustedSnapshot + 后台 AuthorityCurrent 刷新（核对文档 N4 的“先按 scope 准入再确认公网”），由 cyfs-gateway 在迁移 `rtcp.rs` 时决定，本仓库只保证两档都能表达。失败侧的退避（§4）在两档下都生效。

**R4. 默认调用方的回流仍可能发生，但深度为 1 且有界。** Relay 上 SN resolver、msg_center 等默认策略调用在 authority Unknown 后仍会查 WebProvider，请求可能绕回 Relay 一次；入站 RTCP 用 authority_only，不再向外发补充源请求，所以不会继续套娃，并在各自预算内结束。这是“先能力后安全”的取舍：默认调用方保留从补充源拿 best 的能力。若要在 Relay 进程上整体禁止，应由该进程的 `NameClientConfig` 把默认 opts 收紧为 authority_only，而不是改 resolver 语义。

**R5. authority 已给出有效 best 后，补充源只等宽限期（buckyos#684，2026-10-25 用户裁决）。** 原规则“已有 latest 也继续收集”按顺序等每个补充源，WebProvider 内部最多串 4 次请求、每次上限 10 秒；msg_center 解析代签设备时外层 3 秒超时，BNS 已返回有效设备文档仍被慢 Web 源拖到超时。调整：`get_document` 中 authority 本轮回答的文档已验证并成为 best 时，其余来源用 `budget.child(config.supplement_grace)`（默认 1 秒）并发查询，按注册顺序提交；宽限期到期或单源出错记为该来源 Unknown，不退避（这是调用方自限，不是来源故障），总预算耗尽/取消照常外抛。authority 未给出有效 best（Unknown、负状态、坏文档）时补充源仍逐个在单源上限内等待，s11/s12 语义不变；`supplement_grace = 0` 等于 authority 有效即停。回归：`s11_slow_supplement_after_valid_authority_is_bounded_by_grace`、`s12_authority_unknown_waits_for_slow_supplement_beyond_grace`。

### 5.3 #207 验收清单对应

| #207 验收项 | 本 TODO 落点 |
| --- | --- |
| 单次外部请求在明确预算内失败，自连接不随时间增长 | §4 预算（M1）、authority_only（M2）、R1（M4/M5）；§3 隔离复现 |
| 断开依赖隧道的补充解析路径 / 明确来源策略 / 循环保护 | `network_sources` + `transport_policy` + 每跳门禁（M2）；`permits(source)` 的传输层实现在 cyfs-gateway |
| authority unknown / 超时 / 断连 / 不一致文档分别验证预算、并发、取消、释放、退避 | M1、M5 测试；R2 让“不一致文档”变成明确回答 |
| 跨入站请求 / 跨网络递归被阻止 | R1 + authority_only；§3 回流复现断言深度 1 |
| 同 Relay 其它合法 Zone 不受影响 | 按目标 + 策略隔离的退避与并发上限（M5）；§3 第二 Zone 持续可用 |
| 有效文档、隧道复用、身份变更 / 吊销保持正确 | §10 验收表相关行（M4）；RTCP 迁移时保留 `AuthorityCurrent` 用例 |
| 日志、FD、内存增长受控 | M5 日志限流；§3 10 分钟采样 |
| 坏文档修复与来源追踪 | 运维与 #204，不在本仓库 |

## 6. 明确不在本次范围

- 完整“发布时合法”证明、统一 Zone 写入 API、全局一致快照（设计稿 §9 已排除）。
- `Link` 指向独立 Card、发布端吊销/注销生命周期。
- N1 Boot/LKGS、N4 连接生命周期、N6 NDN 路径断言、N7 `/identifiers/self` 的上游契约。
- AppDoc 统一为 DID Document JSON/JWT 的迁移（设计稿末尾 TODO(AppDoc)），单独排期。
- `independent_control_plane` 在 cyfs-gateway 传输层的实现；本仓库只提供 `TransportPolicy::permits(source)` 接口与 opts 透传（issue cyfs-gateway#207）。

## 7. 上游契约待办（原核对文档 N1–N7，待转为各上游仓库 issue）

原 `resolve-did组件与使用模式核对.md` 已删除（行号引用全部失效）；其 N1–N7 不属于 name-client 范围，摘要保留在此，待分别开到 buckyos / cyfs-gateway / cyfs-ndn / websdk 的 issue：

| 编号 | 仓库 | 要点 |
| --- | --- | --- |
| N1 Boot / LKGS | buckyos node_daemon、sys_config_service | "已知 V2 但运行态仍用 V1"不是 stale 也不是 Lock：`ResolvedCurrent` 与 `AcceptedOperationalState` 分开存储；boot 恢复模式在 Missing/Expired/Revoked/Tombstoned 下能否继续；Owner 固定信任根的维护流程；Boot 派生 JSON 要标明原始 JWT/hash 与接纳依据（重构后对应 `lock_document` + `commit_candidate_doc(configured_trust)`，不再有 verified cache 投影） |
| N2 控制面投影 | buckyos sys_config_service、cyfs-sn | 合成 Owner / 业务状态映射是"持续按多个来源生成一份新文档"：记录输入版本/hash、转换版本、scope、接纳来源与依赖期限；账户停用、Zone 内禁入与 method 永久注销不能共用 Revoked/Tombstoned 推导全球状态 |
| N3 多身份依赖 | cyfs-gateway bns-server、cyfs-sn | `Device → Zone membership → Owner → 登记/域名绑定` 链；回答应带请求身份、实际 doc_type、source document key、绑定证据与依赖集合；设备槽位联合校验只挂显式 `device`（D4），校验失败回答 `invalid`（R2） |
| N4 先 scope 准入再公网确认 | cyfs-gateway rtcp | "文档有效性 / 此刻准入 / 连接当前信任等级"分别建模；异步确认只更新对应 revision/generation；哪些变化只阻止新连接、哪些拆除存量连接；未发布设备的 scope 准入是独立显式策略（重构后 `AuthorityCurrent` 用 `select_authority_current` + 本轮 receipt） |
| N5 独立公钥 Provider | buckyos-base kRPC、sn-business | `S2sPublicKeyProvider` 管理 `DID → key` 而非文档；派生公钥缓存若承接 Current 语义须携带身份版本/依赖/硬期限，公钥字节未变但身份被禁用时如何失效；不要求 provider_only 伪造公网 receipt |
| N6 NDN 路径断言 | cyfs-ndn | 用解析结果验证派生签名对象：独立的对象身份、权限范围、重放/版本策略与期限；底层 Zone/Owner 失效如何影响尚未过期的断言 |
| N7 `/identifiers/self` | buckyos sys_config_service、websdk | 端点自描述 / 服务发现与身份认证分开；信任当前 origin / 父域的条件；`self` 不当全局 DID / cache key |
