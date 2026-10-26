# resolve-did：用于提前发现潜在 BUG 的单元测试设计

本文以 [resolve-did.py](./resolve-did.py) 为语义依据，结合 [HTTP binding](./http_did_resolver_api.md) 和当前 [resolver 实现](../src/name-client/src/resolver/mod.rs) 设计测试。目标是用小而确定的反例，发现版本、证据、缓存与并发相互作用时的错误。

本文最初是测试设计；2026-10-26 已按本文实现全部用例，并修复了用例暴露的缺陷，见 [§6 实施记录](#6-实施记录2026-10-26)。§1–§5 保留设计原文：其中“现有覆盖”是撰写时对源码的静态核对，“建议补充”是当时应新增的断言。`resolve-did.py` 是伪代码，测试落在 Rust 实现上，没有逐行翻译它。

## 1. 设计原则：让错误实现无法侥幸通过

常规测试容易只问“能否解析出文档”。这里同时观察四件事：**返回的是哪一份确切文档、依据来自哪里、发生了哪些 I/O、缓存留下了什么**。

- **成对反例**：两个输入只差一个条件，例如 `iat < T` 与 `iat == T`、普通业务 JSON 与声明为 DID 文档的损坏 JSON。避免“全部拒绝”或“全部放行”的实现通过测试。
- **先污染、后探测**：先用另一查询、另一策略或另一 scope 预热缓存，再执行目标调用。冷缓存测试看不见证据串用。
- **分开事实与选择**：`is_signed=true` 不等于有效，`validity=valid` 不等于命中 exact/closest，`is_published=true` 不等于 latest。
- **精确安排交错**：通过屏障和事件控制并发，断言必须先发生的事件；不用“sleep 一下应该已经开始了”安排顺序。
- **每例对应一种错误改法**：说明删除哪个检查、合并哪个键或换错哪个时间基准，会被该测试发现。

优先级中的 P0 指应先实现的身份、证据和并发正确性测试；P1 指随后补齐的兼容性与生命周期测试。

| 编号 | 测试主题 | 优先级 | 主要落点 |
| --- | --- | --- | --- |
| T01 | 坏候选不能抢占版本槽 | P0 | `doc_result`、`verify` |
| T02 | 验证报告必须属于确切输入 | P0 | `revision`、`verify`、`http_doc` |
| T03 | closest 的边界证据不能串槽 | P0 | `publish_info`、`doc_result` |
| T04 | 来源、签名、发布三个维度独立 | P0 | `source`、`doc_result` |
| T05 | 历史签名 key 与当前撤销线分离 | P0 | `verify` |
| T06 | 站点解绑与验证依据改变的区别 | P1 | `registry`、`verify`、`doc_result` |
| T07 | 文档有效期与查询证据有效期分离 | P0 | `store`、`doc_result` |
| T08 | 负状态不能丢失或扩大作用域 | P0 | `publish_info`、`store` |
| T09 | 复用 opts 不能复用上轮 receipt | P0 | `opts`、`resolve`、`verify` |
| T10 | locker 强制回答、历史目标与 scope 隔离 | P0 | `local_locker`、`zone_locker` |
| T11 | 默认类型与目录／路径入口不能混淆 | P1 | `resolve`、`http_doc`、provider |
| T12 | 合法 header 不能洗白坏正文 | P0 | `http_doc` |
| T13 | 获取策略不等于缓存可信等级 | P0 | `resolve`、provider、`concurrency` |
| T14 | 共享任务发起者并不拥有其他等待者 | P0 | `concurrency`、`budget` |
| T15 | 回流请求不能被外层 I/O 锁死 | P0 | `resolve`、`concurrency` |
| T16 | 提交后重新裁决冲突与撤销 | P0 | `store`、`doc_result`、`verify` |
| T17 | 来源超时、补充宽限期、总预算不是同一种失败 | P0 | `budget`、`resolve` |

## 2. 最小测试装置

建议复用 [resolve_did_scenarios.rs](../src/name-client/tests/resolve_did_scenarios.rs) 的文档／测试密钥工厂，补充下列装置。它们是**建议新增的测试接缝**，不是宣称当前已有这些 API。

| 装置 | 要控制／观察的内容 | 避免的假通过 |
| --- | --- | --- |
| `ScriptedSource` | 按 `(source, operation, DID, actual_doc_type, revision)` 配置回答队列；记录调用与读取次数；未预期调用直接使测试失败 | mock 无条件返回同一份 current，使错查历史也成功 |
| 两套独立固定测试密钥 `K1/K2` | 真实 JWT 签名和验签；可制造同 claims、不同原文的两个合法 JWT | mock 验签恒 true，无法发现错用当前 key |
| `FakeClock` | 分别推进墙钟和单调时钟；读取时不自动推进 | 用真实时间卡 `exp` 边界；把系统时间跳变误当预算流逝 |
| `RequestTrace` | scope、实际类型、完整 revision、来源／传输策略、deadline、receipt 所属调用 | 只数总请求次数，漏掉错误目标和递归策略放宽 |
| `Barrier/oneshot` 与生命周期探针 | 缓存读取完成、任务创建／加入、进入 I/O、允许提交、Future drop、许可释放 | 用耗时阈值代替因果关系，测试偶发成功 |
| 独立 store／locker | 每例隔离；持久化例使用临时目录并重建客户端读取 | 全局缓存使测试顺序决定结果 |

当前 `budget.rs`、`concurrency.rs` 使用 `std::time::Instant`，文档与缓存约束还读取真实 Unix 时间；不能只调用 `tokio::time::pause()` 就声称控制了全部时间。时间边界例应先注入时钟，或将接收 `now` 的纯判断抽出。异步计时若用 Tokio 虚拟时钟，还需统一预算计时来源并启用相应测试能力。屏障本身也必须有测试总超时，错误实现应快速失败而不是挂住 CI。

默认夹具：墙钟 `now=10_000`，目标为 `did:bns:zone1.alice` 的 zone，可信 owner 为 `did:bns:alice`；普通子文档 `exp=20_000`。`V(i,h)` 表示 iat 为 i、内容 hash 为 h 的确切文档，hash 由真实编码计算，不把示意字母作为合法摘要传给解析器。除特指测试外，关闭 locker，使用独立内存 store。

报告断言使用结构化字段和关键原因类别，避免绑定整段错误文案。无效／未知报告应检查四个选择标志全部为 false；布尔事实为 false 时，要结合 `missing/reasons` 区分“未核实”和“已否定”。测试不得把未知发布状态解释成“从未发布”。

## 3. 具体用例

### T01：投毒候选先到，也不能占住合法版本的位置

**构造与步骤**：authority 已发布 `V1(iat=100)`；normal 提供签名错误的 `BadHigh(9000)`、签名错误的 `BadSame(200,h_bad)`、签名正确的 `Good(200,h_good)`。owner 链完整，`Good` 没有发布记录。分别排列三个 normal 候选的到达顺序；每种顺序使用新 store。

**断言**：`latest=V1`、`best=Good`；Good 已验签但未被标为已发布；两个坏候选均不能推进已验证版本基线，也不能产生阻挡 Good 的同 iat 冲突。另用两个都有效、iat 相同但 hash 不同的文档作对照：第一个成功提交者保留，第二个报告 conflict；同 iat 同 hash 重复提交幂等。

**精妙之处**：把“最高版本”“先到者”和“验证通过”拆开，能发现先按 iat 去重、先更新 best 后验签，以及坏候选占槽。不要对两个都有效的冲突文档要求排列不变；它们的合法裁决本来就依赖先提交者。

**现有覆盖／增量**：已有 `s15_bad_candidate_at_same_iat_does_not_block_good_one`；补高 iat 投毒、排列和幂等对照。落点为 `accept_verified`、`candidates_for` 与解析候选循环。

### T02：相同 DID 或相同 claims，不等于同一份验证输入

**构造与步骤**：先缓存有效 `V2(200)`，然后分别验证旧 `V1(100)`、同 iat 改内容的 `V2'(200)`、错误 DID／类型的文档。再构造两份 claims 语义相同、payload 键顺序不同、各自重新正确签名的 JWT `J1/J2`；只发布 `hash(J1)`。JSON 对照仅改变空白和键顺序，保持值及数值表示不变。

**断言**：V1 可以 `is_signed=true`、`validity=valid`，但不是 best，`success(current)=false`；V2' 不能借 V2 的缓存报告成功；错误 DID／类型在任何来源等级下均失败。`hash(J1) != hash(J2)`，J2 不能命中 J1 的 exact 或发布记录，即使单独验签正确；JSON 对照的 hash 相等。将 J1/J2 分别放进声明为文档的 body/header 时，必须报载体冲突。

**精妙之处**：用“两个都合法但并非同一字节串”的 JWT，排除仅因坏签名而拒绝的假通过，发现验签前重序列化、只按 DID/iat 缓存报告、用 JSON 语义等价替代发布 hash 等错误。

**现有覆盖／增量**：已有 `s14_verify_older_v1_does_not_borrow_v2_success` 和 `revision.rs` 的编码测试；补组合到验证缓存与双载体冲突路径。

### T03：有这个历史版本，不等于它就是 closest

**构造**：authority 历史有 `V1(100)`、`V2(200)`，current 为 `V2`；再给 normal 一份有效但未发布的 `V3(240)`。清晰区分“body 已缓存”“某版本已发布”和“某查询边界已确认”。

| 查询／变体 | 期待结果 |
| --- | --- |
| `closest(201)`，持有新鲜 authority current(V2) 依据 | 可推导 V2；该子查询不发历史请求，派生证据指向原 current 回答 |
| `closest(200)` | 必须真正查询历史并选 V1，绝不能选 V2 |
| `closest(199)` | 选 V1；记录完整边界 199，不借用 200 的槽 |
| `exact(200,hash(V2))` | 可由匹配的 current 依据命中 |
| `exact(200,other_hash)` | 不能命中 V2 或返回 current 充数 |
| 仅有 V1 的已发布记录，缺 closest 边界确认 | 不能据本机历史最大值填 closest 槽 |
| 仅有 trust/normal 的 V3，authority 无发布回答 | V3 不能成为 closest，也不能充当 current 发布证明 |
| authority 确认边界内为空／历史不支持／NoAnswer | 均不回退 current；分别保留“确认空”“不支持”“未回答”的原因 |

**步骤与断言**：先执行 `closest(201)` 预热，再依次执行 200、199 和错误 hash exact；反向顺序再跑一次。每次检查选中文档、完整查询键、证据 query/source/derived、历史请求轨迹。假历史回答中加入 `selected.iat == query_iat`、`boundaryConfirmed=false` 或边界不匹配的变体，不得产生成功槽。

**精妙之处**：边界差一秒、缓存顺序不同就足以暴露 `<` 写成 `<=`、按文档版本而非完整查询缓存，以及从“见过”推成“最近已发布”的错误。

**现有覆盖／增量**：已有 `s17`、`s31` 和 `closest_derives_only_after_latest`；补预热后的串槽、错误边界回答、无发布 V3 和证据出处断言。观察特定子查询的 trace，不用整次 resolve 的总调用数代替。

### T04：body 不变，只改变证据，事实字段也必须正确变化

**构造与步骤**：使用同一份未签名 JSON J。在独立夹具中分别从 normal、trust 提供它；normal 还在响应中自报 authority 和 publish_info／owner 绑定。然后在 trust 夹具内保留 J 的缓存，令真实 authority 新回答确认其确切 `(iat,hash)` 为 latest，只返回发布信息，不重新提供 body。

**断言**：normal 的 J 无权免签，自报等级不能生效，也不能修改可信 owner 绑定；trust 的 J 可成为 best，但 `is_signed=false`，没有发布依据时不得设置 `is_published/is_latest`。新 authority 证据到来后，原 J 可复用并成为已发布 latest，仍不能伪造 `is_signed=true`；保留 J 原来源与新增发布证据各自的来源。owner 文档的同类试验只接受 authority/locker 根依据，始终不设置 best。

**精妙之处**：文档字节完全不变，只改证据，专门抓“来源一可信就把所有标志置 true”、远端自报升级以及缓存证据永不更新。也防止实现通过禁止缓存复用来规避问题。

**现有覆盖／增量**：已有 `s13_trust_unsigned_json_becomes_best_without_signed_flag`、`self_signed_owner_cannot_bootstrap_trust`；补远端伪装和 body／发布证据分列升级。

### T05：历史 key 验签，当前 owner 判撤销，时间等号不能错

**构造**：O1：`iat=100, key=K1, exp=400`；O2：`iat=300, key=K2, exp=20_000`，当前为 O2。normal 文档 D：`iat=200, exp=20_000`，由 K1 签名。authority 提供可信 owner 绑定和两份根的发布查询，但不提供可免签锚定 D 的 current 发布记录。

下面每一步及每个参数分支均使用独立 store／receipt 集合，从上述基线重建；不在同一缓存中修改同 iat owner 的内容，否则先触发版本冲突，测不到目标边界。

**步骤与断言**：

1. O2 无撤销线：D 有效，签名依赖为 `closest(200) -> O1`，当前约束依赖为 O2。今天已过 O1.exp，仍不能否定其在 200 时刻的历史用途。
2. 固定 D，只把 O2.valid_iat 分别设为 199、200、201：199 不撤销；200/201 均 `is_signed=true, is_revoked=true, validity=invalid`，全部选择标志为 false。
3. 固定 D.iat=300，分别用 K1/K2 签名，在独立 store 中验证：`closest(300)` 仍选 O1；K1 可通过、K2 失败。避免前一用例的同 iat 冲突干扰。
4. 独立夹具只预置当前 O2，不提供历史查询回答，也没有可复用的历史查询缓存：D 为 unknown，明确缺历史 owner，不能改用 O2。另开独立夹具，将历史 O1.exp 设为恰好等于查询时刻，它不得作为有效历史根。

**精妙之处**：两套真实 key 让“拿当前 owner 代替历史 owner”必然露馅；同时把签名正确、当前撤销和历史过期三条时间轴拆开。只用同一把 key 的轮换测试发现不了这类错误。

**现有覆盖／增量**：已有 `s18`、`s19`；补真实换 key、`<= valid_iat` 等号、历史 exp 参照时刻。外层无论查询 D 的 current 还是 exact，签名根查询都应是 `closest(D.iat)`。

### T06：解绑站点不追溯抹掉信任，撤销却必须立即影响缓存

**构造与步骤**：owner 绑定站点 S；从 S 取得未签名 trust 文档 U 并成为 best。发布 iat 更高的 owner，仅删除 S 的绑定，key／撤销线不变，并把这次更新纳入本机已知材料。复用缓存解析 U；另开新 store，以解绑后的配置请求 S 的新文档。随后在原 store 加入更高版本 owner，其撤销线覆盖 U.iat，再严格离线解析 U。

**断言**：解绑后的旧 U 在 exp 等约束仍满足时可用，保留取得时的 trust 来源，但下一轮来源列表不得再因旧绑定访问 S；新 store 不能凭历史绑定把 S 的新文档当 trust。加入已知撤销线后，旧 U 立即失去选择资格，即使 U 没有签名依赖项、缓存 TTL 尚未到期，也不得绕过检查。

**精妙之处**：同一个 owner 更新动作，按改变的事实得到不同结果，既抓“owner revision 一变就全盘作废”，又抓“trust 文档没有签名依赖，所以永远不重查约束”。这里不要求每次缓存命中联网刷新未知的远端状态。

**现有覆盖／增量**：`s20` 已测签名文档受 owner 撤销；补未签名 trust 文档与仅解绑对照。另对 locker 配置版本变化复用相同失效测试，不能将失效的 locker 依据降格为普通 trust 免签依据。

### T07：长 TTL 不能延长文档生命，读缓存也不能给证据续命

**构造与步骤**：文档 D.exp=10_010，来源缓存截止为 10_100。在 10_009 预热，关闭所有网络，分别将墙钟推进到 10_010 和 10_011。另用 exp 很长的文档和短期 closest 查询回答，先缓存历史目标，再让查询回答／目标槽到期；对同一缓存反复读取。

**断言**：到达 exp 等号即不可选，`is_expired=true`；离线 provider 调用数为零。历史查询依据失效后，即使 body 还在，也不能直接成功选择该目标，必须取得可用依据；重复读取不能把原 checked_at 改成当前时间。用 authority current 推导的历史回答保留原证据出处，不得在旧依据不可复用后继续从它创建“新鲜回答”。

**精妙之处**：分别让“body 活着、证据过期”和“证据活着、body 过期”，避免只测试一个缓存 TTL；反复读还会暴露滑动过期无意刷新证据的问题。普通 current best 的既有信任结论不因“本次未联网”自动失效，不能把此测试误写成强制每次查询 authority。

**现有覆盖／增量**：当前存储和约束测试有基础过期逻辑；补精确等号、反复读取和两种寿命交叉。落点为 `refresh_known_constraints`、`slot_for`、查询缓存读取与派生证据。

### T08：负状态保留事实，但不能越过自己的范围

**构造与步骤**：同一 DID 的 device、zone 分别有有效材料；预热两个 scope 的缓存。按独立分支注入 authority 的 device `Invalid(reason)`、device `Revoked`、DID `Tombstoned`；再交替合并 None、Unknown、来源 NotExist、旧历史 Active 回答，并重建客户端读取持久化缓存。

**断言**：Invalid 是确定回答，保留 reason，可短 TTL 缓存且不计来源失败退避；它不升级为 DID 禁用，也不阻止独立合法候选通过 owner 链成为 best。device Revoked 不得因无回答或历史 Active 消失，也不禁用 zone；DID Tombstoned 覆盖该 DID 各类型。scope A 已知状态不凭空写进 B。终止性负状态的恢复正例须提供真实 authority 新的明确 current 已发布回答，避免测试把“永不恢复”固化成正确行为。

**删除变体**：在 device 已撤销后调用 `remove_doc_result` 删除普通 body，再重启并注入旧 body；撤销事实仍在，不能恢复成功。删除普通缓存同样不能隐式解锁已有 locker。

**精妙之处**：同一批 body 配上不同范围的负事实，能发现 `Option::None` 覆盖旧状态、错误共用 DID／类型键，以及将 Invalid 归为传输错误触发退避。持久化重读可发现只在内存正确的实现。

**现有覆盖／增量**：已有 `s32_invalid_is_an_answer_not_unknown`、`merge_keeps_known_negative_state`；补跨类型、跨 scope 和重启后的完整状态链。

### T09：同一个 normalized opts 连用两次，不能把昨天的回答算作今天的

**构造与步骤**：保存同一份调用配置对象，包括已归一化的变体。第一次开启 `force_authority_query`，authority 返回 V1，缓存 body 和 receipt。第二次最外层调用复用这份配置，仍要求 force，但 authority 返回 NoAnswer／失败；另作 authority 新返回 V1 精确发布记录的正例。第二次开始时总预算仍有余量，避免超时掩盖证据错误。

**断言**：第二次必须有真实 authority I/O；第一轮 receipt 不得使旧验证报告短路，不得成为第二轮的“本轮权威回答”。新回答匹配 V1 时允许复用 body，保留原 body 来源和新的 receipt。另用不同 DID／类型／revision 的新 receipt 作反例，不能满足 V1 的要求；同一轮 document 与 publish_info 可复用满足各自内容需求的回答，无需重复下载。

**准入探针**：调用 `select_authority_current` 时，第二轮 NoAnswer 不得接受第一轮 V1；第二轮有新 V1 receipt 才能选择 V1。即使缓存另有更高的 trust best，也不能拿它替换 receipt 锚定的 V1。此处只测证据门禁，无需建立 RTCP 连接。

**精妙之处**：测试调用者真正会做的“保存 opts 然后重用”，而非每次 new 一个 opts。它抓的是调用上下文泄漏，不是配置相等性。普通 current 返回仍可能使用既有可信缓存；必须断言缺少本轮权威依据，而非武断要求所有缓存结果都为空。

**现有覆盖／增量**：`s28_receipts_are_per_call` 创建了两份新 opts；尚不能证明重用同一份 normalized opts 安全。重点检查最外层调用与 owner 内部递归的边界：前者新建 receipt 集合，后者共享本轮上下文。

### T10：locker 能改变选择，不能替换待验证输入或污染普通缓存

**构造与步骤**：普通缓存有 V1，本地 locker 在 scope A 锁定 V2；执行 current、与 V2 不匹配的 exact、`closest(V2.iat)`，并调用 `verify_document(V1)`。再将本地 locker 回答分别设为 Unknown、明确不存在；清除锁后查询 A，并查询从未加锁的 B。

**装置边界**：A/B 使用隔离的运行环境与 locker；若在一个测试进程内模拟多环境，需显式注入按 scope 路由的 locker。当前 `LockOptions.scope` 仅用于诊断，不能只换这个字符串就当作已隔离。关闭 `simulate_history`，避免测试落入显式模拟完整历史的特殊模式；A 内解锁前后的普通 store 则必须保持同一份，才能测出污染。

**断言**：current 选择 V2 并标记模拟来源；历史查询不能用 V2 冒充不匹配目标；验证 V1 的报告仍属于 V1，不能复制 V2 的成功。明确不存在是强制回答，不访问后续 Zone locker/provider；Unknown／未覆盖才允许继续。解锁后的 A 和独立 B 不能从普通缓存读到之前的模拟 V2 发布事实。

**补充正反例**：`no_request + allow_zone_lock` 可以访问 Zone locker，但所有普通 provider（含 authority）调用为零；`no_request + without_zone_lock` 网络调用全零。Zone locker 向外递归必须关闭再次选择 Zone locker，保留剩余预算和传输限制。

**精妙之处**：把“本机覆盖”“确切输入验证”“严格离线”三个容易被合成一个开关的概念分开；仅检查返回 locked=true 发现不了模拟发布泄漏。

**现有覆盖／增量**：已有 `s21`、`s22` 和 `locked_result_matches_target_revision_only`；补验证另一份输入、解锁／跨 scope 泄漏、no_request 的两种网络含义。

### T11：归一化发生在缓存键之前，而非拿到响应之后

**构造**：对下面的入口用表驱动测试，同时记录实际缓存类型和生成 URL。

| 输入／条件 | 期待 |
| --- | --- |
| 路径对象 `https://example.com/a?lang=zh`，未指定类型 | 实际类型 did-object，原 URL 直取，不加 `/did.json` 或默认 type |
| `https://example.com/a/?lang=zh` | 保留目录语义，取同目录 `did.json`，保留 query |
| `https://example.com/a?next=%2F` | query 中的斜杠不能让路径对象变目录 |
| 路径 URL 已有 `type=profile`，调用未指定类型 | 在查缓存前归一为 profile |
| 已有 `type=profile`，调用显式要求 did-object／其他类型 | 拒绝冲突；默认分支也不能漏检 |
| 同值重复 type／异值重复 type | 不发出重复选择器；冲突必须拒绝，同值采用一致的拒绝或归一策略 |
| 根 `did:bns:alice` 仅 active device | None 归一为 device，不落入 zone 缓存 |
| BNS 多 active 类型不含 zone／含 zone | 前者 ambiguity；后者选择 zone 并记录 warn |
| 根 did:web 默认文档实际为 owner | 记录 requested=None、actual=owner；不写入 zone 槽 |

**步骤与断言**：先显式 zone 查询预热，再请求 None／路径默认；反序再执行。相同实际类型可共享材料，不同实际类型不能串用；错误类型响应不能把显式请求偷偷改成成功。Object DID 不因 type selector 改变。兼容 provider 的 API／旧静态文件路由只按已知配置使用，禁止无限追加后缀试探。

**精妙之处**：URL 看起来只差一个斜杠、类型看起来只是默认值，却会改变身份发现入口和缓存分区。预热能抓到 URL 构造正确、缓存键仍错误的半修复。

**现有覆盖／增量**：`directory_and_object_urls_follow_design_table` 已有基本路由表；补默认分支 type 冲突、重复 selector、业务 query 与实际缓存行为。

### T12：合法 header 与损坏 body 组合，不能凭位置优先级挑一份

**构造与严格断言**：在本地构造 HTTP response parts，无需真实 HTTP 服务。

| body | 声明的 DID header | 期待 |
| --- | --- | --- |
| 未声明为 DID 的 HTML 或业务 JSON `{"title":"hello"}` | 合法 Card | 可提取 Card，业务 body 不参与文档冲突比较 |
| Content-Type／信封表明它是 DID 文档，但 JSON 截断或信封结构错误 | 合法 Card | 拒绝来源回答；不能把坏 body 当 legacy 内容吞掉 |
| 合法 DID 文档 | 缺席 | 按 body 处理 |
| 合法 DID 文档 | 损坏／重复／超限的声明 header | 拒绝；“损坏”不等于“没提供” |
| 同身份类型 iat，但内容 hash 不同的两份文档 | 合法 | 拒绝本次来源回答，不宣布整个 DID 禁用 |
| 明确 revoked 的协议信封，或 HTTP 5xx | 合法 Card | header 不覆盖原状态／传输错误，也不产生成功选择 |

**边界与绑定**：对 header 编码后单值长度做 `16 KiB-1 / 16 KiB / 16 KiB+1` 测试；前两者须仍是合法编码且解析受控，最后一个拒绝。重复 header 即使内容完全一致也拒绝。重定向变体保留原 Object URL 绑定，不能把 Card 存放 URL 当对象身份；header 载体不会提升来源等级、签名或发布事实。

**读取变体**：合法 header 搭配超大媒体 body 时可跳过无关内容；搭配明确声明为 DID 文档但超限的 body 时必须拒绝，不能跳过冲突／状态检查而只信 header。用 fake chunk stream 分别模拟已知 Content-Length 和分块读取，断言读取量与 drop；现有 response-parts 测试只覆盖解析，流读取需另加接缝。

**精妙之处**：两组方向相反的用例同时约束“宽容业务 body”和“严格处理显式文档”，防止一律 JSON=文档、一律解析失败=legacy 这两种省事实现。用有效 body 搭坏 header，能抓到只在 body 缺席时才检查 header 的逻辑。

**现有覆盖／增量**：`http_doc.rs` 已有 HTML/header、重复头和合法文档冲突；补业务 JSON 与显式损坏正文对照、合法 body 配坏头、精确长度边界。`detect_body` 与 `allow_legacy_body` 是值得优先验证的静态疑点，不是已确认故障。

### T13：限制本次获取，不应删除已取得的信任，也不能共享越权任务

**构造与步骤**：先正常取得 trust 的有效 V2；然后 authority_only 解析，authority 只有 V1；冷缓存分支重复 authority_only。另将普通请求暂停在 trust I/O，启动同 DID、同 revision 的 independent_control_plane 请求，并用 trace 检查 owner 递归、fallback、重定向与 Zone locker 的每个后续获取动作。

**断言**：热缓存的 V2 仍可作 best，trust 网络调用为零；冷缓存不能新获取 V2。受限请求不能加入会访问目标隧道入口的共享任务。authority 的等级不能替代通道独立性证明；未知通道按受限策略拒绝。不支持传递限制的 provider 不可恢复默认 HTTP 客户端。

**污染探针**：先策略拒绝，再用允许策略访问同一源；必须真的发起允许的查询，不能被前次诊断的负缓存／退避拦住。反向先普通任务、后受限任务也测试。将来源 ID、revision、scope、force 证据要求分别变更一次，断言应分开的任务确实分开。

**精妙之处**：同一个 trust 源在缓存与 I/O 上有不同许可，能发现“authority_only 顺手删掉 trust best”或“已有可信源就绕过传输限制”。双向安排并发可发现只在某个创建顺序下越权的合并键遗漏。

**现有覆盖／增量**：已有 `s23`、`s26`、`s29`；补热缓存保持、键字段逐项扰动和递归每跳 trace。DNS／代理／真实重定向是否执行策略还需要 provider 组件测试；mock Source 的单元测试不冒充完整网络验证。

### T14：取消发起者，其他等待者仍应等到同一个共享结果

**确定性交错**：所有等待者的 deadline 都足够长，共享任务期限固定；只主动取消 A，不把 A 的 deadline 耗尽混进本例。

```text
A 创建共享任务 ── provider 发出 started ───────────────┐
B 加入同键任务 ── 测试观察 joined(B) ────────────────┤
取消 A；等待 A 返回 Cancelled                         │
C 加入同键任务 ── 测试观察 joined(C) ────────────────┤
释放 provider 的完成屏障 ── B、C 收到同一回答 ────────┘
```

**断言**：provider 实际执行一次，A 的取消不触发共享 I/O 的 drop；B/C 成功，任务 deadline 不因后加入者延长。B 仍在时，A 退出不能删除登记导致 C 新建第二份任务。再把“取消 A”换成 drop/abort A 的等待 Future，检查等待者计数正确；最后一个等待者离开后，未完成 provider Future 被丢弃、许可释放、任务登记可清理。之后同键新请求可正常执行，不被旧任务清理动作误删。

**首次创建变体**：空任务表下让两个调用同时竞争同一槽，确定性调度查找／创建步骤；必须只有一个取得创建权、provider 执行一次。不同策略键的对照则各执行一次。用任务槽状态机或测试调度钩子验证，不能仅靠重复压力测试碰运气；这可发现“先查不存在，再分别 insert”的竞态。

**精妙之处**：共享任务的创建者是最不对称的路径。只取消后加入者，无法发现任务 cancel token 从创建者继承、创建者无条件删除任务、Future 被丢弃后漏减计数等问题。

**现有覆盖／增量**：`single_waiter_cancel_does_not_cancel_others` 实际覆盖后加入者超时；本例覆盖创建者主动取消／drop。当前 `TaskMerger::merge_or_run` 的子预算和退出清理路径值得优先做此验证；尚未用新测试复现，不能直接报告已确认 BUG。

### T15：外层卡在 provider I/O，内层仍能读缓存并完成

**构造与步骤**：缓存中预置能满足内层请求的合法材料。外层 current 请求进入补充 provider 并停在屏障；provider 模拟一次新的入站调用，创建独立请求上下文，以相同 `(scope,DID,doc_type)` 严格离线解析。只有观察到内层完成，测试才释放外层 provider。

**断言**：内层必须在外层 provider 完成之前返回；两者结果均对应各自 revision／策略。另用外层 current、内层 exact 的组合，复测不跨 I/O 占用。这个交错不能证明锁键没有按 revision 错误拆分；锁键需单独断言同 `(scope,DID,doc_type)` 的 current/exact/closest 使用同一键，提交段互斥则用独立临界区探针验证。测试超时只作为死锁失败保护，不是以“少于 1 秒”猜测正确。

**精妙之处**：建立“只有内层先完成，外层才可能完成”的因果结构，稳定杀死跨 I/O 持锁的实现。内层故意使用新入站上下文，避免 visited 检测提前报环而掩盖锁问题。

**现有覆盖／增量**：已有 `s33_inbound_restricted_resolve_is_not_blocked_by_outbound_io`；建议补屏障因果断言，降低时间阈值带来的偶发性。本例验证锁边界，不声称解决真实传输网络环。

### T16：两份旧快照各自验证成功，提交后不能都说成功

**确定性交错**：A/B 读取同一 generation，并在提交前屏障停住；分别验证同 iat、不同 hash 的合法文档。先放行 A 提交，再放行 B。用新的读取者检查最终存储。两种提交顺序各跑一次。

**断言**：只保留先成功提交的版本；另一报告最终为 invalid(conflict)，四个选择标志全 false，不能返回提交前的 valid。相同 hash 对照应幂等；不同 iat 对照最终 best 为较高有效版本，而 latest 只由发布依据决定。两个客户端、两个 store handle 指向同一临时持久化目录，避免仅测一个客户端的内存锁。

**撤销交错变体**：B 读到 Active 快照后暂停，A 提交新的已知撤销事实；B 使用旧快照提交一个本地验证通过的文档。B 没有新 authority current 回答，不能恢复 Active；提交合并后的报告和选择必须服从撤销，fresh reader 亦如此。不得只保存负事实，却仍返回一个成功报告。

**精妙之处**：测试对象包括“对外返回的最终报告”，而非只看数据库最后一行。撤销变体专门发现合并修好了存储，但调用栈仍拿旧 report 放行的错误。

**现有覆盖／增量**：`s30_two_stores_conflict_at_same_iat` 用两份 store 顺序验证；补两者确实从同一旧 generation 起步的屏障和撤销交错。纯 `merge_into` 单元测试先做；真实跨进程文件锁另设小型组件测试，不能用两个 handle 冒充两个操作系统进程。

### T17：超时发生在哪一层，决定继续还是终止

**构造**：将总预算、来源请求上限、补充宽限期设为不同数值，用虚拟单调时钟和可控 provider 逐一跨过边界。

“旧 best、本轮 authority Unknown”分支要强制本轮 authority 查询，或仅使查询缓存到期而保留 best；通过 trace 确认真正收到了本轮 Unknown，避免预热的成功查询缓存绕过测试分支。

| 场景 | 必须观察到的结果 |
| --- | --- |
| 单个来源先超时，总预算仍有余量 | 在剩余预算内继续下一个允许来源；保留来源原因 |
| authority 本轮给出有效 best，补充源到宽限期仍未回答 | 可返回 authority best；慢补充源为本轮 Unknown，不因宽限期计失败退避 |
| authority 本轮 Unknown，只有旧缓存 best，补充源较慢但未超总预算 | 不因旧 best 套用“本轮 authority 已成功”的宽限期，可取得较新的有效补充文档 |
| 总预算耗尽或调用取消，即使已有缓存 best | 返回整次调用的 DeadlineExceeded／Cancelled，不 catch 后 fallback 或假装成功 |
| 先等锁／并发许可消耗预算，再进入 owner current、closest 或重试 | 各层继承原截止时间，剩余预算递减，不能重新获得完整 timeout |

**资源与副作用断言**：未共享的未完成工作被取消；最后一名等待者离开时共享工作清理；不能新写“不存在／禁用／撤销”来描述本地超时，也不能用它污染其他策略的退避。已完成的合法原子提交允许保留，不要求失败调用清空全部缓存。用 DropGuard／许可计数检查清理，不只检查返回快。

**跨主机变体**：Zone locker 客户端已用去部分预算后发送“剩余时长”；服务端使用偏移很大的本机单调时钟重建并收紧预算，剩余时间不增加，也不交换可直接比较的绝对单调时钟值。这里只单测编码与预算计算，真实连接关闭由组件测试验证。

**精妙之处**：同样是没等到回答，来源超时、宽限期与整次取消有不同语义。特别加入“旧 best 存在但本轮 authority 没回答”，能发现以 `result.best.is_some()` 错判宽限期触发条件。

**现有覆盖／增量**：已有 `s11_slow_supplement_after_valid_authority_is_bounded_by_grace`、`s12_authority_unknown_waits_for_slow_supplement_beyond_grace`、`s25` 和预算基础测试；补旧 best 干扰、递归续期、许可等待和资源回收断言。

## 4. 少量属性测试，比随机堆输入更有效

在上述明确反例之后，增加有约束的属性测试。固定 seed，失败时输出最小操作序列、查询键及 trace；使用独立参考表计算期望，不能调用被测选择 helper 计算 expected。

| 属性 | 生成范围与不变量 |
| --- | --- |
| 加入无效噪声不影响正确选择 | 有效非冲突版本集合中插入错误签名／错误身份／重复候选，再排列到达顺序；best/latest 不变 |
| closest 的参考模型 | authority 的固定、无冲突已发布集合 P；对有边界确认的 q，预期严格为 `max {v ∈ P: v.iat < q}`。包含空集合、等号和相邻时间 |
| 隔离键逐项变动 | 只改变 scope、DID、实际 doc_type 或完整 revision，先前目标槽不可无依据复用；访问策略不同的 I/O 任务不得误合并 |
| 状态序列保持已知约束 | `cache → Unknown → verify → restart` 等短序列中，未知回答不清除已知终止状态；没有新 authority current 证据不得恢复可选 |
| 无终止状态变化时的合并 | 同一文档重复提交幂等；无版本冲突的有效集合按不同提交顺序得到相同 best。终止状态与新权威恢复的顺序敏感情况单独按状态机测试，不盲目要求交换律 |

再做定点 mutation 验收：分别把 `<` 改为 `<=`、候选 key 从 `(iat,hash)` 缩成 iat、去掉共享任务键中的策略、共享创建者取消 token、复用上轮 receipt、将坏 header 当缺席、把历史 owner 换成 current。T03、T01、T13、T14、T09、T12、T05 应分别失败；若仍通过，说明测试没有真正约束声称覆盖的错误。

## 5. 实施顺序与完成标准

先落 T09、T12、T14 的最小反例：它们与现有测试看似相近，却检查了不同分支，且源码中已有值得核实的路径。随后落 T03、T05、T16，保护版本边界、根信任和提交裁决；其余按上表补齐。每组独立测试使用描述行为的函数名，例如 `creator_cancel_keeps_joined_waiters_alive`，不写成难以定位失败的大型参数笛卡尔积。

建议测试归属：纯模型放在相应模块的 `#[cfg(test)]`；需要 fake Source 的内核组合例继续放在 `resolve_did_scenarios.rs` 或新建专项测试文件；HTTP 解析用本地 response parts。真实进程锁、DNS／代理／重定向与 socket 释放明确归为组件测试，不依赖公网 BNS、真实 Zone 或真实一年有效期来通过单元测试。

常用检查命令（在 `buckyos-base/src` 执行）：

```bash
cargo test -p name-client --lib resolver::
cargo test -p name-client --test resolve_did_scenarios
```

验收每个用例时，应同时具备：明确的正常对照、最小反例、对文档身份／事实标志／选择标志的断言，以及适用的 I/O／缓存副作用断言。失败信息能指出是“缺材料”“证据不匹配”“确定无效”还是“整次终止”。并发例须证明指定交错确实发生；修复后的实现通过原断言，而不是删掉反例或把无关失败统称为解析失败。

## 6. 实施记录（2026-10-26）

### 6.1 测试落点与运行

| 位置 | 内容 |
| --- | --- |
| `src/name-client/src/resolver/design_tests/fixture.rs` | §2 装置：`ScriptedSource`（按 DID／类型／revision 排队回答，规则优先、模型兜底，未预期调用由 `Fx::finish` 报错）、三把独立 Ed25519 密钥 `K1`／`K2`／攻击者 `KX`、冻结墙钟、`Call` 轨迹（scope、类型、完整 revision、访问策略、传输策略、deadline、递归深度、force）、带 drop 探针的 `Gate` 屏障、本地 HTTP 替身 `LocalHttp` |
| `design_tests/evidence.rs` | T01–T06 |
| `design_tests/cache.rs` | T07、T08、T16 |
| `design_tests/context.rs` | T09、T10、T11、T13 |
| `design_tests/timing.rs` | T14、T15、T17 |
| `design_tests/properties.rs` | §4 的五条属性（固定种子 SplitMix64、独立参考模型，失败时输出种子与操作序列） |
| `http_doc.rs`、`publish_info.rs`、`doc_result.rs` 的 `#[cfg(test)]` | T12、T11 路由表、T03 边界、T07 等号、T16 纯合并 |
| `web_provider_tests.rs` | T11 旧静态路由只按配置使用 |

内核组合测试放在 crate 内（`resolver::design_tests`），可以直接观察 `TaskMerger`、串行锁和存储；`cargo test -p name-client --lib resolver::` 即可运行。共新增 69 个测试。

为满足 §2 的时间要求，新增了三处测试接缝：

- 墙钟：`resolver::clock::unix_now()` 统一替换解析器内的 `buckyos_get_unix_timestamp()`。`#[cfg(test)]` 下可按线程冻结或推进；文件后端的 `spawn_blocking` 合并仍读真实时间。
- 单调时钟：`Budget`、`TaskMerger`、`Backoff` 改用 `tokio::time::Instant`。T17 等用例因此可以用 `start_paused` 的 Tokio 虚拟时钟逐一跨过边界。`ResolveOpts::with_deadline` 仍接收 `std::time::Instant`。
- 流读取：`read_response` 拆出 `read_response_body` 与 `ResponseBody` trait，测试可以用假的分块流断言读取量和 drop。`TaskMerger` 另有测试专用的 `on_lookup_miss` 调度钩子，用于确定性地制造首次创建竞态。

真实 JWT 验签按真实时间检查 `exp`。因此夹具里的时刻都是“真实当前时刻”的偏移：设计稿的 `now=10_000` 对应 `Fx::at(10_000)`，解析器墙钟冻结在同一时刻。

### 6.2 用例对照

| 编号 | 测试 |
| --- | --- |
| T01 | `t01_bad_candidates_never_take_the_version_slot_in_any_order`（三候选全排列）、`t01_first_valid_commit_wins_and_same_hash_is_idempotent` |
| T02 | `t02_reports_belong_to_the_exact_input`（含三种来源等级的身份检查）、`t02_equal_claims_are_not_the_same_signed_input`（键序不同的两个合法 JWT、JSON 对照、body／header 载体冲突） |
| T03 | `t03_closest_boundaries_do_not_share_slots_in_either_order`（正反两种顺序，逐查询检查槽键、证据与历史请求轨迹）、`t03_derived_closest_evidence_points_at_the_current_answer`、`t03_malformed_history_answers_never_fill_a_slot`、`t03_unpublished_material_and_negative_answers_do_not_fall_back`、`closest_boundary_must_strictly_precede_the_query` |
| T04 | `t04_source_signature_and_publication_are_independent`、`t04_new_authority_evidence_upgrades_the_cached_body`、`t04_owner_roots_need_authority_and_never_set_best` |
| T05 | `t05_historical_key_signs_current_owner_constrains`、`t05_valid_iat_boundary_is_inclusive`、`t05_signing_key_follows_the_owner_at_issue_time`、`t05_missing_or_expired_history_is_never_replaced_by_current`、`t05_signing_query_does_not_depend_on_the_outer_revision` |
| T06 | `t06_owner_update_vs_revocation_for_unsigned_trust_documents`、`t06_locker_change_invalidates_documents_verified_through_locked_material` |
| T07 | `t07_document_exp_boundary_is_exact_and_offline`、`t07_short_lived_history_evidence_expires_with_its_answer`、`t07_cache_reads_do_not_renew_current_evidence`、`refresh_expires_at_the_exact_second` |
| T08 | `t08_invalid_is_a_scoped_answer`、`t08_revoked_survives_unknowns_history_and_restart`（含跨 scope、重启）、`t08_tombstone_covers_every_type_until_a_new_current_answer`、`t08_removing_bodies_keeps_negative_facts` |
| T09 | `t09_reused_normalized_opts_do_not_reuse_previous_receipts`、`t09_admission_needs_a_matching_receipt_from_this_round` |
| T10 | `t10_locker_changes_selection_but_not_the_verified_input`、`t10_negative_lock_is_forced_and_unlock_leaves_no_simulated_facts`、`t10_no_request_has_two_network_meanings`（本地 HTTP 替身充当 Zone locker） |
| T11 | `t11_location_table`、`t11_default_type_is_normalized_before_the_cache_key`、`t11_ambiguity_warning_and_actual_type_are_reported`、`t11_wrong_type_response_does_not_satisfy_an_explicit_request`、`legacy_static_routes_follow_configuration_only` |
| T12 | `t12_business_body_does_not_conflict_with_the_card`、`t12_malformed_declared_document_is_rejected_even_with_a_card`、`t12_valid_body_with_corrupt_header_is_rejected`、`t12_header_length_boundary`（16 KiB-1／16 KiB／16 KiB+1）、`t12_conflicts_and_negative_states_beat_the_card`、`t12_redirect_keeps_the_object_binding`、`t12_large_bodies_are_skipped_only_when_undeclared` |
| T13 | `t13_authority_only_keeps_cached_trust_but_cannot_fetch_it`、`t13_independent_control_plane_is_never_merged_with_default_tasks`、`t13_policy_refusal_and_allowed_request_do_not_pollute_each_other`、`t13_merge_key_fields_each_separate_tasks` |
| T14 | `t14_creator_cancel_keeps_joined_waiters_alive`、`t14_dropped_waiters_release_membership_and_last_one_cancels_the_task`、`t14_first_creation_race_yields_a_single_task`（多线程运行时 + 屏障钩子）、`t14_joiners_do_not_extend_the_shared_task_deadline` |
| T15 | `t15_inbound_resolve_completes_while_outer_waits_in_provider_io`、`t15_lock_key_ignores_revision_and_commit_runs_inside_the_lock` |
| T16 | `t16_stale_snapshots_cannot_both_report_success`（两种提交顺序、两个 store handle 共用临时目录）、`t16_same_hash_is_idempotent_and_higher_iat_wins_best`、`t16_stale_snapshot_cannot_resurrect_a_revoked_type`、`merge_does_not_resurrect_state_from_a_stale_snapshot` |
| T17 | `t17_source_timeout_moves_on_within_the_remaining_budget`、`t17_supplement_grace_is_an_unknown_not_a_backoff`、`t17_stale_best_with_unknown_authority_does_not_trigger_the_grace`、`t17_exhaustion_and_cancellation_terminate_without_writing_negative_state`、`t17_lock_and_permit_waits_consume_the_same_deadline`、`t17_zone_locker_sends_remaining_budget_and_no_zone_lock` |
| §4 | `p1_invalid_noise_does_not_change_the_selection`、`p2_closest_matches_the_reference_model`、`p3_isolation_keys_change_with_every_field`、`p4_known_terminal_state_survives_short_sequences`、`p5_merge_is_order_independent_without_terminal_changes` |

与原设计的差异：

- **T05 步骤 3**：冻结稿 §6 已定，签发时 owner 的查询边界取 `closest(doc.iat + 1)`，以覆盖同一秒内激活并签发的情况。所以用例按实现断言：`D.iat == O2.iat` 时签发者是 O2，K2 通过、K1 失败；早一秒时签发者是 O1，K1 通过。步骤 4 的“查询时刻”同样取 `D.iat + 1`。`resolve-did.py` 第 494 行仍写 `closest(doc.iat)`，与冻结稿不一致，尚未回写。
- **T06 站点解绑**：当前实现没有“owner 绑定站点”这一来源配置，trust 来源由 method 注册表静态决定，所以解绑分支没有对应代码。已实现的部分：不改变验证依据的 owner 换版不影响旧 trust 文档；撤销线必须立即作用于没有签名依赖的 trust 文档；locker 配置版本变化的对照。
- **未做的组件测试**：真实跨进程文件锁（T16 用两个 store handle 共用一个目录）；DNS、代理、真实重定向对传输策略的执行；不支持传递限制的 provider 不得退回默认 HTTP 客户端（T13）。这些都需要组件测试环境。

### 6.3 用例暴露并已修复的缺陷

在未修改的源码上，新测试中有 25 个失败、1 个挂起；修复后全部通过。

| 用例 | 缺陷 | 修复 |
| --- | --- | --- |
| T09 | 调用方保存已归一化的 opts 再复用时，第二次最外层调用直接复用上一轮的 receipt：`force_authority_query` 不发 I/O，`select_authority_current` 还会接受上一轮的 V1 | receipt 按轮次记录。最外层调用（`depth == 0`）在同一集合里开始新的一轮，只复用、只采信本轮回答；`ReceiptSet::authority_receipts` 取最近一轮，调用方在调用后读取的仍是本次回答 |
| T12 | 未声明为 DID 文档的业务 JSON 被当作文档，与 header Card 冲突而整次拒绝；声明为 DID 文档或信封但已损坏的正文被当作业务内容吞掉，只信 header；声明为 DID 文档的超限正文在有 header 时被跳过 | `detect_body` 按“是否声明为 DID 文档”分类（DID 类 Content-Type、信封字段、DID 形式的 `id`、JWT）。声明后损坏的正文、声明后超限的正文都拒绝本次来源回答。目录与 resolver API 入口仍把 JSON 当文档 |
| T14 | 共享任务的取消信号是创建者的子 token，创建者一取消，其他等待者就收到 cancelled；创建者退出时无条件删除登记，后来者会新建第二个任务；等待 Future 被 drop 时不递减等待者计数；先查后插存在竞态 | 共享任务使用独立预算（共享上限与创建者剩余预算取小）和独立取消信号；`Membership` RAII 守卫负责离开，最后一个离开者取消任务并清理登记；登记由任务完成时自行删除；用 `entry` 原子地取得创建权 |
| T03 | 来源回答里的 `selected.iat == query_iat`（越界）可以填满 closest 槽 | `PublishInfo::satisfies` 要求严格早于查询边界；locker 的 `simulate_history`（Root Trust）仍按原设计放行 |
| T07 | 查询槽固定存活 1 小时，不受来源回答 `validUntil` 约束；每次缓存读取都按“现在 + TTL”给 current 发布依据和状态续期 | 有效期按依据的检查时刻（`checked_at`）计算，且不超过 `validUntil`；`PublishEvidence` 增加 `valid_until`；合并时保留最新的 `checked_at` |
| T04 | authority 新的 current 回答只给发布信息时，已缓存的同一份 trust body 不会成为 latest | 新增 `DocResult::fill_latest_from_known`：body 保留原来源，发布依据记 authority 来源，不设置 `is_signed` |
| T06 | owner `current` 查询只要缓存里有有效 latest 就提前返回：即使 `force_authority_query` 取到的新回答已指明更新的 latest，也不会提交新版本（s20 原先靠删除 owner 缓存绕过） | `satisfies_published_target(current)` 要求 latest 与已合并的发布依据一致 |
| T06 | 经 locker 提供的 owner 验证的文档，在 locker 配置变化后仍保持有效 | `Dependency` 记录 `simulated`；locker 版本变化时，带模拟依赖的选择也回到重验 |
| T08 | DID 级 Tombstoned 只写进回答它的那个类型，其他类型的缓存仍可选；新的 current 已发布回答也无法解除 DID 级禁用 | 按 scope 保存 DID 级状态记录（伪类型 `did-state`），各类型读结果时按 `did_state_checked_at` 采用较新的一方；新的非推导、非模拟 current 已发布 Active 回答把 DID 级状态记为 Normal |
| T10 | locker 对 latest 之后的 exact 模拟回答“未发布”时，这份模拟发布信息被写进普通缓存，解锁后仍残留 | locker 对目标给出明确回答时作为强制回答返回，不再继续查；带模拟发布信息的这一轮结果不写入普通缓存 |
| T11 | 对象 URL 上重复的 `type` 选择器（同值或异值）被原样发出 | 一律拒绝 |
| T16 | 跨进程合并时，基于旧快照的本地结果把存储中更新的 Revoked 覆盖回 Active，被拒绝的版本也借旧快照复活；`verify_document` 提交后仍返回提交前的 valid 报告 | 状态按 `state_checked_at`／`did_state_checked_at` 裁决，较新的依据胜出；存储中已拒绝的版本不再接受；合并后重新应用约束；`verify_document` 提交后按存储中的最终结果重新判定报告 |

### 6.4 定点 mutation 验收

逐个施加 §4 列出的变异，重建后运行对应用例，验证完毕即还原源码：

| 变异 | 结果 |
| --- | --- |
| 候选键 `(iat, hash)` 缩成 iat | T01 失败 |
| 共享任务键去掉访问策略 | T13 失败 |
| 共享任务继承创建者的取消 token | T14 失败 |
| 复用上一轮 receipt（去掉最外层的新一轮） | T09 失败 |
| 把损坏 header 当缺席 | T12 失败 |
| 把签发时 owner 换成当前 owner | T05 失败 |
| closest 推导 `<` 改为 `<=`（`derive_for`） | T03 内核用例**未失败**：§6.3 新增的严格边界检查会丢弃越界的推导回答，解析转为真正的历史查询，结果不变。纯模型用例 `closest_derives_only_after_latest` 失败 |
| 严格边界检查 `<` 改为 `<=`（`satisfies`） | `t03_malformed_history_answers_never_fill_a_slot` 与 `closest_boundary_must_strictly_precede_the_query` 失败 |

两层 closest 边界各自至少有一个用例约束。
