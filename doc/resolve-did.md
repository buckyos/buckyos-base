# resolve-did 设计冻结

> 状态：流程冻结草案，供团队 review。本文定义目标行为，不表示源码已经实现。
> 本轮以带注释的关键流程和已有场景的简化方案为冻结依据；现有入口与 policy 对照基于 buckyos-base HEAD `168733e`。
> [组件与使用模式核对](./resolve-did组件与使用模式核对.md)是使用证据；[协议冻结讨论伪代码](./resolve-did协议冻结讨论伪代码.md)保留讨论历史。两者的旧建议不自动成为本次要求。

## 0. 先固定默认行为

**在指定 scope 内，设备文档由该 scope 认可的 owner 签发，满足身份、签名、时间和已知撤销约束，且不比该 scope 已接纳的版本老，就通过默认验证。**

- 不要求设备已经上链，也不要求先有这份设备文档的可信缓存。可信 owner 足以支持首次验证。
- 不默认检查 Zone 成员表。需要成员、封禁等高级准入规则时，由 Zone 动态生成 scope 覆盖或 `blocked` 回答。
- 不默认查询公网发布状态，不在 RTCP 建立连接后自动补做公网确认。需要发布证明的调用方显式提出检查要求。
- 验证按需获取材料，能否决就立即退出。不构建统一 snapshot，不要求多个 cache 或远端查询对应同一时刻，也不因材料版本变化反复重建快照。
- “见过”指本 scope 验证并受控接纳过；未验证候选不能推进基线。`revision = (iat, content_hash)`，同 iat 不同 hash 是冲突，`version_seq / mini_version_seq` 不参与判断。

revision 沿用 [现有编码契约](../src/name-client/src/provider.rs)：JWT 对 compact 原文取 hash，JSON 对既定规范化序列化结果取 hash；不把解码后的 JSON 当作原 JWT。内容寻址对象修改内容后使用新身份，不能仅靠更大的 iat 覆盖同一对象身份。

本文冻结获取、验证、锁定的职责，必要的结果语义、受控提交，以及第 7 节的场景组合。S2S 身份不属于 did-resolve 的领域。Info、地址发现、端点自描述、展示资料合并使用各自契约。`did:key / did:dev` 不作为可信 DID Document 的解析入口。

历史验证、Zone 管理 API、业务连接生命周期、批量查询和缓存物理布局不在本次冻结范围。HTTP 字段名可调整，但回答范围、来源、时间、状态含义必须明确。

## 1. 核心动词与组合入口

| 动词 | 职责 | 副作用边界 |
| --- | --- | --- |
| 获取 `get` | 按来源规则返回文档或事实，保留来源与时间 | 可更新查询缓存和已知负状态；不把候选写成已接纳文档 |
| 验证 `verify` | 验证确切输入，缺什么材料才调用获取 | 异步、可按 policy 查询；不提交候选、不推进候选基线 |
| 锁定 `lock / unlock` | 改变 scope 的选择和准入约束 | 管理操作；不自动产生 owner 签名或公网发布证明 |

`commit(report)` 是受控保存验证结果的接口，负责本地版本合并，不再执行解析或联网。普通调用自动提交；RTCP、安装等调用在业务准入后提交。`resolve_did` 消费锁定配置，不执行锁定。

```python
# 以下都是目标伪代码，helper 表示注释规定的职责，不表示已有同名 API。
async def resolve_did(did, doc_type=None):
    result = await resolve_did_ex(did, doc_type, ResolvePolicy.default())
    return result.document

async def resolve_did_ex(did, doc_type, policy):
    report = await resolve_with_options(did, doc_type, Options(policy=policy))
    return report.to_resolved_document_or_error()

async def verify_received(did, doc_type, body, opts):
    # 直接验证收到的字节；不先 resolve 另一份文档，不自动保存。
    return await verify(did, doc_type, body, opts)
```

`Options` 包含 `scope / policy / checks / purpose / commit`；默认 `checks = {valid, not_older_than_seen}`，`purpose = AuthSubject`，解析组合默认 `commit = true`。`checks` 不允许关闭身份、签名、时间、已知撤销和 scope 强制约束；可显式不要求本地最新，以检查旧文档是否仍有效。

## 2. 流程需要的最少事实

### 2.1 查询结果与来源

| 查询结果 | 含义与后续动作 |
| --- | --- |
| `Answered(value)` | 来源给出明确回答；`NoRecord`、`NoBody` 也是回答 |
| `NotApplicable` | 来源不覆盖该查询，继续下一来源 |
| `Unknown(reason)` | 超时、连接失败、5xx、坏响应等未能回答；保留失败原因 |
| `NotConsulted` | 本次来源范围不允许查询，或前面的判断已结束流程 |

`Unknown / NotConsulted` 不能变成 `NoRecord`。缓存 miss 也不是来源的无记录回答。查询轨迹保留实际是否访问了某来源；提前退出后，不补做查询来填满报告。

每份回答保留 `origin / scope / checked_at / valid_until`，文档另有 `locked` 标记及临时材料的硬期限。信任来源由客户端注册的 method authority、配置的 Zone 或有权限的本机管理入口决定，网络 payload 不能自报可信。缓存命中保留原来源和原查询时间。

### 2.2 两类查询键

- 文档：`(did, actual_doc_type) -> Body / NoBody`。`get_owner_document(owner)` 是读取 `(owner, Owner)` 并检查根材料资格的 helper，不要求第三套存储。
- 发布信息：逻辑上 `did -> PublishInfo`。它可以只提供绑定、吊销或锚点，不必带 body。

```python
# 数据形状示意。Record 中 identity 属于整个 DID，docs 属于各文档类型。
PublishInfo = NoRecord | Record(
    owner=None,                       # 无覆盖绑定时使用 method 的结构规则
    identity=Active,                  # Active / Tombstoned / Migrated(target)
    docs={doc_type: DocEntry(anchor=None, revoked_through_iat=None)},
)
ScopeAnswer = Answer(
    body=None,                        # 可只覆盖文档
    publish_info=None,                # 可显式断言 NoRecord；缺字段表示没有覆盖该列
    blocked=False,                    # 对该查询键的局部拒绝
)
```

这里的 `NoRecord` 表示来源明确没有对应发布记录，不表示刚查过公网，也不证明文档最新。`Record{Active}` 可以没有目标类型的 anchor；owner 绑定转移并不要求每种文档都发布。

wire 若按 `(did, doc_type)` 返回局部记录，客户端必须保留回答覆盖范围和逐项 TTL。一个类型未发布不能折叠成整个 DID 的 `NoRecord`；未查询的类型保持未知。did 级 tombstone 必须覆盖所有类型。

`doc_type=None` 仅在入口表示默认身份文档发现；Provider 必须报告实际类型及请求身份绑定。进入精确验证、版本比较和接受存储时使用实际类型。默认查询与显式类型查询应落到同一份身份文档，不能让不同类型共享模糊基线。

### 2.3 验证报告与存储

报告记录确切文档、实际类型、revision、scope、本次使用的 owner/绑定/管理信任依据，以及实际取得的发布事实和依赖期限。它是在流程中积累的事实，不是预先准备的快照。

| 报告部分 | 含义 |
| --- | --- |
| 有效性 | `Valid / Invalid(reason) / Unavailable(dependency)`；缺材料与确定错误分开 |
| 本地版本关系 | `FirstKnown / Same / Newer / Older / Conflict / Unknown` |
| 发布关系 | `NotChecked / NoRecord / NoAnchor / Anchored / Superseded / NewerThanPublished / DifferentDocument` |
| `accepted` | 本次所有要求已满足；不代表业务已授权，也不代表已经提交 |
| 证据与期限 | 使用了什么、来自哪里、何时取得、何时应重查、何时必须失效 |

发布关系只针对确切候选：比 anchor 新的合法签名文档是 `NewerThanPublished`；同 iat 不同 hash 为 `DifferentDocument`，阻止普通接纳。较旧文档可以仍有效，由本地版本要求或显式发布要求决定是否接纳。没有发布查询事实时，不制造“权威当前”结论。

| 本地状态 | 保存内容 | 使用规则 |
| --- | --- | --- |
| 查询缓存 / 候选区 | 来源回答、普通发现的 Observed 文档 | 按来源及范围复用；默认查询 TTL 30 秒；Observations 不推进基线 |
| 接受存储 | 已验证文档及实际信任依据、依赖期限 | 软 TTL 默认 1 小时；过软 TTL 可按 policy 作为待重验候选；不能越过硬期限 |
| 版本基线 | 本客户端在指定 scope 接纳过的 revision | 与 body 缓存淘汰分开；真实无记录才是 FirstKnown，读取失败是 Unknown |
| 已知负状态 | did 级墓碑、逐类型撤销边界、仍生效的 scope 阻止 | 不因查询 TTL 到期或 Unknown 自动清除 |

`OwnerVerified`、method 权威确认、`AdminTrusted` 是不同信任依据，可并存，不作为简单高低分数。`Observed` 不属于接受存储的证据等级。普通旧缓存若缺少可用的信任依据或期限，必须重验后才能进入新接受存储。

## 3. 获取：复用回答，控制来源，不做候选准入

相对优先级是 **本机 Lock > Zone 回答 > 本机接受存储与查询缓存 > method 权威 > 补充源**。body 与 publish_info 独立选择：只锁 body 不隐式覆盖发布信息，只锁发布信息仍可向后寻找 body。锁和 Zone 的实际来源不得因转存而变成公网权威。

```python
async def get(table, key, plan, excluded_bodies=()):
    trace = QueryTrace()
    for source in plan.sources_for(table, key):
        # 每个来源先看可复用的回答；读取一次并不要求查询其他来源。
        # 本机 Lock 每次读当前配置；普通缓存遵守来源范围、TTL 和硬期限。
        answer = read_reusable_answer(source, table, key, plan)
        if answer is None:
            answer = await query_if_allowed(source, table, key, plan)
            remember_query_answer(source, table, key, answer, plan)
            # 失败只做退避；NoRecord / NoBody 可缓存；命中不刷新 checked_at。
        trace.add(source, answer)
        raise_if_applicable_block_or_tombstone(answer, key)
        # through_iat 先保留为事实，取得候选后逐版本判断；它不是整个 DID 终态。
        if answer.is_body() and answer.hash in excluded_bodies:
            continue                      # 同一份已拒绝候选不重复验证
        if answer.satisfies_query(table):
            return answer.with_trace(trace)
        # NoBody 继续找 body；字段缺席、NotApplicable、Unknown 均按计划继续。
        # 身份终态/迁移另作为可信事实保留，不能丢成普通 NoBody。
    return trace.finish_unanswered()
```

`get_document / get_publish_info` 是上面获取逻辑的类型化入口。`get_owner_document` 使用同一文档查询，并限制为可信根来源；补充源或 Observed owner 不能自证信任。一次 wire 同时返回 body 和状态时可拆开复用，无需发两次请求。并发合并按 scope、来源、表、键隔离。

`satisfies_query` 对文档只接受 Body，对发布信息接受 NoRecord 或 Record；NoBody 继续向后找文档。最后没有 body 时，仍将明确 NoBody 与 Unknown / NotConsulted 区分，并保留回答中已经取得的发布事实。普通文档缓存阶段优先提供已接纳的较新候选，不能让 Observed 或旧查询副本覆盖它。

查询缓存只缓存明确回答；`valid_until` 缺省取接收时刻加 30 秒。负事实按第 8 节保留。接受存储只作为文档来源，获取不会把其“曾通过验证”当成本次验证结论。过期 Lock 仍保留并报失效，不能当 miss 回退。

### 3.1 policy 的执行边界

保留现有 [ResolvePolicy](../src/name-client/src/provider.rs) 中有用的访问限制；不把 policy 全部压成一个 `source` 后丢掉递归约束。

| 来源预设 | body 访问范围 | 验证依赖 |
| --- | --- | --- |
| `LocalOnly` | 本机 Lock、允许的本机缓存 / 材料 | 原样传播，零网络 |
| `LocalAndZone` | 本机 Lock、Zone、允许的本机缓存 | 原样传播，不访问公网 authority / supplement |
| `RemoteAuthority` | 本机 Lock 后访问权威及允许的 body 补充源；跳过普通主体缓存，无 stale | owner 可沿用现有 for_owner_lookup 派生 BestAvailable 复用可信材料；不扩大显式安全边界 |
| `BestAvailable` | 正常相对优先级 | 同一相对顺序，收紧 owner 信任资格 |

`RemoteAuthority` 是访问策略，不是证据。显式公网检查通过 `get_publish_info` 的 authority-only 计划取得独立 receipt，可按要求复用原权威缓存或强制重查；该 receipt 不覆盖本机锁，也不能从 scope 回答推导。

| 现有字段 / 配置 | 冻结落点 |
| --- | --- |
| `use_zone_resolver` | 与客户端启用状态取交集；关闭后，主体、owner 和迁移路径都不调用 Zone，防止服务查自己 |
| `current_zone_did` | 仅请求 DID 完全匹配时启用 CurrentZoneBootstrap 补充源；对子 DID、owner、迁移目标重新判断 |
| `allow_stale_cache` | 控制可信 body 的软过期兜底；RemoteAuthority 禁止；不能绕过锁、负状态、硬期限或重验 |
| `enable_cache` | 禁用普通查询缓存与接受 body 缓存读写；不撤销锁、已知负事实和防回退基线 |
| `commit` | 关闭本次候选提交；不禁止获取阶段缓存回答或记住可信负事实 |
| `max_depth / visited` | owner 依赖和迁移按完整文档键限制深度、检测环路；同键的材料查询不重复算递归 |
| `follow_migration` | 仅解析组合可跟随可信目标；验证收到的文档永远不换目标 |
| `local_authority_override` | NameClient 注入自己的 scope store，并向依赖传递 |
| `allow_self_signed_when_missing` | 删除；可信 owner 签名是默认入场规则，owner 自签名不能建立根信任 |
| `allow_unverified_cache_when_unavailable` | 仅旧解析出口可返回明确打标的 ObservedFallback；报告 accepted=false，不进入认证或接受存储 |

`scope.closed_world` 只限制验证依赖：owner、绑定和 scope 配置只读本地配置，缺 owner 即 MissingDependency，不读 Zone 或公网。无发布配置可形成带 ScopeDefault 来源的局部 NoRecord，不能满足公网检查。body 获取仍由 source 决定；整个调用要零网络还须 LocalOnly。所有派生策略保留以上限制，不能重建默认 policy 偷偷扩大范围。

## 4. 验证：先便宜检查，再逐项取证

### 4.1 默认验证主路径

`verify` 不预取完整材料。格式错误、过期、已知阻止、明确回退等应在下一次外部查询前退出。scope、owner 或可选发布查询返回新事实后，也立即处理已经能确定的拒绝。

```python
async def verify(did, doc_type, body, opts):
    require_resolvable_did_and_exact_type(did, doc_type)
    path = opts.path.descend(did, doc_type)
    used = EvidenceLog(body)               # 从已取得的材料开始记录；不发任何查询
    doc = parse_exact_document(body)
    check_id_type_revision_and_exp(doc, did, doc_type)
    check_known_local_constraints(opts.scope, doc, opts.checks)
    # 上面失败时零网络。基线为空可首次接纳；基线读取失败不能当成空。

    rules = await get_effective_scope_rules(did, doc_type, opts, used)
    # 只读本次主体的适用覆盖；可复用 get_document 已带回的 Zone 回答。
    # 不查询 owner，不查询公网，不为填充报告读取其他文档。
    check_scope_block_lock_and_hard_deadline(rules, body)
    # 被锁到 V1 时，收到 V2 也在这里检查，不能通过 verify_received 绕过锁。
    check_known_publication_constraints(doc, rules, used)
    # 处理已取得的墓碑、迁移、撤销边界、冲突；不为此主动出网刷新。

    if doc_type == Owner:
        root = await get_exact_root_evidence_if_needed(did, body, opts, used)
        # 只接受受信 method / scope 对确切根文档的证明。
        # 复用已有来源证明；外部自签 owner 单独出现时没有根信任。
        check_root_identity_time_and_integrity(body, root)
        used.add(root)
    else:
        binding = known_scope_or_method_binding(did, rules, used)
        if binding is None:
            binding = structural_owner(did)
        if binding is None:
            binding = await get_binding_if_allowed(did, opts, used)
            # 仅结构和已有可信材料均不足时补查询；绝不使用 doc.owner 自证。
            check_newly_obtained_denials(doc, used)
        check_owner_binding_and_purpose(doc, binding, opts.purpose)

        grant = authorized_exact_document_grant(body, rules, used)
        if grant is not None:
            check_grant_scope_purpose_and_deadline(grant, doc, opts)
            used.add(grant)                # 管理投影 / method 特定文档，见 4.2
        else:
            require_owner_binding_or_report_missing(binding)
            owner_doc = await get_owner_document(binding.owner, opts.for_owner(path))
            check_root_identity_time_and_integrity(owner_doc.body, owner_doc.evidence)
            check_known_owner_constraints(owner_doc, opts.scope)
            # 包含已经知道的根撤销和版本下限，不为检查而刷新全部 owner 历史。
            check_owner_valid_iat(doc, owner_doc)
            verify_owner_signature(body, owner_doc.main_and_retained_keys)
            used.add(binding, owner_doc)
            # 签名不符就结束；不搜索另一套 owner 来让候选通过。

    if opts.checks.require_publication_evidence():
        receipt = await get_required_authority_receipt(did, doc_type, opts, used)
        # 仅显式 fresh / anchored_current / published 才走这里。
        # 满足要求的已有真实权威 receipt 可复用，不因调用 helper 再查询一次。
        check_authority_identity_binding_and_revocation(doc, receipt, opts)
        check_requested_publication_relation(doc, receipt, opts.checks)
        used.add(receipt)

    check_document_and_dependency_hard_deadlines(doc, used, now())
    # 前面的 I/O 可能跨过 exp；最终只重看时间，不重查全部材料。
    return accepted_report(body, doc, opts.scope, used)
```

每个 `check` 失败立即形成 `Invalid(reason)` 或 `Unavailable(dependency)` 报告并结束；上面的直线伪代码省略统一的错误包装。约束和 grant 以实际读取结果加入 used，只有真正验证过的依据才能进入成功报告。已经确定命中某份文档锁的失败可报告 LockedDocumentInvalid，外部候选不匹配锁则报告 LockedDocumentMismatch；廉价格式检查失败不必为错误打标再查锁。`accepted_report` 只表示本次要求满足，不保存候选，也不授权连接。已获得足够可信 owner 的新设备，即使公网未查询或失败，也可按默认规则通过；不能把这种结果标成 CheckedNoRecord 或公网当前。

获取阶段一并取得的 owner/发布证明可以直接使用，helper 不强制再次访问来源。验证期间各材料可能来自不同时间；记录实际依据和期限，不承诺跨来源原子性，不循环重建。已知变化后的下一次验证使用更新材料。

### 4.2 信任根、管理投影与用途

Owner 是递归基。获取到 owner body 后仍需检查请求身份、可用 key、文档有效期、信任材料硬期限和已知负状态；JWT 的自签名只证明完整性。某份 owner 若被锁定但已经过期，不能继续作为子文档验签材料。

普通 Device 文档默认走 owner 验签。`authorized_exact_document_grant` 只处理显式管理信任或 method 规定的确切文档证明，例如本地生成的 Owner 材料、rootfs 预装 JSON、did:web 的受信发布面。它必须由有权限的输入边界产生，绑定精确内容、scope、用途和期限；普通 Lock、来自补充源的 body、payload 中的 trusted 字段都不能产生此 grant。已知撤销和 scope 阻止仍先执行；结果标注管理 / method 信任，不谎称完成 owner 验签。

`AuthSubject` 需要可信 owner 绑定，并拒绝结构 owner 与生效绑定分离；Owner 根按自身受信身份处理。`ObjectDocument` 可使用独立权威证明处理无结构 owner 的客体，但报告不可用作权限主语。did:web 不凭域名层级猜 owner，使用 method 或 scope 提供的绑定 / 证明。显式公网检查不能让 scope 的绑定冒充公网绑定。

### 4.3 按需取得 scope 约束

`get_effective_scope_rules` 是获取的 helper，不是另一个验证模式。它按本机 Lock、Zone 的相对优先级读取适用于该 DID 和文档键的覆盖，逐列保留来源；普通 Zone 缓存返回 body 不自动意味着锁定，只有受信控制面明确的 `locked` 标记才固定候选。

已有 body 查询回答可复用；直接验证收到的 JWT 时也必须检查这些约束。高优先级已覆盖的列不再向后查询。blocked 在其作用键上终止；未覆盖的列保持缺席，不擅自生成 NoRecord。Host 的锁不能被后来的公网 Active 解锁。

Zone 规则按其有效期复用，动态更新的可见性受该期限影响。若选定 Zone 作为必须遵守的认证 scope，Zone 不可用且没有可复用规则时，返回 MissingDependency(Scope)，不能把 Unknown 当成没有限制。Host 的开放来源搜索可按 policy 继续；已知且仍生效的 blocked 不因搜索失败消失。LocalOnly 和 closed_world 都不借这个 helper 调用 Zone。

### 4.4 显式的发布检查

| 检查 | 要求 | 默认 |
| --- | --- | --- |
| `valid` | 第 4.1 节基本检查及适用 scope 约束 | 恒开 |
| `not_older_than_seen` | 本地基线为 FirstKnown / Same / Newer；Conflict、Older、Unknown 拒绝 | 开 |
| `fresh(max_age)` | 真实权威 NoRecord 或确切 anchor 命中，原 checked_at 在 max_age 内 | 关 |
| `anchored_current(max_age)` | 真实权威 anchor 命中，且在 max_age 内 | 关 |
| `published` | 当前权威 anchor 命中；不宣称历史上曾发布过 | 关 |

以上发布检查只使用有效的真实权威 receipt，不能使用 scope 的局部 NoRecord / anchor 冒充。Record 有绑定但无目标 anchor 时报告 NoAnchor；它不满足上表的发布检查。`fresh` 在 NoRecord 时通过也不保证没有未上链的新版本；防回退来自本地基线。`max_age=0` 明确定义为本次必须实际访问权威，不是允许复用同一秒的旧缓存；缺省 max_age 仍不能超过 receipt 自身的 valid_until。

```python
async def get_required_authority_receipt(did, doc_type, opts, used):
    require_publication_query_allowed(opts.policy, opts.scope)
    # LocalOnly、LocalAndZone、closed_world 等禁止时，立即返回缺材料，不升级来源。
    if not opts.checks.force_current_query():
        receipt = used.reusable_authority_receipt(did, doc_type, opts.checks)
        if receipt is not None:
            return receipt                  # 原始来源、覆盖范围、时间均符合要求
    plan = opts.authority_only_plan(force_query=opts.checks.force_current_query())
    receipt = await get_publish_info(did, plan)
    require_answer_covers_requested_document(receipt, did, doc_type)
    # Unknown / NotConsulted / NotApplicable 都是要求未满足，不能改成 NoRecord。
    require_real_authority_and_freshness(receipt, opts.checks)
    return receipt
```

## 5. 解析与提交：复用同一个验证流程

### 5.1 获取候选后验证

```python
async def resolve_with_options(did, requested_type, opts):
    require_resolvable_did(did)
    if is_info_request(did, requested_type):
        return await resolve_info_contract(did, requested_type, opts.policy)
    rejected = set()
    for attempt in bounded_candidate_attempts():
        answer = await get_document(did, requested_type, opts.sources(), rejected)
        # 先处理回答中已带回的可信拒绝 / 迁移，不额外预取 publish_info。
        raise_if_known_block_or_tombstone(answer, opts.scope)
        if answer.has_trusted_migration():
            return await follow_or_report_migration(did, requested_type, answer, opts)
        body = answer.body
        if body is None:
            body = accepted_stale_body_if_allowed(did, requested_type, opts)
        if body is None:
            return unavailable_report(answer.trace)  # 不继续查 owner 来填报告
        actual_type = require_bound_actual_type(did, requested_type, body)
        report = await verify(did, actual_type, body, opts.with_fetch_evidence(answer))
        if report.accepted:
            if opts.commit:
                return commit(report, opts)         # 使用提交裁决后的结果
            return report
        if body.locked:
            return locked_document_invalid(report)  # 保留锁，禁止换候选
        if report.is_migrated():
            return await follow_or_report_migration(did, actual_type, report, opts)
        if report.is_candidate_specific_rejection() and body.is_supplement_or_observed():
            rejected.add(body.hash)                 # 坏 body 可换；重试次数有限
            continue
        # scope 拒绝、缺 owner 等共同依赖失败，不再找一批同样不能验证的候选。
        return legacy_observed_exit_if_explicitly_allowed(report, body, opts)
    return candidate_attempts_exhausted(rejected)
```

stale 只提供曾具备可信依据且未过硬期限的 body，随后仍走相同 verify。Observed 不参与 stale；Observed 若当前有可信 owner，可以作为普通候选验证并转正。只有旧 `resolve_did_ex` 显式允许观察结果出口且失败仅为缺材料时，才能返回 `ObservedFallback`；accepted 仍为 false，不能建立身份信任。

迁移目标必须来自受信 scope / method 回答，且先处理适用 blocked 和墓碑。`follow_migration=false` 返回目标信息；为 true 时对 target 重新执行获取和验证，保留迁移链，传播来源开关、visited、深度上限并重新检查 current-zone 边界。锁定的旧文档不能通过迁移被替换。`verify_received` 永远只返回原输入的 Migrated 结论。没问到迁移事实时不为了保证“全局当前”额外遍历权威。

### 5.2 受控提交

```python
def commit(report, opts):
    require(report.accepted)
    key = (report.scope, report.did, report.actual_doc_type)
    with local_key_write_guard(key):
        check_hard_deadlines(report, now())
        check_known_local_denials(report)
        relation = compare_to_accepted_baseline(key, report.revision)
        if relation in (Older, Conflict, Unknown):
            return report.rejected_at_commit(relation)
        # 只串行化本地同键合并；不锁远端，不重查 owner，不建立跨来源事务。
        remember_baseline_with_trust_dependencies(key, report)
        if client.enable_cache and report.body_may_be_cached_locally():
            accepted_store.put(key, report.body, report.evidence, report.hard_until)
        return report.with_commit_result(relation)
```

本机 Lock 和 Zone body 不回填本机普通文档缓存；本客户端仍可记录自己在该 scope 已接纳的 revision，这不写入远端 Zone 的管理状态。body 缓存淘汰不抹去普通高水位；临时管理材料到硬期限后，撤掉仅由它支撑的准入和基线，独立可信事实不受影响。

若调用方验证旧文档时关闭了 not_older_than_seen，它可以取得有效性报告，但 commit 仍不能覆盖更高版本。并发 V2 先提交后，V1 不得以 accepted=true 的提交结果返回。返回报告的用途、owner 绑定与依赖必须被保存，客体结果不能通过缓存变成 AuthSubject。

## 6. 动态锁定：把高级准入留在 scope

```python
def lock(scope, key, answer, hard_expires_at=None):
    require_scope_management_permission(scope)
    scope.replace_lock(key, answer, hard_expires_at)
    # 替换的是配置；不会产生 owner 签名，不清除已知墓碑 / 撤销边界。
    # body 锁在 get 和 verify_received 两条路径都生效。

def unlock(scope, key):
    require_scope_management_permission(scope)
    scope.remove_lock(key)
    # 恢复正常来源选择，不清除独立的已接纳高水位。
```

`read_lock` 只读取管理原文，不表示文档合法。Lock 没有软 TTL；可选硬期限到期后保留失效配置并拒绝，不自动回退。SeedTrusted 是有权限的临时信任输入，SeedObserved 是普通候选输入，两者都不具有永久锁定语义。临时依据的副本不能通过重新入缓存延寿。

本机和 Zone 的管理权限分别判断。Zone 内部可以按成员表、管理员封禁或业务状态动态回答；普通账户停用使用 scope blocked，不伪造成 method 永久注销。重新允许由管理面替换 / 删除该规则完成，公网 Active 不覆盖它。

```python
def zone_device_scope_rule(did, doc_type):
    explicit = zone_locks.get((did, doc_type))
    if explicit is not None:
        return explicit                     # 管理者固定 body 或明确阻止
    if zone_policy.strict_membership and doc_type == Device:
        if not zone_members.contains(did):
            return ScopeAnswer(blocked=True)
    return NotApplicable                    # 默认无设备级限制，继续 owner 验签
    # 这是 Zone 服务内的管理规则；RTCP 不读取成员表，也不增加验证分支。
```

scope 更新约束后续认证。存量连接要即时重验或关闭时，由连接管理消费 scope 失效通知或按约定期限重验，仍调用同一个 verify；不要求核心维护全系统连接 / token 依赖图。没有通知和重新查询，就不声称实现即时撤销传播。

## 7. 已有复杂场景怎样变简单

以下均为目标组合；引用的源码和核对稿描述的是迁移前用法。

### 7.1 BNS 名字槽位映射：保留读取规则，去掉默认成员检查

```python
async def bns_get_device_document(did):
    if await registry.has_independent_name(did):
        return await registry.get_document(did, Device)
    parent, slot = split_device_name(did)       # ood1.alice -> alice 的 ood1 槽位
    body = await registry.get_slot(parent, slot)
    require_declared_id_and_type(body, did, Device)
    return body.with_storage_origin(parent, slot)
    # owner 签名由统一 verify 处理；默认不查询 Zone.devices。
```

默认身份发现与显式 Device 查询复用该映射；保留保留字排除和独立登记优先等 BNS 规则。请求身份和存储槽位分别记录，不能改写 JWT 后沿用原签名。若请求发布证明，由 BNS 明确绑定请求 DID、文档类型与该槽位的发布记录，不能从“子名字没有独立登记”推导全局 NoRecord。BNS 内部查询一致性由服务端自行保证，不要求客户端复制依赖图。

若某 Zone 要严格成员准入，在它的查询管理逻辑中对非成员返回 blocked，客户端通过 scope 约束统一执行。Device 与 Owner 未变、仅 Zone 成员表变化时，不推导全局 DID 吊销。依据：[核对 N3](./resolve-did组件与使用模式核对.md#n3-一个解析结果依赖多个身份及登记键映射)。

### 7.2 RTCP：一次默认验证，业务准入后提交

```python
async def admit_rtcp(hello, scope):
    body, device_key = parse_candidate(hello.device_jwt)
    check_hello_bindings_times_and_possession(hello, device_key)
    # 持钥证明在依赖查询前完成；它本身还没有建立逻辑 DID 信任。
    report = await verify_received(hello.did, Device, body, default_options(scope))
    require(report.accepted)
    require(report.device_key == device_key)
    await complete_key_confirmation_and_listener_authorization(hello, report)
    with connection_manager.registration_guard(hello.did):
        committed = commit(report, default_options(scope))
        require(committed.accepted)
        return register_connection(hello, committed)
    # 默认无后台公网确认、确认等级提升或公网否定恢复状态机。
```

连接管理保持已有的并发注册与索引保护，不把网络握手放进 name-client 的本地写锁。默认准入只需可信 owner 签名与版本规则，具体高级身份准入由 scope 的动态锁 / blocked 收紧，listener 保留自己的业务授权。

确实要求公网锚点的部署显式加 anchored_current 检查；结果不满足即拒绝，不再先接入再自动补确认。按 scope 变化重验既有连接是 RTCP 生命周期动作。RTCP 的“旧版本连接应关闭”不能写成 DID Tombstoned。依据：[核对 N4](./resolve-did组件与使用模式核对.md#n4-先按-scope-准入再确认公网结果约束存量连接)。

### 7.3 Boot / LKGS：文档验证和运行版本分开保存

```python
async def boot(node):
    trust = local_activation_trust(node)       # 已激活 owner key，Host closed_world
    candidate = await discover_zone_or_dns_boot(node)
    if candidate is not None:
        report = await verify_received(candidate.did, candidate.type, candidate.body, trust)
        if report.accepted and boot_can_adopt(candidate):
            committed = commit(report, trust)
            if committed.accepted:
                save_operational_state(candidate.body)  # 原 JWT；JSON 仅作运行视图
                return start_from(candidate)
        remember_boot_failure_or_incompatibility(report)
    return boot_recovery_from_lkgs(node)       # Boot 自己决定恢复条件和能力范围
```

LKGS 可以在发现新文档后仍保留旧运行状态，但不能把旧状态反向写成解析当前版本。明确吊销、迁移、过期与网络失败传给 Boot，不压成同一个断网错误。Boot 的维护恢复策略另行规定，不借普通 resolve 的 stale 规则代替。依据：[核对 N1](./resolve-did组件与使用模式核对.md#n1-业务接纳的运行状态boot--lkgs)。

### 7.4 合成 Owner / 控制面投影：生成方负责内容，scope 负责信任

```python
def update_projected_owner(scope, inputs):
    body = deterministic_owner_projection(inputs)
    # 相同输入得到相同字节 / revision；发生实质变化时分配新的 revision。
    # 不能沿用原 JWT 签名；重建时间不能刷新临时信任的硬期限。
    grant = scope.authorize_exact_material(body, deadline=inputs.hard_deadline)
    scope.replace_trusted_material(body.id, Owner, body, grant)
```

生成方管理字段合并和输入依赖；客户端只检查确切输出的 scope 信任、身份、时间和用途。用它验证子文档时仍执行 owner 的签名与时间策略。公网 supplement 入口无权产生同样的管理信任，来源角色由受信接线决定。依据：[核对 N2](./resolve-did组件与使用模式核对.md#n2-控制面投影与字段级信任合成-owner业务状态映射)。

### 7.5 安装与激活：精确内容绑定，显式提出额外要求

```python
async def confirm_publication(did, doc_type, exact_body, opts):
    report = await verify_received(did, doc_type, exact_body,
                                   opts.with_checks(valid, anchored_current(max_age=0)))
    require(report.accepted)                 # 强制本次权威查询并绑定 exact_body
    return report
```

激活的写后读确认使用上面的组合；body 被本机锁命中不能充当公网 receipt。安装仍核对包内内容 ObjectId 与获准 AppDoc 的绑定。rootfs 预装和 LocalDeveloper 使用操作范围内的管理信任材料；临时授权不得泄漏成所有安装任务共享的永久覆盖。需要固定运行期解析时才安装对应 scope Lock。依据：[核对 E1](./resolve-did组件与使用模式核对.md#5-需要明确的延伸边界不宜全部新增为验证模式)。

### 7.6 NDN 路径断言：用 DID 结果验另一个对象

```python
async def verify_path_token(request, token):
    report = await resolve_with_options(zone_did_from_request(request), Zone, default_options())
    require(report.accepted)
    key = require_key_with_scope(report.body, token.kid, ZONE_PUBLISH)
    verify_token_signature_time_host_and_path(token, key, request)
    return verified_path_binding(token.object_id,
                                 hard_until=min(token.exp, report.hard_until))
```

路径 token 的对象身份、重放和映射新旧由 NDN 定义，不能拿 Zone 文档 revision 比较两个 path token，也不写进 Zone 的文档基线。缓存验证材料须遵守实际信任期限；当前 Zone key 能验签不证明路径映射最新。依据：[核对 N6](./resolve-did组件与使用模式核对.md#n6-解析签发者验证另一种对象ndn-路径断言)。

### 7.7 其余边界

| 用法 | 简化后的归属 |
| --- | --- |
| `/identifiers/self`、origin / 父域发现 | 先按发现契约确定环境和候选 DID；正式认证再调用 verify；self 不是全局缓存键 |
| WebSDK 宿主代解析 | 简单展示可取 body；需要认证的桥接接口保留 scope、来源、验证报告，不把 JWT 外形当证明 |
| 地址 / DeviceInfo 发现 | 提供连接地址候选；连接身份单独验证，地址成功不提升 DID 信任 |
| Profile 展示合并、DID Object 结构发现 | 输出展示 / 结构结果，不能回填为已验证身份 |
| S2S 身份 | 完全在本次设计范围外，不增加相应核心接口、依赖或验收要求 |

## 8. 发布状态与负记忆的最小规则

publish_info 多用于显式发布、转移、吊销或注销；普通文档不必上链。下面只规定客户端所依赖的状态含义，发布授权、交易和链上实现属于权威服务。

```python
def publish(state, doc_type, doc):
    require(state.identity != Tombstoned)
    entry = state.entry(doc_type)
    require_newer_than_anchor_and_revocation(doc, entry)
    entry.anchor = revision(doc)              # 初次无 anchor / 撤销边界时按缺席处理
    # 保留已有 revoked_through_iat；新文档不能使已撤销的旧文档复活。

def revoke(state, doc_type, through_iat):
    require(state.identity != Tombstoned)
    old = state.entry(doc_type).revoked_through_iat
    state.entry(doc_type).revoked_through_iat = max_present(old, through_iat)

def tombstone(state):
    state.identity = Tombstoned               # 永久、所有 doc_type 生效
```

撤销按 `candidate.iat <= through_iat` 判断；更大 iat 的文档仍可按 owner 签名通过，是否已发布另看 anchor。客户端已知撤销边界只增不减，NoRecord、Active、TTL 到期都不能擦除；墓碑不能被 Active 翻篇。scope blocked 则由拥有该 scope 的管理者解除，两者不要共用恢复规则。

权威对不同类型的局部 NoRecord 不能清除其他类型的事实。404、5xx 和坏响应不能被统一解释成 NoRecord；协议使用明确的 200 NoRecord，NotApplicable 另行表达。迁移保留可信 target，body 自述无权触发迁移。

## 9. 用场景验证流程，而不只核对枚举

以下是待实现的验收目标；“不查询”也属于结果，测试应记录各来源调用次数。

| 场景 | 预期结果与查询边界 |
| --- | --- |
| body 格式错、id/type 不符、过期 | 立即拒绝；不查询 scope、owner 或公网 |
| 本地已有 V2，收到 V1，默认检查 | 立即 Older；不查询 owner；valid-only 可继续检查有效性 |
| 可信 owner 可用，首次收到合法 Device JWT | 默认通过并可提交；无设备预登记、无成员表查询、无公网发布查询 |
| 公网未问 / Unknown，但可信 owner 与必要 scope 规则可用 | 默认可通过；报告不标 NoRecord / 公网当前 |
| 只有 Observed owner | 缺信任根；不能自签自举或推进任何可信基线 |
| scope blocked，直接 verify_received | 在取 owner 前拒绝；与 resolve 路径一致 |
| scope 锁 V1，直接送来 V2；或者锁 V1 已过期 | 拒绝锁定约束 / LockedDocumentInvalid；不换其他候选 |
| 普通 Zone cache 有 V1，未锁定，收到合法 V2 | 正常比较版本并可接纳；普通 body 回答不隐式变成 pin |
| owner 文档 / 管理证明过硬期限 | 子文档也不能继续使用该材料；stale 不延寿 |
| fresh(60)，有效权威 NoRecord receipt 在 60 秒内 | 通过；scope NoRecord 不能替代；重复调用可复用原 receipt |
| Record Active 有 owner 绑定但无目标 anchor | 报告 NoAnchor；默认可验证，显式发布检查不通过 |
| anchor V2，收到合法 V3 / 同 iat 不同 hash | 分别 NewerThanPublished / DifferentDocument；后者拒绝接纳 |
| 撤销至 iat=100，再收到 99 / 101 | 99 拒绝；101 可按默认规则验签；Active 不擦掉边界 |
| 墓碑后查询从未使用的 doc_type | 仍 Tombstoned；不恢复为 NoRecord |
| body 不可得，仅可信软过期缓存 / 仅 Observed | 前者按 allow_stale 重验；后者没有可信 stale 资格 |
| 两个请求同时验证 V1、V2，V2 先提交 | V1 提交被拒绝；不覆盖 V2；不重建全局快照 |
| 验证期间不同 cache / owner 材料发生更新 | 记录实际依据，不循环重查；下次验证使用更新材料；不宣称原子性 |
| LocalOnly / use_zone_resolver=false / current_zone 边界 | owner、迁移、scope helper 均不扩大范围 |
| closed_world 有可信 owner，输入 body 已给定 | 默认零网络；缺 owner 返回 MissingDependency；显式公网检查不能越界 |
| enable_cache=false / commit=false | 前者禁普通缓存，后者不接纳候选；均不解除已知锁和负事实 |
| 未拿到 body，但回答已带墓碑 / 迁移 | 保留明确拒绝 / 迁移；不额外查 owner 或预取全部发布信息 |
| 成员表移除设备，普通 BNS 解析 / 严格 Zone scope | 普通签名身份不自动吊销；严格 scope 动态 blocked |
| RTCP 正常建连 | 持钥证明、默认 verify、业务授权、commit；无自动公网确认任务 |
| Boot 拒绝运行 V2，继续 LKGS V1 | 运行选择留在 Boot；不倒写解析基线，不把恢复态说成当前有效 |
| 相同输入重建合成 Owner | 内容 / revision 稳定；不重置信任硬期限；不冒充原 JWT |
| 激活确认遇到本机锁；预装与普通安装并发 | 公网证明仍独立取得；管理授权按 scope / 操作隔离 |
| NDN 两个合法 path token 指向不同对象 | 按 NDN 契约处理；不相互覆盖 Zone DID 基线 |

## 10. 实现迁移顺序与收尾

这是目标行为变化，不要求把旧入口的全部内部状态机带入新模型。保留需要的入口返回形式与 policy 访问限制，源码适配点如下：

- [ ] **获取与来源**：[provider.rs](../src/name-client/src/provider.rs)、[name_query.rs](../src/name-client/src/name_query.rs)、[zone_resolver.rs](../src/name-client/src/zone_resolver.rs)。统一回答来源、局部覆盖范围、时间和动态锁标记；owner 复用文档获取；保留完整 policy 传播与默认类型适配。
- [ ] **验证**：[verify.rs](../src/name-client/src/verify.rs)、[verify_context.rs](../src/name-client/src/verify_context.rs)。以第 4 节异步按需流程替代 build_verify_context / 统一 snapshot 的公开组合；同步解析、验签和比较 helper 保留；所有入口验证确切输入并检查 scope 约束。
- [ ] **提交与缓存**：[doc_cache.rs](../src/name-client/src/doc_cache.rs)、[name_client.rs](../src/name-client/src/name_client.rs)。分清候选、接受依据和基线；保留本地同键版本合并及结果裁决；依赖硬期限跟随；Known NoRecord 不删除正缓存，负边界不被新 Active 擦除。
- [ ] **Zone 控制面**：输出显式锁 / blocked / 管理材料，普通 body 回答与锁区分；成员等高级规则在此生成；控制面信任与公网补充源接线分开。
- [ ] **调用者**：BNS 默认设备映射去掉 Zone 成员检查；RTCP 收敛为第 7.2 节；Boot 保留原始 JWT 和独立运行状态；安装、激活、NDN 按第 7 节选择组合；S2S 不纳入本项。
- [ ] **协议与验证**：同步 [HTTP resolver API](./http_did_resolver_api.md)，落实 NoRecord、覆盖范围、真实 receipt、through_iat；为第 9 节建立行为和调用次数断言。权威内部交易 / 发布实现单独安排，不能只改 HTTP bns-server 就宣称链状态机完成。
- [ ] **文档同步**：[简单介绍](./简单介绍resolve-did.md)、[缓存设计](./update-did-cache.md)、[旧验证 TODO](./verify-did-api-boundary-and-freshness-TODO.md)按本稿落地进度标注替代关系；使用核对稿保留历史事实，不把它的旧场景要求误当新冻结结论。

后续 review 只需沿伪代码检查：这一步需要什么可信输入、能否提前退出、最多新增哪些查询、结果是否作用于确切候选、谁负责提交及后续生命周期。缓存后端、wire 字段拼写和 Zone 管理 API 可以独立实现，但不得改变这些行为。
