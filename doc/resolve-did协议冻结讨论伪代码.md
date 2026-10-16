# resolve-did 协议冻结讨论：客户端、验证与作用域覆盖

> 讨论稿，2026-09-11。依据 buckyos-base 当前工作区（HEAD `1ae69b4`）的源码核对。
> 本文不表示协议已经冻结，也不表示下列建议已经实现；不修改现有 API 或运行行为。
> “现状”以实际代码为依据；标为“建议”的接口、字段、分支用于讨论，不是现有 Rust API。

讨论范围是需要信任验证的 DID Document。`Info` 等免验证类型继续走独立契约，不能作为身份凭据；`did:key / did:dev` 仍不能作为这里的解析入口。文档键为 `(did, doc_type)`；身份注销才是整个 DID 的操作。

## 1. 先固定客户端心智模型

```python
# 日常调用：取得本 scope 按来源优先级能看到的有效文档。
# 默认可以联网、读取缓存、回填缓存；不承诺每次访问公网权威。
doc = await client.resolve_did(did, doc_type)

# 从任意来源收到的文档：验证的始终是收到的这些确切字节。
# 不能 resolve 到另一份新文档，再把验证成功算在收到的旧文档头上。
report = verify_received(did, doc_type, received_doc, snapshot, mode=Current)

# 是否把已接受结果保存，是另一个动作。
commit_accepted(report)       # 可选；不调用就不保存该候选
```

“latest”限定在本次选择的 scope 和证据面内：Zone 明确回答时就选 Zone；本机可信缓存命中时可以不访问公网；不会遍历所有来源取最大 `iat`。未验证候选的较大 `iat` 不能推进可信基线，签字权也不能覆盖已发布结果。

验证至少区分以下含义，避免让“旧版本”承担两个不同问题：

| 模式 | 要回答的问题 | 与当前实现的关系 |
| --- | --- | --- |
| `Current`（建议作为业务默认） | 这份文档现在有效，且没有被本次可见的可信最新状态否定吗？ | 现有纯 verify + freshness 检查可组合；需要补齐统一的业务默认门禁 |
| `StillValid`（按需） | 不要求最新，但它现在仍通过有效性检查吗？例如仍受支持的软件旧版本 | 接近 `verify_did_document` + `FreshnessRequirement::AnyValid`；仍检查当前 `exp`、owner 策略和负状态 |
| `AtPublication`（建议新增） | 这份确切文档在有证据的发布时刻是否合法？ | 尚未实现完整历史验证；不能用 `AnyValid` 或历史 key fallback 冒充 |

`RequireAuthorityCurrent` 是 `Current` 的更严格要求：必须取得本次公网权威对确切文档的确认。离线时应失败，不能由本地锁定或 Zone 回答伪造成功。

版本轴沿用现状：`revision = (iat, content_hash)`，`documentVersion = document_iat`；同 `iat` 不同 hash 是冲突。`version_seq / mini_version_seq` 不参与新旧或撤销判断。内容寻址、不可变的命名对象更新时应使用新对象身份，不套用可变名字的原地更新规则。

## 2. 当前实际实现的最小伪代码

以下描述已有行为，省略迁移、Info 和错误包装等细节。


```python
async def resolve_did(did, doc_type):
    return (await resolve_did_ex(did, doc_type, default_policy)).document

async def resolve_did_ex(did, doc_type, policy):
    reject_key_class_did(did)

    if policy.source in [BestAvailable, LocalAndZone] and zone_enabled(policy):
        z = await zone.lookup(did, doc_type)
        if z.answered:                       # 含明确 Missing / Revoked / Tombstoned
            return z.result                  # 不回填本机缓存；优先于本机 override
        # unknown（超时、连接失败、裸 404 等）继续本机路径

    if local_override.exists_and_not_expired(did, doc_type):
        return tagged(local_override.document, LocalAuthorityOverride)

    c = local_cache.lookup(did, doc_type)
    if policy.source != RemoteAuthority:
        if c.negative and c.in_ttl:
            raise Disabled(c.status)
        if c.positive and c.in_ttl:
            if c.evidence in [Published, Verified]:
                if existing_cache_replay_guard_passes(c):
                    return c                 # 不逐次重新完整验签
                remove_cached_document(c)
                c = CacheMiss                # 当前实现会继续尝试后续来源
            if c.evidence == Unverified and policy.source == BestAvailable:
                # 核验这份候选：权威状态 + owner + 签名，成功后 promote
                r = await verify_and_promote(c)
                if r.promoted:
                    return r.document
            # 默认不返回验证不了的观察缓存

    if policy.source in [LocalOnly, LocalAndZone]:
        return trusted_stale_or_error(c, policy)

    r = await resolver_core.authority_then_supplements(did, doc_type, policy)
    if r.negative:
        remember_negative_or_remove_positive(r)
        raise Disabled(r.status)
    if r.resolved:
        block_candidate_if_negative_memory_exists(c, r)
        check_existing_cache_replay_guard(r)
        merge_into_local_cache(r)             # 默认回填；Published > Verified > Unverified
        return r.document
    if c.negative:
        raise Disabled(c.status)
    if r.authority_missing:
        remove_old_positive_cache()
        raise Missing                        # 不能用旧 positive 覆盖明确 Missing
    return trusted_stale_or_error(c, policy)  # RemoteAuthority 禁止 stale

def trusted_stale_or_error(c, policy):
    if c.negative:
        raise Disabled(c.status)             # 负状态 TTL 到期也继续屏蔽兜底
    if policy.source != RemoteAuthority and policy.allow_stale_cache:
        require(c.evidence in [Published, Verified])
        if not c.document.self_expired:
            return tagged(c.document, Fallback)
    raise Unavailable
```

需要保留的现状边界：

- 默认 `BestAvailable`，`allow_stale_cache = true`，`allow_self_signed_when_missing = false`。普通本机缓存 TTL 上限一小时，TTL 到期不是文档失效，也不是删除条目。
- 默认 resolver 在权威 unknown 时不把新补充候选提升为可信结果；可信缓存仍可能兜底。纯 verify 则返回有效性与 freshness 事实，需要调用方应用准入策略，两者不能混为一谈。
- `RemoteAuthority` 跳过 Zone 和普通缓存快路径，但当前代码仍会命中本机 override；因此不能仅看这个选项就宣称拿到了公网权威证明。Owner 依赖还允许按 `for_owner_lookup()` 复用缓存。
- 权威信道取回的 body 在 resolver core 中走 `Anchored` 路径，检查已声明的文档 id 及权威 hash；它没有统一调用纯 verify。不能把“resolve 成功”和“所有返回路径都做过同一套签名、最新性检查”画等号。
- 现有 stale 返回分支主要检查负状态和文档自身 `exp`，没有统一的 Owner 依赖版本重验；上面的 helper 是现状概括，不代表已经实现第 5 节的闭环。

源码：[resolve_did_ex](../src/name-client/src/name_client.rs)、[ResolvePolicy 与 override 存储](../src/name-client/src/provider.rs)、[resolver core](../src/name-client/src/name_query.rs)。

## 3. 任意来源文档：验证与保存分开

先用现有 API 表达调用顺序；A/B 是两种可选路径，purpose 由用途决定，与是否补取材料无关。`accept_current` 是下面建议的应用层 helper。

```python
# A. 已经有可信材料：验证本身同步、无网络、无写入。
report = verify_did_document(expected_did, doc_type, received_doc,
                             snapshot, VerifyOptions(purpose=purpose))
accept_current(report, snapshot)

# B. 需要获取材料：这是显式 resolve 阶段，可能联网和回填解析缓存。
snapshot = await client.build_verify_context(expected_did, doc_type, policy)
report = verify_did_document(expected_did, doc_type, received_doc,
                             snapshot, VerifyOptions(purpose=purpose))
accept_current(report, snapshot)

# 应用完成需要的持钥证明、授权等准入后，才选择保存。
if save_candidate and not report.validity.detached_owner:
    outcome = client.add_verified_cache(expected_did, doc_type, received_doc)
    inspect(outcome)  # 验证成功不意味着写入成功，更不意味着覆盖了原有条目
```

现有 `resolve_and_verify_did_document` 封装 B 的获取与纯验证；`resolve_verify_and_cache_did_document` 再保存候选。**后者没有自动执行 `evaluate_freshness`**，因此不能直接等同于这里的 `Current + 保存`。其保存逻辑在权威 membership 成立时写 `Published`，否则写 `Verified`，并跳过 detached-owner 的客体结果；普通 `add_verified_cache` 只写 `Verified`，调用方不能绕开前述用途限制。

“不更新缓存”还要说清楚范围：纯 `verify_did_document` 完全不写；`resolve_and_verify_*` 不保存收到的候选，但 `build_verify_context` 会记录权威负状态，Owner 解析也可能回填缓存。当前该组合函数上“不写任何 cache”的注释比实际保证更强，讨论时以调用链为准。

建议的 `Current` 门禁如下。它要求“当前可见最新”，不会把“公网没有回答”自动变成“文档非法”，也不会让断网成为新候选的信任来源。

```python
def accept_current(report, snapshot, require_public_current=False):
    # 调用前已完成纯 verify：id/type、expected_owner、签名、exp、valid_iat、负状态。
    require(report.validity_is_valid)
    require_snapshot_dependencies_usable(snapshot)  # 建议补充：期限、Owner 版本和来源

    evaluate_freshness(report, NotOlderThanLocalLatest(snapshot.scope))
    # 上面允许 FirstKnown / Same / Newer，拒绝 Older / Conflict / 基线不可知。

    if snapshot.explicitly_denies_current(received_hash=report.revision.content_hash):
        raise NotCurrent
    # 拒绝权威明确的 Superseded / DifferentDocument 等；不能只检查 local freshness。
    # scope 的 Missing/Expired/Migrated 同样不能按正常 Current 成功；
    # “尚未发布设备”的 bootstrap 准入是单独显式策略，默认关闭。

    if snapshot.authority_unavailable_or_not_consulted:
        require(snapshot.has_accepted_evidence_for_exact_document(report.document)
                or snapshot.has_explicit_scoped_admission(report.document))
        # 新候选只有签名通过、没有发布状态/可信接纳依据时，返回缺证据。

    if require_public_current:
        evaluate_freshness(report, RequireAuthorityCurrent(max_age_secs=policy_age))

    return Accepted(report, scope=snapshot.scope,
                    owner_hash=snapshot.owner_hash,
                    authority_freshness=report.freshness.authority)
```

源码：[纯 verify 与 freshness](../src/name-client/src/verify_context.rs)、[组合 API 与写入](../src/name-client/src/verify.rs)。权限主体使用 `AuthSubject`；软件包等客体可使用 `ObjectDocument`，客体验证成功不能直接当作 RBAC 身份。

## 4. sethost：长期锁定与临时预设分开

`sethost` 只是借用 `/etc/hosts` 语义的沟通术语，不是正式函数名，也不表示存在一个按 scope 路由的统一管理接口。

**本机配置使用 NameClient 的公开函数；Zone 配置使用具体 Zone Resolver 提供的管理接口。** name-client 只消费 Zone 的解析接口，不规定通用的 Zone 写入、锁定或删除函数。某个 Zone Resolver 是否支持这些操作、怎样鉴权和持久化，都由该服务的管理面决定。

```python
# 本机现有 API；这里的 client 是 NameClient 实例。
client.set_local_authority_override(did, doc_type, exact_document,
                                    scope="local-config", expires_at=None)
client.set_local_authority_override(did, doc_type, new_exact_document,
                                    scope="local-config", expires_at=None)
client.clear_local_authority_override(did, doc_type)

# 本机缓存现有 API；其 TTL 是软期限，并非下文建议的预设硬期限。
client.add_observed_cache(did, doc_type, document, source)
client.add_verified_cache(did, doc_type, document)

# Zone 写入：由运维工具调用所部署 Zone Resolver 的实际管理接口。
# 此处不虚构统一函数名，也不能用 scope="zone" 把上面的本机函数变成远程写入。
# 写入后，NameClient 通过普通 resolve 读取 Zone 返回的结果。
```

下文 `Lock / SeedObserved / SeedTrusted` 是讨论中的行为分类，不是三个已有类型或统一 `sethost` API。预设的 `hard_expires_at`、信任证明等是建议语义；具体管理接口能否表达，需分别检查本机实现与所选 Zone Resolver。

| 类型 | 谁可以写 | 使用方式 | 到期与覆盖 |
| --- | --- | --- | --- |
| `Lock` | scope 管理者 | 固定精确文档，明确标注本地控制来源 | 无配置 TTL；只有替换/解锁改变选中文档 |
| `SeedObserved` | 普通发现/投递路径 | 只是候选，使用前必须验证；也可以是 owner 文档 | 硬过期；不能覆盖可信结果或负状态 |
| `SeedTrusted` | 有该 scope 信任写权限的管理者 | 管理者已验证/接纳的材料；可以种入 Owner 信任根 | 硬过期；不伪装为本次公网权威确认，也没有 Lock 的永久覆盖权 |

关键规则：

1. **Owner 候选不能自证信任。** 给 owner 文档加自签名，只证明内部一致；仍需要权威对该确切文档的锚定，或者 scope 管理者显式种入的信任依据。`SeedObserved(owner)` 不能独自完成离线自举。
2. **SeedTrusted 是有权限的信任输入。** 不能接受网络对端在 payload 里自报 `verified=true`。若 child 的 owner 无法解析，管理员可显式接纳该 child，但报告必须标成 `AdminTrusted`，不能谎称本次完成了 Owner 验签；这是第 5 节闭环的显式例外。需要闭环的场景，应同时种入 Owner 文档及必要的 owner 绑定。
3. **硬过期约束要跟随派生结果。** SeedObserved 转正、SeedTrusted 被复制进缓存、用临时 Owner 验过子文档，都必须保留依赖的硬期限；不能靠 promote 或反复读取续命。到期后撤掉配置产生的 owner 绑定、准入依据和临时 latest 基线。独立从权威重新取得的证据可以继续存在。
4. **不同 scope 不自动继承信任。** Owner 递归、读取负状态、比较最新性都必须说明使用的 scope；保存结果必须明确目标存储及其写入权限。Host 的管理权限不能隐式变成 Zone 的管理权限，`add_verified_cache` 不会写入 Zone。

现状与要求的差异：`set_local_authority_override` 已有独立存储、可选过期、不进普通 cache 的行为，但 `scope: String` 只用于记录，索引实际是 `(did, doc_type)`；同一 NameClient 内没有按 scope 隔离。Zone 明确回答优先于它。`add_observed_cache / add_verified_cache` 没有上述配置硬期限和派生依赖机制；普通缓存 TTL 是软期限。

### 锁定与合法性之间需要定案的冲突

“只准替换/解锁改变结果”和“每次返回必须现在合法”在文档过期、Owner 撤销/换 key 时不能无条件同时成立。

本稿建议：**锁定固定候选选择，不能冻结时间和验证规则。** 文档无效时返回 `LockedDocumentInvalid`，保留锁且不回退到其它来源；修复依靠更新 Owner 信任材料、替换锁或解锁。若希望连无效字节也总能读出，应另设管理接口 `read_host_lock`，不能把它当成合法性验证成功。

为满足“本机强制锁定解析结果”，建议把本机 Lock 放在 Zone 查询之前。这是对现有优先级的有意调整，仍待定案。Zone 内部的锁定优先级由该服务定义，不属于这里的 NameClient 本机优先级；公网严格验证仍应独立获取 authority receipt，不能把任一 Lock 变成公网发布证明。

## 5. Owner 闭环与建议的统一主路径

“时刻 T 看到 Owner Document D1，所有子文档都应该是 D1 的签名”，更准确地说是：

> 在同一个 scope 的同一次可信快照里，所有声称由该 Owner 授权的文档，必须通过 D1 当前认可的密钥和策略验证；不能为了让某个子文档通过，再悄悄换成 D0。D1 是策略与公钥材料，不是签名者本身。

D1 可以继续保留历史公钥，所以这个闭环与“正常更新 Owner 不自动撤销旧文档”兼容。若要求只接受 D1 的主 key，相当于采用了更严格的换 key 撤销语义，不能作为无提示的默认变化。

建议给已接受条目增加实际验证依赖，而不只是一个 `Verified` 标记：

本节 `scope.begin_read / transaction / replace_owner` 等是**维护该信任视图的组件内部抽象**，不是 NameClient 操作任意 Zone 的管理函数。在 NameClient 内只能管理自身存储；在 Zone Resolver 内则由该服务自行实现。跨进程的一致快照或版本检查，必须由 Zone 解析协议额外提供证据支持，不能假定客户端持有一个通用的 Zone transaction。

```python
AcceptedEntry = {
    document, revision, evidence, scope,
    expected_owner, owner_document_hash, owner_binding_revision,
    scope_generation, checked_at,
    cache_fresh_until,                  # 软 TTL：到期后是否兜底由策略决定
    trust_hard_until,                   # 文档/临时信任依赖的硬期限，不能 stale 绕过
    admission_kind,                     # OwnerVerified / Anchored / AdminTrusted
}

async def resolve_did(key):             # 建议的统一行为，不是当前函数的逐行转写
    rejected_bodies = set()
    for attempt in bounded_retries:
        view = scope.begin_read()

        # 本机 Lock > Zone 明确回答 > 本机可信条目/预设 > resolver core。
        # Zone 是否、如何在内部实现 Lock，由 Zone 管理面决定。
        # 每层都保留 Missing/Revoked/Tombstoned 与 unknown 的区别。
        selected = await choose_document_or_status(key, view, exclude=rejected_bodies)
        # 普通临时条目过了硬期限即不参与选择；Lock 则保留，交给验证报错。
        # RemoteAuthority 来源可以跳过普通缓存，仍不能暗中解除 Lock。
        # 需要独立公网事实时使用 query_authority，而不是把 Lock 标成 authority。

        if selected.is_effective_negative:
            with scope.commit_if_generation_matches(view) as transaction:
                if not transaction.acquired:
                    continue
                transaction.retain_negative_if_owned_store(selected)
                # 只操作本组件拥有的存储，不反向写 Zone；Zone 回答不回填本机。
                raise selected.status          # 不为负状态继续查询 Owner
        if selected.is_unknown:
            raise Unavailable                  # choose 已尝试允许的可信 stale 兜底

        snapshot = await complete_dependencies(selected, view)
        # 补齐 expected_owner 的材料与 owner 绑定，不从候选自述选择 owner。
        # Owner 的来源选择必须与本 scope 一致；不能主体取 Zone、Owner 私自取 Host。
        # 若补材料期间本 scope 发生了变更，重建快照；重试次数有限。
        if not scope.generation_matches(view):
            continue

        try:
            if selected.is_stale:
                require(policy.allow_stale_cache)
                require(selected.previously_accepted)
            require(now < selected.trust_hard_until)
            # stale 仍走下方验证；软 TTL 到期不能跳过 Owner 闭环。
            accepted = validate_selected(selected, snapshot)
            accepted = accept_current_in_selected_scope(accepted, snapshot)
        except ValidationError as error:
            if selected.is_locked:
                raise LockedDocumentInvalid(error)  # 不更换被锁定的候选
            if selected.is_untrusted_candidate:
                rejected_bodies.add((view.generation, hash(selected.document)))
                continue                       # 一份坏 body 不阻断后续补充源
            raise error

        # 建议：本组件维护的 Owner/scope 视图在验证后又变化时重试。
        # 对远端 Zone 的变化只能依赖服务提供的快照/版本证据，不能当作本地事务。
        with scope.commit_if_generation_matches(view) as transaction:
            if not transaction.acquired:
                continue
            if selected.should_fill_normal_cache:
                transaction.merge_accepted(accepted)
            # Lock 不进普通缓存；Zone 回答保留现状，不自动回填本机。
            return accepted.document
    raise ResolutionAttemptsExhausted          # 附带最后的验证失败/并发变化原因

def validate_selected(selected, snapshot):
    doc = selected.document
    check_id_type_revision_and_exp(doc, selected.key, now)

    if selected.is_owner_document:
        require(snapshot.exact_owner_anchor_or_admin_trust(doc))
        return accepted_owner_root(doc, snapshot)
        # 自签名只能做完整性校验，不是信任根来源。

    owner = snapshot.authority_or_scope_binding.or_structural_owner(selected.did)
    require(owner is not None and doc.declared_owner == owner)

    D1 = snapshot.owner_document(owner)
    if D1 is None:
        if selected.has_authorized_admin_attestation_for_exact_document:
            return accepted(doc, admission_kind=AdminTrusted,
                            owner_chain_verified=False,
                            trust_hard_until=selected.attestation_deadline)
        raise MissingDependency(OwnerDocument(owner))

    require(snapshot.owner_root_is_usable(D1))
    check_owner_valid_iat(D1, doc)       # doc.iat <= D1.valid_iat 时拒绝
    verify_signature(doc, D1.main_key_or_retained_historical_keys)
    check_selected_publication_constraints(doc, snapshot)
    return accepted(doc, admission_kind=OwnerVerified,
                    owner_document_hash=hash(D1),
                    trust_hard_until=min_all_dependency_deadlines(snapshot, doc))
```

这里的 `AdminTrusted` 返回是明确的管理信任例外，并未满足 Owner 签名闭环；要求闭环的调用方应拒绝这种报告。后来 D1 可用时，不能继续走“Owner 缺失”例外，必须按 D1 验证。普通 Lock 只固定选择，不默认提供跳过 Owner 验签的管理员证明。

`check_selected_publication_constraints / accept_current_in_selected_scope` 沿用第 3 节的门禁。显式 Lock 定义本 scope 的选择，可以与公网当前版本不同，但报告必须区分这种覆盖；未锁定的普通候选不得越过当前权威锚点、scope 负状态或已知发布结果。没有新答案时，只能在现有策略允许的范围使用曾被接纳且仍满足依赖检查的缓存。

```python
def on_owner_document_changed(scope, owner, D2):
    with scope.transaction():
        scope.replace_owner(owner, D2)
        scope.advance_generation()
        # 用 expected_owner 反向索引，覆盖 owner != document.id 的子文档。
        scope.mark_dependents_for_revalidation(owner)
        # 标记不等于一律吊销：下次读取按 D2 验证，通过者继续用。

def on_temporary_trust_expired(scope, seed):
    with scope.transaction():
        scope.remove_seed_and_derived_admission(seed)
        scope.advance_generation()
        # 不删除独立权威证据；不把依赖该 seed 的副本留作 stale 兜底。
```

现状缺口：`VerifyContextSnapshot` 已是不可变验证材料，但 `generation` 是构建时的诊断序号，没有提供上述跨条目一致读取和提交检查。缓存未保存 owner hash 依赖；`validate_owner_revocation` 按被查询文档的 DID 查 Owner，`evict_revoked_docs` 也只遍历同 DID 的条目，不能覆盖全部 `expected_owner = alice` 的 `device.alice` 等子文档。`LocalAndZone` 的 Owner 材料读取当前还会先取本机缓存，随后才查 Zone，与主体 Zone 优先的闭环要求有差距。

因此，本节是需要补实现的保证，不能只在现有函数外面加几句注释。快照只要求本 scope 的一致视图；跨公网来源各自的 `checked_at` 仍需记录，不能声称取得了所有权威在同一物理时刻的原子快照。

源码：[snapshot 构建和 Owner 加载](../src/name-client/src/verify.rs)、[缓存撤销检查与清理](../src/name-client/src/doc_cache.rs)。

## 6. Owner 更新后旧文档，以及真正的历史验证

默认规则建议延续现有设计：Owner 的普通资料更新、`iat` 更新、正常 key rotation 本身不级联撤销旧文档。旧文档只要仍能用当前可信 Owner 中认可的 key 验证、未过期、未被 `valid_iat` 或明确撤销否决，就可能通过 `StillValid`；能否通过 `Current` 还要检查最新性。

当前 `get_historical_keys()` 把 `verificationMethod` 中除 `#main_key` 外的 key 作为 fallback，没有实现每把 key 的时间有效区间，也不会自动取得历史 Owner 文档。因此“保留旧 key”不能理解成“该私钥只允许验证轮换前的签发”。`valid_iat` 是文档时间下限，也不能单独证明签名实际发生时间。

真正的 `AtPublication` 必须有历史证据。仅凭候选自己的 `iat`，或者随候选送来一份自签名旧 Owner，不足以证明“当时合法”。建议伪代码：

```python
def verify_at_publication(expected_key, exact_doc, historical_bundle):
    # 证据可以随软件包归档或显式获取；验证本身仍然不联网、不写 cache。
    publication = verify_historical_publication_evidence(historical_bundle)
    require(publication.key == expected_key)
    require(publication.content_hash == hash(exact_doc))
    T = publication.authenticated_publication_time
    # T 是可信发布记录的时间/顺序依据，不直接信任 exact_doc.iat。

    binding_at_T = verify_owner_binding_at(publication, T)
    D_at_T = verify_owner_document_authority_at(historical_bundle, binding_at_T, T)
    state_at_T = verify_subject_and_owner_status_at(historical_bundle, T)
    require(state_at_T.permits_publication)

    check_id_type_revision(exact_doc, expected_key)
    require(exact_doc.owner == binding_at_T.owner)
    check_document_time_at(exact_doc, T)          # 在 T 检查 exp 等，不在 now 检查
    check_owner_policy_at(D_at_T, exact_doc, T)
    verify_signature_at(exact_doc, D_at_T, T)     # 使用有历史依据的授权 key

    return HistoricalReport(document=exact_doc, valid_at=T,
                            usable_as_current_identity=False,
                            current_status=NotEvaluated)

historical = verify_at_publication(key, old_release, archived_evidence)
archive.put(hash(old_release), historical)       # 可选，独立的历史内容存储
# 禁止仅因历史验证成功，就推进普通 resolve 的当前缓存或 latest 基线。
```

本稿建议历史报告只证明历史事实。后来发生吊销、注销，不抹去“此前曾合法发布”的事实，但仍阻止拿它作为现在的身份凭据。软件安装是否还要遵守今日的撤销/支持策略，由安装流程额外检查，不能从 `valid_at=T` 推导“今天仍允许使用”。

这点需要开发者定案：若旧软件只要求“现在仍认可这个旧版本”，应选 `StillValid`，无需引入完整历史索引；若确实要求证明“发布时合法”，历史 owner 绑定、发布锚点、状态和时间证明都是协议能力的一部分。某 method 没有这些材料时返回 `HistoricalEvidenceUnavailable`，不能静默用当前 Owner 得出历史结论。

源码：[历史 key 与 valid_iat](../src/name-lib/src/user.rs)、[当前 verify 的 now/exp 检查](../src/name-client/src/verify_context.rs)。历史公钥 fallback 已实现；上述 `HistoricalReport` 与时间验证入口未实现。

## 7. 无公网环境

“无法访问权威，所以正常 resolve 一定失败、完全依靠 sethost”不符合现状。应区分冷启动与已有信任材料：

| 本地/Zone 情况 | 默认 resolve 的实际或建议结果 |
| --- | --- |
| Zone 有明确答案 | 现状可返回 Zone 结果；无需公网 |
| 有未过 TTL 的 Published/Verified 本机条目 | 现状可命中；不强制本次获取 Owner 或公网 |
| 只有 TTL 已过、文档自身未过期的可信缓存 | 现状在策略允许时可 stale 兜底；闭环方案仍需检查 Owner 与硬期限 |
| 全新机器，无可信缓存/Zone/管理员预设，只有网络发来的候选 | 不能由候选自建信任根，正常可信解析失败 |
| 配置了 Owner 与必要绑定的 Lock/SeedTrusted | 可在指定 scope 内建立离线信任闭环；硬过期和签名策略仍然生效 |
| 明确要求本次公网权威当前证明 | 公网不可达则失败；本地管理配置不能代替此证明 |

```python
# 现有选项：严格零网络；没有可信材料则失败。
policy = ResolvePolicy(source=LocalOnly)

# 现有选项：允许私网/本机 Zone I/O，不访问 method 公网权威。
policy = ResolvePolicy(source=LocalAndZone)

# 本机离线预置：使用现有 API，管理者已在带外验证并接纳这些材料。
# 例：child = did:bns:device.alice，结构默认 owner = did:bns:alice。
client.add_verified_cache(alice, Owner, D1)
client.add_verified_cache(child, Device, device_doc)
doc = await client.resolve_did_ex(child, Device, ResolvePolicy(source=LocalOnly))
# 这只是现有预置路径，不宣称已经具有建议中的硬过期与 Owner 依赖闭环。

# Zone 离线预置：改由所部署 Zone Resolver 的具体管理接口完成。
# NameClient 不负责该写入；客户端随后以 LocalAndZone 或默认策略读取结果。
```

仅在现有 `unverified/` 里放一份 Owner 文档不够：默认 lazy promote 需要权威锚定 Owner。在 `LocalOnly / LocalAndZone` 下，现有 resolve 还不会执行该 lazy promote。现有 `verified/` 写权限和本机 override 能提供管理信任入口，但它们的 scope、硬过期和闭环行为仍以第 4、5 节的缺口为限。

## 8. 身份拥有者的操作：创建/更新、吊销、注销

这些是 method 权威发布面的操作。下列是建议状态机，不是声称 name-client 已实现交易写入接口。Owner 私钥负责签字；操作还须通过 method 的发布权限检查。若 method 允许发布权与签字权分离，仅持有 Owner 私钥不能完成这些状态变更。

```python
# 概念上的权威状态。identity_status 和 retained_revocations 是建议补充。
IdentityState[did] = Active | Tombstoned
DocumentState[did, doc_type] = Missing | Active(revision, hash) | Revoked
RetainedRevocations[did, doc_type] = revoked_through_iat   # 保留此前已撤销版本边界

def publish(did, doc_type, doc, publisher):       # 合并创建/更新
    with authority.transaction():
        require_publish_permission(publisher, did, doc_type)
        require(IdentityState[did] != Tombstoned)
        verify_publishable_with_current_owner(did, doc_type, doc)
        if current_active_hash(did, doc_type) == hash(doc):
            return AlreadyPublished             # 只有仍为 Active 的相同内容才幂等
        require(doc.iat > latest_published_iat_or_minimum(did, doc_type))
        require(doc.iat > RetainedRevocations.get((did, doc_type), minimum))
        # 同 iat 不同 hash 拒绝，已撤销的旧版本不能借“幂等”恢复。
        record_new_active_version_and_advance_authority_seq(did, doc_type, doc)

def revoke(did, doc_type, publisher):
    with authority.transaction():
        require_publish_permission(publisher, did, doc_type)
        require(IdentityState[did] != Tombstoned)
        remember_revoked_through_current_document_iat(did, doc_type)
        DocumentState[did, doc_type] = Revoked
        advance_authority_seq()
        # DID 仍存在；其它 doc_type 不受这次操作影响。

def tombstone(did, publisher):
    with authority.transaction():
        require_identity_deletion_permission(publisher, did)
        IdentityState[did] = Tombstoned          # 建议：永久终态，不可恢复或复用
        advance_authority_seq()
        # 不必删光所有 body，但每个 doc_type 的当前查询都先看身份状态。

def authority_lookup(did, doc_type):
    if IdentityState[did] == Tombstoned:
        return DR(Tombstoned, scope=EntireIdentity)
    return DR(DocumentState.get((did, doc_type), Missing),
              retained_revocations=RetainedRevocations.get((did, doc_type)))
```

建议“吊销后允许发布新版本恢复，但已吊销旧版本不复活”。为此，新的 Active 状态必须保留/提供旧版本撤销证据；只把一个 `Revoked` 标记替换成 `Active` 不够。上面的 `revoked_through_iat` 是讨论字段，不是现有 wire 字段，也不是通过修改 Owner 的全局 `valid_iat` 来实现。这里展示的是已发布文档的撤销；若还要批量撤销从未发布的自签名文档，必须另行明确撤销的 hash 集合或时间边界，不能从“当前发布 iat”推导不存在的范围。

注销后应保留墓碑，不能退回 `Missing`；DID 字符串仍可能格式合法，因此也不是解析语法错误 `InvalidDID`。整个身份的 tombstone 需要在所有 doc_type 前生效。物理删除内容与协议注销分开；历史归档可能继续证明旧事实，但不再证明当前身份有效。

现状已经有 `Revoked / Tombstoned` 和负缓存屏蔽，但公开状态主要是 `(did, doc_type)` 粒度。本机 cache merge 目前允许新的 `Published` 条目替换这两类负状态，没有独立强制“整个 DID 永久注销不可恢复”，也未保存上述跨恢复的撤销边界。因此永久性和恢复规则必须由权威状态机保证，并补齐客户端表示与检查，不能只靠 enum 的名字。

源码：[DocumentStatus / PublishedState](../src/name-client/src/provider.rs)、[负状态与 merge](../src/name-client/src/doc_cache.rs)、[HTTP 状态协议](./http_did_resolver_api.md)。

## 9. 冻结会议需要决定的项目

| 决策 | 本稿建议 | 当前差距 |
| --- | --- | --- |
| 普通调用的默认验证目标 | `Current` = 当前有效 + 选定 scope 已知最新；需要公网最新时显式加严 | resolve 的快路径、Anchored 路径和纯 verify 尚未统一为这套门禁 |
| 旧软件验证语义 | 区分 `StillValid` 和 `AtPublication`；不让历史成功进入当前缓存 | 后者缺历史证据模型与按指定时间验证入口 |
| 本机强制锁定的优先级 | 建议本机 Lock 在 Zone 之前；Zone 内部优先级由服务决定 | 现状 Zone 在本机 override 之前 |
| 锁定后文档失效 | 保留锁、返回错误、不 fallback；读取锁原文用管理接口 | 现状本机 override 直接返回，没有统一有效性检查 |
| scope 的含义与管理入口 | 标明实际信任范围；本机用 NameClient API，Zone 用该服务具体管理 API | override 的 scope 字符串不参与匹配或路由；没有通用 Zone 写入函数 |
| 临时预设到期 | 硬过期，包括派生缓存、临时绑定和准入依据 | 普通 TTL 可 stale；没有依赖期限传播 |
| Owner 闭环 | 按 expected_owner 记录 D1 hash；变化后重验；保留历史 key 可继续认可旧签名 | 缺依赖索引与一致提交；某些路径混合 Host/Zone 材料 |
| Owner 不可达时的可信子文档 | 管理接纳可单独存在，但标注 AdminTrusted；要求闭环时必须种入 Owner | 现有 Verified 条目未记录这一区别和依赖 |
| 吊销后恢复 | 新版本可恢复；保留旧版本撤销边界 | 现有单一负状态可被 Published 替换，缺跨恢复的撤销记录 |
| 注销范围和永久性 | 整个 DID、所有类型、不可恢复/复用；保留墓碑 | 现有表示主要按文档键，负缓存未区分恢复权限 |

## 10. 用于讨论和后续验收的例子

这些是验收场景，不表示本次已新增或运行相应测试。

| 场景 | 应讨论/验证的预期 |
| --- | --- |
| 已知 V2，收到签名正确的 V1 | `Current` 拒绝；`StillValid` 在未过期/撤销时可通过；不回滚当前缓存 |
| 同 iat，不同 hash | 冲突，不能靠来源到达顺序静默选成最新 |
| 验证 received V1 时 resolve 得到 V2 | 对 V1 作判断，不能把 V2 验证成功当作 V1 成功 |
| 验证通过但不保存 | 候选不进入缓存；若选择组合 resolve，依赖回填副作用单独说明 |
| Zone 返回 V2，本机锁定 V1 | 按建议选 V1，并按 scope Owner 验证；公网当前检查仍可否定 V1 |
| 本机 override 的 scope 字符串填成 zone | 仍只写本机实例，不能影响 Zone Resolver 或其它客户端 |
| 锁定 V1 后 V1 过期或 Owner 不再认可其 key | 保留锁、返回 LockedDocumentInvalid，不自动换成 V2 |
| SeedObserved 恰好是 Owner | 没有独立锚定或管理员信任时不能自举；自签正确也不够 |
| SeedTrusted 为子文档但缺 Owner | 仅能以显式管理接纳返回，不能报告已完成 Owner 闭环 |
| 临时 Owner 种子到期，子文档仍在软 TTL 内 | 若子文档只依赖该种子则不能返回；有独立可信材料时可重验 |
| Owner 从 D1 更新到 D2，D2 保留旧 key | 子文档按 D2 重验，通过则继续有效；不因 Owner 的新 iat 自动撤销 |
| D2 删除旧 key 或提高 valid_iat | 所有依赖该 Owner 的子文档受新策略约束，包括不同 DID 的缓存 |
| 验证中 Owner 更新，或者 Zone/Host 视图不一致 | 不混用材料完成闭环；重建快照或明确返回缺证据/并发变化 |
| 无公网但已有可信缓存/Zone | 按 source、软 TTL 与硬期限策略工作，不必然失败 |
| 冷启动离线只有不可信候选 | 缺少信任根，失败；需要 scope 管理者提供信任材料 |
| 曾收到 Revoked，随后权威断网 | 负状态继续阻止旧缓存和新候选兜底，不能因 TTL 到期复活 |
| 吊销 V1 后发布 V2 | V2 可恢复；V1 仍不能作为现在有效的文档；历史发布事实另行验证 |
| 整个 DID 被注销，再查询未用过的 doc_type | 仍返回 Tombstoned，不能返回 Missing 放开自签名准入 |
| 老软件已经过期，但具备当时的完整发布证据 | `AtPublication` 可证明历史事实；不能据此登录或推进当前缓存 |
