# resolve_did 简介：核心设计意图

本文是教程：用一段伪代码和几条约定，讲清 `resolve_did` 的核心设计意图。它刻意省略了大量工程边界；完整设计（W3C 术语对齐、接口定义、状态机全集、可达性敏感文档的安全发布等）见 [resolve_did重构.md](./resolve_did重构.md)，基础设施愿景见 [resolve-did.md](./resolve-did.md)。

## 1. resolve_did 在解决什么问题

`resolve_did(did, doc_type)`：给定一个名字和一种内容类型，返回一份**可信的文档**。

它同时承担两个传统角色的替代：

- 取代 DNS：解析寻址（名字 → 配置、地址）；
- 取代 CA：文档验证的信任根（不再依赖证书链）。

解析单元是 `(did, doc_type)` 而不是 DID：同一个名字可以发布多种类型的内容——一个 `alice` 可以既是网站、又是 Zone、又是一个用户身份。名字的权益靠新增 doc_type 扩展，信用积累在名字上。

理解整个设计，只需要先分清**两种权力**：

- **签字权（构造文档）**：持有 owner key，能签出内容合法的文档，证明"这份内容是 owner 授权的"；
- **发布权（发布文档）**：能把文档写进该 DID method 的权威发布渠道（对 BNS 就是合约交易权限），证明"这是当前公开生效的版本"。

**发布权 ≥ 签字权**：一份签名合法但未发布的文档，不能覆盖已发布的结果。整个解析流程的骨架都围绕这条不变量搭建（第 4 节）。

## 2. 读懂主循环需要的四个约定

### 2.1 结果二分法：DR 与 unknown

provider 的返回值只分两档：

- **DR（Document Result）**：得到了回答。发布状态（`Active / Missing / Revoked / Tombstoned …`）是 DR 的一部分——body 归 body、状态归状态，但它们属于同一个结果；
- **unknown**：没有得到回答（断网、超时）。

界线画在**"有没有得到回答"**，而不是"有没有拿到文档"。特别地，Missing 是权威源给出的回答（"这个名字从未发布过这种文档"），属于 DR，不是 unknown。必须这样分，是因为两档的合法兜底恰好相反：

- Missing → 自签名候选是正路（典型场景：新设备还没上链），"已发布"缓存反而与权威答复矛盾；
- unknown → 已验证缓存是正路，此时若接受自签名候选，等于"谁能断你的网，谁就能给你塞文档"。

### 2.2 provider 是内核模型：一个权威渠道 + 少数补充源

provider 不是应用可扩展的组件——这套机制用来扩展 DID method，不是让 App 注册自己的 provider。由此：

- 所有 provider 都是内核实现。**可信的是"它如实转述了从哪条信道查到了什么"**；内容本身可不可信，仍由 need_proof / verify 判定；
- 每个 DID method **至多一个权威发布渠道**（发布状态的定义权、写入点唯一）。只有权威 provider 会返回发布状态和 doc_hash；补充 provider 永远只返回候选文档。唯一的是"发布渠道"，不是"能读到权威数据的节点数"——委托读取端（镜像、网关）属于同一渠道；
- 一个 method 的 provider 是精心设计的少数几个、按优先级排列。主动查询 first-win，没有读放大；如果低优先级 provider 拿到了比高优先级更新的结果，通常说明哪里配置错了（值得打警告）。

真正的"多来源"不在查询路径上，在 Cache 层（第 5 节）。

### 2.3 need_proof：英雄不问出处，但要验证

DID Document JWT 化之后，一份文档从哪儿拿到都行——但 provider 必须诚实标注它的出处：

- 从权威 / 锚定信道拿到的结果：`need_proof = false`；
- 从其它任何信道拿到的结果：`need_proof = true`，交给上层验证。

need_proof 按**取回信道**和 doc_type 契约打标，永远不看 body 长相——不能因为拿回来的东西没有签名字段，就降级成"不需要验证"。免验证的 Info 类 doc_type（如设备实时信息）也是按契约事先声明的，不是验证失败后的退化。

验证本身很简单，三个条件：

```text
verify(result, doc_hash, owner_doc) =
      hash 匹配（权威源锚定了 hash 时）
    ∧ iat 时刻的 owner key 验签
    ∧ owner 策略检查（revoke_before_iat 等）
```

### 2.4 owner 是递归基

任何需要验证的文档都要回答"用什么验证它"——答案是它 owner 的文档，于是递归调用 `resolve_did(owner, "owner")`。递归靠一条约定终止：

> **owner 文档只有权威 provider 会返回，且 need_proof = false。**

所以 owner 解析不需要独立分支：它走同一个主循环，第二层递归天然不会发生。owner config 的可信度来自"发布动作 + 可认证的权威信道"，而不是签名。要不要给 owner config 签名是可选项，判据是**传播路径**：只要它需要走不可信路径（push、中继、跨节点共享），签名就是它离开权威信道的唯一通行证。did:key / did:dev 是特例——权威就是 DID 自带的自证 key，owner 文档天然自签。

## 3. 主循环：一条路径 + 四个策略点

策略只来自两处：**权威源返回的发布状态**和 **owner_config**（没有 owner_config 时用系统默认）。整个流程里策略恰好有四个使用点，都标在注释里。

```python
def resolve_did(did, doc_type):
    # ---- 0. 缓存快路径 ----
    cached = did_cache.lookup(did, doc_type)
    if cached.is_local_override:      # 开发/测试期的唯一旁路，hosts 语义（第 7 节）
        return cached
    if cached.in_ttl:
        # 负状态也是缓存条目：命中“已吊销”返回的是错误，不是“查不到”
        return cached if cached.is_positive() else error(cached.status)

    # ---- 1. 查询：一个权威渠道 + 少数补充源，first-win ----
    # 每个 method 至多一个权威发布渠道，永远第一；status / doc_hash 只可能来自它。
    # 没有权威渠道的 method（did:key / did:dev）列表里全是补充源，
    # 状态门禁全程不触发，自然退化成“自签名候选 + 自证 key 验证”（第 6 节）。
    authority, supplements = get_authority(did.method), get_supplements(did.method)

    doc_hash = None
    for provider in ([authority] if authority else []) + supplements:
        result = provider.resolve(did, doc_type)

        # 二分法：unknown = 没得到回答（断网/超时）；其余都是 DR，发布状态是 DR 的一部分
        if result.is_unknown():
            continue

        if result.status in (REVOKED, TOMBSTONED):
            # 策略点①：负状态终止查询，删掉 positive cache，并缓存负状态本身
            did_cache.replace_with_negative(did, doc_type, result)
            return error(result.status)

        if result.status == MISSING:
            # 策略点②：权威源明确回答“从未发布”。
            # 自签名候选是否有入场资格由策略决定（例：新设备还没上链 → 允许）
            if not policy.allow_self_signed_when_missing(doc_type):
                return error(MISSING)
            continue

        if result.is_hash_only():
            # 权威源 Active 但只锚定了 hash，body 由后续 provider 提供
            doc_hash = result.doc_hash
            continue

        if result.need_proof:  # 由 provider 按“取回信道”打标，与 body 长相无关
            owner_doc = resolve_did(result.owner, "owner")
            # owner 约定：只有权威 provider 返回、need_proof=false → 递归到此自然终止

            if owner_doc.is_unknown():
                # 策略点③：“验证不了”≠“验证失败”，接不接受未验证结果由策略决定
                if not policy.allow_unproof(doc_type):
                    continue
                did_cache.update(did, doc_type, unproof(result))
                return unproof(result)
            elif owner_doc.is_error():
                continue  # owner 被权威源否定（吊销/不存在）：这份文档直接作废

            # verify = hash 匹配(若有) ∧ iat 时刻 owner key 验签 ∧ owner 策略(revoke_before_iat)
            if not verify(result, doc_hash, owner_doc):
                continue  # 只丢弃这一份 body，不让一份坏结果终止整个解析

        did_cache.update(did, doc_type, result)
        return result

    # ---- 2. 查询没有产出可用文档（全 unknown，或只拿到 hash 却取不到 body）----
    # 策略点④：是否允许用“过期但未作废”的缓存兜底。
    # （若手里有 doc_hash 且 cached 与之匹配，这次兜底其实是精确命中而非降级）
    if cached.not_exp() and policy.allow_stale_cache(doc_type):
        return cached
    return unknown
```

四个策略点展开：

- **①（负状态）** 吊销是终态：停止查询、删掉 positive cache、把负状态本身缓存下来。之后任何 fallback——过期缓存、自签名候选——都会被它屏蔽；
- **②（Missing）** 只有权威源明确回答"从未发布"，自签名候选才有入场资格，是否放行由策略决定；
- **③（unproof）** "验证不了"（owner 解析 unknown）不等于"验证失败"。策略允许时可以返回**明确打标**的未验证结果，并存入缓存的未验证档；
- **④（过期缓存）** 一个回答都没拿到时，才轮到"过期但未作废"的缓存兜底。

## 4. 不变量：签字权 ≠ 发布权

第 1 节的不变量，展开成两条可执行的逻辑：

1. 一旦某 method 的权威源生效，且该名字在权威源上**不是 Missing**；
2. 那么只要权威源不更新，即使你持有 owner key 的签字权，没有发布权也无法产生**已发布级**的可验证结果。

它在代码里有三个执行点：

- **hash 锚定**（主循环）：Active 时只有属于已发布集合的 body 验得过；
- **Missing 门**（策略点②）：自签名候选只有在权威源明确回答"从未发布"时才有入场资格；
- **证据等级**（Cache 合并，第 5 节）：owner 新签的 JWT 永远压不过已发布条目。

精确表述是：没有发布权的文档，最多以**明确打标的降级候选**存在（缓存第二档），永远压不过已发布结果；而且只要本地还记得"这个名字有已发布状态"，它连降级出场的机会都没有——只有既连不上权威源、又没有任何发布状态记忆、策略又放行时，它才会以 unproof 标记露面。

推论：正常路径被完全锁死之后，开发期想在不动权威源的前提下让新文档生效，唯一的缝隙是查询最前端的缓存短路——见第 7 节。

## 5. "英雄不问出处"发生在 Cache 层

主动查询是高度可控的（少数精选 provider、first-win）。真正的多来源在这里：

- 别人 push 给你一个 JWT；
- 通过社交网络拿到一份 DID Document；
- 主循环自己解析出的结果。

它们统一从 `did_cache.update` 进入，合并时才做比较：

```python
def did_cache_update(did, doc_type, incoming):
    current = did_cache.get(did, doc_type)

    if current.is_local_override or current.is_negative():
        return REJECT  # 本地覆盖与负状态屏蔽一切合并写入；吊销只被权威源的新状态翻篇

    # 先比证据等级，同级才比新旧：已发布/已锚定 > 已验证的自签名 > 未验证。
    # 只比 iat 的话，任何人 push 一个更新的自签名 JWT 就能顶掉已发布结果。
    if incoming.rank > current.rank:
        did_cache.write(did, doc_type, incoming)
    elif incoming.rank == current.rank and incoming.iat > current.iat:
        did_cache.write(did, doc_type, incoming)
    else:
        return REJECT
```

两条规则：

1. **先比证据等级，同级才比 iat / version**。等级从高到低：已发布/已锚定 > 已验证的自签名 > 未验证；
2. **负状态与本地覆盖屏蔽一切写入**，吊销只能被权威源的新状态翻篇。

由此也能理解主循环开头的快路径：**进入解析流程，就意味着缓存已经失效**。唯一的例外是负状态——TTL 过期不代表"已吊销"作废，所以快路径命中负状态时返回的是错误，不是"没命中"。

## 6. 发布状态是权威源的记忆（可选能力）

发布状态的本质，是权威源对**"什么被发布过"的记忆**：一个能做成员判断的集合（某个 hash / 版本是否属于已发布版本），"当前指针"只是这个集合上的一个约定。这一下解释了三件事：

- 合约类权威源（BNS）天然支持——事件日志就是历史；
- 它不是强制能力——不是每种发布渠道都有记忆；
- owner-at-iat 校验、previousVersion 回滚这类高级能力，只有有历史的 method 才做得到。

各类 method 的退化梯子：

| method 类型 | 权威源能力 | 解析行为 |
| --- | --- | --- |
| did:bns（合约） | 完整状态 + 已发布版本集合 | 完整流程：状态门禁 + hash 锚定 + 历史校验 |
| did:web 类（canonical endpoint） | 只有"当前内容"，无历史、无强负状态 | 只有 Missing / Active 两态；历史校验退化为"用当前 owner 或拒绝" |
| did:key / did:dev（生成式） | 无发布渠道，权威 = 自证 key | 状态门禁全程不触发；一切都是自签名候选，验签 + iat 仲裁 |

主循环对"没有发布状态的 method"是**自动退化**的，不需要加分支：三个状态门禁只在权威源真的返回状态时才触发。但代价要诚实写出来：**没有发布状态 ⇒ 没有吊销能力**。生成式 DID 的 key 泄露后无处声明作废——这是选 method 时的权衡，也是 BNS 作为 BuckyOS 核心三件套之一存在的理由。

## 7. 开发期旁路：本地覆盖（hosts 语义）

第 4 节锁死了所有正常路径，于是开发/测试期只剩一种办法模拟"已发布"：**手工往 did_cache 写入条目，让查询在最前端短路**。它等价于传统系统的 hosts 文件。因为它短路在权威查询之前、连 REVOKED 都盖得住，三条纪律不可省：

1. **显式打标**：解析结果必须带 LocalOverride 警告，日志和 UI 可识别；
2. **带 scope**：machine / test-env / CI，只能由本地管理员或测试框架写入；
3. **不参与合并与导出**：cache merge 对它拒写，它也永远不进普通缓存、不向外同步。

测试通过后，再执行真正的发布（上链或写入权威渠道）。

## 8. 速查：不能破的规则

1. 吊销之后不允许任何 fallback——负状态要缓存、要屏蔽后续写入，它是"回答"，不是"查不到"；
2. unknown 和 Missing 不能混——界线是"有没有得到回答"，网络错误不能伪装成"从未发布"；
3. 未发布的自签名文档压不过已发布结果——查询路径靠 hash 锚定和 Missing 门，Cache 层靠证据等级；
4. need_proof 按信道和 doc_type 契约打标，永远不看 body 长相；
5. owner 不要写成独立流程——它只是"need_proof = false 的权威结果"，递归自然终止；
6. 一份坏 body 只作废它自己（continue），不终止整个解析；
7. 本地覆盖必须打标、带 scope、不合并不导出。
