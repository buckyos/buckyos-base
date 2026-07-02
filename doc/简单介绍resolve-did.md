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

## 2. 读懂主循环需要的五个约定

### 2.1 结果二分法：DR 与 unknown

provider 的返回值只分两档：

- **DR（Document Result）**：得到了回答。发布状态（`Active / Missing / Revoked / Tombstoned …`）是 DR 的一部分——body 归 body、状态归状态，但它们属于同一个结果；
- **unknown**：没有得到回答（断网、超时）。

界线画在**"有没有得到回答"**，而不是"有没有拿到文档"。特别地，Missing 是权威源给出的回答（"这个名字从未发布过这种文档"），属于 DR，不是 unknown。必须这样分，是因为两档的合法兜底恰好相反：

- Missing → 自签名候选是正路（典型场景：新设备还没上链），"已发布"缓存反而与权威答复矛盾；
- unknown → 已验证缓存是正路，此时若接受自签名候选，等于"谁能断你的网，谁就能给你塞文档"——所以权威源没回答时，候选没有"已验证"的资格，最多按策略点③以明确打标的结果露面（默认拒绝）。

### 2.2 provider 是内核模型：一个权威渠道 + 少数补充源

provider 不是应用可扩展的组件——这套机制用来扩展 DID method，不是让 App 注册自己的 provider。由此：

- 所有 provider 都是内核实现。**可信的是"它如实转述了从哪条信道查到了什么"**；内容本身可不可信，仍由 need_proof / verify 判定；
- 每个 DID method **至多一个权威发布渠道**（发布状态的定义权、写入点唯一）。权威 provider 回答两类问题：**这份 doc 发布过吗**（发布状态 + doc_hash），以及**这个名字的 owner 是谁**（owner 绑定，可以不带文档单独返回）；补充 provider 永远只返回候选文档，给不出这两类回答。唯一的是"发布渠道"，不是"能读到权威数据的节点数"——委托读取端（镜像、网关）属于同一渠道；
- 一个 method 的 provider 是精心设计的少数几个、按优先级排列。主动查询 first-win，没有读放大；如果低优先级 provider 拿到了比高优先级更新的结果，通常说明哪里配置错了（值得打警告）。

真正的"多来源"不在查询路径上，在 Cache 层（第 5 节）。

### 2.3 need_proof：英雄不问出处，但要验证

DID Document JWT 化之后，一份文档从哪儿拿到都行——但 provider 必须诚实标注它的出处：

- 从权威 / 锚定信道拿到的结果：`need_proof = false`；
- 从其它任何信道拿到的结果：`need_proof = true`，交给上层验证。

need_proof 按**取回信道**和 doc_type 契约打标，永远不看 body 长相——不能因为拿回来的东西没有签名字段，就降级成"不需要验证"。免验证的 Info 类 doc_type（如设备实时信息）也是按契约事先声明的，不是验证失败后的退化。

验证本身很简单，四个条件：

```text
verify(result, doc_hash, expected_owner, owner_doc) =
      doc.id == did ∧ doc.owner == expected_owner
    ∧ hash 匹配（权威源锚定了 hash 时）
    ∧ iat 时刻的 owner key 验签
    ∧ owner 策略检查（revoke_before_iat 等）
```

第一行容易被漏掉：文档的自述（我是谁、我归谁）必须与从候选文档**之外**得到的约束一致。expected_owner 从哪来，是下一节的主题。

### 2.4 expected_owner：owner 绑定不由文档自证

验签要用 owner 的 key——那 owner 是谁？**不能问候选文档自己**。候选文档里的 `owner` 字段只是声明：如果直接拿它当验签依据，攻击者伪造一份文档、把 owner 写成自己、再用自己的 key 签名，验证就会“通过”——你验的是攻击者自己指定的 owner（完整攻击链见第 4 节）。

expected_owner 必须来自候选文档**之外**，来源只有两个，按优先级：

1. **权威源的 owner 绑定**（2.2 节的第二类回答）：给定名字回答 owner 是谁，可以不带文档本体。owner 变更和委托只能在这里发布生效；
2. **名字结构的确定性约束**（method 定义的默认值）：二级名字天然自带 owner 假设——`did:bns:app1.alice` 的 expected_owner 就是 `did:bns:alice`，`app1.alice` 不能自称归 mallory 所有；自证 DID（did:key / did:dev）的 owner 结构性地等于名字自身。

拿到之后只做一个检查：`doc.owner == expected_owner`，不一致直接作废——这是强攻击信号，值得打警告。

一级名字（`did:bns:alice`）是根，从结构里推不出 owner，绑定**只能**来自权威源。于是权威源给不出绑定时（不可达，或名字根本未注册），这个名字的候选文档**直接出局**——连以未验证结果露面的资格都没有，唯一的出路是已验证缓存兜底。绝不拿候选文档自己声明的 owner 顶上。

### 2.5 owner 是递归基

任何需要验证的文档都要回答"用什么验证它"——答案是 expected_owner（上一节）的 owner 文档，于是递归调用 `resolve_did(expected_owner, "owner")`。递归靠一条约定终止：

> **owner 文档只有权威 provider 会返回，且 need_proof = false。**

所以 owner 解析不需要独立分支：它走同一个主循环，第二层递归天然不会发生。owner config 的可信度来自"发布动作 + 可认证的权威信道"，而不是签名。要不要给 owner config 签名是可选项，判据是**传播路径**：只要它需要走不可信路径（push、中继、跨节点共享），签名就是它离开权威信道的唯一通行证。did:key / did:dev 是特例——权威就是 DID 自带的自证 key：owner 文档不需要发布、从名字即可直接构造，天然自签；其余 doc_type 没有权威级结果，一律是自签名候选（第 6 节）。

## 3. 主循环：一条路径 + 四个策略点

策略只来自两处：**权威源返回的发布状态**和 **owner_config**（没有 owner_config 时用系统默认）。整个流程里策略恰好有四个使用点，都标在注释里。expected_owner 与候选入场门禁不是策略，是约束——它们决定"用谁验、有没有资格"，没有裁量空间。

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
    # 每个 method 至多一个权威发布渠道，永远第一；status / doc_hash / owner 绑定只可能来自它。
    # 没有权威渠道的 method（did:key / did:dev）列表里全是补充源，
    # 状态门禁全程不触发，自然退化成“自签名候选 + 自证 key 验证”（第 6 节）。
    authority, supplements = get_authority(did.method), get_supplements(did.method)

    # expected_owner 先取名字结构的默认值（2.4 节）：
    # did:bns:app1.alice → did:bns:alice；did:key / did:dev → 名字自身；
    # 一级名字（did:bns:alice）从结构推不出 → None，绑定只能等权威源回答
    doc_hash, expected_owner = None, structural_owner(did)
    authority_unknown = False  # 权威渠道存在却没回答？没有权威渠道的 method 永远 False

    for provider in ([authority] if authority else []) + supplements:
        result = provider.resolve(did, doc_type)

        # 二分法：unknown = 没得到回答（断网/超时）；其余都是 DR，发布状态是 DR 的一部分。
        # 权威源没回答要记下来：候选的“已验证”资格取决于它（2.1 节 → 策略点③）
        if result.is_unknown():
            authority_unknown |= (provider is authority)
            continue

        # 权威源的回答可以携带 owner 绑定（不必带文档本体），并覆盖结构默认值——
        # owner 变更 / 委托只有这条路生效，候选文档说了不算（2.4 节）。
        # Missing 的回答同样可以带绑定（名字已注册、该 doc_type 未发布）
        if provider is authority and result.owner_binding:
            expected_owner = result.owner_binding

        if result.status in (REVOKED, TOMBSTONED):
            # 策略点①：负状态终止查询，删掉 positive cache，并缓存负状态本身
            did_cache.replace_with_negative(did, doc_type, result)
            return error(result.status)

        if result.status == MISSING:
            # 策略点②：权威源明确回答“从未发布”。
            # 自签名候选是否有入场资格由策略决定（例：新设备还没上链 → 允许）
            # 注意：Missing 只发放入场券，不豁免下方的 expected_owner 一致性检查
            if not policy.allow_self_signed_when_missing(doc_type):
                return error(MISSING)
            continue

        if result.is_anchor_only():
            # 权威源 Active 但只带锚点（doc_hash / owner 绑定），body 由后续 provider 提供
            doc_hash = result.doc_hash
            continue

        if result.need_proof:  # 由 provider 按“取回信道”打标，与 body 长相无关
            # 硬规则（2.4 节）：验签用的 owner 绝不由候选文档单方面决定；
            # 推不出 expected_owner 的候选直接出局，连降级露面的资格都没有
            if expected_owner is None:
                continue
            if result.owner != expected_owner:
                continue  # owner 冒充，或未经权威源发布的 owner 变更：作废并打警告

            owner_doc = resolve_did(expected_owner, "owner")
            # owner 约定：只有权威 provider 返回、need_proof=false → 递归到此自然终止

            if owner_doc.is_error():
                continue  # owner 被权威源否定（吊销/不存在）：这份文档直接作废
            if not owner_doc.is_unknown() and not verify(result, doc_hash, expected_owner, owner_doc):
                # verify = id/owner 一致 ∧ hash 匹配(若有) ∧ iat 时刻 owner key 验签 ∧ owner 策略(revoke_before_iat)
                continue  # 验签失败只作废这一份 body，不让一份坏结果终止整个解析

            if authority_unknown or owner_doc.is_unknown():
                # 策略点③：两种“验证不了”都落在这里，它不等于“验证失败”——
                #   权威源没回答 → 发布状态验证不了（就算验签通过，也可能正顶掉已发布甚至已吊销的结果）；
                #   owner config 拿不到 → 签名验证不了。
                # 结果最多以明确打标的 unproof 露面；本地还有任何记忆（已发布/已验证/负状态）时，
                # 连露面资格都没有——把裁决留给结尾的负状态屏蔽与策略点④（第 4 节的记忆规则）
                if not cached.is_empty() or not policy.allow_unproof(doc_type):
                    continue
                did_cache.update(did, doc_type, unproof(result))
                return unproof(result)

        did_cache.update(did, doc_type, result)
        return result

    # ---- 2. 查询没有产出可核实的文档（权威源没回答、候选被作废或无资格露面）----
    # 负状态记忆屏蔽一切兜底，且不受 TTL 约束：过期的“已吊销”也只能被权威源的新回答翻篇
    if cached.is_negative():
        return error(cached.status)
    # 策略点④：是否允许用“过期但未作废”的缓存兜底。
    # （若手里有 doc_hash 且 cached 与之匹配，这次兜底其实是精确命中而非降级）
    if cached.not_exp() and policy.allow_stale_cache(doc_type):
        return cached
    return unknown
```

四个策略点展开：

- **①（负状态）** 吊销是终态：停止查询、删掉 positive cache、把负状态本身缓存下来。之后任何 fallback——过期缓存、自签名候选——都会被它屏蔽；
- **②（Missing）** 只有权威源明确回答“从未发布”，自签名候选才有入场资格，是否放行由策略决定；入场的候选不豁免 expected_owner 一致性与验签；
- **③（unproof）** “验证不了”不等于“验证失败”。两种情况都算验证不了：权威源没回答（发布状态验证不了——就算验签通过，也可能正顶掉一份已发布甚至已吊销的结果），和 owner config 拿不到（签名验证不了）。策略允许时可以返回**明确打标**的未验证结果，并存入缓存的未验证档；但它只在本地毫无记忆时才有露面资格（第 4 节的记忆规则），敏感 doc_type 默认也应当拒绝——权威源没回答时的正路永远是缓存兜底，绝不是相信候选文档；
- **④（过期缓存）** 查询没有产出可核实的结果时，才轮到"过期但未作废"的缓存兜底；负状态记忆排在它前面，且不受 TTL 约束。

## 4. 不变量：签字权 ≠ 发布权

第 1 节的不变量，展开成两条可执行的逻辑：

1. 一旦某 method 的权威源生效，且该名字在权威源上**不是 Missing**；
2. 那么只要权威源不更新，即使你持有 owner key 的签字权，没有发布权也无法产生**已发布级**的可验证结果。

它在代码里有三个执行点：

- **hash 锚定**（主循环）：Active 时只有属于已发布集合的 body 验得过；
- **Missing 门**（策略点②）：自签名候选只有在权威源明确回答"从未发布"时才有入场资格；
- **证据等级**（Cache 合并，第 5 节）：owner 新签的 JWT 永远压不过已发布条目。

精确表述是：没有发布权的文档，最多以**明确打标的降级候选**存在（缓存第二档），永远压不过已发布结果；而且只要本地还记得"这个名字有已发布状态"，它连降级出场的机会都没有——只有既连不上权威源、又没有任何发布状态记忆、策略又放行时，它才会以 unproof 标记露面。

**同一条不变量还堵住一个更隐蔽的洞：owner 冒充。** 候选文档里的 `owner` 字段是签字权范畴的产物——任何人都能签出一份“我归 X 所有”的文档；而“这个名字归谁”是发布权范畴的事实。拿文档自己的声明当验签依据，等于让签字权越过发布权：

```text
用户输入 did:web:app.example.com
    ↓  不可信链路返回伪造 Document，声称 owner = did:web:attacker.com
    ↓  Resolver 拿这个声明去解析 attacker.com 的 owner config
    ↓  用攻击者自己的 key 验签 →“通过”
    ↓  用户安装了假 App
```

问题不在验签本身，在**你验证的是攻击者自己声明的 owner**。所以 2.4 节的规则是硬规则：

> 验签用的 owner 不能由候选 document 单方面决定。Resolver 必须先从权威源（owner 绑定）或 method 定义的名字结构得到 expected_owner，再要求 `doc.owner == expected_owner`，不一致直接拒绝；owner 变更 / 委托必须经权威源发布才能生效。

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

1. **先比证据等级，同级才比 iat / version**。等级从高到低：已发布/已锚定 > 已验证的自签名 > 未验证。“已验证”指通过了含 expected_owner 一致性在内的完整 verify——伪造 owner 的文档永远进不了这一档；
2. **负状态与本地覆盖屏蔽一切写入**，吊销只能被权威源的新状态翻篇。

由此也能理解主循环开头的快路径：**进入解析流程，就意味着缓存已经失效**。唯一的例外是负状态——TTL 过期不代表"已吊销"作废：快路径命中负状态返回错误；就算 TTL 过期进了解析流程，负状态记忆仍屏蔽③/④的一切兜底，只能被权威源的新回答翻篇。

## 6. 发布状态是权威源的记忆（可选能力）

发布状态的本质，是权威源对**"什么被发布过"的记忆**：一个能做成员判断的集合（某个 hash / 版本是否属于已发布版本），"当前指针"只是这个集合上的一个约定。这一下解释了三件事：

- 合约类权威源（BNS）天然支持——事件日志就是历史；
- 它不是强制能力——不是每种发布渠道都有记忆；
- owner-at-iat 校验、previousVersion 回滚这类高级能力，只有有历史的 method 才做得到。

各类 method 的退化梯子：

| method 类型 | 权威源能力 | 解析行为 |
| --- | --- | --- |
| did:bns（合约） | 完整状态 + 已发布版本集合 + owner 绑定（含变更/委托） | 完整流程：状态门禁 + hash 锚定 + owner 一致性 + 历史校验 |
| did:web 类（canonical endpoint） | 只有“当前内容”与当前 owner 绑定，无历史、无强负状态 | 只有 Missing / Active 两态；历史校验退化为“用当前 owner 或拒绝” |
| did:key / did:dev（生成式） | 无发布渠道，权威 = 自证 key（owner ≡ 名字自身） | 状态门禁全程不触发；一切都是自签名候选，验签 + iat 仲裁 |

主循环对"没有发布状态的 method"是**自动退化**的，不需要加分支：三个状态门禁只在权威源真的返回状态时才触发。但代价要诚实写出来：**没有发布状态 ⇒ 没有吊销能力**。生成式 DID 的 key 泄露后无处声明作废——这是选 method 时的权衡，也是 BNS 作为 BuckyOS 核心三件套之一存在的理由。

## 7. 开发期旁路：本地覆盖（hosts 语义）

第 4 节锁死了所有正常路径，于是开发/测试期只剩一种办法模拟"已发布"：**手工往 did_cache 写入条目，让查询在最前端短路**。它等价于传统系统的 hosts 文件。因为它短路在权威查询之前、连 REVOKED 都盖得住，三条纪律不可省：

1. **显式打标**：解析结果必须带 LocalOverride 警告，日志和 UI 可识别；
2. **带 scope**：machine / test-env / CI，只能由本地管理员或测试框架写入；
3. **不参与合并与导出**：cache merge 对它拒写，它也永远不进普通缓存、不向外同步。

测试通过后，再执行真正的发布（上链或写入权威渠道）。

## 8. 速查：不能破的规则

1. 吊销之后不允许任何 fallback——负状态要缓存、要屏蔽后续写入，它是"回答"，不是"查不到"；
2. unknown 和 Missing 不能混——界线是"有没有得到回答"，网络错误不能伪装成"从未发布"；权威源没回答时，候选最多以 unproof 打标露面（默认拒绝），正路是已验证缓存；
3. 未发布的自签名文档压不过已发布结果——查询路径靠 hash 锚定和 Missing 门，Cache 层靠证据等级；
4. need_proof 按信道和 doc_type 契约打标，永远不看 body 长相；
5. 验签用的 owner 不由候选文档决定——expected_owner 只来自权威源的 owner 绑定或名字结构；`doc.owner` 与它不一致直接拒绝，推不出 expected_owner 的候选直接出局；owner 变更 / 委托必须经权威源发布；
6. owner 不要写成独立流程——它只是“need_proof = false 的权威结果”，递归自然终止；
7. 一份坏 body 只作废它自己（continue），不终止整个解析；
8. 本地覆盖必须打标、带 scope、不合并不导出。
