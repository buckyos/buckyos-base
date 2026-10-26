# resolve-did 协议冻结讨论：版本选择、验证与请求边界

> 设计稿，2026-10-20。依据 [resolve-did.py](./resolve-did.py) 伪代码整理，以 `62a5358` 为基线，补充本轮目录/路径入口及 HTTP body/header 文档承载约定。
> 同日按 [resolve-did重构-TODO.md](./resolve-did重构-TODO.md) 的裁决回写：closest 推导规则（§1、§6）、`invalid` 负状态（§2.2）、`doc_type` 归一表（§2.4）、串行锁范围（§4、§5、§7）。wire 细节在 [HTTP DID Resolver API](./http_did_resolver_api.md)。
> 2026-10-20 重构 M1–M6 已按本文实现于 `name-client/src/resolver/`（落点见 [resolve-did重构-TODO.md §2](./resolve-did重构-TODO.md)）。本文省略异步、数据库和 wire 格式；helper 名称已回写为实际 Rust 名（`revision` / `ResolveOpts` / `DocResult` / `DocStore` 等）。
> 本次替换旧稿中的 `Current / StillValid / AtPublication`、验证后另行提交、当前 Owner 密钥统一验签等旧方案。版本查询、事实验证与业务准入分别按下文定义；与其他早期讨论稿冲突时，本轮核对以 `resolve-did.py` 为依据。

讨论范围是需要信任验证的 DID Document。`Info` 等免验证类型继续走独立契约，不能作为身份凭据；`did:key / did:dev` 不作为这里的可信文档解析入口。本文不定义 method 发布交易或 Zone 管理 API。

## 1. 客户端入口与版本模型

```python
# 日常解析：普通文档选择 best，owner 选择 latest。
doc = resolve_did(did, doc_type)

# 精确版本或严格早于指定时间的最近已发布版本。
doc = resolve_did(did, doc_type, revision=Revision.exact(iat, content_hash))
doc = resolve_did(did, doc_type, revision=Revision.closest(query_iat))

# 获取完整结果及原因，控制来源、传输、缓存、locker 和预算。
result = resolve_did_ex(did, doc_type, revision=None, opts=opts)

# 始终验证收到的确切文档；允许按 opts 补材料并更新解析缓存。
report = verify_document(did, doc_type, received_body, revision=None, opts=opts)
if report.success(Revision.current()):
    continue_business_admission(report)  # 持钥证明、连接授权等由业务负责
```

参数 `revision: Revision` 表示**查询条件**；`DocRevision`（`doc.revision()`）表示文档身份 `(iat, content_hash)`，两者不能混用。未指定查询条件等价于 `Revision.current()`。便捷入口 `resolve_did` 默认启用本机 locker、Zone locker 和磁盘缓存。

| 查询/选择 | 含义 | 成功条件 |
| --- | --- | --- |
| `latest` | 在所选 scope 和已有发布依据内，最高的已发布版本 | 有效且有 authority 发布或 locker 模拟发布依据 |
| `best` | 看到并验证通过的最高版本，可以尚未发布 | 普通文档可由 authority、trust 或验签通过的 normal 材料推进 |
| `current()` | 普通文档同时获取 latest 与 best，默认选 best；owner 只取 latest | 输入有效且命中对应选择 |
| `exact(iat, hash)` | 指定的已发布版本 | 精确匹配 iat/hash，且有该查询的发布依据 |
| `closest(iat)` | 已发布版本中最大的 `document.iat < query.iat` | 发布回答确认所选版本及查询边界内没有更高版本 |

Owner 是信任根，只从 authority/locker 取得当前或指定的已发布版本，始终不设置 best。普通 current 解析即使已经取得 latest，也继续收集本轮允许的 trust/normal 来源，以寻找更高的有效 best；authority 未回答不构成停止补充来源的规则。authority 本轮回答的文档已验证并成为 best 时，其余来源并发查询，只在宽限期（`config.supplement_grace`，默认 1 秒）内收集：到期未回答按该来源 Unknown 记录，不退避、不终止调用，按时返回已有选择；宽限期为 0 时不再查询补充来源。authority 未给出有效 best 时，补充来源照旧在单源上限内等待（buckyos#684）。

`exact/closest` 依赖 resolver 的 `publish_info` 查询能力（wire 为 `versionId` / `versionTime`）；locker 可以在自己的 scope 内模拟。不支持或没有回答时保留原因，不能退回 current，也不能把本机曾见过的最大历史版本当成 closest。查询旧版普通文档仍检查它今天是否过期、撤销；这里不提供只证明“发布当时合法”的 `AtPublication` 模式。

**closest 可由 current 回答推出。** authority（或 locker 模拟发布）的 current 回答 L = (iat_L, hash_L, body) 已经证明 `(iat_L, +∞)` 内没有已发布版本，因此对任意 `query_iat > iat_L`，`closest(query_iat) = L`，边界条件自动成立；`exact(iat, hash)` 在 `iat == iat_L && hash == hash_L` 时直接命中。推出的回答按完整查询分槽缓存，证据指向产生它的 current receipt，TTL 相同。只有 authority 档的回答能用于推导，trust/normal 的 body 不能；`query_iat <= iat_L` 时必须发真正的历史查询。这条规则让签发时间晚于当前 Owner 发布时间的文档（绝大多数设备、应用文档）在 resolver 不支持历史查询时也能完成验签。

版本只按 `iat` 比较。相同 iat、相同 hash 幂等；通过验证后，相同 iat、不同 hash 才判冲突，不能让坏候选先占槽。JWT 对原文取 hash，JSON 对既定规范化序列化结果取 hash；JSON 语义合并不能替代 JWT 原文验签或发布 hash 校验。`version_seq / mini_version_seq` 不参与版本或撤销判断。

## 2. 来源、发布事实与结果

### 2.1 三档来源和 locker

| 来源 | 对普通文档的作用 | 不能据此声称的事实 |
| --- | --- | --- |
| `authority` | 确认发布，更新 latest/历史记录；可用文档也参与 best | 来源可信不等于实际执行过 JWT 签名核验 |
| `trust` | 免 Owner 验签，可接受无签名 JSON，参与 best | 不自动设置 `is_signed / is_published`，不改可信 owner 绑定 |
| `normal` | 只贡献候选；按可信 owner 绑定和签名等规则验证后才参与 best | 候选自报来源、owner 或较高 iat 不能建立信任 |

来源等级由本机配置或可信 Owner 绑定决定，不能采用远端 payload 中的 `trusted/verified` 声明。BNS Owner 绑定站点属于 trust，其它配置来源属于 normal。解绑只改变下一次 resolve 的来源列表，不撤销已取得文档的 trust 来源；文档仍受 exp、明确撤销、验证依赖和版本替换约束。

Locker 按 `/etc/hosts` 模型优先且强制回答，顺序为 **本机 locker > Zone locker > 普通缓存与 provider**。它不是第四档普通来源，结果不写入普通来源缓存；可以在 scope 内覆盖根材料或模拟发布，但不能冒充公网权威回答。

Locker 的 Unknown/未覆盖允许继续查找；明确不存在或禁用仍是强制回答。body 与 publish_info 分别回答，缺席的列可继续向后查。锁定当前文档不能冒充 exact/closest 的历史目标，`DocResult::locked_from` 同样按 revision 匹配目标；验证输入时，也不能用另一份锁定文档的成功替代收到文档的判断。

本机配置与 Zone 管理权限分开：NameClient 消费 Zone 的查询接口，不因 `scope` 参数就获得远程写入权限。本文不补造统一 `sethost` 管理函数，也不继续引入旧稿的 `SeedObserved / SeedTrusted` 类型体系。

### 2.2 发布信息与缓存槽

`doc_result` 按 `(scope, did, doc_type)` 保存；latest、best、历史记录保留来源、原查询和验证结果。候选按 `(iat, content_hash)` 保存，允许同一 iat 的多个待验文档并存。exact/closest 按完整查询分槽，不能串用。

`publish_info` 包含 DID/类型级状态、可信 owner 绑定和带明确 iat 的发布记录。公共状态、逐版本记录、查询回答分别缓存：

- `None / NoAnswer` 只是没有回答，不表示禁用，也不证明从未发布。Unknown 不能覆盖已知禁用或撤销。
- `NotExist` 表示该来源没有文档，不自动等于整个 DID 禁用；负状态只覆盖它明确声明的 DID、类型或版本范围。
- `Invalid(reason)` 是 authority 对该 `(did, doc_type)` 做过确定性校验并拒绝的**明确回答**（如 BNS 的 device/zone 身份不一致），不是 Unknown：不触发退避，可缓存（短 TTL），选择时等同 NotExist，不升级为 DID 禁用，也不阻止 trust/normal 候选按 owner 链验签成为 best。authority 不得把这类校验失败报成 5xx（cyfs-gateway#207 根因 3）。
- `record_for(iat)` 只返回覆盖该 iat 的发布记录。V1 的发布 hash 不约束 iat 不同的 V2；同 iat 的已发布 hash 与输入不符则确定无效。
- exact 回答必须带该 iat 的实际发布 hash；closest 除版本记录外，还要提供针对查询边界的回答。裸 body 或单条历史发布记录不足以证明 closest。
- 显式“该版本未发布”和 NoAnswer 都不妨碍继续验签；它们不能使 exact/closest 达成发布目标。

查询缓存保留原时间，读取不续期。发布查询 TTL 与文档 exp 分开，历史查询回答不能无限复用。`allow_local_cache` 只决定普通缓存是否使用磁盘；内存缓存始终存在，验证规则不变。

### 2.3 验证报告

| 报告字段 | 语义 |
| --- | --- |
| `is_signed` | 实际签名核验通过；authority/trust 免签不能设置它 |
| `is_published` | 输入的确切版本有发布依据；locker 模拟发布保留来源标记 |
| `is_revoked / is_expired / is_disabled` | 当前已取得的撤销、时间和禁用事实；未检查的事实保留 unknown/reason |
| `validity` | `valid / invalid / unknown`；缺必要材料是 unknown，确定的身份/hash/签名错误或过期、撤销、禁用是 invalid |
| `is_best / is_latest / is_exact / is_closest` | 输入与可用选择的关系；invalid/unknown 时全部为 False |
| `success(revision)` | validity 为 valid 且命中目标；exact/closest 还必须有对应发布查询依据 |

因此，“签名正确”“当前有效”“命中查询目标”“业务允许使用”是不同结论。旧版可能 `is_signed=True` 且仍 valid，但不是 best；已撤销的旧版也可保留 `is_signed=True`，同时 validity 为 invalid、所有选择标志为 False。

### 2.4 目录型 DID 与路径型 DID Object

本轮确定以下获取规则：

1. **目录型 DID 按 method/发布模式的规则取得 `did.json`。** 无对象子路径的 `did:bns:xxxx` 属于目录型。根域名的静态发布继续使用 `/.well-known/did.json`；显式 HTTP 目录则在该目录下补 `did.json`。
2. **路径型 DID 默认直接请求对象 URL。** 例如 `did:bns:xxxx:aaa:bbb` 映射到对应 host 的 `/aaa/bbb`，不再无条件追加 `/did.json` 或 `/{doc_type}.json`。只有显式选择非默认文档类型时才构造 `?type=...`；通常只有一份默认 DID Object Card，不需要参数。
3. **HTTP 响应 body 和 header 都可以承载 DID Document。** 原 URL 已经提供旧格式对象内容时，可以保留 body 和 Content-Type，通过响应 header 内联对象卡片，见下一节。

目录与路径的分类发生在 URL 拼接之前。对于 HTTP Object URL，检查的是 **URL.path 是否以 `/` 结尾**，query 不参与；不能先去掉尾斜杠，也不能在发现缓存中抹掉两种输入的差异。对于 DID 字符串，由 method 解析根名字和对象子路径：没有对象子路径的 BNS 根即使字符串不带 `/`，仍是目录型。

| 输入及访问模式 | 默认获取地址 |
| --- | --- |
| `did:web:example.com`，根域名静态发布 | `https://example.com/.well-known/did.json` |
| `did:bns:xxxx`，BNS Web 映射的静态来源 | 配置的 bridge host 下 `https://xxxx.{bns_bridge}/.well-known/did.json` |
| `did:bns:xxxx:aaa:bbb`，对象直接入口 | 对应映射 host 下的 `/aaa/bbb` |
| `did:web:example.com:user:alice`，对象直接入口 | `https://example.com/user/alice` |
| `https://example.com/user/alice` | 原 URL，文档可在响应 body 或 header 中 |
| `https://example.com/user/alice?type=xxxx` | 原 URL，显式选择 `xxxx` 文档 |
| `https://example.com/user/alice/` | `https://example.com/user/alice/did.json` |
| `https://example.com/user/alice/?lang=zh` | `https://example.com/user/alice/did.json?lang=zh` |

Object URL 是对象引用，Object DID 是规范身份；例如 URL 的 `/user/alice` 对应 DID 表示中的 `:user:alice`。不能把这种映射理解成任意混合斜杠的 DID 字符串都已被现有解析器支持。

**内部 `doc_type` 与 HTTP `type` 选择参数分开。** 路径对象的默认逻辑类型是 `did-object`，缓存、身份检查和验证仍记录此类型；默认查询不因此追加 `?type=did-object`。入口必须依据已知对象/发布契约选择默认类型，不能把旧的全局 `zone` 默认值直接套给路径对象，也不能根据未验证响应改变调用方要求的类型。显式查询其它类型时使用 URL query API 保留无关参数；与已有 `type` 或业务参数冲突时明确拒绝，不能重复追加或静默覆盖。选择参数不改变 Object DID。

调用入口未指定 `doc_type` 时，可先从输入 URL 的显式 `type` 归一实际类型，再进入按类型分键的缓存与串行流程；调用方已指定时则必须一致。默认查询和目录分支也检查原 URL 已有的选择器，不能因为没有新增参数而漏检。

**`doc_type = None` 的归一发生在缓存键之前**，表示接受 method/provider 定义的默认类型，不是 `zone` 的别名：

| 输入形态 | 默认类型 |
| --- | --- |
| 路径型 DID Object / 不以 `/` 结尾的 Object URL | `did-object` |
| 无对象子路径的 `did:bns:<name>` | BNS provider 在 active 类型集合中选择：有且仅有一个取它；多个且无显式默认值时报 ambiguity；多个且含 `zone` 时取 `zone` 并把 warn 写入结果 reasons |
| `did:web` 根域名 | 读 `/.well-known/did.json`，实际类型由文档内容确定 |
| 其它 method | provider 自己的默认规则，结果必须携带实际类型 |

归一之后缓存键、串行锁、验证都用实际类型；结果携带 `requested_doc_type` 与 `actual_doc_type`。旧实现 Zone 分支的 Device → Agent → Owner“取任意身份文档”探测删除，调用方要类型就传类型。BNS 对 `ood1.<name>` 的设备槽位联合校验只挂在显式 `device` 查询上，不挂在默认查询上。

URL 路由伪代码如下；`location` 表达已知 method/provider 的发布模式，不来自响应中自报的信任字段：

```python
def build_document_request_url(location, doc_type):
    location.check_input_type_selector(doc_type)
    if location.is_resolver_api() or location.is_legacy_static_route():
        return location.existing_document_url(doc_type)
    selector = location.non_default_type_selector(doc_type)
    if location.is_directory():
        return location.directory_document_url(selector)
    url = location.object_url.copy()
    if selector is not None:
        url = url.with_document_type_query(selector)
    return url
```

这里的目录 helper 默认按上述规则补 `did.json`；已有目录显式类型文件继续遵守原发布契约。**兼容目标是保留旧接口和发布方式，同时增加新的对象入口与载体支持。** BNS authority 等现有 `/1.0/identifiers/{did}?type=...` resolver API 不变，根目录 `/.well-known/owner.json` 等类型文件也不变。旧路径型 `did:web` 的 `/{path}/did.json`、`/{path}/{doc_type}.json` 可按已知 method/provider 配置保留为兼容路由；新路径对象不无条件尝试这些后缀，兼容查询仍服从来源、传输和预算限制。

这延续 [DID Object 协议](./did-object-protocol.md) 的 Object URL / Object DID / Card 模型，并细化其发现路由。该文档 §6.1 与 [HTTP resolver 文档](./http_did_resolver_api.md) §1.1 已于 2026-10-20 同步为上述规则；Rust 实现见 `resolver/http.rs`（`DocumentLocation` / `build_document_request_url`）与 `web_provider.rs`。

对象 Card 的 controller/Zone/Owner 是验证链。取得验签根材料时，应先建立可信绑定，再查询对应 Owner DID；不能把这个操作实现为给对象 URL 追加 `/owner.json`，也不能仅凭对象自报 controller 建立信任根。目录/路径分类本身不证明谁拥有对象。

### 2.5 从 HTTP body/header 提取确切文档

新增的 header 承载方式允许原 URL 继续返回 HTML、旧 JSON、媒体等业务内容，旧客户端可继续使用原响应；新客户端从协议声明的响应头提取完整 DID Document。body 继续支持已有裸 JSON/JWT 和 DID Resolution Result 信封。两种载体进入同一套来源判断、版本选择和验证流程。

```text
请求：GET https://example.com/user/alice
响应：
  Content-Type：保持原业务类型
  协议声明的文档响应头：编码后的完整 DID Document / DID Object Card
  body：保持原业务内容
```

上例只固定语义。header 字段名（`BuckyOS-DID-Document`）、`jwt` / `json` 两种编码和 16 KiB 上限已在 [HTTP DID Resolver API §8](./http_did_resolver_api.md) 定下。JSON/JWT 解码后保留确切文档内容，JWT 保留原始 compact 字节；不能对整个 header 或旧业务 body 计算文档 hash。`Link` 指向独立 Card 可以作为后续可选扩展，不替代本轮对 header 内联完整文档的支持。

```python
def document_answer_from_http(response, expected_did, doc_type, opts):
    opts.budget.check()
    answer = decode_http_source_answer(response, allow_legacy_body=True, opts=opts)
    header_doc = decode_declared_document_header(response.headers, opts=opts)
    if header_doc is not None:
        if answer.body is not None:
            require_same_exact_document(answer.body, header_doc, opts=opts)
        else:
            answer.body = header_doc
        answer.remember_document_carrier("header")
    answer.check_requested_document_binding(expected_did, doc_type, opts=opts)
    return answer
```

这些 helper 的约定是：

- 先处理 HTTP 状态和既有发布状态信封。5xx 不因附带 Card 变成成功，明确禁用/撤销也不能被 header 覆盖；允许旧业务 body 不等于吞掉格式错误的显式 DID 文档或信封。
- header 缺席返回 None；明确的文档字段损坏、超限时报告该来源回答错误，不伪装成缺席。解析、响应大小和解码计算都受同一预算限制；取得 header Card 不要求完整下载无关的大业务 body。
- `SourceAnswer.body` 表示提取出的 DID Document，不一定是原 HTTP entity body。普通业务 body 没有声明为 Card 时不参与文档冲突比较。
- body/header 同时提供文档时，要求身份、类型及 iat/hash 一致；否则拒绝该来源回答，不能用载体优先级掩盖冲突，也不能据此写入 DID 禁用状态。
- 提取时检查请求身份、类型及对象 URL 绑定，保留原 Object URL 和实际请求/重定向上下文，不能把 Card 存放地址当成对象身份；提取成功还不是可信验证成功。header 不提升来源等级，不自动设置 `is_signed / is_published`，也不改变 publish_info 或本轮真实 authority receipt 的要求。
- Card 有效不自动证明旧业务 body 的内容完整性。Card 的 iat/hash/exp 与业务 body 的 ETag 分开；Card 更新须使旧响应头可过期或重验，HTTP 缓存期限不能覆盖 Card 自身 exp。
- 无可识别文档且无发布状态回答时，保留“不提供 DID 文档”的原因，不能把普通 HTTP 200 业务内容当作 DID 解析成功。

这一兼容扩展需要 provider 增加 URL 选择和响应归一化实现，不强迫旧服务改 body，也不要求现有 provider 同时支持全部新入口。它不解决第 1 节的历史查询能力缺口：不支持 exact/closest 的来源仍不能伪装成支持。

## 3. 请求来源与传输限制

来源信任等级与网络访问许可是两个维度。每个普通 provider 先检查可复用的本轮回答和查询缓存，再在实际 I/O 前应用请求策略；限制联网不删除已有 trust/normal 材料，也不改变 best 的定义。默认使用普通传输，`force_authority_query=False`。

| 选项 | 目标行为 |
| --- | --- |
| `network_sources="all"` | 默认允许查询 authority/trust/normal |
| `network_sources="authority_only"` | 仅允许普通 provider 中的 authority 发出网络请求，仍可复用允许的本机材料 |
| `no_request`（示例方法为 `.not_allow_request()`） | 禁止所有普通 provider 网络查询，包括 authority；递归 Owner 查询继承 |
| `allow_zone_lock` | 独立控制 Zone locker，不受 no_request 开关控制；仍受传输策略与预算约束 |
| `transport_policy=independent_control_plane` | 只允许本机可信配置声明且实际保证不依赖目标隧道/Relay 转发入口的控制通道；未知则拒绝 |
| `force_authority_query=True` | 跳过权威查询缓存，要求本轮真实权威回答；仍可复用精确匹配的合法 body |

**严格不联网需要同时设置 `no_request + without_zone_lock`。** 本机 locker 是本地访问。Zone locker 向外 resolve 时传递 `without_zone_lock()`，这只避免再次选择自己，不能证明底层传输没有回流。

独立控制通道限制覆盖身份和地址材料获取的每一跳，包括 DNS、代理、重定向、well-known/upper fallback 和内部子查询。authority 名称、来源等级、localhost 地址或远端自报字段都不能证明传输独立；不支持传递限制的 provider/locker 在受限路径不可用。最终绑定已验证身份的 RTCP 拨号由连接准入控制，但其内部发现或补材料仍继承限制，不能恢复默认解析。

统一请求入口的关键逻辑如下：

```python
def request_source(source, operation, did, doc_type, revision, opts):
    opts.budget.check()
    if source.is_zone_locker():
        allowed = opts.allow_zone_lock()
        request_opts = opts.without_zone_lock()
    else:
        allowed = opts.allow_request() and (
            opts.network_sources == "all" or source.is_authority()
        )
        request_opts = opts
    if not allowed or not opts.transport_policy.permits(source):
        reason = "本次请求的来源或传输策略不允许访问"
        opts.record_unanswered(source, operation, reason, cacheable=False)
        return Unknown(reason, cacheable=False)

    query = source.get_document if operation == "document" else source.get_publish_info
    try:
        raw = opts.budget.run(
            lambda: query(did, doc_type, revision, opts=request_opts),
            connect_timeout=min(opts.connect_timeout, opts.budget.remaining()),
            request_timeout=min(opts.request_timeout, opts.budget.remaining()),
        )
        return normalize_source_answer(raw, operation)
    except SourceTimeout as err:
        opts.budget.check()  # 总预算耗尽时向外抛终止错误
        opts.record_unanswered(source, operation, str(err), cacheable=False)
        return Unknown(str(err), cacheable=False)
```

统一回答带 `body / publish_info / reason / cacheable`。只有可缓存的真实来源回答进入共享查询缓存；来源返回的 NoAnswer/Unknown 可用于短期退避。策略拒绝、本地超时、调用取消或预算不足不得写成共享查询缓存的负回答。真实来源/传输失败仍可按访问策略短期退避；策略拒绝、取消和预算不足只记录本次诊断，不影响其它策略的调用。受限调用拒绝访问某站点，不会把该站点降为不可信。

`force_authority_query` 本身不关闭 locker，也不等于 RTCP 的公网当前身份门禁。要求真实权威当前证明时，还要关闭两种 locker，并检查本轮 receipt：

- receipt 属于本次请求上下文，按 DID/doc_type/revision/来源区分，递归共享；最外层新调用建立新的集合，复用 Opts 配置不能继承上轮 receipt。
- `reusable_query_answer` 只复用本轮精确回答；body 与 publish_info 可共用一次回答。缺少所问内容时返回 None，不隐含联网。
- 可按新 receipt 的精确 hash 使用已有合法 body，但保留 body 原来源及证据时间；旧 body、旧验证缓存或旧 latest 单独都不构成本轮权威确认。
- 验证缓存若缺匹配本轮 receipt，不能让 `force_authority_query` 短路。

## 4. 整次调用共用有限预算

`ResolveOpts::normalize` 在最外层以 `monotonic_now() + config.resolve_timeout` 建立有限绝对 deadline，有调用方截止时间时取更早者。`normalize / with / create_get_owner_opts` 返回副本，但共享同一预算、取消信号和请求上下文；来源/传输限制只能收紧，Owner current/closest、fallback 和重试不能续期或恢复默认值。

`resolution_budget` 覆盖锁与并发许可等待、缓存 I/O、locker/provider 查询、解析、验签和提交。同步计算也要限制输入大小、深度、key 数量并分片检查预算，不能只依赖异步超时。单次 connect/total timeout 取配置上限与剩余预算的较小值，provider 内部重试继续消耗同一剩余预算。

跨主机 locker 传递剩余时长，由服务端按自己的单调时钟和本地上限收紧，不能传递假定可跨主机比较的绝对单调时钟。客户端仍执行自己的 deadline/取消，服务端也要终止无用工作，不能靠转发获得新的一整份预算。

| 终止或失败 | 后续行为 |
| --- | --- |
| 单个来源 `SourceTimeout` | 检查总预算，仍有余量时可返回 Unknown 并尝试下个允许来源 |
| `ResolutionDeadlineExceeded` | 终止整次调用，不再 fallback，也不返回旧缓存冒充成功 |
| `ResolutionCancelled` | 终止整次调用，不转成可继续处理的 Unknown |

总超时和取消都不声明 DID 不存在、禁用或撤销。已完成的合法原子提交保留；未完成的非共享子任务取消，连接关闭，锁与许可释放，不遗留后台请求。`serialize_document` 的锁等待同样可取消并受 deadline 约束。

并发控制还需满足：

1. 身份解析阶段也参与任务合并；共享任务有自己的有限预算，每个等待者保留自己的 deadline/取消信号，加入者不能延长任务期限。
2. 合并键包含 scope/DID/doc_type/revision 及来源、传输和证据要求；受限请求不能加入会访问目标站点的任务。
3. 单个等待者离开不取消其它有效等待者的任务，最后一个等待者离开才取消无用任务；并发数和等待队列都有上限。
4. 真实来源/传输失败按目标、来源和访问策略短期退避，错误日志限流；策略拒绝、调用取消或预算不足不能触发影响其它策略的共享退避。

调用链 visited、同键串行和跨进程原子合并均不能代替网络访问门禁。网络回流可能变成一个新的入站请求；退避也不能代替首次请求的门禁和超时。

**同键串行锁不得跨 provider/locker I/O 持有。** 若锁包住整个获取过程，一次默认策略的解析在查补充源时请求回流到本机，变成入站 RTCP 的受限策略解析，后者在同一把 `(scope, did, doc_type)` 锁上等前者，前者又在等它的 TLS 握手：等待环虽受预算约束，但每次都烧满整份预算才失败，健康场景下入站并发查询也要等出站 I/O（cyfs-gateway#207）。因此锁只覆盖两段：读缓存、刷新约束、决定要发哪些查询；验证后原子提交。I/O 阶段不持锁，跨请求去重交给任务合并，而合并键含访问策略，受限请求不会加入会访问目标站点的任务。

## 5. 获取与选择的主路径

以下是对应 Python 文件的流程摘录。helper 的完整约定仍以该文件相邻注释为准。

```python
def resolve_did_ex(did, doc_type, revision=None, opts=None):
    revision = normalize_revision(revision)
    opts = ResolveOpts::normalize(opts, doc_type)
    with resolution_budget(opts):
        # serialize_document 只在 get_document 读缓存段和 update_doc_result 提交段内持有；
        # provider/locker I/O 与候选验证（含 Owner 递归）不持锁，由任务合并去重。
        result, publish_info = get_document(did, doc_type, revision, opts)
        if result.locked or result.state.is_disabled():
            return result
        if doc_type == "owner" or (
            not revision.is_current() and result.satisfies_published_target(revision)
        ):
            return result

        for doc, source in result.candidates.candidates_for(revision, publish_info).descending_iat():
            opts.budget.check()
            report = verify_document_ex(
                did, doc_type, doc, result, publish_info, source, revision, opts
            )
            if report.validity == "unknown":
                continue
            result.candidates.remove(doc.revision())
            if report.validity == "invalid":
                continue
            result.accept_verified(doc, source, report, revision)
            if revision.is_current() and result.best:
                break
            if not revision.is_current() and result.satisfies_published_target(revision):
                break

        if revision.is_current() and result.best:
            result.candidates.clear()
        return update_doc_result(did, doc_type, result, opts)
```

`get_document` 先读取 locker；无覆盖时在串行锁内读取普通结果缓存并刷新已知时间、撤销和依赖约束，然后释放锁，查询并合并 publish_info。已知禁用直接提交返回，否则按 authority > trust > normal 遍历 provider，owner 只查询 authority；每个 provider 查询经 `TaskMerger::merge_or_run`，合并键为 `(scope, provider, did, doc_type, revision, 访问策略)`。每个回答可同时带 body 与 publish_info，拆开缓存以避免重复请求：

- 只有 authority 的 publish_info 可合并普通来源的状态、发布依据和 owner 绑定。Unknown 不抹去已知事实。
- body 先检查 DID/doc_type/iat、同 iat 的发布 hash、时间及已知撤销。authority 更新 latest 或历史；非 owner 的可用 authority/trust 文档也参与 best。
- normal 放入 candidates，按 iat 从高到低逐个验证；同 iat 的坏候选不阻止其它 hash 的合法候选。
- 普通 current 继续收集允许的来源；owner 或 exact/closest 满足发布目标后可停止。
- exact/closest 只检查对应发布查询选中的候选，缺发布依据时不以任意缓存版本代替目标；新回答可复用已有合法 body，无需重复下载。

current 选出 best 后可清空候选，包括暂时缺材料的候选；best 后续失效再 resolve。本机以低成本使用为目标，不承诺保存完整历史或成为其它节点的文档源。失效或缺材料时，完整结果保留原因，`select(revision)` 不能返回不满足条件的文档。

## 6. 验证确切输入与 Owner 的两次查询

`verify_document` 不是旧稿中的纯同步、无副作用验证函数。它按 opts 获取发布与 Owner 材料，保存发布/撤销事实，只有 valid 输入才能推进 best；这一步不依赖后续业务准入结果。业务仍须单独完成持钥证明和权限检查。

其流程是：在同一预算内解析输入并检查身份/type/iat，在文档键锁内读取结果缓存并刷新约束，然后释放锁，再读取 locker。若确切版本的验证缓存仍可复用，则重新应用已知约束并计算本次选择标志；仅在满足目标时快返。否则复用仍有效的原来源材料或按 normal 输入处理，补充材料并验证（不持锁）；未锁定时在锁内原子合并结果，最后针对**收到的输入**重算选择标志。不能先 resolve V2，再把 V2 的成功计给收到的 V1。

验证顺序及关键分支：

1. 查输入 iat 的发布记录；初次 publish_info 不覆盖该版本时，补查 `Revision.exact(doc.iat, doc.content_hash())`。同 iat 发布 hash 不符立即 invalid；随后应用时间、状态和已知撤销约束。
2. owner 输入必须匹配 authority/locker 给出的确切根文档，自签不能自建信任。缺根依据是 unknown。
3. 当前权威发布记录精确锚定输入时可按权威依据通过；单有历史发布记录不能跳过当前有效性判断。
4. authority/trust 来源可免 Owner 验签，接受无签名 JSON；仍检查身份、时间及已知负状态，不把未检查的远端事实写成已检查。
5. 普通来源必须是 JWT，使用可信绑定或 method 名字结构决定 expected_owner；缺绑定是 unknown，自报 owner 不匹配是 invalid。
6. 普通验签分别获取**当前 Owner**与**签发时间之前的最近已发布 Owner**，各负其责。

普通 JWT 的 Owner 分支摘录如下：

```python
expected_owner = get_expected_owner(did, publish_info, result)
if expected_owner is None:
    return report.unknown("缺少可信 owner 绑定")
if doc.owner != expected_owner:
    return report.invalid("owner 不匹配")

owner_opts = opts.create_get_owner_opts()
current_revision = Revision.current()
signing_revision = Revision.closest(doc.iat)
current = resolve_did_ex(expected_owner, "owner", revision=current_revision, opts=owner_opts)
historical = resolve_did_ex(expected_owner, "owner", revision=signing_revision, opts=owner_opts)
current_owner = current.select(current_revision)
signing_owner = historical.select(signing_revision)

if signing_owner is not None:
    if not verify_jwt_signature(doc, signing_owner.get_public_keys(), opts=opts):
        return report.invalid("签名错误")
    report.is_signed = True
else:
    report.add_missing("签发时的 owner 文档：需要 closest 发布依据")

if current_owner is not None:
    if current_owner.valid_iat is not None and doc.iat <= current_owner.valid_iat:
        report.is_revoked = True
    report.remember_owner(expected_owner, current_owner.revision(), role="current")
elif current.state.is_disabled():
    report.is_revoked = True
else:
    report.add_missing("当前 owner 文档：无法判断当前撤销约束")
if signing_owner is not None:
    report.remember_owner(expected_owner, signing_owner.revision(),
                          role="signing", revision=signing_revision)
return report.finish(trusted=report.is_signed)
```

实现里签发时 owner 的查询边界取 `closest(doc.iat + 1)`：`closest` 严格早于，而同一秒内发布 Owner 并签发设备文档是激活流程的常态，签发时 owner 应是 iat 不晚于签发时刻的最近已发布版本。历史 Owner 决定验签 key，当前 Owner 决定当前撤销线 `valid_iat`，阈值比较为 `doc.iat <= valid_iat`。两次查询都可命中缓存，显式使用自己的 revision，同时继承来源、传输、locker 限制和同一预算/取消信号。按 §1 的推导规则，当 current 回答来自 authority 且 `current.iat < doc.iat` 时，`closest(doc.iat)` 就是 current，第二次查询不需要额外网络请求。缺历史材料不能用当前 Owner 冒充；Owner 正常换 key 也不自动按“当前 Owner 是否保留旧 key”裁决历史签名。

BNS 先使用可信 owner 绑定；无对象子路径的名字缺省取上级名字，一级用户的 profile 由自己的 owner 根验证。路径型 DID Object 的 controller/Zone/Owner 链须先形成可信绑定，不把截掉对象路径当成信任证明。其它 method 使用自己的可信绑定规则，不能从候选自报字段选信任根。

普通文档 exp 按 now 判断；owner 的 exact 在指定时刻、closest 在查询时刻检查历史根材料的 exp，不按今天判旧根过期，也不把历史根当当前根。历史验签材料不是完整的“发布当时合法”证明，当前撤销仍可使子文档无效。

`finish` 的优先级为：已知错误/过期/禁用/撤销 → invalid；缺必要材料 → unknown；否则 trusted → valid。未查询到发布信息本身不阻止普通签名文档有效，但不能据此满足 exact/closest；trust 免签不设置 is_signed。

## 7. 合并、缓存失效与预装

同键串行锁使用 `(scope, did, doc_type)`，不同 revision 仍可能更新同一 best，不能分别加锁。锁只覆盖“读缓存、刷新约束、决定查询”和“验证后原子提交”两段，provider/locker I/O 与 Owner 递归不持锁（§4）；提交段重新读取存储中的最新结果再合并，本地 result 只是快照。等待者要重新读取缓存并判断自己的输入、查询和 opts；不持数据库事务等待任何 I/O。Owner 递归使用另一文档键，保留调用链环路检查。

提交时按同键原子合并：每键结果文件 + OS 文件锁提供跨进程裁决（TODO D2：redb 单进程独占，不采用），内存后端提供同样的串行语义；不要求多个不同 DID 或多个公网来源的全局快照。接受规则为：

- unknown 保留待验材料；invalid 不推进 best；valid 才与已验证版本比较。更旧但有效的文档仍可报告签名/发布事实，不会成为 best。
- 同 iat 同 hash 幂等；同 iat 不同 hash 把本次报告改为 invalid(conflict)，保留旧结果。跨进程提交后发现冲突也必须修正报告，不能继续宣称成功。
- 明确是当前发布版本才更新 latest；历史 `is_published=True` 只进入历史记录。owner 始终不写 best。
- exact/closest 的槽位必须保留该查询依据；只有 body 或普通 valid 报告不足以填槽。

每次 resolve/verify 读结果都调用 `refresh_known_constraints`：检查 owner revision、locker 配置版本、已知负状态及本机 exp。实际验证依赖变更时标为需重验；仅修改站点绑定不让旧 trust 文档失效，也不能把已失效的 Owner 验签依据改称免签来源。

失效 best 从选择中移除，可重验 body 回到候选；确定撤销的 body 不重复验证。latest 的发布记录可保留为历史事实，但无效条目不满足 select/success。查询回答过 TTL 不等于清除已知禁用/撤销，旧回答也不能无限复用为 exact/closest 依据。

```python
# 预装 JSON 作为有权限的本机配置 trust 候选，iat 为编译时间。
for doc in build_preinstall_app_docs():
    commit_candidate_doc(doc.did, "app", doc, Source.configured_trust("preinstall"))

# 仅删除普通文档 body，不隐式解锁，不抹掉已知禁用/撤销。
remove_doc_result(did, doc_type, opts)
```

`commit_candidate_doc` 只投递候选，不等于发布或成功选择；不能直接采用远端提交的 source 字符串。预装不增加第四档信任等级，后续进入 best 后仍可被更高 iat 的有效正式/可信版本替代，不改变 latest。候选提交和删除也在统一预算内。

## 8. 使用场景：RTCP、离线和应用文档

### 8.1 Relay 发起 RTCP：从目标解析入口限制请求

目标 HTTPS 可能经过正在建立的同一 Relay/RTCP 入口。因此限制必须从 outbound 身份解析开始，不能等收到 hello 后才处理。

```python
def open_rtcp_tunnel(remote_did, requirement, caller_opts=None):
    opts = ResolveOpts::normalize(caller_opts, "device")
    opts = (
        opts.with_network_sources("authority_only")
        .with_transport_policy(independent_control_plane)
        .without_zone_lock()
    )
    if requirement == "AuthorityCurrent":
        opts = opts.without_local_lock().with_force_authority_query()
    with resolution_budget(opts):
        result = resolve_did_ex(remote_did, "device", opts=opts)
        identity = select_authority_current(result, requirement, opts)
        if identity is None:
            return error("目标身份材料不足或不满足 RTCP 身份要求", result.reason)
        return connect_rtcp_with_identity(remote_did, identity, opts=opts)
```

本示例固定关闭 Zone locker，调用方配置不能重新打开。其它显式允许 Zone locker 的模式，只能使用满足独立控制通道约束并传递剩余预算、取消和 `without_zone_lock` 的服务。

`select_authority_current` 是 RTCP 的证据门禁，不能把普通 `select(current)` 返回的 best 直接当成公网当前身份：

- `AuthorityCurrent` 关闭两种 locker，从**本轮真实 authority receipt**选择有效文档，核对精确 DID/type/iat/hash。即使本地 best 更新，也不能替换 receipt 指定的 body；模拟发布、旧 receipt、旧 latest 或 Unknown 均不满足要求。
- `TrustedSnapshot` 按自身准入策略检查允许的本地依据，不能因为限制了联网来源就放宽验证。
- 隧道复用或建连携带这一确切身份快照；地址材料获取与下层补材料继承限制和剩余预算，不能重新调用默认 resolve。RTCP 仍须完成持钥证明、身份绑定、撤销检查及业务准入。

### 8.2 入站 hello 与严格离线

```python
def on_rtcp_hello(hello, caller_opts=None):
    if hello.to != self.did:
        return error("我不是你的目标")
    opts = ResolveOpts::normalize(caller_opts, "device").not_allow_request().without_zone_lock()
    report = verify_document(hello.from_did, "device", hello.device_doc, opts=opts)
    if not report.success(Revision.current()):
        return error("device doc 验证失败", report.reason)
    # 继续 RTCP 持钥证明和业务准入。
```

同一 outbound/握手链共用剩余预算；新入站在握手入口建立有限预算，不接受对端指定更长期限。缺 Owner 等材料先结束本次握手；应用可在独立、限并发且有退避的控制通道任务中补齐后重试。独立任务可有自己的有限预算，但继续使用独立通道限制，不能在原请求链内恢复默认来源或无限重试。

| 离线材料 | 结果 |
| --- | --- |
| 有可复用的有效 best 或 authority/locker 根材料 | 可按查询目标使用；仍检查 exp、已知撤销、依赖和查询依据 |
| 只有普通 JWT 候选 | 还需可信 owner 绑定、当前 Owner 和有 closest 依据的历史 Owner；缺必要材料为 unknown |
| 只有自签 Owner 候选 | 不能自举信任根；需要 authority/locker 对确切根文档的依据 |
| no_request 但仍启用 Zone locker | 仍可能进行 Zone 网络访问，不是严格离线 |
| 要求本轮真实权威确认但权威不可达 | 不满足 AuthorityCurrent，已有本地材料不能伪装本轮回答 |

### 8.3 Info、profile 与 AppDoc

Info 不走普通 DID Document 验签/发布，由 Zone locker 提供 Zone 内共享。用户 profile 可分别解析 owner/profile 后在应用层按 iat 合并字段，不改变各文档的验证依据。

AppDoc 使用 DID Document 的 JSON/JWT 两种形式和 iat 版本规则：普通来源用 JWT，可信来源可用无签名 JSON。后续迁移要同步 AppDoc/PIKG 的生成、发布、读取和验签，不在 resolver 内增加独立 `AppDocSignatureEnvelope` 适配层。

产品刷新口径为常规缓存窗口约 30 秒；无缓存首次查询可立即看到新版本，离线不承诺 30 秒。安装器区分无法确认有效性、latest、best、已发布历史版本、未确认发布的历史版本；过期、撤销、未完成检查单独显示。安装策略可以允许用户强制安装，但不修改验证事实；升级按 iat 判断。测试环境可通过 locker 改 Owner/root 或模拟发布，配置变化使相关验证缓存重判。

## 9. 冻结前仍需落实的协议与实现边界

本轮伪代码已经明确来源、版本选择、验证副作用、Owner 双查询和请求边界，不再把这些列为旧方案之间的选择题。下表各项的裁决见 [resolve-did重构-TODO.md](./resolve-did重构-TODO.md)；前两行与发布查询协议的 wire 已写入 [HTTP DID Resolver API](./http_did_resolver_api.md)（2026-10-20），其余随实现阶段落实：

| 项目 | 必须表达的保证 |
| --- | --- |
| 目录/路径与旧入口适配 | 默认 did.json 目录规则、路径原 URL、默认类型不发 query、非默认类型的参数选择、尾斜杠保留，以及旧 resolver/静态发布路由兼容 |
| HTTP 文档响应头 | 完整文档承载字段、编码与长度上限、body/header 冲突处理、URL 绑定与缓存失效；同步对象协议和 HTTP binding |
| 发布查询协议 | current/exact/closest、逐版本实际 hash、closest 边界、DID/类型/版本状态覆盖范围及 NoAnswer 原因 |
| 证据与缓存格式 | 原来源/时间、owner current/signing 依赖、locker 版本、查询槽位、receipt 生命周期及不可缓存诊断 |
| provider/locker 接口 | 每跳传输门禁、剩余预算与取消传播、跨主机剩余时长、资源清理；不支持限制时拒绝受限访问 |
| 并发与提交 | 同键串行、跨进程冲突裁决、按访问策略合并任务、有限等待队列及退避隔离 |
| 现有 Rust API 迁移 | 与本文目标逐项对照，不能把旧 ResolvePolicy、纯 verify 或缓存标签直接等同于新语义 |
| 发布端生命周期 | 吊销后恢复、注销永久性和历史证据保存由 method 协议另行明确；本文不凭旧状态机草案宣称已解决 |

完整“发布时合法”证明、统一 Zone 写入 API、全局一致快照，以及旧稿中的临时预设硬期限体系，均不由这份 Python 伪代码提供。Owner 历史材料查询、普通查询 TTL 与文档 exp 应按各自含义实现，不能相互替代。

## 10. 讨论与后续验收清单

以下每行对应 `name-client/tests/resolve_did_scenarios.rs` 中以行号为前缀的测试函数（如 `s11_`、`s31_`）；网络回流、FD 释放类用例须在隔离环境进行（`#[ignore]`）。

| 场景 | 预期 |
| --- | --- |
| 无对象路径的 `did:bns:xxxx` 或根域名静态 DID | 按 method 的目录发布规则取默认 did.json，既有 well-known 和 resolver API 不被替换 |
| `did:bns:xxxx:aaa:bbb` / `did:web:example.com:user:alice` 默认对象查询 | 映射到对象 URL 直接获取；逻辑类型为 did-object，通常不构造 type 参数 |
| `https://example.com/user/alice` 与相同 URL 尾部带 `/` | 前者直取，后者补 did.json；分类前不 trim，query 不干扰目录判断 |
| 路径对象默认或显式类型查询，且 URL 已有参数 | 所有分支先校验已有 type；非默认类型安全合并 query 并保留其它参数；冲突明确拒绝，不改拼类型文件 |
| 旧 provider 发布 `/{path}/did.json` 或 `/{path}/{doc_type}.json` | 已知兼容路由继续工作；新路径入口不无条件追加旧后缀，访问限制不放宽 |
| 原 HTML/JSON/媒体响应在 header 内联 Card | 原 body/Content-Type 保留；提取出的确切文档按相同来源、身份、类型和签名规则处理 |
| body/header 同时有相同 Card，或有不同 Card | 相同文档幂等；不同文档拒绝该来源回答，不静默选择、不写全局禁用 |
| 文档 header 缺席、损坏、超限，或与负状态同在 | 缺席不等于损坏；错误明确保留，header 不覆盖禁用/撤销或绕过预算 |
| 路径对象自报 controller，却没有可信绑定 | 不能自建信任根，也不能用对象自身 `/owner.json` 冒充签发者根材料 |
| authority 发布 V1，trust/合法 normal 提供更高 V2 | latest 保留 V1，best 可到 V2；普通 current 不因已有 latest 停止收集 |
| authority 给出有效 V1，补充来源超过宽限期仍未回答 | 按时返回 best=V1；该来源记 Unknown，不退避，下次调用照常再查 |
| authority Unknown，补充来源仍可用 | 继续查询允许来源并按其信任/验签规则处理，不把 Unknown 当禁用 |
| trust 提供无签名 JSON，随后解绑站点 | 可成为 best，不自动标 signed/published；解绑只改变以后来源列表 |
| 验证 V1 时已有更高有效 best V2 | 报告针对 V1；不回滚 best，不借 V2 成功让 V1 命中 current |
| 同 iat 的坏候选先到、合法候选后到 | 逐个验证，坏候选不占可信槽；两个已验证不同 hash 才判冲突 |
| 输入与同 iat 发布 hash 不同 | invalid；其它 iat 的发布 hash 不否定该输入 |
| exact hash 不符、closest 无边界回答或 provider 不支持 | 不满足目标并保留原因，不回退 current/本机最大历史版本 |
| Owner 历史签名正确，但当前 valid_iat 覆盖子文档 | is_signed=True、is_revoked=True、invalid，所有选择标志 False |
| 缺历史 Owner，但当前 Owner 有可用 key | 保留缺材料原因，不用当前根替代 closest 发布依据 |
| 缓存命中后文档过期、已知撤销或 locker/实际 Owner 依赖变化 | 撤掉选择资格或重验，不能靠缓存命中绕过约束 |
| local/Zone locker 覆盖、缺列或明确禁用 | 本机优先；未覆盖列继续；强制负回答不当 miss；模拟发布不变公网 receipt |
| 冷缓存 no_request + without_zone_lock | 包括 Owner current/closest 在内均不联网，缺材料明确失败 |
| RTCP outbound 遇权威 502/503、断连、不响应或坏身份，目标 HTTPS 指向同 Relay | trust/normal 网络调用为 0；等待、连接和 FD 在总预算内释放；其它合法 Zone 仍可用 |
| 独立 Zone locker 或 authority 的 DNS/代理/重定向/fallback 需要目标隧道 | body/publish_info 都执行门禁，拒绝回流和绕过；不因 authority 等级放行 |
| 锁等待、Owner 递归、多 provider 重试超过总预算或被取消 | 终止整次调用，释放请求/锁/许可；不返回旧缓存成功，不写禁用状态 |
| 不同访问策略并发、单个等待者取消、最后等待者离开 | 不跨策略复用不允许的网络任务；保留其它等待者工作，无用任务取消 |
| AuthorityCurrent 遇旧 receipt、模拟发布、仅 trust best 或更高缓存 best | 只接受本轮真实 authority receipt 精确绑定的有效文档 |
| 同一轮 body/publish_info 复用，随后复用 Opts 发起新调用 | 本轮可复用精确回答；新调用不能继承旧 receipt 或刷新旧证据时间 |
| 策略拒绝或预算不足后，另一普通调用查询相同来源 | 前次诊断不污染共享负缓存/退避，允许的访问仍能进行 |
| 两进程提交同 iat 不同 hash，或删除普通 body | 原子裁决并修正本次冲突报告；删除不解除 locker、不抹负状态 |
| authority 只支持 current，文档 iat 晚于当前 Owner 发布时间 | closest 由 current 回答推出，验签完成且不发历史查询；文档 iat 早于当前 Owner 时仍需真实历史查询，501 保留缺材料原因 |
| authority 回答 `invalid`（如 device/zone 身份不一致） | 明确回答、不退避；类型级负状态；normal JWT 仍可经 owner 链成为 best；AuthorityCurrent 因无 receipt 拒绝 |
| 默认策略解析在查补充源时请求回流，入站受限策略解析同一键 | 入站不被串行锁阻塞，自己查 authority 后在预算内结束；外层补充源失败后同样在预算内结束，不烧满整份预算 |
| BNS 对健康 Zone 返回 503 或不响应，目标 HTTPS 指向同 Relay | 与坏文档场景同样：Relay 对自身的连接数不随时间增长，第二个合法 Zone 持续可用 |
