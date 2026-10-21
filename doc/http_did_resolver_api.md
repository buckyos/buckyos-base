# HTTP DID Resolver API 与 HTTP 文档载体 binding

> 面向读者：在 HTTP 上实现符合 BuckyOS `resolve_did` 语义的 did-resolver 的团队（bns-server 是第一个实现方，
> 但协议本身**与 did:method 无关**）；发布 DID Object 的 HTTP 服务；以及 `name-client` 里 HTTP provider 的维护者。
>
> 语义规范是 [resolve-did 协议冻结讨论](./resolve-did协议冻结讨论伪代码.md) 与 [resolve-did.py](./resolve-did.py)（下称“设计稿”），
> 实施记录是 [resolve-did重构-TODO.md](./resolve-did重构-TODO.md)。本文只定义 wire：请求参数、响应信封、状态码、
> 文档在 HTTP body / header 中的承载方式，以及 Zone locker 的预算传递。
>
> **协议层面定位**：BuckyOS 有两类 did-resolver：
> 1）**基于 HTTP 的**（本文档）——method-agnostic，只要 resolver 按本文档应答，`resolve_did` 就能拿到完整的
>    `PublishInfo` 语义（发布状态、owner 绑定、逐版本发布记录、exact / closest 查询）。
> 2）**基于 DNS 的**（`dns_provider.rs`）——只能通过 TXT 记录表达 `owner` / `boot` / `zone` / device 几种固定 doc_type，
>    没有发布状态机和负状态信令，是过渡期兼容 `did:web` 老客户端的方案，不再扩展。
>
> 任何新 did:method 想要完整的验证 / 发布语义，走的都是本文档的 HTTP 协议，而不是给 DNS resolver 加字段，
> 也不是给 `resolve_did` 加 method-specific 分支。
>
> **落地状态（2026-10-20）**：客户端按 2026-07 旧 API 实现过 §3 信封的消费（`HttpsProvider::resolve_published_state`），
> 将在重构 M2 按本版重写；服务端（bns-server）尚未返回 `buckyos` 扩展块，也未实现 §7 的版本查询。
> 本版相对 2026-09 版的变化：`iat` 参数改为 `versionId` / `versionTime`；501 不再退化为当前 owner；
> `docHash` 在 Active 回答中必填；新增 `invalid` 状态、`latestIat` / `selectedVersion` / `boundaryConfirmed` 字段、
> §8 HTTP 文档响应头、§9 Zone locker 预算字段；§1.1 的路径型静态发布改为“对象 URL 直取”。

## 1. 设计原则：复用现有端点，不新开一套

resolver API 只有一个端点：

```
GET https://{provider}/1.0/identifiers/{did}?type={doc_type}
```

同一个端点在响应体里携带 `PublishInfo` 需要的状态信息，不管背后是 BNS 合约索引、did:web 域名额外部署的动态
resolver，还是未来某个新 method 的 resolver。理由：

1. 避免每个 resolver 实现方维护两套查询路径（拿文档一套、拿状态另一套）导致的不一致。
2. 响应体是 W3C DID Resolution Result（`didResolutionMetadata` / `didDocument` / `didDocumentMetadata`），
   天然 method-agnostic。
3. 一个 provider 服务哪个 method、是 authority 还是 trust / normal，由本机注册决定，不由接口或响应自报。

### 1.1 与静态发布面、对象 URL 的边界

本文档的 resolver API 是 `/1.0/identifiers/{did}`。它**不是** W3C `did:web` 的静态发布路径，也不是 DID Object 的对象 URL。
三类入口并存，由 `name-client` 按已知 method / provider 配置选择（设计稿 §2.4 的 `build_document_request_url`）：

| 入口 | 适用输入 | 响应体 |
| --- | --- | --- |
| `/.well-known/did.json`、`/.well-known/{doc_type}[.json\|.jwt]` | 目录型：`did:web:example.com` 根域名、无对象子路径的 `did:bns:xxxx`（经 bridge host）、以 `/` 结尾的 HTTP 目录 URL | 裸文档 body（JSON/JSON-LD 或 JWT），不是信封 |
| 对象 URL 本身，如 `https://example.com/user/alice`（可带 `?type=`） | 路径型：`did:web:example.com:user:alice`、`did:bns:xxxx:aaa:bbb`、不以 `/` 结尾的 HTTP URL | 业务内容任意；DID Document 在 body **或** §8 的响应头中 |
| `/{path}/did.json`、`/{path}/{doc_type}[.json\|.jwt]` | **兼容路由**：仅对已配置为旧路径型发布模式的 method / provider 使用 | 裸文档 body |
| `/1.0/identifiers/{did}?type=...` | resolver API（本文档） | DID Resolution Result 信封 + `didDocumentMetadata.buckyos` |

规则要点：

- 目录 / 路径的分类在拼 URL 之前完成。HTTP URL 看 `URL.path` 是否以 `/` 结尾，query 不参与，不能先去掉尾斜杠；
  DID 字符串由 method 判断有没有对象子路径。
- 路径型对象的默认逻辑类型是 `did-object`，默认查询**不**追加 `?type=did-object`，也不追加 `/did.json`、`/owner.json`。
  只有显式选择非默认类型时才用 URL query API 设置 `type`；与已有 `type` 或业务参数冲突时拒绝，不重复追加、不静默覆盖。
- 静态发布面只返回文档本体，不要把 §3 的状态信封塞进去。需要 `missing` / `revoked` / `invalid` 等状态语义时走 resolver API。
- `/.well-known/did.json` 是 W3C 兼容基线，保持 JSON/JSON-LD；BuckyOS 扩展的 `{doc_type}[.json|.jwt]` 允许 JWT。
  `doc_type` 只能使用 `[A-Za-z0-9_-]`，不含 `.` 或 `/`。客户端按 body 自动识别 JSON/JSON-LD 与 JWT，不能只依赖 `Content-Type`。
- WebProvider 的根 `did.json` 可以发布 Device、Owner 等默认身份文档。查询 current 的显式类型文件未得到有效文档或明确发布状态时，
  在查询上级 resolver 之前尝试根 `did.json`，且仅接受 DID 和实际文档类型都与请求一致的 body；不能用此兼容入口绕过明确负状态。
  所有尝试共享原请求预算，exact / closest 查询仍只走 resolver API。

## 2. 请求

```
GET {resolver_base}/1.0/identifiers/{did}?type={doc_type}[&versionId={iat}|&versionTime={iat}]
Accept: application/did-resolution
```

| 参数 | 含义 |
| --- | --- |
| `{did}` | 完整 DID 字符串（如 `did:bns:waterflier`），内部 `:` 不做 percent-encode |
| `type` | doc_type。`name-client` **总是显式发送**（`None` 已在客户端按 method 规则归一，见 TODO D4）。缺省时 resolver 按自己的 method 默认规则选择，并在 `buckyos.docType` 返回实际类型；无法唯一确定时返回 `400` + `error: "ambiguousDocType"`。不再约定“缺省 = zone” |
| `versionId` | exact 查询：询问 iat 等于该值的版本是否已发布及其 hash。见 §7 |
| `versionTime` | closest 查询：已发布版本中 `iat` **严格小于**该值的最高版本。见 §7。注意与 W3C DID Resolution 的 `versionTime`（`iat <= T`）语义不同，本 binding 固定为严格早于 |

- `versionId` 与 `versionTime` 互斥；都不带时是 current 查询。
- `Accept` 推荐 `application/did-resolution`。服务端不能只在带 `Accept` 时才返回信封；`/1.0/identifiers` 上一律返回信封。
- 幂等、无副作用，可被 CDN / 网关缓存，但 `Cache-Control` 由 resolver 控制：`revoked` / `tombstoned` / `invalid` 之后不能
  让旧的 `active` 回答继续被缓存层放出。带 `versionId` 的回答在该版本已发布后不再变化，可长期缓存；
  `versionTime` 的回答会随新版本发布而变化（边界内可能出现更高版本），只能短期缓存。

## 3. 响应信封

```jsonc
{
  "didResolutionMetadata": {
    "contentType": "application/did+ld+json",   // 或 "application/did+jwt"
    "error": null                                // 见 §5；仅在错误时非空
  },
  "didDocument": { /* current 查询且 active 时内联当前版本；版本查询时内联选中版本（可选） */ },
  "didDocumentMetadata": {
    "versionId": "1751500000",                   // 字符串化的 documentVersion
    "deactivated": false,                        // revoked / tombstoned 时为 true
    "buckyos": {
      "docType": "zone",
      "documentStatus": "active",                // active | expired | missing | invalid | revoked | tombstoned | migrated
      "documentVersion": 1751500000,             // 本回答所描述版本的 iat
      "docHash": "sha256:...",                   // 本回答所描述版本的内容哈希；active 与版本查询中必填
      "latestIat": 1751500000,                   // 当前已发布的最高 iat；有任何已发布版本时必填
      "selectedVersion": {                       // 仅 versionId / versionTime 查询，见 §7
        "iat": 1751500000, "docHash": "sha256:...", "published": true
      },
      "boundaryConfirmed": true,                 // 仅 versionTime 查询
      "registryVersion": 3,                      // 可选：BNS 登记序号，仅展示
      "authoritySeq": 9,                         // 可选：权威源自身变更序号
      "effectiveOwner": "did:bns:waterflier",    // 权威源的 owner 绑定
      "migrationTarget": null,                   // migrated 时必填
      "reason": null,                            // invalid 时必填，人可读
      "checkedAt": 1751500100,                   // 可选
      "validUntil": 1751503700                   // 可选
    }
  }
}
```

### 版本轴只有 iat

`documentVersion` = 所描述版本的 `iat`。权威侧不引入独立版本序号；owner 侧 `valid_iat`（小于等于该值全部作废）与权威侧
当前发布 iat 用同一把尺子。`version_seq` 已退出流程，`registryVersion` 仅供展示。文档无法得出 iat 时省略 `documentVersion` /
`versionId`，不回落到登记序号。

### `docHash`

**编码后文档字符串**（JWT compact 原文，或 JSON 规范化序列化结果）的 sha256，hex，可带 `sha256:` 前缀，大小写不敏感。
current 查询 `active` 时必填；版本查询中 `selectedVersion.docHash` 必填。客户端用它核对 body、推导 closest（§7）和绑定 receipt。

### 时间维度字段

- `checkedAt`：该条目最近一次经权威源确认 / 写入 Zone 控制面的时刻。缺省时客户端以收到回答的本地时刻代替。
- `validUntil`：来源允许消费方视为新鲜的截止时刻；缺省由客户端按发布查询 TTL 处理。文档自身 `exp` 与它分开。

### 字段 ↔ 客户端类型

| JSON 字段 | `PublishInfo`（重构后，TODO D2） | 说明 |
| --- | --- | --- |
| `buckyos.docType` | `doc_type` | 实际类型 |
| `buckyos.documentStatus` | `type_state` / `did_state` | §4 |
| `buckyos.documentVersion` + `docHash` | `records[]` 中一条 `PublishRecord { iat, hash, is_latest }` | current 时 `is_latest = true` |
| `buckyos.latestIat` | `latest_iat` | |
| `buckyos.selectedVersion` / `boundaryConfirmed` | `records[]` + `boundary` | §7 |
| `buckyos.effectiveOwner` | `owner_binding` | 候选 `doc.owner` 必须与它一致 |
| `buckyos.migrationTarget` | `did_state = Migrated(target)` | |
| `buckyos.reason` | `type_state = Invalid(reason)` | |
| `buckyos.checkedAt` / `validUntil` | 查询回答的 `checked_at` / `valid_until` | |
| `didDocument` | `SourceAnswer.body` | 与 `publish_info` 分列缓存 |

旧草案的 `previousVersion` / `nextVersionId` / `lineageEpoch` / `ownerSource` / `authorityRoot` / `canonicalId` / `equivalentId` 不再消费。

## 4. `documentStatus` 状态机

| `documentStatus` | 语义 | 覆盖范围 | HTTP | `didDocument` | `deactivated` |
| --- | --- | --- | --- | --- | --- |
| `active` | 正常发布，`didDocument` / `docHash` 是当前版本 | 版本 | `200` | 必填（或仅 `docHash`） | `false` |
| `expired` | 曾发布，当前已过期 | 类型 | `200` | 可选 | `false` |
| `missing` | 权威源确认该 `(did, doc_type)` 从未发布，**强负证据，不是网络找不到** | 类型 | `404` | 无 | `false` |
| `invalid` | 权威源对该 `(did, doc_type)` 做过确定性校验并拒绝（例如 BNS 的 device / zone 身份不一致），`reason` 必填 | 类型 | `200` | 无 | `false` |
| `revoked` | 已被 owner / Registry 主动撤销 | 类型 | `410` | 可为 null | `true` |
| `tombstoned` | 永久注销，通常整个 name 被销毁 | DID | `410` | 可为 null | `true` |
| `migrated` | 已迁移到 `migrationTarget` | DID | `200` | 可选 | `false` |

客户端处理（设计稿 §2.2）：

- 负状态只覆盖它声明的范围：`missing` / `invalid` / `revoked` 是类型级，不自动等于整个 DID 禁用；`tombstoned` / `migrated` 是 DID 级。
- `invalid` 是**明确回答**，不是 Unknown：不触发退避，可缓存（短 TTL），选择时等同 `missing`，不阻止 trust / normal 候选按
  owner 链验签成为 best（坏的可能是关联文档而不是这份文档本身）。它的来历见 [cyfs-gateway#207](https://github.com/buckyos/cyfs-gateway/issues/207)：
  BNS 把确定性校验失败报成 502，客户端无法区分“权威说不对”和“权威没回答”。
- `revoked` / `tombstoned` 是终止性负状态，屏蔽一切兜底，只能被权威源新的已发布回答翻篇；resolver 一旦转入必须稳定返回 `410`。
- `migrated` 由调用方决定是否跟随，resolver 不自动跟随。

## 5. HTTP 状态码与错误的边界

**这是本协议最重要的安全约束**：确定性负判定与“网络不通 / 超时 / 内部错误”必须分开，否则要么把网络故障当成 `missing`
硬拒绝，要么把强负状态当成普通没查到而被兜底绕过。

| 场景 | HTTP | `name-client` 侧 |
| --- | --- | --- |
| 明确判定 `missing` | `404` + `documentStatus: "missing"` | 类型级负状态，可缓存 |
| 明确判定 `invalid` | `200` + `documentStatus: "invalid"` + `reason` | 类型级负状态，可缓存（短 TTL） |
| 明确判定 `revoked` / `tombstoned` | `410` + 对应 `documentStatus` | 终止性负状态 |
| 该 provider 对这个 method / name 没有意见（不适用） | `404`，body 省略 `buckyos` 块或没有 `documentStatus` | `NoAnswer`，不是负状态 |
| 不支持版本查询 | `501` + `"buckyos": {"historicalQuerySupported": false}` | `Unknown("此来源不支持指定版本/closest 查询")`，不可缓存为负状态，不回退 current（§7） |
| resolver 内部错误 / 上游不可用 / 投影变更 | `500` / `502` / `503` | `Unknown`，不可缓存为负状态；按目标 + 来源短期退避 |
| 请求超时 / 连接失败 | 无响应 | 同上；单个来源超时后在剩余预算内尝试下个允许来源 |
| 响应体不是合法 JSON / 缺必填字段 | 任意 | 该来源回答错误，不是负状态 |

**resolver 实现方的硬要求**：凡是能确定“这份数据不对”的校验失败（身份不一致、owner 不匹配、签名错误等）必须用 `invalid` 回答，
不得映射成 5xx。5xx 只留给真正的瞬时错误。

`404` 同时用于 `missing` 和“不适用”，靠 `buckyos.documentStatus` 区分，不能只看状态码。

## 6. 文档内容：内联 body 或 `docHash` 锚点

1. **内联**（推荐）：`didDocument` 携带完整文档（JsonLd 对象或 JWT 字符串）。
2. **锚点**：只给 `docHash`，body 由客户端从其它允许的来源取回；只有 hash 命中锚点的 body 才算该已发布版本。
   两者同时给出时客户端也校验内联 body 的 hash。

客户端已缓存的合法 body 可按新回答的精确 hash 复用，不必重复下载（设计稿 §3）。

## 7. 版本查询：`versionId` / `versionTime`

普通来源 JWT 的验签需要两份 Owner 文档：**当前 Owner**决定撤销线 `valid_iat`，**签发时刻之前最近已发布的 Owner**决定验签 key
（设计稿 §6）。后者就是 `closest(doc.iat)`。安装器等场景还需要 `exact(iat, hash)`。

### 7.1 `versionId={iat}`（exact）

回答中 `selectedVersion = { iat, docHash, published }`：

- `published: true`：该 iat 有已发布版本，`docHash` 必填，客户端用它核对输入；不符即 invalid。
- `published: false`：该 iat 从未发布，`docHash` 省略。这不是 `missing`：类型级 `documentStatus` 仍描述当前状态。
- `didDocument` 可选内联该版本。

### 7.2 `versionTime={iat}`（closest）

回答选出已发布版本中 `iat` **严格小于**查询值的最高者：

- `selectedVersion = { iat, docHash, published: true }`，`boundaryConfirmed: true` 表示 `(selected.iat, query)` 区间内没有已发布版本。
- 区间内没有任何版本（DID 当时还没发布）：`selectedVersion: null`，`boundaryConfirmed: true`。
- 回答仍带 `latestIat`。

### 7.3 从 current 回答推导（客户端规则，resolver 无需实现）

authority 的 current 回答 L = (`latestIat`, `docHash`, body) 已经证明 `(latestIat, +∞)` 没有已发布版本，因此客户端可以不发版本查询直接得出：

- 任意 `query_iat > latestIat`：`closest(query_iat) = L`，边界自动满足；
- `exact(iat, hash)` 且 `iat == latestIat && hash == docHash`：直接命中。

推导出的回答按完整查询分槽缓存，证据指向产生它的 current receipt，TTL 相同。只有 authority（或 locker 模拟发布）的回答能用于推导，
trust / normal 的 body 不能。`query_iat <= latestIat` 时必须发真正的 `versionTime` 查询。

### 7.4 不支持历史查询

resolver 没有历史索引时返回 `501` + `historicalQuerySupported: false`。客户端归一为 `Unknown` 并保留原因：

- **不**回退到当前 Owner 验签（2026-09 版的退化规则废除：当前 Owner 是否保留旧 key 不构成历史签名合法的依据）；
- 不当成 `missing`，也不当成 transport error 拒绝整条解析；
- 不满足 exact / closest 目标时报告保留“缺发布依据”，`success(revision)` 为 false。

501 的粒度先按整个 resolver 全有全无处理。

## 8. HTTP 文档响应头（DID Document carrier）

路径型对象的 URL 可以继续返回 HTML、旧 JSON、媒体等业务内容，旧客户端不受影响；新客户端从响应头提取完整 DID Document /
DID Object Card。语义见设计稿 §2.5，本节固定 binding。

```text
请求：GET https://example.com/user/alice
响应：
  200 OK
  Content-Type: text/html                      # 保持业务类型
  BuckyOS-DID-Document: jwt eyJhbGciOi...      # 或 json <base64url>
  ETag: "page-v12"                             # 属于业务 body，与 Card 无关
  body: <html>...</html>
```

| 项 | 规定 |
| --- | --- |
| 字段名 | `BuckyOS-DID-Document`，大小写不敏感（HTTP 头规则） |
| 值格式 | `<kind> <data>`，单个空格分隔。`kind` ∈ `jwt` \| `json` |
| `jwt` | `data` 为 JWT compact 原文（本身只含 base64url 字符和 `.`）。hash 对该原文计算 |
| `json` | `data` 为文档 JSON（UTF-8）的 base64url 无填充编码。解码后按既定规范化序列化计算 hash；不对 header 原文取 hash |
| 长度上限 | 单个头值不超过 16 KiB。超限按“该来源回答损坏”处理，不视为缺席 |
| 多次出现 | 同名头出现多于一次即损坏 |
| 缺席 | 返回 None，继续按 body 判断 |
| body 同时有文档 | 身份、类型、iat、hash 必须一致，否则拒绝本次来源回答；不按位置挑一份，也不写 DID 禁用。JWT 与 JSON 载体 hash 规则不同，混用视为不一致 |
| 普通业务 body | 没有声明为 DID Document 时不参与冲突比较；无可识别文档且无状态回答时保留“不提供 DID 文档”的原因，不把 200 业务内容当解析成功 |
| 与状态的关系 | 5xx 不因附带头变成成功；`invalid` / `revoked` 等明确负状态不能被头覆盖 |
| 信任 | 头只是载体：不提升来源等级，不自动产生 `is_published` / `is_signed`，不改变 publish_info 要求 |
| 缓存 | Card 的 iat / hash / exp 与业务 body 的 `ETag` / `Last-Modified` 分开；Card 更新必须让旧响应头可过期或重验，HTTP 缓存期限不能覆盖 Card 的 `exp` |
| 预算 | 取得头不要求完整下载业务 body；解析与解码受同一解析预算约束 |

`Link` 指向独立 Card 作为后续可选扩展，不替代本节。

## 9. Zone locker 的预算与防自选

zone-resolver-server 用同一套 `/1.0/identifiers/{did}` 信封回答（含 §7 版本查询，可在自己的 scope 内模拟发布）。它不是普通来源，
而是设计稿 §2.1 的 Zone locker。客户端请求时附加：

| 请求头 | 含义 |
| --- | --- |
| `BuckyOS-Resolve-Budget-Ms: <u64>` | 调用方剩余预算（毫秒）。服务端按自己的单调时钟取 `min(本地上限, 收到值)`，超时后终止无用工作。不传绝对时间戳 |
| `BuckyOS-Resolve-No-Zone-Lock: 1` | 服务端自己向外 resolve 时不得再选择 Zone locker（防自选）；它不证明底层传输无回流 |

服务端回答中 `checkedAt` / `validUntil` 必填，并可附 Zone 自身快照序号。客户端对 Zone locker 的 Unknown / 未覆盖继续向后查，
显式 `missing` / `invalid` / `revoked` 是强制回答。

## 10. 未决问题

1. **批量解析**：本版本不支持；单条 `(did, doc_type)` 契约不受影响。
2. **`NotApplicable` 复用 404**：靠 body 区分，待联调验证；必要时改用自定义响应头。
3. **`historicalQuerySupported: false` 的粒度**：先按整个 resolver 全有全无处理。
4. **`ambiguousDocType` 的错误码**：`400` 是否合适，待 bns-server 实现默认类型选择时确认。
5. **服务端排期**：`buckyos` 扩展块、§7 版本查询、`invalid` 状态、§8 响应头、§9 预算头都需要 bns-server / zone-resolver-server /
   DID Object Host 各自实现；客户端对缺省有完备兜底（当成 NoAnswer 或 501 Unknown）。
