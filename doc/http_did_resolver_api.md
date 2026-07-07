# HTTP DID Resolver API（草案）

> 面向读者：任何想在 HTTP 上实现一个符合 BuckyOS `resolve_did` 状态机语义的 did-resolver 的团队
>（bns-server 是第一个、也是目前唯一一个实现方，但协议本身**与 did:method 无关**——did:web 域名上
> 额外部署的动态 resolver endpoint、未来任何新 did:method 的 resolver，都可以照这份协议实现，
> `resolve_did` 那一侧不需要为每个 method 单独写一套解析逻辑）；以及未来在 `name-client` 里实现
> 对应 HTTP 客户端的维护者。
>
> **协议层面定位**：BuckyOS 目前（[resolve-did.md](./resolve-did.md)）有两类 did-resolver：
> 1）**基于 HTTP 的**（本文档）——method-agnostic，只要 resolver 能在 HTTP 上按本文档的约定应答，
>    `resolve_did` 就能拿到完整的 `PublishedState` 语义（Active/Missing/Revoked/Tombstoned/
>    Migrated/Expired、owner 一致性校验、历史 owner 查询）。
> 2）**基于 DNS 的**（`src/name-client/src/dns_provider.rs`）——功能非常受限：只能通过 TXT 记录里
>    `BOOT=`/`PKX=`/`DEV=` 几个约定表达 `owner`/`boot`/`zone`/device 几种固定 doc_type，
>    没有 `PublishedState` 状态机、没有负状态信令（Revoked/Tombstoned 无法表达），本质上是过渡期
>    兼容 `did:web` 老客户端的方案，不打算再扩展。
>
> 换句话说：**任何新 did:method，只要想要完整的验证/状态机语义，走的都应该是本文档定义的 HTTP
> 协议**，而不是给 DNS resolver 加字段，也不是给 `resolve_did` 加 method-specific 分支。
>
> 背景：[简单介绍resolve-did.md](./简单介绍resolve-did.md) 是解析语义的主规范
>（[resolve_did重构.md](./resolve_did重构.md) 是它的历史设计文档）。`resolve_did` 主循环里
> "权威源回答发布状态 + owner 绑定 + doc_hash"这一类回答,在 HTTP 上就按本文档的信封传递。
> **客户端（`name-client`）一侧已经按这份协议实现**：见下面的"落地状态"。
>
> **落地状态**：
> - **客户端（消费方）：已实现。** [`HttpsProvider::resolve_published_state`](../src/name-client/src/https_provider.rs)
>   直接发起 `GET /1.0/identifiers/{did}?type={doc_type}` 请求，按本文档 §3 的信封解析
>   `didDocumentMetadata.buckyos.*`；纯解析逻辑拆成 `parse_published_state_body`（见该文件
>   `#[cfg(test)] mod tests` 里的用例，直接用字面量状态码/JSON body 验证，不需要真的发请求）。
>   `resolve_published_state` 对任何走 `HttpsProvider` 的 did:method 都生效（不只是 BNS）;
>   一个 provider 是不是"权威源"由它在 method registry 里的注册位置决定
>   （`set_method_authority` / `add_method_supplement`），不再由 caps 声明。
>   `BnsProvider::resolve_published_state` 就是一行转发：
>   `self.inner.resolve_published_state(did, doc_type)`，本身不再有任何 transport 抽象或状态机
>   映射代码。
> - **服务端（resolver 实现方，例如 bns-server）：未实现。** 目前没有任何真实端点会在响应体里带
>   `buckyos` 扩展块，所以 `resolve_published_state` 在生产环境里会稳定拿到"没有 `buckyos` 扩展"
>   （见 §5"不适用"分支），`Ok(None)`，安全地回退到现有的 self-signed candidate 解析路径——
>   跟这份协议实现之前的行为完全一样。等 bns-server（或其它 resolver）按本文档实现了
>   `buckyos.*` 扩展，`HttpsProvider` 这边不需要再改一行代码。

## 1. 设计原则：复用现有端点，不新开一套

[resolve-did.md](./resolve-did.md) 第 13-20 行已经把"解析器 0"（BNS 合约的 HTTP 解析器）和"解析器 2"
（通用 HTTP DID 文档解析器，method-agnostic）定义成同一套 URL 约定：

```
GET https://{provider}/1.0/identifiers/{did}?type={doc_type}
```

`src/name-client/src/https_provider.rs` 的 `BaseHttpProvider`(以及 `WebProvider` 的 uppername 回退信道)已经在用这个约定发起
请求，对 `did:web` / `did:key` / `did:bns` 等任意 method 都适用（只负责拿到文档本身，`query_did`，
不带状态语义）；`BnsProvider::query_did` 目前是转发给 `HttpsProvider`
（[bns_provider.rs](../src/name-client/src/bns_provider.rs)，指向 `machine.json` 里
`web3_bridge.bns` 配置的 host；未配置时由可选 `sn_host` 派生为 `bns.{sn_host}`），
只是众多可能的具体部署之一。

**本协议不新增端点，也不区分 did:method**，而是让同一个 `GET /1.0/identifiers/{did}?type={doc_type}`
端点在响应体里携带 `PublishedState` 需要的状态信息——不管这个端点背后是 BNS 合约索引、did:web
域名额外部署的动态 resolver，还是未来某个新 method 的 resolver。理由：

1. 避免每个 resolver 实现方维护两套查询路径（拿文档一套、拿状态另一套）导致的不一致。
2. `HttpsProvider::parse_response`（[https_provider.rs:75-116](../src/name-client/src/https_provider.rs#L75-L116)）
   已经在尝试把响应体解析成 W3C DID Resolution Result（`didDocument` / `didDocumentMetadata.deactivated`），
   延续这个方向成本最低，而且天然 method-agnostic。
3. [resolve_did重构.md](./resolve_did重构.md) 第 1.4 节已经决定对外结果对齐 W3C
   `didResolutionMetadata` / `didDocument` / `didDocumentMetadata` 三段式，wire 协议理应对齐同一套，
   与 method 无关。
4. `resolve_did` 引擎侧的 `NsProvider::resolve_published_state` 也是 method-agnostic 的接口
   （一个 provider 服务哪个 method、是权威渠道还是补充源，由 method registry 的注册位置决定，
   而不是接口本身区分 method），协议层保持一致，未来加新 method 不需要改协议、
   只需要新增一个实现方。

### 1.1 与静态 `/.well-known/*` 发布面的边界

本文档定义的是 BuckyOS 的 HTTP resolver API：`/1.0/identifiers/{did}`。它可以返回 W3C DID
Resolution Result 信封，并在 `didDocumentMetadata.buckyos` 里放 BuckyOS 的发布状态扩展。

它**不是** W3C `did:web` 的静态发布路径。`did:web:example.com` 对应的
`https://example.com/.well-known/did.json` 必须返回裸 DID Document（JSON/JSON-LD 的 DID 文档本体），
不能返回包含 `didResolutionMetadata` / `didDocument` / `didDocumentMetadata` 的 resolution result
信封；否则标准 `did:web` resolver 会把根对象当成 DID Document 解析，进而失败。带路径的
`did:web:example.com:user:alice` 同理，对应 `https://example.com/user/alice/did.json`，也应返回裸
DID Document。这条 `did.json` 路径是 W3C 兼容基线，保持 JSON/JSON-LD，不用 JWT 替代。

BuckyOS 在同一个静态发布目录下扩展 `{doc_type}` 文件名，并允许文档 body 有 JSON/JSON-LD 或 JWT 两种
表示。路径格式是：

```text
https://{hostname}/.well-known/{doc_type}[.{representation}]
https://{hostname}/{did_path}/{doc_type}[.{representation}]

representation = json | jwt
```

- 无后缀的 `{doc_type}` 是自动识别入口，服务端可以返回 JSON/JSON-LD 或 JWT。
- `{doc_type}.json` 是强类型 JSON/JSON-LD 入口。
- `{doc_type}.jwt` 是强类型 JWT 入口。
- `doc_type` 本身只能使用 `[A-Za-z0-9_-]` 这类安全 token，不能包含 `.` 或 `/`，这样后缀解析没有歧义。
- BuckyOS client 不能只依赖 `Content-Type`；需要按 body 自动识别 JSON/JSON-LD 与 JWT。当前
  `EncodedDocument` 本身已经有 `JsonLd` / `Jwt` 两种表示，静态发布面和 resolver 信封里的
  `didDocument` 都遵循同一套识别规则。

同一个服务可以同时提供两类入口：

| 入口 | 用途 | 响应体 |
| --- | --- | --- |
| `/.well-known/did.json`、`/{did_path}/did.json` | W3C `did:web` 兼容入口 | JSON/JSON-LD 裸 DID Document |
| `/.well-known/{doc_type}[.json|.jwt]`、`/{did_path}/{doc_type}[.json|.jwt]` | BuckyOS 静态发布面 | 裸文档 body，JSON/JSON-LD 或 JWT，客户端自动识别 |
| `/1.0/identifiers/{did}?type={doc_type}` | BuckyOS / 通用 HTTP DID resolver API | DID Resolution Result 信封；必要时带 `didDocumentMetadata.buckyos` |

BuckyOS 扩展的 `/.well-known/{doc_type}*` 仍然属于静态发布面：它只能返回某个 doc_type 的文档本体，
不要把 §3 的状态信封塞到这里。需要 `Missing` / `Revoked` / `Tombstoned` / `Migrated` 这类状态语义时，
走 `/1.0/identifiers/{did}?type={doc_type}`。

## 2. 请求

```
GET {resolver_base}/1.0/identifiers/{did}?type={doc_type}&iat={unix_timestamp}
Accept: application/did-resolution
```

- `{did}`：完整 DID 字符串（如 `did:bns:waterflier`），**不做 percent-encode 处理内部的 `:`**，与
  `HttpsProvider::build_url` 现有行为一致。
- `{doc_type}`：可选 query 参数 `type`；缺省时约定为 `zone`（与 `DEFAULT_DID_DOC_TYPE` 一致）。
- `iat`：可选 query 参数，Unix 秒级时间戳。省略时查询"当前状态"（第 3-4 节）；携带时查询
  "在这个时间点生效的状态"，目前只用于 `type=owner`，见第 7 节。其它 `doc_type` 暂不要求支持这个
  参数（没有历史一致性校验的需求）。
- `Accept`：推荐使用 W3C DID Resolution 的 `application/did-resolution`，表示调用方希望拿到完整
  resolution result 信封，而不是只拿裸 DID Document。为了兼容当前 `name-client` 的实现，服务端实现
  BuckyOS 发布状态时，不能只依赖 `Accept` 才返回信封；在未携带 `Accept` 的 `/1.0/identifiers` 请求上，
  也应返回同样的信封（`query_did` 会自动拆出其中的 `didDocument`）。
- 幂等、无副作用，可以被 CDN/网关缓存（但 resolver 实现方自己要通过合适的 `Cache-Control` 控制 TTL，
  不能让 Revoked/Tombstoned 之后的旧响应被缓存层继续放出去；带 `iat` 的历史查询理论上可以被永久
  缓存，因为同一个 `iat` 的答案不应该再变化——除非 §7 描述的"退化成当前 owner"这条路径被触发）。

## 3. 响应信封

响应体是一个 W3C DID Resolution Result，外加一个 `buckyos` 扩展块（对应
[`BuckyOSDocumentMetadata`](../src/name-client/src/provider.rs)）放在 `didDocumentMetadata` 里：

```jsonc
{
  "didResolutionMetadata": {
    "contentType": "application/did+ld+json", // 或 "application/did+jwt"，取决于 didDocument 的编码
    "error": null                              // 见第 5 节；仅在错误时非空
  },
  "didDocument": { /* Active 时建议内联的 DID 文档（JsonLd 或 JWT 字符串），也可只给 docHash 锚点 */ },
  "didDocumentMetadata": {
    "versionId": "3",            // 字符串化的 document_version
    "deactivated": false,        // Revoked/Tombstoned 时为 true
    "buckyos": {
      "docType": "zone",
      "documentStatus": "active",   // active | missing | revoked | tombstoned | migrated | expired
      "documentVersion": 3,
      "authoritySeq": 9,
      "effectiveOwner": "did:bns:waterflier", // 权威源的 owner 绑定，可以不带文档本体单独返回
      "docHash": "sha256:...",      // 可选：已发布 body 的内容哈希锚点（编码后文档字符串的 sha256）
      "migrationTarget": null       // Migrated 时必填，目标 DID 字符串
    }
  }
}
```

### 字段 ↔ Rust 类型对照表

随 `PublishedState` 裁剪（resolve_did 简化,只保留有真实生产者/消费者的字段），客户端只消费下表
字段；旧草案中的 `previousVersion` / `nextVersionId` / `lineageEpoch` / `ownerSource` /
`authorityRoot` / `canonicalId` / `equivalentId` **不再被消费**，服务端可以不实现（返回了也会被
忽略，不会报错）。

| JSON 字段（camelCase） | Rust 字段（`PublishedState`，见 `https_provider.rs` 的 `BuckyosMetadataWire`） | 说明 |
| --- | --- | --- |
| `didDocumentMetadata.versionId` | `document_version` | 字符串化的 `u64`（`documentVersion` 的后备来源） |
| `didDocumentMetadata.buckyos.docType` | `doc_type` | |
| `didDocumentMetadata.buckyos.documentStatus` | `document_status`（`DocumentStatus` 枚举） | 见第 4 节映射 |
| `didDocumentMetadata.buckyos.documentVersion` | `document_version` | |
| `didDocumentMetadata.buckyos.authoritySeq` | `authority_seq` | |
| `didDocumentMetadata.buckyos.effectiveOwner` | `effective_owner`（`DID`） | 权威源的 owner 绑定；候选文档的 `doc.owner` 必须与它一致（expected_owner 硬规则） |
| `didDocumentMetadata.buckyos.docHash` | `document_ref.content_hash` | 已发布 body 的锚点；见第 6 节 |
| `didDocumentMetadata.buckyos.migrationTarget` | `migration_target`（`DID`） | 仅 Migrated 状态使用 |
| `didDocument` | `document_ref.inline_document` | 见第 6 节 |

## 4. `document_status` 状态机

| `documentStatus` | 语义 | HTTP 状态码 | `didDocument` | `deactivated` |
| --- | --- | --- | --- | --- |
| `active` | 正常发布，`didDocument` 是当前版本 | `200` | 必填 | `false` |
| `expired` | 曾发布，当前已过期（是否允许 fallback 由调用方 policy 决定，不是这里判断） | `200` | 可选（建议仍返回最后已知内容） | `false` |
| `missing` | 权威源确认该 `(did, doc_type)` 从未发布 —— **强负证据，不是网络找不到** | `404` | 无 | `false` |
| `revoked` | 该 `(did, doc_type)` 已被 owner/Registry 主动撤销 | `410` | 可为 null | `true` |
| `tombstoned` | 该 `(did, doc_type)` 已被永久注销（比 revoked 更终态，通常对应整个 name 被销毁） | `410` | 可为 null | `true` |
| `migrated` | 该 `(did, doc_type)` 已迁移到 `migrationTarget` | `200` | 可选（旧内容，仅供参考） | `false` |

对应 [`https_provider.rs`](../src/name-client/src/https_provider.rs) 里
`HttpsProvider::published_state_from_wire` 对 `documentStatus` 字符串的匹配分支——resolver
实现方按这张表把状态映射到对应的字符串/状态码即可，客户端这边已经按这份协议实现好了。

`Revoked` / `Tombstoned` 是强负状态（主循环策略点①）：解析引擎收到后终止查询、删除本地 positive
cache、**把负状态本身缓存下来**，之后的任何 fallback——过期缓存、自签名候选、push 写入——都会被它
屏蔽，只能被权威源新的"已发布"回答翻篇。resolver 实现方要保证一旦转入这两个状态，`GET` 必须稳定返回
`410`，不能因为缓存/多副本不一致而偶发地又吐出旧的 `200 active`。

## 5. HTTP 状态码与错误的边界（对应 T3.2）

**这是本协议最重要的安全约束**：`Missing` / `Revoked` / `Tombstoned` 必须是权威源的**明确判定**，
不能和"我这边网络不通/超时/内部错误"混在一起，否则会造成设计文档第 13 节明确禁止的两种误判：

- 真正的网络故障被误当成 `Missing`/`Revoked`，导致本该走 fallback 的场景被硬拒绝；
- 真正的强负状态因为暂时的网络抖动被 resolver 误判成普通"没查到"，从而被后续 fallback 悄悄绕过。

约定：

| 场景 | HTTP 语义 | `name-client` 侧处理 |
| --- | --- | --- |
| 明确判定 Missing | `404`，body 里 `documentStatus: "missing"` | 映射为 `Ok(Some(PublishedState { document_status: Missing, .. }))` |
| 明确判定 Revoked/Tombstoned | `410`，body 里对应 `documentStatus` | 映射为 `Ok(Some(PublishedState { document_status: Revoked/Tombstoned, .. }))` |
| 该 provider 对这个 method/name 没有意见（不适用） | 复用 `404`，但 body 省略 `buckyos` 块或没有 `documentStatus` 字段 | 映射为 `Ok(None)`（不是负状态） |
| resolver 内部错误 / 依赖的上游（链节点等）不可用 | `500`/`502`/`503` | `HttpsProvider::resolve_published_state` 返回 `Err(NSError::Failed(..))`，**绝不**映射成 Missing/Revoked |
| 请求超时 / 连接失败 | （无响应） | 同上，`Err(..)` |
| 响应体不是合法 JSON / 缺少必填字段 | 任意状态码 | 同上，`Err(NSError::Failed("malformed response"))`，视为 transport error，不是负状态 |

`404` 被同时用于 `Missing`（强负状态）和 `NotApplicable`（不适用，非负状态）两种语义，靠 body 里
`buckyos.documentStatus` 字段区分——**不能只看状态码**。如果联调后发现这个重载容易踩坑，可以考虑
`NotApplicable` 改用一个自定义响应头（如 `X-Buckyos-Not-Applicable: 1`）而不是复用 404，待实现阶段
根据实际情况再定。

## 6. 文档内容：内联 body 或 `docHash` 锚点

`PublishedState.document_ref` 在 Rust 里同时支持 `inline_document` 和 `content_hash` 两种形态
（[provider.rs](../src/name-client/src/provider.rs) 的 `DocumentRef`）。协议支持两种回答方式：

1. **内联**（推荐）：`didDocument` 字段直接携带完整文档内容（JsonLd 对象或 JWT 字符串）。
2. **锚点**（anchor-only）：`Active` 回答只携带 `buckyos.docHash`，body 由解析引擎从后续补充源
   取回；只有内容哈希命中锚点的 body 才被视为"属于已发布集合"，验签不通过锚点的候选一律作废
   （简化文档第 4 节的 hash 锚定执行点）。两者同时给出时，客户端也会对内联 body 做锚点校验。

`docHash` 的取值约定：**编码后文档字符串**（JWT 原文，或 JSON 序列化结果）的 sha256，hex 编码，
可带 `sha256:` 前缀，大小写不敏感（见 `provider.rs` 的 `document_content_hash`）。

外链 `uri` 拉取目前仍未实现（`DocumentRef.uri` 只有字段占位）；有真实需求时再补充。

## 7. 历史 owner 查询：`effective_owner_at(iat)`

owner 一致性校验（[resolve_did重构.md](./resolve_did重构.md) 第 5.1 节）理论上需要按签发时刻 `iat`
查历史 owner，而不是只看当前 owner——否则一份很久以前签发、当时合法的文档，会因为"现在"的 owner
已经变了而被误判成冲突。这里不新开端点，而是复用同一个 `type=owner` 查询，加第 2 节提到的 `iat`
参数：

```
GET {resolver_base}/1.0/identifiers/{did}?type=owner&iat={unix_timestamp}
```

- **省略 `iat`**：等价于查询当前状态（第 3-4 节的默认行为）。
- **携带 `iat`**：查询"在 `iat` 这个时间点谁是 owner、用的是哪把 key"。响应信封不变，但语义变成
  历史快照：
  - `didDocument`：`iat` 时刻**生效**的那个版本的 owner 文档（完整内容，包括当时的
    `verificationMethod`）——不是当前版本。如果之后发生过 key rotation 或 owner 变更（name 转让），
    这里应该返回变更前、对这个 `iat` 而言仍然 authoritative 的那一份，这样 resolver 才能同时拿到
    "当时的 owner 身份"和"当时签名用的 key"，不用再多发一次请求。
  - `didDocumentMetadata.buckyos.effectiveOwner`：`iat` 时刻的 owner DID（如果发生过 name 转让，
    可能和当前 owner 不同）。
  - `didDocumentMetadata.buckyos.documentVersion` / `lineageEpoch`：那个时间点对应的版本号/世代号，
    用于判断是否跨越了信任断点（设计文档第 7.1 节第 4 条：lineageEpoch 变化是信任断点）。

**resolver 不一定能回答历史查询**（取决于底层索引/存储是否保留了完整历史事件日志）。这种情况和"这个时间点
确实没有 owner"是两回事，不能混在一起返回同一个状态，否则会把一份合法文档误判成"当时没有 owner"
而拒绝：

| 情况 | HTTP 响应 | `name-client` 侧处理 |
| --- | --- | --- |
| 有历史索引，`iat` 时刻确实还没有 owner（DID 当时还不存在/还没注册） | `404`，`documentStatus: "missing"` | 按第 4 节当作真正的 `Missing` 处理 |
| 有历史索引，正常返回 `iat` 时刻的 owner 快照 | `200` | 按上面描述使用 |
| **没有历史索引能力**，无法回答"某个历史时刻"的查询 | `501 Not Implemented`，body 里 `"buckyos": {"historicalQuerySupported": false}` | 退化为使用**当前** owner（设计文档第 4 节："如果某个 method 无法提供历史 owner，只能退化为使用当前 owner 或拒绝需要历史一致性校验的文档"）——**不能**当成 transport error 直接拒绝整条解析，也不能当成 `Missing` |

用 `501` 专门表示"能力缺失，非错误、非负状态"，和第 5 节"网络/内部错误 → transport error"、
"明确判定 Missing → 404"分开，避免三种语义互相污染。

> 代码侧提醒（不在本文档范围内，留给后续实现）：目前 `verify_need_proof_candidate`
> （[name_query.rs](../src/name-client/src/name_query.rs)）的 expected_owner 用的是"当前
> `effectiveOwner` 绑定（或名字结构默认值）"，签名验证失败时对历史 key 是无差别地逐个尝试
> （`get_historical_keys()`），还没有把候选文档自己的 `iat` 传下去做时间点匹配。等这个端点真正
> 实现之后，应该把候选文档的 `iat` 带上，查询更精确的历史 owner/key，而不是"当前 owner
> + 历史 key 盲试"这种近似实现。这是一个独立的代码改动，不含在这次的文档变更里。

## 8. 未决问题

1. **批量解析**：目前是逐个 `(did, doc_type)` 查询；如果某个 resolver 实现方认为批量端点（例如一次性拿
   `did:bns:$zone` 的多个 doc_type）对性能更友好，可以后续加，不影响本文档已定义的单条查询契约。
  > 本版本协议不支持
2. **`NotApplicable` 复用 404 的问题**：见第 5 节，待联调验证。
3. **`historicalQuerySupported: false` 的粒度**：是整个 resolver 都不支持历史查询，还是可能对
   某些 DID/时间范围支持、对另一些不支持？如果是后者，第 7 节的表需要补一个更细的判断依据（例如
   "只保留最近 N 个版本的历史"），目前先当作全有全无处理。
4. **服务端实现排期**：客户端一侧（`HttpsProvider`）已经按本文档实现，见开头的"落地状态"。
   剩下的是 resolver 实现方（bns-server 或其它 method 的 resolver）什么时候在响应体里加上
   `buckyos` 扩展块——这是一个独立于本文档、需要各 resolver 自己排期的工作。
