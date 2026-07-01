# BNS HTTP Resolver API（草案）

> 面向读者：实现 bns-server 的 did-resolver HTTP 端点的团队，以及未来在 `name-client` 里实现
> `BnsResolveTransport` 的维护者。
>
> 背景：[resolve_did重构.md](./resolve_did重构.md) 把 `resolve_did` 升级为围绕 `PublishedState`
> 状态机的解析引擎；[resolve_did重构_TODO.md](./resolve_did重构_TODO.md) Phase 3（T3.1/T3.2）在
> `src/name-client/src/bns_provider.rs` 里把 `BnsProvider::resolve_published_state` 的状态机
> 映射逻辑和单测跑通了，但只定义到 Rust 层的 `BnsResolveTransport` trait 为止——**没有对接任何真实
> HTTP 请求**。本文档要补的就是这一段：bns-server 需要实现的、`HttpBnsResolveTransport`（尚未实现）
> 需要调用的 HTTP 契约。
>
> 状态：**草案，未实现、未联调**。current: `BnsProvider::new()` 不配置 transport，
> `resolve_published_state` 恒返回 `Ok(None)`，行为上等价于"这个能力还没开"，安全地回退到现有的
> self-signed candidate 解析路径。这份文档定稿、双方对齐之后，才应该开始实现
> `HttpBnsResolveTransport` 和 bns-server 对应的端点。

## 1. 设计原则：复用现有端点，不新开一套

[resolve-did.md](./resolve-did.md) 第 13-20 行已经把"解析器 0"（BNS 合约的 HTTP 解析器）和"解析器 2"
（通用 HTTP DID 文档解析器）定义成同一套 URL 约定：

```
GET https://{provider}/1.0/identifiers/{did}?type={doc_type}
```

`src/name-client/src/https_provider.rs` 的 `HttpsProvider` 已经在用这个约定发起请求，`BnsProvider::query_did`
目前也是转发给它（[bns_provider.rs](../src/name-client/src/bns_provider.rs) 的 `query_did`，指向
`machine.json` 里 `web3_bridge.bns` 配置的 host）。

**本协议不新增端点**，而是让同一个 `GET /1.0/identifiers/{did}?type={doc_type}` 端点在响应体里携带
`PublishedState` 需要的状态信息。理由：

1. 避免 bns-server 维护两套查询路径（拿文档一套、拿状态另一套）导致的不一致。
2. `HttpsProvider::parse_response`（[https_provider.rs:75-116](../src/name-client/src/https_provider.rs#L75-L116)）
   已经在尝试把响应体解析成 W3C DID Resolution Result（`didDocument` / `didDocumentMetadata.deactivated`），
   延续这个方向成本最低。
3. [resolve_did重构.md](./resolve_did重构.md) 第 1.4 节已经决定对外结果对齐 W3C
   `didResolutionMetadata` / `didDocument` / `didDocumentMetadata` 三段式，wire 协议理应对齐同一套。

## 2. 请求

```
GET {resolver_base}/1.0/identifiers/{did}?type={doc_type}
Accept: application/did-resolution+json
```

- `{did}`：完整 DID 字符串（如 `did:bns:waterflier`），**不做 percent-encode 处理内部的 `:`**，与
  `HttpsProvider::build_url` 现有行为一致。
- `{doc_type}`：可选 query 参数 `type`；缺省时约定为 `zone`（与 `DEFAULT_DID_DOC_TYPE` 一致）。
- 幂等、无副作用，可以被 CDN/网关缓存（但 bns-server 自己要通过合适的 `Cache-Control` 控制 TTL，
  不能让 Revoked/Tombstoned 之后的旧响应被缓存层继续放出去）。

## 3. 响应信封

响应体是一个 W3C DID Resolution Result，外加一个 `buckyos` 扩展块（对应
[`BuckyOSDocumentMetadata`](../src/name-client/src/provider.rs)）放在 `didDocumentMetadata` 里：

```jsonc
{
  "didResolutionMetadata": {
    "contentType": "application/did+ld+json", // 或 "application/did+jwt"，取决于 didDocument 的编码
    "error": null                              // 见第 5 节；仅在错误时非空
  },
  "didDocument": { /* Active/Expired 时必填，内联的 DID 文档（JsonLd 或 JWT 字符串） */ },
  "didDocumentMetadata": {
    "versionId": "3",            // 字符串化的 document_version
    "nextVersionId": null,       // 只有确实知道下一版时才填
    "canonicalId": null,
    "equivalentId": [],
    "deactivated": false,        // Revoked/Tombstoned 时为 true
    "buckyos": {
      "docType": "zone",
      "documentStatus": "active",   // active | missing | revoked | tombstoned | migrated | expired
      "documentVersion": 3,
      "previousVersion": 2,
      "lineageEpoch": 1,
      "authoritySeq": 9,
      "effectiveOwner": "did:bns:waterflier",
      "ownerSource": "methodAuthority", // methodAuthority | documentClaim | unknown
      "authorityRoot": "0x...",         // 合约/证明根的十六进制哈希，可为 null
      "migrationTarget": null           // Migrated 时必填，目标 DID 字符串
    }
  }
}
```

### 字段 ↔ Rust 类型对照表

| JSON 字段（camelCase） | Rust 字段（`PublishedState` / `BnsActiveRecord`） | 说明 |
| --- | --- | --- |
| `didDocumentMetadata.versionId` | `document_version` | 字符串化的 `u64` |
| `didDocumentMetadata.nextVersionId` | `next_version` | 只有能证明下一版时才填 |
| `didDocumentMetadata.buckyos.docType` | `doc_type` | |
| `didDocumentMetadata.buckyos.documentStatus` | `document_status`（`DocumentStatus` 枚举） | 见第 4 节映射 |
| `didDocumentMetadata.buckyos.documentVersion` | `document_version` / `BnsActiveRecord.version` | |
| `didDocumentMetadata.buckyos.previousVersion` | `previous_version` | |
| `didDocumentMetadata.buckyos.lineageEpoch` | `lineage_epoch` | 世代变化是信任断点（设计文档 7.1 第 4 条） |
| `didDocumentMetadata.buckyos.authoritySeq` | `authority_seq` | |
| `didDocumentMetadata.buckyos.effectiveOwner` | `effective_owner`（`DID`） | 完整 DID 字符串，如 `did:bns:alice` |
| `didDocumentMetadata.buckyos.ownerSource` | `owner_source`（`OwnerSource` 枚举） | 见下方取值 |
| `didDocumentMetadata.buckyos.authorityRoot` | `authority_root` | |
| `didDocumentMetadata.buckyos.migrationTarget` | `migration_target`（`DID`） | 仅 Migrated 状态使用 |
| `didDocumentMetadata.canonicalId` / `equivalentId` | `canonical_id` / `equivalent_ids` | 只有同 method 强等价时才填，见设计文档 1.4 |
| `didDocument` | `document_ref.inline_document` | 见第 6 节 |

`ownerSource` 取值：`methodAuthority`（Registry 直接给出）、`documentClaim`（退化到文档自声明）、
`unknown`（无法判断，`BnsProvider` 会当作待验证处理）。

## 4. `document_status` 状态机

| `documentStatus` | 语义 | HTTP 状态码 | `didDocument` | `deactivated` |
| --- | --- | --- | --- | --- |
| `active` | 正常发布，`didDocument` 是当前版本 | `200` | 必填 | `false` |
| `expired` | 曾发布，当前已过期（是否允许 fallback 由调用方 policy 决定，不是这里判断） | `200` | 可选（建议仍返回最后已知内容） | `false` |
| `missing` | 权威源确认该 `(did, doc_type)` 从未发布 —— **强负证据，不是网络找不到** | `404` | 无 | `false` |
| `revoked` | 该 `(did, doc_type)` 已被 owner/Registry 主动撤销 | `410` | 可为 null | `true` |
| `tombstoned` | 该 `(did, doc_type)` 已被永久注销（比 revoked 更终态，通常对应整个 name 被销毁） | `410` | 可为 null | `true` |
| `migrated` | 该 `(did, doc_type)` 已迁移到 `migrationTarget` | `200` | 可选（旧内容，仅供参考） | `false` |

对应 `src/name-client/src/bns_provider.rs` 里的 `BnsResolveResponse` 枚举：`Active` / `Expired` /
`Missing` / `Revoked` / `Tombstoned` / `Migrated { target }`。`HttpBnsResolveTransport`（待实现）
应该按这张表把 HTTP 响应解析成这个枚举，再交给已经写好的 `BnsProvider::map_response` 做状态机映射——
**不需要、也不应该在 transport 层重新实现一遍状态机语义**。

`Revoked` / `Tombstoned` 是强负状态：解析引擎收到后会直接拒绝并清掉本地 fallback cache（
`resolve_from_published_state` 里 `DocumentStatus::Revoked | Tombstoned` 分支），**不允许**被后续
self-signed candidate 或本地 cache 绕过。bns-server 端要保证一旦转入这两个状态，`GET` 必须稳定返回
`410`，不能因为缓存/多副本不一致而偶发地又吐出旧的 `200 active`。

## 5. HTTP 状态码与错误的边界（对应 T3.2）

**这是本协议最重要的安全约束**：`Missing` / `Revoked` / `Tombstoned` 必须是权威源的**明确判定**，
不能和"我这边网络不通/超时/内部错误"混在一起，否则会造成设计文档第 13 节明确禁止的两种误判：

- 真正的网络故障被误当成 `Missing`/`Revoked`，导致本该走 fallback 的场景被硬拒绝；
- 真正的强负状态因为暂时的网络抖动被 resolver 误判成普通"没查到"，从而被后续 fallback 悄悄绕过。

约定：

| 场景 | HTTP 语义 | `name-client` 侧处理 |
| --- | --- | --- |
| 明确判定 Missing | `404`，body 里 `documentStatus: "missing"` | 映射为 `BnsResolveResponse::Missing`（`Ok(...)`） |
| 明确判定 Revoked/Tombstoned | `410`，body 里对应 `documentStatus` | 映射为 `Ok(BnsResolveResponse::Revoked/Tombstoned)` |
| 该 provider 对这个 method/name 没有意见（不适用） | 复用 `404`，但 body 省略 `buckyos` 块或显式给 `"documentStatus": null` | 映射为 `BnsResolveResponse::NotApplicable`（`Ok(...)`，不是负状态） |
| bns-server 内部错误 / 依赖的链节点不可用 | `500`/`502`/`503` | `HttpBnsResolveTransport` 返回 `Err(NSError::Failed(..))`，**绝不**映射成 Missing/Revoked |
| 请求超时 / 连接失败 | （无响应） | 同上，`Err(..)` |
| 响应体不是合法 JSON / 缺少必填字段 | 任意状态码 | 同上，`Err(NSError::Failed("malformed response"))`，视为 transport error，不是负状态 |

`404` 被同时用于 `Missing`（强负状态）和 `NotApplicable`（不适用，非负状态）两种语义，靠 body 里
`buckyos.documentStatus` 字段区分——**不能只看状态码**。如果联调后发现这个重载容易踩坑，可以考虑
`NotApplicable` 改用一个自定义响应头（如 `X-Buckyos-Not-Applicable: 1`）而不是复用 404，待实现阶段
根据实际情况再定。

## 6. 文档内容：v1 只要求内联，不做外链 content-hash 拉取

`PublishedState.document_ref` 在 Rust 里同时支持 `inline_document` 和 `uri + content_hash` 两种形态
（[provider.rs](../src/name-client/src/provider.rs) 的 `DocumentRef`），但**这份协议的 v1 版本只要求
内联**：`didDocument` 字段直接携带完整文档内容（JsonLd 对象或 JWT 字符串）。

理由：外链 + content-hash 校验需要额外一次网络往返和一套独立的 hash 校验逻辑，`fetch_document_body`
目前的默认实现也只处理内联情形（见 `BnsProvider::fetch_document_body` 里的注释）。等确认有大文档
（超过合理的响应体大小）需要外链时，再补充：

```jsonc
"buckyos": {
  "documentRefUri": "https://.../blob/abcd1234",
  "contentHash": "sha256:...."
}
```

并在 `name-client` 里实现对应的外链拉取 + hash 校验（目前代码里只有字段占位，没有实现，见
`DocumentRef` 定义处的注释）。

## 7. 未决问题

1. **`effective_owner_at(iat)`**：本文档目前只描述"当前状态"的查询。owner 一致性校验
   （[resolve_did重构.md](./resolve_did重构.md) 第 5.1 节）理论上需要按 `iat` 查历史 owner，但 v1
   协议没有定义历史查询端点。在这个端点补上之前，`name-client` 只能按"当前 `effectiveOwner`"做比较
   （见 `verify_owned_candidate` 里的 `OwnerConflict` 检查），退化路径已经在设计文档第 4 节写明。
2. **批量解析**：目前是逐个 `(did, doc_type)` 查询；如果 bns-server 认为批量端点（例如一次性拿
   `did:bns:$zone` 的多个 doc_type）对性能更友好，可以后续加，不影响本文档已定义的单条查询契约。
3. **`NotApplicable` 复用 404 的问题**：见第 5 节，待联调验证。
4. **谁来发起首次实现**：这份文档定稿后，`name-client` 侧需要新增一个真正发 HTTP 请求的
   `HttpBnsResolveTransport`（实现 `BnsResolveTransport` trait，[bns_provider.rs](../src/name-client/src/bns_provider.rs)），
   替换掉当前 `BnsProvider::new()` 默认的 `transport: None`；这个改动本文档不包含，需要单独排期。
