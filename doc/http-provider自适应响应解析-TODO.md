# HTTP Provider 自适应响应解析 TODO

## 背景

`name-client` 的 `BaseHttpProvider` 同时承担两类查询：

1. `query_did`：获取 DID document 本体。
2. `resolve_published_state`：获取带 `documentStatus` / owner / version / hash 的
   `PublishedState`。

真实 resolver 的返回形式并不完全一致：

- 按 `Accept` 返回 DID Resolution Result JSON 信封；
- 忽略 `Accept`，直接返回裸 JSON/JSON-LD document；
- 直接返回裸 compact JWT；
- 信封的 `didDocument` 是 JSON object 或 JWT string；
- Content-Type 正确、缺失，或与 body 实际形式不一致；
- `404` / `410` 可以带状态信封，也可以是空 body。

2026-07-11 的 `devtest2` 激活回归暴露了一个典型问题：
`resolve_published_state` 未携带 DID Resolution `Accept` 时，SN 返回合法的裸 zone
JWT，客户端却强制按 JSON 信封解析，最终报
`expected value at line 1 column 1`。只补 `Accept` 头可以修复当前 SN，但还不足以让
HTTP provider 面对历史服务、第三方 resolver 和错误 Content-Type 时具有足够的
自适应能力。

## 目标

- 建立一个统一的 HTTP DID 响应归一化层，同时供 `query_did` 和
  `resolve_published_state` 使用。
- 自动识别所有已声明为合法的返回形式，不将 Content-Type 作为唯一
  判据。
- 保持 `Missing` / `Revoked` / `Tombstoned` 等强负状态的安全语义，不因
  “自适应”而吞掉错误或绕过权威否定。
- 新老 resolver 能在同一个 client 中并存，不需要按 did:method 编写格式分支。
- 解析失败时提供可诊断信息，但不把 JWT / DID document 全文写入日志。

## 非目标

- 不放宽 DID document 的签名、owner、doc type、版本或时间有效性校验。
- 不把任意 JSON、HTML 错误页或任意三段字符串当成合法 JWT。
- 不把 `5xx`、超时、TLS 失败或无法解析的 `200` 降级为 `Missing`。
- 不在 `BaseHttpProvider` 内实现 method-specific 逻辑。
- 不用 body sniffing 取代响应大小、重定向、TLS 和 URL 安全限制。

## 合法响应格式矩阵

### 1. 文档本体

| 格式 | 示例 | 归一化结果 |
| --- | --- | --- |
| 裸 JSON / JSON-LD object | `{ "id": "did:web:example.com", ... }` | `EncodedDocument::JsonLd` |
| 裸 compact JWT | `base64url.base64url.base64url` | `EncodedDocument::Jwt` |
| JSON string 包装的 compact JWT | `"base64url.base64url.base64url"` | `EncodedDocument::Jwt`（兼容格式） |
| DID Resolution Result + JSON document | `{ "didDocument": { ... }, ... }` | 拆出 `JsonLd` |
| DID Resolution Result + JWT document | `{ "didDocument": "a.b.c", ... }` | 拆出 `Jwt` |

文档本体必须在后续的 DID/document schema 与签名验证中通过。HTTP 格式识别
成功不代表文档已被信任。

### 2. 发布状态信封

| HTTP | body | 归一化结果 |
| --- | --- | --- |
| `200` | `documentStatus=active` + document/hash | `PublishedState::Active` |
| `200` | `documentStatus=expired` | `PublishedState::Expired` |
| `200` | `documentStatus=migrated` + target | `PublishedState::Migrated` |
| `404` | `documentStatus=missing` | `PublishedState::Missing` |
| `410` | `documentStatus=revoked` | `PublishedState::Revoked` |
| `410` | `documentStatus=tombstoned` | `PublishedState::Tombstoned` |
| `200`/`404` | 合法信封，但无 `buckyos.documentStatus` | `NotApplicable` |
| `404` | 空 body 或普通非状态错误 body | `NotApplicable`，不是强 `Missing` |

### 3. 发布状态查询收到文档本体

`resolve_published_state` 即使携带了 DID Resolution `Accept`，也可能收到裸 JSON
或裸 JWT。这两种 body 是合法文档，但不包含发布状态：

- 不应返回 `malformed resolver response`。
- 应归一化为“只有 document，无 PublishedState”。
- `resolve_published_state` 对外返回 `Ok(None)`。
- 现有 authority fallback 随后通过 `query_did` 取回文档本体，再按权威通道
  证据处理。

这条是 `devtest2` 问题的核心回归要求：服务端忽略 `Accept` 不得让
published-state 查询变成 transport error。

## Content-Type 与 body 识别规则

Content-Type 是提示，不是唯一真值。建议识别顺序：

1. 先根据 HTTP status 建立安全边界，`5xx` / 未声明的状态码不进入文档
   自适应解析。
2. 限制 body 大小，读取 bytes 后去除 UTF-8 BOM 和首尾 ASCII 空白。
3. 对以 `{`、`[`、`"` 开头的 body，或 JSON 类 Content-Type，先尝试 JSON
   解析。
4. JSON object 先按形状判定是 Resolution Result 还是裸 document：
   - 存在 `didResolutionMetadata` / `didDocument` / `didDocumentMetadata` 中任一信封字段，
     则按信封解析；
   - 否则按裸 JSON document 处理。
5. JSON string 只在内容通过 compact JWT 结构校验时转为 JWT。
6. JSON 解析不成功时，再尝试 compact JWT；JWT 至少要求：
   - 恰好三段；
   - header/payload 是非空 base64url；
   - header 能解码为 JSON object；
   - 完整签名与 document schema 校验仍由后续流程负责。
7. 两者都不匹配时明确报 malformed response，不返回 NotFound。

需要识别的 Content-Type 提示至少包括：

- `application/did-resolution`
- `application/did-resolution+json`
- `application/did+json`
- `application/did+ld+json`
- `application/json`
- `application/ld+json`
- `application/jwt`
- `application/did+jwt`
- `application/jose`
- `text/plain`（允许 body sniffing）
- `application/octet-stream`（允许 body sniffing，但必须通过格式硬校验）
- 缺失或无法识别的 Content-Type（允许 body sniffing）

Content-Type 声明为 JSON 但 body 是合法 JWT，或声明为 JWT 但 body 是合法
Resolution Result 时，应接受并记录一条不含 body 的格式不匹配警告。

## 统一归一化模型

新增内部类型（名称可在实现时调整）：

```rust
enum NormalizedHttpDidResponse {
    Document {
        document: EncodedDocument,
        envelope_metadata: Option<DidDocumentMetadataWire>,
    },
    PublishedState(PublishedState),
    NotApplicable,
    Negative {
        status: DocumentStatus,
        state: Option<PublishedState>,
    },
}
```

解析输入应包含：

```rust
struct HttpDidPayload {
    status: StatusCode,
    content_type: Option<String>,
    final_url: Url,
    body: Bytes,
}
```

`query_did` 和 `resolve_published_state` 只负责把统一结果折叠成各自的公开返回
类型，不再各自对 status/body 做一套形状猜测。

## HTTP 状态码安全规则

- `200..=299`：允许文档/信封自适应解析；空 body 是错误，除非未来协议
  明确定义某个状态码为 NotApplicable。
- `404`：
  - 带 `documentStatus=missing` 才是强 Missing；
  - 合法无状态信封、空 body 或普通 404 body 为 NotApplicable。
- `410`：必须有可解析的 `revoked` / `tombstoned` 状态信封；空 410 不得
  凭空猜测具体强负状态，应作为显式错误或按既有 `Disabled` 兼容策略处理。
- `401` / `403`：映射为认证/授权失败，不是 Missing。
- `408` / `429` / `5xx`：临时性 transport/upstream error，不得进入负缓存。
- 重定向：使用 reqwest 明确配置的有限次数策略；禁止 HTTPS 降级到 HTTP，
  本地测试 profile 显式允许时除外。

## 安全与资源限制

- 为 resolver body 设定硬上限，默认值与 DID document/JWT 产品限制对齐，并
  为信封额外预留有界开销。
- 拒绝含 NUL 的文本 body；只接受 UTF-8 JSON 和 ASCII-compatible compact JWT。
- 日志只记录：HTTP status、Content-Type、body 长度、识别形状、最终 URL host、
  DID/doc_type 和错误类型。不记录 body、JWT、owner key 或完整 query token。
- JSON 信封内同时出现互相矛盾的状态时 fail closed，例如：
  - HTTP `200` + `documentStatus=revoked`；
  - HTTP `410` + `documentStatus=active`；
  - `deactivated=true` + `documentStatus=active`；
  - `docType` 与请求 doc type 不一致。
- 不跟随信封中未验证的任意 URL；`migrationTarget` 只作 DID 处理，继续遵循
  resolver policy。

## 实现阶段

### Phase 0：固化现场回归

- [x] 增加 `200 + application/jwt + bare JWT` 输入
  `parse_published_state` 的回归：结果是 `Ok(None)`，不是 malformed error。
- [x] 增加 SN 内容协商回归：
  - 不带 `Accept` 返回裸 JWT；
  - `Accept: application/did-resolution+json` 返回 JSON 信封；
  - 两种都能由同一 client 完成 zone document 解析。
- [x] 保留 `published_state_request_asks_for_resolution_envelope` 请求头测试，但不把服务端
  正确实现 `Accept` 当作 client 能正常工作的必要条件。

### Phase 1：引入统一解析器

- [x] 引入 `HttpDidPayload` 和 `NormalizedHttpDidResponse`。
- [x] 把 response body 的读取、大小限制、BOM/whitespace 处理收敛到一处。
- [x] 把信封识别、裸 JSON 识别、JWT 识别和 status 校验收敛到一处。
- [x] `parse_response_body` 和 `parse_published_state_body` 改为对统一结果的薄适配器。

### Phase 2：补齐信封语义

- [x] 解析 `didResolutionMetadata.error`，建立与 HTTP status / `documentStatus` 的一致性
  规则。
- [x] 支持 `didDocument: null` 的合法负状态信封。
- [x] 统一 `versionId` / `documentVersion`、`effectiveOwner`、`docHash`、
  `migrationTarget` 的解析和错误上下文。
- [x] 对未知扩展字段保持向前兼容；对未知 `documentStatus` fail closed。

### Phase 3：Content-Type 自适应

- [x] 实现 Content-Type 分类器，忽略大小写和参数（如 `charset=utf-8`）。
- [x] 实现 Content-Type 与 body 形状的交叉验证和无敏感信息警告。
- [x] 确保 Content-Type 错误/缺失时仍可识别合法 body，但非法 body 不会被猜成
  JWT。

### Phase 4：状态码、重定向与资源限制

- [x] 为 `401/403/408/429/5xx` 建立稳定的 `NSError` 映射。
- [x] 对 `404` 的 Missing 与 NotApplicable 开发专门矩阵测试。
- [x] 对 `410` 的信封一致性做硬校验。
- [x] 增加 body size limit、redirect limit 和 HTTPS downgrade 防护。

### Phase 5：观测性

- [x] 为每次响应记录结构化诊断字段：`status`、`content_type`、`body_len`、
  `detected_shape`、`did_method`、`doc_type`、`provider_id`。
- [x] 为“Content-Type 与 body 不一致”、“状态信封退化为 document-only”、“非法 body”
  分别建立可聚合的错误码。
- [x] 测试日志不包含 JWT body 和 key material。

### Phase 6：集成和发布

- [x] 在 `buckyos-base` 跑 `cargo test -p name-client --lib -- --test-threads=1`。
- [ ] 在 `cyfs-gateway` 使用 SN resolver 的真实 HTTP 响应跑集成测试。
- [ ] 在 BuckyOS node activation 中验证 `zone` / `boot` / device document 三类 JWT。
- [ ] 更新 `buckyos` 和 `cyfs-gateway` 的 `Cargo.lock` 到新 `buckyos-base` revision。
- [ ] 在 VM 中验证服务端遵守和忽略 `Accept` 两种情况。

## 必要测试矩阵

下列每个用例都要分别覆盖 `query_did` 和 `resolve_published_state`，除非表中明确
只属于其中一条路径。

| HTTP | Content-Type | body | 预期 |
| --- | --- | --- | --- |
| 200 | application/json | 裸 JSON doc | document / published state None |
| 200 | application/jwt | 裸 JWT | document / published state None |
| 200 | application/json | JSON string JWT | JWT / published state None |
| 200 | did-resolution+json | 信封 + JSON doc + Active | document + Active state |
| 200 | did-resolution+json | 信封 + JWT doc + Active | JWT + Active state |
| 200 | application/jwt | 实际是 JSON 信封 | 识别成信封，记 mismatch warning |
| 200 | application/json | 实际是 JWT | 识别成 JWT，记 mismatch warning |
| 200 | 缺失 | 裸 JSON / JWT / 信封 | 均能识别 |
| 200 | text/html | HTML | malformed，不是 NotFound |
| 200 | 任意 | 空 body | malformed |
| 404 | application/json | Missing 信封 | Missing |
| 404 | application/json | 无 buckyos/status 信封 | NotApplicable |
| 404 | text/plain | 空/普通 not found | NotApplicable |
| 410 | application/json | Revoked 信封 | Revoked |
| 410 | application/json | Tombstoned 信封 | Tombstoned |
| 410 | application/json | Active 信封 | 协议矛盾错误 |
| 500/502/503 | 任意 | JSON/HTML/空 | transport/upstream error |
| 429 | 任意 | 任意 | retryable error，不写负缓存 |
| 200 | octet-stream | 超限 body | body-too-large |
| 200 | application/json | 含 NUL / 非 UTF-8 | malformed |

## 验收标准

- [x] `BaseHttpProvider` 只有一套 status/header/body 格式归一化逻辑。
- [x] 合法的裸 JSON、裸 JWT、JSON-string JWT、JSON 信封中的 JSON/JWT 都能自动识别。
- [x] `resolve_published_state` 收到合法裸 document 时返回 `Ok(None)`，不会产生
  malformed error。
- [x] Content-Type 缺失或错误不会阻止合法 body 解析。
- [x] HTML、空 2xx、过大 body、非法 JSON/JWT 不会被接受。
- [x] `5xx` / timeout / TLS 错误不会变成 Missing/Revoked 或进入负缓存。
- [x] Missing/Revoked/Tombstoned 只能由状态码与信封相互一致的权威响应产生。
- [x] 日志可以区分响应形状和失败原因，但不泄露 document/JWT/key。
- [ ] `name-client` 全量单测、SN HTTP resolver 集成测试和 node activation VM 回归全部通过。

## 相关文档与实现

- [`http_did_resolver_api.md`](./http_did_resolver_api.md)
- [`resolve-did.md`](./resolve-did.md)
- [`src/name-client/src/https_provider.rs`](../src/name-client/src/https_provider.rs)
- [`src/name-client/src/provider.rs`](../src/name-client/src/provider.rs)
- [`src/name-client/src/name_query.rs`](../src/name-client/src/name_query.rs)
- `cyfs-gateway/src/components/cyfs-sn/src/sn_did_resolver.rs`
