# verify_did_document_jwt 需求文档

## 背景

应用层经常会收到一份 DID Document JWT, 例如 RTCP 握手里携带的
`device_doc_jwt`。当前上层容易写成以下流程:

1. 不验签解出 JWT payload。
2. 从 payload 的 `owner`/`iss` 取 owner DID。
3. 调 `resolve_auth_key(owner)` 取得公钥。
4. 用该公钥验证 JWT。

这个流程只能证明"JWT 能被它自己声明的 owner 验过", 不能证明"该
Document 的 DID 在名字系统里确实归这个 owner 管"。如果名字系统允许 BNS
owner binding 变更, 或者允许客体文档存在 detached owner, 上层很容易把
"可验签"误当成"可信主体"。

更隐蔽的问题发生在授权阶段: 跨 zone 权限通常基于来源 subject 的 owner,
例如"alice 的 laptop"。如果应用把 `did:bns:laptop.alice` 直接截取成
`did:bns:alice` 做权限主体, 但底层实际 owner binding 已被改成别的 owner,
就可能出现"认证通过, 授权主体错误"的越权。

因此需要在 name-client 底层提供一个面向应用的统一入口:
`verify_did_document_jwt`。这个入口不是重新发明一套验证流程, 而是把当前
`resolve_did` 中 `NeedProof` 候选文档的验证语义封装给"外部已经拿到 JWT"
的场景使用。

## 依据和现状

本文按以下现有实现和文档校准术语:

1. 主规范: [简单介绍resolve-did.md](./简单介绍resolve-did.md)。
2. HTTP 状态协议: [http_did_resolver_api.md](./http_did_resolver_api.md)。
3. 现有实现:
   - `src/name-client/src/provider.rs`
   - `src/name-client/src/name_query.rs`
   - `src/name-client/src/name_client.rs`
   - `src/name-client/src/doc_cache.rs`
   - `src/name-lib/src/did.rs`
   - `src/name-lib/src/user.rs`

现有 `resolve_did` 已经实现了核心安全规则:

```text
doc.id == did
doc.owner/iss == expected_owner
hash 匹配, 如果权威源提供 doc_hash
使用 expected_owner 的 OwnerDocument 验签
OwnerDocument replay guard: valid_iat / mini_version_seq
默认 key 失败后尝试 historical keys, 成功时返回 SignedByHistoricalKey
```

`verify_did_document_jwt` 要解决的是: 当应用已经有一份外部 JWT 时, 不让应用
绕过这些规则自己拼 `payload.owner -> resolve_auth_key -> verify`。

## 目标

`verify_did_document_jwt` 必须完成外部 DID Document JWT 的完整信任判断, 并返回
可直接进入权限系统的结构化身份上下文。

必须保证:

1. 上层不需要自己解析 `doc.owner -> OwnerDocument -> key`。
2. 验签使用的 owner 必须来自权威 owner binding 或 method 结构规则, 不能来自未验证文档自声明。
3. 默认主体认证策略下, 能进入权限系统作为主语的 subject 不允许 detached owner。
4. 返回值明确区分 `subject_did`, `structural_owner`, `authority_owner`, `expected_owner`, `declared_owner`。
5. 支持"当前必须合法"和"签发时曾经合法"两类校验语义, 其中历史语义必须显式依赖 resolver 历史查询能力。
6. OwnerDocument 的 revoke/replay guard 由底层统一应用。

## 非目标

1. 不替代普通业务 JWT 的 `verify-jwt`。普通 JWT 可以继续由调用方提供可信 key map。
2. 不在应用层暴露"根据 payload.iss 自动 resolve key"的便捷 API。
3. 不把业务授权策略写进 name-client。name-client 只输出可信身份上下文。
4. 不要求所有客体文档都满足主体认证约束。客体解析可以显式允许 detached owner。
5. 不在本 API 中实现 RTCP 对端持有 Device 私钥的握手证明。该 API 只验证 DeviceDocument JWT 本身。

## 核心概念

### subject_did

JWT 证明的文档主体 DID, 即 Document 的 `id`。调用方必须显式提供期望 DID,
底层解析 JWT 后检查:

```text
payload.id == did
```

不相等直接失败。认证入口中不应允许只从 JWT payload 自动取 subject。

### structural_owner

由 DID method 的名字结构确定性推出的默认 owner。旧草案里的
`visible_owner` 应改称 `structural_owner`, 以避免应用层误以为可以自行字符串截取。

当前实现对应 `src/name-client/src/provider.rs` 的 `structural_owner(did)`:

```rust
pub fn structural_owner(did: &DID) -> Option<DID> {
    match did.method.as_str() {
        "bns" => did.upper_did(),
        _ => None,
    }
}
```

要点:

1. 目前只有 `did:bns` 定义结构 owner。
2. `did:bns:app1.alice` 的 `structural_owner` 是 `did:bns:alice`。
3. `did:bns:alice` 是一级名字, 从结构里推不出 owner, 返回 `None`。
4. `DID::upper_did()` 虽然能计算部分 `did:web` 上级域名, 但 `did:web` 当前不把上级域名定义为 owner。

示例:

| DID | structural_owner |
| --- | --- |
| `did:bns:alice` | `None` |
| `did:bns:laptop.alice` | `Some(did:bns:alice)` |
| `did:bns:a.b.c` | `Some(did:bns:b.c)` |
| `did:web:ood1.example.com` | `None` |

### authority_owner

权威源返回的 owner binding, 对应 Rust `PublishedState.effective_owner` 和 HTTP
wire 字段 `didDocumentMetadata.buckyos.effectiveOwner`。

本文用 `authority_owner` 指代这个值, 避免把它和最终用于验签的
`expected_owner` 混在一起。代码字段仍然可以叫 `effective_owner`, 但 API 文档
必须解释清楚:

```text
authority_owner = PublishedState.effective_owner
```

### expected_owner

本次验证实际使用的 owner, 只能由候选 JWT 之外的信息决定:

```text
expected_owner = authority_owner.or(structural_owner)
```

规则:

1. `authority_owner` 存在时优先使用它。
2. `authority_owner` 不存在但 `structural_owner` 存在时, 使用 `structural_owner`。
3. 两者都不存在时, `NeedProof` JWT 不能被验证为可信主体。
4. `expected_owner` 绝不能来自 `payload.owner` / `payload.iss`。

### declared_owner

JWT payload 中声明的 owner。对现有 `DeviceDocument` / `ZoneDocument` / `AgentDocument`
等文档, 它来自文档里的 `owner` 字段, 通过 `DIDDocumentTrait::get_iss()` 暴露。

它只是待校验字段:

```text
declared_owner == expected_owner
```

不一致说明 JWT 正在声明未经权威源或 method 规则承认的 owner 关系, 必须失败。

`OwnerDocument` 是特殊递归基, `get_iss()` 当前返回 `None`。验证外部
`DidDocType::Owner` JWT 时不能再递归拿 owner 自己验 owner, 必须依赖 method
authority 的 anchored/current membership。

### authz_owner

权限系统使用的 owner 维度主体。对 `AuthSubject` 场景:

```text
authz_owner = expected_owner
```

但只有 `usable_as_authz_subject == true` 时才能使用。客体文档即使验签通过, 也不得
直接进入 RBAC 或应用内 ACL 作为权限主语。

### BodyEvidence 和 CacheEvidence

需求文档应复用现有实现里的证据术语。

`BodyEvidence` 描述文档 body 是从什么信道取回的:

| BodyEvidence | 含义 |
| --- | --- |
| `Anchored` | 权威信道或权威锚点取回, `need_proof = false` |
| `NeedProof` | 补充信道或外部输入的候选 JWT, 必须完整 verify |
| `UnproofInfo` | method 契约声明的免验证 Info 类 doc_type |

`CacheEvidence` 描述本机 did_cache 的合并等级:

| CacheEvidence | 含义 |
| --- | --- |
| `Published` | 已发布或已锚定 |
| `Verified` | 通过 expected_owner 一致性和 owner 验签的自签名候选 |
| `Unverified` | `update_did_cache` 等旁路写入 |

`verify_did_document_jwt` 的外部 JWT 默认应被当作 `NeedProof` 候选。只有当权威源
证明该 JWT 属于当前发布集合时, 才能提升为 `Published` 证据。

## API 草案

```rust
pub async fn verify_did_document_jwt(
    did: &DID,
    doc_type: DidDocType,
    jwt: &str,
    options: VerifyDidDocumentJwtOptions,
) -> NSResult<VerifiedDidDocument>;
```

### Options

```rust
pub struct VerifyDidDocumentJwtOptions {
    pub purpose: VerifyPurpose,
    pub validity: VerifyValidity,
    pub cache_result: bool,
}

pub enum VerifyPurpose {
    /// 默认模式。用于 RTCP、跨 zone 请求、RBAC principal、应用内权限主语。
    /// 若 authority_owner 与 structural_owner 同时存在且不同, 必须拒绝。
    AuthSubject,

    /// 客体文档解析。允许权威 owner 与结构 owner 不同。
    /// 调用方不得把结果直接作为权限主语使用。
    ObjectDocument,
}

pub enum VerifyValidity {
    /// 当前必须合法。默认推荐。
    CurrentActive,

    /// 签发时合法即可。需要 method 支持历史 owner / 历史发布集合查询。
    ValidAtIssue,
}
```

默认值:

```rust
VerifyDidDocumentJwtOptions {
    purpose: VerifyPurpose::AuthSubject,
    validity: VerifyValidity::CurrentActive,
    cache_result: true,
}
```

### 返回值

```rust
pub struct VerifiedDidDocument {
    pub subject_did: DID,
    pub doc_type: DidDocType,
    pub document: EncodedDocument,

    /// 旧草案 visible_owner。来自 method 结构规则, 当前只有 did:bns。
    pub structural_owner: Option<DID>,

    /// PublishedState.effective_owner / buckyos.effectiveOwner。
    pub authority_owner: Option<DID>,

    /// 本次验签和 owner replay guard 实际使用的 owner。
    /// AuthSubject 成功时必须是 Some。
    pub expected_owner: Option<DID>,

    /// JWT 自声明 owner。OwnerDocument 这类递归基可为 None。
    pub declared_owner: Option<DID>,

    /// 只有 usable_as_authz_subject 为 true 时才可进入权限系统。
    pub authz_owner: Option<DID>,

    pub validity: VerifyValidity,
    pub purpose: VerifyPurpose,
    pub usable_as_authz_subject: bool,

    pub authority_status: Option<DocumentStatus>,
    pub authority_seq: Option<u64>,
    pub document_version: Option<u64>,
    pub body_evidence: BodyEvidence,
    pub cache_evidence: Option<CacheEvidence>,

    pub warnings: Vec<VerifyWarning>,
}
```

便捷 typed wrapper 可以另行提供:

```rust
pub async fn verify_device_document_jwt(
    did: &DID,
    jwt: &str,
    options: VerifyDidDocumentJwtOptions,
) -> NSResult<(DeviceDocument, VerifiedDidDocument)>;
```

## 校验流程

### 1. 解析 JWT payload, 但不信任

底层先把 `jwt` 包成 `EncodedDocument::Jwt(jwt.to_string())`, 再用现有
`parse_did_doc` / typed `decode(..., None)` 解析。这个阶段只能用于提取字段:

1. `id`
2. `owner` / `iss`
3. `iat`
4. `exp`
5. `version_seq`
6. 文档类型特征

必须检查 `payload.id == did`。不相等直接失败。

JWT 形式的 DID Document 必须有 `version_seq`; 这是现有
`ensure_version_seq_for_jwt` 的规则。

### 2. 取得 structural_owner

调用 `structural_owner(did)`。该规则必须来自 name-client 的 DID method 语义,
应用层不得自行字符串截取。

主体认证模式下:

1. 有 `structural_owner` 时, 它是默认 owner 约束。
2. 没有 `structural_owner` 时, 不代表 self-owned, 只能等待权威源给出 `authority_owner`。

### 3. 查询权威状态

查询权威源对 `(did, doc_type)` 的回答, 复用现有 `PublishedState` 语义:

```rust
pub struct PublishedState {
    pub did: DID,
    pub doc_type: String,
    pub document_status: DocumentStatus,
    pub document_ref: Option<DocumentRef>,
    pub document_version: Option<u64>,
    pub effective_owner: Option<DID>,
    pub authority_seq: Option<u64>,
    pub migration_target: Option<DID>,
}
```

`authority_owner = published.effective_owner`。

若权威源没有 `PublishedState` 能力, 但 method authority 能取回当前 body
（典型是 did:web canonical endpoint）, `CurrentActive` 模式下必须要求当前 body
与外部 JWT 一致, 才能把外部 JWT 视为当前发布内容。

### 4. 计算 expected_owner

```text
expected_owner = authority_owner.or(structural_owner)
```

若计算不出 `expected_owner`:

1. `AuthSubject` 必须失败。
2. `NeedProof` 候选不能写入 `Verified` cache。
3. 若权威信道已经证明外部 JWT 就是当前 body, 可以返回非授权主体结果, 但
   `usable_as_authz_subject` 必须为 `false`。

### 5. 默认主体策略检查

当 `purpose == AuthSubject` 时:

```text
expected_owner must exist
if structural_owner exists and authority_owner exists:
    structural_owner must equal authority_owner
```

也就是说, `did:bns:laptop.alice` 的结构 owner 是 `did:bns:alice`。如果 BNS
权威源声明 `authority_owner = did:bns:bob`, 该文档在 `ObjectDocument` 场景可以
按显式策略处理, 但在 `AuthSubject` 场景必须失败。

一级 BNS 名字是例外但不是"结构 self-owned": `did:bns:alice` 的
`structural_owner` 是 `None`。如果 BNS 权威源返回
`authority_owner = did:bns:alice`, 则 `expected_owner = did:bns:alice`, 可以作为
self-owned subject。若权威源不给 owner binding, 不得从名字结构自动推导 self-owned。

### 6. declared_owner 一致性检查

对普通 DID Document JWT, 自声明 owner 必须等于 `expected_owner`:

```text
declared_owner == expected_owner
```

不一致直接失败。这个错误应对应现有 `ResolveWarning::OwnerMismatch` 的强错误版本。

`OwnerDocument` 作为递归基单独处理: 它的可信性来自 method authority 的 anchored
membership, 不从 `declared_owner` 递归回自己。

### 7. 验证当前发布集合

#### CurrentActive

`CurrentActive` 要求外部 JWT 是当前合法发布集合成员:

1. `Active` 继续。
2. `Revoked` / `Tombstoned` / `Migrated` / `Expired` / `Missing` 失败。
3. 若权威源提供 `doc_hash`, 外部 JWT 的 `document_content_hash` 必须匹配。
4. 若权威源内联 `didDocument`, 外部 JWT 必须与内联 body 相同, 或两者 hash 相同。
5. 若 method 只有 canonical endpoint 且没有 `PublishedState`, 当前 endpoint 返回的 body 必须与外部 JWT 一致。
6. `CurrentActive` 不应使用 stale cache 兜底。in-TTL cache 可以作为性能优化, 但必须继续检查外部 JWT 与缓存文档一致, 并应用 owner replay guard。

### 8. 解析 OwnerDocument

递归解析 `expected_owner` 的 `OwnerDocument`。这里不能使用 `declared_owner` 做递归入口。

owner 解析应使用现有 `ResolvePolicy::for_authority_lookup()` 语义:

1. 不允许 Missing 下自签名 fallback。
2. 不允许 stale cache 兜底。
3. 必须应用权威负状态。
4. 用 `descend()` 检查递归深度和环路。

### 9. 验签

用 `expected_owner` 的 `OwnerDocument` 中默认 auth key 验 JWT。默认 key 失败时,
按现有策略尝试 `OwnerDocument::get_historical_keys()`; 成功时返回
`SignedByHistoricalKey` warning。

后续可以扩展为读取 JWT header `kid`, 但当前实现主要使用默认 key 和历史 key fallback。

### 10. Revoke / replay guard

必须统一应用 `OwnerDocument::validate_jwt_revocation`:

1. `valid_iat`: JWT 的 `iat` 必须大于 owner 的 `valid_iat`。
2. `mini_version_seq`: JWT 的 `version_seq` 必须大于 owner 的 `mini_version_seq`。

当 owner policy 要求字段存在而 JWT 缺少字段时必须失败。当前实现已经在
`doc_cache` 读写两侧和 resolver 验证路径应用这类 guard, 新 API 必须复用同一逻辑。

### 11. ValidAtIssue

`ValidAtIssue` 表示"签发时曾经合法", 不能静默退化成当前 owner 验证。

应按 [http_did_resolver_api.md](./http_did_resolver_api.md) 第 7 节复用历史查询:

```text
GET {resolver_base}/1.0/identifiers/{did}?type=owner&iat={jwt.iat}
```

严格语义需要同时回答:

1. `iat` 时刻的 `authority_owner`。
2. `iat` 时刻有效的 OwnerDocument/key。
3. 外部 JWT 在 `iat` 时刻是否属于已发布集合, 或有等价历史发布证据。
4. `iat` 时刻有效的 owner revoke policy。

若 method 或 resolver 不支持历史查询, 本 API 默认返回
`HistoricalVerificationUnsupported`。只有调用方显式选择"接受当前 owner 近似验证"时,
才可以按 `http_did_resolver_api.md` 中的退化说明使用当前 owner; 该模式不得命名为
`ValidAtIssue`, 也不得把结果写入 current positive cache。

当前代码状态: `verify_need_proof_candidate` 还没有把候选 JWT 的 `iat` 传给 resolver,
只是使用当前 `expected_owner` 并在默认 key 失败后盲试 historical keys。因此
`ValidAtIssue` 是未来能力, 不是已完整实现的语义。

## 权限系统约束

权限系统不得自行从名字截取 owner。它只能使用 `VerifiedDidDocument` 中的字段:

1. 授权给设备/应用本身: 使用 `subject_did`。
2. 授权给 owner/account: 使用 `authz_owner`。该字段只有在
   `usable_as_authz_subject == true` 时存在。
3. 授权给 zone: 使用已验证 document 中的 zone 字段, 并继续做 zone binding 检查。

当 `usable_as_authz_subject == false` 时, 该验证结果不能作为权限主语进入 RBAC
或应用内 ACL。

## Cache 行为

`verify_did_document_jwt` 不应让上层调用 `update_did_cache` 来保存"已验证文档"。
`update_did_cache` 在现有实现中明确写入 `CacheEvidence::Unverified`, 不能提升信任等级。

建议缓存规则:

1. `CurrentActive + AuthSubject` 验证通过, 且 JWT 属于当前发布集合时, 可写入
   `CacheEvidence::Published`。
2. `CurrentActive + AuthSubject` 验证通过, 但只证明为 expected_owner 签名的
   NeedProof 候选时, 最多写入 `CacheEvidence::Verified`。
3. `ObjectDocument` 若允许 detached owner, 在 cache 能记录 `purpose` 或
   `usable_as_authz_subject=false` 之前, 不应把 detached NeedProof 结果写入普通
   `Verified` cache。否则后续旧调用方可能把同一 cache 条目误当主体使用。
4. `ObjectDocument` 若有权威 `doc_hash` 或当前发布集合证明, 可按 `Published` 缓存,
   但返回的验证上下文仍然必须标记 `usable_as_authz_subject=false`。
5. `ValidAtIssue` 通过但当前不一定仍合法, 默认不写 current positive cache。
6. 权威负状态应更新 negative cache, 并屏蔽后续 fallback。
7. 缓存命中仍必须应用 owner replay guard。

## 错误类型

建议错误码至少包含:

| 错误 | 含义 |
| --- | --- |
| `InvalidJwtDocument` | JWT 不是可识别 DID Document |
| `DocumentIdMismatch` | `payload.id != did` |
| `OwnerBindingUnavailable` | 无法确定 `expected_owner` |
| `DetachedOwnerRejected` | `authority_owner != structural_owner` 且 purpose 为 `AuthSubject` |
| `DeclaredOwnerMismatch` | `declared_owner != expected_owner` |
| `OwnerDocumentUnavailable` | 无法解析 `expected_owner` 的 OwnerDocument |
| `SignatureVerificationFailed` | owner key 验签失败 |
| `RevokedByOwnerPolicy` | 命中 `valid_iat` / `mini_version_seq` |
| `NotCurrentActive` | `CurrentActive` 模式下不在当前合法集合 |
| `HistoricalVerificationUnsupported` | `ValidAtIssue` 模式下 method 不支持历史查询 |

旧草案里的 `NoVisibleOwner` 应替换为 `OwnerBindingUnavailable`, 因为一级 BNS
名字没有 structural owner 但可以由权威 owner binding 成为合法主体。

## 与现有 API 的关系

### resolve_auth_key

`resolve_auth_key(did)` 只表示"解析这个 DID 自己的 auth key"。它不能用于 DID
Document JWT 的 owner binding 验证。文档中应明确标注:

1. 不要用 `payload.owner` / `payload.iss` 调 `resolve_auth_key` 验 DID Document JWT。
2. 权限主体认证场景必须使用 `verify_did_document_jwt` 或复用同等语义的底层入口。

### resolve_did

`resolve_did` 仍用于"按 DID 解析当前文档"。当应用已经有一份外部传入 JWT 时,
应使用 `verify_did_document_jwt` 验证这份 JWT, 而不是手写 owner/key 逻辑。

实现上可以把外部 JWT 作为候选 body 注入现有 `NeedProof` 验证路径, 并额外做
`CurrentActive` 或 `ValidAtIssue` 的 membership 检查。

### update_did_cache

`update_did_cache` 继续保留为旁路未验证缓存入口。应用层验证通过后不应直接调用它
提升文档信任等级。`verify_did_document_jwt` 应负责按 `CacheEvidence` 受控写入。

## RTCP 迁移示例

RTCP 当前逻辑应从:

```text
decode device_doc_jwt without verify
owner = doc.owner
owner_key = resolve_auth_key(owner)
verify JWT with owner_key
use verified_doc.owner as source owner
update_did_cache
```

迁移为:

```text
verify_device_document_jwt(from_id, device_doc_jwt, AuthSubject + CurrentActive)
use verified.subject_did as source device
use verified.authz_owner as source owner
use verified DeviceDocument default/exchange key as tunnel token verification key
let name-client decide controlled cache write
```

RTCP 返回的 `VerifiedSourceDevice.owner` 必须来自 `authz_owner` 或
`expected_owner`, 不能来自未验证 payload, 也不能来自名字截取。

注意: RTCP 还必须验证对端持有 DeviceDocument 对应私钥, 并继续验证 Device 是否属于当前
ZoneDocument 的 gateway/device 列表。`verify_device_document_jwt` 只解决 DeviceDocument
JWT 的 owner 信任链。

## 测试要求

至少覆盖以下测试:

1. `did:bns:laptop.alice` 的 JWT 声明 owner 为 `did:bns:bob`, 即使用 bob key 签名也必须失败。
2. 权威源声明 `authority_owner = did:bns:bob`, structural owner 为 `did:bns:alice`,
   `AuthSubject` 失败, `ObjectDocument` 可按显式策略继续。
3. `declared_owner != expected_owner` 必须失败。
4. `payload.id != did` 必须失败。
5. `Revoked/Tombstoned/Missing/Expired/Migrated` 在 `CurrentActive` 下失败。
6. OwnerDocument 设置 `valid_iat` 后, 较旧 JWT 失败。
7. OwnerDocument 设置 `mini_version_seq` 后, 较旧 `version_seq` JWT 失败。
8. 默认 key 失败但历史 key 成功时, 验证通过并返回 `SignedByHistoricalKey` warning。
9. `ValidAtIssue` 在 method 不支持历史查询时返回 `HistoricalVerificationUnsupported`。
10. `did:bns:alice` 这类一级 BNS 名字不能从结构推导 self-owned; 只有权威源返回
    `authority_owner = did:bns:alice` 时才能作为 AuthSubject。
11. RTCP 携带逻辑设备名的 `device_doc_jwt` 时, source owner 使用 `authz_owner`,
    并拒绝 detached owner 作为权限主语。
12. `ObjectDocument` detached owner 验证通过时, `usable_as_authz_subject == false`,
    且在没有 purpose-aware cache metadata 前不得写入普通 `Verified` cache。

## 已回答问题

### 1. BNS 一级名字是否统一视为 self-owned subject?

不统一按结构视为 self-owned。

现有 `structural_owner(did)` 对 `did:bns:alice` 返回 `None`。一级名字是根,
从名字结构推不出 owner。它能否作为 self-owned subject 取决于权威源是否返回
owner binding:

```text
authority_owner = did:bns:alice
```

如果权威源返回该绑定, 则 `expected_owner = did:bns:alice`, 可以作为
`AuthSubject`。如果权威源不给 binding, 不能把一级名字候选文档的自声明 owner
当成验签依据。

### 2. ObjectDocument 是否允许写入普通 positive cache?

分情况:

1. 若权威源证明该 JWT 属于当前发布集合, 可以按 `CacheEvidence::Published` 写入普通 cache。
2. 若只是 detached owner 的 `NeedProof` 验签通过, 在 cache 能记录
   `purpose=ObjectDocument` 或 `usable_as_authz_subject=false` 之前, 不应写入普通
   `Verified` cache。

原因是当前 did_cache 的 `CacheEvidence::Verified` 只表达"通过完整 verify", 不表达
"是否可作为授权主体"。为了防止旧调用方绕过 `verify_did_document_jwt` 后误用 cache
结果, detached object 的验证结果需要单独 evidence 标记, 或暂不缓存。

### 3. 历史查询能力的 HTTP/Provider API 是否 follow API 设计文档?

是。历史查询应 follow [http_did_resolver_api.md](./http_did_resolver_api.md) 第 7 节:

```text
GET /1.0/identifiers/{did}?type=owner&iat={unix_timestamp}
```

对 `verify_did_document_jwt`:

1. `CurrentActive` 不需要历史查询。
2. `ValidAtIssue` 必须使用历史 owner/key 和历史发布集合。
3. resolver 返回 `501` / `historicalQuerySupported: false` 时, 本 API 的严格模式应返回
   `HistoricalVerificationUnsupported`。
4. 使用当前 owner 作为 fallback 只能是显式近似模式, 不能叫 `ValidAtIssue`, 也不能写 current positive cache。
