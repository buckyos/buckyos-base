# verify_did_document_jwt 需求文档

## 背景

应用层经常会收到一份 DID Document JWT, 例如 RTCP 握手里携带的
`device_doc_jwt`。当前上层容易写成以下流程:

1. 不验签解出 JWT payload。
2. 从 payload 的 `owner`/`iss` 取 owner DID。
3. 调 `resolve_auth_key(owner)` 取得公钥。
4. 用该公钥验证 JWT。

这个流程只能证明“JWT 能被它自己声明的 owner 验过”, 不能证明“该
Document 的 DID 在名字系统里确实归这个 owner 管”。如果名字系统允许 BNS
owner binding 变更, 或者允许客体文档存在 detached owner, 上层很容易把
“可验签”误当成“可信主体”。

更隐蔽的问题发生在授权阶段: 跨 zone 权限通常基于来源 subject 的 owner,
例如“alice 的 laptop”。如果应用把 `did:bns:laptop.alice` 直接截取成
`did:bns:alice` 做权限主体, 但底层实际 owner binding 已被改成别的 owner,
就可能出现“认证通过, 授权主体错误”的越权。

因此需要在 name-client 底层提供一个面向应用的统一入口:
`verify_did_document_jwt`。

## 目标

`verify_did_document_jwt` 必须完成 DID Document JWT 的完整信任判断, 并返回
可直接进入权限系统的结构化身份上下文。

必须保证:

1. 上层不需要自己解析 `doc.owner -> OwnerDocument -> key`。
2. 验签使用的 owner 来自名字系统的权威 owner binding 或 method 规则, 不能来自未验证文档自声明。
3. 默认主体认证策略下, 能进入权限系统作为主语的 subject, 其名字显现 owner 必须与权威 owner 一致。
4. 返回值明确区分 `subject_did`, `visible_owner`, `effective_owner`, `declared_owner`。
5. 支持“当前必须合法”和“签发时曾经合法”两类校验语义。
6. Revoke/replay guard 由底层统一应用。

## 非目标

1. 不替代普通业务 JWT 的 `verify-jwt`。普通 JWT 可以继续由调用方提供可信 key map。
2. 不在应用层暴露“根据 payload.iss 自动 resolve key”的便捷 API。
3. 不把业务授权策略写进 name-client。name-client 只输出可信身份上下文。
4. 不要求所有客体文档都满足主体认证约束。客体解析可以显式允许 detached owner。

## 核心概念

### subject_did

JWT 证明的文档主体 DID, 即 Document 的 `id`。调用方必须显式提供或由 JWT
解析后与期望值比对。认证入口中推荐由调用方传入期望 DID。

### visible_owner

从名字结构显现出来的 owner。该规则必须由 DID method 在底层定义, 应用层
不得自行字符串截取。

示例:

| DID | visible_owner |
| --- | --- |
| `did:bns:alice` | `did:bns:alice` |
| `did:bns:laptop.alice` | `did:bns:alice` |
| `did:bns:a.b.c` | `did:bns:b.c` |

`did:web` 是否支持 `did:web:app.xxx.com -> did:web:xxx.com` 这类规则, 需要在
method registry 中明确实现。不能由应用层临时按域名字符串截取。

### effective_owner

名字系统权威源认定的 owner binding。若权威源没有显式 owner binding, 可按
method 契约使用 visible owner 作为默认 expected owner。若两者同时存在且不同,
主体认证默认策略必须拒绝。

### declared_owner

JWT payload 中声明的 `owner` 或 `iss`。它只是待校验字段, 不能用于决定验签公钥。

### authz_owner

权限系统使用的 owner 维度主体。对主体认证场景, 它必须等于
`effective_owner`, 且只有当 `usable_as_authz_subject == true` 时才能使用。

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
    pub cache_verified_document: bool,
}

pub enum VerifyPurpose {
    /// 默认模式。用于 RTCP、跨 zone 请求、RBAC principal、应用内权限主语。
    /// 要求 visible_owner == effective_owner。
    AuthSubject,

    /// 客体文档解析。允许权威源声明的 owner 与名字显现 owner 不同。
    /// 调用方不得把结果直接作为权限主语使用。
    ObjectDocument,
}

pub enum VerifyValidity {
    /// 当前必须合法。默认推荐。
    CurrentActive,

    /// 签发时合法即可。需要 method 支持历史 owner binding / 历史发布集合。
    ValidAtIssue,
}
```

默认值:

```rust
VerifyDidDocumentJwtOptions {
    purpose: VerifyPurpose::AuthSubject,
    validity: VerifyValidity::CurrentActive,
    cache_verified_document: true,
}
```

### 返回值

```rust
pub struct VerifiedDidDocument {
    pub subject_did: DID,
    pub doc_type: DidDocType,
    pub document: EncodedDocument,

    pub visible_owner: Option<DID>,
    pub effective_owner: DID,
    pub declared_owner: DID,

    pub validity: VerifyValidity,
    pub purpose: VerifyPurpose,
    pub usable_as_authz_subject: bool,

    pub authority_status: Option<DocumentStatus>,
    pub authority_seq: Option<u64>,
    pub document_version: Option<u64>,

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

底层可以先无验签 decode JWT, 仅用于提取:

1. `id`
2. `owner` / `iss`
3. `iat`
4. `exp`
5. `version_seq`
6. doc type 特征

必须检查 `payload.id == did`。不相等直接失败。

### 2. 取得 visible_owner

调用 method registry 的 owner derivation 规则。该规则必须是底层正式 method
语义, 不是应用层字符串截取。

主体认证模式下:

1. 若 method 支持 visible owner, 记录它。
2. 若 method 不支持 visible owner, 默认不能作为权限主语, 除非调用方选择专门的显式豁免策略。

### 3. 取得 effective_owner

查询权威源 `(did, doc_type)` 的 published state:

1. 若返回 `effective_owner`, 使用它。
2. 若未返回 `effective_owner`, 但 method 定义了 visible owner, 使用 visible owner 作为 expected owner。
3. 若两者都没有, subject JWT 不能验证为权限主语。

### 4. 默认主体策略检查

当 `purpose == AuthSubject` 时:

```text
visible_owner must exist
effective_owner must equal visible_owner
```

如果有人通过 BNS owner transfer 把 `did:bns:laptop.alice` 的 owner 改成
`did:bns:bob`, 该文档在客体解析中可以按显式策略处理, 但在主体认证中必须失败。

### 5. declared_owner 一致性检查

JWT 自声明 owner 必须等于 `effective_owner`:

```text
declared_owner == effective_owner
```

不一致说明 JWT 正在声明未经权威源承认的 owner 关系, 直接失败。

### 6. 解析 OwnerDocument

递归解析 `effective_owner` 的 OwnerDocument。这里不能使用
`declared_owner` 做递归入口, 即使前面已经 decode 出来了。

owner 解析应使用收紧 policy:

1. 不允许 Missing 下自签名 fallback。
2. 不允许 stale cache 兜底。
3. 必须应用权威负状态。

### 7. 验签

用 `effective_owner` 的 OwnerDocument 中的默认 key 验 JWT。默认 key 失败时,
可按现有策略尝试历史 key, 成功时返回 `SignedByHistoricalKey` warning。

### 8. Revoke / replay guard

必须统一应用 OwnerDocument 声明的撤销策略:

1. `valid_iat`
2. `mini_version_seq`

JWT 缺少策略要求字段时必须失败。

### 9. Validity 检查

#### CurrentActive

要求当前权威源回答该 `(did, doc_type)` 处于合法集合:

1. `Active` 通过后继续检查。
2. `Revoked` / `Tombstoned` / `Migrated` / `Expired` / `Missing` 失败。
3. 若权威源提供 `doc_hash`, JWT 内容 hash 必须匹配。
4. 若 method 只有 canonical endpoint 且没有历史集合, 当前 endpoint 返回的 body 必须与 JWT 一致, 或至少由 method 明确声明如何判断 current membership。

#### ValidAtIssue

以 JWT 的 `iat` 为时间点验证:

1. 查询 `owner_at_iat(did, doc_type, iat)`。
2. 查询 `published_at_iat(did, doc_type, iat)` 或等价历史集合。
3. 使用签发时 owner 的 OwnerDocument/key 验签。
4. 应用签发时有效的 revoke policy。

若 method 不支持历史查询, 默认必须返回 `HistoricalVerificationUnsupported`, 不能静默退化为当前 owner 验证。

## 权限系统约束

权限系统不得自行从名字截取 owner。它只能使用 `VerifiedDidDocument` 中的字段:

1. 授权给设备/应用本身: 使用 `subject_did`。
2. 授权给 owner/account: 使用 `effective_owner`。
3. 授权给 zone: 使用已验证 document 中的 zone 字段, 并继续做 zone binding 检查。

当 `usable_as_authz_subject == false` 时, 该验证结果不能作为权限主语进入 RBAC 或应用内 ACL。

## Cache 行为

`verify_did_document_jwt` 不应让上层调用 `update_did_cache` 来保存“已验证文档”。
它应在底层提供受控写入:

1. `CurrentActive + AuthSubject` 验证通过后, 可写入 verified cache。
2. 若权威源 hash/member 证明该 JWT 属于当前发布集合, 可按 published/anchored 证据缓存。
3. `ValidAtIssue` 通过但当前不一定仍合法, 默认不写 current positive cache。
4. 权威负状态应更新 negative cache, 并屏蔽后续 fallback。
5. 缓存命中仍必须应用 owner replay guard。

## 错误类型

建议错误码至少包含:

| 错误 | 含义 |
| --- | --- |
| `InvalidJwtDocument` | JWT 不是可识别 DID Document |
| `DocumentIdMismatch` | `payload.id != did` |
| `NoVisibleOwner` | 主体认证模式下无法从 method 规则得到 visible owner |
| `OwnerBindingUnavailable` | 无法确定 effective owner |
| `DetachedOwnerRejected` | `visible_owner != effective_owner` 且 purpose 为 AuthSubject |
| `DeclaredOwnerMismatch` | `declared_owner != effective_owner` |
| `OwnerDocumentUnavailable` | 无法解析 effective owner 的 OwnerDocument |
| `SignatureVerificationFailed` | owner key 验签失败 |
| `RevokedByOwnerPolicy` | 命中 valid_iat / mini_version_seq |
| `NotCurrentActive` | CurrentActive 模式下不在当前合法集合 |
| `HistoricalVerificationUnsupported` | ValidAtIssue 模式下 method 不支持历史查询 |

## 与现有 API 的关系

### resolve_auth_key

`resolve_auth_key(did)` 只表示“解析这个 DID 自己的 auth key”。它不能用于 DID
Document JWT 的 owner binding 验证。文档中应明确标注:

1. 不要用 `payload.owner` / `payload.iss` 调 `resolve_auth_key` 验 DID Document JWT。
2. 权限主体认证场景必须使用 `verify_did_document_jwt`。

### resolve_did

`resolve_did` 仍用于“按 DID 解析当前文档”。当应用已经有一份外部传入 JWT 时,
应使用 `verify_did_document_jwt` 验证这份 JWT, 而不是手写 owner/key 逻辑。

### update_did_cache

`update_did_cache` 继续保留为旁路未验证缓存入口。应用层验证通过后不应直接调用它
提升文档信任等级。`verify_did_document_jwt` 应负责写 verified/published cache。

## RTCP 迁移要求

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
use verified.effective_owner as source owner
use verified DeviceDocument default key as tunnel token verification key
let name-client decide verified cache write
```

RTCP 返回的 `VerifiedSourceDevice.owner` 必须来自 `effective_owner`, 不能来自未验证
payload, 也不能来自名字截取。

## 测试要求

至少覆盖以下测试:

1. `did:bns:laptop.alice` 的 JWT 声明 owner 为 `did:bns:bob`, 即使用 bob key 签名也必须失败。
2. 权威源声明 `effective_owner = did:bns:bob`, visible owner 为 `did:bns:alice`,
   `AuthSubject` 失败, `ObjectDocument` 可按显式策略继续。
3. `declared_owner != effective_owner` 必须失败。
4. `payload.id != did` 必须失败。
5. `Revoked/Tombstoned/Missing` 在 `CurrentActive` 下失败。
6. OwnerDocument 设置 `valid_iat` 后, 较旧 JWT 失败。
7. OwnerDocument 设置 `mini_version_seq` 后, 较旧 `version_seq` JWT 失败。
8. 默认 key 失败但历史 key 成功时, 验证通过并返回 `SignedByHistoricalKey` warning。
9. `ValidAtIssue` 在 method 不支持历史查询时返回 `HistoricalVerificationUnsupported`。
10. RTCP 携带逻辑设备名的 `device_doc_jwt` 时, source owner 使用 `effective_owner`,
    并拒绝 detached owner 作为权限主语。

## 开放问题

1. `did:web` 是否正式定义 visible owner derivation。如果定义, 需要处理 public suffix
   和多级域名规则, 不能由应用层简单 split。
2. BNS 一级名字如 `did:bns:alice` 是否统一视为 self-owned subject。
3. `ObjectDocument` 是否允许写入普通 positive cache, 还是需要单独 evidence 标记, 防止被权限系统误用。
4. 历史查询能力的 HTTP/Provider API 如何表达 `owner_at_iat` 与 `published_at_iat`。
