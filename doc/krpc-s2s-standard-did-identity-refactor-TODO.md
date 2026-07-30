# kRPC S2S 复用标准 DID 身份：修复 TODO

> 状态：已完成（2026-07-30）。实现、删除项、文档与验收测试均已落地。
>
> 本次没有向前兼容要求。旧的 S2S identity/key-ref 配置、`DID#kid` wire
> 形式和 pinned/resolver 注入接口可以直接删除，不保留兼容层。

## 1. 问题

当前实现把“拥有 DID 的 app”当成一种特殊的 S2S 身份，又定义了一套：

- `appid + zone_did` 身份配置；
- S2S local identity；
- `ServiceKeyRef := DID[#kid]`；
- S2S peer key resolver；
- pinned key / caller asserted / unsafe skip；
- mandatory `authentication.keyref.json`；
- active/grace 多 key candidate。

这重复了标准 DID 协议已经提供的身份和默认密钥语义。调用方必须额外理解一套
S2S 身份规则，且同一个 DID 在不同模块中可能走不同的信任路径。

修复后的原则只有一句：

> S2S app 是一个普通 DID 身份；S2S 层只接收 DID，并使用该 DID 的默认
> Ed25519 密钥。

## 2. 已确认的设计结论

### 2.1 身份与命名

- 上层使用 `name_lib::zone_child_did(zone_did, appid)` 完成
  `appid + zone_did -> service_app_did`。
- 这个合并只是 provisioning / runtime 配置阶段的二级名字 helper，不属于
  kRPC S2S 身份协议。
- 进入 kRPC、HTTP server 和 Identity Manager 后，唯一身份输入是完整 DID，
  例如 `did:bns:event-service.alice`。
- 每个 zone 负责保证自己的二级名字不重名；不增加跨类型冲突兼容规则。
- 一个名字的不同文档类型继续依靠 `doc_type` 区分。文件在同一个 DID 目录下
  并列存在，例如 `did.json`、`app.json`、`info.json`，不增加
  `doc_type` 子目录。

### 2.2 默认密钥

- S2S key reference 就是 DID 本身：
  `did:bns:event-service.alice`。
- DID 单独出现表示使用 DID document 中的默认 authentication key。
- S2S wire、client/server 配置和缓存键都不再暴露 `#kid`。
- DID document 内部的 verification method 可以仍使用 `#main_key` 等标准
  document-local id；S2S 不要求调用方知道或传递它。
- 默认 Ed25519 公钥按标准 DID document 解析，并转换为 X25519 用于 S2S
  key agreement。
- KDF、缓存和监控可以继续使用真实公钥 fingerprint；fingerprint 是内部的
  密钥材料标识，不是公开身份选择器。

### 2.3 标准文件路径

对 DID `D`，默认的最小 file-mode 身份为：

```text
$BUCKYOS_IDENTITY_ROOT/{encode(D)}/did.json
$BUCKYOS_SECURITY_ROOT/{encode(D)}/authentication.private.pem
```

其中：

- `did.json` 的 `id` 必须等于 `D`；
- 默认 authentication verification method 必须是 Ed25519；
- `authentication.private.pem` 是 PKCS#8 PEM；
- 私钥导出的 Ed25519 公钥必须等于 `did.json` 的默认公钥；
- 私钥查找必须是 exact DID，绝不使用 wildcard fallback。

普通 file mode 直接读取 `authentication.private.pem`，不要求
`authentication.keyref.json`。

`authentication.keyref.json` 只作为 direct file 不存在时的可选 fallback，
服务于 HSM、remote 或非默认文件位置等少数场景。当前 S2S 的
Ed25519-to-X25519 流程需要 key-agreement 能力；只有 sign 能力的 signer
不能伪装成可用的 S2S key source。

## 3. 相似 bad smell review

本次 review 不只发现了 `src/name-client/src/identity_s2s.rs`。以下内容属于同一个
重复身份模型，应一次清理。

| 位置 | Bad smell | 修复方向 |
| --- | --- | --- |
| `src/name-client/src/identity_s2s.rs` | 为 S2S 单独加载 mandatory keyref、校验 fingerprint、维护 active/grace provider | 删除整个 S2S 专用 adapter；复用标准 DID document、默认密钥和 IdentityRoots 路径 |
| `src/kRPC/src/s2s/identity.rs` | `S2sLocalIdentityConfig` 同时接收 appid、zone DID 和 key source，并重新派生/证明身份 | kRPC 只接收已经形成的 local DID；删除第二套 identity config |
| `src/kRPC/src/s2s/identity.rs` | `VerifyAgainst`、`CallerAsserted`、`UnsafeSkip` 允许多条身份绑定路径 | 只保留标准校验：本地私钥必须匹配本地 `did.json` 默认公钥 |
| `src/kRPC/src/s2s/peer.rs` | `S2sPeerKeyResolver`、`VerifiedPeerKey` 和 `StaticPeerKeyResolver` 构成平行的 DID key resolver | production 路径直接调用 `NameClient` 的标准 DID 默认公钥解析；测试也用标准 provider/fixture |
| `src/kRPC/src/s2s/client.rs` | remote key 可在 `Pinned` 和自定义 `Resolver` 间选择，还可另填 `remote_key_id` | client 只接收 remote DID；统一经 NameClient 解析默认 key |
| `src/kRPC/src/s2s/server_ctx.rs` | builder 要求 appid + zone DID + local key source + peer resolver，并在请求路径遍历 key candidates | builder 只接收 local DID；标准 roots/resolution 是默认且唯一的 production 路径 |
| `src/kRPC/src/s2s/service_key_ref.rs` | 自定义 `ServiceKeyRef { did, key_id }` 和 `DID#kid` wire grammar | From/To 直接使用 canonical DID；如需严格 wire parser，应把通用 canonical DID 校验放到 name-lib |
| `src/kRPC/src/s2s/service_key_ref.rs` | kRPC 内再次提供 `derive_service_did(appid, zone_did)` | 删除；只在上层调用 `name_lib::zone_child_did` |
| `src/kRPC/src/s2s/headers.rs`、`aad.rs` | header/AAD 类型和说明继承了 `ServiceKeyRef` 的可选 kid 语义 | header/AAD 继续绑定 From/To，但 canonical 值只允许完整 DID |
| `src/kRPC/src/s2s/keys.rs`、server request path | public provider 支持多 key candidates，协议流程遍历 active/grace keys | 新请求只使用当前默认 key；旧 key 仅由已经开始的请求通过 `Arc` snapshot 持有 |
| `src/name-client/src/identity_mgr.rs` | `find_security_file` 可从 exact DID 回退到 wildcard | authentication/private material 必须 exact；wildcard 仅允许用于确有 wildcard 语义的 X.509 server certificate |
| `src/name-client/src/identity_mgr.rs` | legacy private-key helper 先找 mandatory keyref，`X509Paths.keyref` 也是必填 | direct private PEM 优先；keyref 改为 optional fallback |
| `src/name-client/src/identity_mgr.rs` | X.509 local status 把 keyref 是否存在当作本地可用条件 | 直接私钥存在且与证书匹配即可；keyref 只是另一种 key access |
| `src/name-client/src/lib.rs` | free function `resolve_ed25519_exchange_key` 按 device/zone document shape 分支 | 删除或改成 NameClient 上统一的“解析 DID 默认 Ed25519 key”方法，不识别 S2S 特殊身份 |
| crate 依赖方向 | `name-client` 仅为 `identity_s2s.rs` 反向依赖 kRPC，迫使标准 identity 通过 provider 注入回来 | 删除该 adapter 后移除反向依赖，让 kRPC 的默认 S2S feature 直接复用 name-client |
| 文档和示例 | 已把 keyref、`DID#kid`、appid+zone、pinned/resolver 固化成 S2S 使用方式 | 同步改成 DID-only、default-key、direct-file-first |

以下内容不是重复身份模型，必须保留：

- header 的严格大小/字符检查和 canonical encoding；
- X25519、HKDF、AEAD、AAD 和 domain separation；
- public-key fingerprint 参与 KDF、派生 key cache 与观测；
- replay protection、时间窗口、admission policy 和 response binding；
- 解密失败时 fail closed，禁止明文 fallback。

其他与身份模型无关的安全问题继续由 `doc/krpc_s2s_review.md` 跟踪，本 TODO
不顺带改变协议安全边界。

## 4. 目标分层

```text
provisioning / app runtime
  appid + zone_did
        |
        | name_lib::zone_child_did
        v
  service_app_did
        |
        +-------------------------+
        |                         |
        v                         v
IdentityRoots                 NameClient
local did.json + PEM          remote DID resolution
        |                         |
        +-----------+-------------+
                    v
               kRPC S2S
        local DID + remote DID only
```

职责边界：

- `name-lib`
  - DID 数据类型；
  - `zone_child_did`；
  - DID document trait/default authentication key 语义；
  - 可复用的 canonical DID 校验。
- `name-client`
  - IdentityRoots 和标准文件路径；
  - 本地 `did.json` / default private key 绑定校验；
  - 远端 DID document 解析、缓存和 authority refresh。
- `kRPC`
  - S2S wire、key agreement、KDF、AEAD、replay 和请求生命周期；
  - 不定义 app identity、不派生名字、不定义另一套 peer trust source。
- `buckyos-http-server`
  - 接收 service DID 并组装 HTTP/kRPC；
  - 不再接收 appid + zone DID + key provider + peer resolver 的组合。

首选 crate 依赖方向：

```text
name-lib <- name-client <- kRPC <- buckyos-http-server
```

执行时先删除 `name-client -> kRPC` 的唯一用途
`identity_s2s.rs`，再让 kRPC 的 S2S 默认 feature 依赖 name-client，避免循环。
如果需要 feature gating，只允许隐藏依赖成本，不得重新引入 resolver/provider
作为普通调用方必须理解的 production API。

## 5. 目标 API 形状

名称可在实现时按现有风格调整，但 public API 的信息量必须保持如下：

```rust
// 名字派生只发生在上层。
let local_did = zone_child_did(&zone_did, appid)?;

// S2S server 只接收自己的 DID。
let server = S2sRpcServerContext::from_did(local_did).await?;

// S2S client 只接收通信双方的 DID。
let client = S2sClientConfig::new(local_did, remote_did);
```

允许测试和嵌入场景传入独立 `IdentityRoots` / `NameClient` instance，但应放在
`with_runtime`、test helper 或 crate-private 构造器中。普通 API 不暴露：

- raw private key；
- local/remote key id；
- pinned public key；
- caller-asserted binding；
- unsafe skip；
- S2S 专用 peer resolver；
- active/grace candidate list。

NameClient 应提供一个标准方法，语义类似：

```rust
async fn resolve_default_ed25519_key(
    &self,
    did: &DID,
    source: ResolveSourcePolicy,
) -> NSResult<[u8; 32]>;
```

实现只能：

1. 解析指定 DID 的标准 `did.json`；
2. 校验 document `id`；
3. 调用 DID document 的默认 authentication key 语义；
4. 要求 Ed25519 并返回 32-byte 公钥。

不得再按 `device_type`、`hostname`、app 或 S2S 类型分支。

IdentityRoots 应补齐小而通用的 exact-path/load helper，语义类似：

```rust
fn did_document_file(&self, did: &DID) -> NSResult<PathBuf>;
fn authentication_private_key_file(&self, did: &DID) -> NSResult<PathBuf>;
fn resolve_private_key_access(&self, did: &DID) -> NSResult<KeyAccess>;
```

`resolve_private_key_access` 的顺序固定为：

1. exact `authentication.private.pem`；
2. direct file 不存在时，exact `authentication.keyref.json`；
3. 两者都不存在则明确报错。

不要为了这三个 helper 再创建 `identity_s2s` 模块或 S2S 专用身份对象。

## 6. 轮换与 stale cache 的简化

不再把少见的多密钥部署扩散成所有调用方都要理解的 key-id/candidate 协议。

- 一个 DID 在任一时刻只有一个当前默认 S2S key。
- 本地 reload 以原子替换方式更新当前 key。
- 每个已经开始的请求持有当时 key 的 `Arc` snapshot，直到 response 完成；
  snapshot 最后一个引用释放时旧 secret 自动 zeroize。
- server 不为“将来收到的新请求”维护全局 grace key list。
- client 使用缓存中的 remote default key 解密/校验失败时，可以：
  1. 用 `ResolveSourcePolicy::RemoteAuthority` 强制刷新 DID；
  2. 使用新 nonce 只重试一次；
  3. 仍失败则返回原始类别的安全错误。
- fingerprint 继续区分派生 key cache entry，但不出现在 From/To key reference 中。

这使轮换问题回到标准 DID document 发布、NameClient cache refresh 和
in-flight request 生命周期，不再需要公开 `#kid`。

## 7. 实施清单

### Phase A：先修正标准 Identity Manager 契约

- [x] 更新 `doc/did-identity-certificate-manager.md`：
  - [x] direct private PEM 是 file mode 默认路径；
  - [x] keyref 是 optional fallback，不是每个 private capability 的 mandatory sidecar；
  - [x] 明确 authentication private material 只允许 exact DID；
  - [x] 更新 `X509Paths`、local status 和 legacy tool 相关示例。
- [x] 在 `IdentityRoots` 中区分 exact lookup 与 X.509 wildcard lookup。
- [x] 禁止 DID document、authentication private key 和 keyref 使用 wildcard fallback。
- [x] `private_key_file_for_legacy_tool` 改成 direct file first、keyref fallback。
- [x] `X509Paths.keyref` 改成 optional，或移除“路径存在即 mandatory”的类型表达。
- [x] `check_x509_local_status` 支持 direct private key，并直接校验证书公钥绑定。
- [x] 增加 exact `did.json` loader：
  - [x] 校验 JSON 可解析；
  - [x] 校验 `document.id == requested DID`；
  - [x] 获取默认 authentication Ed25519 key。
- [x] 增加 direct PKCS#8 Ed25519 private key loader，并校验其公钥等于
  `did.json` 默认 key。

### Phase B：统一 DID 默认公钥解析

- [x] 把 `resolve_ed25519_exchange_key` 改为 NameClient instance method，或直接删除后
  新增 `resolve_default_ed25519_key`。
- [x] 只复用 `resolve_did_ex`、`DIDDocumentTrait::get_auth_key(None)` 和标准 JWK
  转换；删除 document-shape 特判。
- [x] normal resolve 使用 `BestAvailable`。
- [x] 有界 refresh/retry 使用 `RemoteAuthority`，不得偷偷回落到 pinned key。
- [x] 将 S2S wire 所需的 canonical DID 校验下沉为 name-lib 通用 helper；
  保留 kRPC 的 header 长度限制。

### Phase C：删除平行 S2S 身份模型

- [x] 删除 `src/name-client/src/identity_s2s.rs` 及其 export、测试和依赖。
- [x] 从 name-client 的 `Cargo.toml` 删除对 kRPC 的依赖。
- [x] kRPC S2S 默认实现直接复用 name-client；确认没有形成 crate cycle。
- [x] 删除或彻底瘦身 `src/kRPC/src/s2s/identity.rs`：
  - [x] 删除 `S2sLocalIdentityConfig`；
  - [x] 删除 `S2sLocalKeySource`；
  - [x] 删除 `LocalKeyBindingCheck`；
  - [x] 删除 `CallerAsserted` / `UnsafeSkip`。
- [x] 删除 `src/kRPC/src/s2s/peer.rs` 中的 S2S 专用 production resolver model。
- [x] 删除 client 的 `Pinned` / custom `Resolver` remote key source。
- [x] 删除 `remote_key_id`、explicit local `key_id` 以及相应 builder。
- [x] 删除 `ServiceKeyRef` 的 `key_id` 和 `DID#kid` 解析；From/To 直接保存 DID。
- [x] 同步更新 headers/AAD 的类型、canonical encoding 和注释，但不降低原有
  binding 强度。
- [x] 删除 kRPC 的 `derive_service_did`；调用方在进入 S2S 前使用
  `name_lib::zone_child_did`。
- [x] server builder 改为接收完整 local DID。
- [x] client config 改为接收完整 local DID 和 remote DID。
- [x] HTTP server wiring 不再组装 local key source 和 peer resolver。

### Phase D：简化 key 生命周期

- [x] `S2sLocalKeyHandle` 去掉 optional `key_id`。
- [x] provider/request API 从 `local_key_candidates()` 改成单个当前默认 key snapshot。
- [x] 删除用于接收新请求的 active/grace candidate 遍历。
- [x] reload 只原子替换当前 key；in-flight request 持有自己的 secret snapshot。
- [x] 验证旧 snapshot 最后释放时 secret zeroize。
- [x] remote cached key 失败时只做一次 authority refresh + fresh nonce retry。
- [x] key reload/refresh 后精确失效相关派生 key cache。

### Phase E：文档、示例和清理

- [x] 更新 `doc/krpc-s2s-payload-encryption-TODO.md`，删除已废弃的
  appid+zone、keyref mandatory、`DID#kid`、pinned/resolver 和 grace candidate
  设计。
- [x] 更新 `src/kRPC/readme.md` 的 client/server 示例为 DID-only。
- [x] 更新 `name_lib::zone_child_did` 注释，明确它是上层名字 helper，不是
  kRPC identity derivation。
- [x] 删除不再使用的常量、error variant、feature、dependency 和 re-export。
- [x] 用 `rg` 确认 production code 不再出现已删除概念。

## 8. 必须新增/改写的测试

### 标准路径

- [x] 仅有 `did.json + authentication.private.pem`、完全没有 keyref 时，
  S2S client/server 可正常启动和通信。
- [x] `did:bns:event-service.alice` 和 `did:web:event-service.example.com`
  都走同一套 loader/resolver。
- [x] 同一 DID 目录同时存在 `did.json`、`app.json`、`info.json` 时互不影响。
- [x] direct file 缺失时，合法 file keyref fallback 可工作。
- [x] direct file 存在时，即使旁边有 keyref，也优先使用 direct file。

### 绑定与失败关闭

- [x] `did.json.id` 与目标 DID 不一致时启动失败。
- [x] private key 与 `did.json` 默认公钥不一致时启动失败。
- [x] 默认 verification method 不是 Ed25519 时明确失败。
- [x] authentication 私钥不存在时，不得命中父域或 wildcard 目录。
- [x] remote DID 不存在、document 非法或无默认 key 时请求失败且无明文 fallback。
- [x] 只有 sign capability、没有 key-agreement capability 的 keyref 明确失败。

### Wire 与 API

- [x] From/To 的 canonical wire 值严格等于 DID 字符串。
- [x] `DID#kid` 被拒绝，不再作为合法 S2S key reference。
- [x] malformed/non-canonical/超长 DID header 继续被拒绝。
- [x] public S2S client/server API 不需要 appid、zone DID、raw key、key id、
  pinned key 或 resolver。
- [x] `appid + zone_did` 只在上层 helper 测试中出现。

### 轮换

- [x] remote DID cache 过期导致首次失败时，authority refresh 后用 fresh nonce
  成功重试一次。
- [x] refresh 后仍失败时不继续重试。
- [x] local reload 后，新请求只使用新默认 key。
- [x] reload 前已开始的请求能用自己的 snapshot 完成 response。
- [x] 没有为新请求保留可枚举的旧 key candidate。

## 9. 完成判定

以下条件全部成立才算完成：

- [x] 给定 local DID，系统能从标准两文件布局自动得到并验证本地默认身份。
- [x] 给定 remote DID，系统能通过 NameClient 自动解析默认 Ed25519 公钥。
- [x] S2S public API 和 wire 中不存在独立 `kid`。
- [x] S2S public API 中不存在 appid + zone DID 的身份拼装。
- [x] production code 中不存在 S2S 专用 peer resolver、pinned key trust path 或
  unsafe identity binding bypass。
- [x] 普通 file mode 不创建、不要求、不读取 keyref。
- [x] authentication private material 永远 exact-match DID。
- [x] 现有 S2S 加密、AAD、replay、admission 和 response binding 测试继续通过。
- [x] 文档只描述一套 DID 身份规则：简单、统一、无需 S2S 额外理解。

建议最后执行的静态检查：

```bash
rg -n \
  'IdentityManagerS2sKeyProvider|S2sLocalIdentityConfig|S2sLocalKeySource|LocalKeyBindingCheck|S2sPeerKeyResolver|StaticPeerKeyResolver|remote_key_id|CallerAsserted|UnsafeSkip' \
  src
```

预期 production code 零命中；若测试 helper 仍有同名概念，也应改成标准
NameClient / IdentityRoots fixture，而不是保留旧模型。
