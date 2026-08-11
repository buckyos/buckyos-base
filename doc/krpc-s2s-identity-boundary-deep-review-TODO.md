# kRPC S2S Local / Remote Identity 边界深度 Review 与修复 TODO

> 状态：已完成  
> 编写日期：2026-07-30  
> 完成日期：2026-07-30  
> 规范源：[`did-identity-certificate-manager.md`](./did-identity-certificate-manager.md)  
> 前置历史：[`krpc-s2s-standard-did-identity-refactor-TODO.md`](./krpc-s2s-standard-did-identity-refactor-TODO.md)  
> 目标：对最近新增和重构的 S2S identity、public-key Provider、缓存、reload、
> client/server 装配与测试进行一次完整的边界审查；修复发现的问题，并删除因两次
> 设计偏移留下的重复、含糊或错误路径。

---

## 1. 为什么需要再次 Review

`did-identity-certificate-manager.md` 已明确补充：

> Identity Manager 管理的全部都是当前运行环境持有的 Local Identity。

这是本次 Review 的最高优先级约束。`public identity root` 与 `security root`
不是“本地信息”和“远端信息”的划分，而是**同一个 Local Identity 的公开材料与
私钥能力之间的权限边界**。

前两次实现偏移的共同根因，是没有把下面两件事在类型、API、测试和文档中彻底分开：

1. 当前进程“我是谁、我持有什么私钥能力”；
2. 当前进程“如何信任 target / peer DID 的公钥”。

因此，本轮不只修正文档或调整一次调用顺序，而要确保这个边界成为结构性约束：

```text
Local Identity
  DID
    -> IdentityRoots
    -> local did.json
    -> local authentication.private.pem / local private-key capability
    -> validated immutable local key snapshot

Remote Identity
  target / peer DID
    -> cluster_config S2sPublicKeyProvider（优先）
    -> NameClient DID resolution（仅 Provider 明确不管理时 fallback）
    -> validated and cached remote public-key snapshot
```

任何 production 路径都不得：

- 用 `IdentityRoots` 查询任意 Remote DID 的公钥；
- 把 public identity root 当作 DID resolver cache；
- 因为 public root 中存在 `did.json` 就把它当成受管 Local Identity；
- 绕过 cluster_config Provider，直接把 NameClient 作为 cluster S2S 的首选来源；
- 在每次 S2S request 中重新解析 DID document 或重复加载 peer public key；
- 重新引入 pinned key、`DID#kid`、caller-asserted key 或 S2S 私有 resolver 模型。

---

## 2. Review 的完成定义

本 TODO 完成后必须同时成立：

1. Local Identity 与 Remote Identity 的数据源、类型和生命周期清晰分离。
2. `IdentityRoots` 只参与 Local Identity 的路径计算、材料加载和私钥绑定校验。
3. cluster S2S 的 Remote DID 公钥固定采用
   `cluster_config Provider -> NameClient fallback`。
4. Provider 命中、报错、未管理三种状态语义明确；只有“未管理”允许 fallback。
5. 正常 request 热路径不访问 Provider、不访问 NameClient、不读取身份文件。
6. cluster_config 更新、删除或撤销 key 后，旧缓存不会无限期继续被接受。
7. 解密失败不能被攻击者利用为“每个失败请求都强制做一次远端 DID 解析”。
8. client、server 与 runtime 不维护互相失联的重复 remote-key cache。
9. 测试中 client roots 与 server roots 分离，每个 roots 只包含自己的 Local Identity。
10. base 提供强约束 cluster client/server 构造入口；每个产品用自己的
    cluster_config 结构实现 Provider，而不是由 base 规定产品配置 schema。
11. 文档、代码注释、示例与实现只描述一套一致的身份模型。
12. 无用兼容层、重复缓存、错误 convenience API、过时注释和测试 fixture 被删除。

---

## 3. 不变量与术语

### 3.1 Local Identity

Local Identity 表示当前运行环境持有或获授权调用私钥能力的身份。

对于 S2S file mode，给定 canonical DID `D`，标准入口为：

```text
$BUCKYOS_IDENTITY_ROOT/{encode(D)}/did.json
$BUCKYOS_SECURITY_ROOT/{encode(D)}/authentication.private.pem
```

要求：

- `did.json.id == D`；
- 默认 authentication verification method 是 Ed25519；
- private key 是 PKCS#8 PEM；
- private key 派生出的公钥等于默认 authentication 公钥；
- direct private file 优先；
- direct file 不存在时才允许 exact `authentication.keyref.json` fallback；
- authentication identity 永远 exact-only，不使用 wildcard；
- 只有 sign 能力、没有 X25519/DH 能力的 signer/remote keyref 对当前 S2S profile
  必须明确失败。

### 3.2 Remote Identity

Remote Identity 表示 client target DID 或 server request `From` DID。

Remote public key 的来源顺序固定为：

```text
1. S2sPublicKeyProvider / cluster_config
2. Provider 明确返回 NotManaged 时，NameClient fallback
3. 结果进入带来源和生命周期信息的 S2S remote-key cache
```

Remote key 不得从下列位置获得：

- 当前进程的 `IdentityRoots`；
- caller 传入的 raw/pinned public key；
- `DID#kid`；
- HTTP header 中的 key material；
- 旧的 `S2sPeerKeyResolver` 或等价的平行 resolver。

### 3.3 Provider 的三态语义

当前 `Option<[u8; 32]>` 的语义必须被严格记录，必要时改成显式 enum：

```rust
pub enum S2sProviderLookup {
    Managed { key: S2sPeerPublicKey, generation: u64 },
    NotManaged { generation: u64 },
}
```

语义：

- `Managed(key)`：cluster_config 对此 DID 是权威来源，禁止访问 NameClient；
- `NotManaged`：此 Provider 的管理域不包含该 DID，允许 NameClient fallback；
- `Err`：Provider 管理信息非法、缺 key、配置损坏或暂时不可用，必须 fail closed，
  不得把错误伪装成 `NotManaged`。

Provider 不是 key-id resolver。输入只能是 canonical target DID；输出只能是该 DID
当前唯一的默认 authentication Ed25519 公钥及必要的 revision/provenance 信息。

---

## 4. 已确认需要 Review 的代码范围

### 4.1 Identity Manager / NameClient

- `src/name-client/src/identity_mgr.rs`
  - `IdentityRoots`
  - exact path helpers
  - `load_default_ed25519_public_key`
  - `load_default_ed25519_private_key`
  - `resolve_private_key_access`
  - `find_identity_dir`
  - `IdentityStatus::installed / locally_usable`
- `src/name-client/src/name_client.rs`
  - `resolve_default_ed25519_key`
  - `ResolveSourcePolicy`
  - cache、authority refresh 与证据语义
- `src/name-client/src/lib.rs`
  - public re-export 是否让 Local Identity helper 看起来像通用 Remote DID resolver

### 4.2 kRPC S2S

- `src/kRPC/src/s2s/identity.rs`
  - `S2sPublicKeyProvider`
  - `S2sRuntime`
  - `RuntimeNameClient`
  - local identity loader
  - remote-key cache
  - provider/fallback/reload 顺序
- `src/kRPC/src/s2s/client.rs`
  - Provider 装配
  - transport 构造时 target key 加载
  - client 自有 `remote_key` 与 runtime cache 的重复状态
  - refresh/retry
- `src/kRPC/src/s2s/server_ctx.rs`
  - Provider 装配
  - caller DID cache
  - decrypt failure refresh
  - `from_did` 的 Provider-less 默认行为
- `src/kRPC/src/s2s/keys.rs`
  - public-key validation
  - fingerprint 与 derived-key cache invalidation
- `src/kRPC/src/s2s/error.rs`
  - Provider、fallback、cache、refresh 错误是否能保持 fail closed
- `src/kRPC/src/lib.rs`
  - S2S client transport 的实际构造入口

### 4.3 HTTP / cluster 装配

- `src/buckyos-http-server/src/s2s_rpc_server.rs`
- 所有创建 `S2sRpcServerContext`、`S2sClientConfig`、
  `KrpcTransportSecurity::S2sPayloadV1` 的 production call site
- 实际 cluster_config 数据类型及其加载、更新、删除通知路径
- `S2sPublicKeyProvider` 的 production implementation

执行结论：`buckyos-base` 不是具体产品，仓库中也没有统一的 cluster_config
schema。经确认，不应在 base 中发明 production cluster_config adapter；每个产品
用自己的不可变配置结构实现 `S2sPublicKeyProvider`。base 提供三态查询契约、
generation change token、缓存失效和强约束 client/server 构造入口。HTTP 测试中的
`ProductClusterSnapshot` 仅验证产品侧适配方式，不是公共配置模型。

### 4.4 文档与测试

- `doc/did-identity-certificate-manager.md`
- `doc/krpc-s2s-standard-did-identity-refactor-TODO.md`
- `doc/krpc-s2s-payload-encryption-TODO.md`
- `src/kRPC/readme.md`
- `src/buckyos-http-server/src/test_s2s_rpc_server.rs`
- kRPC/name-client 内所有 S2S identity 测试

---

## 5. 已发现的重点风险

### 5.1 Provider-first 还是可选行为，不是 cluster 装配不变量

Review 前：

- `S2sClientConfig::new` 默认没有 Provider；
- `S2sRpcServerContext::from_did` 默认没有 Provider；
- `S2sRuntime::system` 默认只有可选 global NameClient；
- production `S2sPublicKeyProvider` implementation 在当前仓库中尚未找到。

执行结果：

- generic/non-cluster 模式允许，但必须显式调用
  `system_name_client_fallback` / `from_did_with_name_client_fallback`；
- cluster 模式使用 `S2sClientConfig::for_cluster` /
  `S2sRpcServerContext::cluster_builder` 安装产品 Provider；
- `from_did` 与隐式 `S2sRuntime::system` 已删除；
- base 不拥有具体产品 call site；产品实现 trait 并负责在其装配测试中验证接入。

验收不能只检查“Provider API 存在”，必须检查“常规 cluster 调用路径使用它”。

### 5.2 remote key 存在两层缓存

当前 `S2sRuntime` 有 DID -> remote key cache，`S2sClientTransport` 又保存固定 target
的独立 `RwLock<RemoteDefaultKey>`。

风险：

- runtime cache 被 invalidate 后，client transport 仍可能继续使用旧 snapshot；
- cluster_config 更新很难原子传播到所有 transport；
- reload 需要同时维护两处状态；
- 来源、revision 和 fingerprint 容易失配。

目标：

- 为每个 Remote DID 只保留一个权威 cache entry/handle；
- client 与 server 都读取同一类不可变、可原子替换的 remote-key snapshot；
- 删除重复 `RwLock`、重复 cache 或无法统一失效的 wrapper；
- derived-key cache 依据被替换 fingerprint 精确失效。

### 5.3 cluster_config 更新没有完整的 cache lifecycle

当前缓存命中会直接返回；只有显式 reload 或解密失败才重新读 Provider。

必须覆盖以下事件：

- DID 首次进入 cluster_config；
- 已有 DID key rotation；
- DID 从 cluster_config 删除；
- DID 被禁用或撤销；
- Provider 从 `NotManaged` 变为 `Managed`；
- Provider 从 `Managed` 变为 `NotManaged`；
- Provider generation 整体切换；
- 配置加载失败或部分更新失败。

要求：

- cluster_config publish/swap 成功后必须有明确的 invalidate/reload 通知；
- 更新必须与 cluster_config 的原子 snapshot/generation 对齐；
- 旧 key 不得仅因为仍能成功 decrypt 就无限期继续被接受；
- 删除/撤销后必须 fail closed；
- 如果采用 revision/generation，cache entry 必须保存并比较它；
- 如果采用 push invalidation，必须测试所有已创建 transport/context 都能收到更新；
- 不能依赖“等对端先用新 key 导致一次失败”作为唯一更新机制。

### 5.4 decrypt failure 可能退化成每请求 authority refresh

“每个请求最多 refresh 一次”仍可能被攻击者放大成“每个恶意请求都 refresh 一次”。

尤其 Provider miss 后的 `NameClient::RemoteAuthority` 可能包含网络访问或复杂验证。

需要：

- 按 DID singleflight，防止并发冷启动或并发失败形成解析风暴；
- authority refresh cooldown / rate limit / generation gate；
- Provider-backed key 在 revision 未变化时不要重复做无意义 retry；
- invalid ciphertext 不得无限触发 remote resolution；
- refresh 失败不得污染已有可信 cache entry，也不得回退明文；
- 加入并发与恶意失败请求测试，验证 Provider/NameClient 调用次数有上界。

### 5.5 测试 fixture 把双方身份放在同一个 IdentityRoots

现有 HTTP S2S fixture 在同一组 roots 中写入 client 和 server 两个身份。这不符合
Local Identity 的真实边界，也可能掩盖“错误地从 IdentityRoots 读取 Remote DID”
的回归。

必须改为：

```text
client process fixture:
  client IdentityRoots:
    client did.json
    client private key
  不存在 server did.json/private key

server process fixture:
  server IdentityRoots:
    server did.json
    server private key
  不存在 client did.json/private key

remote public keys:
  只存在于 cluster_config Provider 或独立 NameClient fixture
```

所有端到端测试都应以这个隔离模型为默认。

### 5.6 Local-only 语义没有完全进入 API 名称与可见性

`IdentityRoots::load_default_ed25519_public_key(did)` 名称看起来像通用 DID
public-key resolver，但实际应只解析 Local Identity public material。

Review 并决定：

- 改名为包含 `local_identity` 语义的方法；
- 将只供 private-key binding 校验的 public-key loader 降为 private/crate-private；
- 对外提供语义完整的 `load_local_default_ed25519_identity`；
- 保留发布本机 `did.json` 所需的只读 helper，但文档必须说明它读取的是 Local
  Identity 的公开侧；
- `find_identity_dir`、`IdentityStatus::installed` 是否错误地把只有 public
  directory/material 的状态叫作“identity installed”；
- 是否需要把 material presence、private capability 与 locally usable 分开表达。

Remote public key 必须只从 Provider/NameClient API 暴露，不得复用上述 local loader。

### 5.7 根规范中仍有可能混淆 Local Identity 与 peer trust 的内容

`did-identity-certificate-manager.md` 虽然增加了 Local Identity 范围说明，但仍需
复查：

- `server.ca.pem` / `client.ca.pem` 被描述为 peer CA bundle 或 trust anchor；
- `check_x509_remote_status` 中的 DID document 解析是否明确表示“检查本地身份的
  远端发布状态”，而不是“查询任意 peer DID”；
- peer trust store 是否应移出 Local Identity root；
- 若 CA 文件确实属于 Local Identity，名称和语义是否应限定为该本地证书的 issuer
  chain/validation material。

本轮若需修改根规范，应先改规范再改代码，避免实现继续依赖含糊语义。

### 5.8 文档和代码注释仍存在 NameClient-only 描述

至少检查并修正：

- `krpc-s2s-standard-did-identity-refactor-TODO.md` 的 bad smell 表仍写着
  remote key 统一走 NameClient；
- `src/kRPC/src/s2s/client.rs` 文件头仍写 remote key 来自 NameClient；
- `src/kRPC/src/s2s/server_ctx.rs` 文件头仍写 request path 从 NameClient 解析；
- `from_did` 注释仍把 global NameClient 描述为默认完整方案。

所有描述必须统一为：

```text
Local: IdentityRoots
Remote: cluster_config Provider first; NameClient only on explicit NotManaged
Hot path: in-memory snapshot/cache
```

---

## 6. 目标结构

名称可按现有代码风格调整，但职责必须至少拆成下面三层。

### 6.1 Local identity loader

```rust
struct S2sLocalIdentityLoader {
    roots: IdentityRoots,
}

impl S2sLocalIdentityLoader {
    fn load(&self, local_did: &DID) -> S2sResult<LocalIdentitySnapshot>;
}
```

只允许访问：

- exact local `did.json`；
- exact local authentication private capability；
- local binding validation。

不得持有 NameClient 或 Remote Provider。

### 6.2 Remote public-key source

```rust
struct S2sRemoteIdentitySource {
    provider: Option<Arc<dyn S2sPublicKeyProvider>>,
    name_client_fallback: Option<Arc<NameClient>>,
    cache: RemoteIdentityCache,
}
```

只负责：

- Provider-first lookup；
- `NotManaged` 后 NameClient fallback；
- public-key validation；
- provenance/revision；
- cache/singleflight/invalidation/refresh。

不得访问 IdentityRoots 或 local private key。

### 6.3 Client/server snapshot

client 和 server request path 只能取得不可变 snapshot：

```rust
struct RemoteIdentitySnapshot {
    did: DID,
    ed25519_public: [u8; 32],
    fingerprint: [u8; 32],
    provenance: RemoteKeyProvenance,
    revision: Option<u64>,
}
```

建议 provenance 至少区分：

```rust
enum RemoteKeyProvenance {
    ClusterConfig,
    NameClient,
}
```

request/response 生命周期持有自己的 snapshot。cache 更新只影响后续请求，不在一个
已认证请求中途更换身份。

---

## 7. 分阶段执行清单

### Phase A：锁定规范和调用图

- [x] 把本 TODO 作为本轮 S2S identity Review 的执行清单。
- [x] 逐段核对 `did-identity-certificate-manager.md` 的 Local Identity 定义。
- [x] 修正根规范中 peer trust store / remote status 的含糊表达，或明确记录保留理由。
- [x] 枚举所有 `IdentityRoots` public method 及 production caller。
- [x] 枚举所有 `resolve_default_ed25519_key` caller。
- [x] 枚举所有 `S2sRuntime`、`S2sClientConfig`、`S2sRpcServerContext` 构造点。
- [x] 找到实际 cluster_config 类型、加载位置和更新通知机制。
- [x] 找到所有 `impl S2sPublicKeyProvider`；区分 production、test 与 example。
- [x] 画出 local load、remote initial load、normal request、rotation、revocation 五条
  实际调用链。
- [x] 明确 generic/non-cluster 模式是否允许 NameClient-only。

### Phase B：硬化 Local Identity 边界

- [x] 确认 `IdentityRoots` 不被任何 remote/peer lookup 使用。
- [x] 调整 local public-key loader 的名称、可见性或组合 API，消除 resolver 歧义。
- [x] 保证 local loader 一次完整校验 DID document、default key 与 private capability。
- [x] direct private file 优先，keyref 只在 direct 缺失时 fallback。
- [x] authentication material 保持 exact-only。
- [x] 复查 `find_identity_dir` 与 `IdentityStatus::installed` 的 public-only 语义。
- [x] 删除只服务于错误 remote lookup 语义的 helper、wrapper 或 re-export。
- [x] 添加测试：只有 peer `did.json`、没有 private capability 时，不能被当作可用
  Local Identity。

### Phase C：落实产品定义的 cluster_config Provider 边界

- [x] 明确 adapter 属于各产品；base 不定义 cluster_config schema。
- [x] Provider 契约要求直接读取产品已加载的不可变 snapshot，不访问网络。
- [x] Provider lookup 输入仅为 canonical target DID。
- [x] Provider 返回该 DID 当前唯一默认 authentication Ed25519 key。
- [x] 明确区分 Managed、NotManaged、Invalid/Error。
- [x] 配置存在但 key 缺失/非法时 fail closed，不得 fallback。
- [x] 公钥进入 cache 前完成 Ed25519/X25519 有效性检查。
- [x] 为 cluster client/server 提供 `for_cluster` / `cluster_builder` 强约束入口。
- [x] Review Provider-less `from_did` / `new` / `system` convenience API，删除或显式改名。
- [x] 加入产品侧 snapshot adapter wiring 测试，验证公共集成契约。

### Phase D：统一 remote cache 与更新生命周期

- [x] 记录 client transport、runtime、server context 当前每一层 cache。
- [x] 选择单一 remote cache entry/handle 模型。
- [x] 删除 client/runtime 间重复且无法统一失效的 remote-key 状态。
- [x] cache entry 保存 DID、key、fingerprint、provenance、revision/generation。
- [x] client 固定 target 构造时只加载一次。
- [x] server 首次见到 caller DID 时只加载一次。
- [x] normal request 热路径只读内存 snapshot。
- [x] 同一 DID 的并发首次加载使用 singleflight。
- [x] cluster_config 更新事件能 invalidate/reload 对应 DID。
- [x] cluster_config 删除/禁用事件立即使旧 entry 不可用于新请求。
- [x] Provider 管理域变化能使 NameClient fallback entry 失效。
- [x] key 替换后精确清理旧 fingerprint 的 derived-key cache。
- [x] 已开始的 request/response 继续持有自己的 local/remote snapshot。
- [x] 更新失败不破坏仍然有效的旧 entry，但撤销/禁用不得继续沿用旧 entry。

### Phase E：限制 refresh/retry

- [x] Review client request retry、client response open、server request open 的完整路径。
- [x] 每个协议操作最多一次 key-change retry，并使用 fresh nonce/ciphertext。
- [x] retry 前确认 cache generation/key fingerprint 确有变化；相同 key 不重复计算。
- [x] NameClient authority refresh 按 DID singleflight。
- [x] 增加 refresh cooldown/rate limit，阻止恶意 ciphertext 触发每请求解析。
- [x] Provider error 与 NameClient error 都 fail closed。
- [x] refresh 不得回退 pinned key、stale caller key 或明文。
- [x] refresh 成功后原子替换 snapshot 并清理相关 derived key。
- [x] 记录低敏感度 metrics：cache hit/miss、provider hit/not-managed/error、
  fallback、refresh、revision change；不得记录 secret 或完整 ciphertext。

### Phase F：重写隔离测试

- [x] 将 client/server 测试 fixture 拆成独立 IdentityRoots。
- [x] client roots 中不存在 server DID material。
- [x] server roots 中不存在 client DID material。
- [x] Provider 测试中 NameClient 故意返回错误 key，证明 Provider 优先。
- [x] Provider-only runtime 完全不初始化 NameClient。
- [x] NameClient fallback 测试中 Provider 明确返回 NotManaged。
- [x] Provider Error 测试证明不会 fallback。
- [x] Provider Managed-but-missing/invalid 测试证明 fail closed。
- [x] normal client request 不重复查询 Provider/NameClient。
- [x] normal server request 不重复查询 Provider/NameClient。
- [x] 并发首次请求对同一 DID 不形成查询风暴。
- [x] 不同 caller DID 使用独立 cache entry。
- [x] cluster_config key rotation 后新请求使用新 key。
- [x] cluster_config 删除/撤销后旧 key 立即被拒绝。
- [x] NotManaged -> Managed 时旧 NameClient cache 被替换。
- [x] Managed -> NotManaged 的策略行为被明确测试。
- [x] invalid ciphertext 连续攻击不会每次触发 authority network refresh。
- [x] refresh 得到相同 fingerprint 时不做无意义第二次 decrypt/seal。
- [x] local reload 与 remote reload 不互相污染 cache。
- [x] in-flight request 在合法 rotation 中保持 snapshot 一致。
- [x] `did:web`、`did:bns` 都遵守同一 local/remote 边界。
- [x] fragment、non-canonical DID、非 Ed25519、small-order key 继续 fail closed。

### Phase G：文档、注释和删除

- [x] 修正旧 TODO 中 NameClient-only 的目标描述。
- [x] 修正 client/server/identity 模块头注释。
- [x] 更新 `src/kRPC/readme.md` 的 cluster production 示例。
- [x] 更新 payload encryption 文档的 cache invalidation 与 refresh 限制。
- [x] 清楚标注 Local Identity root 不是 resolver cache。
- [x] 清楚标注 Provider lookup 与 Provider cache 是两个不同概念。
- [x] 删除重复 remote cache、无生产用途 wrapper、危险 convenience API。
- [x] 删除只为共享 roots 测试 fixture 服务的 helper。
- [x] 删除过时 NameClient-only、pinned/resolver、`DID#kid`、appid+zone 描述。
- [x] 用 `rg` 确认 production code 不存在已删除概念或过时注释。

---

## 8. 必须新增的关键测试场景

### 8.1 Local / Remote 物理隔离

```text
Given:
  client roots only contain client identity
  server roots only contain server identity
  remote keys only exist in Provider

Expect:
  S2S roundtrip succeeds
  no remote DID file is read from IdentityRoots
```

再增加反向防回归：

```text
Given:
  peer did.json is maliciously placed under local public identity root
  Provider contains the correct peer key

Expect:
  Provider key wins
  local public root copy is ignored for remote trust
```

### 8.2 Provider 三态

```text
Managed(valid key)       -> success; NameClient calls == 0
NotManaged               -> NameClient fallback
Err / invalid managed    -> fail closed; NameClient calls == 0
```

### 8.3 缓存与配置变更

```text
initial provider K1 -> cached K1
cluster config K2   -> invalidation/revision event
new request         -> K2
old K1 request      -> rejected
```

删除：

```text
initial provider K1 -> cached K1
cluster config removes/disables DID
new request using K1 -> rejected without waiting for decrypt-triggered refresh
```

### 8.4 解析风暴防护

对同一 DID 并发发起多个 cold request 和多个 invalid-ciphertext request，断言：

- initial provider/NameClient load 被 singleflight；
- authority refresh 次数受 cooldown/generation 限制；
- 内存、task 数量和 cache 容量有界；
- 所有失败保持密文错误，不降级明文。

### 8.5 Product wiring contract

使用产品侧最薄 adapter（测试中的 `ProductClusterSnapshot`），base 不规定其结构：

- 通过强约束入口构造 cluster S2S client；
- 通过强约束入口构造 cluster S2S server；
- 断言 Provider 被调用；
- 断言 NameClient 没有被调用；
- 推送一次 cluster_config generation 更新；
- 断言两端 cache 按设计更新。

---

## 9. 静态检查

执行并人工分类命中：

```bash
rg -n \
  'IdentityRoots|load_default_ed25519_public_key|resolve_default_ed25519_key|S2sPublicKeyProvider|S2sRuntime|remote_key|reload_remote_identity' \
  src/name-client src/kRPC src/buckyos-http-server

rg -n \
  'S2sClientConfig::new|S2sRpcServerContext::from_did|S2sRpcServerContext::builder|S2sPayloadV1' \
  src

rg -n \
  'remote default key comes from NameClient|从 NameClient 解析|统一经 NameClient|peer resolver|Pinned|remote_key_id|DID#kid|CallerAsserted|UnsafeSkip' \
  src doc
```

最终预期：

- Remote DID production path 中没有 `IdentityRoots` load；
- Local Identity loader 中没有 NameClient/Provider；
- cluster production path 不存在未安装 Provider 的隐式构造；
- 已删除概念在 production code 零命中；
- 历史文档中的命中被明确标为旧设计，而不是当前目标。

---

## 10. 验证命令

根据 workspace 实际 package/feature 调整，但至少执行：

```bash
cargo fmt --all -- --check
cargo check -p name-client
cargo check -p kRPC
cargo check -p buckyos-http-server
cargo test -p name-client
cargo test -p kRPC
cargo test -p buckyos-http-server
```

若 S2S 受 feature 控制，还必须覆盖：

```text
default features
S2S enabled
S2S disabled
provider-only
provider + NameClient fallback
NameClient-only（仅在明确允许的 non-cluster profile 中）
```

测试必须避免依赖开发机上真实的 zone resolver、global NameClient、环境变量 roots
或外部网络。

---

## 11. 最终验收清单

- [x] 根规范明确且一致地限定 Identity Manager = Local Identity Manager。
- [x] Local Identity 与 Remote Identity 在类型和依赖上结构性分离。
- [x] Local Identity roots 中不需要、也不允许依赖 peer identity material。
- [x] Provider 产品集成契约、generation token 与强约束 client/server 入口已实现；
      具体 cluster_config adapter 由各产品定义。
- [x] Provider 命中优先，NotManaged 才 fallback，Error fail closed。
- [x] normal request 热路径零文件 IO、零 Provider lookup、零 DID resolution。
- [x] 并发 cold load 与失败 refresh 不形成解析风暴。
- [x] config rotation/removal/revocation 能使 cache 及时更新或失效。
- [x] client/runtime/server 不存在失联的重复 remote-key cache。
- [x] remote snapshot provenance/revision/fingerprint 可被验证和观测。
- [x] local/remote rotation 都保持 in-flight snapshot 一致性。
- [x] test fixture 的 client/server IdentityRoots 完全隔离。
- [x] malicious peer file 放入 local public root 不会改变 remote trust。
- [x] Provider 产品 wiring contract 有端到端测试。
- [x] 文档、代码注释和示例没有 NameClient-only 冲突。
- [x] 重复模型、危险 convenience API、过时 wrapper 和无用测试 helper 已删除。
- [x] 本轮触及文件的格式、全部编译、单元测试和真实 HTTP S2S 测试通过。

---

## 12. 建议的执行顺序

不要从局部改名或 cache patch 开始。推荐顺序：

```text
1. 锁定根规范和 production cluster_config 所在位置
2. 拆分测试 roots，先让错误边界暴露出来
3. 拆分 LocalIdentityLoader / RemoteIdentitySource 职责
4. 接入 production Provider
5. 统一 remote cache 与 config generation/invalidation
6. 加 singleflight、refresh gate 和撤销语义
7. 删除重复状态与危险 convenience API
8. 更新文档、静态检查、全量验证
```

每个 Phase 完成后更新本 TODO 的 checkbox，并记录实际删除的类型、方法、文件和兼容
影响。不得为了让旧测试继续通过而重新向 Local Identity roots 写入 peer material。

---

## 13. 执行记录

### 13.1 API 与类型变更

- `IdentityRoots::load_default_ed25519_public_key` 已收为 private
  `load_local_default_ed25519_public_key`，不再暴露成通用 resolver。
- `IdentityRoots::load_default_ed25519_private_key` 已改为语义完整的
  `load_local_default_ed25519_identity`。
- `find_identity_dir` 已改为 `find_identity_material_dir`；
  `IdentityStatus::installed` 已拆明为 `material_present` 与 `locally_usable`。
- 删除无真实远端检查行为的 `check_x509_remote_status`。
- 删除隐式 `S2sRuntime::system`、通用 `S2sRuntime::new` 和
  `S2sRpcServerContext::from_did`；NameClient-only 必须通过包含
  `name_client_fallback` 的 API 显式选择。
- 增加 `S2sProviderLookup::{Managed, NotManaged}`、`S2sPeerPublicKey` 与
  `S2sProviderChangeToken`。base 不定义任何产品 cluster_config schema。
- 增加 `S2sClientConfig::for_cluster` 与
  `S2sRpcServerContext::cluster_builder`。

### 13.2 缓存与生命周期

- Local loader 与 Remote source 分为不共享数据源的两个结构。
- 删除 `S2sClientTransport` 自有的 `RwLock<RemoteDefaultKey>`；client/server
  统一持有 runtime cache entry handle。
- remote snapshot 记录 DID、key、fingerprint、provenance、revision 与
  source generation。
- 产品原子发布配置后推进 generation token；下一次协议操作在访问 Provider 前
  已判定旧 cache stale。
- cold load 与 authority refresh 都按 DID singleflight；NameClient refresh 有
  cooldown；未变化的 Provider generation 不因恶意密文重新 lookup。
- 只有 fingerprint 改变才允许一次 fresh-nonce retry，并精确失效旧 derived key；
  retry 与失败请求实际使用的 fingerprint 绑定，配置恰好在失败和 retry 之间发布时，
  已更新的 generation 不会被误判为“key 未变化”。

### 13.3 测试与范围结论

- HTTP fixture 已拆为物理隔离的 client/server roots，peer public material 只来自
  Provider 或独立 NameClient fixture。
- 新增三态、invalid managed、Provider-only、恶意 peer file、并发 cold load、
  rotation、revocation、管理域切换、Provider generation gate 与 NameClient
  cooldown 测试。
- `buckyos-base` 中不存在统一产品 cluster_config 类型；测试的
  `ProductClusterSnapshot` 只演示产品如何用自己的结构实现公共 trait。

### 13.4 最终验证

2026-07-30 已执行并通过：

```text
rustfmt --edition 2021 --check <本轮新增或重构的 Rust 模块文件>
git diff --check
cargo check -p name-client
cargo check -p kRPC
cargo check -p buckyos-http-server
cargo test -p name-client          # 209 unit + 2 integration
cargo test -p kRPC                 # 50 unit
cargo test -p buckyos-http-server  # 53 unit
```

静态搜索确认 production Rust code 中不存在旧的 S2S peer resolver、pinned key、
caller-asserted / unsafe binding、`remote_key_id` 或 NameClient-only 描述。

`cargo fmt --all -- --check` 也已执行；它会命中本轮开始前即存在、且与本 TODO
无关的 workspace 格式差异（也包括既有 crate root 中的旧格式）。为避免扩大修改
范围，这些基线差异没有被顺带重排；本轮新增或重构的模块文件均已单独通过当前
rustfmt，所有补丁通过 `git diff --check`。
