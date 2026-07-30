# kRPC S2S Payload Encryption Profile v1

状态：已实现；本文描述当前唯一的运行时模型。

## 1. 目标

kRPC S2S 在不增加在线握手的前提下，用双方标准 DID authentication Ed25519
身份保护完整 RPC JSON。Profile 提供：

- 双向 authenticated encryption；
- `From`、`To`、HTTP method、规范化 path、API name 与请求 nonce 的绑定；
- 时间窗、重放、body 大小与明文来源策略；
- 本地身份原子 reload；
- 远端身份轮换时的一次权威源重试。

它不替代 TLS，也不把 NAT、IP 或 session token 当成服务身份。

## 2. 唯一身份模型

### 2.1 wire identity

请求和响应的 `From`、`To` 都是 canonical DID：

```text
did:web:service.example.com
did:bns:service.example
```

不接受 DID URL fragment（例如 `#key-1`），也不接受非 canonical、控制字符、
空 method 或空 method-specific-id。`did:web` 与 `did:bns` 使用完全相同的
S2S 运行时路径。

### 2.2 本地身份

给定 canonical DID `D`，唯一标准入口是：

```text
$BUCKYOS_IDENTITY_ROOT/{encode(D)}/did.json
$BUCKYOS_SECURITY_ROOT/{encode(D)}/authentication.private.pem
```

要求：

1. `did.json.id == D`。
2. 默认 authentication verification method 是 Ed25519。
3. 私钥是 PKCS#8 PEM。
4. 私钥派生出的公钥等于 DID document 的默认 authentication 公钥。
5. authentication 材料 exact-only，不使用 wildcard。
6. 直接私钥不存在时可以读取精确路径下的 `authentication.keyref.json`；
   直接私钥存在时禁止由 keyref 覆盖。
7. signer/remote keyref 没有 X25519 key-agreement 能力时 fail closed。

本地密钥只由 `name-client::IdentityRoots` 加载。运行时持有不可变的
`Arc<LocalEd25519IdentityKey>` 快照，不暴露 seed。

### 2.3 远端身份

远端公钥统一调用：

```rust
NameClient::resolve_default_ed25519_key(did, source).await
```

解析结果必须满足 DID document id、默认 authentication verification method 和
Ed25519 曲线检查。业务层不能注入另一套 peer resolver 或旁路公钥。

## 3. 密码学

Profile v1 使用：

```text
Ed25519 private/public
  -> RFC 7748 compatible X25519 conversion
  -> X25519 static-static Diffie-Hellman
  -> HKDF-SHA-256
  -> XChaCha20-Poly1305
```

HKDF 输入绑定双方 DID 与方向；AEAD AAD 绑定：

```text
profile version
direction
From DID
To DID
timestamp
request nonce
HTTP method
canonical path
API name
```

响应继续绑定请求 nonce。每次 seal 都必须生成新的 24-byte nonce；重试不得复用
旧 nonce 或旧 ciphertext。

## 4. HTTP envelope

加密请求发往：

```text
POST /s2s/{api_name}
Content-Type: application/octet-stream
```

profile headers 表达版本、方向、From、To、时间、nonce 和 request nonce。
任何必需 header 缺失、重复、非 canonical、超限或与路由不一致都必须在解密前
拒绝。失败时不降级到明文。

明文只允许由显式 CIDR 与 API allowlist 同时放行，且不会产生 authenticated
service identity。forwarded source 默认不可信。

## 5. Client API

```rust
let config = S2sClientConfig::new(local_did, remote_did);
let client = kRPC::new_with_transport(
    endpoint,
    session_token,
    KrpcTransportSecurity::S2sPayloadV1(config),
).await?;
```

`S2sClientConfig` 只描述本地 DID、远端 DID、运行时和安全限制。构造时不接受
raw private key、remote public key、key ID 或自定义 resolver。

发送流程：

1. 从标准路径加载本地身份。
2. 用 `NameClient` BestAvailable 解析远端默认 Ed25519 key。
3. 生成新 nonce、AAD 和 ciphertext。
4. 校验响应 DID、方向、request nonce、时间与 AEAD。

## 6. Server API

```rust
let ctx = S2sRpcServerContext::builder(local_did)
    .security_policy(S2sServerSecurityPolicy::public_internet_default())
    .build().await?;
```

或：

```rust
let ctx = S2sRpcServerContext::from_did(local_did).await?;
```

server 从标准路径加载本地身份，从 `NameClient` 解析请求 `From` DID。成功解密后
把认证身份放入 request context；响应使用该请求解密时捕获的本地密钥快照。

## 7. rotation 与 retry

### 7.1 本地 rotation

reload 流程是：

1. 完整读取并验证新的 `did.json` 与私钥；
2. 构造新的不可变快照；
3. 在一次写锁操作中替换 current；
4. 清除 retired fingerprint 对应的派生密钥缓存。

不保留全局候选密钥或 grace 列表。已经解密的 in-flight 请求仍持有旧快照，因此
可以安全完成响应；新请求只使用 current。

### 7.2 远端 rotation

首次使用 BestAvailable 结果。若认证解密失败：

1. 仅允许一次 `RemoteAuthority` 强制刷新；
2. 若 fingerprint 改变，清理旧派生缓存；
3. client 以全新 nonce 重新 seal；server 用新 key 再尝试 decrypt；
4. 第二次失败后返回认证错误，不继续重试，不降级明文。

## 8. replay、限制与错误

replay key 至少包含 direction、双方 DID、request nonce 与时间 bucket。只有 AEAD
验证成功后才写 replay cache，避免未认证输入污染状态。

默认策略必须设置：

- clock skew 和消息最大年龄；
- encrypted/plaintext body 上限；
- header 长度上限；
- replay cache 容量；
- derivation cache 容量；
- public internet 明文 deny。

外部错误保持稳定、低信息量；日志不得记录私钥、shared secret、完整明文、
完整 ciphertext 或可直接重放的 header 集合。

## 9. 验收覆盖

当前测试覆盖：

- 标准两文件 roundtrip，完全不依赖 keyref；
- `did:web` / `did:bns` 同路径；
- fragment、畸形 DID、错误目标拒绝；
- body、path、API、nonce、response binding 篡改拒绝；
- replay、过期、未来时间、oversize；
- 明文 CIDR + API 双 allowlist；
- 本地原子 reload 与 in-flight 快照；
- 远端 stale-first、authority-refresh-success；
- 权威刷新失败后 fail closed；
- 真实 HTTP kRPC call 与 probe。

## 10. 实现位置

```text
src/name-lib/src/did.rs
src/name-client/src/identity_mgr.rs
src/name-client/src/name_client.rs
src/kRPC/src/s2s/
src/buckyos-http-server/src/test_s2s_rpc_server.rs
```

身份管理路径协议见
[`did-identity-certificate-manager.md`](did-identity-certificate-manager.md)。
