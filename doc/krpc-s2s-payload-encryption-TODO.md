# kRPC S2S Payload 加密 Profile TODO

> 状态：**基础库已实现**（2026-07-27，Phase 0–4 全量 + Phase 5/6 可在本仓库
> 落地的部分；见各 Phase 勾选与行内备注）。
>
> 代码入口：
> - 协议基元/密钥/policy/replay/客户端引擎：`src/kRPC/src/s2s/`（`kRPC::s2s`）；
> - 客户端 transport 模式：`kRPC::KrpcTransportSecurity` + `kRPC::new_with_transport`；
> - 服务端入口：`buckyos-http-server::serve_http_by_s2s_rpc_handler`
>   （共享 dispatch 已抽出，`RPCServerHandler`/`RPCServerContext` 见 `kRPC::protocol`）；
> - Identity Manager key provider：`name-client::IdentityManagerS2sKeyProvider`；
> - 共享 service DID 派生：`name_lib::zone_child_did` + `kRPC::s2s::derive_service_did`。
>
> 仍未完成（跨仓库/运维项）：endpoint descriptor 的 name-system 发布、共享
> replay store backend、metric/dashboard/告警接入、durable outbox/DLQ、
> 跨语言互操作实现与性能基准；见 Phase 5/6 未勾选项。
>
> 本 TODO 定义一个**可选的** `kRPC S2S Payload Protection v1`：
> 调用双方已经持有自己的 Ed25519 私钥，并能取得经过验证的对端 Ed25519 公钥；
> 双方不进行在线密钥交换或会话握手，而是在本地把 Ed25519 密钥转换为 X25519，
> 计算并缓存静态共享秘密，再对每个 kRPC JSON Payload 独立执行 AEAD 加密。

## 1. 决策摘要

1. kRPC 保留 HTTP per-request 模型，允许直接调用：

   ```text
   POST http://target_ip:port/s2s/$apiname
   ```

2. `/s2s/` 路径使用 HTTP Header 承载版本、身份 key reference、时间窗口和 nonce；
   HTTP Body 直接承载二进制 `ciphertext || Poly1305 tag`；
   完整 `RPCRequest` / `RPCResponse` JSON 作为 AEAD plaintext。
3. v1 固定使用：
   - Ed25519 公私钥按固定、带测试向量的规则转换为 X25519；
   - X25519 static-static DH；
   - HKDF-SHA-256；
   - XChaCha20-Poly1305；
   - 24-byte CSPRNG nonce；
   - Header 中的 nonce 使用 Base64URL without padding，Body 不做 Base64。
4. DH 和 HKDF 结果按 key epoch 缓存；每次 RPC 的密码学热路径只有：
   - 生成随机 nonce；
   - 请求一次 AEAD seal；
   - 响应一次 AEAD open（服务端方向相反）。
5. 本 Profile 不提供 TLS 1.3 意义上的前向安全。频繁轮换、及时删除旧私钥和派生密钥，
   可以把事后泄露的影响限制在对应 key epoch。使用者必须显式接受该风险。
6. 本 Profile 是 TLS/mTLS 的可选替代或叠加层，不得根据 `http://`、失败重试或服务端响应
   自动降级成明文。
7. 加密解决机密性、完整性和外部攻击者冒充问题，不替代 session token、RBAC、最小权限、
   限流、幂等和可靠事件投递。
8. 低频、best-effort API 必须有主动加密探测和永久错误告警，不能继续依赖真实业务流量
   偶然发现路由或密钥配置漂移。
9. 服务端必须通过 `S2sRpcServerContext` 注入安全策略。基础库默认 fail closed：
   `/s2s/` 只接受加密请求、不信任 forwarded client IP、不允许任意 peer，并强制时间窗口、
   replay 和资源上限。只有显式配置的可信来源网段才能使用明文。
10. `local_service_appid + current_zone_did` 派生 canonical service DID。默认按 Identity
    Manager 的 `authentication.keyref.json` 取得 Ed25519 私钥；context 也允许显式注入私钥或
    key-agreement provider，但必须校验其公钥与派生 service DID 绑定一致。

## 2. 背景

当前 S2S 调用依赖 HTTPS 网关完成 TLS 终止和 `/s2s/$apiname` 路由。网关配置与业务服务的
实际 API、地址和端口属于两个独立控制面，容易发生漂移：

```text
业务接口定义
      |
      v
HTTPS 网关证书 + path route
      |
      v
后端 IP:port
```

高频接口的错误通常会很快暴露；事件上报等低频、best-effort 调用则可能在错误发生很久以后
才被发现。只要调用方把网关返回或静默丢弃当作“已尽力”，永久配置错误就会被误判成临时
网络问题。

本设计把安全能力下沉到 kRPC endpoint，使服务发现中的身份化 endpoint 成为主要控制面：

```text
verified service descriptor
  = target service DID + default key + IP:port + API + security profile
      |
      v
http://target_ip:port/s2s/$apiname
      |
      v
目标服务自身完成身份校验、解密、授权和 handler dispatch
```

这样不再要求中心 HTTPS 网关理解每个 S2S API，也不要求每个服务通过 X.509 证书、SAN 和
网关规则才能在公网上获得 Payload 机密性。

## 3. 目标

1. 在没有 TLS 的公网 HTTP 上保护完整 kRPC request/response JSON 的机密性和完整性。
2. 复用已有 Ed25519/DID 身份与密钥轮换体系，不引入 CA、证书签发或在线握手。
3. 保留“一次 HTTP 请求就是一次 RPC”的模型，不建立加密 session。
4. 允许 HTTP LB、反向代理和普通四层转发存在，同时保持 Payload 端到端加密。
5. 将目标服务身份、API 和请求/响应方向绑定到密文，错误路由必须确定性失败。
6. 让加密成为显式可配置能力，并允许：
   - 明文 HTTP；
   - TLS/mTLS；
   - S2S Payload Protection v1；
   - TLS + S2S Payload Protection v1。
7. 对低频和 best-effort API 提供可主动检测的端到端健康信号。
8. 将每请求密码学成本限制为对称 AEAD；X25519/HKDF 只在 key epoch 首次使用或 cache miss
   时执行。
9. 允许管理员显式配置可信直连网段，使这些来源可以在同一 S2S handler 上使用明文 JSON；
   非可信网段必须使用 S2S Payload Protection。

## 4. 非目标

1. 不声称本协议具有 TLS 1.3 的前向安全、完整 HTTP 元数据保护或协议成熟度。
2. 不保护双方 service DID/key id、目标 IP、端口、HTTP path、消息长度、时序和外层 HTTP status
   等元数据。
3. 不替代 session token、RBAC 或业务权限检查。
4. 不提供第三方可验证的不可否认性。通信双方都能得到同一共享秘密，接收方理论上也能构造
   看似来自发送方的密文。
5. 不解决边缘节点运行时已被完全控制后的数据读取、合法调用和权限滥用问题。
6. 不把 best-effort 自动升级成 exactly-once delivery；可靠事件仍需 outbox、重试队列和
   业务幂等键。
7. v1 不协商算法。版本号唯一决定算法套件，避免协商和降级状态机。
8. v1 的加密 Body 是二进制；不把密文塞进 `RPCRequest.sys` 的 session token，也不再增加
   一层 JSON/Base64 envelope。
9. IP/CIDR allowlist 只表示该网络来源被允许使用明文，不自动证明具体 service DID；
   除非另有经过验证的精确 IP→service DID 绑定，plaintext 请求的 authenticated service identity
   必须保持为空。

## 5. 威胁模型与安全边界

### 5.1 假设

1. 调用方 Ed25519 私钥只由调用方持有。
2. 接收方 Ed25519 私钥只由接收方持有。
3. 双方取得的对端公钥已经通过 DID/name-system 的可信验证流程验证，且调用方明确选择了
   可接受的 freshness policy。
4. CSPRNG、X25519、HKDF-SHA-256 和 XChaCha20-Poly1305 实现正确。
5. nonce 直接取自 OS CSPRNG（`getrandom` 等价物），不使用用户态自维护的 PRNG 状态；
   以 VM/容器快照方式运行的节点依赖 vmgenid 等快照后重播种机制。同 key 重复 nonce
   对 ChaCha20-Poly1305 是灾难性的。
6. 接收方在 dispatch handler 前完成 AEAD 验证和原子 replay check。
7. 密钥轮换后，过期私钥及其派生共享秘密能在 grace period 结束后删除。

### 5.2 需要抵御

- 公网被动监听和抓包；
- HTTP 中间层读取或修改 JSON Payload；
- 外部攻击者伪造、截断或篡改 request/response；
- 把有效密文转发到不同目标服务、不同 API 或相反方向；
- 在有效期内原样重放已经捕获的 request；
- 通过版本或配置错误自动回退到明文；
- 伪造 `Forwarded` / `X-Forwarded-For` / 未验证 `real_src_addr` 绕过明文来源限制；
- HTTPS 网关 path route 与实际服务 API 长期漂移。

### 5.3 明确接受的残余风险

| 风险 | v1 行为 | 缓解方式 |
| --- | --- | --- |
| 当前 key epoch 私钥泄露 | 该 epoch 的历史抓包可能被解密；攻击者可在撤销前冒充节点 | 高频轮换、快速撤销、最小权限、删除派生 key |
| 旧 key epoch 私钥泄露 | 对应旧 epoch 的历史抓包可能被解密 | grace period 后销毁旧私钥和派生 cache，不保留无必要备份 |
| 当前私钥泄露后的主动调用 | 攻击者可以节点身份调用其有权访问的 API | RBAC、资源级权限、限流、行为检测和紧急吊销 |
| 接收方私钥泄露引发 KCI | 拿到 S 的私钥和公开的 P 公钥即可向 S 伪造“来自任意 peer P”的已认证请求，无需 P 的私钥 | 无密码学缓解；失陷节点作为接收方信任过的身份断言全部视为不可信；详见 5.4 |
| HTTP/S2S Header 元数据泄露 | 双方 service DID/key id、path、IP、长度、时间仍可见 | 需要时叠加 TLS/VPN；不在 v1 内解决 |
| 可信网 plaintext 被监听/篡改 | allowlist 网络中的攻击者或已失陷主机可以观察、修改明文 | 默认关闭；显式 CIDR+API；保留 token/RBAC；敏感 API 强制 encrypted |
| 公网 DoS | 攻击者可发送垃圾 Header/Body 消耗解析、key lookup 和解密资源 | Header/Body 上限、速率限制、并发限制、廉价前置校验 |
| 接收方伪造发送方密文 | 对称共享秘密不提供不可否认性 | 不把 S2S 消息当作第三方审计签名 |

### 5.4 与 TLS 1.3 的密码学性质差异

TLS 1.3 临时 ECDHE 会话密钥意味着：长期证书私钥以后泄露，通常不能仅凭历史抓包恢复过去
会话内容。

v1 使用 key epoch 内固定的 static-static DH。它的风险边界是：

```text
epoch E 的任一方私钥泄露
  + 攻击者拥有 epoch E 的对端公钥
  + 攻击者记录了 epoch E 的流量
  => epoch E 的历史 Payload 可被解密
```

频繁轮换只有在下列条件同时成立时，才能把影响限制在单个 epoch：

- 不可由当前私钥推导旧私钥；
- 旧私钥在 grace period 后被真正删除；
- 旧共享秘密和派生 AEAD key 同时从 cache 删除并尽可能清零；
- 日志、core dump、诊断输出和备份没有保存旧密钥材料。

除前向安全外，认证模型也不同。TLS/mTLS 通过私钥签名认证对端，冒充 client 必须持有
client 的私钥；v1 的 static-static DH 是隐式认证：

```text
shared_secret(P, S) = X25519(P_priv, S_pub) = X25519(S_priv, P_pub)
```

因此 S 的私钥泄露不仅允许冒充 S 本身，还允许攻击者只用公开的 P_pub 向 S 伪造
“来自任意 peer P”的已认证请求（Key Compromise Impersonation，KCI）。事件响应上必须把
“节点失陷”理解为：该节点作为接收方所信任的全部 sender 身份断言不可信，而不仅是该节点
自身身份可被冒充；一条身份断言的可信度是 min(本方私钥安全, 对端私钥安全)。v1 对此没有
密码学缓解；长期演进可在 AEAD plaintext 内叠加发送方 Ed25519 签名（sign-then-encrypt）
恢复签名级来源认证。

边缘节点私钥已经泄露时，攻击者主动使用节点身份调用系统通常比离线分析历史流量更直接。
结合边缘节点最小权限和高频轮换，本项目接受上述残余风险，允许使用者按部署场景选择 v1。
这是一项风险接受决策，不表示 v1 与 TLS 1.3 在密码学性质上等价。

## 6. 身份、密钥与轮换

### 6.1 appid、Zone DID 与 canonical service DID

配置侧使用短 `local_service_appid`，密码学身份使用完整、全局唯一的 canonical service DID。
服务启动时必须结合 `current_zone_did` 派生：

```text
derive_service_did(local_service_appid, current_zone_did)
    -> local_service_did
```

对 `did:web` Zone，示例规则是：

```text
local_service_appid = event-service
current_zone_did    = did:web:example.com
local_service_did   = did:web:event-service.example.com
```

实现必须通过共享 DID/Zone helper 派生和 canonicalize，不能在各服务中用字符串直接拼接。
appid 必须是合法单级 service label；Zone DID method 不支持 service child derivation时，context
构造直接失败，不猜测其他规则。

当前 `name-client` 已有内部 `zone_child_did(zone_did, name)`，对 `web` / `bns` 使用
`DID::new(method, "$name.$zone_id")`。实现时应把这条规则下沉成共享、公开并带测试的 helper，
让 name resolution、identity path 和 kRPC S2S 使用同一算法。

`local_service_did` 同时用于：

- 定位本机 active identity material；
- 校验显式传入私钥的 public key binding；
- KDF domain separation；
- S2S Header `From/To`；
- peer admission、RBAC 和 audit。

### 6.2 service key reference

Header 中的 `from` 和 `from_kid` 合并成一个 `ServiceKeyRef`；`to` 使用相同结构：

```text
ServiceKeyRef := canonical_service_did
               | canonical_service_did "#" key_id
```

例如：

```text
KRPC-S2S-From: did:web:event-producer.example.com
KRPC-S2S-To: did:web:event-service.example.com
```

省略 `#key_id` 表示使用该 service DID 的默认 active key。只有显式使用非默认 key、
轮换歧义无法通过 bounded active/grace candidate set 解决，或策略要求精确 key epoch 时，
才写：

```text
KRPC-S2S-From: did:web:event-producer.example.com#key-42
KRPC-S2S-To: did:web:event-service.example.com#key-19
```

要求：

- canonical service DID 和可选 key id 的语法、大小写与规范化由共享 `ServiceKeyRef` 类型定义；
- 同一个显式 key id 不得被重新绑定到不同公钥；
- Header 重复、空值、无法规范化或包含控制字符时直接拒绝；
- 省略 key id 只是 wire 简化，不表示密码学计算可以不确定实际 key；
- KDF/cache 必须绑定实际参与 DH 的 key fingerprint，不能只绑定字符串 `"default"`。

### 6.3 本地私钥来源

服务端解密确实需要本地身份私钥，客户端加密也需要同一类私钥完成 static-static DH。
默认来源遵守
[`did-identity-certificate-manager.md`](did-identity-certificate-manager.md) 的 active identity
path/keyref 协议：

```text
local_service_appid + current_zone_did
  -> canonical local_service_did
  -> IdentityRoots
  -> security root / encoded DID raw host URI /
  -> authentication.keyref.json
  -> authentication.private.pem             # mode=file 时
```

v1 基于 Ed25519 identity key 转换 X25519，因此默认 lookup：

```text
usage     = IdentityUsage::Authentication
algorithm = Ed25519
```

不得误用 `IdentityUsage::Server` 的 TLS P-256/RSA private key。未来使用独立 X25519
`IdentityUsage::KeyAgreement` 时，需要定义新的 profile/version 或明确兼容规则。

`S2sRpcServerContext` 同时允许显式传入私钥或 key provider：

```rust
pub enum S2sLocalKeySource {
    IdentityManager {
        roots: IdentityRoots,
    },
    ExplicitEd25519 {
        key: SecretEd25519Key,
    },
    Provider {
        provider: Arc<dyn S2sKeyAgreementProvider>,
    },
}
```

对应的 client/server 共享配置可以收敛成：

```rust
pub struct S2sLocalIdentityConfig {
    pub service_appid: String,
    pub current_zone_did: DID,
    pub key_source: S2sLocalKeySource,
}
```

`service_did` 是构造结果而不是第二个可独立填写的配置源，避免 appid、Zone 与 DID 漂移。

具体类型可以调整，但语义必须满足：

1. 显式 source 优先；未传入时才使用 Identity Manager 默认路径。
2. 显式 key 的 public key/fingerprint 必须与派生出的 `local_service_did` 及选定 key id 匹配；
   mismatch 直接失败，不能静默回退 Identity Manager。
3. raw private key 类型不得实现会泄露内容的 `Debug`/`Display`/`Serialize`，避免不必要的
   `Clone`，并在 drop/evict 时 zeroize。
4. `authentication.keyref.json` 必须校验 `did`、`usage`、`algorithm` 和
   `public_key_fingerprint`。
5. `mode=file` 可以加载 exportable Ed25519 private key；仅提供 Ed25519 sign 操作的
   signer/remote keyref **不足以**完成 X25519 DH。
6. 非 file keyref 只有在 provider 明确支持 X25519/key-agreement operation 时才能使用；
   否则返回 `KeyAgreementNotSupported` / `PrivateKeyNotUsableForS2s`，不能导出或伪造私钥。
7. `buckyos-http-server` 只消费 kRPC 定义的 provider trait，不直接读取 security root。

建议 provider 暴露“用指定 local key 与 peer X25519 public key 派生 shared secret”的能力，
而不是默认向 HTTP 层返回 raw private key，从而兼容 file、TPM/HSM/TEE 或独立 key agent。

### 6.4 对端公钥来源

- 客户端不得只因为某个 DID Document 能被解析就直接信任其中的 key。
- key 必须来自经过验证的 DID/name-system evidence。
- 取得 target public key 是关键安全行为。**推荐形态是确定值**：客户端直接
  消费 verified service descriptor（§12）给出的
  `(target_service_did, target_service_public_key)`，发送热路径不做任何隐式
  解析，验证责任明确落在产出 descriptor 的服务发现层
  （实现：`S2sClientConfig::with_pinned_key`，构造时即校验公钥有效性）。
  只有确实需要在线轮换发现的动态部署才使用 resolver 形态
  （`S2sClientConfig::with_resolver`），且 resolver 只能返回已验证 key。
- key freshness 是调用方策略：可以接受本地已验证 cache，也可以要求 Zone/Authority 最新。
- 热路径不得隐式执行无界远程 resolve；调用方应预热或使用有界、可观测的 key cache。
- 收到未知 target key reference 或解密失败时，客户端可以显式重新 resolve 一次并使用
  **新 nonce**重试；
  不得无限重试或降级明文。
- key id 被省略时，接收方最多只能尝试配置上限内的 active/grace key candidates，不得扫描
  无界历史 key。正常稳定期应只有一个 default candidate。
- default candidate 顺序固定为 active first、grace keys newest first，并设置很小的 hard limit；
  如果轮换频率和 request lifetime 导致候选数超过上限，sender 必须显式发送
  `service_did#key_id`。

### 6.5 Ed25519 到 X25519 的转换

v1 必须固定一种与 libsodium 语义兼容的转换规则，并提供跨语言测试向量：

- Ed25519 public key 转换为 X25519 public key；
- Ed25519 signing seed/private representation 转换为 X25519 static secret；
- 明确输入是 raw 32-byte seed、expanded secret 还是 PKCS#8，禁止把不同表示直接混用；
- 拒绝无效 Ed25519 public key；
- X25519 DH 后必须拒绝 non-contributory/all-zero shared secret。

当前仓库已有 `ed25519_to_curve25519` 和 `x25519-dalek` 基础代码，但实现前必须把转换规则、
输入格式和固定测试向量独立下来，不能把测试代码中的打印/临时转换逻辑直接作为协议规范。

长期演进可以让 DID Document 发布独立 X25519 exchange key，减少“一把 Ed25519 key 同时承担
签名身份和密钥协商输入”的耦合；这不是 v1 上线的前置条件。同一 key pair 兼用 Ed25519
签名与 X25519 密钥协商的安全性分析见参考文献中的 Thormarker 论文。

### 6.6 轮换

发送请求时：

1. 使用 canonical local service DID 的当前 active default key；
2. 使用服务发现/verified evidence 中目标 service DID 的当前 active default key；
3. 正常情况下 Header 只写 service DID；需要消除轮换歧义时才附带 `#key_id`；
4. cache key 至少包含：

   ```text
   profile_version,
   local_service_did, local_key_fingerprint,
   remote_service_did, remote_key_fingerprint
   ```

接收请求时：

- active private key 正常接收；
- 省略 key id 时，只在有界 active/grace candidate set 中选择；成功解密后固定实际 key epoch；
- grace-period private key 只用于处理轮换期间已发出的请求和对应响应；
- retired/revoked key 不再接收新请求；
- grace period 至少覆盖最大 request lifetime、允许的 clock skew 和一次有界重试窗口；
- grace period 结束后删除私钥以及使用该 key fingerprint 派生的 shared secret/AEAD key。

Identity Manager active path 只保证当前 active material，不保存完整历史。S2S key provider
应在 reload 时把旧 active key 作为内存 grace candidate 保留到期限后 zeroize；如果进程在
grace period 内重启且 provisioner 没有提供旧 key，旧请求可以失败，client 必须 refresh
target key 后以新 nonce 有界重试。需要跨重启兼容旧 key 时，由 rotation/provisioner 明确提供
受保护的 grace-key source，不能依赖 active path 猜测历史版本。

## 7. 密钥派生

### 7.1 shared secret

双方在本地计算：

```text
X25519(
    ed25519_private_to_x25519(local_private_key),
    ed25519_public_to_x25519(remote_public_key)
) -> shared_secret
```

协议不发送临时公钥，不产生额外网络 RTT。这里的“无密钥交换过程”准确含义是：
**没有在线握手或 per-request key exchange**；本地仍然执行一次 static-static DH。

### 7.2 HKDF

不得直接把 X25519 输出当作 AEAD key。使用 HKDF-SHA-256 进行 extract-and-expand，并绑定：

- 协议 domain；
- profile version；
- 双方 canonical service DID 与实际参与 DH 的 key fingerprint；
- 发送方向；
- message kind：request 或 response。

v1 的 key fingerprint 必须由实际 Ed25519 public key 的 canonical 32-byte encoding 计算，
建议冻结为：

```text
SHA256(
    encode(
        "buckyos.krpc.s2s.v1/ed25519-key",
        ed25519_public_key_32_bytes
    )
)
```

fingerprint 是 KDF/cache 的内部确定性 key commitment，不要求在默认 Header 中传输。

概念形式：

```text
ordered_peers = canonical_sort(
    (service_did_A, key_fingerprint_A),
    (service_did_B, key_fingerprint_B)
)

salt = SHA256(
    encode("buckyos.krpc.s2s.v1/kdf-salt", ordered_peers)
)

prk = HKDF-Extract(salt, shared_secret)

key = HKDF-Expand(
    prk,
    encode(
        "buckyos.krpc.s2s.v1/aead-key",
        from_service_did, from_key_fingerprint,
        to_service_did, to_key_fingerprint,
        message_kind
    ),
    32
)
```

`encode(...)` 必须使用协议规定的二进制长度前缀编码，不能依赖 JSON object field order、
调试字符串或平台默认字符编码。`canonical_sort` 按每个 `(service_did, key_fingerprint)`
元组 `encode` 后的字节字典序升序排序；比较规则属于协议的一部分，必须与测试向量一起冻结。

Header 中省略 key id 时，sender 仍然知道自己实际使用的 local key 和 resolve 得到的 remote
default key；receiver 则在有界 active/grace candidate set 中尝试。KDF 使用实际 key
fingerprint，因此错误 candidate 不会产生可用的 AEAD key。

请求和响应使用不同派生 key；A 调 B 与 B 调 A 也使用不同派生 key，防止方向反射和跨上下文
复用。

## 8. Wire protocol

### 8.1 分层

v1 把现有 kRPC JSON 当作需要保护的 application payload，而不是复用 `sys[1]` 的 session
token 字段装载密文：

```text
HTTP request
├── path: /s2s/$apiname
├── KRPC-S2S-* headers: parser dispatch + authenticated metadata
└── binary body: XChaCha20-Poly1305(ciphertext || tag)
                  └── plaintext: 完整 RPCRequest JSON bytes
```

因此公网抓包中：

- 能看到 HTTP method/path、S2S Header、双方 service DID、长度和时序；
- Body 是二进制密文；
- 看不到内部 `method`、`params`、`sys`、session token 和 trace id。

session token 的职责仍然是 application authentication/authorization。它随完整
`RPCRequest` 一起被加密，不能与 transport encryption 混为一个字段。

### 8.2 request

示意 wire：

```http
POST /s2s/event-report-v1 HTTP/1.1
Content-Type: application/vnd.buckyos.krpc-s2s
KRPC-S2S-Version: 1
KRPC-S2S-From: did:web:event-producer.example.com
KRPC-S2S-To: did:web:event-service.example.com
KRPC-S2S-Issued-At: 1785100000
KRPC-S2S-Expires-At: 1785100300
KRPC-S2S-Nonce: <base64url-24-bytes>
Content-Length: <ciphertext-size>

<raw ciphertext || 16-byte Poly1305 tag>
```

plaintext 是当前 `RPCRequest` 的完整 UTF-8 JSON bytes：

```json
{
  "method": "report_event",
  "params": {},
  "sys": [1021, "$tokenstring", "$trace_id"]
}
```

`sys` 数组与现有 kRPC 编码一致：`sys[0]` 是请求 `seq`（示例值 `1021` 只是普通序号，
不是协议常量），`sys[1]` 是可选 session token，`sys[2]` 是可选 trace id。

Header 约束：

- `KRPC-S2S-Version: 1` 唯一确定算法套件，不增加可协商的 algorithm header。
- `KRPC-S2S-From` / `KRPC-S2S-To` 使用规范化 `ServiceKeyRef`；默认 key id 不写。
- `KRPC-S2S-Issued-At` / `KRPC-S2S-Expires-At` 使用 UTC Unix seconds。
- 建议默认 request lifetime 为 5 分钟；服务端必须设置可配置但有上限的最大 lifetime。
- 接收方完整的时间窗校验为：`exp > iat`、`exp - iat <= max_lifetime`、
  `iat <= now + future_clock_skew`、`exp > now`；任何一条不满足即拒绝。
- timestamp 在事件真正发送时生成，不使用事件进入持久队列的时间。
- `KRPC-S2S-Nonce` 是 CSPRNG 生成的独立 24-byte 值，以 Base64URL without padding
  放入 Header。
- Body 是 AEAD 输出的原始 bytes，不做 Base64，也不再包 JSON。
- Header value 长度必须在 key resolve 或密码学操作前受限。

`Content-Type` 与 `KRPC-S2S-Version` 负责 parser dispatch：

- `Content-Type` 按 RFC 9110 解析后只比较小写 `type/subtype`，忽略 `charset` 等参数；
  缺失、无法解析或不是下列两种 media type 时直接拒绝，不做内容嗅探；
- `application/vnd.buckyos.krpc-s2s` 进入 v1 S2S binary body parser；
- `/s2s/` 收到 `application/json` 时先执行 server plaintext admission policy；只有可信来源
  IP 和 API policy 同时允许时，才进入现有 `RPCRequest` JSON parser；
- 安全默认配置拒绝所有 `/s2s/` plaintext；
- encrypted parser 失败后不得把同一 Body 重新解释成 plaintext，plaintext 被拒绝后也不得
  尝试其他 parser。

### 8.3 Header 解析与规范化

HTTP Header name 不区分大小写，但 v1 的 AAD 不使用原始 Header bytes。parser 必须先得到
结构化值，再按协议规范化：

- version 解析为固定宽度整数；
- `From` / `To` 解析为 canonical `ServiceKeyRef`；
- timestamp 解析为无符号整数；
- nonce 解码成恰好 24 bytes；
- 同名 S2S Header 出现多次直接拒绝，不允许逗号合并；
- 前后 OWS 按 HTTP 规则移除，内部空白和控制字符拒绝；
- 未识别的普通 HTTP Header 不进入 AAD，不影响解密；
- 未识别的 `KRPC-S2S-*` Header 默认拒绝，避免实现之间出现安全语义漂移。

### 8.4 request AAD

request AAD 固定按以下字段顺序编码：

```text
"buckyos.krpc.s2s.v1/aad"
version
"request"
"POST"
canonical_from_key_ref
canonical_to_key_ref
canonical_api_name
issued_at
expires_at
```

字符串与 byte string 使用 `u32 big-endian length || bytes`（字符串为 UTF-8 bytes）；
整数使用固定宽度 big-endian：`version` 为 u32，`issued_at` / `expires_at` 为 u64。
nonce 作为 AEAD nonce 参数传入，不需要再次复制进 AAD。

`canonical_from_key_ref` / `canonical_to_key_ref` 逐字节使用 wire Header 规范化后的
`ServiceKeyRef` 字符串：sender 省略 `#key_id` 时，AAD 中同样不含 key id；receiver 在
candidate 尝试过程中不得把补全的 key id 写进 AAD。实际参与 DH 的 key 由 §7.2 KDF 的
key fingerprint 绑定，错误 candidate 只会派生出无法解密的 key，不需要 AAD 参与消歧。

AAD 不绑定实际 IP、port、Host 或未知 Header，以允许 NAT、LB、服务迁移和标准代理 Header
改写。攻击者修改 S2S Header 或 HTTP path 中的 API 名称会导致 AEAD open 失败。

### 8.5 response

response 使用同样的 Header + binary Body：

```http
HTTP/1.1 200 OK
Content-Type: application/vnd.buckyos.krpc-s2s
KRPC-S2S-Version: 1
KRPC-S2S-From: did:web:event-service.example.com
KRPC-S2S-To: did:web:event-producer.example.com
KRPC-S2S-Issued-At: 1785100001
KRPC-S2S-Expires-At: 1785100301
KRPC-S2S-In-Reply-To: <base64url-request-nonce>
KRPC-S2S-Nonce: <base64url-new-24-bytes>
Content-Length: <ciphertext-size>

<raw ciphertext || 16-byte Poly1305 tag>
```

plaintext 是完整 `RPCResponse` JSON bytes。response AAD 固定按以下字段顺序编码
（编码规则与 request AAD 相同）：

```text
"buckyos.krpc.s2s.v1/aad"
version
"response"
"POST"
canonical_from_key_ref     # 逐字节等于 request 的 canonical_to_key_ref
canonical_to_key_ref       # 逐字节等于 request 的 canonical_from_key_ref
canonical_api_name
issued_at                  # response 自身的 Issued-At
expires_at                 # response 自身的 Expires-At
in_reply_to                # request nonce 的 raw 24 bytes（非 Base64URL 字符串）
```

规则：

- response 的 `KRPC-S2S-From` / `KRPC-S2S-To` 必须逐字节回显 request 的 `To` / `From`
  规范化形式；即使实际解密使用的是 grace key 或非默认 key，也不在 Header 和 AAD 中补全
  key id。实际 key pair 由 KDF fingerprint 绑定，client 的 key reference 一致性校验因此
  是纯字符串比较；
- 使用独立 response 派生 key（message kind = `response`）和新的随机 nonce；
- response 必须沿用本次 request 最终解密成功的实际 key pair；即使默认 key 在 handler
  执行期间发生轮换，也不能无提示切到另一组 key；
- 加密 response 必须携带 `Cache-Control: no-store`，防止中间层对 200 响应做启发式缓存。

客户端只有在以下条件全部满足时才接受响应：

- `Content-Type`、版本和必需 Header 正确；
- From/To key reference 与当前请求上下文一致；
- `In-Reply-To` 与本次 request nonce 一致；
- AEAD open 成功；
- 内部 `RPCResponse.seq` 与请求 `RPCRequest.seq` 一致；
- response 没有过期。

普通 HTTP `200` 本身不能表示 RPC 已被目标服务认证和接收。
认证成功后的业务成功/失败都放在加密 `RPCResponse` 中，外层可以统一使用 `200`；只有
HTTP/S2S transport 层在产生认证响应前失败时才使用非 2xx。

### 8.6 可信网明文模式

服务端显式允许可信直连网段后，同一入口可以接受：

```http
POST /s2s/event-report-v1 HTTP/1.1
Content-Type: application/json
Content-Length: <json-size>

<完整 RPCRequest JSON>
```

对应 response 是现有明文 `RPCResponse` JSON。该模式的安全规则：

- 必须先根据可信来源 IP policy 放行，再有界读取和解析 JSON Body；
- 只允许配置中明确列出的 CIDR 和 API；默认 CIDR/API 集合都为空；
- 不自动把 RFC1918、loopback、link-local 或本机接口识别为“可信网”；
- `KRPC-S2S-From` 即使出现在 plaintext 请求中也不产生 authenticated service identity；
- 默认仍要求现有 session token/RBAC 流程，不因为处于 allowlist 网段而跳过业务授权；
- 非可信来源的 plaintext 在进入 JSON parser 和 `RPCHandler` 前拒绝；
- client 必须显式选择 plaintext，不能先尝试加密再自动降级。

## 9. 服务端入口、dispatch 与错误处理

### 9.1 `serve_http_by_s2s_rpc_handler`

现有 `buckyos-http-server` 已提供：

```rust
pub async fn serve_http_by_rpc_handler<T: RPCHandler + Send + Sync + 'static>(
    req: http::Request<BoxBody<Bytes, ServerError>>,
    info: StreamInfo,
    rpc_handler: &T,
) -> ServerResult<http::Response<BoxBody<Bytes, ServerError>>>;
```

v1 应在同一模块增加命名和调用方式一致的入口：

```rust
pub async fn serve_http_by_s2s_rpc_handler<T: RPCHandler + Send + Sync + 'static>(
    req: http::Request<BoxBody<Bytes, ServerError>>,
    info: StreamInfo,
    rpc_handler: &T,
    s2s_context: &S2sRpcServerContext,
) -> ServerResult<http::Response<BoxBody<Bytes, ServerError>>>;
```

这里使用 `serve_...` 而不是 `server_...`，与现有函数命名保持一致。最终类型名可以在实现阶段
调整，但 `S2sRpcServerContext` 至少要提供：

- `local_service_appid` 和 `current_zone_did`；
- 由二者派生并校验的 canonical `local_service_did`；
- Identity Manager 默认 key source，或显式传入的 private key/key-agreement provider；
- active/grace private key provider；
- verified peer public key resolver/cache；
- derived key cache；
- replay store；
- `S2sServerSecurityPolicy`，包括 source IP、plaintext、peer admission、key verification、
  token binding、time/replay、resource limits 和 reject behavior；
- request lifetime、clock skew、Body/Header、candidate count 等限制；
- metric/audit sink。

`serve_http_by_s2s_rpc_handler` 负责 HTTP/S2S transport：

1. 根据 Content-Type、Version 和 S2S Header 选择并执行 parser；
2. 按安全策略解析具有明确 provenance 的 source IP，并先完成 plaintext/encrypted admission；
3. 有界读取 plaintext JSON 或 encrypted binary Body；
4. encrypted 分支完成 key selection、AAD、AEAD、时间窗口和 replay 验证；
5. 解析内部 `RPCRequest` JSON；
6. 构造区分 trusted-network 与 authenticated-service 的 server-side context；
7. 调用共享 RPC dispatch；
8. 按入站 transport mode 生成 plaintext JSON 或 encrypted binary response。

它不得把 name-system 的具体实现硬编码到 `buckyos-http-server`。key resolve、cache、replay
通过 kRPC 定义的 trait/context 注入，避免 HTTP server crate 直接承担身份控制面职责。

### 9.2 共享 RPC dispatch

不能直接复制 `serve_http_by_rpc_handler` 中从 `RPCRequest` 到 `RPCResponse` 的 handler/error
逻辑。应抽出共享内部函数，形成：

```text
serve_http_by_rpc_handler
  -> parse plaintext JSON
  -> dispatch_rpc_request
  -> serialize plaintext JSON response

serve_http_by_s2s_rpc_handler
  -> parse Header + decrypt binary Body + parse JSON
  -> dispatch_rpc_request
  -> serialize JSON + encrypt binary response
```

共享 dispatch 接收独立的 transport context，例如：

```rust
pub struct RPCServerContext {
    pub from_ip: Option<IpAddr>,
    pub source_ip_provenance: SourceIpProvenance,
    pub transport_security: RPCTransportSecurity,
    pub admitted_by_trusted_network: bool,
    pub authenticated_from_service_did: Option<DID>,
    pub authenticated_from_key_fingerprint: Option<[u8; 32]>,
    pub canonical_api_name: Option<String>,
}
```

字段名称可以调整，但必须区分：

- `from_ip`：网络观察值，不是密码学身份；
- `source_ip_provenance`：socket peer 或经过显式 trusted-proxy policy 接受的 forwarded source；
- `admitted_by_trusted_network`：只说明 plaintext transport 被放行，不代表 service 身份；
- `authenticated_from_service_did`：AEAD 成功后确认的 canonical service DID；
- inner JSON/token 中调用方自报的身份：仍需与 authenticated service identity 做策略校验。

当前 `RPCHandler::handle_rpc_call(req, ip_from)` 只能传 IP，生成的 `RPCContext` 也无法获得
authenticated service DID。实现 v1 时必须增加 context-aware handler/adapter，或迁移
`RPCHandler` 签名；不得把 appid 塞进 `from_device`、伪造 IP，或在全局变量中旁路传递。
plaintext 分支把 authenticated 字段设为 `None`；encrypted S2S 分支只能在 AEAD 和 replay
验证成功后填写。

### 9.3 接收顺序

服务端处理 request 的顺序必须固定：

共同前置步骤：

1. 从 `StreamInfo.conn_src_addr` 取得 socket peer；缺失或非法时 fail closed；
2. 只有 socket peer 命中 configured trusted-proxy CIDR 时，才允许按 policy 使用
   `real_src_addr`；普通 HTTP `Forwarded` / `X-Forwarded-For` 默认完全忽略；
3. 检查 HTTP method、canonical API path、Header count/size、Content-Length/body hard limit；
4. 根据 Content-Type 确定 plaintext 或 encrypted，不能通过解析失败切换模式；
5. 在读取完整 Body 前执行该模式的 admission policy。

plaintext 分支：

1. effective source IP 和 canonical API 必须同时命中显式 plaintext allowlist；
2. 有界读取并解析完整 `RPCRequest` JSON；
3. `authenticated_from_service_did = None`，记录 `admitted_by_trusted_network = true`；
4. 执行 session token/RBAC；unless explicit unsafe policy，token 缺失或验证失败不得 dispatch；
5. dispatch handler，生成现有 plaintext `RPCResponse` JSON。

encrypted 分支：

1. 只解析有界 `KRPC-S2S-*` Header，不解析加密 Body 内部 JSON；
2. 检查版本、Header 长度、nonce Base64 和 Body/tag 基本长度；
3. 用未认证的 `Issued-At`/`Expires-At` 按同一套 lifetime/skew 规则做廉价预拒绝，在任何
   key lookup/DH/AEAD 之前丢弃明显过期或超前的请求（Header 被篡改时 AEAD 仍会失败，
   预检不引入新风险，也不能替代第 10 步解密后的重新验证）；
4. 检查 `To` canonical service DID 是本服务，并得到本地有界 active/grace key candidates；
5. 根据 `From` service DID/key reference 取得有界、已经验证的 sender public key candidates；
6. 对 Header 声明的 `From` 执行廉价 pre-admission，限制无关 peer 的 key lookup/AEAD 成本；
7. 计算或读取派生 key，拒绝 all-zero/non-contributory DH；
8. 使用 canonical API 和结构化 S2S Header 构造 AAD；
9. AEAD open；
10. 重新验证已认证的 `iat/exp` 和服务端 lifetime policy；
11. 对成功解密得到的 authenticated identity 完成最终 peer admission；
12. 原子 replay check-and-insert；
13. 解析内部 `RPCRequest`；
14. 将 authenticated service identity 与 token/RBAC policy 联合验证；
15. dispatch handler；
16. 生成与 request nonce 绑定的加密 response。

现有 `client_ip()` 读取的是 `StreamInfo.src_addr`，而 `StreamInfo::with_addrs()` 会优先选择
`real_src_addr`。它可以继续用于非安全日志语义，但不能原样用于 plaintext security
admission；新入口必须使用带 provenance 的独立 source-address resolver。

### 9.4 错误处理

plaintext admission 或 encrypted authentication 完成前的错误必须返回统一、短小、无敏感
细节的 transport failure。不得向未认证调用方区分：

- sender 是否存在；
- sender key reference 是否存在或省略 key id 时尝试了哪些 candidates；
- tag 错误；
- source IP 命中了哪条 CIDR、proxy 或 API rule；
- token/RBAC 状态；
- 某个 API 是否真实存在。

服务内部 metric 可以记录低基数 reason code，但日志不得包含私钥、shared secret、派生 key、
完整 token 或明文敏感 Payload。

解密并认证后的业务错误应放入加密 `RPCResponse`。客户端据此区分：

- transient：超时、临时不可用、明确可重试；
- permanent：身份不匹配、API 不存在、权限拒绝、长期 key/config 错误、参数非法。

best-effort 只允许降低 transient delivery 的保证；permanent failure 必须进入告警或
dead-letter 流程，不能静默丢弃。

## 10. 重放、重试与幂等

### 10.1 transport replay

服务端 replay key：

```text
v,
canonical_from_key_ref, authenticated_from_key_fingerprint,
canonical_to_key_ref, authenticated_to_key_fingerprint,
request_nonce
```

- 在 AEAD 成功之后、handler dispatch 之前执行原子 `put-if-absent`；
- 已存在则拒绝，不再次 dispatch；
- replay entry 至少保留到 `exp + allowed_clock_skew`；
- 多实例服务必须使用共享 replay store、按 sender 稳定路由到同一实例，或提供等价的一致性；
- 仅使用每进程本地 cache 时，文档和配置必须明确它不能抵御跨实例重放。

### 10.2 client retry

网络超时后，客户端不知道服务端是否已经执行请求。重试时：

- 必须生成新的 request Header nonce；
- 可以保留相同的内部 `RPCRequest.seq` / 业务 idempotency key；
- 不得把原 S2S Header + Body 原样重放；
- 重试次数、backoff 和 key refresh 必须有界。

replay cache 只能阻止完全相同的密文被攻击者再次使用，不能自动提供业务 exactly-once。
有副作用的方法必须以 `(authenticated sender, seq)` 或显式 `event_id/idempotency_key` 做业务
去重。

事件上报建议使用：

```text
durable outbox
  -> bounded retry with stable event_id
  -> authenticated encrypted ACK
  -> success / permanent failure DLQ
```

## 11. Client 与 Server 安全配置

### 11.1 client transport mode

client 暴露显式枚举，而不是由 URL scheme 猜测：

```rust
pub enum KrpcTransportSecurity {
    Plaintext,
    Tls,
    S2sPayloadV1 {
        local_identity: S2sLocalIdentityConfig,
        remote_service_did: DID,
    },
    TlsAndS2sPayloadV1 {
        local_identity: S2sLocalIdentityConfig,
        remote_service_did: DID,
    },
}
```

必须满足：

- `S2sPayloadV1` 失败后绝不发送明文；
- 未识别 `v` 直接失败，不尝试 v0/plaintext；
- HTTP redirect 默认禁止；若允许，必须重新验证目标身份和 canonical API，且不能改变安全模式；
- endpoint descriptor 必须明确声明 security profile；
- 只有 endpoint/service policy 明确声明 trusted-network plaintext 时，client 才能配置
  `Plaintext`，不能仅根据目标 IP 看起来像内网就自动选择。

### 11.2 server policy model

`S2sRpcServerContext` 必须持有不可缺省的安全策略对象。建议形态：

```rust
pub struct S2sRpcServerContext {
    local_identity: S2sLocalIdentity, // builder 构造，字段只读
    pub security: S2sServerSecurityPolicy,
    // key provider / peer resolver / derived cache / replay store / metrics ...
}

pub struct S2sLocalIdentity {
    service_appid: String,
    current_zone_did: DID,
    service_did: DID, // 由前两项派生
    key_source: S2sLocalKeySource,
}

pub struct S2sServerSecurityPolicy {
    pub source_ip: SourceIpPolicy,
    pub transport: S2sTransportAdmission,
    pub peer_admission: PeerAdmissionPolicy,
    pub peer_keys: PeerKeyVerificationPolicy,
    pub auth_binding: AuthBindingPolicy,
    pub message: S2sMessagePolicy,
    pub limits: S2sResourceLimits,
    pub rejection: RejectionPolicy,
}
```

这些类型是设计形态，不要求逐字段照抄；但基础库必须提供完整 policy evaluation，应用不能
通过自己拼几个 boolean 重做安全判断。

### 11.3 source IP policy

建议至少支持：

```rust
pub enum SourceIpPolicy {
    /// 安全默认：只使用 TCP/QUIC connection 的直接 peer address。
    SocketPeerOnly,
    /// 只有 socket peer 命中 trusted_proxy_cidrs，才接受 lower layer 提供的 real source。
    TrustedProxy {
        trusted_proxy_cidrs: Vec<IpNet>,
    },
}
```

规则：

- `SocketPeerOnly` 是默认值，使用 `StreamInfo.conn_src_addr`；
- `StreamInfo.src_addr` 和 `real_src_addr` 不能直接作为安全输入；
- 普通请求携带的 `Forwarded`、`X-Forwarded-For`、`X-Real-IP` 默认忽略；
- trusted proxy 模式先校验 `conn_src_addr` 属于 proxy allowlist，再接受由可信 lower layer
  填入的 `real_src_addr`；
- proxy allowlist 为空、地址 provenance 不清楚或解析失败时 fail closed；
- IPv4-mapped IPv6、CIDR canonicalization 和地址比较使用统一、经过测试的 `IpNet` 实现；
- `source_hostname`、MAC、反向 DNS 不能作为公网 plaintext admission 依据。

### 11.4 transport admission 与 IP allowlist

建议：

```rust
pub enum S2sTransportAdmission {
    /// 安全默认。
    EncryptedOnly,
    EncryptedOrPlaintext {
        plaintext_source_cidrs: Vec<IpNet>,
        plaintext_apis: ApiAllowlist,
        plaintext_auth: PlaintextAuthPolicy,
    },
}
```

`EncryptedOrPlaintext` 的判断是：

```text
request mode == plaintext
  AND effective source IP ∈ plaintext_source_cidrs
  AND canonical API ∈ plaintext_apis
  AND plaintext auth policy satisfied
```

规则：

- 基础库不自动加入 `10/8`、`172.16/12`、`192.168/16`、loopback、ULA 或 link-local；
- `0.0.0.0/0`、`::/0` 等全网 plaintext 配置默认拒绝启动，除非调用显式标记为 unsafe 的 API；
- CIDR 允许明文 transport，但不产生 authenticated service DID；
- `PlaintextAuthPolicy` 安全默认要求 session token 存在并进入正常 verifier/RBAC；
- 如应用确实只依赖网络隔离，必须通过名字明确含 `UnsafeNetworkOnly` 的选项显式开启；
- plaintext 被拒绝时，在读取/解析完整 JSON 和 dispatch handler 之前终止；
- encrypted 解析/验证失败绝不 fallback 到 plaintext；
- 同一路径同时支持两种模式是 policy-driven parser dispatch，不是 opportunistic downgrade。

### 11.5 其他验证策略

公网 S2S 至少需要以下可配置项：

| 策略 | 安全默认 |
| --- | --- |
| peer admission | `DenyAll` 或构造 context 时强制选择 explicit service allowlist/policy；`AnyVerifiedService` 必须显式开启 |
| peer key source | 已验证的本地/Zone cache；公网 request hot path 不因随机 appid 无界 remote resolve |
| key freshness | 使用调用方明确的 verified freshness policy，不接受 observed/unverified key |
| target binding | `To` 必须等于派生的本地 canonical service DID，canonical API 必须进入 AAD |
| token binding | 不因 transport 加密或 IP allowlist 跳过 RBAC；支持要求 token subject/audience 与 authenticated service/API 一致 |
| message lifetime | 默认最大 5 分钟，future clock skew 默认不超过 60 秒，可收紧 |
| replay | encrypted request 必须启用，store 故障 fail closed；生产多实例要求 shared/equivalent store |
| key candidates | 默认最多 2 个；超过时要求显式 `service_did#key_id` |
| parser limits | Header 总大小、单字段、Body、JSON depth/complexity 都有 hard limit |
| concurrency | key resolve、DH/AEAD、handler 分别有并发/速率上限 |
| error disclosure | 未认证错误使用统一短响应，不返回 appid/key/API 是否存在 |
| audit | 记录 policy decision reason，但不记录 token、明文 Payload 或密钥材料 |

建议 v1 初始默认值：

| 项目 | 建议默认 |
| --- | --- |
| plaintext CIDR/API | 空，全部拒绝 |
| trusted proxy CIDR | 空，不信任 forwarded source |
| request max lifetime | 300 秒 |
| future clock skew | 60 秒 |
| active/grace candidate | 最多 2 个 |
| Header total size | 16 KiB |
| encrypted/plaintext Body | 1 MiB |
| JSON nesting | 64 层 |
| request-triggered remote key resolve | 0；只使用 verified cache，后台主动刷新 |
| replay store failure | fail closed |
| unauthenticated error detail | 关闭 |
| plaintext rejection | handler 不执行；默认返回无细节的短 403，部署可选择直接关闭连接 |

具体数值需要在实现 review/benchmark 后冻结，并允许服务按 Payload 和机器能力收紧/放宽。
放宽 hard limit 必须是显式配置，不能通过 `0`、空值或解析失败隐式表示 unlimited。

### 11.6 安全构造器与预设

基础库至少提供：

```rust
S2sServerSecurityPolicy::public_internet_default()
S2sServerSecurityPolicy::trusted_network_plaintext(cidrs, apis)
S2sServerSecurityPolicy::builder()

S2sRpcServerContext::builder(local_service_appid, current_zone_did)
    .identity_manager_key(identity_roots) // 默认生产路径
    // 或 .explicit_ed25519_key(secret)
    // 或 .key_agreement_provider(provider)
```

`public_internet_default()`：

- `SocketPeerOnly`；
- `EncryptedOnly`；
- peer fail closed；
- verified keys only；
- replay/time/resource limits 必开；
- generic unauthenticated rejection；
- 不信任 forwarded address。

如果实现 Rust `Default`，其行为必须与 `public_internet_default()` 相同；禁止对安全 policy
直接 `derive(Default)` 后得到 allow-all、unlimited 或 replay disabled。

`trusted_network_plaintext(cidrs, apis)` 在上述默认值上只增加指定 CIDR/API 的 plaintext
admission，并保留 token/RBAC、Body limit、rate limit 和审计。

context 构造或配置 reload 必须验证不变量并返回错误，而不是运行时静默修正：

- 选择 `EncryptedOrPlaintext`，但 CIDR/API 为空或包含全网段；
- trusted proxy policy 没有 proxy CIDR；
- encrypted mode 没有 key provider/replay store；
- appid + Zone DID 无法派生 canonical service DID；
- Identity Manager keyref 的 DID/usage/algorithm/fingerprint 不匹配；
- 显式 private key 的 public key 与 derived service DID/key id 不匹配；
- signer/remote provider 只有 sign capability、不支持 key agreement；
- candidate/lifetime/body limit 超出 library hard cap；
- peer policy 未选择；
- plaintext policy 试图把 IP allowlist 当作 authenticated service identity。

动态 reload 应原子替换完整 immutable policy snapshot；一次 request 从 source admission 到
dispatch 必须使用同一 policy generation，避免半途混用新旧规则。

## 12. 服务发现与消除配置漂移

verified service descriptor 至少应能表达：

```json
{
  "service_appid": "event-service",
  "zone_did": "did:web:example.com",
  "service_did": "did:web:event-service.example.com",
  "endpoint": "http://203.0.113.10:18080",
  "security": "krpc-s2s-v1",
  "apis": ["event-report-v1"]
}
```

目标是让以下字段来自同一份经过验证、可轮换的事实：

- 服务身份；
- appid + Zone DID 与派生 canonical service DID 的一致性；
- endpoint；
- 默认 active key 及可选的显式 key reference；
- 支持的 security profile/version；
- API name/version。

如果现有 name-system 暂时不能一次发布所有字段，应用配置也必须把它们视作一个原子
`S2sEndpoint`，避免分别维护 URL、网关 route 和 peer key。

## 13. 主动探测与可观测性

低频 API 不能等待真实调用发现漂移。每个启用 v1 的 endpoint 应支持加密：

```text
POST /s2s/__probe
```

probe 至少验证：

- endpoint 可达；
- target canonical service DID、默认 active key 和可选显式 key reference 正确；
- 双方 Ed25519→X25519 转换和 HKDF 一致；
- request/response AEAD 正常；
- response 与 request nonce 正确绑定；
- 服务端注册表中存在调用方期望的 API/version，但不执行该业务 API。

probe 不是旁路：它必须走与业务请求完全相同的 admission、时间窗、replay 和资源限制管线。
API registry 存在性查询只对通过 peer admission 的已认证调用方开放，并受 RBAC 约束：
调用方只能探测自己有权调用的 API，避免任意已验证 peer 枚举全部 API registry。

建议 metric：

- `krpc_s2s_admission_total{mode,outcome,reason}`；
- `krpc_s2s_request_total{outcome}`；
- `krpc_s2s_transport_failure_total{reason}`；
- `krpc_s2s_replay_rejected_total`；
- `krpc_s2s_key_cache_hit_total` / `miss_total`；
- `krpc_s2s_probe_success_timestamp`；
- `krpc_s2s_last_authenticated_success_timestamp`；
- `krpc_s2s_permanent_failure_total{api,reason}`；
- outbox backlog、oldest event age、DLQ count。

告警不能只依赖 error ratio，因为低频 API 可能长时间没有分母。至少同时使用：

- 周期 probe 连续失败；
- 距离最后一次 authenticated success 超过阈值；
- permanent failure 出现；
- oldest queued event 超过 SLA。

不得把 sender service DID、key id、trace id 或动态错误字符串无界放入 metric label。

## 14. 资源与 DoS 限制

公网明文 HTTP endpoint 即使 Payload 加密，也仍然暴露解析和密码学入口。实现必须提供：

- HTTP Header count/total-size 与 Body hard limit；
- S2S Header value、key reference 和 ciphertext 长度限制；
- 读取完整 body 前的 Content-Length 检查；
- 对缺少 Content-Length 或 chunked body 仍使用有界 streaming collect；
- 按 source IP 的粗限流；
- plaintext admission 在 Body collect/JSON parse 前完成；
- 认证成功后按 sender identity 的精确限流；
- 并发解密上限；
- DID resolve/cache miss 的 single-flight 和速率限制；
- 派生 key cache 上限、TTL 和按 key epoch 主动失效；
- replay store 容量和过载策略；
- 统一、廉价的未认证错误响应。

不得让攻击者通过随机 `From` service DID/key reference 触发无界远程 DID resolve 或无界
active/grace key candidate 尝试。

## 15. 性能预期

连接池命中、派生 key cache 命中时，每次 RPC 只增加：

- request/response 各一次 XChaCha20-Poly1305；
- 两次 24-byte nonce 生成；
- 少量 S2S Header 解析和 nonce Base64URL 编解码；
- replay store 操作。

它不会在热连接上显著快于 TLS Record 加密，但 binary Body 避免了整个密文的 Base64
约 1/3 体积膨胀，也省掉了 JSON envelope 的解析和内存拷贝。
本 Profile 的主要收益是：

- 不部署 X.509/CA；
- 不依赖中心 HTTPS 网关做 S2S API 分流；
- 冷连接没有 TLS handshake；
- Payload 可以跨越终止 TLS 的 HTTP 中间层保持端到端加密。

实现完成后必须对比：

1. plaintext HTTP；
2. pooled TLS 1.3/mTLS；
3. HTTP + S2S Payload v1；
4. TLS + S2S Payload v1。

分别测试 warm/cold connection、不同 Payload 大小、key cache hit/miss、单实例和集群 replay
store，记录 p50/p95/p99、CPU、allocation 和 wire bytes。

## 16. 实现任务

### Phase 0：冻结协议

- [x] 确认 v1 Header 名称、大小上限、timestamp 单位和默认 lifetime
  （`kRPC::s2s` 常量：`HEADER_S2S_*`、`S2S_DEFAULT_*`、`S2S_HARD_*`）。
- [x] 冻结 `ServiceKeyRef = canonical_service_did[#key_id]` 的语法和 canonical form
  （`s2s/service_key_ref.rs`，含拒绝非 canonical/控制字符/重复 `#` 测试）。
- [x] 冻结 `local_service_appid + current_zone_did -> canonical service DID` 的派生规则和
  test vectors（`derive_service_did` + name-lib/kRPC 两侧测试）。
- [x] 将现有私有 `zone_child_did` 规则下沉为 name-lib 共享 helper，并让 resolver/identity/S2S
  复用（`name_lib::zone_child_did`；name-client `NameClient::zone_child_did` 已委托）。
- [x] 冻结 Ed25519 public key fingerprint 的 domain-separated 计算规则
  （`ed25519_key_fingerprint`，`SHA256(encode("buckyos.krpc.s2s.v1/ed25519-key", pk))`）。
- [x] 定义 canonical length-prefixed encoder，并冻结 AAD/KDF 整数字段宽度
  （`version`=u32，`iat`/`exp`=u64）与 `canonical_sort` 字节字典序比较规则
  （`s2s/codec.rs`，layout 有冻结字节级测试）。
- [x] 冻结 canonical API name 的字符集、长度上限和规范化规则（percent-encoding、大小写、
  `..`/`//` 处理），并保留 `__` 前缀给协议自身（如 `__probe`）（`s2s/api_name.rs`）。
- [x] 冻结 response AAD 字段表与 `In-Reply-To` 在 AAD 中的编码（raw 24 bytes）
  （`s2s/aad.rs`）。
- [x] 冻结“AAD key reference 逐字节使用 wire 形式、response Header 对调回显 request
  `To`/`From`”的规则（`open_request`/`seal_response`/`open_response` 实现并有测试）。
- [x] 固定 Ed25519 private input representation（raw 32-byte seed）和 libsodium-compatible
  转换规则（`s2s/keys.rs` 模块注释 + 实现）。
- [x] 生成并 review Ed25519→X25519、DH、HKDF、request/response AEAD 完整测试向量
  （`frozen_test_vector_conversion_and_kdf`；实现变更导致该测试失败即 wire 不兼容）。
- [ ] 至少使用一个独立实现验证测试向量。
  （Ed25519→X25519 转换已用 `ed25519_to_curve25519` crate 交叉验证;
  DH/HKDF/AEAD 全链路向量的独立实现验证仍待做。）
- [x] 第一轮协议安全 review（2026-07-27）：产出 KCI 残余风险、AAD wire-form 规则、
  response AAD 冻结、API name 规范化等意见，已并入本文档。
- [ ] 测试向量冻结前，由独立实现/外部视角再做一轮密码学 review。

### Phase 1：crypto foundation

- [x] 在 workspace 固定 `hkdf`、`chacha20poly1305`、`zeroize`、`ipnet` 等依赖版本和 feature。
- [x] 提供 key provider 接口，只返回必要的 key handle（`S2sLocalKeyHandle`），不复制或
  打印私钥（`SecretEd25519Key` 无 Clone/Serialize，Debug redacted，drop 即 zeroize）。
- [x] 定义 `S2sKeyAgreementProvider` capability，使非导出 key 可以直接执行 X25519 DH；
  sign-only provider 不得被误判为可用（signer/remote keyref 返回
  `KeyAgreementNotSupported`，见 name-client `identity_s2s.rs`）。
- [x] 提供经过验证的 peer key resolver/cache 接口
  （`S2sPeerKeyResolver` + `StaticPeerKeyResolver`；`refresh_verified_keys` 供显式刷新）。
- [x] 实现 Ed25519→X25519 转换并拒绝无效/non-contributory key。
- [x] 实现 directional request/response key derivation（`derive_aead_key`,方向与
  kind 分离有测试）。
- [x] 实现有界、可失效、尽可能 zeroize-on-evict 的派生 key cache
  （`DerivedKeyCache`,容量/TTL/按 fingerprint 失效）。
- [x] 审计现有测试和日志，删除私钥、转换后私钥、shared secret 的打印
  （name-lib utility.rs 测试中的私钥/PEM 打印已删）。

### Phase 2：protocol types

- [x] 定义严格的 request/response S2S Header DTO 和字段上限（`s2s/headers.rs`：
  重复/缺失/超长/控制字符/未知 `krpc-s2s-*` 一律拒绝）。
- [x] 实现 Header nonce 的 Base64URL no-padding 编解码（严格 32 chars/24 bytes）。
- [x] 实现 binary ciphertext Body，禁止密文 Base64/JSON wrapper。
- [x] 实现 canonical AAD/KDF context encoder。
- [x] 实现完整 `RPCRequest` / `RPCResponse` bytes 的 seal/open（XChaCha20-Poly1305）。
- [x] 增加 unknown version、wrong kind、wrong peer、wrong API、expired message 等结构化错误
  （`S2sError`,含低基数 `reason_code()`）。
- [x] 确保错误类型不会把密码学细节直接返回未认证 peer（服务端统一无细节短 403；
  `DecryptFailed` 刻意不区分失败原因）。

### Phase 3：client

- [x] 为 `kRPC` 增加显式 `KrpcTransportSecurity` 配置
  （`Plaintext`/`Tls`/`S2sPayloadV1`/`TlsAndS2sPayloadV1`，不由 URL scheme 猜测）。
- [x] 不改变现有 plaintext/TLS 模式的 wire compatibility（现有测试全部保留通过）。
- [x] S2S 模式在发送前取得 verified target key，生成 S2S Header 和 binary Body
  （推荐 `with_pinned_key` 直接固定 `(target_service_did, target_public_key)`
  确定值,发送路径零隐式解析;`with_resolver` 供动态部署,见 §6.4）。
- [x] 禁止 redirect/失败后的隐式 plaintext fallback（S2S 模式 reqwest
  `redirect::Policy::none()`;任何失败路径都不会发出明文）。
- [x] 验证 response service DID/key reference、request nonce、时间和内部 seq
  （`open_response` + `check_rpc_response`）。
- [x] 实现一次有界 key refresh retry，并始终使用新 nonce
  （`post_s2s` 两次尝试上限;重试路径 `refresh_verified_keys` + 失效派生 cache）。
- [x] 将 permanent/transient failure 暴露给调用方，避免全部压成 `ReasonError(String)`
  （`RPCErrors::S2sPermanentError` / `S2sTransientError`）。

### Phase 4：server

- [x] 在 `buckyos-http-server` 增加 `serve_http_by_s2s_rpc_handler`（`s2s_rpc_server.rs`）。
- [x] 从现有 `serve_http_by_rpc_handler` 抽出共享 `dispatch_rpc_request`，禁止复制
  handler/error mapping。
- [x] 定义 `S2sRpcServerContext`，包含 local appid、current Zone DID、derived service DID、
  local key source、peer resolver 和 replay store（builder 构造并校验不变量）。
- [x] 接入 Identity Manager：按 derived service DID + `IdentityUsage::Authentication`
  加载 active Ed25519 keyref（name-client `IdentityManagerS2sKeyProvider`；
  监听/自动 reload 由调用方在轮换事件时调用 `reload()`,见 Phase 5 备注）。
- [x] 支持 context 显式传入 Ed25519 private key 或 `S2sKeyAgreementProvider`，并强制校验
  public key 与 derived service DID/key id 匹配（`LocalKeyBindingCheck::VerifyAgainst`,
  测试环境可显式 `unsafe_skip_local_key_binding_check`）。
- [x] 为 signer/remote keyref 定义 key-agreement capability；sign-only provider 返回明确错误。
- [x] 定义 `S2sServerSecurityPolicy`、安全默认值、trusted-network preset 和配置 validation
  （`public_internet_default()`/`trusted_network_plaintext()`/builder;`Default` 即安全默认）。
- [x] 实现 immutable policy snapshot 与原子 reload（`policy_snapshot()`/`reload_policy()`,
  一次 request 全程使用同一 snapshot）。
- [x] 实现基于 `conn_src_addr` 的 source-address resolver；trusted proxy 必须验证 socket peer
  后才能采用 `real_src_addr`（`resolve_effective_source` + `SourceIpProvenance`）。
- [x] 实现 CIDR + canonical API 的 plaintext admission，并确保 admission 在 Body parse 前完成。
- [x] 定义 `RPCServerContext`，迁移或扩展 `RPCHandler` 使 authenticated service DID
  能进入生成的 `RPCContext`（新 `RPCServerHandler` trait + 既有 `RPCHandler` blanket
  adapter;`RPCContext::from_server_context`）。
- [x] 为 `/s2s/$apiname` 增加有界 S2S Header + binary Body parser。
- [x] 在解析内部 JSON 和调用 handler 前完成身份、AEAD、时间和 replay 验证
  （§9.3 顺序在 `serve_encrypted` + `S2sRpcServerContext::open_request` 内固定）。
- [x] 将认证后的 sender service DID/key fingerprint 加入 `RPCContext`，供 token/RBAC
  做一致性检查。
- [x] 实现 request-bound encrypted response（含 `Cache-Control: no-store`）。
- [x] 对未认证错误返回统一 transport failure（统一短 403 "Forbidden",内部只记
  低基数 reason code）。
- [x] 实现共享 replay store trait 和原子 `put-if-absent`（`S2sReplayStore`）。
- [x] 明确单实例 local replay cache 与生产集群 backend 的配置区别
  （`MemoryReplayStore::new_single_instance` 命名 + 文档;共享 backend 经
  `.replay_store(..)` 注入,本仓库未提供具体分布式实现）。
- [x] 保留 `serve_http_by_rpc_handler` 的 plaintext wire compatibility 和现有测试。
- [x] 为现有 `serve_http_by_rpc_handler` 明文入口补上有界 Body 读取（当前 `req.collect()`
  无上限），默认值与 §11.5 的 Body limit 对齐。

### Phase 5：轮换与运维

- [ ] endpoint descriptor 原子绑定 service appid、Zone DID、derived service DID、URL、
  security profile、默认 key 和 API version。（name-system/服务发现侧,跨仓库）
- [ ] active/grace/retired key 生命周期接入现有轮换体系。（provider 侧已具备
  `reload()`/grace 语义,轮换体系触发接线在 buckyos 侧）
- [x] 监听 Identity Manager active key generation 后 reload；reload 后在内存保留有界
  grace key，到期丢弃即 zeroize（`IdentityManagerS2sKeyProvider::reload()`;
  监听触发由部署侧接线,进程重启丢失旧 grace key 的行为已按 §6.6 文档化）。
- [x] key retire 时主动失效派生 key cache（`reload()` 返回 retired fingerprint,
  配合 `S2sRpcServerContext::invalidate_key_fingerprint`）。
- [ ] 定义旧私钥、derived secret 和 crash dump/backup 的删除策略。（运维文档项）
- [x] 实现加密 `__probe` 和 API registry 检查（服务端保留 API + `S2sApiRegistry`
  RBAC 钩子;客户端 `kRPC::probe_s2s()`）。
- [ ] 增加 metric、dashboard、低频 API silence alert、permanent failure alert。
  （库侧已提供低基数 `S2sError::reason_code()` 与 permanent/transient 分类;
  metric 管线接入在部署侧）
- [ ] 为事件上报接入 durable outbox、稳定 event id 和 DLQ。（业务侧）

### Phase 6：安全与兼容验证

已实现的测试见 `src/kRPC/src/s2s/*`（单元）与
`src/buckyos-http-server/src/test_s2s_rpc_server.rs`（服务端/端到端）。

- [x] 篡改每个 S2S Header/AAD 字段都必须导致验证失败
  （`tampering_any_s2s_header_fails_before_handler` + AAD 逐字段单元测试 +
  `tampered_body_rejected`）。
- [x] 跨 API、跨服务、request/response 反射测试
  （`cross_api_reflection_rejected`、`wrong_target_service_rejected`、
  `derived_keys_are_directional_and_kind_separated`）。
- [x] 同 nonce/密文顺序和高并发 replay 测试
  （`replayed_request_rejected_and_not_dispatched_twice`、
  `concurrent_same_nonce_only_one_wins`）。
- [ ] 多实例跨节点 replay 测试。（需共享 replay store backend,本仓库仅有
  单实例 `MemoryReplayStore`）
- [x] active→grace→retired 轮换和 cache eviction 测试
  （`server_grace_key_still_decrypts_after_rotation`、
  `reload_moves_old_key_to_grace`、`derived_key_cache_bounded_ttl_and_invalidate`）。
- [ ] current key compromise/old key deletion 的运维演练。（运维项）
- [ ] Header/parser fuzz、oversized body、random ServiceKeyRef resolve amplification 测试。
  （边界/超限用例已覆盖:oversized body、超长 key ref、非法字符;
  持续 fuzz harness 未建）
- [x] `serve_http_by_s2s_rpc_handler` 的成功、错误、身份传递和加密响应集成测试
  （`encrypted_roundtrip_success_and_identity_passed` 等 + 两个真实 HTTP
  端到端测试 `end_to_end_*`）。
- [x] 默认 policy 拒绝所有 plaintext、unknown peer 和 forwarded source 测试。
- [x] direct socket CIDR、IPv4/IPv6 boundary、IPv4-mapped IPv6 和 trusted proxy provenance 测试。
- [x] 伪造 `Forwarded`/`X-Forwarded-For`/`real_src_addr` 不能绕过 plaintext policy
  （`forwarded_headers_cannot_bypass_plaintext_policy`）。
- [x] plaintext 必须同时命中 source CIDR 和 API allowlist，且不能产生 authenticated service DID
  （`plaintext_needs_cidr_and_api_and_token_and_never_gets_identity`）。
- [x] appid + did:web/did:bns Zone 的 service DID 派生、canonicalization 和非法 label 测试。
- [x] Identity Manager file key、显式 key、provider 三种 local key source 测试
  （`identity_s2s` 测试、显式 key 服务端测试、`TwoKeyProvider` 自定义 provider 测试）。
- [x] 显式 key/DID fingerprint mismatch 与 sign-only keyref 必须在 context 构造时失败
  （`context_construction_rejects_missing_pieces`、`fingerprint_mismatch_fails_at_load`、
  `sign_only_keyref_is_rejected`）。
- [x] Identity Manager active key reload、grace expiry 和进程重启丢失旧 grace key 的测试
  （`reload_moves_old_key_to_grace`;重启丢失 grace key 的行为按 §6.6 定义为
  client refresh+重试路径,由 `end_to_end_client_recovers_from_stale_target_key...` 覆盖）。
- [x] encrypted 验证失败后绝不进入 plaintext parser
  （`encrypted_failure_never_falls_back_to_plaintext_parser`）。
- [x] response From/To 未逐字节对调回显（例如补全 key id）时 client 必须拒绝
  （`client_rejects_response_with_rewritten_key_refs`）。
- [x] Content-Type dispatch 测试：参数被忽略、缺失/未知 media type 被拒绝。
- [x] 无效/unsafe policy 无法构造 context 或 reload。
- [x] 验证解密失败、replay 失败时不会进入 `RPCHandler`（所有拒绝路径断言
  handler 调用次数为 0）。
- [x] 验证 plaintext 入口不能伪造 authenticated service context。
- [ ] Rust 与至少一个其他语言实现互操作测试。
- [x] plaintext downgrade、redirect 和错误重试测试
  （downgrade 由 no-fallback 测试覆盖;redirect 在 S2S 模式经
  `redirect::Policy::none()` 禁用;错误重试由 stale-key 端到端测试覆盖）。
- [ ] 性能基准和公网故障注入测试。

## 17. 上线验收标准

只有满足以下条件才能把 v1 用于公网 S2S：

1. 协议测试向量冻结并通过独立实现验证。
2. local appid + current Zone DID 能唯一派生 canonical service DID，local key source 与该
   DID/fingerprint 验证一致。
3. 默认 server policy 在未额外配置时拒绝 plaintext、forwarded source 和 unknown peer。
4. plaintext 只能通过显式 CIDR + API allowlist 放行，且 IP allowlist 不生成 authenticated
   service DID。
5. `/s2s/` 不存在 encrypted failure → plaintext parser 的自动 fallback。
6. trusted proxy 只在 socket peer 命中 proxy CIDR 时提供 real source。
7. 生产环境使用共享或等价一致的 replay 防护。
8. key rotation 能同时驱动旧 private key 和 derived cache 清理。
9. 低频 endpoint 有持续运行的 encrypted probe 和 silence alert。
10. permanent failure 不会被 best-effort 逻辑吞掉。
11. 有副作用 RPC 有业务 idempotency 策略。
12. sender identity 已进入 RBAC/最小权限判断。
13. 公网 endpoint 已配置 body、并发和 resolve amplification 限制。
14. context construction/reload 能拒绝 unsafe 或不完整 policy。
15. 已完成密码学、安全、运维和跨语言协议 review。

## 18. 参考

- [RFC 7748: Elliptic Curves for Security（X25519）](https://www.rfc-editor.org/rfc/rfc7748.html)
- [RFC 5869: HKDF](https://www.rfc-editor.org/rfc/rfc5869.html)
- [RFC 8439: ChaCha20 and Poly1305 for IETF Protocols](https://www.rfc-editor.org/rfc/rfc8439.html)
- [RFC 9846: The Transport Layer Security (TLS) Protocol Version 1.3](https://www.rfc-editor.org/rfc/rfc9846.html)
- [libsodium: Ed25519 to Curve25519](https://doc.libsodium.org/advanced/ed25519-curve25519)
- [libsodium: AEAD constructions](https://doc.libsodium.org/secret-key_cryptography/aead)
- [Thormarker: On using the same key pair for Ed25519 and an X25519 based KEM](https://eprint.iacr.org/2021/509)
- [x25519-dalek SharedSecret / contributory check](https://docs.rs/x25519-dalek/latest/x25519_dalek/struct.SharedSecret.html)
