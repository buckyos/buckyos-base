# kRPC的协议设计

kPRC帮助应用开发者简单的实现一致的RPC调用。其基本思路是

## 1. 根据一个接口定义产生必要的client-stub和server-parser代码. 使用如下

client:
```rust
rpc_client = new kPRCClient(service_url,session_token);
params = {"a":1,"b":2};
result = rpc_client.call("add",params);
```

我们也鼓励api的提供者提供相应的定制化的client-stub,以便于更好的使用api。

```rust
my_api_client = new MyApiClient(rpc_client);
my_api_client.add(1,2);
```

server:
```rust
impl RPCHandler for MyServer {
    async fn handle_rpc_call(
        &self,
        req: RPCRequest,
        ip_from: IpAddr,
    ) -> Result<RPCResponse, RPCErrors> {
        //match and call handle_add()
    }
}

impl MyServer {
    pub async fn handle_add(a:i32,b:i32) -> Resulct<i32> {
        return a + b; 
    }
}
```

在有足够的信息时，可以做到自动的在进程内调用和发起krpc call之间切换
```rust
impl MyApiClient {
    pub async fn add(a:i32,b:i32) {
        my_server = get_server_instance()
        my_server.handle_add(a,b)
    }
}
```

## 2. kPRC协议是简单的，即使不依赖我们的工具，任何人都可以非常简单的实现(zero-dependency)。
kPRC的核心是一个json,json里定义如下:

request:
```json
{
    "method": "add",
    "params": {
        "a": 1,
        "b": 2
    },
    "sys":[1021,"$tokenstring"]
}
```
1021是本次request的trace-id, $tokenstring是一个token,用于验证客户端的合法性。
服务器处理完成后返回如下：

response:

```json
{
    "result": 3,
    "sys":[1021]
}
```

上述协议是简单且完整的，我们不会在HTTP-Header里加入任何东西，保持协议本身的简洁和完整。

## 3. 基于session_token的鉴权


对RPC中的session token进行验证。session_token的有效期有两种
a. 一次性有效，该session_token是和一次调用绑定的，该次调用完成后session_token失效。
b. 多次有效，通常session_token会标注一个有效期和起始的seq,验证通过后从该seq开始，直到有效期结束，都是有效的。有效期取决于服务端的配置和session_token本身携带的有效期。

session_token的验证也有两种
a. 自验证。这意味着session_token包含签名，如何能得到合适的did public key，就可以验证session_token的合法性。
b. 通过verify_hub验证，通过verify_hub来验证session_token。这类session_token通常是多次有效的。

向verify_hub申请token
verify_hub可以根据需要不断的支持新的session_token的验证方法

## 4. session_token的安全管理

一次verify-hub login返回两个token。 一个是长exp的refresh token,一个是标准的的access session token(时间短），每次session token快过期了，就用refresh token去verify-hub refresh,得到新的refresh token和session token.旧的refresh token会立刻失效


对重放攻击的管理：
session_token中有签发时间和有效期，因此只在这个周期内有效
同一个subject只能有一个有效的session_token，如果有新的session_token生成，旧的session_token会被废弃（自动废弃）。
通过session_token的签发时间可以用来判断谁是新的session_token
考虑到时间的误差，系统不会接受超过可信时间1小时以上的签发时间，防止发生bug


## 5. Skils
1. 根据需求产生一个rust的接口定义文件，核心是定义了api client的接口，并提供了handle_rpc_call的实现。该文件的结构参考 example_krpc_client.rs
2. 根据需要，基于该接口文件，产生type-script的封装

## 6. S2S Payload 加密

kRPC 提供一个可选的、无在线握手的 S2S Payload 加密 Profile（v1，已实现于
`kRPC::s2s` 模块），使服务能够通过 `http://target_ip:port/s2s/$apiname` 直接通信，
同时使用双方已有的 Ed25519/DID 身份密钥保护完整 RPC JSON
（Ed25519→X25519 static-static DH + HKDF-SHA-256 + XChaCha20-Poly1305）。

client:

```rust
use kRPC::{kRPC, KrpcTransportSecurity};
use kRPC::s2s::*;
use name_lib::zone_child_did;

let local_did = zone_child_did(&current_zone_did, "event-producer")?;
let target_did = zone_child_did(&current_zone_did, "event-service")?;
let config = S2sClientConfig::new(local_did, target_did);
let client = kRPC::new_with_transport(
    "http://203.0.113.10:18080/s2s/event-report-v1",
    session_token,
    KrpcTransportSecurity::S2sPayloadV1(config),
).await?;
let result = client.call("report_event", params).await?;
client.probe_s2s(Some("event-report-v1")).await?; // 加密探测
```

server（`buckyos-http-server`）:

```rust
let service_did = zone_child_did(&current_zone_did, "event-service")?;
let ctx = S2sRpcServerContext::builder(service_did)
    .security_policy(S2sServerSecurityPolicy::public_internet_default())
    .build().await?;
// 在 /s2s/ 路由内:
serve_http_by_s2s_rpc_handler(req, info, &my_handler, &ctx).await
```

本地身份只从标准路径加载：
`$BUCKYOS_IDENTITY_ROOT/{encode(DID)}/did.json` 与
`$BUCKYOS_SECURITY_ROOT/{encode(DID)}/authentication.private.pem`。
远端默认 authentication Ed25519 公钥统一由 `NameClient` 解析。
wire 上的 `From`/`To` 都是 canonical DID，不接受 `#kid`；调用方也不再注入
公钥、resolver 或自定义本地 key source。

安全默认 fail closed：`/s2s/` 只接受加密请求、不信任 forwarded source、
peer DenyAll;明文只能通过显式 CIDR + API allowlist 放行且不产生
authenticated service identity;失败绝不降级明文。

正式设计和实现清单见
[kRPC S2S Payload 加密 Profile TODO](../../doc/krpc-s2s-payload-encryption-TODO.md)。
