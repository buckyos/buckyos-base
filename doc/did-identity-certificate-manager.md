# 基于 DID 的 BuckyOS 身份/证书管理器技术需求

> 文件状态：Draft v0.2  
> 目标读者：BuckyOS / OOD runtime、身份系统、证书自动化、服务运行环境、Rust SDK 开发者  
> 核心结论：本组件首先是一套**本地身份材料路径协议**。初始化后它只关心两个根目录：公开身份文件存放处和 `security` 存放区。两个根目录内部都按 `DID::to_raw_host_uri()` 得到 host URI，再把整个 host URI 编码成合法单级目录名，目录下按 usage 平铺文件。
>
> **范围说明：本组件管理的全部都是当前运行环境持有的 Local Identity。** public identity root 中的 DID document、公钥和证书，是本地身份在“别人问我是谁”时用于对外回复或证明自己的公开材料；security root 中保存与该身份对应的私钥或本机获授权调用的私钥能力。两者分目录是为了建立不同的文件权限边界，并不表示这里同时维护一个任意 DID 的公共信息目录。一个身份进入本管理器时必须具有对应的私钥能力，不存在只保存公钥或 DID document、却没有私钥能力的受管身份。仅根据 DID 查询他人的 DID document、公钥或 verification method 属于 DID resolver / name service 的职责，不在本文范围内。

---

## 1. 背景

BuckyOS / OOD 在真实部署中会同时承载多种身份：设备身份、用户身份、服务身份、集群节点身份、服务端 TLS 身份、客户端 mTLS 身份、自动化运维身份等。

DID 体系适合表达原生身份和可验证控制关系，但大量系统组件与传统工具链仍然依赖文件路径形式的证书和私钥。例如：

- `curl`、`openssl`、`nginx`、`haproxy`、`envoy` 等工具通常通过 `cert.pem`、`fullchain.pem`、`privkey.pem` 路径读取身份材料。
- ACME 客户端、集群 CA 客户端、证书续期工具通常在拿到新证书后把证书写入固定路径。
- 传统 TLS 服务端证书仍然以 X.509 / WebPKI / DNS SAN 为主，不能要求所有工具都内建 DID resolver 或 BuckyOS Rust trait。

因此，BuckyOS 需要一个更底层的身份/证书管理基础设施，用`统一本地路径协议`把 DID-native 身份、X.509 证书、私钥、远端 signing service、自动化更新工具连接起来。

本组件不是单纯的“证书申请器”，也不是必须在所有调用链中运行的中心 daemon。它的核心是：

```text
public_identity_root + security_root + encoded DID host URI + usage file name
  => 当前运行环境下可用的身份材料路径
```

换句话说，它提供的是当前 host 环境的 **Active Identity View**：哪些身份材料现在可被运行环境使用，以及它们应当在哪里被找到。

---

## 2. 设计目标

### 2.1 核心目标

1. **DID 作为统一身份主键**  
   系统内部身份均以 DID 表达。传统域名身份通过 `did:web:{host}` 映射到 DID 体系。

2. **两个根目录，权限边界清晰**  
   公开或半公开身份材料放入 public identity root；私钥、key reference、signer descriptor 等敏感材料放入 security root。

3. **路径直接、可预测**  
   根目录下面只按 encoded DID host URI 分一级目录，不再引入 hash、alias、`by-did`、`current`、`expressions/{usage}` 等复杂层级。

4. **usage 作为文件名主键**  
   usage 是系统枚举，文件名以 usage 为稳定 stem，不再按 usage 建目录。不同材料类型通过后缀区分。

5. **兼容 X.509 / WebPKI / ACME**  
   `did:web:example.com` 必须能自然映射到 `example.com` 的传统 X.509 证书管理流程，包括 ACME 续期、TLS 服务端证书、mTLS 客户端证书等。

6. **保留 Key Reference**  
   私钥不一定在本机。`keyref` 是实际引用线索，能描述本地私钥文件、Unix socket signer、HTTP signer、TPM/HSM/TEE handle 或远端 Meta 描述。

7. **Rust SDK 简洁封装**  
   Rust 组件主要提供 root 初始化、DID host URI 计算、文件名编码、usage 文件路径计算、metadata/keyref 解析 helper，而不是把路径协议隐藏在重型中心服务后面。

### 2.2 非目标

本组件不负责完整实现以下能力，但必须给这些能力预留集成点：

- 不实现完整 DID method resolver 集合。
- 不实现完整 ACME 协议客户端。
- 不作为公共 CA 或企业 CA。
- 不替代操作系统 keychain、TPM、HSM、TEE。
- 不要求所有传统工具理解 DID。
- 不强制所有私钥都以文件形式存在。
- 不在 active identity root 中维护完整历史版本库。

---

## 3. 参考标准与兼容边界

本需求基于以下公开标准和事实：

- W3C DID Core v1.0 是 W3C Recommendation；DID Document 可以表达 cryptographic material、verification methods 和 services，用于 DID controller 证明其对 DID 的控制。[^did-core]
- `did:web` method 使用 Web 域名的既有信任基础。`did:web:example.com` 对应 `https://example.com/.well-known/did.json`；`did:web:example.com:user:alice` 对应 `https://example.com/user/alice/did.json`。解析时会把 method-specific-id 中的 `:` 替换成 `/`，并通过 HTTPS GET 获取 `did.json`。[^did-web]
- RFC 5280 定义了 Internet X.509 v3 证书和 CRL profile；Subject Alternative Name 可以绑定 DNS name、IP address、URI 等多种 identity form 到证书 subject，并且这些 identity 需要由 CA 验证。[^rfc5280]
- RFC 8555 ACME 用于自动化证书管理，客户端通过证明对证书中域名的控制来获得 CA 颁发的证书。[^rfc8555]

### 3.1 兼容边界

1. **传统 TLS 客户端仍然验证 DNS SAN**  
   对普通浏览器、`curl`、OpenSSL 客户端而言，`did:web:example.com` 的传统 HTTPS 兼容性来自 X.509 证书中的 `DNS:example.com`，而不是来自 DID 本身。

2. **DID-aware 客户端可以额外验证 DID 绑定**  
   DID-aware 客户端可以在传统 X.509 验证通过后，继续检查证书是否与 DID 绑定，例如：
   - 证书中包含 `URI:did:web:example.com` SAN；
   - DID document 中声明了该证书公钥或 SPKI fingerprint；
   - 本地 `server.meta.json` 声明了 DID 与 X.509 证书的绑定关系；
   - 私有 CA / 集群 CA 强制在客户端证书 URI SAN 中写入 DID。

3. **Public CA 对 URI SAN / 自定义扩展的支持不可假设**  
   RFC 5280 允许 URI SAN，但公共 WebPKI CA 的签发策略可能限制实际可用的 SAN 类型。本系统必须把 `URI:did:web:...` 视为可选增强，而不能作为公网 HTTPS 兼容的唯一条件。

4. **`did:web` 解析依赖 HTTPS**  
   外部解析 `did:web` 时依赖目标域名上的有效 TLS。BuckyOS 本地 identity path 可以先存在，但若公网 TLS 证书不可用，外部 DID 解析也可能不可用。

5. **本地 active identity view 不等于 resolver cache**  
   resolver cache 用于加速 DID document 查询；identity path 用于表达本机持有或可调用的身份材料。两者可以集成，但不应混为一个目录。

---

## 4. 核心概念

### 4.1 DID

系统级身份主键。示例：

```text
did:web:node1.example.com
did:web:example.com:ood:device-001
did:bns:waterflier
did:key:z6Mk...
```

SDK / helper 可以接受普通 hostname 作为兼容输入，例如 `node1.example.com`，并按 `did:web:node1.example.com` 处理。

### 4.2 DID raw host URI 与目录名

本路径协议使用 `DID::to_raw_host_uri()` 得到 DID 对应的 host URI，再把整个 host URI 编码成合法文件名作为目录名。

`to_raw_host_uri()` 语义应当基于现有 `DID::to_raw_host_name()` 扩展：

```text
raw_host_uri = DID::to_raw_host_name()
if DID 带 path segment:
    raw_host_uri += "/" + path_segments.join("/")
```

示例：

```text
did:web:node1.example.com
  raw_host_uri = node1.example.com
  dir_name     = node1.example.com

did:web:example.com:user:alice
  raw_host_uri = example.com/user/alice
  dir_name     = example.com%2Fuser%2Falice

did:bns:waterflier
  raw_host_uri = waterflier.bns.did
  dir_name     = waterflier.bns.did
```

文件名编码算法：

```text
encode_filename(raw_host_uri):
  input: UTF-8 bytes
  keep:  A-Z a-z 0-9 . _ -
  encode all other bytes as %HH with uppercase hex
```

因此 `/` 必须编码为 `%2F`，`%` 必须编码为 `%25`。如果 raw host URI 中已经包含 DID method 自己的 percent encoding，文件名编码仍然要再次编码 `%`，避免反解时产生歧义。编码必须可逆，SDK 不应让调用方手写编码后的目录名。

要求：

1. 目录名必须来自 encoded raw host URI，不再使用 DID 字符串 hash。
2. 不再维护 alias 目录；encoded raw host URI 目录本身就是入口。
3. encoded 目录名必须作为单级目录名使用，不得包含 `/`、`\`、NUL，不得等于 `.` 或 `..`。
4. method-specific 的大小写和 normalization 规则由 DID method 决定；`did:web` host 建议按 DNS 习惯使用小写。
5. `did:web:{host}:{path...}` 与 `did:web:{host}` 不共享目录；前者必须把 path 纳入 raw host URI 后再编码。

### 4.3 精确匹配与非精确匹配

大多数目录是精确 host URI 编码后的目录：

```text
node1.example.com/
example.com/
example.com%2Fuser%2Falice/
waterflier.bns.did/
```

非精确匹配使用传统 wildcard hostname 语义，但 raw host URI 中不用裸 `*`，而是先把 wildcard label 表达为 `_`，再执行文件名编码：

```text
*.example.com      -> _.example.com/
*.svc.example.com  -> _.svc.example.com/
```

匹配规则：

1. 查找身份材料时必须先查精确目录，再查 wildcard 目录。
2. `_.example.com` 表示 `*.example.com`，只匹配单级子域名，例如 `a.example.com`。
3. `_.example.com` 不匹配 `example.com`，也不匹配 `a.b.example.com`。
4. `_` 是 identity manager 在 host URI label 层保留的 wildcard label；精确 hostname 不应被解释成 wildcard 目录。
5. wildcard 目录的 metadata 必须记录真实 pattern，例如 `"host_pattern": "*.example.com"`。
6. wildcard private key 和证书仍然必须遵守 X.509 wildcard SAN 规则。

### 4.4 Usage

usage 是系统支持的枚举，不是自由字符串。路径协议以 usage 作为文件名 stem。

MVP usage：

```text
server          HTTPS / TLS server certificate
client          mTLS client certificate
authentication  DID authentication key
assertion       VC / assertion signing key
key-agreement   encryption / key agreement key
capability      capability invocation / delegation key
```

文件名规则：

```text
{usage}.{material}.{ext}
```

示例：

```text
server.fullchain.pem
server.cert.pem
server.private.pem
authentication.private.pem
assertion.meta.json
```

表达方式如 X.509、DID-native、JWK 不再作为路径层级；它们由 usage 和文件后缀共同表达。

### 4.5 Active Identity View

路径协议暴露的是“当前可用身份视图”，不是完整申请、续期、吊销、审计状态机。

例如：

```text
server.fullchain.pem 存在       => 当前环境可尝试使用 server 证书
server.fullchain.pem 被删除     => 当前环境认为 server 证书不可用
server.meta.json 过期           => helper 可判断该身份不应继续使用
上游已吊销                      => revocation watcher 应删除或禁用 active material
```

active root 下不强制维护 `versions/`。如果 provisioner 需要保留历史版本，应放在自己的状态目录或 archive 目录中，不改变 active path 的平铺结构。

### 4.6 Key Reference

私钥不一定是文件。路径协议保留 key reference：

```text
{usage}.keyref.json
```

`keyref` 是 Meta 风格的引用描述，可以表达：

```text
file private key
unix socket signer
HTTP signer
TPM/HSM/TEE key handle
remote authorization service
```

如果工具能够识别 `keyref` 的 Meta 格式，就可以基于其中描述的方法调用这把 key。传统工具如果只能读取私钥文件，则只能使用 `mode=file` 的 keyref，或由 adapter 把远端 key 暴露成传统兼容接口。

---

## 5. 总体架构

```text
+--------------------------------------------------------------+
| Identity Provision / Renewal Tools                           |
|                                                              |
|  ACME client   Cluster CA client   DID issuer   Revocation   |
|  CSR builder   Key rotation tool   Enrollment   Watcher      |
+------------------------------+-------------------------------+
                               |
                               | write / update / remove
                               v
+--------------------------------------------------------------+
| BuckyOS Identity Path Protocol                               |
|                                                              |
|  public identity root / {encoded raw host URI} / flat files   |
|  security root        / {encoded raw host URI} / flat files   |
+------------------------------+-------------------------------+
                               |
                               | read by path / helper
                               v
+--------------------------------------------------------------+
| Runtime Consumers                                             |
|                                                              |
|  BuckyOS Rust services   curl   nginx   ACME hook   scripts   |
+--------------------------------------------------------------+
```

Rust SDK 与可选 daemon 位于路径协议之上：

```text
Root Helper       负责解析 public identity root 与 security root
Path Helper       负责根据 DID raw host URI、encoded dir name、usage、material 计算路径
Metadata Helper   负责读取 metadata、检查有效期、检查 key/cert 匹配
KeyRef Helper     负责解析 keyref，并在 file/signer/remote 模式间分发
Daemon            可选，用于续期、吊销检测、key signer 等后台任务
```

---

## 6. 路径协议需求

### 6.1 两个根目录

初始化后路径协议只依赖两个根目录：

| 根目录 | 建议环境变量 | 默认值 | 用途 |
|---|---|---|---|
| public identity root | `BUCKYOS_IDENTITY_ROOT` | `$BUCKYOS_ROOT/local/identity` | DID document、证书、公钥、证书链、metadata 等可展示或半公开材料 |
| security root | `BUCKYOS_SECURITY_ROOT` | `$BUCKYOS_ROOT/security` | 私钥文件、keyref、signer descriptor、敏感配置 |

解析顺序：

1. 初始化参数显式传入的 root 优先。
2. 其次读取环境变量 `BUCKYOS_IDENTITY_ROOT` / `BUCKYOS_SECURITY_ROOT`。
3. 如果环境变量不存在，则通过 BuckyOS root 推算默认值。
4. BuckyOS root 的解析沿用现有 `BUCKYOS_ROOT` 逻辑；若 `BUCKYOS_ROOT` 不存在，由运行环境或 `buckyos-kit` 默认规则推断。

建议默认结构：

```text
$BUCKYOS_ROOT/local/identity/
    node1.example.com/
        server.fullchain.pem
        server.cert.pem
        server.meta.json

$BUCKYOS_ROOT/security/
    node1.example.com/
        server.private.pem
```

### 6.2 DID 到目录的映射

规范算法：

```text
input did_or_hostname
  -> canonical DID
  -> DID::to_raw_host_uri()
  -> wildcard label normalization, if needed
  -> encode_filename(raw_host_uri)
  -> root / dir_name /
```

示例：

```text
did:web:node1.example.com
  raw_host_uri: node1.example.com
  dir_name:     node1.example.com
  public:   $BUCKYOS_IDENTITY_ROOT/node1.example.com/
  security: $BUCKYOS_SECURITY_ROOT/node1.example.com/

node1.example.com
  canonical DID: did:web:node1.example.com
  raw_host_uri:  node1.example.com
  dir_name:      node1.example.com
  public:        $BUCKYOS_IDENTITY_ROOT/node1.example.com/

did:web:example.com:user:alice
  raw_host_uri: example.com/user/alice
  dir_name:     example.com%2Fuser%2Falice
  public:   $BUCKYOS_IDENTITY_ROOT/example.com%2Fuser%2Falice/
  security: $BUCKYOS_SECURITY_ROOT/example.com%2Fuser%2Falice/

did:bns:waterflier
  raw_host_uri: waterflier.bns.did
  dir_name:     waterflier.bns.did
  public:   $BUCKYOS_IDENTITY_ROOT/waterflier.bns.did/
  security: $BUCKYOS_SECURITY_ROOT/waterflier.bns.did/

*.example.com
  raw_host_uri: _.example.com
  dir_name:     _.example.com
  public:   $BUCKYOS_IDENTITY_ROOT/_.example.com/
  security: $BUCKYOS_SECURITY_ROOT/_.example.com/
```

要求：

1. SDK / helper 必须接受 DID 和 hostname 两种输入。
2. 机器逻辑必须以 encoded raw host URI 目录为准，不再生成 hash path。
3. 不再定义 alias 算法；不生成 `aliases/`、`by-did/`、`v1/by-did/`。
4. helper 不应要求调用方手写目录名，必须提供稳定的路径计算 API。
5. 对 wildcard 查询，helper 必须明确返回匹配来源：`exact` 或 `wildcard`。

### 6.3 平铺文件命名

目录下文件直接平铺：

```text
{dir_name}/
    did.json
    did.meta.json
    {usage}.{material}.{ext}
```

常用 public identity files：

| 文件 | 语义 |
|---|---|
| `did.json` | DID document 的本地副本、发布源或本地校验材料 |
| `did.meta.json` | DID document 的本地 metadata |
| `server.cert.pem` | server leaf certificate |
| `server.chain.pem` | server intermediate chain，不包含 leaf |
| `server.fullchain.pem` | server leaf + intermediate chain，供 nginx / haproxy 等使用 |
| `server.ca.pem` | 本地 server 证书对应的 issuer / validation chain；可选，不是 peer trust store |
| `server.public.pem` | server public key；可选 |
| `server.csr.pem` | 最近一次 server CSR；可选 |
| `server.meta.json` | server certificate metadata |
| `client.cert.pem` | client leaf certificate |
| `client.chain.pem` | client intermediate chain |
| `client.fullchain.pem` | client leaf + intermediate chain |
| `client.ca.pem` | 本地 client 证书对应的 issuer / validation chain；可选，不是 peer trust store |
| `client.meta.json` | client certificate metadata |
| `authentication.verification-method.json` | DID authentication verification method 副本 |
| `authentication.public.jwk` | authentication public key；可选 |
| `authentication.meta.json` | authentication metadata |
| `assertion.verification-method.json` | assertion verification method 副本 |
| `assertion.public.jwk` | assertion public key；可选 |
| `assertion.meta.json` | assertion metadata |

常用 security files：

| 文件 | 语义 |
|---|---|
| `server.private.pem` | server 私钥文件；本地 file mode 的默认入口 |
| `server.keyref.json` | server key reference；仅在直接私钥文件不存在时作为可选 fallback |
| `client.private.pem` | client 私钥文件；本地 file mode 的默认入口 |
| `client.keyref.json` | client key reference；仅在直接私钥文件不存在时作为可选 fallback |
| `authentication.private.pem` | authentication 私钥文件；本地 Ed25519 身份的标准入口 |
| `authentication.keyref.json` | authentication key reference；仅在直接私钥文件不存在时作为可选 fallback |
| `assertion.private.pem` | assertion 私钥文件；本地 file mode 的默认入口 |
| `assertion.keyref.json` | assertion key reference；仅在直接私钥文件不存在时作为可选 fallback |

要求：

1. active 文件名必须稳定，传统工具只读取这些稳定文件。
2. 不按 usage 建子目录。
3. 不按 expression 建子目录。
4. 不在 public identity root 下复制私钥本体。
5. provisioner 可以使用临时 staging 文件或临时目录完成原子写入，但 staging 不是路径协议的一部分，不能成为调用方依赖的路径。

### 6.4 文件更新语义

active root 中的文件表示当前可用材料。

建议写入流程：

```text
1. 在同一文件系统中写入临时文件。
2. fsync 临时文件和父目录。
3. 校验 cert、直接私钥（或缺失时的 keyref fallback）与 metadata。
4. rename 到稳定文件名。
5. 必要时通知服务 reload。
```

要求：

1. 更新失败不得破坏旧的 active 文件。
2. 同一 usage 的一组文件应尽量作为一个 transaction 更新。
3. 如果平台无法保证多文件原子切换，必须通过 metadata 中的 generation / updated_at 帮助 helper 检测不一致。
4. 历史版本、ACME order、challenge、审计日志等状态不放在 active root 中。

---

## 7. Key Reference

### 7.1 直接私钥与可选 keyref

本地可导出私钥使用稳定的直接文件作为默认入口：

```text
$BUCKYOS_SECURITY_ROOT/{dir_name}/{usage}.private.pem
```

只有直接私钥文件不存在时，helper 才允许回退到对应 keyref：

```text
$BUCKYOS_SECURITY_ROOT/{dir_name}/{usage}.keyref.json
```

因此 keyref 不是安装本地身份的必需文件。public metadata 可以引用可选 keyref
路径，但不应复制敏感 signer descriptor。对 `authentication` 等 DID-native
usage，文件查找必须精确匹配，不允许使用 wildcard 身份材料。

示例：

```text
$BUCKYOS_SECURITY_ROOT/node1.example.com/server.keyref.json
$BUCKYOS_SECURITY_ROOT/node1.example.com/authentication.keyref.json
```

### 7.2 file mode

传统私钥文件模式不需要 keyref。调用方直接读取稳定的
`{usage}.private.pem`。下面的 keyref 仅用于需要以统一引用形式描述文件的
兼容场景；helper 只会在直接文件不存在时读取它：

```json
{
  "schema": "buckyos.identity.keyref.v1",
  "kind": "key",
  "did": "did:web:node1.example.com",
  "usage": "server",
  "algorithm": "P-256",
  "public_key_fingerprint": "sha256:...",
  "mode": "file",
  "exportable": true,
  "ref": {
    "type": "file",
    "path": "${BUCKYOS_SECURITY_ROOT}/node1.example.com/server.private.pem",
    "format": "pkcs8-pem"
  }
}
```

要求：

1. 直接私钥文件存在时，传统工具和 helper 都优先读取直接文件。
2. 只有直接私钥文件不存在且 keyref 为 `mode=file` 时，传统工具可以读取 `ref.path`。
3. `ref.path` 应尽量指向同目录下的 `{usage}.private.pem`。
4. helper 必须检查私钥 public key 与证书 public key 匹配。

### 7.3 signer / remote mode

不可导出私钥或远端 key 模式：

```json
{
  "schema": "buckyos.identity.keyref.v1",
  "kind": "key",
  "did": "did:web:node1.example.com",
  "usage": "authentication",
  "algorithm": "Ed25519",
  "public_key_fingerprint": "sha256:...",
  "mode": "signer",
  "exportable": false,
  "ref": {
    "type": "unix-socket",
    "endpoint": "${BUCKYOS_ROOT}/run/identity/authentication.sock",
    "protocol": "buckyos-sign-v1"
  }
}
```

远端 Meta 引用模式：

```json
{
  "schema": "buckyos.identity.keyref.v1",
  "kind": "key",
  "did": "did:web:node1.example.com",
  "usage": "server",
  "algorithm": "P-256",
  "public_key_fingerprint": "sha256:...",
  "mode": "remote-meta",
  "exportable": false,
  "ref": {
    "type": "meta",
    "url": "https://keys.example.com/buckyos/node1/server.meta.json",
    "method": "buckyos-remote-sign-v1"
  }
}
```

要求：

1. `keyref` 是 reference，不等于私钥本体。
2. 工具识别 `ref.type` / `mode` 时，可以基于 Meta 描述调用 key。
3. 工具不识别该 ref 格式时，必须返回明确错误，例如 `UnsupportedKeyRef`。
4. 传统工具请求私钥路径但 keyref 不是 `mode=file` 时，helper 必须返回 `PrivateKeyNotExportable`。

### 7.4 默认 key 分离

MVP 建议不同 usage 默认使用不同 key：

```text
server          P-256 / RSA / deployment profile 指定的 TLS key
client          P-256 / RSA / deployment profile 指定的 mTLS key
authentication  Ed25519 或 DID method profile 指定的 DID key
assertion       Ed25519 或 DID method profile 指定的 DID key
```

只有在 deployment profile 显式允许、算法和协议栈均支持、并且安全审计接受的情况下，才允许跨 usage 复用同一把 key。

---

## 8. X.509 Metadata

metadata 文件按 usage 命名：

```text
$BUCKYOS_IDENTITY_ROOT/{dir_name}/server.meta.json
$BUCKYOS_IDENTITY_ROOT/{dir_name}/client.meta.json
```

`server.meta.json` 示例：

```json
{
  "schema": "buckyos.identity.x509.metadata.v1",
  "did": "did:web:node1.example.com",
  "raw_host_uri": "node1.example.com",
  "dir_name": "node1.example.com",
  "usage": "server",
  "match": {
    "type": "exact",
    "host": "node1.example.com"
  },
  "certificate": {
    "serial_number": "04:7A:...",
    "issuer": "CN=Example CA,O=Example",
    "subject": "CN=node1.example.com",
    "not_before": "2026-06-13T00:00:00Z",
    "not_after": "2026-09-11T23:59:59Z",
    "fingerprint_sha256": "sha256:...",
    "public_key_fingerprint": "sha256:..."
  },
  "san": {
    "dns": ["node1.example.com"],
    "uri": ["did:web:node1.example.com"]
  },
  "paths": {
    "cert": "server.cert.pem",
    "chain": "server.chain.pem",
    "fullchain": "server.fullchain.pem",
    "private_key": "${BUCKYOS_SECURITY_ROOT}/node1.example.com/server.private.pem"
  },
  "did_binding": {
    "type": "did-web-domain",
    "did": "did:web:node1.example.com",
    "web_origin": "https://node1.example.com",
    "did_document_url": "https://node1.example.com/.well-known/did.json",
    "verification_method": "did:web:node1.example.com#x509-server-key-2026-06"
  },
  "renewal": {
    "manager": "acme",
    "renew_before": "P20D",
    "last_renewed_at": "2026-06-13T00:00:00Z",
    "state_ref": "${BUCKYOS_ROOT}/var/identity/state/acme/node1.example.com"
  },
  "updated_at": "2026-06-13T00:00:00Z",
  "generation": "20260613T000000Z-sha256..."
}
```

wildcard metadata 示例：

```json
{
  "schema": "buckyos.identity.x509.metadata.v1",
  "did": "did:web:_.example.com",
  "raw_host_uri": "_.example.com",
  "dir_name": "_.example.com",
  "usage": "server",
  "match": {
    "type": "wildcard",
    "host_pattern": "*.example.com"
  },
  "san": {
    "dns": ["*.example.com"],
    "uri": []
  }
}
```

要求：

1. `metadata` 必须可以由 helper 独立读取，不依赖外部数据库。
2. `certificate.not_after` 必须存在。
3. `san.dns`、`san.uri` 应从证书真实解析结果生成，不应只写期望值。
4. `did_binding` 用于 DID-aware 校验；传统 TLS 工具可以忽略。
5. `paths` 中可以使用相对路径表达同目录文件，跨 root 的 keyref 应使用绝对路径或可解析变量。
6. 不再需要 `manifest.json`。

---

## 9. `did:web` 兼容传统 X.509 证书管理

### 9.1 基本映射

`did:web` 把传统域名身份提升为 DID：

```text
did:web:example.com
  DID document: https://example.com/.well-known/did.json
  X.509 DNS SAN: DNS:example.com
```

路径 DID：

```text
did:web:example.com:user:alice
  DID document: https://example.com/user/alice/did.json
  X.509 DNS SAN: DNS:example.com
  Optional DID URI SAN: URI:did:web:example.com:user:alice
  raw_host_uri: example.com/user/alice
  dir_name: example.com%2Fuser%2Falice
```

规范要求：

1. 对 `did:web:{host}`，X.509 server certificate 的 `DNS SAN` 必须包含 `{host}` 或匹配 `{host}` 的合法 wildcard。
2. 对 `did:web:{host}:{path...}`，传统 TLS 只能验证 `{host}`；`{path...}` 代表同一 host 下的逻辑 DID，不应被当成独立 DNS identity。
3. helper 可以接受 `{host}` 作为输入，但内部必须先 canonicalize 为 `did:web:{host}`。
4. 对私有 CA、集群 CA、mTLS client cert，应该优先使用 `URI SAN = canonical DID` 表达 DID 绑定。

### 9.2 传统 HTTPS 服务端证书

给定：

```text
DID = did:web:node1.example.com
```

派生：

```text
web_host         = node1.example.com
raw_host_uri     = node1.example.com
dir_name         = node1.example.com
did_document     = https://node1.example.com/.well-known/did.json
x509_dns_san     = DNS:node1.example.com
x509_uri_san     = URI:did:web:node1.example.com   # 可选增强
```

本地路径：

```text
$BUCKYOS_IDENTITY_ROOT/node1.example.com/server.fullchain.pem
$BUCKYOS_IDENTITY_ROOT/node1.example.com/server.cert.pem
$BUCKYOS_IDENTITY_ROOT/node1.example.com/server.chain.pem
$BUCKYOS_IDENTITY_ROOT/node1.example.com/server.meta.json
$BUCKYOS_SECURITY_ROOT/node1.example.com/server.private.pem
```

nginx 示例：

```nginx
ssl_certificate     /buckyos/local/identity/node1.example.com/server.fullchain.pem;
ssl_certificate_key /buckyos/security/node1.example.com/server.private.pem;
```

如果没有直接私钥文件、fallback keyref 又是 signer / remote 模式，传统 nginx
不能直接使用，必须通过 adapter、OpenSSL provider、PKCS#11 或其它兼容层暴露
私钥能力。

### 9.3 wildcard HTTPS 服务端证书

给定：

```text
Host pattern = *.example.com
Filesystem dir = _.example.com
```

本地路径：

```text
$BUCKYOS_IDENTITY_ROOT/_.example.com/server.fullchain.pem
$BUCKYOS_IDENTITY_ROOT/_.example.com/server.meta.json
$BUCKYOS_SECURITY_ROOT/_.example.com/server.keyref.json
```

匹配顺序：

```text
api.example.com
  1. $BUCKYOS_IDENTITY_ROOT/api.example.com/server.fullchain.pem
  2. $BUCKYOS_IDENTITY_ROOT/_.example.com/server.fullchain.pem
```

要求：

1. exact 目录存在时必须优先使用 exact。
2. wildcard 证书 SAN 必须包含合法 `DNS:*.example.com`。
3. wildcard 不覆盖 apex domain `example.com`。

### 9.4 ACME 续期流程

ACME provisioner 不是 identity manager 的核心部分，但必须能按路径协议写入。

流程：

```text
1. 读取 DID 或 host：did:web:node1.example.com
2. 派生 raw_host_uri 和 dir_name：node1.example.com
3. 生成或读取 `server.private.pem`；不可导出私钥可改为安装 fallback keyref。
4. 生成 CSR：
   - DNS SAN 必须包含 node1.example.com
   - URI SAN 可选包含 did:web:node1.example.com
5. 通过 ACME http-01 / dns-01 / tls-alpn-01 证明域名控制权。
6. 获得 cert.pem / chain.pem / fullchain.pem。
7. 写入临时文件。
8. 解析证书并生成 server.meta.json。
9. rename 到平铺 active 文件名。
10. 通知相关服务 reload；或由服务自行 watch path。
```

要求：

1. ACME account key、challenge 状态、订单状态属于 provisioner state，应存放在 `$BUCKYOS_ROOT/var/identity/state/acme/`，不属于 active identity material。
2. active path 只暴露最终可用的证书、链、metadata、直接私钥或可选 keyref。
3. 续期失败不得破坏现有 active 文件。
4. 新证书激活前必须检查：
   - 证书 parse 成功；
   - 当前时间在 `not_before` / `not_after` 范围内；
   - `DNS SAN` 覆盖 DID 派生出的 host 或 wildcard pattern；
   - 证书公钥与直接私钥或 fallback keyref 指向的私钥能力匹配；
   - fullchain 构造成功。

### 9.5 mTLS 客户端证书

给定：

```text
DID = did:web:node1.example.com
usage = client
```

路径：

```text
$BUCKYOS_IDENTITY_ROOT/node1.example.com/client.cert.pem
$BUCKYOS_IDENTITY_ROOT/node1.example.com/client.fullchain.pem
$BUCKYOS_IDENTITY_ROOT/node1.example.com/client.ca.pem
$BUCKYOS_IDENTITY_ROOT/node1.example.com/client.meta.json
$BUCKYOS_SECURITY_ROOT/node1.example.com/client.private.pem
```

私有 CA / 集群 CA 应优先在 client certificate 中写入：

```text
URI SAN: did:web:node1.example.com
```

### 9.6 kRPC S2S 标准 DID 身份

给定任意 canonical DID `D`，kRPC S2S 的本地 Ed25519 身份只使用以下标准入口：

```text
$BUCKYOS_IDENTITY_ROOT/{encode(D)}/did.json
$BUCKYOS_SECURITY_ROOT/{encode(D)}/authentication.private.pem
```

`did.json` 的 `id` 必须等于 `D`，默认 authentication verification method 必须是
Ed25519，私钥派生出的公钥必须与该 verification method 一致。直接私钥文件缺失时
可以读取精确路径下的 `authentication.keyref.json` fallback；直接文件一旦存在就
不得被 keyref 覆盖。S2S 不使用 wildcard、服务专用 key ID 或并行身份目录。

---

## 10. Rust SDK 需求

### 10.1 Root Helper

```rust
pub struct IdentityRoots {
    pub public_root: PathBuf,
    pub security_root: PathBuf,
}

impl IdentityRoots {
    pub fn from_env_or_buckyos_root() -> Result<Self>;
    pub fn new(public_root: PathBuf, security_root: PathBuf) -> Self;
}
```

要求：

1. 显式 root 优先。
2. 环境变量次之。
3. 未提供环境变量时，根据 `BUCKYOS_ROOT` 推导。

### 10.2 Path Helper

```rust
pub enum IdentityUsage {
    Server,
    Client,
    Authentication,
    Assertion,
    KeyAgreement,
    Capability,
}

pub enum IdentityMaterial {
    DidJson,
    Cert,
    Chain,
    Fullchain,
    Ca,
    PublicKey,
    Csr,
    Meta,
    PrivateKey,
    KeyRef,
    VerificationMethod,
}

pub struct X509Paths {
    pub cert: PathBuf,
    pub chain: PathBuf,
    pub fullchain: PathBuf,
    pub ca: Option<PathBuf>,
    pub metadata: PathBuf,
    pub keyref: Option<PathBuf>,
    pub private_key: PathBuf,
}

impl IdentityRoots {
    pub fn raw_host_uri(&self, did_or_hostname: &str) -> Result<String>;
    pub fn dir_name(&self, did_or_hostname: &str) -> Result<String>;
    pub fn public_dir(&self, did_or_hostname: &str) -> Result<PathBuf>;
    pub fn security_dir(&self, did_or_hostname: &str) -> Result<PathBuf>;
    pub fn did_document_file(&self, did: &str) -> Result<PathBuf>;
    pub fn authentication_private_key_file(&self, did: &str) -> Result<PathBuf>;
    pub fn public_file(
        &self,
        did_or_hostname: &str,
        usage: IdentityUsage,
        material: IdentityMaterial,
    ) -> Result<PathBuf>;
    pub fn security_file(
        &self,
        did_or_hostname: &str,
        usage: IdentityUsage,
        material: IdentityMaterial,
    ) -> Result<PathBuf>;
    pub fn x509_paths(&self, did_or_hostname: &str, usage: IdentityUsage) -> Result<X509Paths>;
}
```

Path Helper 只做确定性路径计算，不访问网络，不申请证书，不做吊销检查。

要求：

1. API 必须支持只通过 DID 或 hostname 计算 path。
2. API 不应要求 DID 已经安装。
3. API 必须返回稳定路径，便于调用方拼给传统工具。
4. API 不暴露 hash / alias / expression path。
5. API 只对 X.509 server/client usage 支持 exact/wildcard 匹配；DID document、
   authentication、assertion、key-agreement 和 capability 必须 exact-only。

### 10.3 KeyRef Helper

```rust
pub enum KeyAccess {
    File { path: PathBuf, format: String },
    Signer { endpoint: String, protocol: String },
    RemoteMeta { url: String, method: String },
}

pub struct KeyRef {
    pub did: String,
    pub usage: IdentityUsage,
    pub algorithm: String,
    pub public_key_fingerprint: String,
    pub access: KeyAccess,
    pub exportable: bool,
}

impl IdentityRoots {
    pub fn load_keyref(&self, keyref_path: &Path) -> Result<KeyRef>;
    pub fn private_key_file_for_legacy_tool(&self, did_or_hostname: &str, usage: IdentityUsage) -> Result<PathBuf>;
}
```

`private_key_file_for_legacy_tool` 必须先尝试稳定的直接私钥路径；只有该文件不存在
时才解析 keyref。在 signer / remote mode 时必须返回明确错误：

```text
PrivateKeyNotExportable
```

### 10.4 Metadata / Status Helper

Status helper 用于自动化工具链，不在传统工具热路径中强制调用。

```rust
pub struct IdentityStatus {
    pub material_present: bool,
    pub locally_usable: bool,
    pub match_type: Option<String>,
    pub expired: bool,
    pub not_before_valid: bool,
    pub will_expire_within: Option<Duration>,
    pub revoked: Option<bool>,
    pub key_matches_certificate: Option<bool>,
    pub did_binding_valid: Option<bool>,
}

impl IdentityRoots {
    pub fn check_x509_local_status(&self, did_or_hostname: &str, usage: IdentityUsage) -> Result<IdentityStatus>;
    pub fn parse_x509_metadata(&self, did_or_hostname: &str, usage: IdentityUsage) -> Result<X509Metadata>;
}
```

`material_present` 只表示本地 public certificate / metadata 已存在；只有
`locally_usable` 同时验证了匹配的 private capability，才能表示当前环境可使用该
Local Identity。只有 public directory 或 `did.json` 不能称为已安装身份。

本地检查包括：

```text
文件是否存在
PEM 是否可解析
证书是否在有效期内
证书 SAN 是否覆盖 DID 派生出的 host 或 wildcard pattern
证书 public key 是否匹配直接私钥或 fallback keyref
metadata 是否与证书内容一致
```

OCSP / CRL、远端 DID resolution、peer trust store，以及检查“本地身份在远端发布面
是否已生效”都属于独立的 resolver / publication automation。它们可以读取本地
metadata 作为期望值，但不得通过 `IdentityRoots` 查询任意 peer，也不得把 peer CA
bundle 写入 Local Identity root。

---

## 11. 自动化工具集成

### 11.1 ACME Client

ACME Client 职责：

```text
证书申请
challenge 响应
续期
CSR 生成
证书下载
写入平铺 active identity path
```

Identity Manager 职责：

```text
定义 active path
校验证书 metadata
提供直接私钥优先、keyref fallback 的访问 helper
提供 path / validation / status helper
```

ACME Client 不应把内部 account/order/challenge 状态写入 public identity root。

### 11.2 Revocation Watcher

Revocation Watcher 职责：

```text
定期检查 OCSP / CRL / Cluster CA / DID status
发现 revoked 后禁用 active identity
```

最小行为是移除或重命名对应 usage 的 active 文件，使传统工具下一次读取稳定路径时失败。

原则：

```text
文件存在不等于身份仍被上游承认。
Active path 是使用面，revocation watcher 负责把上游状态投影成本地 active view。
```

### 11.3 Renewal Watcher

Renewal Watcher 职责：

```text
读取 {usage}.meta.json 中的 not_after
计算 renew window
调用 provisioner 续期
续期成功后更新平铺 active 文件
续期失败保持旧 active 文件
```

建议默认策略：

```text
证书剩余有效期 < 1/3 原始有效期 或 < 20 天时开始续期
```

具体策略由 deployment profile 决定。

---

## 12. 配置 Profile

不同 DID method 与 X.509 的绑定方式不同，应通过 profile 表达。Profile 是管理面配置，不是 active identity material。

`identity-profile.json` 示例：

```json
{
  "schema": "buckyos.identity.profile.v1",
  "did": "did:web:node1.example.com",
  "raw_host_uri": "node1.example.com",
  "dir_name": "node1.example.com",
  "x509": {
    "server": {
      "enabled": true,
      "domain_source": "did-web-host",
      "dns_names": ["node1.example.com"],
      "uri_san": ["did:web:node1.example.com"],
      "issuer": "acme",
      "acme": {
        "directory_url": "https://acme-v02.api.letsencrypt.org/directory",
        "challenge": ["http-01", "dns-01"]
      }
    },
    "client": {
      "enabled": true,
      "issuer": "cluster-ca",
      "require_uri_san_did": true
    }
  },
  "key_policy": {
    "default_mode": "file",
    "allow_signer_mode": true,
    "server_algorithms": ["P-256", "RSA"],
    "client_algorithms": ["P-256", "RSA"],
    "authentication_algorithms": ["Ed25519"],
    "allow_cross_usage_key_reuse": false
  }
}
```

要求：

1. Profile 可以由 provisioner 使用，传统工具不读取。
2. Profile 中的 `dns_names` 是期望值；metadata 中的 `san.dns` 是证书真实值。
3. Profile 不改变 active path 的两根目录和平铺文件规则。

---

## 13. 安全需求

### 13.1 私钥保护

1. 私钥不得出现在 public identity root 下。
2. 私钥文件必须设置最小可读权限。
3. 支持不可导出 key，通过 signer endpoint 或 remote Meta 使用。
4. keyref 存在时必须包含 public key fingerprint，便于检查 cert/key 匹配。
5. key rotation 不得静默产生不一致的 active view；必须先生成匹配的新私钥和证书，
   再原子替换稳定文件。使用 keyref fallback 时同样适用。

### 13.2 权限要求

BuckyOS 身份材料隔离基于操作系统原生目录权限，而不是在路径协议中引入用户、服务或 scope 层级。进程只应获得它实际需要的身份目录读写权限；例如某个服务只需要读取一个身份的 server 证书，就只授予该身份 public identity 目录和必要 security 文件的权限。

建议 POSIX 权限：

```text
public identity directories   0755 or 0750
public identity files         0644 or 0640
security directories          0700 or 0750
private key files             0600 or 0640 with restricted group
keyref files                  0600 or 0640 if they expose sensitive endpoint
runtime sockets               0600 or 0660 with restricted group
```

要求：

1. `security` root 可以位于独立分区、加密分区或 secure storage mount。
2. `security` root 主要由内核服务或受信系统服务访问；普通服务默认不应拥有全局读取权限。
3. 访问隔离通过目录和文件权限实现，不通过 identity manager 自定义 scope 实现。
4. 自动化工具写入私钥时必须先设置权限，再激活路径。

### 13.3 防止错误绑定

对 `did:web` + X.509，必须防止以下错误：

```text
did:web:alice.example.com 使用了 bob.example.com 的证书
路径 dir_name 与 metadata.dir_name 不一致
metadata.raw_host_uri 与 canonical DID 不一致
cert SAN 不包含 DID 派生 host 或 wildcard pattern
直接私钥或 fallback keyref 指向的私钥与证书公钥不匹配
URI SAN 中的 DID 与 metadata.did 不一致
```

### 13.4 审计

以下操作必须写审计日志：

```text
install identity material
disable identity
purge private key
rotate key
change keyref mode
revocation detected
renewal failed
```

---

## 14. 错误模型

常见错误：

| 错误 | 含义 | 建议处理 |
|---|---|---|
| `IdentityNotInstalled` | encoded raw host URI 目录或对应 usage 文件不存在 | 返回明确错误，引导 provision |
| `UsageNotInstalled` | 指定 usage 不存在 | 检查 usage 或 provision |
| `UnsupportedUsage` | usage 不在系统枚举中 | 拒绝创建任意文件名 |
| `UnsupportedKeyRef` | 工具不认识 keyref ref 格式 | 使用支持该 ref 的工具或 adapter |
| `PrivateKeyNotExportable` | signer / remote 模式，无法给传统工具私钥路径 | 使用支持 signer 的调用方或生成兼容 key |
| `CertificateExpired` | 证书过期 | renewal watcher 续期 |
| `CertificateNotYetValid` | 证书尚未生效 | 不激活或等待 |
| `CertificateRevoked` | 上游吊销 | disable active files |
| `DidBindingMismatch` | DID 与证书绑定不一致 | 禁止激活 |
| `KeyMismatch` | 证书公钥与直接私钥或 fallback keyref 不匹配 | 禁止激活 |
| `WildcardMismatch` | wildcard 目录或 SAN 与 host 不匹配 | 回退或报错 |

---

## 15. MVP 范围

### M0：路径协议与 Rust Path Helper

必须交付：

```text
root 初始化：显式 root / env / BUCKYOS_ROOT 默认推导
DID / hostname -> raw host URI -> encoded dir name
exact / wildcard 目录匹配
usage -> 平铺文件路径
metadata schema
直接私钥路径与可选 keyref fallback schema
```

### M1：X.509 安装与状态检查

必须交付：

```text
install-x509 helper / provisioner interface
parse cert metadata
check cert/direct-private-key-or-keyref match
check DNS SAN for did:web host
write flat active files
```

### M2：did:web 兼容

必须交付：

```text
did:web host/path parser
did:web -> did document URL helper
did:web -> X.509 DNS SAN derivation
wildcard `_` directory lookup
raw host URI filename encoding
optional URI SAN DID validation
```

### M3：自动化运维集成

必须交付：

```text
ACME provisioner integration interface
renewal watcher interface
revocation watcher interface
audit log
```

### M4：不可导出私钥能力

必须交付：

```text
keyref signer mode
keyref remote-meta mode
unix socket signer protocol draft
CSR signing through keyref
DID-native signing through keyref
```

---

## 16. 验收标准

### 16.1 路径稳定性

给定相同：

```text
public identity root
security root
DID or hostname
usage
material
```

任意语言实现必须得到相同路径。

### 16.2 传统工具可用

对于 `did:web:node1.example.com` 的 server certificate，必须能生成以下可用配置：

```text
fullchain.pem path
private key path or explicit PrivateKeyNotExportable error
```

若 key 是 file mode，以下命令应可工作：

```bash
openssl x509 -in "$FULLCHAIN" -noout -text
curl --cert "$CERT" --key "$KEY" https://peer.example.com/
```

### 16.3 更新不破坏 active 文件

模拟 ACME 续期失败时，旧的 `server.fullchain.pem`、`server.cert.pem`、`server.meta.json` 必须保持可读且内容不变。

### 16.4 wildcard 映射正确

必须通过测试：

```text
api.example.com
  exact miss
  wildcard hit: _.example.com

example.com
  does not match _.example.com

a.b.example.com
  does not match _.example.com
```

### 16.5 did:web 映射正确

必须通过测试：

```text
did:web:example.com
  -> raw_host_uri example.com
  -> dir_name example.com
  -> https://example.com/.well-known/did.json
  -> DNS SAN example.com

did:web:example.com:user:alice
  -> raw_host_uri example.com/user/alice
  -> dir_name example.com%2Fuser%2Falice
  -> https://example.com/user/alice/did.json
  -> DNS SAN example.com
  -> optional URI SAN did:web:example.com:user:alice
```

---

## 17. 示例：完整落地

### 17.1 输入

```text
BUCKYOS_ROOT = /buckyos
DID          = did:web:node1.example.com
usage        = server
```

未提供额外环境变量时：

```text
BUCKYOS_IDENTITY_ROOT = /buckyos/local/identity
BUCKYOS_SECURITY_ROOT = /buckyos/security
```

### 17.2 路径

server fullchain 的稳定路径：

```text
/buckyos/local/identity/node1.example.com/server.fullchain.pem
```

### 17.3 证书安装后目录

```text
/buckyos/local/identity/node1.example.com/
  did.json
  did.meta.json
  server.cert.pem
  server.chain.pem
  server.fullchain.pem
  server.public.pem
  server.csr.pem
  server.meta.json

/buckyos/security/node1.example.com/
  server.private.pem
```

### 17.4 metadata 关键内容

```json
{
  "did": "did:web:node1.example.com",
  "raw_host_uri": "node1.example.com",
  "dir_name": "node1.example.com",
  "usage": "server",
  "san": {
    "dns": ["node1.example.com"],
    "uri": ["did:web:node1.example.com"]
  },
  "paths": {
    "fullchain": "server.fullchain.pem",
    "private_key": "/buckyos/security/node1.example.com/server.private.pem"
  },
  "did_binding": {
    "type": "did-web-domain",
    "did_document_url": "https://node1.example.com/.well-known/did.json"
  }
}
```

### 17.5 服务使用

传统服务：

```nginx
ssl_certificate     /buckyos/local/identity/node1.example.com/server.fullchain.pem;
ssl_certificate_key /buckyos/security/node1.example.com/server.private.pem;
```

BuckyOS Rust 服务：

```rust
let roots = IdentityRoots::from_env_or_buckyos_root()?;
let paths = roots.x509_paths("did:web:node1.example.com", IdentityUsage::Server)?;
let private_key = roots.private_key_file_for_legacy_tool(
    "did:web:node1.example.com",
    IdentityUsage::Server,
)?;
```

---

## 18. 待定问题

1. `BUCKYOS_IDENTITY_ROOT` / `BUCKYOS_SECURITY_ROOT` 是否就是最终环境变量名？  
   本文先按这两个名字描述；实现前可以统一改名，但必须保留“两根目录 + BUCKYOS_ROOT 默认推导”的语义。

2. `to_raw_host_uri()` 是否进入 `name-lib::DID`，还是先由 identity path helper 自己实现？  
   初步建议：先在 identity path helper 中实现并测试；稳定后再下沉到 `name-lib`。

3. 是否允许 public identity root 中存在非敏感 `*.keyref.json` 副本？  
   初步建议：MVP 不允许。keyref 统一放 security root，public metadata 只引用 keyref。

4. signer protocol 是否复用现有标准？  
   需要评估 PKCS#11、OpenSSL provider、SPIFFE/SPIRE、WebCrypto-like local agent、BuckyOS-native signer API。

5. 是否需要定义 BuckyOS 专用 X.509 extension OID 存放 DID？  
   初步建议：MVP 不强依赖；先使用 URI SAN + metadata + DID document binding。

---

## 19. 总结

BuckyOS DID 身份/证书管理器的核心不是一个中心化身份服务，而是一套系统级本地路径协议：

```text
public identity root / encoded DID raw host URI / usage files
security root        / encoded DID raw host URI / usage files
```

它把旧设计中的 hash、alias、`by-did`、expression 目录、usage 目录都降掉，保留真正需要的几个稳定概念：

```text
DID::to_raw_host_uri()
encode_filename(raw_host_uri)
exact / wildcard host URI directory
usage enum
flat active files
keyref as Meta reference
```

通过 `did:web`，传统域名身份可以自然进入 DID 体系：

```text
did:web:example.com
  <=> raw_host_uri example.com
  <=> dir_name example.com
  <=> https://example.com/.well-known/did.json
  <=> X.509 DNS SAN example.com
```

而 BuckyOS-native 组件可以进一步通过 metadata 和 keyref 理解 DID 绑定、远端 key、不可导出 key 与更复杂的信任关系。

---

[^did-core]: W3C, Decentralized Identifiers (DIDs) v1.0, https://www.w3.org/TR/did-core/
[^did-web]: W3C CCG, did:web Method Specification, https://w3c-ccg.github.io/did-method-web/
[^rfc5280]: RFC 5280, Internet X.509 Public Key Infrastructure Certificate and CRL Profile, https://www.rfc-editor.org/rfc/rfc5280
[^rfc8555]: RFC 8555, Automatic Certificate Management Environment (ACME), https://www.rfc-editor.org/rfc/rfc8555
