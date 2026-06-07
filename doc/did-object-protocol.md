# DID Object Protocol

Status: Draft v0.3  
Protocol version: `did-object/1`  
Audience: BuckyOS Runtime, DID Object Provider, DID Object Host, Agent Runtime implementers

本文定义 BuckyOS DID Object Protocol 的第一版正式协议草案。它不是一个新的 HTTP wrapper，也不是 Agent `read()` 的返回格式，而是一套**封闭世界、caller-neutral、可验证、可实现**的对象能力协议。

`Global Object` 是本协议的历史工作名。正式文档使用 **DID Object**，强调对象身份、发现文档和验证链路都与 DID Document 兼容；当本文提到 Object URL、Object Card 或 Object Profile 时，均指 DID Object Protocol 中的协议概念。

核心设计：

- **Object URL = Object Reference**：Object URL 是协议层的一等对象引用，也是调用方引用 DID Object 的稳定 handle。
- **DID Document = DID Object Card**：DID Object Card 是协议层对象视图，负责对象身份、controller、可信发现入口、Profile 引用和 service endpoint。
- **DID Object Profile = constrained WoT TD**：DID Object Profile 使用 W3C Web of Things Thing Description 的受限子集来声明属性、动作、事件、schema 和 endpoint。
- **Trait = named capability contract**：Indexer、Task、MediaResource 等通用能力通过 trait 表达，trait 本身是一组标准 properties/actions/events/schema 约束。
- **Protocol is Read-agnostic**：协议故意不定义 Agent `read()`；`read()` 可以使用 Object URL、DID Object Card、Profile、属性、动作结果、事件帧和 resolver metadata，但其输出还依赖获取链路、adapter、session、cache、policy 和 rendering budget。
- **Runtime wire protocol stays simple**：v1 属性使用 HTTP GET，动作使用 kRPC-style HTTP POST，事件使用 WebSocket v1 binding，并定义订阅生命周期。

规范中的 MUST / SHOULD / MAY 使用通常的协议含义。

---

## 1. Scope

DID Object Protocol 是一个**封闭世界对象能力协议**。

它定义调用方如何：

1. 引用一个已声明对象。
2. 解析对象的 DID Object Card。
3. 验证对象身份和 controller。
4. 获取对象 Profile。
5. 根据 Profile 声明读取属性。
6. 根据 Profile 声明调用动作。
7. 根据 Profile 声明订阅事件。
8. 使用 trait 发现和调用通用对象能力。

它不定义：

- 自然语言到对象的路由。
- 开放世界网页解释。
- Agent `read(input, options?) -> ReadResult`。
- LLM-facing summary、guidance、逐步披露和错误恢复视图。
- session-aware rendering 或 token-budget compression。
- 任意未在 DID Object Card / Profile / Trait 中声明的隐式能力。

推荐定位：

```text
DID Object Protocol:
  closed-world, caller-neutral, declared capabilities only.

Read Runtime:
  open-world, route-dependent, session-aware, agent-facing.

Agent Tool Compatibility:
  optional compatibility profile, not core protocol.
```

### 1.1 Why Read is out of scope

`read()` 不是纯粹由 DID Object Card 决定的函数。它可能从以下链路得到同一对象的不同语义视图：

- Object URL -> DID Object Card -> Profile -> properties。
- 普通 HTTP URL -> site adapter -> canonical object。
- DID -> DID resolver -> DID Object Card。
- local file / CYFS NamedObject / MCP resource -> adapter -> object-like view。
- cache / user session / browser state -> enriched view。

因此本协议只提供 `read()` 可以使用的**稳定对象层材料**，不规定 `read()` 如何渲染给 Agent 或 LLM。

---

## 2. Terminology

| Term | Meaning |
|---|---|
| Object URL | DID Object 的协议层引用。它是 stable handle，通常也是可访问资源根。本文中的 ObjectRef 等价于 Object URL。 |
| DID Object Card | DID Object 的协议层对象视图。v1 固定为 DID Document。本文中的 ObjectView 等价于 DID Object Card，但应理解为 control-plane view，而不是 Agent semantic read view。 |
| Object DID | DID Object Card 中的 DID `id`。用于身份、controller、verification 和信任链。 |
| DID Object Profile | 描述对象类型能力的 constrained WoT Thing Description。包含 properties/actions/events/forms/schema/traits。 |
| DIDObjectService | DID Object Card 中声明 DID Object service endpoint、profile 和 kind 的 DID service。 |
| DID Object Resolver | 把 Object URL 或 DID 解析成 verified DID Object Card 的运行时组件。resolver 算法不属于核心协议。 |
| Property | Profile `properties` 中声明的只读或可观察状态。v1 使用 HTTP GET。 |
| Action | Profile `actions` 中声明的可调用方法。v1 使用 kRPC-style HTTP POST。BuckyOS Agent Runtime 可以把它暴露为 `xcall`。 |
| Event | Profile `events` 中声明的可订阅事件。v1 使用 WebSocket binding，并定义 lease lifecycle。 |
| Subscription | 对某个 object event 的有期限订阅资源。包含 subscription id、lease、cursor 和 stream 状态。 |
| Trait | 具名、版本化的能力契约。实现 trait 的对象必须提供该 trait 要求的 properties/actions/events/schema。 |
| IndexTrait | 标准 trait，用于可查询、可分页、返回 rows 的对象索引器。 |
| Resource Descriptor | 对外部媒体、文件、任务或 stream 的薄描述，不重新定义底层传输协议。 |

### 2.1 ObjectRef / ObjectView naming

在本协议中：

```text
ObjectRef  = Object URL
ObjectView = DID Object Card
```

这和 Agent-facing Spec 中的 ObjectRef / ObjectView 语义不同。Agent Runtime MAY 在 `read()` 输出中构造更轻量的 ObjectRef 或更丰富的 semantic ObjectView，但这些属于 Read Runtime，不属于核心协议。

为避免混淆，本文后续优先使用 **Object URL** 和 **DID Object Card**。

---

## 3. Design Principles

### 3.1 Closed-world interaction

调用方只能访问 DID Object Card / Profile / Trait 中声明过的 properties、actions 和 events。

```text
Declared object
  -> declared profile
  -> declared property/action/event
  -> declared schema
  -> declared endpoint
```

Runtime MUST NOT 根据自然语言、HTML 链接、未声明 HTTP path 或模型猜测隐式调用对象方法。

### 3.2 Caller-neutral protocol

本协议方便 Agent 使用，但不假设调用方一定是 Agent。调用方可以是：

- BuckyOS Agent Runtime。
- 普通应用。
- CLI。
- automation service。
- remote DID Object Host。
- Zone 内部 service。

因此核心 action result 不强制使用 Agent Tool Result 结构。Agent 兼容字段放在非强制 profile / appendix 中。

### 3.3 DID Object Card is control plane, properties/actions/events are data plane

DID Object Card 负责 identity、controller、service discovery 和 Profile 引用。对象实例状态不应塞进 DID Document；动态状态应通过 properties/actions/events 获取。

```text
DID Object Card:
  identity / controller / serviceEndpoint / profile / kind

Runtime interactions:
  property values / action results / event frames
```

### 3.4 Reuse DID and WoT, avoid inventing a full object language

v1 直接复用：

- DID Document 作为 DID Object Card。
- WoT Thing Description 受限子集作为 DID Object Profile。
- HTTP(S) 作为 property/action transport。
- WebSocket 作为 event stream transport。

BuckyOS 扩展字段 MUST 使用明确 namespace，例如 `x-buckyos:*`。

---

## 4. Core Flow

调用方拿到 Object URL：

```text
https://myhome.com/devices/cam01
```

Runtime 通过 DID Object Resolver 得到 DID Object Card。默认 Web-compatible resolution 是：

```text
GET https://myhome.com/devices/cam01/did.json
```

DID Object Card 是 DID Document：

```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://buckyos.org/ns/did-object/v1"
  ],
  "id": "did:web:myhome.com:devices:cam01",
  "alsoKnownAs": ["https://myhome.com/devices/cam01"],
  "controller": "did:web:myhome.com",
  "service": [
    {
      "id": "#did-object",
      "type": "DIDObjectService",
      "serviceEndpoint": "https://myhome.com/devices/cam01",
      "profile": "https://buckyos.org/profiles/web-camera@1",
      "kind": "web.camera"
    }
  ]
}
```

Runtime 获取 Profile：

```text
GET https://buckyos.org/profiles/web-camera@1
```

Runtime 根据 Profile：

- GET declared property endpoint。
- POST declared action endpoint。
- CONNECT / WS subscribe declared event endpoint。
- 若 Profile 声明了 trait，则按 trait contract 调用通用能力。

核心细腰：

```text
Object URL
    -> DID Object Card (DID Document)
    -> DID Object Profile (constrained WoT TD)
    -> Trait contracts
    -> property/action/event endpoint
```

---

## 5. Object URL, DID, and Resolver

### 5.1 Object URL

Object URL 是调用方引用 DID Object 的主 handle。它 SHOULD：

- 稳定。
- 可解析到 DID Object Card。
- 对同一对象长期保持一致。
- 在 DID Object Card 的 `alsoKnownAs` 中出现。
- 在生产环境使用 HTTPS。

示例：

```text
https://myhome.com/devices/cam01
https://agent.booking.com/objects/stay-offer/abc123
https://repo.example.com/repos/buckyos/did-object-protocol
```

Object URL 不一定等于最终服务 endpoint；最终交互入口由 DID Object Card 中的 `DIDObjectService.serviceEndpoint` 决定。

### 5.2 Object DID

Object DID 是对象的可验证身份。

示例：

```text
did:web:myhome.com:devices:cam01
did:web:agent.booking.com:objects:stay-offer:abc123
did:bns:myhome:devices:cam01
```

基于域名的 DID 适合 Host / Zone / Owner 等高层对象：

```text
did:web:myhome.com
did:bns:myhome
```

基于 URI path 的 DID 适合 host 下的子对象：

```text
did:web:myhome.com:devices:cam01
did:web:myhome.com:services:repo
```

Path DID 的可信性通常需要回溯到 controller、Zone 或 Owner，而不是只相信当前 HTTP host。

### 5.3 Resolver assumption

本协议假设 Runtime 有一个 DID Object Resolver：

```ts
resolve(input: ObjectURL | DID): Promise<ResolvedObjectCard>
```

返回：

```json
{
  "object_url": "https://myhome.com/devices/cam01",
  "object_did": "did:web:myhome.com:devices:cam01",
  "object_card": {},
  "verified": true,
  "resolution": {
    "route": "did-web-default",
    "fetched_at": "2026-06-07T12:00:00Z",
    "valid_until": "2026-06-07T13:00:00Z",
    "card_etag": "\"card-v12\"",
    "trust": "verified|zone|official|unverified|cached|stale"
  }
}
```

默认 Web-compatible resolution：

```text
{object_url}/did.json
```

BuckyOS Runtime MAY 支持其他 resolver routes，例如 local registry、Zone registry、BNS、DID resolver cache、host manifest 或预配置 DID Object Host。这些 route 的顺序和实现细节不属于核心协议，只要最终返回合法且可验证的 DID Object Card。

### 5.4 obj:// compatibility

v1 核心协议不要求 `obj://`。上层 Agent Runtime MAY 使用 `obj://` 作为 canonical semantic object URI，但进入本协议 data/control plane 时 SHOULD 能解析为 Object URL 或 Object DID。

如果实现支持 `obj://`，它应被视为 resolver input，而不是 property/action/event 的 wire endpoint。

---

## 6. DID Object Card

DID Object Card v1 固定为 DID Document。

### 6.1 Default DID Object Card URL

```text
{object_url}/did.json
```

示例：

```text
https://myhome.com/devices/cam01/did.json
```

如果对象使用 `did:web:myhome.com:devices:cam01`，其 DID Document 的标准位置自然对应：

```text
https://myhome.com/devices/cam01/did.json
```

生产环境 SHOULD 使用 HTTPS。开发环境或 Zone 内网 MAY 使用 HTTP，但 HTTP 返回的 DID Object Card 不能仅依赖传输可信，必须通过 DID Document 签名、controller、Zone 信任链或 Runtime policy 完成验证。

### 6.2 Required fields

DID Object Card MUST 是合法 DID Document，并至少包含：

| 字段 | 要求 | 说明 |
|---|---|---|
| `@context` | MUST | 必须包含 DID context，可包含 DID Object context。 |
| `id` | MUST | Object DID。 |
| `alsoKnownAs` | SHOULD | Object URL，用于 DID 与 URL 互相确认。 |
| `controller` | SHOULD | 对象 controller DID。 |
| `verificationMethod` | SHOULD | 对象或 controller 的验证方法。 |
| `service` | MUST | 至少包含一个 `DIDObjectService`。 |

`DIDObjectService` 字段：

| 字段 | 要求 | 说明 |
|---|---|---|
| `id` | MUST | DID service id。 |
| `type` | MUST | 固定为 `DIDObjectService`。 |
| `serviceEndpoint` | MUST | 对象交互根 URL。 |
| `profile` | MUST | DID Object Profile URL。 |
| `kind` | SHOULD | 快速识别对象类型，例如 `web.camera`、`object.index`。 |

`profile` 和 `kind` 放在 service 项中，而不是 DID Document 顶层。标准 DID resolver 不理解这些字段时可以忽略；DID Object Runtime 查找 `type = DIDObjectService` 的 service。

### 6.3 DID Object Card cache and version metadata

DID Object Card SHOULD 支持缓存和版本判断：

- HTTP resolver SHOULD 返回 `ETag`。
- HTTP resolver SHOULD 返回 `Last-Modified`。
- Runtime SHOULD 支持 `If-None-Match` 和 `If-Modified-Since`。
- 非 HTTP resolver SHOULD 在 resolver metadata 中提供等价的 `card_version`、`fetched_at`、`valid_until`。

这些元数据不定义 `read()` 的 session 行为，但为上层 session-aware runtime 提供稳定依据。

### 6.4 Multiple services

同一个 DID Document MAY 声明多个 service。DID Object Runtime MUST 选择 `type = DIDObjectService` 的 service。

如果存在多个 `DIDObjectService`，Runtime SHOULD 根据 caller policy、transport 支持、auth 状态或 service priority 选择一个。Profile URL 不同的 service 应被视为不同能力面。

---

## 7. DID Object Profile

DID Object Profile 是 constrained WoT Thing Description document。

Profile 描述对象类型和能力，不描述对象实例的全部动态状态。对象实例状态来自：

- DID Object Card 中的 identity/control-plane metadata。
- property response。
- action result。
- event frame。
- resolver / transport metadata。

Profile MUST 使用 WoT 交互模型：

| DID Object 语义 | WoT TD 字段 |
|---|---|
| 属性 | `properties` |
| 动作 | `actions` |
| 事件 | `events` |
| endpoint | `forms[].href` |
| 操作类型 | `forms[].op` |
| 输入输出 schema | WoT Data Schema / JSON Schema-compatible subset |
| traits | `x-buckyos:traits` |

v1 examples use TD-style JSON documents with WoT-compatible fields. Runtime v1 不要求完整 JSON-LD / RDF 推理。

### 7.1 Profile example

```json
{
  "@context": [
    "https://www.w3.org/2022/wot/td/v1.1",
    "https://buckyos.org/ns/did-object/v1"
  ],
  "id": "https://buckyos.org/profiles/web-camera@1",
  "title": "Web Camera",
  "version": {
    "instance": "1.0.0"
  },
  "x-buckyos:traits": [
    "https://buckyos.org/traits/media-source@1"
  ],
  "properties": {
    "brand": {
      "type": "string",
      "readOnly": true,
      "forms": [
        {
          "href": "props/brand",
          "op": "readproperty",
          "contentType": "application/json"
        }
      ]
    },
    "battery": {
      "type": "integer",
      "unit": "percent",
      "readOnly": true,
      "observable": true,
      "forms": [
        {
          "href": "props/battery",
          "op": "readproperty",
          "contentType": "application/json"
        }
      ]
    }
  },
  "actions": {
    "query_clip": {
      "input": {
        "type": "object",
        "properties": {
          "start_time": {
            "type": "string",
            "format": "date-time"
          },
          "end_time": {
            "type": "string",
            "format": "date-time"
          },
          "mode": {
            "type": "string",
            "enum": ["clip", "live"]
          }
        },
        "required": ["mode"]
      },
      "output": {
        "$ref": "https://buckyos.org/schemas/media-resource-descriptor@1"
      },
      "forms": [
        {
          "href": "methods/query_clip",
          "op": "invokeaction",
          "contentType": "application/json"
        }
      ],
      "x-buckyos:action": {
        "effect": "read",
        "idempotency": "recommended"
      }
    }
  },
  "events": {
    "low_battery": {
      "data": {
        "type": "object",
        "properties": {
          "battery": {
            "type": "integer"
          },
          "timestamp": {
            "type": "string",
            "format": "date-time"
          }
        }
      },
      "forms": [
        {
          "href": "events",
          "op": "subscribeevent",
          "contentType": "application/json"
        }
      ]
    }
  }
}
```

### 7.2 Endpoint resolution

Profile 中的 `forms[].href` MAY 是绝对 URL，也 MAY 是相对 URL。

相对 URL MUST 基于 DID Object Card 中 `DIDObjectService.serviceEndpoint` 解析：

```text
serviceEndpoint = https://myhome.com/devices/cam01
href            = methods/query_clip
resolved        = https://myhome.com/devices/cam01/methods/query_clip
```

`href` 不应使用以 `/` 开头的路径表达对象相对 endpoint。标准 URL 语义中，`/query_clip` 表示 host root 下的路径：

```text
https://myhome.com/query_clip
```

如果 Profile 没有声明 form，BuckyOS DID Object Runtime MAY 使用默认 endpoint 规则：

```text
property: GET  {serviceEndpoint}/props/{property_name}
action:   POST {serviceEndpoint}/methods/{action_name}
event:    WS   {serviceEndpoint}/events
```

默认规则只用于 BuckyOS DID Object Runtime。通用 WoT Consumer 不要求理解该默认规则。

### 7.3 Supported WoT subset

Runtime v1 只要求支持以下字段：

- `@context`
- `id`
- `title`
- `version`
- `properties`
- `actions`
- `events`
- `forms`
- `forms[].href`
- `forms[].op`
- `forms[].contentType`
- WoT Data Schema 中可映射到 JSON Schema 的常用字段
- `x-buckyos:*` 扩展字段

Runtime v1 不要求支持：

- 完整 JSON-LD / RDF 推理。
- 任意外部 `@context` 的语义解释。
- TD Directory / Discovery 全流程。
- MQTT、CoAP、Modbus、BACnet 等非 HTTP/WebSocket binding。
- 独立 `observeproperty` binding。
- 复杂 `queryaction` / `cancelaction` 生命周期。
- Profile 内完整 RBAC。
- TD 自身作为安全根的 RDF canonicalization 签名。

权限、签名、controller、RBAC 和审计由 DID Object Card 与 Runtime policy 处理。

### 7.4 BuckyOS extension namespace

BuckyOS 扩展字段使用 `x-buckyos:*`。v1 预留：

| 字段 | 位置 | 说明 |
|---|---|---|
| `x-buckyos:traits` | profile top-level | 对象实现的 trait URI 列表。 |
| `x-buckyos:action.effect` | action | `read|write|destructive|external` 等 caller-neutral effect hint。 |
| `x-buckyos:action.confirm` | action | `none|runtime|human`，仅为 policy hint，不替代 Runtime 授权。 |
| `x-buckyos:action.idempotency` | action | `none|recommended|required`。 |
| `x-buckyos:agentResult` | action | Agent Tool Result 兼容建议，非核心强约束。 |
| `x-buckyos:event.delivery` | event | `best_effort|at_least_once|durable`，v1 至少支持 best_effort。 |

---

## 8. Trait Model

Trait 是具名、版本化的能力契约。它定义一组 properties/actions/events/schema 和语义约束。

Profile MAY 声明它实现一个或多个 trait：

```json
{
  "x-buckyos:traits": [
    "https://buckyos.org/traits/index@1",
    "https://buckyos.org/traits/task@1"
  ]
}
```

实现某个 trait 意味着：

- Profile MUST 提供该 trait 要求的 property/action/event 名称。
- 输入输出 schema MUST 与 trait contract 兼容。
- endpoint 可以不同，但语义必须一致。
- trait URI 的主版本号表示兼容边界，例如 `@1`。

Trait 不是继承系统，也不是类系统。它更接近 Rust trait：对象可以实现多个 trait，调用方可以基于 trait 调用一组通用方法。

---

## 9. IndexTrait

Indexer 是实现 `IndexTrait` 的特殊 DID Object。它不是独立 tool，而是一个普通 DID Object，额外实现了一组标准索引能力。

适用对象：

- 搜索入口。
- 文件夹。
- 数据集。
- 任务列表。
- issue 列表。
- 商品或预订 offer 列表。
- 邮件 / 日历 / 日志索引。

Trait URI：

```text
https://buckyos.org/traits/index@1
```

推荐 kind：

```text
object.index
```

### 9.1 Required capabilities

实现 IndexTrait 的 Profile MUST 提供：

| 名称 | 类型 | 说明 |
|---|---|---|
| `index_schema` | property | 返回索引的 query schema、columns、result profile 和分页约束。 |
| `query` | action | 使用 query 条件创建或读取一个索引页。 |
| `page` | action | 使用 cursor / snapshot 继续翻页。 |

MAY 提供：

| 名称 | 类型 | 说明 |
|---|---|---|
| `count` | action | 返回符合条件的大致或精确数量。 |
| `changed` | event | 索引内容或结构发生变化。 |
| `expired` | event | 某个 snapshot 或 cursor 失效。 |

### 9.2 Index Profile example

```json
{
  "@context": [
    "https://www.w3.org/2022/wot/td/v1.1",
    "https://buckyos.org/ns/did-object/v1"
  ],
  "id": "https://buckyos.org/profiles/object-index@1",
  "title": "Object Index",
  "version": {
    "instance": "1.0.0"
  },
  "x-buckyos:traits": [
    "https://buckyos.org/traits/index@1"
  ],
  "properties": {
    "index_schema": {
      "$ref": "https://buckyos.org/schemas/index-schema@1",
      "readOnly": true,
      "forms": [
        {
          "href": "props/index_schema",
          "op": "readproperty",
          "contentType": "application/json"
        }
      ]
    }
  },
  "actions": {
    "query": {
      "input": {
        "$ref": "https://buckyos.org/schemas/index-query@1"
      },
      "output": {
        "$ref": "https://buckyos.org/schemas/index-page@1"
      },
      "forms": [
        {
          "href": "methods/query",
          "op": "invokeaction",
          "contentType": "application/json"
        }
      ],
      "x-buckyos:action": {
        "effect": "read",
        "idempotency": "recommended"
      }
    },
    "page": {
      "input": {
        "$ref": "https://buckyos.org/schemas/page-request@1"
      },
      "output": {
        "$ref": "https://buckyos.org/schemas/index-page@1"
      },
      "forms": [
        {
          "href": "methods/page",
          "op": "invokeaction",
          "contentType": "application/json"
        }
      ],
      "x-buckyos:action": {
        "effect": "read",
        "idempotency": "recommended"
      }
    }
  },
  "events": {
    "changed": {
      "data": {
        "$ref": "https://buckyos.org/schemas/index-changed-event@1"
      },
      "forms": [
        {
          "href": "events",
          "op": "subscribeevent",
          "contentType": "application/json"
        }
      ]
    }
  }
}
```

### 9.3 IndexSchema

`index_schema` 返回：

```json
{
  "trait": "https://buckyos.org/traits/index@1",
  "schema_id": "https://booking.example.com/schemas/stay-search-result-table@1",
  "schema_hash": "sha256:...",
  "query_schema": "https://booking.example.com/schemas/stay-search-query@1",
  "result_profile": "https://booking.example.com/profiles/stay-offer@1",
  "object_url_column": "object",
  "columns": [
    {
      "name": "object",
      "type": "object_url",
      "required": true
    },
    {
      "name": "title",
      "type": "string"
    },
    {
      "name": "price",
      "type": "money"
    },
    {
      "name": "rating",
      "type": "number"
    },
    {
      "name": "valid_until",
      "type": "datetime"
    }
  ],
  "sortable": ["price", "rating"],
  "filterable": ["destination", "checkin", "checkout", "guests"],
  "default_page_size": 20,
  "max_page_size": 100
}
```

字段说明：

| 字段 | 要求 | 说明 |
|---|---|---|
| `schema_id` | MUST | 结果表结构的稳定 ID。 |
| `schema_hash` | MUST | 表结构内容 hash，供 cache / session compression 判断结构是否变化。 |
| `query_schema` | SHOULD | query action 的输入 schema。 |
| `result_profile` | SHOULD | row 中 object URL 指向对象的 Profile。 |
| `object_url_column` | SHOULD | 哪一列包含可继续解析的 Object URL。 |
| `columns` | MUST | 列定义。 |
| `sortable` | MAY | 可排序列。 |
| `filterable` | MAY | 可过滤字段。 |
| `max_page_size` | SHOULD | 单页最大行数。 |

### 9.4 IndexQuery

```json
{
  "query": {
    "destination": "Tokyo",
    "checkin": "2026-07-12",
    "checkout": "2026-07-15",
    "guests": 2
  },
  "sort": [
    {
      "field": "price",
      "order": "asc"
    }
  ],
  "page_size": 20,
  "known_schema_hash": "sha256:...",
  "trace_id": "trace_01H..."
}
```

`known_schema_hash` 是普通条件请求 hint，不是 session-aware protocol。Provider 可以据此减少重复返回 schema metadata，但不需要理解调用方 session。

### 9.5 PageRequest

```json
{
  "cursor": "cursor_...",
  "snapshot_id": "snap_01H...",
  "page_size": 20,
  "trace_id": "trace_01H..."
}
```

### 9.6 IndexPage

```json
{
  "index": "https://booking.example.com/objects/stays",
  "schema_id": "https://booking.example.com/schemas/stay-search-result-table@1",
  "schema_hash": "sha256:...",
  "snapshot_id": "snap_01H...",
  "expires_at": "2026-06-07T13:00:00Z",
  "rows": [
    {
      "row_id": "abc123",
      "object": "https://booking.example.com/objects/stay-offer/abc123",
      "object_did": "did:web:booking.example.com:objects:stay-offer:abc123",
      "version": "offer-v3",
      "cells": {
        "title": "Deluxe King Room at Hotel X",
        "price": {
          "amount": 558,
          "currency": "USD"
        },
        "rating": 8.9,
        "valid_until": "2026-07-09T00:00:00Z"
      }
    }
  ],
  "next_cursor": "cursor_...",
  "meta": {
    "generated_at": "2026-06-07T12:00:00Z",
    "affected_objects": [
      "https://booking.example.com/objects/stays"
    ]
  }
}
```

`IndexPage` MUST include `schema_hash` and SHOULD include `snapshot_id` when pagination must be stable.

Rows SHOULD include:

- `object`: Object URL。
- `version`: row object 或 row snapshot 的版本。
- `cells`: 与 `columns` 对应的数据。

Read Runtime 可以把 `IndexPage` 渲染成表格、ref list 或 compressed collection，但这不属于核心协议。

---

## 10. Property Protocol

Property 对应 WoT `properties`。

v1 property access：

```text
GET {property_endpoint}
```

示例：

```text
GET https://myhome.com/devices/cam01/props/brand
```

返回值 MUST 与 Profile 中 property schema 兼容。

简单属性可以直接返回 JSON value：

```json
"AcmeCam"
```

结构化属性可以返回 object：

```json
{
  "value": 87,
  "unit": "percent",
  "updated_at": "2026-06-07T12:00:00Z",
  "version": "battery-v42"
}
```

### 10.1 Property version and conditional GET

Property endpoint SHOULD 支持：

- `ETag`
- `Last-Modified`
- `Cache-Control`
- `If-None-Match`
- `If-Modified-Since`

若 property 未变化，endpoint SHOULD 返回：

```text
304 Not Modified
```

或在非 HTTP binding 中返回等价状态。

这些能力用于 cache、policy 和上层 Read Runtime 的 session-aware compression，但协议不定义 session state。

### 10.2 Property placement guidance

适合放在 property：

- 不太变化的结构化状态。
- 对象摘要。
- 不需要参数的当前状态。
- 小型 JSON metadata。

不适合放在 property：

- 经常变化的大型数据流。
- 需要分页、过滤或排序的数据。
- 会产生副作用的操作。
- 需要确认、授权升级或支付的操作。

经验规则：

```text
small stable state       -> property
parameterized data       -> action
large media/resource     -> action returns resource descriptor
long-lived notification  -> event
search/pageable dataset  -> IndexTrait
```

---

## 11. Action Invocation Protocol

DID Object 的动作对应 WoT `actions`。

BuckyOS Agent Runtime MAY 把 action invocation 暴露为 `xcall(obj, action, params)`，但本协议本身称为 **Action Invocation**，不假设 caller 一定是 Agent。

Runtime 根据 action 的 `forms` 找到 `op = invokeaction` 的 form，解析 endpoint 后发送请求。

v1 default action protocol：

```text
POST {action_endpoint}
Content-Type: application/json
```

### 11.1 Request envelope

请求体使用 kRPC-style envelope：

```json
{
  "method": "query_clip",
  "params": {
    "mode": "clip",
    "start_time": "2026-06-07T10:00:00Z",
    "end_time": "2026-06-07T10:10:00Z"
  },
  "obj": "https://myhome.com/devices/cam01",
  "obj_did": "did:web:myhome.com:devices:cam01",
  "observed": {
    "card_etag": "\"card-v12\"",
    "profile": "https://buckyos.org/profiles/web-camera@1",
    "profile_hash": "sha256:...",
    "object_version": "camera-state-v8",
    "observed_at": "2026-06-07T10:11:00Z"
  },
  "idempotency_key": "idem_01H...",
  "confirm_token": "confirm_01H...",
  "trace_id": "trace_01H..."
}
```

字段：

| 字段 | 要求 | 说明 |
|---|---|---|
| `method` | MUST | WoT action name。必须等于 Profile 中的 action 名。 |
| `params` | MUST | action 参数，必须匹配 action `input` schema。 |
| `obj` | SHOULD | Object URL。若 endpoint 服务多个对象，服务端必须使用它定位对象。 |
| `obj_did` | MAY | Object DID。用于审计和双向确认。 |
| `observed` | MAY | 调用方执行前观察到的对象/card/profile/version，用于 freshness check。 |
| `idempotency_key` | SHOULD | 对可重试或有副作用动作建议提供；Profile 可要求。 |
| `confirm_token` | MAY | 高风险动作确认 token。来源由 Runtime / Provider policy 决定。 |
| `trace_id` | SHOULD | 审计和跨服务 trace。 |

### 11.2 Response envelope

成功返回 MUST 包含 `result`：

```json
{
  "result": {
    "media_type": "video",
    "transport": "http-media",
    "href": "https://myhome.com/devices/cam01/clips/clip123.mp4",
    "content_type": "video/mp4",
    "realtime": false,
    "seekable": true
  },
  "meta": {
    "status": "ok",
    "summary": "Clip is ready.",
    "created_objects": [
      "https://myhome.com/devices/cam01/clips/clip123"
    ],
    "affected_objects": [
      "https://myhome.com/devices/cam01"
    ],
    "invalidated_objects": [],
    "refresh_hints": [
      "https://myhome.com/devices/cam01"
    ]
  }
}
```

`meta` 是可选的协议 metadata。它是 caller-neutral 的 cache / audit / compatibility metadata，不等同于 Agent `InteractionResult`。

错误返回 MUST 包含 `error`：

```json
{
  "error": {
    "code": "permission_denied",
    "message": "Access to camera clips is not allowed for this session.",
    "details": {},
    "retry_after_ms": null,
    "refresh_hints": [
      "https://myhome.com/devices/cam01"
    ]
  }
}
```

### 11.3 Action constraints

Runtime MUST：

- 校验 action 是否存在于 Profile。
- 根据 Profile 的 `input` schema 校验参数。
- 按 DID Object Card、controller、Zone policy 和 caller auth 判断是否允许调用。
- 对高风险 action 执行 confirmation policy。
- 记录审计信息。

Provider MUST：

- 重新校验权限。
- 重新校验对象状态。
- 校验 params schema。
- 对带 `observed` 的请求执行 freshness check，或在无法判断时按 policy 拒绝 / 降级。
- 对 `idempotency_key` 做幂等处理，如果 Profile 要求幂等。

### 11.4 Freshness and stale object handling

如果 Provider 判断调用基于过期状态，应返回错误：

```json
{
  "error": {
    "code": "stale_object",
    "message": "Object changed since caller observed it.",
    "current_version": "offer-v4",
    "refresh_hints": [
      "https://booking.example.com/objects/stay-offer/abc123"
    ]
  }
}
```

不要在核心协议中使用 `read_after`。如果需要提示调用方刷新对象，使用：

```text
affected_objects
invalidated_objects
refresh_hints
```

Agent Runtime MAY 把 `refresh_hints` 转换为 agent-facing `read_after`。

### 11.5 Confirmation

高风险动作包括但不限于：支付、预订、取消、删除、公开发布、授权变更和不可逆外部操作。

Profile MAY 用 `x-buckyos:action.confirm` 声明确认 hint：

```json
{
  "x-buckyos:action": {
    "effect": "destructive",
    "confirm": "human",
    "idempotency": "required"
  }
}
```

Runtime policy 可以比 Profile 更严格。Provider 不能仅依赖 caller 声称已经确认，必须验证确认 token 或执行自己的确认策略。

### 11.6 Long-running actions

长期动作 SHOULD 返回 Task Object 或 Resource Descriptor，而不是阻塞到完成。

示例：

```json
{
  "result": {
    "task": "https://repo.example.com/tasks/build-123",
    "profile": "https://buckyos.org/profiles/task@1"
  },
  "meta": {
    "status": "accepted",
    "affected_objects": [
      "https://repo.example.com/repos/buckyos/did-object-protocol"
    ],
    "refresh_hints": [
      "https://repo.example.com/tasks/build-123"
    ]
  }
}
```

---

## 12. Event Protocol

Event 对应 WoT `events`。

v1 不只定义 WebSocket 数据帧，还定义订阅生命周期。订阅是有期限资源，必须支持创建、续租、取消和状态查询。

### 12.1 Event declaration

Profile 中事件使用 `events` 声明：

```json
{
  "events": {
    "low_battery": {
      "data": {
        "type": "object",
        "properties": {
          "battery": { "type": "integer" },
          "timestamp": { "type": "string", "format": "date-time" }
        }
      },
      "forms": [
        {
          "href": "events",
          "op": "subscribeevent",
          "contentType": "application/json"
        }
      ],
      "x-buckyos:event": {
        "delivery": "best_effort"
      }
    }
  }
}
```

`forms[].href` 可以指向对象共享 event endpoint，也可以指向单个 event endpoint：

```text
wss://myhome.com/devices/cam01/events
wss://myhome.com/devices/cam01/events/low_battery
```

若多个事件共享 endpoint，event frames MUST 包含 `event` 字段。

### 12.2 Required lifecycle operations

Event endpoint MUST 支持：

```text
event.subscribe
event.renew
event.unsubscribe
event.status
event.stream
```

v1 WebSocket binding 使用消息中的 `op` 字段表达这些操作。

### 12.3 WebSocket v1 binding

Runtime 连接 event endpoint：

```text
WS wss://myhome.com/devices/cam01/events
```

订阅请求：

```json
{
  "op": "subscribe",
  "object": "https://myhome.com/devices/cam01",
  "object_did": "did:web:myhome.com:devices:cam01",
  "event": "low_battery",
  "filter": {},
  "ttl_ms": 300000,
  "cursor": null,
  "trace_id": "trace_01H..."
}
```

订阅响应：

```json
{
  "type": "subscription",
  "subscription_id": "sub_01H...",
  "object": "https://myhome.com/devices/cam01",
  "object_did": "did:web:myhome.com:devices:cam01",
  "event": "low_battery",
  "expires_at": "2026-06-07T13:00:00Z",
  "cursor": "42",
  "delivery": "best_effort",
  "refresh_hints": [
    "https://myhome.com/devices/cam01"
  ]
}
```

续租：

```json
{
  "op": "renew",
  "subscription_id": "sub_01H...",
  "ttl_ms": 300000,
  "trace_id": "trace_01H..."
}
```

取消：

```json
{
  "op": "unsubscribe",
  "subscription_id": "sub_01H...",
  "trace_id": "trace_01H..."
}
```

状态查询：

```json
{
  "op": "status",
  "subscription_id": "sub_01H...",
  "trace_id": "trace_01H..."
}
```

状态响应：

```json
{
  "type": "subscription_status",
  "subscription_id": "sub_01H...",
  "state": "active|expired|cancelled|error",
  "expires_at": "2026-06-07T13:00:00Z",
  "cursor": "42"
}
```

### 12.4 EventFrame

```json
{
  "type": "event",
  "event_id": "evt_01H...",
  "subscription_id": "sub_01H...",
  "object": "https://myhome.com/devices/cam01",
  "object_did": "did:web:myhome.com:devices:cam01",
  "event": "low_battery",
  "seq": 42,
  "cursor": "42",
  "timestamp": "2026-06-07T12:00:00Z",
  "summary": "Camera battery is low.",
  "data": {
    "battery": 12
  },
  "affected_objects": [
    "https://myhome.com/devices/cam01"
  ],
  "invalidated_objects": [],
  "refresh_hints": [
    "https://myhome.com/devices/cam01"
  ]
}
```

字段说明：

| 字段 | 要求 | 说明 |
|---|---|---|
| `event_id` | SHOULD | 事件唯一 ID。 |
| `subscription_id` | MUST | 对应订阅。 |
| `object` | MUST | Object URL。 |
| `object_did` | MAY | Object DID。 |
| `event` | MUST | Profile 中声明的 event name。 |
| `seq` | SHOULD | 单对象或单订阅内递增序号。 |
| `cursor` | SHOULD | 可恢复 stream 位置。 |
| `timestamp` | MUST | 事件发生或生成时间。 |
| `summary` | MAY | caller-neutral 摘要，可被 Agent Runtime 使用。 |
| `data` | MUST | 符合 Profile event data schema。 |
| `affected_objects` | SHOULD | 事件影响的对象 URL。 |
| `invalidated_objects` | MAY | 因事件而应失效的对象或 index。 |
| `refresh_hints` | MAY | 调用方可刷新对象的 hint，不等同于 `read_after`。 |

### 12.5 Lease requirements

Subscription MUST 有 `expires_at`。

Runtime SHOULD 在过期前 renew。Provider MAY 拒绝过长 TTL。订阅过期后 Provider SHOULD 停止发送事件并释放资源。

### 12.6 Delivery semantics

v1 Runtime MUST 支持 `best_effort`。

Provider MAY 支持更强语义：

```text
at_least_once
durable
```

如果支持 cursor resume，Provider SHOULD 允许 subscribe 时带 `cursor`。如果 cursor 已失效，应返回：

```json
{
  "type": "error",
  "error": {
    "code": "cursor_expired",
    "message": "The requested cursor is no longer available.",
    "refresh_hints": [
      "https://myhome.com/devices/cam01"
    ]
  }
}
```

### 12.7 KEvent bridge

远端 Provider 不直接控制本地 KEvent。本地 Object Event Runtime 接收远端 EventFrame 后，MAY 发布到本地 KEvent 用于 fanout / wakeup。

不要把 Object URL 原样塞入 KEvent event id。KEvent path 应由 Runtime 编码成合法 path：

```text
/obj/<host>/<kind>/<id>/<event>
```

示例：

```text
/obj/booking.example.com/stay_offer/abc123/changed
/obj/booking.example.com/stay_offer/abc123/expired
```

如果 id 不适合放 path，使用 hash：

```text
/obj/booking.example.com/stay_offer/by_hash/sha256_xxx/changed
```

payload 保留原始 Object URL 和 DID。

---

## 13. Resource Descriptors

DID Object Protocol 不重新定义媒体、文件、任务或 stream 的传输协议。动作可以返回薄 Resource Descriptor 指向外部资源。

### 13.1 Media Resource Descriptor

```json
{
  "media_type": "video|audio|image",
  "transport": "http-media|hls|dash|webrtc-whep",
  "href": "string",
  "content_type": "string",
  "realtime": "boolean",
  "seekable": "boolean",
  "expires_at": "string?"
}
```

点播视频：

```json
{
  "media_type": "video",
  "transport": "http-media",
  "href": "https://myhome.com/devices/cam01/clips/clip123.mp4",
  "content_type": "video/mp4",
  "realtime": false,
  "seekable": true
}
```

实时视频：

```json
{
  "media_type": "video",
  "transport": "webrtc-whep",
  "href": "https://myhome.com/devices/cam01/streams/live/whep",
  "content_type": "application/sdp",
  "realtime": true,
  "seekable": false,
  "expires_at": "2026-06-07T13:00:00Z"
}
```

HLS：

```json
{
  "media_type": "video",
  "transport": "hls",
  "href": "https://myhome.com/devices/cam01/live/index.m3u8",
  "content_type": "application/vnd.apple.mpegurl",
  "realtime": true,
  "seekable": true
}
```

### 13.2 Object Resource Descriptor

如果 action 创建或返回新的 DID Object，结果 SHOULD 返回 Object URL 和 Profile：

```json
{
  "object": "https://booking.example.com/objects/reservation/r789",
  "object_did": "did:web:booking.example.com:objects:reservation:r789",
  "profile": "https://booking.example.com/profiles/stay-reservation@1",
  "kind": "stay.reservation"
}
```

---

## 14. Protocol Invariants for Read-friendly Runtime

本协议不定义 `read()`，但 DID Object 实现 SHOULD 提供以下底层不变量，使上层 Read Runtime 能做稳定解释、缓存和 session-aware compression。

### 14.1 Stable object identity

Provider SHOULD 保证：

- 同一对象的 Object URL 稳定。
- DID Object Card 中 `alsoKnownAs` 包含主要 Object URL。
- alias / redirect 能被 resolver canonicalize。
- Object DID 与 Object URL 能互相确认。

### 14.2 Version metadata

Provider SHOULD 提供：

| 对象 | 推荐版本信号 |
|---|---|
| DID Object Card | `ETag` / `Last-Modified` / resolver `card_version` |
| Profile | versioned profile URL，例如 `@1`，以及可选 `profile_hash` |
| Property | `ETag` / `Last-Modified` / body `version` |
| Action result | `affected_objects` / `created_objects` / `invalidated_objects` / `refresh_hints` |
| Event frame | `event_id` / `seq` / `cursor` / `affected_objects` / `refresh_hints` |
| IndexPage | `schema_hash` / `snapshot_id` / row `version` |

这些字段不让协议知道 session，但让调用方能判断：

```text
same object + same version => likely no need to re-fetch/render
same schema_hash => collection shape unchanged
same snapshot_id + cursor => stable pagination
```

### 14.3 Conditional access

Runtime SHOULD 使用条件请求或等价机制：

```text
If-None-Match
If-Modified-Since
known_schema_hash
observed.object_version
observed.profile_hash
```

Provider SHOULD 在可判断时返回 not-modified / stale / schema-unchanged 等 caller-neutral 信号。

不要把这些信号表述为 `known_in_session` 或 `read_after`；那是上层 Read Runtime 的语言。

---

## 15. Security and Trust Boundary

DID Object Card 负责身份和发现，但不能替代运行时授权。

Runtime MUST：

- 验证 DID Object Card 来源。
- 检查 DID Document 签名、controller 或 Zone 信任链。
- 确认 Object URL 与 DID Object Card `alsoKnownAs` / DID resolution 一致。
- 只允许访问 Profile 中声明的 property/action/event。
- 对 action input 做 schema validation。
- 对 event subscription 做权限检查。
- 对高风险 action 做确认。
- 对 action、property、event subscription 和 event delivery 记录审计。

Provider MUST：

- 不信任 caller 的客户端校验结果。
- 重新校验 auth、RBAC、object state 和 quota。
- 对长生命周期 subscription 设置 TTL。
- 对跨对象或外部副作用操作进行额外 policy 检查。

审计字段 SHOULD 至少包含：

```text
who
when
object_url
object_did
property/action/event
endpoint
trace_id
source
confirmation
result
```

HTTP host 只能作为发现入口。强验证场景下，必须把信任回溯到 DID Document 的签名者、controller、Owner 或 Zone。

### 15.1 Trust metadata

Resolver 或 Runtime MAY 为 DID Object Card / endpoint response 附加 trust metadata：

```json
{
  "source": {
    "type": "object_host|zone_registry|local_registry|did_resolver|cache|adapter",
    "uri": "https://myhome.com/devices/cam01/did.json",
    "trust": "official|verified|zone|local|unverified|cached|stale",
    "fetched_at": "2026-06-07T12:00:00Z",
    "valid_until": "2026-06-07T13:00:00Z"
  }
}
```

这些 metadata 可以被 Read Runtime 使用，但不规定其输出格式。

---

## 16. DID Object Host and Resolver Routes

核心协议只要求 Runtime 能从 Object URL / DID 得到 verified DID Object Card。resolver 算法是实现细节。

### 16.1 Default route

默认 Web-compatible route：

```text
GET {object_url}/did.json
```

### 16.2 Additional routes

BuckyOS Runtime MAY 支持：

- local registry。
- Zone registry。
- BNS。
- DID resolver cache。
- host-level manifest。
- pre-configured DID Object Host。

这些 route MAY 返回 resolver metadata，但最终必须生成合法 DID Object Card。

### 16.3 Host manifest as non-normative route

原生 DID Object Host 可以暴露 host-level manifest：

```text
GET https://booking.example.com/.well-known/did-object.json
```

示例：

```json
{
  "protocol": "did-object/1",
  "object_hosts": ["booking.example.com"],
  "profiles": [
    "https://booking.example.com/profiles/stay-search@1",
    "https://booking.example.com/profiles/stay-offer@1",
    "https://booking.example.com/profiles/stay-reservation@1"
  ],
  "auth": ["oauth2", "session_delegation"],
  "url_claims": ["https://www.booking.example.com/*"]
}
```

该 manifest 是 resolver route 的输入，不替代 DID Object Card。每个 DID Object 仍应能解析到自己的 DID Object Card。

---

## 17. Agent Result Compatibility Profile

本节非核心强约束。它定义 action result / event frame 如何更好兼容 Agent Tool Result。

Provider SHOULD 在 action response `meta` 中使用 caller-neutral 字段：

```json
{
  "meta": {
    "status": "ok|accepted|no_change",
    "summary": "Human-readable short summary.",
    "created_objects": [],
    "affected_objects": [],
    "invalidated_objects": [],
    "refresh_hints": []
  }
}
```

Agent Runtime MAY 映射为：

| Protocol field | Agent-facing meaning |
|---|---|
| `meta.summary` | tool result summary |
| `created_objects` | returned object refs |
| `affected_objects` | objects changed by action/event |
| `invalidated_objects` | cached/read views to invalidate |
| `refresh_hints` | possible `read_after` targets |
| error `code = stale_object` | `status = stale` |
| confirmation error / policy | `status = needs_confirm` |

Profile 可以声明 agent compatibility hints：

```json
{
  "actions": {
    "book": {
      "input": { "$ref": "https://booking.example.com/schemas/booking-request@1" },
      "output": { "$ref": "https://booking.example.com/schemas/reservation@1" },
      "forms": [
        {
          "href": "methods/book",
          "op": "invokeaction",
          "contentType": "application/json"
        }
      ],
      "x-buckyos:agentResult": {
        "summaryField": "summary",
        "objectUrlFields": ["reservation"],
        "refreshObjects": ["self", "created_objects"]
      }
    }
  }
}
```

这些 hints 不影响普通 caller 的协议兼容性。

---

## 18. Relationship to Agent Read Runtime

本节非规范。

Agent Read Runtime 可以使用本协议材料构造 LLM-facing ReadResult，例如：

- Object URL / DID -> canonicalization。
- DID Object Card -> identity / controller / source trust。
- Profile -> properties/actions/events/traits。
- Property values -> object state。
- IndexPage -> table / collection rendering。
- Action meta -> affected objects / refresh hints。
- EventFrame -> invalidation / wakeup / subscription summary。
- ETag / schema_hash / row version -> session-aware compression。

但 Read Runtime 输出还受以下因素影响：

- input route。
- adapter chain。
- user session。
- cache state。
- authorization policy。
- token budget。
- task purpose。
- LLM-facing rendering strategy。

因此本协议只定义底层可验证对象能力，不定义 `read()` 的具体返回结构。

---

## 19. Standard Compatibility

| 标准 / 技术 | 使用方式 |
|---|---|
| W3C DID Core | DID Object Card 使用 DID Document。 |
| did:web | URL path object 可自然映射到 `/{path}/did.json`。 |
| W3C WoT Thing Description | DID Object Profile 使用 constrained TD-style document。 |
| JSON Schema-compatible Data Schema | property/action/event/index schemas。 |
| HTTP(S) | DID Object Card discovery、property GET、action POST。 |
| WebSocket | event subscription lifecycle and stream。 |
| WebRTC / WHEP / HLS / DASH | 通过 Media Resource Descriptor 引用。 |

推荐协议表述：

```text
A DID Object Card is a DID Document.
A DID Object Profile is represented as a constrained WoT Thing Description document.
DID Object Runtime v1 supports HTTP(S) property/action endpoints and WS(S) event endpoints.
```

---

## 20. Implementation Phases

### Phase 1: DID Object Card and Profile

- Object URL -> DID Object Card resolver。
- DID Document verification。
- `DIDObjectService` parsing。
- Profile fetch and cache。
- endpoint resolution rules。

### Phase 2: Property and Action

- property GET。
- action POST kRPC-style envelope。
- schema validation。
- trace_id / audit。
- ETag / conditional access。
- error envelope。

### Phase 3: Event Lifecycle

- event declaration parsing。
- WebSocket v1 binding。
- subscribe / renew / unsubscribe / status。
- lease / expires_at。
- EventFrame with event_id / seq / cursor。
- KEvent bridge。

### Phase 4: Traits and IndexTrait

- `x-buckyos:traits` parsing。
- IndexTrait contract。
- `index_schema` property。
- `query` and `page` actions。
- IndexPage with schema_hash / snapshot_id / row version。

### Phase 5: Agent Compatibility

- action result `meta` compatibility fields。
- event `refresh_hints`。
- stale / confirmation mapping。
- optional `x-buckyos:agentResult` hints。

### Phase 6: Additional resolver routes

- local registry。
- Zone registry。
- BNS。
- host manifest。
- DID Object Host policy and auth integration。

---

## 21. Open Questions

- Profile 主版本是否统一使用 URL 后缀 `@1`，patch/minor 使用 `version.instance`。
- `x-buckyos:action.effect` 是否进入 stronger normative subset，还是只保持 policy hint。
- `confirm_token` 由 Runtime 统一签发，还是 Provider 签发，或两者都支持。
- Event durable delivery 是否进入 v1.1，还是 v2。
- `IndexTrait` 是否需要标准 `sort` / `filter` expression language，还是只规定 schema shape。
- TaskTrait 是否需要与 action long-running semantics 一起标准化。
- Media Resource Descriptor 是否放入独立 schema registry。
- `obj://` 是否在 Agent Runtime 层保持，还是未来引入 core resolver input profile。
- Host manifest 是否应从非规范 resolver route 升级为 core discovery route。

---

## 22. Current Summary

- DID Object Protocol 是封闭世界协议，不定义开放世界 `read()`。
- Object URL 是协议层对象引用；DID Object Card 是协议层对象视图。
- DID Object Card 使用 DID Document；DID Object Profile 使用 constrained WoT TD。
- Action Invocation 是 caller-neutral 协议；Agent `xcall` 是上层包装。
- Event lifecycle 是协议语义，必须支持 lease / renew / unsubscribe / status / stream。
- Indexer 是实现 IndexTrait 的普通 DID Object，而不是单独 tool。
- Session-aware context management 不进入核心协议，但协议必须提供稳定 object/version/schema/event metadata。
- `read_after` 不进入核心协议；使用 `refresh_hints` / `affected_objects` / `invalidated_objects`，由 Agent Runtime 自行映射。
