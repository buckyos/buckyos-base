# 系统支持的 DID Resolver 一览

本文列出系统支持的全部 DID resolver:各自的协议、权威性、典型场景,以及每个 DID method 下的注册顺序。除 `zone_resolver` 外,这里的 `xxx_resolver` 对应代码里的 `NsProvider` 实现(name-client);`zone_resolver` 使用同一套 resolver HTTP API,但语义上是 cache 层组件。注册模型与术语(权威源 / 补充源、need_proof、first-win)见 [简单介绍resolve-did.md](./简单介绍resolve-did.md) 第 2 节,resolver 接口的线上协议见 [http_did_resolver_api.md](./http_did_resolver_api.md)。

先记住框架(简介 2.2 / 2.3 节),后面每一节都只是往里填内容:

- 每个 DID method **至多一个权威发布渠道**,加上按优先级排列的**少数补充源**,主动查询 first-win;
- 权威源能回答**发布状态 + owner 绑定**,取回结果 need_proof = false;补充源永远只产出候选文档,一律 need_proof = true(免验证的 Info 类除外,那是按 doc_type 契约事先声明的);
- 权威还是补充由**注册位置**决定,不由 provider 自己声明;同一权威渠道可以有多个委托读取端(镜像、网关),它们合并算一个权威源。
- `zone_resolver` 不进入这个 provider 排序。它是**伪装成 resolver 的 zone 内权威 cache**:协议形态像 resolver,但查询位置在 cache 层。

## 0. 协议只有两种

1. **HTTP-based**——除 dns_resolver 外,其余全部是 HTTP 协议。接口形态又分两种:
   - **静态文件**:`GET https://{host}/{path}/{doc_type}.json`。不需要运行任何动态服务,静态部署即完成发布;
   - **resolver 接口**:`GET https://{provider}/1.0/identifiers/{did}?type={doc_type}`。标准的 DID resolver HTTP API,响应信封可携带发布状态等元数据。
2. **DNS-based**——只有 dns_resolver,使用 TXT 记录。

下面按类型逐个介绍。

## 1. bns_resolver(did:bns 的权威源)

did:bns 的权威发布渠道是 BNS 智能合约,bns_resolver 是这个渠道的委托读取端(BNS 网关)。它走 resolver 接口,是唯一能对 did:bns 回答**发布状态 + owner 绑定**的 provider。

网关 host 是配置项,选择上:

1. 基本上任何域名都可以配置成 BNS 网关;
2. 我们一般鼓励用户在自己所处的网络环境(境内)自建一个——自建网关读的仍是同一条合约渠道,属于同一权威渠道的另一个读取端,不破坏"至多一个权威渠道";
3. 在自建之前,先用公网的 `bns.buckyos.ai`。

## 2. web_resolver(did:web 的权威源;did:bns 的补充源)

did:web 把身份锚定在域名控制权上:权威发布面就是该域名 HTTPS 站点的固定路径,web_resolver 是这个 canonical endpoint 的读取端。取回按下面两个顺序:

1. **先查 W3C well-known 静态 URL**:`https://{host}/.well-known/{doc_type}.json`(带路径的 did 落在 `/{path}/{doc_type}.json`;默认 doc_type 落在标准的 `did.json` 上);
2. **查询不到,再走上级名字(uppername)的 resolver 接口**:

   ```
   GET https://{uppername}/1.0/identifiers/{did}?type={doc_type}
   ```

   uppername 是去掉名字最左一个 label:`did:web:ood1.example.com` 的 uppername 就是 `did:web:example.com`。上级域名由此可以为它的全部子域集中提供动态解析——BuckyOS 里 zone gateway 为 zone 内设备 DID 提供解析,就是这个形态。

**这个顺序的意义**:只通过静态部署,持有域名和相关 CA 证书的网站运营者,就能发布符合我们 DID Document 规范的文件——不需要运行任何动态服务;上级集中解析是可选的增强。

负回答的合并纪律:两个信道**一致**回答"没有",才归一成 Missing;任一信道传输失败,整体按 unknown 处理——不能把断网伪装成"从未发布"(简介 2.1 节)。

对 did:bns,同样的取回逻辑作用在名字的规范 host 映射上(`did:bns:alice` ↔ `alice.{bns_root}`,通常最终指向对方 zone 的网关)。但这条信道不是 BNS 的权威渠道,只产出 need_proof 候选,所以 web_resolver 在 did:bns 下是补充源。

## 3. dns_resolver(did:web + did:bns 的补充源)

非权威源,使用 DNS TXT 协议(`PKX=` / `BOOT=` / `DEV=` 几类记录,可还原 owner / boot / zone / device 文档)。DNS 信道本身没有认证能力(明文查询,可被伪造),所以它取回的一切都只是 need_proof 候选——"英雄不问出处,但要验证"(简介 2.3 节)。

典型场景是 **Zone 自举**:Zone 在 Booting 阶段自己还没启动——对 did:web 的 Zone 来说,它自己的 HTTPS 服务器这时也没生效——所以必须有一个 Zone 外的系统保存引导信息,DNS 就是这个系统。

Booting 阶段还有一个特殊性:本地已经有 Owner Document,所以 dns_resolver 上保存的那几个文档是 **100% 可验证**的——验签在本地闭环,不依赖任何额外的网络查询。

## 4. sn_resolver(did:web + did:bns 的补充源)

非权威源,走 resolver 接口:

```
GET https://{sn_host}/1.0/identifiers/{did}?type={doc_type}
```

它的价值是支持 **DeviceDocument / DeviceInfo 的查询**:由跨 NAT 的多台 OOD 组成的 BuckyOS 在启动阶段,OOD 之间直连不可达,可以经 SN 拿到另一台 OOD 的 DeviceDocument 和 DeviceInfo,辅助完成组网。(DeviceDocument 是 need_proof 候选,照常验签;DeviceInfo 属于按契约免验证的 Info 类 doc_type。)

## 5. zone_resolver(伪装成 resolver 的 zone 内权威 cache)

zone_resolver 一般是非公开服务,只能 zone 内访问(默认跑在 `127.0.0.1:3180`)。它只使用 resolver 接口(不查 well-known):

```
GET http://127.0.0.1:3180/1.0/identifiers/{did}?type={doc_type}
```

它名字里叫 resolver,接口也长得像 resolver,但在 `name-client` 的设计里它不是
resolver-provider,而是 **cluster-level shared cache / control-plane cache**。换句话说,
它是"伪装成 resolver 的 zone 内权威 cache":

- 对 zone 内客户端来说,它的结果是当前 cluster 的解析控制结果,可以短路外部 DID resolver 查询;
- 对 resolver core 来说,它只是进入 provider 链之前的一次 cache 查询,不参与 method authority /
  supplement 的 first-win 合并;
- 只有 zone_resolver 服务不可用(连接失败、超时、明确 service unavailable)时,才落回本机 local cache
  和后续 provider 流程;
- `Missing / Revoked / Tombstoned / Unknown` 都是它的语义回答,不是 cache miss,不能触发本机 cache
  或外部 authority 兜底。

zone_resolver 通常会包含本机 cache 的能力,并叠加 cluster host / override / negative
state 等管理逻辑。相比传统 hosts 文件只能模拟 IP 解析,它返回完整 DID resolver 结果,
因此可以覆盖 Document、Info、Missing、Revoked / Tombstoned 和 metadata。

zone_resolver 服务的内部实现自己也用 `resolve_did` 完成对外查询(它没命中时替
客户端向权威源/补充源发问)。这类调用必须用
`ResolvePolicy::without_zone_resolver()`(`use_zone_resolver = false`)跳过 Zone
cache 快路径,否则服务会查询到自己(默认 endpoint 就是本机 3180)造成递归。

相比 web_resolver,zone 启动之后通过 zone_resolver 可以获得**更多**的 did-document——比如
zone 内的 device document,这些文档不一定对外发布。它也可以实现 Zone 内短路:只要持续返回某个
DID/doc_type 的结果或负状态,客户端就不会把该请求发送到 Zone 外。

## 6. smart_resolver(所有 did;暂不实现)

非权威源。一种基于社交网络、有一定**动态拓扑**能力的 HTTP-based resolver。

所谓动态拓扑:比如我们通过社交网络得到了应用 AppName 的 Document,而这个 Document 在其他任何地方都查不到。之后如果出现另一个类似的 AppName2,smart_resolver 会这样处理:

1. 我知道 AppName 的 Document 是从好友 A 那里拿到的;
2. 那么我也会尝试从好友 A 那里获取 AppName2 的 Document。

在外人看来,好友 A 和 AppName2 没有任何关系——这种根据历史来源动态扩展查询路径的行为,就叫动态拓扑。

按简介第 5 节的框架,"通过社交网络拿文档"这类多来源本来发生在 Cache 层(push / 共享进缓存);smart_resolver 是把它引入主动查询路径的尝试,永远只产出 need_proof 候选。暂不实现。

## 7. resolver-provider 的注册顺序与 Zone cache

**第一个总是权威源**(简介 2.2 节:权威渠道永远第一;补充源按注册顺序即优先级,first-win,没有读放大。低优先级源拿到比高优先级更新的结果,通常说明哪里配置错了,值得打警告)。

Zone cache 位于 provider 顺序之前:默认先查 `http://127.0.0.1:3180`,服务可用时直接返回
`ZoneHit`;只有服务不可用才进入下面的 provider 注册顺序。

**provider 顺序的另一个设计意图是尽量去中心化**:resolve_did 和 DNS 查询一样,是会被海量调用的基础设施。如果注册顺序里有一台全网共用的服务器排在靠前位置,所有解析流量都会汇聚到它——既给它带来巨大的请求压力(单点故障、易被封锁),也让系统事实上重新中心化。现在的顺序保证**不存在指向单台服务器的热路径**:

- 排第一的 provider 权威源是每个 did **自己的发布面**:did:web 打到目标自己的域名,流量随站点天然分散,与 Web / DNS 本身的去中心化结构同构;zone 内 did 通常已被前置 Zone cache 短路(第 5 节),查询根本不出 zone;
- did:bns 的权威渠道是合约,网关只是可替换的读取端:任何域名都能自建网关、且鼓励自建(第 1 节),`bns.buckyos.ai` 只是自建之前的引导默认值,不是全网必经之路;
- 补充源里,dns_resolver 复用 DNS 自身已分布式部署的基础设施(递归解析 + 缓存),不引入新的集中点;sn_resolver 这类共享服务注册在末位,first-win 意味着只有前面的源都给不出回答时才会打到它——共享基础设施只承接兜底流量,不在热路径上。

### did:bns

```
bns_resolver → web_resolver → dns_resolver → sn_resolver
```

### did:web

```
web_resolver → dns_resolver → sn_resolver
```

### buckyos 内部(zone 场景)

1. name-client 默认启用 zone_resolver cache,默认地址是 `http://127.0.0.1:3180`。它不按 DID 是否属于当前 zone 做客户端侧过滤;覆盖范围、是否允许出 Zone、是否短路,都由 zone_resolver 服务内部策略决定;
2. 当 zone_resolver 服务可用时,它的回答直接返回,不再查 local cache、method authority 或 supplements;
3. 当 zone_resolver 服务不可用时,才退回单机模式:local cache / local override 快路径,再进入上面的 provider 顺序;
4. 如果 current zone 是 `did:web:xxx`,需要走一个特殊流程:zone 的权威发布面是它自己的 HTTPS 服务,启动完成之前不可达。Booting 阶段要靠本地已有的 Owner Document + dns_resolver 引导(见第 3 节)。具体流程待展开。

## 8. 与当前实现的对照(2026-07 快照)

name-client 的 provider 注册(lib.rs 的 `init_name_lib_ex`)已与第 7 节的目标顺序基本一致;
Zone Resolver 的 cache 层化已完成(2026-07-03):

| 本文的 resolver | 代码 | 状态 |
| --- | --- | --- |
| bns_resolver | `BnsProvider`(bns_provider.rs,薄配置壳,HTTP 细节复用 `BaseHttpProvider`) | 已注册为 did:bns 权威源。公网默认网关仍是 `web3.buckyos.ai`——目标名 `bns.buckyos.ai` 的 DNS 尚未上线,不能先切默认值;上线后改 `BuckyOSMachineConfig::default` 与 `get_default_web3_bridge_config` 两处即可 |
| web_resolver | `WebProvider`(web_provider.rs,well-known + uppername 双信道) | 已注册为 did:web 权威源(canonical endpoint 唯一读取端)+ did:bns 第一补充源。did:bns 的名字映射(`did:bns:alice` ↔ `alice.{bns_root}`)已实现,bns_root 与 BNS 网关共用 web3 bridge 配置;一级 bns 名字没有 uppername 回退(那个端点就是 BNS 网关本身,归 bns_resolver 管) |
| dns_resolver | `DnsProvider`(dns_provider.rs) | 已按本文降为补充源:did:web 与 did:bns 下均注册在 web_resolver 之后,取回结果一律 need_proof 候选。原先"经 `AuthorityReaders` 并入 did:web 权威渠道"的注册已移除 |
| sn_resolver | `BaseHttpProvider` 指向 SN host | web3 bridge 配置含 `"sn"` 键时,自动注册为 did:web / did:bns 的末位补充源;默认配置不含 sn,即默认未注册 |
| zone_resolver | `ZoneResolverClient`(zone_resolver.rs,独立 cache 客户端,不是 `NsProvider`),默认启用、默认指向 `http://127.0.0.1:3180`,`NameClient::resolve_did_ex` 第 0 步查询 | **已迁移**:服务可用即独占返回 `CacheStatus::ZoneHit`(负状态 / Missing / unknown 都是回答,不触发 fallback);服务不可用(连接失败/超时/502/503/504)才落回 local cache 和 provider 链。旧的 `set_zone_authority` 接法与 `did_in_zone` 客户端过滤已删除;`disable_zone_resolver()` / `set_zone_resolver_endpoint(...)` 控制启停与地址,zone 回答不回写本机 cache |
| smart_resolver(社交版) | 无 | 暂不实现 |

另外:resolver 接口响应里的 buckyos 扩展信封(发布状态等)客户端解析已就绪(`BaseHttpProvider`),服务端尚未实现;在那之前,did:web 的发布状态由主循环把 200 / 404 / 410 归一成 Active / Missing / 负状态。

**dns_resolver 降级的行为变化**:此前 TXT 记录还原出的文档按权威结果(need_proof = false)直接放行;现在它们是普通候选,须通过 expected_owner 一致性与 owner 验签才可见。对第 3 节的 Zone 自举场景,这正是"本地已有 Owner Document,验签在本地闭环"的前提——纯 TXT 发布、又没有任何 owner 绑定来源的 did,将不再能通过 resolve_did 管线解析(这是本文第 3 节要求的安全语义,不是缺陷)。Booting 具体流程仍待展开(第 7 节)。
