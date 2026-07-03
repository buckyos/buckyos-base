# 系统支持的 DID Resolver 一览

本文列出系统支持的全部 DID resolver:各自的协议、权威性、典型场景,以及每个 DID method 下的注册顺序。这里的 `xxx_resolver` 对应代码里的 `NsProvider` 实现(name-client);注册模型与术语(权威源 / 补充源、need_proof、first-win)见 [简单介绍resolve-did.md](./简单介绍resolve-did.md) 第 2 节,resolver 接口的线上协议见 [http_did_resolver_api.md](./http_did_resolver_api.md)。

先记住框架(简介 2.2 / 2.3 节),后面每一节都只是往里填内容:

- 每个 DID method **至多一个权威发布渠道**,加上按优先级排列的**少数补充源**,主动查询 first-win;
- 权威源能回答**发布状态 + owner 绑定**,取回结果 need_proof = false;补充源永远只产出候选文档,一律 need_proof = true(免验证的 Info 类除外,那是按 doc_type 契约事先声明的);
- 权威还是补充由**注册位置**决定,不由 provider 自己声明;同一权威渠道可以有多个委托读取端(镜像、网关),它们合并算一个权威源。

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

## 5. zone_resolver(zone 内的权威源)

对 zone 内的 did 来说是权威源;一般是非公开服务,只能 zone 内访问(跑在 `127.0.0.1` 上)。只使用 resolver 接口(不查 well-known):

```
GET http://127.0.0.1:3180/1.0/identifiers/{did}?type={doc_type}
```

zone 内 did(设备、应用等)的发布点就是 zone 自己的配置,zone_resolver 是这个发布面的本地直读端。所以"对 zone 内是权威源"与"至多一个权威渠道"不冲突:它和 zone gateway 对外提供的动态解析(web_resolver 的信道 2)读的是同一发布渠道,只是读取端不同。

相比 web_resolver,zone 启动之后通过 zone_resolver 可以获得**更多**的 did-document——比如 zone 内的 device document,这些文档不一定对外发布。

## 6. smart_resolver(所有 did;暂不实现)

非权威源。一种基于社交网络、有一定**动态拓扑**能力的 HTTP-based resolver。

所谓动态拓扑:比如我们通过社交网络得到了应用 AppName 的 Document,而这个 Document 在其他任何地方都查不到。之后如果出现另一个类似的 AppName2,smart_resolver 会这样处理:

1. 我知道 AppName 的 Document 是从好友 A 那里拿到的;
2. 那么我也会尝试从好友 A 那里获取 AppName2 的 Document。

在外人看来,好友 A 和 AppName2 没有任何关系——这种根据历史来源动态扩展查询路径的行为,就叫动态拓扑。

按简介第 5 节的框架,"通过社交网络拿文档"这类多来源本来发生在 Cache 层(push / 共享进缓存);smart_resolver 是把它引入主动查询路径的尝试,永远只产出 need_proof 候选。暂不实现。

## 7. resolver-provider 的注册顺序

**第一个总是权威源**(简介 2.2 节:权威渠道永远第一;补充源按注册顺序即优先级,first-win,没有读放大。低优先级源拿到比高优先级更新的结果,通常说明哪里配置错了,值得打警告)。

### did:bns

```
bns_resolver → web_resolver → dns_resolver → sn_resolver
```

### did:web

```
web_resolver → dns_resolver → sn_resolver
```

### buckyos 内部(zone 场景)

1. buckyos 在启动后,会针对当前 zone 内的 did,把 zone_resolver 注册在最前面(只接收同 zone did 的查询;对 zone 内它就是权威源,见第 5 节);
2. 如果 current zone 是 `did:web:xxx`,需要走一个特殊流程:zone 的权威发布面是它自己的 HTTPS 服务,启动完成之前不可达(先有鸡还是先有蛋),Booting 阶段要靠本地已有的 Owner Document + dns_resolver 引导(见第 3 节)。具体流程待展开。

## 8. 与当前实现的对照(2026-07 快照)

本文描述的是目标形态,与 name-client 当前代码的差异如下,供对齐时参考:

| 本文的 resolver | 代码 | 状态 |
| --- | --- | --- |
| bns_resolver | `BnsProvider`(bns_provider.rs,薄配置壳,HTTP 细节复用 `BaseHttpProvider`) | 已注册为 did:bns 权威源。公网默认网关目前是 `web3.buckyos.ai`,本文的目标名是 `bns.buckyos.ai` |
| web_resolver | `WebProvider`(web_provider.rs,well-known + uppername 双信道) | 已实现,当前只注册给 did:web;did:bns 的直连补充位空缺,待 WebProvider 支持 did:bns 的名字映射后接入 |
| dns_resolver | `DnsProvider`(dns_provider.rs) | 已实现,但注册位置与本文不一致:当前它经 `AuthorityReaders` 与 WebProvider 合并为 did:web 权威渠道的读取端,结果按 need_proof = false 处理;本文的目标是降为补充源(DNS 信道无认证)。did:bns 下当前未注册 |
| sn_resolver | `BaseHttpProvider` 指向 SN host 即可 | 协议能力已具备,默认未注册 |
| zone_resolver | `BaseHttpProvider` 指向 zone 内服务即可 | 协议能力已具备;buckyos 启动时注册 zone_resolver 的机制待接入 |
| smart_resolver(社交版) | 无 | 暂不实现 |

另外:resolver 接口响应里的 buckyos 扩展信封(发布状态等)客户端解析已就绪(`BaseHttpProvider`),服务端尚未实现;在那之前,did:web 的发布状态由主循环把 200 / 404 / 410 归一成 Active / Missing / 负状态。
