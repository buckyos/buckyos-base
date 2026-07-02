在本文档中列出系统支持的DID-Resolver 。首先说协议，协议无非就是两种：
1. HTTP-based
2. DNS-based

除了 DNS Resolver，其他全部都是 HTTP 协议配置的。

按照顺序，我们有这么几种：

## bns_resolver (did:bns)
   (a) 域名基本上都可以配置。
   (b) 我们一般鼓励用户在自己的境内搭一个。
   (c) 在这之前，用公网的bns.buckyos.ai

## web_resolver (did:web)
按下面两个顺序
先使用 well-known ，
查询不到再走GET https://{uppername}/1.0/identifiers/{did}?type={doc_type}
uppername : did:web:ood1.example.com 就是 did:web:example.com
这个顺序的意义在于，只通过静态部署，就能够让持有域名和相关 CA 证书的网站运营者，能去部署符合我们 DID Document 规范的文件。

## dns_resolver (did:web + did:bns)
非权威源。使用DNS TXT 协议

通常用于 Zone 在自启的时候，它在 Booting 阶段因为自己没启动（特别是对于 DID Web 的 Zone 讲，如果它没启动，它这个 HTTPS 服务器也没生效），所以需要有一个 Zone 外的系统来保存引导信息。

然后在 buckyos Booting 这个阶段它相对比较特殊，是因为它在本地已经有 Owner Document，所以说 DNS resolver 上保存的几个Document是100%可以验证的

## sn_resolver (did:web + did:bns)
非权威源。使用下面协议：
```
GET https://{provider}/1.0/identifiers/{did}?type={doc_type} 
```

它的好处是它可以支持DeviceDocument的查询，在有跨NAT的OOD组成的BuckyOS的启动阶段，可以辅助OOD获得另一个OOD的DeviceDocument和DeviceInfo

## zone_resolver (did:web + did:bns)
对zone内来说是权威源，一般是非公开服务，只能zone内访问（跑在127.0.0.1上）
相比web_resolver,Zone内在启动后，可以通过zone_resolver获得更多的did-document.比如zone内的device document
只使用 GET https://{provider}/1.0/identifiers/{did}?type={doc_type} 
 
## smart_resolverr (所有did 暂不实现)
非权威源，是一种基于社交网络的，有一定动态拓扑能力的 http base resolve
所谓动态拓扑是指，比如我们通过社交网络得到了一个应用的 Document，而这个应用的 Document 在其他地方都找不到。

在这种情况下，如果有另一个 类似的AppName2出现，我们会通过smart_resolver进行处理。例如：
1. 我知道这个AppDocument是从好友 A 那里拿到的。
2. 那么最后，我可能也会尝试从好友 A 这里再获取一下AppName2的 Document。

这种行为就叫做动态拓扑。（从外人看好友A和AppName2没有任何关系）

## resolver-provider的 注册顺序

第一个总是权威源

### did:bns
bns_resolver -> web_resolver -> dns_resolver -> sn_resolver

### did:web
web_resolver -> dns_resolver -> sn_resolver

### buckyos内部
1）如果current zone是did:web:xxx 那么需要走一个特殊流程
2）buckyos在启动后，会针对当前zone内的did,设置一个zone-resolver放在最前面（只接收同zone的did查询请求）
