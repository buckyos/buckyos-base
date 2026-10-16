# resolve-did 组件与使用模式核对

> 2026-09-11，静态源码核对。对照 [协议冻结讨论伪代码](./resolve-did协议冻结讨论伪代码.md)。
> 本文整理调用者、基础设施和协议边界，不修改运行行为；“建议”不代表现有 API 或已经冻结的要求。

现有讨论稿对单份 DID Document 的解析、验证、缓存、覆盖和历史验证已有较完整的分类。跨组件核对后，最需要补充的是：**业务接纳状态、合成文档、跨文档解析依赖、连接生命周期、独立公钥信任源、用 DID 文档验证另一类签名对象，以及从访问端点发现 Zone 身份**。这些不能全部归结为 `Current / StillValid / AtPublication` 三种文档验证模式。

另有几项确定的实现差异：BNS HTTP 的 `documentVersion` 仍是登记版本号；部分“公网当前”检查会接受本机 override；RTCP 的 freshness 门禁比讨论稿的 `Current` 更宽；网关动态添加 provider 的接口没有接入新的 DID method 注册路径。它们是已有分类下的实现问题，不应包装成新模式。

## 1. 核对范围与判断方法

检查当前工作区中的源码、调用链和接线配置，包括未提交的讨论稿；排除 `target`、`node_modules`、构建产物和历史部署备份。以生产调用为主，区分仅提供的库 API、测试调用、纯依赖声明和同名的其他业务接口。

| 仓库 | 核对时 HEAD | 结果范围 |
| --- | --- | --- |
| buckyos-base | `1ae69b4` | 解析/验证/cache/provider、身份材料目录、kRPC S2S、HTTP 服务封装 |
| buckyos | `d470ff3f` | node-daemon、system-config Zone Resolver、Control Panel、runtime、Agent DID Object |
| cyfs-gateway | `dd7ae57` | RTCP、BNS 服务/索引/客户端/UI、SN 双入口、DNS/隧道、TLS/ACME、网关管理接线 |
| cyfs-ndn | `00847d7` | NDN 路径断言验证 |
| buckyos-websdk | `afdc5fd` | 宿主解析桥、身份材料配套 |
| BuckyOSApp | `6f39416` | Tauri NameClient 与 iframe 桥 |
| sn-business | `54ef043` | SN 业务的 S2S Provider、身份材料和 Relay 配置 |
| buckyos-devkit / filebrowser / ask-dwell | `96a1832` / `99e9a5bb` / `7ef593d` | 未发现独立的可信 DID Document 解析/验证实现或直接生产调用 |

除 buckyos-base 中原有的未跟踪讨论稿外，上表仓库在核对开始时没有工作区变更。这里描述的是这些源码版本；未核对部署进程、运行时缓存内容或各产品构建时实际锁定的 Git 依赖提交，不能据此断言线上二进制已经采用同一版 name-client。

检索覆盖 `resolve_did / resolve_did_ex / resolveDid / resovle_did`，并扩展到 `query_did`、verify 家族、cache 写入、override、取公钥、`IdentityRoots`、`/1.0/identifiers`、DID Object 和间接地址解析。对命中项继续追踪来源选择、证据、使用目的、保存位置及生效期限。

下文“已覆盖”只表示讨论稿能表达其用途，不表示当前实现已经满足第 3、5 节建议的统一门禁。

## 2. 组件清单

### 2.1 解析基础设施与文档提供方

| 组件 | 实际使用/提供方式 | 与讨论稿的关系及源码 |
| --- | --- | --- |
| name-client 主入口、NameQuery、DocCache | 全局或实例 `resolve_did(_ex)`；Zone、override、本机 cache、method authority、supplement；验证上下文和独立 cache 写入 | 讨论稿 §2–5 的直接对象。[主入口](../src/name-client/src/name_client.rs#L1300)、[纯验证](../src/name-client/src/verify_context.rs#L747)、[组合入口](../src/name-client/src/verify.rs#L497) |
| BnsProvider、WebProvider、BaseHttpProvider | BNS 委托读取、did:web HTTPS 发布面、HTTP 信封解释 | authority/body 分离已覆盖。[默认接线](../src/name-client/src/lib.rs#L115)、[HTTP 状态归一](../src/name-client/src/https_provider.rs#L303) |
| did:web 静态发布；DirServer、Relay/节点网关路由 | 将本地身份目录的 `did.json` 等文档挂载到 HTTPS `/.well-known/`；不是每次请求重新验证 Owner 的 resolver | 属于 §2/§8 的 method 发布面，信任来自域名 HTTPS 发布权限；材料生成与远端消费应分开。[DirServer](../../cyfs-gateway/src/components/cyfs-gateway-lib/src/server/dir_server.rs#L20)、[Relay 接线](../../sn-business/src/apps/sn_gateway/sn_relay.yaml#L57) |
| DnsProvider、LocalConfigDnsProvider；cyfs-dns / 网关 DNS server | 普通 DNS、TXT 文档候选、局部配置；默认 DID 管线中 DNS 仅注册为 current-zone bootstrap 补充源 | 候选来源已覆盖，直接 DNS boot 使用见 N1；不能把 DNS 命中当身份通过。[接线](../src/name-client/src/lib.rs#L126)、[DNS 文档读取](../src/name-client/src/dns_provider.rs#L249)、[LocalDns 转接](../../cyfs-gateway/src/components/cyfs-dns/src/local_dns.rs#L49) |
| ZoneResolverClient | 独立 L1；明确状态终结选择，unknown 继续；不回填本机；保留 snapshot 所需状态 | 已覆盖。但 `Anchored` 在这里表示 Zone 信道信任，不是本次公网 receipt。[lookup](../src/name-client/src/zone_resolver.rs#L110)、[打标](../src/name-client/src/zone_resolver.rs#L318) |
| system-config `ZoneDidResolver` | 从 `boot/config`、`devices/*/doc`、`users/*/doc`、`agents/*/doc`、`resolver/cache/.../{state,doc}` 生成回答；域内 Missing，域外可无意见 | Zone 管理面已提及，**业务状态投影和 Owner 字段合成未分类**，见 N1/N2。[主流程](../../buckyos/src/kernel/sys_config_service/src/zone_did_resolver.rs#L663)、[登记读取](../../buckyos/src/kernel/sys_config_service/src/zone_did_resolver.rs#L491) |
| BNS server / indexer HTTP | `/1.0/identifiers`；读取链事件投影；部分子设备名由父名的文档槽位加 Zone/Owner 联合决定 | 普通权威读取已覆盖；**虚拟设备身份及多依赖解析**见 N3，版本字段差异见 D1。[HTTP 路由](../../cyfs-gateway/src/components/bns-server/src/lib.rs#L758)、[设备映射](../../cyfs-gateway/src/components/bns-server/src/lib.rs#L1069) |
| BNS indexer 存储 / 同步、bns-client / SnBnsController / SN BNS proxy | 提供登记状态、原文、发布/撤销事件及 Owner 快照；当前 registry 默认只读，写入走签名 EVM 交易 | 属于 §8 权威发布面配套。不可把 legacy Rust 状态机当现行发布入口；本次没有完整审计链合约状态机。[只读门禁](../../cyfs-gateway/src/components/bns-indexer/src/registry.rs#L129)、[同步](../../cyfs-gateway/src/components/bns-indexer/src/sync.rs)、[Owner 快照](../../cyfs-gateway/src/components/bns-client/src/sn_bns_controller.rs#L1374)、[proxy 使用](../../cyfs-gateway/src/components/cyfs-sn/src/sn_bns_proxy.rs#L917) |
| SN `SnResolver` / `SnResolverBackedDidResolver` / `SNServer` | 同一服务分 PublicSupplement 与 InternalZoneResolver；后者可把 AuthDB 状态、公钥投影为明确 DID 状态 | scope 概念已覆盖，但**同服务不同入口的信任身份、合成 Owner 和业务封禁投影**需补分类，见 N2。[profile](../../cyfs-gateway/src/components/cyfs-sn/src/sn_did_resolver.rs#L663)、[入口选择](../../cyfs-gateway/src/components/cyfs-sn/src/sn_server.rs#L1943) |
| gateway-app-lib 与 BuckyOS runtime | 初始化全局 NameClient；网关管理命令还可添加 HTTP provider | 初始化是配套；动态注册实际失配见 D6。[gateway 初始化](../../cyfs-gateway/src/components/cyfs-gateway-app-lib/src/gateway.rs#L936)、[runtime 初始化](../../buckyos/src/kernel/buckyos-api/src/runtime.rs#L1252) |

### 2.2 消费者、准入者与缓存写入者

| 组件 | 实际模式 | 归类与结论 |
| --- | --- | --- |
| node-daemon 启动状态机 | 普通 resolve Zone → 网络 JWT 按激活公钥验证；失败再直查 DNS Boot；基于 LKGS 和平滑升级规则接纳；接纳结果投影为 Verified JSON | **N1：业务当前运行状态与解析当前版本分离**。[发现](../../buckyos/src/kernel/node_daemon/src/zone_boot_resolve.rs#L427)、[接纳](../../buckyos/src/kernel/node_daemon/src/zone_boot_resolve.rs#L473) |
| node-daemon Owner 预置 | 激活记录的公钥合成最小 Owner，永久本机 override | 部分属于 Lock，实际是本地根材料投影，见 N1/N2；Zone 仍优先。[安装本地信任](../../buckyos/src/kernel/node_daemon/src/zone_boot_resolve.rs#L611) |
| node-daemon 激活服务器 / node-active | 发布并等待精确 Device JWT 可见；完成激活后保存 Zone JWT 为 Verified | 发布确认已覆盖，公网检查存在 D2；这是写后读确认，不是历史验证。[确认](../../buckyos/src/kernel/node_daemon/src/active_server.rs#L697)、[保存](../../buckyos/src/kernel/node_daemon/src/active_server.rs#L630) |
| node-daemon finder | UDP 发现的原始 Device JWT → Observed；观测 IP → 独立 DeviceInfo cache | 符合候选/Info 分离；现有 soft TTL 尚不等于 §4 的 SeedObserved hard expiry。[写入](../../buckyos/src/kernel/node_daemon/src/finder.rs#L806) |
| RTCP 发起连接 | 目标 DID → 文档 → exchange key；选择 AuthorityCurrent 或 TrustedSnapshot；随后验证握手 | 取信任材料加持钥证明已覆盖，公网命名保证见 D2；key DID 快捷路径独立于 resolve。[目标解析](../../cyfs-gateway/src/components/cyfs-gateway-lib/src/rtcp/rtcp.rs#L1209) |
| RTCP 接收连接及连接管理 | 对收到的确切 JWT 验证；持钥证明、关系准入、listener 授权、cache CAS、连接注册；可异步确认公网并拆除旧连接 | §3 已覆盖验证/保存分离，**N4 补连接生命周期和异步确认**，D3 补门禁差异。[收件验证](../../cyfs-gateway/src/components/cyfs-gateway-lib/src/rtcp/rtcp.rs#L2236)、[提交](../../cyfs-gateway/src/components/cyfs-gateway-lib/src/rtcp/rtcp.rs#L3129) |
| kRPC S2S / buckyos-http-server S2S 封装 | Provider 优先；只有显式配置才可走 NameClient fallback；取默认 Ed25519 key 后缓存，并用于消息认证/加密 | **N5：独立取键信任源和派生缓存**。fallback 是现有库能力，本轮未在产品生产接线发现启用者，不能把全部 S2S 服务算作实际远程解析者。[取键](../src/kRPC/src/s2s/identity.rs#L370)、[HTTP 封装](../src/buckyos-http-server/src/s2s_rpc_server.rs#L54) |
| SN business AppContext；cyfs-sn 到业务服务的 S2S 客户端 | 固定集群/对端公钥 Provider，`provider_only`；本地身份目录负责私钥绑定 | 属于相关身份设施，**不经过 resolve_did**；见 N5。[AppContext](../../sn-business/src/modules/sn-base/src/app_context.rs#L1123)、[cyfs-sn 接线](../../cyfs-gateway/src/components/cyfs-sn/src/sn_server.rs#L2658) |
| Control Panel 应用安装 | `Custom("app")` 解析与证据快照；将包内 candidate 绑定 AppDID/Owner/ObjectId；安装前核对内容身份 | Current 客体用途已覆盖；包载体与当前解析结果分离，见 E1。StrictPublic 见 D2。[resolver](../../buckyos/src/frame/control_panel/src/app_install_resolver.rs#L366)、[内容绑定](../../buckyos/src/frame/control_panel/src/app_install_driver.rs#L968) |
| Control Panel rootfs 预安装 / LocalDeveloper | 预装 AppDoc 写永久本机 override；LocalDeveloper 则在安装快照中显式绑定特定 candidate ObjectId | 管理接纳已有概念，但操作级信任与进程级覆盖应区分，见 E1。[预装](../../buckyos/src/frame/control_panel/src/app_installer.rs#L3390)、[开发者材料](../../buckyos/src/frame/control_panel/src/app_install_driver.rs#L354) |
| NDN toolkit `NameClientPathVerifier` | resolve Zone，按 kid 与 `ZONE_PUBLISH` scope 验 `cyfs-path-obj` JWT，再绑定请求 host/path | **N6：DID 文档是另一种签名断言的验证依赖**。[实现](../../cyfs-ndn/src/ndn-toolkit/src/cyfs_ndn_client.rs#L81) |
| RTCP / IP / TLS / QUIC 地址解析 | `resolve_ip(s)` 内部先查 Device Document 固定 IP；普通名字信息和有同 Zone 关系证据的 Info 是后续信道 | Info 与身份分离已覆盖，地址可用性不等于身份有效性，见 E3。[核心](../src/name-client/src/name_client.rs#L717)、[RTCP](../../cyfs-gateway/src/components/cyfs-gateway-lib/src/rtcp/rtcp.rs#L649)、[TLS](../../cyfs-gateway/src/components/cyfs-gateway-lib/src/tls_tunnel.rs#L47)、[QUIC](../../cyfs-gateway/src/components/cyfs-gateway-lib/src/quic_tunnel.rs#L56)、[IP](../../cyfs-gateway/src/components/cyfs-gateway-lib/src/ip/tunnel.rs#L94) |
| BuckyOSApp / WebSDK 宿主桥 | WebSDK → iframe/native bridge → Tauri → 全局 NameClient；返回 JSON/JWT body | 普通 resolve 用途已覆盖，宿主信任和诊断信息跨边界缺失见 E2。[Tauri](../../BuckyOSApp/src-tauri/src/name_resolution.rs#L49)、[桥](../../BuckyOSApp/src/bridges/iframeBridge.ts#L160)、[SDK](../../buckyos-websdk/src/sdk_core.ts#L100) |
| WebSDK runtime Zone 发现 | 直接 GET 当前 host 或父 host 的 `/1.0/identifiers/self`；由 body.hostname 或 did:web id 得到 Zone host | **N7：尚不知道 DID 时，从访问端点发现环境身份**；不是宿主桥的调用。[发现](../../buckyos-websdk/src/sdk_core.ts#L771) |
| BNS WebUI | HTTP 直接读取 resolution envelope；展示状态、版本、迁移与历史能力缺口 | 属于解析诊断/展示，不是 AuthSubject 验证者；无独立 verify 或可信 cache 写入。[客户端](../../cyfs-gateway/src/apps/bns-webui/src/bns_model/services/did_resolver.ts#L61) |

### 2.3 相关设施及应排除的误报

| 项目 | 核对结果 |
| --- | --- |
| `resolve_owner_document / resolve_user_profile / owner_is_bound_to_zone` | name-client 的可用高层 API；Owner 与 User 分别解析后合并字段，不是对新合成 body 再验签。本工作区未发现库测试以外的直接产品调用，不能把 msg-center 误归为它的使用者。[实现](../src/name-client/src/profile_resolver.rs#L35) |
| `resolve_auth_key` | 可从 key DID 直接取键，或从默认文档取键；明确禁止用候选自述 owner 取键来替代文档 owner binding 验证。本轮未发现生产调用者。[入口](../src/name-client/src/lib.rs#L270) |
| `IdentityRoots` / 本地身份与 X.509 配套 | 使用者包括 buckyos-api `device_identity`、RTCP 本端材料加载、TLS cert resolver、cyfs-acme、SN AppContext/identity_bundle，以及 WebSDK provision/cert/device_identity。它们是材料布局、证书状态和本地公私钥绑定，不是远端 DID 信任证据。[本地加载边界](../src/name-client/src/identity_mgr.rs#L555)、[device_identity](../../buckyos/src/kernel/buckyos-api/src/device_identity.rs#L81)、[TLS](../../cyfs-gateway/src/components/cyfs-gateway-lib/src/stack/tls_cert_resolver.rs#L111)、[ACME](../../cyfs-gateway/src/components/cyfs-acme/src/cert_mgr.rs#L245)、[WebSDK](../../buckyos-websdk/src/device_identity.ts) |
| Agent DID Object / OpenDAN / agent_tool_cli_dev | 经 `DIDObjectClient` 用 HTTP 取 Card/Profile 并做结构校验，不调用可信 resolve/verify 管线；adapter 的提示也只宣称 structural validation。应单列“对象描述发现”，不能视为 `ObjectDocument` 验证已通过。[client](../src/name-client/src/did_obj_client.rs#L35)、[adapter](../../buckyos/src/frame/agent-did-object-lib/src/adapters/did_object.rs#L146) |
| msg-center / ContactMgr / tg_tunnel / Rust、TS msg_center_client 中的 `contact.resolve_did` | 输入 platform/account_id，查询或创建联系人 DID，涉及联系人 DB 与 alias；不返回 DID Document，不使用 name-client。**同名误报，排除。**[实际入口](../../buckyos/src/frame/msg_center/src/contact_mgr.rs#L97) |
| scheduler、repo_service 的 name-client 依赖；runtime 旧 ZoneProvider 注释 | 没有发现独立生产 DID 解析策略；依赖声明、测试 StaticProvider 和注释不算生产调用。runtime 的全局初始化已单列。 |
| SN 的 `did:dev` 读取 | 低层 SnResolver 支持按设备 key 查在线 Info/mini doc；NameClient 仍拒绝以 key DID 为可信解析入口。这是发现/索引协议边界，不能据此声称可信 resolve 已支持 did:dev。[分支](../../cyfs-gateway/src/components/cyfs-sn/src/sn_resolver.rs#L2455) |

## 3. 建议补入讨论稿的七类模式

### N1. 业务接纳的运行状态：Boot / LKGS

**证据。** node-daemon 用激活时固化的 `node_identity.owner_public_key` 验证网络候选；普通 Zone resolve 失败后直接查询 DNS Boot，不依赖尚未启动的 HTTPS 发布面。Warm Restart 即使找到新文档，也可能因角色或共识模型变化拒绝接纳，并继续使用 LKGS。它在任何 discovery 错误后也可以回到 LKGS。接纳之后，`update_zone_document_cache` 将解码后的 Zone 重新序列化为 JSON，写 Verified cache。

源码：[本地锚定](../../buckyos/src/kernel/node_daemon/src/zone_boot_resolve.rs#L111)、[DNS](../../buckyos/src/kernel/node_daemon/src/zone_boot_resolve.rs#L407)、[平滑升级](../../buckyos/src/kernel/node_daemon/src/zone_boot_resolve.rs#L304)、[LKGS 选择](../../buckyos/src/kernel/node_daemon/src/zone_boot_resolve.rs#L499)、[cache 投影](../../buckyos/src/kernel/node_daemon/src/zone_boot_resolve.rs#L577)。system-config 还规定本 Zone 的 Zone/Boot 文档只从已接纳的 `boot/config` 提供，普通 resolver/cache override 不能替代它：[优先级](../../buckyos/src/kernel/sys_config_service/src/zone_did_resolver.rs#L688)。

**为何不是现有三种模式。** “已经知道 V2，但当前运行状态仍使用 V1”不等于没看到新版本的 stale，也不是普通 Lock；选择由业务兼容规则自动决定。`StillValid` 也不足以描述：LKGS 加载做 schema、身份和本地根锚定，没有统一的当前 `exp`/公网负状态门禁。不能把“允许继续启动”标成“V1 当前仍合法”。

**建议补充。** 将 `ResolvedCurrent` 与 `AcceptedOperationalState` 分为两个结果和存储；规定 boot 恢复模式能否在明确 Missing、Expired、Revoked、Tombstoned 时继续，以及恢复态能做哪些操作。Owner 固定信任根的维护/恢复流程也应明确，不以公网 Owner 普通更新自动改变节点根信任。Boot 派生 JSON 应标明原始 JWT/hash、转换规则和接纳依据；不能当作“收到的确切字节”被原样保存。

### N2. 控制面投影与字段级信任：合成 Owner、业务状态映射

**证据。** system-config 对当前 Zone Owner 的主 key 不一致时，保留存储文档的资料字段，将 `verificationMethod / authentication / assertionMethod / capabilityInvocation` 换成本地根 key 对应字段，移除 keyScope 扩展，返回新 JSON；cache 命中也做同样处理并重算 hash。Owner 资料缺失或损坏时，可合成最小 Owner。它明确依赖控制面信道，而不持有 Owner 私钥。

源码：[合成逻辑](../../buckyos/src/kernel/sys_config_service/src/zone_did_resolver.rs#L510)、[实际选择](../../buckyos/src/kernel/sys_config_service/src/zone_did_resolver.rs#L563)、[cache 转换](../../buckyos/src/kernel/sys_config_service/src/zone_did_resolver.rs#L602)。

SN 还有另一种投影：从 BNS Owner/config 或 AuthDB 公钥合成 Owner；内部入口将成功结果补为 Active，并生成 `checkedAt / validUntil`。AuthDB 投影用 `updated_at` 做 `iat`、远期 `exp` 保持 body 稳定。同一服务的 PublicSupplement 不提供相同的明确状态。Suspended/Banned 映射为 Revoked，Deleted 映射为 Tombstoned。

源码：[合成](../../cyfs-gateway/src/components/cyfs-sn/src/sn_did_resolver.rs#L607)、[双角色](../../cyfs-gateway/src/components/cyfs-sn/src/sn_did_resolver.rs#L663)、[业务状态及版本](../../cyfs-gateway/src/components/cyfs-sn/src/sn_did_resolver.rs#L755)、[内部接线](../../cyfs-gateway/src/web3-gateway/web3_gateway.yaml#L97)。内部角色按 transport 目标地址选择，不能只按服务名或 payload 自报来源判断。

**未分类之处。** §4 的 Lock 固定一份精确文档，SeedTrusted 接纳一份材料；这里是**持续按多个来源生成一份新文档**，甚至对同一 Owner 固定部分字段、允许其他字段变化。`AdminTrusted` 可以表达结果的信任性质，但尚不能表达转换过程、字段来源、派生版本和失效。

**建议补充。** 增加“控制面生成/转换的文档”分类，记录输入版本/hash、转换版本、scope、管理接纳来源及所有依赖期限。否则可能沿用原 `iat` 却产生不同 hash，或者最小文档按当前时间重建而虚增版本。业务账户停用、Zone 内禁止准入与 method 永久注销也应区分，不能只靠相同的 Revoked/Tombstoned 枚举名称推导全球永久状态。

### N3. 一个解析结果依赖多个身份及登记键映射

**证据。** BNS 对未单独登记的 `did:bns:ood1.alice` 默认查询，可读取 `(alice, ood1)` 文档槽位，再读取 `(alice, zone)`、`(alice, owner)`；验证 Device/Zone JWT、Owner 时间策略、Zone membership 和设备 key 权限。返回前重读依赖及 checkpoint，检查投影没有变化。真正的身份键与存储键不同。

源码：[映射和重读](../../cyfs-gateway/src/components/bns-server/src/lib.rs#L1069)、[三份文档联合校验](../../cyfs-gateway/src/components/bns-server/src/lib.rs#L1171)、[返回 sourceName/sourceDocType](../../cyfs-gateway/src/components/bns-server/src/lib.rs#L1375)。此特殊映射当前挂在默认类型查询上，不能假定显式 `Device` 与默认查询自动等价。

SN 对托管 did:web 还可通过 user-domain 绑定映射到 BNS，部分 JSON 文档会改写 `id/owner/zone`；JWT 不进入该改写分支，已有匹配 id 的 JSON 也保留原内容：[路由](../../cyfs-gateway/src/components/cyfs-sn/src/sn_did_resolver.rs#L430)、[改写边界](../../cyfs-gateway/src/components/cyfs-sn/src/sn_did_resolver.rs#L1195)。

**未分类之处。** §5 主要描述 `child → expected_owner`，实际还存在 `Device → Zone membership → Owner → 名字登记/域名绑定`。Device 本身未变，Zone 移除该设备就足以使解析不再成立；只保存 Owner hash 的反向索引不够。

**建议补充。** 报告同时记录请求身份、实际 doc_type、source document key、绑定证据和完整依赖集合；定义依赖撤销/迁移怎样投影到主体。保留 BNS 已有的读取一致性检查，并明确客户端缓存/会话多久必须重新确认这些关系。身份映射不等于可以把 V2 或另一 DID 的验签结果记给收到的 V1。

### N4. 先按 scope 准入，再确认公网；结果约束存量连接

**证据。** RTCP 先做设备持钥证明，随后才做 LocalAndZone 文档验证；完成 key confirmation 和 listener 授权后提交精确 JWT。注册时用专门锁串行化 cache CAS 与连接索引变更，处理并发较新/冲突文档。已按 Host/Zone snapshot 准入的连接，可以后台执行 RemoteAuthority 验证：确认 Current 后提升信任，明确否定则记录 negative 并处理关联连接，不能确认则保留 snapshot 信任。曾被公网否定的逻辑身份，恢复分支要求同步 RemoteAuthority、Anchored 和精确 revision 匹配；这些检查能否构成公网证明，另见 D2。

源码：[持钥证明顺序](../../cyfs-gateway/src/components/cyfs-gateway-lib/src/rtcp/rtcp.rs#L2830)、[提交时点](../../cyfs-gateway/src/components/cyfs-gateway-lib/src/rtcp/rtcp.rs#L3129)、[后台确认](../../cyfs-gateway/src/components/cyfs-gateway-lib/src/rtcp/rtcp.rs#L3281)、[恢复](../../cyfs-gateway/src/components/cyfs-gateway-lib/src/rtcp/rtcp.rs#L1994)、[CAS 与索引](../../cyfs-gateway/src/components/cyfs-gateway-lib/src/rtcp/rtcp.rs#L6948)。

**已覆盖部分。** 对确切输入验证，应用准入后再保存，并检查 CacheWriteOutcome，符合 §3 的方向。

**未分类之处。** 文档返回一次之后仍有连接、canonical key/逻辑 DID 索引和 authority ticket；它们必须应对后来的否定及并发变化。一次 `verify_received` 和一次 `commit_accepted` 无法表达整个生命周期。

**建议补充。** 把“文档有效性”“此刻准入资格”“连接当前信任等级”分别建模；明确异步结果只能更新对应的 revision/generation。讨论哪些变化只阻止新连接、哪些必须拆除已有连接，以及确认期限、重试与断网规则。未发布设备的 scope 准入应是独立显式策略，不能以“稍后公网确认”代替初次接纳证据；当前宽门禁见 D3。

### N5. 独立公钥 Provider，以及脱离文档的派生缓存

**证据。** kRPC S2S 支持 `S2sPublicKeyProvider`，其 Managed 结果直接成为远端公钥；NotManaged 才能在已配置时进入 NameClient fallback，Provider 错误不回退。SN 生产接线实际使用 provider_only，配置快照 generation 固定为 1，变更依靠服务重启。

源码：[Provider 分支](../src/kRPC/src/s2s/identity.rs#L370)、[SN 固定快照](../../sn-business/src/modules/sn-base/src/app_context.rs#L222)、[SN provider_only](../../sn-business/src/modules/sn-base/src/app_context.rs#L1123)。

NameClient fallback 提取默认 Ed25519 key 后只缓存 key/fingerprint/provenance；fresh 判定比较 Provider generation。没有 Provider 时 `None == None` 也成立；正常命中没有按 DID 文档 `exp`/Owner hash 重新检查，失败后才可能 RemoteAuthority reload，并有 cooldown。调用方也有显式 reload 能力。

源码：[取键 API](../src/name-client/src/name_client.rs#L1812)、[缓存 fresh 条件](../src/kRPC/src/s2s/identity.rs#L251)、[失败刷新](../src/kRPC/src/s2s/identity.rs#L306)。

**未分类之处。** Provider 管理的是 `DID → key` 配置，不是 `DID → Document` 的 Lock/Seed；派生公钥、会话加密上下文也不在 DocCache 中。仅修好 §5 的文档缓存 Owner 闭环，不会自动使上层公钥缓存失效。旧 key 仍成功验签时，“验签失败后刷新”尤其不能承担撤销传播保证。

**建议补充。** 保留独立的集群公钥信任契约；如果宣称承接 Current 文档语义，就让派生结果携带身份版本、Owner/关系依赖、硬期限或变更通知，并规定在公钥字节没变但身份被禁用时如何失效。不要要求 provider_only 伪造一个公网 DID receipt。

### N6. 解析签发者，验证另一种对象：NDN 路径断言

**证据。** `NameClientPathVerifier` 从请求 host 派生 Zone DID，resolve Zone 文档，取 JWT header 的 kid，并检查 `ZONE_PUBLISH` 权限，再验证收到的 `cyfs-path-obj` JWT 的签名、exp、host、path 和未来 iat。该断言给出路径到 ObjId 的绑定，不是查询键下的 DID Document。

源码：[完整链路](../../cyfs-ndn/src/ndn-toolkit/src/cyfs_ndn_client.rs#L81)。

**未分类之处。** §3 的 `verify_received(did, doc_type, document)` 面向 DID Document；这里 resolve 的文档只是验另一种声明的材料。不能把“Zone 是当前文档”推导成“该 path 映射是最新”，也不能让多个合法 path token 按同一 `(ZoneDID, doc_type)` 互相覆盖。

**建议补充。** 为“用解析结果验证派生签名对象”说明独立的对象身份、权限范围、重放/版本策略和期限；明确是否只要求 token 当前有效，还是要求路径映射最新。底层 Zone/Owner 失效必须如何影响尚未过期的断言，需要单独约定。当前实现依赖普通 resolve 的信任保证，没有补做讨论稿建议的统一 Current 门禁。

### N7. 从访问端点发现环境身份：`/identifiers/self`

**证据。** WebSDK 初始化时，可以先访问当前页面 host 的 `/1.0/identifiers/self`，失败后再访问父 host，读取裸 JSON 的 `hostname`，或从 `id=did:web:...` 派生 Zone host。system-config 的 `name == "self"` 分支直接返回本 Zone 的裸 ZoneDocument JSON。

源码：[SDK 发现与解析](../../buckyos-websdk/src/sdk_core.ts#L771)、[服务端 self](../../buckyos/src/kernel/sys_config_service/src/zone_did_resolver.rs#L679)。

**未分类之处。** 输入是访问地址而非已知的 `(expected_did, doc_type)`，目的在于确定运行环境和后续服务地址。它既不经过宿主 NameClient，也不对返回文档执行统一 verify/freshness。与任意来源收到一份已知身份的文档相比，这里还缺少“期望是谁”的起点。

**建议补充。** 将端点自描述/服务发现与身份认证分开，规定信任当前 origin、父域及返回 hostname 的条件，以及识别出 DID 后哪些操作必须继续做身份验证。保留 discovery 专用返回契约，不把 `self` 当全局 DID/cache key，也不把服务地址推导成功当 Current 身份通过。

## 4. 已有分类下的具体差异

| 编号 | 实际证据 | 对照判断 / 需要处理的边界 |
| --- | --- | --- |
| D1：BNS `documentVersion` 语义不一致 | BNS HTTP 把 `result.document_state.version` 填入 `documentVersion` 和 `versionId`；HTTP provider 原样读取，verify receipt 把它当 document iat。[写出](../../cyfs-gateway/src/components/bns-server/src/lib.rs#L1385)、[读取](../src/name-client/src/https_provider.rs#L415)、[消费](../src/name-client/src/verify_context.rs#L1178) | 与 §1 明确的 `documentVersion = document_iat` 不同。hash/body 精确匹配仍有作用，不能因此断言全部校验失效；但时间比较、诊断以及只剩版本锚点时会混淆两个轴。应分开登记版本与文档 iat。 |
| D2：“公网当前”的调用检查不足 | activation、RTCP outbound 和 RTCP negative recovery 使用 RemoteAuthority + Anchored，部分还比较精确 JWT/revision；本机 override 本身就返回 Anchored。安装 StrictPublic 只关闭几项 fallback，仍用默认 BestAvailable，trust-ready 也接受 Active/Anchored。[override](../src/name-client/src/name_client.rs#L1364)、[激活](../../buckyos/src/kernel/node_daemon/src/active_server.rs#L702)、[RTCP](../../cyfs-gateway/src/components/cyfs-gateway-lib/src/rtcp/rtcp.rs#L1213)、[恢复](../../cyfs-gateway/src/components/cyfs-gateway-lib/src/rtcp/rtcp.rs#L2032)、[安装 policy](../../buckyos/src/frame/control_panel/src/app_install_resolver.rs#L290)、[准入](../../buckyos/src/kernel/buckyos-api/src/app_install.rs#L354) | 讨论稿 §2 已提醒 RemoteAuthority 会命中 override；**加上 Anchored 检查仍不能解决**。若这些业务名义要求本次公网确认，需独立 receipt 和精确文档绑定；StrictPublic 也应明确到底是“可信公开内容”还是 RequireAuthorityCurrent。 |
| D3：RTCP 的 Current 近似门禁较宽 | `freshness_rejection` 拒绝本地 Older/Conflict 与公网 DifferentDocument/Superseded，其他分支放过；不统一拒绝 local Unknown，也没有检查确切候选已被接纳。后台明确保留 Missing 的 snapshot trust。[门禁](../../cyfs-gateway/src/components/cyfs-gateway-lib/src/rtcp/rtcp.rs#L1928)、[Missing 语义](../../cyfs-gateway/src/components/cyfs-gateway-lib/src/rtcp/rtcp.rs#L1967)、[保留](../../cyfs-gateway/src/components/cyfs-gateway-lib/src/rtcp/rtcp.rs#L3399) | 不等同于 §3 `accept_current`。前置纯 verify 仍会阻止签名错误和 terminal negative，不能说“无验证”；差别在缺少确切接纳证据、基线未知和 bootstrap 准入的统一策略。 |
| D4：Boot fallback 混同错误类型 | discovery 将 NSError 包装成 String 后继续 DNS；Warm Restart 对 discovery Err 使用 LKGS；加载 LKGS 只做本地锚定。[错误包装](../../buckyos/src/kernel/node_daemon/src/zone_boot_resolve.rs#L395)、[fallback](../../buckyos/src/kernel/node_daemon/src/zone_boot_resolve.rs#L559)、[加载](../../buckyos/src/kernel/node_daemon/src/zone_boot_resolve.rs#L259) | 与普通 Current 的“明确 Missing/负状态不能被旧 positive 覆盖”不同。合理的业务恢复需求见 N1，但必须显式定义，不能作为普通 resolve 成功。 |
| D5：Owner 和派生期限闭环尚未覆盖这些消费者 | 本机可信 cache 的 Owner replay guard 按被查 DID 找 Owner；Zone 快路径直接返回；kRPC 上层 key 缓存另有 fresh 判定。[guard](../src/name-client/src/doc_cache.rs#L721)、[Zone 返回](../src/name-client/src/name_client.rs#L1339)、[S2S](../src/kRPC/src/s2s/identity.rs#L251) | §5 已承认底层差距。本轮补充影响面：Boot JSON、合成 Owner、RTCP 连接、S2S key、NDN 断言；不能只为 DocCache 加 expected_owner 反向索引就宣称系统闭环。 |
| D6：网关动态 provider 管理仍走旧注册方式 | `add_name_provider` 构造 BaseHttpProvider 后调 `add_provider(..., trust_level)`；BaseHttpProvider 未声明 methods；缺省 methods 为空，因此只加入普通 DNS providers，而它的普通 query 返回 NotFound；trust_level 参数被忽略。[调用](../../cyfs-gateway/src/components/cyfs-gateway-app-lib/src/gateway.rs#L3386)、[默认 methods](../src/name-client/src/provider.rs#L1289)、[注册规则](../src/name-client/src/name_query.rs#L147)、[普通 query](../src/name-client/src/https_provider.rs#L894) | 管理命令报告添加成功不意味着 DID authority/supplement 已接线。这是迁移遗漏，属于来源注册问题；应使用显式 method/role 注册，不能继续按 trust_level 推断信任。 |
| D7：默认 doc_type 实际还有“取任意身份文档”语义 | Zone 对域内名字在 Zone 类型分支做 Device → Agent → Owner 探测；RTCP、取默认公钥、Device 固定 IP 和 activation 都有 `None` 调用；BNS 默认分支也触发设备槽位映射。[Zone 分支](../../buckyos/src/kernel/sys_config_service/src/zone_did_resolver.rs#L801)、[任意文档](../../buckyos/src/kernel/sys_config_service/src/zone_did_resolver.rs#L872)、[取键](../src/name-client/src/name_client.rs#L1818) | 讨论稿固定 `(did, doc_type)`，还需明确默认类型/身份文档发现与精确类型查询的关系。不能机械把所有 None 改 Device；也不能让不同 provider 各自决定后仍共用同一 cache key。 |

另外，§4 建议本机 Lock 优先于 Zone，现状恰好相反。node-daemon 的 Owner override 注释称所有递归都命中本地根，但全局 NameClient 在 Zone 明确回答时先返回；该注释并不构成实际保证。预安装 `scope="rootfs-preinstall"` 也只是标签，不是独立作用域，且本轮未发现产品代码调用 `clear_local_authority_override`。

## 5. 需要明确的延伸边界，不宜全部新增为验证模式

**E1：应用安装。** 包内候选、解析得到的 AppDoc、最终安装的内容对象是三种位置。当前流程通过 ObjectId 和发布绑定防止包覆盖解析结论，这是 §3 “确切文档”原则的客体应用。LocalDeveloper 使用特定 candidate ObjectId 的显式准入，rootfs 预装则写进程级永久 override，二者作用范围不同。未发现生产安装路径使用 `AnyValid / StillValid / AtPublication` 的历史验证入口；当前实现不能被描述为已经支持“旧软件发布时合法”的验证。

**E2：宿主代解析。** WebSDK 的浏览器实现完全依赖 `BuckyApi.resolve_did`，宿主返回 body；桥缺失或错误结果可返回 null，Node 环境的该方法直接报浏览器专用。它不是独立 resolver，也没有把 scope、来源、negative 类型、freshness receipt 暴露给页面。简单展示可以沿用普通 resolve；需要身份准入的网页应有完整结果/验证接口和明确的宿主信任边界，不能把收到一个 JWT 当公网确认。

**E3：地址发现。** name-client 的地址管线有意在 Device Document 查询失败后继续 nameinfo / 合资格的 DeviceInfo；这包括无法取得可信身份材料的情况。它得到的是连接候选地址，不是有效身份。在 RTCP，身份验证另行完成；该发现行为不应被普通 DID negative 的 fallback 禁令直接误杀，也不应被反向当作绕过认证的依据。

**E4：展示合并与结构化对象发现。** `MergedProfile` 有字段来源，DIDObject adapter 只报告结构校验。这些输出本来就不该作为 AuthSubject 或普通 Verified cache 输入。它们与 N2 的关键区别是：N2 的合成 Owner 实际进入了后续认证的信任材料，不能仅以“也是 JSON 合并”同等处理。

## 6. 建议加入冻结会议的验收场景

以下是本轮提出的验收输入，尚未执行动态测试。

| 场景 | 要明确的验收目标 |
| --- | --- |
| Zone V2 已发布且签名有效，但会改变本节点角色；LKGS 为 V1 | 分别报告解析当前版本与业务接纳版本；不能把保留 V1 标成普通 Current |
| Boot 普通解析返回 Revoked，DNS 仍有旧 JWT，LKGS 仍有旧状态 | 明确恢复态是否允许继续、能力范围和状态标记；不把 terminal negative 降为断网 |
| 存储 Owner D2 更新了 key，本地仍固定 D1 key | 合成结果具有自己的 hash/来源；不伪装为 D2 的原始签名文档；冻结依据有明确更新入口 |
| 合成 Owner 的输入 revision 不变，连续读取或服务重启 | hash/revision 稳定；临时依据不能通过重建 exp/iat 延寿 |
| 同一 SN 从公网入口和 loopback 3180 读取同一 Owner | PublicSupplement 不获得内部控制面 Active 权威身份；源角色由受信入口决定 |
| Device body 与 Owner 均不变，但 Zone membership 删除设备 | 下次解析及已派生缓存/连接按约定失效；依赖检查不只关注 Owner |
| RTCP 先按 Host/Zone 准入，后台收到 DifferentDocument；同时又有新握手 | 否定只作用于匹配 ticket/revision；旧连接/旧 cache 不在并发中重新成为当前 |
| RTCP 只有可信 Owner，没有该 child 的确切接纳记录；公网 Missing 或未查询 | 返回缺证据，或进入明确启用的未发布设备准入策略；不隐式等同 Current |
| S2S 公钥没变，但对应 DID 被撤销或文档过期，旧 key 仍能验签 | 依赖通知/硬期限能触发失效，不依赖“等验签失败” |
| RemoteAuthority 返回的 body 来自本机 override，且与待确认 JWT 相同 | 激活、公网严格 RTCP 等不得报告本次公网 AuthorityCurrent |
| BNS 登记 version 为 3，body.iat 为当前 Unix 时间 | 明确字段轴，不能让 3 被当成 document_iat；同时验证 body/hash 绑定仍正确 |
| 安装 StrictPublic，Zone 命中本地覆盖 AppDoc；另一个任务并发进行预装 | 公开安装要求和覆盖权限不被标签/任务间共享状态混淆 |
| 管理命令添加 HTTP DID provider 后查询对应 method | 检查它确实参与指定 authority/supplement 路径，不能只验证命令返回成功 |
| NDN 两个 path token 都由当前 Zone key 签署，路径相同而目标不同 | 由路径断言协议决定有效性/最新性，不按 Zone DID 文档 revision 直接裁决 |
| 显式 Device 查询与 None 查询同一设备 | 说明默认映射及返回类型，缓存键、Owner 材料和版本锚点一致 |
| 页面 origin、父域及 `/self` 返回的 hostname 指向不同站点 | 只按明示的环境发现规则选择服务端点；不得把 hostname 自述成功当作 DID 认证 |

优先处理 D1/D2/D3/D6 这些可直接定位的协议/调用失配；同时为 N1–N7 补充独立业务契约。否则统一 `accept_current` 虽能收紧单次调用，仍会遗漏启动恢复、控制面生成材料、关系依赖、端点发现和已经派生出去的信任状态。

## 7. 本轮验证与限制

- 完成跨仓库检索、生产/测试/同名接口区分，以及以上入口到下游依赖、cache、状态和配置的静态追踪。
- 核对本文 121 处源码/文档链接的目标路径和行号范围，均有效；新增文档未发现空白格式错误。
- 仅新增本核对文档，保留原讨论稿，不改代码、配置、依赖和现有测试。
- 没有运行构建、集成环境、网络请求或修改真实 DID/cache；验收表是后续建议，不是已通过测试的证明。
- “未发现生产调用”限定于本工作区可见源码；独立应用、外部 SDK 用户、链合约和已部署版本仍需各自核对。
