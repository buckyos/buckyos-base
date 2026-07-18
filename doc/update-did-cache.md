# update_did_cache 升级需求

> **2026-07 API 边界重构补记**(doc/verify-did-api-boundary-and-freshness-TODO.md,已实现):
>
> - 公开入口更名为 **`add_observed_cache`**(add_cache 动词的 Observed 入口),语义不变:
>   快速操作、本地校验、恒为 `Unverified`、落 `unverified/`;新增受控入口
>   **`add_verified_cache`**(显式写 `verified/`,安全边界仍是目录 OS 权限)。
> - cache 写入返回结构化 **`CacheWriteOutcome`**(Inserted / ReplacedOlder / AlreadyPresent /
>   IgnoredOlder / RejectedConflict / BlockedByNegativeState / PermissionDenied / SkippedByPolicy),
>   不再只有 `Ok(())`。
> - merge 规则迁移为 **iat-only**(方向翻转):同证据级只比 revision(`iat` + content hash),
>   同 iat 同 hash → `AlreadyPresent`,同 iat 不同 hash → `RejectedConflict`;`version_seq`
>   整体退出流程(用户自定义扩展,不参与比较);命名对象(`is_named_obj_id`)同级不可替换的
>   保护保留;Info doc_type 的 `update_time` 合并规则独立保留(排除在 DocumentRevision 契约外)。
> - 快速校验中"JWT 必须带 version_seq"改为"**必须能得出 iat**"(iat 直接存在,或由
>   `exp - DEFAULT_EXPIRE_TIME` 推导);owner replay guard 只剩 `valid_iat`
>   (`mini_version_seq` 退役,读到只警告)。
> - `verify_and_promote` 重构为"按 `RemoteAuthority` 构建 snapshot → 纯 verify
>   (`verify_did_document`)→ promote 落盘",对外行为等价。
>
> 下文保留原始设计论证;涉及上述条目处以本补记为准。

## 背景

`update_did_cache` 目前是 `name-client` 暴露给上层的旁路缓存写入口:任何拿到一份
文档(push、社交网络、UDP 发现、gossip……)的调用方,都可以喊它一声,把文档塞进本机
`did_cache`。这个入口存在的理由本身没问题——[简单介绍resolve-did.md](./简单介绍resolve-did.md)
第 5 节说得很清楚:"英雄不问出处"必须有地方发生,而这个地方只能是 Cache 层,不能是
查询路径(第 2.2 节:provider 是内核模型,不允许 App 注册自己的信道)。

问题出在**现有实现把"入口宽松"和"出口宽松"焊在了一起**。当前代码:

```266:276:src/name-client/src/name_client.rs
    pub fn update_did_cache(
        &self,
        did: DID,
        doc_type: Option<DidDocType>,
        doc: EncodedDocument,
    ) -> NSResult<()> {
        let exp = Self::cache_ttl_exp(&doc);
        self.doc_cache
            .update(did, doc_type, doc, exp, CacheEvidence::Unverified);
        Ok(())
    }
```

写入时诚实地打了 `CacheEvidence::Unverified` 标签,这一步没错。但 `resolve_did_ex`
的 in-TTL 缓存命中快路径根本不看这个标签:

```814:844:src/name-client/src/name_client.rs
        // 2. in-TTL positive 快路径。owner replay guard 对缓存命中同样生效。
        if let Some(CacheLookup::Positive {
            doc,
            exp,
            evidence,
            in_ttl: true,
        }) = &cached
        {
            match self.validate_doc_replay_guard(did, doc_type.clone(), doc) {
                Ok(()) => {
                    return Ok(ResolvedDocument::from_cache(
                        doc.clone(),
                        did,
                        &doc_type_c,
                        *exp,
                        evidence.to_body_evidence(),
                        CacheStatus::Hit,
                    ));
                }
                Err(err) => {
                    info!(
                        "cached did:{}#{} rejected by owner replay guard: {}",
                        did.to_string(),
                        doc_type_c,
                        err
                    );
                    self.doc_cache.delete(did.clone(), doc_type.clone());
                    cached = None;
                }
            }
        }
```

`evidence` 只是原样透传进返回值的 metadata,不影响"要不要直接返回"这个判断。也就是
说:**任何调用方喊一声 `update_did_cache`,在 TTL 窗口内就能让 `resolve_did`/
`resolve_did_ex` 把这份未经验证的文档当成正常解析结果返回**,和 `Published`/
`Verified` 条目享受完全相同的出口待遇。这与[简单介绍resolve-did.md](./简单介绍resolve-did.md)
第 4 节的不变量("没有发布权的文档,最多以明确打标的降级候选存在,永远压不过已发布
结果")在**读路径**上是矛盾的——合并写入时(`merge_allows`)确实尊重证据等级
(第 5 节),但一旦某个 doc_type 之前从未被 `Published`/`Verified` 结果占位,一次
`update_did_cache` 就足以让该 doc_type 在 TTL 内被当作可信解析结果对外返回。

其次,`update_did_cache` 目前只是一个进程内函数调用(`name-client` crate 内的
Rust API,经 `lib.rs` 转发给全局 `NameClient` 单例)。任何想触发"我观察到一份
文档"这件事的组件,都必须链接 `name-client`、拿到 `GLOBAL_NAME_CLIENT`、用 Rust
调用它。UDP 设备发现、gossip 守护进程、调试工具、非 Rust 组件,都没有更轻量的接入
方式,也没有任何权限分层——因为它们本来就只是在调同一个函数。

因此,本文档把 `update_did_cache` 的定位重新表述为:

> `update_did_cache` 应定义为"观察到 DID Document"的松写入入口,而不是信任入口。
> 任何来自 UDP 发现、gossip、push、文件投递的文档都只能先进入 `Unverified cache`。

并要求配套修正 `resolve_did`/`resolve_did_ex` 的读路径、`doc_cache` 的存储形态,
使"任何人都能让系统观察到一份文档"和"系统信任并返回这份文档"之间,始终隔着一次
真实的验证。

## 依据和现状

本文按以下现有文档和实现校准术语,任何冲突以下列文档/代码为准:

1. 解析语义主规范:[简单介绍resolve-did.md](./简单介绍resolve-did.md)(结果二分法、
   provider 内核模型、need_proof、expected_owner、Cache 层合并规则)。
2. resolver 生态:[已有did-resolver介绍.md](./已有did-resolver介绍.md)
   (`zone_resolver` 是伪装成 resolver 的 zone 内权威 L1 cache,本机 `did_cache`
   是 L2)。
3. HTTP 协议:[http_did_resolver_api.md](./http_did_resolver_api.md)
   (`PublishedState`、`documentStatus`、`effectiveOwner` 等权威源信封字段)。
4. 统一验证入口:[verify-did-document-jwt.md](./verify-did-document-jwt.md)
   (`expected_owner`、`declared_owner`、`CacheEvidence`、`BodyEvidence`、
   `usable_as_authz_subject` 等概念,以及"验证通过后由 name-client 受控写入
   cache,不让应用层自己提升信任等级"的既有原则)。
5. 现有实现:
   - `src/name-client/src/doc_cache.rs`——`CacheEvidence`/`CacheLookup`/
     `DIDDocumentCache` 的三后端(Filesystem/Sqlite/Memory)存储与合并逻辑。
   - `src/name-client/src/name_client.rs`——`update_did_cache`、
     `resolve_did_ex` 的 cache 命中与写回。
   - `src/name-client/src/lib.rs`——模块级 `update_did_cache` 转发函数。
   - `src/name-client/src/verify_did_jwt.rs`——`verify_did_document_jwt` 的
     完整验证流程与受控 cache 写入,是本文件"lazy verify"要复用的核心逻辑来源。
   - `src/name-client/src/provider.rs`——`BodyEvidence`/`CacheEvidence` 的
     概念源头、`ResolvePolicy`。

现有实现已经具备的能力,本文不重新发明:

```text
CacheEvidence: Published > Verified > Unverified(doc_cache.rs)
merge 规则: 先比证据等级,同级只比 revision(iat + content hash);负状态与本地覆盖屏蔽一切写入
owner replay guard: valid_iat(mini_version_seq 已退役,读到只警告),读写两侧统一应用
verify 家族(verify_did_document + build_verify_context): expected_owner 判定 + owner 验签 + revoke/replay guard 的完整实现
```

现有实现的两个明确缺口,是本文要解决的问题:

1. **读路径不过滤证据等级**——上一节已展开,`resolve_did_ex` 的 in-TTL 命中把
   `Unverified` 和 `Published`/`Verified` 一视同仁地直接返回。
2. **写入口只是函数调用,没有文件系统协议与权限分层**——`update_did_cache` 没有
   对应的"任何人往目录里放文件就等效于调用了它"的旁路,也没有区分"谁能让系统
   观察到"和"谁能让系统信任"的目录级权限边界。

此外,`doc_cache.rs` 当前维护了三种存储后端(`Filesystem`/`Sqlite`/`Memory`),
其中 `Sqlite` 后端(`DbStore`)只是把同一套 KV 语义搬进了一张单表,没有任何调用方
利用它做结构化查询(`grep` 确认除 `doc_cache.rs` 自身外,没有代码路径依赖
`CacheBackend::Sqlite`/`DbStore`)。真正需要结构化查询、多维检索能力的场景,应该
交给 [已有did-resolver介绍.md](./已有did-resolver介绍.md) 第 5 节描述的
`zone_resolver`(cluster-level cache / control plane,可以有自己独立的存储实现),
不需要本机单机 `did_cache` 内置一个不完整的 SQL 后端。

## 目标

1. **删除 `doc_cache.rs` 的 SQL 后端**(`CacheBackend::Sqlite` / `DbStore`)。
   本机 `did_cache` 只保留 `Filesystem`(生产默认)与 `Memory`(测试默认)两种
   后端;真正需要 SQL 查询能力的场景走 zone-did-resolve。
2. **把"能让系统观察到"降格成基于文件系统的旁路协议**:任何人只要往指定目录里
   放了约定格式的文件,效果上就等价于调用了一次 `update_did_cache`;进程内的
   `update_did_cache` 函数调用只是这个协议的一层薄封装(省一次文件 IO,语义完全
   相同,不享受任何额外信任)。
3. **通过分目录实现权限控制和生产-消费模型**:
   ```text
   (unverified)did-cache/   普通服务可写,只表示系统收到过
   verified-cache/          只有 name-client / resolver / 受控系统服务可写,
                            验证后会将 did-cache 中的文件移动过来
   ```
   `Published`(权威源结果)和 `Verified`(通过 lazy verify 的自签名候选)都只能
   出现在 `verified-cache/` 里,区别只在 meta 里的 `evidence` 字段,不需要为
   `Published` 单开第三个目录——能写 `verified-cache/` 的都是本文定义下的受控
   写者,这条边界已经把"未经验证"挡在外面了。
4. **调用接口可以做一次快速校验,校验不过不触发文件系统写入**。这不是完整验证,
   只是格式健全性检查(能否解析成 `EncodedDocument`、`id` 是否与调用方声明的
   `did` 一致等),目的是不让明显损坏的数据进 `unverified` 目录。
5. **`resolve_did_ex` 只通过文件系统的当前状态判断如何使用 cache,不假设所有
   cache 文件都是通过正确版本的 `update_did_cache` 写入的**。换句话说:不管
   `unverified` 目录里的文件是被谁、用什么工具、以什么格式扔进来的,resolve 端
   都必须重新做归一化解析和信任判定,不能因为文件存在就当作合法输入,更不能因为
   文件"看起来正常"就跳过验证。
6. **`resolve_did` 默认保持 strict**:只返回 `Published` 或已通过统一 resolver
   验证的 `Verified` 文档。命中 `Unverified` cache 时,在首次使用时 lazy verify;
   验证通过后 promote 到 `Verified cache`(文件系统层面是把文件从 `unverified`
   目录移动到 `verified` 目录),后续才能享受普通 cache hit;验证失败则不能返回;
   验证所需的条件暂不可用(例如 owner document 拿不到、网络不可达)时,保持
   `Unverified`,并按 strict 语义等同 cache miss 处理,不直接返回给调用方。
7. **`resolve_did_ex` 可以支持宽松场景**,但必须在返回的 metadata 里明确暴露
   结果性质:
   ```text
   evidence             = Published | Verified | Unverified | LocalOverride
   cache_status         = Hit | Fallback | ObservedFallback | ZoneHit
   verification_status  = Passed | Failed | Unavailable | NotAttempted
   source               = UdpDiscovery | Gossip | Push | LocalFile | Authority | ZoneResolver
   ```
8. **不开放让普通调用者声明 `Verified`/`Published` 的接口**。`update_did_cache`
   /文件系统协议里的 `incoming/source` 字段可以描述链路来源(便于日志、诊断、
   `smart_resolver` 一类未来能力的动态拓扑记录——见
   [已有did-resolver介绍.md](./已有did-resolver介绍.md) 第 6 节),但信任等级
   必须由 name-client/resolver 统一判定,不接受写入方自报的 evidence。BuckyOS
   设备发现这类系统服务可以作为 privileged producer,拥有写 `unverified`
   目录的权限,但同样要调用统一的 `verify_and_promote`,不要各服务各自实现一遍
   完整验证逻辑。

核心原则:

> **系统收到过 != 系统信任它**。Cache 可以英雄不问出处,但 resolver 的默认返回
> 不能不问出处。

## 非目标

1. 不重新发明验证逻辑。lazy verify 复用
   [verify-did-document-jwt.md](./verify-did-document-jwt.md) 已经定义、
   `src/name-client/src/verify_did_jwt.rs` 已经实现的 `expected_owner` 判定 +
   owner 验签 + revoke/replay guard 流程,本文只定义"什么时候触发它、触发在谁
   身上、结果如何落盘"。
2. 不改变 [简单介绍resolve-did.md](./简单介绍resolve-did.md) 第 3 节主循环的
   四个策略点、`doc_cache.rs` 现有的 `merge_allows` 证据等级比较算法。目录迁移
   只是这些规则在物理存储上的落地方式,不是新的合并语义。
3. 不实现 UDP 发现、gossip、`smart_resolver`(第 6 节,暂不实现)具体协议本身。
   本文只定义它们如何**共同经过**这一个入口进入 cache,以及进入后如何被对待。
4. 不改变 `zone_resolver`(cluster-level L1 cache)的定位和协议——它仍然是
   [已有did-resolver介绍.md](./已有did-resolver介绍.md) 第 5 节描述的"伪装成
   resolver 的 zone 内权威 cache",不参与本文讨论的本机 L2 `did_cache` 文件系统
   协议;`zone_resolver` 服务自己的存储实现由它自己决定,不受"删除 SQL 后端"
   约束(那是关于本机 `did_cache`/`DIDDocumentCache` 的决定)。
5. 不在本文里给出跨平台文件权限(ACL/POSIX 权限位/Windows ACL)的完整实现方案,
   只给出目录级权限模型的设计约定;具体用 uid/gid、ACL 还是应用层校验实现,留给
   实施阶段按部署环境决定(见"未决问题")。
6. 不要求单机模式下必须部署两个物理目录——测试/单机开发环境可以退化为同一个
   `Memory` 后端进程内模拟两个命名空间,只要行为满足"目录即证据"的语义。

## 核心概念

### CacheEvidence 回顾

沿用 `doc_cache.rs` 已有定义,不新增档位:

| CacheEvidence | 含义 | 谁能产生 |
| --- | --- | --- |
| `Published` | 已发布/已锚定,来自权威信道 | `resolve_did_ex` 主循环自己写入(不经过 `update_did_cache`) |
| `Verified` | 通过 `expected_owner` 一致性 + owner 验签的自签名候选 | `verify_and_promote` / `verify_did_document_jwt` |
| `Unverified` | 未经验证的旁路写入 | `update_did_cache`(函数调用或文件系统协议) |

### Observed(观察到) vs Trusted(信任)

这是本文的核心区分,贯穿目录设计和 resolve 行为:

- **Observed**:系统的某个组件在某个信道上看到过这份声称是 `(did, doc_type)`
  的文档。任何人都可以制造"Observed"事件——UDP 广播、gossip 转发、一次 push、
  手工丢一个文件,都算。
- **Trusted**:这份文档经过 [简单介绍resolve-did.md](./简单介绍resolve-did.md)
  2.3/2.4 节定义的 `expected_owner` 一致性 + owner 验签 + revoke/replay guard
  检查,或者本身就来自权威信道。

`update_did_cache`(不论是函数调用还是文件系统协议)只产生 Observed 事件,
产物固定是 `Unverified`。Observed 到 Trusted 的唯一合法路径是
`verify_and_promote`(见下文),没有第二条路。

### 目录即证据

现有 `doc_cache.rs` 的 `StoredMeta.evidence` 字段由写入方在调用时指定
(`update`/`insert` 的 `evidence: CacheEvidence` 参数),这意味着**任何能调用
这两个函数的代码路径,理论上都可以直接声明 `Published`**——目前之所以安全,
只是因为调用点受控(只有 `resolve_did_ex` 主循环和 `verify_did_jwt.rs` 会传
`Published`/`Verified`)。本文要求把这条"信任声明"从函数参数收紧成目录位置:

```text
{did_cache_root}/unverified/{key}.doc.json   # 任何拥有该目录写权限的本机进程
{did_cache_root}/unverified/{key}.meta.json
{did_cache_root}/verified/{key}.doc.json     # 只有 name-client 自身可写
{did_cache_root}/verified/{key}.meta.json
```

- 落在 `unverified/` 目录下的条目,不论 meta 文件里写了什么 `evidence` 字段,
  统一按 `Unverified` 对待——**目录本身就是证据上限,内容自称的证据等级不被
  信任**。
- `verified/` 目录只由 name-client 进程(或与它同 uid、受控的系统组件,例如
  [已有did-resolver介绍.md](./已有did-resolver介绍.md) 第 5 节的
  `zone_resolver` 管理面)写入,`Published` 与 `Verified` 都落在这里,靠 meta
  里的 `evidence` 字段互相区分——这里之所以可以信任 meta 自报的字段,是因为
  目录写权限已经先做了一次身份过滤。
- 验证转正(promote)是一次**文件移动**(`rename`/`mv`),不是"读出内容、重新
  写一份、再删掉旧文件"——移动是本地文件系统上的原子操作,避免中间态被并发
  读者看到半写文件;具体到实现,仍然建议"写临时文件 + `rename` 进目标目录"
  两段式,保证目标目录里出现的文件始终是完整的。

### source:观察来源(不影响信任,只影响诊断)

```text
source = UdpDiscovery | Gossip | Push | LocalFile | Authority | ZoneResolver
```

`source` 描述"这条 Observed 事件是通过哪条链路进来的",写在 `unverified` 目录
下 meta 文件里,供日志、诊断、以及未来 `smart_resolver` 式的动态拓扑记录使用
(见[已有did-resolver介绍.md](./已有did-resolver介绍.md) 第 6 节:根据历史来源
动态扩展查询路径,目前该 resolver 暂不实现,但存 `source` 不妨碍以后接上)。
`source` 绝不参与信任等级判定——判定只看目录位置 + 验证结果。

### lazy verify 与 verify_and_promote

`verify_and_promote` 是本文新增的内部入口,职责是把 `verify_did_document_jwt`
里对"已有 JWT 字符串"的验证逻辑,复用到"cache 里已经躺着一份候选文档"的场景:

```rust
/// 对 `unverified` cache 里 (did, doc_type) 当前的候选文档做一次 lazy verify。
/// 复用 verify_did_document_jwt 的核心判定(expected_owner + owner 验签 +
/// revoke/replay guard),但输入是 cache 条目而不是外部传入的 jwt 字符串。
async fn verify_and_promote(
    &self,
    did: &DID,
    doc_type: Option<DidDocType>,
) -> NSResult<VerifyPromoteOutcome>;

enum VerifyPromoteOutcome {
    /// 验证通过,文件已从 unverified 移动到 verified,可以按 Verified 返回。
    Promoted(EncodedDocument),
    /// 验证明确失败(owner 冒充、签名不对、被 owner policy 吊销……)。
    /// unverified 条目应被删除,避免同一份坏数据反复触发验证开销。
    Rejected(NSError),
    /// 验证所需条件暂不可用(owner document 拿不到、网络不可达)。
    /// unverified 条目保留,不删除、不 promote,策略决定是否可以被
    /// resolve_did_ex 的宽松模式露面。
    Unavailable(NSError),
}
```

触发时机只有一处:`resolve_did_ex` 在本机 cache 命中且证据等级为 `Unverified`
时,在使用它之前调用一次(见下文"resolve 流程整合")。不做后台批量扫描/预热——
[简单介绍resolve-did.md](./简单介绍resolve-did.md) 第 7 节的开发期旁路精神
同样适用于这里:没有人查询的 `Unverified` 条目,不值得主动花验证成本。

## 文件系统协议

### 目录布局

```text
{did_cache_root}/
  unverified/
    {key}.doc.json
    {key}.meta.json
  verified/
    {key}.doc.json
    {key}.meta.json
```

`{key}` 复用现有 `doc_cache.rs` 的 `combine_key`/`did_cache_key` 规则
(`did.to_filename()`,可选 `#{doc_type}` 后缀),不引入新的命名方案,保证现有
调试工具、备份脚本对文件名的假设继续成立。`{did_cache_root}` 默认值不变,仍是
`get_buckyos_service_local_data_dir("did_docs")` / `get_buckyos_system_etc_dir().join("did_docs")`
下新增两级子目录,而不是另起一套路径配置。

### 文件格式

`{key}.doc.json` 内容不变,仍是 `EncodedDocument` 的原文(JWT 字符串或 JSON/
JSON-LD 序列化结果)。`{key}.meta.json` 收紧为写入方**只被允许提供以下字段**,
其余字段(尤其是 `evidence`)由 name-client 在落盘时按目录位置和验证结果重写,
写入方即使提供了也会被忽略:

```jsonc
{
  "source": "UdpDiscovery",       // 可选,观察来源,仅用于诊断
  "observed_at": 1735689600,      // 可选,写入方本地时间戳,仅用于诊断/排障
  "hint_doc_type": "device"       // 可选,当 key 不含 doc_type 后缀时的提示
}
```

`unverified/{key}.meta.json` 落盘时,name-client(或直接写文件的旁路组件)必须
保证 `evidence` 字段最终是 `Unverified`——不接受写入方自报其它值。`verified/`
目录下的 meta 文件由 promote 动作生成,包含完整的
`evidence`/`exp`/`update_from_remote_time` 字段,复用现有 `StoredMeta` 结构。

### 写入协议:原子性与快速校验

不论是进程内 `update_did_cache` 函数调用,还是外部进程直接往 `unverified/`
目录里放文件,都必须遵守:

1. **先写临时文件,再 `rename` 进 `unverified/` 目录**(临时文件建议放在同一
   文件系统的相邻目录,例如 `unverified/.tmp/`,避免跨文件系统 `rename` 退化成
   非原子的 copy+delete)。
2. **写入前做一次快速校验**,校验不通过则不产生任何 `unverified/` 文件:
   - 文档能被 `EncodedDocument::from_str`/`parse_did_doc` 正常解析;
   - 解析出的 `id` 与调用方声明的 `did` 一致(避免明显的错放);
   - JWT 形式的文档必须能得出 revision `iat`(`iat` 直接存在,或由
     `exp - DEFAULT_EXPIRE_TIME` 推导;`ensure_jwt_iat_derivable` 规则——
     旧的"必须带 version_seq"强制项已随 version_seq 退出流程)。
   这一步**不是**完整验证,不检查签名、不检查 owner——它只挡住格式明显损坏或
   张冠李戴的数据,不提升信任等级。
3. **进程内 `add_observed_cache` 调用是这个协议的薄封装**:它跳过一次真实的
   文件系统往返(直接写入内存/文件后端),但产出的落盘结果、meta 字段、
   `Unverified` 证据等级,与"外部进程往目录里丢文件"完全等价。

### 权限模型

| 目录 | 写权限 | 典型写入方 |
| --- | --- | --- |
| `unverified/` | 本机上任意受信任运行的服务/用户(按部署环境的文件系统权限位或运行组决定) | UDP 设备发现、gossip 守护进程、调试工具、`update_did_cache` 调用方 |
| `verified/` | 只有 name-client 自身(或与它同 uid 的受控组件,例如 zone_resolver 管理面) | `verify_and_promote`、`resolve_did_ex` 主循环写入的 `Published` 结果 |

具体的权限实现手段(POSIX 权限位 + 独立运行组、Windows ACL、或者应用层在
写入前自行校验调用者身份)不在本文强制约定范围内,由实施阶段按部署目标平台
选择;但**语义约束是硬性的**:`unverified/` 目录的写权限面必须显著宽于
`verified/`,且普通服务永远不能直接写 `verified/`。

## API 草案

### update_did_cache(进程内薄封装)

```rust
pub async fn update_did_cache(
    did: DID,
    doc_type: Option<DidDocType>,
    doc: EncodedDocument,
    source: Option<UpdateSource>,   // 新增,可选,默认 None
) -> NSResult<()>;

pub enum UpdateSource {
    UdpDiscovery,
    Gossip,
    Push,
    LocalFile,
    Authority,
    ZoneResolver,
}
```

签名在现有基础上只新增可选的 `source`,不破坏现有调用方(可以给默认值)。行为
不变:内部走一次"快速校验 + 原子写入 `unverified/`",产出 `CacheEvidence::
Unverified`,不做任何验证、不提升信任等级。

### verify_and_promote(内部/半公开)

```rust
pub(crate) async fn verify_and_promote(
    &self,
    did: &DID,
    doc_type: Option<DidDocType>,
) -> NSResult<VerifyPromoteOutcome>;
```

复用 `verify_did_jwt.rs` 的核心校验(`expected_owner` 判定 + owner 验签 +
revoke/replay guard),区别只是输入来自 `unverified/` cache 条目而不是外部
传入的 jwt 字符串,`purpose` 固定为等价于 `VerifyPurpose::AuthSubject` 或
`ObjectDocument`(取决于 `doc_type` 是否要求主体认证语义,判定规则与
[verify-did-document-jwt.md](./verify-did-document-jwt.md) 保持一致)、
`validity` 固定为 `CurrentActive`。

### resolve_did_ex 新增 metadata 字段

```rust
pub enum VerificationStatus {
    /// 已通过验证(Published 天然满足,或 Verified 已完成 lazy verify)。
    Passed,
    /// 曾尝试 lazy verify,明确失败。
    Failed,
    /// 验证所需条件暂不可用(owner document 拿不到、网络不可达)。
    Unavailable,
    /// 未尝试验证(strict 模式下命中 Unverified 直接当 miss 处理,不返回给调用方,
    /// 因此这个状态只会出现在显式选择宽松模式、且策略决定不触发验证的路径里)。
    NotAttempted,
}
```

`DidResolutionMetadata`(`provider.rs`)在现有 `evidence`/`cache_status`/
`warnings` 字段基础上新增 `verification_status: Option<VerificationStatus>` 和
`source: Option<UpdateSource>`(命中 `verified/`/`Published` 结果时通常为
`None` 或 `Authority`/`ZoneResolver`)。

## resolve 流程整合

在[简单介绍resolve-did.md](./简单介绍resolve-did.md)第 3 节主循环的"本机缓存
快路径"基础上,插入 lazy verify 分支(伪代码,延续原文风格):

```python
def resolve_did_cache_fast_path(did, doc_type, strict):
    cached = did_cache.lookup(did, doc_type)   # 现在是 unverified/ + verified/ 联合视图
    if cached.is_negative() and cached.in_ttl:
        return error(cached.status)

    if cached.is_positive() and cached.in_ttl:
        if cached.evidence in (PUBLISHED, VERIFIED):
            return cached                       # 现有行为不变

        # evidence == UNVERIFIED:strict 模式下不能直接返回
        outcome = verify_and_promote(did, doc_type)
        match outcome:
            case Promoted(doc):
                return positive(doc, evidence=VERIFIED, verification_status=PASSED)
            case Rejected(err):
                did_cache.delete_unverified(did, doc_type)
                cached = None                   # 当作 cache miss,继续走主循环
            case Unavailable(err):
                if strict:
                    cached = None                # strict: 等同 miss,继续查询/兜底
                else:
                    # 宽松模式(resolve_did_ex 显式选择):可以打标返回
                    return positive(cached.doc, evidence=UNVERIFIED,
                                     verification_status=UNAVAILABLE)

    # 后续与现状一致:进入 provider 主循环 / 策略点④ stale cache 兜底
    ...
```

要点:

1. `resolve_did`(无 `doc_type` 之外不带任何选项的默认调用)固定走 `strict`。
2. `resolve_did_ex` 默认也走 `strict`;是否允许"验证不可用时仍返回 Unverified
   打标结果",由 `ResolvePolicy` 新增的一个显式开关控制(命名待定,建议
   `allow_unverified_cache_when_unavailable`,默认 `false`),不是隐式行为。
3. `Rejected` 之后重新走主循环,与现有"owner replay guard 校验失败,删除缓存,
   `cached = None`,继续查询"(`name_client.rs` 现有 833-844 行)的处理方式
   完全对称,不引入新的控制流模式。
4. `verify_and_promote` 内部的 owner 递归解析,必须使用
   `ResolvePolicy::for_authority_lookup()` 语义(不允许 Missing 自签名 fallback、
   不允许 stale cache 兜底),与 `verify_did_document_jwt` 现有实现一致。

## Cache 合并与落盘规则

`doc_cache.rs` 的 `merge_verdict`(先比证据等级,同级只比 revision——`iat` +
content hash,version_seq 已退出流程;负状态与本地覆盖屏蔽一切写入,结果按
`CacheWriteOutcome` 结构化返回)的执行对象是"跨 `unverified/`/`verified/`
两个目录的联合视图":

1. 写入 `unverified/` 目录(`add_observed_cache` 或直接文件投递)之前,不需要
   跟 `verified/` 目录里的同 key 条目比较——按定义 `Unverified` 永远打不过
   `verified/` 里的任何条目;如果 `verified/` 已有同 key 的 `Published`/
   `Verified` 记录,`unverified/` 里出现的新文件仅仅是被观察到、被记录,但
   查询时永远优先命中 `verified/`。
2. `verify_and_promote` 把 `unverified/` 条目移动进 `verified/` 时,仍然要走
   一次 `merge_verdict` 比较(新条目的证据等级是 `Verified`,可能撞上已有的
   `Published`/更新 revision 的 `Verified`),合并被拒时原 `unverified/` 文件
   应被删除——它已经被验证过一次并且证明"验证通过但不是更优版本",没有继续
   保留的价值。
3. `verified/` 目录内部的合并规则、负状态屏蔽、owner replay guard 联动清理
   (`evict_revoked_docs`),与现状完全一致,不做修改。

## 与现有实现的差异(改动清单)

| 现状 | 目标 | 涉及文件 |
| --- | --- | --- |
| `CacheBackend::{Filesystem,Sqlite,Memory}` 三后端 | 删除 `Sqlite`/`DbStore`,只保留 `Filesystem`/`Memory` | `doc_cache.rs`、`name_client.rs`(`CacheBackend` 匹配分支) |
| `FsStore` 单目录 `{key}.doc.json`/`{key}.meta.json` | 拆分 `unverified/`、`verified/` 两个子目录,`lookup` 做联合视图 | `doc_cache.rs` |
| `StoredMeta.evidence` 由调用方通过 `update`/`insert` 参数指定 | `unverified/` 目录下 evidence 恒为 `Unverified`(忽略调用方输入),`verified/` 目录下才信任显式 evidence | `doc_cache.rs` |
| `resolve_did_ex` in-TTL 命中不区分 evidence,直接返回 | 命中 `Unverified` 时触发 `verify_and_promote`,strict 模式下不通过就当 miss | `name_client.rs` |
| 没有 `verify_and_promote` | 新增,复用 `verify_did_jwt.rs` 核心校验 | `verify_did_jwt.rs`(拆出可复用核心) 或新文件 |
| `update_did_cache` 只是函数调用,无文件系统协议 | 定义 `unverified/` 目录写入协议(原子写 + 快速校验),函数调用是其薄封装 | `name_client.rs`、`doc_cache.rs`、`lib.rs` |
| `DidResolutionMetadata` 无 `verification_status`/`source` | 新增两个字段 | `provider.rs` |
| `ResolvePolicy` 无"是否允许返回 Unavailable 的 Unverified 结果"开关 | 新增显式字段,默认 `false` | `provider.rs` |

## 错误类型

沿用 `NSError` 现有的结构化错误模式(参照
`VerifyDidJwtFailed { code, detail }`,`src/name-lib/src/utility.rs`),建议
新增:

| 错误 | 含义 |
| --- | --- |
| `UnverifiedCacheWriteRejected` | 快速校验未通过(格式无法解析、`id` 与声明的 `did` 不一致等),`unverified/` 目录未产生任何文件 |
| `VerifyAndPromoteUnavailable` | lazy verify 所需条件暂不可用(owner document 拿不到、网络不可达),对应 `VerifyPromoteOutcome::Unavailable` |
| `VerifyAndPromoteRejected` | lazy verify 明确失败,复用 `verify_did_document_jwt` 现有错误码集合(`OwnerBindingUnavailable`/`DeclaredOwnerMismatch`/`SignatureVerificationFailed`/`RevokedByOwnerPolicy` 等,见 [verify-did-document-jwt.md](./verify-did-document-jwt.md) 错误表) |

`strict` 模式下,`VerifyAndPromoteUnavailable`/`VerifyAndPromoteRejected` 都不
应该冒泡成 `resolve_did` 的返回错误——它们只是内部信号,触发"当作 cache miss
继续走主循环"这条路径;只有主循环本身也拿不到可用结果时,才会向上抛出
`NotFound`/`Disabled` 等现有错误类型。

## 与现有 API 的关系

### resolve_did / resolve_did_ex

`resolve_did` 继续是 `resolve_did_ex(did, doc_type, ResolvePolicy::default())
.document` 的薄封装,但 `ResolvePolicy::default()` 隐含 strict 语义(不允许
`Unverified` 结果在验证不可用时露面)。需要宽松语义的调用方必须显式构造
`ResolvePolicy` 并读取完整的 `ResolvedDocument` metadata,不能只要 `.document`
却期待拿到未标注来源的 `Unverified` 内容。

### verify_did_document_jwt

`verify_did_document_jwt` 面向"应用层已经拿到一份外部 JWT 字符串"的场景;
`verify_and_promote` 面向"cache 里已经有一份 Observed 候选"的场景。两者共享
同一套核心校验(`expected_owner`/owner 验签/revoke guard),不应该出现两份
实现——建议把 `verify_did_jwt.rs` 里"给定候选文档 + did + doc_type + purpose
+ validity,返回验证结果"的核心函数提取成两者共用的私有函数,
`verify_did_document_jwt` 和 `verify_and_promote` 分别负责"候选从哪来"和
"结果如何落盘"这两件事各自的差异部分。

### update_did_cache

`update_did_cache` 继续是旁路 Observed 写入口,产物恒为 `Unverified`,新增
`source` 参数与对应的文件系统协议,不改变它"不能被用来提升信任等级"的既有
定位——[verify-did-document-jwt.md](./verify-did-document-jwt.md) 已经写明
"应用层验证通过后不应直接调用它保存已验证文档",本文进一步要求 resolve 端
自己也不再无条件信任 `unverified/` 目录里的任何文件。

### zone_resolver

`zone_resolver`(L1)与本机 `did_cache`(L2)的分层不变。`zone_resolver`
返回 unknown 时才会落到本机 L2,而 L2 现在内部分成 `unverified/`/`verified/`
两层,这一变化对 `zone_resolver` 完全透明——它看到的仍然是
`resolve_did_ex` 的最终结果,不感知本机文件系统协议的内部细节。

## 测试要求

至少覆盖以下测试(在现有 `doc_cache.rs`/`name_client.rs` 测试基础上新增):

1. `unverified/` 目录直接放入格式合法但未签名/签名不匹配 owner 的文件,
   `resolve_did`(strict)不能返回它,且不能因为它的存在而报错(应视为 miss,
   继续走主循环)。
2. 同一 `(did, doc_type)` 在 `verified/` 目录已有 `Published` 记录时,
   `unverified/` 目录出现新文件不应该、也不能够影响 `resolve_did` 的返回结果。
3. `unverified/` 目录里的候选通过 `verify_and_promote` 后,原文件从
   `unverified/` 消失,`verified/` 出现对应文件,证据等级为 `Verified`;
   第二次 `resolve_did` 调用应该是普通 cache hit,不再重复触发验证。
4. `verify_and_promote` 验证明确失败(例如 owner 冒充)时,`unverified/`
   对应文件被删除,不会反复触发验证开销。
5. `verify_and_promote` 因网络不可达返回 `Unavailable` 时:strict 模式下
   `resolve_did` 视为 miss;显式宽松模式下 `resolve_did_ex` 返回
   `evidence=Unverified, verification_status=Unavailable` 的打标结果。
6. 快速校验:写入方声明 `did:web:a`,但文档内容的 `id` 字段是
   `did:web:b`,`unverified/` 目录不应该出现任何文件。
7. 直接绕过 `update_did_cache` 函数、手工在文件系统里往 `unverified/` 目录
   放文件,行为与调用 `update_did_cache` 完全一致——验证"目录即协议"而不是
   "只有这个函数调用才算数"。
8. 尝试往 `verified/` 目录手工放一个自称 `evidence: Published` 的文件(模拟
   低权限进程越权写入):在没有目录级权限隔离的测试环境里,至少要在文档/
   实现层面明确这属于部署方权限配置的责任范围,`doc_cache.rs` 自身不需要
   (也不能够)在应用层重新校验"谁写的"。
9. `merge_allows` 在 promote 阶段失败(已有更优 `verified/` 记录)时,
   `unverified/` 源文件应被清理,不会无限堆积。
10. 删除 SQL 后端后,`CacheBackend::Sqlite` 不再是合法配置项(编译期或运行期
    报错均可,取决于实现方式如何处理旧配置的兼容),现有默认配置
    (`Filesystem`/`Memory`)行为不受影响。

## 已回答问题

### 1. 为什么删除 SQL 后端,而不是继续维护三个后端?

`DbStore` 目前只是把 `Filesystem`/`Memory` 已有的 KV 语义原样搬进一张 SQLite
表,没有任何调用方使用它做过结构化查询,维护成本(schema 迁移、三套测试)大于
收益。真正需要结构化查询能力的场景,属于
[已有did-resolver介绍.md](./已有did-resolver介绍.md) 第 5 节的 `zone_resolver`
职责范围,它是独立服务,可以自己选择存储实现,不需要占用本机 `did_cache` 的
后端选项。

### 2. 为什么是两个目录而不是三个(unverified / verified / published)?

`Published` 与 `Verified` 的共同点是:两者都只能由受控写者(`resolve_did_ex`
主循环、`verify_and_promote`)产生,普通服务不可能写出这两档结果。既然写权限
边界一致,就不需要用目录再切一刀——用 `verified/` 目录下 meta 的 `evidence`
字段区分即可,少一层目录意味着少一次"要不要迁移"的判断(`Published` 结果从
诞生起就直接写 `verified/`,不需要先落 `unverified/` 再提升)。

### 3. lazy verify 的触发时机是查询时,还是需要后台任务?

只在查询时触发(`resolve_did_ex` 命中 `Unverified` cache 的那一刻),不做
后台批量扫描。理由与
[简单介绍resolve-did.md](./简单介绍resolve-did.md) 第 7 节的开发期旁路精神
一致:没有人查询的 `Unverified` 条目不值得花验证成本;后台扫描还会引入"验证
结果先于查询产生,查询时其实是在读一份可能已经过期的验证结论"这种额外的
一致性问题,不如查询时同步验证简单可靠。

### 4. `unverified/` 目录里的文件要不要有独立的 TTL/清理策略?

需要,但复用现有 `StoredMeta.exp`/`is_expired` 机制即可,不需要为
`unverified/` 目录设计新的过期算法。过期的 `unverified/` 文件在下次被查询
到时,会走到"验证所需条件不可用或验证失败"的分支之一,自然会被清理或忽略;
是否需要一个独立的后台 GC 任务定期清理"从未被查询过、已经过期很久"的
`unverified/` 文件,留给实施阶段按磁盘占用情况决定,不影响本文定义的信任
语义。

## 未决问题

1. **跨平台目录权限的具体实现手段**:POSIX 权限位 + 专用运行组、Windows ACL,
   还是应用层在写入前自行校验调用者身份(例如通过 Unix Domain Socket 的
   peer credential)?需要结合实际部署环境(容器化 vs 裸机 vs Windows 服务)
   在实施阶段确定。
2. **多机/多容器部署下,`unverified/` 目录是否需要跨节点共享**?例如同一
   zone 内多个容器都想观察到同一份 gossip 消息时,是各自维护本地
   `unverified/` 目录,还是共享一个卷?这与
   [已有did-resolver介绍.md](./已有did-resolver介绍.md) 第 5 节的
   `zone_resolver` 定位有一定重叠,需要先确认这类场景是否应该直接走
   `zone_resolver` 而不是本机 `did_cache`。
3. **并发写入同一 `unverified/` 文件的锁协议**:多个进程同时观察到同一份
   文档并发写入是否需要文件锁?当前设计依赖"写临时文件 + rename"的原子性
   规避大部分竞态,但"临时文件命名冲突"等边界情况需要在实施阶段补充规则
   (例如临时文件名带调用方 PID/随机后缀)。
4. **`verify_and_promote` 的 `purpose` 判定规则**:如何根据 `doc_type` 自动
   决定用 `AuthSubject` 还是 `ObjectDocument` 语义?
   [verify-did-document-jwt.md](./verify-did-document-jwt.md) 目前是由调用方
   显式传入 `purpose`,`verify_and_promote` 作为 resolve 路径的自动触发点,
   没有一个"调用方"来做这个选择,需要补充一份按 `doc_type` 归类的默认规则表。
