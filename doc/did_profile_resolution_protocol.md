# 需求提取：DID → Profile / OwnerConfig 解析协议（name-client）

> 来源：`Users_Agents_PRD.md` §5.6 / §8.4、`UserType.md` §通过 did 获取 profile / §用户私钥、`control_panel_gap_todo.md` TODO-6。
> 结论：**「给定 user-did，解析其 profile / owner-config」是一个可复用的解析协议，应沉到 buckyos-base 的 name-client，而不是在 control_panel / msg_center / Home Station 各实现一遍。**
> 本文只提取需求与边界，不含实现。面向 name-client 维护者。

---

## 1. 为什么放 name-client（而不是 control_panel）

- **本质是命名解析**：「DID → 它的 profile 文档在哪、怎么取、怎么验签、怎么合并」全是 resolution 关注点，和 `resolve_did` / providers / doc_cache 同层。
- **多消费者**：control_panel（Self/用户 Profile 页）、msg_center（联系人资料）、Home Station（评论作者身份）、AICC（对端身份）都要这条能力。放在细腰层一次实现，避免 N 份合并逻辑漂移。
- **符合细腰原则**：这是该长在 waist 上的协议能力；消费者（如 control_panel TODO-6）只调用，不重造。

---

## 2. 现状（可复用，勿重造）

**name-client（rev 1f5966d）已有：**
- `resolve_did(did, doc_type: Option<&str>) -> EncodedDocument`：底层按 doc_type 取 DID 文档（owner/user/device/zone…）。
- `resolve(name, record_type) -> NameInfo`、`resolve_auth_key(did, kid)`：DNS/密钥解析。
- `DIDObjectClient`：解析 DID-Object-Card → `ObjectProfile`（WoT/TD 风格，traits/properties/actions/events）—— 面向 **对象/Agent 能力 profile**。
- providers：`bns_provider / dns_provider / https_provider / local_ns_provider`；`doc_cache` 缓存。

**name-lib 已有类型：**
- `OwnerConfig`（user.rs）：用户 owner DID 文档，含 `id / verificationMethod / keyScope / wallets / default_zone_did / version_seq / mini_version_seq / valid_iat`，并带 `validate_jwt_revocation()` 重放/吊销校验。
- `ObjectProfile`（object_profile.rs）：WoT 风格 profile（**本协议不复用，见决策2/§4**）。

**缺什么（核心 gap）：**
- 没有 typed 便捷解析：`resolve_owner_config(did)` / `resolve_user_profile(did)`。
- 没有 `UserType.md` 要求的 **owner-config 与 profile 合并协议**（owner-config identity 字段覆盖 resolver 选中的 profile）。
- 没有 **DID 形态感知的 owner-config 解析**（`did:bns:$user.$zone` 请求 profile 时，仍需用 `did:bns:$user` 取 owner-config 验签）。
- 没有扁平的用户 profile 类型（`UserProfile`），现有 `ObjectProfile` 太重。
- `OwnerConfig` 只有 `default_zone_did`，**没有 `binded_zone_list`** —— 本轮决策：加入 `binded_zone_list`，`default_zone_did` 改为派生自 `binded_zone_list[0]`（见 §6）。

---

## 3. 协议要做的事（需求）

### R1　Typed 解析入口
- `resolve_owner_config(did) -> OwnerConfig`：doc_type=`owner`，封装现有 `resolve_did` + 解码 + 验签。
- `resolve_user_profile(did, opts) -> MergedProfile`：doc_type=`user`（对外公开 profile，**扁平 `UserProfile`，见决策2/§4**），含 §R2 合并。
- 形态对齐现有 `DIDObjectClient`（可做成 `ProfileResolver` struct 或顶层 async fn）。

### R2　标准 Profile 解析 + OwnerConfig 合并（协议核心，UserType.md §通过 did 获取 profile）
- **Profile 解析**：`resolve_user_profile` 不手动区分 BNS / 链上 profile 与 zone / 链下 profile，也不按字段合并多个 profile；它只通过标准 `resolve_did(did, doc_type=user)` 获取一个 profile 文档。具体返回链上还是链下结果，由 resolver / provider 的优先级管理决定。
- **OwnerConfig 合并**：`resolve_user_profile` 必须先解析 owner-config（User Document），再用 owner-config 中的 identity 字段覆盖 resolver 选中的 profile。同名字段以 owner-config 为最高优先级；当前明确覆盖 `name / display_name / avatar / meta`，并允许 owner-config 的 `meta` 对象和扩展字段进入最终 profile。
- **OwnerConfig meta overlay**：owner-config 的 `meta` 会保留到最终 `profile.meta`，同时其中的对象字段会作为 identity overlay 应用到 profile。字段名可以是顶层字段（如 `headline`），也可以是简单 JSON path / dot path（如 `$.links.github`）。对象覆盖采用递归合并，因此 `links` / `public_contacts` 使用 map，方便按 key 选择性覆盖。
- 结果需携带 **逐字段来源（provenance）**：标明字段来自 owner-config 还是 resolver 选中的 profile —— 供 UI 区分「文档字段修改成本更高/有生效延迟」（PRD §8.4）。
- profile 文档缺失时仍可用 owner-config 返回基础 identity；owner-config 本身解析失败必须报错。

### R3　DID 形态感知的 OwnerConfig 解析（UserType.md）
- `did:bns:$username`（一级，不带 zone）→ owner-config DID 就是该 DID。
- `did:bns:$username.$zonename`（二级，显式 zone）→ profile 仍按请求 DID 做标准 `resolve_did(did, doc_type=user)`；owner-config 则解析为 `did:bns:$username`，用于取得验签公钥和 identity 覆盖字段。
- `binded_zone_list[0]` 只作为 owner-config 的 default-zone metadata 返回，不参与 profile 源选择。

### R4　doc_type 语义澄清（写进协议文档）
- `doc_type = user`：用户**公开 profile**（头像/昵称/简介/公开可达）。
- `doc_type = owner`：用户作为 zone-owner 的 owner-config，**可能加密**，不一定公开。
- 协议需说明二者解析路径与可见性差异。

### R5　验签与信任
- profile / owner-config 文档由 owner key 签发（JWT）；解析必须验签 + 走 `validate_jwt_revocation`（version_seq / valid_iat 重放守卫，OwnerConfig 已有）。
- 验签失败 / 被吊销 → 拒绝返回，不能降级成「未验证 profile」。

### R6　缓存与新鲜度
- 复用 `doc_cache`；定义 TTL 与刷新语义。底层 provider 可能慢，需 stale-while-revalidate 类策略或显式 `force_refresh`。
- 与 `kevent 是加速通道，不是真理来源` 一致：缓存是加速，权威源由 resolver/provider 链决定，调用方需能强制回源。

---

## 4. 建议 API 形态（草案，供讨论）

**决策2：用户 profile 采用扁平 schema（LinkedIn 风格）**，不复用 WoT/TD 的 `ObjectProfile`（那个为对象/Agent 能力声明设计，太重）。字段以「人的对外名片」为心智：

```rust
// name-lib：新增扁平用户 profile（doc_type=user 的解码目标）
pub struct UserProfile {
    pub did: DID,
    #[serde(skip_serializing_if = "Option::is_none")] pub name: Option<String>,         // 稳定用户名
    #[serde(skip_serializing_if = "Option::is_none")] pub display_name: Option<String>, // 昵称/显示名
    #[serde(skip_serializing_if = "Option::is_none")] pub avatar: Option<String>,       // 头像 URL
    #[serde(skip_serializing_if = "Option::is_none")] pub meta: Option<Value>,          // 通用 identity 扩展
    #[serde(skip_serializing_if = "Option::is_none")] pub headline: Option<String>,     // 一句话简介
    #[serde(skip_serializing_if = "Option::is_none")] pub bio: Option<String>,          // 详细简介/about
    #[serde(skip_serializing_if = "Option::is_none")] pub location: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")] pub organization: Option<String>, // 组织
    #[serde(skip_serializing_if = "Option::is_none")] pub title: Option<String>,        // 头衔
    #[serde(skip_serializing_if = "HashMap::is_empty")] pub links: HashMap<String, ProfileLink>, // 主页/社交外链
    #[serde(skip_serializing_if = "HashMap::is_empty")] pub public_contacts: HashMap<String, ProfileContact>, // 公开可达方式
    #[serde(flatten)]                                  pub extra: HashMap<String, Value>, // 前向扩展
}

// 本地私有 profile：UserProfile 的超集，必须只用于本地/私有存储，
// 不作为 doc_type=user 发布，也不进入链上 DID 文档。发布公开资料时由它派生 UserProfile。
pub struct UserPrivateProfile {
    pub did: DID,
    // 与 UserProfile 相同的公开候选字段：name/display_name/avatar/meta/headline/...
    #[serde(skip_serializing_if = "HashMap::is_empty")] pub links: HashMap<String, ProfileLink>,
    #[serde(skip_serializing_if = "HashMap::is_empty")] pub public_contacts: HashMap<String, ProfileContact>,
    #[serde(skip_serializing_if = "UserProfilePrivacy::is_empty")] pub privacy: UserProfilePrivacy,
    #[serde(skip_serializing_if = "HashMap::is_empty")] pub private_contacts: HashMap<String, ProfileContact>,
    #[serde(skip_serializing_if = "Option::is_none")] pub private_meta: Option<Value>,
    #[serde(skip_serializing_if = "HashMap::is_empty")] pub private_extra: HashMap<String, Value>,
    #[serde(flatten)] pub extra: HashMap<String, Value>,
}
pub enum ProfileVisibility { Public, Private, Contacts, Zone, Custom }
pub struct ProfilePrivacyRule {
    pub visibility: ProfileVisibility,
    #[serde(skip_serializing_if = "Vec::is_empty")] pub allow: Vec<DID>,
    #[serde(skip_serializing_if = "Vec::is_empty")] pub deny: Vec<DID>,
    #[serde(skip_serializing_if = "Vec::is_empty")] pub groups: Vec<String>,
}
pub struct UserProfilePrivacy {
    #[serde(skip_serializing_if = "Option::is_none")] pub default_visibility: Option<ProfilePrivacyRule>,
    #[serde(skip_serializing_if = "HashMap::is_empty")] pub fields: HashMap<String, ProfilePrivacyRule>,
    #[serde(skip_serializing_if = "HashMap::is_empty")] pub links: HashMap<String, ProfilePrivacyRule>,
    #[serde(skip_serializing_if = "HashMap::is_empty")] pub contacts: HashMap<String, ProfilePrivacyRule>,
}
pub struct ProfileLink    { pub label: String, pub url: String }
pub enum ProfileContactPlatform {
    Email, Phone, Telegram, Matrix, Discord, Wechat, Whatsapp, Signal,
    X, Github, Linkedin, Facebook, Instagram, Tiktok, Reddit, Mastodon, Bluesky,
}
pub struct ProfileContact {
    pub platform: ProfileContactPlatform, // 强类型平台枚举，不提供 Other，避免任意扩展
    pub account_id: String,               // 平台内可定位用户的 canonical id：uid/handle/email/E.164/Matrix ID 等
    #[serde(skip_serializing_if = "Option::is_none")] pub display_id: Option<String>, // 可打开 profile page 的公开 handle/username
    #[serde(skip_serializing_if = "Option::is_none")] pub tunnel_id: Option<DID>,     // 可选：平台 tunnel/gateway DID
}

// name-client：顶层 async fn 或 ProfileResolver
pub async fn resolve_owner_config(did: &DID) -> NSResult<OwnerConfig>;

pub struct ProfileResolveOptions {
    pub force_refresh: bool,
}

pub struct MergedProfile {
    pub did: DID,
    pub profile: UserProfile,                          // 扁平
    pub field_sources: HashMap<String, ProfileSource>, // 逐字段来源（顶层字段名 → 来源）
    pub default_zone_did: Option<DID>,                 // = binded_zone_list[0]
}
pub enum ProfileSource { Profile, OwnerConfig }

pub async fn resolve_user_profile(
    did: &DID,
    opts: ProfileResolveOptions,
) -> NSResult<MergedProfile>;
```

`ProfileContact` 的目标是能定位到平台上的特定用户，并让调用方生成「打开 profile page / 添加好友」入口；不承载联系人关系、备注、分组等社交图信息。旧 `kind/value` 可以作为兼容输入读取，但新文档统一写 `platform/account_id`。例如：

```json
{
  "public_contacts": {
    "telegram": {
      "platform": "telegram",
      "account_id": "user:5397330802",
      "display_id": "wacer2026",
      "tunnel_id": "did:web:tg-tunnel.test.buckyos.io"
    },
    "matrix": {
      "platform": "matrix",
      "account_id": "@alice:example.com"
    }
  }
}
```

> 扁平 + `#[serde(flatten)] extra` 兼顾「字段少、好渲染」和「不锁死、可加字段」。`field_sources` 标到**顶层字段名**这一层即可（决策见 §7-Q2）。

---

## 5. 边界（本协议**不**负责）

- **写/编辑 profile**：属 profile 发布链路，留在 control_panel（`user.profile.set`）；本协议只读取 resolver/provider 选中的 profile。
- **联系人/好友关系图**：归 msg_center（`Contact` / `AccessGroupLevel`）。
- **platform/account_id → DID 的发现**：msg_center 既有 `resolve_did`（同名但不同语义），不并入本协议。

---

## 6. `binded_zone_list`（决策1：已定，纳入本协议）

- **决策**：`binded_zone_list: Vec<DID>` 加进 name-lib `OwnerConfig`；**`default_zone_did` 不再是独立字段，改为派生 = `binded_zone_list[0]`**（列表第一项即默认 zone）。
- 语义：一个一级 DID 可同时绑多个 zone（PRD §5.4「暂时把数据绑到别人的 Zone」），列表顺序表达优先级，首项是默认落点。
- **改动点**：
  - name-lib `OwnerConfig`：加 `binded_zone_list`；`get_default_zone_did()` 改为返回 `binded_zone_list.first()`；`set_default_zone_did(z)` 语义变为「把 z 提到列表首位（不存在则插入）」。保留同名 accessor，降低调用方改动面。
  - 序列化：是否保留 `default_zone_did` 作为只读派生字段输出（兼容老读者）待定 —— 倾向**只存 `binded_zone_list`**，`default_zone_did` 仅作 accessor，不再持久化。
- **附带能力**（本协议提供，control_panel 邀请流程 TODO-3 用）：
  - `owner_is_bound_to_zone(did, zone_did) -> bool`：解析 owner-config 后判断 `binded_zone_list` 是否含目标 zone（invite.accept 的校验入口）。
- **迁移**：现有写 `default_zone_did` 的代码（name-lib `set_default_zone_did` / scheduler / node_active 等）需改为操作 `binded_zone_list`。beta2.2 允许破坏性 schema 改动，但要扫一遍存量 owner-config 文档的兼容读取（老文档只有 `default_zone_did` 时，读取层回填进 `binded_zone_list`）。

---

## 7. 开放问题

- ~~Q1 用户 profile schema：WoT 还是扁平？~~ → **已定：扁平 `UserProfile`（LinkedIn 风格，§4）。**
- ~~Q3 `binded_zone_list` 归属？~~ → **已定：进 `OwnerConfig`，`default_zone_did = binded_zone_list[0]`（§6）。**
- **Q2 合并粒度**：顶层字段合并即可，还是支持 `extra` 内嵌套深合并？provenance 暂定标到顶层字段名一层 —— 待确认是否够用。
- **Q5 缓存**：TTL 默认值 / 是否接 kevent 主动失效。

---

## 8. 落地切分建议

1. **协议文档定稿**（本文 → name-client 设计文档），收尾 §7 剩余 Q2/Q4/Q5。
2. **name-lib**：
   - `OwnerConfig` 增 `binded_zone_list`，`default_zone_did` 改派生 accessor + 老文档兼容回填（§6）。
   - 新增扁平 `UserProfile` / `ProfileLink` / `ProfileContact`（§4）。
3. **name-client**：`resolve_owner_config` →（含 owner-config/profile 合并的）`resolve_user_profile` → `owner_is_bound_to_zone`。
4. **存量迁移**：扫所有写/读 `default_zone_did` 的点改走 `binded_zone_list`。
5. **消费者接入**：control_panel TODO-6 `user.profile.get` 直接调本协议；TODO-3 invite.accept 调 `owner_is_bound_to_zone`。
