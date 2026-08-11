# `addr-rtt-db` 组件需求文档

## 一、组件定位

`addr-rtt-db` 提供**全局共享的目标地址连接质量数据库**，用于在多 IP 候选场景下做出最优地址选择。

典型使用方：DNS resolver 拿到一组 IP 后，调用本组件对其排序；连接组件在每次连接尝试后，回调本组件记录结果。组件本身不发起任何网络 I/O，是**纯粹的数据收集与决策辅助层**。

定位边界：

- ✅ 收集连接质量数据
- ✅ 提供地址排序决策
- ✅ 跨组件、跨连接、跨进程重启共享
- ❌ 不实现 DNS 解析
- ❌ 不实现 Happy Eyeballs 竞速逻辑
- ❌ 不实现连接池

## 二、核心设计原则

### 2.1 网络环境通过"当前出口 IP"区分

这是本组件最关键的设计简化。

**不引入复杂的网络指纹机制**（不抓网关 MAC、不抓 SSID、不监听 netlink 事件），而是把"网络环境"这个维度的责任**下推给调用方**：

> 调用方在每次 `record` 和 `rank` 时，都必须提供当前的本机出口 IP。

为什么这样设计：

- **本机出口 IP 是"网络环境"的天然代理变量**——同一个出口 IP 意味着大概率走同一条出网路径
- 出口 IP 变化（WiFi → 4G、家 → 公司）必然导致出口 IP 变化，自动触发数据隔离
- 调用方往往本来就需要知道本机出口 IP（绑定 socket、上报 SN 等），不会增加额外成本
- 组件内部不需要任何后台线程、不需要监听系统事件，**纯无状态被动响应**，跨平台一致

调用方如何拿到"当前出口 IP"由调用方决定（路由表查询、socket `local_addr()`、向 SN 询问等），不在本组件职责范围内。

### 2.2 记录"连接结果"而非"RTT 数值"

接口面向语义化的**连接结果**（成功/超时/拒绝/不可达），而非裸 RTT 数值。失败信息和成功信息同等重要。

### 2.3 不偷偷启动后台任务

组件本身不 spawn 任何 task。持久化、清理等行为都通过显式 API 触发（调用方决定何时调用、由谁调用）。这避免了静默资源消耗，也符合 Rust "no surprise" 哲学。

可选提供 `tokio` feature flag，开启后才注册一个定期 flush 任务，且这个任务的句柄返回给调用方管理。

### 2.4 依赖注入而非全局静态

不提供 `static GLOBAL_DB: Lazy<...>` 这种全局变量。组件作为 `Arc<RttDatabase>` 在系统中传递。如果上层希望全局可达，由上层自己决定如何包装。

## 三、核心数据模型

### 3.1 关键概念

```rust
/// 出口 IP，用于隔离不同网络环境的数据
pub type LocalIp = IpAddr;

/// 目标地址（IP + 端口）
pub type RemoteAddr = SocketAddr;

/// 数据库内部 key
struct EntryKey {
    local: LocalIp,       // 本机出口 IP
    remote: RemoteAddr,   // 目标地址
}
```

**Key 的设计含义**：同一个目标 IP，在不同出口 IP 下被视为完全独立的两条记录。这是网络环境隔离的核心机制。

### 3.2 连接结果

```rust
pub enum ConnectionOutcome {
    /// 连接成功，并完成了至少一次往返
    Success {
        rtt: Duration,
        layer: MeasurementLayer,
    },
    /// 在指定时间内未完成（SYN 超时、握手超时等）
    Timeout { elapsed: Duration },
    /// 对端明确拒绝（RST、ICMP port unreachable）
    Refused,
    /// 路径不可达（ICMP host/network unreachable、no route）
    Unreachable,
    /// 其他错误（DNS、配置等本地错误，不归因到目标地址）
    LocalError,
}

pub enum MeasurementLayer {
    Tcp,          // TCP 三次握手往返
    Tls,          // TLS 握手完成
    Application,  // 应用层第一个有效响应（推荐）
}
```

`LocalError` 类型存在的意义：调用方有时无法区分"远端不可达"和"本地配置错误"，提供这个出口避免把本地错误污染到地址评分上。

### 3.3 地址统计

```rust
pub struct AddressStats {
    pub samples: u64,                       // 总样本数
    pub success_count: u64,                 // 成功次数
    pub rtt_ewma: Option<Duration>,         // EWMA 平滑后的 RTT
    pub rtt_variance: Option<Duration>,     // RTT 方差
    pub last_outcome: Option<OutcomeKind>,  // 最近一次结果类型
    pub last_success_time: Option<SystemTime>,
    pub last_failure_time: Option<SystemTime>,
    pub consecutive_failures: u32,          // 连续失败计数
    pub measurement_layer: MeasurementLayer,
}
```

### 3.4 排序结果

```rust
pub struct RankedAddress {
    pub addr: RemoteAddr,
    pub score: f64,                  // 综合分数（越大越优）
    pub stats: Option<AddressStats>, // 历史数据，无则为新地址
    pub rationale: SortRationale,    // 排序理由（调试用）
}

pub struct SortRationale {
    pub reasons: Vec<&'static str>,
    // 例如：["fresh-data", "low-rtt", "ipv6-preferred", "no-recent-failures"]
}
```

## 四、核心 API

### 4.1 数据库实例

```rust
pub struct RttDatabase { /* 内部字段 */ }

impl RttDatabase {
    /// 创建新实例
    pub fn new(config: Config) -> Self;
    
    /// 从持久化存储恢复
    pub fn open(path: impl AsRef<Path>, config: Config) -> Result<Self>;
}
```

### 4.2 记录连接结果

```rust
impl RttDatabase {
    /// 记录一次连接尝试结果
    /// 
    /// `local`: 本次连接使用的本机出口 IP（必填）
    /// `remote`: 目标地址
    /// `outcome`: 连接结果
    pub fn record(
        &self,
        local: LocalIp,
        remote: RemoteAddr,
        outcome: ConnectionOutcome,
    ) -> Result<()>;
}
```

注意：API 设计为同步 `fn`，因为内部用 `dashmap`/`moka` 写入是非阻塞的。这避免了 `async fn` 的传染性。

### 4.3 地址排序

```rust
impl RttDatabase {
    /// 对一组地址按预测连接质量排序
    /// 
    /// `local`: 当前本机出口 IP（必填，用于查找该网络环境下的历史数据）
    /// `addresses`: 候选地址列表
    /// `policy`: 排序策略
    pub fn rank(
        &self,
        local: LocalIp,
        addresses: &[RemoteAddr],
        policy: &SortPolicy,
    ) -> Vec<RankedAddress>;
    
    /// 查询单条记录（不排序，只读）
    pub fn get_stats(
        &self,
        local: LocalIp,
        remote: RemoteAddr,
    ) -> Option<AddressStats>;
}
```

### 4.4 排序策略

```rust
pub struct SortPolicy {
    /// 数据多旧之后视为不可信（默认 24 小时）
    pub max_age: Duration,
    
    /// 偏好 IPv6（默认 true）
    pub prefer_ipv6: bool,
    
    /// 没有历史数据的地址如何处理
    pub unknown_strategy: UnknownStrategy,
    
    /// 失败惩罚强度，0.0 = 不惩罚，1.0 = 严厉惩罚（默认 0.5）
    pub failure_penalty: f64,
    
    /// 连续失败超过此值的地址直接排到末尾（默认 5）
    pub blacklist_threshold: u32,
    
    /// EWMA 平滑系数（默认 0.125，TCP 标准）
    pub ewma_alpha: f64,
}

pub enum UnknownStrategy {
    /// 排在已知地址前面（鼓励探索）
    Optimistic,
    /// 排在已知地址后面（保守利用）
    Pessimistic,
    /// 用所有已知地址的中位数估算（默认）
    Median,
}

impl Default for SortPolicy { /* ... */ }
```

### 4.5 维护操作

```rust
impl RttDatabase {
    /// 显式清理过期数据
    pub fn cleanup(&self) -> CleanupReport;
    
    /// 持久化到磁盘（如果启用了存储）
    pub fn flush(&self) -> Result<()>;
    
    /// 清空指定 local IP 下的所有数据
    /// （调用方检测到网络环境变化时可主动调用，可选）
    pub fn forget_local(&self, local: LocalIp) -> usize;
    
    /// 清空所有数据
    pub fn clear(&self);
    
    /// 当前总条目数
    pub fn len(&self) -> usize;
    
    /// 导出数据用于诊断
    pub fn dump(&self) -> Vec<(EntryKey, AddressStats)>;
}
```

### 4.6 配置

```rust
pub struct Config {
    /// 总条目数上限，超出 LRU 淘汰（默认 10_000）
    pub max_entries: usize,
    
    /// 单个 local IP 下的条目数上限（默认 1_000）
    pub max_per_local: usize,
    
    /// 异常 RTT 限幅：超过 EWMA × 此值的样本被限幅
    /// 防止偶发巨大 RTT 污染估算（默认 10.0）
    pub rtt_outlier_factor: f64,
    
    /// 持久化策略
    pub persistence: PersistencePolicy,
}

pub enum PersistencePolicy {
    /// 仅内存
    None,
    /// 持久化到指定路径
    Storage {
        path: PathBuf,
        /// 自动 flush 间隔（None = 仅手动）
        auto_flush_interval: Option<Duration>,
    },
}
```

## 五、行为细则

### 5.1 EWMA 更新规则

成功样本到达时：

```
new_rtt_ewma = alpha * sample_rtt + (1 - alpha) * old_rtt_ewma
new_rtt_var  = alpha * |sample_rtt - old_rtt_ewma| + (1 - alpha) * old_rtt_var
```

首次样本：`rtt_ewma = sample`，`rtt_var = sample / 2`。

异常值限幅：若 `sample_rtt > rtt_ewma * outlier_factor`，则截断到 `rtt_ewma * outlier_factor` 后再纳入计算。

### 5.2 失败处理

- `Timeout` / `Unreachable`：`consecutive_failures += 1`，`last_failure_time` 更新
- `Refused`：标记为失败但 `consecutive_failures` 加 0.5（向上取整），因为对端在线
- 任何成功：`consecutive_failures = 0`
- `LocalError`：完全不更新统计

### 5.3 评分函数

排序时每个地址计算综合分数：

```
base_score = if rtt_ewma exists:
    1000 / rtt_ewma_ms
else:
    unknown_strategy 决定的默认值

freshness_factor = max(0, 1 - age / max_age)

success_factor = success_count / samples  // 成功率

failure_penalty = 1 / (1 + consecutive_failures * failure_penalty_strength)

family_bonus = if prefer_ipv6 && is_ipv6: 1.1 else 1.0

final_score = base_score * freshness_factor * success_factor 
              * failure_penalty * family_bonus

if consecutive_failures >= blacklist_threshold:
    final_score = -∞  // 强制排到末尾
```

具体公式可调，但**保留 `rationale` 字段**说明每个因子如何贡献，便于调试。

### 5.4 数据淘汰

- LRU：超过 `max_entries` 时按最近访问时间淘汰
- 单网络环境上限：单个 `local_ip` 的条目超过 `max_per_local` 时，淘汰该 local 下最旧的
- TTL：超过 `max_age * 2` 的条目在 `cleanup()` 时被物理删除

### 5.5 并发模型

- 所有写操作（`record`）：内部用 `dashmap` 或 `moka::sync::Cache`，无外部锁
- 所有读操作（`rank`、`get_stats`）：同上，无锁并发
- `flush` / `cleanup`：可能稍慢，但不阻塞 read/write
- 整个组件 `Send + Sync`，可直接 `Arc::new()` 后跨任务/线程共享

## 六、持久化格式

启用持久化时，使用 `redb` 作为后端（嵌入式、纯 Rust、无 unsafe）。

数据布局：

```
table: address_stats
  key:   bincode(EntryKey { local: LocalIp, remote: RemoteAddr })
  value: bincode(AddressStats)

table: metadata
  key:   "schema_version"
  value: u32
```

`flush()` 调用时执行批量写入。启动 `open()` 时一次性加载到内存（也可改为 lazy load，看实测内存占用）。

**故障容忍**：持久化失败不影响内存中数据使用，只是 log warn，确保进程不会因为磁盘问题挂掉。

## 七、可观测性

### 7.1 指标

提供 metrics 接口（feature flag 可选启用 `metrics` crate 集成）：

```
addr_rtt_db.entries_total              # gauge
addr_rtt_db.records_total{outcome}     # counter
addr_rtt_db.ranks_total                # counter
addr_rtt_db.cache_hits / misses        # counter
addr_rtt_db.flush_duration_seconds     # histogram
addr_rtt_db.cleanup_evicted_total      # counter
```

### 7.2 调试

- `RankedAddress::rationale` 字段说明每个因子的贡献
- `dump()` 方法导出所有数据用于诊断
- 关键决策路径打 `tracing::debug!` 日志

## 八、不在本期范围

明确**不做**的事情，避免范围蔓延：

- ❌ 带宽测量与排序（只关心 RTT + 成功率）
- ❌ 多路径调度
- ❌ 主动健康检查（不发任何网络包）
- ❌ 分布式同步（多个节点共享数据）
- ❌ DNS 缓存（用 `hickory-resolver` 自带的）
- ❌ 网络环境自动检测（由调用方传入 `local_ip`）
- ❌ Happy Eyeballs 竞速（独立组件做）

## 九、依赖

```toml
[dependencies]
dashmap = "6"           # 并发 HashMap（或选 moka）
serde = { version = "1", features = ["derive"] }
bincode = "1"           # 持久化序列化
thiserror = "2"         # 错误类型
tracing = "0.1"         # 日志

[dependencies.redb]
version = "2"
optional = true         # 持久化可选

[dependencies.metrics]
version = "0.24"
optional = true         # 可观测性可选

[features]
default = ["persistence"]
persistence = ["dep:redb"]
metrics = ["dep:metrics"]
```

## 十、典型使用示例

### 10.1 基础使用

```rust
use addr_rtt_db::{RttDatabase, Config, ConnectionOutcome, SortPolicy, MeasurementLayer};
use std::sync::Arc;
use std::time::{Duration, Instant};

// 全局实例（在应用启动时创建一次）
let db = Arc::new(RttDatabase::new(Config::default()));

// === 连接发起方 ===
let local_ip = get_local_outbound_ip()?;  // 调用方负责获取
let candidates = vec![
    "[2001:db8::1]:2980".parse()?,
    "192.0.2.10:2980".parse()?,
    "192.0.2.20:2980".parse()?,
];

// 1. 排序
let ranked = db.rank(local_ip, &candidates, &SortPolicy::default());
for r in &ranked {
    println!("{} score={:.2} reasons={:?}", r.addr, r.score, r.rationale.reasons);
}

// 2. 按顺序尝试连接
let target = ranked[0].addr;
let start = Instant::now();
match try_connect(target).await {
    Ok(_) => {
        db.record(local_ip, target, ConnectionOutcome::Success {
            rtt: start.elapsed(),
            layer: MeasurementLayer::Application,
        })?;
    }
    Err(e) if e.is_timeout() => {
        db.record(local_ip, target, ConnectionOutcome::Timeout {
            elapsed: start.elapsed(),
        })?;
    }
    Err(e) if e.is_refused() => {
        db.record(local_ip, target, ConnectionOutcome::Refused)?;
    }
    Err(_) => {
        db.record(local_ip, target, ConnectionOutcome::Unreachable)?;
    }
}
```

### 10.2 持久化

```rust
let db = RttDatabase::open(
    "/var/lib/buckyos/addr-rtt.db",
    Config {
        persistence: PersistencePolicy::Storage {
            path: "/var/lib/buckyos/addr-rtt.db".into(),
            auto_flush_interval: None,  // 手动管理
        },
        ..Default::default()
    },
)?;

// 应用关闭时
db.flush()?;
```

### 10.3 网络变化通知（可选）

调用方如果检测到出口 IP 变化（例如通过监听网络事件），可以主动清空旧数据：

```rust
let old_local = current_local_ip;
let new_local = detect_new_local_ip()?;
if old_local != new_local {
    let removed = db.forget_local(old_local);
    tracing::info!("Network changed, forgot {} entries for {}", removed, old_local);
}
```

但这不是必需的——即便不主动清理，新的 `local_ip` 也会自然形成新的命名空间，旧数据只是占内存，会被 LRU 淘汰。

## 十一、测试要求

### 11.1 单元测试

- EWMA 计算正确性
- 异常值限幅
- LRU 淘汰
- 持久化 round-trip
- 并发读写无数据竞争（用 `loom` 或大量并发测试）

### 11.2 行为测试

- 同一 remote、不同 local：数据完全隔离
- 连续失败后地址被排到末尾
- 数据过期后自动降权
- 未知地址按策略处理

### 11.3 性能基线

- `record`：单次 < 5 µs
- `rank`（10 地址）：< 50 µs
- `rank`（100 地址）：< 500 µs
- 内存占用：1 万条目 < 5 MB

## 十二、版本演进

**v0.1（MVP）**：
- 内存存储
- 基础 EWMA + 失败计数
- 同步 API
- Optimistic / Pessimistic / Median 策略

**v0.2**：
- redb 持久化
- 异常值限幅
- 完整 rationale

**v0.3**：
- metrics 集成
- 性能调优（按 benchmark 结果）

**v1.0**：
- API 冻结
- 文档完善
- 发布到 crates.io

## 十三、开放问题（待讨论）

1. **`local_ip` 的语义**：统一为"实际用于连接的 source IP"，由调用方在连接成功后从 `socket.local_addr()` 取，但首次连接前调用方可能只能猜（用路由表查询）。两种值都接受，命中即可。

2. **IPv6 隐私扩展地址的处理**：iOS/macOS 的 IPv6 出口 IP 会定期轮换，可能造成数据碎片化。需要把 `local_ip` 折叠到子网前缀（如 `/64`）

