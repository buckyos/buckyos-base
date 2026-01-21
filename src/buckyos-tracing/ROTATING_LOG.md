# 轮转日志系统使用说明

## 功能特性

实现了一个满足以下需求的日志轮转系统：

1. ✅ **固定名称的当前日志文件**：每次启动都写入名为 `current.log` 的文件（可自定义）
2. ✅ **大小限制和自动清理**：可设定单个文件最大大小和文件总数，满了会自动轮转并删除最老的文件
3. ✅ **历史文件包含 PID**：归档文件名格式为 `appname_pid_timestamp_epoch.log`，方便识别重启

## 快速开始

### 基本用法

```rust
use buckyos_tracing::{init_rotating_tracing, RotatingLogConfig};
use tracing::info;

fn main() {
    // 创建配置
    let config = RotatingLogConfig::new("my_app")
        .max_file_size(10 * 1024 * 1024)  // 单个文件最大 10MB
        .max_files(10)                     // 最多保留 10 个历史文件
        .is_service(true)                  // 服务模式
        .current_name("current.log");      // 当前日志文件名

    // 初始化日志系统
    init_rotating_tracing(config).expect("Failed to initialize logger");

    // 使用日志
    info!("Application started, PID: {}", std::process::id());
}
```

## 配置选项

### RotatingLogConfig

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `app_name` | String | "app" | 应用名称，用于日志目录和文件名 |
| `is_service` | bool | false | 是否为服务模式 |
| `max_file_size` | u64 | 10MB | 单个日志文件最大大小（字节） |
| `max_files` | usize | 10 | 最多保留的历史日志文件数 |
| `current_name` | String | "current.log" | 当前日志文件名 |

### Builder 方法

```rust
let config = RotatingLogConfig::new("my_app")
    .max_file_size(5 * 1024 * 1024)    // 设置单文件大小为 5MB
    .max_files(20)                      // 保留 20 个历史文件
    .is_service(true)                   // 启用服务模式
    .current_name("service.log");       // 自定义当前日志文件名
```

## 日志文件结构

### 日志目录

- **非服务模式**：`~/.buckyos/my_app/log/`
- **服务模式**：具体路径由 `get_buckyos_log_dir()` 决定

### 文件命名规则

1. **当前日志文件**：`current.log`（或自定义名称）
   - 始终写入此文件
   - 达到大小限制时会被归档

2. **归档日志文件**：`my_app_12345_20231227_143025_1703666225.log`
   - 格式：`{app_name}_{pid}_{date}_{time}_{epoch}.log`
   - `12345`：进程 PID，方便识别是否重启
   - `20231227_143025`：归档时间戳
   - `1703666225`：Unix epoch 时间戳，确保唯一性

### 示例文件列表

```
~/.buckyos/my_app/log/
├── current.log                                    # 当前日志
├── my_app_12345_20231227_100000_1703635200.log   # PID 12345 的历史日志
├── my_app_12345_20231227_110000_1703638800.log   
├── my_app_12346_20231227_120000_1703642400.log   # PID 12346（重启后）
└── my_app_12346_20231227_130000_1703646000.log   
```

## 工作原理

### 日志轮转流程

1. **写入检测**：每次写入前检查当前文件大小
2. **触发轮转**：如果 `当前大小 + 待写入大小 > max_file_size`，触发轮转
3. **归档当前文件**：
   - 关闭当前文件
   - 重命名为带 PID 和时间戳的归档文件名
4. **清理旧文件**：
   - 列出所有归档文件
   - 按修改时间排序
   - 删除超过 `max_files` 限制的最老文件
5. **创建新文件**：创建新的 `current.log`

### 线程安全

使用 `Arc<Mutex<>>` 确保多线程环境下的写入安全。

## 高级用法

### 结合环境变量控制日志级别

```rust
// 支持通过 RUST_LOG 环境变量控制级别
// export RUST_LOG=debug
// export RUST_LOG=my_app=trace,other_crate=warn

let config = RotatingLogConfig::new("my_app");
init_rotating_tracing(config).expect("Failed to init logger");
```

### 在服务中使用

```rust
use buckyos_tracing::{init_rotating_tracing, RotatingLogConfig};

fn main() {
    // 服务模式：日志文件会包含 PID
    let config = RotatingLogConfig::new("my_service")
        .is_service(true)
        .max_file_size(50 * 1024 * 1024)  // 50MB
        .max_files(30);                    // 保留 30 个文件

    init_rotating_tracing(config).unwrap();

    // 启动服务...
}
```

## 与现有日志系统的比较

### vs `simplelog`
- ❌ `simplelog` 不支持自动轮转
- ❌ 不支持大小限制
- ✅ 本方案支持完整的轮转和清理功能

### vs `tracing-appender::rolling::daily`
- ❌ `daily` 只支持按天轮转
- ❌ 不支持大小限制
- ❌ 不会自动清理旧文件
- ✅ 本方案按大小轮转，自动清理

### vs `flexi_logger`
- ✅ `flexi_logger` 功能强大但是不使用 `tracing`
- ✅ 本方案与 `tracing` 生态完美集成

## 示例运行

```bash
# 运行示例
cd src/buckyos-tracing
cargo run --example rotating_log_example

# 查看生成的日志文件
ls -lh ~/.buckyos/my_app/log/
```

## 注意事项

1. **性能考虑**：每次写入都会检查文件大小，对于极高频的日志可能有轻微性能影响
2. **磁盘空间**：确保 `max_file_size * max_files` 不超过可用磁盘空间
3. **PID 重用**：在极少数情况下，系统可能重用 PID，但加入时间戳可以避免冲突
4. **并发写入**：使用了 Mutex 保护，高并发场景可能有锁竞争

## 故障排查

### 日志文件没有轮转
- 检查 `max_file_size` 是否设置过大
- 确认日志内容已经超过限制大小

### 旧文件没有被删除
- 检查 `max_files` 配置
- 确认文件权限允许删除操作
- 查看标准错误输出中的删除失败信息

### 找不到日志文件
- 检查 `get_buckyos_log_dir()` 返回的路径
- 确认目录创建成功（需要写权限）

