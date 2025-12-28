use buckyos_tracing::{init_rotating_tracing, RotatingLogConfig};
use tracing::{debug, error, info, warn};

fn main() {
    // 方式1: 使用默认配置
    // let config = RotatingLogConfig::new("my_app");

    // 方式2: 自定义配置
    let config = RotatingLogConfig::new("my_app")
        .max_file_size(5 * 1024 * 1024) // 单个文件最大 5MB
        .max_files(10) // 最多保留 10 个历史文件
        .is_service(true) // 服务模式
        .current_name("current.log"); // 当前日志文件名

    // 初始化日志系统
    init_rotating_tracing(config).expect("Failed to initialize logger");

    // 使用日志
    info!("Application started, PID: {}", std::process::id());
    debug!("This is a debug message");
    warn!("This is a warning message");
    error!("This is an error message");

    // 模拟大量日志输出，触发轮转
    for i in 0..1000 {
        info!("Log message #{}: {}", i, "a".repeat(1000));
        std::thread::sleep(std::time::Duration::from_millis(10));
    }

    info!("Application finished");
}

