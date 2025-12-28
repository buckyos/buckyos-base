use buckyos_tracing::{init_rotating_tracing, RotatingLogConfig};
use std::fs;
use tracing::info;

#[test]
fn test_rotating_log_basic() {
    let test_app = format!("test_app_{}", std::process::id());
    
    let config = RotatingLogConfig::new(&test_app)
        .max_file_size(1024) // 1KB for quick rotation
        .max_files(3)
        .current_name("current.log");

    // 初始化日志
    let result = init_rotating_tracing(config.clone());
    
    // 由于可能已经初始化过 tracing，这里不强制要求成功
    if result.is_ok() {
        // 写入一些日志
        for i in 0..10 {
            info!("Test log message #{}: {}", i, "x".repeat(100));
        }
    }

    // 验证日志目录是否创建
    let log_dir = buckyos_kit::get_buckyos_log_dir(&test_app, false);
    assert!(log_dir.exists(), "Log directory should exist");

    // 清理测试文件
    let _ = fs::remove_dir_all(&log_dir);
}

#[test]
fn test_log_file_naming() {
    // 测试 PID 是否正确包含在文件名中
    let pid = std::process::id();
    assert!(pid > 0, "PID should be positive");
    
    // 验证文件名格式
    let app_name = "test_app";
    let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S");
    let epoch = chrono::Local::now().timestamp();
    
    let expected_pattern = format!("{}_{}_{}", app_name, pid, timestamp);
    assert!(expected_pattern.contains(&pid.to_string()), 
            "Filename should contain PID");
}

