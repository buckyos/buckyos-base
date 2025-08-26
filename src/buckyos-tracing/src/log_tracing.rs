use buckyos_kit::get_buckyos_log_dir;
use tracing_subscriber::prelude::*;

pub async fn init_tracing(app_name: &str, is_service: bool) {
    // get log level in env RUST_LOG, default is info
    let log_level = std::env::var("BUCKY_LOG").unwrap_or_else(|_| "info".to_string());

    let pid = std::process::id();
    let log_dir = get_buckyos_log_dir(app_name, is_service);
    std::fs::create_dir_all(&log_dir).unwrap();

    let log_file = if is_service {
        &log_dir.join(format!("{}_{}.log", app_name, pid)) // log_file in target dir, with pid
    } else {
        &log_dir.join(format!("{}.log", app_name))
    };

    // tokio-console 层（后台采样）
    let console_layer = console_subscriber::ConsoleLayer::builder()
        .with_default_env()
        .spawn(); // ← 返回 impl Layer<_>，不是 tuple

    let file_appender = tracing_appender::rolling::daily(&log_dir, log_file.file_name().unwrap());
    let (file_writer, _guard) = tracing_appender::non_blocking(file_appender);

    // 3) 可选：环境变量控制日志级别（未设置则默认 info）
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| log_level.clone().into());

    tracing_subscriber::registry()
        .with(env_filter)
        .with(console_layer)
        .with(
            tracing_subscriber::fmt::layer()
                .with_target(false)
                .with_ansi(true),
        )
        // 文件输出（禁用颜色，指定 writer）
        .with(
            tracing_subscriber::fmt::layer()
                .with_target(false)
                .with_ansi(false)
                .with_writer(file_writer),
        )
        .init();

    tracing::info!("buckyos tracing log level: {}", log_level.clone());
}
