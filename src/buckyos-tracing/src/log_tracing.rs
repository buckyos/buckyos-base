use buckyos_kit::get_buckyos_log_dir;
use tracing_subscriber::filter;
use tracing_subscriber::{prelude::*, EnvFilter};

pub fn init_tracing(app_name: &str, is_service: bool) -> impl Drop {
    let pid = std::process::id();
    let log_dir = get_buckyos_log_dir(app_name, is_service);
    std::fs::create_dir_all(&log_dir).unwrap();

    let name = if is_service {
        format!("{app_name}_{pid}.log")
    } else {
        format!("{app_name}.log")
    };
    let log_file = log_dir.join(name);

    // tokio-console 层（后台采样）
    // 1) console layer（必须在建 runtime 前）
    let console_layer = console_subscriber::ConsoleLayer::builder()
        .with_default_env()
        .spawn(); // ← 返回 impl Layer<_>，不是 tuple

    // 文件日志切割
    let file_appender = tracing_appender::rolling::daily(&log_dir, log_file.file_name().unwrap());
    // guard 需要返回避免drop
    let (file_writer, guard) = tracing_appender::non_blocking(file_appender);

    // 3) 全局过滤器：打开 tokio 的 trace（给 tokio-console 用），其他默认 info
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,tokio=trace,runtime=trace"));

    // 4) 终端层：按全局过滤器
    let stdout_layer = tracing_subscriber::fmt::layer()
        .with_target(false)
        .with_ansi(true);

    // 5) 文件层：只写入“恰好 INFO”的事件（不含 WARN/ERROR/DEBUG/TRACE）
    let only_info = filter::filter_fn(|meta| meta.level() == &tracing::Level::INFO);
    let file_layer = tracing_subscriber::fmt::layer()
        .with_target(false)
        .with_ansi(false)
        .with_writer(file_writer)
        .with_filter(only_info);

    tracing_subscriber::registry()
        // 决定哪些事件进入管道（给 console 层留足 tokio=trace）
        .with(env_filter)
        // tokio-console
        .with(console_layer)
        // 终端输出（受 env_filter 控制）
        .with(stdout_layer)
        // 文件输出（再按 only_info 二次过滤）
        .with(file_layer)
        .init();

    tracing::info!("buckyos tracing init");
    guard
}
