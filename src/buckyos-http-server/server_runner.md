## 需求

`buckyos-http-server` 提供一个轻量级 `Runner`，会监听一个 HTTP（无 TLS）端口，把实现了 `HttpServer` 的实例跑起来。应用只需要关心自己的 `HttpServer` 实现，即可快速构建出一个可独立运行、二进制尽量小的进程。

## 使用示例

```rust
use std::sync::Arc;

use buckyos_http_server::{DirHandlerOptions, HttpServer, Runner, ServerResult};

#[tokio::main]
async fn main() -> ServerResult<()> {
    let runner = Runner::new(3180);
    let app_http_server: Arc<dyn HttpServer> = app::create_http_server();

    runner.add_http_server("/".to_string(), app_http_server)?;
    runner
        .add_dir_handler_with_options(
            "/".to_string(),
            std::path::PathBuf::from("./web"),
            DirHandlerOptions {
                fallback_file: Some("index.html".to_string()),
                ..Default::default()
            },
        )
        .await?;
    runner.start()
}
```

`Runner::add_http_server` 需要一个 `Arc<dyn HttpServer>`；如果手头只有结构体实例，请自行包上一层 `Arc::new(...)`。`Runner::start` 会在后台启动监听任务。

`Runner::add_dir_handler_with_options` 可指定 `fallback_file`，用于 SPA 场景：当静态文件不存在时回退到指定文件（通常是 `index.html`）。
