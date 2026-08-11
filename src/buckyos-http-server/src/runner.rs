use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use buckyos_kit::AsyncStream;
use http_body_util::combinators::BoxBody;
use http_body_util::BodyExt;
use hyper::body::Bytes;
use log::{debug, error, info};
use tokio::net::{TcpListener, TcpStream};

use crate::{
    hyper_serve_http, server_err, DirServer, HttpServer, ServerError, ServerErrorCode,
    ServerResult, StreamInfo,
};

#[derive(Clone)]
struct Router {
    routes: Arc<RwLock<Vec<(String, Arc<dyn HttpServer>)>>>,
}

impl Router {
    fn new() -> Self {
        Self {
            routes: Arc::new(RwLock::new(Vec::new())),
        }
    }

    fn add_route(&self, path: String, server: Arc<dyn HttpServer>) {
        let mut routes = self.routes.write().unwrap();
        routes.push((normalize_route(path), server));
        routes.sort_by(|(a, _), (b, _)| b.len().cmp(&a.len()));
    }
}

#[async_trait::async_trait]
impl HttpServer for Router {
    async fn serve_request(
        &self,
        req: http::Request<BoxBody<Bytes, ServerError>>,
        info: StreamInfo,
    ) -> ServerResult<http::Response<BoxBody<Bytes, ServerError>>> {
        let path = req.uri().path().to_string();
        let routes = self.routes.read().unwrap().clone();
        let src_addr = info.src_addr.as_deref().unwrap_or("unknown");
        info!("{}=>{} {}", src_addr, req.method(), path);

        for (prefix, server) in routes {
            debug!("try match router: {}", prefix);
            if route_matches(&path, &prefix) {
                debug!(" {} match router: {}", path, prefix);
                return server.serve_request(req, info).await;
            }
        }

        http::Response::builder()
            .status(http::StatusCode::NOT_FOUND)
            .body(
                http_body_util::Full::new(Bytes::from("No Router Found"))
                    .map_err(|e| match e {})
                    .boxed(),
            )
            .map_err(|e| server_err!(ServerErrorCode::InvalidData, "{}", e))
    }

    fn id(&self) -> String {
        "router".to_string()
    }

    fn http_version(&self) -> http::Version {
        http::Version::HTTP_11
    }

    fn http3_port(&self) -> Option<u16> {
        None
    }
}

#[derive(Clone)]
pub struct Runner {
    bind_addr: SocketAddr,
    router: Router,
}

#[derive(Clone, Default)]
pub struct DirHandlerOptions {
    pub index_file: Option<String>,
    pub fallback_file: Option<String>,
}

impl Runner {
    pub fn new(port: u16) -> Self {
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port));
        Self::with_addr(addr)
    }

    pub fn with_addr(addr: SocketAddr) -> Self {
        Self {
            bind_addr: addr,
            router: Router::new(),
        }
    }

    pub fn bind_addr(&self) -> SocketAddr {
        self.bind_addr
    }

    pub fn add_http_server(
        &self,
        router_url: String,
        server: Arc<dyn HttpServer>,
    ) -> ServerResult<()> {
        self.router.add_route(router_url, server);
        Ok(())
    }

    pub async fn add_dir_handler(&self, router_url: String, dir: PathBuf) -> ServerResult<()> {
        self.add_dir_handler_with_options(router_url, dir, DirHandlerOptions::default())
            .await
    }

    pub async fn add_dir_handler_with_options(
        &self,
        router_url: String,
        dir: PathBuf,
        options: DirHandlerOptions,
    ) -> ServerResult<()> {
        let mut builder = DirServer::builder()
            .id(router_url.clone())
            .root_path(dir)
            .base_url(router_url.clone());

        if let Some(index_file) = options.index_file {
            builder = builder.index_file(index_file);
        }

        if let Some(fallback_file) = options.fallback_file {
            builder = builder.fallback_file(fallback_file);
        }

        let dir_server = builder.build().await?;
        self.router.add_route(router_url, Arc::new(dir_server));
        Ok(())
    }

    pub fn start(self) -> ServerResult<()> {
        tokio::spawn(async move {
            let _ = self.run().await;
        });
        Ok(())
    }

    pub async fn run(&self) -> ServerResult<()> {
        let listener = TcpListener::bind(self.bind_addr)
            .await
            .map_err(|e| server_err!(ServerErrorCode::BindFailed, "{}", e))?;

        let local_addr = listener.local_addr().unwrap_or(self.bind_addr);
        info!("buckyos-http-server runner listening on {}", local_addr);

        loop {
            let (stream, peer_addr) = match listener.accept().await {
                Ok(ret) => ret,
                Err(e) => {
                    error!("failed to accept tcp connection: {}", e);
                    continue;
                }
            };

            let server = Arc::new(self.router.clone());
            tokio::spawn(async move {
                if let Err(err) = serve_tcp_stream(stream, server, peer_addr).await {
                    error!("failed to serve {}: {:?}", peer_addr, err);
                }
            });
        }
    }
}

async fn serve_tcp_stream(
    stream: TcpStream,
    server: Arc<dyn HttpServer>,
    peer_addr: SocketAddr,
) -> ServerResult<()> {
    let info = StreamInfo::new(peer_addr.to_string());
    let stream: Box<dyn AsyncStream> = Box::new(stream);
    hyper_serve_http(stream, server, info).await
}

fn normalize_route(route: String) -> String {
    if route.is_empty() {
        return "/".to_string();
    }

    if route.starts_with('/') {
        route
    } else {
        format!("/{route}")
    }
}

fn route_matches(path: &str, route: &str) -> bool {
    if route == "/" {
        return path.starts_with('/');
    }

    path == route.trim_end_matches('/') || path.starts_with(route)
}

#[cfg(test)]
mod tests {
    use super::*;

    use http::{Response, StatusCode};
    use http_body_util::combinators::BoxBody;
    use http_body_util::{BodyExt, Full};
    use hyper::body::Bytes;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    struct DummyHttpServer(String);

    #[async_trait::async_trait]
    impl HttpServer for DummyHttpServer {
        async fn serve_request(
            &self,
            _req: http::Request<BoxBody<Bytes, ServerError>>,
            _info: StreamInfo,
        ) -> ServerResult<http::Response<BoxBody<Bytes, ServerError>>> {
            let body_content = format!("runner-ok-{}", self.0);
            let mut resp = Response::new(
                Full::new(Bytes::from(body_content))
                    .map_err(|e| match e {})
                    .boxed(),
            );
            *resp.status_mut() = StatusCode::OK;
            Ok(resp)
        }

        fn id(&self) -> String {
            "dummy".to_string()
        }

        fn http_version(&self) -> http::Version {
            http::Version::HTTP_11
        }

        fn http3_port(&self) -> Option<u16> {
            None
        }
    }

    fn random_loopback() -> SocketAddr {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        addr
    }

    #[tokio::test]
    async fn can_add_multiple_servers() {
        let runner = Runner::new(0);
        runner
            .add_http_server("/a".to_string(), Arc::new(DummyHttpServer("a".into())))
            .unwrap();
        let res = runner.add_http_server("/b".to_string(), Arc::new(DummyHttpServer("b".into())));
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn serves_basic_http_request() {
        let addr = random_loopback();
        let runner = Runner::with_addr(addr);
        runner
            .add_http_server("/".to_string(), Arc::new(DummyHttpServer("root".into())))
            .unwrap();

        let runner_handle = runner.clone();
        let server_task = tokio::spawn(async move {
            let _ = runner_handle.run().await;
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let mut client = TcpStream::connect(addr).await.unwrap();
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();

        let mut buf = vec![0u8; 256];
        let n = client.read(&mut buf).await.unwrap();
        let text = String::from_utf8_lossy(&buf[..n]);
        assert!(text.contains("200 OK"), "{text}");
        assert!(text.contains("runner-ok-root"), "{text}");

        server_task.abort();
        let _ = server_task.await;
    }

    #[tokio::test]
    async fn serves_dir_request() {
        let addr = random_loopback();
        let runner = Runner::with_addr(addr);

        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("test.txt");
        tokio::fs::write(&file_path, b"file-content").await.unwrap();

        runner
            .add_dir_handler("/static".to_string(), temp_dir.path().to_path_buf())
            .await
            .unwrap();

        let runner_handle = runner.clone();
        let server_task = tokio::spawn(async move {
            let _ = runner_handle.run().await;
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let mut client = TcpStream::connect(addr).await.unwrap();
        client
            .write_all(b"GET /static/test.txt HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();

        let mut buf = vec![0u8; 1024];
        let mut text = String::new();

        loop {
            let n = client.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            text.push_str(&String::from_utf8_lossy(&buf[..n]));
            if text.contains("file-content") || text.len() > 4096 {
                break;
            }
        }

        assert!(text.contains("200 OK"), "{text}");
        assert!(text.contains("file-content"), "{text}");

        server_task.abort();
        let _ = server_task.await;
    }
}
