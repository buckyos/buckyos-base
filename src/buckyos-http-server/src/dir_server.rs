use crate::{server_err, HttpServer, ServerError, ServerErrorCode, ServerResult, StreamInfo};
use chrono::{DateTime, Local};
use futures_util::TryStreamExt;
use http::{StatusCode, Version};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::{Bytes, Frame};
use hyper::header::{ETAG, IF_MODIFIED_SINCE, IF_NONE_MATCH, LAST_MODIFIED, RANGE};
use log::{debug, info, warn};
use percent_encoding::{utf8_percent_encode, AsciiSet, CONTROLS};
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::AsyncReadExt;

const PATH_SEGMENT_ENCODE_SET: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'<')
    .add(b'>')
    .add(b'?')
    .add(b'`')
    .add(b'{')
    .add(b'}')
    .add(b'/');

/// DirServer Builder for fluent configuration
pub struct DirServerBuilder {
    id: Option<String>,
    version: Option<String>,
    root_path: Option<PathBuf>,
    index_file: Option<String>,
    fallback_file: Option<String>,
    base_url: Option<String>,
    autoindex: bool,
    etag: Option<bool>,
    if_modified_since: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum IfModifiedSinceMode {
    Off,
    Exact,
    Before,
}

impl IfModifiedSinceMode {
    fn parse(mode: &str) -> Option<Self> {
        match mode {
            "off" => Some(Self::Off),
            "exact" => Some(Self::Exact),
            "before" => Some(Self::Before),
            _ => None,
        }
    }
}

impl DirServerBuilder {
    pub fn id(mut self, id: impl Into<String>) -> Self {
        self.id = Some(id.into());
        self
    }

    pub fn version(mut self, version: impl Into<String>) -> Self {
        self.version = Some(version.into());
        self
    }

    pub fn root_path(mut self, root_path: impl Into<PathBuf>) -> Self {
        self.root_path = Some(root_path.into());
        self
    }

    pub fn index_file(mut self, index_file: impl Into<String>) -> Self {
        self.index_file = Some(index_file.into());
        self
    }

    pub fn fallback_file(mut self, fallback_file: impl Into<String>) -> Self {
        self.fallback_file = Some(fallback_file.into());
        self
    }

    pub fn base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = Some(base_url.into());
        self
    }

    pub fn autoindex(mut self, autoindex: bool) -> Self {
        self.autoindex = autoindex;
        self
    }

    pub fn etag(mut self, etag: bool) -> Self {
        self.etag = Some(etag);
        self
    }

    pub fn if_modified_since(mut self, mode: impl Into<String>) -> Self {
        self.if_modified_since = Some(mode.into());
        self
    }

    pub async fn build(self) -> ServerResult<DirServer> {
        DirServer::create_server(self).await
    }
}

/// DirServer - A simple HTTP server that serves files from a local directory
pub struct DirServer {
    id: String,
    version: http::Version,
    root_dir: PathBuf,
    index_file: String,
    fallback_file: Option<String>,
    base_url: String,
    autoindex: bool,
    etag: bool,
    if_modified_since: IfModifiedSinceMode,
}

impl DirServer {
    pub fn builder() -> DirServerBuilder {
        DirServerBuilder {
            id: None,
            version: None,
            root_path: None,
            index_file: None,
            fallback_file: None,
            base_url: None,
            autoindex: false,
            etag: None,
            if_modified_since: None,
        }
    }

    async fn create_server(builder: DirServerBuilder) -> ServerResult<DirServer> {
        if builder.id.is_none() {
            return Err(server_err!(
                ServerErrorCode::InvalidConfig,
                "id is required"
            ));
        }

        if builder.root_path.is_none() {
            return Err(server_err!(
                ServerErrorCode::InvalidConfig,
                "root_path is required"
            ));
        }

        let root_path = builder.root_path.unwrap();
        if !root_path.exists() {
            return Err(server_err!(
                ServerErrorCode::InvalidConfig,
                "root_path does not exist: {:?}",
                root_path
            ));
        }

        if !root_path.is_dir() {
            return Err(server_err!(
                ServerErrorCode::InvalidConfig,
                "root_path is not a directory: {:?}",
                root_path
            ));
        }

        let version: http::Version = match builder.version {
            Some(ref version) => match version.as_str() {
                "HTTP/0.9" => http::Version::HTTP_09,
                "HTTP/1.0" => http::Version::HTTP_10,
                "HTTP/1.1" => http::Version::HTTP_11,
                "HTTP/2" => http::Version::HTTP_2,
                "HTTP/3" => http::Version::HTTP_3,
                _ => {
                    return Err(server_err!(
                        ServerErrorCode::InvalidConfig,
                        "invalid http version"
                    ));
                }
            },
            None => http::Version::HTTP_11,
        };

        let index_file = builder
            .index_file
            .unwrap_or_else(|| "index.html".to_string());
        let etag = builder.etag.unwrap_or(true);
        let if_modified_since = match builder.if_modified_since {
            Some(mode) => IfModifiedSinceMode::parse(mode.as_str()).ok_or_else(|| {
                server_err!(
                    ServerErrorCode::InvalidConfig,
                    "invalid if_modified_since: {}, expected one of off|exact|before",
                    mode
                )
            })?,
            None => IfModifiedSinceMode::Exact,
        };
        let fallback_file = if let Some(fallback_file) = builder.fallback_file {
            let fallback_path = Path::new(&fallback_file);
            if fallback_path.is_absolute() {
                return Err(server_err!(
                    ServerErrorCode::InvalidConfig,
                    "fallback_file must be a relative path"
                ));
            }
            if fallback_path
                .components()
                .any(|c| matches!(c, Component::ParentDir))
            {
                return Err(server_err!(
                    ServerErrorCode::InvalidConfig,
                    "fallback_file must not contain '..'"
                ));
            }
            Some(fallback_file)
        } else {
            None
        };
        let new_root_dir = root_path.canonicalize().map_err(|e| {
            server_err!(
                ServerErrorCode::IOError,
                "Failed to canonicalize path: {}",
                e
            )
        })?;
        debug!("after normalize,root_dir is : {:?}", new_root_dir);
        Ok(DirServer {
            id: builder.id.unwrap(),
            version,
            root_dir: new_root_dir,
            index_file,
            fallback_file,
            base_url: builder.base_url.unwrap_or_else(|| "/".to_string()),
            autoindex: builder.autoindex,
            etag,
            if_modified_since,
        })
    }

    fn format_http_date(st: SystemTime) -> String {
        httpdate::fmt_http_date(st)
    }

    fn normalize_etag_tag(token: &str) -> &str {
        let token = token.trim();
        if let Some(stripped) = token.strip_prefix("W/") {
            stripped.trim()
        } else {
            token
        }
    }

    fn etag_matches_if_none_match(current_etag: Option<&str>, if_none_match: &str) -> bool {
        let current_etag = match current_etag {
            Some(etag) => etag,
            None => return false,
        };

        let target = Self::normalize_etag_tag(current_etag);
        if_none_match
            .split(',')
            .map(str::trim)
            .any(|item| item == "*" || Self::normalize_etag_tag(item) == target)
    }

    fn compare_if_modified_since(
        &self,
        last_modified: SystemTime,
        if_modified_since: &str,
    ) -> bool {
        let since = match httpdate::parse_http_date(if_modified_since) {
            Ok(t) => t,
            Err(_) => return false,
        };

        let mtime_secs = last_modified
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        let since_secs = since
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();

        match self.if_modified_since {
            IfModifiedSinceMode::Off => false,
            IfModifiedSinceMode::Exact => mtime_secs == since_secs,
            IfModifiedSinceMode::Before => mtime_secs <= since_secs,
        }
    }

    fn request_not_modified(
        &self,
        req: &http::Request<BoxBody<Bytes, ServerError>>,
        current_etag: Option<&str>,
        last_modified: Option<SystemTime>,
    ) -> bool {
        let if_none_match = req
            .headers()
            .get(IF_NONE_MATCH)
            .and_then(|v| v.to_str().ok());

        if let Some(if_none_match) = if_none_match {
            return Self::etag_matches_if_none_match(current_etag, if_none_match);
        }

        let if_modified_since = req
            .headers()
            .get(IF_MODIFIED_SINCE)
            .and_then(|v| v.to_str().ok());

        if let (Some(last_modified), Some(if_modified_since)) = (last_modified, if_modified_since) {
            return self.compare_if_modified_since(last_modified, if_modified_since);
        }

        false
    }

    fn build_etag(file_meta: &std::fs::Metadata) -> Option<String> {
        let modified = file_meta.modified().ok()?;
        let dur = modified.duration_since(UNIX_EPOCH).ok()?;
        Some(format!(
            "\"{:x}-{:x}-{:x}\"",
            file_meta.len(),
            dur.as_secs(),
            dur.subsec_nanos()
        ))
    }

    /// Parse Range header (e.g., "bytes=start-end")
    fn parse_range(&self, range: &str, file_size: u64) -> ServerResult<(u64, u64)> {
        let range = range.trim_start_matches("bytes=");
        let mut parts = range.split('-');

        let start = parts
            .next()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);

        let end = parts
            .next()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(file_size - 1);

        // Validate range
        if start >= file_size || end >= file_size || start > end {
            return Err(server_err!(ServerErrorCode::InvalidParam, "Invalid range"));
        }

        Ok((start, end))
    }

    /// Serve a file from the local directory
    async fn serve_file(
        &self,
        file_path: &Path,
        req: &http::Request<BoxBody<Bytes, ServerError>>,
    ) -> ServerResult<http::Response<BoxBody<Bytes, ServerError>>> {
        let file = tokio::fs::File::open(&file_path).await.map_err(|e| {
            warn!("Failed to open file: {:?}, error: {}", file_path, e);
            server_err!(ServerErrorCode::IOError, "Failed to open file: {}", e)
        })?;

        let file_meta = file.metadata().await.map_err(|e| {
            warn!("Failed to get file metadata: {:?}, error: {}", file_path, e);
            server_err!(
                ServerErrorCode::IOError,
                "Failed to get file metadata: {}",
                e
            )
        })?;

        let file_size = file_meta.len();
        let mime_type = mime_guess::from_path(&file_path).first_or_octet_stream();
        let last_modified = file_meta.modified().ok();
        let etag = if self.etag {
            Self::build_etag(&file_meta)
        } else {
            None
        };

        if self.request_not_modified(&req, etag.as_deref(), last_modified) {
            let mut response_builder = http::Response::builder().status(StatusCode::NOT_MODIFIED);
            if let Some(etag) = etag.as_ref() {
                response_builder = response_builder.header(ETAG, etag.as_str());
            }
            if let Some(last_modified) = last_modified {
                let formatted = Self::format_http_date(last_modified);
                response_builder = response_builder.header(LAST_MODIFIED, formatted);
            }

            return response_builder
                .body(Full::new(Bytes::new()).map_err(|e| match e {}).boxed())
                .map_err(|e| {
                    server_err!(ServerErrorCode::IOError, "Failed to build response: {}", e)
                });
        }

        // Handle Range requests
        if let Some(range_header) = req.headers().get(RANGE) {
            if let Ok(range_str) = range_header.to_str() {
                if let Ok((start, end)) = self.parse_range(range_str, file_size) {
                    let mut file = tokio::io::BufReader::new(file);
                    // Seek to the start position
                    use tokio::io::AsyncSeekExt;
                    file.seek(std::io::SeekFrom::Start(start))
                        .await
                        .map_err(|e| {
                            server_err!(ServerErrorCode::IOError, "Failed to seek file: {}", e)
                        })?;

                    let content_length = end - start + 1;
                    // Take only the content_length bytes
                    let limited_reader = file.take(content_length);
                    let stream = tokio_util::io::ReaderStream::with_capacity(
                        limited_reader,
                        content_length as usize,
                    );
                    let stream_body = StreamBody::new(stream.map_ok(Frame::data));

                    let mut response_builder = http::Response::builder()
                        .status(StatusCode::PARTIAL_CONTENT)
                        .header("Content-Type", mime_type.as_ref())
                        .header("Content-Length", content_length)
                        .header(
                            "Content-Range",
                            format!("bytes {}-{}/{}", start, end, file_size),
                        )
                        .header("Accept-Ranges", "bytes");

                    if let Some(etag) = etag.as_ref() {
                        response_builder = response_builder.header(ETAG, etag.as_str());
                    }
                    if let Some(last_modified) = last_modified {
                        let formatted = Self::format_http_date(last_modified);
                        response_builder = response_builder.header(LAST_MODIFIED, formatted);
                    }

                    return Ok(response_builder
                        .body(
                            BodyExt::map_err(stream_body, |e| {
                                ServerError::new(
                                    ServerErrorCode::StreamError,
                                    format!("Stream error: {}", e),
                                )
                            })
                            .boxed(),
                        )
                        .map_err(|e| {
                            server_err!(ServerErrorCode::IOError, "Failed to build response: {}", e)
                        })?);
                }
            }
        }

        // Non-Range request: return full file
        let stream = tokio_util::io::ReaderStream::with_capacity(file, file_size as usize);
        let stream_body = StreamBody::new(stream.map_ok(Frame::data));

        let mut response_builder = http::Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", mime_type.as_ref())
            .header("Content-Length", file_size)
            .header("Accept-Ranges", "bytes");

        if let Some(etag) = etag.as_ref() {
            response_builder = response_builder.header(ETAG, etag.as_str());
        }
        if let Some(last_modified) = last_modified {
            let formatted = Self::format_http_date(last_modified);
            response_builder = response_builder.header(LAST_MODIFIED, formatted);
        }

        Ok(response_builder
            .body(
                BodyExt::map_err(stream_body, |e| {
                    ServerError::new(ServerErrorCode::StreamError, format!("Stream error: {}", e))
                })
                .boxed(),
            )
            .map_err(|e| {
                server_err!(ServerErrorCode::IOError, "Failed to build response: {}", e)
            })?)
    }

    fn resolve_path(&self, req_path: &str) -> ServerResult<PathBuf> {
        let stripped = req_path.strip_prefix(&self.base_url).unwrap_or(req_path);
        let sub_path = stripped.trim_start_matches('/');
        let mut path = self.root_dir.clone();

        for component in Path::new(sub_path).components() {
            match component {
                Component::CurDir => {}
                Component::Normal(part) => path.push(part),
                Component::ParentDir => {
                    return Err(server_err!(
                        ServerErrorCode::InvalidParam,
                        "path traversal is not allowed"
                    ));
                }
                Component::RootDir | Component::Prefix(_) => {}
            }
        }

        Ok(path)
    }

    fn build_text_response(
        &self,
        status: StatusCode,
        body: impl Into<Bytes>,
    ) -> http::Response<BoxBody<Bytes, ServerError>> {
        http::Response::builder()
            .status(status)
            .body(Full::new(body.into()).map_err(|e| match e {}).boxed())
            .unwrap()
    }

    fn build_html_response(
        &self,
        status: StatusCode,
        body: String,
    ) -> http::Response<BoxBody<Bytes, ServerError>> {
        http::Response::builder()
            .status(status)
            .header("Content-Type", "text/html; charset=utf-8")
            .body(Full::new(Bytes::from(body)).map_err(|e| match e {}).boxed())
            .unwrap()
    }

    fn ensure_path_in_root(&self, path: &Path) -> ServerResult<PathBuf> {
        let canonical_path = path.canonicalize().map_err(|e| {
            server_err!(
                ServerErrorCode::IOError,
                "Failed to canonicalize path: {}",
                e
            )
        })?;
        if !canonical_path.starts_with(&self.root_dir) {
            return Err(server_err!(
                ServerErrorCode::InvalidParam,
                "path out of root directory"
            ));
        }
        Ok(canonical_path)
    }

    fn escape_html(input: &str) -> String {
        let mut escaped = String::with_capacity(input.len());
        for ch in input.chars() {
            match ch {
                '&' => escaped.push_str("&amp;"),
                '<' => escaped.push_str("&lt;"),
                '>' => escaped.push_str("&gt;"),
                '"' => escaped.push_str("&quot;"),
                '\'' => escaped.push_str("&#39;"),
                _ => escaped.push(ch),
            }
        }
        escaped
    }

    fn format_modified_time(st: std::time::SystemTime) -> String {
        let dt: DateTime<Local> = st.into();
        dt.format("%d-%b-%Y %H:%M").to_string()
    }

    async fn serve_directory_listing(
        &self,
        req_path: &str,
        dir_path: &Path,
    ) -> ServerResult<http::Response<BoxBody<Bytes, ServerError>>> {
        struct Entry {
            name: String,
            href: String,
            is_dir: bool,
            modified: String,
            size: String,
        }

        let mut entries = Vec::new();
        let mut read_dir = tokio::fs::read_dir(dir_path).await.map_err(|e| {
            server_err!(ServerErrorCode::IOError, "Failed to read directory: {}", e)
        })?;

        let req_base = if req_path.ends_with('/') {
            req_path.to_string()
        } else {
            format!("{}/", req_path)
        };

        while let Some(entry) = read_dir.next_entry().await.map_err(|e| {
            server_err!(
                ServerErrorCode::IOError,
                "Failed to read directory entry: {}",
                e
            )
        })? {
            let file_name = entry.file_name();
            let name = file_name.to_string_lossy().to_string();
            if name.starts_with('.') {
                continue;
            }

            let metadata = entry.metadata().await.map_err(|e| {
                server_err!(ServerErrorCode::IOError, "Failed to read metadata: {}", e)
            })?;
            let is_dir = metadata.is_dir();
            let encoded_name = utf8_percent_encode(&name, PATH_SEGMENT_ENCODE_SET).to_string();
            let mut href = format!("{}{}", req_base, encoded_name);
            if is_dir {
                href.push('/');
            }

            let modified = metadata
                .modified()
                .ok()
                .map(Self::format_modified_time)
                .unwrap_or_else(|| "-".to_string());
            let size = if is_dir {
                "-".to_string()
            } else {
                metadata.len().to_string()
            };

            entries.push(Entry {
                name,
                href,
                is_dir,
                modified,
                size,
            });
        }

        entries.sort_by(|a, b| {
            b.is_dir
                .cmp(&a.is_dir)
                .then_with(|| a.name.as_bytes().cmp(b.name.as_bytes()))
        });

        let escaped_path = Self::escape_html(req_path);
        let mut html = String::new();
        html.push_str("<!doctype html>\r\n<html lang=\"en\">\r\n<head>\r\n<meta charset=\"utf-8\">\r\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\r\n<title>Index of ");
        html.push_str(&escaped_path);
        html.push_str("</title>\r\n<style>\r\n:root {\r\n  color-scheme: light;\r\n  --bg: #f3f6fb;\r\n  --panel: #ffffff;\r\n  --text: #1f2937;\r\n  --muted: #64748b;\r\n  --line: #d8e1ec;\r\n  --link: #0f62d6;\r\n  --link-hover: #0b4fb0;\r\n}\r\n* { box-sizing: border-box; }\r\nbody {\r\n  margin: 0;\r\n  font-family: \"Segoe UI\", \"PingFang SC\", \"Microsoft YaHei\", sans-serif;\r\n  color: var(--text);\r\n  background: radial-gradient(circle at top right, #e8f0ff 0%, var(--bg) 45%, #edf2f9 100%);\r\n}\r\nmain {\r\n  max-width: 980px;\r\n  margin: 24px auto;\r\n  padding: 0 16px;\r\n}\r\nsection {\r\n  background: var(--panel);\r\n  border: 1px solid var(--line);\r\n  border-radius: 12px;\r\n  box-shadow: 0 10px 24px rgba(15, 23, 42, 0.08);\r\n  overflow: hidden;\r\n}\r\nh1 {\r\n  margin: 0;\r\n  padding: 18px 20px;\r\n  font-size: 20px;\r\n  font-weight: 600;\r\n  letter-spacing: 0.01em;\r\n}\r\nhr {\r\n  margin: 0;\r\n  border: 0;\r\n  border-top: 1px solid var(--line);\r\n}\r\npre {\r\n  margin: 0;\r\n  padding: 14px 20px 20px;\r\n  overflow-x: auto;\r\n  font-family: Consolas, \"Courier New\", monospace;\r\n  font-size: 14px;\r\n  line-height: 1.55;\r\n}\r\na {\r\n  color: var(--link);\r\n  text-decoration: none;\r\n}\r\na:hover {\r\n  color: var(--link-hover);\r\n  text-decoration: underline;\r\n}\r\n@media (max-width: 640px) {\r\n  main {\r\n    margin: 14px auto;\r\n    padding: 0 10px;\r\n  }\r\n  h1 {\r\n    padding: 14px 14px;\r\n    font-size: 18px;\r\n  }\r\n  pre {\r\n    padding: 10px 14px 14px;\r\n    font-size: 13px;\r\n  }\r\n}\r\n</style>\r\n</head>\r\n<body>\r\n<main><section>\r\n<h1>Index of ");
        html.push_str(&escaped_path);
        html.push_str("</h1><hr><pre><a href=\"../\">../</a>\r\n");

        for entry in entries {
            let mut display_name = entry.name;
            if entry.is_dir {
                display_name.push('/');
            }

            let mut short_name: String = display_name.chars().take(50).collect();
            if display_name.chars().count() > 50 {
                short_name = format!("{}..>", display_name.chars().take(47).collect::<String>());
            }

            let escaped_name = Self::escape_html(&short_name);
            let escaped_href = Self::escape_html(&entry.href);
            let pad = 50usize.saturating_sub(short_name.chars().count());
            let spaces = " ".repeat(pad);
            html.push_str(&format!(
                "<a href=\"{}\">{}</a>{} {} {:>19}\r\n",
                escaped_href, escaped_name, spaces, entry.modified, entry.size
            ));
        }

        html.push_str("</pre><hr></section></main></body>\r\n</html>\r\n");
        Ok(self.build_html_response(StatusCode::OK, html))
    }
}

#[async_trait::async_trait]
impl HttpServer for DirServer {
    async fn serve_request(
        &self,
        req: http::Request<BoxBody<Bytes, ServerError>>,
        _info: StreamInfo,
    ) -> ServerResult<http::Response<BoxBody<Bytes, ServerError>>> {
        let req_path = req.uri().path();
        let req_method = req.method();

        debug!("DirServer[{}] {} {}", self.id, req_method, req_path);

        // Only support GET and HEAD methods
        if req_method != hyper::Method::GET && req_method != hyper::Method::HEAD {
            warn!("Method not allowed: {}", req_method);
            return Ok(
                self.build_text_response(StatusCode::METHOD_NOT_ALLOWED, "Method not allowed")
            );
        }

        let mut file_path = match self.resolve_path(req_path) {
            Ok(path) => path,
            Err(_) => {
                warn!("Path traversal attempt: {}", req_path);
                return Ok(self.build_text_response(StatusCode::FORBIDDEN, "Forbidden"));
            }
        };

        if file_path.exists() {
            file_path = match self.ensure_path_in_root(&file_path) {
                Ok(path) => path,
                Err(_) => {
                    warn!("Path traversal attempt: {:?}", file_path);
                    return Ok(self.build_text_response(StatusCode::FORBIDDEN, "Forbidden"));
                }
            };
        }

        if file_path.is_dir() {
            let index_path = file_path.join(&self.index_file);
            if index_path.exists() && index_path.is_file() {
                let index_path = match self.ensure_path_in_root(&index_path) {
                    Ok(path) => path,
                    Err(_) => {
                        warn!("Path traversal attempt: {:?}", index_path);
                        return Ok(self.build_text_response(StatusCode::FORBIDDEN, "Forbidden"));
                    }
                };
                info!("Serving index file: {:?}", index_path);
                return self.serve_file(&index_path, &req).await;
            }

            if self.autoindex {
                info!("Serving directory listing: {:?}", file_path);
                return self.serve_directory_listing(req_path, &file_path).await;
            }
        }

        // Check if file exists
        if !file_path.exists() || !file_path.is_file() {
            warn!("File not found: {:?}", file_path);
            if let Some(fallback_file) = &self.fallback_file {
                let fallback_path = self.root_dir.join(fallback_file);
                match self.ensure_path_in_root(&fallback_path) {
                    Ok(fallback_path) => {
                        if fallback_path.exists() && fallback_path.is_file() {
                            info!("Fallback to file: {:?}", fallback_path);
                            return self.serve_file(&fallback_path, &req).await;
                        }
                        warn!("Fallback file not found: {:?}", fallback_path);
                    }
                    Err(e) => {
                        warn!(
                            "Failed to resolve fallback file: {:?}, error: {}",
                            fallback_path, e
                        );
                    }
                }
            }
            return Ok(self.build_text_response(StatusCode::NOT_FOUND, "Not found"));
        }

        info!("Serving file: {:?}", file_path);

        // Serve the file
        self.serve_file(&file_path, &req).await
    }

    fn id(&self) -> String {
        self.id.clone()
    }

    fn http_version(&self) -> Version {
        self.version
    }

    fn http3_port(&self) -> Option<u16> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{hyper_serve_http1, StreamInfo};
    use http_body_util::Full;
    use hyper_util::rt::TokioIo;
    use std::sync::Arc;

    async fn request_dir_server(
        server: Arc<DirServer>,
        uri: &str,
        headers: &[(&str, String)],
    ) -> http::Response<hyper::body::Incoming> {
        let (client, server_stream) = tokio::io::duplex(4096);

        tokio::spawn(async move {
            hyper_serve_http1(Box::new(server_stream), server, StreamInfo::default())
                .await
                .unwrap();
        });

        let mut builder = http::Request::builder().method("GET").uri(uri);
        for (name, value) in headers {
            builder = builder.header(*name, value.as_str());
        }

        let request = builder.body(Full::new(Bytes::new())).unwrap();

        let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
            .handshake(TokioIo::new(client))
            .await
            .unwrap();

        tokio::spawn(async move {
            conn.await.unwrap();
        });

        sender.send_request(request).await.unwrap()
    }

    #[tokio::test]
    async fn test_create_server_without_id() {
        let result = DirServer::builder()
            .root_path(PathBuf::from("/tmp"))
            .build()
            .await;
        assert!(result.is_err());
        if let Err(e) = result {
            assert_eq!(e.code(), ServerErrorCode::InvalidConfig);
        }
    }

    #[tokio::test]
    async fn test_create_server_without_root_dir() {
        let result = DirServer::builder().id("test").build().await;
        assert!(result.is_err());
        if let Err(e) = result {
            assert_eq!(e.code(), ServerErrorCode::InvalidConfig);
        }
    }

    #[tokio::test]
    async fn test_create_server_with_valid_config() {
        let temp_dir = tempfile::tempdir().unwrap();

        let result = DirServer::builder()
            .id("test")
            .root_path(temp_dir.path().to_path_buf())
            .build()
            .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_serve_existing_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        tokio::fs::write(temp_dir.path().join("test.txt"), b"Hello, World!")
            .await
            .unwrap();

        let server = Arc::new(
            DirServer::builder()
                .id("test")
                .root_path(temp_dir.path().to_path_buf())
                .build()
                .await
                .unwrap(),
        );

        let resp = request_dir_server(server, "http://localhost/test.txt", &[]).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let body_bytes = resp.collect().await.unwrap().to_bytes();
        assert_eq!(body_bytes.as_ref(), b"Hello, World!");
    }

    #[tokio::test]
    async fn test_serve_non_existent_file() {
        let temp_dir = tempfile::tempdir().unwrap();

        let server = Arc::new(
            DirServer::builder()
                .id("test")
                .root_path(temp_dir.path().to_path_buf())
                .build()
                .await
                .unwrap(),
        );

        let resp = request_dir_server(server, "http://localhost/non_existent.txt", &[]).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_dir_prefers_index_file_before_autoindex_listing() {
        let temp_dir = tempfile::tempdir().unwrap();
        tokio::fs::write(temp_dir.path().join("index.html"), b"index-body")
            .await
            .unwrap();
        tokio::fs::write(temp_dir.path().join("another.txt"), b"another")
            .await
            .unwrap();

        let server = Arc::new(
            DirServer::builder()
                .id("test")
                .root_path(temp_dir.path().to_path_buf())
                .autoindex(true)
                .build()
                .await
                .unwrap(),
        );

        let resp = request_dir_server(server, "http://localhost/", &[]).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body_bytes = resp.collect().await.unwrap().to_bytes();
        assert_eq!(body_bytes.as_ref(), b"index-body");
    }

    #[tokio::test]
    async fn test_dir_returns_listing_when_index_missing_and_autoindex_enabled() {
        let temp_dir = tempfile::tempdir().unwrap();
        tokio::fs::write(temp_dir.path().join("visible.txt"), b"visible")
            .await
            .unwrap();
        tokio::fs::write(temp_dir.path().join(".hidden.txt"), b"hidden")
            .await
            .unwrap();

        let server = Arc::new(
            DirServer::builder()
                .id("test")
                .root_path(temp_dir.path().to_path_buf())
                .autoindex(true)
                .build()
                .await
                .unwrap(),
        );

        let resp = request_dir_server(server, "http://localhost/", &[]).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let content_type = resp
            .headers()
            .get("Content-Type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        assert_eq!(content_type, "text/html; charset=utf-8");

        let body = String::from_utf8(resp.collect().await.unwrap().to_bytes().to_vec()).unwrap();
        assert!(body.contains("visible.txt"));
        assert!(!body.contains(".hidden.txt"));
        assert!(body.contains("Index of /"));
    }

    #[tokio::test]
    async fn test_if_none_match_returns_not_modified() {
        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("etag.txt");
        tokio::fs::write(&file_path, b"etag-body").await.unwrap();

        let server = Arc::new(
            DirServer::builder()
                .id("test")
                .root_path(temp_dir.path().to_path_buf())
                .build()
                .await
                .unwrap(),
        );

        let first_resp = request_dir_server(server.clone(), "http://localhost/etag.txt", &[]).await;
        assert_eq!(first_resp.status(), StatusCode::OK);
        let etag = first_resp
            .headers()
            .get(ETAG)
            .and_then(|v| v.to_str().ok())
            .unwrap()
            .to_string();

        let second_resp = request_dir_server(
            server,
            "http://localhost/etag.txt",
            &[("if-none-match", etag)],
        )
        .await;
        assert_eq!(second_resp.status(), StatusCode::NOT_MODIFIED);
    }

    #[tokio::test]
    async fn test_if_modified_since_exact_returns_not_modified() {
        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("ims.txt");
        tokio::fs::write(&file_path, b"ims-body").await.unwrap();

        let metadata = tokio::fs::metadata(&file_path).await.unwrap();
        let modified = metadata.modified().unwrap();
        let since = httpdate::fmt_http_date(modified);

        let server = Arc::new(
            DirServer::builder()
                .id("test")
                .root_path(temp_dir.path().to_path_buf())
                .if_modified_since("exact")
                .build()
                .await
                .unwrap(),
        );

        let resp = request_dir_server(
            server,
            "http://localhost/ims.txt",
            &[("if-modified-since", since)],
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_MODIFIED);
    }

    #[tokio::test]
    async fn test_invalid_if_modified_since_config() {
        let temp_dir = tempfile::tempdir().unwrap();
        let result = DirServer::builder()
            .id("test")
            .root_path(temp_dir.path().to_path_buf())
            .if_modified_since("invalid")
            .build()
            .await;

        assert!(result.is_err());
        if let Err(e) = result {
            assert_eq!(e.code(), ServerErrorCode::InvalidConfig);
        }
    }
}
