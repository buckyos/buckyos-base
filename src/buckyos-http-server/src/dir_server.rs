use crate::{server_err, HttpServer, ServerError, ServerErrorCode, ServerResult, StreamInfo};
use chrono::{DateTime, Local};
use futures_util::TryStreamExt;
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Version};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::{Bytes, Frame};
use hyper::header::{
    ACCEPT_RANGES, ALLOW, CACHE_CONTROL, CONTENT_LENGTH, CONTENT_RANGE, CONTENT_TYPE, ETAG,
    IF_MATCH, IF_MODIFIED_SINCE, IF_NONE_MATCH, IF_RANGE, IF_UNMODIFIED_SINCE, LAST_MODIFIED,
    LOCATION, RANGE,
};
use log::{debug, info, warn};
use percent_encoding::{percent_decode_str, AsciiSet, CONTROLS};
use std::ffi::{OsStr, OsString};
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncSeekExt};

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
    .add(b'/')
    .add(b'\\')
    .add(b'[')
    .add(b']')
    .add(b'^')
    .add(b'|');

/// Read buffer behind a file body stream. Memory per response is bounded by
/// this, whatever the file or range size.
const STREAM_BUFFER_SIZE: usize = 64 * 1024;

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
    cache_policy: Option<String>,
    html_cache_control: Option<String>,
    cache_control: Option<String>,
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

/// `Cache-Control` sent with file responses (200, 206 and 304) and listings.
#[derive(Clone, Debug, Default)]
struct CachePolicy {
    html: Option<HeaderValue>,
    other: Option<HeaderValue>,
}

impl CachePolicy {
    /// The default preset: HTML entry points revalidate on every use, so a page
    /// never keeps referencing the assets of an older deployment.
    fn html_revalidate() -> Self {
        Self {
            html: Some(HeaderValue::from_static("no-cache")),
            other: None,
        }
    }

    fn preset(name: &str) -> Option<Self> {
        match name {
            "html-revalidate" => Some(Self::html_revalidate()),
            "none" => Some(Self::default()),
            _ => None,
        }
    }

    fn header_value(&self, is_html: bool) -> Option<&HeaderValue> {
        if is_html {
            self.html.as_ref()
        } else {
            self.other.as_ref()
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PathError {
    /// A `..` segment, literal or percent-encoded.
    Traversal,
    /// A segment that does not decode to exactly one file name, e.g. an
    /// encoded separator or NUL.
    Invalid,
}

/// What a candidate path refers to once symlinks are followed.
enum Lookup {
    File(PathBuf),
    Dir(PathBuf),
    /// The canonical target lies outside the root directory.
    OutsideRoot,
    Missing,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RangeSelection {
    /// The complete representation, with 200.
    Full,
    /// Bytes `start..=end`, with 206.
    Partial(u64, u64),
    /// 416 Range Not Satisfiable.
    Unsatisfiable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Precondition {
    Proceed,
    NotModified,
    Failed,
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

    /// Cache-Control preset: `html-revalidate` (the default: HTML responses
    /// carry `no-cache`, other files none) or `none`.
    pub fn cache_policy(mut self, preset: impl Into<String>) -> Self {
        self.cache_policy = Some(preset.into());
        self
    }

    /// Cache-Control for HTML responses, replacing the preset's value.
    pub fn html_cache_control(mut self, value: impl Into<String>) -> Self {
        self.html_cache_control = Some(value.into());
        self
    }

    /// Cache-Control for non-HTML file responses, replacing the preset's value.
    pub fn cache_control(mut self, value: impl Into<String>) -> Self {
        self.cache_control = Some(value.into());
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
    /// Decoded segments of the mount prefix stripped from request paths.
    base_segments: Vec<OsString>,
    autoindex: bool,
    etag: bool,
    if_modified_since: IfModifiedSinceMode,
    cache_policy: CachePolicy,
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
            cache_policy: None,
            html_cache_control: None,
            cache_control: None,
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
        let mut cache_policy = match builder.cache_policy {
            Some(preset) => CachePolicy::preset(preset.as_str()).ok_or_else(|| {
                server_err!(
                    ServerErrorCode::InvalidConfig,
                    "invalid cache_policy: {}, expected one of html-revalidate|none",
                    preset
                )
            })?,
            None => CachePolicy::html_revalidate(),
        };
        if let Some(value) = builder.html_cache_control {
            cache_policy.html = Some(Self::parse_cache_control("html_cache_control", value)?);
        }
        if let Some(value) = builder.cache_control {
            cache_policy.other = Some(Self::parse_cache_control("cache_control", value)?);
        }
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
        let base_url = builder.base_url.unwrap_or_else(|| "/".to_string());
        let base_segments = Self::decode_path(&base_url).map_err(|_| {
            server_err!(
                ServerErrorCode::InvalidConfig,
                "invalid base_url: {}",
                base_url
            )
        })?;
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
            base_segments,
            autoindex: builder.autoindex,
            etag,
            if_modified_since,
            cache_policy,
        })
    }

    fn parse_cache_control(field: &str, value: String) -> ServerResult<HeaderValue> {
        HeaderValue::try_from(value.as_str()).map_err(|_| {
            server_err!(
                ServerErrorCode::InvalidConfig,
                "invalid {}: {:?} is not a valid header value",
                field,
                value
            )
        })
    }

    fn format_http_date(st: SystemTime) -> String {
        httpdate::fmt_http_date(st)
    }

    fn unix_secs(time: SystemTime) -> u64 {
        time.duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs()
    }

    fn trim_ows(mut input: &[u8]) -> &[u8] {
        while let [b' ' | b'\t', rest @ ..] = input {
            input = rest;
        }
        while let [rest @ .., b' ' | b'\t'] = input {
            input = rest;
        }
        input
    }

    /// Splits a leading `[W/]"opaque"` entity tag off `input`, returning
    /// whether it is weak, the quoted opaque tag and the remaining input.
    fn split_entity_tag(input: &[u8]) -> Option<(bool, &[u8], &[u8])> {
        let (weak, quoted) = match input.strip_prefix(b"W/") {
            Some(rest) => (true, rest),
            None => (false, input),
        };
        if quoted.first() != Some(&b'"') {
            return None;
        }
        let len = quoted[1..].iter().position(|&b| b == b'"')? + 2;
        Some((weak, &quoted[..len], &quoted[len..]))
    }

    /// Whether one `If-Match` / `If-None-Match` field line matches the current
    /// entity tag (RFC 9110 §8.8.3.2). `*` matches whenever a current
    /// representation exists, which is always the case for a served file.
    fn entity_tags_match(value: &[u8], current_etag: Option<&str>, strong: bool) -> bool {
        let current = current_etag.and_then(|etag| Self::split_entity_tag(etag.as_bytes()));
        let mut rest = value;
        loop {
            while let [b' ' | b'\t' | b',', tail @ ..] = rest {
                rest = tail;
            }
            if rest.is_empty() {
                return false;
            }
            if rest[0] == b'*' {
                return true;
            }
            match Self::split_entity_tag(rest) {
                Some((weak, tag, tail)) => {
                    if let Some((current_weak, current_tag, _)) = current {
                        let comparable = !strong || (!weak && !current_weak);
                        if comparable && tag == current_tag {
                            return true;
                        }
                    }
                    rest = tail;
                }
                // Skip a malformed member.
                None => match rest.iter().position(|&b| b == b',') {
                    Some(pos) => rest = &rest[pos + 1..],
                    None => return false,
                },
            }
        }
    }

    /// `None` when the field is absent, otherwise whether any of its lines
    /// matches the current entity tag.
    fn entity_tag_field_matches(
        headers: &HeaderMap,
        name: HeaderName,
        current_etag: Option<&str>,
        strong: bool,
    ) -> Option<bool> {
        let mut values = headers.get_all(name).iter().peekable();
        values.peek()?;
        Some(values.any(|value| Self::entity_tags_match(value.as_bytes(), current_etag, strong)))
    }

    fn header_date(headers: &HeaderMap, name: HeaderName) -> Option<SystemTime> {
        let value = headers.get(name)?.to_str().ok()?;
        httpdate::parse_http_date(value).ok()
    }

    fn compare_if_modified_since(&self, last_modified: SystemTime, since: SystemTime) -> bool {
        let mtime_secs = Self::unix_secs(last_modified);
        let since_secs = Self::unix_secs(since);

        match self.if_modified_since {
            IfModifiedSinceMode::Off => false,
            IfModifiedSinceMode::Exact => mtime_secs == since_secs,
            IfModifiedSinceMode::Before => mtime_secs <= since_secs,
        }
    }

    /// Evaluates the preconditions of a GET/HEAD in the order of RFC 9110
    /// §13.2.2. `If-Range` is not part of this; it only decides whether a
    /// `Range` is honored.
    fn evaluate_preconditions(
        &self,
        headers: &HeaderMap,
        current_etag: Option<&str>,
        last_modified: Option<SystemTime>,
    ) -> Precondition {
        match Self::entity_tag_field_matches(headers, IF_MATCH, current_etag, true) {
            Some(false) => return Precondition::Failed,
            Some(true) => {}
            None => {
                // Ignored when the date is invalid or the file has no usable mtime.
                if let (Some(last_modified), Some(since)) = (
                    last_modified,
                    Self::header_date(headers, IF_UNMODIFIED_SINCE),
                ) {
                    if Self::unix_secs(last_modified) > Self::unix_secs(since) {
                        return Precondition::Failed;
                    }
                }
            }
        }

        match Self::entity_tag_field_matches(headers, IF_NONE_MATCH, current_etag, false) {
            Some(true) => return Precondition::NotModified,
            Some(false) => {}
            None => {
                if let (Some(last_modified), Some(since)) =
                    (last_modified, Self::header_date(headers, IF_MODIFIED_SINCE))
                {
                    if self.compare_if_modified_since(last_modified, since) {
                        return Precondition::NotModified;
                    }
                }
            }
        }

        Precondition::Proceed
    }

    /// `If-Range` holds when its entity tag matches strongly or its date
    /// equals `Last-Modified`; otherwise the complete current representation
    /// is sent instead of a range of it.
    fn if_range_holds(
        value: &HeaderValue,
        current_etag: Option<&str>,
        last_modified: Option<SystemTime>,
    ) -> bool {
        let value = Self::trim_ows(value.as_bytes());
        if let Some((weak, tag, rest)) = Self::split_entity_tag(value) {
            let current = current_etag.and_then(|etag| Self::split_entity_tag(etag.as_bytes()));
            return match current {
                Some((current_weak, current_tag, _)) => {
                    !weak && !current_weak && rest.is_empty() && tag == current_tag
                }
                None => false,
            };
        }

        let since = std::str::from_utf8(value)
            .ok()
            .and_then(|value| httpdate::parse_http_date(value).ok());
        match (last_modified, since) {
            (Some(last_modified), Some(since)) => {
                Self::unix_secs(last_modified) == Self::unix_secs(since)
            }
            _ => false,
        }
    }

    /// Digits of a range position; values beyond `u64` saturate, which keeps
    /// their meaning (past the end of any file).
    fn parse_range_pos(digits: &str) -> Option<u64> {
        if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        Some(digits.parse::<u64>().unwrap_or(u64::MAX))
    }

    /// Selects the byte range a `Range` field asks for (RFC 9110 §14.1.2).
    /// Only a single `bytes` range is served; another unit, an invalid field
    /// or several ranges fall back to the complete representation, which a
    /// server may always send instead.
    fn select_range(range: &str, file_size: u64) -> RangeSelection {
        let Some((unit, specs)) = range.split_once('=') else {
            return RangeSelection::Full;
        };
        if !unit.trim().eq_ignore_ascii_case("bytes") {
            return RangeSelection::Full;
        }

        let mut specs = specs.split(',').map(str::trim).filter(|s| !s.is_empty());
        let (Some(spec), None) = (specs.next(), specs.next()) else {
            return RangeSelection::Full;
        };
        let Some((first, last)) = spec.split_once('-') else {
            return RangeSelection::Full;
        };
        let (first, last) = (first.trim(), last.trim());

        if first.is_empty() {
            let Some(suffix) = Self::parse_range_pos(last) else {
                return RangeSelection::Full;
            };
            if suffix == 0 {
                return RangeSelection::Unsatisfiable;
            }
            if file_size == 0 {
                // Satisfiable, but zero bytes cannot be written as a
                // Content-Range; the (empty) whole is the same answer.
                return RangeSelection::Full;
            }
            return RangeSelection::Partial(file_size.saturating_sub(suffix), file_size - 1);
        }

        let Some(start) = Self::parse_range_pos(first) else {
            return RangeSelection::Full;
        };
        let end = if last.is_empty() {
            None
        } else {
            match Self::parse_range_pos(last) {
                Some(end) if end >= start => Some(end),
                _ => return RangeSelection::Full,
            }
        };
        if start >= file_size {
            return RangeSelection::Unsatisfiable;
        }
        let end = end.map_or(file_size - 1, |end| end.min(file_size - 1));
        RangeSelection::Partial(start, end)
    }

    fn build_etag(file_size: u64, last_modified: Option<SystemTime>) -> Option<String> {
        let dur = last_modified?.duration_since(UNIX_EPOCH).ok()?;
        Some(format!(
            "\"{:x}-{:x}-{:x}\"",
            file_size,
            dur.as_secs(),
            dur.subsec_nanos()
        ))
    }

    fn empty_body() -> BoxBody<Bytes, ServerError> {
        Full::new(Bytes::new()).map_err(|e| match e {}).boxed()
    }

    /// Streams `length` bytes of `file` from `start` through a bounded buffer.
    async fn file_body(
        mut file: tokio::fs::File,
        start: u64,
        length: u64,
    ) -> ServerResult<BoxBody<Bytes, ServerError>> {
        if length == 0 {
            return Ok(Self::empty_body());
        }
        if start > 0 {
            file.seek(std::io::SeekFrom::Start(start))
                .await
                .map_err(|e| server_err!(ServerErrorCode::IOError, "Failed to seek file: {}", e))?;
        }

        let capacity = length.min(STREAM_BUFFER_SIZE as u64) as usize;
        let stream = tokio_util::io::ReaderStream::with_capacity(file.take(length), capacity);
        let stream_body = StreamBody::new(stream.map_ok(Frame::data));
        Ok(BodyExt::map_err(stream_body, |e| {
            ServerError::new(ServerErrorCode::StreamError, format!("Stream error: {}", e))
        })
        .boxed())
    }

    fn with_representation_headers(
        &self,
        mut builder: http::response::Builder,
        is_html: bool,
        etag: Option<&str>,
        last_modified: Option<SystemTime>,
    ) -> http::response::Builder {
        if let Some(cache_control) = self.cache_policy.header_value(is_html) {
            builder = builder.header(CACHE_CONTROL, cache_control.clone());
        }
        if let Some(etag) = etag {
            builder = builder.header(ETAG, etag);
        }
        if let Some(last_modified) = last_modified {
            builder = builder.header(LAST_MODIFIED, Self::format_http_date(last_modified));
        }
        builder
    }

    /// Serve a file from the local directory. `file_path` is the canonical
    /// path to open; `mime_path` is the name the client asked for, which
    /// decides the Content-Type even when `file_path` is a symlink target.
    async fn serve_file(
        &self,
        file_path: &Path,
        mime_path: &Path,
        req: &http::Request<BoxBody<Bytes, ServerError>>,
    ) -> ServerResult<http::Response<BoxBody<Bytes, ServerError>>> {
        let file = match tokio::fs::File::open(&file_path).await {
            Ok(file) => file,
            Err(e) => {
                warn!("Failed to open file: {:?}, error: {}", file_path, e);
                return match e.kind() {
                    std::io::ErrorKind::NotFound => {
                        Ok(self.build_text_response(StatusCode::NOT_FOUND, "Not found"))
                    }
                    std::io::ErrorKind::PermissionDenied => {
                        Ok(self.build_text_response(StatusCode::FORBIDDEN, "Forbidden"))
                    }
                    _ => Err(server_err!(
                        ServerErrorCode::IOError,
                        "Failed to open file: {}",
                        e
                    )),
                };
            }
        };

        let file_meta = file.metadata().await.map_err(|e| {
            warn!("Failed to get file metadata: {:?}, error: {}", file_path, e);
            server_err!(
                ServerErrorCode::IOError,
                "Failed to get file metadata: {}",
                e
            )
        })?;

        let file_size = file_meta.len();
        let mime_type = mime_guess::from_path(mime_path).first_or_octet_stream();
        let is_html = mime_type.essence_str() == "text/html";
        // Reproducible archives can use an epoch mtime for every package version.
        // Such timestamps cannot validate content changes, even for equal-size files.
        let last_modified = file_meta
            .modified()
            .ok()
            .filter(|mtime| *mtime > UNIX_EPOCH);
        let etag = if self.etag {
            Self::build_etag(file_size, last_modified)
        } else {
            None
        };

        match self.evaluate_preconditions(req.headers(), etag.as_deref(), last_modified) {
            Precondition::Proceed => {}
            Precondition::Failed => {
                return Ok(self
                    .build_text_response(StatusCode::PRECONDITION_FAILED, "Precondition failed"));
            }
            Precondition::NotModified => {
                return self
                    .with_representation_headers(
                        http::Response::builder().status(StatusCode::NOT_MODIFIED),
                        is_html,
                        etag.as_deref(),
                        last_modified,
                    )
                    .body(Self::empty_body())
                    .map_err(|e| {
                        server_err!(ServerErrorCode::IOError, "Failed to build response: {}", e)
                    });
            }
        }

        // Range is defined for GET only; HEAD describes the full representation.
        let range = match req.headers().get(RANGE) {
            Some(range) if req.method() == Method::GET => {
                let honored = req.headers().get(IF_RANGE).is_none_or(|if_range| {
                    Self::if_range_holds(if_range, etag.as_deref(), last_modified)
                });
                match range.to_str() {
                    Ok(range) if honored => Self::select_range(range, file_size),
                    _ => RangeSelection::Full,
                }
            }
            _ => RangeSelection::Full,
        };

        let mut response_builder = http::Response::builder().header(ACCEPT_RANGES, "bytes");
        let (status, start, content_length) = match range {
            RangeSelection::Full => (StatusCode::OK, 0, file_size),
            RangeSelection::Partial(start, end) => {
                response_builder = response_builder.header(
                    CONTENT_RANGE,
                    format!("bytes {}-{}/{}", start, end, file_size),
                );
                (StatusCode::PARTIAL_CONTENT, start, end - start + 1)
            }
            RangeSelection::Unsatisfiable => {
                return response_builder
                    .status(StatusCode::RANGE_NOT_SATISFIABLE)
                    .header(CONTENT_RANGE, format!("bytes */{}", file_size))
                    .header(CONTENT_TYPE, "text/plain; charset=utf-8")
                    .body(
                        Full::new(Bytes::from_static(b"Range not satisfiable"))
                            .map_err(|e| match e {})
                            .boxed(),
                    )
                    .map_err(|e| {
                        server_err!(ServerErrorCode::IOError, "Failed to build response: {}", e)
                    });
            }
        };

        let body = if req.method() == Method::HEAD {
            Self::empty_body()
        } else {
            Self::file_body(file, start, content_length).await?
        };

        self.with_representation_headers(
            response_builder
                .status(status)
                .header(CONTENT_TYPE, mime_type.as_ref())
                .header(CONTENT_LENGTH, content_length),
            is_html,
            etag.as_deref(),
            last_modified,
        )
        .body(body)
        .map_err(|e| server_err!(ServerErrorCode::IOError, "Failed to build response: {}", e))
    }

    #[cfg(unix)]
    fn os_string_from_bytes(bytes: Vec<u8>) -> Result<OsString, PathError> {
        use std::os::unix::ffi::OsStringExt;
        Ok(OsString::from_vec(bytes))
    }

    #[cfg(not(unix))]
    fn os_string_from_bytes(bytes: Vec<u8>) -> Result<OsString, PathError> {
        String::from_utf8(bytes)
            .map(OsString::from)
            .map_err(|_| PathError::Invalid)
    }

    /// Decodes one URL path segment. Empty and `.` segments yield `None`.
    fn decode_path_segment(raw: &str) -> Result<Option<OsString>, PathError> {
        let bytes: Vec<u8> = percent_decode_str(raw).collect();
        match bytes.as_slice() {
            b"" | b"." => return Ok(None),
            b".." => return Err(PathError::Traversal),
            _ => {}
        }
        if bytes.contains(&0) || (cfg!(windows) && bytes.contains(&b':')) {
            return Err(PathError::Invalid);
        }

        let segment = Self::os_string_from_bytes(bytes)?;
        // The decoded segment must stay one plain file name; this rejects
        // encoded separators and, on Windows, drive or UNC prefixes.
        let mut components = Path::new(&segment).components();
        match (components.next(), components.next()) {
            (Some(Component::Normal(name)), None) if name == segment.as_os_str() => {
                Ok(Some(segment))
            }
            _ => Err(PathError::Invalid),
        }
    }

    /// Decodes a URL path exactly once, segment by segment.
    fn decode_path(raw_path: &str) -> Result<Vec<OsString>, PathError> {
        let mut segments = Vec::new();
        for raw in raw_path.split('/') {
            if let Some(segment) = Self::decode_path_segment(raw)? {
                segments.push(segment);
            }
        }
        Ok(segments)
    }

    fn resolve_path(&self, req_path: &str) -> Result<PathBuf, PathError> {
        let segments = Self::decode_path(req_path)?;
        // base_url is a rewrite, not an access check: a path without the
        // prefix still resolves relative to the root.
        let sub_path = segments
            .strip_prefix(self.base_segments.as_slice())
            .unwrap_or(&segments);

        let mut path = self.root_dir.clone();
        for segment in sub_path {
            path.push(segment);
        }
        Ok(path)
    }

    async fn lookup(&self, path: &Path) -> Lookup {
        let canonical_path = match tokio::fs::canonicalize(path).await {
            Ok(path) => path,
            Err(_) => return Lookup::Missing,
        };
        if !canonical_path.starts_with(&self.root_dir) {
            return Lookup::OutsideRoot;
        }
        match tokio::fs::metadata(&canonical_path).await {
            Ok(metadata) if metadata.is_file() => Lookup::File(canonical_path),
            Ok(metadata) if metadata.is_dir() => Lookup::Dir(canonical_path),
            _ => Lookup::Missing,
        }
    }

    fn build_text_response(
        &self,
        status: StatusCode,
        body: impl Into<Bytes>,
    ) -> http::Response<BoxBody<Bytes, ServerError>> {
        http::Response::builder()
            .status(status)
            .header(CONTENT_TYPE, "text/plain; charset=utf-8")
            .body(Full::new(body.into()).map_err(|e| match e {}).boxed())
            .unwrap()
    }

    /// 301 to the trailing-slash form of a directory URL, keeping the query.
    /// The target is relative to the request URL, so it stays correct behind
    /// `base_url` and any prefix rewrite applied before this server.
    fn build_directory_redirect(
        &self,
        req: &http::Request<BoxBody<Bytes, ServerError>>,
    ) -> http::Response<BoxBody<Bytes, ServerError>> {
        let last_segment = req.uri().path().rsplit('/').next().unwrap_or_default();
        let mut location = format!("./{}/", last_segment);
        if let Some(query) = req.uri().query() {
            location.push('?');
            location.push_str(query);
        }
        match HeaderValue::try_from(location) {
            Ok(location) => http::Response::builder()
                .status(StatusCode::MOVED_PERMANENTLY)
                .header(LOCATION, location)
                .body(Self::empty_body())
                .unwrap(),
            Err(_) => self.build_text_response(StatusCode::BAD_REQUEST, "Bad request"),
        }
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

    /// Percent-encodes a file name as one URL path segment. On Unix the raw
    /// bytes are encoded, so names that are not UTF-8 still round-trip.
    #[cfg(unix)]
    fn encode_file_name(name: &OsStr) -> String {
        use std::os::unix::ffi::OsStrExt;
        percent_encoding::percent_encode(name.as_bytes(), PATH_SEGMENT_ENCODE_SET).to_string()
    }

    #[cfg(not(unix))]
    fn encode_file_name(name: &OsStr) -> String {
        percent_encoding::utf8_percent_encode(&name.to_string_lossy(), PATH_SEGMENT_ENCODE_SET)
            .to_string()
    }

    fn format_modified_time(st: std::time::SystemTime) -> String {
        let dt: DateTime<Local> = st.into();
        dt.format("%d-%b-%Y %H:%M").to_string()
    }

    async fn serve_directory_listing(
        &self,
        req: &http::Request<BoxBody<Bytes, ServerError>>,
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

            // Follow symlinks like requests do; a dangling one shows as itself.
            let metadata = match tokio::fs::metadata(entry.path()).await {
                Ok(metadata) => Some(metadata),
                Err(_) => entry.metadata().await.ok(),
            };
            let is_dir = metadata.as_ref().is_some_and(|m| m.is_dir());
            // Relative links resolve under this listing's own (slash-terminated) URL.
            let mut href = format!("./{}", Self::encode_file_name(&file_name));
            if is_dir {
                href.push('/');
            }

            let modified = metadata
                .as_ref()
                .and_then(|m| m.modified().ok())
                .map(Self::format_modified_time)
                .unwrap_or_else(|| "-".to_string());
            let size = match &metadata {
                Some(metadata) if !is_dir => metadata.len().to_string(),
                _ => "-".to_string(),
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

        let display_path = percent_decode_str(req.uri().path()).decode_utf8_lossy();
        let escaped_path = Self::escape_html(&display_path);
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

        let content_length = html.len();
        let body = if req.method() == Method::HEAD {
            Self::empty_body()
        } else {
            Full::new(Bytes::from(html)).map_err(|e| match e {}).boxed()
        };
        let mut response_builder = http::Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "text/html; charset=utf-8")
            .header(CONTENT_LENGTH, content_length);
        if let Some(cache_control) = self.cache_policy.header_value(true) {
            response_builder = response_builder.header(CACHE_CONTROL, cache_control.clone());
        }
        response_builder
            .body(body)
            .map_err(|e| server_err!(ServerErrorCode::IOError, "Failed to build response: {}", e))
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
        if req_method != Method::GET && req_method != Method::HEAD {
            warn!("Method not allowed: {}", req_method);
            let mut response =
                self.build_text_response(StatusCode::METHOD_NOT_ALLOWED, "Method not allowed");
            response
                .headers_mut()
                .insert(ALLOW, HeaderValue::from_static("GET, HEAD"));
            return Ok(response);
        }

        let file_path = match self.resolve_path(req_path) {
            Ok(path) => path,
            Err(PathError::Traversal) => {
                warn!("Path traversal attempt: {}", req_path);
                return Ok(self.build_text_response(StatusCode::FORBIDDEN, "Forbidden"));
            }
            Err(PathError::Invalid) => {
                warn!("Invalid request path: {}", req_path);
                return Ok(self.build_text_response(StatusCode::BAD_REQUEST, "Bad request"));
            }
        };
        // A trailing slash names a directory; it never selects a file.
        let names_dir = req_path.ends_with('/');

        match self.lookup(&file_path).await {
            Lookup::File(path) if !names_dir => {
                info!("Serving file: {:?}", path);
                return self.serve_file(&path, &file_path, &req).await;
            }
            Lookup::Dir(dir_path) => {
                let index_path = match self.lookup(&dir_path.join(&self.index_file)).await {
                    Lookup::File(index_path) => Some(index_path),
                    Lookup::OutsideRoot => {
                        warn!(
                            "Path traversal attempt: {:?}",
                            dir_path.join(&self.index_file)
                        );
                        return Ok(self.build_text_response(StatusCode::FORBIDDEN, "Forbidden"));
                    }
                    _ => None,
                };

                if index_path.is_some() || self.autoindex {
                    // Relative URLs in an index page or listing need the trailing slash.
                    if !names_dir {
                        return Ok(self.build_directory_redirect(&req));
                    }
                    if let Some(index_path) = index_path {
                        info!("Serving index file: {:?}", index_path);
                        return self
                            .serve_file(&index_path, Path::new(&self.index_file), &req)
                            .await;
                    }
                    info!("Serving directory listing: {:?}", dir_path);
                    return self.serve_directory_listing(&req, &dir_path).await;
                }
            }
            Lookup::OutsideRoot => {
                warn!("Path traversal attempt: {:?}", file_path);
                return Ok(self.build_text_response(StatusCode::FORBIDDEN, "Forbidden"));
            }
            Lookup::File(_) | Lookup::Missing => {}
        }

        warn!("File not found: {:?}", file_path);
        if let Some(fallback_file) = &self.fallback_file {
            let fallback_path = self.root_dir.join(fallback_file);
            match self.lookup(&fallback_path).await {
                Lookup::File(path) => {
                    info!("Fallback to file: {:?}", path);
                    return self.serve_file(&path, Path::new(fallback_file), &req).await;
                }
                Lookup::OutsideRoot => {
                    warn!(
                        "Fallback file is out of root directory: {:?}",
                        fallback_path
                    );
                }
                Lookup::Dir(_) | Lookup::Missing => {
                    warn!("Fallback file not found: {:?}", fallback_path);
                }
            }
        }
        Ok(self.build_text_response(StatusCode::NOT_FOUND, "Not found"))
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
    use hyper::body::Body;
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
    async fn test_html_revalidates_for_index_and_fallback_paths() {
        let temp_dir = tempfile::tempdir().unwrap();
        let body = b"<script src='/assets/app.js'></script>";
        tokio::fs::write(temp_dir.path().join("index.html"), body)
            .await
            .unwrap();
        tokio::fs::create_dir(temp_dir.path().join("assets"))
            .await
            .unwrap();
        tokio::fs::write(temp_dir.path().join("assets/app.js"), b"export {}")
            .await
            .unwrap();

        let server = Arc::new(
            DirServer::builder()
                .id("test")
                .root_path(temp_dir.path().to_path_buf())
                .fallback_file("index.html")
                .build()
                .await
                .unwrap(),
        );

        for path in ["/", "/index.html", "/documents/notes?src=notes.md"] {
            let uri = format!("http://localhost{path}");
            let response = request_dir_server(server.clone(), &uri, &[]).await;
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(response.headers()[CACHE_CONTROL], "no-cache");
            let etag = response.headers()[ETAG].to_str().unwrap().to_string();
            let modified = response.headers()[LAST_MODIFIED]
                .to_str()
                .unwrap()
                .to_string();
            assert_eq!(response.collect().await.unwrap().to_bytes().as_ref(), body);

            for validator in [("if-none-match", etag), ("if-modified-since", modified)] {
                let response = request_dir_server(server.clone(), &uri, &[validator]).await;
                assert_eq!(response.status(), StatusCode::NOT_MODIFIED);
                assert_eq!(response.headers()[CACHE_CONTROL], "no-cache");
            }

            let response =
                request_dir_server(server.clone(), &uri, &[("range", "bytes=0-6".to_string())])
                    .await;
            assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
            assert_eq!(response.headers()[CACHE_CONTROL], "no-cache");
            assert_eq!(
                response.collect().await.unwrap().to_bytes().as_ref(),
                &body[..7]
            );
        }

        let uri = "http://localhost/assets/app.js";
        let response = request_dir_server(server.clone(), uri, &[]).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(!response.headers().contains_key(CACHE_CONTROL));
        let etag = response.headers()[ETAG].to_str().unwrap().to_string();
        assert_eq!(
            response.collect().await.unwrap().to_bytes().as_ref(),
            b"export {}"
        );
        let response = request_dir_server(server.clone(), uri, &[("if-none-match", etag)]).await;
        assert_eq!(response.status(), StatusCode::NOT_MODIFIED);
        assert!(!response.headers().contains_key(CACHE_CONTROL));
        let response = request_dir_server(server, uri, &[("range", "bytes=0-5".to_string())]).await;
        assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
        assert!(!response.headers().contains_key(CACHE_CONTROL));
        assert_eq!(
            response.collect().await.unwrap().to_bytes().as_ref(),
            b"export"
        );
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
    async fn test_archive_mtime_does_not_validate_stale_content() {
        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("index.html");
        let old_body = b"<script src='/assets/old.js'></script>";
        let new_body = b"<script src='/assets/new.js'></script>";
        assert_eq!(old_body.len(), new_body.len());

        for mode in ["exact", "before"] {
            for modified in [UNIX_EPOCH, UNIX_EPOCH - Duration::from_secs(1)] {
                tokio::fs::write(&file_path, old_body).await.unwrap();
                std::fs::File::open(&file_path)
                    .unwrap()
                    .set_times(std::fs::FileTimes::new().set_modified(modified))
                    .unwrap();

                let server = Arc::new(
                    DirServer::builder()
                        .id("test")
                        .root_path(temp_dir.path().to_path_buf())
                        .if_modified_since(mode)
                        .build()
                        .await
                        .unwrap(),
                );

                let initial = request_dir_server(server.clone(), "http://localhost/", &[]).await;
                assert_eq!(initial.status(), StatusCode::OK);
                assert_eq!(initial.headers()[CACHE_CONTROL], "no-cache");
                assert!(!initial.headers().contains_key(ETAG));
                assert!(!initial.headers().contains_key(LAST_MODIFIED));
                assert_eq!(
                    initial.collect().await.unwrap().to_bytes().as_ref(),
                    old_body
                );

                // A package update changes the asset URL but preserves its size and mtime.
                tokio::fs::write(&file_path, new_body).await.unwrap();
                std::fs::File::open(&file_path)
                    .unwrap()
                    .set_times(std::fs::FileTimes::new().set_modified(modified))
                    .unwrap();

                let old_etag = format!("\"{:x}-0-0\"", old_body.len());
                let old_date = httpdate::fmt_http_date(UNIX_EPOCH);
                for headers in [
                    vec![("if-none-match", old_etag.clone())],
                    vec![("if-modified-since", old_date.clone())],
                    vec![("if-none-match", old_etag), ("if-modified-since", old_date)],
                ] {
                    let response =
                        request_dir_server(server.clone(), "http://localhost/", &headers).await;
                    assert_eq!(response.status(), StatusCode::OK);
                    assert_eq!(response.headers()[CACHE_CONTROL], "no-cache");
                    assert!(!response.headers().contains_key(ETAG));
                    assert!(!response.headers().contains_key(LAST_MODIFIED));
                    assert_eq!(
                        response.collect().await.unwrap().to_bytes().as_ref(),
                        new_body
                    );
                }
            }
        }
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

    async fn send_dir_request(
        server: Arc<DirServer>,
        method: &str,
        uri: &str,
        headers: &[(&str, String)],
    ) -> http::Response<BoxBody<Bytes, ServerError>> {
        let mut builder = http::Request::builder().method(method).uri(uri);
        for (name, value) in headers {
            builder = builder.header(*name, value.as_str());
        }
        let request = builder
            .body(Full::new(Bytes::new()).map_err(|e| match e {}).boxed())
            .unwrap();
        server
            .serve_request(request, StreamInfo::default())
            .await
            .unwrap()
    }

    async fn body_of(resp: http::Response<BoxBody<Bytes, ServerError>>) -> Vec<u8> {
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec()
    }

    fn header<'a, B>(resp: &'a http::Response<B>, name: &str) -> Option<&'a str> {
        resp.headers().get(name).and_then(|v| v.to_str().ok())
    }

    /// Writes one raw HTTP/1.1 request to the server and returns the whole
    /// response stream, so a HEAD response can be checked for stray body bytes.
    async fn raw_http_exchange(server: Arc<DirServer>, request: &str) -> Vec<u8> {
        use tokio::io::AsyncWriteExt;

        let (mut client, server_stream) = tokio::io::duplex(64 * 1024);
        tokio::spawn(async move {
            let _ = hyper_serve_http1(Box::new(server_stream), server, StreamInfo::default()).await;
        });
        client.write_all(request.as_bytes()).await.unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        response
    }

    async fn digits_server(etag: bool) -> (tempfile::TempDir, Arc<DirServer>) {
        let temp_dir = tempfile::tempdir().unwrap();
        tokio::fs::write(temp_dir.path().join("digits.txt"), b"0123456789")
            .await
            .unwrap();
        tokio::fs::write(temp_dir.path().join("empty.txt"), b"")
            .await
            .unwrap();
        let server = Arc::new(
            DirServer::builder()
                .id("test")
                .root_path(temp_dir.path().to_path_buf())
                .etag(etag)
                .build()
                .await
                .unwrap(),
        );
        (temp_dir, server)
    }

    #[tokio::test]
    async fn test_file_body_uses_bounded_stream_buffer() {
        let temp_dir = tempfile::tempdir().unwrap();
        let size = 64 * 1024 * 1024u64;
        // Sparse: the test needs the size, not the disk space.
        let file = std::fs::File::create(temp_dir.path().join("big.bin")).unwrap();
        file.set_len(size).unwrap();
        drop(file);

        let server = Arc::new(
            DirServer::builder()
                .id("test")
                .root_path(temp_dir.path().to_path_buf())
                .build()
                .await
                .unwrap(),
        );

        // HEAD never builds a file stream.
        let resp = send_dir_request(server.clone(), "HEAD", "/big.bin", &[]).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(header(&resp, "content-length"), Some("67108864"));
        assert_eq!(resp.body().size_hint().exact(), Some(0));
        assert!(resp.body().is_end_stream());

        let start = 32 * 1024 * 1024u64;
        let end = start + 1024 * 1024 - 1;
        for (method_headers, expected_len) in [
            (vec![], size),
            (
                vec![("range", format!("bytes={}-{}", start, end))],
                end - start + 1,
            ),
        ] {
            let mut body = send_dir_request(server.clone(), "GET", "/big.bin", &method_headers)
                .await
                .into_body();
            let mut total = 0u64;
            let mut largest = 0usize;
            while let Some(frame) = body.frame().await {
                let data = frame.unwrap().into_data().unwrap();
                largest = largest.max(data.len());
                total += data.len() as u64;
            }
            assert_eq!(total, expected_len);
            assert!(
                largest > 0 && largest <= STREAM_BUFFER_SIZE,
                "frame of {largest} bytes"
            );
        }
    }

    #[tokio::test]
    async fn test_percent_encoded_paths_are_decoded_once() {
        let temp_dir = tempfile::tempdir().unwrap();
        for (name, body) in [
            ("a b.txt", "space"),
            ("中文.txt", "unicode"),
            ("100%.txt", "percent"),
            ("%41.txt", "literal-escape"),
        ] {
            tokio::fs::write(temp_dir.path().join(name), body)
                .await
                .unwrap();
        }
        tokio::fs::create_dir(temp_dir.path().join("sub dir"))
            .await
            .unwrap();
        tokio::fs::write(temp_dir.path().join("sub dir/inner.txt"), b"inner")
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

        for (uri, body) in [
            ("/a%20b.txt", "space"),
            ("/%E4%B8%AD%E6%96%87.txt", "unicode"),
            ("/100%25.txt", "percent"),
            // Decoding happens once: %2541 is the literal name "%41.txt".
            ("/%2541.txt", "literal-escape"),
            ("/sub%20dir/inner.txt", "inner"),
            ("/./sub%20dir//inner.txt", "inner"),
        ] {
            let resp = send_dir_request(server.clone(), "GET", uri, &[]).await;
            assert_eq!(resp.status(), StatusCode::OK, "{uri}");
            assert_eq!(body_of(resp).await, body.as_bytes(), "{uri}");
        }

        for (uri, status) in [
            ("/%41.txt", StatusCode::NOT_FOUND),
            ("/%2e%2e/etc/passwd", StatusCode::FORBIDDEN),
            ("/sub%20dir/%2E%2E/a%20b.txt", StatusCode::FORBIDDEN),
            ("/../a%20b.txt", StatusCode::FORBIDDEN),
            ("/sub%20dir%2Finner.txt", StatusCode::BAD_REQUEST),
            ("/a%00b.txt", StatusCode::BAD_REQUEST),
        ] {
            let resp = send_dir_request(server.clone(), "GET", uri, &[]).await;
            assert_eq!(resp.status(), status, "{uri}");
        }
    }

    fn listing_hrefs(html: &str) -> Vec<String> {
        html.split("<a href=\"")
            .skip(1)
            .filter_map(|rest| rest.split('"').next())
            .map(|href| {
                href.replace("&quot;", "\"")
                    .replace("&#39;", "'")
                    .replace("&lt;", "<")
                    .replace("&gt;", ">")
                    .replace("&amp;", "&")
            })
            .filter(|href| href != "../")
            .collect()
    }

    #[tokio::test]
    async fn test_autoindex_links_resolve_to_listed_entries() {
        let temp_dir = tempfile::tempdir().unwrap();
        let names = [
            "a b.txt",
            "中文.txt",
            "100%.txt",
            "q?x#y.txt",
            "amp&'quote\".txt",
            "back\\slash.txt",
            "colon:name.txt",
        ];
        for name in names {
            tokio::fs::write(temp_dir.path().join(name), name)
                .await
                .unwrap();
        }
        tokio::fs::create_dir(temp_dir.path().join("sub dir"))
            .await
            .unwrap();
        tokio::fs::write(temp_dir.path().join("sub dir/inner.txt"), b"inner")
            .await
            .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            let name = OsStr::from_bytes(b"raw\xff.txt");
            tokio::fs::write(temp_dir.path().join(name), b"raw-bytes")
                .await
                .unwrap();
        }

        let server = Arc::new(
            DirServer::builder()
                .id("test")
                .root_path(temp_dir.path().to_path_buf())
                .autoindex(true)
                .build()
                .await
                .unwrap(),
        );

        let resp = send_dir_request(server.clone(), "GET", "/", &[]).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let html = String::from_utf8(body_of(resp).await).unwrap();
        let hrefs = listing_hrefs(&html);
        let expected_entries = names.len() + 1 + usize::from(cfg!(unix));
        assert_eq!(hrefs.len(), expected_entries, "{hrefs:?}");

        let mut bodies = Vec::new();
        for href in hrefs {
            // The listing is served at "/", so "./x" resolves to "/x".
            let path = href.strip_prefix("./").expect("listing links are relative");
            let resp = send_dir_request(server.clone(), "GET", &format!("/{path}"), &[]).await;
            assert_eq!(resp.status(), StatusCode::OK, "{href}");
            let body = body_of(resp).await;
            if href.ends_with('/') {
                let sub_html = String::from_utf8(body).unwrap();
                assert!(sub_html.contains("Index of /sub dir/"), "{sub_html}");
                let sub_hrefs = listing_hrefs(&sub_html);
                assert_eq!(sub_hrefs, vec!["./inner.txt".to_string()]);
                let resp =
                    send_dir_request(server.clone(), "GET", "/sub%20dir/inner.txt", &[]).await;
                assert_eq!(body_of(resp).await, b"inner");
            } else {
                bodies.push(body);
            }
        }
        for name in names {
            assert!(bodies.iter().any(|body| body == name.as_bytes()), "{name}");
        }
        #[cfg(unix)]
        assert!(bodies.iter().any(|body| body == b"raw-bytes"));
    }

    #[tokio::test]
    async fn test_directory_urls_redirect_to_trailing_slash() {
        let temp_dir = tempfile::tempdir().unwrap();
        for dir in ["docs", "listed", "bare"] {
            tokio::fs::create_dir(temp_dir.path().join(dir))
                .await
                .unwrap();
        }
        tokio::fs::write(temp_dir.path().join("docs/index.html"), b"docs-index")
            .await
            .unwrap();
        tokio::fs::write(temp_dir.path().join("listed/item.txt"), b"item")
            .await
            .unwrap();
        tokio::fs::write(temp_dir.path().join("bare/item.txt"), b"item")
            .await
            .unwrap();
        tokio::fs::write(temp_dir.path().join("file.txt"), b"file")
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

        for (uri, location) in [
            ("/docs", "./docs/"),
            ("/docs?lang=en&x=1", "./docs/?lang=en&x=1"),
        ] {
            for method in ["GET", "HEAD"] {
                let resp = send_dir_request(server.clone(), method, uri, &[]).await;
                assert_eq!(
                    resp.status(),
                    StatusCode::MOVED_PERMANENTLY,
                    "{method} {uri}"
                );
                assert_eq!(header(&resp, "location"), Some(location));
            }
        }
        let resp = send_dir_request(server.clone(), "GET", "/docs/?lang=en", &[]).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_of(resp).await, b"docs-index");

        // Without an index or autoindex nothing is served as a directory, so
        // there is nothing to redirect to.
        let resp = send_dir_request(server.clone(), "GET", "/bare", &[]).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        // A trailing slash never selects a file.
        let resp = send_dir_request(server.clone(), "GET", "/file.txt/", &[]).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        let listing = Arc::new(
            DirServer::builder()
                .id("test")
                .root_path(temp_dir.path().to_path_buf())
                .base_url("/static")
                .autoindex(true)
                .build()
                .await
                .unwrap(),
        );
        for (uri, location) in [("/static", "./static/"), ("/static/listed", "./listed/")] {
            let resp = send_dir_request(listing.clone(), "GET", uri, &[]).await;
            assert_eq!(resp.status(), StatusCode::MOVED_PERMANENTLY, "{uri}");
            assert_eq!(header(&resp, "location"), Some(location));
        }
        let resp = send_dir_request(listing, "GET", "/static/listed/", &[]).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let html = String::from_utf8(body_of(resp).await).unwrap();
        assert_eq!(listing_hrefs(&html), vec!["./item.txt".to_string()]);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_symlink_mime_type_follows_requested_name() {
        let temp_dir = tempfile::tempdir().unwrap();
        let outside_dir = tempfile::tempdir().unwrap();
        let root = temp_dir.path();
        tokio::fs::write(root.join("blob"), b"export {}")
            .await
            .unwrap();
        tokio::fs::write(root.join("page"), b"<p>page</p>")
            .await
            .unwrap();
        tokio::fs::write(outside_dir.path().join("secret.txt"), b"secret")
            .await
            .unwrap();
        std::os::unix::fs::symlink(root.join("blob"), root.join("app.js")).unwrap();
        std::os::unix::fs::symlink("page", root.join("index.html")).unwrap();
        std::os::unix::fs::symlink(outside_dir.path().join("secret.txt"), root.join("leak.txt"))
            .unwrap();

        let server = Arc::new(
            DirServer::builder()
                .id("test")
                .root_path(root.to_path_buf())
                .build()
                .await
                .unwrap(),
        );

        let js_type = mime_guess::from_path("app.js").first_or_octet_stream();
        let resp = send_dir_request(server.clone(), "GET", "/app.js", &[]).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(header(&resp, "content-type"), Some(js_type.as_ref()));
        assert_eq!(body_of(resp).await, b"export {}");

        let resp = send_dir_request(server.clone(), "GET", "/blob", &[]).await;
        assert_eq!(
            header(&resp, "content-type"),
            Some("application/octet-stream")
        );

        // The index file is a symlink too; its configured name decides the type.
        let resp = send_dir_request(server.clone(), "GET", "/", &[]).await;
        assert_eq!(header(&resp, "content-type"), Some("text/html"));
        assert_eq!(header(&resp, "cache-control"), Some("no-cache"));

        let resp = send_dir_request(server, "GET", "/leak.txt", &[]).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_range_requests() {
        let (_temp_dir, server) = digits_server(true).await;

        for (range, body, content_range) in [
            ("bytes=0-1", "01", "bytes 0-1/10"),
            ("bytes=-3", "789", "bytes 7-9/10"),
            ("bytes=-30", "0123456789", "bytes 0-9/10"),
            ("bytes=5-", "56789", "bytes 5-9/10"),
            ("bytes=5-999", "56789", "bytes 5-9/10"),
            ("bytes=9-9", "9", "bytes 9-9/10"),
            ("BYTES = 2-3", "23", "bytes 2-3/10"),
            ("bytes=3-4,", "34", "bytes 3-4/10"),
            (
                "bytes=0-99999999999999999999999",
                "0123456789",
                "bytes 0-9/10",
            ),
        ] {
            let resp = send_dir_request(
                server.clone(),
                "GET",
                "/digits.txt",
                &[("range", range.to_string())],
            )
            .await;
            assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT, "{range}");
            assert_eq!(
                header(&resp, "content-range"),
                Some(content_range),
                "{range}"
            );
            assert_eq!(
                header(&resp, "content-length"),
                Some(body.len().to_string().as_str())
            );
            assert_eq!(body_of(resp).await, body.as_bytes(), "{range}");
        }

        for range in [
            "bytes=10-",
            "bytes=10-20",
            "bytes=-0",
            "bytes=99999999999999999999999-",
        ] {
            let resp = send_dir_request(
                server.clone(),
                "GET",
                "/digits.txt",
                &[("range", range.to_string())],
            )
            .await;
            assert_eq!(resp.status(), StatusCode::RANGE_NOT_SATISFIABLE, "{range}");
            assert_eq!(
                header(&resp, "content-range"),
                Some("bytes */10"),
                "{range}"
            );
        }

        // Multipart ranges are not supported, and invalid fields or other
        // units are ignored: the complete file with 200, never an invented range.
        for range in [
            "bytes=0-1,7-8",
            "bytes=0-1, 20-30",
            "bytes=3-1",
            "bytes=a-b",
            "bytes=",
            "bytes=-",
            "bytes=1",
            "items=0-1",
            "0-1",
        ] {
            let resp = send_dir_request(
                server.clone(),
                "GET",
                "/digits.txt",
                &[("range", range.to_string())],
            )
            .await;
            assert_eq!(resp.status(), StatusCode::OK, "{range}");
            assert!(!resp.headers().contains_key(CONTENT_RANGE), "{range}");
            assert_eq!(body_of(resp).await, b"0123456789", "{range}");
        }

        for (range, status, content_range) in [
            (
                "bytes=0-0",
                StatusCode::RANGE_NOT_SATISFIABLE,
                Some("bytes */0"),
            ),
            (
                "bytes=0-",
                StatusCode::RANGE_NOT_SATISFIABLE,
                Some("bytes */0"),
            ),
            ("bytes=-5", StatusCode::OK, None),
            (
                "bytes=-0",
                StatusCode::RANGE_NOT_SATISFIABLE,
                Some("bytes */0"),
            ),
        ] {
            let resp = send_dir_request(
                server.clone(),
                "GET",
                "/empty.txt",
                &[("range", range.to_string())],
            )
            .await;
            assert_eq!(resp.status(), status, "empty {range}");
            assert_eq!(
                header(&resp, "content-range"),
                content_range,
                "empty {range}"
            );
            if status == StatusCode::OK {
                assert_eq!(header(&resp, "content-length"), Some("0"));
                assert!(body_of(resp).await.is_empty());
            }
        }
    }

    #[tokio::test]
    async fn test_conditional_request_precedence() {
        let (temp_dir, server) = digits_server(true).await;
        let resp = send_dir_request(server.clone(), "GET", "/digits.txt", &[]).await;
        let etag = header(&resp, "etag").unwrap().to_string();
        let last_modified = header(&resp, "last-modified").unwrap().to_string();
        let modified = tokio::fs::metadata(temp_dir.path().join("digits.txt"))
            .await
            .unwrap()
            .modified()
            .unwrap();
        let earlier = httpdate::fmt_http_date(modified - Duration::from_secs(3600));
        let later = httpdate::fmt_http_date(modified + Duration::from_secs(3600));
        let stale_etag = "\"a-1-1\"".to_string();
        let weak_etag = format!("W/{etag}");

        let cases: Vec<(Vec<(&str, String)>, StatusCode)> = vec![
            (vec![("if-match", etag.clone())], StatusCode::OK),
            (
                vec![("if-match", format!("{stale_etag}, {etag}"))],
                StatusCode::OK,
            ),
            (vec![("if-match", "*".to_string())], StatusCode::OK),
            (
                vec![("if-match", stale_etag.clone())],
                StatusCode::PRECONDITION_FAILED,
            ),
            // If-Match uses the strong comparison.
            (
                vec![("if-match", weak_etag.clone())],
                StatusCode::PRECONDITION_FAILED,
            ),
            (
                vec![("if-match", "garbage".to_string())],
                StatusCode::PRECONDITION_FAILED,
            ),
            // A failed If-Match outranks a matching If-None-Match.
            (
                vec![
                    ("if-match", stale_etag.clone()),
                    ("if-none-match", etag.clone()),
                ],
                StatusCode::PRECONDITION_FAILED,
            ),
            (
                vec![("if-unmodified-since", earlier.clone())],
                StatusCode::PRECONDITION_FAILED,
            ),
            (vec![("if-unmodified-since", later.clone())], StatusCode::OK),
            (
                vec![("if-unmodified-since", "not a date".to_string())],
                StatusCode::OK,
            ),
            // If-Match present: If-Unmodified-Since is not evaluated.
            (
                vec![
                    ("if-match", etag.clone()),
                    ("if-unmodified-since", earlier.clone()),
                ],
                StatusCode::OK,
            ),
            (
                vec![("if-none-match", etag.clone())],
                StatusCode::NOT_MODIFIED,
            ),
            // If-None-Match uses the weak comparison.
            (
                vec![("if-none-match", weak_etag.clone())],
                StatusCode::NOT_MODIFIED,
            ),
            (
                vec![("if-none-match", "*".to_string())],
                StatusCode::NOT_MODIFIED,
            ),
            (vec![("if-none-match", stale_etag.clone())], StatusCode::OK),
            // If-None-Match present: If-Modified-Since is not evaluated.
            (
                vec![
                    ("if-none-match", stale_etag.clone()),
                    ("if-modified-since", last_modified.clone()),
                ],
                StatusCode::OK,
            ),
            (
                vec![("if-modified-since", last_modified.clone())],
                StatusCode::NOT_MODIFIED,
            ),
            // Range on a not-modified resource is still 304.
            (
                vec![
                    ("if-none-match", etag.clone()),
                    ("range", "bytes=0-1".to_string()),
                ],
                StatusCode::NOT_MODIFIED,
            ),
        ];
        for (headers, status) in cases {
            for method in ["GET", "HEAD"] {
                let resp = send_dir_request(server.clone(), method, "/digits.txt", &headers).await;
                assert_eq!(resp.status(), status, "{method} {headers:?}");
            }
        }

        let mut headers = http::HeaderMap::new();
        headers.append(IF_NONE_MATCH, HeaderValue::from_static("\"other\""));
        headers.append(IF_NONE_MATCH, HeaderValue::try_from(etag.as_str()).unwrap());
        assert_eq!(
            server.evaluate_preconditions(&headers, Some(etag.as_str()), Some(modified)),
            Precondition::NotModified
        );

        // If-Range decides between the range and the complete current file,
        // so a resumed download never mixes two versions.
        for (if_range, status) in [
            (etag.clone(), StatusCode::PARTIAL_CONTENT),
            (last_modified.clone(), StatusCode::PARTIAL_CONTENT),
            (stale_etag.clone(), StatusCode::OK),
            (weak_etag.clone(), StatusCode::OK),
            (earlier.clone(), StatusCode::OK),
            ("garbage".to_string(), StatusCode::OK),
        ] {
            let resp = send_dir_request(
                server.clone(),
                "GET",
                "/digits.txt",
                &[
                    ("range", "bytes=2-3".to_string()),
                    ("if-range", if_range.clone()),
                ],
            )
            .await;
            assert_eq!(resp.status(), status, "{if_range}");
            let body = body_of(resp).await;
            if status == StatusCode::OK {
                assert_eq!(body, b"0123456789");
            } else {
                assert_eq!(body, b"23");
            }
        }
        // A stale If-Range also bypasses an unsatisfiable range.
        let resp = send_dir_request(
            server.clone(),
            "GET",
            "/digits.txt",
            &[("range", "bytes=50-".to_string()), ("if-range", stale_etag)],
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        // If-Range without Range changes nothing.
        let resp = send_dir_request(
            server,
            "GET",
            "/digits.txt",
            &[("if-range", "\"other\"".to_string())],
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_conditional_requests_without_etag() {
        let (_temp_dir, server) = digits_server(false).await;
        let resp = send_dir_request(server.clone(), "GET", "/digits.txt", &[]).await;
        assert!(!resp.headers().contains_key(ETAG));

        for (headers, status) in [
            (
                vec![("if-none-match", "*".to_string())],
                StatusCode::NOT_MODIFIED,
            ),
            (
                vec![("if-none-match", "\"a-1-1\"".to_string())],
                StatusCode::OK,
            ),
            (vec![("if-match", "*".to_string())], StatusCode::OK),
            (
                vec![("if-match", "\"a-1-1\"".to_string())],
                StatusCode::PRECONDITION_FAILED,
            ),
            (
                vec![
                    ("range", "bytes=0-1".to_string()),
                    ("if-range", "\"a-1-1\"".to_string()),
                ],
                StatusCode::OK,
            ),
        ] {
            let resp = send_dir_request(server.clone(), "GET", "/digits.txt", &headers).await;
            assert_eq!(resp.status(), status, "{headers:?}");
        }
    }

    fn split_raw_response(raw: &[u8]) -> (String, Vec<u8>) {
        let end = raw
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .expect("response head must be complete");
        (
            String::from_utf8(raw[..end].to_vec())
                .unwrap()
                .to_ascii_lowercase(),
            raw[end + 4..].to_vec(),
        )
    }

    #[tokio::test]
    async fn test_head_over_http_has_metadata_and_no_body() {
        let (temp_dir, server) = digits_server(true).await;
        tokio::fs::create_dir(temp_dir.path().join("listed"))
            .await
            .unwrap();
        tokio::fs::write(temp_dir.path().join("listed/item.txt"), b"item")
            .await
            .unwrap();
        let listing = Arc::new(
            DirServer::builder()
                .id("test")
                .root_path(temp_dir.path().to_path_buf())
                .autoindex(true)
                .build()
                .await
                .unwrap(),
        );

        for range in ["", "Range: bytes=0-1\r\n"] {
            let raw = raw_http_exchange(
                server.clone(),
                &format!(
                    "HEAD /digits.txt HTTP/1.1\r\nHost: localhost\r\n{range}Connection: close\r\n\r\n"
                ),
            )
            .await;
            let (head, body) = split_raw_response(&raw);
            assert!(head.starts_with("http/1.1 200 ok"), "{head}");
            assert!(head.contains("\r\ncontent-length: 10"), "{head}");
            assert!(head.contains("\r\naccept-ranges: bytes"), "{head}");
            assert!(head.contains("\r\netag: "), "{head}");
            assert!(!head.contains("content-range"), "{head}");
            assert!(body.is_empty(), "HEAD sent {} body bytes", body.len());
        }

        let get = raw_http_exchange(
            listing.clone(),
            "GET /listed/ HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        let (_, get_body) = split_raw_response(&get);
        let raw = raw_http_exchange(
            listing,
            "HEAD /listed/ HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        let (head, body) = split_raw_response(&raw);
        assert!(head.starts_with("http/1.1 200 ok"), "{head}");
        assert!(
            head.contains(&format!("\r\ncontent-length: {}", get_body.len())),
            "{head}"
        );
        assert!(body.is_empty());

        // Keep-alive: the next response starts right after the HEAD response head.
        let raw = raw_http_exchange(
            server,
            "HEAD /digits.txt HTTP/1.1\r\nHost: localhost\r\n\r\nGET /digits.txt HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        let (_, rest) = split_raw_response(&raw);
        assert!(rest.starts_with(b"HTTP/1.1 200 OK"));
        assert!(rest.ends_with(b"\r\n\r\n0123456789"));
    }

    #[tokio::test]
    async fn test_cache_policy_is_configurable() {
        let temp_dir = tempfile::tempdir().unwrap();
        tokio::fs::write(temp_dir.path().join("index.html"), b"<p>x</p>")
            .await
            .unwrap();
        tokio::fs::write(temp_dir.path().join("app.js"), b"export {}")
            .await
            .unwrap();
        tokio::fs::create_dir(temp_dir.path().join("listed"))
            .await
            .unwrap();

        async fn cache_headers(
            server: DirServer,
        ) -> (
            Option<String>,
            Option<String>,
            Option<String>,
            Option<String>,
        ) {
            let server = Arc::new(server);
            let html = send_dir_request(server.clone(), "GET", "/", &[]).await;
            let etag = header(&html, "etag").unwrap().to_string();
            let not_modified =
                send_dir_request(server.clone(), "GET", "/", &[("if-none-match", etag)]).await;
            assert_eq!(not_modified.status(), StatusCode::NOT_MODIFIED);
            let js = send_dir_request(server.clone(), "GET", "/app.js", &[]).await;
            let listing = send_dir_request(server, "GET", "/listed/", &[]).await;
            assert_eq!(listing.status(), StatusCode::OK);
            let get = |resp: &http::Response<BoxBody<Bytes, ServerError>>| {
                header(resp, "cache-control").map(str::to_string)
            };
            (get(&html), get(&not_modified), get(&js), get(&listing))
        }

        let builder = || {
            DirServer::builder()
                .id("test")
                .root_path(temp_dir.path().to_path_buf())
                .autoindex(true)
        };
        let no_cache = Some("no-cache".to_string());

        let default = cache_headers(builder().build().await.unwrap()).await;
        assert_eq!(
            default,
            (no_cache.clone(), no_cache.clone(), None, no_cache.clone())
        );

        let explicit = builder()
            .cache_policy("html-revalidate")
            .build()
            .await
            .unwrap();
        assert_eq!(cache_headers(explicit).await, default);

        let none = builder().cache_policy("none").build().await.unwrap();
        assert_eq!(cache_headers(none).await, (None, None, None, None));

        let custom = builder()
            .cache_policy("none")
            .html_cache_control("max-age=60")
            .cache_control("public, max-age=31536000, immutable")
            .build()
            .await
            .unwrap();
        let html = Some("max-age=60".to_string());
        assert_eq!(
            cache_headers(custom).await,
            (
                html.clone(),
                html.clone(),
                Some("public, max-age=31536000, immutable".to_string()),
                html
            )
        );

        for builder in [
            builder().cache_policy("aggressive"),
            builder().html_cache_control("no-cache\r\nx-injected: 1"),
            builder().cache_control("max-age=1\n"),
        ] {
            let err = builder.build().await.err().expect("invalid cache config");
            assert_eq!(err.code(), ServerErrorCode::InvalidConfig);
        }
    }

    #[tokio::test]
    async fn test_method_not_allowed_lists_allowed_methods() {
        let (_temp_dir, server) = digits_server(true).await;
        let resp = send_dir_request(server, "POST", "/digits.txt", &[]).await;
        assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(header(&resp, "allow"), Some("GET, HEAD"));
    }

    #[tokio::test]
    async fn test_base_url_strips_whole_segments() {
        let temp_dir = tempfile::tempdir().unwrap();
        tokio::fs::write(temp_dir.path().join("did.json"), b"did")
            .await
            .unwrap();
        tokio::fs::create_dir(temp_dir.path().join(".well-knownx"))
            .await
            .unwrap();
        tokio::fs::write(temp_dir.path().join(".well-knownx/did.json"), b"other")
            .await
            .unwrap();
        let server = Arc::new(
            DirServer::builder()
                .id("test")
                .root_path(temp_dir.path().to_path_buf())
                .base_url("/.well-known")
                .build()
                .await
                .unwrap(),
        );

        for (uri, body) in [
            ("/.well-known/did.json", "did"),
            ("/%2Ewell-known/did.json", "did"),
            ("/did.json", "did"),
            // Not the mount prefix: resolved relative to the root as is.
            ("/.well-knownx/did.json", "other"),
        ] {
            let resp = send_dir_request(server.clone(), "GET", uri, &[]).await;
            assert_eq!(resp.status(), StatusCode::OK, "{uri}");
            assert_eq!(body_of(resp).await, body.as_bytes(), "{uri}");
        }
    }
}
