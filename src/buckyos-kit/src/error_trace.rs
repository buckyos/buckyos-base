use std::backtrace::{Backtrace, BacktraceStatus};
use std::error::Error;
use std::fmt;
use std::panic::Location;

/// Where an error was created, plus a backtrace when the environment asks for one.
///
/// Error types keep one of these next to their code and message. The constructor that
/// builds the error is marked `#[track_caller]`, so the location is the line that
/// created the error (for `xxx_err!`/`into_xxx_err!` it is the macro call site).
///
/// The backtrace comes from [`Backtrace::capture`]: it is only taken when
/// `RUST_BACKTRACE` or `RUST_LIB_BACKTRACE` is set, otherwise the cost is one cached
/// env check.
///
/// This is diagnostic data for `Debug` output and logs. Never put it into `Display`:
/// error text is often returned to clients.
pub struct ErrorTrace {
    location: &'static Location<'static>,
    backtrace: Option<Box<Backtrace>>,
}

impl ErrorTrace {
    #[track_caller]
    pub fn capture() -> Self {
        let backtrace = Backtrace::capture();
        let backtrace = match backtrace.status() {
            BacktraceStatus::Captured => Some(Box::new(backtrace)),
            _ => None,
        };
        Self {
            location: Location::caller(),
            backtrace,
        }
    }

    pub fn location(&self) -> &'static Location<'static> {
        self.location
    }

    pub fn backtrace(&self) -> Option<&Backtrace> {
        self.backtrace.as_deref()
    }

    /// Multi-line `Debug` form shared by error types that carry an `ErrorTrace`:
    ///
    /// ```text
    /// {code:?}: {msg}
    ///     at crate-dir/src/file.rs:line
    /// Stack backtrace:            (only when captured)
    /// ...
    /// Caused by: {source:?}       (each layer prints its own location)
    /// ```
    pub fn fmt_debug(
        &self,
        f: &mut fmt::Formatter<'_>,
        code: &dyn fmt::Debug,
        msg: &str,
        source: Option<&(dyn Error + 'static)>,
    ) -> fmt::Result {
        write!(f, "{:?}", code)?;
        if !msg.is_empty() {
            write!(f, ": {}", msg)?;
        }
        write!(f, "\n    at {}", self)?;
        if let Some(backtrace) = &self.backtrace {
            let backtrace = backtrace.to_string();
            write!(f, "\nStack backtrace:\n{}", backtrace.trim_end())?;
        }
        if let Some(source) = source {
            write!(f, "\nCaused by: {:?}", source)?;
        }
        Ok(())
    }
}

/// `crate-dir/src/file.rs:line`
impl fmt::Display for ErrorTrace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}",
            short_source_path(self.location.file()),
            self.location.line()
        )
    }
}

impl fmt::Debug for ErrorTrace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ErrorTrace")
            .field("location", &format_args!("{}", self))
            .field("backtrace", &self.backtrace.is_some())
            .finish()
    }
}

/// One-line `Display` form for error types: `{code:?}: {msg}: {source}`, empty parts
/// left out. It carries no location or backtrace, so it is safe to send to clients.
pub struct ErrorLine<'a> {
    code: &'a dyn fmt::Debug,
    msg: &'a str,
    source: Option<&'a (dyn Error + 'static)>,
}

impl<'a> ErrorLine<'a> {
    pub fn new(
        code: &'a dyn fmt::Debug,
        msg: &'a str,
        source: Option<&'a (dyn Error + 'static)>,
    ) -> Self {
        Self { code, msg, source }
    }
}

impl fmt::Display for ErrorLine<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.code)?;
        if !self.msg.is_empty() {
            write!(f, ": {}", self.msg)?;
        }
        if let Some(source) = self.source {
            write!(f, ": {}", source)?;
        }
        Ok(())
    }
}

// `file!()` is relative to the workspace root for local crates and absolute for
// registry/git checkouts; keep only `<crate-dir>/src/...`.
fn short_source_path(file: &str) -> &str {
    let is_sep = |c: u8| c == b'/' || c == b'\\';
    let bytes = file.as_bytes();
    for (idx, _) in file.rmatch_indices("src") {
        let starts_segment = idx == 0 || is_sep(bytes[idx - 1]);
        let ends_segment = bytes.get(idx + 3).map(|c| is_sep(*c)).unwrap_or(false);
        if !starts_segment || !ends_segment {
            continue;
        }
        if idx == 0 {
            return file;
        }
        let start = file[..idx - 1]
            .rfind(['/', '\\'])
            .map(|pos| pos + 1)
            .unwrap_or(0);
        return &file[start..];
    }
    file
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    enum TestErrorCode {
        #[default]
        Failed,
        NotFound,
    }

    #[derive(thiserror::Error)]
    #[error("{}", self.display_line())]
    struct TestError {
        code: TestErrorCode,
        msg: String,
        #[source]
        source: Option<Box<dyn Error + Send + Sync + 'static>>,
        trace: ErrorTrace,
    }

    impl TestError {
        #[track_caller]
        fn new(code: TestErrorCode, msg: impl Into<String>) -> Self {
            Self {
                code,
                msg: msg.into(),
                source: None,
                trace: ErrorTrace::capture(),
            }
        }

        #[track_caller]
        fn with_source(
            code: TestErrorCode,
            msg: impl Into<String>,
            source: impl Into<Box<dyn Error + Send + Sync + 'static>>,
        ) -> Self {
            Self {
                code,
                msg: msg.into(),
                source: Some(source.into()),
                trace: ErrorTrace::capture(),
            }
        }

        fn display_line(&self) -> ErrorLine<'_> {
            ErrorLine::new(
                &self.code,
                &self.msg,
                self.source.as_deref().map(|e| e as &(dyn Error + 'static)),
            )
        }
    }

    impl fmt::Debug for TestError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            self.trace.fmt_debug(
                f,
                &self.code,
                &self.msg,
                self.source.as_deref().map(|e| e as &(dyn Error + 'static)),
            )
        }
    }

    macro_rules! test_err {
        ( $fmt:literal ) => {
            TestError::new(::std::default::Default::default(), format!($fmt))
        };
        ( $code:path, $($arg:tt)* ) => {
            TestError::new($code, format!($($arg)*))
        };
    }

    macro_rules! into_test_err {
        ( $code:path, $($arg:tt)* ) => {
            |e| TestError::with_source($code, format!($($arg)*), e)
        };
    }

    #[test]
    fn location_is_constructor_call_site() {
        let line = line!() + 1;
        let trace = ErrorTrace::capture();
        assert_eq!(trace.location().file(), file!());
        assert_eq!(trace.location().line(), line);

        let line = line!() + 1;
        let err = TestError::new(TestErrorCode::NotFound, "x");
        assert_eq!(err.trace.location().line(), line);
    }

    #[test]
    fn location_is_macro_call_site() {
        let line = line!() + 1;
        let err = test_err!(TestErrorCode::NotFound, "user {} not found", "alice");
        assert_eq!(err.trace.location().file(), file!());
        assert_eq!(err.trace.location().line(), line);
        assert_eq!(err.code, TestErrorCode::NotFound);

        let line = line!() + 1;
        let err = test_err!("no code");
        assert_eq!(err.trace.location().line(), line);
        assert_eq!(err.code, TestErrorCode::Failed);

        let io: Result<(), std::io::Error> = Err(std::io::Error::other("disk"));
        let line = line!() + 1;
        let err = io.map_err(into_test_err!(TestErrorCode::Failed, "read")).unwrap_err();
        assert_eq!(err.trace.location().line(), line);
    }

    #[test]
    fn display_is_one_line_without_location() {
        let inner = test_err!(TestErrorCode::NotFound, "user alice not found");
        let outer = TestError::with_source(TestErrorCode::Failed, "load profile", inner);
        let text = outer.to_string();
        assert_eq!(
            text,
            "Failed: load profile: NotFound: user alice not found"
        );
        assert!(!text.contains(".rs:"));

        let empty = TestError::new(TestErrorCode::Failed, "");
        assert_eq!(empty.to_string(), "Failed");
    }

    #[test]
    fn debug_prints_location_of_every_layer() {
        let inner_line = line!() + 1;
        let inner = test_err!(TestErrorCode::NotFound, "user alice not found");
        let outer_line = line!() + 1;
        let outer = TestError::with_source(TestErrorCode::Failed, "load profile", inner);

        let text = format!("{:?}", outer);
        let short = short_source_path(file!());
        let outer_at = format!("    at {}:{}", short, outer_line);
        let inner_at = format!("    at {}:{}", short, inner_line);
        assert!(text.starts_with("Failed: load profile\n"), "{text}");
        assert!(text.contains(&outer_at), "{text}");
        assert!(text.contains("Caused by: NotFound: user alice not found"), "{text}");
        assert!(text.contains(&inner_at), "{text}");
        assert!(text.find(&outer_at).unwrap() < text.find(&inner_at).unwrap());
    }

    #[test]
    fn source_is_exposed_through_error_trait() {
        let io: Result<(), std::io::Error> = Err(std::io::Error::other("disk"));
        let err = io.map_err(into_test_err!(TestErrorCode::Failed, "read")).unwrap_err();
        let source = Error::source(&err).unwrap();
        assert_eq!(
            source.downcast_ref::<std::io::Error>().unwrap().kind(),
            std::io::ErrorKind::Other
        );
    }

    #[test]
    fn no_backtrace_without_env() {
        let enabled = |name: &str| std::env::var(name).map(|v| v != "0").unwrap_or(false);
        if enabled("RUST_BACKTRACE") || enabled("RUST_LIB_BACKTRACE") {
            return;
        }
        let trace = ErrorTrace::capture();
        assert!(trace.backtrace().is_none());
        assert!(!format!("{:?}", test_err!("x")).contains("Stack backtrace"));
    }

    #[test]
    fn short_source_path_keeps_crate_dir() {
        assert_eq!(
            short_source_path("components/cyfs-sn/src/sn_auth.rs"),
            "cyfs-sn/src/sn_auth.rs"
        );
        assert_eq!(
            short_source_path(
                "/cargo/git/checkouts/cyfs-gateway-1/5d2be8e/src/components/cyfs-sn/src/api/auth.rs"
            ),
            "cyfs-sn/src/api/auth.rs"
        );
        assert_eq!(short_source_path("src/lib.rs"), "src/lib.rs");
        assert_eq!(
            short_source_path("buckyos-kit/src/srcmap.rs"),
            "buckyos-kit/src/srcmap.rs"
        );
        assert_eq!(
            short_source_path("C:\\work\\base\\src\\kRPC\\src\\lib.rs"),
            "kRPC\\src\\lib.rs"
        );
        assert_eq!(short_source_path("main.rs"), "main.rs");
    }
}
