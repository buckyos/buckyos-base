use buckyos_kit::{ErrorLine, ErrorTrace};
use std::error::Error;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum JsRuntimeErrorCode {
    #[default]
    Failed,
    JsFailed,
    InvalidPath,
}

#[derive(thiserror::Error)]
#[error("{}", self.display_line())]
pub struct JsRuntimeError {
    code: JsRuntimeErrorCode,
    msg: String,
    #[source]
    source: Option<Box<dyn Error + Send + Sync + 'static>>,
    trace: ErrorTrace,
}

pub type JsRuntimeResult<T> = Result<T, JsRuntimeError>;

impl JsRuntimeError {
    #[track_caller]
    pub fn new(code: JsRuntimeErrorCode, msg: impl Into<String>) -> Self {
        Self {
            code,
            msg: msg.into(),
            source: None,
            trace: ErrorTrace::capture(),
        }
    }

    #[track_caller]
    pub fn with_source(
        code: JsRuntimeErrorCode,
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

    pub fn code(&self) -> JsRuntimeErrorCode {
        self.code
    }

    pub fn msg(&self) -> &str {
        &self.msg
    }

    pub fn trace(&self) -> &ErrorTrace {
        &self.trace
    }

    fn source_ref(&self) -> Option<&(dyn Error + 'static)> {
        self.source.as_deref().map(|e| e as &(dyn Error + 'static))
    }

    fn display_line(&self) -> ErrorLine<'_> {
        ErrorLine::new(&self.code, &self.msg, self.source_ref())
    }
}

impl fmt::Debug for JsRuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.trace
            .fmt_debug(f, &self.code, &self.msg, self.source_ref())
    }
}

/// `js_runtime_err!(code)` / `js_runtime_err!(code, fmt, args..)` / `js_runtime_err!(fmt, args..)`
#[macro_export]
macro_rules! js_runtime_err {
    ( $fmt:literal ) => {
        $crate::JsRuntimeError::new(::std::default::Default::default(), format!($fmt))
    };
    ( $fmt:literal, $($arg:tt)* ) => {
        $crate::JsRuntimeError::new(::std::default::Default::default(), format!($fmt, $($arg)*))
    };
    ( $code:path ) => {
        $crate::JsRuntimeError::new($code, ::std::string::String::new())
    };
    ( $code:path, $($arg:tt)* ) => {
        $crate::JsRuntimeError::new($code, format!($($arg)*))
    };
}

/// Closure for `map_err`: wraps the error as `source`. Same forms as `js_runtime_err!`.
#[macro_export]
macro_rules! into_js_runtime_err {
    ( $fmt:literal ) => {
        |e| $crate::JsRuntimeError::with_source(::std::default::Default::default(), format!($fmt), e)
    };
    ( $fmt:literal, $($arg:tt)* ) => {
        |e| $crate::JsRuntimeError::with_source(::std::default::Default::default(), format!($fmt, $($arg)*), e)
    };
    ( $code:path ) => {
        |e| $crate::JsRuntimeError::with_source($code, ::std::string::String::new(), e)
    };
    ( $code:path, $($arg:tt)* ) => {
        |e| $crate::JsRuntimeError::with_source($code, format!($($arg)*), e)
    };
}
