//! Runs JS packages with Boa: a package is a directory holding `pkg.yaml` (optional)
//! and a main script (`main.js` by default) that exports `main(args)`.
//!
//! Callers that need Boa types (`JsValue`, `JsString`, `NativeFunction`...) depend on
//! `boa_engine` directly, using the same version as this crate.

mod console_logger;
mod error;
mod js_engine;
mod js_pkg;

pub use error::*;
pub use js_engine::*;
pub use js_pkg::*;
