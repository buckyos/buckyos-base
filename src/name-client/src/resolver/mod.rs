//! resolve-did 重构后的解析器内核(设计稿:doc/resolve-did.py 与
//! doc/resolve-did协议冻结讨论伪代码.md;实施记录:doc/resolve-did重构-TODO.md)。
//!
//! 模块分层:
//! - `revision` / `budget` / `opts` / `publish_info` / `source` / `verify_result`:核心类型与预算(M1);
//! - `http_doc` / 各 provider:来源层(M2;模块不叫 `http`,避免 `use name_client::*` 遮蔽 http crate);
//! - `doc_result` / `store` / `local_locker` / `zone_locker`:缓存、locker 与提交(M3);
//! - `resolve` / `verify`:解析与验证主路径(M4);
//! - `concurrency`:串行锁、任务合并、退避与日志限流(M5)。

pub mod budget;
pub mod concurrency;
pub mod doc_result;
pub mod http_doc;
pub mod local_locker;
pub mod opts;
pub mod publish_info;
pub mod registry;
pub mod resolve;
pub mod revision;
pub mod source;
pub mod store;
pub mod verify;
pub mod verify_result;
pub mod zone_locker;

pub use budget::*;
pub use concurrency::*;
pub use doc_result::*;
pub use http_doc::*;
pub use local_locker::*;
pub use opts::*;
pub use publish_info::*;
pub use registry::*;
pub use resolve::*;
pub use revision::*;
pub use source::*;
pub use store::*;
pub use verify::*;
pub use verify_result::*;
pub use zone_locker::*;
