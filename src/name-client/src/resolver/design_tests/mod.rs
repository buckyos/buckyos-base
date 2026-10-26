//! doc/resolve-did单元测试设计.md 的内核组合测试。
//!
//! - `fixture`:ScriptedSource、K1/K2/KX、冻结墙钟、RequestTrace、闸门;
//! - `evidence`:T01–T06(版本槽、验证输入、closest 边界、证据维度、历史 key、站点绑定);
//! - `cache`:T07、T08、T16(有效期、负状态范围、提交后重新裁决);
//! - `context`:T09、T10、T11、T13(receipt、locker、默认类型、获取策略);
//! - `timing`:T14、T15、T17(共享任务、回流、预算分层);
//! - `properties`:§4 有约束的属性测试。
//!
//! 纯模型测试放在各模块自己的 `#[cfg(test)]` 里,HTTP 解析在 `http_doc` 里。

mod fixture;

mod cache;
mod context;
mod evidence;
mod properties;
mod timing;
