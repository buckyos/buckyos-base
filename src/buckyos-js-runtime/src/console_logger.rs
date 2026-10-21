use boa_engine::{Context, JsResult};
use boa_macros::{Finalize, Trace};
use boa_runtime::{ConsoleState, Logger};
use std::sync::{Arc, Mutex};
use boa_gc::Tracer;

#[derive(Debug, Clone)]
pub struct LogCache {
    entries: Arc<Mutex<Vec<String>>>,
}

unsafe impl boa_gc::Trace for LogCache {
    unsafe fn trace(&self, _tracer: &mut Tracer) {
    }

    unsafe fn trace_non_roots(&self) {
    }

    fn run_finalizer(&self) {
    }
}

impl boa_gc::Finalize for LogCache {
    fn finalize(&self) {
    }
}

impl LogCache {
    pub fn new() -> Self {
        LogCache {
            entries: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn push(&self, msg: String) {
        let mut cache = self.entries.lock().unwrap();
        cache.push(msg);
    }

    pub fn get_logs(&self) -> Vec<String> {
        let cache = self.entries.lock().unwrap();
        cache.clone()
    }
}

#[derive(Debug, Trace, Finalize)]
pub struct ConsoleLogger {
    pub log_cache: LogCache,
}

impl ConsoleLogger {
    pub fn new(log_cache: LogCache) -> Self {
        ConsoleLogger {
            log_cache,
        }
    }
}

impl Logger for ConsoleLogger {
    fn log(&self, msg: String, state: &ConsoleState, _context: &mut Context) -> JsResult<()> {
        let indent = state.indent();
        let formatted_msg = format!("{msg:>indent$}");
        log::info!("{}", formatted_msg);

        // 添加到缓存
        self.log_cache.push(formatted_msg);
        Ok(())
    }

    fn info(&self, msg: String, state: &ConsoleState, _context: &mut Context) -> JsResult<()> {
        let indent = state.indent();
        let formatted_msg = format!("{msg:>indent$}");
        log::info!("{}", formatted_msg);

        // 添加到缓存
        self.log_cache.push(formatted_msg);
        Ok(())
    }

    fn warn(&self, msg: String, state: &ConsoleState, _context: &mut Context) -> JsResult<()> {
        let indent = state.indent();
        let formatted_msg = format!("{msg:>indent$}");
        log::warn!("{}", formatted_msg);

        // 添加到缓存
        self.log_cache.push(formatted_msg);
        Ok(())
    }

    fn error(&self, msg: String, state: &ConsoleState, _context: &mut Context) -> JsResult<()> {
        let indent = state.indent();
        let formatted_msg = format!("{msg:>indent$}");
        log::error!("{}", formatted_msg);

        // 添加到缓存
        self.log_cache.push(formatted_msg);
        Ok(())
    }
}
