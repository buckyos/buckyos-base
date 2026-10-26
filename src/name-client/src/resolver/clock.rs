//! 墙钟(unix 秒):文档 exp、发布查询 TTL、查询槽与缓存条目共用的时间来源。
//!
//! 单调时间(预算、共享任务、退避)用 `tokio::time::Instant`,测试可用 Tokio 虚拟时钟;
//! 墙钟另由这里统一读取。`#[cfg(test)]` 下可在**当前线程**冻结 / 推进墙钟:
//! `#[tokio::test]` 默认是单线程运行时,spawn 的任务也在同一线程上执行;
//! `spawn_blocking`(文件后端的合并)不在测试线程上,仍读取真实时间。

use buckyos_kit::buckyos_get_unix_timestamp;

/// 当前墙钟(unix 秒)。
pub fn unix_now() -> u64 {
    #[cfg(test)]
    if let Some(now) = test_clock::get() {
        return now;
    }
    buckyos_get_unix_timestamp()
}

#[cfg(test)]
pub(crate) mod test_clock {
    use std::cell::Cell;

    thread_local! {
        static NOW: Cell<Option<u64>> = const { Cell::new(None) };
    }

    pub fn get() -> Option<u64> {
        NOW.with(|now| now.get())
    }

    /// 冻结当前线程的墙钟;读取时不会自动推进。
    pub fn set(now: u64) {
        NOW.with(|cell| cell.set(Some(now)));
    }

    pub fn advance(secs: u64) {
        NOW.with(|cell| {
            let now = cell.get().expect("test clock is not frozen");
            cell.set(Some(now + secs));
        });
    }

    pub fn clear() {
        NOW.with(|cell| cell.set(None));
    }

    /// 作用域内冻结墙钟,离开时恢复真实时间。
    pub struct Frozen;

    impl Frozen {
        pub fn at(now: u64) -> Self {
            set(now);
            Frozen
        }
    }

    impl Drop for Frozen {
        fn drop(&mut self) {
            clear();
        }
    }
}
