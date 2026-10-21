#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

use nonzero_ext::nonzero;
use pin_project::pin_project;
use std::io;
use std::io::Error;
use std::marker::PhantomData;
use std::num::NonZeroU64;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::SystemTime;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub trait SpeedStat: 'static + Send + Sync {
    fn get_write_speed(&self) -> u64;
    fn get_write_sum_size(&self) -> u64;
    fn get_read_speed(&self) -> u64;
    fn get_read_sum_size(&self) -> u64;
}

pub trait SpeedTracker: SpeedStat {
    fn add_write_data_size(&self, size: u64);
    fn add_read_data_size(&self, size: u64);
}

pub trait TimePicker: 'static + Sync + Send {
    fn now() -> u128;
}

pub struct SystemTimePicker;

impl TimePicker for SystemTimePicker {
    fn now() -> u128 {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    }
}

struct DataItem {
    size: u64,
    time: u64,
}

pub(crate) struct SpeedState<T: TimePicker> {
    sum_size: u64,
    last_time: u128,
    speed_duration: NonZeroU64,
    data_items: Vec<DataItem>,
    _time_picker: PhantomData<T>,
}

impl<T: TimePicker> SpeedState<T> {
    fn new(speed_duration: NonZeroU64) -> SpeedState<T> {
        SpeedState {
            sum_size: 0,
            last_time: T::now(),
            speed_duration,
            data_items: vec![],
            _time_picker: Default::default(),
        }
    }

    pub fn add_data(&mut self, size: u64) {
        self.sum_size += size;
        let now = T::now().max(self.last_time);
        self.clear_invalid_item(now);

        if now / 1000 == self.last_time / 1000 {
            if self.data_items.len() == 0 {
                self.data_items.push(DataItem {
                    size,
                    time: (now / 1000) as u64,
                });
            } else {
                let last_item = self.data_items.last_mut().unwrap();
                if last_item.time == (now / 1000) as u64 {
                    last_item.size += size;
                } else {
                    self.data_items.push(DataItem {
                        size,
                        time: (now / 1000) as u64,
                    });
                }
            }
        } else {
            let duration = now - self.last_time;
            let mut pos = 0;
            let mut offset = 1000 - self.last_time % 1000;
            let mut sec = (self.last_time / 1000) as u64;
            while pos < duration {
                let mut weight = offset;
                if pos + offset > duration {
                    weight = duration - pos;
                }
                let data_size = (size as u128 * weight / duration) as u64;
                if self.data_items.len() == 0 {
                    self.data_items.push(DataItem {
                        size: data_size,
                        time: sec,
                    });
                } else {
                    let last_item = self.data_items.last_mut().unwrap();
                    if last_item.time == sec {
                        last_item.size += data_size;
                    } else {
                        self.data_items.push(DataItem {
                            size: data_size,
                            time: sec,
                        })
                    }
                }
                pos += offset;
                offset = 1000;
                sec += 1;
            }
        }
        self.last_time = now;
    }

    pub fn clear_invalid_item(&mut self, now: u128) {
        let now = (now / 1000) as u64;
        self.data_items
            .retain(|item| now.saturating_sub(item.time) <= self.speed_duration.get());
    }

    pub fn get_speed(&self) -> u64 {
        let now = (T::now().max(self.last_time) / 1000) as u64;
        let mut sum_size = 0;
        for item in self.data_items.iter() {
            if item.time < now && now.saturating_sub(item.time) <= self.speed_duration.get() {
                sum_size += item.size;
            }
        }

        sum_size / self.speed_duration
    }

    pub fn get_sum_size(&self) -> u64 {
        self.sum_size
    }
}

pub struct DefaultSpeedStat<T: TimePicker = SystemTimePicker> {
    upload_state: Mutex<SpeedState<T>>,
    download_state: Mutex<SpeedState<T>>,
}

impl DefaultSpeedStat {
    pub fn new() -> DefaultSpeedStat {
        Self {
            upload_state: Mutex::new(SpeedState::new(nonzero!(5u64))),
            download_state: Mutex::new(SpeedState::new(nonzero!(5u64))),
        }
    }

    /// Creates a new DefaultSpeedStat instance with the specified duration
    ///
    /// # Parameters
    /// * `duration` - The duration for statistics, in seconds
    ///
    /// # Returns
    /// Returns a new DefaultSpeedStat instance containing initialized upload and download states
    pub fn new_with_duration(duration: u64) -> DefaultSpeedStat {
        DefaultSpeedStat {
            upload_state: Mutex::new(SpeedState::new(NonZeroU64::new(duration).unwrap())),
            download_state: Mutex::new(SpeedState::new(NonZeroU64::new(duration).unwrap())),
        }
    }
}

impl<T: TimePicker> DefaultSpeedStat<T> {
    pub(crate) fn new_with_time_picker() -> DefaultSpeedStat<T> {
        DefaultSpeedStat {
            upload_state: Mutex::new(SpeedState::new(nonzero!(5u64))),
            download_state: Mutex::new(SpeedState::new(nonzero!(5u64))),
        }
    }
}

impl<T: TimePicker> SpeedTracker for DefaultSpeedStat<T> {
    fn add_write_data_size(&self, size: u64) {
        self.upload_state.lock().unwrap().add_data(size);
    }

    fn add_read_data_size(&self, size: u64) {
        self.download_state.lock().unwrap().add_data(size);
    }
}

impl<T: TimePicker> SpeedStat for DefaultSpeedStat<T> {
    fn get_write_speed(&self) -> u64 {
        self.upload_state.lock().unwrap().get_speed()
    }

    fn get_write_sum_size(&self) -> u64 {
        self.upload_state.lock().unwrap().get_sum_size()
    }

    fn get_read_speed(&self) -> u64 {
        self.download_state.lock().unwrap().get_speed()
    }

    fn get_read_sum_size(&self) -> u64 {
        self.download_state.lock().unwrap().get_sum_size()
    }
}

#[pin_project]
pub struct StatStream<T: AsyncRead + AsyncWrite + Send + 'static> {
    #[pin]
    stream: T,
    stat: Arc<dyn SpeedTracker>,
}

impl<T: AsyncRead + AsyncWrite + Send + 'static> StatStream<T> {
    pub fn new(stream: T) -> StatStream<T> {
        StatStream {
            stream,
            stat: Arc::new(DefaultSpeedStat::new()),
        }
    }

    pub fn new_with_tracker(stream: T, tracker: Arc<dyn SpeedTracker>) -> StatStream<T> {
        StatStream {
            stream,
            stat: tracker,
        }
    }
}

impl<T: AsyncRead + AsyncWrite + Send + 'static> StatStream<T> {
    pub(crate) fn new_test<S: TimePicker>(stream: T) -> StatStream<T> {
        StatStream {
            stream,
            stat: Arc::new(DefaultSpeedStat::<S>::new_with_time_picker()),
        }
    }

    pub fn get_speed_stat(&self) -> Arc<dyn SpeedStat> {
        self.stat.clone()
    }

    pub fn raw_stream(&mut self) -> &mut T {
        &mut self.stream
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> AsyncRead for StatStream<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.project();
        let filled_len = buf.filled().len();
        match this.stream.poll_read(cx, buf) {
            Poll::Ready(res) => {
                if res.is_ok() {
                    this.stat
                        .add_read_data_size((buf.filled().len() - filled_len) as u64);
                }
                Poll::Ready(res)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> AsyncWrite for StatStream<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        let this = self.project();
        match this.stream.poll_write(cx, buf) {
            Poll::Ready(Ok(size)) => {
                this.stat.add_write_data_size(size as u64);
                Poll::Ready(Ok(size))
            }
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        self.project().stream.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        self.project().stream.poll_shutdown(cx)
    }
}

#[pin_project]
pub struct StatRead<T: AsyncRead + Send + 'static> {
    #[pin]
    reader: T,
    stat: Arc<dyn SpeedTracker>,
}

impl<T: AsyncRead + Send + 'static> StatRead<T> {
    pub fn new(reader: T) -> StatRead<T> {
        StatRead {
            reader,
            stat: Arc::new(DefaultSpeedStat::new()),
        }
    }

    pub fn new_with_tracker(reader: T, tracker: Arc<dyn SpeedTracker>) -> StatRead<T> {
        StatRead {
            reader,
            stat: tracker,
        }
    }
}

impl<T: AsyncRead + Send + 'static> StatRead<T> {
    pub(crate) fn new_test<S: TimePicker>(reader: T) -> StatRead<T> {
        StatRead {
            reader,
            stat: Arc::new(DefaultSpeedStat::<S>::new_with_time_picker()),
        }
    }

    pub fn get_speed_stat(&self) -> Arc<dyn SpeedStat> {
        self.stat.clone()
    }

    pub fn raw_reader(&mut self) -> &mut T {
        &mut self.reader
    }
}

impl<T: AsyncRead + Unpin + Send + 'static> AsyncRead for StatRead<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.project();
        let filled_len = buf.filled().len();
        match this.reader.poll_read(cx, buf) {
            Poll::Ready(res) => {
                if res.is_ok() {
                    this.stat
                        .add_read_data_size((buf.filled().len() - filled_len) as u64);
                }
                Poll::Ready(res)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

#[pin_project]
pub struct StatWrite<T: AsyncWrite + Send + 'static> {
    #[pin]
    writer: T,
    stat: Arc<dyn SpeedTracker>,
}

impl<T: AsyncWrite + Send + 'static> StatWrite<T> {
    pub fn new(writer: T) -> StatWrite<T> {
        StatWrite {
            writer,
            stat: Arc::new(DefaultSpeedStat::new()),
        }
    }

    pub fn new_with_tracker(writer: T, tracker: Arc<dyn SpeedTracker>) -> StatWrite<T> {
        StatWrite {
            writer,
            stat: tracker,
        }
    }
}

impl<T: AsyncWrite + Send + 'static> StatWrite<T> {
    pub(crate) fn new_test<S: TimePicker>(writer: T) -> StatWrite<T> {
        StatWrite {
            writer,
            stat: Arc::new(DefaultSpeedStat::<S>::new_with_time_picker()),
        }
    }

    pub fn get_speed_stat(&self) -> Arc<dyn SpeedStat> {
        self.stat.clone()
    }

    pub fn raw_writer(&mut self) -> &mut T {
        &mut self.writer
    }
}

impl<T: AsyncWrite + Unpin + Send + 'static> AsyncWrite for StatWrite<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        let this = self.project();
        match this.writer.poll_write(cx, buf) {
            Poll::Ready(Ok(size)) => {
                this.stat.add_write_data_size(size as u64);
                Poll::Ready(Ok(size))
            }
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        self.project().writer.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        self.project().writer.poll_shutdown(cx)
    }
}
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    struct PartialStream {
        max_write_size: usize,
        read_size: usize,
    }

    impl AsyncRead for PartialStream {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let size = self.read_size.min(buf.remaining());
            buf.put_slice(&[0; 3][..size]);
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for PartialStream {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<Result<usize, io::Error>> {
            Poll::Ready(Ok(self.max_write_size.min(buf.len())))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn test_stat_stream_partial_write_counts_returned_size() {
        let tracker = Arc::new(DefaultSpeedStat::new());
        let stream = PartialStream {
            max_write_size: 3,
            read_size: 0,
        };
        let mut stream = StatStream::new_with_tracker(stream, tracker.clone());

        let written = stream.write(&[0; 10]).await.unwrap();

        assert_eq!(written, 3);
        assert_eq!(tracker.get_write_sum_size(), 3);
    }

    #[tokio::test]
    async fn test_stat_stream_partial_read_counts_newly_filled_size() {
        let tracker = Arc::new(DefaultSpeedStat::new());
        let stream = PartialStream {
            max_write_size: 0,
            read_size: 3,
        };
        let mut stream = StatStream::new_with_tracker(stream, tracker.clone());
        let mut storage = [0; 10];
        let mut buf = ReadBuf::new(&mut storage);
        buf.put_slice(&[0; 4]);

        let result =
            futures::future::poll_fn(|cx| Pin::new(&mut stream).poll_read(cx, &mut buf)).await;

        assert!(result.is_ok());
        assert_eq!(buf.filled().len(), 7);
        assert_eq!(tracker.get_read_sum_size(), 3);
    }

    #[tokio::test]
    async fn test_stat_stream_counts_only_transferred_bytes() {
        let tracker = Arc::new(DefaultSpeedStat::new());
        let stream = PartialStream {
            max_write_size: 3,
            read_size: 3,
        };
        let mut stream = StatStream::new_with_tracker(stream, tracker.clone());

        stream.write_all(&[0; 10]).await.unwrap();
        assert_eq!(tracker.get_write_sum_size(), 10);

        let mut storage = [0; 10];
        let mut buf = ReadBuf::new(&mut storage);
        buf.put_slice(&[0; 4]);
        let result =
            futures::future::poll_fn(|cx| Pin::new(&mut stream).poll_read(cx, &mut buf)).await;

        assert!(result.is_ok());
        assert_eq!(buf.filled().len(), 7);
        assert_eq!(tracker.get_read_sum_size(), 3);
    }

    #[tokio::test]
    async fn test_split_stat_io_counts_only_transferred_bytes() {
        let write_tracker = Arc::new(DefaultSpeedStat::new());
        let writer = PartialStream {
            max_write_size: 3,
            read_size: 0,
        };
        let mut writer = StatWrite::new_with_tracker(writer, write_tracker.clone());

        writer.write_all(&[0; 10]).await.unwrap();
        assert_eq!(write_tracker.get_write_sum_size(), 10);

        let zero_tracker = Arc::new(DefaultSpeedStat::new());
        let zero_writer = PartialStream {
            max_write_size: 0,
            read_size: 0,
        };
        let mut zero_writer = StatWrite::new_with_tracker(zero_writer, zero_tracker.clone());
        let err = zero_writer.write_all(&[0]).await.unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::WriteZero);
        assert_eq!(zero_tracker.get_write_sum_size(), 0);

        let read_tracker = Arc::new(DefaultSpeedStat::new());
        let reader = PartialStream {
            max_write_size: 0,
            read_size: 3,
        };
        let mut reader = StatRead::new_with_tracker(reader, read_tracker.clone());
        let mut storage = [0; 10];
        let mut buf = ReadBuf::new(&mut storage);
        buf.put_slice(&[0; 4]);
        let result =
            futures::future::poll_fn(|cx| Pin::new(&mut reader).poll_read(cx, &mut buf)).await;

        assert!(result.is_ok());
        assert_eq!(buf.filled().len(), 7);
        assert_eq!(read_tracker.get_read_sum_size(), 3);
    }

    #[test]
    fn test_speed_state_new() {
        // Mock TimePicker for testing
        static MOCK_TIME: AtomicU64 = AtomicU64::new(0);

        struct MockTimePicker;

        impl TimePicker for MockTimePicker {
            fn now() -> u128 {
                MOCK_TIME.load(Ordering::Relaxed) as u128
            }
        }

        // Helper function to set mock time
        fn set_mock_time(time_ms: u64) {
            MOCK_TIME.store(time_ms, Ordering::Relaxed);
        }

        set_mock_time(1000);
        let state: SpeedState<MockTimePicker> = SpeedState::new(nonzero!(5u64));

        assert_eq!(state.sum_size, 0);
        assert_eq!(state.last_time, 1000);
        assert_eq!(state.data_items.len(), 0);
    }

    #[test]
    fn test_add_data_same_second() {
        // Mock TimePicker for testing
        static MOCK_TIME: AtomicU64 = AtomicU64::new(0);

        struct MockTimePicker;

        impl TimePicker for MockTimePicker {
            fn now() -> u128 {
                MOCK_TIME.load(Ordering::Relaxed) as u128
            }
        }

        // Helper function to set mock time
        fn set_mock_time(time_ms: u64) {
            MOCK_TIME.store(time_ms, Ordering::Relaxed);
        }

        set_mock_time(1500);
        let mut state: SpeedState<MockTimePicker> = SpeedState::new(nonzero!(5u64));

        state.add_data(100);
        assert_eq!(state.sum_size, 100);
        assert_eq!(state.data_items.len(), 1);
        assert_eq!(state.data_items[0].size, 100);
        assert_eq!(state.data_items[0].time, 1); // 1000 / 1000 = 1

        state.add_data(200);
        assert_eq!(state.sum_size, 300);
        assert_eq!(state.data_items.len(), 1);
        assert_eq!(state.data_items[0].size, 300); // 合并到同一秒
    }

    #[test]
    fn test_add_data_different_seconds() {
        // Mock TimePicker for testing
        static MOCK_TIME: AtomicU64 = AtomicU64::new(0);

        struct MockTimePicker;

        impl TimePicker for MockTimePicker {
            fn now() -> u128 {
                MOCK_TIME.load(Ordering::Relaxed) as u128
            }
        }

        // Helper function to set mock time
        fn set_mock_time(time_ms: u64) {
            MOCK_TIME.store(time_ms, Ordering::Relaxed);
        }

        // Helper function to advance mock time
        fn advance_mock_time(delta_ms: u64) {
            MOCK_TIME.fetch_add(delta_ms, Ordering::Relaxed);
        }

        set_mock_time(1000);
        let mut state: SpeedState<MockTimePicker> = SpeedState::new(nonzero!(5u64));

        state.add_data(100);
        advance_mock_time(2000); // 时间前进到3000ms
        state.add_data(200);

        assert_eq!(state.sum_size, 300);
        assert_eq!(state.data_items.len(), 2);
        assert_eq!(state.data_items[0].size, 200);
        assert_eq!(state.data_items[0].time, 1);
        assert_eq!(state.data_items[1].size, 100);
        assert_eq!(state.data_items[1].time, 2);

        assert_eq!(state.get_speed(), 60);
        advance_mock_time(500);
        assert_eq!(state.get_speed(), 60);
        //
        state.add_data(300);
        assert_eq!(state.sum_size, 600);
        assert_eq!(state.get_speed(), 60);
        advance_mock_time(500);
        assert_eq!(state.get_speed(), 120);
    }

    #[test]
    fn test_add_data_cross_seconds_distribution() {
        // Mock TimePicker for testing
        static MOCK_TIME: AtomicU64 = AtomicU64::new(0);

        struct MockTimePicker;

        impl TimePicker for MockTimePicker {
            fn now() -> u128 {
                MOCK_TIME.load(Ordering::Relaxed) as u128
            }
        }

        // Helper function to set mock time
        fn set_mock_time(time_ms: u64) {
            MOCK_TIME.store(time_ms, Ordering::Relaxed);
        }

        // Helper function to advance mock time
        fn advance_mock_time(delta_ms: u64) {
            MOCK_TIME.fetch_add(delta_ms, Ordering::Relaxed);
        }

        // 测试跨秒时数据如何分配到不同的秒中
        set_mock_time(1500); // 1.5秒
        let mut state: SpeedState<MockTimePicker> = SpeedState::new(nonzero!(5u64));
        advance_mock_time(1500);

        // 从1500ms到3000ms，增加1500ms，跨越2个完整的秒(2s和3s)
        // 1.5s到2s有500ms，2s到3s有1000ms
        // 总共1500ms，添加300字节数据
        state.add_data(300);
        advance_mock_time(1500);

        // 应该创建两个数据项: 一个在第2秒，一个在第3秒
        // 第2秒应该有 300 * 500/1500 = 100 字节
        // 第3秒应该有 300 * 1000/1500 = 200 字节
        assert_eq!(state.data_items.len(), 2);
        assert_eq!(state.data_items[0].time, 1);
        assert_eq!(state.data_items[0].size, 100);
        assert_eq!(state.data_items[1].time, 2);
        assert_eq!(state.data_items[1].size, 200);

        // 测试跨秒时数据如何分配到不同的秒中
        set_mock_time(1500); // 1.5秒
        let mut state: SpeedState<MockTimePicker> = SpeedState::new(nonzero!(5u64));
        advance_mock_time(2000);

        // 从1500ms到3000ms，增加1500ms，跨越2个完整的秒(2s和3s)
        // 1.5s到2s有500ms，2s到3s有1000ms
        // 总共1500ms，添加300字节数据
        state.add_data(400);
        advance_mock_time(1500);

        // 应该创建两个数据项: 一个在第2秒，一个在第3秒
        // 第2秒应该有 300 * 500/1500 = 100 字节
        // 第3秒应该有 300 * 1000/1500 = 200 字节
        assert_eq!(state.data_items.len(), 3);
        assert_eq!(state.data_items[0].time, 1);
        assert_eq!(state.data_items[0].size, 100);
        assert_eq!(state.data_items[1].time, 2);
        assert_eq!(state.data_items[1].size, 200);
        assert_eq!(state.data_items[2].time, 3);
        assert_eq!(state.data_items[2].size, 100);
    }

    #[test]
    fn test_clear_invalid_item() {
        // Mock TimePicker for testing
        static MOCK_TIME: AtomicU64 = AtomicU64::new(0);

        struct MockTimePicker;

        impl TimePicker for MockTimePicker {
            fn now() -> u128 {
                MOCK_TIME.load(Ordering::Relaxed) as u128
            }
        }

        // Helper function to set mock time
        fn set_mock_time(time_ms: u64) {
            MOCK_TIME.store(time_ms, Ordering::Relaxed);
        }

        let mut state: SpeedState<MockTimePicker> = SpeedState::new(nonzero!(5u64));

        // 添加几个不同时间的数据项
        state.data_items.push(DataItem { size: 100, time: 5 }); // 5秒时的数据，应该被清除
        state.data_items.push(DataItem { size: 200, time: 7 }); // 7秒时的数据，应该保留
        state.data_items.push(DataItem { size: 300, time: 8 }); // 8秒时的数据，应该保留

        set_mock_time(11000); // 当前时间10秒
        state.clear_invalid_item(MockTimePicker::now());

        assert_eq!(state.data_items.len(), 2);
        assert_eq!(state.data_items[0].time, 7);
        assert_eq!(state.data_items[1].time, 8);
    }

    #[test]
    fn test_get_speed() {
        // Mock TimePicker for testing
        static MOCK_TIME: AtomicU64 = AtomicU64::new(0);

        struct MockTimePicker;

        impl TimePicker for MockTimePicker {
            fn now() -> u128 {
                MOCK_TIME.load(Ordering::Relaxed) as u128
            }
        }

        // Helper function to set mock time
        fn set_mock_time(time_ms: u64) {
            MOCK_TIME.store(time_ms, Ordering::Relaxed);
        }

        // Helper function to advance mock time
        fn advance_mock_time(delta_ms: u64) {
            MOCK_TIME.fetch_add(delta_ms, Ordering::Relaxed);
        }

        set_mock_time(10000); // 10秒
        let mut state: SpeedState<MockTimePicker> = SpeedState::new(nonzero!(5u64));

        state.add_data(100);
        advance_mock_time(1000);
        state.add_data(200);
        advance_mock_time(1000);
        state.add_data(300);
        advance_mock_time(1000);
        state.add_data(400);
        advance_mock_time(1000);
        state.add_data(500);
        advance_mock_time(1000);
        state.add_data(600);
        advance_mock_time(1000);
        state.add_data(700);

        let speed = state.get_speed();
        // 应该计算 300+400+500+600+700 = 2500 字节在4秒内 => 2500/5 = 500 bytes/sec
        assert_eq!(speed, 500);
    }

    #[test]
    fn test_get_sum_size() {
        // Mock TimePicker for testing
        static MOCK_TIME: AtomicU64 = AtomicU64::new(0);

        struct MockTimePicker;

        impl TimePicker for MockTimePicker {
            fn now() -> u128 {
                MOCK_TIME.load(Ordering::Relaxed) as u128
            }
        }

        let mut state: SpeedState<MockTimePicker> = SpeedState::new(nonzero!(10u64));
        state.add_data(100);
        state.add_data(200);
        assert_eq!(state.get_sum_size(), 300);
    }

    #[test]
    fn test_add_data_handles_clock_rollback() {
        static MOCK_TIME: AtomicU64 = AtomicU64::new(0);

        struct MockTimePicker;

        impl TimePicker for MockTimePicker {
            fn now() -> u128 {
                MOCK_TIME.load(Ordering::Relaxed) as u128
            }
        }

        fn set_mock_time(time_ms: u64) {
            MOCK_TIME.store(time_ms, Ordering::Relaxed);
        }

        set_mock_time(10_000);
        let mut state: SpeedState<MockTimePicker> = SpeedState::new(nonzero!(5u64));
        state.add_data(100);

        set_mock_time(9_000);
        state.add_data(50);

        assert_eq!(state.get_sum_size(), 150);
        assert_eq!(state.last_time, 10_000);
        assert_eq!(state.data_items.len(), 1);
        assert_eq!(state.data_items[0].time, 10);
        assert_eq!(state.data_items[0].size, 150);
    }

    #[test]
    fn test_speed_queries_handle_future_items_without_overflow() {
        static MOCK_TIME: AtomicU64 = AtomicU64::new(0);

        struct MockTimePicker;

        impl TimePicker for MockTimePicker {
            fn now() -> u128 {
                MOCK_TIME.load(Ordering::Relaxed) as u128
            }
        }

        fn set_mock_time(time_ms: u64) {
            MOCK_TIME.store(time_ms, Ordering::Relaxed);
        }

        let mut state: SpeedState<MockTimePicker> = SpeedState::new(nonzero!(5u64));
        state.data_items.push(DataItem {
            size: 100,
            time: 12,
        });

        set_mock_time(11_000);
        state.clear_invalid_item(MockTimePicker::now());
        assert_eq!(state.data_items.len(), 1);
        assert_eq!(state.get_speed(), 0);
    }

    #[test]
    fn test_speed_stat_impl() {
        // Mock TimePicker for testing
        static MOCK_TIME: AtomicU64 = AtomicU64::new(0);

        struct MockTimePicker;

        impl TimePicker for MockTimePicker {
            fn now() -> u128 {
                MOCK_TIME.load(Ordering::Relaxed) as u128
            }
        }

        // Helper function to set mock time
        fn set_mock_time(time_ms: u64) {
            MOCK_TIME.store(time_ms, Ordering::Relaxed);
        }

        let stat: DefaultSpeedStat<MockTimePicker> = DefaultSpeedStat::new_with_time_picker();

        stat.add_write_data_size(100);
        stat.add_read_data_size(200);

        // 由于没有时间流逝，速度为0
        assert_eq!(stat.get_write_speed(), 0);
        assert_eq!(stat.get_read_speed(), 0);

        // 模拟时间流逝后再次检查
        set_mock_time(5000);
        stat.add_write_data_size(500);
        stat.add_read_data_size(1000);
        set_mock_time(6000);
        stat.add_write_data_size(0);
        stat.add_read_data_size(0);

        // 现在应该有速度了
        assert!(stat.get_write_speed() > 0);
        assert!(stat.get_read_speed() > 0);
    }

    // 注意: StatStream的测试需要tokio运行时，这里省略了复杂的AsyncRead/AsyncWrite mock
    #[tokio::test]
    async fn test_stat_stream_creation() {
        static MOCK_TIME: AtomicU64 = AtomicU64::new(0);

        struct MockTimePicker;

        impl TimePicker for MockTimePicker {
            fn now() -> u128 {
                MOCK_TIME.load(Ordering::Relaxed) as u128
            }
        }

        // Helper function to advance mock time
        fn advance_mock_time(delta_ms: u64) {
            MOCK_TIME.fetch_add(delta_ms, Ordering::Relaxed);
        }

        // 创建一个简单的mock stream用于测试
        struct MockStream {
            future: Option<Pin<Box<dyn Future<Output = ()> + Send>>>,
        }

        impl AsyncRead for MockStream {
            fn poll_read(
                mut self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                _buf: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                if self.future.is_none() {
                    self.future = Some(Box::pin(tokio::time::sleep(Duration::from_millis(10))));
                }
                match Pin::new(self.future.as_mut().unwrap()).poll(_cx) {
                    Poll::Ready(_) => {
                        self.future = None;
                        _buf.set_filled(10);
                        Poll::Ready(Ok(()))
                    }
                    Poll::Pending => Poll::Pending,
                }
            }
        }

        impl AsyncWrite for MockStream {
            fn poll_write(
                mut self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                buf: &[u8],
            ) -> Poll<Result<usize, io::Error>> {
                if self.future.is_none() {
                    self.future = Some(Box::pin(tokio::time::sleep(Duration::from_millis(10))));
                }
                match Pin::new(self.future.as_mut().unwrap()).poll(_cx) {
                    Poll::Ready(_) => {
                        self.future = None;
                        Poll::Ready(Ok(buf.len()))
                    }
                    Poll::Pending => Poll::Pending,
                }
            }

            fn poll_flush(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
            ) -> Poll<Result<(), io::Error>> {
                Poll::Ready(Ok(()))
            }

            fn poll_shutdown(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
            ) -> Poll<Result<(), Error>> {
                Poll::Ready(Ok(()))
            }
        }

        impl Unpin for MockStream {}

        let stream = MockStream { future: None };
        let mut stat_stream = StatStream::new_test::<MockTimePicker>(stream);
        let speed_stat = stat_stream.get_speed_stat();
        let mut upload_size = 0;
        let mut download_size = 0;
        let mut buf = vec![0u8; 4096];
        advance_mock_time(500);
        for i in 0..100 {
            let size = stat_stream.write(&buf).await.unwrap();
            stat_stream.flush().await.unwrap();
            upload_size += size;
            let size = stat_stream.read(&mut buf).await.unwrap();
            download_size += size;
            advance_mock_time(1000);
            if i < 5 {
                assert_eq!(speed_stat.get_write_speed(), (upload_size / 5) as u64);
                assert_eq!(speed_stat.get_read_speed(), (download_size / 5) as u64);
            } else {
                assert_eq!(speed_stat.get_write_sum_size(), upload_size as u64);
                assert_eq!(speed_stat.get_read_sum_size(), download_size as u64);
                assert_eq!(speed_stat.get_write_speed(), (4096 * 5 - 2048) / 5);
                assert_eq!(speed_stat.get_read_speed(), (10 * 5 - 5) / 5);
            }
        }
        stat_stream.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn test_stat_read_creation() {
        static MOCK_TIME: AtomicU64 = AtomicU64::new(0);

        struct MockTimePicker;

        impl TimePicker for MockTimePicker {
            fn now() -> u128 {
                MOCK_TIME.load(Ordering::Relaxed) as u128
            }
        }

        // Helper function to advance mock time
        fn advance_mock_time(delta_ms: u64) {
            MOCK_TIME.fetch_add(delta_ms, Ordering::Relaxed);
        }

        // 创建一个简单的mock reader用于测试
        struct MockReader {
            future: Option<Pin<Box<dyn Future<Output = ()> + Send>>>,
        }

        impl AsyncRead for MockReader {
            fn poll_read(
                mut self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                _buf: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                if self.future.is_none() {
                    self.future = Some(Box::pin(tokio::time::sleep(Duration::from_millis(10))));
                }
                match Pin::new(self.future.as_mut().unwrap()).poll(_cx) {
                    Poll::Ready(_) => {
                        self.future = None;
                        _buf.set_filled(10);
                        Poll::Ready(Ok(()))
                    }
                    Poll::Pending => Poll::Pending,
                }
            }
        }

        impl Unpin for MockReader {}

        let reader = MockReader { future: None };
        let mut stat_reader = StatRead::new_test::<MockTimePicker>(reader);
        let speed_stat = stat_reader.get_speed_stat();
        let mut download_size = 0;
        let mut buf = vec![0u8; 4096];
        advance_mock_time(500);
        for i in 0..100 {
            let size = stat_reader.read(&mut buf).await.unwrap();
            download_size += size;
            advance_mock_time(1000);
            if i < 5 {
                assert_eq!(speed_stat.get_read_speed(), (download_size / 5) as u64);
            } else {
                assert_eq!(speed_stat.get_read_sum_size(), download_size as u64);
                assert_eq!(speed_stat.get_read_speed(), (10 * 5 - 5) / 5);
            }
        }
    }

    #[tokio::test]
    async fn test_stat_write_creation() {
        static MOCK_TIME: AtomicU64 = AtomicU64::new(0);

        struct MockTimePicker;

        impl TimePicker for MockTimePicker {
            fn now() -> u128 {
                MOCK_TIME.load(Ordering::Relaxed) as u128
            }
        }

        // Helper function to advance mock time
        fn advance_mock_time(delta_ms: u64) {
            MOCK_TIME.fetch_add(delta_ms, Ordering::Relaxed);
        }

        // 创建一个简单的mock writer用于测试
        struct MockWriter {
            future: Option<Pin<Box<dyn Future<Output = ()> + Send>>>,
        }

        impl AsyncWrite for MockWriter {
            fn poll_write(
                mut self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                buf: &[u8],
            ) -> Poll<Result<usize, io::Error>> {
                if self.future.is_none() {
                    self.future = Some(Box::pin(tokio::time::sleep(Duration::from_millis(10))));
                }
                match Pin::new(self.future.as_mut().unwrap()).poll(_cx) {
                    Poll::Ready(_) => {
                        self.future = None;
                        Poll::Ready(Ok(buf.len()))
                    }
                    Poll::Pending => Poll::Pending,
                }
            }

            fn poll_flush(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
            ) -> Poll<Result<(), io::Error>> {
                Poll::Ready(Ok(()))
            }

            fn poll_shutdown(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
            ) -> Poll<Result<(), Error>> {
                Poll::Ready(Ok(()))
            }
        }

        impl Unpin for MockWriter {}

        let writer = MockWriter { future: None };
        let mut stat_writer = StatWrite::new_test::<MockTimePicker>(writer);
        let speed_stat = stat_writer.get_speed_stat();
        let mut upload_size = 0;
        let buf = vec![0u8; 4096];
        advance_mock_time(500);
        for i in 0..100 {
            let size = stat_writer.write(&buf).await.unwrap();
            stat_writer.flush().await.unwrap();
            upload_size += size;
            advance_mock_time(1000);
            if i < 5 {
                assert_eq!(speed_stat.get_write_speed(), (upload_size / 5) as u64);
            } else {
                assert_eq!(speed_stat.get_write_sum_size(), upload_size as u64);
                assert_eq!(speed_stat.get_write_speed(), (4096 * 5 - 2048) / 5);
            }
        }
        stat_writer.shutdown().await.unwrap();
    }
}
