#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

use crate::SpeedLimitSession;

#[async_trait::async_trait]
pub trait DatagramSend: Send + 'static {
    type Error;
    async fn send_to(&mut self, buf: &[u8]) -> Result<usize, Self::Error>;
}

#[async_trait::async_trait]
pub trait DatagramRecv: Send + 'static {
    type Error;
    async fn recv_from(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error>;
}

enum ReadState {
    Idle,
    Reading((usize, usize)),
}

enum WriteState {
    Idle,
    Writing((usize, usize)),
}

pub struct LimitDatagramSend<S: DatagramSend> {
    inner: S,
    write_limiter: SpeedLimitSession,
    write_state: WriteState,
}

impl <S: DatagramSend> LimitDatagramSend<S> {
    pub fn new(inner: S, write_limiter: SpeedLimitSession) -> Self {
        Self {
            inner,
            write_limiter,
            write_state: WriteState::Idle
        }
    }
}

#[async_trait::async_trait]
impl <S: DatagramSend> DatagramSend for LimitDatagramSend<S> {
    type Error = S::Error;

    async fn send_to(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        match &mut self.write_state {
            WriteState::Idle => {
                let write_len = self.write_limiter.until_ready().await;
                self.inner.send_to(buf).await?;
                if buf.len() > write_len {
                    self.write_state = WriteState::Idle;
                } else {
                    self.write_state = WriteState::Writing((write_len, buf.len()));
                }
                Ok(buf.len())
            }
            WriteState::Writing((write_len, written_len)) => {
                self.inner.send_to(buf).await?;
                if *written_len + buf.len() >= *write_len {
                    self.write_state = WriteState::Idle;
                    Ok(buf.len())
                } else {
                    self.write_state = WriteState::Writing((*write_len, *written_len + buf.len()));
                    Ok(buf.len())
                }
            },
        }
    }
}

pub struct LimitDatagramRecv<R: DatagramRecv> {
    inner: R,
    read_limiter: SpeedLimitSession,
    read_state: ReadState,
}

impl<R: DatagramRecv> LimitDatagramRecv<R> {
    pub fn new(inner: R, read_limiter: SpeedLimitSession) -> Self {
        Self {
            inner,
            read_limiter,
            read_state: ReadState::Idle,
        }
    }
}

#[async_trait::async_trait]
impl<R: DatagramRecv> DatagramRecv for LimitDatagramRecv<R> {
    type Error = R::Error;
    async fn recv_from(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        match &mut self.read_state {
            ReadState::Idle => {
                let read_len = self.read_limiter.until_ready().await;
                let len = self.inner.recv_from(buf).await?;
                if len > read_len {
                    self.read_state = ReadState::Idle;
                    Ok(len)
                } else {
                    self.read_state = ReadState::Reading((read_len, len));
                    Ok(len)
                }
            },
            ReadState::Reading((read_len, readded_len)) => {
                let len = self.inner.recv_from(buf).await?;
                if *readded_len + len >= *read_len {
                    self.read_state = ReadState::Idle;
                } else {
                    self.read_state = ReadState::Reading((*read_len, *readded_len + len));
                }
                Ok(len)
            },
        }
    }
}

#[async_trait::async_trait]
pub trait Datagram: Send + 'static {
    type Error;
    async fn send_to(&mut self, buf: &[u8]) -> Result<usize, Self::Error>;
    async fn recv_from(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error>;
}

pub struct LimitDatagram<D: Datagram> {
    inner: D,
    write_limiter: SpeedLimitSession,
    read_limiter: SpeedLimitSession,
    read_state: ReadState,
    write_state: WriteState,
}

impl<D: Datagram> LimitDatagram<D> {
    pub fn new(inner: D, read_limit: SpeedLimitSession, write_limit: SpeedLimitSession) -> Self {
        Self { inner,
            write_limiter: write_limit,
            read_limiter: read_limit,
            read_state: ReadState::Idle,
            write_state: WriteState::Idle,
        }
    }
}

#[async_trait::async_trait]
impl<D: Datagram> Datagram for LimitDatagram<D> {
    type Error = D::Error;

    async fn send_to(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        match &mut self.write_state {
            WriteState::Idle => {
                let write_len = self.write_limiter.until_ready().await;
                self.inner.send_to(buf).await?;
                if buf.len() > write_len {
                    self.write_state = WriteState::Idle;
                } else {
                    self.write_state = WriteState::Writing((write_len, buf.len()));
                }
                Ok(buf.len())
            }
            WriteState::Writing((write_len, written_len)) => {
                self.inner.send_to(buf).await?;
                if *written_len + buf.len() >= *write_len {
                    self.write_state = WriteState::Idle;
                    Ok(buf.len())
                } else {
                    self.write_state = WriteState::Writing((*write_len, *written_len + buf.len()));
                    Ok(buf.len())
                }
            },
        }
    }

    async fn recv_from(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        match &mut self.read_state {
            ReadState::Idle => {
                let read_len = self.read_limiter.until_ready().await;
                let len = self.inner.recv_from(buf).await?;
                if len > read_len {
                    self.read_state = ReadState::Idle;
                    Ok(len)
                } else {
                    self.read_state = ReadState::Reading((read_len, len));
                    Ok(len)
                }
            },
            ReadState::Reading((read_len, readded_len)) => {
                let len = self.inner.recv_from(buf).await?;
                if *readded_len + len >= *read_len {
                    self.read_state = ReadState::Idle;
                } else {
                    self.read_state = ReadState::Reading((*read_len, *readded_len + len));
                }
                Ok(len)
            },
        }
    }
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::sync::{Arc, Mutex};
    use std::collections::VecDeque;
    use std::num::NonZeroU32;
    use std::time::{Duration, Instant};

    // Mock Datagram 实现用于测试
    #[derive(Clone)]
    struct MockDatagram {
        // 记录调用历史
        call_history: Arc<Mutex<Vec<String>>>,
        // 预设的返回值队列
        send_returns: Arc<Mutex<VecDeque<Result<usize, &'static str>>>>,
        recv_returns: Arc<Mutex<VecDeque<Result<usize, &'static str>>>>,
    }

    impl MockDatagram {
        fn new() -> Self {
            Self {
                call_history: Arc::new(Mutex::new(Vec::new())),
                send_returns: Arc::new(Mutex::new(VecDeque::new())),
                recv_returns: Arc::new(Mutex::new(VecDeque::new())),
            }
        }

        // 设置send_to的返回值
        fn with_send_result(self, result: Result<usize, &'static str>) -> Self {
            self.send_returns.lock().unwrap().push_back(result);
            self
        }

        // 设置recv_from的返回值
        fn with_recv_result(self, result: Result<usize, &'static str>) -> Self {
            self.recv_returns.lock().unwrap().push_back(result);
            self
        }

        // 获取调用历史
        fn get_call_history(&self) -> Vec<String> {
            self.call_history.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl Datagram for MockDatagram {
        type Error = &'static str;

        async fn send_to(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
            self.call_history.lock().unwrap().push("send_to".to_string());
            match self.send_returns.lock().unwrap().pop_front() {
                Some(_result) => Ok(buf.len()),
                None => Ok(buf.len()), // 默认返回缓冲区长度
            }
        }

        async fn recv_from(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
            self.call_history.lock().unwrap().push("recv_from".to_string());
            match self.recv_returns.lock().unwrap().pop_front() {
                Some(_result) => Ok(buf.len()),
                None => Ok(buf.len()), // 默认返回0
            }
        }
    }

    // Mock LimitRef 实现
    struct MockLimitRef {
        read_limit: Option<usize>,
        write_limit: Option<usize>,
    }

    // 测试new方法的基本功能
    #[tokio::test]
    async fn test_limit_datagram_new() {
        let mock_datagram = MockDatagram::new();
        let read_limiter = crate::SpeedLimiter::new(None, Some(NonZeroU32::new(10).unwrap()), Some(NonZeroU32::new(10).unwrap()));
        let read_limit = read_limiter.new_limit_session();
        let write_limiter = crate::SpeedLimiter::new(None, Some(NonZeroU32::new(10).unwrap()), Some(NonZeroU32::new(10).unwrap()));
        let write_limit = write_limiter.new_limit_session();
        let limit_datagram = LimitDatagram::new(mock_datagram, read_limit, write_limit);

        // 验证初始状态
        match limit_datagram.read_state {
            ReadState::Idle => (),
            _ => panic!("Expected ReadState::Idle"),
        }
        match limit_datagram.write_state {
            WriteState::Idle => (),
            _ => panic!("Expected WriteState::Idle"),
        }
    }

    // 测试在无写限制时send_to的行为
    #[tokio::test]
    async fn test_send_to_without_write_limit() {
        let mock_datagram = MockDatagram::new().with_send_result(Ok(10));
        let read_limiter = crate::SpeedLimiter::new(None, Some(NonZeroU32::new(10).unwrap()), Some(NonZeroU32::new(10).unwrap()));
        let read_limit = read_limiter.new_limit_session();
        let write_limiter = crate::SpeedLimiter::new(None, Some(NonZeroU32::new(10).unwrap()), Some(NonZeroU32::new(10).unwrap()));
        let write_limit = write_limiter.new_limit_session();
        let mut limit_datagram = LimitDatagram::new(mock_datagram, read_limit, write_limit);

        let buffer = [0u8; 10];
        let result = limit_datagram.send_to(&buffer).await;

        // 验证结果
        assert_eq!(result, Ok(10));
    }

    // 测试在无读限制时recv_from的行为
    #[tokio::test]
    async fn test_recv_from_without_read_limit() {
        let mock_datagram = MockDatagram::new().with_recv_result(Ok(10));
        let read_limiter = crate::SpeedLimiter::new(None, Some(NonZeroU32::MAX), Some(NonZeroU32::new(1024).unwrap()));
        let read_limit = read_limiter.new_limit_session();
        let write_limiter = crate::SpeedLimiter::new(None, Some(NonZeroU32::new(10).unwrap()), Some(NonZeroU32::new(10).unwrap()));
        let write_limit = write_limiter.new_limit_session();
        let mut limit_datagram = LimitDatagram::new(mock_datagram, read_limit, write_limit);

        let mut buffer = [0u8; 10];
        let result = limit_datagram.recv_from(&mut buffer).await;

        // 验证结果
        assert_eq!(result, Ok(10));
    }

    // 测试有写限制时首次send_to的行为
    #[tokio::test]
    async fn test_send_to_with_write_limit_initial() {
        let mock_datagram = MockDatagram::new().with_send_result(Ok(10));
        let read_limiter = crate::SpeedLimiter::new(None, Some(NonZeroU32::MAX), Some(NonZeroU32::new(1024).unwrap()));
        let read_limit = read_limiter.new_limit_session();
        let write_limiter = crate::SpeedLimiter::new(None, Some(NonZeroU32::new(10).unwrap()), Some(NonZeroU32::new(10).unwrap()));
        let write_limit = write_limiter.new_limit_session();
        let mut limit_datagram = LimitDatagram::new(mock_datagram, read_limit, write_limit);

        let buffer = [0u8; 10];
        let result = limit_datagram.send_to(&buffer).await;

        // 验证结果
        assert!(result.is_ok());
    }

    // 测试有读限制时首次recv_from的行为
    #[tokio::test]
    async fn test_recv_from_with_read_limit_initial() {
        let mock_datagram = MockDatagram::new().with_recv_result(Ok(10));
        let read_limiter = crate::SpeedLimiter::new(None, Some(NonZeroU32::new(10).unwrap()), Some(NonZeroU32::new(10).unwrap()));
        let read_limit = read_limiter.new_limit_session();
        let write_limiter = crate::SpeedLimiter::new(None, Some(NonZeroU32::new(10).unwrap()), Some(NonZeroU32::new(10).unwrap()));
        let write_limit = write_limiter.new_limit_session();
        let mut limit_datagram = LimitDatagram::new(mock_datagram, read_limit, write_limit);

        let mut buffer = [0u8; 10];
        let result = limit_datagram.recv_from(&mut buffer).await;

        // 验证结果
        assert!(result.is_ok());
    }

    // 测试Writing状态下的send_to行为
    #[tokio::test]
    async fn test_send_to_in_writing_state() {
        let mock_datagram = MockDatagram::new()
            .with_send_result(Ok(5))
            .with_send_result(Ok(5));

        let read_limiter = crate::SpeedLimiter::new(None, Some(NonZeroU32::new(10).unwrap()), Some(NonZeroU32::new(10).unwrap()));
        let read_limit = read_limiter.new_limit_session();
        let write_limiter = crate::SpeedLimiter::new(None, Some(NonZeroU32::new(1).unwrap()), Some(NonZeroU32::new(10).unwrap()));
        let write_limit = write_limiter.new_limit_session();
        let mut limit_datagram = LimitDatagram::new(mock_datagram, read_limit, write_limit);

        // 第一次调用进入Writing状态
        let buffer1 = [0u8; 5];
        let _ = limit_datagram.send_to(&buffer1).await;

        // 验证状态
        match limit_datagram.write_state {
            WriteState::Writing(_) => (),
            _ => panic!("Expected WriteState::Writing"),
        }

        let start = Instant::now();
        // 第二次调用保持在Writing状态
        let buffer2 = [0u8; 2];
        let result = limit_datagram.send_to(&buffer2).await;
        assert!(start.elapsed() <= Duration::from_millis(50));
        // 验证结果
        assert_eq!(result, Ok(2));

        // 第二次调用保持在Writing状态
        let buffer2 = [0u8; 5];
        let result = limit_datagram.send_to(&buffer2).await;

        // 验证结果
        assert_eq!(result, Ok(5));
        assert!(start.elapsed() <= Duration::from_millis(100));
        // 第二次调用保持在Writing状态
        let buffer2 = [0u8; 5];
        let result = limit_datagram.send_to(&buffer2).await;

        // 验证结果
        assert_eq!(result, Ok(5));
        assert!(start.elapsed() >= Duration::from_millis(900));
    }

    // 测试Reading状态下的recv_from行为
    #[tokio::test]
    async fn test_recv_from_in_reading_state() {
        let mock_datagram = MockDatagram::new()
            .with_recv_result(Ok(5))
            .with_recv_result(Ok(5));
        let read_limiter = crate::SpeedLimiter::new(None, Some(NonZeroU32::new(1).unwrap()), Some(NonZeroU32::new(10).unwrap()));
        let read_limit = read_limiter.new_limit_session();
        let write_limiter = crate::SpeedLimiter::new(None, Some(NonZeroU32::new(1).unwrap()), Some(NonZeroU32::new(10).unwrap()));
        let write_limit = write_limiter.new_limit_session();
        let mut limit_datagram = LimitDatagram::new(mock_datagram, read_limit, write_limit);

        // 第一次调用进入Reading状态
        let mut buffer1 = [0u8; 5];
        let _ = limit_datagram.recv_from(&mut buffer1).await;

        // 验证状态
        match limit_datagram.read_state {
            ReadState::Reading(_) => (),
            _ => panic!("Expected ReadState::Reading"),
        }

        let start = Instant::now();
        // 第二次调用保持在Reading状态
        let mut buffer2 = [0u8; 2];
        let result = limit_datagram.recv_from(&mut buffer2).await;
        assert!(start.elapsed() <= Duration::from_millis(50));

        // 验证结果
        assert_eq!(result, Ok(2));

        let mut buffer2 = [0u8; 5];
        let result = limit_datagram.recv_from(&mut buffer2).await;
        assert!(start.elapsed() <= Duration::from_millis(100));

        // 验证结果
        assert_eq!(result, Ok(5));

        let mut buffer2 = [0u8; 5];

        let result = limit_datagram.recv_from(&mut buffer2).await;
        assert!(start.elapsed() > Duration::from_millis(900));

        // 验证结果
        assert_eq!(result, Ok(5));
    }

    // 测试Writing状态完成后回到Idle状态
    #[tokio::test]
    async fn test_send_to_complete_writing_state() {
        let mock_datagram = MockDatagram::new()
            .with_send_result(Ok(5))
            .with_send_result(Ok(5));
        let read_limiter = crate::SpeedLimiter::new(None, Some(NonZeroU32::new(10).unwrap()), Some(NonZeroU32::new(1).unwrap()));
        let read_limit = read_limiter.new_limit_session();
        let write_limiter = crate::SpeedLimiter::new(None, Some(NonZeroU32::new(10).unwrap()), Some(NonZeroU32::new(1).unwrap()));
        let write_limit = write_limiter.new_limit_session();
        let mut limit_datagram = LimitDatagram::new(mock_datagram, read_limit, write_limit);

        // 第一次调用进入Writing状态
        let buffer1 = [0u8; 5];
        let _ = limit_datagram.send_to(&buffer1).await;

        // 第二次调用完成Writing状态，回到Idle
        let buffer2 = [0u8; 5];
        let _ = limit_datagram.send_to(&buffer2).await;

        // 验证状态回到Idle
        match limit_datagram.write_state {
            WriteState::Idle => (),
            _ => panic!("Expected WriteState::Idle"),
        }
    }

    // 测试Reading状态完成后回到Idle状态
    #[tokio::test]
    async fn test_recv_from_complete_reading_state() {
        let mock_datagram = MockDatagram::new()
            .with_recv_result(Ok(5))
            .with_recv_result(Ok(5));
        let read_limiter = crate::SpeedLimiter::new(None, Some(NonZeroU32::new(10).unwrap()), Some(NonZeroU32::new(1).unwrap()));
        let read_limit = read_limiter.new_limit_session();
        let write_limiter = crate::SpeedLimiter::new(None, Some(NonZeroU32::new(10).unwrap()), Some(NonZeroU32::new(1).unwrap()));
        let write_limit = write_limiter.new_limit_session();
        let mut limit_datagram = LimitDatagram::new(mock_datagram, read_limit, write_limit);

        // 第一次调用进入Reading状态
        let mut buffer1 = [0u8; 5];
        let _ = limit_datagram.recv_from(&mut buffer1).await;

        // 第二次调用完成Reading状态，回到Idle
        let mut buffer2 = [0u8; 5];
        let _ = limit_datagram.recv_from(&mut buffer2).await;

        // 验证状态回到Idle
        match limit_datagram.read_state {
            ReadState::Idle => (),
            _ => panic!("Expected ReadState::Idle"),
        }
    }


    // Mock DatagramSend 实现用于测试 LimitDatagramSend
    #[derive(Clone)]
    struct MockDatagramSend {
        call_history: Arc<Mutex<Vec<String>>>,
        send_returns: Arc<Mutex<VecDeque<Result<usize, &'static str>>>>,
    }

    impl MockDatagramSend {
        fn new() -> Self {
            Self {
                call_history: Arc::new(Mutex::new(Vec::new())),
                send_returns: Arc::new(Mutex::new(VecDeque::new())),
            }
        }

        fn with_send_result(self, result: Result<usize, &'static str>) -> Self {
            self.send_returns.lock().unwrap().push_back(result);
            self
        }

        fn get_call_history(&self) -> Vec<String> {
            self.call_history.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl DatagramSend for MockDatagramSend {
        type Error = &'static str;

        async fn send_to(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
            self.call_history.lock().unwrap().push("send_to".to_string());
            let result = self.send_returns.lock().unwrap().pop_front().unwrap_or(Ok(buf.len()));
            // 模拟实际发送操作的时间消耗
            tokio::time::sleep(Duration::from_millis(10)).await;
            result
        }
    }

    // Mock DatagramRecv 实现用于测试 LimitDatagramRecv
    #[derive(Clone)]
    struct MockDatagramRecv {
        call_history: Arc<Mutex<Vec<String>>>,
        recv_returns: Arc<Mutex<VecDeque<Result<usize, &'static str>>>>,
    }

    impl MockDatagramRecv {
        fn new() -> Self {
            Self {
                call_history: Arc::new(Mutex::new(Vec::new())),
                recv_returns: Arc::new(Mutex::new(VecDeque::new())),
            }
        }

        fn with_recv_result(self, result: Result<usize, &'static str>) -> Self {
            self.recv_returns.lock().unwrap().push_back(result);
            self
        }

        fn get_call_history(&self) -> Vec<String> {
            self.call_history.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl DatagramRecv for MockDatagramRecv {
        type Error = &'static str;

        async fn recv_from(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
            self.call_history.lock().unwrap().push("recv_from".to_string());
            let result = self.recv_returns.lock().unwrap().pop_front().unwrap_or(Ok(buf.len()));
            // 模拟实际接收操作的时间消耗
            tokio::time::sleep(Duration::from_millis(10)).await;
            result
        }
    }

    // 测试 LimitDatagramSend 的基本功能
    #[tokio::test]
    async fn test_limit_datagram_send_new() {
        let mock_sender = MockDatagramSend::new();
        let write_limiter = crate::SpeedLimiter::new(None, Some(NonZeroU32::new(10).unwrap()), Some(NonZeroU32::new(10).unwrap()));
        let write_limit = write_limiter.new_limit_session();
        let limit_sender = LimitDatagramSend::new(mock_sender, write_limit);

        match limit_sender.write_state {
            WriteState::Idle => (),
            _ => panic!("Expected WriteState::Idle"),
        }
    }

    // 测试 LimitDatagramSend 在无限制时的行为
    #[tokio::test]
    async fn test_limit_datagram_send_without_limit() {
        let mock_sender = MockDatagramSend::new().with_send_result(Ok(10));
        let write_limiter = crate::SpeedLimiter::new(None, Some(NonZeroU32::new(100).unwrap()), Some(NonZeroU32::new(100).unwrap()));
        let write_limit = write_limiter.new_limit_session();
        let mut limit_sender = LimitDatagramSend::new(mock_sender, write_limit);

        let buffer = [0u8; 10];
        let result = limit_sender.send_to(&buffer).await;

        assert_eq!(result, Ok(10));
    }

    // 测试 LimitDatagramSend 在有限制时的行为
    #[tokio::test]
    async fn test_limit_datagram_send_with_limit() {
        let mock_sender = MockDatagramSend::new().with_send_result(Ok(5));
        let write_limiter = crate::SpeedLimiter::new(None, Some(NonZeroU32::new(10).unwrap()), Some(NonZeroU32::new(10).unwrap()));
        let write_limit = write_limiter.new_limit_session();
        let mut limit_sender = LimitDatagramSend::new(mock_sender, write_limit);

        let buffer = [0u8; 5];
        let result = limit_sender.send_to(&buffer).await;

        assert!(result.is_ok());
    }

    // 测试 LimitDatagramSend Writing 状态下的行为
    #[tokio::test]
    async fn test_limit_datagram_send_in_writing_state() {
        let mock_sender = MockDatagramSend::new()
            .with_send_result(Ok(5))
            .with_send_result(Ok(3));

        let write_limiter = crate::SpeedLimiter::new(None, Some(NonZeroU32::new(1).unwrap()), Some(NonZeroU32::new(60).unwrap()));
        let write_limit = write_limiter.new_limit_session();
        let mut limit_sender = LimitDatagramSend::new(mock_sender, write_limit);

        // 第一次调用进入Writing状态
        let buffer1 = [0u8; 5];
        let _ = limit_sender.send_to(&buffer1).await;

        // 验证状态
        match &limit_sender.write_state {
            WriteState::Writing((limit, written)) => {
                assert_eq!(*limit, 60);
                assert_eq!(*written, 5);
            },
            _ => panic!("Expected WriteState::Writing"),
        }

        // 第二次调用保持在Writing状态
        let buffer2 = [0u8; 3];
        let result = limit_sender.send_to(&buffer2).await;

        // 验证结果
        assert_eq!(result, Ok(3));
    }

    // 测试 LimitDatagramSend Writing 状态完成后回到 Idle 状态
    #[tokio::test]
    async fn test_limit_datagram_send_complete_writing_state() {
        let mock_sender = MockDatagramSend::new()
            .with_send_result(Ok(3))
            .with_send_result(Ok(3));

        let write_limiter = crate::SpeedLimiter::new(None, Some(NonZeroU32::new(5).unwrap()), Some(NonZeroU32::new(5).unwrap()));
        let write_limit = write_limiter.new_limit_session();
        let mut limit_sender = LimitDatagramSend::new(mock_sender, write_limit);

        // 第一次调用进入Writing状态
        let buffer1 = [0u8; 3];
        let _ = limit_sender.send_to(&buffer1).await;

        // 验证状态
        match &limit_sender.write_state {
            WriteState::Writing((limit, written)) => {
                assert_eq!(*limit, 5);
                assert_eq!(*written, 3);
            },
            _ => panic!("Expected WriteState::Writing"),
        }

        // 第二次调用完成后应回到Idle状态
        let buffer2 = [0u8; 3];
        let _ = limit_sender.send_to(&buffer2).await;

        // 验证状态回到Idle
        match limit_sender.write_state {
            WriteState::Idle => (),
            _ => panic!("Expected WriteState::Idle"),
        }
    }

    // 测试 LimitDatagramRecv 的基本功能
    #[tokio::test]
    async fn test_limit_datagram_recv_new() {
        let mock_receiver = MockDatagramRecv::new();
        let read_limiter = crate::SpeedLimiter::new(None, Some(NonZeroU32::new(10).unwrap()), Some(NonZeroU32::new(10).unwrap()));
        let read_limit = read_limiter.new_limit_session();
        let limit_receiver = LimitDatagramRecv::new(mock_receiver, read_limit);

        match limit_receiver.read_state {
            ReadState::Idle => (),
            _ => panic!("Expected ReadState::Idle"),
        }
    }

    // 测试 LimitDatagramRecv 在无限制时的行为
    #[tokio::test]
    async fn test_limit_datagram_recv_without_limit() {
        let mock_receiver = MockDatagramRecv::new().with_recv_result(Ok(10));
        let read_limiter = crate::SpeedLimiter::new(None, Some(NonZeroU32::new(100).unwrap()), Some(NonZeroU32::new(100).unwrap()));
        let read_limit = read_limiter.new_limit_session();
        let mut limit_receiver = LimitDatagramRecv::new(mock_receiver, read_limit);

        let mut buffer = [0u8; 10];
        let result = limit_receiver.recv_from(&mut buffer).await;

        assert_eq!(result, Ok(10));
    }

    // 测试 LimitDatagramRecv 在有限制时的行为
    #[tokio::test]
    async fn test_limit_datagram_recv_with_limit() {
        let mock_receiver = MockDatagramRecv::new().with_recv_result(Ok(5));
        let read_limiter = crate::SpeedLimiter::new(None, Some(NonZeroU32::new(10).unwrap()), Some(NonZeroU32::new(10).unwrap()));
        let read_limit = read_limiter.new_limit_session();
        let mut limit_receiver = LimitDatagramRecv::new(mock_receiver, read_limit);

        let mut buffer = [0u8; 5];
        let result = limit_receiver.recv_from(&mut buffer).await;

        assert!(result.is_ok());
    }

    // 测试 LimitDatagramRecv Reading 状态下的行为
    #[tokio::test]
    async fn test_limit_datagram_recv_in_reading_state() {
        let mock_receiver = MockDatagramRecv::new()
            .with_recv_result(Ok(5))
            .with_recv_result(Ok(3));

        let read_limiter = crate::SpeedLimiter::new(None, Some(NonZeroU32::new(1).unwrap()), Some(NonZeroU32::new(60).unwrap()));
        let read_limit = read_limiter.new_limit_session();
        let mut limit_receiver = LimitDatagramRecv::new(mock_receiver, read_limit);

        // 第一次调用进入Reading状态
        let mut buffer1 = [0u8; 5];
        let _ = limit_receiver.recv_from(&mut buffer1).await;

        // 验证状态
        match &limit_receiver.read_state {
            ReadState::Reading((limit, read)) => {
                assert_eq!(*limit, 60);
                assert_eq!(*read, 5);
            },
            _ => panic!("Expected ReadState::Reading"),
        }

        // 第二次调用保持在Reading状态
        let mut buffer2 = [0u8; 3];
        let result = limit_receiver.recv_from(&mut buffer2).await;

        // 验证结果
        assert_eq!(result, Ok(3));
    }

    // 测试 LimitDatagramRecv Reading 状态完成后回到 Idle 状态
    #[tokio::test]
    async fn test_limit_datagram_recv_complete_reading_state() {
        let mock_receiver = MockDatagramRecv::new()
            .with_recv_result(Ok(3))
            .with_recv_result(Ok(3));

        let read_limiter = crate::SpeedLimiter::new(None, Some(NonZeroU32::new(5).unwrap()), Some(NonZeroU32::new(5).unwrap()));
        let read_limit = read_limiter.new_limit_session();
        let mut limit_receiver = LimitDatagramRecv::new(mock_receiver, read_limit);

        // 第一次调用进入Reading状态
        let mut buffer1 = [0u8; 3];
        let _ = limit_receiver.recv_from(&mut buffer1).await;

        // 验证状态
        match &limit_receiver.read_state {
            ReadState::Reading((limit, read)) => {
                assert_eq!(*limit, 5);
                assert_eq!(*read, 3);
            },
            _ => panic!("Expected ReadState::Reading"),
        }

        // 第二次调用完成后应回到Idle状态
        let mut buffer2 = [0u8; 3];
        let _ = limit_receiver.recv_from(&mut buffer2).await;

        // 验证状态回到Idle
        match limit_receiver.read_state {
            ReadState::Idle => (),
            _ => panic!("Expected ReadState::Idle"),
        }
    }

}
