#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

use crate::SpeedLimitSession;
use std::io::Error;
use std::pin::{Pin};
use std::task::{Context, Poll};
use pin_project::pin_project;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

enum ReadState {
    Idle,
    Waiting(Option<(Pin<Box<dyn Future<Output=usize> + Send + Sync + 'static>>, usize)>),
    Reading(Option<(usize, usize)>),
}

enum WriteState {
    Idle,
    Waiting(Option<(Pin<Box<dyn Future<Output=usize> + Send + Sync + 'static>>, usize)>),
    Writing(Option<(usize, usize)>),
}

#[pin_project]
pub struct LimitStream<S: AsyncRead + AsyncWrite + Unpin + Send> {
    #[pin]
    read: LimitRead<crate::split::ReadHalf<S>>,
    #[pin]
    write: LimitWrite<crate::split::WriteHalf<S>>,
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send + 'static> LimitStream<S> {
    pub fn new(stream: S, read_limit: SpeedLimitSession, write_limit: SpeedLimitSession) -> Self {
        let (read, write) = crate::split::split(stream);
        let limit_read = LimitRead::new(read, read_limit);
        let limit_write = LimitWrite::new(write, write_limit);
        LimitStream {
            read: limit_read,
            write: limit_write,
        }
    }
    pub fn with_lock_raw_stream<R>(&mut self, f: impl FnOnce(Pin<&mut S>) -> R) -> R {
        self.read.raw_read().with_lock(f)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send + 'static> AsyncWrite for LimitStream<S> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize, Error>> {
        self.project().write.poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        self.project().write.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        self.project().write.poll_shutdown(cx)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send + 'static> AsyncRead for LimitStream<S> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        self.project().read.poll_read(cx, buf)
    }
}

#[pin_project]
pub struct LimitRead<S: AsyncRead + Unpin + Send> {
    #[pin]
    read: S,
    read_limit: SpeedLimitSession,
    read_state: ReadState,
}

impl<S: AsyncRead + Unpin + Send + 'static> LimitRead<S> {
    pub fn new(read: S, read_limit: SpeedLimitSession) -> Self {
        LimitRead {
            read,
            read_limit,
            read_state: ReadState::Idle,
        }
    }

    pub fn raw_read_mut(&mut self) -> &mut S {
        &mut self.read
    }

    pub fn raw_read(&self) -> &S {
        &self.read
    }

    pub fn into_raw_read(self) -> S {
        self.read
    }
}

impl<S: AsyncRead + Unpin + Send + 'static> AsyncRead for LimitRead<S> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        let this = self.project();
        buf.initialize_unfilled();
        match this.read_state {
            ReadState::Idle => {
                let mut readded_len = 0;

                let read_limit: &'static mut SpeedLimitSession = unsafe {
                    std::mem::transmute(this.read_limit)
                };
                let mut waiting_future = Box::pin(read_limit.until_ready());
                match Pin::new(&mut waiting_future).poll(cx) {
                    Poll::Ready(read_len) => {
                        let mut read_buf = if read_len <= buf.remaining() {
                            buf.take(read_len)
                        } else {
                            buf.take(buf.remaining())
                        };
                        match this.read.poll_read(cx, &mut read_buf) {
                            Poll::Ready(Ok(())) => {
                                let len = read_buf.filled().len();
                                readded_len += len;
                                buf.advance(len);
                                if readded_len >= read_len {
                                    *this.read_state = ReadState::Idle;
                                } else {
                                    *this.read_state = ReadState::Reading(Some((read_len, readded_len)));
                                }
                                Poll::Ready(Ok(()))
                            },
                            Poll::Ready(Err(e)) => {
                                *this.read_state = ReadState::Idle;
                                Poll::Ready(Err(e))
                            },
                            Poll::Pending => {
                                *this.read_state = ReadState::Reading(Some((read_len, readded_len)));
                                Poll::Pending
                            }
                        }
                    }
                    Poll::Pending => {
                        *this.read_state = ReadState::Waiting(Some((waiting_future, readded_len)));
                        Poll::Pending
                    }
                }
            }
            ReadState::Waiting(state) => {
                let (mut rx, mut readded_len) = state.take().unwrap();
                match Pin::new(&mut rx).poll(cx) {
                    Poll::Ready(read_len) => {
                        let mut read_buf = if (read_len - readded_len) <= buf.remaining() {
                            buf.take(read_len - readded_len)
                        } else {
                            buf.take(buf.remaining())
                        };
                        match this.read.poll_read(cx, &mut read_buf) {
                            Poll::Ready(Ok(())) => {
                                let len = read_buf.filled().len();
                                readded_len += len;
                                buf.advance(len);
                                if readded_len >= read_len {
                                    *this.read_state = ReadState::Idle;
                                } else {
                                    *this.read_state = ReadState::Reading(Some((read_len, readded_len)));
                                }
                                Poll::Ready(Ok(()))
                            }
                            Poll::Ready(Err(e)) => {
                                *this.read_state = ReadState::Idle;
                                Poll::Ready(Err(e))
                            },
                            Poll::Pending => {
                                *this.read_state = ReadState::Reading(Some((read_len, readded_len)));
                                Poll::Pending
                            }
                        }
                    }
                    Poll::Pending => {
                        *this.read_state = ReadState::Waiting(Some((rx, readded_len)));
                        Poll::Pending
                    }
                }
            },
            ReadState::Reading(state) => {
                match state.take() {
                    Some((read_len, mut readded_len)) => {
                        let mut read_buf = if (read_len - readded_len) <= buf.remaining() {
                            buf.take(read_len - readded_len)
                        } else {
                            buf.take(buf.remaining())
                        };
                        match this.read.poll_read(cx, &mut read_buf) {
                            Poll::Ready(Ok(())) => {
                                let len = read_buf.filled().len();
                                readded_len += len;
                                buf.advance(len);
                                if readded_len >= read_len {
                                    *this.read_state = ReadState::Idle;
                                } else {
                                    *this.read_state = ReadState::Reading(Some((read_len, readded_len)));
                                }
                                Poll::Ready(Ok(()))
                            }
                            Poll::Ready(Err(e)) => {
                                *this.read_state = ReadState::Idle;
                                Poll::Ready(Err(e))
                            },
                            Poll::Pending => {
                                *this.read_state = ReadState::Reading(Some((read_len, readded_len)));
                                Poll::Pending
                            }
                        }
                    },
                    None => {
                        match this.read.poll_read(cx, buf) {
                            Poll::Ready(Ok(())) => {
                                *this.read_state = ReadState::Idle;
                                Poll::Ready(Ok(()))
                            },
                            Poll::Ready(Err(e)) => {
                                *this.read_state = ReadState::Idle;
                                Poll::Ready(Err(e))
                            },
                            Poll::Pending => {
                                *this.read_state = ReadState::Reading(None);
                                Poll::Pending
                            }
                        }
                    }
                }

            }
        }
    }
}

#[pin_project]
pub struct LimitWrite<S: AsyncWrite + Unpin + Send> {
    #[pin]
    write: S,
    write_limit: SpeedLimitSession,
    write_state: WriteState,
}

impl<S: AsyncWrite + Unpin + Send + 'static> LimitWrite<S> {
    pub fn new(write: S, write_limit: SpeedLimitSession) -> Self {
        LimitWrite {
            write,
            write_limit,
            write_state: WriteState::Idle,
        }
    }
    pub fn raw_write_mut(&mut self) -> &mut S {
        &mut self.write
    }

    pub fn raw_write(&self) -> &S {
        &self.write
    }

    pub fn into_raw_write(self) -> S {
        self.write
    }
}

impl<S: AsyncWrite + Unpin + Send + 'static> AsyncWrite for LimitWrite<S> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize, Error>> {
        let this = self.project();
        match this.write_state {
            WriteState::Idle => {
                let mut written_len = 0;
                let write_limiter: &'static mut SpeedLimitSession = unsafe {
                    std::mem::transmute(this.write_limit)
                };
                let mut waiting_future = Box::pin(write_limiter.until_ready());
                match Pin::new(&mut waiting_future).poll(cx) {
                    Poll::Ready(write_len) => {
                        let write_buf = if write_len <= buf.len() {
                            &buf[..write_len]
                        } else {
                            buf
                        };
                        match this.write.poll_write(cx, write_buf) {
                            Poll::Ready(Ok(len)) => {
                                written_len += len;
                                if written_len >= write_len {
                                    *this.write_state = WriteState::Idle;
                                } else {
                                    *this.write_state = WriteState::Writing(Some((write_len, written_len)));
                                }
                                Poll::Ready(Ok(written_len))
                            }
                            Poll::Ready(Err(e)) => {
                                *this.write_state = WriteState::Idle;
                                Poll::Ready(Err(e))
                            }
                            Poll::Pending => {
                                *this.write_state = WriteState::Writing(Some((write_len, written_len)));
                                Poll::Pending
                            }
                        }
                    }
                    Poll::Pending => {
                        *this.write_state = WriteState::Waiting(Some((waiting_future, written_len)));
                        Poll::Pending
                    }
                }
            }
            WriteState::Waiting(state) => {
                let (mut waiting_future, mut written_len) = state.take().unwrap();
                match Pin::new(&mut waiting_future).poll(cx) {
                    Poll::Ready(write_len) => {
                        let write_buf = if write_len - written_len <= buf.len() {
                            &buf[..(write_len - written_len)]
                        } else {
                            buf
                        };
                        match this.write.poll_write(cx, write_buf) {
                            Poll::Ready(Ok(len)) => {
                                written_len += len;
                                if written_len >= write_len {
                                    *this.write_state = WriteState::Idle;
                                } else {
                                    *this.write_state = WriteState::Writing(Some((write_len, written_len)));
                                }
                                Poll::Ready(Ok(len))
                            },
                            Poll::Ready(Err(e)) => {
                                *this.write_state = WriteState::Idle;
                                Poll::Ready(Err(e))
                            },
                            Poll::Pending => {
                                *this.write_state = WriteState::Writing(Some((write_len, written_len)));
                                Poll::Pending
                            }
                        }
                    }
                    Poll::Pending => {
                        *this.write_state = WriteState::Waiting(Some((waiting_future, written_len)));
                        Poll::Pending
                    }
                }
            }
            WriteState::Writing(state) => {
                match state.take() {
                    Some((write_len, mut written_len)) => {
                        let write_buf = if write_len - written_len <= buf.len() {
                            &buf[..(write_len - written_len)]
                        } else {
                            buf
                        };
                        match this.write.poll_write(cx, write_buf) {
                            Poll::Ready(Ok(len)) => {
                                written_len += len;
                                if written_len >= write_len {
                                    *this.write_state = WriteState::Idle;
                                } else {
                                    *this.write_state = WriteState::Writing(Some((write_len, written_len)));
                                }
                                Poll::Ready(Ok(len))
                            },
                            Poll::Ready(Err(e)) => {
                                *this.write_state = WriteState::Idle;
                                Poll::Ready(Err(e))
                            },
                            Poll::Pending => {
                                *this.write_state = WriteState::Writing(Some((write_len, written_len)));
                                Poll::Pending
                            }
                        }
                    },
                    None => {
                        match this.write.poll_write(cx, buf) {
                            Poll::Ready(Ok(len)) => {
                                *this.write_state = WriteState::Idle;
                                Poll::Ready(Ok(len))
                            },
                            Poll::Ready(Err(e)) => {
                                *this.write_state = WriteState::Idle;
                                Poll::Ready(Err(e))
                            },
                            Poll::Pending => {
                                *this.write_state = WriteState::Writing(None);
                                Poll::Pending
                            }
                        }
                    }
                }
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        self.project().write.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        self.project().write.poll_shutdown(cx)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::future::poll_fn;
    use super::*;
    use std::io::{Error, ErrorKind};
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use std::time::{Duration, Instant};
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
    use futures::task::noop_waker;
    use std::num::NonZeroU32;

    // Mock stream implementation for testing
    struct MockStream {
        read_data: Vec<u8>,
        read_pos: usize,
        read_should_pending: bool,
        read_error: Option<Error>,
        write_should_pending: bool,
        write_error: Option<Error>,
        written_data: Vec<u8>,
    }

    impl MockStream {
        fn new(read_data: Vec<u8>) -> Self {
            Self {
                read_data,
                read_pos: 0,
                read_should_pending: false,
                read_error: None,
                write_should_pending: false,
                write_error: None,
                written_data: Vec::new(),
            }
        }

        fn with_read_pending(mut self) -> Self {
            self.read_should_pending = true;
            self
        }

        fn with_read_error(mut self, error: Error) -> Self {
            self.read_error = Some(error);
            self
        }

        fn with_write_pending(mut self) -> Self {
            self.write_should_pending = true;
            self
        }

        fn with_write_error(mut self, error: Error) -> Self {
            self.write_error = Some(error);
            self
        }

        fn written_data(&self) -> &[u8] {
            &self.written_data
        }
    }

    impl AsyncRead for MockStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>
        ) -> Poll<std::io::Result<()>> {
            if let Some(error) = self.read_error.take() {
                return Poll::Ready(Err(error));
            }

            if self.read_should_pending {
                return Poll::Pending;
            }

            let remaining = self.read_data.len() - self.read_pos;
            if remaining == 0 {
                return Poll::Ready(Ok(()));
            }

            let to_copy = std::cmp::min(remaining, buf.remaining());
            buf.put_slice(&self.read_data[self.read_pos..self.read_pos + to_copy]);
            self.read_pos += to_copy;

            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for MockStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8]
        ) -> Poll<Result<usize, Error>> {
            if let Some(error) = self.write_error.take() {
                return Poll::Ready(Err(error));
            }

            if self.write_should_pending {
                return Poll::Pending;
            }

            self.written_data.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn test_read_without_limit() {
        let mock_stream = MockStream::new(vec![1, 2, 3, 4, 5]);
        let read_limit = crate::SpeedLimiter::new(None, Some(NonZeroU32::MAX), Some(NonZeroU32::new(1024).unwrap())).new_limit_session();
        let write_limit = crate::SpeedLimiter::new(None, Some(NonZeroU32::MAX), Some(NonZeroU32::new(1024).unwrap())).new_limit_session();
        let mut limit_stream = LimitStream::new(mock_stream, read_limit, write_limit);

        let mut buffer = [0u8; 10];
        let mut read_buf = ReadBuf::new(&mut buffer);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // 测试无限制读取
        let result = Pin::new(&mut limit_stream).poll_read(&mut cx, &mut read_buf);
        assert!(result.is_ready());
        assert_eq!(read_buf.filled(), &[1, 2, 3, 4, 5]);
    }

    #[tokio::test]
    async fn test_read_without_limit1() {
        let mock_stream = MockStream::new(vec![1, 2, 3, 4, 5]).with_read_pending();
        let read_limit = crate::SpeedLimiter::new(None, Some(NonZeroU32::MAX), Some(NonZeroU32::new(1024).unwrap())).new_limit_session();
        let write_limit = crate::SpeedLimiter::new(None, Some(NonZeroU32::MAX), Some(NonZeroU32::new(1024).unwrap())).new_limit_session();
        let mut limit_stream = LimitStream::new(mock_stream, read_limit, write_limit);

        let mut buffer = [0u8; 3];
        let mut read_buf = ReadBuf::new(&mut buffer);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // 测试无限制读取
        let result = Pin::new(&mut limit_stream).poll_read(&mut cx, &mut read_buf);
        assert!(result.is_pending());
        limit_stream.with_lock_raw_stream(|stream| {
            stream.get_mut().read_should_pending = false;
        });
        let result = Pin::new(&mut limit_stream).poll_read(&mut cx, &mut read_buf);
        assert!(result.is_ready());
        assert_eq!(read_buf.filled(), &[1, 2, 3]);
        let mut read_buf = ReadBuf::new(&mut buffer);
        let result = Pin::new(&mut limit_stream).poll_read(&mut cx, &mut read_buf);
        assert!(result.is_ready());
        assert_eq!(read_buf.filled(), &[4, 5]);
    }

    #[tokio::test]
    async fn test_read_without_limit2() {
        let mock_stream = MockStream::new(vec![1, 2, 3, 4, 5]).with_read_pending();
        let read_limit = crate::SpeedLimiter::new(None, Some(NonZeroU32::MAX), Some(NonZeroU32::new(1024).unwrap())).new_limit_session();
        let write_limit = crate::SpeedLimiter::new(None, Some(NonZeroU32::MAX), Some(NonZeroU32::new(1024).unwrap())).new_limit_session();
        let mut limit_stream = LimitStream::new(mock_stream, read_limit, write_limit);

        let mut buffer = [0u8; 3];
        let mut read_buf = ReadBuf::new(&mut buffer);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // 测试无限制读取
        let result = Pin::new(&mut limit_stream).poll_read(&mut cx, &mut read_buf);
        assert!(result.is_pending());
        limit_stream.with_lock_raw_stream(|stream| {
            let stream = stream.get_mut();
            stream.read_should_pending = false;
            let error = Error::new(ErrorKind::Other, "read error");
            stream.read_error = Some(error);
        });
        let result = Pin::new(&mut limit_stream).poll_read(&mut cx, &mut read_buf);
        assert!(result.is_ready());

        if let Poll::Ready(ret) = result {
            assert!(ret.is_err());
        }
    }

    #[tokio::test]
    async fn test_read_without_limit_err() {
        let error = Error::new(ErrorKind::Other, "read error");
        let mock_stream = MockStream::new(vec![1, 2, 3, 4, 5]).with_read_error(error);
        let read_limit = crate::SpeedLimiter::new(None, Some(NonZeroU32::MAX), Some(NonZeroU32::new(1024).unwrap())).new_limit_session();
        let write_limit = crate::SpeedLimiter::new(None, Some(NonZeroU32::MAX), Some(NonZeroU32::new(1024).unwrap())).new_limit_session();
        let mut limit_stream = LimitStream::new(mock_stream, read_limit, write_limit);

        let mut buffer = [0u8; 10];
        let mut read_buf = ReadBuf::new(&mut buffer);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // 测试无限制读取
        let result = Pin::new(&mut limit_stream).poll_read(&mut cx, &mut read_buf);
        assert!(result.is_ready());
        match result {
            Poll::Ready(ret) => assert!(ret.is_err()),
            Poll::Pending => panic!("Expected ready"),
        }
    }

    #[tokio::test]
    async fn test_read_with_limit() {
        let mock_stream = MockStream::new(vec![1, 2, 3, 4, 5]);
        let read_limiter = crate::SpeedLimiter::new(None, Some(NonZeroU32::new(1).unwrap()), Some(NonZeroU32::new(1).unwrap()));
        let read_limit = read_limiter.new_limit_session();
        let write_limiter = crate::SpeedLimiter::new(None, Some(NonZeroU32::MAX), Some(NonZeroU32::new(1).unwrap()));
        let write_limit = write_limiter.new_limit_session();
        let mut limit_stream = LimitStream::new(mock_stream, read_limit, write_limit);

        let mut buffer = [0u8; 10];
        let mut read_buf = ReadBuf::new(&mut buffer);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // 第一次读取应该等待令牌
        let result = Pin::new(&mut limit_stream).poll_read(&mut cx, &mut read_buf);
        assert!(result.is_ready());
        assert_eq!(read_buf.filled(), &[1]);

        let start = Instant::now();
        let mut read_buf = ReadBuf::new(&mut buffer);
        let result = poll_fn(|cx| {
            Pin::new(&mut limit_stream).poll_read(cx, &mut read_buf)
        }).await;
        assert!(start.elapsed() >= Duration::from_millis(900));
        assert!(result.is_ok());
        assert_eq!(read_buf.filled(), &[2]);

        let mut read_buf = ReadBuf::new(&mut buffer);
        let result = poll_fn(|cx| {
            Pin::new(&mut limit_stream).poll_read(cx, &mut read_buf)
        }).await;
        assert!(start.elapsed() >= Duration::from_millis(1900));
        assert!(result.is_ok());
        assert_eq!(read_buf.filled(), &[3]);
    }

    #[tokio::test]
    async fn test_read_with_limit2() {
        let mock_stream = MockStream::new(vec![1, 2, 3, 4, 5]);
        let read_limiter = crate::SpeedLimiter::new(None, Some(NonZeroU32::new(1).unwrap()), Some(NonZeroU32::new(2).unwrap()));
        let read_limit = read_limiter.new_limit_session();
        let write_limiter = crate::SpeedLimiter::new(None, Some(NonZeroU32::MAX), Some(NonZeroU32::new(1).unwrap()));
        let write_limit = write_limiter.new_limit_session();
        let mut limit_stream = LimitStream::new(mock_stream, read_limit, write_limit);

        let mut buffer = [0u8; 10];
        let mut read_buf = ReadBuf::new(&mut buffer);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // 第一次读取应该等待令牌
        let result = Pin::new(&mut limit_stream).poll_read(&mut cx, &mut read_buf);
        assert!(result.is_ready());
        assert_eq!(read_buf.filled(), &[1, 2]);

        let start = Instant::now();
        let mut read_buf = ReadBuf::new(&mut buffer);
        let result = poll_fn(|cx| {
            Pin::new(&mut limit_stream).poll_read(cx, &mut read_buf)
        }).await;
        assert!(start.elapsed() >= Duration::from_millis(900));
        assert!(result.is_ok());
        assert_eq!(read_buf.filled(), &[3, 4]);

        let mut read_buf = ReadBuf::new(&mut buffer);
        let result = poll_fn(|cx| {
            Pin::new(&mut limit_stream).poll_read(cx, &mut read_buf)
        }).await;
        assert!(start.elapsed() >= Duration::from_millis(1900));
        assert!(result.is_ok());
        assert_eq!(read_buf.filled(), &[5]);
    }

    #[tokio::test]
    async fn test_read_with_limit3() {
        let mock_stream = MockStream::new(vec![1, 2, 3, 4, 5]);
        let read_limiter = crate::SpeedLimiter::new(None, Some(NonZeroU32::new(1).unwrap()), Some(NonZeroU32::new(2).unwrap()));
        let read_limit = read_limiter.new_limit_session();
        let write_limiter = crate::SpeedLimiter::new(None, Some(NonZeroU32::MAX), Some(NonZeroU32::new(1).unwrap()));
        let write_limit = write_limiter.new_limit_session();
        let mut limit_stream = LimitStream::new(mock_stream, read_limit, write_limit);

        let mut buffer = [0u8; 1];
        let mut read_buf = ReadBuf::new(&mut buffer);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let result = Pin::new(&mut limit_stream).poll_read(&mut cx, &mut read_buf);
        assert!(result.is_ready());
        assert_eq!(read_buf.filled(), &[1]);

        let mut read_buf = ReadBuf::new(&mut buffer);
        let result = Pin::new(&mut limit_stream).poll_read(&mut cx, &mut read_buf);
        assert!(result.is_ready());
        assert_eq!(read_buf.filled(), &[2]);

        let start = Instant::now();
        let mut read_buf = ReadBuf::new(&mut buffer);
        let result = poll_fn(|cx| {
            Pin::new(&mut limit_stream).poll_read(cx, &mut read_buf)
        }).await;
        assert!(start.elapsed() >= Duration::from_millis(900));
        assert!(result.is_ok());
        assert_eq!(read_buf.filled(), &[3]);

        let mut read_buf = ReadBuf::new(&mut buffer);
        let result = poll_fn(|cx| {
            Pin::new(&mut limit_stream).poll_read(cx, &mut read_buf)
        }).await;
        assert!(start.elapsed() < Duration::from_millis(1100));
        assert!(result.is_ok());
        assert_eq!(read_buf.filled(), &[4]);
    }

    #[tokio::test]
    async fn test_read_with_limit4() {
        let mock_stream = MockStream::new(vec![1, 2, 3, 4, 5]);
        let read_limiter = crate::SpeedLimiter::new(None, Some(NonZeroU32::new(2).unwrap()), Some(NonZeroU32::new(1).unwrap()));
        let read_limit = read_limiter.new_limit_session();
        let write_limiter = crate::SpeedLimiter::new(None, Some(NonZeroU32::MAX), Some(NonZeroU32::new(1).unwrap()));
        let write_limit = write_limiter.new_limit_session();
        let mut limit_stream = LimitStream::new(mock_stream, read_limit, write_limit);

        let mut buffer = [0u8; 1];
        let mut read_buf = ReadBuf::new(&mut buffer);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let result = Pin::new(&mut limit_stream).poll_read(&mut cx, &mut read_buf);
        assert!(result.is_ready());
        assert_eq!(read_buf.filled(), &[1]);

        let mut read_buf = ReadBuf::new(&mut buffer);
        let result = Pin::new(&mut limit_stream).poll_read(&mut cx, &mut read_buf);
        assert!(result.is_ready());
        assert_eq!(read_buf.filled(), &[2]);

        let mut read_buf = ReadBuf::new(&mut buffer);
        let result = Pin::new(&mut limit_stream).poll_read(&mut cx, &mut read_buf);
        assert!(result.is_pending());
        tokio::time::sleep(Duration::from_millis(600)).await;
        let result = Pin::new(&mut limit_stream).poll_read(&mut cx, &mut read_buf);
        assert!(result.is_ready());
        assert_eq!(read_buf.filled(), &[3]);

    }

    #[tokio::test]
    async fn test_read_with_limit5() {
        let mock_stream = MockStream::new(vec![1, 2, 3, 4, 5]);
        let read_limiter = crate::SpeedLimiter::new(None, Some(NonZeroU32::new(2).unwrap()), Some(NonZeroU32::new(1).unwrap()));
        let read_limit = read_limiter.new_limit_session();
        let write_limiter = crate::SpeedLimiter::new(None, Some(NonZeroU32::MAX), Some(NonZeroU32::new(1).unwrap()));
        let write_limit = write_limiter.new_limit_session();
        let mut limit_stream = LimitStream::new(mock_stream, read_limit, write_limit);

        let mut buffer = [0u8; 1];
        let mut read_buf = ReadBuf::new(&mut buffer);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let result = Pin::new(&mut limit_stream).poll_read(&mut cx, &mut read_buf);
        assert!(result.is_ready());
        assert_eq!(read_buf.filled(), &[1]);
        let mut read_buf = ReadBuf::new(&mut buffer);
        let result = Pin::new(&mut limit_stream).poll_read(&mut cx, &mut read_buf);
        assert!(result.is_ready());
        assert_eq!(read_buf.filled(), &[2]);

        let mut read_buf = ReadBuf::new(&mut buffer);
        let result = Pin::new(&mut limit_stream).poll_read(&mut cx, &mut read_buf);
        assert!(result.is_pending());
        tokio::time::sleep(Duration::from_millis(1100)).await;
        limit_stream.with_lock_raw_stream(|stream| {
            stream.get_mut().read_should_pending = true;
        });
        let result = Pin::new(&mut limit_stream).poll_read(&mut cx, &mut read_buf);
        assert!(result.is_pending());
        limit_stream.with_lock_raw_stream(|stream| {
            stream.get_mut().read_should_pending = false;
        });
        let result = Pin::new(&mut limit_stream).poll_read(&mut cx, &mut read_buf);
        assert!(result.is_ready());
        assert_eq!(read_buf.filled(), &[3]);
        limit_stream.with_lock_raw_stream(|stream| {
            let error = Error::new(ErrorKind::Other, "read error");
            stream.get_mut().read_error = Some(error);
        });
        let mut read_buf = ReadBuf::new(&mut buffer);
        let result = Pin::new(&mut limit_stream).poll_read(&mut cx, &mut read_buf);
        assert!(result.is_ready());

        if let Poll::Ready(Err(e)) = result {
            assert_eq!(e.kind(), ErrorKind::Other);
        }
    }

    #[tokio::test]
    async fn test_read_with_limit6() {
        let mock_stream = MockStream::new(vec![1, 2, 3, 4, 5]);
        let read_limiter = crate::SpeedLimiter::new(None, Some(NonZeroU32::new(2).unwrap()), Some(NonZeroU32::new(1).unwrap()));
        let read_limit = read_limiter.new_limit_session();
        let write_limiter = crate::SpeedLimiter::new(None, Some(NonZeroU32::MAX), Some(NonZeroU32::new(1).unwrap()));
        let write_limit = write_limiter.new_limit_session();
        let mut limit_stream = LimitStream::new(mock_stream, read_limit, write_limit);

        let mut buffer = [0u8; 1];
        let mut read_buf = ReadBuf::new(&mut buffer);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let result = Pin::new(&mut limit_stream).poll_read(&mut cx, &mut read_buf);
        assert!(result.is_ready());
        assert_eq!(read_buf.filled(), &[1]);

        let mut read_buf = ReadBuf::new(&mut buffer);
        let result = Pin::new(&mut limit_stream).poll_read(&mut cx, &mut read_buf);
        assert!(result.is_ready());
        assert_eq!(read_buf.filled(), &[2]);

        let mut read_buf = ReadBuf::new(&mut buffer);
        let result = Pin::new(&mut limit_stream).poll_read(&mut cx, &mut read_buf);
        assert!(result.is_pending());
        tokio::time::sleep(Duration::from_millis(600)).await;
        limit_stream.with_lock_raw_stream(|stream| {
            let error = Error::new(ErrorKind::Other, "read error");
            stream.get_mut().read_error = Some(error);
        });
        let result = Pin::new(&mut limit_stream).poll_read(&mut cx, &mut read_buf);
        assert!(result.is_ready());

        if let Poll::Ready(Err(e)) = result {
            assert_eq!(e.kind(), ErrorKind::Other);
        }
    }

    #[tokio::test]
    async fn test_write_without_limit() {
        let mock_stream = MockStream::new(vec![]);
        let read_limiter = crate::SpeedLimiter::new(None, Some(NonZeroU32::new(1).unwrap()), Some(NonZeroU32::new(1).unwrap()));
        let read_limit = read_limiter.new_limit_session();
        let write_limiter = crate::SpeedLimiter::new(None, Some(NonZeroU32::MAX), Some(NonZeroU32::new(1024).unwrap()));
        let write_limit = write_limiter.new_limit_session();
        let mut limit_stream = LimitStream::new(mock_stream, read_limit, write_limit);

        let data = [1, 2, 3, 4, 5];
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // 测试无限制写入
        let result = Pin::new(&mut limit_stream).poll_write(&mut cx, &data);
        assert!(result.is_ready());

        if let Poll::Ready(Ok(written)) = result {
            assert_eq!(written, 5);
        }
    }

    #[tokio::test]
    async fn test_write_without_limit2() {
        let error = Error::new(ErrorKind::Other, "write error");
        let mock_stream = MockStream::new(vec![]).with_write_error(error);
        let read_limiter = crate::SpeedLimiter::new(None, Some(NonZeroU32::new(1).unwrap()), Some(NonZeroU32::new(1).unwrap()));
        let read_limit = read_limiter.new_limit_session();
        let write_limiter = crate::SpeedLimiter::new(None, Some(NonZeroU32::MAX), Some(NonZeroU32::new(1024).unwrap()));
        let write_limit = write_limiter.new_limit_session();
        let mut limit_stream = LimitStream::new(mock_stream, read_limit, write_limit);

        let data = [1, 2, 3, 4, 5];
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // 测试无限制写入
        let result = Pin::new(&mut limit_stream).poll_write(&mut cx, &data);
        assert!(result.is_ready());

        if let Poll::Ready(ret) = result {
            assert!(ret.is_err());
            if let Err(e) = ret {
                assert_eq!(e.kind(), ErrorKind::Other);
            }
        }
    }

    #[tokio::test]
    async fn test_write_without_limit3() {
        let mock_stream = MockStream::new(vec![]).with_write_pending();
        let read_limiter = crate::SpeedLimiter::new(None, Some(NonZeroU32::new(1).unwrap()), Some(NonZeroU32::new(1).unwrap()));
        let read_limit = read_limiter.new_limit_session();
        let write_limiter = crate::SpeedLimiter::new(None, Some(NonZeroU32::MAX), Some(NonZeroU32::new(1024).unwrap()));
        let write_limit = write_limiter.new_limit_session();
        let mut limit_stream = LimitStream::new(mock_stream, read_limit, write_limit);

        let data = [1, 2, 3, 4, 5];
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let result = Pin::new(&mut limit_stream).poll_write(&mut cx, &data);
        assert!(result.is_pending());

        limit_stream.with_lock_raw_stream(|stream| {
            stream.get_mut().write_should_pending = false;
        });

        // 测试无限制写入
        let result = Pin::new(&mut limit_stream).poll_write(&mut cx, &data);
        assert!(result.is_ready());

        if let Poll::Ready(Ok(written)) = result {
            assert_eq!(written, 5);
        }
    }

    #[tokio::test]
    async fn test_write_without_limit4() {
        let mock_stream = MockStream::new(vec![]).with_write_pending();
        let read_limiter = crate::SpeedLimiter::new(None, Some(NonZeroU32::new(1).unwrap()), Some(NonZeroU32::new(1).unwrap()));
        let read_limit = read_limiter.new_limit_session();
        let write_limiter = crate::SpeedLimiter::new(None, Some(NonZeroU32::MAX), Some(NonZeroU32::new(1024).unwrap()));
        let write_limit = write_limiter.new_limit_session();
        let mut limit_stream = LimitStream::new(mock_stream, read_limit, write_limit);

        let data = [1, 2, 3, 4, 5];
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let result = Pin::new(&mut limit_stream).poll_write(&mut cx, &data);
        assert!(result.is_pending());

        limit_stream.with_lock_raw_stream(|stream| {
            let stream = stream.get_mut();
            stream.write_should_pending = false;
            let ererror = Error::new(ErrorKind::Other, "write error");
            stream.write_error = Some(ererror);
        });

        // 测试无限制写入
        let result = Pin::new(&mut limit_stream).poll_write(&mut cx, &data);
        assert!(result.is_ready());

        if let Poll::Ready(ret) = result {
            assert!(ret.is_err());
            if let Err(e) = ret {
                assert_eq!(e.kind(), ErrorKind::Other);
            }
        }
    }

    #[tokio::test]
    async fn test_write_with_limit() {
        let mock_stream = MockStream::new(vec![]);
        let read_limiter = crate::SpeedLimiter::new(None, Some(NonZeroU32::new(1).unwrap()), Some(NonZeroU32::new(1).unwrap()));
        let read_limit = read_limiter.new_limit_session();
        let write_limiter = crate::SpeedLimiter::new(None, Some(NonZeroU32::new(1).unwrap()), Some(NonZeroU32::new(1).unwrap()));
        let write_limit = write_limiter.new_limit_session();
        let mut limit_stream = LimitStream::new(mock_stream, read_limit, write_limit);

        let data = [1, 2, 3, 4, 5];
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // 第一次写入应该等待令牌
        let result = Pin::new(&mut limit_stream).poll_write(&mut cx, &data);
        // 由于使用了实际的SpeedLimiter，可能返回Pending或Ready
        assert!(result.is_ready());
        if let Poll::Ready(Ok(written)) = result {
            assert_eq!(written, 1);
        }

        // 第一次写入应该等待令牌
        let result = Pin::new(&mut limit_stream).poll_write(&mut cx, &data);
        assert!(result.is_pending());
        let start = Instant::now();
        let result = poll_fn(|cx| {
            Pin::new(&mut limit_stream).poll_write(cx, &data)
        }).await;
        assert!(start.elapsed() >= Duration::from_millis(900));
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 1);

        let result = poll_fn(|cx| {
            Pin::new(&mut limit_stream).poll_write(cx, &data)
        }).await;
        assert!(start.elapsed() >= Duration::from_millis(1900));
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 1);
    }

    #[tokio::test]
    async fn test_write_with_limit1() {
        let mock_stream = MockStream::new(vec![]).with_write_pending();
        let read_limiter = crate::SpeedLimiter::new(None, Some(NonZeroU32::new(1).unwrap()), Some(NonZeroU32::new(1).unwrap()));
        let read_limit = read_limiter.new_limit_session();
        let write_limiter = crate::SpeedLimiter::new(None, Some(NonZeroU32::new(1).unwrap()), Some(NonZeroU32::new(1).unwrap()));
        let write_limit = write_limiter.new_limit_session();
        let mut limit_stream = LimitStream::new(mock_stream, read_limit, write_limit);

        let data = [1, 2, 3, 4, 5];
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let result = Pin::new(&mut limit_stream).poll_write(&mut cx, &data);
        // 由于使用了实际的SpeedLimiter，可能返回Pending或Ready
        assert!(result.is_pending());
        limit_stream.with_lock_raw_stream(|stream| {
            stream.get_mut().write_should_pending = false;
        });

        let result = Pin::new(&mut limit_stream).poll_write(&mut cx, &data);
        assert!(result.is_ready());
        if let Poll::Ready(ret) = result {
            assert!(ret.is_ok());
            assert_eq!(ret.unwrap(), 1);
        }

        tokio::time::sleep(Duration::from_millis(1100)).await;
        limit_stream.with_lock_raw_stream(|stream| {
            stream.get_mut().write_should_pending = true;
        });

        let result = Pin::new(&mut limit_stream).poll_write(&mut cx, &data);
        assert!(result.is_pending());

        let result = Pin::new(&mut limit_stream).poll_write(&mut cx, &data);
        assert!(result.is_pending());

        limit_stream.with_lock_raw_stream(|stream| {
            let stream = stream.get_mut();
            stream.write_should_pending = false;
            let ererror = Error::new(ErrorKind::Other, "write error");
            stream.write_error = Some(ererror);
        });

        let result = Pin::new(&mut limit_stream).poll_write(&mut cx, &data);
        assert!(result.is_ready());
        if let Poll::Ready(Err(e)) = result {
            assert_eq!(e.kind(), ErrorKind::Other);
        }
    }

    #[tokio::test]
    async fn test_write_with_limit2() {
        let mock_stream = MockStream::new(vec![]).with_write_pending();
        let read_limiter = crate::SpeedLimiter::new(None, Some(NonZeroU32::new(1).unwrap()), Some(NonZeroU32::new(1).unwrap()));
        let read_limit = read_limiter.new_limit_session();
        let write_limiter = crate::SpeedLimiter::new(None, Some(NonZeroU32::new(1).unwrap()), Some(NonZeroU32::new(2).unwrap()));
        let write_limit = write_limiter.new_limit_session();
        let mut limit_stream = LimitStream::new(mock_stream, read_limit, write_limit);

        let data = [1];
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let result = Pin::new(&mut limit_stream).poll_write(&mut cx, &data);
        // 由于使用了实际的SpeedLimiter，可能返回Pending或Ready
        assert!(result.is_pending());
        limit_stream.with_lock_raw_stream(|stream| {
            let stream = stream.get_mut();
            stream.write_should_pending = false;
        });

        let result = Pin::new(&mut limit_stream).poll_write(&mut cx, &data);
        assert!(result.is_ready());
        if let Poll::Ready(ret) = result {
            assert!(ret.is_ok());
            assert_eq!(ret.unwrap(), 1);
        }
        let result = Pin::new(&mut limit_stream).poll_write(&mut cx, &data);
        assert!(result.is_ready());
        if let Poll::Ready(ret) = result {
            assert!(ret.is_ok());
            assert_eq!(ret.unwrap(), 1);
        }
    }

    #[tokio::test]
    async fn test_write_with_limit3() {
        let mock_stream = MockStream::new(vec![]);
        let read_limiter = crate::SpeedLimiter::new(None, Some(NonZeroU32::new(1).unwrap()), Some(NonZeroU32::new(1).unwrap()));
        let read_limit = read_limiter.new_limit_session();
        let write_limiter = crate::SpeedLimiter::new(None, Some(NonZeroU32::new(1).unwrap()), Some(NonZeroU32::new(2).unwrap()));
        let write_limit = write_limiter.new_limit_session();
        let mut limit_stream = LimitStream::new(mock_stream, read_limit, write_limit);

        let data = [1];
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let result = Pin::new(&mut limit_stream).poll_write(&mut cx, &data);
        assert!(result.is_ready());
        if let Poll::Ready(ret) = result {
            assert!(ret.is_ok());
            assert_eq!(ret.unwrap(), 1);
        }

        let result = Pin::new(&mut limit_stream).poll_write(&mut cx, &data);
        assert!(result.is_ready());
        if let Poll::Ready(ret) = result {
            assert!(ret.is_ok());
            assert_eq!(ret.unwrap(), 1);
        }

        let result = Pin::new(&mut limit_stream).poll_write(&mut cx, &data);
        // 由于使用了实际的SpeedLimiter，可能返回Pending或Ready
        assert!(result.is_pending());
        limit_stream.with_lock_raw_stream(|stream| {
            let stream = stream.get_mut();
            stream.write_should_pending = false;
        });

        tokio::time::sleep(Duration::from_millis(1100)).await;
        let result = Pin::new(&mut limit_stream).poll_write(&mut cx, &data);
        assert!(result.is_ready());
        if let Poll::Ready(ret) = result {
            assert!(ret.is_ok());
            assert_eq!(ret.unwrap(), 1);
        }
        let result = Pin::new(&mut limit_stream).poll_write(&mut cx, &data);
        assert!(result.is_ready());
        if let Poll::Ready(ret) = result {
            assert!(ret.is_ok());
            assert_eq!(ret.unwrap(), 1);
        }
    }

    #[tokio::test]
    async fn test_write_with_limit4() {
        let mock_stream = MockStream::new(vec![]);
        let read_limiter = crate::SpeedLimiter::new(None, Some(NonZeroU32::new(1).unwrap()), Some(NonZeroU32::new(1).unwrap()));
        let read_limit = read_limiter.new_limit_session();
        let write_limiter = crate::SpeedLimiter::new(None, Some(NonZeroU32::new(1).unwrap()), Some(NonZeroU32::new(2).unwrap()));
        let write_limit = write_limiter.new_limit_session();
        let mut limit_stream = LimitStream::new(mock_stream, read_limit, write_limit);

        let data = [1];
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let result = Pin::new(&mut limit_stream).poll_write(&mut cx, &data);
        assert!(result.is_ready());
        if let Poll::Ready(ret) = result {
            assert!(ret.is_ok());
            assert_eq!(ret.unwrap(), 1);
        }

        let result = Pin::new(&mut limit_stream).poll_write(&mut cx, &data);
        assert!(result.is_ready());
        if let Poll::Ready(ret) = result {
            assert!(ret.is_ok());
            assert_eq!(ret.unwrap(), 1);
        }

        let result = Pin::new(&mut limit_stream).poll_write(&mut cx, &data);
        assert!(result.is_pending());

        tokio::time::sleep(Duration::from_millis(1100)).await;
        limit_stream.with_lock_raw_stream(|stream| {
            let stream = stream.get_mut();
            stream.write_should_pending = true;
        });
        let result = Pin::new(&mut limit_stream).poll_write(&mut cx, &data);
        assert!(result.is_pending());

        limit_stream.with_lock_raw_stream(|stream| {
            let stream = stream.get_mut();
            stream.write_should_pending = false;
            let ererror = Error::new(ErrorKind::Other, "write error");
            stream.write_error = Some(ererror);
        });
        let result = Pin::new(&mut limit_stream).poll_write(&mut cx, &data);
        assert!(result.is_ready());
        if let Poll::Ready(ret) = result {
            assert!(ret.is_err());
        }
    }

    #[tokio::test]
    async fn test_write_with_limit5() {
        let mock_stream = MockStream::new(vec![]);
        let read_limiter = crate::SpeedLimiter::new(None, Some(NonZeroU32::new(1).unwrap()), Some(NonZeroU32::new(1).unwrap()));
        let read_limit = read_limiter.new_limit_session();
        let write_limiter = crate::SpeedLimiter::new(None, Some(NonZeroU32::new(1).unwrap()), Some(NonZeroU32::new(2).unwrap()));
        let write_limit = write_limiter.new_limit_session();
        let mut limit_stream = LimitStream::new(mock_stream, read_limit, write_limit);

        let data = [1];
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let result = Pin::new(&mut limit_stream).poll_write(&mut cx, &data);
        assert!(result.is_ready());
        if let Poll::Ready(ret) = result {
            assert!(ret.is_ok());
            assert_eq!(ret.unwrap(), 1);
        }

        let result = Pin::new(&mut limit_stream).poll_write(&mut cx, &data);
        assert!(result.is_ready());
        if let Poll::Ready(ret) = result {
            assert!(ret.is_ok());
            assert_eq!(ret.unwrap(), 1);
        }

        let result = Pin::new(&mut limit_stream).poll_write(&mut cx, &data);
        assert!(result.is_pending());

        tokio::time::sleep(Duration::from_millis(1100)).await;

        limit_stream.with_lock_raw_stream(|stream| {
            let stream = stream.get_mut();
            let ererror = Error::new(ErrorKind::Other, "write error");
            stream.write_error = Some(ererror);
        });

        let result = Pin::new(&mut limit_stream).poll_write(&mut cx, &data);
        assert!(result.is_ready());
        if let Poll::Ready(ret) = result {
            assert!(ret.is_err());
        }
    }

    #[tokio::test]
    async fn test_read_error_propagation() {
        let error = Error::new(ErrorKind::Other, "read error");
        let mock_stream = MockStream::new(vec![]).with_read_error(error);
        let read_limiter = crate::SpeedLimiter::new(None, Some(NonZeroU32::new(1).unwrap()), Some(NonZeroU32::new(1).unwrap()));
        let read_limit = read_limiter.new_limit_session();
        let write_limiter = crate::SpeedLimiter::new(None, Some(NonZeroU32::new(10).unwrap()), Some(NonZeroU32::new(10).unwrap()));
        let write_limit = write_limiter.new_limit_session();
        let mut limit_stream = LimitStream::new(mock_stream, read_limit, write_limit);

        let mut buffer = [0u8; 10];
        let mut read_buf = ReadBuf::new(&mut buffer);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let result = Pin::new(&mut limit_stream).poll_read(&mut cx, &mut read_buf);
        assert!(result.is_ready());

        if let Poll::Ready(Err(e)) = result {
            assert_eq!(e.kind(), ErrorKind::Other);
        }
    }

    #[tokio::test]
    async fn test_write_error_propagation() {
        let error = Error::new(ErrorKind::Other, "write error");
        let mock_stream = MockStream::new(vec![]).with_write_error(error);
        let read_limiter = crate::SpeedLimiter::new(None, Some(NonZeroU32::new(1).unwrap()), Some(NonZeroU32::new(1).unwrap()));
        let read_limit = read_limiter.new_limit_session();
        let write_limiter = crate::SpeedLimiter::new(None, Some(NonZeroU32::new(10).unwrap()), Some(NonZeroU32::new(10).unwrap()));
        let write_limit = write_limiter.new_limit_session();
        let mut limit_stream = LimitStream::new(mock_stream, read_limit, write_limit);

        let data = [1, 2, 3, 4, 5];
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let result = Pin::new(&mut limit_stream).poll_write(&mut cx, &data);
        assert!(result.is_ready());

        if let Poll::Ready(Err(e)) = result {
            assert_eq!(e.kind(), ErrorKind::Other);
        }
    }

    #[tokio::test]
    async fn test_read_limit_pending_handling() {
        let mock_stream = MockStream::new(vec![1, 2, 3, 4, 5]).with_read_pending();
        let read_limiter = crate::SpeedLimiter::new(None, Some(NonZeroU32::new(1).unwrap()), Some(NonZeroU32::new(1).unwrap()));
        let read_limit = read_limiter.new_limit_session();
        let write_limiter = crate::SpeedLimiter::new(None, Some(NonZeroU32::new(1).unwrap()), Some(NonZeroU32::new(1).unwrap()));
        let write_limit = write_limiter.new_limit_session();
        let mut limit_stream = LimitStream::new(mock_stream, read_limit, write_limit);

        let mut buffer = [0u8; 10];
        let mut read_buf = ReadBuf::new(&mut buffer);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // 第一次应该返回Pending
        let result = Pin::new(&mut limit_stream).poll_read(&mut cx, &mut read_buf);
        assert!(result.is_pending());
        let result = Pin::new(&mut limit_stream).poll_read(&mut cx, &mut read_buf);
        assert!(result.is_pending());
    }

    #[tokio::test]
    async fn test_read_limit_pending_handling2() {
        let mock_stream = MockStream::new(vec![1, 2, 3, 4, 5]);
        let read_limiter = crate::SpeedLimiter::new(None, Some(NonZeroU32::new(1).unwrap()), Some(NonZeroU32::new(1).unwrap()));
        let read_limit = read_limiter.new_limit_session();
        let write_limiter = crate::SpeedLimiter::new(None, Some(NonZeroU32::new(1).unwrap()), Some(NonZeroU32::new(1).unwrap()));
        let write_limit = write_limiter.new_limit_session();
        let mut limit_stream = LimitStream::new(mock_stream, read_limit, write_limit);

        let mut buffer = [0u8; 1];
        let mut read_buf = ReadBuf::new(&mut buffer);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // 第一次应该返回Pending
        let result = Pin::new(&mut limit_stream).poll_read(&mut cx, &mut read_buf);
        assert!(result.is_ready());
        let result = Pin::new(&mut limit_stream).poll_read(&mut cx, &mut read_buf);
        assert!(result.is_pending());
        let result = Pin::new(&mut limit_stream).poll_read(&mut cx, &mut read_buf);
        assert!(result.is_pending());
    }

    #[tokio::test]
    async fn test_read_pending_handling() {
        let mock_stream = MockStream::new(vec![1, 2, 3, 4, 5]).with_read_pending();
        let read_limiter = crate::SpeedLimiter::new(None, Some(NonZeroU32::new(1).unwrap()), Some(NonZeroU32::new(1).unwrap()));
        let read_limit = read_limiter.new_limit_session();
        let write_limiter = crate::SpeedLimiter::new(None, Some(NonZeroU32::MAX), Some(NonZeroU32::new(1).unwrap()));
        let write_limit = write_limiter.new_limit_session();
        let mut limit_stream = LimitStream::new(mock_stream, read_limit, write_limit);

        let mut buffer = [0u8; 10];
        let mut read_buf = ReadBuf::new(&mut buffer);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // 第一次应该返回Pending
        let result = Pin::new(&mut limit_stream).poll_read(&mut cx, &mut read_buf);
        assert!(result.is_pending());
        let result = Pin::new(&mut limit_stream).poll_read(&mut cx, &mut read_buf);
        assert!(result.is_pending());
    }

    #[tokio::test]
    async fn test_write_pending_handling() {
        let mock_stream = MockStream::new(vec![]).with_write_pending();
        let read_limiter = crate::SpeedLimiter::new(None, Some(NonZeroU32::new(1).unwrap()), Some(NonZeroU32::new(1).unwrap()));
        let read_limit = read_limiter.new_limit_session();
        let write_limiter = crate::SpeedLimiter::new(None, Some(NonZeroU32::MAX), Some(NonZeroU32::new(1).unwrap()));
        let write_limit = write_limiter.new_limit_session();
        let mut limit_stream = LimitStream::new(mock_stream, read_limit, write_limit);

        let data = [1, 2, 3, 4, 5];
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // 第一次应该返回Pending
        let result = Pin::new(&mut limit_stream).poll_write(&mut cx, &data);
        assert!(result.is_pending());
        let result = Pin::new(&mut limit_stream).poll_write(&mut cx, &data);
        assert!(result.is_pending());
    }

    #[tokio::test]
    async fn test_flush_and_shutdown() {
        let mock_stream = MockStream::new(vec![]);
        let read_limiter = crate::SpeedLimiter::new(None, Some(NonZeroU32::new(1).unwrap()), Some(NonZeroU32::new(1).unwrap()));
        let read_limit = read_limiter.new_limit_session();
        let write_limiter = crate::SpeedLimiter::new(None, Some(NonZeroU32::MAX), Some(NonZeroU32::new(1).unwrap()));
        let write_limit = write_limiter.new_limit_session();
        let mut limit_stream = LimitStream::new(mock_stream, read_limit, write_limit);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // 测试flush
        let flush_result = Pin::new(&mut limit_stream).poll_flush(&mut cx);
        assert!(flush_result.is_ready());

        // 测试shutdown
        let shutdown_result = Pin::new(&mut limit_stream).poll_shutdown(&mut cx);
        assert!(shutdown_result.is_ready());
    }

    #[tokio::test]
    async fn test_mixed_read_write() {
        let mock_stream = MockStream::new(vec![1, 2, 3, 4, 5]);
        let read_limiter = crate::SpeedLimiter::new(None, Some(NonZeroU32::new(10).unwrap()), Some(NonZeroU32::new(10).unwrap()));
        let read_limit = read_limiter.new_limit_session();
        let write_limiter = crate::SpeedLimiter::new(None, Some(NonZeroU32::new(10).unwrap()), Some(NonZeroU32::new(10).unwrap()));
        let write_limit = write_limiter.new_limit_session();
        let mut limit_stream = LimitStream::new(mock_stream, read_limit, write_limit);

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // 先写入数据
        let write_data = [6, 7, 8, 9, 10];
        let write_result = Pin::new(&mut limit_stream).poll_write(&mut cx, &write_data);
        assert!(write_result.is_ready());

        // 再读取数据
        let mut buffer = [0u8; 10];
        let mut read_buf = ReadBuf::new(&mut buffer);
        let read_result = Pin::new(&mut limit_stream).poll_read(&mut cx, &mut read_buf);
        assert!(read_result.is_ready());
    }
}
