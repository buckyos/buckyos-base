use std::{cmp, io};
use std::ops::DerefMut;
use std::pin::Pin;
use std::sync::Mutex;
use std::task::{ready, Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use crate::buf::{Buf, DEFAULT_MAX_BUF_SIZE};

#[async_trait::async_trait]
pub trait SimpleAsyncRead: Send + 'static + Unpin {
    async fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize>;
}

#[async_trait::async_trait]
pub trait SimpleAsyncWrite: Send + 'static + Unpin {
    async fn write(&mut self, buf: &[u8]) -> std::io::Result<usize>;
    async fn flush(&mut self) -> std::io::Result<()>;
    async fn shutdown(&mut self) -> std::io::Result<()>;
}

enum State<T> {
    Idle(Option<Buf>),
    Busy(Pin<Box<dyn Future<Output=(std::io::Result<usize>, Buf, T)> + Send>>),
}

enum FlushState<T> {
    Idle,
    Busy(Pin<Box<dyn Future<Output=(std::io::Result<()>, T)> + Send>>),
}

enum ShutdownState<T> {
    Idle,
    Busy(Pin<Box<dyn Future<Output=(std::io::Result<()>, T)> + Send>>),
}

struct ReadHolderInner<T: SimpleAsyncRead> {
    inner: Option<T>,
    state: State<T>,
}
pub struct SimpleAsyncReadHolder<T: SimpleAsyncRead> {
    inner: Mutex<ReadHolderInner<T>>,
}

impl<T: SimpleAsyncRead> SimpleAsyncReadHolder<T> {
    pub fn new(inner: T) -> SimpleAsyncReadHolder<T> {
        SimpleAsyncReadHolder {
            inner: Mutex::new(ReadHolderInner {
                inner: Some(inner),
                state: State::Idle(Some(Buf::with_capacity(0))),
            }),
        }
    }

    pub fn with_lock_read<R>(&self, f: impl FnOnce(Option<&mut T>) -> R) -> R {
        let mut state = self.inner.lock().unwrap();
        f(state.inner.as_mut())
    }

    pub fn into_read(self) -> Option<T> {
        let mut state = self.inner.lock().unwrap();
        return state.inner.take();
    }
}

impl <T: SimpleAsyncRead> AsyncRead for SimpleAsyncReadHolder<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        dst: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut state = self.inner.lock().unwrap();
        loop {
            match &mut state.deref_mut().state {
                State::Idle(buf_cell) => {
                    let mut buf = buf_cell.take().unwrap();

                    if !buf.is_empty() {
                        buf.copy_to(dst);
                        *buf_cell = Some(buf);
                        return Poll::Ready(Ok(()));
                    }

                    let mut inner = state.inner.take().unwrap();
                    let max_buf_size = cmp::min(dst.remaining(), DEFAULT_MAX_BUF_SIZE);
                    state.state = State::Busy(Box::pin(async move {
                        let ret = unsafe {buf.read_from_async(&mut inner, max_buf_size).await };
                        (ret, buf, inner)
                    }));
                }
                State::Busy(rx) => {
                    let (res, mut buf, inner) = ready!(Pin::new(rx).poll(cx));
                    state.inner = Some(inner);

                    match res {
                        Ok(_) => {
                            buf.copy_to(dst);
                            state.state = State::Idle(Some(buf));
                            return Poll::Ready(Ok(()));
                        }
                        Err(e) => {
                            assert!(buf.is_empty());

                            state.state = State::Idle(Some(buf));
                            return Poll::Ready(Err(e));
                        }
                    }
                }
            }
        }
    }
}

struct SimpleAsyncWriteHolderInner<T: SimpleAsyncWrite> {
    inner: Option<T>,
    state: State<T>,
    flush_state: FlushState<T>,
    shutdown_state: ShutdownState<T>,
}
pub struct SimpleAsyncWriteHolder<T: SimpleAsyncWrite> {
    inner: Mutex<SimpleAsyncWriteHolderInner<T>>,
}

impl<T: SimpleAsyncWrite> SimpleAsyncWriteHolder<T> {
    pub fn new(inner: T) -> SimpleAsyncWriteHolder<T> {
        Self {
            inner: Mutex::new(SimpleAsyncWriteHolderInner {
                inner: Some(inner),
                state: State::Idle(Some(Buf::with_capacity(0))),
                flush_state: FlushState::Idle,
                shutdown_state: ShutdownState::Idle,
            }),
        }
    }

    pub fn with_lock_write<R>(&self, f: impl FnOnce(Option<&mut T>) -> R) -> R {
        let mut state = self.inner.lock().unwrap();
        f(state.inner.as_mut())
    }

    pub fn into_write(self) -> Option<T> {
        let mut state = self.inner.lock().unwrap();
        return state.inner.take();
    }
}

impl<T: SimpleAsyncWrite> AsyncWrite for SimpleAsyncWriteHolder<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        src: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut state = self.inner.lock().unwrap();
        loop {
            match state.deref_mut().state {
                State::Idle(ref mut buf_cell) => {
                    let mut buf = buf_cell.take().unwrap();

                    assert!(buf.is_empty());

                    buf.copy_from(src, DEFAULT_MAX_BUF_SIZE);
                    let mut inner = state.inner.take().unwrap();

                    state.state = State::Busy(Box::pin(async move {
                        let res = buf.write_to_async(&mut inner).await;

                        (res, buf, inner)
                    }));
                }
                State::Busy(ref mut rx) => {
                    let (res, buf, inner) = ready!(Pin::new(rx).poll(cx));
                    state.state = State::Idle(Some(buf));
                    state.inner = Some(inner);

                    // If error, return
                    return Poll::Ready(res);
                }
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        let mut state = self.inner.lock().unwrap();
        loop {
            match state.deref_mut().flush_state {
                // The buffer is not used here
                FlushState::Idle => {
                        let mut inner = state.inner.take().unwrap();

                        state.flush_state = FlushState::Busy(Box::pin(async move {
                            let res = inner.flush().await;
                            (res, inner)
                        }));
                }
                FlushState::Busy(ref mut rx) => {
                    let (res, inner) = ready!(Pin::new(rx).poll(cx));
                    state.flush_state = FlushState::Idle;
                    state.inner = Some(inner);

                    // If error, return
                    return Poll::Ready(res);
                }
            }
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        let mut state = self.inner.lock().unwrap();
        loop {
            match state.deref_mut().shutdown_state {
                ShutdownState::Idle => {
                        let mut inner = state.inner.take().unwrap();

                        state.shutdown_state = ShutdownState::Busy(Box::pin(async move {
                            let res = inner.shutdown().await;
                            (res, inner)
                        }));
                }
                ShutdownState::Busy(ref mut rx) => {
                    let (res, inner) = ready!(Pin::new(rx).poll(cx));
                    state.shutdown_state = ShutdownState::Idle;
                    state.inner = Some(inner);
                    return Poll::Ready(res);
                }
            }
        }
    }
}

#[cfg(test)]
mod test {
    use std::io;
    use std::sync::{Arc, Mutex};
    use crate::{SimpleAsyncRead, SimpleAsyncReadHolder, SimpleAsyncWrite, SimpleAsyncWriteHolder};
    use tokio::io::AsyncWriteExt;
    use tokio::io::AsyncReadExt;

    pub struct TestSimpleAsyncWrite {
        buf: Arc<Mutex<Vec<u8>>>
    }

    impl TestSimpleAsyncWrite {
        pub fn new(buf: Arc<Mutex<Vec<u8>>>) -> TestSimpleAsyncWrite {
            TestSimpleAsyncWrite {
                buf,
            }
        }
    }

    #[async_trait::async_trait]
    impl SimpleAsyncWrite for TestSimpleAsyncWrite {
        async fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            {
                let mut buffer = self.buf.lock().unwrap();
                buffer.extend_from_slice(buf);
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(1)).await;
            Ok(buf.len())
        }

        async fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }

        async fn shutdown(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    pub struct TestSimpleAsyncRead {
        buf: Arc<Mutex<Vec<u8>>>
    }

    impl TestSimpleAsyncRead {
        pub fn new(buf: Arc<Mutex<Vec<u8>>>) -> TestSimpleAsyncRead {
            TestSimpleAsyncRead { buf }
        }
    }

    #[async_trait::async_trait]
    impl SimpleAsyncRead for TestSimpleAsyncRead {
        async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            tokio::time::sleep(tokio::time::Duration::from_millis(1)).await;
            let buffer = self.buf.lock().unwrap();
            let len = buffer.len();
            buf.copy_from_slice(&buffer[..len]);
            Ok(buf.len())
        }
    }

    #[tokio::test]
    async fn test_simple_async_io() {
        let buf = Arc::new(Mutex::new(Vec::new()));
        let mut write = SimpleAsyncWriteHolder::new(TestSimpleAsyncWrite::new(buf.clone()));
        let data = "tttt".to_string();
        write.write_all(data.as_bytes()).await.unwrap();
        write.flush().await.unwrap();
        write.shutdown().await.unwrap();

        let mut read = SimpleAsyncReadHolder::new(TestSimpleAsyncRead::new(buf.clone()));
        let mut buf = [0u8; 4];

        read.read(&mut buf).await.unwrap();
        assert_eq!(String::from_utf8_lossy(buf.as_slice()), data);
    }
}
