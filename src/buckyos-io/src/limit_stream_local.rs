#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

use crate::SpeedLimitSession;
use pin_project::pin_project;
use std::future::Future;
use std::io::Error;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

enum ReadState {
    Idle,
    Waiting(Option<(Pin<Box<dyn Future<Output = usize> + 'static>>, usize)>),
    Reading(Option<(usize, usize)>),
}

enum WriteState {
    Idle,
    Waiting(Option<(Pin<Box<dyn Future<Output = usize> + 'static>>, usize)>),
    Writing(Option<(usize, usize)>),
}

#[pin_project]
pub struct LocalLimitStream<S: AsyncRead + AsyncWrite + Unpin> {
    #[pin]
    read: LocalLimitRead<crate::split::ReadHalf<S>>,
    #[pin]
    write: LocalLimitWrite<crate::split::WriteHalf<S>>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> LocalLimitStream<S> {
    pub fn new(stream: S, read_limit: SpeedLimitSession, write_limit: SpeedLimitSession) -> Self {
        let (read, write) = crate::split::split(stream);
        let limit_read = LocalLimitRead::new(read, read_limit);
        let limit_write = LocalLimitWrite::new(write, write_limit);
        LocalLimitStream {
            read: limit_read,
            write: limit_write,
        }
    }

    pub fn with_lock_raw_stream<R>(&mut self, f: impl FnOnce(Pin<&mut S>) -> R) -> R {
        self.read.raw_read().with_lock(f)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for LocalLimitStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, Error>> {
        self.project().write.poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        self.project().write.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        self.project().write.poll_shutdown(cx)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for LocalLimitStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.project().read.poll_read(cx, buf)
    }
}

#[pin_project]
pub struct LocalLimitRead<S: AsyncRead + Unpin> {
    #[pin]
    read: S,
    read_limit: SpeedLimitSession,
    read_state: ReadState,
}

impl<S: AsyncRead + Unpin> LocalLimitRead<S> {
    pub fn new(read: S, read_limit: SpeedLimitSession) -> Self {
        LocalLimitRead {
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

impl<S: AsyncRead + Unpin> AsyncRead for LocalLimitRead<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.project();
        buf.initialize_unfilled();
        match this.read_state {
            ReadState::Idle => {
                let mut readded_len = 0;
                let read_limit: &'static mut SpeedLimitSession =
                    unsafe { std::mem::transmute(this.read_limit) };
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
                                    *this.read_state =
                                        ReadState::Reading(Some((read_len, readded_len)));
                                }
                                Poll::Ready(Ok(()))
                            }
                            Poll::Ready(Err(e)) => {
                                *this.read_state = ReadState::Idle;
                                Poll::Ready(Err(e))
                            }
                            Poll::Pending => {
                                *this.read_state =
                                    ReadState::Reading(Some((read_len, readded_len)));
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
                                    *this.read_state =
                                        ReadState::Reading(Some((read_len, readded_len)));
                                }
                                Poll::Ready(Ok(()))
                            }
                            Poll::Ready(Err(e)) => {
                                *this.read_state = ReadState::Idle;
                                Poll::Ready(Err(e))
                            }
                            Poll::Pending => {
                                *this.read_state =
                                    ReadState::Reading(Some((read_len, readded_len)));
                                Poll::Pending
                            }
                        }
                    }
                    Poll::Pending => {
                        *this.read_state = ReadState::Waiting(Some((rx, readded_len)));
                        Poll::Pending
                    }
                }
            }
            ReadState::Reading(state) => match state.take() {
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
                                *this.read_state =
                                    ReadState::Reading(Some((read_len, readded_len)));
                            }
                            Poll::Ready(Ok(()))
                        }
                        Poll::Ready(Err(e)) => {
                            *this.read_state = ReadState::Idle;
                            Poll::Ready(Err(e))
                        }
                        Poll::Pending => {
                            *this.read_state = ReadState::Reading(Some((read_len, readded_len)));
                            Poll::Pending
                        }
                    }
                }
                None => match this.read.poll_read(cx, buf) {
                    Poll::Ready(Ok(())) => {
                        *this.read_state = ReadState::Idle;
                        Poll::Ready(Ok(()))
                    }
                    Poll::Ready(Err(e)) => {
                        *this.read_state = ReadState::Idle;
                        Poll::Ready(Err(e))
                    }
                    Poll::Pending => {
                        *this.read_state = ReadState::Reading(None);
                        Poll::Pending
                    }
                },
            },
        }
    }
}

#[pin_project]
pub struct LocalLimitWrite<S: AsyncWrite + Unpin> {
    #[pin]
    write: S,
    write_limit: SpeedLimitSession,
    write_state: WriteState,
}

impl<S: AsyncWrite + Unpin> LocalLimitWrite<S> {
    pub fn new(write: S, write_limit: SpeedLimitSession) -> Self {
        LocalLimitWrite {
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

impl<S: AsyncWrite + Unpin> AsyncWrite for LocalLimitWrite<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, Error>> {
        let this = self.project();
        match this.write_state {
            WriteState::Idle => {
                let mut written_len = 0;
                let write_limiter: &'static mut SpeedLimitSession =
                    unsafe { std::mem::transmute(this.write_limit) };
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
                                    *this.write_state =
                                        WriteState::Writing(Some((write_len, written_len)));
                                }
                                Poll::Ready(Ok(written_len))
                            }
                            Poll::Ready(Err(e)) => {
                                *this.write_state = WriteState::Idle;
                                Poll::Ready(Err(e))
                            }
                            Poll::Pending => {
                                *this.write_state =
                                    WriteState::Writing(Some((write_len, written_len)));
                                Poll::Pending
                            }
                        }
                    }
                    Poll::Pending => {
                        *this.write_state =
                            WriteState::Waiting(Some((waiting_future, written_len)));
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
                                    *this.write_state =
                                        WriteState::Writing(Some((write_len, written_len)));
                                }
                                Poll::Ready(Ok(len))
                            }
                            Poll::Ready(Err(e)) => {
                                *this.write_state = WriteState::Idle;
                                Poll::Ready(Err(e))
                            }
                            Poll::Pending => {
                                *this.write_state =
                                    WriteState::Writing(Some((write_len, written_len)));
                                Poll::Pending
                            }
                        }
                    }
                    Poll::Pending => {
                        *this.write_state =
                            WriteState::Waiting(Some((waiting_future, written_len)));
                        Poll::Pending
                    }
                }
            }
            WriteState::Writing(state) => match state.take() {
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
                                *this.write_state =
                                    WriteState::Writing(Some((write_len, written_len)));
                            }
                            Poll::Ready(Ok(len))
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
                None => match this.write.poll_write(cx, buf) {
                    Poll::Ready(Ok(len)) => {
                        *this.write_state = WriteState::Idle;
                        Poll::Ready(Ok(len))
                    }
                    Poll::Ready(Err(e)) => {
                        *this.write_state = WriteState::Idle;
                        Poll::Ready(Err(e))
                    }
                    Poll::Pending => {
                        *this.write_state = WriteState::Writing(None);
                        Poll::Pending
                    }
                },
            },
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        self.project().write.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        self.project().write.poll_shutdown(cx)
    }
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::SpeedLimiter;
    use std::cell::RefCell;
    use std::io;
    use std::num::NonZeroU32;
    use std::rc::Rc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    struct LocalMockStream {
        read_data: Rc<RefCell<Vec<u8>>>,
        written_data: Rc<RefCell<Vec<u8>>>,
    }

    impl AsyncRead for LocalMockStream {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let mut read_data = self.read_data.borrow_mut();
            let len = read_data.len().min(buf.remaining());
            buf.put_slice(&read_data[..len]);
            read_data.drain(..len);
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for LocalMockStream {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.written_data.borrow_mut().extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn local_limit_stream_accepts_non_send_inner() {
        let read_data = Rc::new(RefCell::new(vec![1, 2, 3]));
        let written_data = Rc::new(RefCell::new(Vec::new()));
        let mock = LocalMockStream {
            read_data,
            written_data: written_data.clone(),
        };
        let read_limit = SpeedLimiter::new(None, None, NonZeroU32::new(64)).new_limit_session();
        let write_limit = SpeedLimiter::new(None, None, NonZeroU32::new(64)).new_limit_session();
        let mut stream = LocalLimitStream::new(mock, read_limit, write_limit);

        let mut read_buf = [0; 3];
        stream.read_exact(&mut read_buf).await.unwrap();
        stream.write_all(&[4, 5, 6]).await.unwrap();

        assert_eq!(read_buf, [1, 2, 3]);
        assert_eq!(&*written_data.borrow(), &[4, 5, 6]);
    }
}
