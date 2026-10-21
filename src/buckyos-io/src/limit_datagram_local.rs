#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

use crate::SpeedLimitSession;

#[async_trait::async_trait(?Send)]
pub trait LocalDatagramSend {
    type Error;
    async fn send_to(&mut self, buf: &[u8]) -> Result<usize, Self::Error>;
}

#[async_trait::async_trait(?Send)]
pub trait LocalDatagramRecv {
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

pub struct LocalLimitDatagramSend<S: LocalDatagramSend> {
    inner: S,
    write_limiter: SpeedLimitSession,
    write_state: WriteState,
}

impl<S: LocalDatagramSend> LocalLimitDatagramSend<S> {
    pub fn new(inner: S, write_limiter: SpeedLimitSession) -> Self {
        Self {
            inner,
            write_limiter,
            write_state: WriteState::Idle,
        }
    }
}

#[async_trait::async_trait(?Send)]
impl<S: LocalDatagramSend> LocalDatagramSend for LocalLimitDatagramSend<S> {
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
            }
        }
    }
}

pub struct LocalLimitDatagramRecv<R: LocalDatagramRecv> {
    inner: R,
    read_limiter: SpeedLimitSession,
    read_state: ReadState,
}

impl<R: LocalDatagramRecv> LocalLimitDatagramRecv<R> {
    pub fn new(inner: R, read_limiter: SpeedLimitSession) -> Self {
        Self {
            inner,
            read_limiter,
            read_state: ReadState::Idle,
        }
    }
}

#[async_trait::async_trait(?Send)]
impl<R: LocalDatagramRecv> LocalDatagramRecv for LocalLimitDatagramRecv<R> {
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
            }
            ReadState::Reading((read_len, readded_len)) => {
                let len = self.inner.recv_from(buf).await?;
                if *readded_len + len >= *read_len {
                    self.read_state = ReadState::Idle;
                } else {
                    self.read_state = ReadState::Reading((*read_len, *readded_len + len));
                }
                Ok(len)
            }
        }
    }
}

#[async_trait::async_trait(?Send)]
pub trait LocalDatagram {
    type Error;
    async fn send_to(&mut self, buf: &[u8]) -> Result<usize, Self::Error>;
    async fn recv_from(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error>;
}

pub struct LocalLimitDatagram<D: LocalDatagram> {
    inner: D,
    write_limiter: SpeedLimitSession,
    read_limiter: SpeedLimitSession,
    read_state: ReadState,
    write_state: WriteState,
}

impl<D: LocalDatagram> LocalLimitDatagram<D> {
    pub fn new(inner: D, read_limit: SpeedLimitSession, write_limit: SpeedLimitSession) -> Self {
        Self {
            inner,
            write_limiter: write_limit,
            read_limiter: read_limit,
            read_state: ReadState::Idle,
            write_state: WriteState::Idle,
        }
    }
}

#[async_trait::async_trait(?Send)]
impl<D: LocalDatagram> LocalDatagram for LocalLimitDatagram<D> {
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
            }
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
            }
            ReadState::Reading((read_len, readded_len)) => {
                let len = self.inner.recv_from(buf).await?;
                if *readded_len + len >= *read_len {
                    self.read_state = ReadState::Idle;
                } else {
                    self.read_state = ReadState::Reading((*read_len, *readded_len + len));
                }
                Ok(len)
            }
        }
    }
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::SpeedLimiter;
    use std::cell::RefCell;
    use std::num::NonZeroU32;
    use std::rc::Rc;

    struct LocalMockDatagram {
        calls: Rc<RefCell<Vec<&'static str>>>,
    }

    #[async_trait::async_trait(?Send)]
    impl LocalDatagram for LocalMockDatagram {
        type Error = &'static str;

        async fn send_to(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
            self.calls.borrow_mut().push("send_to");
            Ok(buf.len())
        }

        async fn recv_from(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
            self.calls.borrow_mut().push("recv_from");
            Ok(buf.len())
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn local_limit_datagram_accepts_non_send_inner() {
        let calls = Rc::new(RefCell::new(Vec::new()));
        let mock = LocalMockDatagram {
            calls: calls.clone(),
        };
        let read_limit = SpeedLimiter::new(None, None, NonZeroU32::new(64)).new_limit_session();
        let write_limit = SpeedLimiter::new(None, None, NonZeroU32::new(64)).new_limit_session();
        let mut datagram = LocalLimitDatagram::new(mock, read_limit, write_limit);

        let mut recv_buf = [0; 8];
        assert_eq!(datagram.send_to(&[1, 2, 3]).await, Ok(3));
        assert_eq!(datagram.recv_from(&mut recv_buf).await, Ok(8));
        assert_eq!(&*calls.borrow(), &["send_to", "recv_from"]);
    }
}
