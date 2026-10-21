use std::future::poll_fn;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::{self, Instant};

const DEFAULT_COPY_BUF_SIZE: usize = 8 * 1024;
const MAX_COPY_OPS_PER_POLL: usize = 128;

#[derive(Debug)]
struct CopyBuffer {
    read_done: bool,
    need_flush: bool,
    pos: usize,
    cap: usize,
    amt: u64,
    buf: Box<[u8]>,
}

impl CopyBuffer {
    fn new(buf_size: usize) -> Self {
        Self {
            read_done: false,
            need_flush: false,
            pos: 0,
            cap: 0,
            amt: 0,
            buf: vec![0; buf_size].into_boxed_slice(),
        }
    }

    fn poll_fill_buf<R>(
        &mut self,
        cx: &mut Context<'_>,
        reader: Pin<&mut R>,
        made_progress: &mut bool,
    ) -> Poll<io::Result<()>>
    where
        R: AsyncRead + ?Sized,
    {
        let mut buf = ReadBuf::new(&mut self.buf);
        buf.set_filled(self.cap);

        let res = reader.poll_read(cx, &mut buf);
        if let Poll::Ready(Ok(())) = res {
            let filled_len = buf.filled().len();
            self.read_done = self.cap == filled_len;
            *made_progress |= self.cap != filled_len;
            self.cap = filled_len;
        }
        res
    }

    fn poll_write_buf<R, W>(
        &mut self,
        cx: &mut Context<'_>,
        mut reader: Pin<&mut R>,
        mut writer: Pin<&mut W>,
        made_progress: &mut bool,
        ops_remaining: &mut usize,
    ) -> Poll<io::Result<usize>>
    where
        R: AsyncRead + ?Sized,
        W: AsyncWrite + ?Sized,
    {
        match writer
            .as_mut()
            .poll_write(cx, &self.buf[self.pos..self.cap])
        {
            Poll::Pending => {
                if !self.read_done && self.cap < self.buf.len() {
                    ready!(self.poll_fill_buf(cx, reader.as_mut(), made_progress))?;
                    ready!(consume_copy_budget(cx, ops_remaining));
                }
                Poll::Pending
            }
            Poll::Ready(Ok(len)) => {
                *made_progress |= len > 0;
                Poll::Ready(Ok(len))
            }
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
        }
    }

    fn poll_copy<R, W>(
        &mut self,
        cx: &mut Context<'_>,
        mut reader: Pin<&mut R>,
        mut writer: Pin<&mut W>,
        made_progress: &mut bool,
        ops_remaining: &mut usize,
    ) -> Poll<io::Result<u64>>
    where
        R: AsyncRead + ?Sized,
        W: AsyncWrite + ?Sized,
    {
        loop {
            if self.cap < self.buf.len() && !self.read_done {
                match self.poll_fill_buf(cx, reader.as_mut(), made_progress) {
                    Poll::Ready(Ok(())) => {
                        ready!(consume_copy_budget(cx, ops_remaining));
                    }
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                    Poll::Pending => {
                        if self.pos == self.cap {
                            if self.need_flush {
                                ready!(writer.as_mut().poll_flush(cx))?;
                                *made_progress = true;
                                self.need_flush = false;
                                ready!(consume_copy_budget(cx, ops_remaining));
                            }

                            return Poll::Pending;
                        }
                    }
                }
            }

            while self.pos < self.cap {
                let len = ready!(self.poll_write_buf(
                    cx,
                    reader.as_mut(),
                    writer.as_mut(),
                    made_progress,
                    ops_remaining
                ))?;
                if len == 0 {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "write zero byte into writer",
                    )));
                }

                self.pos += len;
                self.amt += len as u64;
                self.need_flush = true;
                ready!(consume_copy_budget(cx, ops_remaining));
            }

            debug_assert!(
                self.pos <= self.cap,
                "writer returned length larger than input slice"
            );

            self.pos = 0;
            self.cap = 0;

            if self.read_done {
                ready!(writer.as_mut().poll_flush(cx))?;
                *made_progress = true;
                return Poll::Ready(Ok(self.amt));
            }
        }
    }
}

enum TransferState {
    Running(CopyBuffer),
    ShuttingDown(u64),
    Done(u64),
}

fn timeout_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        "bidirectional copy idle timeout elapsed",
    )
}

fn invalid_buffer_size_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "copy buffer size must be greater than zero",
    )
}

fn consume_copy_budget(cx: &mut Context<'_>, ops_remaining: &mut usize) -> Poll<()> {
    debug_assert!(*ops_remaining > 0);
    *ops_remaining -= 1;

    if *ops_remaining == 0 {
        cx.waker().wake_by_ref();
        Poll::Pending
    } else {
        Poll::Ready(())
    }
}

fn transfer_one_direction<A, B>(
    cx: &mut Context<'_>,
    state: &mut TransferState,
    r: &mut A,
    w: &mut B,
    made_progress: &mut bool,
    ops_remaining: &mut usize,
) -> Poll<io::Result<u64>>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    let mut r = Pin::new(r);
    let mut w = Pin::new(w);

    loop {
        match state {
            TransferState::Running(buf) => {
                let count = ready!(buf.poll_copy(
                    cx,
                    r.as_mut(),
                    w.as_mut(),
                    made_progress,
                    ops_remaining
                ))?;
                *state = TransferState::ShuttingDown(count);
            }
            TransferState::ShuttingDown(count) => {
                ready!(w.as_mut().poll_shutdown(cx))?;
                *made_progress = true;
                *state = TransferState::Done(*count);
            }
            TransferState::Done(count) => return Poll::Ready(Ok(*count)),
        }
    }
}

/// Copies data between two streams until EOF, error, or idle timeout.
///
/// This follows `tokio::io::copy_bidirectional` transfer semantics. The
/// timeout is an idle timeout, not a total deadline, and is reset whenever
/// either direction makes IO progress.
pub async fn copy_bidirectional_with_timeout<A, B>(
    a: &mut A,
    b: &mut B,
    timeout: Duration,
) -> io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    copy_bidirectional_with_timeout_and_sizes(
        a,
        b,
        timeout,
        DEFAULT_COPY_BUF_SIZE,
        DEFAULT_COPY_BUF_SIZE,
    )
    .await
}

pub async fn copy_bidirectional_with_timeout_and_sizes<A, B>(
    a: &mut A,
    b: &mut B,
    timeout: Duration,
    a_to_b_buf_size: usize,
    b_to_a_buf_size: usize,
) -> io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    if timeout.is_zero() {
        return Err(timeout_error());
    }
    if a_to_b_buf_size == 0 || b_to_a_buf_size == 0 {
        return Err(invalid_buffer_size_error());
    }

    let mut a_to_b = TransferState::Running(CopyBuffer::new(a_to_b_buf_size));
    let mut b_to_a = TransferState::Running(CopyBuffer::new(b_to_a_buf_size));
    let idle_timer = time::sleep(timeout);
    tokio::pin!(idle_timer);

    poll_fn(|cx| {
        if Pin::new(&mut idle_timer).poll(cx).is_ready() {
            return Poll::Ready(Err(timeout_error()));
        }

        let mut made_progress = false;
        let mut a_to_b_ops = MAX_COPY_OPS_PER_POLL;
        let mut b_to_a_ops = MAX_COPY_OPS_PER_POLL;
        let a_to_b_ret =
            transfer_one_direction(cx, &mut a_to_b, a, b, &mut made_progress, &mut a_to_b_ops)?;
        let b_to_a_ret =
            transfer_one_direction(cx, &mut b_to_a, b, a, &mut made_progress, &mut b_to_a_ops)?;

        if made_progress {
            idle_timer.as_mut().reset(Instant::now() + timeout);
        }

        if let (Poll::Ready(a_to_b_ret), Poll::Ready(b_to_a_ret)) = (a_to_b_ret, b_to_a_ret) {
            return Poll::Ready(Ok((a_to_b_ret, b_to_a_ret)));
        }

        Poll::Pending
    })
    .await
}

pub async fn copy_bidirectional_with_idle_timeout<A, B>(
    a: &mut A,
    b: &mut B,
    timeout: Duration,
) -> io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    copy_bidirectional_with_timeout(a, b, timeout).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    struct AlwaysReadyIo;

    impl AsyncRead for AlwaysReadyIo {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if buf.remaining() > 0 {
                buf.put_slice(b"x");
            }
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for AlwaysReadyIo {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn idle_connection_times_out() {
        let (_client, mut proxy_client) = tokio::io::duplex(64);
        let (mut proxy_server, _server) = tokio::io::duplex(64);
        let err = copy_bidirectional_with_timeout(
            &mut proxy_client,
            &mut proxy_server,
            Duration::from_millis(20),
        )
        .await
        .unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn active_one_way_transfer_resets_idle_timeout() {
        let (mut client, mut proxy_client) = tokio::io::duplex(64);
        let (mut proxy_server, mut server) = tokio::io::duplex(64);

        let handle = tokio::spawn(async move {
            copy_bidirectional_with_timeout(
                &mut proxy_client,
                &mut proxy_server,
                Duration::from_millis(80),
            )
            .await
        });

        client.write_all(b"hello").await.unwrap();
        time::sleep(Duration::from_millis(30)).await;
        client.write_all(b"world").await.unwrap();
        client.shutdown().await.unwrap();

        let mut out = Vec::new();
        server.read_to_end(&mut out).await.unwrap();
        server.shutdown().await.unwrap();

        let (a_to_b, b_to_a) = handle.await.unwrap().unwrap();
        assert_eq!(out, b"helloworld");
        assert_eq!(a_to_b, 10);
        assert_eq!(b_to_a, 0);
    }

    #[tokio::test]
    async fn zero_buffer_size_is_rejected() {
        let (_client, mut proxy_client) = tokio::io::duplex(64);
        let (mut proxy_server, _server) = tokio::io::duplex(64);
        let err = copy_bidirectional_with_timeout_and_sizes(
            &mut proxy_client,
            &mut proxy_server,
            Duration::from_secs(1),
            0,
            DEFAULT_COPY_BUF_SIZE,
        )
        .await
        .unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);

        let (_client, mut proxy_client) = tokio::io::duplex(64);
        let (mut proxy_server, _server) = tokio::io::duplex(64);
        let err = copy_bidirectional_with_timeout_and_sizes(
            &mut proxy_client,
            &mut proxy_server,
            Duration::from_secs(1),
            DEFAULT_COPY_BUF_SIZE,
            0,
        )
        .await
        .unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[tokio::test]
    async fn always_ready_io_yields_to_runtime() {
        let mut a = AlwaysReadyIo;
        let mut b = AlwaysReadyIo;
        let result = time::timeout(
            Duration::from_millis(50),
            copy_bidirectional_with_timeout_and_sizes(
                &mut a,
                &mut b,
                Duration::from_secs(60),
                1,
                1,
            ),
        )
        .await;

        assert!(result.is_err());
    }
}
