#![allow(unused)]

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex;
use std::task::{Context, Poll};

pub struct ReadHalf<T> {
    inner: Arc<Inner<T>>,
}

pub struct WriteHalf<T> {
    inner: Arc<Inner<T>>,
}

pub fn split<T>(stream: T) -> (ReadHalf<T>, WriteHalf<T>)
{
    let inner = Arc::new(Inner {
        stream: Mutex::new(stream),
    });

    let rd = ReadHalf {
        inner: inner.clone(),
    };

    let wr = WriteHalf { inner };

    (rd, wr)
}

struct Inner<T> {
    stream: Mutex<T>,
}

impl<T> Inner<T> {
    fn with_lock<R>(&self, f: impl FnOnce(Pin<&mut T>) -> R) -> R {
        let mut guard = self.stream.lock().unwrap();

        let stream = unsafe { Pin::new_unchecked(&mut *guard) };

        f(stream)
    }
}

impl<T> ReadHalf<T> {
    pub fn with_lock<R>(&self, f: impl FnOnce(Pin<&mut T>) -> R) -> R {
        self.inner.with_lock(f)
    }

    pub fn is_pair_of(&self, other: &WriteHalf<T>) -> bool {
        other.is_pair_of(self)
    }

    #[track_caller]
    pub fn unsplit(self, wr: WriteHalf<T>) -> T
    where
        T: Unpin,
    {
        if self.is_pair_of(&wr) {
            drop(wr);

            let inner = Arc::try_unwrap(self.inner)
                .ok()
                .expect("`Arc::try_unwrap` failed");

            inner.stream.into_inner().unwrap()
        } else {
            panic!("Unrelated `split::Write` passed to `split::Read::unsplit`.")
        }
    }
}

impl<T> WriteHalf<T> {
    pub fn with_lock<R>(&self, f: impl FnOnce(Pin<&mut T>) -> R) -> R {
        self.inner.with_lock(f)
    }

    pub fn is_pair_of(&self, other: &ReadHalf<T>) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }
}

impl<T: tokio::io::AsyncRead> tokio::io::AsyncRead for ReadHalf<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.inner.with_lock(|stream| stream.poll_read(cx, buf))
    }
}

impl<T: tokio::io::AsyncWrite> tokio::io::AsyncWrite for WriteHalf<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        self.inner.with_lock(|stream| stream.poll_write(cx, buf))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        self.inner.with_lock(|stream| stream.poll_flush(cx))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        self.inner.with_lock(|stream| stream.poll_shutdown(cx))
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<Result<usize, io::Error>> {
        self.inner
            .with_lock(|stream| stream.poll_write_vectored(cx, bufs))
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.with_lock(|stream| stream.is_write_vectored())
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    // 创建一个简单的模拟类型用于测试
    #[derive(Debug, PartialEq)]
    struct MockStream {
        id: usize,
        data: Vec<u8>,
    }

    impl MockStream {
        fn new(id: usize) -> Self {
            Self {
                id,
                data: vec![],
            }
        }
    }

    #[test]
    fn test_split_creates_paired_halves() {
        let stream = MockStream::new(1);
        let (read_half, write_half) = split(stream);

        // 验证两个半部分是配对的
        assert!(read_half.is_pair_of(&write_half));
        assert!(write_half.is_pair_of(&read_half));
    }

    #[test]
    fn test_halves_from_different_streams_are_not_paired() {
        let stream1 = MockStream::new(1);
        let stream2 = MockStream::new(2);

        let (read_half1, write_half1) = split(stream1);
        let (_read_half2, write_half2) = split(stream2);

        // 验证来自不同流的半部分不是配对的
        assert!(!read_half1.is_pair_of(&write_half2));
        assert!(!write_half2.is_pair_of(&read_half1));
    }

    #[test]
    #[should_panic(expected = "Unrelated `split::Write` passed to `split::Read::unsplit`.")]
    fn test_unsplit_panics_when_halves_are_not_paired() {
        let stream1 = MockStream::new(1);
        let stream2 = MockStream::new(2);

        let (read_half, _write_half) = split(stream1);
        let (_read_half2, write_half2) = split(stream2);

        // 尝试合并不配对的读写半部分应该panic
        let _ = read_half.unsplit(write_half2);
    }

    #[test]
    fn test_with_lock_functionality() {
        // 这个测试主要验证内部锁机制是否正常工作
        let stream = MockStream::new(1);
        let (read_half, write_half) = split(stream);

        // 验证我们可以通过读半部分访问内部流
        let read_inner_ptr = {
            let guard = read_half.inner.stream.lock().unwrap();
            &*guard as *const _ as usize
        };

        // 验证我们可以通过写半部分访问内部流
        let write_inner_ptr = {
            let guard = write_half.inner.stream.lock().unwrap();
            &*guard as *const _ as usize
        };

        // 验证两个半部分确实共享同一个内部流实例
        assert_eq!(read_inner_ptr, write_inner_ptr);
    }
}
