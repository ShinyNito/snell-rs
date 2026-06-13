use std::collections::VecDeque;
use std::future::poll_fn;
use std::io::IoSlice;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use bytes::{Buf, Bytes};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::error::Result;
use crate::session::reuse::{ReuseClientReader, ReuseClientWriter};
use crate::session::tcp::{TcpClientWriter, TcpReader};

const PLAIN_UPLOAD_COALESCE_LIMIT: usize = 256 * 1024;
const PLAIN_UPLOAD_COALESCE_MAX_SLICES: usize = 128;

pub(crate) trait PlainPayloadSource {
    fn poll_take_payload_chunk(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<Bytes>>>;
}

impl<R> PlainPayloadSource for TcpReader<R>
where
    R: AsyncRead + Unpin,
{
    fn poll_take_payload_chunk(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<Bytes>>> {
        TcpReader::poll_take_payload_chunk(self, cx)
    }
}

impl<R> PlainPayloadSource for ReuseClientReader<R>
where
    R: AsyncRead + Unpin,
{
    fn poll_take_payload_chunk(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<Bytes>>> {
        ReuseClientReader::poll_take_payload_chunk(self, cx)
    }
}

pub(crate) struct PlainUploadBatch {
    chunks: VecDeque<Bytes>,
    len: usize,
}

impl PlainUploadBatch {
    pub(crate) fn new() -> Self {
        Self {
            chunks: VecDeque::new(),
            len: 0,
        }
    }

    pub(crate) fn push(&mut self, payload: Bytes) {
        if payload.is_empty() {
            return;
        }
        self.len += payload.len();
        self.chunks.push_back(payload);
    }

    pub(crate) fn len(&self) -> usize {
        self.len
    }

    fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn poll_write_to<W>(&mut self, plain: &mut W, cx: &mut Context<'_>) -> Poll<Result<usize>>
    where
        W: AsyncWrite + Unpin,
    {
        let mut slices: [IoSlice<'_>; PLAIN_UPLOAD_COALESCE_MAX_SLICES] =
            std::array::from_fn(|_| IoSlice::new(&[]));
        let mut slice_count = 0;
        for chunk in self.chunks.iter().take(PLAIN_UPLOAD_COALESCE_MAX_SLICES) {
            slices[slice_count] = IoSlice::new(chunk);
            slice_count += 1;
        }

        match Pin::new(plain).poll_write_vectored(cx, &slices[..slice_count]) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(n)) => Poll::Ready(Ok(n)),
            Poll::Ready(Err(err)) => Poll::Ready(Err(err.into())),
        }
    }

    fn advance(&mut self, mut n: usize) {
        while n > 0 {
            let Some(front) = self.chunks.front_mut() else {
                debug_assert_eq!(self.len, 0);
                return;
            };

            if n < front.len() {
                front.advance(n);
                self.len -= n;
                return;
            }

            let front_len = front.len();
            n -= front_len;
            self.len -= front_len;
            self.chunks.pop_front();
        }
    }
}

macro_rules! define_plain_to_snell_writer_relay {
    ($fn_name:ident, $writer:ident) => {
        pub(crate) async fn $fn_name<R, W>(plain: &mut R, snell: &mut $writer<W>) -> Result<u64>
        where
            R: AsyncRead + Unpin,
            W: AsyncWrite + Unpin,
        {
            let mut total = 0;

            loop {
                match snell.write_payload_message_from_reader(plain).await? {
                    Some(n) => total += n as u64,
                    None => {
                        snell.close_write().await?;
                        return Ok(total);
                    }
                }
            }
        }
    };
}

pub(crate) async fn relay_tcp_reader_to_plain<S, W>(
    snell: &mut S,
    plain: &mut W,
    total: &mut u64,
    initial_payload: PlainUploadBatch,
) -> Result<()>
where
    S: PlainPayloadSource,
    W: AsyncWrite + Unpin,
{
    let mut buffered = initial_payload;

    loop {
        match poll_fn(|cx| poll_coalesce_plain_upload(snell, &mut buffered, cx)).await? {
            PlainUploadPoll::Flush => {
                flush_plain_upload(plain, total, &mut buffered).await?;
            }
            PlainUploadPoll::Done => {
                flush_plain_upload(plain, total, &mut buffered).await?;
                plain.shutdown().await?;
                return Ok(());
            }
        }
    }
}

enum PlainUploadPoll {
    Flush,
    Done,
}

fn poll_coalesce_plain_upload<S>(
    snell: &mut S,
    buffered: &mut PlainUploadBatch,
    cx: &mut Context<'_>,
) -> Poll<Result<PlainUploadPoll>>
where
    S: PlainPayloadSource,
{
    loop {
        if buffered.len() >= PLAIN_UPLOAD_COALESCE_LIMIT {
            return Poll::Ready(Ok(PlainUploadPoll::Flush));
        }

        match snell.poll_take_payload_chunk(cx) {
            Poll::Pending if buffered.is_empty() => return Poll::Pending,
            Poll::Pending => return Poll::Ready(Ok(PlainUploadPoll::Flush)),
            Poll::Ready(Ok(Some(payload))) => {
                buffered.push(payload);
            }
            Poll::Ready(Ok(None)) => return Poll::Ready(Ok(PlainUploadPoll::Done)),
            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
        }
    }
}

async fn flush_plain_upload<W>(
    plain: &mut W,
    total: &mut u64,
    buffered: &mut PlainUploadBatch,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    poll_fn(|cx| {
        while !buffered.is_empty() {
            let n = ready!(buffered.poll_write_to(plain, cx))?;
            if n == 0 {
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "failed to write coalesced plain payload",
                )
                .into()));
            }
            buffered.advance(n);
            *total += n as u64;
        }
        Poll::Ready(Ok(()))
    })
    .await
}

define_plain_to_snell_writer_relay!(relay_plain_to_client_writer, TcpClientWriter);
define_plain_to_snell_writer_relay!(relay_plain_to_reuse_client_writer, ReuseClientWriter);
