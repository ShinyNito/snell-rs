use super::{
    AsyncWrite, BytesMut, COMMAND_TUNNEL, Context, Error, FRAME_HEAD_INITIAL_CAPACITY, Instant,
    PAYLOAD_WRITE_BATCH_MAX_RECORDS, PayloadSource, PayloadWriteStatus, PendingPayloadBatch, Pin,
    Poll, Result, STREAM_BUFFER_INITIAL_CAPACITY, STREAM_BUFFER_RETAIN_CAPACITY, SnellPsk,
    V6ChunkSizer, V6FrameEncoder, compact_stream_buffer_for_reuse, poll_fn,
    poll_write_all_vectored, ready, write_all_vectored, write_error_reply, write_pong_reply,
    write_tcp_request_header, write_tunnel_reply, write_udp_request_header,
};

#[cfg(test)]
use super::SALT_SIZE;

pub struct V6StreamWriter<W> {
    inner: W,
    secret: SnellPsk,
    encoder: V6FrameEncoder,
    chunk_sizer: V6ChunkSizer,
    head: BytesMut,
    payload: BytesMut,
    source_batch: PendingPayloadBatch,
    buffer_batch: PendingPayloadBatch,
    pending_source_error: Option<Error>,
    buffer_written: usize,
    pending_frame_write: bool,
}

impl<W> V6StreamWriter<W>
where
    W: AsyncWrite + Unpin,
{
    pub fn new(inner: W, secret: &SnellPsk) -> Result<Self> {
        let encoder = V6FrameEncoder::new(secret.as_bytes())?;
        Ok(Self::from_parts(inner, secret.clone(), encoder))
    }

    #[cfg(test)]
    pub(crate) fn new_with_salt(
        inner: W,
        secret: &SnellPsk,
        salt: [u8; SALT_SIZE],
    ) -> Result<Self> {
        let encoder = V6FrameEncoder::with_salt(secret.as_bytes(), salt)?;
        Ok(Self::from_parts(inner, secret.clone(), encoder))
    }

    fn from_parts(inner: W, secret: SnellPsk, encoder: V6FrameEncoder) -> Self {
        Self {
            inner,
            secret,
            encoder,
            chunk_sizer: V6ChunkSizer::new(),
            head: BytesMut::with_capacity(FRAME_HEAD_INITIAL_CAPACITY),
            payload: BytesMut::with_capacity(STREAM_BUFFER_INITIAL_CAPACITY),
            source_batch: PendingPayloadBatch::new(),
            buffer_batch: PendingPayloadBatch::new(),
            pending_source_error: None,
            buffer_written: 0,
            pending_frame_write: false,
        }
    }

    async fn write_payload_buffer(&mut self, payload_len: usize) -> Result<usize> {
        self.head.clear();
        let wire_len = self.encoder.encode_payload_in_place(
            self.secret.v6_profile(),
            &mut self.payload,
            payload_len,
            &mut self.head,
        )?;
        let Self {
            inner,
            secret,
            head,
            payload,
            chunk_sizer,
            ..
        } = self;
        write_all_vectored(inner, head, payload).await?;
        if payload_len != 0 {
            chunk_sizer.commit_record(secret.v6_profile(), Instant::now());
        }
        Ok(wire_len)
    }

    pub(in crate::framed) fn poll_write_payload_from_buffer(
        &mut self,
        plain: &mut BytesMut,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<usize>>> {
        self.poll_write_from_buffer(plain, &[], cx)
    }

    pub(in crate::framed) fn poll_write_tunnel_reply_from_buffer(
        &mut self,
        plain: &mut BytesMut,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<usize>>> {
        self.poll_write_from_buffer(plain, &[COMMAND_TUNNEL], cx)
    }

    pub(in crate::framed) const fn has_pending_message_write(&self) -> bool {
        !self.source_batch.is_empty() || !self.buffer_batch.is_empty()
    }

    pub(in crate::framed) fn poll_write_payload_from_source<R>(
        &mut self,
        reader: Pin<&mut R>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<PayloadWriteStatus>>
    where
        R: PayloadSource + ?Sized,
    {
        self.poll_write_from_source(reader, &[], cx)
    }

    pub(in crate::framed) fn poll_write_tunnel_reply_from_source<R>(
        &mut self,
        reader: Pin<&mut R>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<PayloadWriteStatus>>
    where
        R: PayloadSource + ?Sized,
    {
        self.poll_write_from_source(reader, &[COMMAND_TUNNEL], cx)
    }

    fn poll_write_from_buffer(
        &mut self,
        plain: &mut BytesMut,
        first_record_prefix: &[u8],
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<usize>>> {
        if plain.is_empty() && self.buffer_batch.is_empty() && self.buffer_written == 0 {
            return Poll::Ready(Ok(None));
        }

        loop {
            if self.buffer_batch.is_empty() {
                if plain.is_empty() {
                    let written = self.buffer_written;
                    self.buffer_written = 0;
                    return Poll::Ready(Ok(Some(written)));
                }

                while !plain.is_empty() && !self.buffer_batch.is_full() {
                    if let Err(err) = self.prepare_buffer_record(plain, first_record_prefix) {
                        self.buffer_batch.discard();
                        self.buffer_written = 0;
                        return Poll::Ready(Err(err));
                    }
                }
            }

            ready!(self.buffer_batch.poll_write_all(&mut self.inner, cx))?;
            self.buffer_written += self.buffer_batch.finish_written();
        }
    }

    fn prepare_buffer_record(
        &mut self,
        plain: &mut BytesMut,
        first_record_prefix: &[u8],
    ) -> Result<()> {
        let prefix = if self.buffer_written == 0 && self.buffer_batch.is_empty() {
            first_record_prefix
        } else {
            &[]
        };
        let now = Instant::now();
        let limit = self
            .chunk_sizer
            .peek_limit(self.secret.v6_profile(), self.encoder.seq(), now);
        let Some(read_limit) = limit.checked_sub(prefix.len()).filter(|limit| *limit != 0) else {
            return Err(Error::PayloadTooLarge);
        };
        let read_len = plain.len().min(read_limit);

        let record = self.buffer_batch.begin_record();
        if prefix.is_empty() {
            record.payload = plain.split_to(read_len);
        } else {
            let chunk = plain.split_to(read_len);
            record.payload.reserve(prefix.len() + chunk.len());
            record.payload.extend_from_slice(prefix);
            record.payload.extend_from_slice(&chunk);
        }
        let payload_len = prefix.len() + read_len;
        self.encoder.encode_payload_in_place(
            self.secret.v6_profile(),
            &mut record.payload,
            payload_len,
            &mut record.head,
        )?;
        self.chunk_sizer
            .commit_record(self.secret.v6_profile(), now);
        self.buffer_batch.commit_record(read_len);
        Ok(())
    }

    fn poll_write_from_source<R>(
        &mut self,
        mut reader: Pin<&mut R>,
        first_record_prefix: &[u8],
        cx: &mut Context<'_>,
    ) -> Poll<Result<PayloadWriteStatus>>
    where
        R: PayloadSource + ?Sized,
    {
        if self.source_batch.is_empty() {
            if let Some(err) = self.pending_source_error.take() {
                return Poll::Ready(Err(err));
            }

            if ready!(self.prepare_source_batch(reader.as_mut(), first_record_prefix, cx))? == 0 {
                return Poll::Ready(Ok(PayloadWriteStatus::SourceEof));
            }
        }

        ready!(self.source_batch.poll_write_all(&mut self.inner, cx))?;
        let plain_len = self.source_batch.finish_written();
        Poll::Ready(Ok(PayloadWriteStatus::Written(plain_len)))
    }

    fn prepare_source_batch<R>(
        &mut self,
        mut reader: Pin<&mut R>,
        first_record_prefix: &[u8],
        cx: &mut Context<'_>,
    ) -> Poll<Result<usize>>
    where
        R: PayloadSource + ?Sized,
    {
        let now = Instant::now();
        let profile = self.secret.v6_profile().clone();
        let mut chunk_sizer = self.chunk_sizer.clone();
        let mut seq = self.encoder.seq();
        let mut iovecs: [libc::iovec; PAYLOAD_WRITE_BATCH_MAX_RECORDS] =
            std::array::from_fn(|_| libc::iovec {
                iov_base: std::ptr::null_mut(),
                iov_len: 0,
            });
        let mut read_limits = [0; PAYLOAD_WRITE_BATCH_MAX_RECORDS];
        let mut record_count = 0;
        let mut planned_read_len = 0;

        while !self.source_batch.is_full() && planned_read_len < PendingPayloadBatch::target_bytes()
        {
            let prefix = if self.source_batch.active_len() == 0 {
                first_record_prefix
            } else {
                &[]
            };
            let limit = chunk_sizer.peek_limit(&profile, seq, now);
            let Some(read_limit) = limit.checked_sub(prefix.len()).filter(|limit| *limit != 0)
            else {
                self.source_batch.discard();
                return Poll::Ready(Err(Error::PayloadTooLarge));
            };

            let record = self.source_batch.begin_source_record();
            iovecs[record_count] = record.prepare_spare(prefix, read_limit);
            read_limits[record_count] = read_limit;
            record_count += 1;
            planned_read_len += read_limit;
            chunk_sizer.commit_record(&profile, now);
            seq = seq.wrapping_add(1);
        }

        let read_total = match reader
            .as_mut()
            .poll_read_payload_into_slots(cx, &mut iovecs[..record_count])
        {
            Poll::Ready(Ok(read_total)) => read_total,
            Poll::Ready(Err(err)) => {
                self.source_batch.discard();
                return Poll::Ready(Err(err.into()));
            }
            Poll::Pending => {
                self.source_batch.discard();
                return Poll::Pending;
            }
        };
        if read_total == 0 {
            self.source_batch.discard();
            return Poll::Ready(Ok(0));
        }

        let mut remaining = read_total;
        let mut committed_records = 0;
        for (index, read_limit) in read_limits.iter().copied().enumerate().take(record_count) {
            let read_len = remaining.min(read_limit);
            if read_len == 0 {
                break;
            }
            let payload_len = {
                let record = self.source_batch.source_record(index);
                record.finish_read(read_len)
            };
            let record = self.source_batch.source_record(index);
            if let Err(err) = self.encoder.encode_payload_in_place(
                &profile,
                &mut record.payload,
                payload_len,
                &mut record.head,
            ) {
                self.source_batch.discard();
                return Poll::Ready(Err(err));
            }
            self.chunk_sizer.commit_record(&profile, now);
            self.source_batch.finish_source_record(index, read_len);
            remaining -= read_len;
            committed_records += 1;
        }
        debug_assert_eq!(remaining, 0);
        self.source_batch.truncate_active(committed_records);
        Poll::Ready(Ok(read_total))
    }

    pub(in crate::framed) fn poll_write_tcp_request(
        &mut self,
        host: &str,
        port: u16,
        reuse: bool,
        cx: &mut Context<'_>,
    ) -> Poll<Result<()>> {
        if !self.pending_frame_write {
            self.payload.clear();
            write_tcp_request_header(
                &mut self.payload,
                host,
                port,
                crate::ProtocolVersion::V6,
                reuse,
            )?;
        }
        self.poll_write_control_payload(cx)
    }

    pub async fn write_udp_request(&mut self) -> Result<()> {
        self.payload.clear();
        write_udp_request_header(&mut self.payload, crate::ProtocolVersion::V6)?;
        self.write_control_payload().await
    }

    pub async fn write_empty_tunnel_reply(&mut self) -> Result<()> {
        poll_fn(|cx| self.poll_write_empty_tunnel_reply(cx)).await
    }

    pub(in crate::framed) fn poll_write_empty_tunnel_reply(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<()>> {
        if !self.pending_frame_write {
            self.payload.clear();
            write_tunnel_reply(&mut self.payload, &[]);
            self.head.clear();
            let payload_len = self.payload.len();
            self.encoder.encode_payload_in_place(
                self.secret.v6_profile(),
                &mut self.payload,
                payload_len,
                &mut self.head,
            )?;
            self.pending_frame_write = true;
        }
        ready!(poll_write_all_vectored(
            &mut self.inner,
            cx,
            &mut self.head,
            &mut self.payload
        ))?;
        self.chunk_sizer
            .commit_record(self.secret.v6_profile(), Instant::now());
        self.pending_frame_write = false;
        self.head.clear();
        self.payload.clear();
        Poll::Ready(Ok(()))
    }

    pub async fn write_pong_reply(&mut self) -> Result<()> {
        self.payload.clear();
        write_pong_reply(&mut self.payload);
        self.write_control_payload().await
    }

    pub async fn write_error_reply(&mut self, code: u8, message: &str) -> Result<()> {
        self.payload.clear();
        write_error_reply(&mut self.payload, code, message);
        self.write_control_payload().await
    }

    pub(in crate::framed) fn poll_write_zero_chunk(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<()>> {
        if !self.pending_frame_write {
            self.head.clear();
            self.payload.clear();
            self.encoder
                .encode_empty_frame(self.secret.v6_profile(), &mut self.head)?;
            self.pending_frame_write = true;
        }
        ready!(poll_write_all_vectored(
            &mut self.inner,
            cx,
            &mut self.head,
            &mut self.payload
        ))?;
        self.pending_frame_write = false;
        self.head.clear();
        self.payload.clear();
        Poll::Ready(Ok(()))
    }

    pub(in crate::framed) fn poll_flush(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>> {
        ready!(Pin::new(&mut self.inner).poll_flush(cx))?;
        Poll::Ready(Ok(()))
    }

    pub(crate) fn compact_buffers_for_reuse(&mut self) {
        compact_stream_buffer_for_reuse(&mut self.payload);
        self.source_batch.compact_for_reuse();
        self.buffer_batch.compact_for_reuse();
        self.pending_source_error = None;
        self.buffer_written = 0;
        self.pending_frame_write = false;
        self.head.clear();
        if self.head.capacity() > STREAM_BUFFER_RETAIN_CAPACITY {
            self.head = BytesMut::with_capacity(FRAME_HEAD_INITIAL_CAPACITY);
        }
    }

    #[cfg(test)]
    pub(crate) const fn has_committed_chunk_record(&self) -> bool {
        self.chunk_sizer.has_committed_record()
    }

    async fn write_control_payload(&mut self) -> Result<()> {
        let payload_len = self.payload.len();
        let wire_len = self.write_payload_buffer(payload_len).await?;
        tracing::trace!(payload_len, wire_len, "wrote snell v6 request frame");
        Ok(())
    }

    fn poll_write_control_payload(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>> {
        if !self.pending_frame_write {
            self.head.clear();
            let payload_len = self.payload.len();
            self.encoder.encode_payload_in_place(
                self.secret.v6_profile(),
                &mut self.payload,
                payload_len,
                &mut self.head,
            )?;
            self.pending_frame_write = true;
        }
        ready!(poll_write_all_vectored(
            &mut self.inner,
            cx,
            &mut self.head,
            &mut self.payload
        ))?;
        self.chunk_sizer
            .commit_record(self.secret.v6_profile(), Instant::now());
        self.pending_frame_write = false;
        self.head.clear();
        self.payload.clear();
        Poll::Ready(Ok(()))
    }
}
