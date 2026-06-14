use super::{
    AsyncWrite, BytesMut, COMMAND_TUNNEL, Context, FRAME_HEAD_INITIAL_CAPACITY, Instant,
    MessageRecordEncoder, Pin, Poll, Result, STREAM_BUFFER_INITIAL_CAPACITY,
    STREAM_BUFFER_RETAIN_CAPACITY, SharedV6Profile, SnellPsk, V6ChunkSizer, V6FrameEncoder,
    compact_stream_buffer_for_reuse, encode_payload_message_from_buffer, poll_fn,
    poll_write_all_contiguous, poll_write_all_vectored, ready, write_all_vectored,
    write_error_reply, write_pong_reply, write_tcp_request_header, write_tunnel_reply,
    write_udp_request_header,
};

#[cfg(test)]
use super::SALT_SIZE;

pub struct V6StreamWriter<W> {
    inner: W,
    profile: SharedV6Profile,
    encoder: V6FrameEncoder,
    chunk_sizer: V6ChunkSizer,
    head: BytesMut,
    payload: BytesMut,
    wire: BytesMut,
    pending_message_written: Option<usize>,
    pending_frame_write: bool,
}

impl<W> V6StreamWriter<W>
where
    W: AsyncWrite + Unpin,
{
    pub fn new(inner: W, secret: &SnellPsk) -> Result<Self> {
        let encoder = V6FrameEncoder::new(secret.as_bytes())?;
        Ok(Self::from_parts(inner, secret.clone_v6_profile(), encoder))
    }

    #[cfg(test)]
    pub(crate) fn new_with_salt(
        inner: W,
        secret: &SnellPsk,
        salt: [u8; SALT_SIZE],
    ) -> Result<Self> {
        let encoder = V6FrameEncoder::with_salt(secret.as_bytes(), salt)?;
        Ok(Self::from_parts(inner, secret.clone_v6_profile(), encoder))
    }

    fn from_parts(inner: W, profile: SharedV6Profile, encoder: V6FrameEncoder) -> Self {
        Self {
            inner,
            profile,
            encoder,
            chunk_sizer: V6ChunkSizer::new(),
            head: BytesMut::with_capacity(FRAME_HEAD_INITIAL_CAPACITY),
            payload: BytesMut::with_capacity(STREAM_BUFFER_INITIAL_CAPACITY),
            wire: BytesMut::with_capacity(STREAM_BUFFER_INITIAL_CAPACITY),
            pending_message_written: None,
            pending_frame_write: false,
        }
    }

    async fn write_payload_buffer(&mut self, payload_len: usize) -> Result<usize> {
        self.head.clear();
        let wire_len = self.encoder.encode_payload_in_place(
            &self.profile,
            &mut self.payload,
            payload_len,
            &mut self.head,
        )?;
        let Self {
            inner,
            profile,
            head,
            payload,
            chunk_sizer,
            ..
        } = self;
        write_all_vectored(inner, head, payload).await?;
        if payload_len != 0 {
            chunk_sizer.commit_record(profile, Instant::now());
        }
        Ok(wire_len)
    }

    pub(in crate::framed) fn poll_write_payload_message_from_buffer(
        &mut self,
        plain: &mut BytesMut,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<usize>>> {
        self.poll_write_message_from_buffer(plain, &[], cx)
    }

    pub(in crate::framed) fn poll_write_tunnel_reply_message_from_buffer(
        &mut self,
        plain: &mut BytesMut,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<usize>>> {
        self.poll_write_message_from_buffer(plain, &[COMMAND_TUNNEL], cx)
    }

    pub(in crate::framed) const fn has_pending_message_write(&self) -> bool {
        self.pending_message_written.is_some()
    }

    fn poll_write_message_from_buffer(
        &mut self,
        plain: &mut BytesMut,
        first_record_prefix: &[u8],
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<usize>>> {
        if self.pending_message_written.is_none() {
            let Some(written) =
                encode_payload_message_from_buffer(self, plain, first_record_prefix)?
            else {
                return Poll::Ready(Ok(None));
            };
            self.pending_message_written = Some(written);
        }
        let Self { inner, wire, .. } = self;
        ready!(poll_write_all_contiguous(inner, cx, wire))?;
        Poll::Ready(Ok(self.pending_message_written.take()))
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
                &self.profile,
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
            .commit_record(&self.profile, Instant::now());
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
                .encode_empty_frame(&self.profile, &mut self.head)?;
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
        compact_stream_buffer_for_reuse(&mut self.wire);
        self.pending_message_written = None;
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
                &self.profile,
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
            .commit_record(&self.profile, Instant::now());
        self.pending_frame_write = false;
        self.head.clear();
        self.payload.clear();
        Poll::Ready(Ok(()))
    }
}

impl<W> MessageRecordEncoder for V6StreamWriter<W> {
    fn clear_wire(&mut self) {
        self.wire.clear();
    }

    fn peek_record_limit(&mut self, now: Instant) -> usize {
        self.chunk_sizer
            .peek_limit(&self.profile, self.encoder.seq(), now)
    }

    fn commit_record_limit(&mut self, now: Instant, _limit: usize) {
        self.chunk_sizer.commit_record(&self.profile, now);
    }

    fn encode_record_into(&mut self, prefix: &[u8], payload: &[u8]) -> Result<usize> {
        self.encoder
            .encode_payload_parts_into(&self.profile, prefix, payload, &mut self.wire)
    }
}
