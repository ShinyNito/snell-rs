use super::*;

pub struct V6StreamWriter<W> {
    inner: W,
    encoder: V6FrameEncoder,
    chunk_sizer: V6ChunkSizer,
    head: BytesMut,
    payload: BytesMut,
    wire: BytesMut,
}

impl<W> V6StreamWriter<W>
where
    W: AsyncWrite + Unpin,
{
    pub fn new(inner: W, psk: &[u8]) -> Result<Self> {
        let encoder = V6FrameEncoder::new(psk)?;
        Ok(Self::from_parts(inner, encoder))
    }

    #[cfg(test)]
    pub(crate) fn new_with_salt(inner: W, psk: &[u8], salt: [u8; SALT_SIZE]) -> Result<Self> {
        let encoder = V6FrameEncoder::with_salt(psk, salt)?;
        Ok(Self::from_parts(inner, encoder))
    }

    fn from_parts(inner: W, encoder: V6FrameEncoder) -> Self {
        let chunk_sizer = V6ChunkSizer::new(encoder.profile().clone());
        Self {
            inner,
            encoder,
            chunk_sizer,
            head: BytesMut::with_capacity(FRAME_HEAD_INITIAL_CAPACITY),
            payload: BytesMut::with_capacity(STREAM_BUFFER_INITIAL_CAPACITY),
            wire: BytesMut::with_capacity(STREAM_BUFFER_INITIAL_CAPACITY),
        }
    }

    async fn write_empty_frame(&mut self) -> Result<()> {
        self.head.clear();
        self.payload.clear();
        self.encoder.encode_empty_frame(&mut self.head)?;
        let Self { inner, head, .. } = self;
        write_all_vectored(inner, head, &[]).await?;
        Ok(())
    }

    async fn write_payload_buffer(&mut self, payload_len: usize) -> Result<usize> {
        self.head.clear();
        let wire_len =
            self.encoder
                .encode_payload_in_place(&mut self.payload, payload_len, &mut self.head)?;
        let Self {
            inner,
            head,
            payload,
            chunk_sizer,
            ..
        } = self;
        write_all_vectored(inner, head, payload).await?;
        if payload_len != 0 {
            chunk_sizer.commit_record(Instant::now());
        }
        Ok(wire_len)
    }

    pub async fn write_payload_message_from_buffer(
        &mut self,
        plain: &mut BytesMut,
    ) -> Result<Option<usize>> {
        self.write_message_from_buffer(plain, &[]).await
    }

    pub async fn write_tunnel_reply_message_from_buffer(
        &mut self,
        plain: &mut BytesMut,
    ) -> Result<Option<usize>> {
        self.write_message_from_buffer(plain, &[COMMAND_TUNNEL])
            .await
    }

    async fn write_message_from_buffer(
        &mut self,
        plain: &mut BytesMut,
        first_record_prefix: &[u8],
    ) -> Result<Option<usize>> {
        let written = encode_payload_message_from_buffer(self, plain, first_record_prefix)?;
        if written.is_none() {
            return Ok(None);
        }
        let Self { inner, wire, .. } = self;
        write_all_contiguous(inner, wire).await?;
        Ok(written)
    }

    pub async fn write_tcp_request(&mut self, host: &str, port: u16, reuse: bool) -> Result<()> {
        self.payload.clear();
        write_tcp_request_header(
            &mut self.payload,
            host,
            port,
            crate::ProtocolVersion::V6,
            reuse,
        )?;
        self.write_control_payload().await
    }

    pub async fn write_udp_request(&mut self) -> Result<()> {
        self.payload.clear();
        write_udp_request_header(&mut self.payload, crate::ProtocolVersion::V6)?;
        self.write_control_payload().await
    }

    pub async fn write_empty_tunnel_reply(&mut self) -> Result<()> {
        self.payload.clear();
        write_tunnel_reply(&mut self.payload, &[]);
        self.write_payload_buffer(self.payload.len()).await?;
        Ok(())
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

    pub async fn write_zero_chunk(&mut self) -> Result<()> {
        self.write_empty_frame().await?;
        Ok(())
    }

    pub async fn shutdown(&mut self) -> Result<()> {
        self.inner.shutdown().await?;
        Ok(())
    }

    pub(crate) fn compact_buffers_for_reuse(&mut self) {
        compact_stream_buffer_for_reuse(&mut self.payload);
        compact_stream_buffer_for_reuse(&mut self.wire);
        self.head.clear();
        if self.head.capacity() > STREAM_BUFFER_RETAIN_CAPACITY {
            self.head = BytesMut::with_capacity(FRAME_HEAD_INITIAL_CAPACITY);
        }
    }

    #[cfg(test)]
    pub(crate) fn has_committed_chunk_record(&self) -> bool {
        self.chunk_sizer.has_committed_record()
    }

    async fn write_control_payload(&mut self) -> Result<()> {
        let payload_len = self.payload.len();
        let wire_len = self.write_payload_buffer(payload_len).await?;
        tracing::trace!(payload_len, wire_len, "wrote snell v6 request frame");
        Ok(())
    }
}

impl<W> MessageRecordEncoder for V6StreamWriter<W> {
    fn clear_wire(&mut self) {
        self.wire.clear();
    }

    fn peek_record_limit(&mut self, now: Instant) -> usize {
        self.chunk_sizer.peek_limit(self.encoder.seq(), now)
    }

    fn commit_record_limit(&mut self, now: Instant, _limit: usize) {
        self.chunk_sizer.commit_record(now);
    }

    fn encode_record_into(&mut self, prefix: &[u8], payload: &[u8]) -> Result<usize> {
        self.encoder
            .encode_payload_parts_into(prefix, payload, &mut self.wire)
    }
}
