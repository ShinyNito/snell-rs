use super::*;

pub struct V6StreamWriter<W> {
    inner: W,
    encoder: V6FrameEncoder,
    chunk_sizer: V6ChunkSizer,
    head: BytesMut,
    payload: BytesMut,
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
        }
    }

    #[cfg(test)]
    pub(crate) async fn write_test_frame(&mut self, payload: &[u8]) -> Result<usize> {
        if payload.is_empty() {
            self.write_empty_frame().await?;
            return Ok(0);
        }

        self.payload.clear();
        self.payload.extend_from_slice(payload);
        self.write_payload_buffer(payload.len(), false).await?;
        Ok(payload.len())
    }

    async fn write_empty_frame(&mut self) -> Result<()> {
        self.head.clear();
        self.payload.clear();
        self.encoder.encode_empty_frame(&mut self.head)?;
        let Self { inner, head, .. } = self;
        write_all_vectored(inner, head, &[]).await?;
        Ok(())
    }

    async fn write_payload_buffer(
        &mut self,
        payload_len: usize,
        advance_chunk_sizer: bool,
    ) -> Result<usize> {
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
        if advance_chunk_sizer && payload_len != 0 {
            chunk_sizer.commit_record(Instant::now());
        }
        Ok(wire_len)
    }

    pub async fn write_payload_from_reader<R>(&mut self, plain: &mut R) -> Result<Option<usize>>
    where
        R: AsyncRead + Unpin,
    {
        let Some(frame) = self.read_payload_frame_from_reader(plain, &[]).await? else {
            return Ok(None);
        };

        let wire_len = self.write_payload_buffer(frame.payload_len, false).await?;
        self.chunk_sizer.commit_record(Instant::now());
        tracing::trace!(
            payload_len = frame.read_len,
            wire_len,
            "wrote snell v6 payload frame"
        );
        Ok(Some(frame.read_len))
    }

    pub async fn write_tunnel_reply_from_reader<R>(
        &mut self,
        plain: &mut R,
    ) -> Result<Option<usize>>
    where
        R: AsyncRead + Unpin,
    {
        let prefix = [COMMAND_TUNNEL];

        let Some(frame) = self.read_payload_frame_from_reader(plain, &prefix).await? else {
            return Ok(None);
        };

        let wire_len = self.write_payload_buffer(frame.payload_len, false).await?;
        self.chunk_sizer.commit_record(Instant::now());
        tracing::trace!(
            payload_len = frame.read_len,
            wire_len,
            "wrote snell v6 tunnel payload frame"
        );
        Ok(Some(frame.read_len))
    }

    async fn read_payload_frame_from_reader<R>(
        &mut self,
        plain: &mut R,
        prefix: &[u8],
    ) -> Result<Option<ReaderPayloadFrame>>
    where
        R: AsyncRead + Unpin,
    {
        poll_fn(|cx| {
            let now = Instant::now();
            let limit = self.chunk_sizer.peek_limit(self.encoder.seq(), now);
            let prefix_len = prefix.len();
            let Some(read_limit) = limit.checked_sub(prefix_len).filter(|limit| *limit != 0) else {
                self.payload.clear();
                return Poll::Ready(Err(crate::error::Error::PayloadTooLarge));
            };

            self.payload.clear();
            self.payload
                .reserve(limit + crate::protocol::crypto::AEAD_TAG_SIZE);
            if !prefix.is_empty() {
                self.payload.extend_from_slice(prefix);
            }

            match poll_read_into_spare(plain, cx, &mut self.payload, read_limit) {
                Poll::Pending => {
                    self.payload.clear();
                    Poll::Pending
                }
                Poll::Ready(Ok(read_len)) => {
                    if read_len == 0 {
                        self.payload.clear();
                        return Poll::Ready(Ok(None));
                    }
                    Poll::Ready(Ok(Some(ReaderPayloadFrame {
                        payload_len: prefix_len + read_len,
                        read_len,
                        limit,
                    })))
                }
                Poll::Ready(Err(err)) => {
                    self.payload.clear();
                    Poll::Ready(Err(err))
                }
            }
        })
        .await
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
        self.write_control_scratch().await
    }

    pub async fn write_udp_request(&mut self) -> Result<()> {
        self.payload.clear();
        write_udp_request_header(&mut self.payload, crate::ProtocolVersion::V6)?;
        self.write_control_scratch().await
    }

    #[cfg(test)]
    pub(crate) async fn write_test_udp_packet(
        &mut self,
        address: AddressRef<'_>,
        port: u16,
        payload: &[u8],
    ) -> Result<usize> {
        self.payload.clear();
        write_udp_request_prefix(&mut self.payload, address, port)?;
        self.payload.extend_from_slice(payload);
        self.finish_udp_payload_message(self.payload.len()).await?;
        Ok(payload.len())
    }

    #[cfg(test)]
    pub(crate) async fn write_test_udp_response(
        &mut self,
        address: AddressRef<'_>,
        port: u16,
        payload: &[u8],
    ) -> Result<usize> {
        self.payload.clear();
        write_udp_response_prefix(&mut self.payload, address, port)?;
        self.payload.extend_from_slice(payload);
        self.finish_udp_payload_message(self.payload.len()).await?;
        Ok(payload.len())
    }

    pub(crate) async fn try_write_ipv4_udp_response_from_socket(
        &mut self,
        socket: &UdpSocket,
    ) -> Result<Option<(usize, SocketAddr)>> {
        self.try_write_udp_response_from_socket(socket, UdpResponseIpVersion::V4)
            .await
    }

    pub(crate) async fn try_write_ipv6_udp_response_from_socket(
        &mut self,
        socket: &UdpSocket,
    ) -> Result<Option<(usize, SocketAddr)>> {
        self.try_write_udp_response_from_socket(socket, UdpResponseIpVersion::V6)
            .await
    }

    pub(crate) fn start_payload_frame(&mut self) -> &mut BytesMut {
        self.payload.clear();
        &mut self.payload
    }

    pub(crate) async fn finish_udp_payload_message(&mut self, payload_len: usize) -> Result<usize> {
        if self.payload.len() != payload_len {
            return Err(Error::FrameLengthMismatch);
        }
        if payload_len > MAX_V6_RECORD_PAYLOAD_LEN {
            return Err(Error::PayloadTooLarge);
        }

        let mut payload = BytesMut::new();
        std::mem::swap(&mut self.payload, &mut payload);
        let mut written = 0;
        while !payload.is_empty() {
            let now = Instant::now();
            let limit = self.chunk_sizer.peek_limit(self.encoder.seq(), now);
            if limit == 0 {
                return Err(Error::PayloadTooLarge);
            }

            let chunk_len = payload.len().min(limit);
            let mut chunk = payload.split_to(chunk_len);
            std::mem::swap(&mut self.payload, &mut chunk);
            let wire_len = self.write_payload_buffer(chunk_len, false).await?;
            self.chunk_sizer.commit_record(now);
            self.payload.clear();
            written += chunk_len;
            tracing::trace!(
                payload_len = chunk_len,
                wire_len,
                "wrote snell v6 udp payload message chunk"
            );
        }
        Ok(written)
    }

    pub(crate) async fn write_owned_udp_payload_message(
        &mut self,
        mut payload: BytesMut,
    ) -> Result<usize> {
        let payload_len = payload.len();
        std::mem::swap(&mut self.payload, &mut payload);
        self.finish_udp_payload_message(payload_len).await
    }

    pub async fn write_empty_tunnel_reply(&mut self) -> Result<()> {
        self.payload.clear();
        write_tunnel_reply(&mut self.payload, &[]);
        self.write_payload_buffer(self.payload.len(), true).await?;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) async fn write_test_tunnel_reply(&mut self, payload: &[u8]) -> Result<usize> {
        self.payload.clear();
        write_tunnel_reply(&mut self.payload, &[]);
        self.payload.extend_from_slice(payload);
        self.write_payload_buffer(self.payload.len(), true).await?;
        Ok(payload.len())
    }

    pub async fn write_pong_reply(&mut self) -> Result<()> {
        self.payload.clear();
        write_pong_reply(&mut self.payload);
        self.write_control_scratch().await
    }

    pub async fn write_error_reply(&mut self, code: u8, message: &str) -> Result<()> {
        self.payload.clear();
        write_error_reply(&mut self.payload, code, message);
        self.write_control_scratch().await
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
        self.head.clear();
        if self.head.capacity() > STREAM_BUFFER_RETAIN_CAPACITY {
            self.head = BytesMut::with_capacity(FRAME_HEAD_INITIAL_CAPACITY);
        }
    }

    #[cfg(test)]
    pub(crate) fn frame_capacity(&self) -> usize {
        self.payload.capacity()
    }

    #[cfg(test)]
    pub(crate) fn has_committed_chunk_record(&self) -> bool {
        self.chunk_sizer.has_committed_record()
    }

    async fn try_write_udp_response_from_socket(
        &mut self,
        socket: &UdpSocket,
        ip_version: UdpResponseIpVersion,
    ) -> Result<Option<(usize, SocketAddr)>> {
        self.payload.clear();
        let prefix_len = ip_version.prefix_len();
        let payload_limit = MAX_V6_RECORD_PAYLOAD_LEN - prefix_len;
        self.payload
            .reserve(MAX_V6_RECORD_PAYLOAD_LEN + crate::protocol::crypto::AEAD_TAG_SIZE);
        self.payload.resize(prefix_len, 0);

        let min_spare = payload_limit + 1;
        let spare_len = self.payload.chunk_mut().len();
        if spare_len < min_spare {
            self.payload.reserve(min_spare);
        }

        let (payload_len, peer) = match socket.try_recv_buf_from(&mut self.payload) {
            Ok(result) => result,
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                self.payload.clear();
                return Ok(None);
            }
            Err(err) => {
                self.payload.clear();
                return Err(err.into());
            }
        };

        if payload_len > payload_limit {
            self.payload.clear();
            return Err(Error::PayloadTooLarge);
        }
        if !ip_version.matches(peer.ip()) {
            self.payload.clear();
            return Err(Error::InvalidAddressType);
        }

        let mut prefix = &mut self.payload[..prefix_len];
        write_udp_response_prefix(&mut prefix, AddressRef::Ip(peer.ip()), peer.port())?;
        debug_assert!(prefix.is_empty());

        let frame_len = prefix_len + payload_len;
        let stream_len = self.finish_udp_payload_message(frame_len).await?;
        tracing::trace!(
            payload_len,
            stream_len,
            "wrote snell v6 udp response stream"
        );
        Ok(Some((payload_len, peer)))
    }

    async fn write_control_scratch(&mut self) -> Result<()> {
        self.write_plain_scratch(true).await
    }

    async fn write_plain_scratch(&mut self, advance_chunk_sizer: bool) -> Result<()> {
        let payload_len = self.payload.len();
        let wire_len = self
            .write_payload_buffer(payload_len, advance_chunk_sizer)
            .await?;
        tracing::trace!(payload_len, wire_len, "wrote snell v6 request frame");
        Ok(())
    }
}
