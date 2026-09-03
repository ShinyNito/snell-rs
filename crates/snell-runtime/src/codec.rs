use snell_protocol::{
    DecodeStatus, DecodedRecord, EncodeBuffer, RecvBuffer, Result, V4Decoder, V4Encoder,
    V4Reservation, V6ShapedDecoder, V6ShapedEncoder, V6ShapedReservation, V6UnshapedDecoder,
    V6UnshapedEncoder, V6UnshapedReservation,
};

pub(crate) trait TcpReservation {
    fn payload_mut(&mut self) -> &mut [u8];
    fn capacity(&self) -> usize;
    fn seal(self, written: usize) -> Result<()>;
}

pub(crate) trait TcpEncoder {
    fn reserve<'a>(
        &'a mut self,
        buf: &'a mut EncodeBuffer,
        prefix: &[u8],
        hint: usize,
    ) -> Result<impl TcpReservation + 'a>;
}

pub(crate) trait TcpDecoder {
    fn decode(&mut self, buf: &mut RecvBuffer) -> Result<DecodeStatus>;
    fn consume(&mut self, buf: &mut RecvBuffer, record: &DecodedRecord) -> Result<()>;
}

impl TcpReservation for V4Reservation<'_> {
    fn payload_mut(&mut self) -> &mut [u8] {
        V4Reservation::payload_mut(self)
    }

    fn capacity(&self) -> usize {
        V4Reservation::capacity(self)
    }

    fn seal(self, written: usize) -> Result<()> {
        V4Reservation::seal(self, written)
    }
}

impl TcpEncoder for V4Encoder {
    fn reserve<'a>(
        &'a mut self,
        buf: &'a mut EncodeBuffer,
        prefix: &[u8],
        hint: usize,
    ) -> Result<impl TcpReservation + 'a> {
        V4Encoder::reserve(self, buf, prefix, hint)
    }
}

impl TcpDecoder for V4Decoder {
    fn decode(&mut self, buf: &mut RecvBuffer) -> Result<DecodeStatus> {
        V4Decoder::decode(self, buf)
    }

    fn consume(&mut self, buf: &mut RecvBuffer, record: &DecodedRecord) -> Result<()> {
        V4Decoder::consume(self, buf, record)
    }
}

impl TcpReservation for V6ShapedReservation<'_> {
    fn payload_mut(&mut self) -> &mut [u8] {
        V6ShapedReservation::payload_mut(self)
    }

    fn capacity(&self) -> usize {
        V6ShapedReservation::capacity(self)
    }

    fn seal(self, written: usize) -> Result<()> {
        V6ShapedReservation::seal(self, written)
    }
}

impl TcpEncoder for V6ShapedEncoder {
    fn reserve<'a>(
        &'a mut self,
        buf: &'a mut EncodeBuffer,
        prefix: &[u8],
        hint: usize,
    ) -> Result<impl TcpReservation + 'a> {
        V6ShapedEncoder::reserve(self, buf, prefix, hint)
    }
}

impl TcpDecoder for V6ShapedDecoder {
    fn decode(&mut self, buf: &mut RecvBuffer) -> Result<DecodeStatus> {
        V6ShapedDecoder::decode(self, buf)
    }

    fn consume(&mut self, buf: &mut RecvBuffer, record: &DecodedRecord) -> Result<()> {
        V6ShapedDecoder::consume(self, buf, record)
    }
}

impl TcpReservation for V6UnshapedReservation<'_> {
    fn payload_mut(&mut self) -> &mut [u8] {
        V6UnshapedReservation::payload_mut(self)
    }

    fn capacity(&self) -> usize {
        V6UnshapedReservation::capacity(self)
    }

    fn seal(self, written: usize) -> Result<()> {
        V6UnshapedReservation::seal(self, written)
    }
}

impl TcpEncoder for V6UnshapedEncoder {
    fn reserve<'a>(
        &'a mut self,
        buf: &'a mut EncodeBuffer,
        prefix: &[u8],
        hint: usize,
    ) -> Result<impl TcpReservation + 'a> {
        V6UnshapedEncoder::reserve(self, buf, prefix, hint)
    }
}

impl TcpDecoder for V6UnshapedDecoder {
    fn decode(&mut self, buf: &mut RecvBuffer) -> Result<DecodeStatus> {
        V6UnshapedDecoder::decode(self, buf)
    }

    fn consume(&mut self, buf: &mut RecvBuffer, record: &DecodedRecord) -> Result<()> {
        V6UnshapedDecoder::consume(self, buf, record)
    }
}
