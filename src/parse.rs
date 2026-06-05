use winnow::Parser;
use winnow::error::ContextError;

use crate::error::{Error, Result};

pub(crate) fn read_u8(input: &mut &[u8], err: Error) -> Result<u8> {
    winnow::binary::u8::<_, ContextError>(input).map_err(|_| err)
}

pub(crate) fn read_be_u16(input: &mut &[u8], err: Error) -> Result<u16> {
    winnow::binary::be_u16::<_, ContextError>(input).map_err(|_| err)
}

pub(crate) fn take_bytes<'a>(input: &mut &'a [u8], len: usize, err: Error) -> Result<&'a [u8]> {
    winnow::token::take::<_, _, ContextError>(len)
        .parse_next(input)
        .map_err(|_| err)
}

pub(crate) fn read_array<const N: usize>(input: &mut &[u8], err: Error) -> Result<[u8; N]> {
    let bytes = take_bytes(input, N, err)?;
    let mut out = [0; N];
    out.copy_from_slice(bytes);
    Ok(out)
}
