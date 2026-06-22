pub mod address;
pub mod snell;
pub mod socks5;

/// Exact-read friendly parse state, shared by all protocol codecs.
///
/// `Need(total)` means the caller should make sure the same buffer contains at
/// least `total` bytes, then call the parser again.
///
/// Parsers intentionally accept buffers longer than the protocol object and
/// expose `header_len` / `consumed_len` where needed. This is important for
/// codecs (e.g. Snell/TCP records) that may already contain application
/// payload after a command header in the same buffer.
///
/// Each codec module defines its own `ParseResult<T>` alias that binds this
/// generic state to its own concrete error type — see
/// [`socks5::ParseResult`] and [`snell::ParseResult`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseState<T> {
    Need(usize),
    Done(T),
}
