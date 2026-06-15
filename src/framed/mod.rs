mod buffer;
mod reader;
#[cfg(test)]
mod tests;
mod writer;

pub(crate) use reader::SnellStreamReader;
pub(crate) use writer::{
    PayloadSource, PayloadWriteStatus, SnellStreamWriter, poll_read_payload_into_slots_fallback,
};

use crate::MAX_PACKET_SIZE;

pub const TCP_RECORD_MSS: usize = 1460;
pub const TCP_FIRST_RECORD_OVERHEAD: usize = 55;
pub const TCP_STEADY_RECORD_OVERHEAD: usize = 39;
pub const TCP_RECORD_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
pub(crate) const STREAM_BUFFER_INITIAL_CAPACITY: usize = 2048;
pub(crate) const STREAM_READ_AHEAD_CAPACITY: usize = 64 * 1024;
pub(crate) const STREAM_BUFFER_RETAIN_CAPACITY: usize = MAX_PACKET_SIZE + 1024;
pub(super) const FRAME_HEAD_INITIAL_CAPACITY: usize = 512;
