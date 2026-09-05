from pathlib import Path
import re

ROOT = Path.cwd()

def load(path):
    return (ROOT / path).read_text()

def save(path, text):
    p = ROOT / path
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)

def sub(text, old, new, count=1):
    assert text.count(old) == count, (old[:160], text.count(old), count)
    return text.replace(old, new)

def func(text, marker, replacement):
    start = text.index(marker)
    brace = text.index('{', start)
    depth = 1
    end = brace + 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    return text[:start] + replacement + text[end:]

p = 'crates/snell-protocol/Cargo.toml'
save(p, sub(load(p), '[dependencies]\n', '[dependencies]\nbytes.workspace = true\n'))
p = 'Cargo.lock'
s=load(p)
a=s.index('name = "snell-protocol"')
b=s.index('[[package]]',a)
block=s[a:b]
block=sub(block,' "blake2",',' "blake2",\n "bytes",')
save(p,s[:a]+block+s[b:])
p = 'crates/snell-protocol/src/lib.rs'
save(p, sub(load(p), 'pub use buffer::{EncodeBuffer, RecvBuffer};', 'pub use buffer::{EncodeBuffer, PayloadBuffer, RecvBuffer};'))
p = 'crates/snell-protocol/src/buffer.rs'
s = load(p)
s = sub(s, 'use std::mem::MaybeUninit;', 'use std::mem::MaybeUninit;\n\nuse bytes::{BufMut, buf::UninitSlice};')
s = sub(s, 'storage: Vec::with_capacity(max),', 'storage: Vec::new(),', 2)
s = s.replace('/// Fixed capacity: `new(max)` does `Vec::with_capacity(max)` and never reallocates.\n', '/// Allocation is lazy and grows geometrically up to the hard limit.\n')
s = s.replace('/// `storage.len()` is the live end. Front `start` is consumed. The kernel writes\n', '/// `storage.len()` is the initialized end. Front `start` is consumed. I/O writes\n')
s = s.replace('    /// Compacts only when `max - len < min`. Capacity is `>= max` for the lifetime\n    /// of the buffer; this never grows.\n', '    /// Compacts or grows only when the allocated tail cannot fit `min`.\n    /// Call only after outstanding decoded records have been consumed.\n')
start = s.index('    pub fn spare_capacity_mut')
end = s.index('    /// Copy `bytes`', start)
s = s[:start] + '''    pub fn spare_capacity_mut(&mut self, min: usize) -> Result<&mut [MaybeUninit<u8>]> {
        if self.len().checked_add(min).is_none_or(|n| n > self.max) {
            return Err(Error::PayloadTooLarge);
        }
        if self.storage.capacity().min(self.max) - self.storage.len() < min {
            self.compact();
            grow(&mut self.storage, self.max, min);
        }
        let writable = self.storage.capacity().min(self.max) - self.storage.len();
        Ok(&mut self.storage.spare_capacity_mut()[..writable])
    }

    pub fn capacity(&self) -> usize {
        self.storage.capacity()
    }

    /// Increase the protocol limit without copying buffered bytes.
    pub fn set_max(&mut self, max: usize) -> Result<()> {
        if max < self.max {
            return Err(Error::PayloadTooLarge);
        }
        self.max = max;
        Ok(())
    }

    /// Reclaim idle capacity while preserving any pipelined bytes.
    pub fn shrink_idle(&mut self) {
        self.compact();
        self.storage.shrink_to_fit();
    }

''' + s[end:]
s = s.replace('let writable = self.max - self.storage.len();', 'let writable = self.storage.capacity().min(self.max) - self.storage.len();')
a=s.index('    /// Commit `n` bytes previously initialized in the spare tail.\n')
b=s.index('    pub fn consume',a)
s=s[:a]+s[b:]
a=s.index('    /// Commit `n` bytes previously initialized in the spare tail.\n')
b=s.index('    /// Zero-fill', a)
s=s[:a]+s[b:]
a=s.index('    pub fn spare_capacity_mut', s.index('impl EncodeBuffer'))
b=s.index('    /// Absolute end index',a)
s=s[:a]+'''    pub fn spare_capacity_mut(&mut self, min: usize) -> Result<&mut [MaybeUninit<u8>]> {
        if self.len().checked_add(min).is_none_or(|n| n > self.max) {
            return Err(Error::PayloadTooLarge);
        }
        if self.storage.capacity().min(self.max) - self.storage.len() < min {
            self.compact();
            grow(&mut self.storage, self.max, min);
        }
        let writable = self.storage.capacity().min(self.max) - self.storage.len();
        Ok(&mut self.storage.spare_capacity_mut()[..writable])
    }

    /// An idle encoder must have no pending wire bytes.
    pub fn shrink_idle(&mut self) -> Result<()> {
        if !self.is_empty() {
            return Err(Error::PendingWire);
        }
        self.storage = Vec::new();
        self.sent = 0;
        Ok(())
    }

''' + s[b:]
s=s.replace('[`Self::commit_init`]', '[`Self::commit`]')
a=s.index('/// Shared reservation `seal_init` bookkeeping:')
b=s.index('#[cfg(test)]',a)
s=s[:a]+'''/// A bounded, append-only payload writer. Initialized length can advance only
/// through `BufMut`'s unsafe contract or its safe copying methods.
pub struct PayloadBuffer<'a> {
    buf: &'a mut EncodeBuffer,
    end: usize,
}

impl<'a> PayloadBuffer<'a> {
    pub(crate) fn new(buf: &'a mut EncodeBuffer, end: usize) -> Self {
        Self { buf, end }
    }
}

// SAFETY: chunks expose only reserved spare capacity, and advance_mut requires
// the caller to have initialized exactly the bytes being committed.
unsafe impl BufMut for PayloadBuffer<'_> {
    fn remaining_mut(&self) -> usize {
        self.end.saturating_sub(self.buf.end())
    }

    fn chunk_mut(&mut self) -> &mut UninitSlice {
        let n = self.remaining_mut();
        UninitSlice::uninit(&mut self.buf.spare_uninit()[..n])
    }

    unsafe fn advance_mut(&mut self, n: usize) {
        assert!(n <= self.remaining_mut(), "payload initialization exceeds reservation");
        // SAFETY: BufMut caller initialized n bytes, and n is within the slot.
        unsafe { self.buf.commit(n).expect("reserved payload capacity") };
    }
}

// SAFETY: the I/O adapter prepares capacity first. No safe method exposes
// uninitialized bytes as u8; only an unsafe advance commits them.
unsafe impl BufMut for RecvBuffer {
    fn remaining_mut(&self) -> usize {
        self.storage.capacity().min(self.max) - self.storage.len()
    }

    fn chunk_mut(&mut self) -> &mut UninitSlice {
        let n = self.remaining_mut();
        UninitSlice::uninit(&mut self.storage.spare_capacity_mut()[..n])
    }

    unsafe fn advance_mut(&mut self, n: usize) {
        // SAFETY: BufMut caller initialized n bytes. commit checks the bound.
        unsafe { self.commit(n).expect("prepared receive capacity") };
    }
}

fn grow(storage: &mut Vec<u8>, max: usize, additional: usize) {
    let needed = storage.len() + additional;
    if needed > storage.capacity() {
        let target = needed.max(storage.capacity().saturating_mul(2)).max(4096).min(max);
        storage.reserve_exact(target - storage.len());
    }
}

''' + s[b:]
s=s.replace('        buf.commit_init(2).unwrap();', '        // SAFETY: the preceding write initialized both bytes.\n        unsafe { buf.commit(2).unwrap() };')
s=s.replace('        buf.commit_init(4).unwrap();', '        // SAFETY: the preceding write initialized all four bytes.\n        unsafe { buf.commit(4).unwrap() };')
s=s.replace('fn commit_init_advances_filled()', 'fn initialized_commit_advances_filled()')
pos=s.rfind('}')
s=s[:pos]+'''
    #[test]
    fn capacity_is_lazy_and_idle_buffers_release_backing_storage() {
        let mut recv = RecvBuffer::new(crate::V6_WIRE_CAP);
        let mut encode = EncodeBuffer::new(crate::V6_WIRE_CAP);
        assert_eq!(recv.capacity(), 0);
        assert_eq!(encode.capacity(), 0);
        recv.extend_from_slice(b"small").unwrap();
        assert!(recv.capacity() < crate::V6_WIRE_CAP);
        recv.extend_from_slice(&vec![0xA5; 60_000]).unwrap();
        recv.consume(recv.len()).unwrap();
        recv.shrink_idle();
        encode.reserve_zeroed(60_000).unwrap();
        assert!(encode.shrink_idle().is_err());
        encode.advance(encode.len()).unwrap();
        encode.shrink_idle().unwrap();
        assert_eq!(recv.capacity(), 0);
        assert_eq!(encode.capacity(), 0);
    }

    #[test]
    fn shrinking_preserves_pipelined_data_and_protocol_limit() {
        let mut recv = RecvBuffer::new(crate::V6_WIRE_CAP);
        let data = vec![0xA5; 50_000];
        recv.extend_from_slice(&data).unwrap();
        recv.consume(123).unwrap();
        recv.shrink_idle();
        assert_eq!(recv.filled(), &data[123..]);
        assert_eq!(recv.max(), crate::V6_WIRE_CAP);
        recv.consume(recv.len()).unwrap();
        recv.extend_from_slice(&vec![1; crate::V6_WIRE_CAP]).unwrap();
        assert_eq!(recv.len(), crate::V6_WIRE_CAP);
        assert!(recv.extend_from_slice(&[1]).is_err());
    }

    #[test]
    fn warmed_buffers_do_not_reallocate() {
        let mut recv = RecvBuffer::new(crate::V6_WIRE_CAP);
        recv.extend_from_slice(&vec![0; crate::V6_WIRE_CAP]).unwrap();
        let ptr = recv.filled().as_ptr();
        let capacity = recv.capacity();
        for _ in 0..100 {
            recv.consume(recv.len()).unwrap();
            recv.extend_from_slice(&[1; 16383]).unwrap();
            assert_eq!(recv.filled().as_ptr(), ptr);
            assert_eq!(recv.capacity(), capacity);
        }
    }

    #[test]
    fn payload_bufmut_commits_only_initialized_bytes() {
        let mut encode = EncodeBuffer::new(64);
        encode.reserve_record(32, 4).unwrap();
        {
            let mut slot = PayloadBuffer::new(&mut encode, 16);
            slot.put_slice(b"hello");
            slot.put_slice(b"world");
            assert_eq!(slot.remaining_mut(), 2);
        }
        assert_eq!(encode.pending(), b"\\0\\0\\0\\0helloworld");
    }
''' + s[pos:]
save(p,s)

for name in ['v4', 'v6_shaped', 'v6_unshaped']:
    p=f'crates/snell-protocol/src/{name}.rs'
    s=load(p)
    a=s.index('    /// Uninitialized payload slot after the prefix.')
    b=s.index('    pub fn capacity',a)
    s=s[:a]+'''    /// Append into the reserved payload without zero-filling unused capacity.
    pub fn payload_buf(&mut self) -> crate::PayloadBuffer<'_> {
        let end = self.encoder.payload_start + self.encoder.max_payload;
        crate::PayloadBuffer::new(self.buf, end)
    }

'''+s[b:]
    a=s.index('    /// Seal after the caller initialized `written` bytes')
    b=s.index('\n}',a)
    s=s[:a]+s[b:]
    s=re.sub(r'(\w+)\.payload_uninit\(\)\[\.\.([^\]]+)\]\.write_copy_of_slice\(([^;]+)\);', r'bytes::BufMut::put_slice(&mut \1.payload_buf(), \3);',s)
    s=s.replace('.seal_init(', '.seal(')
    save(p,s)

p='crates/snell-runtime/src/codec.rs'
s=load(p)
s=sub(s,'use std::mem::MaybeUninit;\n\n','use snell_protocol::PayloadBuffer;\n\n')
a=s.index('    /// Uninitialized payload slot;')
b=s.index('    fn capacity',a)
s=s[:a]+"    fn payload_buf(&mut self) -> PayloadBuffer<'_>;\n"+s[b:]
s=sub(s,'    /// Seal after initializing `written` bytes of [`Self::payload_uninit`].\n    fn seal_init(self, written: usize) -> Result<()>;\n','')
for typ in ['V4Reservation','V6ShapedReservation','V6UnshapedReservation']:
    start=s.index(f'impl TcpReservation for {typ}')
    a=s.index('    fn payload_uninit',start)
    b=s.index('    fn capacity',a)
    s=s[:a]+f'''    fn payload_buf(&mut self) -> PayloadBuffer<'_> {{
        {typ}::payload_buf(self)
    }}

'''+s[b:]
    start=s.index(f'impl TcpReservation for {typ}')
    a=s.index('    fn seal_init',start)
    b=s.index('\n}',a)
    s=s[:a]+s[b:]
save(p,s)

p='crates/snell-runtime/src/bufio.rs'
s=load(p)
s='#![allow(unsafe_code)]\n#![deny(unsafe_op_in_unsafe_fn)]\n\n'+s
s=s.replace('use std::task::Poll;', 'use std::task::{Context, Poll};\n\nuse bytes::BufMut;')
s=func(s,'pub(crate) async fn read_into_recv', '''pub(crate) async fn read_into_recv<R: AsyncRead + Unpin>(
    reader: &mut R,
    recv: &mut RecvBuffer,
) -> Result<usize, SessionError> {
    poll_fn(|cx| poll_recv(cx, reader, recv, recv.len() + 1)).await
}

pub(crate) fn poll_recv<R: AsyncRead + Unpin>(
    cx: &mut Context<'_>,
    reader: &mut R,
    recv: &mut RecvBuffer,
    minimum: usize,
) -> Poll<Result<usize, SessionError>> {
    if let Err(error) = recv.spare_capacity_mut(minimum.saturating_sub(recv.len()).max(1)) {
        return Poll::Ready(Err(error.into()));
    }
    poll_read_buf(cx, reader, recv).map_err(SessionError::from)
}

/// Keep initialized-length advancement next to the ReadBuf that proves it.
pub(crate) fn poll_read_buf<R: AsyncRead + Unpin, B: BufMut>(
    cx: &mut Context<'_>,
    reader: &mut R,
    dst: &mut B,
) -> Poll<io::Result<usize>> {
    let n = {
        // SAFETY: ReadBuf never de-initializes the exposed spare capacity.
        let spare = unsafe { dst.chunk_mut().as_uninit_slice_mut() };
        let mut buf = ReadBuf::uninit(spare);
        match Pin::new(reader).poll_read(cx, &mut buf) {
            Poll::Ready(Ok(())) => buf.filled().len(),
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => return Poll::Pending,
        }
    };
    // SAFETY: n was obtained from ReadBuf::filled(), on this exact chunk.
    unsafe { dst.advance_mut(n) };
    Poll::Ready(Ok(n))
}''')
save(p,s)

p='crates/snell-runtime/src/session.rs'
s=load(p)
s=s.replace('MAX_PACKET_SIZE, MAX_PACKET_SIZE_V6,', 'MAX_PACKET_SIZE_V6,')
s=s.replace('use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};', 'use tokio::io::{AsyncRead, AsyncWrite};')
s=s.replace('use crate::bufio::{drain_encode, read_into_recv};', 'use crate::bufio::{drain_encode, poll_read_buf, poll_recv, read_into_recv};')
s=s.replace('const RECORD_HINT: usize = MAX_PACKET_SIZE;', 'const RECORD_HINT: usize = MAX_PACKET_SIZE_V6;')
s=s.replace('    let psk_bytes = psk.as_bytes().to_vec();\n    let key = kdf.run(move || aead_key(&psk_bytes, &salt)).await??;', '    let psk = psk.clone();\n    let key = kdf.run(move || aead_key(psk.as_bytes(), &salt)).await??;')
a=s.index("/// Drop the session's touched buffer pages")
b=s.index('async fn fill_until',a)
s=s[:a]+s[b:]
s=s.replace('    initial_to_plain: &[u8],\n    initial_to_snell: &[u8],', '    initial_to_plain: Vec<u8>,')
s=s.replace('write_all(plain, initial_to_plain)', 'write_all(plain, &initial_to_plain)')
a=s.index('    if !initial_to_snell.is_empty()')
b=s.index('    let (mut snell_r',a)
s=s[:a]+'    drop(initial_to_plain);\n\n'+s[b:]
a=s.index('                            let read = {')
b=s.index('                            match read {',a)
s=s[:a]+'''                            let read = poll_read_buf(cx, reader, &mut reservation.payload_buf());
'''+s[b:]
s=s.replace('reservation.seal_init(n)', 'reservation.seal(n)')
a=s.index('                        let n = {',s.index('async fn pump_snell_to_plain'))
b=s.index('                        if n == 0',a)
s=s[:a]+'''                        let n = match poll_recv(cx, reader, recv, minimum) {
                            Poll::Ready(Ok(n)) => n,
                            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                            Poll::Pending => return Poll::Pending,
                        };
'''+s[b:]
s=sub(s,'                        if let Err(error) = recv.commit_init(n) {\n                            return Poll::Ready(Err(error.into()));\n                        }\n','')
s=s.replace('    while recv.len() < minimum {\n', '    while recv.len() < minimum {\n        recv.spare_capacity_mut(minimum - recv.len())?;\n')
save(p,s)

for name in ['server','client']:
    p=f'crates/snell-runtime/src/{name}.rs'
    s=load(p)
    s=s.replace('ServerFirst, ensure_bulk,', 'ServerFirst,')
    s=s.replace('relay, release_bulk,', 'relay,')
    s=s.replace('        recv = ensure_bulk(recv)?;\n        encode = new_encode();\n', '        recv.set_max(snell_protocol::V6_WIRE_CAP)?;\n')
    s=s.replace('            &connect.leftover,\n            &[],', '            connect.leftover,')
    s=s.replace('                &leftover,\n                &[],', '                leftover,')
    s=s.replace('        let released = release_bulk(recv, encode)?;\n        recv = released.0;\n        encode = released.1;', '''        // Pipelined reuse continues immediately without allocation churn.
        if recv.is_empty() {
            recv.shrink_idle();
            encode.shrink_idle()?;
        }''')
    save(p,s)
p='crates/snell-runtime/src/udp.rs'
s=load(p).replace('decode_once, ensure_bulk,', 'decode_once,')
s=s.replace('recv = ensure_bulk(recv)?;', 'recv.set_max(snell_protocol::V6_WIRE_CAP)?;')
save(p,s)
p='crates/snell-runtime/src/auto.rs'
s=load(p)
s=s.replace('                let bytes = record.plaintext(recv.filled()).to_vec();\n                decoder.consume(recv, &record)?;\n                if plain.push(&bytes).is_err() {', '                let pushed = plain.push(record.plaintext(recv.filled()));\n                decoder.consume(recv, &record)?;\n                if pushed.is_err() {')
save(p,s)
