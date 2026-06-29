use super::labels::MIX_OFFSET;
use super::{ShapedProfile, usize_from_u32};

const MIX_ROUND_MOD3_RECIPROCAL: u32 = 171;
const MIX_ROUND_MOD3_SHIFT: u32 = 9;
const MIX_ROUND_BYTE_MASK: u32 = 0xff;

const MAX_FOLDED_ROUNDS_USIZE: usize = 3;
const MAX_FOLDED_ROUNDS: u32 = MAX_FOLDED_ROUNDS_USIZE as u32;
const MAX_FOLDED_STRIDE: usize = 15;
const FIXED_STRIDE_FOLD_MAX_LEN: usize = 256;
const WORD_BYTES: usize = 8;
const STRIDE_TABLE_LEN: usize = MAX_FOLDED_STRIDE + 1;
static STRIDE_MASKS: [[[u64; STRIDE_TABLE_LEN]; STRIDE_TABLE_LEN]; STRIDE_TABLE_LEN] =
    build_stride_masks();
static NEXT_BASE_MOD: [[usize; STRIDE_TABLE_LEN]; STRIDE_TABLE_LEN] = build_next_base_mods();
const STRIDE2_MASKS: [u64; 2] = [lane_mask(2, 0, 0), lane_mask(2, 1, 0)];
const STRIDE3_MASKS: [[u64; 3]; 3] = [
    [lane_mask(3, 0, 0), lane_mask(3, 0, 2), lane_mask(3, 0, 1)],
    [lane_mask(3, 1, 0), lane_mask(3, 1, 2), lane_mask(3, 1, 1)],
    [lane_mask(3, 2, 0), lane_mask(3, 2, 2), lane_mask(3, 2, 1)],
];
const STRIDE4_MASKS: [u64; 4] = [
    lane_mask(4, 0, 0),
    lane_mask(4, 1, 0),
    lane_mask(4, 2, 0),
    lane_mask(4, 3, 0),
];

#[derive(Clone, Copy)]
struct StrideStep {
    stride: usize,
    selected_mod: usize,
    base_mod: usize,
}

#[derive(Clone, Copy)]
struct StridePlan {
    steps: [StrideStep; MAX_FOLDED_ROUNDS_USIZE],
    len: usize,
}

#[derive(Clone, Copy)]
struct WordSegment {
    padding_ptr: *mut u8,
    payload_ptr: *mut u8,
    logical_base: usize,
    payload_base: usize,
    logical_end: usize,
}

impl StrideStep {
    #[inline(always)]
    fn with_logical_base(mut self, logical_base: usize) -> Self {
        self.base_mod = logical_base % self.stride;
        self
    }

    #[inline(always)]
    fn advance_word(&mut self) {
        self.base_mod = NEXT_BASE_MOD[self.stride][self.base_mod];
    }
}

impl StridePlan {
    #[inline(always)]
    const fn new() -> Self {
        Self {
            steps: [StrideStep {
                stride: 1,
                selected_mod: 0,
                base_mod: 0,
            }; MAX_FOLDED_ROUNDS_USIZE],
            len: 0,
        }
    }

    #[inline(always)]
    fn push(&mut self, stride: usize, selected_mod: usize) {
        debug_assert!(self.len < MAX_FOLDED_ROUNDS_USIZE);
        debug_assert!((1..=MAX_FOLDED_STRIDE).contains(&stride));
        debug_assert!(selected_mod < stride);

        self.steps[self.len] = StrideStep {
            stride,
            selected_mod,
            base_mod: 0,
        };
        self.len += 1;
    }

    #[inline(always)]
    fn swaps_byte(self, logical_offset: usize) -> bool {
        match self.len {
            0 => false,
            1 => byte_matches_stride(self.steps[0], logical_offset),
            2 => {
                byte_matches_stride(self.steps[0], logical_offset)
                    ^ byte_matches_stride(self.steps[1], logical_offset)
            }
            _ => {
                byte_matches_stride(self.steps[0], logical_offset)
                    ^ byte_matches_stride(self.steps[1], logical_offset)
                    ^ byte_matches_stride(self.steps[2], logical_offset)
            }
        }
    }
}

pub(crate) fn mix_padding_payload(
    profile: &ShapedProfile,
    seq: u32,
    padding: &mut [u8],
    payload_cipher: &mut [u8],
) {
    let n = padding.len().min(payload_cipher.len());
    if n == 0 {
        return;
    }
    match profile.mix_mode {
        0 => mix_fixed_stride_folded(profile, padding, payload_cipher, n),
        1 => mix_alternating_block_folded(profile, padding, payload_cipher, n),
        2 => mix_prf_stride_folded(profile, seq, padding, payload_cipher, n),
        _ => unreachable!("mix mode is derived modulo 3"),
    }
}

pub(crate) fn mix_padding_payload_split(
    profile: &ShapedProfile,
    seq: u32,
    padding: &mut [u8],
    payload_cipher: &mut [u8],
    payload_tag: &mut [u8],
) {
    let n = padding.len().min(payload_cipher.len() + payload_tag.len());
    if n == 0 {
        return;
    }
    match profile.mix_mode {
        0 => mix_fixed_stride_split_folded(profile, padding, payload_cipher, payload_tag, n),
        1 => mix_alternating_block_split_folded(profile, padding, payload_cipher, payload_tag, n),
        2 => mix_prf_stride_split_folded(profile, seq, padding, payload_cipher, payload_tag, n),
        _ => unreachable!("mix mode is derived modulo 3"),
    }
}

fn mix_fixed_stride_folded(
    profile: &ShapedProfile,
    padding: &mut [u8],
    payload_cipher: &mut [u8],
    n: usize,
) {
    if n <= FIXED_STRIDE_FOLD_MAX_LEN
        && let Some(plan) = fixed_stride_plan(profile)
    {
        swap_payload_stride_plan(padding, payload_cipher, n, plan);
        return;
    }

    for round in 0..profile.mix_rounds {
        mix_fixed_stride(profile, round, padding, payload_cipher, n);
    }
}

fn mix_fixed_stride_split_folded(
    profile: &ShapedProfile,
    padding: &mut [u8],
    payload_cipher: &mut [u8],
    payload_tag: &mut [u8],
    n: usize,
) {
    if n <= FIXED_STRIDE_FOLD_MAX_LEN
        && let Some(plan) = fixed_stride_plan(profile)
    {
        swap_payload_stride_plan_split(padding, payload_cipher, payload_tag, n, plan);
        return;
    }

    for round in 0..profile.mix_rounds {
        mix_fixed_stride_split(profile, round, padding, payload_cipher, payload_tag, n);
    }
}

fn mix_prf_stride_folded(
    profile: &ShapedProfile,
    seq: u32,
    padding: &mut [u8],
    payload_cipher: &mut [u8],
    n: usize,
) {
    if let Some(plan) = prf_stride_plan(profile, seq) {
        swap_payload_stride_plan(padding, payload_cipher, n, plan);
        return;
    }

    for round in 0..profile.mix_rounds {
        mix_prf_stride(profile, seq, round, padding, payload_cipher, n);
    }
}

fn mix_prf_stride_split_folded(
    profile: &ShapedProfile,
    seq: u32,
    padding: &mut [u8],
    payload_cipher: &mut [u8],
    payload_tag: &mut [u8],
    n: usize,
) {
    if let Some(plan) = prf_stride_plan(profile, seq) {
        swap_payload_stride_plan_split(padding, payload_cipher, payload_tag, n, plan);
        return;
    }

    for round in 0..profile.mix_rounds {
        mix_prf_stride_split(profile, seq, round, padding, payload_cipher, payload_tag, n);
    }
}

fn fixed_stride_plan(profile: &ShapedProfile) -> Option<StridePlan> {
    if profile.mix_rounds > MAX_FOLDED_ROUNDS {
        return None;
    }

    let mut plan = StridePlan::new();
    for round in 0..profile.mix_rounds {
        let stride = (profile.mix_stride + usize_from_u32(mix_round_delta(round))).max(1);
        if stride > MAX_FOLDED_STRIDE {
            return None;
        }
        plan.push(stride, profile.mix_offset_base % stride);
    }
    Some(plan)
}

fn prf_stride_plan(profile: &ShapedProfile, seq: u32) -> Option<StridePlan> {
    if profile.mix_rounds > MAX_FOLDED_ROUNDS {
        return None;
    }

    let mut plan = StridePlan::new();
    for round in 0..profile.mix_rounds {
        let stride = (profile.mix_stride + usize_from_u32(mix_round_delta(round))).max(1);
        if stride > MAX_FOLDED_STRIDE {
            return None;
        }
        let off =
            (profile.prf32(MIX_OFFSET, seq, round) as usize + profile.mix_offset_base) % stride;
        plan.push(stride, off);
    }
    Some(plan)
}

fn mix_fixed_stride(
    profile: &ShapedProfile,
    round: u32,
    padding: &mut [u8],
    payload_cipher: &mut [u8],
    n: usize,
) {
    let stride = (profile.mix_stride + usize_from_u32(mix_round_delta(round))).max(1);
    if stride == 1 {
        padding[..n].swap_with_slice(&mut payload_cipher[..n]);
        return;
    }

    let off = profile.mix_offset_base % stride;
    swap_payload_stride(padding, payload_cipher, n, off, stride);
}

fn mix_fixed_stride_split(
    profile: &ShapedProfile,
    round: u32,
    padding: &mut [u8],
    payload_cipher: &mut [u8],
    payload_tag: &mut [u8],
    n: usize,
) {
    let stride = (profile.mix_stride + usize_from_u32(mix_round_delta(round))).max(1);
    if stride == 1 {
        swap_payload_range_split(padding, payload_cipher, payload_tag, 0, n);
        return;
    }

    let off = profile.mix_offset_base % stride;
    swap_payload_stride_split(padding, payload_cipher, payload_tag, n, off, stride);
}

fn mix_alternating_block_folded(
    profile: &ShapedProfile,
    padding: &mut [u8],
    payload_cipher: &mut [u8],
    n: usize,
) {
    let block = profile.mix_block;
    let full_len = n - n % block;
    let even = profile.mix_rounds.div_ceil(2) % 2 == 1;
    let odd = (profile.mix_rounds / 2) % 2 == 1;
    match (even, odd) {
        (true, true) => padding[..full_len].swap_with_slice(&mut payload_cipher[..full_len]),
        (true, false) => swap_payload_blocks(padding, payload_cipher, n, block, 0),
        (false, true) => swap_payload_blocks(padding, payload_cipher, n, block, block),
        (false, false) => {}
    }
}

fn mix_alternating_block_split_folded(
    profile: &ShapedProfile,
    padding: &mut [u8],
    payload_cipher: &mut [u8],
    payload_tag: &mut [u8],
    n: usize,
) {
    let block = profile.mix_block;
    let full_len = n - n % block;
    let even = profile.mix_rounds.div_ceil(2) % 2 == 1;
    let odd = (profile.mix_rounds / 2) % 2 == 1;
    match (even, odd) {
        (true, true) => swap_payload_range_split(padding, payload_cipher, payload_tag, 0, full_len),
        (true, false) => {
            swap_payload_blocks_split(padding, payload_cipher, payload_tag, n, block, 0)
        }
        (false, true) => {
            swap_payload_blocks_split(padding, payload_cipher, payload_tag, n, block, block)
        }
        (false, false) => {}
    }
}

fn mix_prf_stride(
    profile: &ShapedProfile,
    seq: u32,
    round: u32,
    padding: &mut [u8],
    payload_cipher: &mut [u8],
    n: usize,
) {
    let stride = (profile.mix_stride + usize_from_u32(mix_round_delta(round))).max(1);
    let off = (profile.prf32(MIX_OFFSET, seq, round) as usize + profile.mix_offset_base) % stride;
    if stride == 1 {
        padding[..n].swap_with_slice(&mut payload_cipher[..n]);
        return;
    }

    swap_payload_stride(padding, payload_cipher, n, off, stride);
}

fn mix_prf_stride_split(
    profile: &ShapedProfile,
    seq: u32,
    round: u32,
    padding: &mut [u8],
    payload_cipher: &mut [u8],
    payload_tag: &mut [u8],
    n: usize,
) {
    let stride = (profile.mix_stride + usize_from_u32(mix_round_delta(round))).max(1);
    let off = (profile.prf32(MIX_OFFSET, seq, round) as usize + profile.mix_offset_base) % stride;
    if stride == 1 {
        swap_payload_range_split(padding, payload_cipher, payload_tag, 0, n);
        return;
    }

    swap_payload_stride_split(padding, payload_cipher, payload_tag, n, off, stride);
}

#[inline(always)]
fn swap_payload_stride_plan(
    padding: &mut [u8],
    payload_cipher: &mut [u8],
    n: usize,
    plan: StridePlan,
) {
    debug_assert!(n <= padding.len());
    debug_assert!(n <= payload_cipher.len());

    swap_payload_stride_plan_segment(padding, payload_cipher, 0, 0, n, plan);
}

#[inline(always)]
fn swap_payload_stride_plan_split(
    padding: &mut [u8],
    payload_cipher: &mut [u8],
    payload_tag: &mut [u8],
    n: usize,
    plan: StridePlan,
) {
    debug_assert!(n <= padding.len());
    debug_assert!(n <= payload_cipher.len() + payload_tag.len());

    let cipher_len = payload_cipher.len();
    let cipher_limit = n.min(cipher_len);
    swap_payload_stride_plan_segment(padding, payload_cipher, 0, 0, cipher_limit, plan);

    if cipher_limit < n {
        swap_payload_stride_plan_segment(padding, payload_tag, cipher_len, 0, n, plan);
    }
}

#[inline(always)]
fn swap_payload_stride_plan_segment(
    padding: &mut [u8],
    payload_segment: &mut [u8],
    logical_start: usize,
    payload_start: usize,
    logical_end: usize,
    plan: StridePlan,
) {
    debug_assert!(logical_start <= logical_end);
    debug_assert!(logical_end <= padding.len());
    debug_assert!(payload_start + logical_end - logical_start <= payload_segment.len());

    let logical_tail = swap_payload_stride_plan_words(
        padding.as_mut_ptr(),
        payload_segment.as_mut_ptr(),
        logical_start,
        payload_start,
        logical_end,
        plan,
    );
    swap_payload_stride_plan_tail(
        padding,
        payload_segment,
        logical_tail,
        payload_start + logical_tail - logical_start,
        logical_end,
        plan,
    );
}

#[inline(always)]
fn swap_payload_stride_plan_words(
    padding_ptr: *mut u8,
    payload_ptr: *mut u8,
    logical_start: usize,
    payload_start: usize,
    logical_end: usize,
    plan: StridePlan,
) -> usize {
    let segment = WordSegment {
        padding_ptr,
        payload_ptr,
        logical_base: logical_start,
        payload_base: payload_start,
        logical_end,
    };

    match plan.len {
        0 => logical_end,
        1 => swap_payload_stride_plan_words_1(segment, plan.steps[0]),
        2 => swap_payload_stride_plan_words_2(segment, plan.steps[0], plan.steps[1]),
        _ => swap_payload_stride_plan_words_3(segment, plan.steps[0], plan.steps[1], plan.steps[2]),
    }
}

#[inline(always)]
fn swap_payload_stride_plan_words_1(mut segment: WordSegment, step: StrideStep) -> usize {
    let mut step = step.with_logical_base(segment.logical_base);
    while segment.logical_base + WORD_BYTES <= segment.logical_end {
        let mask = STRIDE_MASKS[step.stride][step.selected_mod][step.base_mod];
        if mask != 0 {
            swap_masked_u64_at(
                segment.padding_ptr,
                segment.payload_ptr,
                segment.logical_base,
                segment.payload_base,
                mask,
            );
        }
        step.advance_word();
        segment.logical_base += WORD_BYTES;
        segment.payload_base += WORD_BYTES;
    }
    segment.logical_base
}

#[inline(always)]
fn swap_payload_stride_plan_words_2(
    mut segment: WordSegment,
    step0: StrideStep,
    step1: StrideStep,
) -> usize {
    let mut step0 = step0.with_logical_base(segment.logical_base);
    let mut step1 = step1.with_logical_base(segment.logical_base);
    while segment.logical_base + WORD_BYTES <= segment.logical_end {
        let mask = STRIDE_MASKS[step0.stride][step0.selected_mod][step0.base_mod]
            ^ STRIDE_MASKS[step1.stride][step1.selected_mod][step1.base_mod];
        if mask != 0 {
            swap_masked_u64_at(
                segment.padding_ptr,
                segment.payload_ptr,
                segment.logical_base,
                segment.payload_base,
                mask,
            );
        }
        step0.advance_word();
        step1.advance_word();
        segment.logical_base += WORD_BYTES;
        segment.payload_base += WORD_BYTES;
    }
    segment.logical_base
}

#[inline(always)]
fn swap_payload_stride_plan_words_3(
    mut segment: WordSegment,
    step0: StrideStep,
    step1: StrideStep,
    step2: StrideStep,
) -> usize {
    let mut step0 = step0.with_logical_base(segment.logical_base);
    let mut step1 = step1.with_logical_base(segment.logical_base);
    let mut step2 = step2.with_logical_base(segment.logical_base);
    while segment.logical_base + WORD_BYTES <= segment.logical_end {
        let mask = STRIDE_MASKS[step0.stride][step0.selected_mod][step0.base_mod]
            ^ STRIDE_MASKS[step1.stride][step1.selected_mod][step1.base_mod]
            ^ STRIDE_MASKS[step2.stride][step2.selected_mod][step2.base_mod];
        if mask != 0 {
            swap_masked_u64_at(
                segment.padding_ptr,
                segment.payload_ptr,
                segment.logical_base,
                segment.payload_base,
                mask,
            );
        }
        step0.advance_word();
        step1.advance_word();
        step2.advance_word();
        segment.logical_base += WORD_BYTES;
        segment.payload_base += WORD_BYTES;
    }
    segment.logical_base
}

#[inline(always)]
fn swap_payload_stride_plan_tail(
    padding: &mut [u8],
    payload_segment: &mut [u8],
    mut logical_base: usize,
    mut payload_base: usize,
    logical_end: usize,
    plan: StridePlan,
) {
    while logical_base < logical_end {
        if plan.swaps_byte(logical_base) {
            // SAFETY: `logical_base < logical_end <= padding.len()`, and the
            // segment bounds were checked by `swap_payload_stride_plan_segment`.
            unsafe {
                std::ptr::swap(
                    padding.as_mut_ptr().add(logical_base),
                    payload_segment.as_mut_ptr().add(payload_base),
                );
            }
        }
        logical_base += 1;
        payload_base += 1;
    }
}

#[inline(always)]
fn swap_payload_stride(
    padding: &mut [u8],
    payload_cipher: &mut [u8],
    n: usize,
    off: usize,
    stride: usize,
) {
    debug_assert!(stride > 0);
    debug_assert!(n <= padding.len());
    debug_assert!(n <= payload_cipher.len());

    let off = swap_payload_stride_masked(padding, payload_cipher, n, off, stride);
    swap_payload_stride_bytes(padding, payload_cipher, n, off, stride);
}

#[inline(always)]
fn swap_payload_stride_bytes(
    padding: &mut [u8],
    payload_cipher: &mut [u8],
    n: usize,
    mut off: usize,
    stride: usize,
) {
    while off < n {
        // SAFETY: `off < n`, and callers pass `n <= padding.len()` and
        // `n <= payload_cipher.len()`. The two mutable slices are distinct
        // regions, so swapping one byte at the same offset cannot alias.
        unsafe {
            std::ptr::swap(
                padding.as_mut_ptr().add(off),
                payload_cipher.as_mut_ptr().add(off),
            );
        }
        off += stride;
    }
}

#[inline(always)]
fn swap_payload_stride_masked(
    padding: &mut [u8],
    payload_cipher: &mut [u8],
    limit: usize,
    off: usize,
    stride: usize,
) -> usize {
    let padding_ptr = padding.as_mut_ptr();
    let payload_ptr = payload_cipher.as_mut_ptr();
    let mut base = 0;
    match stride {
        2 => {
            let mask = STRIDE2_MASKS[off & 1];
            while base + 8 <= limit {
                swap_masked_u64(padding_ptr, payload_ptr, base, mask);
                base += 8;
            }
        }
        3 => {
            let masks = STRIDE3_MASKS[off % 3];
            let mut mask_index = 0;
            while base + 8 <= limit {
                swap_masked_u64(padding_ptr, payload_ptr, base, masks[mask_index]);
                mask_index = if mask_index == 2 { 0 } else { mask_index + 1 };
                base += 8;
            }
        }
        4 => {
            let mask = STRIDE4_MASKS[off & 3];
            while base + 8 <= limit {
                swap_masked_u64(padding_ptr, payload_ptr, base, mask);
                base += 8;
            }
        }
        5..=MAX_FOLDED_STRIDE => {
            let selected_mod = off % stride;
            let mut base_mod = 0;
            while base + 8 <= limit {
                let mask = STRIDE_MASKS[stride][selected_mod][base_mod];
                if mask != 0 {
                    swap_masked_u64(padding_ptr, payload_ptr, base, mask);
                }
                base_mod = NEXT_BASE_MOD[stride][base_mod];
                base += 8;
            }
        }
        _ => {}
    }
    first_stride_offset_at_or_after(base, off, stride)
}

#[inline(always)]
fn swap_payload_stride_split(
    padding: &mut [u8],
    payload_cipher: &mut [u8],
    payload_tag: &mut [u8],
    n: usize,
    off: usize,
    stride: usize,
) {
    debug_assert!(stride > 0);
    debug_assert!(n <= padding.len());
    debug_assert!(n <= payload_cipher.len() + payload_tag.len());

    let cipher_len = payload_cipher.len();
    let cipher_limit = n.min(cipher_len);
    let mut off = swap_payload_stride_masked(padding, payload_cipher, cipher_limit, off, stride);

    while off < cipher_limit {
        // SAFETY: `off < cipher_limit <= cipher_len` and `off < n <= padding.len()`.
        // `padding` and `payload_cipher` are distinct mutable slices.
        unsafe {
            std::ptr::swap(
                padding.as_mut_ptr().add(off),
                payload_cipher.as_mut_ptr().add(off),
            );
        }
        off += stride;
    }

    while off < n {
        let tag_off = off - cipher_len;
        // SAFETY: here `off >= cipher_len`, so `tag_off` is in the tag segment.
        // The function precondition gives `n <= cipher_len + payload_tag.len()`,
        // therefore `tag_off < payload_tag.len()`, and `off < n <= padding.len()`.
        unsafe {
            std::ptr::swap(
                padding.as_mut_ptr().add(off),
                payload_tag.as_mut_ptr().add(tag_off),
            );
        }
        off += stride;
    }
}

#[inline(always)]
fn swap_payload_blocks(
    padding: &mut [u8],
    payload_cipher: &mut [u8],
    n: usize,
    block: usize,
    mut off: usize,
) {
    let step = block * 2;
    while off + block <= n {
        let end = off + block;
        padding[off..end].swap_with_slice(&mut payload_cipher[off..end]);
        off += step;
    }
}

#[inline(always)]
fn swap_payload_blocks_split(
    padding: &mut [u8],
    payload_cipher: &mut [u8],
    payload_tag: &mut [u8],
    n: usize,
    block: usize,
    mut off: usize,
) {
    let step = block * 2;
    let cipher_len = payload_cipher.len();
    let cipher_limit = n.min(cipher_len);

    while off + block <= cipher_limit {
        let end = off + block;
        padding[off..end].swap_with_slice(&mut payload_cipher[off..end]);
        off += step;
    }

    if off + block <= n && off < cipher_len {
        let end = off + block;
        swap_payload_range_split(padding, payload_cipher, payload_tag, off, end);
        off += step;
    }

    while off + block <= n {
        let end = off + block;
        let tag_start = off - cipher_len;
        let tag_end = tag_start + block;
        padding[off..end].swap_with_slice(&mut payload_tag[tag_start..tag_end]);
        off += step;
    }
}

#[inline(always)]
fn swap_masked_u64(padding_ptr: *mut u8, payload_ptr: *mut u8, base: usize, mask: u64) {
    swap_masked_u64_at(padding_ptr, payload_ptr, base, base, mask);
}

#[inline(always)]
fn swap_masked_u64_at(
    padding_ptr: *mut u8,
    payload_ptr: *mut u8,
    padding_base: usize,
    payload_base: usize,
    mask: u64,
) {
    // SAFETY: callers only pass offsets when `offset + 8 <= len` for both
    // slices. `read_unaligned`/`write_unaligned` avoid alignment requirements,
    // and the two mutable slices are distinct regions. The mask is defined in
    // little-endian lane order, so normalize words around native-endian memory.
    unsafe {
        let padding_word_ptr = padding_ptr.add(padding_base).cast::<u64>();
        let payload_word_ptr = payload_ptr.add(payload_base).cast::<u64>();
        let padding_word = u64::from_le(std::ptr::read_unaligned(padding_word_ptr));
        let payload_word = u64::from_le(std::ptr::read_unaligned(payload_word_ptr));
        let swap_bits = (padding_word ^ payload_word) & mask;
        std::ptr::write_unaligned(padding_word_ptr, (padding_word ^ swap_bits).to_le());
        std::ptr::write_unaligned(payload_word_ptr, (payload_word ^ swap_bits).to_le());
    }
}

#[inline(always)]
fn byte_matches_stride(step: StrideStep, logical_offset: usize) -> bool {
    logical_offset % step.stride == step.selected_mod
}

const fn build_stride_masks() -> [[[u64; STRIDE_TABLE_LEN]; STRIDE_TABLE_LEN]; STRIDE_TABLE_LEN] {
    let mut masks = [[[0; STRIDE_TABLE_LEN]; STRIDE_TABLE_LEN]; STRIDE_TABLE_LEN];
    let mut stride = 1;
    while stride <= MAX_FOLDED_STRIDE {
        let mut selected_mod = 0;
        while selected_mod < stride {
            let mut base_mod = 0;
            while base_mod < stride {
                masks[stride][selected_mod][base_mod] = lane_mask(stride, selected_mod, base_mod);
                base_mod += 1;
            }
            selected_mod += 1;
        }
        stride += 1;
    }
    masks
}

const fn build_next_base_mods() -> [[usize; STRIDE_TABLE_LEN]; STRIDE_TABLE_LEN] {
    let mut next = [[0; STRIDE_TABLE_LEN]; STRIDE_TABLE_LEN];
    let mut stride = 1;
    while stride <= MAX_FOLDED_STRIDE {
        let mut base_mod = 0;
        while base_mod < stride {
            next[stride][base_mod] = (base_mod + 8) % stride;
            base_mod += 1;
        }
        stride += 1;
    }
    next
}

const fn lane_mask(stride: usize, selected_mod: usize, base_mod: usize) -> u64 {
    let mut mask = 0;
    let mut lane = 0;
    while lane < 8 {
        if (base_mod + lane) % stride == selected_mod {
            mask |= 0xff << (lane * 8);
        }
        lane += 1;
    }
    mask
}

const fn first_stride_offset_at_or_after(start: usize, off: usize, stride: usize) -> usize {
    if start <= off {
        off
    } else {
        let rem = (start - off) % stride;
        if rem == 0 {
            start
        } else {
            start + (stride - rem)
        }
    }
}

fn swap_payload_range_split(
    padding: &mut [u8],
    payload_cipher: &mut [u8],
    payload_tag: &mut [u8],
    start: usize,
    end: usize,
) {
    let mut off = start;
    if off < payload_cipher.len() {
        let cipher_end = end.min(payload_cipher.len());
        padding[off..cipher_end].swap_with_slice(&mut payload_cipher[off..cipher_end]);
        off = cipher_end;
    }
    if off < end {
        let tag_start = off - payload_cipher.len();
        let tag_end = end - payload_cipher.len();
        padding[off..end].swap_with_slice(&mut payload_tag[tag_start..tag_end]);
    }
}

const fn mix_round_delta(round: u32) -> u32 {
    let quotient = (MIX_ROUND_MOD3_RECIPROCAL * round) >> MIX_ROUND_MOD3_SHIFT;
    (round - 3 * quotient) & MIX_ROUND_BYTE_MASK
}
