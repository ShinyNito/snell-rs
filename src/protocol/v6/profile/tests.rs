use super::*;
use crate::test_support::TEST_PSK;

#[test]
fn profile_derivation_matches_reversed_constants() {
    let profile = V6Profile::derive(TEST_PSK);

    assert_eq!(profile.namespaces.profile, 0x0f8a_72f8_718e_3d8b);
    assert_eq!(profile.namespaces.prefix, 0xff24_1509_13b4_c0fe);
    assert_eq!(profile.namespaces.motif, 0xb29c_2bd0_d53d_60b1);
    assert_eq!(profile.namespaces.salt, 0xe515_cadf_c530_bec6);
    assert_eq!(profile.namespaces.mix, 0x5192_75b5_59af_5b64);
    assert_eq!(profile.namespaces.chunk, 0x2434_d6b4_2325_f973);
    assert_eq!(profile.namespaces.write, 0xf731_7535_404e_e993);

    assert_eq!(profile.profile_id, 2_951_777_511);
    assert_eq!(profile.generator, 0);
    assert_eq!(profile.pad_min, 139);
    assert_eq!(profile.pad_max, 397);
    assert_eq!(profile.pad_count, 7);
    assert_eq!(profile.pad_interval, 10);
    assert_eq!(profile.small_limit, 597);
    assert_eq!(profile.bit_min, 37);
    assert_eq!(profile.bit_max, 71);
    assert_eq!(profile.salt_block_len, 135);
    assert_eq!(profile.mix_stride_handshake, 189);
    assert_eq!(profile.prefix_min_record, 20);
    assert_eq!(profile.prefix_max_record, 128);
    assert_eq!(profile.mix_mode, 2);
    assert_eq!(profile.mix_rounds, 1);
    assert_eq!(profile.mix_stride, 7);
    assert_eq!(profile.mix_offset_base, 2);
    assert_eq!(profile.mix_block, 52);
    assert_eq!(profile.chunk_policy, 1);
    assert_eq!(profile.chunk_initial, 711);
    assert_eq!(profile.chunk_max, 12_887);
    assert_eq!(profile.chunk_step, 2_920);
    assert_eq!(profile.chunk_jitter, 156);
    assert_eq!(profile.idle_reset, Duration::from_secs(32));
    assert_eq!(profile.write_policy, 0);
    assert_eq!(profile.write_first, 6);
    assert_eq!(profile.write_jitter, 46);
    assert_eq!(profile.write_jitter_percent, 14);
    assert_eq!(
        profile.salt_positions,
        [
            99, 132, 33, 35, 0, 56, 44, 6, 29, 26, 98, 31, 76, 18, 80, 86
        ]
    );
    assert_eq!(
        (0..SALT_SIZE)
            .map(|i| profile.salt_mask(i))
            .collect::<Vec<_>>(),
        [
            80, 44, 193, 191, 14, 154, 209, 39, 0, 61, 47, 128, 242, 232, 128, 184
        ]
    );
    assert_eq!(
        profile.chunk_buckets,
        [6636, 8677, 11013, 5579, 9822, 7434, 12267, 4943]
    );
    assert_eq!(
        profile.write_buckets,
        [1390, 1437, 1249, 1339, 326, 865, 708, 868]
    );
    assert_eq!(
        profile.write_seq,
        [1331, 528, 711, 1001, 422, 1040, 880, 690]
    );
    assert_eq!(
        [
            profile.g1, profile.g2, profile.g3, profile.g4, profile.g5, profile.g6
        ],
        [63, 19, 53, 0, 6, 14]
    );
}

#[test]
fn runtime_prf_and_fill_match_reversed_constants() {
    let profile = V6Profile::derive(TEST_PSK);
    let mut fill = BytesMut::new();
    let mut salt_fill = BytesMut::new();

    profile.append_official_fill(7, 32, &mut fill);
    profile.append_official_fill(u32::MAX, 32, &mut salt_fill);

    assert_eq!(
        &fill[..],
        &[
            0x59, 0x66, 0x4d, 0xd2, 0xd2, 0x99, 0x78, 0x96, 0x4b, 0xca, 0x36, 0xf0, 0x4b, 0xc9,
            0x17, 0x65, 0xd4, 0x6a, 0xb4, 0x4d, 0xaa, 0x4b, 0xe2, 0xf0, 0xb4, 0x3a, 0xcc, 0xac,
            0x5a, 0x59, 0xa9, 0xa5,
        ]
    );
    assert_eq!(
        &salt_fill[..],
        &[
            0x53, 0xd2, 0x2d, 0x93, 0x4e, 0x96, 0x96, 0xd2, 0xf0, 0x2b, 0xca, 0xd1, 0x33, 0xac,
            0xa5, 0x87, 0xb2, 0xa5, 0x65, 0xb4, 0x59, 0xd8, 0x96, 0x93, 0x53, 0x27, 0xc5, 0x6a,
            0x69, 0xca, 0x95, 0x4e,
        ]
    );
    assert_eq!(
        (0..8)
            .map(|seq| profile.record_prefix_len(seq))
            .collect::<Vec<_>>(),
        [49, 122, 90, 125, 118, 47, 102, 88]
    );
    assert_eq!(
        [
            profile.prf32(LABEL_MIX_OFFSET, 7, 2),
            profile.prf32(LABEL_RECORD_PREFIX, 0, 0),
            profile.prf32(LABEL_PAYLOAD_PADDING, 1, 120),
            profile.prf32(LABEL_CHUNK_SIZE, 2, 512),
            profile.prf32(LABEL_CHUNK_JITTER_VALUE, 2, 512),
        ],
        [
            1_074_551_323,
            351_646_673,
            107_949_104,
            859_498_871,
            3_087_932_833
        ]
    );
    assert_eq!(
        [
            profile.final_padding_len(0, 0, true),
            profile.final_padding_len(0, 18, true),
            profile.final_padding_len(1, 120, false),
            profile.final_padding_len(7, 1024, false),
        ],
        [974, 893, 1104, 188]
    );
    assert_eq!(
        V6Profile::derive(b"cap-search-262").final_padding_len(6, 0, false),
        MAX_EXTRA_TARGET_PADDING
    );
    assert_eq!(
        [
            profile.chunk_limit(0, 0),
            profile.chunk_limit(1, profile.chunk_initial),
            profile.chunk_limit(2, 512),
        ],
        [12267, 7434, 4943]
    );
}

#[test]
fn optimized_official_fill_matches_reference() {
    for psk in [
        TEST_PSK,
        b"mix-mode-a",
        b"mix-mode-b",
        b"mix-mode-c",
        b"other psk",
    ] {
        let profile = V6Profile::derive(psk);
        for seq in [0, 1, 2, 7, 31, u32::MAX] {
            for len in [0, 1, 7, 8, 31, 32, 96, 127, 512, 1500] {
                let mut actual = BytesMut::new();
                let mut expected = BytesMut::new();

                let actual_range = profile.append_official_fill(seq, len, &mut actual);
                let expected_range = append_reference_fill(&profile, seq, len, &mut expected);

                assert_eq!(actual_range, expected_range);
                assert_eq!(
                    actual,
                    expected,
                    "psk={:?} seq={seq} len={len}",
                    std::str::from_utf8(psk).unwrap_or("<non-utf8>")
                );
            }
        }
    }
}

fn append_reference_fill(
    profile: &V6Profile,
    seq: u32,
    len: usize,
    out: &mut BytesMut,
) -> Range<usize> {
    let start = out.len();
    reference_expand_stream(
        profile.namespaces.for_label(LABEL_PADDING),
        LABEL_PADDING,
        seq,
        len,
        out,
    );
    let end = out.len();
    let fill = &mut out[start..end];
    match profile.generator {
        0 => reference_generator_0(profile, seq, fill),
        1 => reference_generator_1(profile, fill),
        2 => reference_generator_2(profile, fill),
        3 => reference_generator_3(profile, seq, fill),
        _ => unreachable!("generator is masked to 0..=3"),
    }
    start..end
}

fn reference_expand_stream(namespace: u64, label: u32, seq: u32, len: usize, out: &mut BytesMut) {
    out.reserve(len);
    let target_len = out.len() + len;
    let mut state = STREAM_INITIAL_STATE.wrapping_add((seq as u64).wrapping_mul(DOMAIN_MUL))
        ^ (label as u64).wrapping_mul(STREAM_LABEL_MUL)
        ^ (len as u64)
            .wrapping_mul(STREAM_LEN_MUL)
            .wrapping_add(STREAM_LEN_ADD)
        ^ namespace;

    while out.len() < target_len {
        state = state.wrapping_add(GOLDEN_RATIO_64);
        let word = splitmix64(state).to_le_bytes();
        let remaining = target_len - out.len();
        out.extend_from_slice(&word[..remaining.min(word.len())]);
    }
}

fn reference_expand_array<const N: usize>(namespace: u64, label: u32, seq: u32) -> [u8; N] {
    let mut out = BytesMut::with_capacity(N);
    reference_expand_stream(namespace, label, seq, N, &mut out);
    let mut array = [0; N];
    array.copy_from_slice(&out);
    array
}

fn reference_generator_0(profile: &V6Profile, seq: u32, out: &mut [u8]) {
    let percent = profile.pick(
        LABEL_BIT_PERCENT,
        seq,
        0,
        profile.bit_min as usize,
        profile.bit_max as usize,
    );
    let scaled = percent * 8;
    let target_bits = if scaled <= 49 {
        1
    } else if scaled > 749 {
        7
    } else {
        (scaled + 50) / 100
    } as u32;

    for (i, byte) in out.iter_mut().enumerate() {
        let orig = *byte;
        let mut b = *byte;
        for k in 0..8 {
            if b.count_ones() == target_bits {
                break;
            }
            let bit = (usize::from(orig) + i + 3 * k) & 7;
            if b.count_ones() < target_bits {
                b |= 1 << bit;
            } else {
                b &= !(1 << bit);
            }
        }
        *byte = b;
    }
}

fn reference_generator_1(profile: &V6Profile, out: &mut [u8]) {
    let total = profile.g1 + profile.g2 + profile.g3;
    for (i, byte) in out.iter_mut().enumerate() {
        let b = *byte;
        let r = usize::from(b) % total;
        *byte = if r < profile.g1 {
            0x20 + b.wrapping_add(i as u8) % 0x5f
        } else if r < profile.g1 + profile.g2 {
            0x80 + ((b ^ i as u8) % 0x40)
        } else {
            0xc0 + b.wrapping_add((7 * i) as u8) % 0x40
        };
    }
}

fn reference_generator_2(profile: &V6Profile, out: &mut [u8]) {
    for (i, byte) in out.iter_mut().enumerate() {
        let b = *byte;
        let hi = (((b >> 4).wrapping_add((i & 3) as u8).wrapping_add(3)) << 4) & 0xf0;
        let lo = ((b & 0x0f) as usize + profile.g4 + (i & 1)) % 10;
        *byte = hi | lo as u8;
    }
}

fn reference_generator_3(profile: &V6Profile, seq: u32, out: &mut [u8]) {
    let motif =
        reference_expand_array::<32>(profile.namespaces.for_label(LABEL_MOTIF), LABEL_MOTIF, seq);
    let motif_len = (profile.g5 * 4).min(motif.len());
    let interval = profile.g6;
    for (i, byte) in out.iter_mut().enumerate() {
        let b = *byte;
        let r = i % interval;
        *byte = if r < interval - 3 {
            ((profile.g5 + 3) * i) as u8 ^ motif[i % motif_len]
        } else if r < interval - 1 {
            0x30 + b % 10
        } else {
            b
        };
    }
}
