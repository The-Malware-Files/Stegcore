// Author:  Daniel Iwugo
// Comment: Christ is King
// Copyright (C) 2026 Daniel Iwugo
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Stegcore-Commercial
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.
//
// Commercial licensing: daniel@themalwarefiles.com

//! Two digests the brute-force module needs, implemented here rather than
//! taken as dependencies.
//!
//! **MD5** is required for bit-exact compatibility with OpenStego, which seeds
//! its bit-position generator from `Long.parseLong(md5hex[0..15], 16)`. It is
//! used only to reproduce another tool's key schedule, never to protect
//! anything of ours. MD5 is broken for collision resistance and must not be
//! used anywhere else in this workspace.
//!
//! **SHA-256 and HMAC-SHA-256** are required by the acceptable-use record
//! (`AUP.md` section 3.1 commits to recording a SHA-256 of the input file) and
//! by engagement-manifest verification.
//!
//! Both are written out here deliberately. Baseline section 5 asks whether a
//! few lines of our own code could replace a dependency; for three textbook
//! compression functions with published test vectors the answer is yes, and it
//! keeps three more crates out of a tree that already carries parsers on the
//! untrusted-input path. Correctness is pinned by the published vectors in the
//! tests below (RFC 1321 for MD5, FIPS 180-4 for SHA-256, RFC 4231 for HMAC).

// ---------------------------------------------------------------------------
// MD5 (RFC 1321)
// ---------------------------------------------------------------------------

const MD5_S: [u32; 64] = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9,
    14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15,
    21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];

/// `floor(abs(sin(i + 1)) * 2^32)` for i in 0..64, per RFC 1321 section 3.4.
const MD5_K: [u32; 64] = [
    0xd76a_a478,
    0xe8c7_b756,
    0x2420_70db,
    0xc1bd_ceee,
    0xf57c_0faf,
    0x4787_c62a,
    0xa830_4613,
    0xfd46_9501,
    0x6980_98d8,
    0x8b44_f7af,
    0xffff_5bb1,
    0x895c_d7be,
    0x6b90_1122,
    0xfd98_7193,
    0xa679_438e,
    0x49b4_0821,
    0xf61e_2562,
    0xc040_b340,
    0x265e_5a51,
    0xe9b6_c7aa,
    0xd62f_105d,
    0x0244_1453,
    0xd8a1_e681,
    0xe7d3_fbc8,
    0x21e1_cde6,
    0xc337_07d6,
    0xf4d5_0d87,
    0x455a_14ed,
    0xa9e3_e905,
    0xfcef_a3f8,
    0x676f_02d9,
    0x8d2a_4c8a,
    0xfffa_3942,
    0x8771_f681,
    0x6d9d_6122,
    0xfde5_380c,
    0xa4be_ea44,
    0x4bde_cfa9,
    0xf6bb_4b60,
    0xbebf_bc70,
    0x289b_7ec6,
    0xeaa1_27fa,
    0xd4ef_3085,
    0x0488_1d05,
    0xd9d4_d039,
    0xe6db_99e5,
    0x1fa2_7cf8,
    0xc4ac_5665,
    0xf429_2244,
    0x432a_ff97,
    0xab94_23a7,
    0xfc93_a039,
    0x655b_59c3,
    0x8f0c_cc92,
    0xffef_f47d,
    0x8584_5dd1,
    0x6fa8_7e4f,
    0xfe2c_e6e0,
    0xa301_4314,
    0x4e08_11a1,
    0xf753_7e82,
    0xbd3a_f235,
    0x2ad7_d2bb,
    0xeb86_d391,
];

/// MD5 of `data`. Present only to reproduce OpenStego's seed derivation.
pub fn md5(data: &[u8]) -> [u8; 16] {
    let mut state: [u32; 4] = [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476];

    let mut padded = Vec::with_capacity(data.len() + 72);
    padded.extend_from_slice(data);
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    // Length in bits, little endian. A `u64` cannot overflow here: an input
    // long enough to wrap 2^64 bits cannot be held in memory.
    padded.extend_from_slice(&((data.len() as u64).wrapping_mul(8)).to_le_bytes());

    for block in padded.chunks_exact(64) {
        let mut m = [0u32; 16];
        for (i, word) in block.chunks_exact(4).enumerate() {
            m[i] = u32::from_le_bytes([word[0], word[1], word[2], word[3]]);
        }
        let [mut a, mut b, mut c, mut d] = state;
        for i in 0..64 {
            let (f, g) = match i / 16 {
                0 => ((b & c) | (!b & d), i),
                1 => ((d & b) | (!d & c), (5 * i + 1) % 16),
                2 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | !d), (7 * i) % 16),
            };
            let tmp = d;
            d = c;
            c = b;
            let sum = a.wrapping_add(f).wrapping_add(MD5_K[i]).wrapping_add(m[g]);
            b = b.wrapping_add(sum.rotate_left(MD5_S[i]));
            a = tmp;
        }
        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
    }

    let mut out = [0u8; 16];
    for (i, word) in state.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    out
}

// ---------------------------------------------------------------------------
// SHA-256 (FIPS 180-4)
// ---------------------------------------------------------------------------

const SHA256_K: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

/// Streaming SHA-256, so a multi-gigabyte carrier can be hashed for the
/// acceptable-use record without being held in memory.
#[derive(Debug, Clone)]
pub struct Sha256 {
    state: [u32; 8],
    buffer: [u8; 64],
    buffered: usize,
    len_bytes: u64,
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256 {
    pub fn new() -> Self {
        Self {
            state: [
                0x6a09_e667,
                0xbb67_ae85,
                0x3c6e_f372,
                0xa54f_f53a,
                0x510e_527f,
                0x9b05_688c,
                0x1f83_d9ab,
                0x5be0_cd19,
            ],
            buffer: [0u8; 64],
            buffered: 0,
            len_bytes: 0,
        }
    }

    pub fn update(&mut self, mut data: &[u8]) {
        self.len_bytes = self.len_bytes.wrapping_add(data.len() as u64);
        if self.buffered > 0 {
            let want = 64 - self.buffered;
            let take = want.min(data.len());
            self.buffer[self.buffered..self.buffered + take].copy_from_slice(&data[..take]);
            self.buffered += take;
            data = &data[take..];
            if self.buffered < 64 {
                // Still short of a block. Returning here matters: falling
                // through would reach the remainder handling below and reset
                // `buffered` to zero, silently dropping the bytes just copied in.
                return;
            }
            let block = self.buffer;
            self.compress(&block);
            self.buffered = 0;
        }
        let mut chunks = data.chunks_exact(64);
        for block in &mut chunks {
            // `chunks_exact` guarantees the length, so the conversion holds.
            let mut fixed = [0u8; 64];
            fixed.copy_from_slice(block);
            self.compress(&fixed);
        }
        let rest = chunks.remainder();
        self.buffer[..rest.len()].copy_from_slice(rest);
        self.buffered = rest.len();
    }

    pub fn finalise(mut self) -> [u8; 32] {
        let bit_len = self.len_bytes.wrapping_mul(8);
        self.update_raw_pad(bit_len);
        let mut out = [0u8; 32];
        for (i, word) in self.state.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }

    fn update_raw_pad(&mut self, bit_len: u64) {
        let mut tail = Vec::with_capacity(128);
        tail.push(0x80u8);
        let total = self.buffered + 1;
        let pad = if total % 64 <= 56 {
            56 - (total % 64)
        } else {
            120 - (total % 64)
        };
        tail.extend(std::iter::repeat(0u8).take(pad));
        tail.extend_from_slice(&bit_len.to_be_bytes());
        // `update` would re-count these bytes into the length, so splice them
        // into the buffer directly.
        let mut staged = Vec::with_capacity(self.buffered + tail.len());
        staged.extend_from_slice(&self.buffer[..self.buffered]);
        staged.extend_from_slice(&tail);
        self.buffered = 0;
        for block in staged.chunks_exact(64) {
            let mut fixed = [0u8; 64];
            fixed.copy_from_slice(block);
            self.compress(&fixed);
        }
    }

    fn compress(&mut self, block: &[u8; 64]) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            let b = &block[i * 4..i * 4 + 4];
            w[i] = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let mut h = self.state;
        for i in 0..64 {
            let s1 = h[4].rotate_right(6) ^ h[4].rotate_right(11) ^ h[4].rotate_right(25);
            let ch = (h[4] & h[5]) ^ (!h[4] & h[6]);
            let t1 = h[7]
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(SHA256_K[i])
                .wrapping_add(w[i]);
            let s0 = h[0].rotate_right(2) ^ h[0].rotate_right(13) ^ h[0].rotate_right(22);
            let maj = (h[0] & h[1]) ^ (h[0] & h[2]) ^ (h[1] & h[2]);
            let t2 = s0.wrapping_add(maj);
            h[7] = h[6];
            h[6] = h[5];
            h[5] = h[4];
            h[4] = h[3].wrapping_add(t1);
            h[3] = h[2];
            h[2] = h[1];
            h[1] = h[0];
            h[0] = t1.wrapping_add(t2);
        }
        for (dst, src) in self.state.iter_mut().zip(h.iter()) {
            *dst = dst.wrapping_add(*src);
        }
    }
}

/// SHA-256 of a byte slice, as 32 bytes.
pub fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalise()
}

/// Lowercase hexadecimal rendering, for records a human has to read.
pub fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap_or('0'));
        s.push(char::from_digit((b & 0x0f) as u32, 16).unwrap_or('0'));
    }
    s
}

/// HMAC-SHA-256 (RFC 2104), used to verify an engagement manifest against a
/// key the operator controls.
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut block = [0u8; 64];
    if key.len() > 64 {
        block[..32].copy_from_slice(&sha256_bytes(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }

    let mut inner_key = [0x36u8; 64];
    let mut outer_key = [0x5cu8; 64];
    for i in 0..64 {
        inner_key[i] ^= block[i];
        outer_key[i] ^= block[i];
    }

    let mut inner = Sha256::new();
    inner.update(&inner_key);
    inner.update(message);
    let inner_digest = inner.finalise();

    let mut outer = Sha256::new();
    outer.update(&outer_key);
    outer.update(&inner_digest);
    outer.finalise()
}

/// Constant-time equality for two digests, so a manifest check does not leak
/// how much of a forged tag was correct through its own timing.
pub fn digests_equal(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn md5_matches_rfc1321_vectors() {
        let cases: [(&str, &str); 7] = [
            ("", "d41d8cd98f00b204e9800998ecf8427e"),
            ("a", "0cc175b9c0f1b6a831c399e269772661"),
            ("abc", "900150983cd24fb0d6963f7d28e17f72"),
            ("message digest", "f96b697d7cb7938d525a2f31aaf161d0"),
            (
                "abcdefghijklmnopqrstuvwxyz",
                "c3fcd3d76192e4007dfb496cca67e13b",
            ),
            (
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                "d174ab98d277d9f5a5611c2c9f419d9f",
            ),
            (
                "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
                "57edf4a22be3c955ac49da2e2107b67a",
            ),
        ];
        for (input, expect) in cases {
            assert_eq!(hex(&md5(input.as_bytes())), expect, "md5({input:?})");
        }
    }

    #[test]
    fn sha256_matches_published_vectors() {
        assert_eq!(
            hex(&sha256_bytes(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex(&sha256_bytes(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex(&sha256_bytes(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    #[test]
    fn sha256_handles_the_block_boundary_cases() {
        // 55, 56 and 64 bytes exercise each padding branch.
        for n in [54usize, 55, 56, 57, 63, 64, 65, 119, 120, 121] {
            let data = vec![b'x'; n];
            let mut streamed = Sha256::new();
            for chunk in data.chunks(7) {
                streamed.update(chunk);
            }
            assert_eq!(
                streamed.finalise(),
                sha256_bytes(&data),
                "streaming disagreed with one-shot at {n} bytes"
            );
        }
    }

    #[test]
    fn sha256_streaming_matches_one_shot_on_a_long_input() {
        let data: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();
        let mut streamed = Sha256::new();
        for chunk in data.chunks(97) {
            streamed.update(chunk);
        }
        assert_eq!(streamed.finalise(), sha256_bytes(&data));
    }

    #[test]
    fn hmac_matches_rfc4231_case_1() {
        let key = [0x0bu8; 20];
        let tag = hmac_sha256(&key, b"Hi There");
        assert_eq!(
            hex(&tag),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn hmac_matches_rfc4231_case_2() {
        let tag = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(
            hex(&tag),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn hmac_hashes_an_over_long_key() {
        // RFC 4231 case 6: a 131-byte key, longer than the 64-byte block.
        let key = [0xaau8; 131];
        let tag = hmac_sha256(
            &key,
            b"Test Using Larger Than Block-Size Key - Hash Key First",
        );
        assert_eq!(
            hex(&tag),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    #[test]
    fn digest_comparison_rejects_length_and_content_differences() {
        assert!(digests_equal(&[1, 2, 3], &[1, 2, 3]));
        assert!(!digests_equal(&[1, 2, 3], &[1, 2, 4]));
        assert!(!digests_equal(&[1, 2, 3], &[1, 2]));
        assert!(digests_equal(&[], &[]));
    }

    #[test]
    fn hex_renders_low_nibbles_and_is_lowercase() {
        assert_eq!(hex(&[0x00, 0x0f, 0xa5, 0xff]), "000fa5ff");
    }
}
