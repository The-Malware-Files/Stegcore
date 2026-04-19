// Copyright (C) 2026 The Malware Files
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.

// JPEG DCT coefficient steganography — JSteg-style LSB embedding.
// Parses JPEG entropy data, modifies quantized AC coefficient LSBs,
// re-encodes with the original Huffman tables.  Output is a valid JPEG.
//
// Technique: skip DC coefficients and any AC coefficient whose absolute
// value is 0 or 1 (modifying those would create / destroy zero-runs and
// break the EOB structure).  Embed one payload bit per eligible
// coefficient LSB.  Coefficient selection is permuted by a ChaCha8 RNG
// seeded from the passphrase so the positions are secret.

use std::collections::HashMap;

use rand::{seq::SliceRandom, SeedableRng};
use rand_chacha::ChaCha8Rng;

use crate::errors::StegError;

// ── JPEG markers ──────────────────────────────────────────────────────────────

const SOI: u16 = 0xFFD8;
const EOI: u16 = 0xFFD9;
const SOS: u16 = 0xFFDA;
const DHT: u16 = 0xFFC4;
const DQT: u16 = 0xFFDB;
const SOF0: u16 = 0xFFC0; // Baseline DCT
const SOF1: u16 = 0xFFC1; // Extended sequential
const DRI: u16 = 0xFFDD;
const RST0: u16 = 0xFFD0;
const RST7: u16 = 0xFFD7;
const APP0: u16 = 0xFFE0;
const APP15: u16 = 0xFFEF;
const COM: u16 = 0xFFFE;

// Zigzag scan order — maps coefficient index (0..63) to (row, col) in 8×8 block.
#[rustfmt::skip]
const ZIGZAG: [usize; 64] = [
     0,  1,  8, 16,  9,  2,  3, 10,
    17, 24, 32, 25, 18, 11,  4,  5,
    12, 19, 26, 33, 40, 48, 41, 34,
    27, 20, 13,  6,  7, 14, 21, 28,
    35, 42, 49, 56, 57, 50, 43, 36,
    29, 22, 15, 23, 30, 37, 44, 51,
    58, 59, 52, 45, 38, 31, 39, 46,
    53, 60, 61, 54, 47, 55, 62, 63,
];

// ── Huffman table ─────────────────────────────────────────────────────────────

#[derive(Clone)]
struct HuffTable {
    /// Decode: canonical code → (symbol, code_len)
    decode: HashMap<u16, (u8, u8)>,
    /// Encode: symbol → (code, code_len)
    encode: HashMap<u8, (u16, u8)>,
    /// Maximum code length present (for reading)
    max_len: u8,
}

impl HuffTable {
    /// Build from the BITS[16] + HUFFVAL[] representation in the JPEG DHT segment.
    fn from_jpeg(bits: &[u8; 16], huffval: &[u8]) -> Self {
        let mut decode = HashMap::new();
        let mut encode = HashMap::new();
        let mut code: u16 = 0;
        let mut val_idx: usize = 0;
        let mut max_len: u8 = 0;

        for len in 1u8..=16 {
            for _ in 0..bits[(len - 1) as usize] {
                let sym = huffval[val_idx];
                val_idx += 1;
                decode.insert(code, (sym, len));
                encode.insert(sym, (code, len));
                if len > max_len {
                    max_len = len;
                }
                code += 1;
            }
            code <<= 1;
        }

        HuffTable {
            decode,
            encode,
            max_len,
        }
    }

    fn encode_sym(&self, sym: u8) -> Option<(u16, u8)> {
        self.encode.get(&sym).copied()
    }
}

// ── Bit reader (entropy stream, with byte-stuffing removal) ───────────────────

struct BitReader<'a> {
    data: &'a [u8],
    pos: usize, // byte position
    buf: u64,   // bit buffer (MSB-first)
    bits: u8,   // valid bits in buf
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        BitReader {
            data,
            pos: 0,
            buf: 0,
            bits: 0,
        }
    }

    /// Refill buffer, skipping byte-stuffing (0xFF 0x00 → 0xFF).
    fn refill(&mut self) {
        while self.bits <= 56 && self.pos < self.data.len() {
            let b = self.data[self.pos];
            self.pos += 1;
            // Byte stuffing: 0xFF in entropy data is followed by 0x00
            if b == 0xFF {
                if self.pos < self.data.len() && self.data[self.pos] == 0x00 {
                    self.pos += 1; // consume the stuffed 0x00
                }
                // 0xFF followed by non-zero is a marker — stop consuming
                else {
                    // Back up — we've consumed the 0xFF; the marker byte is next.
                    // Don't add 0xFF to the buffer; restart markers are handled
                    // by the MCU loop, not here.
                    break;
                }
            }
            self.buf = (self.buf << 8) | (b as u64);
            self.bits += 8;
        }
    }

    fn peek(&mut self, n: u8) -> Result<u16, StegError> {
        if self.bits < n {
            self.refill();
        }
        if self.bits < n {
            return Err(StegError::CorruptedFile);
        }
        Ok(((self.buf >> (self.bits - n)) & ((1u64 << n) - 1)) as u16)
    }

    fn consume(&mut self, n: u8) {
        debug_assert!(self.bits >= n, "BitReader underflow: {} < {}", self.bits, n);
        self.bits -= n;
        self.buf &= (1u64 << self.bits) - 1;
    }

    fn read_bits(&mut self, n: u8) -> Result<u16, StegError> {
        let v = self.peek(n)?;
        self.consume(n);
        Ok(v)
    }

    /// Decode one Huffman symbol from the stream.
    ///
    /// Canonical Huffman codes are prefix-free but shorter-length codes can
    /// share the same numeric value as longer ones (e.g. a length-2 code of
    /// value 0b00 = 0 will appear under key 0 in the table, just like a
    /// hypothetical length-1 code 0b0 = 0 would).  We MUST check that the
    /// stored code length equals the length we are currently trying.
    fn decode_huffman(&mut self, table: &HuffTable) -> Result<u8, StegError> {
        for len in 1..=table.max_len {
            if self.bits < len {
                self.refill();
            }
            if self.bits < len {
                return Err(StegError::CorruptedFile);
            }
            let candidate = ((self.buf >> (self.bits - len)) & ((1u64 << len) - 1)) as u16;
            // Must verify code_len == len: canonical codes at different lengths
            // can have identical numeric values.
            if let Some(&(sym, code_len)) = table.decode.get(&candidate) {
                if code_len == len {
                    self.consume(len);
                    return Ok(sym);
                }
            }
        }
        Err(StegError::CorruptedFile)
    }

    /// Decode a signed value from `cat` bits (category = bit width of |value|).
    fn read_value(&mut self, cat: u8) -> Result<i16, StegError> {
        if cat == 0 {
            return Ok(0);
        }
        let raw = self.read_bits(cat)?;
        // If leading bit is 1 → positive; else negative.
        if raw >= (1u16 << (cat - 1)) {
            Ok(raw as i16)
        } else {
            // Negative: value = raw - (2^cat - 1)
            Ok(raw as i16 - ((1i16 << cat) - 1))
        }
    }
}

// ── Bit writer (entropy stream, with byte-stuffing insertion) ─────────────────

struct BitWriter {
    buf: u64,
    bits: u8,
    out: Vec<u8>,
}

impl BitWriter {
    fn new() -> Self {
        BitWriter {
            buf: 0,
            bits: 0,
            out: Vec::new(),
        }
    }

    fn write_bits(&mut self, value: u16, len: u8) {
        debug_assert!(
            self.bits + len <= 64,
            "BitWriter overflow: {} + {} > 64",
            self.bits,
            len
        );
        self.buf = (self.buf << len) | (value as u64);
        self.bits += len;
        while self.bits >= 8 {
            self.bits -= 8;
            let byte = ((self.buf >> self.bits) & 0xFF) as u8;
            self.out.push(byte);
            // Byte stuffing: 0xFF in entropy data must be followed by 0x00
            if byte == 0xFF {
                self.out.push(0x00);
            }
        }
    }

    fn write_huffman(&mut self, sym: u8, table: &HuffTable) -> Result<(), StegError> {
        let (code, len) = table.encode_sym(sym).ok_or(StegError::CorruptedFile)?;
        self.write_bits(code, len);
        Ok(())
    }

    fn write_value(&mut self, value: i16, cat: u8) {
        if cat == 0 {
            return;
        }
        let raw: u16 = if value >= 0 {
            value as u16
        } else {
            // Negative: one's complement in category range
            ((1i16 << cat) - 1 + value) as u16
        };
        self.write_bits(raw, cat);
    }

    /// Flush remaining bits (pad with 1s to byte boundary — JPEG spec).
    fn flush(&mut self) {
        if self.bits > 0 {
            let pad = 8 - self.bits;
            let byte = (((self.buf << pad) | ((1u64 << pad) - 1)) & 0xFF) as u8;
            self.out.push(byte);
            if byte == 0xFF {
                self.out.push(0x00);
            }
            self.bits = 0;
            self.buf = 0;
        }
    }

    fn finish(mut self) -> Vec<u8> {
        self.flush();
        self.out
    }
}

// ── JPEG structural types ─────────────────────────────────────────────────────

#[derive(Clone, Default)]
struct FrameComponent {
    id: u8,
    h_samp: u8,
    v_samp: u8,
    #[allow(dead_code)]
    qt_id: u8,
}

#[derive(Clone, Default)]
struct ScanComponent {
    comp_id: u8,
    dc_table: u8,
    ac_table: u8,
}

struct JpegContext {
    /// Header bytes: everything up to and including the SOS header (not entropy data)
    header: Vec<u8>,
    /// Raw entropy bytes (after SOS header, before EOI)
    entropy: Vec<u8>,
    /// EOI bytes (0xFF 0xD9)
    trailer: Vec<u8>,

    frame_comps: Vec<FrameComponent>,
    scan_comps: Vec<ScanComponent>,
    dc_tables: HashMap<u8, HuffTable>,
    ac_tables: HashMap<u8, HuffTable>,
    restart_interval: u16,
    width: u16,
    height: u16,
}

// ── JPEG parser ───────────────────────────────────────────────────────────────

fn parse_jpeg(data: &[u8]) -> Result<JpegContext, StegError> {
    if data.len() < 2 || data[0] != 0xFF || data[1] != 0xD8 {
        return Err(StegError::UnsupportedFormat("not a JPEG".into()));
    }

    let mut ctx = JpegContext {
        header: Vec::new(),
        entropy: Vec::new(),
        trailer: vec![0xFF, 0xD9],
        frame_comps: Vec::new(),
        scan_comps: Vec::new(),
        dc_tables: HashMap::new(),
        ac_tables: HashMap::new(),
        restart_interval: 0,
        width: 0,
        height: 0,
    };

    let mut i = 0usize;

    while i < data.len() {
        // Expect a marker (0xFF xx)
        if data[i] != 0xFF {
            return Err(StegError::CorruptedFile);
        }
        // Skip any 0xFF padding bytes
        while i < data.len() && data[i] == 0xFF {
            i += 1;
        }
        if i >= data.len() {
            break;
        }
        let marker_byte = data[i];
        i += 1;
        let marker = 0xFF00u16 | (marker_byte as u16);

        match marker {
            m if m == SOI => {
                ctx.header.extend_from_slice(&[0xFF, 0xD8]);
            }
            m if m == EOI => {
                // We're done — stop parsing
                break;
            }
            m if (RST0..=RST7).contains(&m) => {
                // Restart markers inside entropy data — handled during decode
                ctx.header.extend_from_slice(&[0xFF, marker_byte]);
            }
            m if m == SOS => {
                // Read the SOS segment header (length-prefixed)
                if i + 2 > data.len() {
                    return Err(StegError::CorruptedFile);
                }
                let seg_len = u16::from_be_bytes([data[i], data[i + 1]]) as usize;
                if i + seg_len > data.len() {
                    return Err(StegError::CorruptedFile);
                }
                let seg = &data[i..i + seg_len];

                // Parse scan components
                if seg.len() < 3 {
                    return Err(StegError::CorruptedFile);
                }
                let n_comps = seg[2] as usize;
                if seg.len() < 3 + n_comps * 2 {
                    return Err(StegError::CorruptedFile);
                }
                ctx.scan_comps.clear();
                for c in 0..n_comps {
                    let base = 3 + c * 2;
                    ctx.scan_comps.push(ScanComponent {
                        comp_id: seg[base],
                        dc_table: seg[base + 1] >> 4,
                        ac_table: seg[base + 1] & 0x0F,
                    });
                }

                // Append SOS segment to header
                ctx.header.extend_from_slice(&[0xFF, 0xDA]);
                ctx.header.extend_from_slice(&data[i..i + seg_len]);
                i += seg_len;

                // Everything from here until the next 0xFF xx (non-stuffed) is entropy data.
                let entropy_start = i;
                let mut j = i;
                while j < data.len() {
                    if data[j] == 0xFF {
                        if j + 1 < data.len() {
                            let next = data[j + 1];
                            if next == 0x00 {
                                // Byte stuffing — skip both bytes
                                j += 2;
                                continue;
                            } else if (0xD0..=0xD7).contains(&next) {
                                // RST marker inside entropy — include it
                                j += 2;
                                continue;
                            } else {
                                // Real marker — entropy data ends here
                                break;
                            }
                        } else {
                            break;
                        }
                    }
                    j += 1;
                }
                ctx.entropy = data[entropy_start..j].to_vec();
                i = j;
                // Don't break yet — there may be more segments (unlikely but valid)
            }
            m if m == DHT => {
                if i + 2 > data.len() {
                    return Err(StegError::CorruptedFile);
                }
                let seg_len = u16::from_be_bytes([data[i], data[i + 1]]) as usize;
                if i + seg_len > data.len() {
                    return Err(StegError::CorruptedFile);
                }
                let seg = &data[i + 2..i + seg_len]; // skip length field
                ctx.header.extend_from_slice(&[0xFF, 0xC4]);
                ctx.header.extend_from_slice(&data[i..i + seg_len]);
                i += seg_len;

                // Parse one or more Huffman tables in this segment
                let mut k = 0usize;
                while k < seg.len() {
                    if k + 17 > seg.len() {
                        break;
                    }
                    let tc_th = seg[k]; // Tc (0=DC, 1=AC) in high nibble, Th in low nibble
                    let tc = (tc_th >> 4) & 0x0F;
                    let th = tc_th & 0x0F;
                    k += 1;

                    let mut bits = [0u8; 16];
                    bits.copy_from_slice(&seg[k..k + 16]);
                    k += 16;

                    let total_vals: usize = bits.iter().map(|&b| b as usize).sum();
                    if k + total_vals > seg.len() {
                        return Err(StegError::CorruptedFile);
                    }
                    let huffval = &seg[k..k + total_vals];
                    k += total_vals;

                    let table = HuffTable::from_jpeg(&bits, huffval);
                    if tc == 0 {
                        ctx.dc_tables.insert(th, table);
                    } else {
                        ctx.ac_tables.insert(th, table);
                    }
                }
            }
            m if m == DQT => {
                if i + 2 > data.len() {
                    return Err(StegError::CorruptedFile);
                }
                let seg_len = u16::from_be_bytes([data[i], data[i + 1]]) as usize;
                ctx.header.extend_from_slice(&[0xFF, 0xDB]);
                ctx.header.extend_from_slice(&data[i..i + seg_len]);
                i += seg_len;
            }
            m if m == SOF0 || m == SOF1 => {
                if i + 2 > data.len() {
                    return Err(StegError::CorruptedFile);
                }
                let seg_len = u16::from_be_bytes([data[i], data[i + 1]]) as usize;
                if i + seg_len > data.len() {
                    return Err(StegError::CorruptedFile);
                }
                let seg = &data[i..i + seg_len];

                if seg.len() >= 9 {
                    ctx.height = u16::from_be_bytes([seg[3], seg[4]]);
                    ctx.width = u16::from_be_bytes([seg[5], seg[6]]);
                    let n_comps = seg[7] as usize;
                    ctx.frame_comps.clear();
                    for c in 0..n_comps {
                        let base = 8 + c * 3;
                        if base + 3 <= seg.len() {
                            ctx.frame_comps.push(FrameComponent {
                                id: seg[base],
                                h_samp: (seg[base + 1] >> 4) & 0x0F,
                                v_samp: seg[base + 1] & 0x0F,
                                qt_id: seg[base + 2],
                            });
                        }
                    }
                }

                ctx.header.extend_from_slice(&[0xFF, marker_byte]);
                ctx.header.extend_from_slice(&data[i..i + seg_len]);
                i += seg_len;
            }
            m if m == DRI => {
                if i + 4 > data.len() {
                    return Err(StegError::CorruptedFile);
                }
                ctx.restart_interval = u16::from_be_bytes([data[i + 2], data[i + 3]]);
                let seg_len = u16::from_be_bytes([data[i], data[i + 1]]) as usize;
                ctx.header.extend_from_slice(&[0xFF, 0xDD]);
                ctx.header.extend_from_slice(&data[i..i + seg_len]);
                i += seg_len;
            }
            m if (APP0..=APP15).contains(&m) || m == COM => {
                if i + 2 > data.len() {
                    return Err(StegError::CorruptedFile);
                }
                let seg_len = u16::from_be_bytes([data[i], data[i + 1]]) as usize;
                ctx.header.extend_from_slice(&[0xFF, marker_byte]);
                ctx.header.extend_from_slice(&data[i..i + seg_len]);
                i += seg_len;
            }
            _ => {
                // Unknown marker — preserve as-is if it has a length field
                if i + 2 <= data.len() {
                    let seg_len = u16::from_be_bytes([data[i], data[i + 1]]) as usize;
                    if i + seg_len <= data.len() {
                        ctx.header.extend_from_slice(&[0xFF, marker_byte]);
                        ctx.header.extend_from_slice(&data[i..i + seg_len]);
                        i += seg_len;
                        continue;
                    }
                }
                return Err(StegError::UnsupportedFormat(
                    "unrecognised JPEG marker".into(),
                ));
            }
        }
    }

    Ok(ctx)
}

// ── MCU geometry ──────────────────────────────────────────────────────────────

/// Number of data units (8×8 blocks) per MCU per component.
fn mcu_count(ctx: &JpegContext) -> usize {
    let max_h = ctx.frame_comps.iter().map(|c| c.h_samp).max().unwrap_or(1);
    let max_v = ctx.frame_comps.iter().map(|c| c.v_samp).max().unwrap_or(1);
    let mcu_w = (ctx.width as usize).div_ceil(max_h as usize * 8);
    let mcu_h = (ctx.height as usize).div_ceil(max_v as usize * 8);
    mcu_w * mcu_h
}

// ── Coefficient I/O ───────────────────────────────────────────────────────────

/// Decode all quantized DCT coefficients from the entropy stream.
/// Returns one Vec<[i16;64]> per data unit, ordered by MCU scan order.
fn decode_coefficients(ctx: &JpegContext) -> Result<Vec<Vec<[i16; 64]>>, StegError> {
    let n_comps = ctx.scan_comps.len();

    // Map component id → frame component index
    let fc_map: HashMap<u8, &FrameComponent> =
        ctx.frame_comps.iter().map(|fc| (fc.id, fc)).collect();

    // Per-component DC predictor
    let mut dc_pred = vec![0i16; n_comps];

    // Output: one inner Vec per component
    let mut all_coeffs: Vec<Vec<[i16; 64]>> = vec![Vec::new(); n_comps];

    let total_mcu = mcu_count(ctx);

    let mut reader = BitReader::new(&ctx.entropy);
    let mut restart_count: u16 = 0;

    for _mcu_idx in 0..total_mcu {
        // Restart interval handling
        if ctx.restart_interval > 0 && restart_count == ctx.restart_interval {
            // The BitReader will have stopped at the RST marker.
            // Consume the marker (2 bytes of 0xFF Dn already in stream).
            // Reset DC predictors.
            for pred in dc_pred.iter_mut() {
                *pred = 0;
            }
            restart_count = 0;
            // Flush the bit buffer completely — RST markers sit at byte boundaries.
            reader.bits = 0;
            reader.buf = 0;
            // Skip past the RST marker bytes in the raw data stream.
            // refill() stopped consuming when it hit 0xFF; the marker byte (0xDn)
            // is at reader.pos. Advance past it.
            if reader.pos < reader.data.len() {
                // The 0xFF was consumed by refill but not added to buf.
                // The 0xDn marker byte is next.
                reader.pos += 1; // skip the 0xDn byte
            }
        }

        for (ci, sc) in ctx.scan_comps.iter().enumerate() {
            let fc = fc_map.get(&sc.comp_id).ok_or(StegError::CorruptedFile)?;

            let h_samp = fc.h_samp.max(1) as usize;
            let v_samp = fc.v_samp.max(1) as usize;
            let du_count = h_samp * v_samp;

            let dc_table = ctx
                .dc_tables
                .get(&sc.dc_table)
                .ok_or(StegError::CorruptedFile)?;
            let ac_table = ctx
                .ac_tables
                .get(&sc.ac_table)
                .ok_or(StegError::CorruptedFile)?;

            for _du in 0..du_count {
                let mut block = [0i16; 64];

                // DC coefficient
                let dc_cat = reader.decode_huffman(dc_table)?;
                let dc_diff = reader.read_value(dc_cat)?;
                dc_pred[ci] = dc_pred[ci].wrapping_add(dc_diff);
                block[ZIGZAG[0]] = dc_pred[ci];

                // AC coefficients
                let mut k = 1usize;
                while k < 64 {
                    let rs = reader.decode_huffman(ac_table)?;
                    if rs == 0x00 {
                        // EOB — rest of block is zero
                        break;
                    }
                    if rs == 0xF0 {
                        // ZRL — 16 zero coefficients
                        k += 16;
                        continue;
                    }
                    let run = (rs >> 4) as usize;
                    let cat = rs & 0x0F;
                    k += run;
                    if k >= 64 {
                        return Err(StegError::CorruptedFile);
                    }
                    let val = reader.read_value(cat)?;
                    block[ZIGZAG[k]] = val;
                    k += 1;
                }

                all_coeffs[ci].push(block);
            }
        }

        restart_count += 1;
    }

    Ok(all_coeffs)
}

/// Re-encode all quantized DCT coefficients back to a JPEG entropy stream.
fn encode_coefficients(
    ctx: &JpegContext,
    all_coeffs: &[Vec<[i16; 64]>],
) -> Result<Vec<u8>, StegError> {
    let n_comps = ctx.scan_comps.len();
    let fc_map: HashMap<u8, &FrameComponent> =
        ctx.frame_comps.iter().map(|fc| (fc.id, fc)).collect();

    let mut dc_pred = vec![0i16; n_comps];
    // Per-component data unit index
    let mut du_idx = vec![0usize; n_comps];

    let total_mcu = mcu_count(ctx);
    let mut writer = BitWriter::new();
    let mut restart_count: u16 = 0;
    let mut rst_sequence: u8 = 0; // cycles 0..7 for RST0..RST7

    for _mcu_idx in 0..total_mcu {
        if ctx.restart_interval > 0 && restart_count == ctx.restart_interval {
            writer.flush();
            // Write RST marker (cycle RST0..RST7)
            writer
                .out
                .extend_from_slice(&[0xFF, 0xD0 + (rst_sequence % 8)]);
            rst_sequence = rst_sequence.wrapping_add(1);
            for pred in dc_pred.iter_mut() {
                *pred = 0;
            }
            restart_count = 0;
        }

        for (ci, sc) in ctx.scan_comps.iter().enumerate() {
            let fc = fc_map.get(&sc.comp_id).ok_or(StegError::CorruptedFile)?;

            let h_samp = fc.h_samp.max(1) as usize;
            let v_samp = fc.v_samp.max(1) as usize;
            let du_count = h_samp * v_samp;

            let dc_table = ctx
                .dc_tables
                .get(&sc.dc_table)
                .ok_or(StegError::CorruptedFile)?;
            let ac_table = ctx
                .ac_tables
                .get(&sc.ac_table)
                .ok_or(StegError::CorruptedFile)?;

            for _du in 0..du_count {
                let idx = du_idx[ci];
                if idx >= all_coeffs[ci].len() {
                    return Err(StegError::CorruptedFile);
                }
                let block = &all_coeffs[ci][idx];
                du_idx[ci] += 1;

                // DC
                let dc_val = block[ZIGZAG[0]];
                let dc_diff = dc_val.wrapping_sub(dc_pred[ci]);
                dc_pred[ci] = dc_val;
                let cat = category(dc_diff);
                writer.write_huffman(cat, dc_table)?;
                writer.write_value(dc_diff, cat);

                // AC — re-compute run-length coding from the block
                let mut k = 1usize;
                while k < 64 {
                    // Count zeros before next non-zero
                    let run_start = k;
                    while k < 64 && block[ZIGZAG[k]] == 0 {
                        k += 1;
                    }
                    if k == 64 {
                        // EOB
                        writer.write_huffman(0x00, ac_table)?;
                        break;
                    }
                    let mut run = k - run_start;
                    // Emit ZRL tokens for runs ≥ 16
                    while run >= 16 {
                        writer.write_huffman(0xF0, ac_table)?;
                        run -= 16;
                    }
                    let val = block[ZIGZAG[k]];
                    let cat = category(val);
                    let rs = ((run as u8) << 4) | cat;
                    writer.write_huffman(rs, ac_table)?;
                    writer.write_value(val, cat);
                    k += 1;
                }
            }
        }

        restart_count += 1;
    }

    Ok(writer.finish())
}

/// Value category = bit width of |value|, clamped to 0..=15.
fn category(value: i16) -> u8 {
    if value == 0 {
        return 0;
    }
    let abs = value.unsigned_abs();
    let cat = (16u32 - abs.leading_zeros()) as u8;
    cat.min(15)
}

// ── Eligible coefficient positions ───────────────────────────────────────────

/// Collect (component_index, data_unit_index, coefficient_index_in_block) for
/// every AC coefficient whose |value| >= 2 — these are safe to modify.
fn eligible_positions(all_coeffs: &[Vec<[i16; 64]>]) -> Vec<(usize, usize, usize)> {
    let mut positions = Vec::new();
    for (ci, blocks) in all_coeffs.iter().enumerate() {
        for (di, block) in blocks.iter().enumerate() {
            // k=0 is the DC coefficient — skip it
            for k in 1..64 {
                let v = block[ZIGZAG[k]].abs();
                if v >= 2 {
                    positions.push((ci, di, k));
                }
            }
        }
    }
    positions
}

/// Permute the eligible positions list using ChaCha8 seeded from passphrase.
fn permute_positions(
    mut positions: Vec<(usize, usize, usize)>,
    passphrase: &[u8],
) -> Vec<(usize, usize, usize)> {
    // XOR-fold the passphrase into the seed to preserve entropy from the
    // full passphrase rather than silently truncating at 32 bytes.
    let mut seed = [0u8; 32];
    for (i, &b) in passphrase.iter().enumerate() {
        seed[i % 32] ^= b;
    }
    let mut rng = ChaCha8Rng::from_seed(seed);
    positions.shuffle(&mut rng);
    positions
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Capacity: how many bytes can be hidden in this JPEG.
pub fn jpeg_capacity(data: &[u8]) -> Result<usize, StegError> {
    let ctx = parse_jpeg(data)?;
    let all_coeffs = decode_coefficients(&ctx)?;
    let positions = eligible_positions(&all_coeffs);
    Ok(positions.len() / 8)
}

/// Embed `payload` bytes into `jpeg_data`, using the passphrase to permute
/// coefficient selection.  Returns the modified JPEG bytes.
pub fn embed_jpeg(
    jpeg_data: &[u8],
    payload: &[u8],
    passphrase: &[u8],
) -> Result<Vec<u8>, StegError> {
    if payload.is_empty() {
        return Err(StegError::EmptyPayload);
    }

    let ctx = parse_jpeg(jpeg_data)?;
    let mut all_coeffs = decode_coefficients(&ctx)?;

    let raw_positions = eligible_positions(&all_coeffs);
    let positions = permute_positions(raw_positions, passphrase);

    // We need 64 bits (8 bytes) for the length prefix + 8 bits per payload byte
    let bits_needed = (4 + payload.len()) * 8; // 4-byte length prefix
    if positions.len() < bits_needed {
        return Err(StegError::InsufficientCapacity {
            required: bits_needed,
            available: positions.len(),
        });
    }

    // Build bit stream: [32-bit payload length BE][payload bytes]
    let mut bit_stream: Vec<u8> = Vec::with_capacity(4 + payload.len());
    let len_bytes = (payload.len() as u32).to_be_bytes();
    bit_stream.extend_from_slice(&len_bytes);
    bit_stream.extend_from_slice(payload);

    // Embed bits into coefficient LSBs
    for (bit_idx, &(ci, di, k)) in positions.iter().enumerate().take(bits_needed) {
        let byte_idx = bit_idx / 8;
        let bit_pos = 7 - (bit_idx % 8);
        let bit = (bit_stream[byte_idx] >> bit_pos) & 1;

        let coeff = &mut all_coeffs[ci][di][ZIGZAG[k]];
        // Preserve sign: set LSB of absolute value
        if *coeff > 0 {
            *coeff = (*coeff & !1) | (bit as i16);
        } else {
            // Negative: flip sign, set LSB, flip back
            let abs_val = (-*coeff & !1) | (bit as i16);
            *coeff = -abs_val;
        }
    }

    let new_entropy = encode_coefficients(&ctx, &all_coeffs)?;

    let mut out = Vec::with_capacity(ctx.header.len() + new_entropy.len() + 2);
    out.extend_from_slice(&ctx.header);
    out.extend_from_slice(&new_entropy);
    out.extend_from_slice(&ctx.trailer); // EOI
    Ok(out)
}

/// Extract bytes previously embedded by `embed_jpeg`.
pub fn extract_jpeg(jpeg_data: &[u8], passphrase: &[u8]) -> Result<Vec<u8>, StegError> {
    let ctx = parse_jpeg(jpeg_data)?;
    let all_coeffs = decode_coefficients(&ctx)?;

    let raw_positions = eligible_positions(&all_coeffs);
    let positions = permute_positions(raw_positions, passphrase);

    if positions.len() < 32 {
        return Err(StegError::NoPayloadFound);
    }

    // Read 32-bit length prefix
    let mut len_bits = 0u32;
    for &(ci, di, k) in positions.iter().take(32) {
        let coeff = all_coeffs[ci][di][ZIGZAG[k]];
        let lsb = (coeff.abs() & 1) as u32;
        len_bits = (len_bits << 1) | lsb;
    }

    let payload_len = len_bits as usize;
    // Cap payload to what the coefficients can actually hold, minus the
    // 4-byte length prefix. Also reject zero and anything over 16 MB.
    let max_payload = positions.len().saturating_sub(32) / 8;
    if payload_len == 0 || payload_len > max_payload || payload_len > 16_000_000 {
        return Err(StegError::NoPayloadFound);
    }

    let bits_needed = (4 + payload_len) * 8;
    if positions.len() < bits_needed {
        return Err(StegError::NoPayloadFound);
    }

    // Read payload bytes
    let mut payload = vec![0u8; payload_len];
    for bit_idx in 0..payload_len * 8 {
        let pos_idx = 32 + bit_idx;
        let (ci, di, k) = positions[pos_idx];
        let coeff = all_coeffs[ci][di][ZIGZAG[k]];
        let lsb = (coeff.abs() & 1) as u8;
        let byte_idx = bit_idx / 8;
        let bit_pos = 7 - (bit_idx % 8);
        payload[byte_idx] |= lsb << bit_pos;
    }

    Ok(payload)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal valid 8×8 grayscale JPEG with known Huffman tables.
    /// Generated by encoding a flat grey image and capturing the bytes.
    fn tiny_jpeg() -> Vec<u8> {
        // This is a 8×8 pixel solid grey JPEG generated by the `image` crate.
        // We construct it programmatically to avoid shipping test fixtures.
        use image::{GrayImage, Luma};
        let mut img = GrayImage::new(64, 64);
        // Fill with varied content so we have enough high-variance coefficients.
        for y in 0..64u32 {
            for x in 0..64u32 {
                let v = ((x * 4 + y * 3) % 256) as u8;
                img.put_pixel(x, y, Luma([v]));
            }
        }
        let mut buf = std::io::Cursor::new(Vec::new());
        img.write_to(&mut buf, image::ImageFormat::Jpeg).unwrap();
        buf.into_inner()
    }

    fn varied_rgb_jpeg() -> Vec<u8> {
        use image::{ImageBuffer, Rgb};
        let mut img: ImageBuffer<Rgb<u8>, Vec<u8>> = ImageBuffer::new(128, 128);
        for y in 0..128u32 {
            for x in 0..128u32 {
                let r = ((x * 3 + y * 7) % 256) as u8;
                let g = ((x * 5 + y * 11) % 256) as u8;
                let b = ((x * 7 + y * 13) % 256) as u8;
                img.put_pixel(x, y, Rgb([r, g, b]));
            }
        }
        let mut buf = std::io::Cursor::new(Vec::new());
        img.write_to(&mut buf, image::ImageFormat::Jpeg).unwrap();
        buf.into_inner()
    }

    #[test]
    fn parse_valid_jpeg() {
        let jpeg = tiny_jpeg();
        let ctx = parse_jpeg(&jpeg).expect("parse failed");
        assert!(!ctx.dc_tables.is_empty(), "no DC tables");
        assert!(!ctx.ac_tables.is_empty(), "no AC tables");
        assert!(!ctx.entropy.is_empty(), "no entropy data");
    }

    #[test]
    fn parse_invalid_bytes_returns_error() {
        let result = parse_jpeg(b"not a jpeg");
        assert!(matches!(result, Err(StegError::UnsupportedFormat(_))));
    }

    #[test]
    fn decode_reencode_roundtrip() {
        // Decode and re-encode without modification — output should be valid.
        let jpeg = tiny_jpeg();
        let ctx = parse_jpeg(&jpeg).expect("parse failed");
        let coeffs = decode_coefficients(&ctx).expect("decode failed");
        let new_entropy = encode_coefficients(&ctx, &coeffs).expect("encode failed");

        // Build the new JPEG
        let mut rebuilt = Vec::new();
        rebuilt.extend_from_slice(&ctx.header);
        rebuilt.extend_from_slice(&new_entropy);
        rebuilt.extend_from_slice(&ctx.trailer);

        // Verify it's a valid JPEG by parsing again
        let ctx2 = parse_jpeg(&rebuilt).expect("rebuilt JPEG is invalid");
        let coeffs2 = decode_coefficients(&ctx2).expect("decode of rebuilt failed");

        // Coefficient values should be identical
        assert_eq!(coeffs.len(), coeffs2.len());
        for (c1, c2) in coeffs.iter().zip(coeffs2.iter()) {
            assert_eq!(c1.len(), c2.len());
            for (b1, b2) in c1.iter().zip(c2.iter()) {
                assert_eq!(b1, b2, "coefficient mismatch after re-encode");
            }
        }
    }

    #[test]
    fn embed_extract_roundtrip_grayscale() {
        let jpeg = tiny_jpeg();
        let payload = b"steganography test payload";
        let passphrase = b"test-passphrase";

        let stego = embed_jpeg(&jpeg, payload, passphrase).expect("embed failed");
        assert_ne!(stego, jpeg, "stego should differ from original");

        let extracted = extract_jpeg(&stego, passphrase).expect("extract failed");
        assert_eq!(extracted, payload);
    }

    #[test]
    fn embed_extract_roundtrip_rgb() {
        let jpeg = varied_rgb_jpeg();
        let payload = b"rgb jpeg round trip test";
        let passphrase = b"another-passphrase";

        let stego = embed_jpeg(&jpeg, payload, passphrase).expect("embed failed");
        let extracted = extract_jpeg(&stego, passphrase).expect("extract failed");
        assert_eq!(extracted, payload);
    }

    #[test]
    fn wrong_passphrase_returns_wrong_data() {
        let jpeg = varied_rgb_jpeg();
        let payload = b"secret message";

        let stego = embed_jpeg(&jpeg, payload, b"correct-pass").expect("embed failed");
        // Wrong passphrase reads different bit positions — should not return the correct payload
        let result = extract_jpeg(&stego, b"wrong-pass");
        if let Ok(extracted) = result {
            assert_ne!(extracted, payload, "wrong passphrase returned correct data")
        }
    }

    #[test]
    fn empty_payload_returns_error() {
        let jpeg = tiny_jpeg();
        let result = embed_jpeg(&jpeg, b"", b"pass");
        assert!(matches!(result, Err(StegError::EmptyPayload)));
    }

    #[test]
    fn capacity_is_positive() {
        let jpeg = varied_rgb_jpeg();
        let cap = jpeg_capacity(&jpeg).expect("capacity failed");
        assert!(cap > 0, "expected positive capacity");
    }

    #[test]
    fn embed_large_payload_roundtrip() {
        let jpeg = varied_rgb_jpeg();
        let cap = jpeg_capacity(&jpeg).expect("capacity failed");
        // Embed a payload that fills roughly half capacity
        let payload_size = (cap / 2).min(1000);
        let payload: Vec<u8> = (0..payload_size).map(|i| (i % 256) as u8).collect();
        let passphrase = b"large-payload-test";

        let stego = embed_jpeg(&jpeg, &payload, passphrase).expect("embed failed");
        let extracted = extract_jpeg(&stego, passphrase).expect("extract failed");
        assert_eq!(extracted, payload);
    }

    #[test]
    fn stego_jpeg_is_valid_jpeg() {
        let jpeg = varied_rgb_jpeg();
        let stego = embed_jpeg(&jpeg, b"hello world", b"pass").expect("embed failed");
        // Verify it starts with SOI and ends with EOI
        assert_eq!(&stego[..2], &[0xFF, 0xD8], "missing SOI");
        assert_eq!(&stego[stego.len() - 2..], &[0xFF, 0xD9], "missing EOI");
        // Verify it can be opened as an image
        let result = image::load_from_memory_with_format(&stego, image::ImageFormat::Jpeg);
        assert!(
            result.is_ok(),
            "stego JPEG is not readable: {:?}",
            result.err()
        );
    }

    #[test]
    fn category_values() {
        assert_eq!(category(0), 0);
        assert_eq!(category(1), 1);
        assert_eq!(category(-1), 1);
        assert_eq!(category(2), 2);
        assert_eq!(category(-2), 2);
        assert_eq!(category(3), 2);
        assert_eq!(category(4), 3);
        assert_eq!(category(127), 7);
        assert_eq!(category(-128), 8);
        assert_eq!(category(1023), 10);
        // i16::MIN = -32768 has unsigned_abs() = 32768 whose leading_zeros() = 0,
        // giving raw category = 16.  The .min(15) cap must clamp it to 15.
        assert_eq!(category(i16::MIN), 15);
        assert_eq!(category(i16::MAX), 15);
    }
}
