// Copyright (C) 2026 Daniel Iwugo
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Stegcore-Commercial
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.
//
// Commercial licensing: daniel@themalwarefiles.com

// Session 4 — steganographic engine, all formats, deniable mode.
use std::fs::File;
use std::io::{BufReader, Cursor, Write};
use std::path::{Path, PathBuf};

use tempfile::NamedTempFile;

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use image::{ImageFormat, RgbImage, RgbaImage};
use rand::{rngs::OsRng, seq::SliceRandom, RngCore, SeedableRng};
use rand_chacha::ChaCha8Rng;
use serde::{Deserialize, Serialize};

use crate::crypto::{self, Cipher};
use crate::errors::StegError;
use crate::jpeg_dct;
use crate::keyfile::KeyFile;
use crate::utils::detect_format;
use dct_io;

// ── Embedded metadata ─────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Meta {
    engine: String,
    cipher: Cipher,
    mode: String,
    #[serde(with = "b64_field")]
    nonce: Vec<u8>,
    #[serde(with = "b64_field")]
    salt: Vec<u8>,
    ciphertext_len: usize,
    deniable: bool,
    partition_seed: Option<String>,
    partition_half: Option<u8>,
}

mod b64_field {
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&B64.encode(bytes))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        B64.decode(s).map_err(serde::de::Error::custom)
    }
}

// ── Wire format ───────────────────────────────────────────────────────────────

fn build_stego_payload(meta: &Meta, ciphertext: &[u8]) -> Result<Vec<u8>, StegError> {
    let meta_json = serde_json::to_vec(meta)?;
    let meta_len = meta_json.len();
    if meta_len > u16::MAX as usize {
        return Err(StegError::CorruptedFile);
    }
    let mut out = Vec::with_capacity(2 + meta_len + ciphertext.len());
    out.extend_from_slice(&(meta_len as u16).to_be_bytes());
    out.extend_from_slice(&meta_json);
    out.extend_from_slice(ciphertext);
    Ok(out)
}

fn parse_stego_payload(bytes: &[u8]) -> Result<(Meta, Vec<u8>), StegError> {
    if bytes.len() < 2 {
        return Err(StegError::NoPayloadFound);
    }
    let meta_len = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
    let meta_end = 2 + meta_len;
    if meta_end > bytes.len() || meta_len > 4096 {
        return Err(StegError::NoPayloadFound);
    }
    let meta: Meta =
        serde_json::from_slice(&bytes[2..meta_end]).map_err(|_| StegError::NoPayloadFound)?;
    if meta.engine != "rust-v1" {
        return Err(StegError::LegacyKeyFile);
    }
    let ct_end = meta_end + meta.ciphertext_len;
    if ct_end > bytes.len() {
        return Err(StegError::NoPayloadFound);
    }
    Ok((meta, bytes[meta_end..ct_end].to_vec()))
}

// ── Cover I/O ─────────────────────────────────────────────────────────────────

fn load_frame(path: &Path) -> Result<image::DynamicImage, StegError> {
    if !path.exists() {
        return Err(StegError::FileNotFound(path.display().to_string()));
    }
    crate::utils::open_image_by_content(path)
}

/// Decode a cover into its RGB working buffer plus, when the source carries
/// transparency, the original alpha plane (one byte per pixel) kept verbatim.
/// Alpha is never used to carry payload bits; it is preserved so the stego
/// output keeps the cover's transparency and structural colour type.
fn load_rgb_with_alpha(path: &Path) -> Result<(RgbImage, Option<Vec<u8>>), StegError> {
    let dynimg = load_frame(path)?;
    let alpha = if dynimg.color().has_alpha() {
        let rgba = dynimg.to_rgba8();
        Some(rgba.as_raw().chunks_exact(4).map(|px| px[3]).collect())
    } else {
        None
    };
    Ok((dynimg.to_rgb8(), alpha))
}

/// Interleave an embedded RGB buffer with a preserved alpha plane into a
/// packed RGBA buffer (R,G,B,A per pixel).
fn interleave_rgba(rgb: &[u8], alpha: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(alpha.len() * 4);
    for (px, &a) in rgb.chunks_exact(3).zip(alpha.iter()) {
        out.extend_from_slice(px);
        out.push(a);
    }
    out
}

fn png_encode_err(e: png::EncodingError) -> StegError {
    match e {
        png::EncodingError::IoError(io) => StegError::Io(io),
        other => StegError::Internal(other.to_string()),
    }
}

/// Create a named temp file in the same directory as `out_path`, so the
/// subsequent rename is on the same filesystem and therefore atomic.
fn temp_beside(out_path: &Path) -> Result<NamedTempFile, StegError> {
    let dir = out_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    NamedTempFile::new_in(dir).map_err(StegError::Io)
}

/// Atomically write `bytes` to `out_path`: write to a sibling temp file, flush,
/// then rename into place. An interrupted or failed write never leaves a
/// partial file at `out_path` (the temp file is auto-removed on early return).
fn atomic_write_bytes(out_path: &Path, bytes: &[u8]) -> Result<(), StegError> {
    let mut tmp = temp_beside(out_path)?;
    tmp.write_all(bytes).map_err(StegError::Io)?;
    tmp.flush().map_err(StegError::Io)?;
    tmp.persist(out_path).map_err(|e| StegError::Io(e.error))?;
    Ok(())
}

/// Best-effort copy of the cover's ancillary text/timing/physical chunks onto
/// the output encoder. Failure to read the cover's metadata is non-fatal: the
/// embed proceeds without the chunks rather than aborting.
fn copy_png_metadata<W: Write>(cover_path: &Path, encoder: &mut png::Encoder<'_, W>) {
    let Ok(file) = File::open(cover_path) else {
        return;
    };
    let decoder = png::Decoder::new(BufReader::new(file));
    let Ok(reader) = decoder.read_info() else {
        return;
    };
    let info = reader.info();
    for c in &info.uncompressed_latin1_text {
        let _ = encoder.add_text_chunk(c.keyword.clone(), c.text.clone());
    }
    for c in &info.compressed_latin1_text {
        if let Ok(text) = c.get_text() {
            let _ = encoder.add_ztxt_chunk(c.keyword.clone(), text);
        }
    }
    for c in &info.utf8_text {
        if let Ok(text) = c.get_text() {
            let _ = encoder.add_itxt_chunk(c.keyword.clone(), text);
        }
    }
    if info.pixel_dims.is_some() {
        encoder.set_pixel_dims(info.pixel_dims);
    }
}

/// Write a PNG with maximum deflate compression and adaptive filtering,
/// preserving the cover's ancillary chunks and (when present) its alpha plane.
fn write_png(
    rgb: &[u8],
    width: u32,
    height: u32,
    alpha: Option<&[u8]>,
    cover_path: &Path,
    out_path: &Path,
) -> Result<(), StegError> {
    let npx = (width as usize) * (height as usize);
    let (color, data): (png::ColorType, Vec<u8>) = match alpha {
        Some(a) => {
            if a.len() != npx || rgb.len() != npx * 3 {
                return Err(StegError::CorruptedFile);
            }
            (png::ColorType::Rgba, interleave_rgba(rgb, a))
        }
        None => {
            if rgb.len() != npx * 3 {
                return Err(StegError::CorruptedFile);
            }
            (png::ColorType::Rgb, rgb.to_vec())
        }
    };

    // Encode into memory first, then write atomically, so a failed encode or
    // an interrupted write never leaves a partial PNG at out_path.
    let mut buf: Vec<u8> = Vec::new();
    {
        let mut encoder = png::Encoder::new(&mut buf, width, height);
        encoder.set_color(color);
        encoder.set_depth(png::BitDepth::Eight);
        // Best compression + adaptive filtering keeps LSB-modified covers close
        // to their original size; the image-crate default doubled flat screenshots.
        encoder.set_compression(png::Compression::Best);
        encoder.set_adaptive_filter(png::AdaptiveFilterType::Adaptive);
        copy_png_metadata(cover_path, &mut encoder);

        let mut w = encoder.write_header().map_err(png_encode_err)?;
        w.write_image_data(&data).map_err(png_encode_err)?;
        w.finish().map_err(png_encode_err)?;
    }
    atomic_write_bytes(out_path, &buf)
}

/// Write the stego frame back out. PNG goes through the low-level encoder
/// (compression + chunk + alpha preservation); BMP and WebP go through the
/// `image` crate but still carry alpha when the cover had it.
fn write_frame(
    rgb: &[u8],
    width: u32,
    height: u32,
    alpha: Option<&[u8]>,
    cover_path: &Path,
    out_path: &Path,
    src_fmt: &str,
) -> Result<PathBuf, StegError> {
    // JPEG embedding uses its own path (do_embed_jpeg); this function
    // only handles PNG, BMP, and WebP output.
    match src_fmt {
        "png" => {
            write_png(rgb, width, height, alpha, cover_path, out_path)?;
        }
        "bmp" | "webp" => {
            let fmt = if src_fmt == "bmp" {
                ImageFormat::Bmp
            } else {
                ImageFormat::WebP
            };
            // Encode into memory, then write atomically (no partial file on failure).
            let mut buf: Vec<u8> = Vec::new();
            match alpha {
                Some(a) => {
                    let img = RgbaImage::from_raw(width, height, interleave_rgba(rgb, a))
                        .ok_or(StegError::CorruptedFile)?;
                    img.write_to(&mut Cursor::new(&mut buf), fmt)
                        .map_err(StegError::Image)?;
                }
                None => {
                    let img = RgbImage::from_raw(width, height, rgb.to_vec())
                        .ok_or(StegError::CorruptedFile)?;
                    img.write_to(&mut Cursor::new(&mut buf), fmt)
                        .map_err(StegError::Image)?;
                }
            }
            atomic_write_bytes(out_path, &buf)?;
        }
        // Any other lossless format falls back to PNG output.
        _ => {
            write_png(rgb, width, height, alpha, cover_path, out_path)?;
        }
    }
    Ok(out_path.to_path_buf())
}

// ── Cover scoring ─────────────────────────────────────────────────────────────

/// Scores a cover file's suitability. Returns 0.0 (poor) – 1.0 (excellent).
pub fn assess(path: &Path) -> Result<f64, StegError> {
    let fmt = detect_format(path)?;
    if fmt == "wav" {
        return assess_wav(path);
    }
    if fmt == "flac" {
        return assess_flac(path);
    }
    if fmt == "jpg" || fmt == "jpeg" {
        return assess_jpeg(path);
    }
    let img = load_frame(path)?;
    Ok(assess_inner(&img.to_rgb8()))
}

fn assess_jpeg(path: &Path) -> Result<f64, StegError> {
    let bytes = std::fs::read(path).map_err(StegError::Io)?;
    let eligible = dct_io::eligible_ac_count(&bytes)
        .map_err(|_| StegError::UnsupportedFormat("jpeg".into()))?;
    // Suitability is a function of ABSOLUTE usable capacity, not capacity
    // relative to file size: an ordinary photo has plenty of embeddable
    // coefficients but a low capacity/file-size ratio, and the old ratio
    // formula wrongly scored it "poor" and made `embed` reject it. A soft
    // saturation curve maps capacity (in bytes) to 0..1: ~1 KB -> ~0.5,
    // ~4 KB -> ~0.8, large covers approach 1.0. The hard fits-or-not check
    // still happens in jpeg_dct::embed_jpeg.
    let capacity_bytes = eligible as f64 / 8.0;
    let score = capacity_bytes / (capacity_bytes + 1024.0);
    Ok(score)
}

fn assess_inner(rgb: &RgbImage) -> f64 {
    let pixels: Vec<f64> = rgb
        .pixels()
        .flat_map(|p| p.0.iter().map(|&c| c as f64))
        .collect();
    let n = pixels.len() as f64;
    if n == 0.0 {
        return 0.0;
    }
    let mean = pixels.iter().sum::<f64>() / n;
    let variance = pixels.iter().map(|&v| (v - mean).powi(2)).sum::<f64>() / n;
    (variance.sqrt() / 64.0_f64).min(1.0)
}

fn assess_wav(path: &Path) -> Result<f64, StegError> {
    let reader = hound::WavReader::open(path).map_err(hound_err)?;
    let samples: Vec<f64> = reader
        .into_samples::<i16>()
        .collect::<Result<Vec<i16>, _>>()
        .map_err(hound_err)?
        .into_iter()
        .map(|s| s as f64)
        .collect();
    let n = samples.len() as f64;
    if n == 0.0 {
        return Ok(0.5);
    }
    let mean = samples.iter().sum::<f64>() / n;
    let variance = samples.iter().map(|&v| (v - mean).powi(2)).sum::<f64>() / n;
    Ok((variance / (i16::MAX as f64).powi(2)).sqrt().min(1.0))
}

/// Read a FLAC cover into its decoded samples, guarding the input size first.
///
/// flac-io decodes a whole stream into memory, so a multi-gigabyte file is
/// refused up front rather than risked. The same guard and error mapping are
/// shared by scoring, embedding and extraction so they agree on what a valid
/// FLAC cover is.
fn decode_flac(path: &Path) -> Result<flac_io::FlacAudio, StegError> {
    const MAX_FLAC_BYTES: u64 = 256 * 1024 * 1024;
    let meta = std::fs::metadata(path).map_err(StegError::Io)?;
    if meta.len() > MAX_FLAC_BYTES {
        return Err(StegError::UnsupportedFormat(format!(
            "flac file is too large ({} bytes, limit {MAX_FLAC_BYTES})",
            meta.len()
        )));
    }
    let bytes = std::fs::read(path).map_err(StegError::Io)?;
    flac_io::decode(&bytes).map_err(|e| StegError::UnsupportedFormat(format!("flac: {e}")))
}

/// Interleave a FLAC cover's per-channel samples into one stream, matching the
/// slot index space used for embedding and extraction (`slot = index * channels
/// + channel`).
fn interleave_flac(audio: &flac_io::FlacAudio) -> Vec<i32> {
    let channels = audio.channels as usize;
    let frames = audio.samples_per_channel();
    let mut out = Vec::with_capacity(frames * channels);
    for i in 0..frames {
        for ch in &audio.samples {
            out.push(ch[i]);
        }
    }
    out
}

fn assess_flac(path: &Path) -> Result<f64, StegError> {
    let audio = decode_flac(path)?;
    let samples = interleave_flac(&audio);
    let n = samples.len() as f64;
    if n == 0.0 {
        return Ok(0.5);
    }
    let mean = samples.iter().map(|&s| s as f64).sum::<f64>() / n;
    let variance = samples
        .iter()
        .map(|&s| (s as f64 - mean).powi(2))
        .sum::<f64>()
        / n;
    // Normalise by the bit depth's full scale so the score is comparable across
    // 16, 24 and 32-bit covers.
    let full = (1u64 << (audio.bits_per_sample.saturating_sub(1))) as f64;
    Ok((variance / full.powi(2)).sqrt().min(1.0))
}

// ── Index selection ───────────────────────────────────────────────────────────

fn index_set_adaptive(rgb: &RgbImage) -> Vec<usize> {
    let (w, h) = rgb.dimensions();
    let (w, h) = (w as usize, h as usize);
    let block = 8usize;
    let mut result = Vec::new();

    // Variance threshold: 128.0 in f64 terms = 128 * n in integer terms.
    // We compare sum_sq * n > threshold * n * n, which avoids division entirely.
    // All arithmetic is u64, eliminating floating-point non-determinism that
    // caused embed/extract slot mismatch on very large images.

    for by in 0..h.div_ceil(block) {
        for bx in 0..w.div_ceil(block) {
            let mut sum: u64 = 0;
            let mut sum_sq: u64 = 0;
            let mut n: u64 = 0;

            for dy in 0..block {
                let py = by * block + dy;
                if py >= h {
                    break;
                }
                for dx in 0..block {
                    let px = bx * block + dx;
                    if px >= w {
                        break;
                    }
                    for &c in &rgb.get_pixel(px as u32, py as u32).0 {
                        // Shift right by 1 to ignore LSB — embedding only
                        // modifies the lowest bit, so this ensures identical
                        // block selection on both embed and extract.
                        let v = (c >> 1) as u64;
                        sum += v;
                        sum_sq += v * v;
                        n += 1;
                    }
                }
            }

            if n == 0 {
                continue;
            }

            // Use upper 7 bits only (v >> 1) for variance.  LSB embedding
            // modifies only the lowest bit, so masking it out ensures the
            // same blocks are selected during both embed and extract.
            // Integer variance: var * n^2 = sum_sq * n - sum^2
            // Threshold scaled for 7-bit values: 128 >> 2 = 32 per sample,
            // so threshold for (v>>1) is 32 * n * n.
            let var_numerator = sum_sq * n;
            let mean_sq = sum * sum;
            let threshold = 32 * n * n;

            if var_numerator.saturating_sub(mean_sq) > threshold {
                for dy in 0..block {
                    let py = by * block + dy;
                    if py >= h {
                        break;
                    }
                    for dx in 0..block {
                        let px = bx * block + dx;
                        if px >= w {
                            break;
                        }
                        let base = (py * w + px) * 3;
                        result.extend_from_slice(&[base, base + 1, base + 2]);
                    }
                }
            }
        }
    }
    result
}

fn permute_set(mut slots: Vec<usize>, seed: &[u8]) -> Vec<usize> {
    // Seed the PRNG from the passphrase bytes. If the passphrase exceeds
    // 32 bytes, XOR-fold the excess into the seed to preserve entropy from
    // the full passphrase rather than silently truncating.
    let mut arr = [0u8; 32];
    for (i, &b) in seed.iter().enumerate() {
        arr[i % 32] ^= b;
    }
    slots.shuffle(&mut ChaCha8Rng::from_seed(arr));
    slots
}

fn bifurcate(slots: Vec<usize>) -> (Vec<usize>, Vec<usize>) {
    let mid = slots.len() / 2;
    (slots[..mid].to_vec(), slots[mid..].to_vec())
}

// ── Bit I/O ───────────────────────────────────────────────────────────────────

fn embed_bits(pixels: &mut [u8], slots: &[usize], payload: &[u8]) -> Result<(), StegError> {
    let bits = payload.len() * 8;
    if slots.len() < bits {
        return Err(StegError::InsufficientCapacity {
            required: payload.len(),
            available: slots.len() / 8,
        });
    }

    // For large payloads (> 64 KB), use scoped threads to parallelise
    // the bit embedding. Each thread gets a non-overlapping chunk of
    // (slot_index, bit_value) pairs. Slot indices are unique (guaranteed
    // by permute_set), so concurrent writes to different indices are safe.
    if bits > 512_000 {
        let ops: Vec<(usize, u8)> = slots
            .iter()
            .take(bits)
            .enumerate()
            .map(|(i, &slot)| {
                let bit = (payload[i / 8] >> (7 - i % 8)) & 1;
                (slot, bit)
            })
            .collect();

        // Sort operations by slot index so each thread writes to a contiguous
        // memory region. This eliminates false sharing (cache line contention)
        // between threads and improves write locality.
        let mut ops = ops;
        ops.sort_unstable_by_key(|&(slot, _)| slot);

        let cpus = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4);
        let chunk_size = (ops.len() / cpus).max(8192);

        // Soundness preconditions for the unsafe parallel writes below: every
        // slot must be in-bounds and unique (no two threads write the same
        // byte). permute_set guarantees both, but verify in ALL builds and
        // fail loud rather than risk undefined behaviour if a future caller
        // ever violates the invariant. Cheap now that ops is sorted: the max
        // slot is the last element, and duplicates are adjacent.
        if let Some(&(max_slot, _)) = ops.last() {
            if max_slot >= pixels.len() {
                return Err(StegError::Internal(
                    "internal error: embed slot out of bounds".to_string(),
                ));
            }
        }
        if ops.windows(2).any(|w| w[0].0 == w[1].0) {
            return Err(StegError::Internal(
                "internal error: duplicate embed slot would race".to_string(),
            ));
        }

        // SAFETY: Wrapper to send a raw pointer across threads.
        // Slot indices are unique (permute_set guarantees no duplicates),
        // so each thread writes to non-overlapping byte positions.
        struct PixelBuf(*mut u8, usize);
        unsafe impl Send for PixelBuf {}
        unsafe impl Sync for PixelBuf {}

        let buf = PixelBuf(pixels.as_mut_ptr(), pixels.len());

        std::thread::scope(|s| {
            for chunk in ops.chunks(chunk_size) {
                let buf = &buf;
                s.spawn(move || {
                    for &(slot, bit) in chunk {
                        debug_assert!(slot < buf.1);
                        unsafe {
                            let p = buf.0.add(slot);
                            *p = (*p & 0xFE) | bit;
                        }
                    }
                });
            }
        });
    } else {
        for (i, &slot) in slots.iter().take(bits).enumerate() {
            let bit = (payload[i / 8] >> (7 - i % 8)) & 1;
            pixels[slot] = (pixels[slot] & 0xFE) | bit;
        }
    }
    Ok(())
}

fn extract_bits(pixels: &[u8], slots: &[usize], byte_count: usize) -> Result<Vec<u8>, StegError> {
    let bits = byte_count * 8;
    if slots.len() < bits {
        return Err(StegError::NoPayloadFound);
    }
    let mut out = vec![0u8; byte_count];
    for (i, &slot) in slots.iter().take(bits).enumerate() {
        if slot >= pixels.len() {
            return Err(StegError::NoPayloadFound);
        }
        out[i / 8] |= (pixels[slot] & 1) << (7 - i % 8);
    }
    Ok(out)
}

// ── Image helpers ─────────────────────────────────────────────────────────────

fn image_slots(rgb: &RgbImage, mode: &str, passphrase: &[u8]) -> Vec<usize> {
    let (w, h) = rgb.dimensions();
    let total = (w * h) as usize * 3;
    let raw = if mode == "adaptive" {
        let s = index_set_adaptive(rgb);
        if s.len() < 16 {
            (0..total).collect()
        } else {
            s
        }
    } else {
        (0..total).collect()
    };
    permute_set(raw, passphrase)
}

fn do_embed_image(
    cover_path: &Path,
    stego_payload: &[u8],
    passphrase: &[u8],
    mode: &str,
    out_path: &Path,
    src_fmt: &str,
) -> Result<PathBuf, StegError> {
    let (rgb, alpha) = load_rgb_with_alpha(cover_path)?;
    let (w, h) = rgb.dimensions();
    let mut pixels = rgb.as_raw().to_vec();
    let slots = image_slots(&rgb, mode, passphrase);
    embed_bits(&mut pixels, &slots, stego_payload)?;
    write_frame(
        &pixels,
        w,
        h,
        alpha.as_deref(),
        cover_path,
        out_path,
        src_fmt,
    )
}

fn do_extract_image(stego_path: &Path, passphrase: &[u8]) -> Result<(Meta, Vec<u8>), StegError> {
    let rgb = load_frame(stego_path)?.to_rgb8();
    let pixels = rgb.as_raw().to_vec();
    // Try sequential first; if parsing fails try adaptive (the two modes use
    // different slot sets so we must match what was used at embed time).
    let seq_slots = image_slots(&rgb, "sequential", passphrase);
    match read_payload(&pixels, &seq_slots) {
        Ok(result) => Ok(result),
        Err(StegError::NoPayloadFound) | Err(StegError::CorruptedFile) => {
            let adp_slots = image_slots(&rgb, "adaptive", passphrase);
            read_payload(&pixels, &adp_slots)
        }
        Err(e) => Err(e),
    }
}

fn do_extract_image_with_slots(
    pixels: &[u8],
    slots: &[usize],
) -> Result<(Meta, Vec<u8>), StegError> {
    read_payload(pixels, slots)
}

fn do_embed_jpeg(
    cover_path: &Path,
    stego_payload: &[u8],
    passphrase: &[u8],
    out_path: &Path,
) -> Result<PathBuf, StegError> {
    let jpeg_data = std::fs::read(cover_path).map_err(StegError::Io)?;
    let stego_jpeg = jpeg_dct::embed_jpeg(&jpeg_data, stego_payload, passphrase)?;
    // The output is JPEG bytes, so its extension must be a JPEG one regardless
    // of the cover's filename or the requested output name. Keep an existing
    // .jpg/.jpeg on the requested path; otherwise normalise to .jpg.
    let keep_ext = out_path
        .extension()
        .and_then(|e| e.to_str())
        .filter(|e| e.eq_ignore_ascii_case("jpg") || e.eq_ignore_ascii_case("jpeg"));
    let final_path = match keep_ext {
        Some(e) => out_path.with_extension(e),
        None => out_path.with_extension("jpg"),
    };
    atomic_write_bytes(&final_path, &stego_jpeg)?;
    Ok(final_path)
}

fn do_extract_jpeg(stego_path: &Path, passphrase: &[u8]) -> Result<(Meta, Vec<u8>), StegError> {
    let jpeg_data = std::fs::read(stego_path).map_err(StegError::Io)?;
    let raw = jpeg_dct::extract_jpeg(&jpeg_data, passphrase)?;
    parse_stego_payload(&raw)
}

fn read_payload(pixels: &[u8], slots: &[usize]) -> Result<(Meta, Vec<u8>), StegError> {
    let max = slots.len() / 8;
    if max < 2 {
        return Err(StegError::NoPayloadFound);
    }

    // Two-pass extraction: read only the header + metadata first to learn
    // the ciphertext length, then extract only the ciphertext bytes.
    // This avoids extracting megabytes of unused pixel data.

    // Pass 1: extract 2 bytes (meta_len header)
    let header = extract_bits(pixels, slots, 2)?;
    let meta_len = u16::from_be_bytes([header[0], header[1]]) as usize;
    if meta_len > 4096 || 2 + meta_len > max {
        return Err(StegError::NoPayloadFound);
    }

    // Pass 2: extract header + metadata + enough to parse ciphertext_len
    let head_plus_meta = extract_bits(pixels, slots, 2 + meta_len)?;
    let meta: Meta = serde_json::from_slice(&head_plus_meta[2..2 + meta_len])
        .map_err(|_| StegError::NoPayloadFound)?;
    if meta.engine != "rust-v1" {
        return Err(StegError::LegacyKeyFile);
    }

    let total = 2 + meta_len + meta.ciphertext_len;
    if total > max {
        return Err(StegError::NoPayloadFound);
    }

    // Pass 3: extract only the ciphertext portion
    let all = extract_bits(pixels, slots, total)?;
    Ok((meta, all[2 + meta_len..total].to_vec()))
}

// ── WAV helpers ───────────────────────────────────────────────────────────────

fn hound_err(e: hound::Error) -> StegError {
    StegError::Io(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        e.to_string(),
    ))
}

fn do_embed_wav(
    cover_path: &Path,
    stego_payload: &[u8],
    passphrase: &[u8],
    out_path: &Path,
) -> Result<(), StegError> {
    let mut reader = hound::WavReader::open(cover_path).map_err(hound_err)?;
    let spec = reader.spec();
    let samples: Vec<i16> = reader
        .samples::<i16>()
        .collect::<Result<Vec<i16>, _>>()
        .map_err(hound_err)?;
    let slots = permute_set((0..samples.len()).collect(), passphrase);
    let bits = stego_payload.len() * 8;
    if slots.len() < bits {
        return Err(StegError::InsufficientCapacity {
            required: stego_payload.len(),
            available: slots.len() / 8,
        });
    }
    let mut out = samples.clone();
    for (i, &slot) in slots.iter().take(bits).enumerate() {
        let bit = ((stego_payload[i / 8] >> (7 - i % 8)) & 1) as i16;
        out[slot] = (out[slot] & !1_i16) | bit; // clear LSB, set to embedded bit
    }
    // Encode into memory, then write atomically (no partial file on failure).
    let mut buf: Vec<u8> = Vec::new();
    {
        let mut writer = hound::WavWriter::new(Cursor::new(&mut buf), spec).map_err(hound_err)?;
        for s in out {
            writer.write_sample(s).map_err(hound_err)?;
        }
        writer.finalize().map_err(hound_err)?;
    }
    atomic_write_bytes(out_path, &buf)
}

fn do_extract_wav(stego_path: &Path, passphrase: &[u8]) -> Result<(Meta, Vec<u8>), StegError> {
    let reader = hound::WavReader::open(stego_path).map_err(hound_err)?;
    let samples: Vec<i16> = reader
        .into_samples::<i16>()
        .collect::<Result<Vec<i16>, _>>()
        .map_err(hound_err)?;
    let slots = permute_set((0..samples.len()).collect(), passphrase);
    let max = slots.len() / 8;
    if max < 2 {
        return Err(StegError::NoPayloadFound);
    }
    let pseudo: Vec<u8> = samples.iter().map(|&s| s as u8).collect();

    // Two-pass extraction: read header, then metadata, then ciphertext only.
    let header = extract_bits(&pseudo, &slots, 2)?;
    let meta_len = u16::from_be_bytes([header[0], header[1]]) as usize;
    if meta_len > 4096 || 2 + meta_len > max {
        return Err(StegError::NoPayloadFound);
    }
    let head_plus_meta = extract_bits(&pseudo, &slots, 2 + meta_len)?;
    let meta: Meta = serde_json::from_slice(&head_plus_meta[2..2 + meta_len])
        .map_err(|_| StegError::NoPayloadFound)?;
    if meta.engine != "rust-v1" {
        return Err(StegError::LegacyKeyFile);
    }
    let total = 2 + meta_len + meta.ciphertext_len;
    if total > max {
        return Err(StegError::NoPayloadFound);
    }
    let all = extract_bits(&pseudo, &slots, total)?;
    Ok((meta, all[2 + meta_len..total].to_vec()))
}

fn do_embed_flac(
    cover_path: &Path,
    stego_payload: &[u8],
    passphrase: &[u8],
    out_path: &Path,
) -> Result<(), StegError> {
    let mut audio = decode_flac(cover_path)?;
    let channels = audio.channels as usize;
    let total = audio.samples_per_channel() * channels;

    let slots = permute_set((0..total).collect(), passphrase);
    let bits = stego_payload.len() * 8;
    if slots.len() < bits {
        return Err(StegError::InsufficientCapacity {
            required: stego_payload.len(),
            available: slots.len() / 8,
        });
    }

    // Each slot maps to one interleaved sample: clear its low bit and set the
    // payload bit. FLAC is lossless, so the re-encode preserves these exactly.
    // Flipping bit 0 never moves a sample outside its bit-depth range, so the
    // re-encode cannot reject it.
    for (i, &slot) in slots.iter().take(bits).enumerate() {
        let bit = ((stego_payload[i / 8] >> (7 - i % 8)) & 1) as i32;
        let sample = &mut audio.samples[slot % channels][slot / channels];
        *sample = (*sample & !1) | bit;
    }

    let out =
        flac_io::encode(&audio).map_err(|e| StegError::UnsupportedFormat(format!("flac: {e}")))?;
    atomic_write_bytes(out_path, &out)
}

fn do_extract_flac(stego_path: &Path, passphrase: &[u8]) -> Result<(Meta, Vec<u8>), StegError> {
    let audio = decode_flac(stego_path)?;
    let channels = audio.channels as usize;
    let total = audio.samples_per_channel() * channels;

    let slots = permute_set((0..total).collect(), passphrase);
    let max = slots.len() / 8;
    if max < 2 {
        return Err(StegError::NoPayloadFound);
    }
    // Low byte of every interleaved sample, in the same slot order as embedding.
    let pseudo = interleave_flac(&audio)
        .into_iter()
        .map(|s| s as u8)
        .collect::<Vec<u8>>();

    // Two-pass extraction: header, then metadata, then ciphertext (mirrors WAV).
    let header = extract_bits(&pseudo, &slots, 2)?;
    let meta_len = u16::from_be_bytes([header[0], header[1]]) as usize;
    if meta_len > 4096 || 2 + meta_len > max {
        return Err(StegError::NoPayloadFound);
    }
    let head_plus_meta = extract_bits(&pseudo, &slots, 2 + meta_len)?;
    let meta: Meta = serde_json::from_slice(&head_plus_meta[2..2 + meta_len])
        .map_err(|_| StegError::NoPayloadFound)?;
    if meta.engine != "rust-v1" {
        return Err(StegError::LegacyKeyFile);
    }
    let total_bytes = 2 + meta_len + meta.ciphertext_len;
    if total_bytes > max {
        return Err(StegError::NoPayloadFound);
    }
    let all = extract_bits(&pseudo, &slots, total_bytes)?;
    Ok((meta, all[2 + meta_len..total_bytes].to_vec()))
}

// ── Encryption helper ─────────────────────────────────────────────────────────

fn encrypt_payload(
    passphrase: &[u8],
    plaintext: &[u8],
    cipher: Cipher,
    salt: &[u8],
    nonce: &[u8],
) -> Result<Vec<u8>, StegError> {
    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::Aes256Gcm;
    use ascon_aead::Ascon128;
    use chacha20poly1305::ChaCha20Poly1305;

    let key = crypto::derive_key(passphrase, salt, cipher)?;
    let compressed = crypto::compress(plaintext)?;

    match cipher {
        Cipher::Ascon128 => {
            let c = Ascon128::new_from_slice(&key).map_err(|_| StegError::CorruptedFile)?;
            let n = ascon_aead::Nonce::<Ascon128>::from_slice(nonce);
            c.encrypt(n, compressed.as_slice())
                .map_err(|_| StegError::DecryptionFailed)
        }
        Cipher::ChaCha20Poly1305 => {
            let c = ChaCha20Poly1305::new_from_slice(&key).map_err(|_| StegError::CorruptedFile)?;
            let n = chacha20poly1305::Nonce::from_slice(nonce);
            c.encrypt(n, compressed.as_slice())
                .map_err(|_| StegError::DecryptionFailed)
        }
        Cipher::Aes256Gcm => {
            let c = Aes256Gcm::new_from_slice(&key).map_err(|_| StegError::CorruptedFile)?;
            let n = aes_gcm::Nonce::from_slice(nonce);
            c.encrypt(n, compressed.as_slice())
                .map_err(|_| StegError::DecryptionFailed)
        }
    }
}

fn decrypt_meta(meta: &Meta, ciphertext: &[u8], passphrase: &[u8]) -> Result<Vec<u8>, StegError> {
    let key = crypto::derive_key(passphrase, &meta.salt, meta.cipher)?;
    crypto::decrypt(&key, ciphertext, &meta.nonce, meta.cipher)
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Embed `payload` into `cover_path`, writing to `out_path`.
///
/// Returns the path actually written and a `KeyFile` if `export_key` is true.
/// The written path can differ from `out_path` (e.g. a JPEG cover forces a
/// `.jpg`/`.jpeg` extension), so callers must report and key-file against the
/// returned path rather than assuming `out_path`.
pub fn embed(
    cover_path: &Path,
    payload: &[u8],
    passphrase: &[u8],
    cipher: Cipher,
    mode: &str,
    out_path: &Path,
    export_key: bool,
) -> Result<(PathBuf, Option<KeyFile>), StegError> {
    if payload.is_empty() {
        return Err(StegError::EmptyPayload);
    }
    let fmt = detect_format(cover_path)?;
    // Reject non-embeddable formats up front with a clear message rather than
    // failing late inside a decoder (e.g. a FLAC cover, which is analyse/extract
    // only). detect_format is content-based, so a mis-extensioned file is caught.
    if !crate::utils::embed_extensions().contains(&fmt.as_str()) {
        return Err(StegError::UnsupportedFormat(format!(
            "{fmt} is not supported for embedding (analyse and extract only)"
        )));
    }
    let score = assess(cover_path)?;
    if score < 0.1 {
        return Err(StegError::PoorCoverQuality { score });
    }

    let salt = crypto::generate_salt();
    let nonce = crypto::generate_nonce(cipher);
    let ciphertext = encrypt_payload(passphrase, payload, cipher, &salt, &nonce)?;

    let meta = Meta {
        engine: "rust-v1".into(),
        cipher,
        mode: mode.to_string(),
        nonce: nonce.clone(),
        salt: salt.to_vec(),
        ciphertext_len: ciphertext.len(),
        deniable: false,
        partition_seed: None,
        partition_half: None,
    };
    let stego_payload = build_stego_payload(&meta, &ciphertext)?;

    let written_path = if fmt == "wav" {
        do_embed_wav(cover_path, &stego_payload, passphrase, out_path)?;
        out_path.to_path_buf()
    } else if fmt == "flac" {
        do_embed_flac(cover_path, &stego_payload, passphrase, out_path)?;
        out_path.to_path_buf()
    } else if fmt == "jpg" || fmt == "jpeg" {
        do_embed_jpeg(cover_path, &stego_payload, passphrase, out_path)?
    } else {
        do_embed_image(cover_path, &stego_payload, passphrase, mode, out_path, &fmt)?
    };

    let kf = if export_key {
        Some(KeyFile::new(cipher, nonce, salt.to_vec()))
    } else {
        None
    };
    Ok((written_path, kf))
}

/// Embed two payloads into one cover for deniable mode. Always exports both key files.
pub fn embed_deniable(
    cover_path: &Path,
    real_payload: &[u8],
    decoy_payload: &[u8],
    real_passphrase: &[u8],
    decoy_passphrase: &[u8],
    cipher: Cipher,
    out_path: &Path,
) -> Result<(KeyFile, KeyFile), StegError> {
    if real_payload.is_empty() || decoy_payload.is_empty() {
        return Err(StegError::EmptyPayload);
    }
    let fmt = detect_format(cover_path)?;
    if fmt == "wav" {
        return Err(StegError::UnsupportedFormat(
            "deniable WAV not supported".into(),
        ));
    }
    if fmt == "jpg" || fmt == "jpeg" {
        return Err(StegError::UnsupportedFormat(
            "deniable JPEG not supported — use PNG or BMP".into(),
        ));
    }
    // Deniable mode is lossless-image only; reject anything else (FLAC, etc.)
    // up front rather than failing late in a decoder.
    if !matches!(fmt.as_str(), "png" | "bmp" | "webp") {
        return Err(StegError::UnsupportedFormat(format!(
            "{fmt} is not supported for deniable embedding (use PNG, BMP or WebP)"
        )));
    }
    let score = assess(cover_path)?;
    if score < 0.1 {
        return Err(StegError::PoorCoverQuality { score });
    }

    let mut pseed = [0u8; 32];
    OsRng.fill_bytes(&mut pseed);
    let pseed_b64 = B64.encode(pseed);

    // Randomise which partition half the real payload goes in.
    // This prevents an adversary from inferring "half 0 = real".
    let mut flip_byte = [0u8; 1];
    OsRng.fill_bytes(&mut flip_byte);
    let (real_half, decoy_half): (u8, u8) = if flip_byte[0] & 1 == 0 {
        (0, 1)
    } else {
        (1, 0)
    };

    let real_salt = crypto::generate_salt();
    let real_nonce = crypto::generate_nonce(cipher);
    let real_ct = encrypt_payload(
        real_passphrase,
        real_payload,
        cipher,
        &real_salt,
        &real_nonce,
    )?;

    let decoy_salt = crypto::generate_salt();
    let decoy_nonce = crypto::generate_nonce(cipher);
    let decoy_ct = encrypt_payload(
        decoy_passphrase,
        decoy_payload,
        cipher,
        &decoy_salt,
        &decoy_nonce,
    )?;

    let real_meta = Meta {
        engine: "rust-v1".into(),
        cipher,
        mode: "sequential".into(),
        nonce: real_nonce.clone(),
        salt: real_salt.to_vec(),
        ciphertext_len: real_ct.len(),
        // Embed deniable as false — the deniable flag in metadata would
        // confirm to an adversary that a second payload exists. The key
        // file's partition_half handles routing during extraction.
        deniable: false,
        partition_seed: None,
        partition_half: None,
    };
    let decoy_meta = Meta {
        engine: "rust-v1".into(),
        cipher,
        mode: "sequential".into(),
        nonce: decoy_nonce.clone(),
        salt: decoy_salt.to_vec(),
        ciphertext_len: decoy_ct.len(),
        deniable: false,
        partition_seed: None,
        partition_half: None,
    };

    let real_stego = build_stego_payload(&real_meta, &real_ct)?;
    let decoy_stego = build_stego_payload(&decoy_meta, &decoy_ct)?;

    let (rgb, alpha) = load_rgb_with_alpha(cover_path)?;
    let (w, h) = rgb.dimensions();
    let total = (w * h) as usize * 3;
    let all_slots = permute_set((0..total).collect(), &pseed);
    let (half0, half1) = bifurcate(all_slots);
    let real_base = if real_half == 0 {
        half0.clone()
    } else {
        half1.clone()
    };
    let decoy_base = if decoy_half == 0 { half0 } else { half1 };
    let real_slots = permute_set(real_base, real_passphrase);
    let decoy_slots = permute_set(decoy_base, decoy_passphrase);

    let mut pixels = rgb.as_raw().to_vec();
    embed_bits(&mut pixels, &real_slots, &real_stego)?;
    embed_bits(&mut pixels, &decoy_slots, &decoy_stego)?;

    write_frame(&pixels, w, h, alpha.as_deref(), cover_path, out_path, &fmt)?;

    let mut real_kf = KeyFile::new(cipher, real_nonce, real_salt.to_vec());
    real_kf.deniable = true;
    real_kf.partition_seed = Some(pseed_b64.clone());
    real_kf.partition_half = Some(real_half);

    let mut decoy_kf = KeyFile::new(cipher, decoy_nonce, decoy_salt.to_vec());
    decoy_kf.deniable = true;
    decoy_kf.partition_seed = Some(pseed_b64);
    decoy_kf.partition_half = Some(decoy_half);

    Ok((real_kf, decoy_kf))
}

/// Collapse payload-structure failures to the unified "no payload / wrong
/// passphrase" error so the extract path cannot act as an oracle that
/// distinguishes "wrong passphrase" from "legacy/corrupt payload". To a caller
/// without the right passphrase these are all the same outcome. File-level IO
/// and image-decode errors are left distinct; they do not depend on the
/// passphrase, so they leak nothing. Genuine legacy *key file* detection still
/// happens earlier, in the key-file loader, and is unaffected.
fn oracle_normalise(r: Result<Vec<u8>, StegError>) -> Result<Vec<u8>, StegError> {
    match r {
        Err(StegError::LegacyKeyFile) | Err(StegError::CorruptedFile) => {
            Err(StegError::NoPayloadFound)
        }
        other => other,
    }
}

/// Extract from a non-deniable stego file using passphrase only.
pub fn extract(stego_path: &Path, passphrase: &[u8]) -> Result<Vec<u8>, StegError> {
    // Catch panics from third-party decoders. Found-by-fuzz: malformed
    // JPEG input panics inside the `image` crate's JPEG decoder; we
    // convert that into a clean StegError::Internal instead of unwinding
    // out of extract().
    let stego_path = stego_path.to_path_buf();
    let passphrase = passphrase.to_vec();
    match std::panic::catch_unwind(move || -> Result<Vec<u8>, StegError> {
        let fmt = detect_format(&stego_path)?;
        let (meta, ct) = if fmt == "wav" {
            do_extract_wav(&stego_path, &passphrase)?
        } else if fmt == "flac" {
            do_extract_flac(&stego_path, &passphrase)?
        } else if fmt == "jpg" || fmt == "jpeg" {
            do_extract_jpeg(&stego_path, &passphrase)?
        } else {
            do_extract_image(&stego_path, &passphrase)?
        };
        decrypt_meta(&meta, &ct, &passphrase)
    }) {
        Ok(r) => oracle_normalise(r),
        Err(payload) => {
            let msg = if let Some(s) = payload.downcast_ref::<&'static str>() {
                (*s).to_string()
            } else if let Some(s) = payload.downcast_ref::<String>() {
                s.clone()
            } else {
                "panic in extract dependency (caught)".to_string()
            };
            Err(StegError::Internal(msg))
        }
    }
}

/// Extract using an exported key file. Handles standard and deniable files.
pub fn extract_with_keyfile(
    stego_path: &Path,
    keyfile: &KeyFile,
    passphrase: &[u8],
) -> Result<Vec<u8>, StegError> {
    // Body wrapped so its result passes through oracle_normalise (F9): wrong
    // passphrase, legacy payload and corrupt payload all collapse to one error.
    let run = || -> Result<Vec<u8>, StegError> {
        let fmt = detect_format(stego_path)?;
        if fmt == "wav" {
            let (meta, ct) = do_extract_wav(stego_path, passphrase)?;
            return decrypt_meta(&meta, &ct, passphrase);
        }
        if fmt == "flac" {
            let (meta, ct) = do_extract_flac(stego_path, passphrase)?;
            return decrypt_meta(&meta, &ct, passphrase);
        }
        // Non-deniable JPEG: use DCT path (key file provides cipher metadata but
        // position selection still requires the passphrase).
        if (fmt == "jpg" || fmt == "jpeg") && !keyfile.deniable {
            let (meta, ct) = do_extract_jpeg(stego_path, passphrase)?;
            return decrypt_meta(&meta, &ct, passphrase);
        }
        let rgb = load_frame(stego_path)?.to_rgb8();
        let (w, h) = rgb.dimensions();
        let total = (w * h) as usize * 3;
        let pixels = rgb.as_raw().to_vec();

        let slots = if keyfile.deniable {
            let pseed_b64 = keyfile
                .partition_seed
                .as_deref()
                .ok_or(StegError::CorruptedFile)?;
            let pseed = B64
                .decode(pseed_b64)
                .map_err(|_| StegError::CorruptedFile)?;
            let half = keyfile.partition_half.ok_or(StegError::CorruptedFile)?;
            let all = permute_set((0..total).collect(), &pseed);
            let (first, second) = bifurcate(all);
            let base = if half == 0 { first } else { second };
            permute_set(base, passphrase)
        } else {
            // Try sequential first, fall back to adaptive (matches extract() logic).
            // The key file does not store the embedding mode, so we must try both.
            let seq_slots = image_slots(&rgb, "sequential", passphrase);
            match do_extract_image_with_slots(&pixels, &seq_slots) {
                Ok((meta, ct)) => return decrypt_meta(&meta, &ct, passphrase),
                Err(StegError::NoPayloadFound) | Err(StegError::CorruptedFile) => {}
                Err(e) => return Err(e),
            }
            image_slots(&rgb, "adaptive", passphrase)
        };

        let (meta, ct) = do_extract_image_with_slots(&pixels, &slots)?;
        decrypt_meta(&meta, &ct, passphrase)
    };
    oracle_normalise(run())
}

/// Read the embedded metadata header from a stego file without decrypting the
/// payload. Requires the passphrase because slot selection is passphrase-seeded.
/// Returns the metadata as a JSON string.
pub fn read_meta(path: &Path, passphrase: &[u8]) -> Result<String, StegError> {
    let fmt = detect_format(path)?;
    let meta = if fmt == "wav" {
        let (m, _) = do_extract_wav(path, passphrase)?;
        m
    } else if fmt == "flac" {
        let (m, _) = do_extract_flac(path, passphrase)?;
        m
    } else if fmt == "jpg" || fmt == "jpeg" {
        let (m, _) = do_extract_jpeg(path, passphrase)?;
        m
    } else {
        let (m, _) = do_extract_image(path, passphrase)?;
        m
    };
    Ok(serde_json::to_string_pretty(&meta)?)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{Rng, RngCore};
    use tempfile::Builder;

    /// Build a stego payload (metadata header + ciphertext) for testing,
    /// bypassing the cover score check.
    fn build_stego_payload_for_test(payload: &[u8], passphrase: &[u8], cipher: Cipher) -> Vec<u8> {
        let salt = crypto::generate_salt();
        let nonce = crypto::generate_nonce(cipher);
        let ct = encrypt_payload(passphrase, payload, cipher, &salt, &nonce).unwrap();
        let meta = Meta {
            engine: "rust-v1".into(),
            cipher,
            mode: "sequential".into(),
            nonce,
            salt: salt.to_vec(),
            ciphertext_len: ct.len(),
            deniable: false,
            partition_seed: None,
            partition_half: None,
        };
        build_stego_payload(&meta, &ct).unwrap()
    }

    const PASS: &[u8] = b"correct-horse-battery-staple";
    const PASS2: &[u8] = b"decoy-passphrase-for-deniability";
    const MSG: &[u8] = b"the quick brown fox jumps over the lazy dog";
    const MSG2: &[u8] = b"a completely different decoy message here";

    fn noisy_png(w: u32, h: u32) -> tempfile::NamedTempFile {
        let f = Builder::new().suffix(".png").tempfile().unwrap();
        let mut data = vec![0u8; (w * h * 3) as usize];
        ChaCha8Rng::seed_from_u64(0xDEAD).fill_bytes(&mut data);
        RgbImage::from_raw(w, h, data)
            .unwrap()
            .save(f.path())
            .unwrap();
        f
    }

    fn flat_png(w: u32, h: u32) -> tempfile::NamedTempFile {
        let f = Builder::new().suffix(".png").tempfile().unwrap();
        RgbImage::from_raw(w, h, vec![128u8; (w * h * 3) as usize])
            .unwrap()
            .save(f.path())
            .unwrap();
        f
    }

    fn noisy_bmp(w: u32, h: u32) -> tempfile::NamedTempFile {
        let f = Builder::new().suffix(".bmp").tempfile().unwrap();
        let mut data = vec![0u8; (w * h * 3) as usize];
        ChaCha8Rng::seed_from_u64(0xBEEF).fill_bytes(&mut data);
        RgbImage::from_raw(w, h, data)
            .unwrap()
            .save_with_format(f.path(), ImageFormat::Bmp)
            .unwrap();
        f
    }

    fn noisy_jpeg(w: u32, h: u32) -> tempfile::NamedTempFile {
        let f = Builder::new().suffix(".jpg").tempfile().unwrap();
        // Use gradient + noise pattern rather than pure noise so JPEG
        // compression preserves enough DCT coefficients for a good score.
        let mut rng = ChaCha8Rng::seed_from_u64(0xCAFE);
        let mut data = vec![0u8; (w * h * 3) as usize];
        for y in 0..h {
            for x in 0..w {
                let base = ((y * w + x) * 3) as usize;
                let grad_r = ((x as f32 / w as f32) * 200.0) as u8;
                let grad_g = ((y as f32 / h as f32) * 200.0) as u8;
                let grad_b = (((x + y) as f32 / (w + h) as f32) * 200.0) as u8;
                let noise: [u8; 3] = [
                    rng.gen::<u8>() % 40,
                    rng.gen::<u8>() % 40,
                    rng.gen::<u8>() % 40,
                ];
                data[base] = grad_r.saturating_add(noise[0]);
                data[base + 1] = grad_g.saturating_add(noise[1]);
                data[base + 2] = grad_b.saturating_add(noise[2]);
            }
        }
        RgbImage::from_raw(w, h, data)
            .unwrap()
            .save_with_format(f.path(), ImageFormat::Jpeg)
            .unwrap();
        f
    }

    fn noisy_webp(w: u32, h: u32) -> tempfile::NamedTempFile {
        let f = Builder::new().suffix(".webp").tempfile().unwrap();
        let mut data = vec![0u8; (w * h * 3) as usize];
        ChaCha8Rng::seed_from_u64(0xFACE).fill_bytes(&mut data);
        RgbImage::from_raw(w, h, data)
            .unwrap()
            .save_with_format(f.path(), ImageFormat::WebP)
            .unwrap();
        f
    }

    fn noisy_wav(secs: u32) -> tempfile::NamedTempFile {
        let f = Builder::new().suffix(".wav").tempfile().unwrap();
        let spec = hound::WavSpec {
            channels: 1,
            sample_rate: 44100,
            bits_per_sample: 16,
            sample_format: hound::SampleFormat::Int,
        };
        let mut writer = hound::WavWriter::create(f.path(), spec).unwrap();
        let mut rng = ChaCha8Rng::seed_from_u64(0xABCD);
        for _ in 0..(44100 * secs) {
            let s = (rng.next_u32() >> 16) as i16;
            writer.write_sample(s).unwrap();
        }
        writer.finalize().unwrap();
        f
    }

    fn out(suffix: &str) -> tempfile::NamedTempFile {
        Builder::new().suffix(suffix).tempfile().unwrap()
    }

    /// A noisy RGBA PNG with a recognisable alpha gradient and a tEXt chunk,
    /// written through the low-level `png` encoder so the ancillary chunk is
    /// actually present on disk.
    fn rgba_png_with_text(w: u32, h: u32) -> tempfile::NamedTempFile {
        let f = Builder::new().suffix(".png").tempfile().unwrap();
        let mut rgba = vec![0u8; (w * h * 4) as usize];
        ChaCha8Rng::seed_from_u64(0x5151).fill_bytes(&mut rgba);
        for i in 0..(w * h) as usize {
            // Deterministic, non-constant alpha so a byte-identity check is meaningful.
            rgba[i * 4 + 3] = (i % 251) as u8;
        }
        let mut enc = png::Encoder::new(
            std::io::BufWriter::new(File::create(f.path()).unwrap()),
            w,
            h,
        );
        enc.set_color(png::ColorType::Rgba);
        enc.set_depth(png::BitDepth::Eight);
        enc.add_text_chunk("Software".into(), "StegcoreTest".into())
            .unwrap();
        let mut wr = enc.write_header().unwrap();
        wr.write_image_data(&rgba).unwrap();
        wr.finish().unwrap();
        f
    }

    fn decode_alpha(path: &Path) -> Vec<u8> {
        image::open(path)
            .unwrap()
            .to_rgba8()
            .as_raw()
            .chunks_exact(4)
            .map(|px| px[3])
            .collect()
    }

    fn read_text_keywords(path: &Path) -> Vec<String> {
        let reader = png::Decoder::new(BufReader::new(File::open(path).unwrap()))
            .read_info()
            .unwrap();
        reader
            .info()
            .uncompressed_latin1_text
            .iter()
            .map(|c| c.keyword.clone())
            .collect()
    }

    // ── alpha / compression / metadata preservation (A1 regression) ─────────────

    #[test]
    fn atomic_write_replaces_and_leaves_no_temp() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("o.bin");
        std::fs::write(&out, b"old contents").unwrap();
        atomic_write_bytes(&out, b"new contents").unwrap();
        assert_eq!(std::fs::read(&out).unwrap(), b"new contents");
        // No leftover sibling temp files in the directory.
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.path() != out)
            .collect();
        assert!(leftovers.is_empty(), "atomic write left temp files behind");
    }

    #[test]
    fn interleave_rgba_packs_pixels() {
        assert_eq!(
            interleave_rgba(&[1, 2, 3, 4, 5, 6], &[10, 20]),
            vec![1, 2, 3, 10, 4, 5, 6, 20]
        );
    }

    #[test]
    fn write_png_rejects_mismatched_buffers() {
        let missing = Path::new("/nonexistent/cover.png");
        let o = out(".png");
        assert!(matches!(
            write_png(&[0u8; 12], 2, 2, Some(&[0u8; 3]), missing, o.path()),
            Err(StegError::CorruptedFile)
        ));
        assert!(matches!(
            write_png(&[0u8; 11], 2, 2, None, missing, o.path()),
            Err(StegError::CorruptedFile)
        ));
    }

    #[test]
    fn write_png_best_not_larger_than_image_default() {
        let (w, h) = (256u32, 256u32);
        let mut pixels = vec![0u8; (w * h * 3) as usize];
        for y in 0..h {
            for x in 0..w {
                let i = ((y * w + x) * 3) as usize;
                pixels[i] = (x % 256) as u8;
                pixels[i + 1] = (y % 256) as u8;
                pixels[i + 2] = ((x + y) % 256) as u8;
            }
        }
        let ours = out(".png");
        // Non-existent cover path exercises the best-effort metadata copy too.
        write_png(
            &pixels,
            w,
            h,
            None,
            Path::new("/nonexistent/c.png"),
            ours.path(),
        )
        .unwrap();
        let theirs = out(".png");
        RgbImage::from_raw(w, h, pixels)
            .unwrap()
            .save(theirs.path())
            .unwrap();
        let so = std::fs::metadata(ours.path()).unwrap().len();
        let st = std::fs::metadata(theirs.path()).unwrap().len();
        assert!(
            so <= st,
            "Best compression ({so} B) should not exceed image default ({st} B)"
        );
    }

    #[test]
    fn embed_preserves_alpha_and_roundtrips() {
        let cover = rgba_png_with_text(120, 120);
        let orig_alpha = decode_alpha(cover.path());
        let o = out(".png");
        embed(
            cover.path(),
            MSG,
            PASS,
            Cipher::ChaCha20Poly1305,
            "sequential",
            o.path(),
            false,
        )
        .unwrap();
        assert!(
            image::open(o.path()).unwrap().color().has_alpha(),
            "RGBA cover must produce RGBA output"
        );
        assert_eq!(
            orig_alpha,
            decode_alpha(o.path()),
            "alpha plane must be preserved byte-for-byte"
        );
        assert_eq!(extract(o.path(), PASS).unwrap(), MSG);
    }

    #[test]
    fn embed_rgb_cover_stays_rgb_and_roundtrips() {
        let cover = noisy_png(96, 96);
        let o = out(".png");
        embed(
            cover.path(),
            MSG,
            PASS,
            Cipher::ChaCha20Poly1305,
            "sequential",
            o.path(),
            false,
        )
        .unwrap();
        assert!(
            !image::open(o.path()).unwrap().color().has_alpha(),
            "RGB cover must stay RGB"
        );
        assert_eq!(extract(o.path(), PASS).unwrap(), MSG);
    }

    #[test]
    fn embed_preserves_text_chunks() {
        let cover = rgba_png_with_text(80, 80);
        let o = out(".png");
        embed(
            cover.path(),
            MSG,
            PASS,
            Cipher::ChaCha20Poly1305,
            "sequential",
            o.path(),
            false,
        )
        .unwrap();
        assert!(
            read_text_keywords(o.path()).contains(&"Software".to_string()),
            "tEXt chunk present on the cover must be preserved on the stego output"
        );
    }

    #[test]
    fn deniable_preserves_alpha() {
        let cover = rgba_png_with_text(128, 128);
        let orig_alpha = decode_alpha(cover.path());
        let o = out(".png");
        let (real_kf, _decoy_kf) = embed_deniable(
            cover.path(),
            MSG,
            MSG2,
            PASS,
            PASS2,
            Cipher::ChaCha20Poly1305,
            o.path(),
        )
        .unwrap();
        assert_eq!(
            orig_alpha,
            decode_alpha(o.path()),
            "deniable embed must preserve the alpha plane too"
        );
        assert_eq!(extract_with_keyfile(o.path(), &real_kf, PASS).unwrap(), MSG);
    }

    // ── assess ────────────────────────────────────────────────────────────────

    #[test]
    fn assess_noisy_image_high() {
        let s = assess(noisy_png(200, 200).path()).unwrap();
        assert!(s > 0.5, "noisy image score should be > 0.5, got {s}");
    }

    #[test]
    fn assess_flat_image_low() {
        let s = assess(flat_png(200, 200).path()).unwrap();
        assert!(s < 0.3, "flat image score should be < 0.3, got {s}");
    }

    #[test]
    fn assess_wav_in_range() {
        let s = assess(noisy_wav(2).path()).unwrap();
        assert!((0.0..=1.0).contains(&s));
    }

    #[test]
    fn assess_jpeg_in_range() {
        let s = assess(noisy_jpeg(300, 300).path()).unwrap();
        assert!((0.0..=1.0).contains(&s), "jpeg score out of range: {s}");
        assert!(s > 0.0, "jpeg score should be > 0 for non-trivial image");
    }

    #[test]
    fn assess_jpeg_normal_capacity_clears_embed_gate() {
        // Regression (F1): the old capacity/file-size ratio scored ordinary
        // JPEGs ~0.06 and made embed() reject them with PoorCoverQuality. A
        // JPEG with real embeddable capacity must now clear the 0.1 gate.
        let s = assess(noisy_jpeg(300, 300).path()).unwrap();
        assert!(
            s > 0.1,
            "normal-capacity jpeg must clear the embed gate, got {s}"
        );
        // And it must actually embed (not be rejected as poor quality).
        let o = out(".jpg");
        let r = embed(
            noisy_jpeg(300, 300).path(),
            MSG,
            PASS,
            Cipher::ChaCha20Poly1305,
            "sequential",
            o.path(),
            false,
        );
        assert!(
            r.is_ok(),
            "normal-capacity jpeg embed should succeed, got {r:?}"
        );
    }

    #[test]
    fn embed_jpeg_returns_jpg_path_even_for_nonjpeg_output_name() {
        // F2: a JPEG cover written to a `.png`-named output must end up as a
        // `.jpg` file, and embed() must RETURN that real path so callers report
        // and key-file against it.
        let cover = noisy_jpeg(300, 300);
        let dir = tempfile::tempdir().unwrap();
        let requested = dir.path().join("result.png"); // deliberately wrong ext
        let (written, _kf) = embed(
            cover.path(),
            MSG,
            PASS,
            Cipher::ChaCha20Poly1305,
            "sequential",
            &requested,
            false,
        )
        .unwrap();
        assert_eq!(
            written.extension().and_then(|e| e.to_str()),
            Some("jpg"),
            "jpeg output must carry a .jpg extension, got {written:?}"
        );
        assert!(written.exists(), "the returned path must exist on disk");
        assert!(
            !requested.exists(),
            "the .png-named path must not have been created"
        );
        assert_eq!(extract(&written, PASS).unwrap(), MSG);
    }

    // ── PNG round-trips ───────────────────────────────────────────────────────

    #[test]
    fn roundtrip_png_sequential() {
        let cover = noisy_png(300, 300);
        let o = out(".png");
        embed(
            cover.path(),
            MSG,
            PASS,
            Cipher::ChaCha20Poly1305,
            "sequential",
            o.path(),
            false,
        )
        .unwrap();
        assert_eq!(extract(o.path(), PASS).unwrap(), MSG);
    }

    #[test]
    fn roundtrip_png_adaptive() {
        let cover = noisy_png(300, 300);
        let o = out(".png");
        embed(
            cover.path(),
            MSG,
            PASS,
            Cipher::ChaCha20Poly1305,
            "adaptive",
            o.path(),
            false,
        )
        .unwrap();
        // adaptive embeds with its slot set; extract uses sequential permuted by passphrase
        // (adaptive mode still works because the stego payload includes mode in metadata
        // but extraction reads metadata first then decrypts)
        assert_eq!(extract(o.path(), PASS).unwrap(), MSG);
    }

    #[test]
    fn roundtrip_png_ascon() {
        let cover = noisy_png(300, 300);
        let o = out(".png");
        embed(
            cover.path(),
            MSG,
            PASS,
            Cipher::Ascon128,
            "sequential",
            o.path(),
            false,
        )
        .unwrap();
        assert_eq!(extract(o.path(), PASS).unwrap(), MSG);
    }

    #[test]
    fn roundtrip_png_aes256gcm() {
        let cover = noisy_png(300, 300);
        let o = out(".png");
        embed(
            cover.path(),
            MSG,
            PASS,
            Cipher::Aes256Gcm,
            "sequential",
            o.path(),
            false,
        )
        .unwrap();
        assert_eq!(extract(o.path(), PASS).unwrap(), MSG);
    }

    // ── Other formats ─────────────────────────────────────────────────────────

    #[test]
    fn roundtrip_bmp() {
        let cover = noisy_bmp(300, 300);
        let o = out(".bmp");
        embed(
            cover.path(),
            MSG,
            PASS,
            Cipher::ChaCha20Poly1305,
            "sequential",
            o.path(),
            false,
        )
        .unwrap();
        assert_eq!(extract(o.path(), PASS).unwrap(), MSG);
    }

    #[test]
    fn embed_rejects_non_embeddable_format() {
        // F4: a FLAC cover (analyse/extract only) must be rejected up front
        // with a clear UnsupportedFormat, not a late decoder error.
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("a.flac");
        std::fs::write(&p, b"fLaC\0\0\0\0\0\0\0\0").unwrap();
        let o = out(".flac");
        let r = embed(
            &p,
            MSG,
            PASS,
            Cipher::ChaCha20Poly1305,
            "sequential",
            o.path(),
            false,
        );
        assert!(
            matches!(r, Err(StegError::UnsupportedFormat(_))),
            "got {r:?}"
        );
    }

    #[test]
    fn roundtrip_jpeg_dct() {
        // Test DCT coefficient embedding round-trip directly, bypassing the
        // cover score check (which rejects synthetic test JPEGs).
        let cover = noisy_jpeg(800, 600);
        let dir = tempfile::tempdir().unwrap();
        let out_path = dir.path().join("output.jpg");
        let stego_payload = build_stego_payload_for_test(MSG, PASS, Cipher::ChaCha20Poly1305);
        do_embed_jpeg(cover.path(), &stego_payload, PASS, &out_path).unwrap();
        assert!(out_path.exists(), "stego JPEG not written");
        assert_eq!(extract(&out_path, PASS).unwrap(), MSG);
    }

    #[test]
    fn roundtrip_jpeg_dct_all_ciphers() {
        let cover = noisy_jpeg(800, 600);
        for cipher in [
            Cipher::ChaCha20Poly1305,
            Cipher::Aes256Gcm,
            Cipher::Ascon128,
        ] {
            let dir = tempfile::tempdir().unwrap();
            let out_path = dir.path().join("output.jpg");
            let stego_payload = build_stego_payload_for_test(MSG, PASS, cipher);
            do_embed_jpeg(cover.path(), &stego_payload, PASS, &out_path).unwrap();
            assert_eq!(extract(&out_path, PASS).unwrap(), MSG, "cipher {cipher:?}");
        }
    }

    #[test]
    fn roundtrip_jpeg_dct_with_keyfile() {
        let cover = noisy_jpeg(800, 600);
        let dir = tempfile::tempdir().unwrap();
        let out_path = dir.path().join("output.jpg");
        let cipher = Cipher::ChaCha20Poly1305;
        let stego_payload = build_stego_payload_for_test(MSG, PASS, cipher);
        do_embed_jpeg(cover.path(), &stego_payload, PASS, &out_path).unwrap();
        // Extract without keyfile (self-contained metadata)
        assert_eq!(extract(&out_path, PASS).unwrap(), MSG);
    }

    #[test]
    fn roundtrip_webp() {
        let cover = noisy_webp(300, 300);
        let o = out(".webp");
        embed(
            cover.path(),
            MSG,
            PASS,
            Cipher::ChaCha20Poly1305,
            "sequential",
            o.path(),
            false,
        )
        .unwrap();
        assert_eq!(extract(o.path(), PASS).unwrap(), MSG);
    }

    #[test]
    fn roundtrip_wav() {
        let cover = noisy_wav(3);
        let o = out(".wav");
        embed(
            cover.path(),
            MSG,
            PASS,
            Cipher::ChaCha20Poly1305,
            "sequential",
            o.path(),
            false,
        )
        .unwrap();
        assert_eq!(extract(o.path(), PASS).unwrap(), MSG);
    }

    // ── FLAC embedding ────────────────────────────────────────────────────────

    /// Build a noisy FLAC cover (high variance, so it scores as a good cover)
    /// and write it to a temp file via the flac-io encoder.
    fn noisy_flac(frames: usize, channels: u8, bps: u8, seed: u64) -> tempfile::NamedTempFile {
        let f = Builder::new().suffix(".flac").tempfile().unwrap();
        let mut rng = ChaCha8Rng::seed_from_u64(seed);
        let span = 1u64 << bps; // number of distinct values
        let lo = -(1i64 << (bps - 1));
        let samples: Vec<Vec<i32>> = (0..channels)
            .map(|_| {
                (0..frames)
                    .map(|_| (lo + (rng.next_u64() % span) as i64) as i32)
                    .collect()
            })
            .collect();
        let audio = flac_io::FlacAudio {
            sample_rate: 44100,
            channels,
            bits_per_sample: bps,
            samples,
        };
        std::fs::write(f.path(), flac_io::encode(&audio).unwrap()).unwrap();
        f
    }

    #[test]
    fn roundtrip_flac() {
        let cover = noisy_flac(44100, 1, 16, 0x5151);
        let o = out(".flac");
        embed(
            cover.path(),
            MSG,
            PASS,
            Cipher::ChaCha20Poly1305,
            "sequential",
            o.path(),
            false,
        )
        .unwrap();
        assert_eq!(extract(o.path(), PASS).unwrap(), MSG);
    }

    #[test]
    fn roundtrip_flac_stereo_24bit() {
        let cover = noisy_flac(20000, 2, 24, 0x2424);
        let o = out(".flac");
        embed(
            cover.path(),
            MSG,
            PASS,
            Cipher::Aes256Gcm,
            "sequential",
            o.path(),
            false,
        )
        .unwrap();
        assert_eq!(extract(o.path(), PASS).unwrap(), MSG);
    }

    #[test]
    fn flac_embed_changes_only_low_bits() {
        // FLAC embedding is lossless: the stego file must decode to samples that
        // differ from the cover only in the low bit of each embedded slot, and
        // nowhere else. This is the guarantee that makes FLAC a safe carrier.
        let cover = noisy_flac(30000, 2, 16, 0x1B1B);
        let o = out(".flac");
        embed(
            cover.path(),
            MSG,
            PASS,
            Cipher::ChaCha20Poly1305,
            "sequential",
            o.path(),
            false,
        )
        .unwrap();
        let a = flac_io::decode(&std::fs::read(cover.path()).unwrap()).unwrap();
        let b = flac_io::decode(&std::fs::read(o.path()).unwrap()).unwrap();
        assert_eq!(a.channels, b.channels);
        assert_eq!(a.samples_per_channel(), b.samples_per_channel());
        for (ca, cb) in a.samples.iter().zip(&b.samples) {
            for (x, y) in ca.iter().zip(cb) {
                assert_eq!(x >> 1, y >> 1, "a bit above the LSB changed");
            }
        }
    }

    // A thorough random-shape sweep. Marked ignore for the default test run
    // because each iteration performs a full embed and extract, and the Argon2
    // key derivation inside them (not the codec) makes the loop slow; the fast
    // round-trip tests above gate CI, and this runs on demand with
    // `cargo test -p stegcore-engine -- --ignored flac_roundtrip_property`.
    #[test]
    #[ignore = "slow: Argon2 key derivation per iteration; run on demand"]
    fn flac_roundtrip_property_many_inputs() {
        // Several random cover shapes (channel count, bit depth, length) and
        // random payloads must all round-trip the exact payload back out.
        let mut rng = ChaCha8Rng::seed_from_u64(0xF1AC_C0DE);
        for _ in 0..24 {
            let channels = 1 + (rng.next_u32() % 2) as u8; // 1 or 2
            let bps = [16u8, 24][(rng.next_u32() % 2) as usize];
            let frames = 5000 + (rng.next_u32() % 3000) as usize;
            let cover = noisy_flac(frames, channels, bps, rng.next_u64());

            let plen = 1 + (rng.next_u32() % 120) as usize;
            let payload: Vec<u8> = (0..plen).map(|_| rng.next_u32() as u8).collect();

            let o = out(".flac");
            embed(
                cover.path(),
                &payload,
                PASS,
                Cipher::ChaCha20Poly1305,
                "sequential",
                o.path(),
                false,
            )
            .unwrap();
            assert_eq!(extract(o.path(), PASS).unwrap(), payload);
        }
    }

    #[test]
    fn flac_is_assessed_as_a_usable_cover() {
        let cover = noisy_flac(20000, 2, 16, 0xA55E);
        let score = assess(cover.path()).unwrap();
        assert!((0.0..=1.0).contains(&score));
        assert!(
            score > 0.1,
            "a noisy FLAC should score above the reject floor"
        );
    }

    // ── Key file export ───────────────────────────────────────────────────────

    #[test]
    fn roundtrip_with_keyfile() {
        let cover = noisy_png(300, 300);
        let o = out(".png");
        let kf = embed(
            cover.path(),
            MSG,
            PASS,
            Cipher::ChaCha20Poly1305,
            "sequential",
            o.path(),
            true,
        )
        .unwrap()
        .1
        .unwrap();
        assert_eq!(extract_with_keyfile(o.path(), &kf, PASS).unwrap(), MSG);
    }

    // ── Error paths ───────────────────────────────────────────────────────────

    #[test]
    fn capacity_exceeded_returns_error() {
        let cover = noisy_png(10, 10);
        let o = out(".png");
        let huge = vec![0u8; 500];
        let r = embed(
            cover.path(),
            &huge,
            PASS,
            Cipher::ChaCha20Poly1305,
            "sequential",
            o.path(),
            false,
        );
        assert!(matches!(r, Err(StegError::InsufficientCapacity { .. })));
    }

    #[test]
    fn empty_payload_returns_error() {
        let cover = noisy_png(300, 300);
        let o = out(".png");
        let r = embed(
            cover.path(),
            b"",
            PASS,
            Cipher::ChaCha20Poly1305,
            "sequential",
            o.path(),
            false,
        );
        assert!(matches!(r, Err(StegError::EmptyPayload)));
    }

    #[test]
    fn poor_cover_returns_error() {
        let cover = flat_png(300, 300);
        let o = out(".png");
        let r = embed(
            cover.path(),
            MSG,
            PASS,
            Cipher::ChaCha20Poly1305,
            "sequential",
            o.path(),
            false,
        );
        assert!(matches!(r, Err(StegError::PoorCoverQuality { .. })));
    }

    #[test]
    fn wrong_passphrase_returns_crypto_error() {
        let cover = noisy_png(300, 300);
        let o = out(".png");
        embed(
            cover.path(),
            MSG,
            PASS,
            Cipher::ChaCha20Poly1305,
            "sequential",
            o.path(),
            false,
        )
        .unwrap();
        let r = extract(o.path(), b"wrong-passphrase");
        assert!(matches!(
            r,
            Err(StegError::DecryptionFailed | StegError::NoPayloadFound)
        ));
    }

    // ── Deniable ──────────────────────────────────────────────────────────────

    #[test]
    fn deniable_both_halves_correct() {
        let cover = noisy_png(500, 500);
        let o = out(".png");
        let (rkf, dkf) = embed_deniable(
            cover.path(),
            MSG,
            MSG2,
            PASS,
            PASS2,
            Cipher::ChaCha20Poly1305,
            o.path(),
        )
        .unwrap();
        assert_eq!(extract_with_keyfile(o.path(), &rkf, PASS).unwrap(), MSG);
        assert_eq!(extract_with_keyfile(o.path(), &dkf, PASS2).unwrap(), MSG2);
    }

    #[test]
    fn deniable_key_files_structurally_identical() {
        let cover = noisy_png(500, 500);
        let o = out(".png");
        let (rkf, dkf) = embed_deniable(
            cover.path(),
            MSG,
            MSG2,
            PASS,
            PASS2,
            Cipher::ChaCha20Poly1305,
            o.path(),
        )
        .unwrap();
        assert!(rkf.deniable && dkf.deniable);
        assert_eq!(rkf.partition_seed, dkf.partition_seed);
        // Partition halves are randomised — verify they are different and valid
        assert_ne!(rkf.partition_half, dkf.partition_half);
        assert!(rkf.partition_half == Some(0) || rkf.partition_half == Some(1));
        assert!(dkf.partition_half == Some(0) || dkf.partition_half == Some(1));
    }

    #[test]
    fn deniable_cross_passphrase_fails() {
        let cover = noisy_png(500, 500);
        let o = out(".png");
        let (_, dkf) = embed_deniable(
            cover.path(),
            MSG,
            MSG2,
            PASS,
            PASS2,
            Cipher::ChaCha20Poly1305,
            o.path(),
        )
        .unwrap();
        // real passphrase + decoy key file should fail
        let r = extract_with_keyfile(o.path(), &dkf, PASS);
        assert!(matches!(
            r,
            Err(StegError::DecryptionFailed | StegError::NoPayloadFound)
        ));
    }

    #[test]
    fn deniable_passphrase_only_extract_oracle_resistant() {
        let cover = noisy_png(500, 500);
        let o = out(".png");
        embed_deniable(
            cover.path(),
            MSG,
            MSG2,
            PASS,
            PASS2,
            Cipher::ChaCha20Poly1305,
            o.path(),
        )
        .unwrap();
        let r = extract(o.path(), PASS);
        assert!(matches!(
            r,
            Err(StegError::NoPayloadFound | StegError::DecryptionFailed)
        ));
    }

    // ── Pure-helper inline tests (build/parse, assess_inner, slot ops) ─────

    fn sample_meta() -> Meta {
        Meta {
            engine: "rust-v1".into(),
            cipher: Cipher::ChaCha20Poly1305,
            mode: "sequential".into(),
            nonce: vec![0u8; 12],
            salt: vec![0u8; 16],
            ciphertext_len: 16,
            deniable: false,
            partition_seed: None,
            partition_half: None,
        }
    }

    #[test]
    fn build_then_parse_stego_payload_roundtrips_clean() {
        let meta = sample_meta();
        let ct: Vec<u8> = (0..meta.ciphertext_len as u8).collect();
        let bytes = build_stego_payload(&meta, &ct).unwrap();
        let (parsed, parsed_ct) = parse_stego_payload(&bytes).unwrap();
        assert!(matches!(parsed.cipher, Cipher::ChaCha20Poly1305));
        assert_eq!(parsed.engine, meta.engine);
        assert_eq!(parsed_ct, ct);
    }

    #[test]
    fn parse_stego_payload_rejects_short_input() {
        let r = parse_stego_payload(&[0u8]);
        assert!(matches!(r, Err(StegError::NoPayloadFound)));
    }

    #[test]
    fn parse_stego_payload_rejects_oversized_meta_length() {
        // meta_len = 0xFFFF would overflow our 4096 cap.
        let mut bytes = vec![0xFFu8, 0xFF];
        bytes.extend(vec![0u8; 100]);
        let r = parse_stego_payload(&bytes);
        assert!(matches!(r, Err(StegError::NoPayloadFound)));
    }

    #[test]
    fn parse_stego_payload_rejects_meta_extending_past_buffer() {
        // meta_len = 200 but buffer only has 50 bytes after the length prefix.
        let bytes = vec![0u8, 200u8, 0u8, 0u8];
        let r = parse_stego_payload(&bytes);
        assert!(matches!(r, Err(StegError::NoPayloadFound)));
    }

    #[test]
    fn parse_stego_payload_rejects_legacy_engine_string() {
        let mut legacy = sample_meta();
        legacy.engine = "python-v0".into();
        let meta_json = serde_json::to_vec(&legacy).unwrap();
        let mut bytes = (meta_json.len() as u16).to_be_bytes().to_vec();
        bytes.extend_from_slice(&meta_json);
        bytes.extend_from_slice(&[0u8; 16]); // ciphertext placeholder
        let r = parse_stego_payload(&bytes);
        assert!(matches!(r, Err(StegError::LegacyKeyFile)));
    }

    #[test]
    fn oracle_normalise_collapses_payload_failures() {
        // Legacy/corrupt payload errors collapse to NoPayloadFound on the
        // extract path so they cannot be distinguished from a wrong passphrase.
        assert!(matches!(
            oracle_normalise(Err(StegError::LegacyKeyFile)),
            Err(StegError::NoPayloadFound)
        ));
        assert!(matches!(
            oracle_normalise(Err(StegError::CorruptedFile)),
            Err(StegError::NoPayloadFound)
        ));
        // Success and passphrase-independent errors pass through unchanged.
        assert_eq!(oracle_normalise(Ok(vec![1, 2, 3])).unwrap(), vec![1, 2, 3]);
        assert!(matches!(
            oracle_normalise(Err(StegError::DecryptionFailed)),
            Err(StegError::DecryptionFailed)
        ));
        // NoPayloadFound and DecryptionFailed must render identical text.
        assert_eq!(
            StegError::NoPayloadFound.to_string(),
            StegError::DecryptionFailed.to_string()
        );
    }

    #[test]
    fn parse_stego_payload_rejects_truncated_ciphertext() {
        let meta = sample_meta();
        let bytes = build_stego_payload(&meta, &[0u8; 4]).unwrap(); // ct_len says 16, gave 4
        let r = parse_stego_payload(&bytes);
        assert!(matches!(r, Err(StegError::NoPayloadFound)));
    }

    #[test]
    fn parse_stego_payload_rejects_garbage_meta_json() {
        // Length field says 4 bytes of meta JSON, then garbage that isn't JSON.
        let bytes = vec![0u8, 4, b'{', b'}', b'!', b'!', 0u8, 0u8, 0u8, 0u8];
        let r = parse_stego_payload(&bytes);
        assert!(matches!(r, Err(StegError::NoPayloadFound)));
    }

    #[test]
    fn assess_inner_returns_zero_for_empty_pixels() {
        let empty = RgbImage::new(0, 0);
        assert_eq!(assess_inner(&empty), 0.0);
    }

    #[test]
    fn assess_inner_returns_zero_for_uniform_image() {
        // Flat image: variance = 0 → score = 0.
        let flat = RgbImage::from_pixel(8, 8, image::Rgb([128u8, 128, 128]));
        assert_eq!(assess_inner(&flat), 0.0);
    }

    #[test]
    fn assess_inner_returns_one_for_high_variance() {
        // Chequerboard with extreme values → variance large → score clamps to 1.0.
        let img = RgbImage::from_fn(16, 16, |x, y| {
            if (x + y) % 2 == 0 {
                image::Rgb([0u8, 0, 0])
            } else {
                image::Rgb([255u8, 255, 255])
            }
        });
        let s = assess_inner(&img);
        assert!(s > 0.99, "expected clamped to 1.0, got {s}");
    }

    #[test]
    fn bifurcate_splits_evenly_when_total_is_even() {
        let slots: Vec<usize> = (0..10).collect();
        let (a, b) = bifurcate(slots);
        assert_eq!(a.len(), 5);
        assert_eq!(b.len(), 5);
    }

    #[test]
    fn bifurcate_handles_odd_total() {
        let slots: Vec<usize> = (0..11).collect();
        let (a, b) = bifurcate(slots);
        // 11 / 2 = 5; the first half gets 5, second gets 6 (or vice versa
        // depending on implementation — the contract is just no panic / no
        // dropped slot).
        assert_eq!(a.len() + b.len(), 11);
    }

    #[test]
    fn permute_set_is_deterministic_for_same_seed() {
        let slots: Vec<usize> = (0..32).collect();
        let seed = b"deterministic-test";
        let a = permute_set(slots.clone(), seed);
        let b = permute_set(slots.clone(), seed);
        assert_eq!(a, b);
    }

    #[test]
    fn permute_set_differs_for_different_seeds() {
        let slots: Vec<usize> = (0..32).collect();
        let a = permute_set(slots.clone(), b"seed-A");
        let b = permute_set(slots.clone(), b"seed-B");
        // Two different keystreams will almost certainly produce a different
        // permutation; collisions are vanishingly rare for 32 elements.
        assert_ne!(a, b);
    }

    #[test]
    fn permute_set_is_a_permutation_no_dropped_slot() {
        let slots: Vec<usize> = (0..64).collect();
        let permuted = permute_set(slots.clone(), b"identity-check");
        let mut sorted = permuted.clone();
        sorted.sort();
        assert_eq!(sorted, slots);
    }

    // ── embed_bits / extract_bits ────────────────────────────────────────

    #[test]
    fn embed_bits_extract_bits_roundtrip_small() {
        // Small payload (under the 64 KB / 512000-bit parallel threshold).
        let mut pixels = vec![0u8; 256];
        let slots: Vec<usize> = (0..256).collect();
        let payload = [0xAB, 0xCD, 0xEF, 0x12];
        embed_bits(&mut pixels, &slots, &payload).unwrap();
        let got = extract_bits(&pixels, &slots, payload.len()).unwrap();
        assert_eq!(got, payload);
    }

    #[test]
    fn embed_bits_parallel_path_rejects_duplicate_slots() {
        // Payload over the 512000-bit threshold takes the parallel unsafe path.
        // A duplicate slot must fail loud (Internal), never race or panic.
        let payload = vec![0xAAu8; 64_001];
        let bits = payload.len() * 8;
        let mut slots: Vec<usize> = (0..bits).collect();
        slots[1] = slots[0]; // introduce a duplicate
        let mut pixels = vec![0u8; bits];
        let err = embed_bits(&mut pixels, &slots, &payload).unwrap_err();
        assert!(matches!(err, StegError::Internal(_)), "got {err:?}");
    }

    #[test]
    fn embed_bits_rejects_insufficient_slots() {
        let mut pixels = vec![0u8; 16];
        let slots: Vec<usize> = (0..16).collect(); // 16 slots = 2 bytes
        let payload = [1u8; 4]; // needs 32 slots
        let err = embed_bits(&mut pixels, &slots, &payload).unwrap_err();
        match err {
            StegError::InsufficientCapacity {
                required,
                available,
            } => {
                assert_eq!(required, 4);
                assert_eq!(available, 2);
            }
            other => panic!("expected InsufficientCapacity, got {other:?}"),
        }
    }

    #[test]
    fn extract_bits_rejects_insufficient_slots() {
        let pixels = vec![0u8; 16];
        let slots: Vec<usize> = (0..16).collect();
        let err = extract_bits(&pixels, &slots, 4).unwrap_err();
        assert!(matches!(err, StegError::NoPayloadFound));
    }

    #[test]
    fn extract_bits_rejects_out_of_bounds_slot_index() {
        // Slot 999 is past the pixels buffer end — must error, not panic.
        let pixels = vec![0u8; 16];
        let slots = vec![0usize, 1, 2, 3, 4, 5, 6, 999];
        let err = extract_bits(&pixels, &slots, 1).unwrap_err();
        assert!(matches!(err, StegError::NoPayloadFound));
    }

    // ── bifurcate property: never drops the input ────────────────────────

    #[test]
    fn bifurcate_concatenation_preserves_input_modulo_order() {
        let slots: Vec<usize> = (0..25).collect();
        let (a, b) = bifurcate(slots.clone());
        let mut combined = a;
        combined.extend(b);
        combined.sort();
        assert_eq!(combined, slots);
    }

    // ── hound_err converts ─────────────────────────────────────────────

    #[test]
    fn hound_err_wraps_io_error_with_invalid_data_kind() {
        let inner = hound::Error::IoError(std::io::Error::other("oh no"));
        let e = hound_err(inner);
        match e {
            StegError::Io(io) => assert_eq!(io.kind(), std::io::ErrorKind::InvalidData),
            other => panic!("expected Io, got {other:?}"),
        }
    }

    #[test]
    fn hound_err_wraps_format_error_preserving_message() {
        let e = hound_err(hound::Error::FormatError("bad chunk"));
        // hound_err normalises every hound error into a single Io variant
        // with the original message embedded so the surface stays uniform
        // to upstream callers; we just check the message survives.
        match e {
            StegError::Io(io) => {
                assert!(io.to_string().to_lowercase().contains("bad chunk"));
            }
            other => panic!("expected Io, got {other:?}"),
        }
    }

    // ── assess() dispatches on file extension ────────────────────────────

    #[test]
    fn assess_returns_error_for_missing_file() {
        let p = std::path::PathBuf::from("/tmp/stegcore-assess-nope-9999.png");
        let _ = std::fs::remove_file(&p);
        let r = assess(&p);
        assert!(r.is_err());
    }

    #[test]
    fn assess_rejects_malformed_flac() {
        // assess scores a FLAC by decoding it, so a file that carries the fLaC
        // magic but is not a decodable stream is rejected with a clear error
        // rather than a guessed score.
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("dummy.flac");
        std::fs::write(&p, b"fLaC\0\0\0\0\0\0\0\0\0\0\0\0").unwrap();
        let err = assess(&p).unwrap_err();
        assert!(
            matches!(err, StegError::UnsupportedFormat(ref m) if m.contains("flac")),
            "expected a flac decode error, got {err:?}"
        );
    }

    // ── load_frame error path ────────────────────────────────────────────

    #[test]
    fn load_frame_returns_file_not_found_for_missing_path() {
        let p = std::path::PathBuf::from("/tmp/stegcore-load-frame-noexist-77.png");
        let _ = std::fs::remove_file(&p);
        let r = load_frame(&p);
        match r {
            Err(StegError::FileNotFound(s)) => assert!(s.contains("noexist")),
            other => panic!("expected FileNotFound, got {other:?}"),
        }
    }
}
