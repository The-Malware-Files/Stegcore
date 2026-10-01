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
use crate::forensics::{WIRE_FORMAT_LEGACY_SHUFFLE, WIRE_FORMAT_VERSION};
use crate::jpeg_dct;
use crate::keyfile::KeyFile;
use crate::slotseed;
use crate::utils::detect_format;
use crate::wav;
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

/// Wire-format tags this build can read.
///
/// `rust-v1` is the zstd-era payload, `rust-v2` the lz4 one, `rust-v3` the
/// two-stage carrier layout. **None of them selects a code path.** Compression
/// format is detected from the decrypted bytes, and the carrier layout is
/// discovered by trying it, because both facts have to be settled before this
/// tag can be read at all: the tag lives inside `Meta`, and `Meta` lives behind
/// whichever permutation the reader is trying. So the tag records provenance for
/// the forensics layer and for a human reading a `stegcore info` dump; it never
/// branches the reader.
fn is_supported_engine(tag: &str) -> bool {
    tag == "rust-v1" || tag == "rust-v2" || tag == "rust-v3"
}

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
    if !is_supported_engine(&meta.engine) {
        return Err(StegError::LegacyKeyFile);
    }
    let ct_end = meta_end + meta.ciphertext_len;
    if ct_end > bytes.len() {
        return Err(StegError::NoPayloadFound);
    }
    Ok((meta, bytes[meta_end..ct_end].to_vec()))
}

/// True when `bytes` (a payload already extracted from a cover) carries
/// Stegcore's wire format: a length-prefixed metadata block whose `engine` tag
/// is the current one, followed by a ciphertext of the declared length. Used by
/// the forensics layer to identify Stegcore output.
pub(crate) fn looks_like_stego_payload(bytes: &[u8]) -> bool {
    parse_stego_payload(bytes).is_ok()
}

/// Encrypt `payload` under `passphrase` into a self-contained blob in
/// Stegcore's wire format (length-prefixed metadata + ciphertext).
///
/// This is the same byte format the LSB carriers spread across pixels, but
/// returned whole so a document carrier (PDF, OOXML) can store it in a metadata
/// field rather than in pixels. [`open_blob`] is the inverse.
pub fn seal_blob(passphrase: &[u8], payload: &[u8], cipher: Cipher) -> Result<Vec<u8>, StegError> {
    if payload.is_empty() {
        return Err(StegError::EmptyPayload);
    }
    let salt = crypto::generate_salt();
    let nonce = crypto::generate_nonce(cipher);
    let ciphertext = encrypt_payload(passphrase, payload, cipher, &salt, &nonce)?;
    let meta = Meta {
        // A blob owns its own bytes and stores the salt at a known offset in
        // them, so there is no permutation to seed and `rust-v3` buys it
        // nothing. Tagging it v3 would claim a protection it does not have.
        engine: WIRE_FORMAT_LEGACY_SHUFFLE.into(),
        cipher,
        mode: "watermark".into(),
        nonce,
        salt: salt.to_vec(),
        ciphertext_len: ciphertext.len(),
        deniable: false,
        partition_seed: None,
        partition_half: None,
    };
    build_stego_payload(&meta, &ciphertext)
}

/// Decrypt a blob produced by [`seal_blob`] back to its plaintext.
///
/// A wrong passphrase, a truncated blob, or bytes that are not a Stegcore blob
/// all collapse to the same oracle-resistant error, matching the rest of the
/// extract surface.
pub fn open_blob(blob: &[u8], passphrase: &[u8]) -> Result<Vec<u8>, StegError> {
    oracle_normalise((|| {
        let (meta, ct) = parse_stego_payload(blob)?;
        decrypt_meta(&meta, &ct, passphrase)
    })())
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

/// Score a WAV cover's suitability from its sample variance.
///
/// Streamed in two passes rather than decoded whole: holding every sample cost
/// about 14 times the file size in peak resident memory, so a 120 MB 8-bit cover
/// drove this to 1.80 GiB with no limit anywhere in the path. The variance needs
/// the mean, which is why there are two passes, and each pass adds its terms in
/// the same order the whole-file version did, so the score is unchanged.
fn assess_wav(path: &Path) -> Result<f64, StegError> {
    // Normalise against the file's own full scale. Measuring an 8-bit file
    // against i16::MAX made ordinary audio look like silence, scored it zero,
    // and refused it as an unsuitable cover (issue #47).
    // The streaming reader scales float samples into the 24-bit range, so a
    // float file is measured against that scale rather than its own 1.0.
    let mut reader = wav::chunks(path)?;
    let spec = reader.spec();
    let scale = if spec.sample_format == hound::SampleFormat::Float {
        8_388_607.0
    } else {
        wav::full_scale(&spec)
    };

    let mut count: u64 = 0;
    let mut sum = 0.0f64;
    while let Some(chunk) = reader.next_chunk()? {
        for &s in chunk {
            sum += s as f64;
            count += 1;
        }
    }
    if count == 0 {
        return Ok(0.5);
    }
    let n = count as f64;
    let mean = sum / n;

    let mut reader = wav::chunks(path)?;
    let mut sq = 0.0f64;
    while let Some(chunk) = reader.next_chunk()? {
        for &s in chunk {
            sq += (s as f64 - mean).powi(2);
        }
    }
    let variance = sq / n;
    Ok((variance / scale.powi(2)).sqrt().min(1.0))
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

/// The legacy slot permutation: a ChaCha8 shuffle seeded by an XOR-fold of the
/// raw seed bytes.
///
/// # Status
///
/// Still load-bearing, in three places and no more:
///
/// 1. Reading files written by 4.1.0 and earlier, which can only be read with it.
/// 2. The forensics layer, which reconstructs it to identify Stegcore's own
///    output.
/// 3. **Stage one of the `rust-v3` layout**, where it locates the 32-byte salt
///    block and nothing else. The payload's own positions come from
///    [`slotseed::derive_slot_seed`](crate::slotseed::derive_slot_seed) instead;
///    see [`slotseed`](crate::slotseed) for why the derivation could not simply
///    be moved here.
///
/// So a passphrase still seeds this shuffle on the write path, and the two
/// collision families below still apply to stage one. They cost less than they
/// did: a colliding passphrase now reproduces the salt-block positions, reads
/// the same 32 bytes, and then has to pay a full Argon2id derivation to discover
/// that stage two does not parse. Before `rust-v3` the same collision bought a
/// 2.39 ms rejection.
///
/// It is also still the whole slot derivation for the JPEG DCT carrier (through
/// that module's own equivalent) and for sealed blobs, neither of which
/// `rust-v3` reaches.
///
/// # Two collision families, both with working witnesses
///
/// The XOR-fold is not a hash, and it loses two properties a hash would have
/// given. Both were confirmed, not theorised:
///
/// 1. **Prefixed NUL bytes fold identically.** `arr[i % 32] ^= b` leaves `arr`
///    unchanged for a zero byte, so 32 NUL bytes in front of a passphrase
///    produce the same 32-byte seed as the passphrase alone, and therefore the
///    same slot order.
/// 2. **Block order does not matter.** XOR is commutative, so for a passphrase
///    longer than 32 bytes any permutation of its 32-byte blocks folds to the
///    same seed.
///
/// Neither is a decryption break: the AEAD key comes from Argon2id over the raw
/// passphrase, so a colliding passphrase reproduces the slot order and then fails
/// to decrypt. What it costs is that the slot order, which is what the cheap
/// pre-filter tests, is keyed by a weaker secret than the payload is.
///
/// # The accidental protection, which a plausible refactor would delete
///
/// **Do not change this to `partial_shuffle`, and do not make a reader walk the
/// slot stream from the back.** Either would look like a pure speedup and both
/// would remove a real protection that exists here only by accident.
///
/// `slice::shuffle` is Fisher-Yates running *backwards*: it walks `i` from
/// `len - 1` down to 1, so the last positions are settled first and position
/// zero is settled last. A reader needs the *front* of the stream, because the
/// 2-byte length header is read from the first 16 slots.
///
/// ```text
///   shuffle settles:  [ last ..................... first ]
///                       ^ first draw        last draw ^
///   reader needs:     [ first 16 slots ]
///                       ^ available only after every draw
/// ```
///
/// So there is no way to produce the first 16 slots without running the whole
/// shuffle over every slot in the cover. An attacker filtering candidate
/// passphrases pays the full permutation for each one, which is 99.994% of the
/// measured per-guess cost. `partial_shuffle(k)` would hand them the first `k`
/// positions for `k` draws instead of `len - 1`, turning a 2.49 ms filter on a
/// 200x200 carrier into something far cheaper still.
///
/// This was never written down before 2026-10-01, which means the protection had
/// been one refactor away from deletion for its whole life. It is pinned by
/// `permute_set_still_shuffles_the_whole_set_back_to_front` and by the
/// known-answer vector in `permute_set_matches_its_published_vector`, so a change
/// of shuffle strategy fails the suite rather than quietly succeeding.
pub(crate) fn permute_set(mut slots: Vec<usize>, seed: &[u8]) -> Vec<usize> {
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

// ── The rust-v3 two-stage layout ──────────────────────────────────────────────

/// Stage one: the slots carrying the per-file salt block.
///
/// Taken from the cheap passphrase permutation over the **whole** carrier, never
/// over the mode's reduced set. That is deliberate and it is what keeps a
/// legitimate extract at two derivations rather than three. If the salt block
/// moved with the embedding mode, a reader that does not know the mode (which is
/// every reader, because the mode is a field of `Meta` and `Meta` is behind the
/// permutation) would have to read a different salt candidate per mode and pay a
/// derivation on each. One address space for the salt block, one derivation.
///
/// Returns `None` when the carrier is too small to hold the layout, so the
/// caller can decline it through the same `NoPayloadFound` as any other failure.
pub(crate) fn v3_salt_block_slots(total: usize, passphrase: &[u8]) -> Option<Vec<usize>> {
    if total < slotseed::MIN_V3_SLOTS {
        return None;
    }
    let mut all = permute_set((0..total).collect(), passphrase);
    // Truncating after the full shuffle, not during it. `permute_set`'s doc
    // explains why that is not a wasted pass: Fisher-Yates settles position zero
    // last, so the front of the stream does not exist until every draw is done,
    // and an attacker pays the whole permutation per candidate either way.
    all.truncate(slotseed::SALT_BLOCK_BITS);
    Some(all)
}

/// Stage two: the slots carrying the metadata and the ciphertext.
///
/// `raw` is the embedding mode's slot set in its own canonical order (ascending
/// for sequential, block-scan order for adaptive). The salt block's slots are
/// removed so the two stages cannot collide, then what is left is permuted by
/// the derived seed.
///
/// The filter preserves `raw`'s order and the reserved set is a positional
/// bitmap rather than a hash set, so no iteration order over an unordered
/// collection reaches the result. Two runs on one carrier agree byte for byte.
pub(crate) fn v3_payload_slots(
    raw: Vec<usize>,
    salt_slots: &[usize],
    total: usize,
    seed: &[u8; slotseed::SLOT_SEED_LEN],
) -> Vec<usize> {
    let mut reserved = vec![false; total];
    for &s in salt_slots {
        if s < total {
            reserved[s] = true;
        }
    }
    let rest: Vec<usize> = raw.into_iter().filter(|&s| !reserved[s]).collect();
    // A 32-byte seed folds to itself in `permute_set`, so this is a plain
    // ChaCha8 shuffle with no XOR fold in the path: the fold's two collision
    // families cannot reach stage two.
    permute_set(rest, seed)
}

/// Both stages at once, for a writer that is generating a fresh salt block or a
/// reader that has just recovered one.
///
/// Sequenced rather than parallel, and the stage-two seed is derived before the
/// message key is touched, so the two 128 MiB Argon2id working sets never exist
/// at the same time. That was ADR-002 loophole 7: two derivations must not mean
/// double peak memory on a machine that may already be tight.
fn v3_slots(
    total: usize,
    raw: Vec<usize>,
    passphrase: &[u8],
    salt_block: &[u8],
) -> Result<(Vec<usize>, Vec<usize>), StegError> {
    let salt_slots = v3_salt_block_slots(total, passphrase).ok_or(StegError::NoPayloadFound)?;
    let seed = slotseed::derive_slot_seed(passphrase, salt_block)?;
    let payload_slots = v3_payload_slots(raw, &salt_slots, total, &seed);
    Ok((salt_slots, payload_slots))
}

/// Lift the stage-one salt block out of a carrier's low bits.
fn v3_read_salt_block(
    carrier: &[u8],
    total: usize,
    passphrase: &[u8],
) -> Result<(Vec<usize>, Vec<u8>), StegError> {
    let salt_slots = v3_salt_block_slots(total, passphrase).ok_or(StegError::NoPayloadFound)?;
    let salt_block = extract_bits(carrier, &salt_slots, slotseed::SALT_BLOCK_LEN)?;
    Ok((salt_slots, salt_block))
}

/// Read a `rust-v3` payload out of a carrier whose low bits are `carrier` and
/// whose mode slot sets are `raw_sets`, tried in order.
///
/// One salt-block read and **one** stage-two derivation serve every mode, which
/// is the whole reason the salt block lives in the full address space. A wrong
/// passphrase therefore costs exactly one derivation here no matter how many
/// modes are on the list.
fn v3_read_payload(
    carrier: &[u8],
    total: usize,
    passphrase: &[u8],
    raw_sets: &[Vec<usize>],
) -> Result<(Meta, Vec<u8>), StegError> {
    let (salt_slots, salt_block) = v3_read_salt_block(carrier, total, passphrase)?;
    let seed = slotseed::derive_slot_seed(passphrase, &salt_block)?;

    let mut last = StegError::NoPayloadFound;
    for raw in raw_sets {
        let slots = v3_payload_slots(raw.clone(), &salt_slots, total, &seed);
        match read_payload(carrier, &slots) {
            Ok(found) => return Ok(found),
            // Every structural failure is a candidate for the next mode, and all
            // of them collapse to one error at the public boundary anyway. A
            // garbage metadata block that happens to parse as JSON with an
            // unrecognised `engine` tag must not abort the ladder early, which
            // would give it a distinguishable duration and error path.
            Err(
                e @ (StegError::NoPayloadFound
                | StegError::CorruptedFile
                | StegError::LegacyKeyFile),
            ) => last = e,
            Err(other) => return Err(other),
        }
    }
    Err(last)
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

/// The raw, unpermuted slot set an embedding mode selects, in its own canonical
/// order. Ascending for sequential; block-scan order for adaptive, which falls
/// back to the whole frame when variance selection finds too little to work with.
fn image_raw_slots(rgb: &RgbImage, mode: &str) -> Vec<usize> {
    let (w, h) = rgb.dimensions();
    let total = (w * h) as usize * 3;
    if mode == "adaptive" {
        let s = index_set_adaptive(rgb);
        if s.len() < 16 {
            (0..total).collect()
        } else {
            s
        }
    } else {
        (0..total).collect()
    }
}

/// The legacy (`rust-v1` and `rust-v2`) image slot order: one passphrase-seeded
/// permutation, payload from its first slot.
fn image_slots(rgb: &RgbImage, mode: &str, passphrase: &[u8]) -> Vec<usize> {
    permute_set(image_raw_slots(rgb, mode), passphrase)
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
    let total = (w * h) as usize * 3;
    let mut pixels = rgb.as_raw().to_vec();

    let salt_block = crypto::generate_salt();
    let (salt_slots, payload_slots) =
        v3_slots(total, image_raw_slots(&rgb, mode), passphrase, &salt_block)?;

    // Disjoint by construction: `v3_payload_slots` removes the salt block's
    // slots from the payload set, so the write order does not matter.
    embed_bits(&mut pixels, &salt_slots, &salt_block)?;
    embed_bits(&mut pixels, &payload_slots, stego_payload)?;

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

/// Read an image payload, trying the layouts cheapest-first.
///
/// # Why the legacy layout is tried first
///
/// It costs no key derivation, so a file written by 4.1.0 or earlier opens at
/// exactly the cost it opened at before this change: nothing regresses for
/// somebody's existing library. A `rust-v3` file fails both legacy attempts on
/// a couple of cheap permutations and then opens on the third, paying the two
/// derivations its format exists to charge.
///
/// It does not reintroduce the weakness. A `rust-v3` file never yields to the
/// legacy layout, so somebody guessing at one still has to reach the v3 attempt,
/// and that attempt derives before it can reject. The gain is only for files
/// written in the new format; files already on disk stay exactly as weak as they
/// are, which is not fixable, because their layout is fixed.
fn do_extract_image(stego_path: &Path, passphrase: &[u8]) -> Result<(Meta, Vec<u8>), StegError> {
    let rgb = load_frame(stego_path)?.to_rgb8();
    let pixels = rgb.as_raw().to_vec();
    let (w, h) = rgb.dimensions();
    let total = (w * h) as usize * 3;

    for mode in ["sequential", "adaptive"] {
        match read_payload(&pixels, &image_slots(&rgb, mode, passphrase)) {
            Ok(found) => return Ok(found),
            Err(
                StegError::NoPayloadFound | StegError::CorruptedFile | StegError::LegacyKeyFile,
            ) => {}
            Err(e) => return Err(e),
        }
    }

    let raw_sets = vec![
        image_raw_slots(&rgb, "sequential"),
        image_raw_slots(&rgb, "adaptive"),
    ];
    v3_read_payload(&pixels, total, passphrase, &raw_sets)
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
    if !is_supported_engine(&meta.engine) {
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

fn do_embed_wav(
    cover_path: &Path,
    stego_payload: &[u8],
    passphrase: &[u8],
    out_path: &Path,
) -> Result<(), StegError> {
    let mut file = wav::read(cover_path)?;
    let total = file.samples.len();

    let salt_block = crypto::generate_salt();
    let (salt_slots, slots) = v3_slots(total, (0..total).collect(), passphrase, &salt_block)?;

    let bits = stego_payload.len() * 8;
    if slots.len() < bits {
        return Err(StegError::InsufficientCapacity {
            required: stego_payload.len(),
            available: slots.len() / 8,
        });
    }
    for (i, &slot) in salt_slots.iter().enumerate() {
        let bit = (salt_block[i / 8] >> (7 - i % 8)) & 1;
        file.samples.set_lsb(slot, bit);
    }
    for (i, &slot) in slots.iter().take(bits).enumerate() {
        let bit = (stego_payload[i / 8] >> (7 - i % 8)) & 1;
        file.samples.set_lsb(slot, bit);
    }
    // Encode into memory, then write atomically (no partial file on failure).
    let buf = wav::encode(file.spec, &file.samples)?;
    atomic_write_bytes(out_path, &buf)
}

/// The legacy-then-`rust-v3` ladder for a carrier with one slot set and no
/// embedding modes, which is both audio formats.
///
/// Shared rather than copied. The WAV and FLAC readers each carried their own
/// transcription of the three-pass header walk, so a fix to one silently left
/// the other behind; both now go through `read_payload` and this ladder.
fn extract_single_mode_carrier(
    carrier: &[u8],
    total: usize,
    passphrase: &[u8],
) -> Result<(Meta, Vec<u8>), StegError> {
    match read_payload(carrier, &permute_set((0..total).collect(), passphrase)) {
        Ok(found) => return Ok(found),
        Err(StegError::NoPayloadFound | StegError::CorruptedFile | StegError::LegacyKeyFile) => {}
        Err(e) => return Err(e),
    }
    v3_read_payload(carrier, total, passphrase, &[(0..total).collect()])
}

fn do_extract_wav(stego_path: &Path, passphrase: &[u8]) -> Result<(Meta, Vec<u8>), StegError> {
    let file = wav::read(stego_path)?;
    let total = file.samples.len();
    let pseudo: Vec<u8> = (0..total).map(|i| file.samples.low_byte(i)).collect();
    extract_single_mode_carrier(&pseudo, total, passphrase)
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

    let salt_block = crypto::generate_salt();
    let (salt_slots, slots) = v3_slots(total, (0..total).collect(), passphrase, &salt_block)?;

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
    for (i, &slot) in salt_slots.iter().enumerate() {
        let bit = ((salt_block[i / 8] >> (7 - i % 8)) & 1) as i32;
        let sample = &mut audio.samples[slot % channels][slot / channels];
        *sample = (*sample & !1) | bit;
    }
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

    // Low byte of every interleaved sample, in the same slot order as embedding.
    let pseudo = interleave_flac(&audio)
        .into_iter()
        .map(|s| s as u8)
        .collect::<Vec<u8>>();

    extract_single_mode_carrier(&pseudo, total, passphrase)
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

    // The JPEG DCT carrier runs its own shuffle and `rust-v3` does not reach it,
    // so it keeps the tag that describes what it actually does. See
    // [`WIRE_FORMAT_LEGACY_SHUFFLE`](crate::forensics::WIRE_FORMAT_LEGACY_SHUFFLE).
    let is_jpeg = fmt == "jpg" || fmt == "jpeg";
    let engine_tag = if is_jpeg {
        WIRE_FORMAT_LEGACY_SHUFFLE
    } else {
        WIRE_FORMAT_VERSION
    };

    let meta = Meta {
        engine: engine_tag.into(),
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
    } else if is_jpeg {
        do_embed_jpeg(cover_path, &stego_payload, passphrase, out_path)?
    } else {
        do_embed_image(cover_path, &stego_payload, passphrase, mode, out_path, &fmt)?
    };

    let kf = if export_key {
        Some(KeyFile::new_tagged(
            engine_tag,
            cipher,
            nonce,
            salt.to_vec(),
        ))
    } else {
        None
    };
    Ok((written_path, kf))
}

/// Slot order within one deniable half, `rust-v3` style.
///
/// `base` is the half of the partition this payload occupies, in partition
/// order. The seed comes from the key file's salt, so the payload starts at the
/// half's first slot with nothing reserved ahead of it: there is no salt block
/// here, and `deniable_half_has_no_salt_block` proves the offset is zero.
fn deniable_half_slots_v3(
    base: Vec<usize>,
    passphrase: &[u8],
    salt: &[u8],
) -> Result<Vec<usize>, StegError> {
    let seed = slotseed::derive_slot_seed(passphrase, salt)?;
    Ok(permute_set(base, &seed))
}

/// Slot order within one deniable half, as 4.1.0 and earlier wrote it.
fn deniable_half_slots_legacy(base: Vec<usize>, passphrase: &[u8]) -> Vec<usize> {
    permute_set(base, passphrase)
}

/// Every random choice `embed_deniable` makes, lifted out of it.
///
/// Not a convenience. The claim deniable mode rests on is that the file does not
/// reveal which half is real, and that claim cannot be *tested* while the coin
/// that decides it is drawn inside the function under test. With the entropy
/// supplied, the symmetry test can embed the same two payloads under opposite
/// coins and assert the two files are byte-identical, which is the claim stated
/// as an equation rather than as a hope.
#[derive(Debug, Clone)]
struct DeniableEntropy {
    /// Seeds the partition shuffle that splits the cover into two halves.
    pseed: [u8; 32],
    /// Which half the real payload goes in. 0 or 1, from an `OsRng` coin.
    real_half: u8,
    real_salt: [u8; 32],
    real_nonce: Vec<u8>,
    decoy_salt: [u8; 32],
    decoy_nonce: Vec<u8>,
}

impl DeniableEntropy {
    fn fresh(cipher: Cipher) -> Self {
        let mut pseed = [0u8; 32];
        OsRng.fill_bytes(&mut pseed);

        // Randomise which partition half the real payload goes in, so an
        // adversary cannot infer "half 0 is always the real one".
        let mut coin = [0u8; 1];
        OsRng.fill_bytes(&mut coin);

        DeniableEntropy {
            pseed,
            real_half: coin[0] & 1,
            real_salt: crypto::generate_salt(),
            real_nonce: crypto::generate_nonce(cipher),
            decoy_salt: crypto::generate_salt(),
            decoy_nonce: crypto::generate_nonce(cipher),
        }
    }
}

/// Embed two payloads into one cover for deniable mode. Always exports both key files.
///
/// # Deniable mode needs no stage-one salt block, and that is the point
///
/// An ordinary `rust-v3` file hides a 32-byte salt block in the carrier because
/// the reader has nowhere else to find a salt before it can derive anything.
/// A deniable file does have somewhere else: this function already writes the
/// salt into both exported key files, and `extract_with_keyfile` is holding one
/// of them before it touches a pixel. So the stage-two seed comes from
/// `derive_slot_seed(passphrase, keyfile.salt)` and the carrier keeps nothing
/// extra at all.
///
/// That matters more than it saves. ADR-002's loophole 5 called the deniable
/// interaction the sharpest unknown in the whole change, because the obvious
/// construction wanted **two** stage-one blocks, one per half, and two blocks
/// are two positions, and two positions are something the real/decoy coin could
/// be inferred from. Zero blocks cannot leak a coin. The file written here is
/// the same shape as the one 4.1.0 wrote: two payloads, one per half, nothing
/// else.
///
/// What the coin still touches is exactly one thing: which half index each
/// payload is written into. Both halves are then treated by identical code with
/// identical structure, so the coin cannot be recovered from the file. That is
/// proved, not asserted, by `deniable_file_is_identical_under_the_opposite_coin`.
pub fn embed_deniable(
    cover_path: &Path,
    real_payload: &[u8],
    decoy_payload: &[u8],
    real_passphrase: &[u8],
    decoy_passphrase: &[u8],
    cipher: Cipher,
    out_path: &Path,
) -> Result<(KeyFile, KeyFile), StegError> {
    embed_deniable_with_entropy(
        cover_path,
        real_payload,
        decoy_payload,
        real_passphrase,
        decoy_passphrase,
        cipher,
        out_path,
        &DeniableEntropy::fresh(cipher),
    )
}

#[allow(clippy::too_many_arguments)]
fn embed_deniable_with_entropy(
    cover_path: &Path,
    real_payload: &[u8],
    decoy_payload: &[u8],
    real_passphrase: &[u8],
    decoy_passphrase: &[u8],
    cipher: Cipher,
    out_path: &Path,
    entropy: &DeniableEntropy,
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

    let pseed_b64 = B64.encode(entropy.pseed);

    let real_half = entropy.real_half & 1;
    let decoy_half = 1 - real_half;

    let real_salt = entropy.real_salt;
    let real_nonce = entropy.real_nonce.clone();
    let real_ct = encrypt_payload(
        real_passphrase,
        real_payload,
        cipher,
        &real_salt,
        &real_nonce,
    )?;

    let decoy_salt = entropy.decoy_salt;
    let decoy_nonce = entropy.decoy_nonce.clone();
    let decoy_ct = encrypt_payload(
        decoy_passphrase,
        decoy_payload,
        cipher,
        &decoy_salt,
        &decoy_nonce,
    )?;

    let real_meta = Meta {
        engine: WIRE_FORMAT_VERSION.into(),
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
        engine: WIRE_FORMAT_VERSION.into(),
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
    let all_slots = permute_set((0..total).collect(), &entropy.pseed);
    let (half0, half1) = bifurcate(all_slots);
    let real_base = if real_half == 0 {
        half0.clone()
    } else {
        half1.clone()
    };
    let decoy_base = if decoy_half == 0 { half0 } else { half1 };

    // `rust-v3` inside the halves, with no stage-one block: the seed comes from
    // the salt that is already going into the key file. Identical treatment for
    // both halves, so nothing here can be a function of the coin.
    let real_slots = deniable_half_slots_v3(real_base, real_passphrase, &real_salt)?;
    let decoy_slots = deniable_half_slots_v3(decoy_base, decoy_passphrase, &decoy_salt)?;

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
fn oracle_normalise<T>(r: Result<T, StegError>) -> Result<T, StegError> {
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

        if keyfile.deniable {
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

            // The deniable carrier holds no stage-one salt block, so it cannot
            // say which layout wrote it; the key file's tag is the only record.
            // Both layouts are still tried, cheapest first, because a key file
            // whose tag is wrong or absent must not make a recoverable file
            // unrecoverable.
            let (preferred, fallback) = if keyfile.uses_derived_slot_seed() {
                (
                    deniable_half_slots_v3(base.clone(), passphrase, &keyfile.salt)?,
                    deniable_half_slots_legacy(base, passphrase),
                )
            } else {
                (
                    deniable_half_slots_legacy(base.clone(), passphrase),
                    deniable_half_slots_v3(base, passphrase, &keyfile.salt)?,
                )
            };

            match do_extract_image_with_slots(&pixels, &preferred) {
                Ok((meta, ct)) => return decrypt_meta(&meta, &ct, passphrase),
                Err(
                    StegError::NoPayloadFound | StegError::CorruptedFile | StegError::LegacyKeyFile,
                ) => {}
                Err(e) => return Err(e),
            }
            let (meta, ct) = do_extract_image_with_slots(&pixels, &fallback)?;
            return decrypt_meta(&meta, &ct, passphrase);
        }

        // Non-deniable image: the key file records no embedding mode and no
        // layout we can trust over the file itself, so this is the same
        // legacy-then-v3 ladder `extract` walks.
        for mode in ["sequential", "adaptive"] {
            match do_extract_image_with_slots(&pixels, &image_slots(&rgb, mode, passphrase)) {
                Ok((meta, ct)) => return decrypt_meta(&meta, &ct, passphrase),
                Err(
                    StegError::NoPayloadFound | StegError::CorruptedFile | StegError::LegacyKeyFile,
                ) => {}
                Err(e) => return Err(e),
            }
        }
        let raw_sets = vec![
            image_raw_slots(&rgb, "sequential"),
            image_raw_slots(&rgb, "adaptive"),
        ];
        let (meta, ct) = v3_read_payload(&pixels, total, passphrase, &raw_sets)?;
        decrypt_meta(&meta, &ct, passphrase)
    };
    oracle_normalise(run())
}

/// Read the embedded metadata header from a stego file. Requires the passphrase
/// because slot selection is passphrase-seeded, and the passphrase must
/// additionally authenticate: the payload is decrypted and its AEAD tag verified
/// before any metadata is returned, then the plaintext is discarded.
///
/// Returns the metadata as a JSON string.
///
/// The decryption is not here to produce the plaintext, it is the proof of
/// possession. Without it this function answered "yes, and here are the salt,
/// the nonce, the cipher and the payload length" to any passphrase that merely
/// reproduced the slot permutation, which is a weaker secret than the key
/// (`permute_set` folds the passphrase with XOR and seeds ChaCha8; no KDF is
/// involved) and which cost no Argon2id work to confirm. That made `info` a
/// positive confirmation oracle roughly two orders of magnitude cheaper than
/// the `extract` path whose cost the tool advertises.
pub fn read_meta(path: &Path, passphrase: &[u8]) -> Result<String, StegError> {
    let read = || -> Result<String, StegError> {
        let fmt = detect_format(path)?;
        let (meta, ct) = if fmt == "wav" {
            do_extract_wav(path, passphrase)?
        } else if fmt == "flac" {
            do_extract_flac(path, passphrase)?
        } else if fmt == "jpg" || fmt == "jpeg" {
            do_extract_jpeg(path, passphrase)?
        } else {
            do_extract_image(path, passphrase)?
        };
        let plaintext = zeroize::Zeroizing::new(decrypt_meta(&meta, &ct, passphrase)?);
        drop(plaintext);
        Ok(serde_json::to_string_pretty(&meta)?)
    };
    oracle_normalise(read())
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
            engine: WIRE_FORMAT_VERSION.into(),
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

    // ── Byte-perfect copyright vector ─────────────────────────────────────────

    /// Golden stego payload for fixed (passphrase, payload, cipher, salt,
    /// nonce). With every crypto input pinned, the whole pipeline (Argon2 key
    /// derivation, zstd compression, AEAD encryption, and the wire format) is a
    /// pure function of the inputs, so the output bytes are fixed. A third-party
    /// tool that produces these exact bytes from the same inputs has copied the
    /// pipeline. Combined with the permutation vectors (which fix where the
    /// bytes land in a cover), this pins Stegcore's output byte for byte.
    ///
    /// Regenerate after a deliberate, version-bumped format change with
    /// `REGEN_VECTORS=1 cargo test -p stegcore-engine byte_perfect`.
    ///
    /// `rust-v3` moved this by exactly one byte: the tag inside the metadata
    /// JSON. Nothing else in the payload block changed, because `rust-v3`
    /// changed *where* the block goes in a carrier and not what the block is.
    /// The v2 vector is kept below as a historical record rather than edited,
    /// per the rule in `forensics.rs`.
    const BYTE_PERFECT_GOLDEN: &str =
        "00e77b22656e67696e65223a22727573742d7633222c22636970686572223a2263686163686132302d706f6c7931333035222c226d6f6465223a2273657175656e7469616c222c226e6f6e6365223a2249694969496949694969496949694969222c2273616c74223a22455245524552455245524552455245524552455245524552455245524552455245524552455245524552453d222c22636970686572746578745f6c656e223a38322c2264656e6961626c65223a66616c73652c22706172746974696f6e5f73656564223a6e756c6c2c22706172746974696f6e5f68616c66223a6e756c6c7dbfc6094e058596a028f6567c6e9526502766fc442a06d9af3221171cdcb5b09e1f988dde17f43a43f9ad65e451a00d126d8e0769921e97b8deca6249f156e7bbcae5173ca7680255f86e712a76f0890bfe77";

    /// The `rust-v2` byte-perfect vector, kept as a historical record.
    ///
    /// Not edited and not deleted: the published vectors are evidence about
    /// which format they describe, and a vector that has been quietly rewritten
    /// is evidence of nothing. The test below holds it to the one thing that
    /// still has to be true of it, which is that this build can still read it.
    const BYTE_PERFECT_GOLDEN_V2: &str =
        "00e77b22656e67696e65223a22727573742d7632222c22636970686572223a2263686163686132302d706f6c7931333035222c226d6f6465223a2273657175656e7469616c222c226e6f6e6365223a2249694969496949694969496949694969222c2273616c74223a22455245524552455245524552455245524552455245524552455245524552455245524552455245524552453d222c22636970686572746578745f6c656e223a38322c2264656e6961626c65223a66616c73652c22706172746974696f6e5f73656564223a6e756c6c2c22706172746974696f6e5f68616c66223a6e756c6c7dbfc6094e058596a028f6567c6e9526502766fc442a06d9af3221171cdcb5b09e1f988dde17f43a43f9ad65e451a00d126d8e0769921e97b8deca6249f156e7bbcae5173ca7680255f86e712a76f0890bfe77";

    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("vector is hex"))
            .collect()
    }

    /// The historical v2 vector must still parse under this build, which is the
    /// whole compatibility promise restated at the byte level.
    #[test]
    fn the_v2_byte_perfect_vector_still_parses() {
        let bytes = hex_to_bytes(BYTE_PERFECT_GOLDEN_V2);
        let (meta, ct) = parse_stego_payload(&bytes)
            .expect("a rust-v2 payload must still parse after the v3 bump");
        assert_eq!(meta.engine, "rust-v2");
        assert_eq!(ct.len(), meta.ciphertext_len);

        // And it is genuinely the same payload block the v3 vector is, give or
        // take the tag, which is what makes "one byte moved" a checked claim
        // rather than a comment.
        let v3 = hex_to_bytes(BYTE_PERFECT_GOLDEN);
        assert_eq!(v3.len(), bytes.len());
        let differing = v3.iter().zip(bytes.iter()).filter(|(a, b)| a != b).count();
        assert_eq!(
            differing, 1,
            "the v2 and v3 payload blocks should differ only in the tag byte"
        );
    }

    fn deterministic_stego_payload() -> Vec<u8> {
        let passphrase = b"stegcore-copyright-vector";
        let payload = b"Stegcore byte-perfect copyright vector, wire format rust-v1.";
        let cipher = Cipher::ChaCha20Poly1305;
        let salt = [0x11u8; 32];
        let nonce = vec![0x22u8; cipher.nonce_len()];
        let ct = encrypt_payload(passphrase, payload, cipher, &salt, &nonce).unwrap();
        let meta = Meta {
            engine: WIRE_FORMAT_VERSION.into(),
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

    fn to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn byte_perfect_stego_payload_vector() {
        let hex = to_hex(&deterministic_stego_payload());
        if std::env::var("REGEN_VECTORS").is_ok() {
            eprintln!("BYTE_PERFECT_GOLDEN = \"{hex}\"");
            return;
        }
        assert_eq!(
            hex, BYTE_PERFECT_GOLDEN,
            "byte-perfect stego payload changed; the crypto or wire-format \
             pipeline moved. If deliberate, bump the wire format and regenerate \
             with REGEN_VECTORS=1"
        );
    }

    #[test]
    fn deterministic_stego_payload_is_stable_across_runs() {
        // The byte-perfect vector is only meaningful if the pipeline is a pure
        // function of its inputs; prove that here independent of the golden.
        assert_eq!(deterministic_stego_payload(), deterministic_stego_payload());
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

    /// An output path inside a private temp dir, holding NO open file handle
    /// on the target file. The engine writes the stego output by renaming a
    /// sibling temp file into place; Windows refuses to rename over an open
    /// file (Unix allows it), so returning a `NamedTempFile` here (which keeps
    /// its handle open) made every embed test fail on Windows with
    /// "Access is denied". The temp dir cleans up the output on drop.
    struct OutPath {
        _dir: tempfile::TempDir,
        path: std::path::PathBuf,
    }

    impl OutPath {
        fn path(&self) -> &std::path::Path {
            &self.path
        }
    }

    fn out(suffix: &str) -> OutPath {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(format!("out{suffix}"));
        OutPath { _dir: dir, path }
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
    fn streamed_wav_scoring_is_bit_identical_to_the_whole_file_sum() {
        // Scoring streams in two passes now, because decoding the whole file
        // cost about 14 times its size in peak memory. The number it produces
        // has to be the same f64 to the last bit, or every cover that sat near
        // the embed gate's threshold changes side.
        let file = noisy_wav(3);
        let path = file.path();

        let whole = wav::read(path).unwrap();
        let scale = if matches!(whole.samples, wav::Samples::Float(_)) {
            8_388_607.0
        } else {
            wav::full_scale(&whole.spec)
        };
        let samples: Vec<f64> = whole
            .samples
            .to_i32()
            .into_iter()
            .map(|s| s as f64)
            .collect();
        let n = samples.len() as f64;
        let mean = samples.iter().sum::<f64>() / n;
        let variance = samples.iter().map(|&v| (v - mean).powi(2)).sum::<f64>() / n;
        let reference = (variance / scale.powi(2)).sqrt().min(1.0);

        let streamed = assess_wav(path).unwrap();
        assert_eq!(
            streamed.to_bits(),
            reference.to_bits(),
            "streamed {streamed} against whole-file {reference}"
        );
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

    // ── WAV sample formats (issue #47) ────────────────────────────────────────
    //
    // Every audio path used to read `samples::<i16>()`, so 16-bit PCM was the
    // only carrier that worked: 24-bit and float died inside hound, and 8-bit
    // was refused as a poor cover because the quality score divided by
    // i16::MAX. These cover the formats a real recording actually arrives in.

    /// A noisy WAV in an arbitrary spec, amplitude filling the format's range.
    fn noisy_wav_spec(
        bits: u16,
        format: hound::SampleFormat,
        channels: u16,
        frames: u32,
    ) -> tempfile::NamedTempFile {
        let f = Builder::new().suffix(".wav").tempfile().unwrap();
        let spec = hound::WavSpec {
            channels,
            sample_rate: 44100,
            bits_per_sample: bits,
            sample_format: format,
        };
        let mut writer = hound::WavWriter::create(f.path(), spec).unwrap();
        let mut rng = ChaCha8Rng::seed_from_u64(0x5EED);
        for _ in 0..(frames * channels as u32) {
            match format {
                hound::SampleFormat::Float => {
                    let v = (rng.next_u32() as f64 / u32::MAX as f64) as f32 * 1.6 - 0.8;
                    writer.write_sample(v).unwrap();
                }
                hound::SampleFormat::Int => {
                    let span = 1i64 << (bits - 1);
                    let v = (rng.next_u32() as i64 % span) - span / 2;
                    writer.write_sample(v as i32).unwrap();
                }
            }
        }
        writer.finalize().unwrap();
        f
    }

    fn wav_roundtrip_at(bits: u16, format: hound::SampleFormat, channels: u16) {
        let cover = noisy_wav_spec(bits, format, channels, 44100);
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
        .unwrap_or_else(|e| panic!("embed failed for {bits}-bit {format:?}: {e}"));
        assert_eq!(
            extract(o.path(), PASS).unwrap(),
            MSG,
            "payload did not survive {bits}-bit {format:?}"
        );

        // The carrier must come back in the format the user handed us.
        let before = hound::WavReader::open(cover.path()).unwrap().spec();
        let after = hound::WavReader::open(o.path()).unwrap().spec();
        assert_eq!(before.bits_per_sample, after.bits_per_sample);
        assert_eq!(before.sample_format, after.sample_format);
        assert_eq!(before.channels, after.channels);
        assert_eq!(before.sample_rate, after.sample_rate);
    }

    #[test]
    fn roundtrip_wav_8bit() {
        wav_roundtrip_at(8, hound::SampleFormat::Int, 1);
    }

    #[test]
    fn roundtrip_wav_24bit() {
        wav_roundtrip_at(24, hound::SampleFormat::Int, 1);
    }

    #[test]
    fn roundtrip_wav_32bit_int() {
        wav_roundtrip_at(32, hound::SampleFormat::Int, 1);
    }

    #[test]
    fn roundtrip_wav_32bit_float() {
        wav_roundtrip_at(32, hound::SampleFormat::Float, 1);
    }

    #[test]
    fn roundtrip_wav_stereo_24bit() {
        wav_roundtrip_at(24, hound::SampleFormat::Int, 2);
    }

    /// The 8-bit half of issue #47: ordinary audio scored 0 and was refused as
    /// an unsuitable cover, because the score was normalised against i16::MAX.
    #[test]
    fn assess_8bit_wav_is_not_scored_as_silence() {
        let cover = noisy_wav_spec(8, hound::SampleFormat::Int, 1, 44100);
        let score = assess(cover.path()).unwrap();
        assert!(
            score > 0.1,
            "8-bit audio scored {score}, which the embed gate would refuse"
        );
    }

    /// A quality score should mean the same thing at every bit depth: the same
    /// signal at 8 and 16 bits should land in the same region, not an order of
    /// magnitude apart.
    #[test]
    fn assess_is_comparable_across_bit_depths() {
        let a = assess(noisy_wav_spec(8, hound::SampleFormat::Int, 1, 44100).path()).unwrap();
        let b = assess(noisy_wav_spec(16, hound::SampleFormat::Int, 1, 44100).path()).unwrap();
        assert!(
            (a - b).abs() < 0.25,
            "8-bit scored {a}, 16-bit scored {b}; normalisation is still bit-depth dependent"
        );
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
            engine: WIRE_FORMAT_VERSION.into(),
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
            oracle_normalise(Err::<Vec<u8>, _>(StegError::LegacyKeyFile)),
            Err(StegError::NoPayloadFound)
        ));
        assert!(matches!(
            oracle_normalise(Err::<Vec<u8>, _>(StegError::CorruptedFile)),
            Err(StegError::NoPayloadFound)
        ));
        // Success and passphrase-independent errors pass through unchanged.
        assert_eq!(oracle_normalise(Ok(vec![1, 2, 3])).unwrap(), vec![1, 2, 3]);
        assert!(matches!(
            oracle_normalise(Err::<Vec<u8>, _>(StegError::DecryptionFailed)),
            Err(StegError::DecryptionFailed)
        ));
        // NoPayloadFound and DecryptionFailed must render identical text.
        assert_eq!(
            StegError::NoPayloadFound.to_string(),
            StegError::DecryptionFailed.to_string()
        );
    }

    #[test]
    fn seal_blob_round_trips() {
        let blob = seal_blob(b"pass", b"hello watermark", Cipher::ChaCha20Poly1305).unwrap();
        // The blob is in the engine's wire format.
        assert!(looks_like_stego_payload(&blob));
        assert_eq!(open_blob(&blob, b"pass").unwrap(), b"hello watermark");
    }

    #[test]
    fn seal_blob_round_trips_every_cipher() {
        for cipher in [
            Cipher::Ascon128,
            Cipher::ChaCha20Poly1305,
            Cipher::Aes256Gcm,
        ] {
            let blob = seal_blob(b"k", b"payload bytes", cipher).unwrap();
            assert_eq!(open_blob(&blob, b"k").unwrap(), b"payload bytes");
        }
    }

    #[test]
    fn seal_blob_rejects_empty_payload() {
        assert!(matches!(
            seal_blob(b"pass", b"", Cipher::ChaCha20Poly1305),
            Err(StegError::EmptyPayload)
        ));
    }

    #[test]
    fn open_blob_wrong_passphrase_is_oracle_resistant() {
        let blob = seal_blob(b"right", b"secret", Cipher::Aes256Gcm).unwrap();
        let err = open_blob(&blob, b"wrong").unwrap_err();
        assert_eq!(err.to_string(), StegError::NoPayloadFound.to_string());
    }

    #[test]
    fn open_blob_rejects_non_blob_bytes() {
        assert!(open_blob(b"not a stegcore blob at all", b"pass").is_err());
        assert!(open_blob(&[], b"pass").is_err());
    }

    #[test]
    fn seal_blob_is_not_byte_stable_across_calls() {
        // Fresh salt and nonce per call, so two seals of the same input differ.
        let a = seal_blob(b"k", b"same", Cipher::ChaCha20Poly1305).unwrap();
        let b = seal_blob(b"k", b"same", Cipher::ChaCha20Poly1305).unwrap();
        assert_ne!(a, b);
        // Both still decrypt to the same plaintext.
        assert_eq!(open_blob(&a, b"k").unwrap(), open_blob(&b, b"k").unwrap());
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

    /// The legacy permutation's published vector for a 16-slot set under the seed
    /// `b"stegcore-kat"`. Regenerated only when the format deliberately changes,
    /// and then the old value is kept in the history rather than edited away.
    const KAT_PROBE: [usize; 16] = [6, 14, 8, 4, 12, 13, 0, 1, 10, 15, 3, 11, 2, 7, 5, 9];

    /// Known-answer vector for the legacy permutation.
    ///
    /// The point of a KAT here is not that these particular numbers matter; it is
    /// that ANY change to the shuffle strategy changes them. `partial_shuffle`,
    /// a forwards Fisher-Yates, a different PRNG or a different seed fold would
    /// all still produce a valid permutation and would all fail this test. See
    /// `permute_set`'s doc comment for why that matters: the protection against
    /// cheap candidate filtering is a property of the shuffle direction, and
    /// nothing else in the suite would notice it going away.
    #[test]
    fn permute_set_matches_its_published_vector() {
        let got = permute_set((0..16).collect(), b"stegcore-kat");
        assert_eq!(got, KAT_PROBE, "the legacy slot permutation changed");
    }

    /// The whole set is shuffled, so the front of the stream cannot be produced
    /// without doing the work for every slot.
    ///
    /// Growing the set only at the tail changes the front of the result. Under
    /// `partial_shuffle(16)` the first 16 positions would be drawn first and
    /// would not depend on how many slots followed them, so this assertion is
    /// what fails if anyone makes that change.
    #[test]
    fn permute_set_still_shuffles_the_whole_set_back_to_front() {
        let seed = b"length-dependence";
        let short = permute_set((0..64).collect(), seed);
        let long = permute_set((0..4096).collect(), seed);
        let short_front: Vec<usize> = short.iter().take(16).copied().collect();
        let long_front: Vec<usize> = long
            .iter()
            .take(16)
            .copied()
            .filter(|slot| *slot < 64)
            .collect();
        assert_ne!(
            short_front,
            long.iter().take(16).copied().collect::<Vec<usize>>(),
            "the front of the permutation did not depend on the size of the set, \
             which means the shuffle is no longer covering the whole set"
        );
        // Stated as its own assertion so the failure message is unambiguous: the
        // prefix of a 4096-slot permutation is essentially never a prefix of a
        // 64-slot one, because the draws that settle position zero come last.
        assert!(
            long_front.len() < 16,
            "a 4096-slot permutation's first 16 slots were all below 64, which is \
             what a partial shuffle of the first 16 positions would produce"
        );
    }

    /// The first collision family, with its witness, so it cannot be rediscovered
    /// as a surprise. Documented on `permute_set`; asserted here.
    #[test]
    fn leading_nul_bytes_fold_to_the_same_legacy_seed() {
        let plain = permute_set((0..64).collect(), b"correct horse");
        let mut prefixed = vec![0u8; 32];
        prefixed.extend_from_slice(b"correct horse");
        let padded = permute_set((0..64).collect(), &prefixed);
        assert_eq!(
            plain, padded,
            "the XOR-fold collision family has been closed; update permute_set's docs"
        );
    }

    /// The second collision family: XOR is commutative over 32-byte blocks.
    #[test]
    fn reordering_32_byte_blocks_folds_to_the_same_legacy_seed() {
        let first = [b'a'; 32];
        let second = [b'b'; 32];
        let mut forwards = first.to_vec();
        forwards.extend_from_slice(&second);
        let mut backwards = second.to_vec();
        backwards.extend_from_slice(&first);
        assert_eq!(
            permute_set((0..64).collect(), &forwards),
            permute_set((0..64).collect(), &backwards),
            "the block-commutativity collision family has been closed; update the docs"
        );
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
        let e = crate::wav::hound_err(inner);
        match e {
            StegError::Io(io) => assert_eq!(io.kind(), std::io::ErrorKind::InvalidData),
            other => panic!("expected Io, got {other:?}"),
        }
    }

    #[test]
    fn hound_err_wraps_format_error_preserving_message() {
        let e = crate::wav::hound_err(hound::Error::FormatError("bad chunk"));
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

    // ── read_meta: the `info` oracle (X1) ────────────────────────────────

    /// A passphrase that reproduces the slot permutation without being the
    /// passphrase. `permute_set` folds the seed into 32 bytes with XOR, so
    /// prefixing 32 zero bytes leaves the fold unchanged while `derive_key`
    /// sees different input. This is the cheapest witness that permutation
    /// agreement is a weaker secret than the key.
    fn permutation_twin(passphrase: &[u8]) -> Vec<u8> {
        let mut v = vec![0u8; 32];
        v.extend_from_slice(passphrase);
        assert!(
            passphrase.len() <= 32,
            "the fold only cancels within 32 bytes"
        );
        v
    }

    #[test]
    fn permutation_twin_really_selects_the_same_slots() {
        // Guards the two tests below from going vacuous: if the fold is ever
        // replaced with a hash (ledger item X5) the twin stops colliding and
        // those tests would pass for the wrong reason.
        let a = permute_set((0..512).collect(), PASS);
        let b = permute_set((0..512).collect(), &permutation_twin(PASS));
        assert_eq!(a, b);
    }

    #[test]
    fn read_meta_returns_the_header_for_the_right_passphrase() {
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
        let json = read_meta(o.path(), PASS).unwrap();
        assert!(json.contains("\"engine\""), "got {json}");
        assert!(json.contains("chacha20-poly1305"), "got {json}");
    }

    /// The property, not the implementation: `read_meta` must disclose nothing
    /// to a caller who cannot decrypt the payload, however close that caller
    /// gets to the slot selection. `DecryptionFailed` rather than
    /// `NoPayloadFound` is the non-vacuity check: it proves the metadata was
    /// located and parsed, and that authentication is what refused.
    #[test]
    fn read_meta_refuses_a_passphrase_that_cannot_decrypt() {
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
        let twin = permutation_twin(PASS);
        assert!(extract(o.path(), &twin).is_err());
        match read_meta(o.path(), &twin) {
            Err(StegError::DecryptionFailed) => {}
            other => panic!("read_meta disclosed metadata without authenticating: {other:?}"),
        }
    }

    #[test]
    fn read_meta_refuses_a_permutation_twin_on_jpeg_too() {
        // The JPEG DCT path reaches `decrypt_meta` through its own ladder, so
        // it needs its own witness.
        let cover = noisy_jpeg(300, 300);
        let o = out(".jpg");
        let (written, _) = embed(
            cover.path(),
            MSG,
            PASS,
            Cipher::ChaCha20Poly1305,
            "sequential",
            o.path(),
            false,
        )
        .unwrap();
        assert!(read_meta(&written, PASS).is_ok());
        match read_meta(&written, &permutation_twin(PASS)) {
            Err(StegError::DecryptionFailed) => {}
            other => panic!("read_meta disclosed metadata without authenticating: {other:?}"),
        }
    }

    /// `info` must not become a presence oracle: a wrong passphrase on a stego
    /// file and any passphrase on an untouched cover have to fail the same way.
    #[test]
    fn read_meta_fails_identically_on_a_stego_file_and_a_clean_cover() {
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
        let on_stego = read_meta(o.path(), b"a different passphrase").unwrap_err();
        let on_clean = read_meta(cover.path(), b"a different passphrase").unwrap_err();
        assert_eq!(on_stego.to_string(), on_clean.to_string());
        assert!(matches!(on_stego, StegError::NoPayloadFound));
        assert!(matches!(on_clean, StegError::NoPayloadFound));
    }

    #[test]
    fn oracle_normalise_collapses_payload_failures_for_the_metadata_type_too() {
        // read_meta carries a String where extract carries Vec<u8>. Both go
        // through the same normalisation, or `info` leaks exit code 4 on a
        // structure failure where `extract` says 2.
        assert!(matches!(
            oracle_normalise(Err::<String, _>(StegError::CorruptedFile)),
            Err(StegError::NoPayloadFound)
        ));
        assert!(matches!(
            oracle_normalise(Err::<String, _>(StegError::LegacyKeyFile)),
            Err(StegError::NoPayloadFound)
        ));
        assert_eq!(
            oracle_normalise(Ok::<_, StegError>("kept".to_string())).unwrap(),
            "kept"
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

    // ── rust-v3: the two-stage layout ─────────────────────────────────────────

    /// Write a cover the way 4.1.0 wrote it: one passphrase-seeded permutation
    /// over the whole mode set, payload from its first slot, no salt block.
    ///
    /// This is the only way to produce a legacy carrier now that nothing in the
    /// engine writes one, and it is the fixture the dual-read direction of the
    /// matrix is tested against. It is a transcription of the pre-v3
    /// `do_embed_image`, kept deliberately small so it cannot drift into
    /// re-testing the new path by accident.
    fn write_legacy_v2_png(
        cover: &Path,
        out: &Path,
        payload: &[u8],
        passphrase: &[u8],
        mode: &str,
    ) {
        let salt = crypto::generate_salt();
        let nonce = crypto::generate_nonce(Cipher::ChaCha20Poly1305);
        let ct =
            encrypt_payload(passphrase, payload, Cipher::ChaCha20Poly1305, &salt, &nonce).unwrap();
        let meta = Meta {
            engine: WIRE_FORMAT_LEGACY_SHUFFLE.into(),
            cipher: Cipher::ChaCha20Poly1305,
            mode: mode.into(),
            nonce,
            salt: salt.to_vec(),
            ciphertext_len: ct.len(),
            deniable: false,
            partition_seed: None,
            partition_half: None,
        };
        let stego_payload = build_stego_payload(&meta, &ct).unwrap();

        let (rgb, alpha) = load_rgb_with_alpha(cover).unwrap();
        let (w, h) = rgb.dimensions();
        let mut pixels = rgb.as_raw().to_vec();
        let slots = permute_set(image_raw_slots(&rgb, mode), passphrase);
        embed_bits(&mut pixels, &slots, &stego_payload).unwrap();
        write_frame(&pixels, w, h, alpha.as_deref(), cover, out, "png").unwrap();
    }

    /// Matrix row 1: new code writes and reads its own format.
    #[test]
    fn v3_round_trips_through_the_public_api() {
        for mode in ["sequential", "adaptive"] {
            let cover = noisy_png(64, 64);
            let out = Builder::new().suffix(".png").tempfile().unwrap();
            embed(
                cover.path(),
                MSG,
                PASS,
                Cipher::ChaCha20Poly1305,
                mode,
                out.path(),
                false,
            )
            .unwrap_or_else(|e| panic!("embed in {mode} mode: {e:?}"));
            assert_eq!(
                extract(out.path(), PASS).unwrap_or_else(|e| panic!("extract {mode}: {e:?}")),
                MSG,
                "v3 round trip failed in {mode} mode"
            );
        }
    }

    /// Matrix row 1, the tag: a file this build writes says `rust-v3`.
    #[test]
    fn v3_files_carry_the_v3_tag() {
        let cover = noisy_png(64, 64);
        let out = Builder::new().suffix(".png").tempfile().unwrap();
        embed(
            cover.path(),
            MSG,
            PASS,
            Cipher::ChaCha20Poly1305,
            "sequential",
            out.path(),
            false,
        )
        .unwrap();
        let meta = read_meta(out.path(), PASS).unwrap();
        assert!(
            meta.contains("\"engine\": \"rust-v3\""),
            "expected a rust-v3 tag, got {meta}"
        );
    }

    /// Matrix row 2: new code reads a 4.1.0 file, and gets the same bytes back.
    #[test]
    fn v3_build_reads_a_legacy_file_byte_identically() {
        for mode in ["sequential", "adaptive"] {
            let cover = noisy_png(64, 64);
            let out = Builder::new().suffix(".png").tempfile().unwrap();
            write_legacy_v2_png(cover.path(), out.path(), MSG, PASS, mode);
            assert_eq!(
                extract(out.path(), PASS)
                    .unwrap_or_else(|e| panic!("legacy {mode} must still open: {e:?}")),
                MSG,
                "a 4.1.0 file in {mode} mode came back wrong"
            );
        }
    }

    /// Matrix row 3, stated as a test rather than only in the CHANGELOG: a
    /// 4.1.0 build reads a v3 file by running the legacy derivation, and that
    /// derivation finds nothing. Reproduced here by calling the legacy slot
    /// order directly, which is exactly what that build would do.
    #[test]
    fn a_legacy_reader_finds_nothing_in_a_v3_file() {
        let cover = noisy_png(64, 64);
        let out = Builder::new().suffix(".png").tempfile().unwrap();
        embed(
            cover.path(),
            MSG,
            PASS,
            Cipher::ChaCha20Poly1305,
            "sequential",
            out.path(),
            false,
        )
        .unwrap();

        let rgb = load_frame(out.path()).unwrap().to_rgb8();
        let pixels = rgb.as_raw().to_vec();
        for mode in ["sequential", "adaptive"] {
            let legacy = permute_set(image_raw_slots(&rgb, mode), PASS);
            assert!(
                read_payload(&pixels, &legacy).is_err(),
                "the legacy {mode} derivation found a payload in a v3 file; the \
                 CHANGELOG's compatibility claim would be wrong"
            );
        }
    }

    #[test]
    fn v3_rejects_the_wrong_passphrase() {
        let cover = noisy_png(64, 64);
        let out = Builder::new().suffix(".png").tempfile().unwrap();
        embed(
            cover.path(),
            MSG,
            PASS,
            Cipher::ChaCha20Poly1305,
            "sequential",
            out.path(),
            false,
        )
        .unwrap();
        assert!(matches!(
            extract(out.path(), b"not the passphrase"),
            Err(StegError::NoPayloadFound) | Err(StegError::DecryptionFailed)
        ));
    }

    /// A carrier too small for the salt block must be declined through the same
    /// error as everything else, so a too-small file is not told apart from a
    /// payload-free one. ADR-002 loophole 3.
    #[test]
    fn a_carrier_too_small_for_the_salt_block_declines_quietly() {
        assert!(v3_salt_block_slots(slotseed::MIN_V3_SLOTS - 1, PASS).is_none());
        assert!(v3_salt_block_slots(slotseed::MIN_V3_SLOTS, PASS).is_some());

        let tiny = vec![0u8; 64];
        assert!(matches!(
            v3_read_payload(&tiny, 64, PASS, &[(0..64).collect()]),
            Err(StegError::NoPayloadFound)
        ));
    }

    #[test]
    fn the_salt_block_and_the_payload_never_share_a_slot() {
        let total = 4096;
        let salt_slots = v3_salt_block_slots(total, PASS).unwrap();
        let seed = [0x7fu8; slotseed::SLOT_SEED_LEN];
        let payload = v3_payload_slots((0..total).collect(), &salt_slots, total, &seed);

        assert_eq!(salt_slots.len(), slotseed::SALT_BLOCK_BITS);
        assert_eq!(payload.len(), total - slotseed::SALT_BLOCK_BITS);

        let mut seen = vec![false; total];
        for s in salt_slots.iter().chain(payload.iter()) {
            assert!(!seen[*s], "slot {s} used twice across the two stages");
            seen[*s] = true;
        }
        assert!(
            seen.iter().all(|&b| b),
            "the two stages must cover the carrier"
        );
    }

    #[test]
    fn v3_slot_sets_are_reproducible() {
        let total = 2048;
        let salt_block = [0x3cu8; slotseed::SALT_BLOCK_LEN];
        let a = v3_slots(total, (0..total).collect(), PASS, &salt_block).unwrap();
        let b = v3_slots(total, (0..total).collect(), PASS, &salt_block).unwrap();
        assert_eq!(a, b, "two runs on one input must agree");
    }

    #[test]
    fn v3_round_trips_through_wav_and_flac() {
        // Audio carriers take the same two-stage layout through the shared
        // single-mode ladder, so they are worth exercising end to end rather
        // than trusting the image case to cover them.
        let cover = noisy_wav(1);
        let out = Builder::new().suffix(".wav").tempfile().unwrap();
        embed(
            cover.path(),
            MSG,
            PASS,
            Cipher::ChaCha20Poly1305,
            "sequential",
            out.path(),
            false,
        )
        .unwrap();
        assert_eq!(extract(out.path(), PASS).unwrap(), MSG);
        assert!(extract(out.path(), b"wrong one entirely").is_err());
    }

    // ── Deniable mode: proving the absence of a salt block ────────────────────

    fn fixed_deniable_entropy(real_half: u8) -> DeniableEntropy {
        DeniableEntropy {
            pseed: [0x11u8; 32],
            real_half,
            real_salt: [0x22u8; 32],
            real_nonce: vec![0x33u8; Cipher::ChaCha20Poly1305.nonce_len()],
            decoy_salt: [0x44u8; 32],
            decoy_nonce: vec![0x55u8; Cipher::ChaCha20Poly1305.nonce_len()],
        }
    }

    /// **The absence proof.**
    ///
    /// The claim deniable mode makes is that the file does not say which half is
    /// real. Stated as an equation: putting A in half 0 and B in half 1 must
    /// produce the same bytes whether the coin called A real and B decoy, or
    /// B real and A decoy. If any byte of the output were a function of the
    /// coin, these two files would differ.
    ///
    /// Every other input is pinned, so the only thing varying between the two
    /// calls is the coin and the labels that follow it. A salt block per half
    /// would break this immediately: the real half's block and the decoy half's
    /// block would be written in the order the coin chose.
    #[test]
    fn deniable_file_is_identical_under_the_opposite_coin() {
        let cover = noisy_png(96, 96);

        // Coin 0: real = A goes to half 0, decoy = B goes to half 1.
        let out_a = Builder::new().suffix(".png").tempfile().unwrap();
        let (kf_real_a, kf_decoy_a) = embed_deniable_with_entropy(
            cover.path(),
            MSG,
            MSG2,
            PASS,
            PASS2,
            Cipher::ChaCha20Poly1305,
            out_a.path(),
            &fixed_deniable_entropy(0),
        )
        .unwrap();

        // Coin 1: real = B goes to half 1, decoy = A goes to half 0. The same
        // two payloads land in the same two halves under the same two
        // passphrases, with the real/decoy labels swapped. Salts and nonces
        // follow their payloads so the ciphertexts are identical too.
        let swapped = DeniableEntropy {
            pseed: [0x11u8; 32],
            real_half: 1,
            real_salt: [0x44u8; 32],
            real_nonce: vec![0x55u8; Cipher::ChaCha20Poly1305.nonce_len()],
            decoy_salt: [0x22u8; 32],
            decoy_nonce: vec![0x33u8; Cipher::ChaCha20Poly1305.nonce_len()],
        };
        let out_b = Builder::new().suffix(".png").tempfile().unwrap();
        let (kf_real_b, kf_decoy_b) = embed_deniable_with_entropy(
            cover.path(),
            MSG2,
            MSG,
            PASS2,
            PASS,
            Cipher::ChaCha20Poly1305,
            out_b.path(),
            &swapped,
        )
        .unwrap();

        let bytes_a = std::fs::read(out_a.path()).unwrap();
        let bytes_b = std::fs::read(out_b.path()).unwrap();
        assert_eq!(
            bytes_a, bytes_b,
            "the stego file differs by which half the coin called real, so the \
             coin leaks into the artefact"
        );
        assert_eq!(
            bytes_a.len(),
            bytes_b.len(),
            "file size differs by the coin"
        );

        // The routing lives only in the key files, which is where it is supposed
        // to live: the real key file in one run is the decoy key file in the
        // other, and the two carry opposite halves.
        assert_eq!(kf_real_a.partition_half, Some(0));
        assert_eq!(kf_decoy_a.partition_half, Some(1));
        assert_eq!(kf_real_b.partition_half, Some(1));
        assert_eq!(kf_decoy_b.partition_half, Some(0));
        assert_eq!(kf_real_a.salt, kf_decoy_b.salt);
        assert_eq!(kf_decoy_a.salt, kf_real_b.salt);
    }

    /// Neither embedded metadata block may admit that deniable mode was used.
    /// Already true before `rust-v3`; pinned here because the two-stage layout
    /// touched this function and a regression would be silent.
    #[test]
    fn neither_deniable_half_admits_it_is_deniable() {
        let cover = noisy_png(96, 96);
        let out = Builder::new().suffix(".png").tempfile().unwrap();
        let (real_kf, decoy_kf) = embed_deniable_with_entropy(
            cover.path(),
            MSG,
            MSG2,
            PASS,
            PASS2,
            Cipher::ChaCha20Poly1305,
            out.path(),
            &fixed_deniable_entropy(0),
        )
        .unwrap();

        for (kf, expected) in [(&real_kf, MSG), (&decoy_kf, MSG2)] {
            let rgb = load_frame(out.path()).unwrap().to_rgb8();
            let (w, h) = rgb.dimensions();
            let total = (w * h) as usize * 3;
            let pixels = rgb.as_raw().to_vec();
            let pseed = B64.decode(kf.partition_seed.as_deref().unwrap()).unwrap();
            let (first, second) = bifurcate(permute_set((0..total).collect(), &pseed));
            let base = if kf.partition_half == Some(0) {
                first
            } else {
                second
            };
            let passphrase: &[u8] = if expected == MSG { PASS } else { PASS2 };
            let slots = deniable_half_slots_v3(base, passphrase, &kf.salt).unwrap();
            let (meta, _) = read_payload(&pixels, &slots).unwrap();

            assert!(
                !meta.deniable,
                "a half admitted deniable mode in its metadata"
            );
            assert!(meta.partition_seed.is_none());
            assert!(meta.partition_half.is_none());
        }
    }

    /// **No stage-one block in a deniable half**, proved by offset rather than
    /// by counting modified pixels.
    ///
    /// The payload has to start at slot zero of the half's derived order. If a
    /// salt block had been reserved, the first 256 slots would hold random bytes
    /// and the metadata length header would be 256 slots further along, so
    /// reading from offset zero would fail.
    #[test]
    fn deniable_half_has_no_salt_block() {
        let cover = noisy_png(96, 96);
        let out = Builder::new().suffix(".png").tempfile().unwrap();
        let (real_kf, _) = embed_deniable_with_entropy(
            cover.path(),
            MSG,
            MSG2,
            PASS,
            PASS2,
            Cipher::ChaCha20Poly1305,
            out.path(),
            &fixed_deniable_entropy(0),
        )
        .unwrap();

        let rgb = load_frame(out.path()).unwrap().to_rgb8();
        let (w, h) = rgb.dimensions();
        let total = (w * h) as usize * 3;
        let pixels = rgb.as_raw().to_vec();
        let pseed = B64
            .decode(real_kf.partition_seed.as_deref().unwrap())
            .unwrap();
        let (first, second) = bifurcate(permute_set((0..total).collect(), &pseed));
        let base = if real_kf.partition_half == Some(0) {
            first
        } else {
            second
        };
        let slots = deniable_half_slots_v3(base, PASS, &real_kf.salt).unwrap();

        // Offset zero parses.
        assert!(
            read_payload(&pixels, &slots).is_ok(),
            "the payload does not start at the half's first slot, so something \
             is reserved ahead of it"
        );
        // And offset 256, where a salt block would have pushed it, does not.
        assert!(
            read_payload(&pixels, &slots[slotseed::SALT_BLOCK_BITS..]).is_err(),
            "the payload also parses 256 slots in, which makes the offset test \
             vacuous"
        );
    }

    #[test]
    fn deniable_round_trips_both_halves_through_the_public_api() {
        let cover = noisy_png(96, 96);
        let out = Builder::new().suffix(".png").tempfile().unwrap();
        let (real_kf, decoy_kf) = embed_deniable(
            cover.path(),
            MSG,
            MSG2,
            PASS,
            PASS2,
            Cipher::ChaCha20Poly1305,
            out.path(),
        )
        .unwrap();

        assert!(
            real_kf.uses_derived_slot_seed(),
            "a new key file must say v3"
        );
        assert_eq!(
            extract_with_keyfile(out.path(), &real_kf, PASS).unwrap(),
            MSG
        );
        assert_eq!(
            extract_with_keyfile(out.path(), &decoy_kf, PASS2).unwrap(),
            MSG2
        );
        // Each passphrase opens only its own half.
        assert!(extract_with_keyfile(out.path(), &real_kf, PASS2).is_err());
        assert!(extract_with_keyfile(out.path(), &decoy_kf, PASS).is_err());
    }

    /// A key file whose tag was lost or mangled must not make a recoverable
    /// file unrecoverable: the reader tries the other layout as well.
    #[test]
    fn a_deniable_key_file_with_a_stale_tag_still_opens_the_file() {
        let cover = noisy_png(96, 96);
        let out = Builder::new().suffix(".png").tempfile().unwrap();
        let (mut real_kf, _) = embed_deniable(
            cover.path(),
            MSG,
            MSG2,
            PASS,
            PASS2,
            Cipher::ChaCha20Poly1305,
            out.path(),
        )
        .unwrap();

        real_kf.engine = "rust-v1".into();
        assert!(!real_kf.uses_derived_slot_seed());
        assert_eq!(
            extract_with_keyfile(out.path(), &real_kf, PASS).unwrap(),
            MSG,
            "the fallback layout attempt is missing"
        );
    }

    // ── Forensics reaches the new layout ─────────────────────────────────────

    /// JOB 4's first half: copyright detection has to recognise a v3 file, or
    /// the licence is unenforceable against exactly the files this release
    /// writes. Reconstructs the positions from the published forensics surface
    /// and checks the payload really is there.
    #[test]
    fn forensics_reconstructs_v3_positions() {
        use crate::forensics;

        let cover = noisy_png(64, 64);
        let out = Builder::new().suffix(".png").tempfile().unwrap();
        embed(
            cover.path(),
            MSG,
            PASS,
            Cipher::ChaCha20Poly1305,
            "sequential",
            out.path(),
            false,
        )
        .unwrap();

        let rgb = load_frame(out.path()).unwrap().to_rgb8();
        let (w, h) = rgb.dimensions();
        let total = (w * h) as usize * 3;
        let pixels = rgb.as_raw().to_vec();

        let salt_positions = forensics::salt_block_positions(PASS, total).unwrap();
        let salt_block = extract_bits(&pixels, &salt_positions, slotseed::SALT_BLOCK_LEN).unwrap();
        let positions = forensics::embedding_positions_v3(PASS, &salt_block, total).unwrap();

        let (meta, _) = read_payload(&pixels, &positions)
            .expect("the forensics reconstruction must locate a v3 payload");
        assert_eq!(meta.engine, "rust-v3");

        // And the same reconstruction must NOT locate a payload under a wrong
        // passphrase, or "these are Stegcore's positions" would mean nothing.
        let wrong_salt = forensics::salt_block_positions(b"a different one", total).unwrap();
        let wrong_block = extract_bits(&pixels, &wrong_salt, slotseed::SALT_BLOCK_LEN).unwrap();
        let wrong_positions =
            forensics::embedding_positions_v3(b"a different one", &wrong_block, total).unwrap();
        assert!(read_payload(&pixels, &wrong_positions).is_err());
    }

    #[test]
    fn forensics_v3_refuses_a_wrong_length_salt_block() {
        use crate::forensics;
        assert!(matches!(
            forensics::embedding_positions_v3(PASS, &[0u8; 8], 4096),
            Err(StegError::CorruptedFile)
        ));
    }
}
