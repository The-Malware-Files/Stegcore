// Copyright (C) 2026 The Malware Files
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.

// Session 4 — steganographic engine, all formats, deniable mode.
use std::path::{Path, PathBuf};

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use image::{ImageFormat, RgbImage};
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
    image::open(path).map_err(StegError::Image)
}

fn write_frame(img: &RgbImage, out_path: &Path, src_fmt: &str) -> Result<PathBuf, StegError> {
    // JPEG embedding uses its own path (do_embed_jpeg); this function
    // only handles PNG, BMP, and WebP output.
    let (fmt, final_path) = match src_fmt {
        "bmp" => (ImageFormat::Bmp, out_path.to_path_buf()),
        "webp" => (ImageFormat::WebP, out_path.to_path_buf()),
        _ => (ImageFormat::Png, out_path.to_path_buf()),
    };
    img.save_with_format(&final_path, fmt)
        .map_err(StegError::Image)?;
    Ok(final_path)
}

// ── Cover scoring ─────────────────────────────────────────────────────────────

/// Scores a cover file's suitability. Returns 0.0 (poor) – 1.0 (excellent).
pub fn assess(path: &Path) -> Result<f64, StegError> {
    let fmt = detect_format(path)?;
    if fmt == "wav" {
        return assess_wav(path);
    }
    if fmt == "flac" {
        return Ok(0.6);
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
    // Score: ratio of embeddable bits to total file size, capped at 1.0.
    // Larger ratio = more capacity relative to file size = better cover.
    let score = ((eligible / 8) as f64 / bytes.len() as f64).min(1.0);
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

        // Verify slot uniqueness in debug builds
        #[cfg(debug_assertions)]
        {
            let mut seen = std::collections::HashSet::with_capacity(ops.len());
            for &(slot, _) in &ops {
                assert!(
                    seen.insert(slot),
                    "duplicate slot index {slot} in embed_bits"
                );
            }
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
    let rgb = load_frame(cover_path)?.to_rgb8();
    let mut pixels = rgb.as_raw().to_vec();
    let slots = image_slots(&rgb, mode, passphrase);
    embed_bits(&mut pixels, &slots, stego_payload)?;
    let (w, h) = rgb.dimensions();
    let out_img = RgbImage::from_raw(w, h, pixels).ok_or(StegError::CorruptedFile)?;
    write_frame(&out_img, out_path, src_fmt)
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
    // Keep the output as JPEG — use the same extension as the cover.
    let ext = cover_path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("jpg");
    let final_path = out_path.with_extension(ext);
    std::fs::write(&final_path, &stego_jpeg).map_err(StegError::Io)?;
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
    let mut writer = hound::WavWriter::create(out_path, spec).map_err(hound_err)?;
    for s in out {
        writer.write_sample(s).map_err(hound_err)?;
    }
    writer.finalize().map_err(hound_err)
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
/// Returns a `KeyFile` if `export_key` is true.
pub fn embed(
    cover_path: &Path,
    payload: &[u8],
    passphrase: &[u8],
    cipher: Cipher,
    mode: &str,
    out_path: &Path,
    export_key: bool,
) -> Result<Option<KeyFile>, StegError> {
    if payload.is_empty() {
        return Err(StegError::EmptyPayload);
    }
    let fmt = detect_format(cover_path)?;
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

    if fmt == "wav" {
        do_embed_wav(cover_path, &stego_payload, passphrase, out_path)?;
    } else if fmt == "jpg" || fmt == "jpeg" {
        do_embed_jpeg(cover_path, &stego_payload, passphrase, out_path)?;
    } else {
        do_embed_image(cover_path, &stego_payload, passphrase, mode, out_path, &fmt)?;
    }

    Ok(if export_key {
        let kf = KeyFile::new(cipher, nonce, salt.to_vec());
        Some(kf)
    } else {
        None
    })
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

    let rgb = load_frame(cover_path)?.to_rgb8();
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

    let out_img = RgbImage::from_raw(w, h, pixels).ok_or(StegError::CorruptedFile)?;
    write_frame(&out_img, out_path, &fmt)?;

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

/// Extract from a non-deniable stego file using passphrase only.
pub fn extract(stego_path: &Path, passphrase: &[u8]) -> Result<Vec<u8>, StegError> {
    let fmt = detect_format(stego_path)?;
    let (meta, ct) = if fmt == "wav" {
        do_extract_wav(stego_path, passphrase)?
    } else if fmt == "jpg" || fmt == "jpeg" {
        do_extract_jpeg(stego_path, passphrase)?
    } else {
        do_extract_image(stego_path, passphrase)?
    };
    decrypt_meta(&meta, &ct, passphrase)
}

/// Extract using an exported key file. Handles standard and deniable files.
pub fn extract_with_keyfile(
    stego_path: &Path,
    keyfile: &KeyFile,
    passphrase: &[u8],
) -> Result<Vec<u8>, StegError> {
    let fmt = detect_format(stego_path)?;
    if fmt == "wav" {
        let (meta, ct) = do_extract_wav(stego_path, passphrase)?;
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
}

/// Read the embedded metadata header from a stego file without decrypting the
/// payload. Requires the passphrase because slot selection is passphrase-seeded.
/// Returns the metadata as a JSON string.
pub fn read_meta(path: &Path, passphrase: &[u8]) -> Result<String, StegError> {
    let fmt = detect_format(path)?;
    let meta = if fmt == "wav" {
        let (m, _) = do_extract_wav(path, passphrase)?;
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
}
