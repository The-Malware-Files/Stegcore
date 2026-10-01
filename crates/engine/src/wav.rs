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

//! WAV carrier I/O in the file's own sample width, shared by the embedder and
//! the analyser.
//!
//! Both used to read `samples::<i16>()`, which quietly limited every audio
//! feature to 16-bit PCM. A 24-bit file failed with hound's "the sample has
//! more bits than the destination type", a float file with "the sample format
//! differs from the destination format", and an 8-bit file was refused as a
//! poor cover because the quality score divided by `i16::MAX` and so read real
//! audio as near-silence. Reading each file at its own width fixes all three.
//!
//! 16-bit files decode to the identical values the old path produced, so stego
//! files written before this change still extract.

use std::fs::File;
use std::io::{BufReader, Cursor};
use std::path::Path;

use hound::{SampleFormat, WavSpec};

use crate::errors::StegError;

/// Scale factor that maps a 32-bit float sample into the 24-bit signed range,
/// so a float file's variance is comparable with an integer file's. Shared by
/// the whole-file and the streaming readers so the two cannot drift apart.
const FLOAT_TO_I24: f32 = 8_388_607.0;

/// Decoded samples, kept in the file's own domain so they can be written back
/// without changing the format the user handed us.
pub(crate) enum Samples {
    /// 8, 16, 24 and 32-bit PCM, widened to `i32` for uniform handling.
    Int(Vec<i32>),
    /// 32-bit IEEE float.
    Float(Vec<f32>),
}

impl Samples {
    pub(crate) fn len(&self) -> usize {
        match self {
            Samples::Int(v) => v.len(),
            Samples::Float(v) => v.len(),
        }
    }

    /// Set the least significant bit of one sample.
    ///
    /// For float samples the bit lands in the mantissa's low bit of the IEEE
    /// bit pattern, which is the only place a change survives a byte-exact
    /// round trip through the file.
    pub(crate) fn set_lsb(&mut self, index: usize, bit: u8) {
        let bit = u32::from(bit & 1);
        match self {
            Samples::Int(v) => v[index] = (v[index] & !1) | bit as i32,
            Samples::Float(v) => {
                let bits = (v[index].to_bits() & !1) | bit;
                v[index] = f32::from_bits(bits);
            }
        }
    }

    /// The low byte of a sample, the view the extractor reads bits out of.
    pub(crate) fn low_byte(&self, index: usize) -> u8 {
        match self {
            Samples::Int(v) => (v[index] & 0xFF) as u8,
            Samples::Float(v) => (v[index].to_bits() & 0xFF) as u8,
        }
    }

    /// Sample values as `i32`, for the statistical detectors. Float samples are
    /// scaled to the 24-bit signed range so their variance is comparable.
    ///
    /// Test-only now that analysis streams: it is the whole-file reference the
    /// streaming reader and the streaming detectors are checked against, so it
    /// stays rather than being deleted, and the production paths cannot reach
    /// for it by accident.
    #[cfg(test)]
    pub(crate) fn to_i32(&self) -> Vec<i32> {
        match self {
            Samples::Int(v) => v.clone(),
            Samples::Float(v) => v.iter().map(|&f| (f * FLOAT_TO_I24) as i32).collect(),
        }
    }
}

pub(crate) struct Wav {
    pub(crate) spec: WavSpec,
    pub(crate) samples: Samples,
}

pub(crate) fn hound_err(e: hound::Error) -> StegError {
    StegError::Io(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        e.to_string(),
    ))
}

/// Describe a spec the way a person would, for error messages.
fn describe(spec: &WavSpec) -> String {
    let kind = match spec.sample_format {
        SampleFormat::Float => "float",
        SampleFormat::Int => "PCM",
    };
    format!(
        "{}-bit {} at {} Hz, {} channel(s)",
        spec.bits_per_sample, kind, spec.sample_rate, spec.channels
    )
}

/// Which of the two decode domains a spec falls into.
///
/// hound decodes 8, 16, 24 and 32-bit integers into `i32`, and 32-bit IEEE
/// floats into `f32`. Anything else (64-bit float, ADPCM and friends) is
/// refused by name rather than as a decoder error nobody can act on.
#[derive(Debug, PartialEq, Eq)]
enum Domain {
    Int,
    Float,
}

fn domain(spec: &WavSpec) -> Result<Domain, StegError> {
    match (spec.sample_format, spec.bits_per_sample) {
        (SampleFormat::Int, 8 | 16 | 24 | 32) => Ok(Domain::Int),
        (SampleFormat::Float, 32) => Ok(Domain::Float),
        _ => Err(StegError::UnsupportedFormat(format!(
            "WAV is {}; Stegcore supports 8, 16, 24 and 32-bit PCM and 32-bit float",
            describe(spec)
        ))),
    }
}

/// Read a WAV file at its own sample width.
///
/// This decodes the whole file into memory, which the embed and extract paths
/// need because they rewrite samples in place and re-encode. Peak memory is
/// about 4 bytes per sample whatever the file's own width, so an 8-bit cover
/// costs four times its file size. Analysis does not need the whole file and
/// must not pay that: it uses [`chunks`] instead.
pub(crate) fn read(path: &Path) -> Result<Wav, StegError> {
    let reader = hound::WavReader::open(path).map_err(hound_err)?;
    let spec = reader.spec();

    let samples = match domain(&spec)? {
        Domain::Int => Samples::Int(
            reader
                .into_samples::<i32>()
                .collect::<Result<Vec<i32>, _>>()
                .map_err(hound_err)?,
        ),
        Domain::Float => Samples::Float(
            reader
                .into_samples::<f32>()
                .collect::<Result<Vec<f32>, _>>()
                .map_err(hound_err)?,
        ),
    };

    Ok(Wav { spec, samples })
}

// ── Streaming reader ──────────────────────────────────────────────────────────

/// Samples per analysis chunk. 65536 `i32` values is 256 KiB: large enough that
/// the per-chunk bookkeeping disappears against the decode cost, small enough
/// that peak memory does not move with the length of the file. It is also a
/// whole multiple of the chi-squared block size, though the accumulators carry
/// their own partial block and so do not depend on that.
pub(crate) const CHUNK_SAMPLES: usize = 65_536;

enum ChunkIter {
    Int(hound::WavIntoSamples<BufReader<File>, i32>),
    Float(hound::WavIntoSamples<BufReader<File>, f32>),
}

/// A WAV file read a chunk at a time, in the same `i32` domain [`Samples::to_i32`]
/// produces, so a streaming detector sees exactly the values a whole-file one did.
///
/// Holding the whole file was measured at about 14 times the file size in peak
/// resident memory (a 120 MB 8-bit cover drove `score` to 1.80 GiB), with no
/// size limit anywhere in the audio path. Streaming removes the amplification
/// without putting a user-visible ceiling on how long a clip may be.
pub(crate) struct SampleChunks {
    spec: WavSpec,
    declared_samples: u32,
    iter: ChunkIter,
    buf: Vec<i32>,
}

impl SampleChunks {
    pub(crate) fn spec(&self) -> WavSpec {
        self.spec
    }

    /// Samples the data chunk's declared length says this file holds.
    ///
    /// Used only to choose a sampling stride up front, never as a count of what
    /// was actually decoded: a truncated file declares more than it delivers,
    /// and every accumulator counts what it really saw.
    pub(crate) fn declared_samples(&self) -> u32 {
        self.declared_samples
    }

    /// The next chunk of at most [`CHUNK_SAMPLES`] samples, or `None` once the
    /// stream is exhausted. A decode error is returned, never skipped.
    pub(crate) fn next_chunk(&mut self) -> Result<Option<&[i32]>, StegError> {
        self.buf.clear();
        while self.buf.len() < CHUNK_SAMPLES {
            match &mut self.iter {
                ChunkIter::Int(it) => match it.next() {
                    Some(s) => self.buf.push(s.map_err(hound_err)?),
                    None => break,
                },
                ChunkIter::Float(it) => match it.next() {
                    Some(s) => self.buf.push((s.map_err(hound_err)? * FLOAT_TO_I24) as i32),
                    None => break,
                },
            }
        }
        if self.buf.is_empty() {
            Ok(None)
        } else {
            Ok(Some(&self.buf))
        }
    }
}

/// Open a WAV file for chunked reading. Refuses the same formats [`read`] does,
/// with the same message, so the two entry points agree on what a valid file is.
pub(crate) fn chunks(path: &Path) -> Result<SampleChunks, StegError> {
    let reader = hound::WavReader::open(path).map_err(hound_err)?;
    let spec = reader.spec();
    let declared_samples = reader.len();
    let iter = match domain(&spec)? {
        Domain::Int => ChunkIter::Int(reader.into_samples::<i32>()),
        Domain::Float => ChunkIter::Float(reader.into_samples::<f32>()),
    };
    Ok(SampleChunks {
        spec,
        declared_samples,
        iter,
        buf: Vec::with_capacity(CHUNK_SAMPLES),
    })
}

// ── The streaming reader as a sample source ───────────────────────────────────

/// The chunked reader presented as a [`crate::audio_analysis::SampleSource`], so
/// every audio statistic in the engine comes out of the one implementation in
/// that module and the WAV side contributes a reader rather than a second copy of
/// the rules.
///
/// Why this exists rather than a channel fix in the analyser: the audio
/// accumulator used to partition samples with `index % 3`, an RGB channel layout
/// applied to audio, whatever the header declared. Measured on a 13 minute real
/// stereo recording, first million frames: the sample pair estimate on the clean
/// file read 0.234 and 0.365 per channel when the header was honoured, and 0.705
/// to 0.710 under the three way split, against 0.917 and 0.937 for the same file
/// with its whole LSB plane replaced. So the split did not blur the answer, it
/// moved clean audio two thirds of the way to looking fully embedded, and the
/// neighbour roughness rose from 0.50 to 0.82 because a three way split over two
/// channels destroys the temporal adjacency the estimate is built on.
///
/// Decimation is therefore by FRAME and never by sample. Taking every n-th
/// interleaved sample rotates the channel assignment whenever n and the channel
/// count share no factor, which is the same defect arriving by a different route.
pub(crate) struct ChunkSource {
    reader: SampleChunks,
    channels: usize,
    bits: u16,
    /// Keep one frame in every `frame_stride`. One reads the file whole.
    frame_stride: usize,
    frame_index: usize,
    within_frame: usize,
    /// The samples kept from the chunk currently being handed out.
    pending: Vec<i32>,
    drained: usize,
    finished: bool,
}

/// Open a WAV file as a sample source. Reads the header only; nothing is decoded
/// until the source is read.
pub(crate) fn source(path: &Path) -> Result<ChunkSource, StegError> {
    let reader = chunks(path)?;
    let spec = reader.spec();
    // Float samples are scaled into the 24-bit signed range by this reader, so 24
    // is the width the statistics should bin against. The header's 32 would size
    // the histogram for a range the values never reach.
    let bits = match spec.sample_format {
        SampleFormat::Float => 24,
        SampleFormat::Int => spec.bits_per_sample,
    };
    Ok(ChunkSource {
        channels: (spec.channels as usize).max(1),
        bits,
        reader,
        frame_stride: 1,
        frame_index: 0,
        within_frame: 0,
        pending: Vec::with_capacity(CHUNK_SAMPLES),
        drained: 0,
        finished: false,
    })
}

impl ChunkSource {
    pub(crate) fn spec(&self) -> WavSpec {
        self.reader.spec()
    }

    pub(crate) fn declared_samples(&self) -> u32 {
        self.reader.declared_samples()
    }

    /// Keep one frame in every `frames`, for the sampled analysis budget.
    pub(crate) fn with_frame_stride(mut self, frames: usize) -> Self {
        self.frame_stride = frames.max(1);
        self
    }

    /// Refill `pending` from the reader. `false` once the stream is spent.
    fn refill(&mut self) -> Result<bool, StegError> {
        self.pending.clear();
        self.drained = 0;
        let Some(chunk) = self.reader.next_chunk()? else {
            self.finished = true;
            return Ok(false);
        };
        if self.frame_stride == 1 {
            self.pending.extend_from_slice(chunk);
            return Ok(true);
        }
        for &s in chunk {
            if self.frame_index % self.frame_stride == 0 {
                self.pending.push(s);
            }
            self.within_frame += 1;
            if self.within_frame == self.channels {
                self.within_frame = 0;
                self.frame_index += 1;
            }
        }
        Ok(true)
    }
}

impl crate::audio_analysis::SampleSource for ChunkSource {
    fn read_chunk(&mut self, out: &mut [i32]) -> Result<usize, StegError> {
        if out.is_empty() {
            return Ok(0);
        }
        // A chunk can decimate down to nothing, which is not the end of the
        // stream. Returning zero there would truncate the analysis at the first
        // sparse chunk and report a partial measurement as a whole one.
        while self.drained == self.pending.len() {
            if self.finished || !self.refill()? {
                return Ok(0);
            }
        }
        let n = (self.pending.len() - self.drained).min(out.len());
        out[..n].copy_from_slice(&self.pending[self.drained..self.drained + n]);
        self.drained += n;
        Ok(n)
    }

    fn channels(&self) -> usize {
        self.channels
    }

    fn bits_per_sample(&self) -> u16 {
        self.bits
    }
}

/// Encode samples back into WAV bytes using the spec they came from.
pub(crate) fn encode(spec: WavSpec, samples: &Samples) -> Result<Vec<u8>, StegError> {
    let mut buf: Vec<u8> = Vec::new();
    {
        let mut writer = hound::WavWriter::new(Cursor::new(&mut buf), spec).map_err(hound_err)?;
        match samples {
            Samples::Int(v) => {
                for &s in v {
                    writer.write_sample(s).map_err(hound_err)?;
                }
            }
            Samples::Float(v) => {
                for &s in v {
                    writer.write_sample(s).map_err(hound_err)?;
                }
            }
        }
        writer.finalize().map_err(hound_err)?;
    }
    Ok(buf)
}

/// Full-scale amplitude for this spec, so a quality score means the same thing
/// at every bit depth. Dividing an 8-bit file's variance by `i16::MAX` is what
/// made real audio score zero and get refused as an unsuitable cover.
pub(crate) fn full_scale(spec: &WavSpec) -> f64 {
    match spec.sample_format {
        SampleFormat::Float => 1.0,
        SampleFormat::Int => match spec.bits_per_sample {
            8 => i8::MAX as f64,
            16 => i16::MAX as f64,
            24 => 8_388_607.0,
            _ => i32::MAX as f64,
        },
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn write_wav(
        name: &str,
        bits: u16,
        fmt: SampleFormat,
        channels: u16,
        n: usize,
    ) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(name);
        let spec = WavSpec {
            channels,
            sample_rate: 44100,
            bits_per_sample: bits,
            sample_format: fmt,
        };
        let mut writer = hound::WavWriter::create(&path, spec).unwrap();
        let span: i64 = 1 << (bits - 1);
        // `n` counts frames, so a stereo file gets two samples per iteration:
        // hound refuses to finalise a writer left part way through a frame.
        for i in 0..n * channels as usize {
            match fmt {
                SampleFormat::Int => {
                    let v = ((i as i64 * 7919) % span) - span / 2;
                    writer.write_sample(v as i32).unwrap();
                }
                SampleFormat::Float => {
                    let v = ((i % 1000) as f32 / 500.0) - 1.0;
                    writer.write_sample(v).unwrap();
                }
            }
        }
        writer.finalize().unwrap();
        path
    }

    /// The streaming reader must hand back exactly the values the whole-file
    /// reader produces, in the same order: anything else silently changes every
    /// audio detector's answer.
    #[test]
    fn chunked_read_yields_the_same_values_as_a_whole_file_read() {
        let cases = [
            ("wav_chunk_8.wav", 8u16, SampleFormat::Int, 1u16),
            ("wav_chunk_16.wav", 16, SampleFormat::Int, 2),
            ("wav_chunk_24.wav", 24, SampleFormat::Int, 1),
            ("wav_chunk_32f.wav", 32, SampleFormat::Float, 1),
        ];
        // Deliberately not a whole multiple of the chunk size.
        let n = CHUNK_SAMPLES + 777;
        for (name, bits, fmt, channels) in cases {
            let path = write_wav(name, bits, fmt, channels, n);
            let whole = read(&path).unwrap().samples.to_i32();

            let mut reader = chunks(&path).unwrap();
            let mut streamed: Vec<i32> = Vec::new();
            let mut chunk_count = 0;
            while let Some(chunk) = reader.next_chunk().unwrap() {
                assert!(chunk.len() <= CHUNK_SAMPLES, "{name}: oversized chunk");
                assert!(!chunk.is_empty(), "{name}: empty chunk yielded");
                streamed.extend_from_slice(chunk);
                chunk_count += 1;
            }
            assert_eq!(streamed, whole, "{name}: streamed values differ");
            assert!(chunk_count >= 2, "{name}: expected more than one chunk");
            std::fs::remove_file(&path).ok();
        }
    }

    #[test]
    fn a_zero_sample_file_yields_no_chunks() {
        let path = write_wav("wav_chunk_empty.wav", 16, SampleFormat::Int, 1, 0);
        let mut reader = chunks(&path).unwrap();
        assert!(reader.next_chunk().unwrap().is_none());
        // And again, so a second call after the end is not a surprise.
        assert!(reader.next_chunk().unwrap().is_none());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn the_declared_count_matches_what_the_stream_delivers() {
        let path = write_wav("wav_chunk_declared.wav", 16, SampleFormat::Int, 2, 5000);
        let mut reader = chunks(&path).unwrap();
        let declared = reader.declared_samples() as usize;
        let mut seen = 0usize;
        while let Some(chunk) = reader.next_chunk().unwrap() {
            seen += chunk.len();
        }
        assert_eq!(declared, seen);
        assert_eq!(seen, 10_000, "5000 frames of stereo is 10000 samples");
        assert_eq!(reader.spec().channels, 2);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn both_readers_refuse_an_unsupported_width_with_the_same_message() {
        // 64-bit float is a legal WAV and not something this engine decodes.
        // The two entry points must agree, or a file that scores refuses to
        // analyse (or worse, the other way round).
        let path = std::env::temp_dir().join("wav_chunk_f64.wav");
        let spec = WavSpec {
            channels: 1,
            sample_rate: 44100,
            bits_per_sample: 64,
            sample_format: SampleFormat::Float,
        };
        // hound will not write 64-bit float, so the header is written by hand.
        let data_len: u32 = 8;
        let mut bytes: Vec<u8> = Vec::new();
        bytes.extend_from_slice(b"RIFF");
        bytes.extend_from_slice(&(36 + data_len).to_le_bytes());
        bytes.extend_from_slice(b"WAVEfmt ");
        bytes.extend_from_slice(&16u32.to_le_bytes());
        bytes.extend_from_slice(&3u16.to_le_bytes()); // IEEE float
        bytes.extend_from_slice(&spec.channels.to_le_bytes());
        bytes.extend_from_slice(&spec.sample_rate.to_le_bytes());
        bytes.extend_from_slice(&(spec.sample_rate * 8).to_le_bytes());
        bytes.extend_from_slice(&8u16.to_le_bytes());
        bytes.extend_from_slice(&64u16.to_le_bytes());
        bytes.extend_from_slice(b"data");
        bytes.extend_from_slice(&data_len.to_le_bytes());
        bytes.extend_from_slice(&[0u8; 8]);
        std::fs::write(&path, &bytes).unwrap();

        let whole = read(&path).err().map(|e| e.to_string());
        let streamed = chunks(&path).err().map(|e| e.to_string());
        assert!(
            whole.is_some(),
            "whole-file read accepted a 64-bit float WAV"
        );
        assert_eq!(whole, streamed, "the two readers disagree");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn an_unsupported_width_is_named_in_the_refusal() {
        // The parity test above is caught by hound's own header check, so the
        // engine's own refusal is exercised directly: a user who hands over a
        // format we do not decode is told which format that was, rather than
        // reading a decoder error they cannot act on.
        let spec = WavSpec {
            channels: 1,
            sample_rate: 48_000,
            bits_per_sample: 64,
            sample_format: SampleFormat::Float,
        };
        let err = domain(&spec).unwrap_err().to_string();
        assert!(err.contains("64-bit float"), "{err}");
        assert!(err.contains("48000 Hz"), "{err}");
        assert!(domain(&WavSpec {
            bits_per_sample: 12,
            sample_format: SampleFormat::Int,
            ..spec
        })
        .is_err());
        for bits in [8u16, 16, 24, 32] {
            assert!(domain(&WavSpec {
                bits_per_sample: bits,
                sample_format: SampleFormat::Int,
                ..spec
            })
            .is_ok());
        }
    }

    #[test]
    fn a_truncated_data_chunk_is_an_error_not_a_short_read() {
        // Silently returning fewer samples would make an analysis of a damaged
        // file look like an analysis of a sound one.
        let path = write_wav("wav_chunk_truncated.wav", 16, SampleFormat::Int, 1, 4000);
        let mut bytes = std::fs::read(&path).unwrap();
        bytes.truncate(bytes.len() - 3); // leaves a partial sample at the end
        std::fs::write(&path, &bytes).unwrap();

        let mut reader = chunks(&path).unwrap();
        let mut result = Ok(());
        loop {
            match reader.next_chunk() {
                Ok(Some(_)) => continue,
                Ok(None) => break,
                Err(e) => {
                    result = Err(e);
                    break;
                }
            }
        }
        assert!(result.is_err(), "a truncated sample must be reported");
        std::fs::remove_file(&path).ok();
    }
}
