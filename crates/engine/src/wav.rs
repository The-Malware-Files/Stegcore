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

use std::io::Cursor;
use std::path::Path;

use hound::{SampleFormat, WavSpec};

use crate::errors::StegError;

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
    pub(crate) fn to_i32(&self) -> Vec<i32> {
        match self {
            Samples::Int(v) => v.clone(),
            Samples::Float(v) => v.iter().map(|&f| (f * 8_388_607.0) as i32).collect(),
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

/// Read a WAV file at its own sample width.
pub(crate) fn read(path: &Path) -> Result<Wav, StegError> {
    let reader = hound::WavReader::open(path).map_err(hound_err)?;
    let spec = reader.spec();

    // hound decodes 8, 16, 24 and 32-bit integers into i32, and 32-bit IEEE
    // floats into f32. Anything else (64-bit float, ADPCM and friends) is
    // refused by name rather than as a decoder error nobody can act on.
    let samples = match (spec.sample_format, spec.bits_per_sample) {
        (SampleFormat::Int, 8 | 16 | 24 | 32) => Samples::Int(
            reader
                .into_samples::<i32>()
                .collect::<Result<Vec<i32>, _>>()
                .map_err(hound_err)?,
        ),
        (SampleFormat::Float, 32) => Samples::Float(
            reader
                .into_samples::<f32>()
                .collect::<Result<Vec<f32>, _>>()
                .map_err(hound_err)?,
        ),
        _ => {
            return Err(StegError::UnsupportedFormat(format!(
                "WAV is {}; Stegcore supports 8, 16, 24 and 32-bit PCM and 32-bit float",
                describe(&spec)
            )))
        }
    };

    Ok(Wav { spec, samples })
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
