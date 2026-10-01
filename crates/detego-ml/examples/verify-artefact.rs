// Author:  Daniel Iwugo
// Comment: Christ is King
// Copyright (C) 2026 Daniel Iwugo
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Stegcore-Commercial

//! Prove that the runtime which SERVES agrees with the runtime that TRAINED.
//!
//! `export_onnx.py` already asserts that its ONNX graph matches torch to within
//! 1e-5, but it asserts it through `onnxruntime`, which is not what ships. What
//! ships is `tract`. Between those two there is a hop nothing was checking, and
//! an operator ladder of three runtimes where only two rungs are nailed down is
//! the shape of a problem that surfaces as a wrong verdict rather than an error.
//!
//! This closes it. Run it against a downloaded artefact before publishing it:
//!
//! ```text
//! cargo run --release --features backend-tract --example verify-artefact -- \
//!     --onnx     artefacts/yedroudj-net-spatial-v1.onnx \
//!     --card     artefacts/yedroudj-net-spatial-v1.card.json \
//!     --batch    runs/yedroudj-spatial/verify-batch.npy \
//!     --expected artefacts/yedroudj-net-spatial-v1.verify-expected.json
//! ```
//!
//! It is an example rather than a test because the inputs are a trained artefact
//! and an 8 MB tensor batch, which do not belong in the repository. The committed
//! tests pin the backend against three tiny synthetic graphs; this pins it
//! against the real thing at release time.
//!
//! Exit status is 0 only when every sample agrees inside the tolerance the
//! expectations file itself declares.

use std::path::PathBuf;
use std::process::ExitCode;

#[cfg(not(feature = "backend-tract"))]
fn main() -> ExitCode {
    eprintln!(
        "build this with --features backend-tract; there is nothing to verify without a backend"
    );
    ExitCode::FAILURE
}

#[cfg(feature = "backend-tract")]
fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("verification failed: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(feature = "backend-tract")]
fn run() -> Result<(), String> {
    use detego_ml::backend::tract::TractBackend;
    use detego_ml::model::{Backend, ModelCard};
    use detego_ml::representation::Representation;

    let args = Args::parse()?;

    let card_text = read_text(&args.card)?;
    let card = ModelCard::from_json(&card_text)
        .map_err(|e| format!("the card is not one this build accepts: {e}"))?;
    println!(
        "card: {} in the {} domain, {}px cover crop",
        card.architecture.name(),
        card.domain.name(),
        card.input_side
    );

    let onnx = std::fs::read(&args.onnx).map_err(|e| format!("{}: {e}", args.onnx.display()))?;
    // The digest check is the same one a weight store performs, done here too so
    // this tool refuses an artefact whose card and graph were never a pair.
    let digest = sha256_hex(&onnx);
    if !digest.eq_ignore_ascii_case(&card.weights_sha256) {
        return Err(format!(
            "the card declares sha256 {} but the graph is {digest}; these two files are not a pair",
            card.weights_sha256
        ));
    }

    let backend = TractBackend::from_onnx(&onnx, card.domain, card.input_side)
        .map_err(|e| format!("tract could not load the graph: {e}"))?;

    let expected = Expectations::parse(&read_text(&args.expected)?)?;
    let batch = Npy::parse(
        &std::fs::read(&args.batch).map_err(|e| format!("{}: {e}", args.batch.display()))?,
    )?;

    if batch.shape.len() != 4 {
        return Err(format!(
            "the batch is rank {}, expected (n, c, h, w)",
            batch.shape.len()
        ));
    }
    let [c, h, w] = [batch.shape[1], batch.shape[2], batch.shape[3]];
    if [c, h, w] != backend.shape() {
        return Err(format!(
            "the batch is {c}x{h}x{w} but this graph takes {:?}; the round trip must be asserted \
             at the shape that will actually be served",
            backend.shape()
        ));
    }
    if batch.shape[0] != expected.logits.len() {
        return Err(format!(
            "{} samples in the batch but {} expectations",
            batch.shape[0],
            expected.logits.len()
        ));
    }

    let per_sample = c * h * w;
    let mut worst = 0.0f64;
    let mut worst_at = 0usize;
    for (i, want_row) in expected.logits.iter().enumerate() {
        let slice = &batch.data[i * per_sample..(i + 1) * per_sample];
        let input = Representation::from_parts(card.domain, slice.to_vec(), c, h, w)
            .map_err(|e| format!("sample {i}: {e}"))?;
        let got = backend
            .logit(&input)
            .map_err(|e| format!("sample {i}: tract refused it: {e}"))?;
        // The expectations file records whatever the head produced, so collapse it
        // the same way the backend does rather than assuming a shape.
        let want = match want_row.len() {
            1 => want_row[0],
            2 => want_row[1] - want_row[0],
            n => return Err(format!("sample {i}: {n} expected values, want 1 or 2")),
        };
        let delta = (got - want).abs();
        if delta > worst {
            worst = delta;
            worst_at = i;
        }
    }

    println!(
        "{} samples: worst disagreement {worst:.3e} at sample {worst_at}, tolerance {:.0e}",
        expected.logits.len(),
        expected.tolerance
    );
    if worst > expected.tolerance {
        return Err(format!(
            "tract and torch disagree by {worst:.3e}, above the {:.0e} this artefact declares. \
             Do not publish it: the runtime that serves does not reproduce the runtime that \
             trained.",
            expected.tolerance
        ));
    }
    println!("VERIFY_OK {}", expected.name);
    Ok(())
}

#[cfg(feature = "backend-tract")]
fn read_text(p: &std::path::Path) -> Result<String, String> {
    std::fs::read_to_string(p).map_err(|e| format!("{}: {e}", p.display()))
}

#[cfg(feature = "backend-tract")]
fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

struct Args {
    onnx: PathBuf,
    card: PathBuf,
    batch: PathBuf,
    expected: PathBuf,
}

impl Args {
    fn parse() -> Result<Self, String> {
        let mut onnx = None;
        let mut card = None;
        let mut batch = None;
        let mut expected = None;
        let mut it = std::env::args().skip(1);
        while let Some(flag) = it.next() {
            let value = it
                .next()
                .ok_or_else(|| format!("{flag} needs a path after it"))?;
            match flag.as_str() {
                "--onnx" => onnx = Some(PathBuf::from(value)),
                "--card" => card = Some(PathBuf::from(value)),
                "--batch" => batch = Some(PathBuf::from(value)),
                "--expected" => expected = Some(PathBuf::from(value)),
                other => return Err(format!("unknown argument {other}")),
            }
        }
        Ok(Self {
            onnx: onnx.ok_or("--onnx is required")?,
            card: card.ok_or("--card is required")?,
            batch: batch.ok_or("--batch is required")?,
            expected: expected.ok_or("--expected is required")?,
        })
    }
}

struct Expectations {
    name: String,
    tolerance: f64,
    logits: Vec<Vec<f64>>,
}

impl Expectations {
    fn parse(text: &str) -> Result<Self, String> {
        let v: serde_json::Value =
            serde_json::from_str(text).map_err(|e| format!("expectations are not JSON: {e}"))?;
        let logits = v["logits"]
            .as_array()
            .ok_or("expectations have no `logits` array")?
            .iter()
            .map(|row| {
                row.as_array()
                    .ok_or_else(|| "a logits row is not an array".to_string())
                    .and_then(|r| {
                        r.iter()
                            .map(|x| {
                                x.as_f64()
                                    .ok_or_else(|| "a logit is not a number".to_string())
                            })
                            .collect()
                    })
            })
            .collect::<Result<Vec<Vec<f64>>, String>>()?;
        if logits.is_empty() {
            return Err("the expectations file records no samples".to_string());
        }
        Ok(Self {
            name: v["name"].as_str().unwrap_or("unnamed").to_string(),
            tolerance: v["tolerance"]
                .as_f64()
                .ok_or("expectations have no `tolerance`")?,
            logits,
        })
    }
}

/// The smallest NumPy `.npy` reader that is honest about what it does not handle.
///
/// Only C-order little-endian `float32`, which is what `train.py` writes. Every
/// other case is refused by name rather than misread: a Fortran-order array read
/// as C-order produces a transposed tensor, a plausible number and no error.
struct Npy {
    shape: Vec<usize>,
    data: Vec<f32>,
}

impl Npy {
    fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 10 || &bytes[0..6] != b"\x93NUMPY" {
            return Err("not a .npy file".to_string());
        }
        let major = bytes[6];
        let header_len = match major {
            1 => u16::from_le_bytes([bytes[8], bytes[9]]) as usize,
            2 | 3 => u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]) as usize,
            v => return Err(format!(".npy version {v} is not supported")),
        };
        let header_start = if major == 1 { 10 } else { 12 };
        let header = bytes
            .get(header_start..header_start + header_len)
            .ok_or("the .npy header is truncated")?;
        let header = std::str::from_utf8(header).map_err(|_| "the .npy header is not UTF-8")?;

        if !(header.contains("'<f4'") || header.contains("\"<f4\"")) {
            return Err(format!(
                "this reader only handles little-endian float32; header says {header}"
            ));
        }
        if header.contains("'fortran_order': True") {
            return Err(
                "the array is Fortran order; reading it as C order would silently transpose it"
                    .to_string(),
            );
        }

        let open = header.find('(').ok_or("no shape in the .npy header")?;
        let close = header[open..].find(')').ok_or("unterminated shape")? + open;
        let shape: Vec<usize> = header[open + 1..close]
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| {
                s.parse::<usize>()
                    .map_err(|_| format!("bad shape entry {s:?}"))
            })
            .collect::<Result<_, _>>()?;

        let count = shape.iter().product::<usize>();
        let body = &bytes[header_start + header_len..];
        if body.len() < count * 4 {
            return Err(format!(
                "the .npy body holds {} bytes but its shape {shape:?} needs {}",
                body.len(),
                count * 4
            ));
        }
        let data = body[..count * 4]
            .chunks_exact(4)
            .map(|c| f32::from_le_bytes([c[0], c[1], c[2], c[3]]))
            .collect();
        Ok(Self { shape, data })
    }
}
