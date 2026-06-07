// Copyright (C) 2026 Daniel Iwugo
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Stegcore-Commercial
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.
//
// Commercial licensing: daniel@themalwarefiles.com

//! Comparator embedders for the benchmark's stego split.
//!
//! Each embedder hides a fixed payload in a cover, producing a stego PNG. The
//! orchestration writes them as `image_<index>_<tool>_0.png`, the filename the
//! `audit` command parses, so the stego split flows straight through
//! audit/score/benchmark alongside the clean covers. With both classes present
//! the benchmark can finally report ROC AUC, not just a false-positive rate.
//!
//! Embedders are external tools, driven by shell-out (the same pattern `score`
//! and `corpus` use). The [`Embedder`] trait keeps the orchestration testable:
//! a stub embedder exercises the whole loop without any tool installed.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// A single external embedder.
pub trait Embedder {
    /// Lowercase ASCII identifier, used in the stego filename's tool field
    /// (must match the audit filename grammar: `[a-z]+`).
    fn id(&self) -> &str;
    /// Embed `payload` into `cover`, writing the stego image to `out`.
    fn embed(&self, cover: &Path, payload: &Path, out: &Path) -> Result<(), String>;
}

/// Outcome of embedding a corpus.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct EmbedOutcome {
    pub embedded: usize,
    pub failed: usize,
}

/// Embed every cover in `covers` with `embedder`, writing the results into
/// `stego_dir` as `image_<cover-stem>_<tool>_0.png`. A cover whose embed fails
/// (or produces no file) is counted and skipped, never fatal. The cover stem
/// must be numeric for the audit grammar; non-numeric stems are skipped with a
/// warning.
pub fn embed_corpus(
    embedder: &dyn Embedder,
    covers: &[PathBuf],
    payload: &Path,
    stego_dir: &Path,
) -> std::io::Result<EmbedOutcome> {
    fs::create_dir_all(stego_dir)?;
    let mut outcome = EmbedOutcome::default();
    for cover in covers {
        let stem = cover.file_stem().and_then(|s| s.to_str()).unwrap_or("");
        if stem.is_empty() || !stem.bytes().all(|b| b.is_ascii_digit()) {
            eprintln!("  skipping {} (non-numeric stem)", cover.display());
            outcome.failed += 1;
            continue;
        }
        let out = stego_dir.join(format!("image_{stem}_{}_0.png", embedder.id()));
        match embedder.embed(cover, payload, &out) {
            Ok(()) if out.is_file() => outcome.embedded += 1,
            Ok(()) => {
                eprintln!(
                    "  {} produced no output for {}",
                    embedder.id(),
                    cover.display()
                );
                outcome.failed += 1;
            }
            Err(e) => {
                eprintln!("  {} failed on {}: {e}", embedder.id(), cover.display());
                outcome.failed += 1;
            }
        }
    }
    Ok(outcome)
}

fn run(mut cmd: Command, what: &str) -> Result<(), String> {
    match cmd.output() {
        Ok(o) if o.status.success() => Ok(()),
        Ok(o) => Err(format!(
            "{what}: {}",
            String::from_utf8_lossy(&o.stderr)
                .chars()
                .take(160)
                .collect::<String>()
        )),
        Err(e) => Err(format!("{what}: {e}")),
    }
}

/// LSBSteg (Robin David), driven through the venv python and `LSBSteg.py`.
/// LSBSteg rewrites a `.jpg` output request to `.png` itself, so we ask for
/// `.jpg` and collect the `.png` it actually writes.
pub struct LsbStegEmbedder {
    pub python: PathBuf,
    pub script: PathBuf,
}

impl Embedder for LsbStegEmbedder {
    fn id(&self) -> &str {
        "lsbsteg"
    }

    fn embed(&self, cover: &Path, payload: &Path, out: &Path) -> Result<(), String> {
        let call_out = out.with_extension("jpg");
        let mut cmd = Command::new(&self.python);
        cmd.arg(&self.script)
            .args(["encode", "-i"])
            .arg(cover)
            .arg("-o")
            .arg(&call_out)
            .arg("-f")
            .arg(payload);
        run(cmd, "lsbsteg")?;
        let produced = call_out.with_extension("png");
        if produced.exists() && produced != *out {
            fs::rename(&produced, out).map_err(|e| format!("lsbsteg rename: {e}"))?;
        }
        if out.is_file() {
            Ok(())
        } else {
            Err("lsbsteg wrote no png".into())
        }
    }
}

/// OpenStego's default RandomLSB plugin (no password), driven through a built
/// docker image. The container only sees a bind-mounted directory, so the
/// cover and payload are staged into a temp dir mounted at `/work` and the
/// stego is copied back out.
pub struct OpenStegoEmbedder {
    /// Docker image tag, e.g. `stegcore-cmp/openstego:0.8.6`.
    pub image: String,
    /// Docker executable; `docker` in production, a stub in tests.
    pub docker_bin: PathBuf,
}

impl Embedder for OpenStegoEmbedder {
    fn id(&self) -> &str {
        "openstego"
    }

    fn embed(&self, cover: &Path, payload: &Path, out: &Path) -> Result<(), String> {
        let work = tempfile::tempdir().map_err(|e| format!("openstego tempdir: {e}"))?;
        let w = work.path();
        fs::copy(cover, w.join("cover.png")).map_err(|e| format!("stage cover: {e}"))?;
        fs::copy(payload, w.join("payload.bin")).map_err(|e| format!("stage payload: {e}"))?;

        let mut cmd = Command::new(&self.docker_bin);
        cmd.args(["run", "--rm", "-v"])
            .arg(format!("{}:/work", w.display()))
            .arg(&self.image)
            .args([
                "embed",
                "-mf",
                "/work/payload.bin",
                "-cf",
                "/work/cover.png",
                "-sf",
                "/work/stego.png",
            ]);
        run(cmd, "openstego")?;

        let produced = w.join("stego.png");
        if !produced.is_file() {
            return Err("openstego wrote no stego".into());
        }
        fs::copy(&produced, out).map_err(|e| format!("collect stego: {e}"))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// A stub embedder that just copies the cover to the output, so the
    /// orchestration is covered without any tool installed.
    struct CopyStub;
    impl Embedder for CopyStub {
        fn id(&self) -> &str {
            "stub"
        }
        fn embed(&self, cover: &Path, _payload: &Path, out: &Path) -> Result<(), String> {
            fs::copy(cover, out).map(|_| ()).map_err(|e| e.to_string())
        }
    }

    /// A stub that always fails.
    struct FailStub;
    impl Embedder for FailStub {
        fn id(&self) -> &str {
            "fail"
        }
        fn embed(&self, _c: &Path, _p: &Path, _o: &Path) -> Result<(), String> {
            Err("nope".into())
        }
    }

    fn covers(dir: &Path, names: &[&str]) -> Vec<PathBuf> {
        names
            .iter()
            .map(|n| {
                let p = dir.join(n);
                fs::write(&p, b"\x89PNG\r\n\x1a\nbody").unwrap();
                p
            })
            .collect()
    }

    #[test]
    fn embed_corpus_names_and_counts() {
        let tmp = TempDir::new().unwrap();
        let cov = covers(tmp.path(), &["00000.png", "00001.png"]);
        let payload = tmp.path().join("p.bin");
        fs::write(&payload, b"secret").unwrap();
        let stego = tmp.path().join("stego");

        let out = embed_corpus(&CopyStub, &cov, &payload, &stego).unwrap();
        assert_eq!(out.embedded, 2);
        assert_eq!(out.failed, 0);
        assert!(stego.join("image_00000_stub_0.png").is_file());
        assert!(stego.join("image_00001_stub_0.png").is_file());
    }

    #[test]
    fn embed_corpus_skips_non_numeric_stems() {
        let tmp = TempDir::new().unwrap();
        let cov = covers(tmp.path(), &["cover_a.png"]);
        let payload = tmp.path().join("p.bin");
        fs::write(&payload, b"x").unwrap();
        let out = embed_corpus(&CopyStub, &cov, &payload, &tmp.path().join("s")).unwrap();
        assert_eq!(out.embedded, 0);
        assert_eq!(out.failed, 1);
    }

    #[test]
    fn embed_corpus_records_embedder_failure() {
        let tmp = TempDir::new().unwrap();
        let cov = covers(tmp.path(), &["00007.png"]);
        let payload = tmp.path().join("p.bin");
        fs::write(&payload, b"x").unwrap();
        let out = embed_corpus(&FailStub, &cov, &payload, &tmp.path().join("s")).unwrap();
        assert_eq!(out.embedded, 0);
        assert_eq!(out.failed, 1);
    }

    #[test]
    fn embedder_ids_match_audit_grammar() {
        // The tool field must be lowercase ASCII with no underscore.
        for id in [
            LsbStegEmbedder {
                python: "p".into(),
                script: "s".into(),
            }
            .id(),
            OpenStegoEmbedder {
                image: "i".into(),
                docker_bin: "docker".into(),
            }
            .id(),
        ] {
            assert!(!id.is_empty() && id.bytes().all(|b| b.is_ascii_lowercase()));
        }
    }

    #[cfg(unix)]
    fn write_exec(path: &Path, body: &str) {
        use std::os::unix::fs::PermissionsExt;
        fs::write(path, body).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn lsbsteg_embedder_drives_a_stub_and_collects_png() {
        let tmp = TempDir::new().unwrap();
        // Stub "python": ignores the script arg, parses -o, writes the sibling
        // .png that LSBSteg would have produced from the .jpg request.
        let py = tmp.path().join("py.sh");
        write_exec(
            &py,
            "#!/bin/sh\nwhile [ $# -gt 0 ]; do [ \"$1\" = \"-o\" ] && { shift; OUT=$1; }; shift; done\nprintf 'png' > \"${OUT%.jpg}.png\"\n",
        );
        let e = LsbStegEmbedder {
            python: py,
            script: tmp.path().join("LSBSteg.py"),
        };
        let cover = tmp.path().join("c.png");
        fs::write(&cover, b"cover").unwrap();
        let payload = tmp.path().join("p.bin");
        fs::write(&payload, b"secret").unwrap();
        let out = tmp.path().join("image_00001_lsbsteg_0.png");
        e.embed(&cover, &payload, &out).unwrap();
        assert!(out.is_file());
    }

    #[cfg(unix)]
    #[test]
    fn lsbsteg_embedder_reports_failure() {
        let tmp = TempDir::new().unwrap();
        let py = tmp.path().join("py.sh");
        write_exec(&py, "#!/bin/sh\nexit 1\n");
        let e = LsbStegEmbedder {
            python: py,
            script: tmp.path().join("x.py"),
        };
        let r = e.embed(
            &tmp.path().join("c.png"),
            &tmp.path().join("p.bin"),
            &tmp.path().join("o.png"),
        );
        assert!(r.is_err());
    }

    #[cfg(unix)]
    #[test]
    fn openstego_embedder_drives_a_stub_docker() {
        let tmp = TempDir::new().unwrap();
        let cover = tmp.path().join("c.png");
        fs::write(&cover, b"cover").unwrap();
        let payload = tmp.path().join("p.bin");
        fs::write(&payload, b"secret").unwrap();
        // Stub "docker": parse `-v host:/work` and write stego.png into the
        // host side, as the real container would.
        let docker = tmp.path().join("docker.sh");
        write_exec(
            &docker,
            "#!/bin/sh\nwhile [ $# -gt 0 ]; do [ \"$1\" = \"-v\" ] && { shift; MNT=$1; }; shift; done\nHOST=${MNT%%:*}\nprintf 'stego' > \"$HOST/stego.png\"\n",
        );
        let e = OpenStegoEmbedder {
            image: "stub".into(),
            docker_bin: docker,
        };
        let out = tmp.path().join("image_00002_openstego_0.png");
        e.embed(&cover, &payload, &out).unwrap();
        assert!(out.is_file());
    }

    #[cfg(unix)]
    #[test]
    fn openstego_embedder_errors_when_no_stego_written() {
        let tmp = TempDir::new().unwrap();
        let cover = tmp.path().join("c.png");
        fs::write(&cover, b"cover").unwrap();
        let payload = tmp.path().join("p.bin");
        fs::write(&payload, b"x").unwrap();
        let docker = tmp.path().join("docker.sh");
        write_exec(&docker, "#!/bin/sh\nexit 0\n"); // writes no stego
        let e = OpenStegoEmbedder {
            image: "stub".into(),
            docker_bin: docker,
        };
        let r = e.embed(&cover, &payload, &tmp.path().join("o.png"));
        assert!(r.is_err());
    }
}
