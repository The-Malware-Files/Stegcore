<div align="center">

<img src="icon.svg" alt="Stegcore logo" width="96" height="96">

# Stegcore

**Hide encrypted messages inside ordinary files**

[![CI](https://github.com/The-Malware-Files/Stegcore/actions/workflows/ci.yml/badge.svg)](https://github.com/The-Malware-Files/Stegcore/actions/workflows/ci.yml)
[![Coverage](https://codecov.io/gh/The-Malware-Files/Stegcore/branch/main/graph/badge.svg)](https://codecov.io/gh/The-Malware-Files/Stegcore)
[![Release](https://img.shields.io/github/v/release/The-Malware-Files/Stegcore)](https://github.com/The-Malware-Files/Stegcore/releases/latest)
[![Licence: AGPL-3.0](https://img.shields.io/badge/licence-AGPL--3.0--or--later-blue)](LICENSE)
[![Commercial licence available](https://img.shields.io/badge/commercial-available-purple)](COMMERCIAL.md)

</div>

---

## What is this

Stegcore hides encrypted messages inside everyday pictures and sound files. The file still looks and sounds completely normal. Nobody can tell it contains a hidden message, not your internet provider, not a border agent, not a forensic analyst with professional tools.

Your data never leaves your device. No accounts. No cloud. No telemetry. No network connections of any kind. One passphrase to hide, the same passphrase to recover.

If someone ever forces you to hand over a password, give them the decoy one. Stegcore can hold two messages in the same file, each with its own passphrase. Nobody looking at the file can tell which half has the real message, or that a second message exists at all.

> **Steganalysis at Aletheia parity.** Stegcore matches
> [Aletheia](https://github.com/daniellerch/aletheia), the public reference
> for steganalysis, on three classical detectors (Sample Pair Analysis, RS,
> Weighted Stego) to floating-point precision, and runs roughly 100× faster
> on the RS code path in Rust. Detector thresholds are calibrated against
> real clean images (Cassavia 2022, BOSSbase 1.01 and an ALASKA2 sample) at a
> documented low false-alarm rate, never guessed. Everything else (embedding,
> extracting, encryption, deniable mode, GUI, CLI) is production-ready.

<details>
<summary>What is under the hood</summary>

Three authenticated ciphers (Ascon-128, ChaCha20-Poly1305, AES-256-GCM). Argon2id for turning passphrases into encryption keys, tuned to make brute force painful. Adaptive embedding that picks noisy parts of the cover file so the hidden data disappears into the natural grain. Deniable dual-payload mode. Steganalysis suite at Aletheia parity on the classical SPA / RS / WS detectors, plus tiered structural tool fingerprinting (Exact and Heuristic). Desktop GUI and CLI. One small native binary.

</details>

---

## Install

### Download a binary (recommended)

Grab the latest release for your platform from the [**Releases page**](https://github.com/The-Malware-Files/Stegcore/releases).

| Platform | CLI | GUI |
|---|---|---|
| **Linux x86_64** | `.tar.gz` | `.AppImage` or `.deb` |
| **macOS (Intel and Apple Silicon)** | Universal binary | `.dmg` |
| **Windows x86_64** | `.zip` | `.msi` |

### One line installer

Same URL works on Linux, macOS and Windows. Detects your platform automatically.

**Linux and macOS:**
```bash
curl -fsSL https://raw.githubusercontent.com/The-Malware-Files/Stegcore/main/install | sh
```

**Windows (PowerShell):**
```powershell
irm https://raw.githubusercontent.com/The-Malware-Files/Stegcore/main/install | iex
```

<details>
<summary>Installer options</summary>

```bash
# Pin a version
STEGCORE_VERSION=v4.0.1 curl -fsSL .../install.sh | bash

# Custom install directory
STEGCORE_DIR=/opt/stegcore curl -fsSL .../install.sh | bash

# Uninstall
bash install.sh --uninstall
```

```powershell
# Windows options
.\install.ps1 -Component both          # CLI plus GUI
.\install.ps1 -Version v4.0.1          # Pin version
.\install.ps1 -Uninstall               # Remove
.\install.ps1 -DryRun                  # Preview only
```

</details>

### Build from source

```sh
cargo build --workspace --release
```

This produces the CLI at `target/release/stegcore`. For the desktop app, run `cargo tauri build` from the repo root.

---

## CLI usage

```bash
# Guided wizard (best for first time users)
stegcore wizard

# Hide a message
stegcore embed cover.png secret.txt -o stego.png

# Recover a message
stegcore extract stego.png -o recovered.txt

# Check a file for a hidden message
stegcore analyse suspect.png

# Scan a folder with a progress bar
stegcore analyse *.png --json

# Works in pipes
echo "secret" | stegcore embed cover.png - -o stego.png
stegcore extract stego.png --raw | xxd
```

### Other useful commands

```bash
stegcore score cover.png        # Is this file a good hiding spot?
stegcore diff cover.png stego.png   # Show the pixel difference
stegcore info stego.png         # Read metadata (needs the passphrase)
stegcore ciphers                # List available encryption options
stegcore doctor                 # System health check
stegcore benchmark              # Test how fast your machine runs the ciphers
stegcore completions bash       # Shell completion setup
stegcore verse                  # A small daily encouragement
```

Full flag reference: `stegcore --help`.

---

## GUI

Launch Stegcore, then follow the step-by-step wizards for hiding, recovering, or checking files. Drag and drop works everywhere.

| Feature | What it does |
|---|---|
| Embed wizard | Four-step flow: message, cover file, options, confirm |
| Extract wizard | Three-step flow: stego file, passphrase, recovered payload |
| Analysis dashboard | Animated charts for each detector with the verdict and per-test scores. |
| Audio analysis | Waveform view with suspicious regions highlighted |
| Pixel diff | Before and after comparison on embed success |
| Export | Copy the dashboard to clipboard, export as PDF, HTML, JSON or CSV |

Analysis history stays on your device. Nothing leaves.

---

## Supported formats

| Format | Hide | Recover | Analyse | Notes |
|---|---|---|---|---|
| PNG | ✓ | ✓ | ✓ | Best capacity and concealment |
| BMP | ✓ | ✓ | ✓ | Lossless |
| JPEG | ✓ | ✓ | ✓ | JSteg style JPEG embedding |
| WebP | ✓ | ✓ | ✓ | Lossless WebP |
| WAV | ✓ | ✓ | ✓ | PCM audio, least significant bit |
| FLAC | ✓ | ✓ | ✓ | Lossless audio, bit-exact round-trip |

---

## Why Stegcore

| | Stegcore | Steghide | OpenStego | OpenPuff |
|---|---|---|---|---|
| Works offline | ✓ | ✓ | ✓ | ✓ |
| Modern encryption | 3 authenticated ciphers plus Argon2id | Rijndael plus MD5 | AES-128 | AES-256 |
| Deniable dual-payload | ✓ | ✗ | ✗ | ✓ |
| Built-in analysis | ✓ (SPA + RS + WS + fingerprints) | ✗ | ✗ | ✗ |
| Cover scoring | ✓ | ✗ | ✗ | ✗ |
| Pixel diff | ✓ | ✗ | ✗ | ✗ |
| GUI + CLI | ✓ | CLI only | GUI only | GUI only |
| Works in pipes | ✓ | ✗ | ✗ | ✗ |
| Actively maintained | ✓ (2026) | ✗ (2003) | ✗ (2016) | ✗ (2018) |

---

## How well does the analysis work

Stegcore is built in public, so we are specific about what it catches and what it does not.

- **Classical detectors at Aletheia parity.** Sample Pair Analysis, RS and Weighted Stego match the public [Aletheia](https://github.com/daniellerch/aletheia) reference to floating-point precision, and run far faster in Rust.
- **Strong** on spatial least-significant-bit replacement at moderate and higher payloads, and on tools that leave a structural fingerprint (OpenStego, for example), where a hit is effectively decisive.
- **Hard, and we say so.** Very low payloads, LSB-matching, and JPEG-domain hiding are difficult for classical steganalysis. Stegcore does not pretend otherwise.

Per-release detection numbers, measured on public datasets against Aletheia, are published in the [changelog](CHANGELOG.md). You can rerun the analysis on your own files:

```bash
stegcore analyse your-images/*.png --json > your-scores.jsonl
```

---

## Docs

- [CLI reference](USAGE.md)
- [Architecture](ARCHITECTURE.md)
- [Changelog](CHANGELOG.md)
- [Security and threat model](SECURITY.md)
- [Contributing](CONTRIBUTING.md)

---

## Licence

Stegcore is dual-licensed.

- **AGPL-3.0-or-later**: the default. Free for individuals, researchers,
  open-source projects, NGOs, and anyone willing to release their own
  derivative source under the same terms. See [LICENSE](LICENSE).
- **Commercial licence**: for organisations that want to build on
  Stegcore inside proprietary software, internal tools, or hosted
  services without the AGPL source-release obligation.
  See [COMMERCIAL.md](COMMERCIAL.md).

Either licence applies to the same codebase; you pick the one that
fits your situation. The [Acceptable Use Policy](AUP.md) applies
regardless of which licence you use.

Contact: `ops@themalwarefiles.com`
