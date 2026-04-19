<div align="center">

<img src="icon.svg" alt="Stegcore logo" width="96" height="96">

# Stegcore

**Hide encrypted messages inside ordinary files**

[![CI](https://github.com/elementmerc/Stegcore/actions/workflows/ci.yml/badge.svg)](https://github.com/elementmerc/Stegcore/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/elementmerc/Stegcore)](https://github.com/elementmerc/Stegcore/releases/latest)
[![Licence: AGPL-3.0](https://img.shields.io/badge/licence-AGPL--3.0--or--later-blue)](LICENSE)

<!-- <img src="docs/demo.gif" alt="Stegcore GUI demo" width="720"> -->

</div>

---

Stegcore hides encrypted messages inside ordinary images and audio files. The result looks and sounds completely normal — indistinguishable from the original. Not to your ISP, not to a border agent, not to a forensic examiner with professional tools.

Your data never leaves your device. No accounts, no cloud, no telemetry, no network connections of any kind. One passphrase to hide, the same passphrase to recover. If someone demands your password, give them the decoy — two messages, two passphrases, structurally identical halves.

> 🎉 **Tested against [Aletheia](https://github.com/daniellerch/aletheia), the leading open-source steganalysis toolkit.** Adaptive mode passed all four classical detectors (SPA, RS, Weighted Stego, Triples) on real-world images. [Details →](docs/vs-alternatives.md#detection-resistance)

<details>
<summary>What's under the hood</summary>

Three authenticated ciphers (Ascon-128, ChaCha20-Poly1305, AES-256-GCM). Argon2id key derivation. Adaptive texture-aware embedding. Deniable dual-payload mode. Built-in steganalysis suite with five detectors and tool fingerprinting. Desktop GUI and CLI. Native binary — no Python, no Java, no Electron.
</details>

---

## Install

### Download a binary (recommended)

Grab the latest release for your platform from the [**Releases page**](https://github.com/elementmerc/Stegcore/releases).

| Platform | CLI | GUI |
|---|---|---|
| **Linux x86_64** | `.tar.gz` | `.AppImage` / `.deb` |
| **macOS (Intel + Apple Silicon)** | Universal binary | `.dmg` |
| **Windows x86_64** | `.zip` | `.msi` |

### One-line installer

Same URL works on both Unix and Windows — auto-detects your platform:

**Linux / macOS:**
```bash
curl -fsSL https://raw.githubusercontent.com/elementmerc/Stegcore/main/install | sh
```

**Windows (PowerShell):**
```powershell
irm https://raw.githubusercontent.com/elementmerc/Stegcore/main/install | iex
```

<details>
<summary>Installer options</summary>

```bash
# Pin a version
STEGCORE_VERSION=v4.0.0-beta.1 curl -fsSL .../install.sh | bash

# Custom install directory
STEGCORE_DIR=/opt/stegcore curl -fsSL .../install.sh | bash

# Uninstall
bash install.sh --uninstall
```

```powershell
# Windows options
.\install.ps1 -Component both          # CLI + GUI
.\install.ps1 -Version v4.0.0-beta.1   # Pin version
.\install.ps1 -Uninstall               # Remove
.\install.ps1 -DryRun                  # Preview only
```
</details>

### Package managers (coming soon)

```bash
# Homebrew (macOS / Linux)
brew install elementmerc/tap/stegcore

# Winget (Windows)
winget install elementmerc.Stegcore
```

### Building from source

```sh
cargo build --workspace --release
```

Produces `target/release/stegcore` (CLI). For the desktop app, run
`cargo tauri build` from the repo root.

---

## CLI usage

```bash
# Guided wizard (recommended for new users)
stegcore wizard

# Embed
stegcore embed cover.png secret.txt -o stego.png

# Extract
stegcore extract stego.png -o recovered.txt

# Analyse for hidden content
stegcore analyse suspect.png

# Batch analyse with progress
stegcore analyse *.png --json

# Pipe support
echo "secret" | stegcore embed cover.png - -o stego.png
stegcore extract stego.png --raw | xxd
```

### Additional commands

```bash
# Score a cover file's suitability
stegcore score cover.png

# Compare original vs stego (pixel diff)
stegcore diff cover.png stego.png

# Read embedded metadata (requires passphrase)
stegcore info stego.png

# List available ciphers
stegcore ciphers

# System health check
stegcore doctor

# Benchmark cipher throughput
stegcore benchmark

# Generate shell completions
stegcore completions bash > ~/.local/share/bash-completion/completions/stegcore

# Bible verse
stegcore verse
```

Full flag reference: `stegcore --help`

---

## GUI

Launch Stegcore, then follow the step-by-step wizards for embedding,
extracting, or analysing files. Drag and drop works everywhere.

| Feature | What it does |
|---|---|
| Embed wizard | 4-step guided flow: message → cover → options → confirm |
| Extract wizard | 3-step flow: stego file → passphrase → recovered payload |
| Steganalysis dashboard | Animated charts: Chi-Squared (block-based), RS Analysis (per-channel), SPA gauge (DWW quadratic), LSB Entropy heatmap (per-channel autocorrelation) |
| Audio analysis | Oscilloscope trace with suspicious region highlighting |
| Pixel diff | Before/after comparison on embed success |
| Export | Copy dashboard to clipboard, export as PDF/HTML/JSON/CSV |

**Keyboard shortcuts** — E (embed), X (extract), A (analyse), L (learn), R (reload), ? (shortcuts overlay).

**First-run wizard** walks new users through the acceptable use policy,
licence, and preferences (theme, default cipher).

**Settings** — theme (dark/light), interface size (small/default/large/xl),
default cipher, embedding mode, auto-score, clipboard auto-clear, reduce
motion.

Analysis history stays local. Nothing leaves your device.

---

## Supported formats

| Format | Embed | Extract | Analyse | Notes |
|---|---|---|---|---|
| PNG | ✓ | ✓ | ✓ | Best capacity and concealment |
| BMP | ✓ | ✓ | ✓ | Lossless |
| JPEG | ✓ | ✓ | ✓ | JSteg DCT coefficient LSB |
| WebP | ✓ | ✓ | ✓ | Lossless WebP |
| WAV | ✓ | ✓ | ✓ | PCM audio sample LSB |
| FLAC | — | ✓ | ✓ | Decode-only |

---

## Why Stegcore?

| | Stegcore | Steghide | OpenStego | OpenPuff |
|---|---|---|---|---|
| Offline | ✓ | ✓ | ✓ | ✓ |
| Modern encryption | 3 AEAD + Argon2id | Rijndael + MD5 | AES-128 | AES-256 |
| Deniable mode | ✓ | ✗ | ✗ | ✓ |
| Built-in steganalysis | ✓ | ✗ | ✗ | ✗ |
| Cover scoring | ✓ | ✗ | ✗ | ✗ |
| Pixel diff | ✓ | ✗ | ✗ | ✗ |
| GUI + CLI | ✓ | CLI only | GUI only | GUI only |
| Pipe support | ✓ | ✗ | ✗ | ✗ |
| Active development | ✓ (2026) | ✗ (2003) | ✗ (2016) | ✗ (2018) |

---

## Docs

- [CLI reference](USAGE.md)
- [Architecture](ARCHITECTURE.md)
- [Changelog](CHANGELOG.md)
- [Security & threat model](SECURITY.md)
- [Contributing](CONTRIBUTING.md)

---

## Licence

Stegcore is licensed under AGPL-3.0-or-later. See [LICENSE](LICENSE).

Contact: ops@themalwarefiles.com
