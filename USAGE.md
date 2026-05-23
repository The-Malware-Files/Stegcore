# Stegcore; CLI Usage Guide

Full reference for the Stegcore CLI. The GUI is self-explanatory with
step-by-step wizards. This document covers the terminal.

> **Looking for flag-by-flag detail?** See [docs/cli-reference.md](docs/cli-reference.md)
> for every subcommand's options and JSON output shapes. This guide
> covers the everyday workflow.

---

## Two ways to use the CLI

**Guided wizard (beginners):**
```bash
stegcore wizard
```
Walks you through every step with plain-English prompts. No flags
needed. Covers embedding, extracting, scoring, and analysis.

**Power-user commands (scripting):**
```bash
stegcore embed cover.png secret.txt -o stego.png --cipher chacha20-poly1305
stegcore extract stego.png -o recovered.txt --passphrase "$PASS"
```

Both modes call the same underlying code.

---

## Global flags

These flags work with any command:

| Flag | Description |
|---|---|
| `-v, --verbose` | Show detailed error chains |
| `--json` | Output results as JSON (machine-readable) |
| `-q, --quiet` | Suppress all output except errors (exit code only) |

---

## Commands

### `embed`; Hide a file inside a cover

```bash
stegcore embed <cover> <payload> [options]
```

| Flag | Default | Description |
|---|---|---|
| `-o, --output` | auto-generated | Output stego file path (defaults to `<stem>_stego.<ext>`) |
| `--cipher` | `chacha20-poly1305` | Cipher: `ascon-128`, `aes-256-gcm`, `chacha20-poly1305` |
| `--mode` | `adaptive` | Embedding mode: `adaptive` (secure) or `sequential` (high capacity) |
| `--deniable` | off | Enable deniable dual-payload mode |
| `--decoy` |; | Decoy payload file (required with `--deniable`) |
| `--export-key` | off | Export a `.json` key file alongside the output |
| `--passphrase` | prompt | Passphrase (omit for secure interactive prompt) |

**Examples:**
```bash
# Basic embed (auto-names output to photo_stego.png)
stegcore embed photo.png secret.txt

# With specific cipher and key export
stegcore embed photo.png secret.txt -o stego.png --cipher aes-256-gcm --export-key

# Deniable mode
stegcore embed photo.png real.txt -o stego.png --deniable --decoy decoy.txt

# Pipe from stdin
echo "secret message" | stegcore embed photo.png - -o stego.png

# Scripted (JSON output)
stegcore embed photo.png secret.txt --json --passphrase "my passphrase"
```

### `extract`; Recover a hidden file

```bash
stegcore extract <stego> [options]
```

| Flag | Default | Description |
|---|---|---|
| `-o, --output` | auto-generated | Output recovered file path (defaults to `extracted_<stem>`) |
| `--key-file` | none | Optional key file for extraction |
| `--passphrase` | prompt | Passphrase |
| `--stdout` | off | Print extracted text to stdout |
| `--raw` | off | Write raw bytes to stdout (for piping binary data) |

**Examples:**
```bash
# Basic extract
stegcore extract stego.png -o recovered.txt

# With key file
stegcore extract stego.png -o recovered.txt --key-file stego.key.json

# Pipe to another tool
stegcore extract stego.png --raw | xxd

# Print text payload directly
stegcore extract stego.png --stdout
```

### `analyse`; Detect hidden content

```bash
stegcore analyse <file>... [options]
```

| Flag | Default | Description |
|---|---|---|
| `--report` | `table` | Output format: `table`, `html`, `json`, `csv` |
| `-o, --output` |; | Report output path (required for html/csv) |
| `--watch <dir>` | off | Monitor a directory for new files and analyse them automatically |
| `--json` | off | Output results as JSON |
| `--verbose` | off | Show per-test details |

Runs the full steganalysis suite: Chi-Squared (block-based), Sample Pair
Analysis (DWW quadratic), RS Analysis (per-channel), LSB Entropy
(per-channel autocorrelation), and Tool Fingerprinting. Returns a verdict
(Clean / Suspicious / Likely Stego) with an overall score 0–100.

**Examples:**
```bash
# Single file
stegcore analyse suspect.png

# Batch with progress bar and ETA
stegcore analyse *.png --json

# Watch a directory for new files
stegcore analyse --watch /tmp/incoming/

# Generate an HTML report
stegcore analyse suspect.png --report html -o report.html

# Verbose with per-test breakdown
stegcore analyse suspect.png --verbose
```

### `score`; Rate a cover file

```bash
stegcore score <cover>
```

Returns a 0.0–1.0 suitability score. Higher is better. Considers
entropy, texture density, and resolution.

### `diff`; Compare original and stego file

```bash
stegcore diff <original> <stego>
```

Reports changed pixels, maximum delta, and whether modifications are
LSB-only (visually identical). Useful for verifying embedding quality.

### `info`; Read embedded metadata

```bash
stegcore info <stego> [--json]
```

Displays the cipher, mode, and format info embedded in a stego file.
Requires the passphrase (slot selection is passphrase-seeded).

### `ciphers`; List available ciphers

```bash
stegcore ciphers [--json]
```

### `doctor`; System health check

```bash
stegcore doctor
```

Verifies engine status, temp directory access, disk space, platform
info, and available formats/ciphers. Useful for troubleshooting.

### `benchmark`; Cipher throughput test

```bash
stegcore benchmark
```

Measures Argon2id key derivation speed, encryption throughput for all
three ciphers, and I/O write speed. Results in MB/s.

### `wizard`; Interactive guided mode

```bash
stegcore wizard
```

### `verse`; Show the daily verse

```bash
stegcore verse [--json]
```

### `completions`; Generate shell completions

```bash
stegcore completions bash > ~/.local/share/bash-completion/completions/stegcore
stegcore completions zsh > ~/.zfunc/_stegcore
stegcore completions fish > ~/.config/fish/completions/stegcore.fish
```

---

## Configuration

Stegcore reads defaults from `~/.config/stegcore/config.toml` (Linux/macOS)
or `%APPDATA%\stegcore\config.toml` (Windows):

```toml
default_cipher = "chacha20-poly1305"
default_mode = "adaptive"
export_key = false
verbose = false
verses = true
```

All config values can be overridden by command-line flags.

---

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | User error (bad input, insufficient capacity, empty payload) |
| 2 | Crypto error (wrong passphrase, decryption failed) |
| 3 | I/O error (file not found, permission denied) |
| 4 | Format error (unsupported format, corrupted file) |

---

## JSON output

All commands support `--json` for scripted pipelines:

```bash
stegcore embed cover.png secret.txt --json --passphrase "$PASS"
```

```json
{
  "ok": true,
  "data": {
    "outputPath": "photo_stego.png",
    "keyFilePath": null
  }
}
```

Errors:
```json
{
  "ok": false,
  "error": "Insufficient capacity: payload requires 45 KB but cover supports 12 KB"
}
```

---

## Privacy

Stegcore is completely offline. It makes no network connections, sends no
telemetry, and requires no account. All processing happens locally on your
machine.

## Licence

Stegcore is dual-licensed: [AGPL-3.0-or-later](LICENSE) for individuals
and open-source projects; a [commercial licence](COMMERCIAL.md) for
organisations that cannot meet AGPL's source-release obligation. The
[Acceptable Use Policy](AUP.md) applies regardless of which licence you
use.
