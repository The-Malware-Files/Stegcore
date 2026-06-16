# CLI Reference

## Global flags

| Flag | Description |
|------|-------------|
| `--version` | Print version and exit |
| `--help` | Show help for any command |
| `--json` | Output results as JSON (all commands) |
| `-v, --verbose` | Show full error chain on failure |
| `-q, --quiet` | Suppress all output except errors (exit code only) |

---

## stegcore embed

Hide a file inside a cover image or audio file.

```
stegcore embed <cover> <payload> [options]
```

| Argument | Description |
|----------|-------------|
| `<cover>` | Cover file (PNG, BMP, JPEG, WAV, WebP) |
| `<payload>` | File to hide (use `-` for stdin) |

| Option | Default | Description |
|--------|---------|-------------|
| `-o, --output <path>` | auto-generated | Output stego file path |
| `--passphrase <phrase>` | (prompted) | Encryption passphrase |
| `--mode adaptive\|sequential` | `adaptive` | Embedding mode |
| `--cipher chacha20-poly1305\|ascon-128\|aes-256-gcm` | `chacha20-poly1305` | Cipher |
| `--export-key` | off | Export a key file alongside the output |
| `--deniable` | off | Enable dual-payload mode |
| `--decoy <file>` | (required with `--deniable`) | Decoy message file |
| `--decoy-passphrase <phrase>` | (prompted with `--deniable`) | Decoy passphrase |
| `--json` | off | JSON output |

**Examples:**

```bash
# Basic embed (auto-names output)
stegcore embed photo.png secret.txt

# With all options
stegcore embed photo.png secret.txt -o output.png \
  --passphrase "my passphrase" \
  --mode adaptive \
  --cipher chacha20-poly1305 \
  --export-key

# Deniable mode
stegcore embed photo.png real.txt -o output.png \
  --passphrase "real-pass" \
  --deniable \
  --decoy decoy.txt \
  --decoy-passphrase "decoy-pass"

# Pipe from stdin
echo "secret message" | stegcore embed photo.png - -o output.png
```

**JSON output shape:**
```json
{
  "ok": true,
  "data": {
    "outputPath": "/path/to/output.png",
    "keyFilePath": null
  }
}
```

---

## stegcore extract

Recover hidden data from a stego file.

```
stegcore extract <stego> [options]
```

| Argument | Description |
|----------|-------------|
| `<stego>` | Stego file to extract from |

| Option | Default | Description |
|--------|---------|-------------|
| `-o, --output <path>` | auto-generated | Save extracted data to this path |
| `--passphrase <phrase>` | (prompted) | Passphrase used during embedding |
| `--key-file <path>` | (none) | Optional key file (not required for standard embeds) |
| `--stdout` | off | Print extracted text to stdout |
| `--raw` | off | Write raw bytes to stdout (for piping) |
| `--json` | off | JSON output |

**Examples:**

```bash
# Extract to file
stegcore extract output.png -o recovered.txt

# With key file
stegcore extract output.png -o recovered.txt --key-file output.key.json

# Print text directly
stegcore extract output.png --stdout

# Pipe raw bytes to another tool
stegcore extract output.png --raw | xxd
```

**JSON output shape:**
```json
{
  "ok": true,
  "data": {
    "bytes": 42,
    "output": "/path/to/recovered.txt"
  }
}
```

---

## stegcore analyse

Analyse a file for signs of hidden content. Runs the full Aletheia-
parity detector suite (Sample Pair Analysis, RS, Weighted Stego) plus
tiered structural fingerprinting, signal-only Chi-Squared, and
signal-only LSB Entropy. Calibrated against the Cassavia 2022,
BOSSbase 1.01 and ALASKA2 union at a documented combined false-positive
ceiling of about 4%.

```
stegcore analyse [FILE] [--batch GLOB] [options]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--batch <glob>` | (none) | Glob pattern for batch analysis (e.g. `"*.png"`) |
| `--report table\|html\|json\|csv` | `table` | Output format |
| `-o <path>` | (required for html/csv) | Report output path |
| `--watch <dir>` | (none) | Monitor a directory for new files |
| `--json` | off | JSON output to stdout |
| `--verbose` | off | Show per-test details |

**Examples:**

```bash
stegcore analyse photo.png
stegcore analyse photo.png --json
stegcore analyse photo.png --report html -o report.html
stegcore analyse --batch "*.png" --report csv -o scan.csv
stegcore analyse --watch /tmp/incoming/
```

**JSON output shape:**
```json
{
  "file": "photo.png",
  "format": "png",
  "verdict": "Clean",
  "overall_score": 0.12,
  "tool_fingerprint": null,
  "tool_fingerprint_tier": null,
  "tests": [
    { "name": "Chi-Squared",            "score": 0.10, "confidence": "High",   "detail": "LSB distribution normal" },
    { "name": "Sample Pair Analysis",   "score": 0.14, "confidence": "Medium", "detail": "No significant embedding detected" },
    { "name": "RS Analysis",            "score": 0.11, "confidence": "Medium", "detail": "Regular/Singular asymmetry within calibration band" },
    { "name": "Weighted Stego",         "score": 0.13, "confidence": "Medium", "detail": "Within calibrated false-positive band" },
    { "name": "LSB Entropy",            "score": 0.42, "confidence": "Low",    "detail": "Per-channel autocorrelation within range" },
    { "name": "Tool Fingerprint",       "score": 0.0,  "confidence": "High",   "detail": "No structural match" }
  ]
}
```

- `verdict` is one of `"Clean"` / `"Suspicious"` / `"LikelyStego"`.
- `tool_fingerprint_tier` is `"exact"`, `"heuristic"`, or `null`.
  An `Exact` tier short-circuits the verdict to `LikelyStego`. A
  `Heuristic` tier floors it at `Suspicious`. Either way `tool_
  fingerprint` carries the human-readable label.

---

## stegcore score

Score a cover file's suitability for embedding.

```
stegcore score <file> [--json]
```

Returns a quality score between 0.0 (poor) and 1.0 (excellent). Files scoring below 0.25 will be refused by `embed`.

---

## stegcore diff

Compare original and stego file at pixel level.

```
stegcore diff <original> <stego> [--json]
```

Reports changed pixels, maximum delta, and whether modifications are LSB-only.

---

## stegcore info

Read metadata embedded in a stego file without extracting.

```
stegcore info <stego> [--json]
```

Displays cipher, mode, and format info. Requires the passphrase (slot selection is passphrase-seeded).

---

## stegcore ciphers

List available ciphers.

```
stegcore ciphers [--json]
```

---

## stegcore wizard

Interactive guided embed/extract workflow.

```
stegcore wizard
```

Prompts for each step interactively. Useful if you prefer not to pass options on the command line.

---

## stegcore doctor

System health check.

```
stegcore doctor [--json]
```

Verifies engine status, temp directory access, disk space, platform info, and available formats/ciphers.

---

## stegcore benchmark

Cipher throughput test.

```
stegcore benchmark [--json]
```

Measures Argon2id key derivation speed, encryption throughput for all three ciphers, and I/O write speed.

---

## stegcore verse

Show the daily Bible verse.

```
stegcore verse [--json]
```

---

## stegcore completions

Generate shell completion scripts.

```
stegcore completions <shell>
```

Supported shells: `bash`, `zsh`, `fish`.

```bash
stegcore completions bash > ~/.local/share/bash-completion/completions/stegcore
stegcore completions zsh > ~/.zfunc/_stegcore
stegcore completions fish > ~/.config/fish/completions/stegcore.fish
```

---

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | User error (wrong passphrase, payload too large, poor cover quality, etc.) |
| `2` | Encryption error (decryption failed, unsupported cipher) |
| `3` | I/O error (file not found, permission denied, disk full) |
| `4` | Format error (unsupported extension, corrupted file) |

---

## Docker

```bash
# Single file
docker run --rm -v $(pwd):/data ghcr.io/the-malware-files/stegcore \
  embed /data/cover.png /data/secret.txt -o /data/output.png

# Batch scan
docker run --rm -v $(pwd)/photos:/data ghcr.io/the-malware-files/stegcore \
  analyse /data/*.png --report html -o /data/report.html
```
