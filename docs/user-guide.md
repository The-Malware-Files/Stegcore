# Stegcore User Guide

Stegcore lets you hide messages inside photos and audio files that look completely ordinary. You pick a cover file, provide a passphrase, and Stegcore does the rest. The output is indistinguishable from an unmodified file; even to forensic analysis tools.

No special knowledge required. If you can attach a file to an email, you can use Stegcore.

---

## Install

### Linux / macOS

```bash
curl -fsSL https://raw.githubusercontent.com/elementmerc/Stegcore/main/install.sh | bash
```

Or download the script and inspect it first:

```bash
curl -fsSL https://raw.githubusercontent.com/elementmerc/Stegcore/main/install.sh -o install.sh
less install.sh
bash install.sh
```

### Windows (PowerShell)

```powershell
irm https://raw.githubusercontent.com/elementmerc/Stegcore/main/install.ps1 | iex
```

Or download and inspect first:

```powershell
Invoke-WebRequest https://raw.githubusercontent.com/elementmerc/Stegcore/main/install.ps1 -OutFile install.ps1
Get-Content install.ps1
.\install.ps1
```

### Docker

```bash
docker pull ghcr.io/elementmerc/stegcore:latest
docker run --rm -v $(pwd)/files:/data ghcr.io/elementmerc/stegcore \
  embed /data/cover.png /data/message.txt -o /data/output.png
```

### Manual download

Download the binary for your platform from the [releases page](https://github.com/elementmerc/Stegcore/releases) and place it somewhere on your `PATH`.

---

## Quickstart

**Hide a message:**

```bash
stegcore embed cover.png message.txt -o output.png
# Enter passphrase when prompted
```

**Recover it:**

```bash
stegcore extract output.png -o recovered.txt
# Enter passphrase when prompted
```

That is it. The output file looks like an ordinary image. The original cover file is unchanged.

---

## Choosing a cover file

Any photo with varied texture and detail works well. Solid-colour images or simple graphics may be refused if they do not meet the quality threshold.

Supported formats for embedding: **PNG, BMP, JPEG, WAV, WebP**

JPEG embedding operates in the DCT coefficient domain; the output is a valid JPEG file and the quality level is preserved exactly.

Supported formats for extraction and analysis: **PNG, BMP, JPEG, WAV, WebP, FLAC**

---

## Embedding modes

| Mode | When to use |
|------|-------------|
| **Adaptive** (default) | More resistant to detection. Use this unless you need extra capacity. |
| **Sequential** | Fits more data. Use when your message is large and you trust the distribution channel. |

Select the mode with `--mode adaptive` or `--mode sequential`. The GUI offers both with a toggle.

---

## Choosing a cipher

Three options are available. All provide strong authenticated encryption.

| Cipher | Good for |
|--------|----------|
| ChaCha20-Poly1305 (default) | General use. Fast on all hardware. |
| Ascon-128 | Constrained environments. Very compact. |
| AES-256-GCM | Environments where AES hardware acceleration is present. |

The cipher used during embedding is stored inside the output file. You do not need to remember which one you used; extraction is automatic.

---

## Deniable mode

Deniable mode lets you embed two separate messages in one file, each protected by a different passphrase.

```bash
stegcore embed cover.png real_message.txt -o output.png \
  --passphrase "real-passphrase" \
  --deniable \
  --decoy decoy_message.txt \
  --decoy-passphrase "decoy-passphrase"
```

If you are ever asked to reveal your passphrase, you can provide the decoy passphrase. The two halves are structurally identical; there is no way to tell which is "real".

---

## Key files (optional)

By default, all information needed for extraction is embedded in the output file. You only need your passphrase to extract.

If you need to share the metadata separately; for example, over a different channel; you can export a key file:

```bash
stegcore embed cover.png message.txt -o output.png --export-key
```

The recipient can then use:

```bash
stegcore extract output.png --key-file output.key.json
```

---

## Passphrase guidance

- Longer is better. Aim for at least 20 characters.
- A random phrase of several words is easier to remember and harder to crack than a short complex string.
- Do not reuse passphrases across different embedded files.
- The GUI shows a strength indicator as you type.

---

## Dragging and dropping (GUI)

Drop a cover image or audio file directly onto the application window to start embedding. Drop a stego file to start extracting. The application routes automatically based on file type.

---

## Keyboard shortcuts (GUI)

| Key | Action |
|-----|--------|
| `E` | Go to Embed |
| `X` | Go to Extract |
| `A` | Go to Analyse |
| `L` | Go to Learn |
| `R` | Reload analysis |
| `?` | Show shortcuts overlay |

---

## Analyse a file

The built-in analysis suite checks a file for signs of hidden content and, where possible, identifies which tool was used to embed it.

```bash
stegcore analyse suspicious.png
```

Output includes a score for each detector and an overall verdict: **Clean**, **Suspicious**, or **Likely contains hidden data**.

To save a report:

```bash
stegcore analyse suspicious.png --report html -o report.html
stegcore analyse suspicious.png --report json -o report.json
```

Batch scanning:

```bash
stegcore analyse *.png --report html -o report.html
```

---

## Scripting

All commands support `--json` output for machine-readable results:

```bash
stegcore embed cover.png message.txt -o output.png --passphrase "..." --json
stegcore extract output.png --passphrase "..." --json
stegcore analyse output.png --json
```

Exit codes: `0` success / `1` user error / `2` crypto error / `3` I/O error / `4` format error

---

## Uninstall

```bash
# Linux / macOS
bash install.sh --uninstall

# Windows
.\install.ps1 -Uninstall
```

---

## Licence

Stegcore is dual-licensed: [AGPL-3.0-or-later](../LICENSE) for
individuals and open-source projects; a [commercial licence](../COMMERCIAL.md)
for organisations that cannot meet AGPL's source-release obligation.
The [Acceptable Use Policy](../AUP.md) applies regardless of which
licence you use.
