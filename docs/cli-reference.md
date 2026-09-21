# CLI reference

Every command, every flag, and the shape of every JSON reply. If you just want
to hide and recover a file, start with [Hiding and recovering](user-guide).

There are two ways in, and they run the same code underneath:

```bash
stegcore wizard                                    # guided, no flags to learn
stegcore embed cover.png secret.txt -o stego.png   # direct
```

## Global flags

These work on every command.

| Flag | What it does |
|---|---|
| `--version` | Print the version and exit |
| `-h, --help` | Help for the whole tool or for one command |
| `--json` | Print the result as JSON instead of a formatted table |
| `-v, --verbose` | Show the full error chain when something fails |
| `-q, --quiet` | Print nothing but errors. The exit code is the answer |

Commands that write a file also take `--force`, which overwrites an existing
output instead of refusing.

## Passphrases

Three ways to supply one, in order of preference.

| Way | Safe to script | Why |
|---|---|---|
| Interactive prompt (the default) | No | The passphrase never leaves the terminal |
| `--passphrase-file <path>` | Yes | The value never appears in the process command line |
| `--passphrase <phrase>` | No | Readable by every local user while the command runs, because `/proc/<pid>/cmdline` is world readable |

Stegcore prints a warning when it sees `--passphrase` on the command line, and
suppresses that warning under `--json` and `--quiet` so pipelines stay clean.

---

## stegcore embed

Hide a file inside a cover image or audio file.

```
stegcore embed [OPTIONS] <COVER> <PAYLOAD>
```

| Argument | What it is |
|---|---|
| `<COVER>` | Cover file: PNG, BMP, JPEG, WebP, WAV or FLAC |
| `<PAYLOAD>` | The file to hide. Use `-` to read it from stdin |

| Option | Default | What it does |
|---|---|---|
| `-o, --output <PATH>` | auto-generated | Where to write the stego file |
| `--mode <MODE>` | `adaptive` | `adaptive` or `sequential` |
| `--cipher <CIPHER>` | `chacha20-poly1305` | `chacha20-poly1305`, `ascon-128` or `aes-256-gcm` |
| `--passphrase <PHRASE>` | prompt | See [Passphrases](#passphrases) |
| `--passphrase-file <PATH>` | prompt | Read the passphrase from a file. One trailing newline is stripped |
| `--deniable` | off | Carry a second, decoy message. Needs `--export-key` |
| `--decoy <FILE>` | required with `--deniable` | The decoy message |
| `--decoy-passphrase <PHRASE>` | prompt | The passphrase that reveals the decoy |
| `--export-key` | off | Write a `.json` key file beside the output |
| `--force` | off | Overwrite the output if it already exists |

**Deniable mode needs `--export-key`.** Which half of the file holds which
message is recorded only in the key files, so a deniable embed without them
would produce a file neither passphrase can open. Stegcore refuses the command
rather than writing one, and tells you to add the flag.

```bash
# The short version
stegcore embed photo.png secret.txt

# Named output, a different cipher, and a key file
stegcore embed photo.png secret.txt -o stego.png \
  --cipher aes-256-gcm --export-key

# Two messages, two passphrases
stegcore embed photo.png real.txt -o stego.png \
  --deniable --decoy decoy.txt --export-key

# From stdin
echo "secret" | stegcore embed photo.png - -o stego.png
```

```json
{
  "ok": true,
  "data": {
    "output": "stego.png",
    "key_file": "stego.json"
  }
}
```

Without `--export-key` there's no `key_file` field at all. A deniable embed
returns `real_key` and `decoy_key` in its place, one file each.

---

## stegcore extract

Recover a hidden file.

```
stegcore extract [OPTIONS] <STEGO>
```

| Option | Default | What it does |
|---|---|---|
| `-o, --output <PATH>` | `./extracted.<stego-stem>` | Where to save the payload |
| `--passphrase <PHRASE>` | prompt | See [Passphrases](#passphrases) |
| `--passphrase-file <PATH>` | prompt | Read the passphrase from a file |
| `--key-file <PATH>` | none | A key file, if one was exported. Required for a deniable file, optional otherwise |
| `--stdout` | off | Print a text payload to stdout |
| `--raw` | off | Write raw bytes to stdout, for piping |
| `--force` | off | Overwrite the output if it already exists |

`-o`, `--stdout` and `--raw` are mutually exclusive.

```bash
stegcore extract stego.png -o recovered.txt
stegcore extract stego.png --stdout
stegcore extract stego.png --raw | xxd
stegcore extract stego.png -o recovered.txt --key-file stego.json

# A deniable file: one key file per message
stegcore extract stego.png --stdout --key-file stego.real.json
stegcore extract stego.png --stdout --key-file stego.decoy.json
```

```json
{
  "ok": true,
  "data": {
    "output": "recovered.txt",
    "bytes": 25
  }
}
```

---

## stegcore analyse

Check a file for hidden content. See [Analysing files](analysing) for what the
verdict means and how far to trust it.

```
stegcore analyse [OPTIONS] [FILE]
```

| Option | Default | What it does |
|---|---|---|
| `--batch <GLOB>` | none | Analyse everything matching a pattern. Quote it |
| `--report <FORMAT>` | `table` | `table`, `html`, `json` or `csv` |
| `-o, --output <PATH>` | none | Where to write the report. Required for `html` and `csv` |
| `--watch <DIR>` | none | Watch a directory and analyse new files as they arrive |
| `--force` | off | Overwrite the report if it already exists |

Pass either `FILE` or `--batch`, not both. A shell glob on its own
(`stegcore analyse *.png`) expands to several arguments and is refused, because
the command takes one file.

```bash
stegcore analyse suspect.png
stegcore analyse suspect.png --verbose
stegcore analyse --batch "*.png" --json
stegcore analyse suspect.png --report html -o report.html
stegcore analyse --watch /tmp/incoming/
```

`--json` prints the usual envelope with an array of reports, one per file:

```json
{
  "ok": true,
  "data": [
    {
      "file": "suspect.png",
      "format": "png",
      "verdict": "likely_stego",
      "overall_score": 1.0,
      "tool_fingerprint": null,
      "tests": [
        {
          "name": "Chi-Squared",
          "score": 0.912,
          "confidence": "high",
          "detail": "LSB pair distribution is highly uniform (score 0.91)"
        },
        {
          "name": "Weighted Stego",
          "score": 1.0,
          "confidence": "high",
          "detail": "Weighted-stego residual indicates LSB replacement (score 1.00)"
        }
      ]
    }
  ]
}
```

Trimmed for reading. The real reply also carries a `distribution` array on the
tests that have chart data and a `block_entropy` grid for the heatmap, and it
lists all five detectors rather than two.

| Field | Values |
|---|---|
| `verdict` | `clean`, `suspicious`, `likely_stego` |
| `confidence` | `low`, `medium`, `high` |
| `tool_fingerprint` | The tool's name, or `null` when nothing matched |
| `tool_fingerprint_tier` | `exact` or `heuristic`. Absent when no fingerprint matched |

`--report json -o report.json` writes the bare array instead, without the
`ok`/`data` envelope.

---

## stegcore watermark

Write or read back an ownership mark. Writing one is gated on consent.

```
stegcore watermark [OPTIONS] <FILE>
```

| Option | Default | What it does |
|---|---|---|
| `-t, --text <TEXT>` | required to write | The mark to write |
| `-o, --output <PATH>` | `<name>_marked.<ext>` | Where to write the marked file |
| `--verify` | off | Read the mark back instead of writing one |
| `--i-am-authorised` | off | Confirm you may mark this file. Recorded once per machine |
| `--cipher <CIPHER>` | `chacha20-poly1305` | As for `embed` |
| `--passphrase <PHRASE>` | prompt | See [Passphrases](#passphrases) |
| `--passphrase-file <PATH>` | prompt | Read the passphrase from a file |
| `--force` | off | Overwrite the output if it already exists |

Carriers: PNG, BMP, WebP, PDF, DOCX, PPTX and XLSX.

Without recorded consent, writing a mark exits **2** and writes nothing. The
consent is machine-local and shared with the desktop app, so you confirm once.

```bash
stegcore watermark photo.png --text "owner: Acme Corp" --i-am-authorised
stegcore watermark photo.png --text "ref: INV-2026-001" -o marked.png
stegcore watermark marked.png --verify
```

---

## stegcore score

Rate how well a file would hide something.

```
stegcore score [OPTIONS] <FILE>
```

Returns 0.0 to 1.0, higher is better, from entropy, texture and resolution.
`embed` refuses a cover scoring below 0.25.

```json
{
  "ok": true,
  "data": {
    "score": 1.0,
    "percent": 100,
    "label": "Excellent"
  }
}
```

---

## stegcore diff

Compare a cover with its stego version.

```
stegcore diff [OPTIONS] <ORIGINAL> <STEGO>
```

Reports changed pixels, changed channels, the largest single change, and
whether every change was confined to the least significant bit.

```json
{
  "ok": true,
  "data": {
    "width": 512,
    "height": 512,
    "total_pixels": 262144,
    "total_channels": 786432,
    "changed_pixels": 1837,
    "changed_channels": 1901,
    "percent_pixels_changed": 0.7,
    "percent_channels_changed": 0.24,
    "max_delta": 1,
    "lsb_only": true,
    "identical": false
  }
}
```

---

## stegcore info

Read the metadata stored inside a stego file without extracting the payload.

```
stegcore info [OPTIONS] <FILE>
```

Needs the passphrase, because which slots hold the data is derived from it.

```json
{
  "ok": true,
  "data": {
    "cipher": "chacha20-poly1305",
    "mode": "adaptive",
    "engine": "rust-v2",
    "ciphertext_len": 47,
    "deniable": false,
    "partition_half": null,
    "partition_seed": null,
    "nonce": "0gdb1WWg8PesPaXL",
    "salt": "vvBEoUbES+aGT/msn+SeDnT03pJo+MbnTSHIoFD3i+s="
  }
}
```

A deniable file has no readable metadata here: `info` reports a wrong
passphrase for both halves, because the routing lives in the key files rather
than in the file. Use `extract --key-file` instead.

---

## The small commands

| Command | What it does |
|---|---|
| `stegcore wizard` | The guided flow, for embedding and extracting without flags |
| `stegcore ciphers` | List the ciphers this build supports |
| `stegcore doctor` | Check the engine, the temp directory, disk space and available formats |
| `stegcore build-info` | Version, commit and build identity |
| `stegcore benchmark` | Argon2id speed, cipher throughput and write speed, in MB/s |
| `stegcore verse` | The day's Bible verse |

All of them take `--json`.

### stegcore completions

```
stegcore completions <SHELL>
```

`bash`, `elvish`, `fish`, `powershell` or `zsh`.

```bash
stegcore completions bash > ~/.local/share/bash-completion/completions/stegcore
stegcore completions zsh  > ~/.zfunc/_stegcore
stegcore completions fish > ~/.config/fish/completions/stegcore.fish
```

---

## Configuration file

Defaults live in the platform's own configuration directory, under `stegcore`:

| Platform | Path |
|---|---|
| Linux | `~/.config/stegcore/config.toml`, or `$XDG_CONFIG_HOME` if you set it |
| macOS | `~/Library/Application Support/stegcore/config.toml` |
| Windows | `%APPDATA%\stegcore\config.toml` |

Every value is a default that a command-line flag overrides.

```toml
default_cipher = "chacha20-poly1305"
default_mode = "adaptive"
default_output_folder = "~/stegcore-out"
export_key = false
verbose = false
verses = true
```

A missing or unreadable file is not an error; Stegcore falls back to its own
defaults.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | You asked for something that can't be done: payload too large, empty payload, cover quality too low |
| 2 | Wrong passphrase, nothing hidden in the file, or watermarking refused for want of consent |
| 3 | File not found, permission denied, disk full |
| 4 | Unsupported or corrupted format |
| 130 | Interrupted with Ctrl+C |

Under `--json`, a failure still prints an envelope:

```json
{
  "ok": false,
  "error": "Cover file is too small to hold this payload (need 2008101 bytes, have 60000)"
}
```

## Docker

```bash
# One file
docker run --rm -v $(pwd):/data ghcr.io/the-malware-files/stegcore \
  embed /data/cover.png /data/secret.txt -o /data/output.png

# A folder
docker run --rm -v $(pwd)/photos:/data ghcr.io/the-malware-files/stegcore \
  analyse --batch "/data/*.png" --report html -o /data/report.html
```
