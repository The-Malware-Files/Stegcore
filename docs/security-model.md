# Security Model

Privacy is a right, not a feature. This document describes who Stegcore is built for, what it protects against, and, just as importantly, what it does not.

---

## Who is this for?

A journalist carrying interview recordings across a border checkpoint. An activist coordinating in a country where WhatsApp is monitored. A domestic abuse survivor who needs to keep evidence on a shared device. A whistleblower exfiltrating documents from an organisation that inspects outgoing files.

These people don't need another encryption tutorial. They need a tool that works, that doesn't require a security background, and that holds up when someone is looking.

---

## Threat model

### 1. Someone who can see your files

A cloud storage provider, an email gateway, a family member, a border agent scrolling through your gallery.

**How Stegcore helps:** The output file looks and sounds completely ordinary. A photo of a sunset is still a photo of a sunset. There is no visual or audible difference. No metadata changes, no suspicious file extensions, no extra files to explain.

### 2. Someone who suspects you're hiding data

A forensic examiner who runs your files through statistical analysis tools: chi-squared tests, sample pair analysis, RS analysis.

**How Stegcore helps:** Adaptive embedding mode concentrates modifications in areas of natural texture where statistical tests can't distinguish them from normal image noise. In testing against Aletheia (the most sophisticated open-source steganalysis toolkit), all four classical detectors failed to detect Stegcore's adaptive embedding.

No tool can promise absolute invisibility against unlimited analysis. What Stegcore does is raise the cost of detection to the point where it exceeds the cost of targeted, warrant-based investigation, which is how privacy *should* work.

### 3. Someone who demands your passphrase

A government agent, an abusive partner, or anyone with the leverage to force you to reveal what's hidden.

**How Stegcore helps:** Deniable mode embeds two separate messages with two separate passphrases. Give them one passphrase; they get a plausible decoy message. The real message stays hidden behind the other passphrase. The two halves of the file are structurally identical. There is no way to prove the second message exists.

---

## Encryption

Your data is encrypted before it is hidden. If the hidden data were somehow extracted without the passphrase, it would be unreadable ciphertext.

Stegcore uses authenticated encryption: the passphrase not only encrypts your data but also authenticates it. Any modification to the stego file, even a single bit, will cause extraction to fail with an error rather than returning corrupted data.

Your passphrase is processed through a memory-hard key derivation function (Argon2id) before use. This makes brute-force attacks significantly harder than attacking a simple password hash.

---

## What Stegcore does not protect against

- **Metadata:** file creation times, EXIF data, and operating system metadata are not modified. If your cover file contains identifying metadata, that metadata may remain.
- **Traffic analysis:** Stegcore does not hide that you are sending a file; only that the file contains hidden data. Use appropriate transport security for your channel.
- **Device compromise:** if your device is compromised before embedding or after extraction, an attacker may have access to your plaintext data regardless of what Stegcore does.
- **Cover file selection:** embedding always modifies the cover file in some way. If you share the same cover image before and after embedding, a forensic examiner could detect that the file changed. Always embed into a fresh copy of a cover file.
- **Passphrase strength:** no encryption protects a short or guessable passphrase. Use a long, random passphrase.

---

## Supported ciphers

All three ciphers provide authenticated encryption with additional data (AEAD). They are all considered secure for the purpose of protecting personal data.

| Cipher | Notes |
|--------|-------|
| ChaCha20-Poly1305 | Default. Fast on all hardware including devices without AES acceleration. |
| Ascon-128 | Compact. Designed for constrained environments. |
| AES-256-GCM | Standard. Hardware-accelerated on most modern CPUs. |

---

## Steganalysis suite

Stegcore includes a built-in steganalysis suite. Every detector is
calibrated against the union of Cassavia 2022, BOSSbase 1.01 and an
ALASKA2 sample at a documented **combined false-positive ceiling of
about 4%**, held on the worst clean sub-distribution. Numbers are fit
by the scripts in `private/calibration/`, not hand-tuned.

### Verdict-gating detectors

These three classical detectors decide the verdict. All three are
ports of the [Aletheia](https://github.com/daniellerch/aletheia)
reference implementations and **agree with Aletheia to
floating-point precision** on the documented test corpus. Stegcore is
allowed to be faster (~100× on RS in Rust); it is not allowed to be a
different answer.

- **Sample Pair Analysis** (DWW quadratic estimator) — estimates
  embedding rate from trace multiset asymmetry.
- **RS Analysis** (per-channel) — Regular/Singular group asymmetry
  with the correct F₋₁ flipping mask.
- **Weighted Stego** (per-channel) — third Aletheia-parity detector
  added in v4.0.1.

Equal-weighted ensemble at the calibrated per-detector thresholds.

### Signal-only detectors

These provide useful diagnostic detail in the report but no longer
gate the verdict (their FPR characteristics did not meet the
calibrated bar, but they are kept visible for analyst judgement).

- **Chi-Squared** (block-based) — LSB pair distribution uniformity.
- **LSB Entropy** (per-channel autocorrelation) — spatial correlation
  of least significant bits.

### Structural tool fingerprints (tiered)

Each fingerprint carries an explicit confidence tier:

- **Exact**: a fingerprint that cannot fire on a clean cover.
  Short-circuits the verdict to "Likely Stego".
- **Heuristic**: a fingerprint with a documented non-zero false-
  positive rate on clean imagery. Floors the verdict at "Suspicious";
  does not short-circuit.

Tier choice is empirically justified by FPR on a clean corpus before
a fingerprint is allowed to ship. The validation harness at
`tests/fingerprint/harness.py` runs the proof-of-correctness on
every release.

Current fingerprints are OpenStego and Camouflage (Exact tier), and
LSBSteg, F5 and appended-data-after-EOF (Heuristic tier). Steghide
does not currently carry a structural fingerprint; its detection would
require seed brute-force, which Stegcore does not perform.

### Dispatcher

Analysis dispatches by **magic-byte content sniffing** (PNG, BMP,
JPEG, RIFF/WAVE, FLAC) with extension as fallback. A cover named
`cat.jpg` that is in fact a PNG still routes to the PNG analysis
path. Closes the extension-only-routing class of user-facing rough
edge.

### Ensemble verdict

The combined output is one of:

- **Clean**: no detector exceeded its calibrated threshold and no
  fingerprint matched.
- **Suspicious**: at least one calibrated detector fired, or a
  Heuristic fingerprint matched.
- **Likely Stego**: multiple calibrated detectors fired, or an
  Exact fingerprint matched.

A reproduction methodology and the head-to-head numbers against
Aletheia live in the project README's *How well does the analysis
work?* section.

---

## Reporting a vulnerability

See [SECURITY.md](../SECURITY.md) for the responsible disclosure process.
