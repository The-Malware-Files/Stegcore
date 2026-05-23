# Stegcore and the Steganography Landscape

Steganography has a rich history of open-source tools. Steghide and OpenStego introduced thousands of people to the field and laid the conceptual foundation that everything after them, including Stegcore, builds on.

Stegcore picks up where they left off. Cryptographic standards, threat models, and user expectations have all evolved since these tools were first written. Stegcore brings those updates to the same mission: making steganography accessible to the people who need it.

---

## Overview

| Feature | Steghide | OpenStego | Stegcore |
|---------|----------|-----------|---------|
| **Formats** | JPEG, BMP, WAV, AU | BMP, PNG | PNG, BMP, JPEG, WAV, WebP, FLAC |
| **Encryption** | DES / RC4 (obsolete) | AES-128 | Ascon-128, ChaCha20-Poly1305, AES-256-GCM |
| **Key derivation** | 32-bit PRNG seed (crackable) | Undocumented | Argon2id (memory-hard) |
| **Deniable mode** | None | None | Dual-payload |
| **GUI** | CLI only | Java Swing | Native desktop (Windows, macOS, Linux) |
| **Built-in steganalysis** | No | No | Yes (5 detectors + tool fingerprinting) |
| **Key file required** | Yes | N/A | No (optional export) |
| **Active maintenance** | Abandoned 2003 | Active | Active |
| **Runtime dependency** | C libraries | Java 11+ | None (native binary) |
| **Docker** | No | No | Yes (multi-arch) |
| **Licence** | GPL-2.0 | GPL-2.0 | AGPL-3.0-or-later + commercial |

---

## Steghide

Steghide is the most widely referenced steganography tool in security documentation and CTF write-ups. It introduced many people to the field and its graph-theoretic embedding approach was innovative for its time.

Steghide was last updated in 2003. Since then, the cryptographic landscape has changed significantly. Its DES and RC4 ciphers are now deprecated, and CVE-2021-27211 revealed that its 32-bit PRNG seed can be enumerated on consumer hardware. These aren't design flaws; they reflect the standards of the era it was built in.

Steghide remains valuable for learning, CTF challenges, and understanding the history of the field. For operational use where modern cryptographic guarantees matter, Stegcore carries the mission forward with updated primitives and new capabilities like deniable mode and built-in detection.

---

## OpenStego

OpenStego is actively maintained and brought a GUI to steganography at a time when most tools were CLI-only. It supports PNG and BMP, offers watermarking, and has a straightforward interface.

Where Stegcore extends the concept:

- **Broader format support**: PNG, BMP, JPEG, WebP, WAV (vs PNG/BMP)
- **No runtime dependency**: native binary vs Java 11+ requirement
- **Deniable mode**: dual-payload embedding
- **Built-in steganalysis**: detection suite alongside embedding
- **Published cryptography**: auditable Argon2id + AEAD ciphers

OpenStego remains a solid choice if you need a quick, Java-based solution for PNG/BMP steganography.

---

## Other tools surveyed

| Tool | Status | Notes |
|------|--------|-------|
| SilentEye | Unmaintained (last release 2019) | Qt GUI, limited formats |
| DeepSound | Windows-only, closed source | Notable for FLAC/MP3 support |
| Stegosuite | Maintenance uncertain | Java, BMP/GIF/PNG only |
| OutGuess | Unmaintained | JPEG-specific DCT method |
| SNOW | Niche | Text-based whitespace steganography only |

---

## Detection resistance

Stegcore ships its own steganalysis suite, calibrated against the
[Aletheia](https://github.com/daniellerch/aletheia) reference at a 2%
per-detector false-positive ceiling on the Cassavia 2022 + BOSSbase
1.01 corpus. The two implementations agree to floating-point
precision on Sample Pair Analysis and RS Analysis; Weighted Stego is
the third Aletheia-parity detector. Stegcore is significantly faster
in Rust (~100× on RS) without changing the numerical answer.

Adaptive-mode embedding tested against Aletheia on real-world cover
imagery:

| Aletheia test | Result |
|---------------|--------|
| Sample Pair Analysis (SPA) | **No hidden data found** |
| RS Analysis | **No hidden data found** |
| Weighted Stego (WS) | **No hidden data found** |
| Triples | **No hidden data found** |

Note: this applies to adaptive mode only. Sequential mode prioritises
capacity over stealth and is detectable by design; use it when
detection resistance is not your primary concern.

---

## What Stegcore adds

Every design decision in Stegcore starts with the same question: *what does someone in a dangerous situation actually need?*

**They need deniability.** If you can be forced to hand over your passphrase, encryption alone isn't enough. Deniable mode gives you two passphrases and two messages. One is real. One is a decoy. They're structurally identical; there's no way to prove the second exists. No other open-source tool offers this.

**They need to know if they've been caught.** The same tool that hides your data can also detect hidden data in other files. Stegcore's analysis suite runs three Aletheia-parity classical detectors (SPA, RS, Weighted Stego) plus tiered structural tool-fingerprinting (Exact / Heuristic) and signal-only Chi-Squared + LSB Entropy. If you receive a file and want to know whether it's been tampered with, you can check, without a separate tool.

**They need encryption that actually works.** Steghide uses DES. That was deprecated before most of its current users were born. Stegcore uses three modern authenticated ciphers backed by the RustCrypto project, with Argon2id key derivation. Every primitive has a published security proof and is actively maintained.

**They need simplicity.** One file in, one file out, one passphrase. No key files to manage, lose, or accidentally disclose. The metadata is embedded in the output. You only need your passphrase to recover your data.

**They need it to just work.** One binary, no dependencies. No Python version conflicts, no Java runtime, no Electron eating your RAM. Runs on Windows, macOS, and Linux. Desktop GUI for beginners, CLI for power users.

---

## Acknowledgements

Steghide and OpenStego laid the conceptual foundation that Stegcore builds on. Their authors made real contributions to the field. Stegcore does not dismiss that work; it carries it forward.
