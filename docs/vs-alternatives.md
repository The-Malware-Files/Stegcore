# How Stegcore compares

Steganography has a long history of open-source tools. Steghide and OpenStego introduced thousands of people to the field and laid the conceptual foundation that everything after them, including Stegcore, builds on.

Stegcore picks up where they left off. Cryptographic standards, threat models, and user expectations have all evolved since these tools were first written. Stegcore brings those updates to the same mission: making steganography accessible to the people who need it.

---

## Overview

| Feature | Steghide | OpenStego | Stegcore |
|---------|----------|-----------|---------|
| **Formats** | JPEG, BMP, WAV, AU | BMP, PNG | PNG, BMP, JPEG, WAV, WebP, FLAC |
| **Encryption** | Rijndael-128 in CBC, integrity by CRC32 | AES-128 | Ascon-128, ChaCha20-Poly1305, AES-256-GCM, all authenticated |
| **Key derivation** | Passphrase hash, 32-bit seed (enumerable) | Undocumented | Argon2id (memory-hard) |
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

Steghide was last updated in 2003, and cryptographic practice has moved on since. Its default cipher is Rijndael with a 128-bit key in CBC mode, which its own manual page states, and integrity is a CRC32 rather than an authentication tag, so a tampered file can decrypt to something. It hashes the passphrase rather than putting it through a modern key derivation function, and CVE-2021-27211 showed that its 32-bit seed can be enumerated on ordinary hardware, which is what Stegseek does. These aren't design flaws; they're the standards of the era it was built in.

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
[Aletheia](https://github.com/daniellerch/aletheia) reference on the
union of Cassavia 2022, BOSSbase 1.01 and an ALASKA2 sample, at a
documented combined false-positive ceiling of about 4% held on the
worst clean sub-distribution. The two implementations agree to
floating-point precision on Sample Pair Analysis, RS Analysis and
Weighted Stego. Stegcore is faster in Rust (~24× on RS) without
changing the numerical answer.

How well embedded data resists detection depends on how much of it
there is, and no tool escapes that:

| Payload | Adaptive mode against classical detectors |
|---------|-------------------------------------------|
| Below ~5% of capacity | Not flagged in our testing |
| Above ~10% of capacity | Detectable, and detected |
| Sequential mode, any payload | Detectable by design |

Sequential mode prioritises capacity over stealth. Use it when
detection resistance is not your concern.

Per-release detection numbers, with the corpus and payload rates they
were measured at, are published in the
[changelog](https://github.com/The-Malware-Files/Stegcore/blob/main/CHANGELOG.md).

---

## What Stegcore adds

Every design decision in Stegcore starts with the same question: *what does someone in a dangerous situation actually need?*

**They need deniability.** If you can be forced to hand over your passphrase, encryption alone isn't enough. Deniable mode gives you two passphrases and two messages. One is real. One is a decoy. They're structurally identical, and neither half is marked as the real one. We know of no other open-source tool that offers this.

**They need to know if they've been caught.** The same tool that hides your data can also detect hidden data in other files. Stegcore's analysis suite runs three Aletheia-parity classical detectors (SPA, RS, Weighted Stego) plus tiered structural tool-fingerprinting (Exact / Heuristic) and signal-only Chi-Squared + LSB Entropy. If you receive a file and want to know whether it's been tampered with, you can check, without a separate tool.

**They need encryption that still holds up.** Stegcore uses three authenticated ciphers from the RustCrypto project with Argon2id key derivation. Every primitive has a published security analysis and is actively maintained, which is not true of a tool whose key schedule was settled in 2003.

**They need simplicity.** One file in, one file out, one passphrase. No key files to manage, lose, or accidentally disclose. The metadata is embedded in the output. You only need your passphrase to recover your data.

**They need it to just work.** One binary, no dependencies. No Python version conflicts, no Java runtime, no Electron eating your RAM. Runs on Windows, macOS, and Linux. Desktop GUI for beginners, CLI for power users.

---

## Acknowledgements

Steghide and OpenStego laid the conceptual foundation that Stegcore builds on. Their authors made real contributions to the field. Stegcore does not dismiss that work; it carries it forward.
