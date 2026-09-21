# What Stegcore is

Stegcore hides an encrypted message inside an ordinary picture or sound file.
The result opens normally in any viewer or player and looks and sounds exactly
like what it is: a photo, a recording. One passphrase puts the message in, the
same passphrase takes it out.

It also works the other way round. Stegcore reads a file and tells you whether
something looks hidden inside it, which is the same job a forensic analyst does
and the reason the hiding side is built the way it is.

Nothing leaves your machine. No account, no cloud, no telemetry, no network
calls of any kind.

## What it does

| | |
|---|---|
| Hide | A file inside a PNG, BMP, JPEG, WAV or WebP cover |
| Recover | The same file back, given the passphrase |
| Analyse | Any supported file, for signs of hidden content |
| Score | A cover, for how well it would hide something |
| Deniable mode | Two messages in one file, one passphrase each |
| Watermark | An ownership mark in an image or an office document |

Three authenticated ciphers (ChaCha20-Poly1305, Ascon-128, AES-256-GCM) and
Argon2id to turn a passphrase into a key. A desktop app and a command line tool
over the same engine.

## Supported formats

| Format | Hide | Recover | Analyse | Notes |
|---|---|---|---|---|
| PNG | yes | yes | yes | Best capacity, and the easiest to hide in well |
| BMP | yes | yes | yes | Lossless |
| JPEG | yes | yes | yes | JSteg-style embedding in the DCT coefficients |
| WebP | yes | yes | yes | Lossless WebP |
| WAV | yes | yes | yes | PCM audio |
| FLAC | yes | yes | yes | Lossless audio, bit-exact round trip |

## What it is not

Stegcore doesn't hide that you sent a file, only that the file carries
something. It doesn't strip EXIF or filesystem timestamps from your cover. It
can't rescue a short passphrase.

It also doesn't claim its detection catches everything. Very low payloads,
LSB-matching and JPEG-domain hiding are hard for classical steganalysis, and
[Analysing files](analysing) says where the line is.

The [security model](security-model) is the page to read before relying on any
of this in a situation that matters, and the
[Acceptable Use Policy](https://github.com/The-Malware-Files/Stegcore/blob/main/AUP.md)
applies whichever licence you use.

## Where to go next

| If you want to | Read |
|---|---|
| Install it | [Install](install) |
| Hide and recover a file | [Hiding and recovering](user-guide) |
| Check a file for hidden content | [Analysing files](analysing) |
| Know what it protects against | [The security model](security-model) |
| Look up a flag | [CLI reference](cli-reference) |
| Compare it with other tools | [How it compares](vs-alternatives) |
