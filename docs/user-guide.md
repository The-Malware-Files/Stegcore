# Hiding and recovering

If you can attach a file to an email, you can use Stegcore. This page is the
whole everyday workflow. [Install](install) first if you haven't.

## The short version

```bash
# Hide it
stegcore embed cover.png message.txt -o output.png

# Get it back
stegcore extract output.png -o recovered.txt
```

Both prompt for the passphrase. The cover file is never modified; `output.png`
is a new file that happens to carry your message.

Prefer not to type flags? `stegcore wizard` asks the same questions one at a
time, and the desktop app does it with drag and drop.

## Choosing a cover

Any photograph with varied texture works. Flat colour, simple graphics and
screenshots are poor hiding places, and Stegcore refuses a cover that scores
too low rather than producing something obvious.

```bash
stegcore score holiday.jpg
```

Higher is better, out of 100. Below 25 and `embed` will decline.

Two habits worth keeping:

- Embed into a fresh copy of a cover you haven't published. If the original is
  findable, anyone can difference the two.
- A bigger, busier picture holds more and hides it better.

## Embedding modes

| Mode | What you get | What you give up |
|---|---|---|
| `adaptive` (the default) | Changes go where the picture is already noisy, so they're harder to spot | Less room |
| `sequential` | More room | Detectable by design |

```bash
stegcore embed cover.png message.txt --mode sequential
```

Use adaptive unless you need the capacity and the channel is one you trust.

## Choosing a cipher

All three are authenticated, meaning a tampered file fails to open rather than
returning quiet nonsense.

| Cipher | Pick it when |
|---|---|
| `chacha20-poly1305` (the default) | You have no reason to pick another. Fast everywhere |
| `ascon-128` | You want the smallest, most compact option |
| `aes-256-gcm` | The machine has AES hardware acceleration |

The choice is recorded inside the file, so extraction doesn't ask you to
remember which one you used.

## Passphrases

- Longer beats complicated. Aim for 20 characters or more.
- Several random words are easier to remember and harder to guess than a short
  jumble.
- Don't reuse one across files. The desktop app shows a strength meter as you
  type.
- In a script, use `--passphrase-file`. `--passphrase` puts the secret in the
  process command line, where any local user can read it.

## Deniable mode

Deniable mode puts two messages in one file, each with its own passphrase. Hand
over the decoy passphrase and what comes out is the decoy message. The two
halves are built the same way and neither is marked, so the file alone doesn't
say which is which.

```bash
stegcore embed cover.png real.txt -o output.png \
  --deniable --decoy decoy.txt --export-key
```

That writes `output.real.json` and `output.decoy.json` beside the image. Each
one opens its own half:

```bash
stegcore extract output.png --stdout --key-file output.decoy.json
stegcore extract output.png --stdout --key-file output.real.json
```

**Keep `--export-key`.** Which half holds which message is recorded only in
those key files. Leave the flag off and the file is unopenable by either
passphrase, and Stegcore won't warn you.

The guarantee has a limit worth understanding. It holds against someone who has
the stego file and one passphrase. Someone who also has the original cover can
difference the two and count more changed pixels than the disclosed message
accounts for. Don't keep the cover where the stego file can be found.

## Key files

Outside deniable mode you don't need one. Everything extraction needs is in the
file itself, so the passphrase is enough.

Export one when you want to send that metadata by a different route:

```bash
stegcore embed cover.png message.txt -o output.png --export-key
stegcore extract output.png --key-file output.json
```

## Scripting

Every command takes `--json`, and the exit code carries the answer on its own
under `--quiet`.

```bash
stegcore embed cover.png message.txt -o output.png \
  --passphrase-file pass.txt --json
```

```json
{
  "ok": true,
  "data": {
    "output": "output.png"
  }
}
```

Exit codes and every reply shape are in the [CLI reference](cli-reference).

## In the desktop app

Drop a cover onto the window to start hiding; drop a stego file to start
recovering. It routes on the file, not on which button you pressed.

| Key | Goes to |
|---|---|
| `E` | Embed |
| `X` | Extract |
| `A` | Analyse |
| `W` | Watermark |
| `R` | Reload the analysis |
| `?` | The shortcut list |
| `Esc` | Close, or go back |

## Licence

Stegcore is dual licensed:
[AGPL-3.0-or-later](https://github.com/The-Malware-Files/Stegcore/blob/main/LICENSE)
for individuals and open-source projects, or a
[commercial licence](https://github.com/The-Malware-Files/Stegcore/blob/main/COMMERCIAL.md)
for organisations that can't meet the AGPL's source-release obligation. The
[Acceptable Use Policy](https://github.com/The-Malware-Files/Stegcore/blob/main/AUP.md)
applies either way.
