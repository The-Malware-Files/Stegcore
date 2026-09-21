# Install

Stegcore ships as one native binary. There's no runtime to install first, no
Python, no Java, and nothing to sign up for.

## Pick a route

| Route | Best for | Gets you |
|---|---|---|
| [Installer script](#installer-script) | Most people | The CLI, on your `PATH` |
| [Download a build](#download-a-build) | Anyone who'd rather read before running | CLI and desktop app |
| [Docker](#docker) | Servers and pipelines | The CLI, isolated |
| [From source](#from-source) | Contributors | Whatever's on your branch |

## Installer script

The same URL works on Linux, macOS and Windows, and picks the right build for
your machine.

```bash
curl -fsSL https://raw.githubusercontent.com/The-Malware-Files/Stegcore/main/install | sh
```

```powershell
irm https://raw.githubusercontent.com/The-Malware-Files/Stegcore/main/install | iex
```

Downloading it first and reading it is the better habit:

```bash
curl -fsSL https://raw.githubusercontent.com/The-Malware-Files/Stegcore/main/install.sh -o install.sh
less install.sh
bash install.sh
```

```powershell
Invoke-WebRequest https://raw.githubusercontent.com/The-Malware-Files/Stegcore/main/install.ps1 -OutFile install.ps1
Get-Content install.ps1
.\install.ps1
```

### Options

```bash
STEGCORE_VERSION=v4.0.1 bash install.sh   # pin a version
STEGCORE_DIR=/opt/stegcore bash install.sh # choose where it lands
bash install.sh --uninstall
```

```powershell
.\install.ps1 -Component both     # CLI and desktop app
.\install.ps1 -Version v4.0.1
.\install.ps1 -DryRun             # show what it would do
.\install.ps1 -Uninstall
```

## Download a build

Everything is on the
[releases page](https://github.com/The-Malware-Files/Stegcore/releases).

| Platform | CLI | Desktop app |
|---|---|---|
| Linux x86_64 | `.tar.gz` | `.AppImage` or `.deb` |
| macOS, Intel and Apple Silicon | Universal binary | `.dmg` |
| Windows x86_64 | `.zip` | `.msi` |

Put the CLI binary somewhere on your `PATH` and you're done.

## Docker

```bash
docker pull ghcr.io/the-malware-files/stegcore:latest

docker run --rm -v $(pwd)/files:/data ghcr.io/the-malware-files/stegcore \
  embed /data/cover.png /data/message.txt -o /data/output.png
```

The image is multi-architecture, so it runs natively on x86_64 and arm64.

## From source

```sh
cargo build --workspace --release
```

The CLI lands at `target/release/stegcore`. For the desktop app, run
`cargo tauri build` from the repository root.

## Check it worked

```bash
stegcore --version
stegcore doctor
```

`doctor` checks the engine, the temp directory, disk space and the formats and
ciphers this build supports. It's the first thing to run if something later
behaves oddly.

## Uninstall

```bash
bash install.sh --uninstall   # Linux and macOS
```

```powershell
.\install.ps1 -Uninstall
```

Stegcore also leaves a settings directory at `~/.config/stegcore` on Linux and
macOS, or `%APPDATA%\stegcore` on Windows. Delete it if you want no trace that
the tool was on the machine.
