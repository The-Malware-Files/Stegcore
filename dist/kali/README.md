# Stegcore Debian/Kali package

This directory builds a single `.deb` that installs both Stegcore
surfaces:

- `stegcore` : the command-line tool, in `/usr/bin`.
- `stegcore-gui` : the desktop application, in `/usr/bin`, with a
  launcher entry in the applications menu and an icon.

It targets Kali Linux and Debian/Ubuntu derivatives on `amd64`.

## What gets installed

| Path | Contents |
|---|---|
| `/usr/bin/stegcore` | CLI binary |
| `/usr/bin/stegcore-gui` | GUI binary |
| `/usr/share/applications/stegcore.desktop` | Menu launcher |
| `/usr/share/icons/hicolor/128x128/apps/stegcore.png` | App icon |
| `/usr/share/bash-completion/completions/stegcore` | Bash completion |
| `/usr/share/zsh/vendor-completions/_stegcore` | Zsh completion |
| `/usr/share/fish/vendor_completions.d/stegcore.fish` | Fish completion |
| `/usr/share/doc/stegcore/LICENSE` | AGPL-3.0-or-later text |
| `/usr/share/doc/stegcore/copyright` | Machine-readable copyright |

## Runtime dependencies

The CLI is statically self-contained apart from `libc`. The GUI is a
Tauri (WebKitGTK) application, so it needs the system web view and GTK
stack. The `Depends` line is derived from `ldd` on the actual GUI
binary, not guessed:

```
libc6, libwebkit2gtk-4.1-0, libgtk-3-0t64 | libgtk-3-0,
libsoup-3.0-0, libjavascriptcoregtk-4.1-0
```

`libgtk-3-0t64 | libgtk-3-0` lists the time64 package first (current
Kali rolling and Debian trixie) with the pre-transition name as a
fallback for older targets. The GUI does not link any appindicator
library, so none is required.

## Building

You need release builds of both binaries first:

```sh
# from the repository root
cargo build --release -p stegcore-cli --bin stegcore
npm --prefix frontend run build      # produces frontend/dist
cargo tauri build                    # or: cargo build --release -p stegcore-tauri --bin stegcore-gui
```

Then build the package, passing both binaries:

```sh
./dist/kali/build-deb.sh \
    target/release/stegcore \
    src-tauri/target/release/stegcore-gui
```

The version is read from `dist/kali/control` (single source of truth),
producing `stegcore_<version>-1_amd64.deb` in the working directory.

## Installing

```sh
sudo apt install ./stegcore_4.0.2-1_amd64.deb
```

`apt` resolves the WebKitGTK and GTK dependencies automatically. After
install, `stegcore --version` runs the CLI and "Stegcore" appears in the
applications menu.

## Smoke-build evidence

Built on Ubuntu 26.04 (amd64) from release binaries on 2026-06-05:

- Output: `stegcore_4.0.2-1_amd64.deb`, 6.8 MB.
- `dpkg-deb --contents` lists both binaries, the launcher, the icon, all
  three completion files, the licence and the copyright.
- `target/release/stegcore --version` reports `stegcore 4.0.2`.
- `ldd` on `stegcore-gui` resolves to the five `Depends` libraries above
  and nothing else outside the base system; no appindicator linkage.
- `lintian` reports zero errors. Three warnings remain and are expected
  for a first external package: `initial-upload-closes-no-bugs` (no bug
  to close on first upload) and `no-manual-page` on each binary.
- `desktop-file-validate` passes on `stegcore.desktop`.

Installing on a clean Kali/Debian box and confirming both the CLI and the
GUI launch (with the WebKitGTK dependencies pulled in by `apt`) is the
final manual step before proposing the package upstream.

## Kali intake

Kali does not use the Debian ITP (Intent To Package) process. New
packages are requested through the Kali GitLab package-request tracker;
file there rather than against Debian when proposing Stegcore for the
Kali repositories.
