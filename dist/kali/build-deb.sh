#!/usr/bin/env bash
# Build a .deb package for Kali Linux / Debian / Ubuntu.
#
# Packages both the command-line tool (stegcore) and the desktop GUI
# (stegcore-gui), plus a launcher entry, icon, and shell completions.
#
# Usage:
#   ./dist/kali/build-deb.sh <cli-binary> <gui-binary>
#
# Example (after `cargo build --release` and `cargo tauri build`):
#   ./dist/kali/build-deb.sh \
#       target/release/stegcore \
#       src-tauri/target/release/stegcore-gui
set -euo pipefail

CLI_BINARY="${1:?Usage: build-deb.sh <cli-binary> <gui-binary>}"
GUI_BINARY="${2:?Usage: build-deb.sh <cli-binary> <gui-binary>}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

for f in "$CLI_BINARY" "$GUI_BINARY"; do
  if [[ ! -f "$f" ]]; then
    echo "error: binary not found: $f" >&2
    exit 1
  fi
done

# Single source of truth for the version: the control file.
VERSION="$(awk -F': ' '/^Version:/ {print $2}' "$SCRIPT_DIR/control" | cut -d- -f1)"
if [[ -z "$VERSION" ]]; then
  echo "error: could not read Version from $SCRIPT_DIR/control" >&2
  exit 1
fi
ARCH="amd64"
ICON_SRC="$REPO_ROOT/src-tauri/icons/128x128.png"
LICENCE_SRC="$REPO_ROOT/LICENSE"

PKG_DIR="$(mktemp -d)"
trap 'rm -rf "$PKG_DIR"' EXIT
chmod 755 "$PKG_DIR"

mkdir -p "$PKG_DIR/DEBIAN"
mkdir -p "$PKG_DIR/usr/bin"
mkdir -p "$PKG_DIR/usr/share/applications"
mkdir -p "$PKG_DIR/usr/share/icons/hicolor/128x128/apps"
mkdir -p "$PKG_DIR/usr/share/doc/stegcore"
mkdir -p "$PKG_DIR/usr/share/bash-completion/completions"
mkdir -p "$PKG_DIR/usr/share/zsh/vendor-completions"
mkdir -p "$PKG_DIR/usr/share/fish/vendor_completions.d"

# Control metadata.
cp "$SCRIPT_DIR/control" "$PKG_DIR/DEBIAN/"

# Binaries, stripped of debug symbols to keep the package small.
cp "$CLI_BINARY" "$PKG_DIR/usr/bin/stegcore"
cp "$GUI_BINARY" "$PKG_DIR/usr/bin/stegcore-gui"
chmod 755 "$PKG_DIR/usr/bin/stegcore" "$PKG_DIR/usr/bin/stegcore-gui"
strip --strip-unneeded "$PKG_DIR/usr/bin/stegcore" "$PKG_DIR/usr/bin/stegcore-gui"

# Desktop launcher + icon.
cp "$SCRIPT_DIR/stegcore.desktop" "$PKG_DIR/usr/share/applications/stegcore.desktop"
if [[ -f "$ICON_SRC" ]]; then
  cp "$ICON_SRC" "$PKG_DIR/usr/share/icons/hicolor/128x128/apps/stegcore.png"
else
  echo "warning: icon not found at $ICON_SRC; launcher will use a generic icon" >&2
fi

# Documentation: package licence, copyright, and Debian changelog.
if [[ -f "$SCRIPT_DIR/copyright" ]]; then
  cp "$SCRIPT_DIR/copyright" "$PKG_DIR/usr/share/doc/stegcore/copyright"
fi
if [[ -f "$LICENCE_SRC" ]]; then
  cp "$LICENCE_SRC" "$PKG_DIR/usr/share/doc/stegcore/LICENSE"
fi
if [[ -f "$SCRIPT_DIR/changelog.Debian" ]]; then
  # -n keeps the gzip output reproducible (no embedded timestamp).
  gzip -9nc "$SCRIPT_DIR/changelog.Debian" \
    > "$PKG_DIR/usr/share/doc/stegcore/changelog.Debian.gz"
fi

# Shell completions, generated from the CLI binary.
"$CLI_BINARY" completions bash > "$PKG_DIR/usr/share/bash-completion/completions/stegcore" 2>/dev/null || true
"$CLI_BINARY" completions zsh  > "$PKG_DIR/usr/share/zsh/vendor-completions/_stegcore" 2>/dev/null || true
"$CLI_BINARY" completions fish > "$PKG_DIR/usr/share/fish/vendor_completions.d/stegcore.fish" 2>/dev/null || true

# Normalise permissions regardless of the build umask: directories 0755,
# shared data files 0644 (the binaries under usr/bin keep their 0755).
find "$PKG_DIR" -type d -exec chmod 755 {} +
find "$PKG_DIR/usr/share" -type f -exec chmod 644 {} +

OUTPUT="stegcore_${VERSION}-1_${ARCH}.deb"
dpkg-deb --root-owner-group --build "$PKG_DIR" "$OUTPUT"
echo "Built: $OUTPUT"
