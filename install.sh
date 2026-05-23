#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Stegcore — Universal Installer
#
# Works on Linux, macOS, and Windows (Git Bash / MSYS2 / WSL).
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/The-Malware-Files/Stegcore/main/install.sh | bash
#   wget -qO- https://raw.githubusercontent.com/The-Malware-Files/Stegcore/main/install.sh | bash
#
# Options (environment variables):
#   STEGCORE_VERSION=latest    Pin a specific version (default: latest)
#   STEGCORE_DIR=~/.stegcore   Custom install directory
#   STEGCORE_NO_MODIFY_PATH=1  Don't modify shell profile
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

# ── Help / Uninstall flags ────────────────────────────────────────────────────

show_help() {
  cat <<'HELP'
Stegcore Installer

Usage:
  curl -fsSL https://raw.githubusercontent.com/The-Malware-Files/Stegcore/main/install.sh | bash
  bash install.sh [--uninstall] [--help]

Options:
  --help        Show this help message
  --uninstall   Remove Stegcore and clean up PATH entries

Environment variables:
  STEGCORE_VERSION=latest        Pin a specific version (default: latest)
  STEGCORE_DIR=~/.stegcore       Custom install directory
  STEGCORE_NO_MODIFY_PATH=1      Don't modify shell profile
HELP
  exit 0
}

do_uninstall() {
  local dir="${STEGCORE_DIR:-$HOME/.stegcore}"
  if [ ! -d "$dir" ]; then
    echo "Stegcore is not installed at $dir"
    exit 0
  fi
  echo "Removing $dir..."
  rm -rf "$dir"
  # Clean PATH entries from shell profiles
  for profile in "$HOME/.bashrc" "$HOME/.bash_profile" "$HOME/.zshrc"; do
    if [ -f "$profile" ]; then
      # Remove lines containing stegcore PATH export
      sed -i.bak '/# Stegcore/d;/\.stegcore\/bin/d' "$profile" 2>/dev/null || true
      rm -f "${profile}.bak"
    fi
  done
  # Fish
  local fish_conf="$HOME/.config/fish/config.fish"
  if [ -f "$fish_conf" ]; then
    sed -i.bak '/stegcore/d' "$fish_conf" 2>/dev/null || true
    rm -f "${fish_conf}.bak"
  fi
  echo "Stegcore has been uninstalled."
  exit 0
}

# Parse flags (works even when piped)
for arg in "$@"; do
  case "$arg" in
    --help|-h) show_help ;;
    --uninstall) do_uninstall ;;
  esac
done

# ── Colours (degrade gracefully if not a tty) ────────────────────────────────

if [ -t 1 ] && command -v tput &>/dev/null && [ "$(tput colors 2>/dev/null || echo 0)" -ge 8 ]; then
  BOLD="$(tput bold)"
  CYAN="$(tput setaf 6)"
  GREEN="$(tput setaf 2)"
  YELLOW="$(tput setaf 3)"
  RED="$(tput setaf 1)"
  DIM="$(tput setaf 8)"
  RESET="$(tput sgr0)"
else
  BOLD="" CYAN="" GREEN="" YELLOW="" RED="" DIM="" RESET=""
fi

info()    { echo "${CYAN}${BOLD}▸${RESET} $*"; }
success() { echo "${GREEN}${BOLD}✓${RESET} $*"; }
warn()    { echo "${YELLOW}${BOLD}⚠${RESET} $*"; }
error()   { echo "${RED}${BOLD}✗${RESET} $*" >&2; }
dim()     { echo "${DIM}  $*${RESET}"; }

# ── Platform detection ───────────────────────────────────────────────────────

detect_os() {
  case "$(uname -s)" in
    Linux*)   echo "linux" ;;
    Darwin*)  echo "macos" ;;
    CYGWIN*|MINGW*|MSYS*) echo "windows" ;;
    *)
      if grep -qiE "(microsoft|wsl)" /proc/version 2>/dev/null; then
        echo "linux"
      else
        error "Unsupported operating system: $(uname -s)"
        exit 1
      fi
      ;;
  esac
}

detect_arch() {
  case "$(uname -m)" in
    x86_64|amd64)   echo "x86_64" ;;
    aarch64|arm64)   echo "aarch64" ;;
    armv7l)          echo "armv7" ;;
    *)
      error "Unsupported architecture: $(uname -m)"
      exit 1
      ;;
  esac
}

OS="$(detect_os)"
ARCH="$(detect_arch)"
VERSION="${STEGCORE_VERSION:-latest}"
INSTALL_DIR="${STEGCORE_DIR:-$HOME/.stegcore}"

# ── Banner ───────────────────────────────────────────────────────────────────

echo ""
echo "${BOLD}  ╔═══════════════════════════════════╗${RESET}"
echo "${BOLD}  ║         ${CYAN}STEGCORE INSTALLER${RESET}${BOLD}         ║${RESET}"
echo "${BOLD}  ║   ${DIM}Hide · Encrypt · Deny${RESET}${BOLD}           ║${RESET}"
echo "${BOLD}  ╚═══════════════════════════════════╝${RESET}"
echo ""
info "Operating system: ${BOLD}${OS}${RESET}"
info "Architecture:     ${BOLD}${ARCH}${RESET}"
info "Version:          ${BOLD}${VERSION}${RESET}"
info "Install to:       ${BOLD}${INSTALL_DIR}${RESET}"
echo ""

# ── Prerequisites ────────────────────────────────────────────────────────────

check_command() {
  command -v "$1" &>/dev/null
}

DOWNLOAD_CMD=""
if check_command curl; then
  DOWNLOAD_CMD="curl"
elif check_command wget; then
  DOWNLOAD_CMD="wget"
else
  error "Neither curl nor wget found. Please install one and try again."
  exit 1
fi

if ! check_command tar && [ "$OS" != "windows" ]; then
  error "tar is required but not found. Please install it and try again."
  exit 1
fi

# ── Resolve version ──────────────────────────────────────────────────────────

REPO="The-Malware-Files/Stegcore"
API_URL="https://api.github.com/repos/${REPO}/releases"

resolve_version() {
  if [ "$VERSION" = "latest" ]; then
    info "Fetching latest release…"
    local url="${API_URL}/latest"
    local json
    if [ "$DOWNLOAD_CMD" = "curl" ]; then
      json="$(curl -fsSL "$url" 2>/dev/null)" || {
        error "Failed to fetch latest release from GitHub."
        error "Check your internet connection or try again later."
        exit 1
      }
    else
      json="$(wget -qO- "$url" 2>/dev/null)" || {
        error "Failed to fetch latest release from GitHub."
        exit 1
      }
    fi
    VERSION="$(echo "$json" | grep -o '"tag_name":[[:space:]]*"[^"]*"' | head -1 | cut -d'"' -f4)"
    if [ -z "$VERSION" ]; then
      error "Could not determine latest version. Try setting STEGCORE_VERSION manually."
      exit 1
    fi
  fi
  success "Version: ${VERSION}"
}

resolve_version

# ── Build asset name ─────────────────────────────────────────────────────────

build_asset_name() {
  local ext="tar.gz"
  local os_name="$OS"

  case "$OS" in
    windows) ext="zip"; os_name="windows" ;;
    macos)   os_name="darwin" ;;
  esac

  echo "stegcore-${VERSION}-${os_name}-${ARCH}.${ext}"
}

ASSET="$(build_asset_name)"
DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${VERSION}/${ASSET}"
CHECKSUM_URL="https://github.com/${REPO}/releases/download/${VERSION}/stegcore-${VERSION}-checksums.sha256"

# ── Download ─────────────────────────────────────────────────────────────────

TEMP_DIR="$(mktemp -d 2>/dev/null || mktemp -d -t stegcore-install)"
trap 'rm -rf "$TEMP_DIR"' EXIT

download_file() {
  local url="$1"
  local dest="$2"
  info "Downloading $(basename "$dest")…"

  if [ "$DOWNLOAD_CMD" = "curl" ]; then
    curl -fSL --progress-bar "$url" -o "$dest" 2>&1 || {
      error "Download failed: $url"
      dim "The release for ${OS}/${ARCH} may not be available yet."
      dim "Check: https://github.com/${REPO}/releases/tag/${VERSION}"
      exit 1
    }
  else
    wget --show-progress -q "$url" -O "$dest" 2>&1 || {
      error "Download failed: $url"
      exit 1
    }
  fi
  success "Downloaded $(basename "$dest")"
}

download_file "$DOWNLOAD_URL" "${TEMP_DIR}/${ASSET}"

# ── Verify checksum ──────────────────────────────────────────────────────────

verify_checksum() {
  local checksum_file="${TEMP_DIR}/checksums.sha256"
  info "Verifying checksum…"

  if [ "$DOWNLOAD_CMD" = "curl" ]; then
    curl -fsSL "$CHECKSUM_URL" -o "$checksum_file" 2>/dev/null
  else
    wget -q "$CHECKSUM_URL" -O "$checksum_file" 2>/dev/null
  fi

  if [ ! -f "$checksum_file" ] || [ ! -s "$checksum_file" ]; then
    warn "Checksum file not available — cannot verify download integrity."
    warn "This could mean the release is still being published, or the"
    warn "checksums were not included. Proceeding without verification."
    return 0
  fi

  local expected
  expected="$(grep "$ASSET" "$checksum_file" | awk '{print $1}')"
  if [ -z "$expected" ]; then
    warn "No checksum entry found for ${ASSET}."
    warn "Proceeding without verification."
    return 0
  fi

  local actual
  if check_command sha256sum; then
    actual="$(sha256sum "${TEMP_DIR}/${ASSET}" | awk '{print $1}')"
  elif check_command shasum; then
    actual="$(shasum -a 256 "${TEMP_DIR}/${ASSET}" | awk '{print $1}')"
  else
    warn "sha256sum/shasum not found — skipping verification."
    return 0
  fi

  if [ "$actual" = "$expected" ]; then
    success "Checksum verified"
  else
    error "Checksum mismatch!"
    error "Expected: ${expected}"
    error "Got:      ${actual}"
    error "The download may be corrupted. Please try again."
    exit 1
  fi
}

verify_checksum

# ── Handle existing installation ─────────────────────────────────────────────

if [ -d "$INSTALL_DIR/bin" ] && [ "$(ls -A "$INSTALL_DIR/bin" 2>/dev/null)" ]; then
  # Check if same version is already installed
  local_version=""
  if [ -x "$INSTALL_DIR/bin/stegcore" ]; then
    local_version="$("$INSTALL_DIR/bin/stegcore" --version 2>/dev/null | head -1 | awk '{print $NF}')" || true
  fi
  if [ -n "$local_version" ] && [ "$local_version" = "$VERSION" ]; then
    success "Stegcore ${VERSION} is already installed."
    dim "To reinstall, remove ${INSTALL_DIR} first."
    exit 0
  fi
  warn "Existing installation found at ${INSTALL_DIR}"
  if [ -n "$local_version" ]; then
    dim "Upgrading ${local_version} → ${VERSION}"
  else
    dim "Updating in place…"
  fi
fi

# ── Extract and install ──────────────────────────────────────────────────────

info "Installing to ${INSTALL_DIR}…"
mkdir -p "$INSTALL_DIR/bin"

case "$ASSET" in
  *.tar.gz)
    tar xzf "${TEMP_DIR}/${ASSET}" -C "${TEMP_DIR}"
    ;;
  *.zip)
    if check_command unzip; then
      unzip -qo "${TEMP_DIR}/${ASSET}" -d "${TEMP_DIR}"
    elif check_command powershell; then
      powershell -Command "Expand-Archive -Force '${TEMP_DIR}/${ASSET}' '${TEMP_DIR}'"
    else
      error "Neither unzip nor powershell available to extract .zip"
      exit 1
    fi
    ;;
esac

INSTALLED=0
for bin in stegcore stegcore-gui stegcore.exe stegcore-gui.exe; do
  found="$(find "$TEMP_DIR" -name "$bin" -type f 2>/dev/null | head -1)"
  if [ -n "$found" ]; then
    cp "$found" "$INSTALL_DIR/bin/"
    chmod +x "$INSTALL_DIR/bin/$bin" 2>/dev/null || true
    success "Installed $bin"
    INSTALLED=$((INSTALLED + 1))
  fi
done

if [ "$INSTALLED" -eq 0 ]; then
  error "No binaries found in the downloaded archive."
  error "The release format may have changed. Please report this at:"
  dim "https://github.com/${REPO}/issues"
  exit 1
fi

# ── Update PATH ──────────────────────────────────────────────────────────────

BIN_DIR="$INSTALL_DIR/bin"
add_to_path() {
  if [ "${STEGCORE_NO_MODIFY_PATH:-0}" = "1" ]; then
    dim "Skipping PATH modification (STEGCORE_NO_MODIFY_PATH=1)"
    return
  fi

  case ":$PATH:" in
    *":${BIN_DIR}:"*) return ;;
  esac

  local shell_name
  shell_name="$(basename "${SHELL:-/bin/sh}")"
  local profile=""

  case "$shell_name" in
    bash)
      if [ -f "$HOME/.bashrc" ]; then profile="$HOME/.bashrc"
      elif [ -f "$HOME/.bash_profile" ]; then profile="$HOME/.bash_profile"
      fi
      ;;
    zsh)  profile="$HOME/.zshrc" ;;
    fish)
      fish_conf="$HOME/.config/fish/config.fish"
      if [ -f "$fish_conf" ] && ! grep -q "stegcore" "$fish_conf" 2>/dev/null; then
        echo "fish_add_path ${BIN_DIR}" >> "$fish_conf"
        success "Added to ${fish_conf}"
      fi
      return
      ;;
  esac

  if [ -n "$profile" ] && [ -f "$profile" ]; then
    if ! grep -q "stegcore" "$profile" 2>/dev/null; then
      echo "" >> "$profile"
      echo "# Stegcore" >> "$profile"
      echo "export PATH=\"${BIN_DIR}:\$PATH\"" >> "$profile"
      success "Added ${BIN_DIR} to ${profile}"
    fi
  fi
}

add_to_path

# ── Shell completions ────────────────────────────────────────────────────────

install_completions() {
  local bin="${BIN_DIR}/stegcore"
  [ -x "$bin" ] || return 0

  local shell_name
  shell_name="$(basename "${SHELL:-/bin/sh}")"

  case "$shell_name" in
    bash)
      local comp_dir="${HOME}/.local/share/bash-completion/completions"
      mkdir -p "$comp_dir"
      "$bin" completions bash > "$comp_dir/stegcore" 2>/dev/null && \
        success "Installed bash completions" || true
      ;;
    zsh)
      local comp_dir="${HOME}/.zfunc"
      mkdir -p "$comp_dir"
      "$bin" completions zsh > "$comp_dir/_stegcore" 2>/dev/null && \
        success "Installed zsh completions" || true
      ;;
    fish)
      local comp_dir="${HOME}/.config/fish/completions"
      mkdir -p "$comp_dir"
      "$bin" completions fish > "$comp_dir/stegcore.fish" 2>/dev/null && \
        success "Installed fish completions" || true
      ;;
  esac
}

install_completions

# ── Done ─────────────────────────────────────────────────────────────────────

# ── Post-install verification ─────────────────────────────────────────────────

info "Verifying installation…"
if [ -x "$BIN_DIR/stegcore" ]; then
  installed_ver="$("$BIN_DIR/stegcore" --version 2>/dev/null | head -1)" || installed_ver="unknown"
  success "Binary works: ${installed_ver}"
else
  warn "Binary installed but not executable. Check permissions."
fi

# ── Done ─────────────────────────────────────────────────────────────────────

echo ""
echo "${GREEN}${BOLD}  ╔═══════════════════════════════════╗${RESET}"
echo "${GREEN}${BOLD}  ║       Stegcore installed!         ║${RESET}"
echo "${GREEN}${BOLD}  ╚═══════════════════════════════════╝${RESET}"
echo ""
dim "Run 'stegcore --help' to get started."
dim "Run 'stegcore wizard' for the guided experience."
dim "Run 'stegcore verse' for a word of encouragement."
echo ""
if ! command -v stegcore &>/dev/null; then
  warn "Restart your shell or run:"
  dim "  export PATH=\"${BIN_DIR}:\$PATH\""
fi
