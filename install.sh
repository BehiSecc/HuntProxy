#!/usr/bin/env bash
set -Eeuo pipefail

if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
  GREEN='\033[0;32m'
  BLUE='\033[0;34m'
  YELLOW='\033[0;33m'
  RED='\033[0;31m'
  RESET='\033[0m'
else
  GREEN=''
  BLUE=''
  YELLOW=''
  RED=''
  RESET=''
fi

info() { printf '%b==>%b %s\n' "$BLUE" "$RESET" "$*"; }
ok() { printf '%b✓%b %s\n' "$GREEN" "$RESET" "$*"; }
warn() { printf '%b!%b %s\n' "$YELLOW" "$RESET" "$*"; }
die() { printf '%berror:%b %s\n' "$RED" "$RESET" "$*" >&2; exit 1; }

[[ -n "${HOME:-}" ]] || die 'HOME is not set'

INSTALL_DIR="${HUNTPROXY_INSTALL_DIR:-$HOME/.local/bin}"
DATA_DIR="${HUNTPROXY_DATA_DIR:-$HOME/.huntproxy}"
ORIGINAL_PATH="${PATH:-}"
TEMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/huntproxy-install.XXXXXX")"
trap 'rm -rf "$TEMP_DIR"' EXIT

mkdir -p "$INSTALL_DIR" "$DATA_DIR"
chmod 700 "$DATA_DIR"

os_name="$(uname -s)"
arch_name="$(uname -m)"
case "$os_name" in
  Linux) platform=linux ;;
  Darwin) platform=macos ;;
  *) die "unsupported operating system: $os_name" ;;
esac
case "$arch_name" in
  x86_64|amd64) architecture=x86_64 ;;
  arm64|aarch64) architecture=aarch64 ;;
  *) die "unsupported CPU architecture: $arch_name" ;;
esac

as_root() {
  if [[ "$(id -u)" -eq 0 ]]; then
    "$@"
  elif command -v sudo >/dev/null 2>&1; then
    sudo "$@"
  else
    die "root access is required to install OS packages: $*"
  fi
}

install_curl() {
  command -v curl >/dev/null 2>&1 && return
  info 'Installing curl'
  if command -v apt-get >/dev/null 2>&1; then
    as_root apt-get update
    as_root apt-get install -y curl ca-certificates
  elif command -v dnf >/dev/null 2>&1; then
    as_root dnf install -y curl ca-certificates
  elif command -v pacman >/dev/null 2>&1; then
    as_root pacman -Syu --needed --noconfirm curl ca-certificates
  elif command -v zypper >/dev/null 2>&1; then
    as_root zypper --non-interactive install curl ca-certificates
  else
    die 'curl is required; install it and rerun this script'
  fi
}

install_node() {
  if command -v node >/dev/null 2>&1 && command -v npm >/dev/null 2>&1 \
    && [[ "$(node -p 'Number(process.versions.node.split(".")[0]) >= 18' 2>/dev/null)" == true ]]; then
    return
  fi
  info 'Installing Node.js and npm'
  if [[ "$platform" == macos ]] && command -v brew >/dev/null 2>&1; then
    brew install node
  elif command -v apt-get >/dev/null 2>&1; then
    as_root apt-get update
    as_root apt-get install -y nodejs npm
  elif command -v dnf >/dev/null 2>&1; then
    as_root dnf install -y nodejs npm
  elif command -v pacman >/dev/null 2>&1; then
    as_root pacman -Syu --needed --noconfirm nodejs npm
  elif command -v zypper >/dev/null 2>&1; then
    as_root zypper --non-interactive install nodejs npm
  else
    die 'Node.js and npm are required; install them and rerun this script'
  fi
  [[ "$(node -p 'Number(process.versions.node.split(".")[0]) >= 18' 2>/dev/null)" == true ]] \
    || die 'HuntProxy requires Node.js 18 or newer; upgrade Node.js and rerun this script'
}

install_build_tools() {
  if command -v cc >/dev/null 2>&1 && command -v c++ >/dev/null 2>&1 \
    && command -v make >/dev/null 2>&1 && command -v pkg-config >/dev/null 2>&1 \
    && command -v cmake >/dev/null 2>&1 && command -v clang >/dev/null 2>&1; then
    return
  fi
  info 'Ensuring native build tools are installed'
  if [[ "$platform" == macos ]]; then
    xcode-select -p >/dev/null 2>&1 \
      || die 'Install Xcode Command Line Tools with `xcode-select --install`, then rerun'
  elif command -v apt-get >/dev/null 2>&1; then
    as_root apt-get update
    as_root apt-get install -y build-essential pkg-config cmake clang
  elif command -v dnf >/dev/null 2>&1; then
    as_root dnf install -y gcc gcc-c++ make pkgconf-pkg-config cmake clang
  elif command -v pacman >/dev/null 2>&1; then
    as_root pacman -Syu --needed --noconfirm base-devel pkgconf cmake clang
  elif command -v zypper >/dev/null 2>&1; then
    as_root zypper --non-interactive install -t pattern devel_basis
    as_root zypper --non-interactive install pkg-config cmake clang
  else
    die 'Install a C/C++ compiler, make, pkg-config, CMake, and Clang, then rerun'
  fi
}

install_rust() {
  if command -v cargo >/dev/null 2>&1; then
    return
  fi
  command -v curl >/dev/null 2>&1 || die 'curl is required to install Rust'
  info 'Installing the Rust toolchain'
  curl --proto '=https' --tlsv1.2 -fsSL https://sh.rustup.rs \
    | sh -s -- -y --profile minimal
  export PATH="$HOME/.cargo/bin:$PATH"
}

install_huntproxy() {
  local source_dir=$PWD
  local destination="$INSTALL_DIR/HuntProxy"

  if [[ -n "${HUNTPROXY_BINARY_URL:-}" ]]; then
    command -v curl >/dev/null 2>&1 || die 'curl is required to download HuntProxy'
    info 'Downloading HuntProxy'
    curl --proto '=https' --tlsv1.2 -fL "$HUNTPROXY_BINARY_URL" -o "$TEMP_DIR/HuntProxy"
    if [[ -n "${HUNTPROXY_BINARY_SHA256:-}" ]]; then
      if command -v sha256sum >/dev/null 2>&1; then
        printf '%s  %s\n' "$HUNTPROXY_BINARY_SHA256" "$TEMP_DIR/HuntProxy" | sha256sum -c -
      elif command -v shasum >/dev/null 2>&1; then
        printf '%s  %s\n' "$HUNTPROXY_BINARY_SHA256" "$TEMP_DIR/HuntProxy" | shasum -a 256 -c -
      else
        die 'cannot verify HUNTPROXY_BINARY_SHA256: no SHA-256 tool found'
      fi
    fi
    chmod 755 "$TEMP_DIR/HuntProxy"
    "$TEMP_DIR/HuntProxy" --version >/dev/null \
      || die 'downloaded HuntProxy binary failed verification'
    install -m 0755 "$TEMP_DIR/HuntProxy" "$destination"
  elif [[ -f "$source_dir/Cargo.toml" && -f "$source_dir/src/main.rs" ]] \
    && grep -q 'name = "HuntProxy"' "$source_dir/Cargo.toml"; then
    install_build_tools
    install_rust
    info 'Building HuntProxy from this source checkout'
    cargo build --release --manifest-path "$source_dir/Cargo.toml" --bin HuntProxy
    install -m 0755 "$source_dir/target/release/HuntProxy" "$destination"
  elif command -v HuntProxy >/dev/null 2>&1; then
    destination="$(command -v HuntProxy)"
    warn "Using the existing HuntProxy binary at $destination"
  else
    die 'HuntProxy has no published download URL yet. Run this script from its source checkout or set HUNTPROXY_BINARY_URL.'
  fi

  HUNTPROXY_BIN="$destination"
  ok "HuntProxy: $HUNTPROXY_BIN"
}

install_curl
install_huntproxy
install_node

export PATH="$INSTALL_DIR:$PATH"
export HUNTPROXY_DATA_DIR="$DATA_DIR"

browser_args=(browser install)
if [[ "$platform" == linux ]] && command -v apt-get >/dev/null 2>&1; then
  browser_args+=(--with-deps)
fi
info 'Installing Playwright and Chromium'
"$HUNTPROXY_BIN" "${browser_args[@]}"

info "Initializing $DATA_DIR"
"$HUNTPROXY_BIN" init >/dev/null
"$HUNTPROXY_BIN" doctor

ok 'HuntProxy is ready'
printf '\nNext: connect HuntProxy to your AI agent through MCP.\n'
printf 'MCP:  {"command":"%s","args":["mcp"]}\n' "$HUNTPROXY_BIN"
printf 'Optional UI: run %s serve, then open http://127.0.0.1:17890\n' "$HUNTPROXY_BIN"
if [[ ":$ORIGINAL_PATH:" != *":$INSTALL_DIR:"* ]]; then
  warn "Add this to your shell profile: export PATH=\"$INSTALL_DIR:\$PATH\""
fi
