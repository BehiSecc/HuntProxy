#!/usr/bin/env bash
set -Eeuo pipefail

REPOSITORY="BehiSecc/HuntProxy"
# The oldest release this installer can install (the first with `install-release`).
MINIMUM_VERSION="0.2.0"
# HuntProxy provisions its own runtime; these pins only locate it when Chromium
# needs system libraries. Keep them in step with src/installation.rs.
NODE_VERSION="22.23.2"
PLAYWRIGHT_VERSION="1.63.0"

if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
  GREEN='\033[0;32m'; BLUE='\033[0;34m'; YELLOW='\033[0;33m'; RED='\033[0;31m'; RESET='\033[0m'
else
  GREEN=''; BLUE=''; YELLOW=''; RED=''; RESET=''
fi

info() { printf '%b==>%b %s\n' "$BLUE" "$RESET" "$*"; }
ok() { printf '%b✓%b %s\n' "$GREEN" "$RESET" "$*"; }
warn() { printf '%b!%b %s\n' "$YELLOW" "$RESET" "$*"; }
die() { printf '%berror:%b %s\n' "$RED" "$RESET" "$*" >&2; exit 1; }

usage() {
  cat <<'EOF'
Install HuntProxy and its local runtime from verified upstream downloads.

Usage: install.sh [--version VERSION] [--install-dir DIR] [--data-dir DIR]

Options:
  --version VERSION   Install a release such as 0.2.0 or v0.2.0 (default: latest;
                      0.2.0 is the oldest release this installer can install)
  --install-dir DIR   Install the executable here (default: ~/.local/bin)
  --data-dir DIR      Store HuntProxy data here (default: ~/.huntproxy)
  -h, --help          Show this help

Environment equivalents:
  HUNTPROXY_VERSION, HUNTPROXY_INSTALL_DIR, HUNTPROXY_DATA_DIR

The installer downloads the HuntProxy release binary and verifies its
checksum. The release then provisions its private Node.js runtime, its
version-matched browser SDK and Chromium, and the first-party plugins.
Unmodified official plugins are upgraded; modified packages and custom plugin
folders are preserved. Existing project data, CA files, and MCP client
configuration are preserved.
EOF
}

[[ -n "${HOME:-}" ]] || die 'HOME is not set'

INSTALL_DIR="${HUNTPROXY_INSTALL_DIR:-$HOME/.local/bin}"
DATA_DIR="${HUNTPROXY_DATA_DIR:-$HOME/.huntproxy}"
REQUESTED_VERSION="${HUNTPROXY_VERSION:-latest}"
ORIGINAL_PATH="${PATH:-}"

while (($#)); do
  case "$1" in
    --version)
      (($# >= 2)) || die '--version requires a value'
      REQUESTED_VERSION=$2; shift 2
      ;;
    --install-dir)
      (($# >= 2)) || die '--install-dir requires a value'
      INSTALL_DIR=$2; shift 2
      ;;
    --data-dir)
      (($# >= 2)) || die '--data-dir requires a value'
      DATA_DIR=$2; shift 2
      ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done

[[ -n "$INSTALL_DIR" ]] || die 'install directory cannot be empty'
[[ -n "$DATA_DIR" ]] || die 'data directory cannot be empty'
case "$DATA_DIR" in /|.) die 'data directory is too broad' ;; esac
[[ "$DATA_DIR" != "$HOME" ]] || die 'data directory cannot be HOME itself'

case "$REQUESTED_VERSION" in
  latest) ;;
  v[0-9]*.[0-9]*.[0-9]*) ;;
  [0-9]*.[0-9]*.[0-9]*) REQUESTED_VERSION="v$REQUESTED_VERSION" ;;
  *) die 'version must be "latest" or a stable semantic version such as v0.2.0' ;;
esac
if [[ "$REQUESTED_VERSION" != latest ]] && [[ ! "$REQUESTED_VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  die 'version must be a stable semantic version such as v0.2.0'
fi

for command_name in awk cat chmod curl grep id mkdir mktemp rm sed tar tr uname; do
  command -v "$command_name" >/dev/null 2>&1 \
    || die "$command_name is required; install it and rerun this script"
done

if command -v sha256sum >/dev/null 2>&1; then
  sha256_file() { sha256sum "$1" | awk '{print $1}'; }
elif command -v shasum >/dev/null 2>&1; then
  sha256_file() { shasum -a 256 "$1" | awk '{print $1}'; }
else
  die 'a SHA-256 tool (sha256sum or shasum) is required'
fi

TEMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/huntproxy-install.XXXXXX")"

# Everything this script changes outside TEMP_DIR is done by `HuntProxy
# install-release`, which rolls itself back and reports the result when it fails.
cleanup() {
  local status=$?
  set +e
  rm -rf -- "$TEMP_DIR"
  exit "$status"
}
trap cleanup EXIT

curl_download() {
  curl --proto '=https' --tlsv1.2 --retry 3 --retry-all-errors -fsSL "$1" -o "$2"
}

version_at_least() {
  local actual=${1#v} minimum=${2#v}
  awk -v actual="$actual" -v minimum="$minimum" 'BEGIN {
    split(actual, a, "."); split(minimum, m, ".");
    for (i = 1; i <= 3; i++) {
      if ((a[i] + 0) > (m[i] + 0)) exit 0;
      if ((a[i] + 0) < (m[i] + 0)) exit 1;
    }
    exit 0;
  }'
}

browser_node_supported() {
  local version
  [[ -x "$1" ]] || return 1
  version="$("$1" --version 2>/dev/null)" || return 1
  [[ "$version" =~ ^v([0-9]+)\. ]] || return 1
  ((10#${BASH_REMATCH[1]} >= 20))
}

install_chromium_runtime_libraries() {
  local playwright_path=$1 node_path=$2
  [[ -x "$node_path" && -f "$playwright_path/cli.js" ]] || return 1
  command -v apt-get >/dev/null 2>&1 || return 1
  if [[ "$(id -u)" == 0 ]]; then
    DEBIAN_FRONTEND=noninteractive "$node_path" "$playwright_path/cli.js" install-deps chromium
  else
    sudo env DEBIAN_FRONTEND=noninteractive "$node_path" "$playwright_path/cli.js" install-deps chromium
  fi
}

os_name="$(uname -s)"; arch_name="$(uname -m)"
case "$os_name/$arch_name" in
  Linux/x86_64|Linux/amd64) ASSET_NAME='huntproxy-linux-x86_64.tar.gz' ;;
  Linux/arm64|Linux/aarch64) ASSET_NAME='huntproxy-linux-aarch64.tar.gz' ;;
  Darwin/x86_64|Darwin/amd64) ASSET_NAME='huntproxy-mac-intel-chip.tar.gz' ;;
  Darwin/arm64|Darwin/aarch64) ASSET_NAME='huntproxy-mac-apple-chip.tar.gz' ;;
  Linux/*|Darwin/*) die "unsupported CPU architecture: $arch_name" ;;
  *) die "unsupported operating system: $os_name" ;;
esac
# Resolve and verify the HuntProxy release before touching its destination.
DOWNLOAD_DIR="$TEMP_DIR/release"; mkdir -p "$DOWNLOAD_DIR"
if [[ "$REQUESTED_VERSION" == latest ]]; then
  RELEASE_JSON="$TEMP_DIR/latest-release.json"
  curl_download "https://api.github.com/repos/$REPOSITORY/releases/latest" "$RELEASE_JSON" \
    || die "no public HuntProxy release was found in $REPOSITORY"
  RELEASE_TAG="$(sed -n 's/^[[:space:]]*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/p' "$RELEASE_JSON" | awk 'NR == 1 { first = $0 } END { print first }')"
  [[ -n "$RELEASE_TAG" ]] || die 'the latest GitHub release response was invalid'
else
  RELEASE_TAG=$REQUESTED_VERSION
fi
[[ "$RELEASE_TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] \
  || die "release has an unsupported version tag: $RELEASE_TAG"
version_at_least "$RELEASE_TAG" "$MINIMUM_VERSION" \
  || die "HuntProxy $RELEASE_TAG is no longer supported; install v$MINIMUM_VERSION or newer"

info "Downloading HuntProxy $RELEASE_TAG"
RELEASE_URL="https://github.com/$REPOSITORY/releases/download/$RELEASE_TAG"
curl_download "$RELEASE_URL/$ASSET_NAME" "$DOWNLOAD_DIR/$ASSET_NAME" \
  || die "could not download $ASSET_NAME from $REPOSITORY"
curl_download "$RELEASE_URL/SHA256SUMS" "$DOWNLOAD_DIR/SHA256SUMS" \
  || die 'could not download the release checksums'

checksum_matches="$(awk -v name="$ASSET_NAME" '($2 == name || $2 == "*" name) { print $1 }' "$DOWNLOAD_DIR/SHA256SUMS")"
[[ "$checksum_matches" =~ ^[0-9A-Fa-f]{64}$ ]] \
  || die "SHA256SUMS must contain exactly one valid checksum for $ASSET_NAME"
actual_checksum="$(sha256_file "$DOWNLOAD_DIR/$ASSET_NAME" | tr '[:upper:]' '[:lower:]')"
checksum_matches="$(printf '%s' "$checksum_matches" | tr '[:upper:]' '[:lower:]')"
[[ "$actual_checksum" == "$checksum_matches" ]] || die "checksum verification failed for $ASSET_NAME"
ok 'HuntProxy checksum verified'

archive_members="$(tar -tzf "$DOWNLOAD_DIR/$ASSET_NAME")" || die 'the release archive could not be read'
while IFS= read -r member; do
  case "$member" in HuntProxy|LICENSE) ;; *) die "unexpected release archive member: $member" ;; esac
done <<<"$archive_members"
[[ "$(awk '$0 == "HuntProxy" { count++ } END { print count + 0 }' <<<"$archive_members")" == 1 ]] \
  || die 'the release archive must contain exactly one HuntProxy executable'
member_details="$(tar -tvzf "$DOWNLOAD_DIR/$ASSET_NAME" HuntProxy)" || die 'cannot inspect HuntProxy archive member'
[[ "${member_details:0:1}" == '-' ]] || die 'the HuntProxy archive member must be a regular file'
STAGED_BIN="$TEMP_DIR/HuntProxy"
tar -xOzf "$DOWNLOAD_DIR/$ASSET_NAME" HuntProxy >"$STAGED_BIN" || die 'cannot extract HuntProxy'
chmod 755 "$STAGED_BIN"
binary_version="$("$STAGED_BIN" --version 2>/dev/null | awk '{print $NF}')" || die 'the downloaded binary cannot run'
[[ "$binary_version" == "${RELEASE_TAG#v}" ]] || die "release $RELEASE_TAG contains HuntProxy $binary_version"

# Persist absolute paths in generated configuration and MCP registrations. A
# relative installer path would otherwise be resolved against each client's
# working directory rather than the directory where this script was invoked.
mkdir -p "$DATA_DIR" "$INSTALL_DIR"
DATA_DIR="$(cd "$DATA_DIR" && pwd -P)"
INSTALL_DIR="$(cd "$INSTALL_DIR" && pwd -P)"
HOME_CANON="$(cd "$HOME" && pwd -P)"
[[ "$DATA_DIR" != / && "$DATA_DIR" != "$HOME_CANON" ]] \
  || die 'data directory is too broad'
chmod 700 "$DATA_DIR"

info 'Coordinating release preparation and activation (upgrading a large database can take a while; do not interrupt)'
if ! "$STAGED_BIN" install-release \
  --executable "$INSTALL_DIR/HuntProxy" \
  --data-dir "$DATA_DIR" >"$TEMP_DIR/install-release.log" 2>&1; then
  linux_id=''
  if [[ "$os_name" == Linux && -r /etc/os-release ]]; then
    linux_id="$(sed -n 's/^ID=//p' /etc/os-release | tr -d '"' | awk 'NR == 1 { print }')"
  fi
  stable_playwright="$DATA_DIR/runtime/playwright-core-$PLAYWRIGHT_VERSION"
  runtime_node=''
  if [[ -f "$DATA_DIR/config.toml" ]]; then
    runtime_node="$(sed -n 's/^node_path = "\(.*\)"$/\1/p' "$DATA_DIR/config.toml" | awk 'NR == 1 { print }')"
  fi
  if ! browser_node_supported "$runtime_node"; then
    runtime_node="$DATA_DIR/runtime/node-$NODE_VERSION/bin/node"
  fi
  if ! browser_node_supported "$runtime_node"; then
    runtime_node="$(command -v node 2>/dev/null || true)"
  fi
  can_request_packages=0
  if [[ "$(id -u)" == 0 ]] || { command -v sudo >/dev/null 2>&1 && [[ -t 0 || -t 1 ]]; }; then
    can_request_packages=1
  fi
  if [[ "$linux_id" =~ ^(ubuntu|debian)$ ]] \
    && [[ "$can_request_packages" -eq 1 ]] \
    && browser_node_supported "$runtime_node" \
    && [[ -f "$stable_playwright/cli.js" ]] \
    && grep -Eqi 'chromium|browser validation|browser worker' "$TEMP_DIR/install-release.log"; then
    info 'Chromium needs Debian/Ubuntu runtime libraries; requesting system package access'
    if install_chromium_runtime_libraries "$stable_playwright" "$runtime_node" >"$TEMP_DIR/browser-deps.log" 2>&1 \
      && "$STAGED_BIN" install-release \
        --executable "$INSTALL_DIR/HuntProxy" \
        --data-dir "$DATA_DIR" >>"$TEMP_DIR/install-release.log" 2>&1; then
      :
    else
      sed -n '1,160p' "$TEMP_DIR/browser-deps.log" >&2
      sed -n '1,160p' "$TEMP_DIR/install-release.log" >&2
      die 'coordinated release installation failed'
    fi
  else
    sed -n '1,160p' "$TEMP_DIR/install-release.log" >&2
    die 'coordinated release installation failed'
  fi
fi
[[ -x "$INSTALL_DIR/HuntProxy" ]] || die 'coordinated installation did not create the executable'
installed_version="$("$INSTALL_DIR/HuntProxy" --version 2>/dev/null | awk '{print $NF}')" \
  || die 'the installed executable failed its final check'
[[ "$installed_version" == "$binary_version" ]] \
  || die "coordinated installation activated HuntProxy $installed_version instead of $binary_version"
ok 'Release runtime, data, plugins, and executable installed'

configure_mcp_clients() {
  local names=() commands=() choice selected index client command
  for client in claude codex opencode; do
    command="$(command -v "$client" 2>/dev/null || true)"
    [[ -n "$command" && -x "$command" ]] || continue
    "$command" --version >/dev/null 2>&1 || continue
    "$command" mcp add --help >/dev/null 2>&1 || continue
    case "$client" in claude) names+=("Claude Code") ;; codex) names+=("Codex") ;; opencode) names+=("OpenCode") ;; esac
    commands+=("$command")
  done
  ((${#names[@]})) || return 0
  if ! { printf '' >/dev/tty; } 2>/dev/null; then
    warn 'AI clients were found, but no interactive terminal is available; MCP setup was skipped.'
    return 0
  fi
  printf '\nInstall HuntProxy MCP for:\n' >/dev/tty
  index=0
  while ((index < ${#names[@]})); do
    printf '  %d) %s\n' "$((index + 1))" "${names[$index]}" >/dev/tty
    index=$((index + 1))
  done
  printf 'Select numbers separated by commas (Enter skips): ' >/dev/tty
  IFS= read -r choice </dev/tty || return 0
  choice="$(printf '%s' "$choice" | tr ',' ' ')"
  [[ -n "${choice//[[:space:]]/}" ]] || return 0
  for selected in $choice; do
    [[ "$selected" =~ ^[0-9]+$ ]] || { warn "Ignoring invalid MCP selection: $selected"; continue; }
    index=$((selected - 1))
    ((index >= 0 && index < ${#names[@]})) || { warn "Ignoring invalid MCP selection: $selected"; continue; }
    client="${names[$index]}"; command="${commands[$index]}"
    case "$client" in
      'Claude Code')
        if (cd "$TEMP_DIR" && "$command" mcp get huntproxy >/dev/null 2>&1); then warn 'Claude Code already has an MCP named huntproxy; left unchanged'; continue; fi
        if (cd "$TEMP_DIR" && "$command" mcp add --transport stdio --scope user huntproxy -- "$INSTALL_DIR/HuntProxy" --data-dir "$DATA_DIR" mcp >/dev/null); then
          if (cd "$TEMP_DIR" && "$command" mcp get huntproxy >/dev/null 2>&1); then
            ok 'HuntProxy MCP installed for Claude Code'
          else
            (cd "$TEMP_DIR" && "$command" mcp remove --scope user huntproxy >/dev/null 2>&1) || true
            warn 'Claude Code MCP verification failed and was rolled back; HuntProxy itself is installed'
          fi
        else
          warn 'Claude Code MCP setup failed; HuntProxy itself is installed'
        fi
        ;;
      Codex)
        if (cd "$TEMP_DIR" && "$command" mcp get huntproxy --json >/dev/null 2>&1); then warn 'Codex already has an MCP named huntproxy; left unchanged'; continue; fi
        if (cd "$TEMP_DIR" && "$command" mcp add huntproxy -- "$INSTALL_DIR/HuntProxy" --data-dir "$DATA_DIR" mcp >/dev/null); then
          if (cd "$TEMP_DIR" && "$command" mcp get huntproxy --json >/dev/null 2>&1); then
            ok 'HuntProxy MCP installed for Codex'
          else
            (cd "$TEMP_DIR" && "$command" mcp remove huntproxy >/dev/null 2>&1) || true
            warn 'Codex MCP verification failed and was rolled back; HuntProxy itself is installed'
          fi
        else
          warn 'Codex MCP setup failed; HuntProxy itself is installed'
        fi
        ;;
      OpenCode)
        open_config="$TEMP_DIR/opencode-config.json"
        (cd "$TEMP_DIR" && "$command" debug config --pure >"$open_config" 2>/dev/null) || : >"$open_config"
        if grep -q '"huntproxy"' "$open_config"; then warn 'OpenCode already has an MCP named huntproxy; left unchanged'; continue; fi
        if (cd "$TEMP_DIR" && "$command" mcp add huntproxy -- "$INSTALL_DIR/HuntProxy" --data-dir "$DATA_DIR" mcp >/dev/null); then
          if (cd "$TEMP_DIR" && "$command" debug config --pure >"$open_config" 2>/dev/null) \
            && grep -q '"huntproxy"' "$open_config"; then
            ok 'HuntProxy MCP installed for OpenCode'
          else
            (cd "$TEMP_DIR" && "$command" mcp remove huntproxy >/dev/null 2>&1) || true
            warn 'OpenCode MCP verification failed and was rolled back; HuntProxy itself is installed'
          fi
        else
          warn 'OpenCode MCP setup failed; HuntProxy itself is installed'
        fi
        ;;
    esac
  done
}

ok "HuntProxy $binary_version is ready"
printf '\nBinary: %s\nData:   %s\nRun:    %s --data-dir %q serve\n' "$INSTALL_DIR/HuntProxy" "$DATA_DIR" "$INSTALL_DIR/HuntProxy" "$DATA_DIR"
if [[ ":$ORIGINAL_PATH:" != *":$INSTALL_DIR:"* ]]; then
  warn "Add this to your shell profile: export PATH=\"$INSTALL_DIR:\$PATH\""
fi
configure_mcp_clients
