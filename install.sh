#!/usr/bin/env bash
set -Eeuo pipefail

REPOSITORY="BehiSecc/HuntProxy"

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

usage() {
  cat <<'EOF'
Download and install a verified HuntProxy binary from GitHub Releases.

Usage: install.sh [--version VERSION] [--install-dir DIR]

Options:
  --version VERSION   Install a release such as 0.2.0 or v0.2.0 (default: latest)
  --install-dir DIR   Install the executable here (default: ~/.local/bin)
  -h, --help          Show this help

Environment equivalents:
  HUNTPROXY_VERSION, HUNTPROXY_INSTALL_DIR

Private repositories require an authenticated GitHub CLI (`gh`). Public
repositories use curl directly. This script only downloads, verifies, and
installs the HuntProxy executable; it does not install dependencies or modify
HuntProxy's data directory.
EOF
}

[[ -n "${HOME:-}" ]] || die 'HOME is not set'

INSTALL_DIR="${HUNTPROXY_INSTALL_DIR:-$HOME/.local/bin}"
REQUESTED_VERSION="${HUNTPROXY_VERSION:-latest}"
ORIGINAL_PATH="${PATH:-}"

while (($#)); do
  case "$1" in
    --version)
      (($# >= 2)) || die '--version requires a value'
      REQUESTED_VERSION=$2
      shift 2
      ;;
    --install-dir)
      (($# >= 2)) || die '--install-dir requires a value'
      INSTALL_DIR=$2
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *) die "unknown option: $1" ;;
  esac
done

[[ -n "$INSTALL_DIR" ]] || die 'install directory cannot be empty'

case "$REQUESTED_VERSION" in
  latest) ;;
  v[0-9]*.[0-9]*.[0-9]*) ;;
  [0-9]*.[0-9]*.[0-9]*) REQUESTED_VERSION="v$REQUESTED_VERSION" ;;
  *) die 'version must be "latest" or a stable semantic version such as v0.2.0' ;;
esac
if [[ "$REQUESTED_VERSION" != latest ]] \
  && [[ ! "$REQUESTED_VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  die 'version must be a stable semantic version such as v0.2.0'
fi

for command_name in tar awk sed tr cp mv chmod mkdir mktemp head uname rm; do
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

have_authenticated_gh() {
  command -v gh >/dev/null 2>&1 && gh auth status -h github.com >/dev/null 2>&1
}

if ! have_authenticated_gh; then
  command -v curl >/dev/null 2>&1 \
    || die 'curl is required for public GitHub Release downloads'
fi

TEMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/huntproxy-install.XXXXXX")"
NEW_BIN=''
cleanup() {
  local status=$?
  set +e
  [[ -z "$NEW_BIN" || ! -e "$NEW_BIN" ]] || rm -f -- "$NEW_BIN"
  rm -rf -- "$TEMP_DIR"
  exit "$status"
}
trap cleanup EXIT

os_name="$(uname -s)"
arch_name="$(uname -m)"
case "$os_name/$arch_name" in
  Linux/x86_64|Linux/amd64) ASSET_NAME='huntproxy-linux-x86_64.tar.gz' ;;
  Linux/arm64|Linux/aarch64) ASSET_NAME='huntproxy-linux-aarch64.tar.gz' ;;
  Darwin/x86_64|Darwin/amd64) ASSET_NAME='huntproxy-mac-intel-chip.tar.gz' ;;
  Darwin/arm64|Darwin/aarch64) ASSET_NAME='huntproxy-mac-apple-chip.tar.gz' ;;
  Linux/*|Darwin/*) die "unsupported CPU architecture: $arch_name" ;;
  *) die "unsupported operating system: $os_name" ;;
esac

curl_download() {
  curl --proto '=https' --tlsv1.2 --retry 3 --retry-all-errors -fsSL "$1" -o "$2"
}

DOWNLOAD_DIR="$TEMP_DIR/release"
mkdir -p "$DOWNLOAD_DIR"

if have_authenticated_gh; then
  if [[ "$REQUESTED_VERSION" == latest ]]; then
    RELEASE_TAG="$(gh release view --repo "$REPOSITORY" --json tagName --jq .tagName)" \
      || die "no published HuntProxy release was found in $REPOSITORY"
  else
    RELEASE_TAG=$REQUESTED_VERSION
  fi
  info "Downloading HuntProxy $RELEASE_TAG from GitHub Releases"
  gh release download "$RELEASE_TAG" --repo "$REPOSITORY" \
    --pattern "$ASSET_NAME" --pattern SHA256SUMS --dir "$DOWNLOAD_DIR" --clobber \
    || die "could not download $RELEASE_TAG from $REPOSITORY"
else
  if [[ "$REQUESTED_VERSION" == latest ]]; then
    RELEASE_JSON="$TEMP_DIR/latest-release.json"
    curl_download "https://api.github.com/repos/$REPOSITORY/releases/latest" "$RELEASE_JSON" \
      || die "no public HuntProxy release was found; private repositories require authenticated gh"
    RELEASE_TAG="$(sed -n 's/^[[:space:]]*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/p' "$RELEASE_JSON" | head -n 1)"
    [[ -n "$RELEASE_TAG" ]] || die 'the latest GitHub release response was invalid'
  else
    RELEASE_TAG=$REQUESTED_VERSION
  fi
  info "Downloading HuntProxy $RELEASE_TAG from GitHub Releases"
  RELEASE_URL="https://github.com/$REPOSITORY/releases/download/$RELEASE_TAG"
  curl_download "$RELEASE_URL/$ASSET_NAME" "$DOWNLOAD_DIR/$ASSET_NAME" \
    || die "could not download $ASSET_NAME; private repositories require authenticated gh"
  curl_download "$RELEASE_URL/SHA256SUMS" "$DOWNLOAD_DIR/SHA256SUMS" \
    || die 'could not download the release checksums'
fi

[[ "$RELEASE_TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] \
  || die "release has an unsupported version tag: $RELEASE_TAG"
[[ -f "$DOWNLOAD_DIR/$ASSET_NAME" && -f "$DOWNLOAD_DIR/SHA256SUMS" ]] \
  || die 'the release is missing its archive or SHA256SUMS'

checksum_matches="$(awk -v name="$ASSET_NAME" '
  ($2 == name || $2 == "*" name) { print $1 }
' "$DOWNLOAD_DIR/SHA256SUMS")"
[[ "$checksum_matches" =~ ^[0-9A-Fa-f]{64}$ ]] \
  || die "SHA256SUMS must contain exactly one valid checksum for $ASSET_NAME"
actual_checksum="$(sha256_file "$DOWNLOAD_DIR/$ASSET_NAME")"
actual_checksum="$(printf '%s' "$actual_checksum" | tr '[:upper:]' '[:lower:]')"
checksum_matches="$(printf '%s' "$checksum_matches" | tr '[:upper:]' '[:lower:]')"
[[ "$actual_checksum" == "$checksum_matches" ]] \
  || die "checksum verification failed for $ASSET_NAME"
ok 'Release checksum verified'

archive_members="$(tar -tzf "$DOWNLOAD_DIR/$ASSET_NAME")" \
  || die 'the release archive could not be read'
while IFS= read -r member; do
  case "$member" in
    HuntProxy|LICENSE) ;;
    *) die "the release archive contains an unexpected member: $member" ;;
  esac
done <<<"$archive_members"
member_count="$(awk '$0 == "HuntProxy" { count++ } END { print count + 0 }' <<<"$archive_members")"
[[ "$member_count" == 1 ]] || die 'the release archive must contain exactly one HuntProxy executable'
member_details="$(tar -tvzf "$DOWNLOAD_DIR/$ASSET_NAME" HuntProxy)" \
  || die 'the HuntProxy archive member could not be inspected'
[[ "${member_details:0:1}" == '-' ]] || die 'the HuntProxy archive member must be a regular file'
STAGED_BIN="$TEMP_DIR/HuntProxy"
tar -xOzf "$DOWNLOAD_DIR/$ASSET_NAME" HuntProxy >"$STAGED_BIN" \
  || die 'the HuntProxy executable could not be extracted'
chmod 755 "$STAGED_BIN"
binary_version="$("$STAGED_BIN" --version 2>/dev/null | awk '{print $NF}')" \
  || die 'the downloaded HuntProxy executable could not run on this machine'
[[ "$binary_version" == "${RELEASE_TAG#v}" ]] \
  || die "release $RELEASE_TAG contains HuntProxy $binary_version"

mkdir -p "$INSTALL_DIR"
NEW_BIN="$(mktemp "$INSTALL_DIR/.HuntProxy.new.XXXXXX")"
cp -- "$STAGED_BIN" "$NEW_BIN"
chmod 755 "$NEW_BIN"
"$NEW_BIN" --version >/dev/null || die 'the installed executable failed its final check'
mv -f -- "$NEW_BIN" "$INSTALL_DIR/HuntProxy"
NEW_BIN=''

ok "HuntProxy $binary_version installed"
printf '\nBinary: %s\nRun:    %s --help\n' "$INSTALL_DIR/HuntProxy" "$INSTALL_DIR/HuntProxy"
if [[ ":$ORIGINAL_PATH:" != *":$INSTALL_DIR:"* ]]; then
  warn "Add this to your shell profile: export PATH=\"$INSTALL_DIR:\$PATH\""
fi
