#!/usr/bin/env bash
set -Eeuo pipefail

REPOSITORY="BehiSecc/HuntProxy"
PLUGIN_REPOSITORY="BehiSecc/HuntProxy-Plugins"
NODE_VERSION="v22.23.2"

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
  --version VERSION   Install a release such as 0.2.0 or v0.2.0 (default: latest)
  --install-dir DIR   Install the executable here (default: ~/.local/bin)
  --data-dir DIR      Store HuntProxy data here (default: ~/.huntproxy)
  -h, --help          Show this help

Environment equivalents:
  HUNTPROXY_VERSION, HUNTPROXY_INSTALL_DIR, HUNTPROXY_DATA_DIR

The installer downloads the HuntProxy release binary, a private Node.js runtime,
Playwright Chromium, and the current first-party plugin snapshot. It never uses
Git or builds HuntProxy from source. Existing data, CA files, and plugin folders
are preserved.
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

for command_name in awk cat chmod cp curl grep head id mkdir mktemp mv rm sed sleep sort tar tr uname; do
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
NEW_BIN=''; LOCK_DIR=''; LOCK_HELD=0; VERIFY_PID=''; NODE_BACKUP=''; WORKER_BACKUP=''; PLUGIN_DIR=''
NODE_INCOMING=''; PLUGIN_INCOMING=''; PLUGIN_SOURCE_TEMP=''
NODE_INSTALLED=0; WORKER_TOUCHED=0; STATE_BACKED_UP=0; INSTALL_COMPLETE=0
NEW_PLUGIN_LIST="$TEMP_DIR/new-plugins"
: >"$NEW_PLUGIN_LIST"
STATE_BACKUP="$TEMP_DIR/state-backup"
STATE_FILES=(config.toml huntproxy.db huntproxy.db-wal huntproxy.db-shm bb.db bb.db-wal bb.db-shm ca/ca.crt ca/ca.key placeholder.key .mcp-stop-guard)

remove_managed_tree() {
  local target=$1 parent=$2
  [[ -n "$target" && "$target" == "$parent/"* && "$target" != "$parent" ]] || return 1
  rm -rf -- "$target"
}

cleanup() {
  local status=$?
  set +e
  if [[ -n "$VERIFY_PID" ]]; then
    kill "$VERIFY_PID" >/dev/null 2>&1
    wait "$VERIFY_PID" >/dev/null 2>&1
  fi
  if [[ "$status" -ne 0 && "$INSTALL_COMPLETE" -eq 0 ]]; then
    if [[ "$WORKER_TOUCHED" -eq 1 && -n "${WORKER_DIR:-}" ]]; then
      remove_managed_tree "$WORKER_DIR" "$DATA_DIR"
      [[ -z "$WORKER_BACKUP" || ! -d "$WORKER_BACKUP" ]] || mv -- "$WORKER_BACKUP" "$WORKER_DIR"
    fi
    if [[ "$NODE_INSTALLED" -eq 1 && -n "${MANAGED_NODE_DIR:-}" ]]; then
      remove_managed_tree "$MANAGED_NODE_DIR" "$DATA_DIR/runtime"
      [[ -z "$NODE_BACKUP" || ! -d "$NODE_BACKUP" ]] || mv -- "$NODE_BACKUP" "$MANAGED_NODE_DIR"
    fi
    while IFS= read -r plugin_path; do
      [[ -z "$plugin_path" ]] || remove_managed_tree "$plugin_path" "$PLUGIN_DIR"
    done <"$NEW_PLUGIN_LIST"
    if [[ "$STATE_BACKED_UP" -eq 1 ]]; then
      for relative in "${STATE_FILES[@]}"; do
        state_target="$DATA_DIR/$relative"
        state_source="$STATE_BACKUP/$relative"
        [[ ! -f "$state_target" && ! -L "$state_target" ]] || rm -f -- "$state_target"
        if [[ -f "$state_source" ]]; then
          mkdir -p "${state_target%/*}"
          cp -p -- "$state_source" "$state_target"
        fi
      done
    fi
    warn 'Installation failed before the HuntProxy binary was replaced.'
  fi
  [[ -z "$NEW_BIN" || ! -e "$NEW_BIN" ]] || rm -f -- "$NEW_BIN"
  [[ -z "$NODE_INCOMING" || ! -d "$NODE_INCOMING" ]] || remove_managed_tree "$NODE_INCOMING" "$DATA_DIR/runtime"
  [[ -z "$PLUGIN_INCOMING" || ! -d "$PLUGIN_INCOMING" ]] || remove_managed_tree "$PLUGIN_INCOMING" "$PLUGIN_DIR"
  [[ -z "$PLUGIN_SOURCE_TEMP" || ! -f "$PLUGIN_SOURCE_TEMP" ]] || rm -f -- "$PLUGIN_SOURCE_TEMP"
  [[ -z "$NODE_BACKUP" || ! -d "$NODE_BACKUP" ]] || remove_managed_tree "$NODE_BACKUP" "$DATA_DIR/runtime"
  [[ -z "$WORKER_BACKUP" || ! -d "$WORKER_BACKUP" ]] || remove_managed_tree "$WORKER_BACKUP" "$DATA_DIR"
  [[ "$LOCK_HELD" -eq 0 || ! -d "$LOCK_DIR" ]] || rmdir "$LOCK_DIR" >/dev/null 2>&1
  rm -rf -- "$TEMP_DIR"
  exit "$status"
}
trap cleanup EXIT

curl_download() {
  curl --proto '=https' --tlsv1.2 --retry 3 --retry-all-errors -fsSL "$1" -o "$2"
}

os_name="$(uname -s)"; arch_name="$(uname -m)"
case "$os_name/$arch_name" in
  Linux/x86_64|Linux/amd64)
    ASSET_NAME='huntproxy-linux-x86_64.tar.gz'; NODE_PLATFORM='linux-x64'
    ;;
  Linux/arm64|Linux/aarch64)
    ASSET_NAME='huntproxy-linux-aarch64.tar.gz'; NODE_PLATFORM='linux-arm64'
    ;;
  Darwin/x86_64|Darwin/amd64)
    ASSET_NAME='huntproxy-mac-intel-chip.tar.gz'; NODE_PLATFORM='darwin-x64'
    ;;
  Darwin/arm64|Darwin/aarch64)
    ASSET_NAME='huntproxy-mac-apple-chip.tar.gz'; NODE_PLATFORM='darwin-arm64'
    ;;
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

# Download an official, checksum-verified Node runtime for the browser worker.
NODE_ASSET="node-$NODE_VERSION-$NODE_PLATFORM.tar.gz"
NODE_DOWNLOAD="$TEMP_DIR/node-download"; mkdir -p "$NODE_DOWNLOAD"
info "Downloading Node.js $NODE_VERSION"
curl_download "https://nodejs.org/dist/$NODE_VERSION/$NODE_ASSET" "$NODE_DOWNLOAD/$NODE_ASSET" \
  || die "could not download $NODE_ASSET"
curl_download "https://nodejs.org/dist/$NODE_VERSION/SHASUMS256.txt" "$NODE_DOWNLOAD/SHASUMS256.txt" \
  || die 'could not download Node.js checksums'
node_checksum="$(awk -v name="$NODE_ASSET" '$2 == name { print $1 }' "$NODE_DOWNLOAD/SHASUMS256.txt")"
[[ "$node_checksum" =~ ^[0-9A-Fa-f]{64}$ ]] || die "Node.js checksums do not contain $NODE_ASSET"
[[ "$(sha256_file "$NODE_DOWNLOAD/$NODE_ASSET")" == "$node_checksum" ]] || die 'Node.js checksum verification failed'
NODE_ROOT="${NODE_ASSET%.tar.gz}"
node_members="$(tar -tzf "$NODE_DOWNLOAD/$NODE_ASSET")" || die 'the Node.js archive could not be read'
while IFS= read -r member; do
  case "${member%/}" in
    "$NODE_ROOT"|"$NODE_ROOT"/*) ;;
    *) die "unsafe Node.js archive member: $member" ;;
  esac
  case "/${member%/}/" in */../*|*//*) die "unsafe Node.js archive path: $member" ;; esac
done <<<"$node_members"
mkdir -p "$TEMP_DIR/node"
tar -xzf "$NODE_DOWNLOAD/$NODE_ASSET" -C "$TEMP_DIR/node" || die 'could not extract Node.js'
STAGED_NODE="$TEMP_DIR/node/$NODE_ROOT"
[[ "$("$STAGED_NODE/bin/node" --version)" == "$NODE_VERSION" ]] || die 'the staged Node.js runtime failed verification'
PATH="$STAGED_NODE/bin:$PATH" "$STAGED_NODE/bin/npm" --version >/dev/null \
  || die 'the staged npm executable failed verification'
ok 'Node.js checksum and runtime verified'

# Resolve master once, then download and validate that immutable plugin snapshot.
PLUGIN_JSON="$TEMP_DIR/plugin-commit.json"
curl_download "https://api.github.com/repos/$PLUGIN_REPOSITORY/commits/master" "$PLUGIN_JSON" \
  || die "could not resolve $PLUGIN_REPOSITORY master"
PLUGIN_SHA="$(sed -n 's/^[[:space:]]*"sha":[[:space:]]*"\([0-9a-f]*\)".*/\1/p' "$PLUGIN_JSON" | awk 'NR == 1 { first = $0 } END { print first }')"
[[ "$PLUGIN_SHA" =~ ^[0-9a-f]{40}$ ]] || die 'the plugin commit response was invalid'
PLUGIN_ARCHIVE="$TEMP_DIR/plugins.tar.gz"
info "Downloading first-party plugins at ${PLUGIN_SHA:0:12}"
curl_download "https://github.com/$PLUGIN_REPOSITORY/archive/$PLUGIN_SHA.tar.gz" "$PLUGIN_ARCHIVE" \
  || die 'could not download the first-party plugins'
plugin_members="$(tar -tzf "$PLUGIN_ARCHIVE")" || die 'the plugin archive could not be read'
PLUGIN_ROOT=''
while IFS= read -r member; do
  normalized="${member%/}"
  case "$normalized" in ''|/*|..|../*|*/..|*/../*) die "unsafe plugin archive path: $member" ;; esac
  root="${normalized%%/*}"
  [[ -n "$PLUGIN_ROOT" ]] || PLUGIN_ROOT=$root
  [[ "$root" == "$PLUGIN_ROOT" ]] || die 'the plugin archive contains multiple roots'
done <<<"$plugin_members"
plugin_details="$(tar -tvzf "$PLUGIN_ARCHIVE")" || die 'the plugin archive could not be inspected'
while IFS= read -r detail; do
  case "${detail:0:1}" in -|d) ;; *) die 'the plugin archive contains a link or special file' ;; esac
done <<<"$plugin_details"
mkdir -p "$TEMP_DIR/plugins"
tar -xzf "$PLUGIN_ARCHIVE" -C "$TEMP_DIR/plugins" || die 'could not extract the plugins'
PLUGIN_SOURCE="$TEMP_DIR/plugins/$PLUGIN_ROOT"
[[ -d "$PLUGIN_SOURCE/plugins" ]] || die 'the plugin snapshot has no plugins directory'
plugin_count=0
for plugin_source in "$PLUGIN_SOURCE/plugins/"*; do
  [[ -d "$plugin_source" ]] || continue
  [[ -f "$plugin_source/plugin.json" && -f "$plugin_source/index.js" ]] \
    || die "invalid plugin directory: ${plugin_source##*/}"
  plugin_count=$((plugin_count + 1))
done
[[ "$plugin_count" -gt 0 ]] || die 'the plugin snapshot is empty'
if ! PATH="$STAGED_NODE/bin:$PATH" "$STAGED_NODE/bin/npm" test --prefix "$PLUGIN_SOURCE" >"$TEMP_DIR/plugin-tests.log" 2>&1; then
  sed -n '1,160p' "$TEMP_DIR/plugin-tests.log" >&2
  die 'the first-party plugin validation suite failed'
fi
ok "$plugin_count first-party plugins validated"

# From this point on, serialize target changes and keep rollback copies.
mkdir -p "$DATA_DIR" "$INSTALL_DIR"
chmod 700 "$DATA_DIR"
LOCK_DIR="$DATA_DIR/.installer-lock"
mkdir "$LOCK_DIR" 2>/dev/null || die "another installer is active; remove $LOCK_DIR only if no installer is running"
LOCK_HELD=1

ca_cert_exists=0; ca_key_exists=0
[[ ! -e "$DATA_DIR/ca/ca.crt" ]] || ca_cert_exists=1
[[ ! -e "$DATA_DIR/ca/ca.key" ]] || ca_key_exists=1
case "$ca_cert_exists$ca_key_exists" in
  00|11) ;;
  *) die "incomplete CA in $DATA_DIR/ca; restore the missing certificate or key before installing" ;;
esac
if [[ -S "$DATA_DIR/daemon.sock" ]]; then
  status_output="$("$STAGED_BIN" --data-dir "$DATA_DIR" status 2>&1 || true)"
  case "$status_output" in *'daemon: running'*|*'daemon: unhealthy'*) die 'HuntProxy is running; run HuntProxy stop, restart/reconnect AI clients, then rerun the installer' ;; esac
fi

mkdir -p "$STATE_BACKUP"
for relative in "${STATE_FILES[@]}"; do
  state_target="$DATA_DIR/$relative"
  [[ ! -L "$state_target" ]] || die "refusing symlinked state file: $state_target"
  if [[ -f "$state_target" ]]; then
    state_source="$STATE_BACKUP/$relative"
    mkdir -p "${state_source%/*}"
    cp -p -- "$state_target" "$state_source"
  fi
done
STATE_BACKED_UP=1
STOP_GUARD_EXISTED=0
[[ ! -f "$STATE_BACKUP/.mcp-stop-guard" ]] || STOP_GUARD_EXISTED=1

MANAGED_NODE_DIR="$DATA_DIR/runtime/node"
mkdir -p "$DATA_DIR/runtime"
NODE_INCOMING="$(mktemp -d "$DATA_DIR/runtime/.node.new.XXXXXX")"
cp -R "$STAGED_NODE/." "$NODE_INCOMING/"
[[ "$("$NODE_INCOMING/bin/node" --version)" == "$NODE_VERSION" ]] || die 'the copied Node.js runtime failed verification'
if [[ -e "$MANAGED_NODE_DIR" ]]; then
  NODE_BACKUP="$(mktemp -d "$DATA_DIR/runtime/.node.old.XXXXXX")"
  rmdir "$NODE_BACKUP"
  mv -- "$MANAGED_NODE_DIR" "$NODE_BACKUP"
fi
mv -- "$NODE_INCOMING" "$MANAGED_NODE_DIR"
NODE_INCOMING=''
NODE_INSTALLED=1
export PATH="$MANAGED_NODE_DIR/bin:$PATH"

# Only initialize when there is no CA. This keeps old release binaries from
# rotating an existing CA; the application also enforces this invariant.
if [[ ! -e "$DATA_DIR/ca/ca.crt" && ! -e "$DATA_DIR/ca/ca.key" ]]; then
  info "Initializing $DATA_DIR"
  "$STAGED_BIN" --data-dir "$DATA_DIR" init >"$TEMP_DIR/init.log" \
    || { sed -n '1,120p' "$TEMP_DIR/init.log" >&2; die 'HuntProxy initialization failed'; }
fi
[[ -f "$DATA_DIR/ca/ca.crt" && -f "$DATA_DIR/ca/ca.key" ]] \
  || die 'HuntProxy initialization did not create a complete CA'
CA_CERT_HASH="$(sha256_file "$DATA_DIR/ca/ca.crt")"
CA_KEY_HASH="$(sha256_file "$DATA_DIR/ca/ca.key")"

WORKER_DIR="$DATA_DIR/browser-worker-$binary_version"
if [[ -d "$WORKER_DIR" ]]; then
  WORKER_BACKUP="$(mktemp -d "$DATA_DIR/.browser-worker.old.XXXXXX")"
  rmdir "$WORKER_BACKUP"
  mv -- "$WORKER_DIR" "$WORKER_BACKUP"
fi
WORKER_TOUCHED=1
browser_args=(--data-dir "$DATA_DIR" browser install)
if [[ "$os_name" == Linux && -r /etc/os-release ]]; then
  linux_id="$(sed -n 's/^ID=//p' /etc/os-release | tr -d '"' | awk 'NR == 1 { print }')"
  if [[ "$linux_id" == ubuntu || "$linux_id" == debian ]]; then
    if [[ "$(id -u)" == 0 ]] || { command -v sudo >/dev/null 2>&1 && [[ -t 0 || -t 1 ]]; }; then
      browser_args+=(--with-deps)
      info 'Installing Chromium and required Debian/Ubuntu system libraries'
    else
      info 'Installing Chromium (system libraries cannot be elevated noninteractively)'
    fi
  else
    info 'Installing Chromium; automatic system libraries are supported only on Debian/Ubuntu'
  fi
else
  info 'Installing Chromium'
fi
"$STAGED_BIN" "${browser_args[@]}" >"$TEMP_DIR/browser-install.log" 2>&1 \
  || { sed -n '1,160p' "$TEMP_DIR/browser-install.log" >&2; die 'browser runtime installation failed'; }

WORKER_PATH="$WORKER_DIR/index.js"
[[ -f "$WORKER_PATH" ]] || die 'browser worker was not installed'
cat >"$TEMP_DIR/browser-smoke.ndjson" <<'EOF'
{"jsonrpc":"2.0","id":1,"method":"hello"}
{"jsonrpc":"2.0","id":2,"method":"session.start","params":{"session_id":1,"engine":"chromium","url":"about:blank","persistent":false}}
{"jsonrpc":"2.0","id":3,"method":"session.stop","params":{"session_id":1}}
EOF
PLAYWRIGHT_BROWSERS_PATH=0 \
HUNTPROXY_PLAYWRIGHT_CORE_PATH="$WORKER_DIR/node_modules/playwright-core" \
"$MANAGED_NODE_DIR/bin/node" "$WORKER_PATH" <"$TEMP_DIR/browser-smoke.ndjson" >"$TEMP_DIR/browser-smoke.out" 2>"$TEMP_DIR/browser-smoke.err" \
  || { sed -n '1,120p' "$TEMP_DIR/browser-smoke.err" >&2; die 'Chromium launch check failed'; }
if ! "$MANAGED_NODE_DIR/bin/node" -e '
const fs = require("fs");
const rows = fs.readFileSync(process.argv[1], "utf8").trim().split(/\n+/).map(JSON.parse);
for (const id of [1, 2, 3]) {
  const row = rows.find((entry) => entry.id === id);
  if (!row || row.error) process.exit(1);
}
' "$TEMP_DIR/browser-smoke.out"; then
  sed -n '1,120p' "$TEMP_DIR/browser-smoke.out" >&2
  sed -n '1,120p' "$TEMP_DIR/browser-smoke.err" >&2
  die 'the browser worker did not complete its launch check'
fi
ok 'Chromium launched successfully'

PLUGIN_DIR="$DATA_DIR/plugins"
if [[ -f "$DATA_DIR/config.toml" ]]; then
  configured_plugin_dir="$(sed -n 's/^plugin_dir = "\(.*\)"$/\1/p' "$DATA_DIR/config.toml" | awk 'NR == 1 { print }')"
  [[ -z "$configured_plugin_dir" ]] || PLUGIN_DIR=$configured_plugin_dir
fi
mkdir -p "$PLUGIN_DIR"; chmod 700 "$PLUGIN_DIR"
installed_plugins=0; preserved_plugins=0
for plugin_source in "$PLUGIN_SOURCE/plugins/"*; do
  [[ -d "$plugin_source" ]] || continue
  plugin_name="${plugin_source##*/}"
  plugin_target="$PLUGIN_DIR/$plugin_name"
  if [[ -e "$plugin_target" ]]; then
    preserved_plugins=$((preserved_plugins + 1))
    continue
  fi
  plugin_incoming="$(mktemp -d "$PLUGIN_DIR/.plugin.new.XXXXXX")"
  PLUGIN_INCOMING=$plugin_incoming
  cp -R "$plugin_source/." "$plugin_incoming/"
  mv -- "$plugin_incoming" "$plugin_target"
  PLUGIN_INCOMING=''
  printf '%s\n' "$plugin_target" >>"$NEW_PLUGIN_LIST"
  installed_plugins=$((installed_plugins + 1))
done
ok "$installed_plugins plugins installed; $preserved_plugins existing plugin folders preserved"

# Doctor output stays private: only concise assertions are surfaced.
DOCTOR_OUTPUT="$("$STAGED_BIN" --data-dir "$DATA_DIR" doctor 2>&1)" || die 'HuntProxy doctor failed'
printf '%s\n' "$DOCTOR_OUTPUT" | grep -Eq '^[[:space:]]*db:.*exists=true$' || die 'database readiness check failed'
printf '%s\n' "$DOCTOR_OUTPUT" | grep -Eq '^[[:space:]]*ca:.*exists=true$' || die 'CA readiness check failed'
printf '%s\n' "$DOCTOR_OUTPUT" | grep -Eq '^[[:space:]]*node:[[:space:]]+.+$' || die 'Node.js readiness check failed'
printf '%s\n' "$DOCTOR_OUTPUT" | grep -Eq '^[[:space:]]*node:[[:space:]]+not found$' && die 'Node.js readiness check failed'
printf '%s\n' "$DOCTOR_OUTPUT" | grep -Eq '^[[:space:]]*worker:[[:space:]]+ready$' || die 'browser worker readiness check failed'
printf '%s\n' "$DOCTOR_OUTPUT" | grep -Eq '^[[:space:]]*chromium:[[:space:]]+.+$' || die 'Chromium readiness check failed'
printf '%s\n' "$DOCTOR_OUTPUT" | grep -Eq '^[[:space:]]*chromium:[[:space:]]+not found$' && die 'Chromium readiness check failed'
[[ "$(sha256_file "$DATA_DIR/ca/ca.crt")" == "$CA_CERT_HASH" ]] || die 'CA certificate changed during installation'
[[ "$(sha256_file "$DATA_DIR/ca/ca.key")" == "$CA_KEY_HASH" ]] || die 'CA key changed during installation'

# Load the final plugin set through the real daemon, then shut down that
# foreground verification process without creating an MCP stop guard.
API_ADDR="$(printf '%s\n' "$DOCTOR_OUTPUT" | awk '$1 == "api:" { print $2; exit }')"
[[ -n "$API_ADDR" ]] || die 'could not resolve the local API address'
"$STAGED_BIN" --data-dir "$DATA_DIR" serve >"$TEMP_DIR/serve.log" 2>&1 &
VERIFY_PID=$!
health_ready=0
for _ in 1 2 3 4 5 6 7 8 9 10; do
  if curl -fsS "http://$API_ADDR/api/v1/health" >"$TEMP_DIR/health.json" 2>/dev/null; then health_ready=1; break; fi
  sleep 1
done
[[ "$health_ready" -eq 1 ]] || { sed -n '1,120p' "$TEMP_DIR/serve.log" >&2; die 'the HuntProxy daemon did not become healthy'; }
curl -fsS "http://$API_ADDR/api/v1/extensions" -o "$TEMP_DIR/extensions.json" || die 'could not verify loaded plugins'
"$MANAGED_NODE_DIR/bin/node" -e '
const fs = require("fs");
const result = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
if (!Array.isArray(result.plugins) || !Array.isArray(result.load_issues) || result.load_issues.length) process.exit(1);
' "$TEMP_DIR/extensions.json" || die 'one or more installed plugins failed to load'
kill "$VERIFY_PID" >/dev/null 2>&1 || true
wait "$VERIFY_PID" >/dev/null 2>&1 || true
VERIFY_PID=''
if [[ "$STOP_GUARD_EXISTED" -eq 1 ]]; then
  cp -p -- "$STATE_BACKUP/.mcp-stop-guard" "$DATA_DIR/.mcp-stop-guard"
fi
ok 'HuntProxy daemon and plugins verified'

# The executable is the last component replaced.
NEW_BIN="$(mktemp "$INSTALL_DIR/.HuntProxy.new.XXXXXX")"
cp -- "$STAGED_BIN" "$NEW_BIN"; chmod 755 "$NEW_BIN"
"$NEW_BIN" --version >/dev/null || die 'the installed executable failed its final check'
mv -f -- "$NEW_BIN" "$INSTALL_DIR/HuntProxy"
NEW_BIN=''; INSTALL_COMPLETE=1
if PLUGIN_SOURCE_TEMP="$(mktemp "$PLUGIN_DIR/.first-party-source.new.XXXXXX")" \
  && printf '%s\n' "$PLUGIN_SHA" >"$PLUGIN_SOURCE_TEMP" \
  && chmod 600 "$PLUGIN_SOURCE_TEMP" \
  && mv -f -- "$PLUGIN_SOURCE_TEMP" "$PLUGIN_DIR/.huntproxy-first-party-source"; then
  PLUGIN_SOURCE_TEMP=''
else
  [[ -z "$PLUGIN_SOURCE_TEMP" || ! -f "$PLUGIN_SOURCE_TEMP" ]] || rm -f -- "$PLUGIN_SOURCE_TEMP"
  PLUGIN_SOURCE_TEMP=''
  warn 'Could not record the first-party plugin source commit.'
fi

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
  if ! printf '' >/dev/tty 2>/dev/null; then
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
