#!/usr/bin/env bash
set -Eeuo pipefail

readonly CARGO_DENY_VERSION="0.20.2"
readonly CARGO_DENY_SHA256="9f12ed4c49936e09b48bf862b595cde2fe64fcbd9d74dfacac6131ca824c8d5f"
readonly CARGO_DENY_URL="https://github.com/EmbarkStudios/cargo-deny/releases/download/${CARGO_DENY_VERSION}/cargo-deny-${CARGO_DENY_VERSION}-x86_64-unknown-linux-musl.tar.gz"

repo_dir="$(cd "$(dirname "$0")/.." && pwd -P)"
cleanup_audit_dir=0
if [[ -n "${HUNTPROXY_AUDIT_DIR:-}" ]]; then
  audit_dir="$HUNTPROXY_AUDIT_DIR"
  mkdir -p "$audit_dir"
else
  audit_dir="$(mktemp -d "${TMPDIR:-/tmp}/huntproxy-dependency-audit.XXXXXX")"
  cleanup_audit_dir=1
fi

cleanup() {
  if [[ "$cleanup_audit_dir" == 1 ]]; then
    rm -rf -- "$audit_dir"
  fi
}
trap cleanup EXIT

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "required dependency-audit command is unavailable: $1" >&2
    exit 1
  fi
}

require_command cargo
require_command npm
require_command python3

if [[ -n "${CARGO_DENY_BIN:-}" ]]; then
  cargo_deny="$CARGO_DENY_BIN"
  if [[ ! -f "$cargo_deny" || ! -x "$cargo_deny" ]]; then
    echo "CARGO_DENY_BIN is not an executable regular file: $cargo_deny" >&2
    exit 1
  fi
else
  require_command curl
  require_command sha256sum
  require_command tar

  archive="$audit_dir/cargo-deny.tar.gz"
  cargo_deny="$audit_dir/cargo-deny"
  curl --proto '=https' --tlsv1.2 --connect-timeout 15 --max-time 120 \
    --retry 3 --retry-all-errors --retry-max-time 300 \
    --fail --location --silent --show-error "$CARGO_DENY_URL" --output "$archive"
  printf '%s  %s\n' "$CARGO_DENY_SHA256" "$archive" | sha256sum -c -

  mapfile -t cargo_deny_members < <(
    tar -tzf "$archive" | while IFS= read -r member; do
      if [[ "$member" == "cargo-deny" || "$member" == */cargo-deny ]]; then
        printf '%s\n' "$member"
      fi
    done
  )
  if [[ "${#cargo_deny_members[@]}" -ne 1 ]]; then
    echo "cargo-deny archive did not contain exactly one cargo-deny executable" >&2
    exit 1
  fi
  cargo_deny_member="${cargo_deny_members[0]}"
  if [[ "$cargo_deny_member" == /* || "/$cargo_deny_member/" == *"/../"* ]]; then
    echo "cargo-deny archive contained an unsafe executable path" >&2
    exit 1
  fi
  if [[ "$(tar -tvzf "$archive" "$cargo_deny_member" | cut -c1)" != "-" ]]; then
    echo "cargo-deny archive executable is not a regular file" >&2
    exit 1
  fi
  tar -xOzf "$archive" "$cargo_deny_member" > "$cargo_deny"
  chmod 755 "$cargo_deny"
fi

if [[ "$("$cargo_deny" --version)" != "cargo-deny $CARGO_DENY_VERSION" ]]; then
  echo "cargo-deny version mismatch; expected $CARGO_DENY_VERSION" >&2
  exit 1
fi

advisory_db="$audit_dir/advisory-db"
audit_config="$audit_dir/deny.toml"
python3 - "$repo_dir/deny.toml" "$audit_config" "$advisory_db" <<'PY'
import json
import pathlib
import sys

source = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
header = "[advisories]\n"
if source.count(header) != 1:
    raise SystemExit("deny.toml must contain exactly one [advisories] table")
configured = source.replace(
    header,
    f"{header}db-path = {json.dumps(sys.argv[3])}\n",
    1,
)
pathlib.Path(sys.argv[2]).write_text(configured, encoding="utf-8")
PY

echo "== Rust dependency policy and advisories =="
(cd "$repo_dir" && "$cargo_deny" --locked --config "$audit_config" check all)

echo "== Browser worker production dependency advisories =="
(cd "$repo_dir/browser-worker" && npm audit --omit=dev --json)

echo "Dependency audits passed"
