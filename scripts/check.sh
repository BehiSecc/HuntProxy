#!/usr/bin/env bash
set -euo pipefail
export PATH="${HOME}/.cargo/bin:${PATH}"
cd "$(dirname "$0")/.."

echo "== fmt =="
cargo fmt --check

echo "== clippy =="
cargo clippy --all-targets -- -D warnings

echo "== test =="
cargo test --all-targets

echo "== browser worker syntax =="
node --check browser-worker/index.js

echo "== build =="
cargo build --release

if command -v cargo-deny >/dev/null 2>&1; then
  echo "== deny =="
  cargo deny check
else
  echo "== deny skipped (cargo-deny not installed) =="
fi

echo "OK"
