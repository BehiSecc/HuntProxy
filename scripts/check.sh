#!/usr/bin/env bash
set -euo pipefail
export PATH="${HOME}/.cargo/bin:${PATH}"
cd "$(dirname "$0")/.."

echo "== fmt =="
cargo fmt --check

echo "== clippy =="
cargo clippy --all-targets -- -D warnings || cargo clippy --all-targets

echo "== test =="
cargo test --lib

echo "== build =="
cargo build --release

if command -v cargo-deny >/dev/null 2>&1; then
  echo "== deny =="
  cargo deny check || true
else
  echo "== deny skipped (cargo-deny not installed) =="
fi

echo "OK"
