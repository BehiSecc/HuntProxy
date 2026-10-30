#!/usr/bin/env bash
set -euo pipefail

quick=false
if [[ $# -gt 0 ]]; then
  if [[ $# -ne 1 || $1 != --quick ]]; then
    echo "Usage: $0 [--quick]" >&2
    exit 2
  fi
  quick=true
fi

export PATH="${HOME}/.cargo/bin:${PATH}"
cd "$(dirname "$0")/.."

echo "== fmt =="
cargo fmt --check

echo "== Rust dependency notices =="
python3 scripts/test-prepare-rust-notices.py
python3 scripts/prepare-rust-notices.py --check

echo "== release asset validation =="
python3 scripts/test-prepare-release-assets.py

echo "== clippy =="
cargo clippy --locked --all-targets -- -D warnings

echo "== test =="
cargo test --locked --all-targets

echo "== browser worker syntax =="
node --check browser-worker/index.js
node --check browser-worker/headless.js

if [[ $quick == true ]]; then
  echo "== release build skipped (--quick) =="
else
  echo "== build =="
  cargo build --release --locked
fi

echo "OK"
