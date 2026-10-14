#!/usr/bin/env bash
set -euo pipefail
export PATH="${HOME}/.cargo/bin:${PATH}"
cd "$(dirname "$0")/.."

echo "== fmt =="
cargo fmt --check

echo "== Rust dependency notices =="
python3 scripts/prepare-rust-notices.py --check

echo "== release asset validation =="
python3 scripts/test-prepare-release-assets.py

echo "== clippy =="
cargo clippy --locked --all-targets -- -D warnings

echo "== test =="
cargo test --locked --all-targets

echo "== browser worker syntax =="
node --check browser-worker/index.js

echo "== build =="
cargo build --release --locked

echo "OK"
