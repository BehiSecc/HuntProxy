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
# cargo clippy sets RUSTC_WORKSPACE_WRAPPER, which the BoringSSL build script
# watches. In a target directory shared with the test build below, every
# switch between the two would rebuild BoringSSL, so clippy keeps its own.
cargo clippy --locked --all-targets \
  --target-dir "${CARGO_TARGET_DIR:-target}/clippy" -- -D warnings

echo "== test =="
cargo test --locked --all-targets

echo "== browser worker syntax =="
node --check browser-worker/index.js
node --check browser-worker/headless.js

echo "== browser worker tests =="
if [[ ! -d browser-worker/node_modules ]]; then
  echo "browser-worker/node_modules is missing: run npm ci --ignore-scripts in browser-worker" >&2
  exit 1
fi
# Tests that drive Chromium skip themselves when no browser runtime is installed.
(cd browser-worker && npm test --silent)

echo "== web UI tests =="
node --test tests/ui_project_selection.test.cjs

# Whether Playwright and a compatible Chromium are installed, as the worker finds them.
browser_runtime_ready() {
  node browser-worker/index.js --inspect-runtime 2>/dev/null | node -e '
    let text = "";
    process.stdin.on("data", (chunk) => { text += chunk; }).on("end", () => {
      let runtime = {};
      try { runtime = JSON.parse(text); } catch {}
      process.exit(runtime.chromium_path && runtime.playwright_core_path && !runtime.compatibility_error ? 0 : 1);
    });'
}

if [[ $quick == true ]]; then
  echo "== live browser tests skipped (--quick) =="
  echo "== release build skipped (--quick) =="
else
  if browser_runtime_ready; then
    echo "== live browser tests =="
    # One browser at a time: the tests measure timing and share Chromium's sandbox.
    cargo test --locked --test browser_profile_isolation -- --ignored --test-threads=1
  else
    echo "== live browser tests skipped: no installed Playwright and Chromium =="
  fi
  echo "== build =="
  cargo build --release --locked
fi

echo "OK"
