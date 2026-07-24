# bb — local-first HTTP workbench

`bb` is an agent-safe, open-source HTTP testing workbench for **authorized** targets. Primary loop:

```text
capture → search → inspect safely → derive → send/fuzz/browse → compare → preserve evidence
```

## Install (from source)

```bash
# Requires Rust stable (see rust-toolchain.toml)
export PATH="$HOME/.cargo/bin:$PATH"
cargo build --release
# binary: target/release/bb
```

Optional browsers:

```bash
bb browser install          # worker deps (playwright-core)
# Lightpanda: place `lightpanda` on PATH
# Chromium: system Chrome or `npx playwright install chromium`
```

## Quick start

```bash
bb init --data-dir ~/.local/share/bb
bb serve --data-dir ~/.local/share/bb
```

- **Web UI:** http://127.0.0.1:17890  
- **Proxy:** 127.0.0.1:17891 (requires project capture credential)  
- **Doctor:** `bb doctor --data-dir ~/.local/share/bb`  
- **Stop:** `bb stop --data-dir ~/.local/share/bb`

### Connect an agent (stdio MCP)

```bash
bb mcp --data-dir ~/.local/share/bb
```

MCP protocol is on **stdout**; logs on **stderr**. Every project-scoped tool requires an explicit `project_id`.

### Capture traffic

1. Create a project in the UI (name + target URL).
2. Click **New credential** and copy the Bearer or Basic presentation (shown once).
3. Point a browser/client at `127.0.0.1:17891` with that credential.
4. History updates live; secrets are redacted as `<redacted>`.

## Architecture

One Rust binary (`bb serve`) owns SQLite, the proxy, jobs, and browser children. CLI and stdio MCP are adapters over a private local socket / loopback API.

See `plans/` for the full product, technical, research, and verification specs. ADRs live in `docs/adr/`.

## License

No project license file has been selected yet. Fingerprint dependencies use the exact-pinned permissive Apache-2.0 prerelease path documented in `docs/adr/0001-semantic-transport.md`. **Final licensing is an owner decision before public distribution.**

## Development

```bash
cargo test --lib
cargo fmt
cargo clippy --all-targets -- -D warnings   # when clean
```

Phase 0 spikes (results under `spikes/*/RESULT.md`):

- Hudsucker proxy / ValidatedDial CONNECT
- Wreq + primp transport comparison
- Lightpanda CDP + cookie/storage migration to Chromium
