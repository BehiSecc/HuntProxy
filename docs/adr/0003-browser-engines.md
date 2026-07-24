# ADR 0003: Browser engines and migration

**Status:** Accepted  
**Date:** 2026-07-24

## Context

Lightpanda is the fast engine; Chromium is compatibility fallback.

## Decision

- Pin Playwright worker (`playwright-core`) over CDP for Lightpanda; `chromium.launch()` for Chromium.
- After `connectOverCDP`, always `browser.newContext()` + `newPage()` (default context unusable on tested Lightpanda build).
- Extract cookies via `context.cookies()` and storage via `page.evaluate` — do **not** trust Lightpanda `storageState().origins`.
- Checkpoint values stay in daemon memory only; SQLite stores version/status/hash.
- Lightpanda proxy: `--proxy-bearer-token` and/or Basic in `--http-proxy` URL.
- Chromium/external: Basic user `bb` + same token as password.
- Auto fallback at most once per session; explicit “Switch to Chromium” always available.
- `LIGHTPANDA_DISABLE_TELEMETRY=true`.

## Proven

Phase 0 spike (`spikes/lightpanda_spike`): 16/16 PASS including cookie + localStorage + sessionStorage transfer to system Chrome.
