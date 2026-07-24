# ADR 0002: Proxy ingress (Hudsucker)

**Status:** Accepted  
**Date:** 2026-07-24

## Context

Need MITM capture for intercept path and non-terminating CONNECT for Chromium fidelity.

## Decision

- Use **Hudsucker 0.25** (`http2`, `rcgen-ca`, `rustls-client`; decoder disabled).
- **Never** use Hudsucker default CONNECT passthrough (it re-resolves authority via DNS).
- Implement CONNECT/WebSocket dial in `handle_request` using `ValidatedDial` approved IPs only.
- MITM upstream uses custom connector with approved-IP dial.
- Capture quality labels must record Hyper normalization (lowercased names, cookie join, best-effort case).

## Proven

Phase 0 spike (`spikes/hudsucker_spike`): HTTP proxy, custom CONNECT, MITM TLS, streaming body caps, duplicate headers, concurrent correlation, client disconnect — all PASS.
