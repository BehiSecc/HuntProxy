# ADR 0001: Semantic outbound transport

**Status:** Accepted  
**Date:** 2026-07-24

## Context

Reply, Fuzzer, proxy intercept path, and crawler requests need a semantic HTTP client that:
- dials only `ValidatedDial` approved IPs (no second DNS lookup),
- can apply protocol-profile matching (TLS/H2) without claiming undetectability,
- remains permissively licensed (no GPL `wreq-util 2.2.6`).

## Decision

1. **Primary interface:** `SemanticTransport` trait in `src/transport/`.
2. **Default runtime path:** `GenericTransport` (Hyper/rustls-style raw HTTP/1.1 over approved-IP TCP/TLS) with `transport_profile=generic_unprofiled` and provenance `generic_unprofiled`.
3. **Profile path:** exact-pinned `wreq =6.0.0-rc.29` + `wreq-util =3.0.0-rc.14` (Apache-2.0) behind the trait when the Phase 0 spike confirms clean builds on target platforms. Isolated factory: `try_wreq_transport()`.
4. **Fallback if Wreq/BoringSSL fails:** keep GenericTransport only; do not retain two half-working stacks.
5. **Language:** “protocol-profile matching” / “compatibility mode” — never “undetectable”.

## Consequences

- MVP ships a working semantic path even if Wreq pin fails CI on a platform.
- Fingerprint gates for Chrome-like profiles apply only when Wreq path is enabled and verified.
- Project license remains an owner decision before publication; do not silently adopt GPL util.

## Spike cross-reference

- `spikes/transport_spike/RESULT.md` (when present)
- Hudsucker CONNECT must use custom ValidatedDial dialer (`spikes/hudsucker_spike/RESULT.md`)
