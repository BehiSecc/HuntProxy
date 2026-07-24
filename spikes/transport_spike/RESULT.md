# Phase 0 Semantic Transport Spike — RESULT

**Date:** 2026-07-24  
**Host:** Linux amd64, `rustc 1.97.1`, `cargo 1.97.1`  
**Crate:** `/home/administrator/HuntProxy/spikes/transport_spike/` (standalone; not wired into `bb` workspace)

## Recommendation (ADR-ready)

**Primary implementation for `SemanticTransport`: pinned Wreq + Wreq-util.**

| Choice | Role |
|--------|------|
| **`wreq =6.0.0-rc.29` + `wreq-util =3.0.0-rc.14`** | **Primary** semantic egress with Chrome-like TLS/HTTP2 profiles (BoringSSL via `btls`) |
| **`primp =1.3.1`** | **Secondary / license-fallback** if BoringSSL graph or build reliability is rejected (MIT, rustls forks) |
| **Generic Hyper + rustls** (already in `bb`) | **Availability fallback only** — `transport_profile=generic_unprofiled`, never claim Chromium wire identity |

### Why Wreq wins this spike

1. **Builds cleanly** on this Linux amd64 host with the exact pins and feature set required by the plan (no cookies / no decompression / no system-proxy / `prefix-symbols`).
2. **All required capabilities proven** against a local origin (see proof matrix).
3. **Profile surface** is first-class (`wreq_util::Emulation::Chrome147` → TLS + HTTP/2 options + optional headers), matching the product need for intercept/profile path.
4. **ValidatedDial** maps directly onto `ClientBuilder::dns_resolver` / `resolve` / `resolve_to_addrs` with hostname preserved for Host/`:authority` and SNI.
5. Binary size is smaller than the primp spike binary on this host (~8.5 MiB vs ~11 MiB release, stripped, thin LTO).

### Why not primp as primary

- Younger stack: forks of reqwest/hyper/h2/rustls (`primp-*` packages); less aligned with the plan’s researched Wreq path.
- Default feature set turns on **impersonate + cookies + default-tls**; product must keep cookie store off and avoid system-proxy (spike always uses `no_proxy()`).
- Profiles work, but the project plan and main `Cargo.toml` already pin Wreq; switching primary would re-open fingerprint and dependency work.
- Keep primp evaluated and buildable as a comparison binary for license/owner decision.

### Why not generic Hyper/rustls as primary

- No browser TLS/HTTP2 fingerprint control.
- Still required as a **degraded** path if profile transport fails to compile on a target platform; label explicitly `generic_unprofiled`.

---

## Build success / failure

### Wreq path (primary)

```toml
wreq = { version = "=6.0.0-rc.29", default-features = false,
         features = ["webpki-roots", "tokio-rt", "stream", "prefix-symbols"] }
wreq-util = { version = "=3.0.0-rc.14", default-features = false,
              features = ["emulation", "tokio-rt"] }
```

| Item | Result |
|------|--------|
| Compile | **SUCCESS** (BoringSSL via `btls-sys` 0.5.6 built with cmake/clang/go present) |
| Features excluded | cookies, gzip/brotli/deflate/zstd decompression, system-proxy, hickory-dns |
| GPL `wreq-util 2.2.6` | **Not present** in spike `Cargo.lock` (only `3.0.0-rc.14`) |
| Release binary | `target/release/wreq_spike` ≈ **8.5 MiB** (8 854 768 bytes) |
| Clean-ish first wall time | First attempt hit 300 s tool timeout while compiling `transport_spike` after `btls` finished; resume finished in **~36 s**. Expect **several minutes** for cold `btls-sys`/BoringSSL on a clean machine. |
| Proof suite wall | **~0.4–0.5 s** (includes local origin + all cases) |
| Peak RSS (suite) | ~12 MiB |

**Run:** `cargo run --release --bin wreq_spike`

**Proof matrix (wreq_spike): 11/11 PASS**

| Check | Result | Notes |
|-------|--------|-------|
| HTTP/1.1 GET | PASS | Host = `origin.localtest:<port>`; custom DNS hit |
| HTTP/2 over TLS | PASS | ALPN h2; authority `h2.localtest:<port>` |
| Streaming upload | PASS | `Body::wrap_stream` 8×1 KiB → origin `received=8192` |
| Streaming download (partial) | PASS | `bytes_stream`, stop after 3 frames |
| Cancellation (timeout) | PASS | 200 ms client timeout on `/slow` |
| Cancellation (drop stream) | PASS | Drop after first frame |
| Custom CA / self-signed | PASS | Fails without CA; succeeds with `CertStore` PEM stack |
| ValidatedDial (custom `Resolve`) | PASS | Hostname `this-host-must-never-resolve.invalid`; no system DNS; fails without override |
| ValidatedDial (`resolve` override) | PASS | Same unresolvable name via `ClientBuilder::resolve` |
| Emulation API | PASS | `Emulation::Chrome147` accepted |
| Emulation request | PASS | 200 + HTTP/2 to local TLS origin with custom CA |

### Primp path (comparison)

```toml
primp = { version = "=1.3.1" }  # feature `primp` on spike crate
```

| Item | Result |
|------|--------|
| Compile | **SUCCESS** (`--features primp --no-default-features`) |
| Release binary | `target/release/primp_spike` ≈ **11 MiB** (11 190 752 bytes) |
| First build wall | ~**121 s** (deps + rustls forks; code error then fixed) |
| Proof suite wall | **~0.5 s** |
| Peak RSS (suite) | ~11 MiB |

**Run:** `cargo run --release --bin primp_spike --features primp --no-default-features`

**Proof matrix (primp_spike): 11/11 PASS** (same functional surface: H1, H2/TLS, upload, stream download, timeout cancel, custom CA, resolve override, `Impersonate::ChromeV147`).

---

## License notes (what was resolved)

> Final project licensing remains an **owner decision** before publication. This table records crates.io metadata + LICENSE files observed in the registry sources used by the spike. It is **not** a legal opinion. Run `cargo deny` on the main workspace before distribution and review BoringSSL notices in `btls-sys`’s vendored tree.

### Direct pins (Wreq path)

| Crate | Version | License (crate) |
|-------|---------|-----------------|
| wreq | 6.0.0-rc.29 | Apache-2.0 |
| wreq-util | 3.0.0-rc.14 | Apache-2.0 |
| ~~wreq-util 2.2.6~~ | stable | **GPL-3.0 — DO NOT USE** |

### Notable transitive (Wreq / BoringSSL graph)

| Crate | Version | License (crate) | Notes |
|-------|---------|-----------------|-------|
| btls | 0.5.6 | Apache-2.0 | Safe BoringSSL wrapper used by wreq |
| btls-sys | 0.5.6 | MIT | FFI + **vendored BoringSSL** under `deps/boringssl/` (LICENSE begins Apache-2.0; full BoringSSL notice set must be redistributed) |
| tokio-btls | 0.5.6 | MIT OR Apache-2.0 | |
| http2 | 0.5.19 | MIT | Wreq’s HTTP/2 stack fork |
| wreq-proto | 0.2.5 | Apache-2.0 | |
| wreq-rt | 0.2.2-rc.4 | Apache-2.0 | |

### Primp path

| Crate | Version | License (crate) |
|-------|---------|-----------------|
| primp | 1.3.1 | MIT |
| primp-reqwest | 0.13.4 | MIT OR Apache-2.0 |
| primp-rustls | 0.23.40 | Apache-2.0 OR ISC OR MIT |
| primp-h2 | 0.4.15 | MIT |
| primp-hyper / primp-hyper-util / primp-hyper-rustls / primp-tokio-rustls | (as locked) | MIT OR Apache-2.0 family |

**Constraint compliance:** spike never enables Wreq cookie storage, response decompression, or system-proxy features; never depends on GPL `wreq-util 2.2.6`.

---

## ValidatedDial: what the library can / cannot enforce

Shape used in this spike (and planned for `bb`):

```text
ValidatedDial { hostname, port, approved_socket_addrs, policy_epoch, expires_at }
```

### Can enforce (with Wreq — recommended pattern)

| Capability | Mechanism |
|------------|-----------|
| Dial only approved IP(s) | `ClientBuilder::dns_resolver(impl Resolve)` returning **only** approved `SocketAddr`s, **or** `resolve` / `resolve_to_addrs` overrides for that hostname |
| No second DNS that bypasses policy | Custom `Resolve` that **errors** for any host not in the approved map (never falls back to GAI/system DNS). Proven with hostname `this-host-must-never-resolve.invalid` |
| Preserve hostname for Host / `:authority` | Put hostname in the request URI; origin observed `origin.localtest:…` / `h2.localtest:…` / unresolvable name as Host/authority |
| Preserve hostname for SNI / cert verify | Same URI host; custom CA test verifies hostname against self-signed SAN |
| Request-scoped policy | Prefer **one client (or connector config) per** `(authority, approved_ip, profile, policy_epoch, dns_expiry)` pool key; do not share pools across dials |

### Important library limitations (both Wreq and primp)

1. **Port in `SocketAddr` is ignored** by `resolve` / `resolve_to_addrs` (documented by Wreq). The URI port (from `ValidatedDial.port`) is what is dialed. Always put the policy port in the URL, not only in the override address.
2. **Enforcement is cooperative.** Nothing stops a future code path from building a bare `Client::new()` that performs system DNS. `SemanticTransport` must be the **only** egress construction site.
3. **Overrides are hostname-keyed**, not full `ValidatedDial`-aware inside the crate. Policy epoch / expiry / pool drain are **application** responsibilities.
4. **Connection reuse** can pin an old IP if the pool is not keyed/drained when DNS lease or `policy_epoch` changes. Plan: drain pools on scope/DNS change.
5. **Redirects** to a new host would re-enter DNS. Spike uses `redirect::Policy::none()`; production should keep that or re-validate every hop.
6. **SNI vs dial IP** is supported (hostname in TLS, IP from resolver). Do **not** put the raw IP in the URL if you need name-based cert verification and Host fidelity.

### Primp ValidatedDial surface

Same reqwest-style API: `resolve`, `resolve_to_addrs`, `dns_resolver`. Proven with `resolve` + unresolvable hostname. Same port-in-SocketAddr caveat.

---

## Profile / emulation availability

| Library | API | Spike status |
|---------|-----|--------------|
| wreq-util | `Emulation::Chrome147` (and many Chrome/Edge/Firefox/Safari/Opera/OkHttp profiles) | Builds; TLS handshake + HTTP/2 request to local origin **PASS**. Full JA3/JA4/H2 SETTINGS parity vs real Chromium **not** measured here (needs TrackMe / external fixture — plan’s next fingerprint step). |
| primp | `Impersonate::ChromeV147` (V144–V148 + random Chrome) | Builds; request **PASS** on local origin. Same external fingerprint gap. |

Product note (from plan): use **transport-only** profile mode where possible so identity headers remain under application control (`protocol_profile_only`), not silent Chromium UA injection. Spike overrode `user-agent` on the emulation request for that reason.

---

## Rough measurements (this host)

| Metric | Wreq spike | Primp spike |
|--------|------------|-------------|
| Release binary size | ~8.5 MiB | ~11 MiB |
| Full proof suite wall | ~0.42–0.49 s | ~0.47–0.48 s |
| Max RSS during suite | ~12 MiB | ~11 MiB |
| Cold dependency build | Dominated by **BoringSSL/`btls-sys`** (minutes first time) | Dominated by rustls/hyper forks (~2 min first time) |
| Rebuild after code change | ~36–55 s release | ~55 s release |

Cold start of the binary itself is small relative to suite work (process + client init + local servers + multiple handshakes still &lt; 0.5 s total).

---

## ADR-ready decision text (draft)

**Decision:** Implement `SemanticTransport` on **exact-pinned** `wreq 6.0.0-rc.29` + `wreq-util 3.0.0-rc.14` with `default-features = false` and only `webpki-roots`, `tokio-rt`, `stream`, `prefix-symbols` / `emulation`, `tokio-rt`.

**Consequences:**

- Positive: Chrome-like TLS/HTTP2 profiles; streaming; cancellation; custom CA; ValidatedDial via custom DNS resolver; builds on Linux amd64 with standard cmake/clang/go.
- Negative: Vendored BoringSSL lengthens clean builds and requires license/notice review for redistribution; prerelease pins must stay exact (no caret ranges) because earlier util RCs had different licenses.
- Fallback: If a platform cannot build BoringSSL, ship **generic Hyper/rustls** labeled `generic_unprofiled`, or evaluate **primp 1.3.1** as a profile-capable MIT alternative after fingerprint parity work.
- Non-goals: Do not enable Wreq cookies, auto-decompression, or system-proxy. Do not depend on GPL `wreq-util 2.2.6`.

**Validation:** This spike’s `wreq_spike` binary (11/11) is the acceptance evidence for API fit; wire-level fingerprint match vs Chromium remains a follow-up against the TrackMe fixture.

---

## How to reproduce

```bash
export PATH="$HOME/.cargo/bin:$PATH"
cd spikes/transport_spike

# Primary
cargo build --release --bin wreq_spike
./target/release/wreq_spike

# Comparison
cargo build --release --bin primp_spike --features primp --no-default-features
./target/release/primp_spike
```

Toolchain needs for Wreq: `cmake`, `clang`, `go`, `ninja` (for `btls-sys` BoringSSL).

---

## Spike layout

```
spikes/transport_spike/
  Cargo.toml          # standalone; exact pins; features wreq-backend | primp
  Cargo.lock
  RESULT.md           # this file
  src/lib.rs          # shared origin + ValidatedDial helpers
  src/origin.rs       # local HTTP/HTTPS origin (ALPN h2 + http/1.1)
  src/validated_dial.rs
  src/bin/wreq_spike.rs
  src/bin/primp_spike.rs
```

---

## Open follow-ups (out of scope for this spike)

1. TrackMe / JA4 / H2 SETTINGS comparison against a real matching Chromium build.
2. macOS arm64/x86_64 and Linux arm64 release builds of the same pins.
3. `cargo deny` + full notice file packaging for BoringSSL.
4. Wire `SemanticTransport` behind a trait in `bb` with pool key `(authority, approved_ip, profile, policy_epoch, expires_at)`.
5. Confirm “transport-only” emulation without unwanted default identity headers for Lightpanda path.
