# Hudsucker Phase 0 Spike — RESULT

- Date: unix-1784912628
- Crate: `spikes/hudsucker_spike` (standalone; does not modify main `bb` crate)
- Hudsucker: 0.25 (`default-features = false`, features: `http2`, `rcgen-ca`, `rustls-client`)
- Origin: local Hyper HTTP + HTTPS fixtures

## Summary

- Proof points: **9 PASS**, **0 FAIL**
- Findings recorded: 4

## Proof points

| Status | Proof | Detail |
|--------|-------|--------|
| PASS | HTTP proxy request | status=200 OK body="hello-from-origin" |
| PASS | CONNECT with ValidatedDial (passthrough, no default authority dial) | status=200 OK custom_dials=1 dialed_approved=true fake_host_dns_empty=true body="hello-from-origin" |
| PASS | Intercepted TLS (MITM) with generated certificates | status=200 OK dialed_validated=true body="hello-from-origin" headers=[("connection", "close"), ("content-length", "17"), ("date", "Fri, 24 Jul 2026 17:03:47 GMT"), ("X-Spike-Exchange-Id", "3")] |
| PASS | Streaming response without full body capture buffering | status=200 OK client_body=2098254 capture=Some(65536) total_seen=Some(2097152) capped=Some(true) BODY_CAP=65536 |
| PASS | Streaming request without full body capture buffering | status=200 OK origin_got=524288 upload=524288 req_captured=Some(65536) req_total=Some(524288) capped=Some(true) resp=echoed=524288 |
| PASS | Body cap behavior (capture <= CAP while total_seen can exceed) | exchanges with cap evidence: [(4, "/stream", 0, 0, 65536, 2097152), (5, "/echo", 65536, 524288, 13, 13)] |
| PASS | Ordered/duplicate headers (as Hyper exposes) | status=200 OK body_len=92 client set-cookie=["a=1; Path=/", "b=2; Path=/"] x-dup=["one", "two"] handler set-cookie=["a=1; Path=/", "b=2; Path=/"] hyper normalizes names to lowercase; HeaderMap preserves insertion order for get_all/iter. hudsucker normalize_request joins Cookie headers with '; ' and removes Host before upstream forward (capture_quality impact). |
| PASS | Concurrent requests with correct correlation | client_ok=8/8 unique_exchange_ids=8 unique_tokens=8 details=["i=0 status=200 OK origin_id=Some(\"0\") exchange_id=Some(\"8\") matched=true", "i=1 status=200 OK origin_id=Some(\"1\") exchange_id=Some(\"9\") matched=true", "i=2 status=200 OK origin_id=Some(\"2\") exchange_id=Some(\"10\") matched=true", "i=3 status=200 OK origin_id=Some(\"3\") exchange_id=Some(\"11\") matched=true", "i=4 status=200 OK origin_id=Some(\"4\") exchange_id=Some(\"12\") matched=true", "i=5 status=200 OK origin_id=Some(\"5\") exchange_id=Some(\"13\") matched=true", "i=6 status=200 OK origin_id=Some(\"6\") exchange_id=Some(\"14\") matched=true", "i=7 status=200 OK origin_id=Some(\"7\") exchange_id=Some(\"7\") matched=true"] |
| PASS | Graceful handling of client disconnect | partial_read=2062 subsequent_hello status=200 OK (proxy did not hang/panic) |

## Findings / API notes

### FINDING: Hudsucker default CONNECT passthrough dial

hudsucker 0.25 process_connect uses TcpStream::connect(authority.as_ref()) for non-intercept / non-TLS-intercept tunnels (internal.rs). That path resolves the authority string via the OS. This spike bypasses it by returning a CONNECT response from handle_request and dialing ValidatedDial.approved directly. Product code must keep that custom path (or patch hudsucker) and must not rely on with_http_connector for raw CONNECT tunnels — the connector is only used for MITM-forwarded HTTP(S).

### FINDING: Hyper/Hudsucker header normalization

1) Header names lowercased by Hyper http::HeaderName. 2) Original wire case is not recoverable after parse (except http1_preserve_header_case / title_case on client builder — hudsucker enables title_case_headers + preserve_header_case on its default Client/Server builders for forwarding). 3) Duplicate headers: HeaderMap preserves multiple values; iter order is insertion order. 4) Cookie request headers are joined by hudsucker::normalize_request. 5) Host request header is stripped by normalize_request (Hyper re-adds). Labels: header_names=http_lowercased; cookie_join=hudsucker_normalized; host=stripped_then_readded; wire_case=best_effort_via_preserve_header_case.

### FINDING: Concurrent HTTP/2 streams

Spike proved concurrent correlation over concurrent HTTP/1.1 connections. Hudsucker enables h2 ALPN on MITM certs when feature http2 is on, and clones HttpHandler per request so request/response share one handler instance (per-exchange fields are safe). Full H2 stream multiplexing correlation was not separately instrumented in this harness (would need H2 client frames); pattern is the same handler clone model.

### FINDING: decoder feature disabled

Spike builds hudsucker with default-features=false and features=[http2, rcgen-ca, rustls-client] only. decode_request/decode_response are not available; bodies are not auto-decompressed by hudsucker. Streaming taps observe raw framed bytes as Hyper delivers them.

## ValidatedDial events (sample)

```
host=127.0.0.1 port=38089 dialed=127.0.0.1:38089 dns_resolution=false
host=origin.validated-dial.test port=38089 dialed=127.0.0.1:38089 dns_resolution=false
host=origin.validated-dial.test port=39971 dialed=127.0.0.1:39971 dns_resolution=false
host=127.0.0.1 port=38089 dialed=127.0.0.1:38089 dns_resolution=false
host=127.0.0.1 port=38089 dialed=127.0.0.1:38089 dns_resolution=false
host=127.0.0.1 port=38089 dialed=127.0.0.1:38089 dns_resolution=false
host=127.0.0.1 port=38089 dialed=127.0.0.1:38089 dns_resolution=false
host=127.0.0.1 port=38089 dialed=127.0.0.1:38089 dns_resolution=false
host=127.0.0.1 port=38089 dialed=127.0.0.1:38089 dns_resolution=false
host=127.0.0.1 port=38089 dialed=127.0.0.1:38089 dns_resolution=false
host=127.0.0.1 port=38089 dialed=127.0.0.1:38089 dns_resolution=false
host=127.0.0.1 port=38089 dialed=127.0.0.1:38089 dns_resolution=false
host=127.0.0.1 port=38089 dialed=127.0.0.1:38089 dns_resolution=false
host=127.0.0.1 port=38089 dialed=127.0.0.1:38089 dns_resolution=false
host=127.0.0.1 port=38089 dialed=127.0.0.1:38089 dns_resolution=false
host=127.0.0.1 port=38089 dialed=127.0.0.1:38089 dns_resolution=false
```

## Architecture used in spike

```
client --HTTP absolute-form--> Hudsucker --ValidatedDialConnector--> Hyper origin (HTTP)
client --CONNECT fake-host--> SpikeHandler (ValidatedDial TcpStream::connect(ip)) --> origin (passthrough)
client --CONNECT + TLS------> Hudsucker MITM (rcgen cert) --HttpsConnector<ValidatedDial>--> HTTPS origin
```
## capture_quality implications

- `header_names`: lowercased by Hyper (`http::HeaderName`)
- `header_order`: best-effort insertion order via `HeaderMap::iter` / `get_all`
- `header_case`: wire case not available after parse unless using Hyper HTTP/1 case maps (`preserve_header_case`); Hudsucker enables this on default client/server builders
- `cookie_headers`: joined by `hudsucker::normalize_request` before upstream
- `host_header`: stripped then re-added by Hyper client
- `body_representation`: raw frames when decoder feature is off; capture buffer capped at BODY_CAP with `total_seen` for overflow labeling
- `dial_policy`: ValidatedDial only; no second DNS lookup on proven paths
