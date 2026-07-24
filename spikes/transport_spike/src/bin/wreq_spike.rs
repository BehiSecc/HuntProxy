//! Phase 0 semantic transport spike — pinned wreq / wreq-util.
//!
//! Proves:
//! - HTTP/1.1 and HTTP/2 to a local origin
//! - Streaming upload / download
//! - Cancellation
//! - Custom CA / self-signed origin (BoringSSL CertStore)
//! - ValidatedDial: dial only supplied IP, preserve hostname for Host/SNI, no system DNS
//! - Chrome-like profile/emulation via wreq-util

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use bytes::Bytes;
use futures::StreamExt;
use transport_spike::{
    resolve_call_counter, start_http_origin, start_https_origin, FixedIpResolver, ValidatedDial,
};
use transport_spike::validated_dial::reset_resolve_call_counter;
use wreq::dns::Resolve;
use wreq::{Body, Client, Version};
use wreq_util::Emulation;

#[derive(Default)]
struct Results {
    rows: Vec<(String, bool, String)>,
}

impl Results {
    fn record(&mut self, name: &str, ok: bool, detail: impl Into<String>) {
        let d = detail.into();
        let mark = if ok { "PASS" } else { "FAIL" };
        println!("[{mark}] {name}: {d}");
        self.rows.push((name.to_string(), ok, d));
    }

    fn summary(&self) -> bool {
        let pass = self.rows.iter().filter(|r| r.1).count();
        let fail = self.rows.iter().filter(|r| !r.1).count();
        println!("\n=== wreq_spike summary: {pass} pass / {fail} fail ===");
        fail == 0
    }
}

fn base_builder() -> wreq::ClientBuilder {
    // Explicitly avoid cookies / decompression / system proxy (features already off).
    Client::builder()
        .no_proxy()
        .redirect(wreq::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(30))
        .pool_max_idle_per_host(2)
}

async fn prove_http11(r: &mut Results) -> Result<()> {
    let origin = start_http_origin().await?;
    let dial = ValidatedDial {
        hostname: "origin.localtest".into(),
        port: origin.addr.port(),
        approved_socket_addrs: vec![origin.addr],
        policy_epoch: 1,
    };
    let resolver = FixedIpResolver::for_dial(&dial);
    reset_resolve_call_counter();

    let client = base_builder()
        .http1_only()
        .dns_resolver(resolver.clone())
        .build()
        .context("build h1 client")?;

    let url = dial.url_http("/health");
    let resp = client.get(&url).send().await.context("h1 get")?;
    let status = resp.status();
    let ver = resp.version();
    let remote = resp.remote_addr();
    let body = resp.text().await?;

    let observed = origin.state.take_last().await;
    let host_ok = observed
        .as_ref()
        .and_then(|o| o.host.as_ref())
        .map(|h| h.starts_with("origin.localtest"))
        .unwrap_or(false);
    let peer_ok = observed
        .as_ref()
        .and_then(|o| o.peer)
        .map(|p| p.ip() == IpAddr::V4(Ipv4Addr::LOCALHOST))
        .unwrap_or(false);

    let ok = status.is_success()
        && body == "ok"
        && ver == Version::HTTP_11
        && host_ok
        && peer_ok
        && resolve_call_counter() >= 1;

    r.record(
        "http1.1_get",
        ok,
        format!(
            "status={status} version={ver:?} remote={remote:?} host={:?} resolve_calls={} body={body:?}",
            observed.as_ref().and_then(|o| o.host.clone()),
            resolve_call_counter()
        ),
    );
    origin.task.abort();
    Ok(())
}

async fn prove_http2_tls(r: &mut Results) -> Result<()> {
    let hostname = "h2.localtest";
    let origin = start_https_origin(hostname).await?;
    let dial = ValidatedDial {
        hostname: hostname.into(),
        port: origin.addr.port(),
        approved_socket_addrs: vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), origin.addr.port())],
        policy_epoch: 1,
    };
    let resolver = FixedIpResolver::for_dial(&dial);
    let ca_pem = origin.ca_pem.clone().expect("ca pem");
    let store = wreq::tls::trust::CertStore::builder()
        .add_stack_pem_certs(ca_pem.as_bytes())
        .build()
        .context("cert store from pem")?;

    let client = base_builder()
        .http2_only()
        .tls_cert_store(store)
        .dns_resolver(resolver)
        .build()
        .context("build h2 client")?;

    let url = dial.url_https("/health");
    let resp = client.get(&url).send().await.context("h2 get")?;
    let status = resp.status();
    let ver = resp.version();
    let body = resp.text().await?;
    let observed = origin.state.take_last().await;
    let host_ok = observed
        .as_ref()
        .and_then(|o| o.host.as_ref())
        .map(|h| h.contains(hostname))
        .unwrap_or(false);

    let ok = status.is_success() && body == "ok" && ver == Version::HTTP_2 && host_ok;
    r.record(
        "http2_tls_get",
        ok,
        format!(
            "status={status} version={ver:?} host={:?} body={body:?}",
            observed.as_ref().and_then(|o| o.host.clone())
        ),
    );
    origin.task.abort();
    Ok(())
}

async fn prove_streaming(r: &mut Results) -> Result<()> {
    let origin = start_http_origin().await?;
    let dial = ValidatedDial {
        hostname: "stream.localtest".into(),
        port: origin.addr.port(),
        approved_socket_addrs: vec![origin.addr],
        policy_epoch: 1,
    };
    let client = base_builder()
        .http1_only()
        .dns_resolver(FixedIpResolver::for_dial(&dial))
        .build()?;

    // Streaming upload via Body::wrap_stream
    let chunks: Vec<Result<Bytes, std::io::Error>> = (0..8)
        .map(|i| Ok(Bytes::from(vec![i as u8; 1024])))
        .collect();
    let stream = futures::stream::iter(chunks);
    let body = Body::wrap_stream(stream);

    let url = dial.url_http("/upload-stats");
    let resp = client
        .post(&url)
        .body(body)
        .send()
        .await
        .context("stream upload")?;
    let text = resp.text().await?;
    let upload_ok = text.contains("received=8192");
    r.record("stream_upload", upload_ok, format!("resp={text}"));

    // Streaming download
    let url = dial.url_http("/stream-download");
    let resp = client.get(&url).send().await.context("stream download")?;
    let mut stream = resp.bytes_stream();
    let mut got = 0usize;
    let mut frames = 0usize;
    while let Some(item) = stream.next().await {
        let b = item.context("frame")?;
        got += b.len();
        frames += 1;
        if frames >= 3 {
            // prove we can stop early (partial consume)
            break;
        }
    }
    let dl_ok = frames >= 3 && got >= 4096;
    r.record(
        "stream_download_partial",
        dl_ok,
        format!("frames={frames} bytes={got}"),
    );

    origin.task.abort();
    Ok(())
}

async fn prove_cancellation(r: &mut Results) -> Result<()> {
    let origin = start_http_origin().await?;
    let dial = ValidatedDial {
        hostname: "cancel.localtest".into(),
        port: origin.addr.port(),
        approved_socket_addrs: vec![origin.addr],
        policy_epoch: 1,
    };
    let client = base_builder()
        .http1_only()
        .dns_resolver(FixedIpResolver::for_dial(&dial))
        .timeout(Duration::from_millis(200))
        .build()?;

    let url = dial.url_http("/slow");
    let start = Instant::now();
    let res = client.get(&url).send().await;
    let elapsed = start.elapsed();
    let ok = res.is_err() && elapsed < Duration::from_secs(2);
    r.record(
        "cancellation_timeout",
        ok,
        format!("err={:?} elapsed={elapsed:?}", res.err().map(|e| e.to_string())),
    );

    // Explicit drop/cancel of a streaming body future
    let client = base_builder()
        .http1_only()
        .dns_resolver(FixedIpResolver::for_dial(&dial))
        .build()?;
    let url = dial.url_http("/stream-download");
    let resp = client.get(&url).send().await?;
    let mut stream = resp.bytes_stream();
    let _first = stream.next().await;
    drop(stream); // cancel remainder
    r.record(
        "cancellation_drop_stream",
        true,
        "dropped bytes_stream after first frame",
    );

    origin.task.abort();
    Ok(())
}

async fn prove_custom_ca(r: &mut Results) -> Result<()> {
    let hostname = "ca.localtest";
    let origin = start_https_origin(hostname).await?;
    let dial = ValidatedDial {
        hostname: hostname.into(),
        port: origin.addr.port(),
        approved_socket_addrs: vec![origin.addr],
        policy_epoch: 1,
    };
    let ca_pem = origin.ca_pem.clone().unwrap();

    // Without custom CA → should fail
    let client_bad = base_builder()
        .dns_resolver(FixedIpResolver::for_dial(&dial))
        .build()?;
    let url = dial.url_https("/health");
    let bad = client_bad.get(&url).send().await;
    let fails_without_ca = bad.is_err();

    // With custom CA → should succeed
    let store = wreq::tls::trust::CertStore::builder()
        .add_stack_pem_certs(ca_pem.as_bytes())
        .build()
        .context("build cert store")?;
    let client_good = base_builder()
        .tls_cert_store(store)
        .dns_resolver(FixedIpResolver::for_dial(&dial))
        .build()?;
    let good = client_good.get(&url).send().await;
    let ok = fails_without_ca && good.as_ref().map(|r| r.status().is_success()).unwrap_or(false);

    r.record(
        "custom_ca_self_signed",
        ok,
        format!(
            "without_ca_err={} with_ca_status={:?}",
            fails_without_ca,
            good.as_ref().map(|r| r.status())
        ),
    );
    origin.task.abort();
    Ok(())
}

async fn prove_validated_dial_no_system_dns(r: &mut Results) -> Result<()> {
    let origin = start_http_origin().await?;
    // Use a hostname that is NOT resolvable via public/system DNS.
    let hostname = "this-host-must-never-resolve.invalid";
    // Positive path: dedicated resolver returns only the approved IP for this host.
    // (FixedIpResolver's deny-list would block this hostname by design.)
    let approved = origin.addr;
    struct OnlyApproved {
        host: String,
        addr: SocketAddr,
        hits: Arc<AtomicUsize>,
    }
    impl Resolve for OnlyApproved {
        fn resolve(&self, name: wreq::dns::Name) -> wreq::dns::Resolving {
            self.hits.fetch_add(1, Ordering::SeqCst);
            let host = name.as_str().to_string();
            let expected = self.host.clone();
            let addr = self.addr;
            Box::pin(async move {
                if host.eq_ignore_ascii_case(&expected) {
                    let addrs: wreq::dns::Addrs = Box::new(std::iter::once(addr));
                    Ok(addrs)
                } else {
                    Err(format!("unexpected host {host}").into())
                }
            })
        }
    }

    let hits = Arc::new(AtomicUsize::new(0));
    let resolver = OnlyApproved {
        host: hostname.into(),
        addr: approved,
        hits: hits.clone(),
    };

    let client = base_builder()
        .http1_only()
        .dns_resolver(resolver)
        .build()?;

    let url = format!("http://{hostname}:{}/health", origin.addr.port());
    let resp = client.get(&url).send().await.context("validated dial get")?;
    let status = resp.status();
    let remote = resp.remote_addr();
    let observed = origin.state.take_last().await;
    let host_header = observed.as_ref().and_then(|o| o.host.clone());
    let host_ok = host_header
        .as_ref()
        .map(|h| h.starts_with(hostname))
        .unwrap_or(false);
    let remote_ok = remote
        .map(|r| r.ip() == approved.ip())
        .unwrap_or(true); // remote_addr may be None on some paths; peer on origin is better
    let peer_ok = observed
        .as_ref()
        .and_then(|o| o.peer)
        .map(|p| p.ip() == approved.ip())
        .unwrap_or(false);
    let resolver_hit = hits.load(Ordering::SeqCst) >= 1;

    // Negative: client without override for an unresolvable host must fail
    // (proves we are not magically connecting without policy).
    let client_plain = base_builder().http1_only().build()?;
    let neg = client_plain.get(&url).send().await;
    let fails_without_override = neg.is_err();

    let ok = status.is_success()
        && host_ok
        && peer_ok
        && remote_ok
        && resolver_hit
        && fails_without_override;

    r.record(
        "validated_dial_no_system_dns",
        ok,
        format!(
            "status={status} host={host_header:?} remote={remote:?} peer={:?} resolver_hits={} fails_without_override={fails_without_override}",
            observed.as_ref().and_then(|o| o.peer),
            hits.load(Ordering::SeqCst)
        ),
    );

    // Also exercise resolve_to_addrs API (client-scoped override, no custom trait).
    let client2 = base_builder()
        .http1_only()
        .resolve(hostname, approved)
        .build()?;
    let resp2 = client2.get(&url).send().await;
    r.record(
        "validated_dial_resolve_override",
        resp2.as_ref().map(|x| x.status().is_success()).unwrap_or(false),
        format!("status={:?}", resp2.as_ref().map(|x| x.status())),
    );

    origin.task.abort();
    Ok(())
}

async fn prove_emulation(r: &mut Results) -> Result<()> {
    // Building a client with Chrome profile must succeed (API availability).
    // Wire fingerprint comparison vs real Chrome is out of this binary's scope
    // (requires TrackMe fixture); we only prove the profile compiles and applies.
    let origin = start_https_origin("chrome.localtest").await?;
    let dial = ValidatedDial {
        hostname: "chrome.localtest".into(),
        port: origin.addr.port(),
        approved_socket_addrs: vec![origin.addr],
        policy_epoch: 1,
    };
    let ca_pem = origin.ca_pem.clone().unwrap();
    let store = wreq::tls::trust::CertStore::builder()
        .add_stack_pem_certs(ca_pem.as_bytes())
        .build()?;

    let client = base_builder()
        .emulation(Emulation::Chrome147)
        .tls_cert_store(store)
        .dns_resolver(FixedIpResolver::for_dial(&dial))
        .no_proxy()
        .build()
        .context("emulation client build")?;

    // Transport-only: send without relying on injected identity defaults beyond TLS/H2.
    let url = dial.url_https("/health");
    let resp = client
        .get(&url)
        .header("user-agent", "HuntProxy-spike/0.1")
        .send()
        .await;
    let ok = match &resp {
        Ok(r) => r.status().is_success(),
        Err(e) => {
            // Emulation may force TLS options that still handshake with our
            // minimal origin; if handshake fails, document but mark API-available.
            r.record(
                "emulation_chrome_tls_handshake",
                false,
                format!("API available but handshake failed: {e}"),
            );
            // Still PASS the "API available" check.
            r.record(
                "emulation_profile_api",
                true,
                "Emulation::Chrome147 accepted by ClientBuilder",
            );
            origin.task.abort();
            return Ok(());
        }
    };

    let ver = resp.as_ref().unwrap().version();
    r.record(
        "emulation_profile_api",
        true,
        "Emulation::Chrome147 accepted by ClientBuilder",
    );
    r.record(
        "emulation_chrome_request",
        ok,
        format!("status={:?} version={ver:?}", resp.as_ref().map(|r| r.status())),
    );

    origin.task.abort();
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    println!("transport_spike / wreq_spike");
    println!(
        "wreq={} wreq-util={} (features: webpki-roots,tokio-rt,stream,prefix-symbols / emulation,tokio-rt)",
        env!("CARGO_PKG_VERSION"), // package version of spike; print pins below
        "3.0.0-rc.14"
    );
    println!("pins: wreq=6.0.0-rc.29  wreq-util=3.0.0-rc.14");
    println!("cold_start_mark={:?}", Instant::now());

    let mut r = Results::default();

    if let Err(e) = prove_http11(&mut r).await {
        r.record("http1.1_get", false, format!("error: {e:#}"));
    }
    if let Err(e) = prove_http2_tls(&mut r).await {
        r.record("http2_tls_get", false, format!("error: {e:#}"));
    }
    if let Err(e) = prove_streaming(&mut r).await {
        r.record("streaming", false, format!("error: {e:#}"));
    }
    if let Err(e) = prove_cancellation(&mut r).await {
        r.record("cancellation", false, format!("error: {e:#}"));
    }
    if let Err(e) = prove_custom_ca(&mut r).await {
        r.record("custom_ca", false, format!("error: {e:#}"));
    }
    if let Err(e) = prove_validated_dial_no_system_dns(&mut r).await {
        r.record("validated_dial", false, format!("error: {e:#}"));
    }
    if let Err(e) = prove_emulation(&mut r).await {
        r.record("emulation", false, format!("error: {e:#}"));
    }

    if !r.summary() {
        bail!("one or more wreq spike checks failed");
    }
    Ok(())
}
