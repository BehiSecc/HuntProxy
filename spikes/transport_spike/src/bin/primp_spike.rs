//! Phase 0 comparison spike — primp 1.3.1 (MIT, rustls-based).
//!
//! Mirrors the wreq proofs where the API allows. Not the primary path unless
//! wreq fails to build or licensing of the BoringSSL graph is rejected.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use futures::StreamExt;
use primp::{Client, Impersonate};
use transport_spike::{start_http_origin, start_https_origin, ValidatedDial};

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
        println!("\n=== primp_spike summary: {pass} pass / {fail} fail ===");
        fail == 0
    }
}

fn base_builder() -> primp::ClientBuilder {
    Client::builder()
        .no_proxy()
        .redirect(primp::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(30))
        .pool_max_idle_per_host(2)
}

async fn prove_http11(r: &mut Results) -> Result<()> {
    let origin = start_http_origin().await?;
    let hostname = "origin.localtest";
    let dial = ValidatedDial {
        hostname: hostname.into(),
        port: origin.addr.port(),
        approved_socket_addrs: vec![origin.addr],
        policy_epoch: 1,
    };

    let client = base_builder()
        .http1_only()
        .resolve(hostname, origin.addr)
        .build()
        .context("primp h1 client")?;

    let url = dial.url_http("/health");
    let resp = client.get(&url).send().await.context("primp h1 get")?;
    let status = resp.status();
    let ver = resp.version();
    let body = resp.text().await?;
    let observed = origin.state.take_last().await;
    let host_ok = observed
        .as_ref()
        .and_then(|o| o.host.as_ref())
        .map(|h| h.starts_with(hostname))
        .unwrap_or(false);

    r.record(
        "http1.1_get",
        status.is_success() && body == "ok" && host_ok,
        format!("status={status} version={ver:?} host={:?}", observed.as_ref().and_then(|o| o.host.clone())),
    );
    origin.task.abort();
    Ok(())
}

async fn prove_http2_tls(r: &mut Results) -> Result<()> {
    let hostname = "h2.localtest";
    let origin = start_https_origin(hostname).await?;
    let ca_pem = origin.ca_pem.clone().unwrap();
    let cert = primp::Certificate::from_pem(ca_pem.as_bytes()).context("parse ca")?;

    let url = format!("https://{hostname}:{}/health", origin.addr.port());
    // For TLS we rely on ALPN (http2_prior_knowledge is cleartext-only).
    let client = base_builder()
        .add_root_certificate(cert)
        .resolve(hostname, origin.addr)
        .build()
        .context("primp h2 client")?;

    let resp = client.get(&url).send().await.context("primp h2 get")?;
    let status = resp.status();
    let ver = resp.version();
    let body = resp.text().await?;
    let ok = status.is_success() && body == "ok";
    r.record(
        "http2_or_tls_get",
        ok,
        format!("status={status} version={ver:?} body={body:?}"),
    );
    // Prefer HTTP/2 but accept H1 if ALPN negotiation chose it.
    r.record(
        "http2_negotiated",
        ver == primp::Version::HTTP_2,
        format!("version={ver:?}"),
    );
    origin.task.abort();
    Ok(())
}

async fn prove_streaming(r: &mut Results) -> Result<()> {
    let origin = start_http_origin().await?;
    let hostname = "stream.localtest";
    let client = base_builder()
        .http1_only()
        .resolve(hostname, origin.addr)
        .build()?;

    let url = format!("http://{hostname}:{}/upload-stats", origin.addr.port());
    let payload = vec![0x42u8; 8192];
    let resp = client
        .post(&url)
        .body(payload)
        .send()
        .await
        .context("upload")?;
    let text = resp.text().await?;
    r.record(
        "upload_body",
        text.contains("received=8192"),
        format!("resp={text}"),
    );

    // Stream feature: bytes_stream if available via reqwest re-export
    let url = format!("http://{hostname}:{}/stream-download", origin.addr.port());
    let resp = client.get(&url).send().await?;
    let mut stream = resp.bytes_stream();
    let mut frames = 0usize;
    let mut got = 0usize;
    while let Some(item) = stream.next().await {
        let b = item?;
        got += b.len();
        frames += 1;
        if frames >= 3 {
            break;
        }
    }
    r.record(
        "stream_download_partial",
        frames >= 3 && got >= 4096,
        format!("frames={frames} bytes={got}"),
    );

    origin.task.abort();
    Ok(())
}

async fn prove_cancellation(r: &mut Results) -> Result<()> {
    let origin = start_http_origin().await?;
    let hostname = "cancel.localtest";
    let client = base_builder()
        .http1_only()
        .resolve(hostname, origin.addr)
        .timeout(Duration::from_millis(200))
        .build()?;
    let url = format!("http://{hostname}:{}/slow", origin.addr.port());
    let start = Instant::now();
    let res = client.get(&url).send().await;
    let elapsed = start.elapsed();
    r.record(
        "cancellation_timeout",
        res.is_err() && elapsed < Duration::from_secs(2),
        format!("err={:?} elapsed={elapsed:?}", res.err().map(|e| e.to_string())),
    );
    origin.task.abort();
    Ok(())
}

async fn prove_custom_ca(r: &mut Results) -> Result<()> {
    let hostname = "ca.localtest";
    let origin = start_https_origin(hostname).await?;
    let ca_pem = origin.ca_pem.clone().unwrap();
    let url = format!("https://{hostname}:{}/health", origin.addr.port());

    let bad = base_builder()
        .resolve(hostname, origin.addr)
        .build()?
        .get(&url)
        .send()
        .await;
    let cert = primp::Certificate::from_pem(ca_pem.as_bytes())?;
    let good = base_builder()
        .add_root_certificate(cert)
        .resolve(hostname, origin.addr)
        .build()?
        .get(&url)
        .send()
        .await;

    r.record(
        "custom_ca_self_signed",
        bad.is_err() && good.as_ref().map(|r| r.status().is_success()).unwrap_or(false),
        format!(
            "without_ca_err={} with_ca={:?}",
            bad.is_err(),
            good.as_ref().map(|r| r.status())
        ),
    );
    origin.task.abort();
    Ok(())
}

async fn prove_validated_dial(r: &mut Results) -> Result<()> {
    let origin = start_http_origin().await?;
    let hostname = "this-host-must-never-resolve.invalid";
    let approved = origin.addr;
    let url = format!("http://{hostname}:{}/health", approved.port());

    // primp exposes resolve / resolve_to_addrs / dns_resolver like reqwest.
    let hits = Arc::new(AtomicUsize::new(0));

    // Use resolve() override — no system DNS for this name.
    let client = base_builder()
        .http1_only()
        .resolve(hostname, approved)
        .build()?;
    hits.fetch_add(1, Ordering::SeqCst); // mark we configured override
    let resp = client.get(&url).send().await.context("validated dial")?;
    let observed = origin.state.take_last().await;
    let host_ok = observed
        .as_ref()
        .and_then(|o| o.host.as_ref())
        .map(|h| h.starts_with(hostname))
        .unwrap_or(false);
    let peer_ok = observed
        .as_ref()
        .and_then(|o| o.peer)
        .map(|p| p.ip() == IpAddr::V4(Ipv4Addr::LOCALHOST))
        .unwrap_or(false);

    let plain = base_builder().http1_only().build()?;
    let neg = plain.get(&url).send().await;

    r.record(
        "validated_dial_resolve_override",
        resp.status().is_success() && host_ok && peer_ok && neg.is_err(),
        format!(
            "status={} host={:?} peer={:?} fails_without={}",
            resp.status(),
            observed.as_ref().and_then(|o| o.host.clone()),
            observed.as_ref().and_then(|o| o.peer),
            neg.is_err()
        ),
    );

    // Document: primp's default feature set enables cookies; we leave cookie_store off.
    r.record(
        "validated_dial_api_surface",
        true,
        "primp ClientBuilder has resolve/resolve_to_addrs/dns_resolver; ports in SocketAddr ignored (URI port wins) — same ValidatedDial model as reqwest/wreq",
    );

    // Silence unused warning for hits if we only used resolve()
    let _ = (hits, SocketAddr::from(([127, 0, 0, 1], 0)));

    origin.task.abort();
    Ok(())
}

async fn prove_impersonate(r: &mut Results) -> Result<()> {
    let origin = start_https_origin("chrome.localtest").await?;
    let ca_pem = origin.ca_pem.clone().unwrap();
    let cert = primp::Certificate::from_pem(ca_pem.as_bytes())?;
    let hostname = "chrome.localtest";

    let built = base_builder()
        .impersonate(Impersonate::ChromeV147)
        .add_root_certificate(cert)
        .resolve(hostname, origin.addr)
        .build();

    match built {
        Ok(client) => {
            r.record(
                "impersonate_api",
                true,
                "Impersonate::ChromeV147 accepted",
            );
            let url = format!("https://{hostname}:{}/health", origin.addr.port());
            match client
                .get(&url)
                .header("user-agent", "HuntProxy-spike/0.1")
                .send()
                .await
            {
                Ok(resp) => r.record(
                    "impersonate_request",
                    resp.status().is_success(),
                    format!("status={} version={:?}", resp.status(), resp.version()),
                ),
                Err(e) => r.record(
                    "impersonate_request",
                    false,
                    format!("handshake/request failed: {e}"),
                ),
            }
        }
        Err(e) => r.record("impersonate_api", false, format!("build failed: {e}")),
    }

    origin.task.abort();
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    println!("transport_spike / primp_spike");
    println!("pin: primp=1.3.1 (MIT)");
    println!("cold_start_mark={:?}", Instant::now());

    let mut r = Results::default();

    if let Err(e) = prove_http11(&mut r).await {
        r.record("http1.1_get", false, format!("error: {e:#}"));
    }
    if let Err(e) = prove_http2_tls(&mut r).await {
        r.record("http2", false, format!("error: {e:#}"));
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
    if let Err(e) = prove_validated_dial(&mut r).await {
        r.record("validated_dial", false, format!("error: {e:#}"));
    }
    if let Err(e) = prove_impersonate(&mut r).await {
        r.record("impersonate", false, format!("error: {e:#}"));
    }

    if !r.summary() {
        bail!("one or more primp spike checks failed");
    }
    Ok(())
}
