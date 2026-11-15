//! Measures what representative agent workflows cost in tool round trips and
//! returned bytes, and guards the output budget against regressions.
//!
//! The workflows mirror how agents were observed using the MCP tools: triage a
//! busy host, page through its history, read an exchange with both bodies,
//! re-read an evidence set, find a string in a large script, list scripts and
//! routes, and send a query with an over-escaped quote.
//!
//! Run with `cargo test --test agent_output_cost -- --nocapture` to print the
//! cost table.

use huntproxy::app::{bootstrap_state, AppState};
use huntproxy::config::Config;
use huntproxy::domain::*;
use huntproxy::mcp::call_tool;
use huntproxy::storage::NewExchange;
use serde_json::{json, Value};
use std::sync::Arc;
use tempfile::TempDir;

/// Every tool result must fit this many bytes of compact JSON.
const OUTPUT_BUDGET: usize = 24_000;
/// Smallest size at which an observed MCP client clips a result mid-JSON.
const CLIENT_CLIP: usize = 32_768;

const APP_HOST: &str = "app.example.test";
const STATIC_HOST: &str = "static.example.test";
const API_EXCHANGES: usize = 600;
const SCRIPT_FILES: usize = 300;
const NEEDLE: &str = "needle_token_42";

struct Workflow {
    name: &'static str,
    calls: usize,
    bytes: usize,
    largest: usize,
    clipped: usize,
}

impl Workflow {
    fn new(name: &'static str) -> Self {
        Self {
            name,
            calls: 0,
            bytes: 0,
            largest: 0,
            clipped: 0,
        }
    }

    /// Calls a tool and records what the agent would receive, error or not.
    async fn call(
        &mut self,
        state: &Arc<AppState>,
        name: &str,
        args: Value,
    ) -> DomainResult<Value> {
        let result = call_tool(state.clone(), name, args).await;
        let size = match &result {
            Ok(value) => serde_json::to_string(value).unwrap().len(),
            Err(error) => error.to_string().len(),
        };
        self.calls += 1;
        self.bytes += size;
        self.largest = self.largest.max(size);
        if size > CLIENT_CLIP {
            self.clipped += 1;
        }
        result
    }
}

fn header(name: &str, value: &str, ordinal: u32) -> HeaderEntry {
    HeaderEntry {
        name: name.into(),
        value: value.as_bytes().to_vec(),
        ordinal,
    }
}

fn request_headers(host: &str, json_body: bool) -> Vec<HeaderEntry> {
    let mut headers = vec![
        ("host", host),
        (
            "user-agent",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36",
        ),
        ("accept", "application/json, text/plain, */*"),
        ("accept-language", "en-US,en;q=0.9"),
        ("accept-encoding", "gzip, deflate, br, zstd"),
        ("cookie", "sid=fixture-session; theme=dark"),
        ("authorization", "Bearer fixture-token"),
        ("origin", "https://app.example.test"),
        ("referer", "https://app.example.test/dashboard"),
        ("sec-ch-ua", "\"Chromium\";v=\"156\", \"Not:A-Brand\";v=\"8\""),
        ("sec-ch-ua-mobile", "?0"),
        ("sec-ch-ua-platform", "\"Linux\""),
        ("sec-fetch-dest", "empty"),
        ("sec-fetch-mode", "cors"),
        ("sec-fetch-site", "same-origin"),
        ("x-requested-with", "XMLHttpRequest"),
    ];
    if json_body {
        headers.push(("content-type", "application/json"));
    }
    headers
        .into_iter()
        .enumerate()
        .map(|(ordinal, (name, value))| header(name, value, ordinal as u32))
        .collect()
}

fn response_headers(content_type: &str) -> Vec<HeaderEntry> {
    [
        ("content-type", content_type),
        ("date", "Mon, 09 Nov 2026 06:57:47 GMT"),
        (
            "cache-control",
            "no-cache, no-store, max-age=0, must-revalidate",
        ),
        ("x-content-type-options", "nosniff"),
        ("x-frame-options", "SAMEORIGIN"),
        (
            "strict-transport-security",
            "max-age=31536000; includeSubDomains",
        ),
        ("server", "fixture"),
        ("alt-svc", "h3=\":443\"; ma=2592000"),
        (
            "set-cookie",
            "sid=fixture-session; Path=/; Secure; HttpOnly",
        ),
        ("vary", "Origin, X-Origin, Referer"),
        (
            "content-security-policy",
            "default-src 'self'; script-src 'self' https://static.example.test; report-uri /csp",
        ),
    ]
    .into_iter()
    .enumerate()
    .map(|(ordinal, (name, value))| header(name, value, ordinal as u32))
    .collect()
}

/// A JSON document of roughly `target` bytes.
fn json_body(seed: usize, target: usize) -> Vec<u8> {
    let mut items = Vec::new();
    let mut size = 0;
    let mut index = 0;
    while size < target {
        let item = json!({
            "id": seed * 1000 + index,
            "name": format!("item-{seed}-{index}"),
            "owner": format!("user-{}", (seed + index) % 17),
            "tags": ["alpha", "beta"],
            "updated_at": "2026-11-09T06:57:47Z"
        });
        size += item.to_string().len() + 1;
        items.push(item);
        index += 1;
    }
    json!({ "items": items, "next_page": null })
        .to_string()
        .into_bytes()
}

fn script_body(target: usize, needle_at: Option<usize>) -> Vec<u8> {
    let mut body = String::with_capacity(target + 64);
    let mut index = 0;
    while body.len() < target {
        if needle_at.is_some_and(|at| body.len() >= at && !body.contains(NEEDLE)) {
            body.push_str(&format!("var {NEEDLE}=\"/api/v2/internal/export\";\n"));
        }
        body.push_str(&format!(
            "function f{index}(a,b){{return a.concat(b).map(function(x){{return x*{index};}});}}\n"
        ));
        index += 1;
    }
    body.into_bytes()
}

fn base_exchange(project_id: ProjectId, host: &str, method: &str, path: &str) -> NewExchange {
    NewExchange {
        project_id,
        source: ExchangeSource::Proxy,
        protocol: "HTTP/2".into(),
        method: method.into(),
        scheme: "https".into(),
        authority: host.into(),
        host: host.into(),
        port: 443,
        path: path.into(),
        query: None,
        status_code: Some(200),
        mime: Some("application/json; charset=utf-8".into()),
        completion: CompletionState::Complete,
        capture_quality: CaptureQuality::Semantic,
        header_representation: HeaderRepresentation::Semantic,
        body_representation: BodyRepresentation::SemanticEncoded,
        cache_provenance: CacheProvenance::None,
        transport_provenance: Some(TransportProvenance::ProtocolProfileOnly),
        transport_profile: Some("fixture".into()),
        request_headers: request_headers(host, method != "GET"),
        response_headers: response_headers("application/json; charset=utf-8"),
        request_body: None,
        response_body: None,
        duration_ms: Some(42),
        lineage: ExchangeLineage::default(),
        page_title: None,
        error_message: None,
    }
}

struct Fixture {
    _directory: TempDir,
    state: Arc<AppState>,
    project_id: ProjectId,
    /// POST exchanges with a request body and a mid-sized response body.
    evidence: Vec<i64>,
    bundle: i64,
}

async fn fixture() -> Fixture {
    let directory = tempfile::tempdir().unwrap();
    let config = Config {
        data_dir: directory.path().to_path_buf(),
        spool_dir: directory.path().join("spool"),
        export_dir: directory.path().join("exports"),
        runtime_dir: directory.path().join("runtime"),
        plugin_dir: directory.path().join("plugins"),
        ..Config::default()
    };
    let state = bootstrap_state(config).await.unwrap();
    let project = state
        .db
        .create_project(CreateProjectRequest {
            name: "Agent output cost".into(),
            target_url: format!("https://{APP_HOST}/"),
            advanced: None,
        })
        .await
        .unwrap();
    let project_id = project.id;

    let resources = [
        "accounts",
        "campaigns",
        "creatives",
        "reports",
        "users",
        "assets",
    ];
    let statuses = [200, 200, 200, 302, 403, 404, 500, 200];
    let response_sizes = [180, 700, 2_400, 9_000];
    let mut evidence = Vec::new();
    for index in 0..API_EXCHANGES {
        let post = index % 3 == 0;
        let resource = resources[index % resources.len()];
        let mut exchange = base_exchange(
            project_id,
            APP_HOST,
            if post { "POST" } else { "GET" },
            &format!("/api/v{}/{resource}/{}", 1 + index % 2, 1000 + index),
        );
        if index % 4 == 0 {
            exchange.query = Some(format!("view=full&page={}&rpcids=r{index}", index % 9));
        }
        exchange.status_code = Some(statuses[index % statuses.len()]);
        exchange.response_body = Some(json_body(
            index,
            response_sizes[index % response_sizes.len()],
        ));
        if post {
            exchange.request_body = Some(json_body(index, 300 + (index % 5) * 150));
        }
        let mid_sized_response = response_sizes[index % response_sizes.len()] == 2_400;
        let id = state.db.insert_exchange(exchange).await.unwrap().get();
        if post && mid_sized_response && evidence.len() < 8 {
            evidence.push(id);
        }
    }
    assert_eq!(evidence.len(), 8);

    for index in 0..SCRIPT_FILES {
        let mut exchange = base_exchange(
            project_id,
            STATIC_HOST,
            "GET",
            &format!(
                "/assets/chunk-{index}.{:08x}.js",
                index * 2_654_435_761_usize % 0xffff_ffff
            ),
        );
        exchange.mime = Some("text/javascript".into());
        exchange.response_headers = response_headers("text/javascript");
        exchange.response_body = Some(script_body(2_000, None));
        state.db.insert_exchange(exchange).await.unwrap();
    }
    let mut bundle = base_exchange(project_id, STATIC_HOST, "GET", "/assets/main.bundle.js");
    bundle.mime = Some("text/javascript".into());
    bundle.response_headers = response_headers("text/javascript");
    bundle.response_body = Some(script_body(300_000, Some(165_000)));
    let bundle = state.db.insert_exchange(bundle).await.unwrap().get();

    Fixture {
        _directory: directory,
        state,
        project_id,
        evidence,
        bundle,
    }
}

/// What this build of the tools can do in one call, so each workflow takes
/// the shortest path the tools offer.
struct Capabilities {
    inline_bodies: bool,
    batch_read: bool,
    body_search: bool,
    lenient_quotes: bool,
}

async fn probe(fixture: &Fixture) -> Capabilities {
    let state = &fixture.state;
    let project = fixture.project_id.get();
    let one = call_tool(
        state.clone(),
        "exchange_get",
        json!({"project_id": project, "exchange_id": fixture.evidence[0]}),
    )
    .await
    .unwrap();
    let batch = call_tool(
        state.clone(),
        "exchange_get",
        json!({"project_id": project, "exchange_ids": fixture.evidence}),
    )
    .await;
    let search = call_tool(
        state.clone(),
        "exchange_body",
        json!({"project_id": project, "exchange_id": fixture.bundle, "search": NEEDLE}),
    )
    .await;
    let quoted = call_tool(
        state.clone(),
        "history_search",
        json!({"project_id": project, "q": "path:~\\\"api/v2\" method:POST", "limit": 5}),
    )
    .await;
    Capabilities {
        inline_bodies: one.get("response_body").is_some(),
        batch_read: batch.is_ok_and(|value| value.get("exchanges").is_some()),
        body_search: search.is_ok_and(|value| value.get("matches").is_some()),
        lenient_quotes: quoted.is_ok_and(|page| has_rows(&page)),
    }
}

fn has_rows(page: &Value) -> bool {
    page["items"]
        .as_array()
        .is_some_and(|items| !items.is_empty())
}

/// Reads one exchange with its headers and both bodies.
async fn read_exchange(
    workflow: &mut Workflow,
    fixture: &Fixture,
    capabilities: &Capabilities,
    exchange_id: i64,
) {
    let project = fixture.project_id.get();
    workflow
        .call(
            &fixture.state,
            "exchange_get",
            json!({"project_id": project, "exchange_id": exchange_id}),
        )
        .await
        .unwrap();
    if capabilities.inline_bodies {
        return;
    }
    for side in ["request", "response"] {
        workflow
            .call(
                &fixture.state,
                "exchange_body",
                json!({"project_id": project, "exchange_id": exchange_id, "side": side, "max_bytes": 10_000}),
            )
            .await
            .unwrap();
    }
}

/// Follows a paged listing to its end and returns how many rows it yielded.
async fn page_listing(
    workflow: &mut Workflow,
    fixture: &Fixture,
    tool: &str,
    mut args: Value,
    rows_key: &str,
) -> usize {
    let mut rows = 0;
    for _ in 0..200 {
        let page = workflow
            .call(&fixture.state, tool, args.clone())
            .await
            .unwrap();
        rows += count_rows(&page[rows_key]);
        match page.get("next_offset").filter(|next| !next.is_null()) {
            Some(next) => args["offset"] = next.clone(),
            None => return rows,
        }
    }
    panic!("{tool} listing did not finish paging");
}

/// Counts list rows, or the routes nested under per-host sitemap entries.
fn count_rows(value: &Value) -> usize {
    let Some(items) = value.as_array() else {
        return 0;
    };
    let nested: Vec<usize> = items
        .iter()
        .filter_map(|item| item.get("routes").and_then(Value::as_array))
        .map(Vec::len)
        .collect();
    if nested.is_empty() {
        items.len()
    } else {
        nested.iter().sum()
    }
}

#[tokio::test]
async fn representative_agent_workflows_stay_cheap() {
    let fixture = fixture().await;
    let capabilities = probe(&fixture).await;
    let state = &fixture.state;
    let project = fixture.project_id.get();
    let mut workflows = Vec::new();

    // Triage a busy host the way agents most often ask for it.
    let mut triage = Workflow::new("triage host (limit 100)");
    triage
        .call(
            state,
            "history_search",
            json!({"project_id": project, "q": format!("host:{APP_HOST}"), "limit": 100}),
        )
        .await
        .unwrap();
    workflows.push(triage);

    // Walk the whole host history with the returned cursor.
    let mut walk = Workflow::new("page through host history");
    let mut cursor = Value::Null;
    let mut seen = std::collections::BTreeSet::new();
    for _ in 0..200 {
        let mut args =
            json!({"project_id": project, "q": format!("host:{APP_HOST}"), "limit": 100});
        if !cursor.is_null() {
            args["cursor"] = cursor.clone();
        }
        let page = walk.call(state, "history_search", args).await.unwrap();
        for item in page["items"].as_array().unwrap() {
            assert!(
                seen.insert(item["exchange_id"].as_i64().unwrap()),
                "history paging repeated a row"
            );
        }
        cursor = page["next"].clone();
        if cursor.is_null() {
            break;
        }
    }
    assert_eq!(seen.len(), API_EXCHANGES, "history paging skipped rows");
    workflows.push(walk);

    let mut read_one = Workflow::new("read one exchange with bodies");
    read_exchange(&mut read_one, &fixture, &capabilities, fixture.evidence[0]).await;
    workflows.push(read_one);

    let mut evidence = Workflow::new("re-read evidence set of 8");
    if capabilities.batch_read {
        let batch = evidence
            .call(
                state,
                "exchange_get",
                json!({"project_id": project, "exchange_ids": fixture.evidence}),
            )
            .await
            .unwrap();
        assert_eq!(batch["exchanges"].as_array().unwrap().len(), 8);
        assert!(
            batch
                .get("not_returned")
                .is_none_or(|ids| ids.as_array().is_some_and(Vec::is_empty)),
            "an eight-exchange evidence set must fit one result"
        );
    } else {
        for exchange_id in fixture.evidence.clone() {
            read_exchange(&mut evidence, &fixture, &capabilities, exchange_id).await;
        }
    }
    workflows.push(evidence);

    let mut find = Workflow::new("find string in 300 KB script");
    if capabilities.body_search {
        let found = find
            .call(
                state,
                "exchange_body",
                json!({"project_id": project, "exchange_id": fixture.bundle, "search": NEEDLE}),
            )
            .await
            .unwrap();
        let first = &found["matches"][0];
        assert!(first["context"].as_str().unwrap().contains(NEEDLE));
        // The reported offset must be usable for a plain read.
        let page = call_tool(
            state.clone(),
            "exchange_body",
            json!({"project_id": project, "exchange_id": fixture.bundle, "offset": first["offset"], "max_bytes": NEEDLE.len()}),
        )
        .await
        .unwrap();
        assert_eq!(page["preview"], NEEDLE);
    } else {
        let mut offset = json!(0);
        let mut found = false;
        for _ in 0..100 {
            let page = find
                .call(
                    state,
                    "exchange_body",
                    json!({"project_id": project, "exchange_id": fixture.bundle, "offset": offset, "max_bytes": 20_000}),
                )
                .await
                .unwrap();
            if page["preview"].as_str().unwrap().contains(NEEDLE) {
                found = true;
                break;
            }
            offset = page["next_offset"].clone();
        }
        assert!(found);
    }
    workflows.push(find);

    let mut scripts = Workflow::new("list scripts of a domain");
    let listed = page_listing(
        &mut scripts,
        &fixture,
        "js_files",
        json!({"project_id": project, "domain": STATIC_HOST}),
        "files",
    )
    .await;
    assert_eq!(listed, SCRIPT_FILES + 1);
    workflows.push(scripts);

    let mut routes = Workflow::new("list routes of a host");
    let host_routes = routes
        .call(
            state,
            "sitemap",
            json!({"project_id": project, "host": APP_HOST}),
        )
        .await
        .unwrap();
    let rows_key = if host_routes.get("routes").is_some() {
        "routes"
    } else {
        "hosts"
    };
    let mut listed = count_rows(&host_routes[rows_key]);
    if let Some(next) = host_routes
        .get("next_offset")
        .filter(|next| !next.is_null())
    {
        listed += page_listing(
            &mut routes,
            &fixture,
            "sitemap",
            json!({"project_id": project, "host": APP_HOST, "offset": next}),
            rows_key,
        )
        .await;
    }
    assert_eq!(listed, API_EXCHANGES);
    workflows.push(routes);

    // A query written with an escaped opening quote, as models often emit it.
    let mut query = Workflow::new("query with escaped quote");
    let escaped = query
        .call(
            state,
            "history_search",
            json!({"project_id": project, "q": "path:~\\\"api/v2\" method:POST", "limit": 5}),
        )
        .await;
    let rows = match escaped {
        Ok(page) if has_rows(&page) => page,
        // An error or a silent empty result makes the agent rewrite and resend.
        _ => query
            .call(
                state,
                "history_search",
                json!({"project_id": project, "q": "path:~\"api/v2\" method:POST", "limit": 5}),
            )
            .await
            .unwrap(),
    };
    assert_eq!(rows["items"].as_array().unwrap().len(), 5);
    workflows.push(query);

    println!(
        "\n{:<34} {:>5} {:>9} {:>9} {:>8}",
        "workflow", "calls", "bytes", "largest", "clipped"
    );
    for workflow in &workflows {
        println!(
            "{:<34} {:>5} {:>9} {:>9} {:>8}",
            workflow.name, workflow.calls, workflow.bytes, workflow.largest, workflow.clipped
        );
    }
    println!(
        "{:<34} {:>5} {:>9} {:>9} {:>8}\n",
        "TOTAL",
        workflows
            .iter()
            .map(|workflow| workflow.calls)
            .sum::<usize>(),
        workflows
            .iter()
            .map(|workflow| workflow.bytes)
            .sum::<usize>(),
        workflows
            .iter()
            .map(|workflow| workflow.largest)
            .max()
            .unwrap(),
        workflows
            .iter()
            .map(|workflow| workflow.clipped)
            .sum::<usize>(),
    );

    assert!(
        capabilities.inline_bodies,
        "exchange_get must inline bodies"
    );
    assert!(
        capabilities.batch_read,
        "exchange_get must accept exchange_ids"
    );
    assert!(
        capabilities.body_search,
        "exchange_body must support search"
    );
    assert!(
        capabilities.lenient_quotes,
        "history_search must accept an escaped opening quote"
    );
    for workflow in &workflows {
        assert!(
            workflow.largest <= OUTPUT_BUDGET,
            "`{}` returned a {} byte result; the output budget is {OUTPUT_BUDGET}",
            workflow.name,
            workflow.largest
        );
    }
    let calls = |name: &str| {
        workflows
            .iter()
            .find(|workflow| workflow.name == name)
            .unwrap()
            .calls
    };
    assert_eq!(calls("read one exchange with bodies"), 1);
    assert_eq!(calls("re-read evidence set of 8"), 1);
    assert_eq!(calls("find string in 300 KB script"), 1);
    assert_eq!(calls("query with escaped quote"), 1);
}
