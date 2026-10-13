<div align="center">
<a id="huntproxy"></a>
<img src="hp-logo.png" alt="HuntProxy" width="280" />
</div>

<p align="center">
  <strong>A web security workbench built for AI agents.</strong>
</p>

<p align="center">
  <a href="https://github.com/BehiSecc/HuntProxy/releases"><img alt="Latest release" src="https://img.shields.io/github/v/release/BehiSecc/HuntProxy?style=flat-square"></a>
  <a href="./LICENSE"><img alt="Apache 2.0 license" src="https://img.shields.io/badge/license-Apache--2.0-blue?style=flat-square"></a>
  <img alt="Linux and macOS" src="https://img.shields.io/badge/platform-Linux%20%7C%20macOS-555?style=flat-square">
  <img alt="MCP compatible" src="https://img.shields.io/badge/interface-MCP-7c3aed?style=flat-square">
</p>

## Introduction

Every time I wanted to hunt on a program, I had to fire up Burp Suite, make sure Burp MCP was alive, and then ask Claude or Codex for assistance.

It was straightforward, but doing the same thing on my VPS was painful. So I was stuck with my local setup, but I didn't want project data on my main Mac, didn't want to hurt its battery, and didn't want to worry about RAM usage.

And the whole flow still felt way too manual.

I had to browse and explore the target myself. I had to run plugins myself. I had to keep everything alive and connected myself.

Hell, even having to turn on my Mac just to continue hunting started to feel like a problem.

I kept thinking: this is too much work. In the age of AI agents, it shouldn't be done this way.

So HuntProxy was born to let me (and you) keep hunting from anywhere: locally or on a VPS, from a laptop or a phone, just by typing what we want in plain English, without having to do absolutely anything else.

## 📚 Table of Contents

- [HuntProxy](#huntproxy)
  - [ Installation](#-installation)
  - [ Your First Project](#-your-first-project)
  - [ Features](#-features)
  - [ Example Prompts](#-example-prompts)
  - [ CLI Reference](#-cli-reference)
  - [ Plugins](#-plugins)
  - [ Don't Be Afraid of CAPTCHAs](#captcha-and-bot-checks)
  - [ FAQ](#-faq)
  - [ Update & Uninstall](#-update--uninstall)
  - [ Contribution](#-contribution)
  - [ Contact](#-contact)

## 📥 Installation

HuntProxy supports Linux and macOS:

```bash
curl -fsSL https://raw.githubusercontent.com/BehiSecc/HuntProxy/master/install.sh | bash
```

The installer sets up HuntProxy, its browser runtime, and a private data directory at `~/.huntproxy`.

The normal HuntProxy workflow begins inside your AI agent. Connect HuntProxy through MCP, then start hunting with a prompt.

Check the installation at any time with:

```bash
HuntProxy doctor
```

<details>
<summary><strong>Run with Docker</strong></summary>

Build the image and keep HuntProxy's project data in a named volume:

```bash
docker build -t huntproxy:local .
docker volume create huntproxy-data
docker run -d \
  --name huntproxy \
  --network host \
  --shm-size=1g \
  -v huntproxy-data:/data \
  huntproxy:local
```

Connect your AI agent to the running container:

```json
{
  "mcpServers": {
    "huntproxy": {
      "command": "docker",
      "args": ["exec", "-i", "huntproxy", "HuntProxy", "mcp"]
    }
  }
}
```

The MCP bridge connects to the HuntProxy daemon already running inside the container.

For Docker updates, rebuild the image and recreate the container with the same `huntproxy-data` volume. Reconnect MCP clients that use `docker exec` after recreating the container.

Optionally, open the web interface at [http://127.0.0.1:17890](http://127.0.0.1:17890).

> [!NOTE]
> This setup uses host networking because HuntProxy listens on loopback by default. Host-network support is platform-dependent; the native installer is currently the simplest path on macOS.

</details>

<details>
<summary><strong>Connect HuntProxy to Your Agent</strong></summary>

HuntProxy speaks MCP over standard input/output. When your agent connects, the bridge starts the local HuntProxy daemon automatically and keeps the project available across prompts.

### Codex

Add this to `~/.codex/config.toml`:

```toml
[mcp_servers.huntproxy]
command = "/path/to/HuntProxy"
args = ["mcp"]
```

Restart Codex, then ask it to create a HuntProxy project.

### Other Clients

Use this standard JSON configuration in any client that supports local stdio MCP servers:

```json
{
  "mcpServers": {
    "huntproxy": {
      "command": "/path/to/HuntProxy",
      "args": ["mcp"]
    }
  }
}
```

Replace `/path/to/HuntProxy` with the absolute path to the binary. It is usually located at `~/.local/bin/HuntProxy`—for example, `/home/you/.local/bin/HuntProxy`.

</details>

## 🚀 Your First Project

After connecting HuntProxy, give your agent a target and an objective:

```text
Use HuntProxy MCP. Create a project named "First Hunt" for
https://example-target.com/. Start a browser, explore the
application, and show me its sitemap and state-changing requests.
```

That single prompt begins the workflow. The agent creates a project, launches a persistent Chromium session, explores the target, records the resulting traffic, and builds a map it can use in later prompts.

## 🧰 Features

HuntProxy gives agents a complete hunting loop: build context → investigate → test a hypothesis → keep the proof.

### Build and Preserve Context

| Capability | What your agent can do |
| --- | --- |
| **Projects** | Keep a target's traffic, browser state, cookies, notes, and test results together. |
| **Capture proxy & History** | Record HTTP/HTTPS traffic and search it by host, path, method, status, source, labels, request content, and Boolean expressions. |
| **Persistent browser profiles** | Run separate named Chromium identities in one project for cross-account testing. Each profile keeps its own cookies and site storage across restarts. |
| **Sitemap** | Turn saved traffic into a host-and-route tree with methods, statuses, parameters, content types, and exchange counts. |
| **JavaScript & page discovery** | Find JavaScript and the pages that loaded it, extract endpoints, URLs, emails, and request parameter names, and build target-specific wordlists. Page analysis follows same-origin JavaScript bundles listed in HTML script tags and Modern.js route manifests. |
| **WebSockets** | Inspect captured connections and messages, then inject text or binary frames into a live connection. |

Different browser profiles can remain open together up to the project's browser limit (two by default). Browser commands share one worker queue, and only one session can be handed to CDP at a time.

Use `browser_manage(project_id=PROJECT_ID, op="status")` at profile or control transitions to inspect active persistent sessions and browser resources. Resource capacity also counts temporary browsers used by tools and extensions; per-session control indicates whether the agent or a person through CDP owns that browser, and the CDP occupancy flag covers the shared port across projects. Reuse a valid matching session when capacity is full. Suspend only an unnecessary idle session you own, preserving its profile; keep simultaneous-account workflows and operator handoffs intact. Retain the result between transitions instead of checking status before every browser action.

For an ordinary file input, use `browser_action` with `action: {type: "upload", locator: {css: "input[type=file]"}, files: ["/absolute/path/monthly-summary.csv"]}`. Set `via_chooser: true` and select the Browse button when the application opens a file chooser. Paths belong to the HuntProxy machine; files must be readable regular files, with at most 16 per action. The default upload timeout is 10 seconds and can be set up to 30 seconds. An empty file list clears a direct input. Selection uses the existing browser and normal UI/capture flow.

`action: {type: "inspect"}` returns passive page readiness, recent resource metadata and diagnostic locations; add `locator` for element state. Its `data.content` contains JSON when `truncated` is false. Increase `max_bytes` from the 4096-byte default up to 65536 when more detail is needed. Console message text, storage and credentials are excluded. These actions retain session ownership and respect a person's CDP handoff.

Agents can keep routine browser work inside `browser_action`. Use `pages` to list, open, select, or close tabs; reuse a returned `page_id` only with its `runtime_generation`. Closing the last tab creates a clean `about:blank` page. Use `events` with its sequence cursor to observe bounded popup, navigation, dialog, request, response, console-error, and window-message metadata. Event payloads exclude message contents, headers, bodies, cookies, and storage. `scroll` accepts a locator or bounded wheel deltas. `screenshot` captures a viewport, element, or bounded full page; MCP clients receive the PNG as an image content block.

`action: {type: "request", method: "POST", url: "https://target.example/api/items", body_text: "..."}` sends one request from a reusable isolated world on the active page. The URL must have that page's exact HTTP(S) origin, and HuntProxy rechecks the effective URL after request rules. The request uses the live browser cookie jar and normal browser CSP, service-worker, Origin, Referer, proxy, and capture behavior. Redirects and retries are disabled. Request bodies are limited to 2 MiB, response previews to 64 KiB, and Fetch-managed or duplicate headers are rejected instead of being silently changed. A completed response is drained so History can retain its normal full captured evidence even when the returned preview is short; a timeout is never retried and can leave explicitly incomplete evidence.

`browser_cdp` remains available for operator handoff and for unusual interactions that the structured actions cannot express. While a CDP handoff is active, `browser_action` pauses as before. Returning control creates a new runtime generation, so list pages and restart event cursors before continuing.

CDP handoff preserves every open tab, the selected tab, and each tab's session storage. Waiting for browser events releases the worker between polls so other sessions can keep working.

### Test Hypotheses

| Capability | What your agent can do |
| --- | --- |
| **Reply** | Reuse and modify captured requests over HTTP/1.1 or HTTP/2, or preserve exact HTTP/1.1 bytes for advanced framing tests. |
| **Fuzzer** | Run sniper, battering ram, pitchfork, or cluster bomb jobs with wordlists, number ranges, and regex-bypass payloads; group responses to spot meaningful differences. |
| **Request rules** | Apply ordered URL, header, and body rewrites across Proxy, Browser, Reply, Fuzzer, the crawler, and semantic plugin requests. Raw transports stay byte-exact. |
| **Compare & utilities** | Diff saved exchanges, transform encodings, inspect large bodies in pages, and copy requests as runnable cURL or Python. |

Reply and Fuzzer drafts accept a request-local `identity`: `{mode: "named", profile: "member"}` selects a saved cookie profile, `{mode: "anonymous"}` removes credential headers, and omitted/null or `{mode: "default"}` keeps existing behavior. Named selection removes inherited credentials and credential rewrites; deliberate non-Cookie credential overrides remain. Cookie overrides conflict with named selection, while a Cookie tombstone suppresses its selected cookie. Missing, expired or non-applicable profiles fail without falling back. The browser and default jar are unchanged, and named Fuzzer jobs pin their cookie selection at launch. Verify the actor through normal application behavior; returned identity metadata describes the selection only.

Raw HTTP/1 replies preserve received bytes and status after a later connection error. Inspect `response_complete`, `truncated`, `read_outcome` and optional `transport_error` alongside the saved exchange. A framed response can be complete while the connection still reports an error. Raw HTTP/2 operations retain decoded stream evidence and identify transport errors on affected streams. Incomplete/error records remain evidence rather than clean results; no automatic retry is introduced.

### Keep the Proof and Extend the Hunt

| Capability | What your agent can do |
| --- | --- |
| **Findings & annotations** | Attach titles, labels, notes, and findings directly to the exchange that proves them. |
| **Portable projects** | Create sanitized project exports by default, opt into complete sensitive exports when needed, transfer HAR history, and back up the database. |
| **Credential handling** | Keep credentials locally usable for authenticated work without exposing them through routine inspection tools. |
| **Bounded plugins** | Add focused testing workflows while HuntProxy retains control of network access, credentials, limits, cancellation, History, and evidence. |

> [!TIP]
> **The cool part?** You do not need to learn or explore every feature before you start. Just ask your agent to use HuntProxy MCP for the hunt. It can discover the available tools, choose what it needs, and keep the workflow moving.

## 💬 Example Prompts

Just describe what you want to investigate. HuntProxy keeps the browser, traffic, and results connected while your agent works.

Map the target:

```text
Browse the application, then show me its sitemap, loaded JavaScript files, and
state-changing requests.
```

Review interesting traffic:

```text
Show me the recent POST and PUT requests in project 1. Highlight
requests containing object IDs, roles, or permission-related parameters.
```

Replay a request:

```text
Replay exchange 42 with the id changed from 123 to 124, then compare the new
response with the original.
```

Fuzz a parameter:

```text
Fuzz the id parameter in exchange 42 with numbers 1 through 50. Group similar
responses and show me the results that differ from the baseline.
```

Inspect the JavaScript:

```text
Analyze the JavaScript files loaded by this project and show me the API routes,
parameter names, and URLs that have not appeared in History yet.
```

Compare two accounts:

```text
Store /tmp/member.json and /tmp/admin.json as cookie profiles named member and
admin in project 1. Start matching browser profiles with cookie_profile set to
the same names, then use their session IDs to compare the accounts. On later
starts, omit cookie_profile to resume each browser's latest saved state.
```

Test for request smuggling:

```text
Use the Request Smuggler plugin on exchange 42. Generate a unique marker,
choose the most relevant techniques, and show me confirmed findings separately
from diagnostic signals.
```

Save a finding:

```text
Mark exchange 42 as a finding, add a short description and reproduction steps,
and generate a cURL command.
```

### Search Saved History

Pass a query in `history_search`'s `q` argument. Keep each field, operator, and value together: `status>=400`, not `status:>=400` or `status >= 400`.

| Query | Matches |
| --- | --- |
| `host:example.com method:GET status>=400` | GET requests to this host with status 400 or higher |
| `path:~"monthly report"` | Paths containing the literal phrase |
| `request:~"monthly report"` | Request target, headers, or decoded body containing the phrase |
| `(status:200 OR status:304) NOT path:~.js` | Either status, excluding paths containing `.js` |
| `time>2026-10-12T00:00:00Z time<=2026-10-13T00:00:00Z` | Exchanges within these timestamp bounds |
| `duration>=1000 response_size>1024` | Duration of at least one second and response body larger than 1 KiB |

`field:value` means equality; `field:~value` means contains. Comparisons use `>`, `>=`, `<`, `<=`, or `!=` directly after the field. Adjacent terms mean AND; Boolean precedence is NOT, AND, then OR. Double quotes keep spaces and parentheses inside a value. Bare words search summary fields, not request bodies. `path:/api/*`, `path:*.js`, and `path:*report*` select prefix, suffix, and contains matches.

`duration` is milliseconds; `request_size` and `response_size` are body bytes. `time` compares stored UTC RFC 3339 timestamp text, not Unix seconds; copy the stored format for precise cutoffs. Use the tool schema's field names, and narrow full request searches with summary filters when practical. A query error is not an empty result: follow its returned repair guidance and rerun the corrected query before drawing conclusions.

Search results identify exchanges but do not include full bodies. `reply_send` returns an `exchange_id` and a 4 KiB response preview; pass that ID to `exchange_body` with `side: "response"` to read the captured response, or `side: "request"` to read the captured request. Each call returns up to 1 MiB; continue at `next_offset` while `truncated` is true. The default UTF-8 preview replaces invalid byte sequences, so use `encoding: "base64"` when exact page bytes matter. Response bodies are decoded by default; set `raw: true` to read the captured response bytes before content decoding. This reads saved evidence and avoids replaying the request or fetching byte ranges from the target.

Call `overview` with a `project_id` for exchange counts by source, captured replies sent, findings, distinct hosts, and the last exchange time.

## 💻 CLI Reference

Most projects begin with a prompt, not a terminal command. MCP handles day-to-day hunting; the CLI handles setup, diagnostics, project maintenance and data transfer.

| Command | Purpose |
| --- | --- |
| `HuntProxy init` | Create the data directory, configuration, database, and local CA. |
| `HuntProxy serve` | Keep the local daemon, inspector, and capture proxy running manually. |
| `HuntProxy mcp` | Start the stdio MCP bridge and auto-start the daemon if needed. |
| `HuntProxy doctor` | Check paths, browser dependencies, daemon state, and recent startup diagnostics. |
| `HuntProxy status` | Show whether the daemon is running. |
| `HuntProxy stop` | Gracefully stop HuntProxy and its managed browsers. |
| `HuntProxy restart` | Restart or recover the daemon while preserving saved testing state. |
| `HuntProxy project …` | Create, list, rename, export, import, view usage, reconcile, or delete projects. |
| `HuntProxy har …` | Import or export HAR 1.2 HTTP history. |
| `HuntProxy backup <file>` | Create a consistent SQLite backup. |
| `HuntProxy history clear …` | Remove saved exchanges older than a chosen timestamp. |
| `HuntProxy browser cdp …` | Hand an active browser to Chrome DevTools or return it to the agent. |

Use `HuntProxy --help` or `HuntProxy <command> --help` for the complete command reference.

<details>
<summary><strong>Project Maintenance Examples</strong></summary>

```bash
HuntProxy project create demo https://example.com
HuntProxy project list
HuntProxy project rename 1 "Acme Portal"
HuntProxy project usage 1
HuntProxy project export 1 ./acme-project.huntproxy
HuntProxy project import ./acme-project.huntproxy
HuntProxy har export 1 ./acme-history.har
HuntProxy backup ./huntproxy-backup.sqlite3
```

Sanitized project exports are for sharing, not recovery: they omit credentials, bodies, replay state, and browser state. For the most complete export, add `--include-secrets --include-chromium-profile` and protect the result like credentials.

</details>

## 🧩 Plugins

HuntProxy plugins give the agent focused workflows for parameter discovery, authorization analysis, race conditions, request smuggling, cache behavior, JWTs, CSRF, uploads, bypasses, IP rotation, and more.

Explore the maintained collection or learn how to build your own in [HuntProxy-Plugins](https://github.com/BehiSecc/HuntProxy-Plugins).

Extension previews include a bounded `planning_summary` with the plugin's selection and exclusion details. Job results retain a host-owned `execution` summary in both compact and full views, including partial results after failure or cancellation. Its counts describe top-level planned, returned, skipped, and unobserved operations; error, not-tested, and evidence-limited counts can overlap. Compact results include `evidence_exchange_count`; full results retain the evidence IDs. Large planning details may be compacted or omitted to retain current execution evidence; `plan_result_omitted_reason` explains this. `observations_recorded` means observations returned, not that requests or controls were clean. Existing `operation_count` and `completed_operations` fields are request-weighted progress and do not count requests actually sent. Analysis retries preserve the execution summary without replaying operations.

<a id="captcha-and-bot-checks"></a>

## 🛡️ Don't Be Afraid of CAPTCHAs

### How Can I Reduce CAPTCHAs and Bot Detection?

CAPTCHAs and bot checks are common when hunting from a VPS because datacenter IP addresses are easier to recognize. Routing HuntProxy through a reputable residential proxy is usually the most effective fix.

Choose one configuration and add it to `~/.huntproxy/config.toml`. Then run `HuntProxy restart` (or call `huntproxy_restart` from the connected agent) and verify with `HuntProxy doctor`.

For all traffic:

```toml
[upstream_proxies]
default = "http://127.0.0.1:8080"
```

With authentication:

```toml
[upstream_proxies]
default = "http://username:password@proxy.example.com:8080"
```

For selected HuntProxy projects only:

```toml
[upstream_proxies]

[[upstream_proxies.project_rules]]
project_id = 41
proxy = "socks5h://username:password@127.0.0.1:1080"
```

Project rules route all traffic for that project and take priority over host
rules and the default. A transient per-request override still takes priority.

For selected hosts only:

```toml
[upstream_proxies]

[[upstream_proxies.rules]]
host = "*.example.com"
proxy = "socks5h://username:password@127.0.0.1:1080"

[[upstream_proxies.rules]]
host = "api.example.org"
proxy = "http://127.0.0.1:8080"
```

`*.example.com` matches its subdomains, not `example.com` itself. Exact host rules take priority over wildcard rules.

### What If the Agent Still Faces a CAPTCHA?

A proxy can reduce bot checks, but it cannot prevent every CAPTCHA. When one still appears:

- [Give the agent a logged-in session](#logged-in-session).
- Ask the agent to hand you the browser through CDP, solve the CAPTCHA yourself, then return control so it can continue.

## 💡 FAQ

<details>
<summary><strong>Can HuntProxy replace Burp Suite for agent-driven testing?</strong></summary>

HuntProxy is designed to be the primary web security workbench for an AI agent. It covers the capture, history, browser, replay, fuzzing, discovery, plugin, and evidence workflows agents need, but it is not a pixel-for-pixel Burp clone.

Its defining difference is the operating model: the agent works through MCP, project state survives between prompts, and every important action remains inspectable. You can use HuntProxy on its own for agent-driven testing or alongside existing security tools.

</details>

<details>
<summary><strong>Which AI agents can use HuntProxy?</strong></summary>

Any AI agent with MCP support on Linux or macOS.

</details>

<details>
<summary><strong>Can I do bug hunting from my phone?</strong></summary>

Yes. Run HuntProxy and your agent on a VPS, connect from your phone with [Tailscale](https://tailscale.com/) and SSH, and use [tmux](https://github.com/tmux/tmux) or [Herdr](https://github.com/herdrdev/herdr) to keep the session alive.

</details>

<details>
<summary><strong>Do I need to keep HuntProxy running?</strong></summary>

Not necessarily. `HuntProxy mcp` starts the daemon automatically. By default, an MCP-started daemon shuts down after one hour without MCP or UI control activity, while the inexpensive MCP bridge stays connected. The next tool call automatically recovers an idle or unexpectedly terminated daemon. After an explicit `huntproxy_stop`, call `huntproxy_restart` on the same connection. Run `HuntProxy serve` when you want the workbench to stay active until explicitly stopped.

</details>

<details>
<summary><strong>What survives between sessions?</strong></summary>

Projects, captured traffic, findings, managed cookies, Reply and Fuzzer state, and every named Chromium profile's cookies and site storage are persisted locally. Starting a profile again resumes its saved workspace. Active browsers and running Fuzzer/plugin jobs are interrupted by a restart; memory-only plugin results and analysis checkpoints are lost, so collect those first. Plugin-generated History and saved findings remain available.

</details>

<details>
<summary><strong>Where is my data stored?</strong></summary>

By default, HuntProxy stores its database, configuration, browser profiles, CA, logs, plugins, and exports in `~/.huntproxy`. Use `--data-dir` or `HUNTPROXY_DATA_DIR` to choose a different location.

</details>

<a id="logged-in-session"></a>

<details>
<summary><strong>How can I give the agent a logged-in session?</strong></summary>

There are three common ways:

- **Load existing cookies:** Save a raw `Cookie` header value or browser-export JSON cookie array to a UTF-8 file and load it into the project for HTTP tools. To import it into a persistent browser, store a named cookie profile and explicitly start its matching browser with `cookie_profile` set to that name. Starting or restarting a browser without `cookie_profile` preserves its own jar, including Google accounts, without importing project or named cookies.
- **Log in through the browser:** Ask the agent to hand you the project's Chromium browser through CDP. Complete the login, CAPTCHA, or two-factor authentication yourself, then tell the agent to take control back and continue.
- **Provide the credentials:** Give the agent the username and password and ask it to sign in through the managed browser.

The cookie file must be on the same machine as HuntProxy. A raw cookie file should contain only the value, for example `sid=...; csrf=...`, without the `Cookie:` prefix. Credentials shared directly in a prompt pass through your AI client, so prefer a temporary or test account when possible.

</details>

<details>
<summary><strong>Can the agent see my credentials?</strong></summary>

Sensitive headers are redacted from ordinary inspection tools but remain available locally for authenticated browsing, replay, and fuzzing. Explicit reveals are audited. The `copy_as` tool includes sensitive headers by default so its output is runnable; set `include_secrets: false` for a redacted copy. Protect `~/.huntproxy`, full exports, and backups because they can contain sensitive data.

</details>

<details>
<summary><strong>Does HuntProxy send my data to the cloud?</strong></summary>

HuntProxy has no HuntProxy-hosted cloud backend: project data is stored locally and its services listen on loopback by default. It still sends traffic to targets you direct it to, through any upstream proxy you configure, and IpRotate communicates with AWS when enabled. Your AI client and model provider may process content returned through MCP under their own privacy terms.

</details>

<details>
<summary><strong>Does project scope stop out-of-scope requests?</strong></summary>

No. Capture scope is not a general outbound allowlist: Proxy, Browser, Reply, and Fuzzer can send requests that are not saved to History. The built-in crawler and plugin host apply tighter scope checks, but you should still give the agent explicit authorization boundaries and monitor the hunt.

</details>

<details>
<summary><strong>Can I take over the agent's browser?</strong></summary>

Yes. Just ask your agent to hand you the browser. When you are done, ask it to take control back and continue.

</details>

## 🔄 Update & Uninstall

### Update

Update HuntProxy to the latest release:

```bash
HuntProxy update
```

For native installations from v0.2 onward, the updater prepares the matching browser runtime and official plugins, preserves project data, and restarts the daemon if it was running. Existing projects open normally; there is no re-export or conversion step. Older `.huntproxy` bundles are upgraded during ordinary import. Customized and third-party plugin folders are preserved; an incompatible preserved Racer package returns a clear compatibility error.

The v0.2 MCP bridge refreshes the daemon's tool catalog after later updates and sends the standard `tools/list_changed` notification, so clients that support it can discover new features on the same connection. It keeps the last validated catalog while the daemon is idle or stopped.

**Upgrading from v0.1.1:** its already-published updater requires `HuntProxy stop` and an MCP client reconnect after `HuntProxy update`. The new executable prepares its runtime and plugins automatically on first startup. This one-time limitation belongs to the old updater; subsequent updates use the coordinated workflow.

Updates keep a private database/configuration/plugin restore point and the previous executable. Failed preparation or activation restores the previous installation. Interrupted v0.2 updates recover before opening project data. A schema migration also keeps a private copy of the earlier database. Active browsers and jobs stop during replacement; saved projects, history, identities, and browser profile storage remain available.

`HuntProxy backup` copies only SQLite; it omits configuration, the CA, plugins, and browser profiles. Update restore points also omit browser profiles and the CA because the updater preserves those in place. For a complete independent backup, stop HuntProxy and copy its data directory plus any configured external paths.

See the [v0.2.0 release notes](docs/releases/v0.2.0.md) for the compatibility changes.

### Uninstall

Stop HuntProxy and remove the executable:

```bash
HuntProxy stop
rm "$HOME/.local/bin/HuntProxy"
```

This keeps your projects and configuration in `~/.huntproxy`. Before deleting that directory, copy it in full if you may need to recover anything. Deletion cannot be undone.

## 🤝 Contribution

If you have suggestions, improvements, or new resources to add:

1. Fork this repo
2. Make your changes
3. Submit a Pull Request

You can also open an [Issue](https://github.com/BehiSecc/HuntProxy/issues) 🐛 if you spot something that needs fixing.

## 📬 Contact

If you want to contact me, you can reach me on [X](https://x.com/Behi_Sec).
