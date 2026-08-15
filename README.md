<div align="center">
<a id="huntproxy"></a>
<img src="hp-logo.png" alt="HuntProxy" width="280" />
</div>

<p align="center">
  <strong>A web security workbench, built for AI agents.</strong>
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
| **Persistent browser** | Let the agent browse authenticated applications through managed Chromium while cookies and site storage survive restarts. |
| **Sitemap** | Turn saved traffic into a host-and-route tree with methods, statuses, parameters, content types, and exchange counts. |
| **JavaScript & page discovery** | Find JavaScript and the pages that loaded it, extract endpoints, URLs, and emails, and build target-specific wordlists. |
| **WebSockets** | Inspect captured connections and messages, then inject text or binary frames into a live connection. |

### Test Hypotheses

| Capability | What your agent can do |
| --- | --- |
| **Reply** | Reuse and modify captured requests over HTTP/1.1 or HTTP/2, or preserve exact HTTP/1.1 bytes for advanced framing tests. |
| **Fuzzer** | Run sniper, battering ram, pitchfork, or cluster bomb jobs with wordlists, number ranges, and regex-bypass payloads; group responses to spot meaningful differences. |
| **Request rules** | Apply ordered URL, header, and body rewrites across Proxy, Browser, Reply, Fuzzer, the crawler, and semantic plugin requests. Raw transports stay byte-exact. |
| **Compare & utilities** | Diff saved exchanges, transform encodings, inspect large bodies in pages, and copy requests as runnable cURL or Python. |

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

<a id="captcha-and-bot-checks"></a>

## 🛡️ Don't Be Afraid of CAPTCHAs

### How Can I Reduce CAPTCHAs and Bot Detection?

CAPTCHAs and bot checks are common when hunting from a VPS because datacenter IP addresses are easier to recognize. Routing HuntProxy through a reputable residential proxy is usually the most effective fix.

Choose one configuration and add it to `~/.huntproxy/config.toml`. Then run `HuntProxy stop`, restart/reconnect your AI client, and verify with `HuntProxy doctor`.

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

Not necessarily. `HuntProxy mcp` starts the daemon automatically. By default, an inactive MCP bridge exits after one hour, and an MCP-started daemon also shuts down after one hour without MCP or UI control activity. Compatible clients can relaunch the bridge when needed. Run `HuntProxy serve` when you want the workbench to stay active until explicitly stopped.

</details>

<details>
<summary><strong>What survives between sessions?</strong></summary>

Projects, captured traffic, findings, managed cookies, Reply and Fuzzer state, and the project's Chromium cookies and site storage are persisted locally. Starting the project browser again resumes its saved workspace. Plugin-generated History entries and saved findings also persist, but plugin job status, result summaries, and resumable analysis checkpoints should be collected before restarting HuntProxy.

</details>

<details>
<summary><strong>Where is my data stored?</strong></summary>

By default, HuntProxy stores its database, configuration, browser profiles, CA, logs, plugins, and exports in `~/.huntproxy`. Use `--data-dir` or `HUNTPROXY_DATA_DIR` to choose a different location.

</details>

<a id="logged-in-session"></a>

<details>
<summary><strong>How can I give the agent a logged-in session?</strong></summary>

There are three common ways:

- **Load existing cookies:** Save the cookies to a UTF-8 file as either a raw `Cookie` header value or a browser-export JSON cookie array, then ask the agent to load that file into the project for the target URL.
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

Rerun the installer to replace the executable:

```bash
curl -fsSL https://raw.githubusercontent.com/BehiSecc/HuntProxy/master/install.sh | bash
```

`HuntProxy backup` copies only SQLite; it omits configuration, the CA, plugins, and browser profiles. For full recovery, stop HuntProxy and copy its data directory plus any configured external paths. The installer leaves that data untouched.

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
