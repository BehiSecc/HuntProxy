# HuntProxy

An HTTP workbench for your hackbots. HuntProxy captures, searches, replays,
fuzzes, and browses authorized web targets through one local Rust service.

## Install

From a source checkout:

```bash
./install.sh
```

The installer supports Linux and macOS on x86_64 and ARM64. It installs
HuntProxy, Node.js when needed, Playwright, and Chromium, then
initializes `~/.huntproxy`. After release binaries are published, the same
script can be piped to Bash with the platform's binary URL:

```bash
curl -fsSL <INSTALL.SH-URL> | HUNTPROXY_BINARY_URL=<BINARY-URL> bash
```

Then start the workbench:

```bash
HuntProxy serve
```

- Web UI: http://127.0.0.1:17890
- Proxy: `127.0.0.1:17891`
- Diagnostics: `HuntProxy doctor`
- Stop: `HuntProxy stop`

`--data-dir` is optional. The default is `~/.huntproxy`, which HuntProxy
creates automatically.

## MCP

Generic JSON configuration:

```json
{
  "mcpServers": {
    "huntproxy": {
      "command": "HuntProxy",
      "args": ["mcp"]
    }
  }
}
```

Codex configuration (`~/.codex/config.toml`):

```toml
[mcp_servers.huntproxy]
command = "HuntProxy"
args = ["mcp"]
```

`HuntProxy mcp` starts the local daemon automatically. Project-scoped tools
require an explicit `project_id`.

To reuse an authenticated session, call the `cookies` tool with `action: "set"`,
the project's ID, a target URL, and either a raw Cookie header or browser-export
JSON cookie array in `cookie`, or a local UTF-8 `file_path` containing either
format. JSON cookies for unrelated domains and expired cookies are skipped.
Domain, path, expiry, HTTP-only, Secure, and
SameSite attributes are retained for Chromium, and HuntProxy selects applicable
cookie pairs for each managed request URL. Values remain hidden from normal tool output.
Matching cookies are then used automatically by Reply, Fuzzer, and new or
active browser sessions. Raw Reply remains byte-exact unless
`use_project_cookies: true` is explicitly set.

Browser state is private and persistent per project. Cookies and site storage
survive `stop`, daemon restarts, and idle shutdown; omit `url` from the next
`browser_start` call to resume the last page. Use `browser_manage` with
`op: "stop"` for one session or `op: "stop_all"` to suspend every browser in a
project without clearing its state. `browser_manage` status can omit
`session_id` to list active project browsers. Use `op: "reset_profile"` with
`confirm: true` to clear browser-derived state; cookies configured with the
`cookies` tool remain separately managed and should also be cleared for a
complete logout. After one hour without MCP/UI control activity, an MCP
auto-started daemon exits and its browser processes close. A daemon started
explicitly with `HuntProxy serve` stays running until stopped.
Set `idle_timeout_seconds` in `~/.huntproxy/config.toml` to change this timeout;
use `0` to disable it.

Outbound requests are direct by default. To use an HTTP or SOCKS5 upstream
proxy globally or for selected hosts, add this to `~/.huntproxy/config.toml`
and restart HuntProxy:

```toml
[upstream_proxies]
default = "http://127.0.0.1:8080" # optional fallback

[[upstream_proxies.rules]]
host = "*.example.com"
proxy = "socks5h://user:password@127.0.0.1:1080"

[[upstream_proxies.rules]]
host = "api.example.com"
proxy = "http://127.0.0.1:8888"
```

Exact host rules win over wildcard rules; the longest matching wildcard wins.
`*.example.com` matches subdomains, not the apex. `reply_send` and
`reply_send_raw` also accept a transient `upstream_proxy` override. Supported
schemes are `http`, `socks5` (local DNS), and `socks5h` (proxy DNS).

## Extensions

HuntProxy loads first-party extensions from `~/.huntproxy/plugins` when the
daemon starts. Copy each extension directory directly beneath that path, or
point development installs at a checkout of the extension pack:

```toml
plugin_dir = "/home/administrator/HuntProxy-Plugins/plugins"
```

Restart HuntProxy after installing, updating, enabling, or disabling an
extension. Nothing runs merely because it is installed. An agent uses this
bounded flow:

```text
extension_list
  -> extension_describe(plugin_id)
  -> extension_run(project_id, plugin_id, action, base_exchange_id, input)
  -> job_status(job_id) / job_results(job_id) / job_cancel(job_id)
```

HuntProxy owns all extension network I/O, scope checks, concurrency, rate
limits, cancellation, history, and findings. Generated requests appear in
History with `plugin`, the extension name, and `plugin:<id>` labels. Packages
are SHA-256 integrity-pinned; this first version does not yet include a
publisher-signature trust store. The low-level HTTP/1 path supports exact bytes
and synchronized final-byte release. Malformed HTTP/2 and true HTTP/2
single-packet release are reported as unsupported instead of silently falling
back to a weaker technique.

The UI restores an active Chromium browser after a page refresh and shows its
current URL and title. Browser startup and navigation errors remain visible to
the caller.

For a login that must be completed manually, note the `chromium_path` from
`HuntProxy doctor` while the daemon is running, then stop HuntProxy and launch
that executable with:

```bash
<chromium_path> --user-data-dir="$HOME/.huntproxy/browser-profiles/projects/<project-id>/chromium/default"
```

Complete the login, close Chromium fully, start HuntProxy again, and start that
project's browser. Never open the same profile manually while HuntProxy is using it. This is
especially useful for Google or hardware-key sign-in that cannot be completed
headlessly.

Reply drafts accept `body_text` or `body_json` as convenient alternatives to
byte-array `body_override`. When adapting a captured request to a different
endpoint, set `inheritance: "cookies_auth_only"` to retain only Cookie,
Authorization, and Origin; `full_request` remains the compatibility default.
Semantic Reply always recalculates message framing, and `reply_send` includes a
decoded 4 KiB response preview. `exchange_body` decodes gzip, Brotli, and
deflate responses by default; pass `raw: true` for the captured bytes.
Set `body_format` to `json`, `xml`, `form_urlencoded`, or `multipart` to
validate/serialize the body and update Content-Type. Form formats use ordered
`body_params` name/value entries. Explicit method changes do not accidentally
inherit the old request body or entity headers.

`reply_send_raw` is the explicit byte-preserving HTTP/1.1 path for framing and
desynchronization checks. It can split one request at `pause_at_byte`, pause,
optionally half-close the write side, and collect multiple responses with
`response_mode: "until_idle"`. The default remains one ordinary complete
response. Use base64 input when offsets or non-UTF-8 bytes matter. Raw response
transcripts are preserved; `exchange_body` presents the first entity normally
and returns the complete transcript with `raw: true`. Malformed HTTP/2 framing
is not supported because semantic HTTP/2 clients normalize messages.

History filters support Boolean expressions, for example
`(request:~this OR request:~that) method:PUT`; `request:~text` searches the
request target, headers, and body. Fuzzer templates accept inline `wordlists`
or local UTF-8 `wordlist_files`, with one payload per line. Native
`payload_generators` provide inclusive signed number ranges and bounded,
[REcollapse](https://github.com/0xacb/recollapse)-inspired regex bypass
mutations without requiring Python. Regex bypass defaults to URL-encoded byte
mutations at the start, around separators, at the end, and in place of regex
metacharacters (REcollapse by André Baptista, MIT).
`request_rules` applies ordered, optional-host URL, header, and text-body
match/replace rules to semantic traffic; Raw Reply remains exact. Fuzzer
results are grouped by response signature and can be compared with the base or
another case through `fuzz_manage`. Use `exchange_compare` for a bounded,
secret-safe request/response diff between any two History entries.
`websocket_manage` lists intercepted WebSocket connections and frames and can
inject text or binary messages in either direction while a connection is live.
The `sitemap` tool returns sorted routes for every saved host or one requested
host. The `findings` tool links a title and description to an exchange and can
list or remove those findings. `copy_as` converts any saved request to cURL or
Python requests, including sensitive headers so the result is immediately
runnable. Set `include_secrets: false` when a redacted copy is preferred.
`page_analyzer` accepts either a saved `exchange_id` or an absolute `url` and
returns sorted, unique endpoints, URLs, and emails from decoded JavaScript or
HTML. It performs static text analysis only and does not scan or return secrets.

Use `js_files` with only `project_id` to list JavaScript from saved history,
add `domain` to filter it, or add `url` to perform a fresh, ephemeral Chromium
load. JavaScript results retain the page URLs and hosts that
included or loaded them. `get_words` builds a target-specific wordlist from
saved traffic and includes JavaScript related to the requested site by default;
set `include_js: false` to omit it.

Browser-loaded HTML is crawled one level in the background: HuntProxy fetches
passive assets and same-origin, query-free navigations that do not look
state-changing, with at most 64 candidates and four concurrent GETs. When an
authenticated browser session is available, matching same-origin requests use
that browser context. Crawling still obeys capture scope and exclusions.

Use `huntproxy_stop` to gracefully close HuntProxy and its browsers;
restart the MCP client (or run `HuntProxy serve`) when you want to use it again.
The stop command prefers the private local socket and only uses a verified PID
as a fallback. `HuntProxy doctor` includes the bounded daemon log and the most
recent startup output when troubleshooting.

If your MCP client cannot find `HuntProxy`, use the absolute path printed by
the installer (normally `/home/you/.local/bin/HuntProxy`); MCP clients do not
always inherit your shell's `PATH`.

## Examples

```bash
HuntProxy project create demo https://example.com
HuntProxy project list
HuntProxy doctor
```

Project maintenance is available in the UI and CLI:

```bash
HuntProxy project rename 1 "Acme portal"
HuntProxy project usage 1
HuntProxy project reconcile 1
HuntProxy project export 1 ./acme-project.huntproxy
HuntProxy project export 1 ./acme-full.huntproxy --include-secrets
HuntProxy project import ./acme-project.huntproxy
HuntProxy har export 1 ./acme-history.har
HuntProxy har import 1 ./acme-history.har
HuntProxy history clear 1 --before 2026-01-01T00:00:00Z
HuntProxy backup ./huntproxy-backup.sqlite3
HuntProxy project delete 1
```

Usage is maintained transactionally. `project reconcile` recalculates counters
from saved history after an interrupted migration or suspected inconsistency;
omit the project ID to reconcile every project.

Portable `.huntproxy` exports are sanitized by default. Add `--include-secrets`
for a complete logical project including captured credentials, managed cookies,
Reply/Fuzzer state, and the portable browser checkpoint. Add
`--include-chromium-profile` only when a best-effort, same-platform Chromium
profile is also required. Full exports and SQLite backups must be treated as
sensitive files. HAR 1.2 transfer is intentionally limited to HTTP history.

`HuntProxy serve` stays in the foreground. In the UI, create a project and a
Proxy credential before sending traffic through `127.0.0.1:17891`.

Example agent tasks:

- “Create a project for `https://example.com` and inspect its login flow.”
- “Set project 1 cookies for `https://example.com` from `/tmp/cookies.txt`, then browse `/account`.”
- “Show POST requests in project 1 and compare their responses.”
- “Dump the sitemap for `example.com` and mark exchange 42 as a finding.”
- “Replay exchange 42 as POST with a JSON body.”
- “List JavaScript files for `example.com` from project 1 history.”
- “Load `https://example.com` and return every JavaScript URL and path.”
- “Build a target-specific wordlist for `example.com`, including related JavaScript.”
- “Analyze exchange 42 for endpoints, URLs, and emails.”
- “Fuzz `§id§` with every number from 1 through 100, stepping by 1.”
- “Generate regex-bypass payloads for `admin@example.com` and fuzz `§email§`.”
- “Send this exact raw HTTP/1.1 request with CRLF using `reply_send_raw`.”
- “Stop HuntProxy.”

Capture scope is optional. Empty scope saves everything; configured scope only
controls what is stored in History. It never restricts destinations. Sensitive
header values are redacted from normal agent output while remaining usable for
replay and fuzzing.

Capture hosts accept exact names and wildcard suffixes such as `*.example.com`.
Multiple include and exclude patterns are supported; exclusions always win. An
empty include list with exclusions captures every host except those exclusions.

## Development

```bash
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
```

## Update and uninstall

To update, download the latest checkout and run `./install.sh` again. The
installer replaces the binary and browser worker while preserving
`~/.huntproxy`. Back up first with `HuntProxy backup` when upgrading important
data.

To remove the program but keep your projects:

```bash
HuntProxy stop
rm "$HOME/.local/bin/HuntProxy"
```

To remove all HuntProxy data as well, delete `~/.huntproxy` only after making
any desired backup or project exports.

## License

Apache License 2.0. See [LICENSE](LICENSE).
