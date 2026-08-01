# HuntProxy

An HTTP workbench for your hackbots. HuntProxy captures, searches, replays,
fuzzes, and browses authorized web targets through one local Rust service.

## Install

From a source checkout:

```bash
./install.sh
```

The installer supports Linux and macOS on x86_64 and ARM64. It installs
HuntProxy, Node.js when needed, Lightpanda, Playwright, and Chromium, then
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
the project's ID, a target URL, and either the exact Cookie header value in
`cookie` or a local `file_path`. Values remain hidden from normal tool output.
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
complete logout. After one hour without MCP/UI
control activity, the MCP bridge and daemon exit and browser processes close.
Set `idle_timeout_seconds` in `~/.huntproxy/config.toml` to change this timeout;
use `0` to disable it.

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

History filters support Boolean expressions, for example
`(request:~this OR request:~that) method:PUT`; `request:~text` searches the
request target, headers, and body. Fuzzer templates accept inline `wordlists`
or local UTF-8 `wordlist_files`, with one payload per line. Native
`payload_generators` provide inclusive signed number ranges and bounded,
[REcollapse](https://github.com/0xacb/recollapse)-inspired regex bypass
mutations without requiring Python. Regex bypass defaults to URL-encoded byte
mutations at the start, around separators, at the end, and in place of regex
metacharacters (REcollapse by André Baptista, MIT).
The `sitemap` tool returns sorted routes for every saved host or one requested
host. The `findings` tool links a title and description to an exchange and can
list or remove those findings. `copy_as` converts any saved request to cURL or
Python requests, including sensitive headers so the result is immediately
runnable. Set `include_secrets: false` when a redacted copy is preferred.
`page_analyzer` accepts either a saved `exchange_id` or an absolute `url` and
returns sorted, unique endpoints, URLs, and emails from decoded JavaScript or
HTML. It performs static text analysis only and does not scan or return secrets.

Use `js_files` with only `project_id` to list JavaScript from saved history,
add `domain` to filter it, or add `url` to perform a fresh, ephemeral,
Lightpanda-first load. JavaScript results retain the page URLs and hosts that
included or loaded them. `get_words` builds a target-specific wordlist from
saved traffic and includes JavaScript related to the requested site by default;
set `include_js: false` to omit it.

Browser-loaded HTML is crawled one level in the background: HuntProxy follows
at most 64 discovered links/assets with four concurrent GETs. These requests
are saved into History and Sitemap only when their destinations match capture
scope; excluded hosts are never crawled.

Use `huntproxy_stop` to gracefully close HuntProxy and its browsers;
restart the MCP client (or run `HuntProxy serve`) when you want to use it again.

If your MCP client cannot find `HuntProxy`, use the absolute path printed by
the installer (normally `/home/you/.local/bin/HuntProxy`); MCP clients do not
always inherit your shell's `PATH`.

## Examples

```bash
HuntProxy project create demo https://example.com
HuntProxy project list
HuntProxy doctor
```

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
