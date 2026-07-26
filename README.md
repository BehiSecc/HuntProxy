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
project without clearing its state. Use `op: "reset_profile"` with
`confirm: true` to clear browser-derived state; cookies configured with the
`cookies` tool remain separately managed and should also be cleared for a
complete logout. After 30 minutes without MCP/UI
control activity, the MCP bridge and daemon exit and browser processes close.
Set `idle_timeout_seconds` in `~/.huntproxy/config.toml` to change this timeout;
use `0` to disable it.

Use `js_files` with only `project_id` to list JavaScript from saved history,
add `domain` to filter it, or add `url` to perform a fresh, ephemeral,
Lightpanda-first load. Use `huntproxy_stop` to gracefully close HuntProxy and its browsers;
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
- “List JavaScript files for `example.com` from project 1 history.”
- “Load `https://example.com` and return every JavaScript URL and path.”
- “Send this exact raw HTTP/1.1 request with CRLF using `reply_send_raw`.”
- “Stop HuntProxy.”

Capture scope is optional. Empty scope saves everything; configured scope only
controls what is stored in History. It never restricts destinations. Sensitive
header values are redacted from normal agent output while remaining usable for
replay and fuzzing.

## Development

```bash
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
```
