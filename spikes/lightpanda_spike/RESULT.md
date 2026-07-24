# Lightpanda CDP Spike — RESULT

**Overall: PASS** (16 passed, 0 failed)

Date: 2026-07-24T16:59:12.906Z

## Environment

- lightpanda: `/home/administrator/.local/bin/lightpanda` (1.0.0-nightly.8285+de85a51d)
- playwright-core: 1.49.1 (Node 18 compatible)
- Node: v18.19.1
- `LIGHTPANDA_DISABLE_TELEMETRY=true`
- CDP: `lightpanda serve --host 127.0.0.1 --port 9222` → `ws://127.0.0.1:9222/`

## Proof checklist

| Status | Proof | Detail |
|--------|-------|--------|
| PASS | proxy-bearer-token flag documented | --proxy-bearer-token <TOKEN> → Proxy-Authorization: Bearer <token>; --http-proxy <URL> for proxy URL |
| PASS | local HTTP fixture started | http://127.0.0.1:36643 |
| PASS | lightpanda CDP ready | Browser=Lightpanda/1.0 ws=ws://127.0.0.1:9222/ |
| PASS | playwright connectOverCDP | contexts=1 version=124.0.6367.29 |
| PASS | lightpanda newContext+newPage | url=about:blank |
| PASS | lightpanda navigate /set | url=http://127.0.0.1:36643/set ready=true |
| PASS | extract cookies explicitly (context.cookies) | count=4 names=[lp_spike_api, lp_spike_http, lp_spike_js, lp_spike_server] httpOnly=true |
| PASS | extract localStorage explicitly (page.evaluate) | {"lp_spike_ls":"local_storage_val"} |
| PASS | extract sessionStorage explicitly (page.evaluate) | {"lp_spike_ss":"session_storage_val"} |
| PASS | disconnect CDP (browser.close) | CDP client closed |
| PASS | chromium launch | executablePath=/usr/bin/google-chrome-stable |
| PASS | chromium cookies after import | names=[lp_spike_api, lp_spike_http, lp_spike_js, lp_spike_server] doc.cookie=lp_spike_server=from_set_cookie; lp_spike_js=js_cookie_val; lp_spike_api=api_cookie_val |
| PASS | chromium localStorage after import | local_storage_val |
| PASS | chromium sessionStorage after import | session_storage_val |
| PASS | cookie/storage transfer Lightpanda → Chromium | cookies + localStorage + sessionStorage verified in Chromium from Lightpanda extract |
| PASS | proxy-bearer-token CLI accepts flag | lightpanda serve started with --proxy-bearer-token and --http-proxy |

## Proxy / Bearer auth flags

From `lightpanda serve --help` (common options):

```
--http-proxy <URL>
        HTTP proxy for all HTTP requests.
        username:password may be included for basic auth.
        Defaults to none.

--proxy-bearer-token <TOKEN>
        Token sent for bearer authentication with the proxy:
        Proxy-Authorization: Bearer <token>.
```

Also relevant for session fixtures:

```
--cookie <PATH>       Path to JSON file to load cookies from (read-only).
--cookie-jar <PATH>   Path to JSON file to save cookies to on exit (write-only).
```

CLI accepts both flags together (smoke-tested with a dummy proxy URL on port 9233).
Full proxy auth traffic path was not exercised against a real authenticating proxy in this spike.

## Method

1. Start Node `http` fixture on ephemeral port (`/set` and `/check`).
2. Spawn `lightpanda serve` with `LIGHTPANDA_DISABLE_TELEMETRY=true`.
3. `chromium.connectOverCDP('http://127.0.0.1:9222')` via playwright-core.
4. **`browser.newContext()` + `newPage()`** (required; default context fails on this Lightpanda build).
5. Navigate `/set`, set cookies via page JS + `context.addCookies`, set local/sessionStorage.
6. Extract via `context.cookies()` + `page.evaluate` for storage — do **not** rely only on `storageState()` (origins empty).
7. Launch Chromium headless, `addCookies` + `addInitScript` for storage, navigate `/check`, verify.
8. Clean up child processes by PID on exit.

## Findings / quirks

- `/json/list` returns `[]`; `/json/new` is 404. Playwright still connects and can create contexts.
- Default context after connect is present but navigation/cookies hit `BrowserContextNotLoaded` / `TargetAlreadyLoaded`.
- `storageState()` returns cookies but `origins: []` even when `localStorage`/`sessionStorage` are set — use explicit `page.evaluate`.
- `Target.createBrowserContext` logs `not_implemented` for some params but still works for basic newContext.

## Notes

- Lightpanda serve common options include:
-   --http-proxy <URL>           HTTP proxy; username:password may be included for basic auth.
-   --proxy-bearer-token <TOKEN> Token for Proxy-Authorization: Bearer <token>.
-   --cookie <PATH>              Load cookies from JSON (read-only).
-   --cookie-jar <PATH>          Save cookies on exit (write-only).
- Telemetry: LIGHTPANDA_DISABLE_TELEMETRY=true (confirmed in serve logs).
- Quirk: after connectOverCDP, use browser.newContext()+newPage(); default context is unusable (BrowserContextNotLoaded / TargetAlreadyLoaded).
- Quirk: storageState().origins is empty even when localStorage is set — extract storage via page.evaluate.
- storageState() cookie count: 4
- storageState() origins: 0 (localStorage not included by Lightpanda here)

## How to re-run

```bash
cd /home/administrator/HuntProxy/spikes/lightpanda_spike
export PATH="$HOME/.cargo/bin:$PATH"
export LIGHTPANDA_DISABLE_TELEMETRY=true
node spike.js
```
