# Browser configuration

Source and manual installations can run `HuntProxy browser install` to install browser-worker dependencies and the paired Chromium. The native installer and updater prepare the browser runtime automatically. For release pins, see [releasing](releasing.md).

Browsers run headless by default. Persistent workspaces use native headless compatibility mode by default; set `HUNTPROXY_BROWSER_HEADLESS_COMPAT=false` to use standard Playwright headless mode. Set `HUNTPROXY_BROWSER_HEADLESS=false` for a headed workspace; on Linux, it needs a display such as Xvfb.

Set `HUNTPROXY_CHROME_EXECUTABLE=/absolute/path/to/chrome` to select an installed browser. Configure `node_path` in `~/.huntproxy/config.toml` to select Node; the installer supplies a private Node runtime. Browser installation uses the same selected Node as the worker.

Set environment variables before starting the daemon; existing sessions retain their process until restarted. `HuntProxy doctor` and browser status report the browser path, version, and mode.

If Chromium's sandbox cannot start, HuntProxy retries without it and reports the fallback in browser status and `HuntProxy doctor`.

By default, the proxy verifies origin certificates using combined Chromium and Mozilla roots. Chromium root loading does not implement Chrome's additional root-policy or certificate-transparency checks. Raw HTTP/1 and HTTP/2 requests use Mozilla roots.

For authorized testing of targets with self-signed, private-CA, expired, or hostname-mismatched certificates, add this top-level setting to `~/.huntproxy/config.toml` (before any `[table]`):

```toml
verify_upstream_tls = false
```

The default is `true`, including for existing configuration files without this setting. Run `HuntProxy restart` after changing it. The setting applies to all target traffic: proxy forwarding, Reply/replay, crawler requests, raw HTTP/1 and HTTP/2, and WebSockets. TLS encryption remains enabled when verification is disabled, but the target's identity is no longer authenticated, allowing man-in-the-middle attacks. Use `true` to restore certificate verification.

Update checks, update downloads, and runtime installation downloads continue to verify certificates independently. Browsers must still trust HuntProxy's local interception CA.

Chrome background requests to a small set of internal endpoints are forwarded but omitted from browser History.
