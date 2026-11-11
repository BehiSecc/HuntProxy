# Browser configuration

Source and manual installations can run `HuntProxy browser install` to install browser-worker dependencies and the paired Chromium. The native installer and updater prepare the browser runtime automatically. For release pins, see [releasing](releasing.md).

Browsers run headless by default. Persistent workspaces use native headless compatibility mode by default; set `HUNTPROXY_BROWSER_HEADLESS_COMPAT=false` to use standard Playwright headless mode. Set `HUNTPROXY_BROWSER_HEADLESS=false` for a headed workspace; on Linux, it needs a display such as Xvfb.

Set `HUNTPROXY_CHROME_EXECUTABLE=/absolute/path/to/chrome` to select an installed browser. Configure `node_path` in `~/.huntproxy/config.toml` to select Node; the installer supplies a private Node runtime. Browser installation uses the same selected Node as the worker.

Set environment variables before starting the daemon; existing sessions retain their process until restarted. `HuntProxy doctor` and browser status report the browser path, version, and mode.

If Chromium's sandbox cannot start, HuntProxy retries without it and reports the fallback in browser status and `HuntProxy doctor`.

HuntProxy authenticates the browser to its own proxy and never offers those credentials to a site. A site's own HTTP authentication challenge is handled as in a plain browser, so a headless navigation to a protected page fails with `net::ERR_INVALID_AUTH_CREDENTIALS`. Put the site's credentials in the URL (`https://user:password@host/`) to sign in.

The proxy verifies origin certificates using combined Chromium and Mozilla roots. Chromium root loading does not implement Chrome's additional root-policy or certificate-transparency checks.

Chrome background requests to a small set of internal endpoints are forwarded but omitted from browser History.
