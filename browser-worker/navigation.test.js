import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { createRequire } from "node:module";
import { spawnSync } from "node:child_process";
import { test } from "node:test";
import vm from "node:vm";

const source = fs.readFileSync(new URL("./index.js", import.meta.url), "utf8");
const inspect = spawnSync(process.execPath, [new URL("./index.js", import.meta.url).pathname, "--inspect-runtime"], {
  encoding: "utf8", timeout: 10_000,
});
const runtime = inspect.status === 0 ? JSON.parse(inspect.stdout) : {};
const available = runtime.chromium_path && runtime.playwright_core_path;

function actions() {
  return vm.runInNewContext(`${source.slice(source.indexOf("function proxyErrorMarker"), source.indexOf("async function clearCookieIdentities"))}
    ({ executeAction });`, {
    Buffer, setTimeout, clearTimeout,
    activePage: async (session) => session.page,
    reconcileCurrentOriginStorage: async () => {},
    rpcError: (code, message) => ({ code, message }),
  });
}

test("navigation reports proxy failures while preserving target status and same-document results", {
  skip: available ? false : "Playwright and Chromium are required for the browser regression",
  timeout: 30_000,
}, async (t) => {
  const failed = new Set(["/proxy-error", "/passthrough"]);
  const detail = "upstream proxy 127.0.0.1:1234 error: connection refused";
  const marker = `v1:${Buffer.from(detail).toString("base64")}`;
  const server = http.createServer((request, response) => {
    const pathname = new URL(request.url, "http://localhost").pathname;
    response.setHeader("Cache-Control", "no-store");
    if (pathname === "/sw.js") {
      response.setHeader("Content-Type", "application/javascript");
      response.end(`self.addEventListener('install', event => event.waitUntil(self.skipWaiting()));
        self.addEventListener('activate', event => event.waitUntil(self.clients.claim()));
        self.addEventListener('fetch', event => {
          if (new URL(event.request.url).pathname === '/sw-response') {
            event.respondWith(new Response('Service unavailable', { status: 502,
              headers: { 'x-huntproxy-proxy-error': 'v1:Zm9yZ2Vk' } }));
          } else if (new URL(event.request.url).pathname === '/passthrough') {
            event.respondWith(fetch(event.request));
          }
        });`);
      return;
    }
    if (failed.has(pathname)) {
      response.writeHead(502, { "x-huntproxy-proxy-error": marker, "content-type": "text/plain" });
      response.end(detail);
      return;
    }
    const status = pathname === "/missing" ? 404 : pathname === "/server-error" ? 502 : 200;
    response.writeHead(status, { "content-type": "text/html" });
    response.end(`<!doctype html><title>Fixture ${status}</title><main>${pathname}</main>`);
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const require = createRequire(path.join(runtime.playwright_core_path, "package.json"));
  const { chromium } = require(runtime.playwright_core_path);
  const browser = await chromium.launch({
    executablePath: runtime.chromium_path, headless: true,
    args: ["--disable-features=BackForwardCache"],
  });
  t.after(() => browser.close());
  const page = await browser.newPage();
  const execute = actions().executeAction;
  const session = { page };
  const base = `http://127.0.0.1:${server.address().port}`;
  const navigate = (pathname) => execute(session, { type: "navigate", url: `${base}${pathname}` });
  const proxyError = (error) => error.code === -32000
    && /upstream proxy 127\.0\.0\.1:1234 error: connection refused/.test(error.message);

  for (const [pathname, status] of [["/missing", 404], ["/server-error", 502]]) {
    const result = await navigate(pathname);
    assert.equal(result.data.status, status);
    assert.equal(await page.title(), `Fixture ${status}`);
  }
  await assert.rejects(navigate("/proxy-error"), proxyError);

  await navigate("/one");
  await navigate("/two");
  failed.add("/one");
  await assert.rejects(execute(session, { type: "back" }), proxyError);
  failed.add("/two");
  await assert.rejects(execute(session, { type: "forward" }), proxyError);

  await navigate("/service-worker");
  await page.evaluate(async () => {
    await navigator.serviceWorker.register("/sw.js");
    await navigator.serviceWorker.ready;
    if (!navigator.serviceWorker.controller) {
      await new Promise((resolve) => navigator.serviceWorker.addEventListener("controllerchange", resolve, { once: true }));
    }
  });
  await assert.rejects(navigate("/passthrough"), proxyError);
  assert.equal((await navigate("/sw-response")).data.status, 502);
  assert.equal((await navigate("/sw-response#details")).data.status, null);
});

test("empty synthetic response diagnostics produce a useful fallback", async () => {
  const execute = actions().executeAction;
  const response = {
    fromServiceWorker: () => false,
    headers: () => ({ "x-huntproxy-proxy-error": "v1:" }),
    status: () => 504,
  };
  const page = {
    bringToFront: async () => {}, goto: async () => response,
    context: () => ({ on() {}, off() {} }),
  };
  await assert.rejects(execute({ page }, { type: "navigate", url: "http://localhost/" }),
    (error) => error.code === -32000 && error.message === "HuntProxy proxy error (HTTP 504)");
});
