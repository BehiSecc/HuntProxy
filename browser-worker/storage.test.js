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

function seeding() {
  const code = source.slice(source.indexOf("const STORAGE_SEED_STEP_MS"), source.indexOf("async function extractCheckpoint"));
  return vm.runInNewContext(`${code}\n({ seedBrowserStorage, navigateAfterSeed });`, {
    URL, Date, Set, Object, String, Array, Boolean, Promise, setTimeout, clearTimeout,
    rpcError: (code, message) => ({ code, message }),
    activePage: async (session) => session.page,
    navigateWithProxyCheck: async (page, operation) => operation(),
    reconcileCurrentOriginStorage: async () => {},
  });
}

const swScript = (marker) => `self.addEventListener('install', e => e.waitUntil(self.skipWaiting()));
self.addEventListener('activate', e => e.waitUntil(self.clients.claim()));
self.addEventListener('fetch', e => {
  if (e.request.mode === 'navigate' && new URL(e.request.url).pathname === '/') {
    e.respondWith(new Response('<!doctype html><title>${marker}</title>sw', { headers: { 'Content-Type': 'text/html' } }));
  }
});`;

async function harness(t, args = []) {
  const requests = [];
  const server = http.createServer((request, response) => {
    requests.push(request.url);
    response.setHeader("Cache-Control", "no-store");
    if (request.url === "/sw.js") {
      response.setHeader("Content-Type", "application/javascript");
      response.end(swScript("SW"));
      return;
    }
    response.setHeader("Content-Type", "text/html");
    response.end("<!doctype html><title>real</title>real");
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const require = createRequire(path.join(runtime.playwright_core_path, "package.json"));
  const { chromium } = require(runtime.playwright_core_path);
  const browser = await chromium.launch({ executablePath: runtime.chromium_path, headless: true, args });
  t.after(() => browser.close());
  const context = await browser.newContext({ serviceWorkers: "allow" });
  const page = await context.newPage();
  const origin = `http://127.0.0.1:${server.address().port}`;
  const real = () => requests.filter((url) => url !== "/favicon.ico");
  return { requests: real, context, page, origin };
}

const read = (page) => page.evaluate(() => ({
  local: Object.fromEntries(Object.entries(localStorage)),
  session: Object.fromEntries(Object.entries(sessionStorage)),
}));

test("storage seed writes every origin without contacting the server and removes its route", {
  skip: available ? false : "Playwright and Chromium are required for the browser regression",
  timeout: 60_000,
}, async (t) => {
  const { requests, context, page, origin } = await harness(t);
  const other = origin.replace("127.0.0.1", "localhost");
  const { seedBrowserStorage } = seeding();
  const session = { context, page, restoredOrigins: new Set(), restoreState: {
    local_storage: { [origin]: { old: "checkpoint" } }, session_storage: {},
  } };
  const seeded = await seedBrowserStorage(session, { origins: [
    { origin, local_storage: [{ name: "token", value: "t1" }], session_storage: [{ name: "csrf", value: "c1" }] },
    { origin: other, local_storage: [{ name: "idp", value: "i1" }], session_storage: [] },
  ] });
  assert.equal(seeded.returnTo, "about:blank");
  assert.deepEqual(requests(), [], "seeding must not reach the server");
  // The seed wins over the older checkpoint.
  assert.deepEqual(session.restoreState.local_storage[origin], { token: "t1" });
  assert.deepEqual(session.restoreState.session_storage[origin], { csrf: "c1" });
  assert.ok(session.restoredOrigins.has(origin) && session.restoredOrigins.has(other));

  // The route is gone: the next navigation is real.
  await page.goto(`${origin}/`);
  assert.deepEqual(requests(), ["/"]);
  assert.deepEqual(await read(page), { local: { token: "t1" }, session: { csrf: "c1" } });
  await page.goto(`${other}/`);
  assert.deepEqual((await read(page)).local, { idp: "i1" });

  // Re-seeding replaces rather than merges, and clear_origins empties an origin.
  await seedBrowserStorage(session, {
    origins: [{ origin, local_storage: [{ name: "token", value: "t2" }] }],
    clear_origins: [other],
  });
  assert.equal(requests().length, 2, "re-seeding must not reach the server either");
  await page.goto(`${origin}/`);
  assert.deepEqual(await read(page), { local: { token: "t2" }, session: {} });
  await page.goto(`${other}/`);
  assert.deepEqual(await read(page), { local: {}, session: {} });
});

test("storage seed is not intercepted by a service worker and returns to the previous page", {
  skip: available ? false : "Playwright and Chromium are required for the browser regression",
  timeout: 60_000,
}, async (t) => {
  const { requests, context, page, origin } = await harness(t);
  const { seedBrowserStorage, navigateAfterSeed } = seeding();
  await page.goto(`${origin}/plain`);
  await page.evaluate(async () => {
    await navigator.serviceWorker.register("/sw.js", { scope: "/" });
    await navigator.serviceWorker.ready;
  });
  // A controlled navigation to / is answered by the worker, not the network.
  await page.goto(`${origin}/`);
  assert.equal(await page.title(), "SW");
  await page.goto(`${origin}/plain`);
  const before = requests().length;

  const session = { context, page };
  const seeded = await seedBrowserStorage(session, {
    origins: [{ origin, local_storage: [{ name: "token", value: "sw-token" }] }],
  });
  assert.equal(seeded.returnTo, `${origin}/plain`);
  assert.equal(requests().length, before, "neither the network nor the worker's origin saw the seed");
  await navigateAfterSeed(session, seeded, null);
  assert.equal(page.url(), `${origin}/plain`);
  assert.deepEqual((await read(page)).local, { token: "sw-token" });
  // The bypass was lifted: the worker answers the app's first real load again.
  await page.goto(`${origin}/`);
  assert.equal(await page.title(), "SW");
  assert.deepEqual((await read(page)).local, { token: "sw-token" });
});

test("storage seed failures name the origin, never the value, and always remove the route", {
  skip: available ? false : "Playwright and Chromium are required for the browser regression",
  timeout: 90_000,
}, async (t) => {
  const { requests, context, page, origin } = await harness(t);
  const { seedBrowserStorage } = seeding();
  const session = { context, page };
  const secret = "SECRET-".repeat(2_000_000);
  await assert.rejects(
    seedBrowserStorage(session, { origins: [{ origin, local_storage: [{ name: "big", value: secret }] }] }),
    (error) => error.code === -32000 && error.message.includes(origin)
      && /QuotaExceededError/.test(error.message) && !error.message.includes("SECRET"),
  );
  await assert.rejects(seedBrowserStorage(session, { origins: [{ origin: `${origin}/path` }] }),
    (error) => error.code === -32602);
  // After failures the route is gone and the failed origin kept nothing.
  assert.deepEqual(requests(), []);
  await page.goto(`${origin}/`);
  assert.deepEqual(requests(), ["/"]);
  assert.deepEqual(await read(page), { local: {}, session: {} });
});

test("storage seed on an origin whose storage is disabled fails fast instead of hanging", {
  skip: available ? false : "Playwright and Chromium are required for the browser regression",
  timeout: 60_000,
}, async (t) => {
  const { requests, context, page, origin } = await harness(t, ["--disable-local-storage"]);
  const { seedBrowserStorage } = seeding();
  const started = Date.now();
  await assert.rejects(
    seedBrowserStorage({ context, page }, { origins: [{ origin, local_storage: [{ name: "k", value: "SECRET" }] }] }),
    (error) => error.code === -32000 && error.message.includes(origin) && !error.message.includes("SECRET"),
  );
  assert.ok(Date.now() - started < 15_000);
  // The route was removed even though the write failed.
  await page.goto(`${origin}/`);
  assert.deepEqual(requests(), ["/"]);
});
