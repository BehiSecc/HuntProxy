import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import net from "node:net";
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
  const code = source.slice(source.indexOf("// The sessionStorage saved for every origin"), source.indexOf("async function extractCheckpoint"));
  return vm.runInNewContext(`${code}\n({ seedBrowserStorage, navigateAfterSeed, pendingStorageRestore });`, {
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
  t.after(() => new Promise((resolve) => { server.close(resolve); server.closeAllConnections(); }));
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
  // The seeding document is the locally fulfilled one, not the worker's page.
  assert.equal(await page.title(), "storage seed");
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

test("a relaunched profile gets its saved storage back before the first load", {
  skip: available ? false : "Playwright and Chromium are required for the browser regression",
  timeout: 60_000,
}, async (t) => {
  const { requests, context, page, origin } = await harness(t);
  const { seedBrowserStorage, pendingStorageRestore } = seeding();
  const state = {
    local_storage: { [origin]: { token: "saved" } },
    session_storage: { [origin]: { csrf: "saved-csrf" } },
  };
  const session = { context, page, restoreState: state, restoredOrigins: new Set(), preferProfileState: true };
  // An initialized Chromium profile keeps localStorage itself: only sessionStorage is restored.
  const plain = (value) => JSON.parse(JSON.stringify(value));
  const restore = plain(pendingStorageRestore(session, `${origin}/app`));
  assert.deepEqual(restore, { origin, local_storage: [], session_storage: [{ name: "csrf", value: "saved-csrf" }], keep_local: true });
  await page.goto(`${origin}/`);
  await page.evaluate(() => localStorage.setItem("native", "kept"));
  const before = requests().length;
  await seedBrowserStorage(session, { origins: [restore] });
  assert.equal(requests().length, before);
  await page.goto(`${origin}/`);
  assert.deepEqual(await read(page), { local: { native: "kept" }, session: { csrf: "saved-csrf" } });
  assert.equal(pendingStorageRestore(session, `${origin}/app`), null, "each origin is restored once");
  // A fresh Chromium directory restores localStorage from the checkpoint too.
  const fresh = { ...session, preferProfileState: false, restoredOrigins: new Set() };
  assert.deepEqual(plain(pendingStorageRestore(fresh, `${origin}/`).local_storage), [{ name: "token", value: "saved" }]);
  assert.equal(pendingStorageRestore(fresh, "about:blank"), null);
  assert.equal(pendingStorageRestore({ ...fresh, restoreState: null }, `${origin}/`), null);
});

function handoff() {
  const cut = (from, to) => source.slice(source.indexOf(from), source.indexOf(to));
  const code = `${cut("async function checkpointRuntimePages", "async function launchSessionRuntime")}\n${cut("// The sessionStorage saved for every origin", "async function extractCheckpoint")}`;
  return vm.runInNewContext(`${code}\n({ checkpointRuntimePages, restoreRuntimePages, seedBrowserStorage });`, {
    URL, Date, Set, Object, String, Array, Boolean, Promise, setTimeout, clearTimeout,
    rpcError: (code, message) => ({ code, message }),
    activePage: async (session) => session.page,
    navigateWithProxyCheck: async (page, operation) => operation(),
    reconcileCurrentOriginStorage: async () => {},
  });
}

// Mirrors relaunchSession: capture the tabs, start a fresh browser (Chromium
// drops sessionStorage on exit), and restore the tabs into it.
async function relaunch(t, session) {
  const { checkpointRuntimePages, restoreRuntimePages } = handoff();
  const state = await checkpointRuntimePages(session);
  await session.browser.close();
  const require = createRequire(path.join(runtime.playwright_core_path, "package.json"));
  const { chromium } = require(runtime.playwright_core_path);
  const browser = await chromium.launch({ executablePath: runtime.chromium_path, headless: true });
  t.after(() => browser.close().catch(() => {}));
  const context = await browser.newContext({ serviceWorkers: "allow" });
  const next = { context };
  await restoreRuntimePages(next, state);
  Object.assign(session, { browser, context, page: next.page });
  return state;
}

test("a CDP handoff keeps seeded sessionStorage for a tab that sits on about:blank, in both directions", {
  skip: available ? false : "Playwright and Chromium are required for the browser regression",
  timeout: 120_000,
}, async (t) => {
  const { requests, context, page, origin } = await harness(t);
  const other = origin.replace("127.0.0.1", "localhost");
  const { seedBrowserStorage } = handoff();
  const session = { browser: context.browser(), context, page, restoredOrigins: new Set(), restoreState: { local_storage: {}, session_storage: {} } };
  try {
    await seedBrowserStorage(session, { origins: [
      { origin, session_storage: [{ name: "token", value: "pasted-token" }, { name: "csrf", value: "pasted-csrf" }] },
      { origin: other, session_storage: [{ name: "other", value: "second" }] },
    ] });
    await session.page.goto("about:blank");
    const seededRequests = requests().length;

    // Enable: the tab is on about:blank, yet the helper finds the storage once it navigates.
    await relaunch(t, session);
    assert.equal(session.page.url(), "about:blank");
    assert.equal(requests().length, seededRequests, "restoring reaches no target");
    await session.page.goto(`${origin}/`);
    assert.deepEqual((await read(session.page)).session, { token: "pasted-token", csrf: "pasted-csrf" });

    // The app changes a value and drops one; the next handoff (disable, tab on the app) keeps the live values.
    await session.page.evaluate(() => { sessionStorage.setItem("token", "rotated"); sessionStorage.removeItem("csrf"); });
    await relaunch(t, session);
    assert.equal(session.page.url(), `${origin}/`);
    assert.deepEqual((await read(session.page)).session, { token: "rotated" });

    // Repeated cycles with the tab back on about:blank must not resurrect the changed values.
    await session.page.goto("about:blank");
    await relaunch(t, session);
    await session.page.goto(`${origin}/`);
    assert.deepEqual((await read(session.page)).session, { token: "rotated" });
    await session.page.goto(`${other}/`);
    assert.deepEqual((await read(session.page)).session, { other: "second" });
    await session.page.goto("about:blank");
    await relaunch(t, session);
    await session.page.goto(`${other}/`);
    assert.deepEqual((await read(session.page)).session, { other: "second" });

    // An app that cleared everything stays cleared.
    await session.page.goto(`${origin}/`);
    await session.page.evaluate(() => sessionStorage.clear());
    await relaunch(t, session);
    await session.page.goto("about:blank");
    await relaunch(t, session);
    await session.page.goto(`${origin}/`);
    assert.deepEqual((await read(session.page)).session, {});
  } finally {
    // Release the relaunched browser before the harness closes its server.
    await session.browser.close().catch(() => {});
  }
});

test("a handoff restore failure is best effort and leaves no seeding route", {
  skip: available ? false : "Playwright and Chromium are required for the browser regression",
  timeout: 60_000,
}, async (t) => {
  const { requests, context, origin } = await harness(t, ["--disable-local-storage"]);
  const { restoreRuntimePages } = handoff();
  const runtimeLike = { context };
  const state = { pages: [{ url: "about:blank", session_storage: {} }], active_index: 0, storage: { [origin]: { token: "secret-value" } } };
  await restoreRuntimePages(runtimeLike, state);
  assert.equal(runtimeLike.page.url(), "about:blank");
  await runtimeLike.page.goto(`${origin}/`);
  assert.deepEqual(requests(), ["/"], "the seeding route is gone");
  assert.equal(await runtimeLike.page.title(), "real");
});

test("a handoff puts a blank tab back on about:blank even if Chromium reopened the previous page", {
  skip: available ? false : "Playwright and Chromium are required for the browser regression",
  timeout: 60_000,
}, async (t) => {
  const { context, page, origin } = await harness(t);
  const { restoreRuntimePages } = handoff();
  await page.goto(`${origin}/`);
  const runtimeLike = { context };
  await restoreRuntimePages(runtimeLike, { pages: [{ url: "about:blank", session_storage: {} }], active_index: 0, storage: {} });
  assert.equal(runtimeLike.page.url(), "about:blank");
});

test("a chrome-error tab is captured as about:blank and other unsupported tabs are still refused", {
  skip: available ? false : "Playwright and Chromium are required for the browser regression",
  timeout: 60_000,
}, async (t) => {
  const { origin } = await harness(t);
  const { checkpointRuntimePages } = handoff();
  // A browser reached over CDP, as the daemon does, strands a refused navigation on an error page.
  const probe = net.createServer();
  await new Promise((resolve) => probe.listen(0, "127.0.0.1", resolve));
  const port = probe.address().port;
  await new Promise((resolve) => probe.close(resolve));
  const require = createRequire(path.join(runtime.playwright_core_path, "package.json"));
  const { chromium } = require(runtime.playwright_core_path);
  const launched = await chromium.launch({ executablePath: runtime.chromium_path, headless: true, args: [`--remote-debugging-port=${port}`] });
  const connected = await chromium.connectOverCDP(`http://127.0.0.1:${port}`);
  try {
    const context = connected.contexts()[0];
    const page = await context.newPage();
    const session = { context, page, restoredOrigins: new Set(), restoreState: { session_storage: { [origin]: { token: "kept" } } } };
    await page.goto(`${origin}/`);
    await page.goto("http://127.0.0.1:1/").catch(() => {});
    await page.waitForURL(/^chrome-error:/, { timeout: 10_000 });
    assert.match(page.url(), /^chrome-error:/);
    const state = JSON.parse(JSON.stringify(await checkpointRuntimePages(session)));
    assert.deepEqual(state.pages, [{ url: "about:blank", session_storage: {} }]);
    assert.deepEqual(state.storage, { [origin]: { token: "kept" } }, "saved storage survives a tab on an error page");
    await page.goto("data:text/html,unsupported", { waitUntil: "commit", timeout: 10_000 });
    const refused = await checkpointRuntimePages(session).then(() => null, (error) => error);
    assert.match(refused?.message ?? "", /cannot preserve an open data: tab/);
  } finally {
    // Release the page before the harness closes its server.
    await connected.close().catch(() => {});
    await launched.close();
  }
});
