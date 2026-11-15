import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { createRequire } from "node:module";
import { spawnSync } from "node:child_process";
import { test } from "node:test";
import vm from "node:vm";
import { EventEmitter } from "node:events";

const source = fs.readFileSync(new URL("./index.js", import.meta.url), "utf8");
const inspect = spawnSync(process.execPath, [new URL("./index.js", import.meta.url).pathname, "--inspect-runtime"], {
  encoding: "utf8", timeout: 10_000,
});
const runtime = inspect.status === 0 ? JSON.parse(inspect.stdout) : {};
const available = runtime.chromium_path && runtime.playwright_core_path;

// Load the actual tracking functions without starting the worker's stdio loop.
function tracking() {
  return vm.runInNewContext(`${source.slice(source.indexOf("const MAX_SESSION_EVENTS"), source.indexOf("async function activePage"))}
    ${source.slice(source.indexOf("function requireRuntimeGeneration"), source.indexOf("async function performPages"))}
    ${source.slice(source.indexOf("async function performEvents"), source.indexOf("async function performScroll"))}
    ({ initializeSessionTracking, drainWindowMessages, disposeSessionTracking, performEvents, recordSessionEvent,
      waitForEvents, javascriptFilesSince });`, {
    Buffer, URL, setTimeout, rpcError: (code, message) => ({ code, message }),
  });
}

async function observed(tracker, session, predicate) {
  const deadline = Date.now() + 5_000;
  do {
    await tracker.drainWindowMessages(session);
    const events = session.events.map(({ event }) => event);
    if (predicate(events)) return events;
    await new Promise((resolve) => setTimeout(resolve, 20));
  } while (Date.now() < deadline);
  assert.fail("Expected browser event was not observed");
}

test("isolated message queues preserve page events, navigation, popups and diagnostics", {
  skip: available ? false : "Playwright and Chromium are required for the browser regression",
  timeout: 30_000,
}, async (t) => {
  const csp = "default-src 'self'; script-src 'self' 'unsafe-inline'; frame-src 'self'";
  const html = `<!doctype html><title>Message workspace</title>
    <a href="/next">Continue</a><button onclick="window.open('/popup')">Open details</button>
    <iframe src="/frame"></iframe>
    <script>window.postMessage('first document', '*');console.warn('workspace diagnostic');</script>`;
  const server = http.createServer((request, response) => {
    response.setHeader("Content-Type", "text/html; charset=utf-8");
    response.setHeader("Content-Security-Policy", csp);
    if (request.url === "/frame") response.end("<script>parent.postMessage([1,2,3], '*')</script>");
    else if (request.url === "/next") response.end("<!doctype html><title>Next workspace</title><script>window.postMessage('next document', '*');throw new Error('workspace diagnostic')</script>");
    else if (request.url === "/popup") response.end("<!doctype html><title>Details</title><button onclick=\"window.postMessage(new Uint8Array([1,2,3,4]), '*')\">Send details</button>");
    else response.end(html);
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  // The browser is still open when this runs; see evaluate.test.js.
  t.after(() => new Promise((resolve) => { server.close(resolve); server.closeAllConnections(); }));
  const require = createRequire(path.join(runtime.playwright_core_path, "package.json"));
  const { chromium } = require(runtime.playwright_core_path);
  const browser = await chromium.launch({ executablePath: runtime.chromium_path, headless: true });
  t.after(() => browser.close());
  const context = await browser.newContext();
  const page = await context.newPage();
  const tracker = tracking();
  const session = { context, page };
  await tracker.initializeSessionTracking(session);
  t.after(() => tracker.disposeSessionTracking(session));
  const base = `http://127.0.0.1:${server.address().port}`;
  const response = await page.goto(base);
  assert.equal((await response.body()).toString(), html);
  assert.equal(response.headers()["content-security-policy"], csp);
  assert.deepEqual(await page.evaluate(() => Object.getOwnPropertyNames(window)
    .filter((name) => name.startsWith("__huntproxy_messages_"))), []);
  let events = await observed(tracker, session, (items) => items.some((event) => event.kind === "window_message"
    && event.source_relation === "same_window" && event.data_size === 14)
    && items.some((event) => event.kind === "window_message" && event.source_relation === "other_window"));
  const first = events.find((event) => event.kind === "window_message" && event.data_size === 14);
  assert.equal(first.data_type, "string");
  assert.equal(first.origin, `${base}/`);
  assert.equal(events.some((event) => event.kind === "console" && event.level === "warning"
    && event.text === "workspace diagnostic"), true);
  assert.equal(events.some((event) => event.kind === "window_message" && event.data_type === "array" && event.data_size === 3), true);

  const popupPromise = page.waitForEvent("popup");
  await page.getByRole("button", { name: "Open details" }).click();
  const popup = await popupPromise;
  await popup.waitForLoadState();
  // Popup attachment is asynchronous. Wait for readiness before interacting;
  // first-inline-script events in a new popup have no delivery guarantee.
  await tracker.drainWindowMessages(session);
  assert.deepEqual(await popup.evaluate(() => Object.getOwnPropertyNames(window)
    .filter((name) => name.startsWith("__huntproxy_messages_"))), []);
  await popup.getByRole("button", { name: "Send details" }).click();
  events = await observed(tracker, session, (items) => items.some((event) => event.kind === "window_message"
    && event.page_id !== first.page_id && event.data_type === "typed_array" && event.data_size === 4));
  assert.equal(events.some((event) => event.kind === "popup"), true);
  await popup.close();
  await page.getByRole("link", { name: "Continue" }).click();
  events = await observed(tracker, session, (items) => items.some((event) => event.kind === "window_message"
    && event.data_size === 13) && items.some((event) => event.kind === "page_error"));
  assert.equal(events.find((event) => event.kind === "page_error").text, "Error: workspace diagnostic");
  assert.deepEqual(await page.evaluate(() => Object.getOwnPropertyNames(window)
    .filter((name) => name.startsWith("__huntproxy_messages_"))), []);
  const beforeCrossOrigin = session.eventSequence;
  await page.goto(`http://localhost:${server.address().port}/next`);
  await observed(tracker, session, (items) => items.some((event) => event.sequence > beforeCrossOrigin
    && event.kind === "window_message" && event.data_size === 13));
  await page.goBack();
  await page.evaluate(() => new Promise((resolve) => {
    window.addEventListener("message", resolve, { once: true });
    window.postMessage("restored workspace", "*");
  }));
  await observed(tracker, session, (items) => items.some((event) => event.kind === "window_message"
    && event.data_size === 18));
  const beforeBurst = session.eventSequence;
  await page.evaluate(() => new Promise((resolve) => {
    let received = 0;
    const listener = () => {
      if (++received === 140) {
        window.removeEventListener("message", listener);
        resolve();
      }
    };
    window.addEventListener("message", listener);
    for (let i = 0; i < 140; i++) window.postMessage("workspace update", "*");
  }));
  await tracker.drainWindowMessages(session);
  assert.equal(session.events.filter(({ event }) => event.sequence > beforeBurst && event.kind === "window_message").length, 128);
  assert.equal(session.events.some(({ event }) => event.kind === "observer_error"), false);
  assert.equal(session.messageObservers.size, 1);
  await tracker.disposeSessionTracking(session);
  assert.equal(session.messageObservers.size, 0);
});

test("observer setup failure preserves console/page events and stays visible through filters", async () => {
  const tracker = tracking();
  const page = new EventEmitter();
  page.isClosed = () => false;
  const context = {
    on() {}, off() {}, pages: () => [page],
    newCDPSession: async () => { throw new Error("unavailable"); },
  };
  const session = { context, page };
  await tracker.initializeSessionTracking(session);
  const warning = (text) => ({
    type: () => "warning", text: () => text,
    location: () => ({ url: "http://localhost/workspace?token=1", lineNumber: 1, columnNumber: 1 }),
  });
  page.emit("console", warning("workspace warning"));
  page.emit("pageerror", new Error("workspace diagnostic"));
  const first = await tracker.performEvents(session, {});
  assert.deepEqual(Array.from(first.data.events, (event) => event.kind), ["observer_error", "console", "page_error"]);
  // Events carry what the page said; runtime inspection still keeps only where.
  const [, said, thrown] = JSON.parse(JSON.stringify(first.data.events));
  assert.deepEqual([said.level, said.url, said.text, said.text_length], ["warning", "http://localhost/workspace", "workspace warning", undefined]);
  assert.equal(thrown.text, "Error: workspace diagnostic");
  assert.deepEqual(JSON.parse(JSON.stringify(session.runtimeErrors)), [
    { kind: "console", level: "warning", url: "http://localhost/workspace", line: 1, column: 1 }, { kind: "page_error" },
  ]);
  // A long message is cut, and says how long it was. Other levels are not recorded.
  page.emit("console", warning(`${"é".repeat(999)}😀 and the rest`));
  page.emit("console", { ...warning("just a log line"), type: () => "log" });
  const long = (await tracker.performEvents(session, { runtime_generation: 1, after_sequence: first.data.latest_sequence })).data.events;
  assert.equal(long.length, 1);
  assert.equal(long[0].text.length, 1000);
  assert.equal(long[0].text_length, 2 * 999 + 4 + " and the rest".length);
  assert.equal(first.data.observer_errors[0].operation, "initialization");
  const filtered = await tracker.performEvents(session, { kinds: ["window_message"] });
  assert.equal(filtered.data.events.length, 0);
  assert.equal(filtered.data.observer_errors[0].observer, "window_message");
  page.emit("pageerror", new Error("later diagnostic"));
  const later = await tracker.performEvents(session, {
    runtime_generation: 1, after_sequence: long[0].sequence,
  });
  assert.deepEqual(Array.from(later.data.events, (event) => event.kind), ["page_error"]);
  assert.equal(later.data.observer_errors.length, 1);
  await tracker.disposeSessionTracking(session);
});

test("observer read failure preserves buffered events and reports one persistent diagnostic", async () => {
  const tracker = tracking();
  const page = { isClosed: () => false };
  const state = {
    ready: Promise.resolve(), contexts: new Set([1]),
    connection: { send: async () => ({ exceptionDetails: { text: "unavailable" } }) },
  };
  const session = {
    pages: new Map([[1, page]]), pageIds: new WeakMap([[page, 1]]),
    messageObservers: new Map([[page, state]]), messageObserverKey: "observer",
    events: [], eventSequence: 0, eventBytes: 0, runtimeGeneration: 1,
  };
  tracker.recordSessionEvent(session, "console", { level: "warning" }, page);
  tracker.recordSessionEvent(session, "page_error", {}, page);
  const first = await tracker.performEvents(session, {});
  assert.deepEqual(Array.from(first.data.events, (event) => event.kind), ["console", "page_error", "observer_error"]);
  assert.equal(first.data.observer_errors[0].operation, "read");
  const later = await tracker.performEvents(session, {
    runtime_generation: 1, after_sequence: first.data.latest_sequence, kinds: ["observer_error"],
  });
  assert.equal(later.data.events.length, 0);
  assert.equal(later.data.observer_errors.length, 1);
});

// A page whose message observer cannot start; its other events still flow.
function quietSession() {
  const page = new EventEmitter();
  page.isClosed = () => false;
  page.url = () => "https://app.test/";
  const context = {
    on() {}, off() {}, pages: () => [page],
    newCDPSession: async () => { throw new Error("unavailable"); },
  };
  return { page, session: { context, page } };
}

test("waiting for events ends at the first match or at its deadline, without a checkpoint", async () => {
  const tracker = tracking();
  const { page, session } = quietSession();
  await tracker.initializeSessionTracking(session);
  const query = { kinds: ["page_error"] };
  const wait = async (action, milliseconds) => ({ ...await tracker.waitForEvents(session, action, milliseconds) });
  // Nothing matches: the wait lasts as long as asked.
  let started = Date.now();
  assert.deepEqual(await wait(query, 150), { ready: false });
  let elapsed = Date.now() - started;
  assert.ok(elapsed >= 150 && elapsed < 3_000, `${elapsed} ms`);
  // A match that arrives meanwhile ends it early, well before the cap below.
  setTimeout(() => page.emit("pageerror", new Error("late")), 60);
  started = Date.now();
  assert.deepEqual(await wait(query, 5_000), { ready: true });
  elapsed = Date.now() - started;
  assert.ok(elapsed < 900, `${elapsed} ms`);
  // A match that is already there is reported at once, a seen one is not.
  started = Date.now();
  assert.deepEqual(await wait(query, 5_000), { ready: true });
  assert.ok(Date.now() - started < 900);
  const seen = { ...query, runtime_generation: 1, after_sequence: session.eventSequence };
  assert.deepEqual(await wait(seen, 100), { ready: false });
  // The cursor is checked as when reading events.
  await assert.rejects(tracker.waitForEvents(session, { runtime_generation: 9 }, 100),
    (error) => error.code === -32001);
  // The worker handles one request at a time: a long wait is cut short.
  started = Date.now();
  assert.deepEqual(await wait(seen, 60_000), { ready: false });
  elapsed = Date.now() - started;
  assert.ok(elapsed >= 1_000 && elapsed < 10_000, `${elapsed} ms`);
  await tracker.disposeSessionTracking(session);
});

function scriptResponse(url, { status = 200, type = "application/javascript" } = {}) {
  return {
    url: () => url, status: () => status, headers: () => ({ "content-type": type }),
    request: () => ({
      frame: () => ({ url: () => "https://app.test/" }),
      resourceType: () => "script", isNavigationRequest: () => false,
    }),
  };
}

test("each JavaScript file is reported once, also across a CDP handoff or resume", async () => {
  const tracker = tracking();
  const { page, session } = quietSession();
  await tracker.initializeSessionTracking(session);
  // Objects made inside the vm have another realm's prototypes.
  const since = (cursor) => JSON.parse(JSON.stringify(tracker.javascriptFilesSince(session, cursor)));
  const urls = (reply) => reply.files.map((file) => file.url);
  page.emit("response", scriptResponse("https://app.test/a.js"));
  page.emit("response", scriptResponse("https://app.test/b.mjs", { type: "text/plain" }));
  page.emit("response", scriptResponse("https://app.test/page", { type: "text/html" }));
  const first = since();
  assert.deepEqual(urls(first), ["https://app.test/a.js", "https://app.test/b.mjs"]);
  assert.deepEqual(Object.keys(first.files[0]).sort(),
    ["host", "mime", "path", "source_page_url", "status_code", "url"]);
  assert.equal(first.cursor, 2);
  assert.deepEqual(since(first.cursor), { files: [], cursor: 2 });

  // The same response again is not news; a changed one is, alone.
  page.emit("response", scriptResponse("https://app.test/a.js"));
  assert.deepEqual(since(2), { files: [], cursor: 2 });
  page.emit("response", scriptResponse("https://app.test/a.js", { status: 304 }));
  const changed = since(2);
  assert.deepEqual(changed.files.map((file) => [file.url, file.status_code]), [["https://app.test/a.js", 304]]);
  assert.equal(changed.cursor, 3);

  // A handoff or resume replaces the browser runtime but not the session: what
  // was reported stays reported, and new files still count on from the cursor.
  const known = new Map(session.javascriptFiles);
  await tracker.disposeSessionTracking(session);
  const relaunched = quietSession();
  Object.assign(session, relaunched.session);
  await tracker.initializeSessionTracking(session, known, 2);
  assert.deepEqual(since(3), { files: [], cursor: 3 });
  relaunched.page.emit("response", scriptResponse("https://app.test/c.js"));
  const resumed = since(3);
  assert.deepEqual(urls(resumed), ["https://app.test/c.js"]);
  assert.equal(resumed.cursor, 4);

  // No cursor, or one this session never issued, means everything.
  for (const cursor of [undefined, null, -1, 99, "2", 1.5]) {
    assert.equal(since(cursor).files.length, 3, String(cursor));
  }
  await tracker.disposeSessionTracking(session);
});
