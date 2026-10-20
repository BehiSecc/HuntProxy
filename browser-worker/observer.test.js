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
    ({ initializeSessionTracking, drainWindowMessages, disposeSessionTracking, performEvents, recordSessionEvent });`, {
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
  t.after(() => new Promise((resolve) => server.close(resolve)));
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
  assert.equal(events.some((event) => event.kind === "console" && event.level === "warning"), true);
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
  page.emit("console", {
    type: () => "warning",
    location: () => ({ url: "http://localhost/workspace", lineNumber: 1, columnNumber: 1 }),
  });
  page.emit("pageerror", new Error("workspace diagnostic"));
  const first = await tracker.performEvents(session, {});
  assert.deepEqual(Array.from(first.data.events, (event) => event.kind), ["observer_error", "console", "page_error"]);
  assert.equal(first.data.observer_errors[0].operation, "initialization");
  const filtered = await tracker.performEvents(session, { kinds: ["window_message"] });
  assert.equal(filtered.data.events.length, 0);
  assert.equal(filtered.data.observer_errors[0].observer, "window_message");
  page.emit("pageerror", new Error("later diagnostic"));
  const later = await tracker.performEvents(session, {
    runtime_generation: 1, after_sequence: first.data.latest_sequence,
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
