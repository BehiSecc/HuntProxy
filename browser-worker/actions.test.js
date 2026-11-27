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
const between = (start, end) => source.slice(source.indexOf(start), source.indexOf(end));

// Load the actual action functions without starting the worker's stdio loop.
function actions() {
  return vm.runInNewContext(`${between("function publicLocation", "function recordSessionEvent")}
    ${between("async function uploadFiles", "async function inspectRuntime")}
    ${between("function locatorFor", "async function pageSummaries")}
    ${between("async function browserRequestInIsolatedWorld", "function proxyErrorMarker")}
    ${between("function proxyErrorMarker", "async function clearCookieIdentities")}
    ({ executeAction, actionError, actionTimeout, evaluationValue, LOCATOR_TIMEOUT_MS, NAVIGATION_TIMEOUT_MS,
      MAX_SNAPSHOT_BYTES });`, {
    Buffer, URL, fs, path, setTimeout, clearTimeout,
    activePage: async (session) => session.page,
    reconcileCurrentOriginStorage: async () => {},
    rpcError: (code, message) => Object.assign(new Error(message), { code }),
  });
}

function listen(handler) {
  return new Promise((resolve) => {
    const server = http.createServer(handler);
    server.listen(0, "127.0.0.1", () => resolve(server));
  });
}

// Playwright's messages as 1.63 writes them, call-log dimming included.
const dim = (line) => `\x1b[2m${line}\x1b[22m`;
const playwright = (head, ...log) => new Error([head, "Call log:", ...log.map(dim)].join("\n"));

test("locator failures say what went wrong and what to do, without the repeated call log", () => {
  const { actionError } = actions();
  const click = { type: "click", locator: { css: "#go" }, timeout_ms: 800 };
  const message = (error, action = click) => actionError(error, action).message;

  assert.equal(message(playwright("locator.click: Timeout 800ms exceeded.", "  - waiting for locator('#missing')")),
    "no element matched locator('#missing') within 800 ms; take a snapshot to see what is on the page");
  assert.equal(message(playwright("locator.waitFor: Timeout 300ms exceeded.", "  - waiting for locator('#late') to be visible"),
    { type: "wait", for_what: "selector", value: "#late" }),
  "no element matched locator('#late') within 300 ms; take a snapshot to see what is on the page");

  const retries = Array.from({ length: 20 }, () => [
    "    2 × waiting for element to be visible, enabled and stable",
    "      - <div id=\"overlay\" class=\"cdk-overlay-backdrop\"></div> intercepts pointer events",
    "    - retrying click action",
  ]).flat();
  const intercepted = playwright("locator.click: Timeout 800ms exceeded.", "  - waiting for locator('#go')",
    "    - locator resolved to <button id=\"go\">Go</button>", "  - attempting click action", ...retries);
  assert.equal(message(intercepted), "locator('#go') was found, but <div id=\"overlay\" class=\"cdk-overlay-backdrop\"></div> "
    + "intercepts pointer events, so the click could not land within 800 ms. Close the overlay first (press Escape or "
    + "click its close control), or click the element itself from browser_evaluate with element.click().");

  assert.match(message(playwright("locator.selectOption: Error: Element is not a <select> element",
    "  - waiting for locator('#box')", "    - locator resolved to <div id=\"box\" role=\"listbox\">x</div>"),
  { type: "select", locator: { css: "#box" }, value: "a" }),
  /^locator\.selectOption: Error: Element is not a <select> element\n.*custom listbox: click it, then click the option\.$/s);
  assert.match(message(playwright("locator.setInputFiles: Error: Node is not an HTMLInputElement",
    "  - waiting for locator('#box')"), { type: "upload", locator: { css: "#box" }, files: [] }),
  /input\[type=file\].*via_chooser:true/s);

  // Anything else keeps its message and the first lines of its log.
  const hidden = playwright("locator.fill: Timeout 800ms exceeded.", "  - waiting for locator('#name')",
    "    - locator resolved to <input id=\"name\" hidden/>", "  - fill(\"a\")", "  - attempting fill action",
    ...Array.from({ length: 30 }, () => "    - element is not visible"));
  assert.equal(message(hidden), "locator.fill: Timeout 800ms exceeded.\nCall log:\n  - waiting for locator('#name')\n"
    + "  - locator resolved to <input id=\"name\" hidden/>\n  - fill(\"a\")\n  - attempting fill action");

  // The strict-mode hint stays.
  assert.match(message(playwright("locator.click: Error: strict mode violation: locator('li') resolved to 3 elements:",
    "  - waiting for locator('li')")), /Set nth on the locator/);

  // Errors of HuntProxy's own, and ones without a locator, are returned as they are.
  const own = Object.assign(new Error("frame matches no frame"), { code: -32602 });
  assert.equal(actionError(own, click), own);
  const navigation = playwright("page.goto: Timeout 30000ms exceeded.", "  - navigating to \"https://app.test/\"");
  assert.equal(actionError(navigation, { type: "navigate", url: "https://app.test/" }), navigation);
});

test("timeouts default per kind of action and stay within 1..30000 ms", () => {
  const { actionTimeout, LOCATOR_TIMEOUT_MS, NAVIGATION_TIMEOUT_MS } = actions();
  assert.equal(LOCATOR_TIMEOUT_MS, 10_000);
  assert.equal(NAVIGATION_TIMEOUT_MS, 30_000);
  assert.equal(actionTimeout({}, LOCATOR_TIMEOUT_MS), 10_000);
  assert.equal(actionTimeout({ timeout_ms: null }, NAVIGATION_TIMEOUT_MS), 30_000);
  assert.equal(actionTimeout({ timeout_ms: 2500 }, LOCATOR_TIMEOUT_MS), 2500);
  for (const timeout of [0, 30_001, 1.5, "100"]) {
    assert.throws(() => actionTimeout({ timeout_ms: timeout }, LOCATOR_TIMEOUT_MS), /timeout_ms must be 1\.\.30000/);
  }
});

test("an evaluated object or array is returned as JSON when it fits", () => {
  const { evaluationValue, MAX_SNAPSHOT_BYTES } = actions();
  assert.deepEqual(evaluationValue({ a: [1, "x"] }), { a: [1, "x"] });
  assert.deepEqual(evaluationValue([]), []);
  for (const value of ["text", 1, null, undefined, true]) assert.equal(evaluationValue(value), undefined);
  assert.equal(evaluationValue(["x".repeat(MAX_SNAPSHOT_BYTES)]), undefined);
});

test("interactions honour timeout_ms, wait_ms, max_bytes and wait_until, and requests handle redirects", {
  skip: available ? false : "Playwright and Chromium are required for the browser regression",
  timeout: 120_000,
}, async (t) => {
  const hits = new Map();
  const app = await listen((request, response) => {
    const url = new URL(request.url, "http://localhost");
    hits.set(url.pathname, (hits.get(url.pathname) ?? 0) + 1);
    if (url.pathname === "/redirect") {
      response.writeHead(302, { location: "/target" });
      return response.end();
    }
    if (url.pathname === "/target") {
      response.setHeader("Content-Type", "application/json");
      return response.end(JSON.stringify({ arrived: true }));
    }
    if (url.pathname === "/broken") return request.socket.destroy();
    response.setHeader("Content-Type", "text/html; charset=utf-8");
    response.end(`<!doctype html><title>Form</title>
      <button id="later">Show later</button><p id="status">idle</p>
      <button id="covered">Covered</button>
      <div id="overlay" class="cdk-overlay-backdrop" style="position:fixed;left:0;top:0;width:100vw;height:100vh"></div>
      <div id="listbox" role="listbox">Pick</div>
      <ul>${"<li>row of a long list</li>".repeat(200)}</ul>
      <script>
        document.querySelector("#later").addEventListener("click", () => setTimeout(() => {
          document.querySelector("#status").textContent = "ready";
        }, 800));
        document.querySelector("#covered").addEventListener("click", () => { window.coveredClicks = (window.coveredClicks || 0) + 1; });
      </script>`);
  });
  t.after(() => new Promise((resolve) => { app.close(resolve); app.closeAllConnections(); }));
  const base = `http://127.0.0.1:${app.address().port}`;
  const require = createRequire(path.join(runtime.playwright_core_path, "package.json"));
  const { chromium } = require(runtime.playwright_core_path);
  const browser = await chromium.launch({ executablePath: runtime.chromium_path, headless: true });
  t.after(() => browser.close());
  const context = await browser.newContext();
  const page = await context.newPage();
  const session = { context, page };
  const { executeAction } = actions();
  // Copied out of the vm realm the worker functions were loaded in.
  const execute = async (action) => JSON.parse(JSON.stringify(await executeAction(session, action)));
  const failure = async (action) => {
    const started = Date.now();
    const error = await executeAction(session, action).then(() => null, (thrown) => thrown);
    assert.ok(error, `${JSON.stringify(action)} should fail`);
    return { message: error.message, elapsed: Date.now() - started };
  };

  await t.test("navigate waits as asked", async () => {
    const result = await execute({ type: "navigate", url: base, wait_until: "networkidle", timeout_ms: 20_000 });
    assert.equal(result.data.status, 200);
    assert.match((await failure({ type: "navigate", url: base, wait_until: "commit" })).message, /wait_until must be/);
  });

  await t.test("a locator timeout is the one asked for and says nothing matched", async () => {
    const { message, elapsed } = await failure({ type: "click", locator: { css: "#missing" }, timeout_ms: 400 });
    assert.equal(message, "no element matched locator('#missing') within 400 ms; take a snapshot to see what is on the page");
    assert.ok(elapsed < 5_000, `${elapsed} ms`);
    const wait = await failure({ type: "wait", for_what: "text", value: "never shown", timeout_ms: 300 });
    assert.match(wait.message, /^no element matched getByText\('never shown'\)\.first\(\) within 300 ms/);
  });

  await t.test("an overlay that takes the click is named, with ways past it", async () => {
    const { message } = await failure({ type: "click", locator: { css: "#covered" }, timeout_ms: 600 });
    assert.match(message, /^locator\('#covered'\) was found, but <div id="overlay" class="cdk-overlay-backdrop"[^>]*><\/div> intercepts pointer events/);
    assert.match(message, /press Escape.*element\.click\(\)/);
    assert.doesNotMatch(message, /retrying/);
    // The suggested dispatched click reaches the covered element.
    await execute({ type: "evaluate", expression: "document.querySelector('#covered').click()" });
    assert.equal(await page.evaluate(() => window.coveredClicks), 1);
  });

  await t.test("select on a custom listbox says how to choose its option", async () => {
    const { message } = await failure({ type: "select", locator: { role: "listbox" }, value: "a", timeout_ms: 1_000 });
    assert.match(message, /custom listbox: click it, then click the option/);
  });

  await t.test("wait_ms pauses before the snapshot, which max_bytes bounds", async () => {
    await page.evaluate(() => document.querySelector("#overlay").remove());
    const quick = await execute({ type: "click", locator: { css: "#later" }, snapshot: true });
    assert.doesNotMatch(quick.data.snapshot.content, /ready/);
    await page.evaluate(() => { document.querySelector("#status").textContent = "idle"; });
    const settled = await execute({ type: "click", locator: { css: "#later" }, wait_ms: 1500, snapshot: true });
    assert.match(settled.data.snapshot.content, /ready/);
    const small = await execute({ type: "press", key: "Shift", snapshot: true, max_bytes: 64 });
    assert.ok(Buffer.byteLength(small.data.snapshot.content) <= 64);
    assert.equal(small.data.snapshot.truncated, true);
    assert.equal(small.data.snapshot.next_offset, Buffer.byteLength(small.data.snapshot.content));
  });

  await t.test("an upload aimed at the wrong element says what to target", async () => {
    const file = new URL("./index.js", import.meta.url).pathname;
    const direct = await failure({ type: "upload", locator: { css: "#listbox" }, files: [file], timeout_ms: 1_000 });
    assert.match(direct.message, /input\[type=file\].*via_chooser:true/s);
    const chooser = await failure({ type: "upload", locator: { css: "#status" }, files: [file], via_chooser: true, timeout_ms: 500 });
    assert.match(chooser.message, /^upload file chooser did not open within 500 ms; the locator must be the control/);
  });

  await t.test("an evaluated object comes back as JSON", async () => {
    const result = await execute({ type: "evaluate", expression: "({ ready: document.title, rows: [1, 2] })" });
    assert.deepEqual(result.data, { type: "object", value: { ready: "Form", rows: [1, 2] } });
    const large = await execute({ type: "evaluate", expression: "Array.from({ length: 5000 }, (_, id) => ({ id }))" });
    assert.equal(large.data.value, undefined);
    assert.equal(large.data.truncated, true);
    assert.ok(large.data.content.startsWith("[{\"id\":0},"));
  });

  await t.test("a request stops at a redirect unless follow_redirects, and is sent once", async () => {
    hits.clear();
    const stopped = await failure({ type: "request", method: "GET", url: `${base}/redirect` });
    assert.match(stopped.message, /got a redirect, which page fetch cannot expose; pass follow_redirects:true/);
    assert.equal(hits.get("/redirect"), 1);
    assert.equal(hits.get("/target"), undefined);
    const followed = await execute({ type: "request", method: "GET", url: `${base}/redirect`, follow_redirects: true });
    assert.equal(followed.data.status, 200);
    assert.equal(followed.data.final_url, `${base}/target`);
    assert.equal(hits.get("/redirect"), 2);
    assert.equal(hits.get("/target"), 1);
    const broken = await failure({ type: "request", method: "POST", url: `${base}/broken`, body_text: "x" });
    assert.equal(broken.message, "browser request failed without a response (network error, CORS or CSP); it was not retried");
  });
});
