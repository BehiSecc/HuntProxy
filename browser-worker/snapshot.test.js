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
  return vm.runInNewContext(`${between("function locatorFor", "async function pageSummaries")}
    ${between("function proxyErrorMarker", "async function clearCookieIdentities")}
    ({ executeAction, snapshotSlice, MAX_SNAPSHOT_BYTES });`, {
    Buffer, setTimeout, clearTimeout,
    activePage: async (session) => session.page,
    reconcileCurrentOriginStorage: async () => {},
    rpcError: (code, message) => Object.assign(new Error(message), { code }),
  });
}

function tracking() {
  return vm.runInNewContext(`${between("const MAX_SESSION_EVENTS", "async function activePage")}
    ${between("function requireRuntimeGeneration", "async function performPages")}
    ${between("async function performEvents", "async function performScroll")}
    ({ initializeSessionTracking, performEvents, recordSessionEvent });`, {
    Buffer, URL, setTimeout, rpcError: (code, message) => ({ code, message }),
  });
}

// Reads every page of a snapshot by following next_offset.
async function readAll(execute, session, action) {
  const pages = [];
  let offset = 0;
  for (;;) {
    const { data } = await execute(session, { ...action, type: "snapshot", offset });
    pages.push(data);
    if (data.next_offset === undefined) return pages;
    assert.equal(data.truncated, true);
    assert.equal(data.next_offset, (data.offset ?? 0) + Buffer.byteLength(data.content));
    offset = data.next_offset;
  }
}

test("snapshot slices keep whole characters and always advance", () => {
  const { snapshotSlice } = actions();
  const text = "aé🦀\"\n".repeat(50);
  const bytes = Buffer.byteLength(text);
  for (const maxBytes of [1, 2, 3, 5, 7, 64]) {
    let offset = 0;
    let joined = "";
    for (;;) {
      const slice = snapshotSlice(text, offset, maxBytes);
      assert.equal(slice.total_bytes, bytes);
      assert.ok(Buffer.byteLength(slice.content) <= Math.max(maxBytes, 4));
      joined += slice.content;
      if (slice.next_offset === undefined) break;
      assert.ok(slice.next_offset > offset);
      offset = slice.next_offset;
    }
    assert.equal(joined, text, `max_bytes ${maxBytes}`);
  }
  // An offset inside a character starts at the next whole one and says so.
  assert.deepEqual({ ...snapshotSlice("é🦀", 1, 64) }, { content: "🦀", truncated: false, total_bytes: 6, offset: 2 });
  assert.deepEqual({ ...snapshotSlice("abc", 10, 64) }, { content: "", truncated: false, total_bytes: 3, offset: 3 });
});

test("event rows omit null and empty members and the repeated generation", async () => {
  const tracker = tracking();
  const session = { context: { on() {}, pages: () => [] } };
  await tracker.initializeSessionTracking(session);
  tracker.recordSessionEvent(session, "page", { action: "opened", url: null, opener_page_id: null, note: "", extra: {} });
  tracker.recordSessionEvent(session, "request", { method: "GET", url: "https://app.test/", navigation: false });
  const { data } = await tracker.performEvents(session, {});
  assert.equal(data.runtime_generation, 1);
  assert.deepEqual(JSON.parse(JSON.stringify(data.events.map((row) => Object.keys(row)))), [
    ["sequence", "kind", "observed_at", "action"],
    ["sequence", "kind", "observed_at", "method", "url", "navigation"],
  ]);
  assert.equal(data.next_sequence, 2);
  // The stored events keep their full shape.
  assert.equal(session.events[0].event.runtime_generation, 1);
});

test("snapshots of a large page page exactly, scope to a locator, and actions can return the resulting page", {
  skip: available ? false : "Playwright and Chromium are required for the browser regression",
  timeout: 120_000,
}, async (t) => {
  // Text that JSON escaping inflates, multi-byte characters, and a lot of it.
  const rows = Array.from({ length: 700 }, (_, index) =>
    `<li><a href="/item?id=${index}&q=&quot;x&quot;">Item ${index} "quoted" é🦀 \\ tab\tend</a></li>`).join("\n");
  const large = `<!doctype html><title>Catalogue</title><main><h1>Catalogue</h1>
    <section id="filters" data-kind="filters"><h2>Filters</h2><label>Name <input name="q"></label></section>
    <ul>${rows}</ul></main>`;
  const form = `<!doctype html><title>Search</title><form action="/results"><label>Query <input name="q"></label>
    <button>Search</button></form><a href="/results?q=link">Results</a>`;
  const server = http.createServer((request, response) => {
    response.setHeader("Content-Type", "text/html; charset=utf-8");
    const url = new URL(request.url, "http://localhost");
    if (url.pathname === "/large") response.end(large);
    else if (url.pathname === "/results") {
      response.end(`<!doctype html><title>Results</title><h1>Results for ${url.searchParams.get("q")}</h1>`);
    } else response.end(form);
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const require = createRequire(path.join(runtime.playwright_core_path, "package.json"));
  const { chromium } = require(runtime.playwright_core_path);
  const browser = await chromium.launch({ executablePath: runtime.chromium_path, headless: true });
  t.after(() => browser.close());
  const context = await browser.newContext();
  const page = await context.newPage();
  const session = { context, page };
  const { executeAction: execute, MAX_SNAPSHOT_BYTES } = actions();
  const base = `http://127.0.0.1:${server.address().port}`;
  await execute(session, { type: "navigate", url: `${base}/large` });

  const html = await page.content();
  const tree = await page.locator("body").ariaSnapshot();
  for (const [format, full] of [["dom", html], ["accessibility", tree]]) {
    assert.ok(Buffer.byteLength(full) > 2 * MAX_SNAPSHOT_BYTES, format);
    // Even an explicit request for megabytes ships at most one budget.
    const { data: first } = await execute(session, { type: "snapshot", format, max_bytes: 2_000_000 });
    assert.equal(first.format, format);
    assert.ok(Buffer.byteLength(first.content) <= MAX_SNAPSHOT_BYTES);
    assert.equal(first.total_bytes, Buffer.byteLength(full));
    const pages = await readAll(execute, session, { format });
    assert.equal(pages.map((slice) => slice.content).join(""), full, format);
    assert.equal(pages.at(-1).truncated, false);
  }

  const { data: filters } = await execute(session, { type: "snapshot", format: "dom", locator: { css: "#filters" } });
  assert.match(filters.content, /^<section id="filters" data-kind="filters"><h2>Filters<\/h2>/);
  assert.equal(filters.truncated, false);
  assert.ok(!filters.content.includes("Item 1"));
  const { data: region } = await execute(session, { type: "snapshot", locator: { css: "#filters" } });
  assert.match(region.content, /heading "Filters"/);
  assert.ok(!region.content.includes("Item 1"));
  await assert.rejects(execute(session, { type: "snapshot", locator: { css: "li" } }), /strict mode violation/);

  // Without the flag an action returns only its own result.
  await execute(session, { type: "navigate", url: base });
  const filled = await execute(session, { type: "fill", locator: { role: "textbox", name: "Query" }, value: "shoes" });
  assert.equal(filled.data, null);
  const pressed = await execute(session, { type: "press", locator: { role: "textbox", name: "Query" }, key: "Enter", snapshot: true });
  assert.match(pressed.data.snapshot.content, /heading "Results for shoes"/);
  assert.equal(pressed.data.snapshot.truncated, false);
  const back = await execute(session, { type: "back", snapshot: true });
  assert.match(back.data.snapshot.content, /button "Search"/);
  assert.match(back.data.url, /127\.0\.0\.1/);
  const clicked = await execute(session, { type: "click", locator: { role: "link", name: "Results" }, snapshot: true });
  assert.match(clicked.data.snapshot.content, /heading "Results for link"/);
  assert.ok(clicked.data.url.endsWith("/results?q=link"));
  const navigated = await execute(session, { type: "navigate", url: `${base}/large`, snapshot: true });
  assert.equal(navigated.data.status, 200);
  assert.ok(Buffer.byteLength(navigated.data.snapshot.content) <= MAX_SNAPSHOT_BYTES);
  assert.equal(navigated.data.snapshot.total_bytes, Buffer.byteLength(tree));
  assert.equal(navigated.data.snapshot.next_offset, Buffer.byteLength(navigated.data.snapshot.content));
  // The rest is read with ordinary snapshot paging.
  const { data: rest } = await execute(session, { type: "snapshot", offset: navigated.data.snapshot.next_offset });
  assert.ok(tree.startsWith(navigated.data.snapshot.content + rest.content));
  // A snapshot never takes the flag itself.
  const plain = await execute(session, { type: "snapshot", snapshot: true, locator: { css: "#filters" } });
  assert.equal(plain.data.snapshot, undefined);
});
