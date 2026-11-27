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
    ${between("function locatorFor", "async function pageSummaries")}
    ${between("function proxyErrorMarker", "async function clearCookieIdentities")}
    ({ executeAction, evaluationContent, MAX_SNAPSHOT_BYTES });`, {
    Buffer, URL, setTimeout, clearTimeout,
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

test("evaluation content keeps strings verbatim and encodes everything else as JSON", () => {
  const { evaluationContent } = actions();
  assert.equal(evaluationContent("a \"quoted\"\nline"), "a \"quoted\"\nline");
  assert.equal(evaluationContent({ a: [1, null, "x"] }), "{\"a\":[1,null,\"x\"]}");
  assert.equal(evaluationContent(0), "0");
  assert.equal(evaluationContent(false), "false");
  assert.equal(evaluationContent(null), "null");
  assert.equal(evaluationContent(undefined), "undefined");
});

test("evaluate runs page JavaScript in the selected page and its frames", {
  skip: available ? false : "Playwright and Chromium are required for the browser regression",
  timeout: 180_000,
}, async (t) => {
  // A second local origin, embedded both same-site and cross-site.
  const widget = await listen((request, response) => {
    response.setHeader("Content-Type", "text/html; charset=utf-8");
    if (request.url.startsWith("/legal")) return response.end("<!doctype html><title>Legal</title><p>No scripts here</p>");
    response.end(`<!doctype html><title>Widget</title><p id="who">widget</p>
      <script>window.widget = { host: location.host, path: location.pathname };</script>`);
  });
  const widgetPort = widget.address().port;
  let posts = 0;
  const app = await listen((request, response) => {
    const url = new URL(request.url, "http://localhost");
    if (url.pathname === "/app.js") {
      response.setHeader("Content-Type", "text/javascript");
      return response.end(`window.app = { token: "tok-123", user: { id: 7, roles: ["admin"] }, sign(value) { return "sig:" + value; } };
        localStorage.setItem("session", "abc");
        window.addEventListener("message", function onMessage() {});
        window.cart = { items: [1, 2], get total() { throw new Error("price service down"); } };`);
    }
    if (url.pathname === "/api/items") {
      if (request.method === "POST") posts += 1;
      response.setHeader("Content-Type", "application/json");
      return response.end(JSON.stringify({ method: request.method, items: [{ id: 1, name: "one" }, { id: 2, name: "two" }] }));
    }
    response.setHeader("Content-Type", "text/html; charset=utf-8");
    if (url.pathname === "/plain") return response.end("<!doctype html><title>Plain</title><p>No frames</p>");
    if (url.pathname === "/next") return response.end("<!doctype html><title>Next</title><p>Arrived</p>");
    // Inline script and eval are both forbidden to the page itself.
    response.setHeader("Content-Security-Policy", "script-src 'self'; require-trusted-types-for 'script'");
    response.end(`<!doctype html><title>Shop</title><h1 id="title">Shop <b>open</b></h1>
      <nav><a href="/a?x=1">First</a><a href="/b">Second</a></nav><!-- note -->
      <p id="terms">${"terms and conditions ".repeat(60)}</p>
      <iframe name="help" src="http://127.0.0.1:${widgetPort}/help?topic=cart#top"></iframe>
      <iframe src="http://localhost:${widgetPort}/ads/slot"></iframe>
      <iframe src="http://localhost:${widgetPort}/ads/other"></iframe>
      <iframe name="legal" src="http://127.0.0.1:${widgetPort}/legal"></iframe>
      <script src="/app.js"></script>`);
  });
  // Hooks run in registration order, so the browser is still open here: drop
  // its keep-alive connections, or close() waits for a browser that never goes.
  t.after(() => Promise.all([app, widget].map((server) => new Promise((resolve) => { server.close(resolve); server.closeAllConnections(); }))));
  const base = `http://127.0.0.1:${app.address().port}`;
  const require = createRequire(path.join(runtime.playwright_core_path, "package.json"));
  const { chromium } = require(runtime.playwright_core_path);
  const browser = await chromium.launch({ executablePath: runtime.chromium_path, headless: true });
  t.after(() => browser.close());
  const context = await browser.newContext();
  const page = await context.newPage();
  page.on("dialog", (dialog) => void dialog.dismiss().catch(() => undefined));
  const session = { context, page };
  const { executeAction: execute, MAX_SNAPSHOT_BYTES } = actions();
  await execute(session, { type: "navigate", url: base });
  await page.waitForLoadState("load");
  // Copied out of the vm realm the worker functions were loaded in.
  const evaluate = async (expression, extra = {}) => ({ ...(await execute(session, { type: "evaluate", expression, ...extra })).data });
  const value = async (expression, extra) => {
    const data = await evaluate(expression, extra);
    // An object or array that fits is returned as it is.
    if ("value" in data) return data.value;
    assert.equal(data.truncated, false, expression);
    return data.type === "string" || data.type === "node" || data.type === "function" ? data.content : JSON.parse(data.content);
  };

  await t.test("expressions, statements, top-level await and function sources", async () => {
    assert.deepEqual(await evaluate("1 + 1"), { type: "number", content: "2", truncated: false, total_bytes: 1 });
    assert.deepEqual(await evaluate("document.title"), { type: "string", content: "Shop", truncated: false, total_bytes: 4 });
    assert.equal(await value("app.token"), "tok-123");
    assert.equal((await evaluate("undefined")).content, "undefined");
    assert.equal((await evaluate("null")).type, "null");
    assert.equal((await evaluate("0 / 0")).content, "NaN");
    assert.equal((await evaluate("12345678901234567890n")).content, "12345678901234567890n");
    // Declarations can be repeated, as in the DevTools console.
    assert.equal(await value("const total = 5; total * 2"), 10);
    assert.equal(await value("const total = 6; total * 2"), 12);
    assert.deepEqual(await value("const response = await fetch('/api/items'); (await response.json()).items.map((item) => item.name)"), ["one", "two"]);
    assert.deepEqual(await value("fetch('/api/items').then((response) => response.status)"), 200);
    // An object literal and a block are each read as what they are.
    assert.deepEqual(await value("{a: 1, b: [2]}"), { a: 1, b: [2] });
    assert.equal(await value("{ let base = 2; base * 3 }"), 6);
    // Function sources are called; a function the page owns is returned as source.
    assert.equal(await value("() => document.querySelectorAll('a').length"), 2);
    assert.equal(await value("async () => (await fetch('/api/items')).status"), 200);
    assert.equal(await value("function () { return location.pathname; }"), "/");
    assert.equal(await value("function double(n) { return n * 2; }\ndouble(21)"), 42);
    // Statements that end with a function show it; only a source that is one
    // function is called.
    assert.equal(await value("window.calls = 0"), 0);
    assert.equal(await value("function make() { return () => { window.calls += 1; }; }\nmake()"), "() => { window.calls += 1; }");
    assert.equal(await value("window.calls"), 0);
    assert.equal(await value("(n = Math.max(1, 2)) => n"), "(n = Math.max(1, 2)) => n");
    const signer = await evaluate("app.sign");
    assert.equal(signer.type, "function");
    assert.match(signer.content, /^sign\(value\) \{ return "sig:" \+ value; \}$/);
    assert.equal(await value("app.sign('x')"), "sig:x");
  });

  await t.test("page state and the DevTools console helpers under a strict CSP", async () => {
    assert.deepEqual(await value("app"), { token: "tok-123", user: { id: 7, roles: ["admin"] }, sign: "[Function: sign]" });
    assert.equal(await value("eval('2 + 2')"), 4);
    assert.deepEqual(await value("localStorage"), { session: "abc", length: 1 });
    assert.equal(await value("getEventListeners(window).message[0].listener.name"), "onMessage");
    assert.equal(await value("$$('nav a').length"), 2);
    assert.equal(await value("alert('dismissed'); 'after the dialog'"), "after the dialog");
    // A page fetch is ordinary page traffic, sent once.
    assert.equal(await value("(await fetch('/api/items', {method: 'POST', body: '{}'})).status"), 200);
    assert.equal(posts, 1);
  });

  await t.test("values that JSON cannot carry", async () => {
    const heading = await evaluate("document.querySelector('#title')");
    assert.deepEqual(heading, { type: "node", content: "<h1 id=\"title\">Shop <b>open</b></h1>", truncated: false, total_bytes: 36 });
    assert.deepEqual(await value("document.querySelectorAll('nav a')"), ["<a href=\"/a?x=1\">First</a>", "<a href=\"/b\">Second</a>"]);
    assert.deepEqual(await value("[...document.querySelector('nav a').attributes]"), ["href=\"/a?x=1\""]);
    assert.equal(await value("document.querySelector('#title').firstChild"), "Shop ");
    // A large node inside a list is cut, so it cannot hide the rest.
    const [terms, tail] = await value("[document.querySelector('#terms'), 'tail']");
    assert.ok(terms.startsWith("<p id=\"terms\">terms and conditions ") && terms.endsWith("…") && terms.length === 401, terms);
    assert.equal(tail, "tail");
    // Asked for by itself, the same node is returned whole.
    assert.equal((await evaluate("document.querySelector('#terms')")).content,
      `<p id="terms">${"terms and conditions ".repeat(60)}</p>`);
    // A getter that throws is reported in place. Chromium's own deep
    // serialization hangs on this object and then kills the browser.
    assert.deepEqual(await value("cart"), { items: [1, 2], total: "[Throws: price service down]" });
    assert.deepEqual(await value("(() => { const node = { name: 'a' }; node.self = node; node.list = [node]; return node; })()"),
      { name: "a", self: "[Circular]", list: ["[Circular]"] });
    assert.deepEqual(await value("({ map: new Map([['k', { v: 1 }]]), set: new Set([1, 'a']), when: new Date(0), re: /x/gi, big: 1n, nan: NaN, none: undefined, nothing: null, error: new TypeError('bad input'), bytes: new Uint8Array([1, 2]) })"),
      { map: [["k", { v: 1 }]], set: [1, "a"], when: "1970-01-01T00:00:00.000Z", re: "/x/gi", big: "1n", nan: "NaN", nothing: null, error: "TypeError: bad input", bytes: [1, 2] });
    assert.deepEqual(await value("[undefined, () => 1, Symbol('s'), window, new WeakMap(), Promise.resolve(1), new URL('http://a.test/b?c=1')]"),
      [null, "[Function]", "Symbol(s)", "[Window]", "[WeakMap]", "[Promise]", "http://a.test/b?c=1"]);
    // Cross-origin windows and objects refuse access instead of failing the call.
    const [crossWindow, crossLocation] = await value("[frames[1], frames[1].location]");
    assert.equal(crossWindow, "[Window]");
    assert.match(crossLocation, /^\[Unreadable: /);
    assert.deepEqual(await value("({ a: { b: { c: { d: { e: { f: { g: { h: { i: 1 } } } } } } } } })"),
      { a: { b: { c: { d: { e: { f: { g: { h: "[Object]" } } } } } } } });
    // An object with a then method is shown, not waited for; a promise a
    // function source returns still is, from another frame's realm too.
    const started = Date.now();
    assert.deepEqual(await value("({ then() {}, id: 7 })"), { then: "[Function: then]", id: 7 });
    assert.deepEqual(await value("() => ({ then() {}, id: 8 })"), { then: "[Function: then]", id: 8 });
    // Well short of the 10 s deadline either one would have waited for.
    assert.ok(Date.now() - started < 8_000);
    assert.equal(await value("async () => 9"), 9);
    assert.equal(await value("() => { const realm = document.createElement('iframe'); realm.id = 'realm'; document.body.append(realm); return realm.contentWindow.Promise.resolve(10); }"), 10);
    assert.equal(await value("document.querySelector('#realm').remove(); 'removed'"), "removed");
    assert.equal(await value("({ ['__proto__']: 1, toString: 2 })['__proto__']"), 1);
    assert.deepEqual(await value("JSON.parse('{\"__proto__\": {\"polluted\": true}, \"kept\": 1}')"), JSON.parse("{\"__proto__\": {\"polluted\": true}, \"kept\": 1}"));
  });

  await t.test("exceptions are reported as the result", async () => {
    const missing = await execute(session, { type: "evaluate", expression: "missing.value" });
    assert.equal(missing.message, "expression threw");
    assert.equal(missing.data.type, "exception");
    assert.match(missing.data.content, /^ReferenceError: missing is not defined/);
    assert.match((await evaluate("let = ;")).content, /^SyntaxError: /);
    assert.match((await evaluate("await Promise.reject(new RangeError('too far'))")).content, /^RangeError: too far/);
    assert.match((await evaluate("Promise.reject(new RangeError('later'))")).content, /^RangeError: later/);
    assert.match((await evaluate("() => { throw new TypeError('in function'); }")).content, /^TypeError: in function/);
    assert.equal((await evaluate("throw 'plain text'")).content, "plain text");
    assert.equal((await evaluate("throw 'plain text'")).type, "exception");
  });

  await t.test("results are bounded and say when they were cut", async () => {
    const long = await evaluate("'é'.repeat(50000)");
    assert.equal(long.truncated, true);
    assert.equal(long.total_bytes, 100_000);
    assert.equal(Buffer.byteLength(long.content), MAX_SNAPSHOT_BYTES);
    assert.equal(long.next_offset, undefined);
    const many = await evaluate("Array.from({ length: 400000 }, (_, index) => ({ id: index, name: 'item ' + index }))");
    assert.equal(many.truncated, true);
    assert.ok(Buffer.byteLength(many.content) <= MAX_SNAPSHOT_BYTES);
    assert.ok(many.content.startsWith("[{\"id\":0,\"name\":\"item 0\"},"));
    // The page stopped building long before all 400000 rows.
    assert.ok(many.total_bytes > 1_000_000 && many.total_bytes < 3_000_000, String(many.total_bytes));
    // An endless iterator ends at the same limit.
    const endless = await evaluate("(function* () { for (let index = 0; ; index += 1) yield index; })()");
    assert.equal(endless.truncated, true);
    assert.ok(endless.content.startsWith("[0,1,2,"));
  });

  await t.test("a deadline stops a loop and leaves the page usable", async () => {
    const started = Date.now();
    await assert.rejects(evaluate("while (true) {}", { timeout_ms: 500 }), /evaluate timed out after 500 ms/);
    await assert.rejects(evaluate("await new Promise(() => {})", { timeout_ms: 300 }), /evaluate timed out after 300 ms/);
    await assert.rejects(evaluate("new Promise(() => {})", { timeout_ms: 300 }), /evaluate timed out after 300 ms/);
    await assert.rejects(evaluate("() => { for (;;) {} }", { timeout_ms: 300 }), /evaluate timed out after 300 ms/);
    assert.ok(Date.now() - started < 10_000);
    assert.equal(await value("document.title"), "Shop");
    for (const action of [
      { type: "evaluate" }, { type: "evaluate", expression: "  " }, { type: "evaluate", expression: 5 },
      { type: "evaluate", expression: "1", timeout_ms: 0 }, { type: "evaluate", expression: "1", timeout_ms: 30_001 },
    ]) {
      await assert.rejects(execute(session, action), (error) => error.code === -32602, JSON.stringify(action));
    }
  });

  await t.test("frames are selected by name or URL", async () => {
    // Same site as the page: it shares the page's process and CDP session.
    const help = await evaluate("[widget.path, location.hash, typeof app]", { frame: "help" });
    assert.deepEqual(help.value, ["/help", "#top", "undefined"]);
    assert.equal(help.frame_url, `http://127.0.0.1:${widgetPort}/help`);
    assert.deepEqual((await evaluate("widget", { frame: "/help?topic=cart" })).value, { host: `127.0.0.1:${widgetPort}`, path: "/help" });
    // Another site: an out-of-process frame with a CDP session of its own.
    const slot = await evaluate("document.querySelector('#who')", { frame: "ads/slot" });
    assert.deepEqual([slot.type, slot.content], ["node", "<p id=\"who\">widget</p>"]);
    assert.equal(slot.frame_url, `http://localhost:${widgetPort}/ads/slot`);
    assert.equal((await evaluate("await new Promise((resolve) => setTimeout(() => resolve(widget.host), 50))", { frame: `http://localhost:${widgetPort}/ads/other` })).content, `localhost:${widgetPort}`);
    assert.deepEqual((await evaluate("{host: location.host}", { frame: "help" })).value, { host: `127.0.0.1:${widgetPort}` });
    assert.match((await evaluate("nope()", { frame: "help" })).content, /^ReferenceError: nope is not defined/);
    // A frame whose document runs no script of its own can still be evaluated in.
    assert.equal((await evaluate("document.title + ' ' + typeof widget", { frame: "legal" })).content, "Legal undefined");
    await assert.rejects(evaluate("1", { frame: "/ads/" }),
      (error) => error.code === -32602 && /matches 2 frames/.test(error.message) && error.message.includes("/ads/slot") && error.message.includes("/ads/other"));
    await assert.rejects(evaluate("1", { frame: "checkout" }),
      (error) => error.code === -32602 && /matches no frame/.test(error.message) && error.message.includes("name=help") && !error.message.includes("topic=cart"));
    // The page itself is not a frame to select.
    await assert.rejects(evaluate("1", { frame: base }), /matches no frame/);
    await assert.rejects(evaluate("while (true) {}", { frame: "ads/slot", timeout_ms: 400 }), /timed out/);
    assert.equal((await evaluate("widget.path", { frame: "ads/slot" })).content, "/ads/slot");
  });

  await t.test("navigation started by the expression", async () => {
    await assert.rejects(evaluate("location.href = '/next'; await new Promise(() => {})"), /interrupted because the page or frame navigated or closed/);
    await page.waitForURL(`${base}/next`);
    assert.equal(await value("document.title"), "Next");
    await execute(session, { type: "navigate", url: `${base}/plain` });
    await assert.rejects(evaluate("1", { frame: "help" }), /matches no frame of the selected page; frames: none/);
    // A synchronous result is returned even though the page then navigates.
    assert.equal(await value("location.assign('/next'); 'leaving'"), "leaving");
    await page.waitForURL(`${base}/next`);
  });
});
