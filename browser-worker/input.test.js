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

// Load the actual tracking and action functions without starting the worker's stdio loop.
function worker() {
  return vm.runInNewContext(`${between("const MAX_SESSION_EVENTS", "async function uploadFiles")}
    ${between("function locatorFor", "async function performEvents")}
    ${between("async function performEvents", "async function performScreenshot")}
    ${between("function proxyErrorMarker", "async function clearCookieIdentities")}
    ({ executeAction, initializeSessionTracking, disposeSessionTracking });`, {
    Buffer, URL, setTimeout, clearTimeout,
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

// Everything the page hears is appended to window.heard, so a test reads back
// exactly which trusted events an action produced.
const PAGE_SCRIPT = `
  window.heard = [];
  const say = (entry) => window.heard.push(entry);
  const pad = document.querySelector("#pad");
  for (const kind of ["mousedown", "mouseup", "click", "dblclick", "contextmenu"]) {
    pad.addEventListener(kind, (event) => {
      if (kind === "contextmenu") event.preventDefault();
      say({ kind, x: event.clientX, y: event.clientY, button: event.button, detail: event.detail, trusted: event.isTrusted,
        keys: ["altKey", "ctrlKey", "metaKey", "shiftKey"].filter((key) => event[key]).join("+") });
    });
  }
  pad.addEventListener("mousemove", (event) => { window.lastMove = { x: event.clientX, y: event.clientY, shift: event.shiftKey }; });
  document.querySelector("#menu").addEventListener("mouseenter", () => { document.querySelector("#submenu").hidden = false; });
  // A card moved with mouse events, as drag-and-drop libraries do it.
  const card = document.querySelector("#card");
  let held = false;
  card.addEventListener("mousedown", () => { held = true; window.cardMoves = 0; });
  document.addEventListener("mousemove", (event) => {
    if (!held) return;
    window.cardMoves += 1;
    card.style.left = (event.clientX - 20) + "px";
    card.style.top = (event.clientY - 15) + "px";
  });
  document.addEventListener("mouseup", (event) => {
    if (!held) return;
    held = false;
    card.style.pointerEvents = "none";
    const zone = document.elementFromPoint(event.clientX, event.clientY)?.closest(".zone");
    card.style.pointerEvents = "";
    say({ kind: "card-drop", zone: zone ? zone.id : null, moves: window.cardMoves });
  });
  // Native HTML drag and drop.
  const chip = document.querySelector("#chip");
  chip.addEventListener("dragstart", (event) => { event.dataTransfer.setData("text/plain", "chip-7"); say({ kind: "dragstart" }); });
  const bin = document.querySelector("#bin");
  bin.addEventListener("dragover", (event) => event.preventDefault());
  bin.addEventListener("drop", (event) => { event.preventDefault(); say({ kind: "drop", data: event.dataTransfer.getData("text/plain") }); });
  // Typing targets.
  const search = document.querySelector("#search");
  for (const kind of ["keydown", "input"]) {
    search.addEventListener(kind, (event) => say({ kind: "search-" + kind, key: event.key ?? event.data, trusted: event.isTrusted }));
  }
  const digits = [...document.querySelectorAll(".otp")];
  digits.forEach((digit, index) => digit.addEventListener("input", () => { if (digit.value && digits[index + 1]) digits[index + 1].focus(); }));
  const editor = document.querySelector("#editor");
  editor.addEventListener("keydown", (event) => { if (event.key === "/") document.querySelector("#commands").hidden = false; });
  document.querySelectorAll("button.row").forEach((row, index) => row.addEventListener("click", () => say({ kind: "row", index })));
`;

const FRAME_PAGE = `<!doctype html><title>Checkout</title><label>Card number <input id="card-number"></label>
  <button id="pay">Pay</button><p id="paid"></p>
  <script>
    window.typed = [];
    document.querySelector("#card-number").addEventListener("keydown", (event) => window.typed.push(event.key));
    document.querySelector("#pay").addEventListener("click", (event) => {
      document.querySelector("#paid").textContent = "paid " + document.querySelector("#card-number").value + (event.detail === 2 ? " twice" : "");
    });
  </script>`;

test("pointer and keyboard input, locators that pick a match or reach into a frame", {
  skip: available ? false : "Playwright and Chromium are required for the browser regression",
  timeout: 240_000,
}, async (t) => {
  const frames = await listen((request, response) => {
    response.setHeader("Content-Type", "text/html; charset=utf-8");
    response.end(FRAME_PAGE);
  });
  const framesPort = frames.address().port;
  const app = await listen((request, response) => {
    const url = new URL(request.url, "http://localhost");
    if (url.pathname === "/page.js") {
      response.setHeader("Content-Type", "text/javascript");
      return response.end(PAGE_SCRIPT);
    }
    response.setHeader("Content-Type", "text/html; charset=utf-8");
    if (url.pathname === "/next") return response.end("<!doctype html><title>Next</title><p>Arrived</p>");
    if (url.pathname === "/guarded") {
      return response.end(`<!doctype html><title>Draft</title><input id="draft"><a href="/next">Leave</a>
        <script>
          let dirty = false;
          document.querySelector("#draft").addEventListener("input", () => { dirty = true; });
          window.addEventListener("beforeunload", (event) => { if (dirty) { event.preventDefault(); event.returnValue = ""; } });
        </script>`);
    }
    response.end(`<!doctype html><title>Board</title>
      <style>
        body { margin: 0; font: 14px sans-serif; }
        #pad { position: absolute; left: 40px; top: 60px; width: 400px; height: 300px; background: #dde; }
        #menu { position: absolute; left: 480px; top: 60px; width: 120px; height: 30px; background: #cdc; }
        #submenu { position: absolute; left: 480px; top: 95px; }
        .zone { position: absolute; top: 400px; width: 200px; height: 120px; background: #eed; }
        #zone-a { left: 40px; } #zone-b { left: 300px; }
        #card { position: absolute; left: 60px; top: 420px; width: 40px; height: 30px; background: #a66; }
        #chip { position: absolute; left: 560px; top: 420px; width: 60px; height: 30px; background: #6a6; }
        #bin { position: absolute; left: 700px; top: 400px; width: 160px; height: 120px; background: #bbb; }
        #form { position: absolute; left: 40px; top: 560px; }
        iframe { position: absolute; top: 760px; width: 380px; height: 120px; }
      </style>
      <div id="pad"></div><div id="menu">Account</div><div id="submenu" hidden>Sign out</div>
      <div class="zone" id="zone-a"></div><div class="zone" id="zone-b"></div><div id="card"></div>
      <div id="chip" draggable="true">chip</div><div id="bin"></div>
      <div id="form"><input id="search" aria-label="Search">
        <input class="otp" maxlength="1" aria-label="Digit 1"><input class="otp" maxlength="1"><input class="otp" maxlength="1"><input class="otp" maxlength="1">
        <div id="editor" contenteditable="true" role="textbox" aria-label="Notes" style="min-width:200px;min-height:20px;border:1px solid #999"></div>
        <ul id="commands" hidden><li>Heading</li></ul>
        <button class="row">Delete</button><button class="row">Delete</button><button class="row">Delete</button></div>
      <iframe name="help" style="left:40px" src="http://127.0.0.1:${framesPort}/help"></iframe>
      <iframe name="pay" style="left:440px" src="http://localhost:${framesPort}/pay?order=7"></iframe>
      <script src="/page.js"></script>`);
  });
  // Hooks run in registration order, so the browser is still open here: drop
  // its keep-alive connections, or close() waits for a browser that never goes.
  t.after(() => Promise.all([app, frames].map((server) => new Promise((resolve) => { server.close(resolve); server.closeAllConnections(); }))));
  const base = `http://127.0.0.1:${app.address().port}`;
  const require = createRequire(path.join(runtime.playwright_core_path, "package.json"));
  const { chromium } = require(runtime.playwright_core_path);
  const browser = await chromium.launch({ executablePath: runtime.chromium_path, headless: true });
  t.after(() => browser.close());
  const context = await browser.newContext({ viewport: { width: 1000, height: 700 } });
  const page = await context.newPage();
  const session = { context, page };
  const { executeAction, initializeSessionTracking, disposeSessionTracking } = worker();
  await initializeSessionTracking(session);
  t.after(() => disposeSessionTracking(session));
  // Results cross the vm realm the worker functions were loaded in.
  const run = async (action) => JSON.parse(JSON.stringify(await executeAction(session, action)));
  const read = async (expression, frame) => {
    const { data } = await run({ type: "evaluate", expression, frame });
    return data.type === "string" ? data.content : JSON.parse(data.content);
  };
  const heard = async () => {
    const entries = await read("window.heard.splice(0)");
    return entries;
  };
  const invalid = (action, pattern) => assert.rejects(executeAction(session, action),
    (error) => error.code === -32602 && pattern.test(error.message), JSON.stringify(action));
  await run({ type: "navigate", url: base });
  await page.waitForLoadState("load");

  await t.test("clicks at a point with any button, count and modifiers", async () => {
    assert.deepEqual(await run({ type: "pointer", op: "click", x: 100, y: 120 }),
      { message: "pointer clicked", data: { url: `${base}/` } });
    assert.deepEqual(await heard(), [
      { kind: "mousedown", x: 100, y: 120, button: 0, detail: 1, trusted: true, keys: "" },
      { kind: "mouseup", x: 100, y: 120, button: 0, detail: 1, trusted: true, keys: "" },
      { kind: "click", x: 100, y: 120, button: 0, detail: 1, trusted: true, keys: "" },
    ]);
    await run({ type: "pointer", op: "click", x: 150.5, y: 200, button: "right" });
    assert.deepEqual((await heard()).map((entry) => [entry.kind, entry.button]), [["mousedown", 2], ["contextmenu", 2], ["mouseup", 2]]);
    await run({ type: "pointer", op: "click", x: 60, y: 80, count: 2 });
    assert.deepEqual((await heard()).filter((entry) => entry.kind === "click" || entry.kind === "dblclick").map((entry) => [entry.kind, entry.detail]),
      [["click", 1], ["click", 2], ["dblclick", 2]]);
    await run({ type: "pointer", op: "click", x: 60, y: 80, modifiers: ["Shift", "Control"] });
    assert.equal((await heard()).at(-1).keys, "ctrlKey+shiftKey");
    // The modifiers are released again.
    await run({ type: "pointer", op: "click", x: 60, y: 80 });
    assert.equal((await heard()).at(-1).keys, "");
  });

  await t.test("clicks an element with the same options and Playwright's checks", async () => {
    await run({ type: "pointer", op: "click", locator: { css: "#pad" }, count: 2, modifiers: ["Alt"] });
    const events = await heard();
    assert.deepEqual(events.at(-1), { kind: "dblclick", x: 240, y: 210, button: 0, detail: 2, trusted: true, keys: "altKey" });
    await run({ type: "pointer", op: "click", locator: { css: "#pad" }, button: "right" });
    assert.equal((await heard()).some((entry) => entry.kind === "contextmenu"), true);
  });

  await t.test("hovers", async () => {
    assert.equal(await read("document.querySelector('#submenu').hidden"), true);
    assert.deepEqual(await run({ type: "pointer", op: "hover", locator: { css: "#menu" } }), { message: "pointer moved", data: null });
    assert.equal(await read("document.querySelector('#submenu').hidden"), false);
    await run({ type: "pointer", op: "hover", x: 333, y: 222, modifiers: ["Shift"] });
    assert.deepEqual(await read("window.lastMove"), { x: 333, y: 222, shift: true });
  });

  await t.test("drags with intermediate movement, between elements or points", async () => {
    const dragged = await run({ type: "pointer", op: "drag", locator: { css: "#card" }, to_locator: { css: "#zone-b" } });
    assert.equal(dragged.message, "pointer dragged");
    assert.deepEqual(dragged.data, { from: { x: 80, y: 435 }, to: { x: 400, y: 460 } });
    const [drop] = (await heard()).filter((entry) => entry.kind === "card-drop");
    assert.equal(drop.zone, "zone-b");
    assert.ok(drop.moves >= 10, `the card heard ${drop.moves} moves`);
    // Back again by coordinates.
    await run({ type: "pointer", op: "drag", x: 400, y: 460, to_x: 120, to_y: 470 });
    assert.equal((await heard()).find((entry) => entry.kind === "card-drop").zone, "zone-a");
    // Native HTML drag and drop sees the same gesture.
    await run({ type: "pointer", op: "drag", locator: { css: "#chip" }, to_locator: { css: "#bin" } });
    assert.deepEqual((await heard()).filter((entry) => entry.kind === "dragstart" || entry.kind === "drop"),
      [{ kind: "dragstart" }, { kind: "drop", data: "chip-7" }]);
    // A destination that cannot be found fails before the button goes down:
    // pressing first would end in a release, and so a click, on the source.
    for (const destination of [{}, { css: "#pad", frame: "nowhere" }, { css: "button.row" }]) {
      await assert.rejects(executeAction(session, { type: "pointer", op: "drag", locator: { css: "#pad" }, to_locator: destination }));
    }
    assert.deepEqual(await heard(), []);
  });

  await t.test("types keystrokes into a locator or whatever has focus", async () => {
    assert.deepEqual(await run({ type: "type", text: "shoes é", locator: { role: "textbox", name: "Search" } }),
      { message: "text typed", data: { characters: 7 } });
    assert.equal(await read("document.querySelector('#search').value"), "shoes é");
    const keys = await heard();
    assert.deepEqual(keys.filter((entry) => entry.kind === "search-keydown").map((entry) => entry.key), ["s", "h", "o", "e", "s", " "]);
    assert.equal(keys.filter((entry) => entry.kind === "search-input").length, 7);
    assert.equal(keys.every((entry) => entry.trusted), true);
    // One character per box: focus moves on as the page reacts to each key.
    await run({ type: "pointer", op: "click", locator: { role: "textbox", name: "Digit 1" } });
    await run({ type: "type", text: "4821" });
    assert.deepEqual(await read("[...document.querySelectorAll('.otp')].map((digit) => digit.value)"), ["4", "8", "2", "1"]);
    // An editor that reacts to keys, and a newline that presses Enter.
    await run({ type: "type", text: "/", locator: { role: "textbox", name: "Notes" } });
    assert.equal(await read("document.querySelector('#commands').hidden"), false);
    await run({ type: "type", text: "a\nb" });
    assert.match(await read("document.querySelector('#editor').innerText"), /^\/a\n+b$/);
    const typed = await run({ type: "type", text: "!", snapshot: true });
    assert.match(typed.data.snapshot.content, /textbox "Notes"/);
    await invalid({ type: "type" }, /type requires text of 1\.\.4096 bytes/);
    await invalid({ type: "type", text: "" }, /type requires text/);
    await invalid({ type: "type", text: "x".repeat(4097) }, /type requires text/);
  });

  await t.test("a locator picks one of several matches", async () => {
    await assert.rejects(executeAction(session, { type: "click", locator: { role: "button", name: "Delete" } }), (error) => {
      assert.match(error.message, /strict mode violation/);
      assert.match(error.message, /resolved to 3 elements/);
      assert.match(error.message, /Set nth on the locator to pick one of them: 0 is the first, -1 the last\.$/);
      assert.ok(!error.message.includes("Call log"));
      return true;
    });
    await run({ type: "click", locator: { role: "button", name: "Delete", nth: 1 } });
    await run({ type: "click", locator: { css: "button.row", nth: -1 } });
    await run({ type: "pointer", op: "click", locator: { text: "Delete", nth: 0 } });
    assert.deepEqual((await heard()).filter((entry) => entry.kind === "row").map((entry) => entry.index), [1, 2, 0]);
    await invalid({ type: "click", locator: { css: "button.row", nth: 1.5 } }, /locator nth must be an integer/);
  });

  await t.test("a locator reaches into same-process and cross-process frames", async () => {
    // Same site as the page.
    await run({ type: "fill", locator: { css: "#card-number", frame: "help" }, value: "4111" });
    await run({ type: "click", locator: { role: "button", name: "Pay", frame: "help" } });
    assert.equal(await read("document.querySelector('#paid').textContent", "help"), "paid 4111");
    // Another site: an out-of-process frame, selected by part of its URL.
    await run({ type: "type", text: "42", locator: { role: "textbox", name: "Card number", frame: "/pay?order=7" } });
    await run({ type: "press", key: "4", locator: { css: "#card-number", frame: "pay" } });
    assert.deepEqual(await read("window.typed", "pay"), ["4", "2", "4"]);
    await run({ type: "pointer", op: "click", locator: { css: "#pay", frame: "pay" }, count: 2 });
    assert.equal(await read("document.querySelector('#paid').textContent", "pay"), "paid 424 twice");
    // The frame's own tree and markup, which the page's snapshot leaves out.
    const tree = await run({ type: "snapshot", locator: { css: "body", frame: "pay" } });
    assert.match(tree.data.content, /textbox "Card number": "424"/);
    assert.match(tree.data.content, /button "Pay"/);
    const markup = await run({ type: "snapshot", format: "dom", locator: { css: "#paid", frame: "pay" } });
    assert.equal(markup.data.content, "<p id=\"paid\">paid 424 twice</p>");
    // A point is in the page's viewport, whatever frame is under it.
    await run({ type: "scroll", locator: { css: "#pay", frame: "help" } });
    const box = await page.frameLocator("iframe[name=help]").locator("#pay").boundingBox();
    await run({ type: "pointer", op: "click", x: box.x + 5, y: box.y + 5 });
    assert.equal(await read("document.querySelector('#paid').textContent", "help"), "paid 4111");
    await invalid({ type: "click", locator: { css: "#pay", frame: "checkout" } },
      /^frame matches no frame of the selected page; frames: .*name=help.*name=pay/);
    await invalid({ type: "click", locator: { css: "#pay", frame: `:${framesPort}/` } }, /^frame matches 2 frames/);
    await invalid({ type: "click", locator: { css: "#pay", frame: "" } }, /frame must be a frame name or part of its URL/);
  });

  await t.test("pages list names the frames", async () => {
    const listed = await run({ type: "pages", op: "list" });
    assert.deepEqual(listed.data.pages, [{ page_id: 1, active: true, url: `${base}/`, title: "Board", frames: [
      { url: `http://127.0.0.1:${framesPort}/help`, name: "help" },
      { url: `http://localhost:${framesPort}/pay`, name: "pay" },
    ] }]);
    // A page full of frames lists a bounded number and says how many it left out.
    await read("for (let index = 0; index < 14; index += 1) { const frame = document.createElement('iframe'); frame.className = 'extra'; frame.srcdoc = '<p>extra</p>'; document.body.append(frame); } 14");
    await page.waitForFunction(() => window.frames.length === 16);
    const [crowded] = (await run({ type: "pages", op: "list" })).data.pages;
    assert.equal(crowded.frames.length, 12);
    assert.equal(crowded.frames_omitted, 4);
    assert.deepEqual(crowded.frames.at(-1), { url: "about:srcdoc" });
    await read("document.querySelectorAll('iframe.extra').forEach((frame) => frame.remove()); 0");
    // Only the selected page's frames are listed.
    const opened = (await run({ type: "pages", op: "new", url: `${base}/next` })).data;
    assert.deepEqual(opened.pages.map((entry) => [entry.active, entry.frames?.length]), [[false, undefined], [true, undefined]]);
    await run({ type: "pages", op: "close", page_id: opened.page_id, runtime_generation: opened.runtime_generation });
    assert.equal((await run({ type: "pages", op: "list" })).data.pages[0].frames.length, 2);
  });

  await t.test("pointer input is validated", async () => {
    for (const [action, pattern] of [
      [{ type: "pointer" }, /pointer op must be click\|hover\|drag/],
      [{ type: "pointer", op: "tap", x: 1, y: 1 }, /pointer op must be/],
      [{ type: "pointer", op: "click" }, /pointer click requires either a locator or x and y/],
      [{ type: "pointer", op: "click", x: 1, y: 1, locator: { css: "#pad" } }, /either a locator or x and y/],
      [{ type: "pointer", op: "click", x: 1 }, /pointer x and y must both be 0\.\.100000/],
      [{ type: "pointer", op: "click", x: -1, y: 1 }, /pointer x and y must both be/],
      [{ type: "pointer", op: "hover" }, /pointer hover requires either a locator or x and y/],
      [{ type: "pointer", op: "click", x: 1, y: 1, button: "back" }, /pointer button must be/],
      [{ type: "pointer", op: "click", x: 1, y: 1, count: 4 }, /count 1\.\.3/],
      [{ type: "pointer", op: "click", x: 1, y: 1, modifiers: ["Hyper"] }, /modifiers Alt\|Control\|Meta\|Shift/],
      [{ type: "pointer", op: "click", x: 1, y: 1, to_x: 2, to_y: 2 }, /pointer destination applies to drag only/],
      [{ type: "pointer", op: "drag", x: 1, y: 1 }, /pointer drag destination requires either a locator or x and y/],
      [{ type: "pointer", op: "drag", to_x: 1, to_y: 1 }, /pointer drag requires either a locator or x and y/],
    ]) {
      await invalid(action, pattern);
    }
    // A refused drag leaves no button held.
    await run({ type: "pointer", op: "hover", x: 300, y: 300 });
    assert.equal(await read("window.heard.length"), 0);
  });

  await t.test("an unsaved-changes guard does not hold the page", async () => {
    await run({ type: "navigate", url: `${base}/guarded` });
    await run({ type: "type", text: "draft", locator: { css: "#draft" } });
    const left = await run({ type: "navigate", url: `${base}/next` });
    assert.equal(left.data.url, `${base}/next`);
    await run({ type: "back" });
    await run({ type: "type", text: "again", locator: { css: "#draft" } });
    await run({ type: "click", locator: { role: "link", name: "Leave" } });
    await page.waitForURL(`${base}/next`);
    const dialogs = (await run({ type: "events", kinds: ["dialog"] })).data.events;
    assert.deepEqual(dialogs.map((event) => [event.dialog_type, event.disposition]),
      [["beforeunload", "accepted"], ["beforeunload", "accepted"]]);
    // Every other dialog is still dismissed.
    assert.equal(await read("confirm('Delete everything?')"), false);
    const [confirmed] = (await run({ type: "events", kinds: ["dialog"], after_sequence: dialogs.at(-1).sequence, runtime_generation: 1 })).data.events;
    assert.deepEqual([confirmed.dialog_type, confirmed.disposition], ["confirm", "dismissed"]);
    // A dialog event says what the dialog said, which is the proof a payload ran.
    assert.deepEqual([confirmed.message, confirmed.message_length], ["Delete everything?", 18]);
    assert.equal(dialogs[0].message, undefined);
    await read(`alert("${"x".repeat(1200)}"); 0`);
    const [long] = (await run({ type: "events", kinds: ["dialog"], after_sequence: confirmed.sequence, runtime_generation: 1 })).data.events;
    assert.deepEqual([long.message.length, long.message_length], [1000, 1200]);
  });

  await t.test("console and error events carry the start of their text", async () => {
    const before = (await run({ type: "events" })).data.latest_sequence;
    await read("console.error('token check failed', {code: 7}); console.warn('slow'); console.log('not recorded'); setTimeout(() => { throw new TypeError('late failure'); }); 0");
    await page.waitForTimeout(300);
    const rows = (await run({ type: "events", kinds: ["console", "page_error"], after_sequence: before, runtime_generation: 1 })).data.events;
    assert.deepEqual(rows.map((event) => [event.kind, event.level, event.text]), [
      ["console", "error", "token check failed {code: 7}"],
      ["console", "warning", "slow"],
      ["page_error", undefined, "TypeError: late failure"],
    ]);
  });
});
