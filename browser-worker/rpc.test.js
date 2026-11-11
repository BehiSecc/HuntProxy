import assert from "node:assert/strict";
import http from "node:http";
import { spawn, spawnSync } from "node:child_process";
import { test } from "node:test";

const workerPath = new URL("./index.js", import.meta.url).pathname;
const inspect = spawnSync(process.execPath, [workerPath, "--inspect-runtime"], { encoding: "utf8", timeout: 60_000 });
const runtime = inspect.status === 0 ? JSON.parse(inspect.stdout) : {};
const available = runtime.chromium_path && runtime.playwright_core_path;

// Drives a real worker over its JSON-RPC stdio; its process group dies with the test.
function startWorker(t) {
  const worker = spawn(process.execPath, [workerPath], {
    stdio: ["pipe", "pipe", "ignore"],
    detached: true,
    env: {
      ...process.env,
      HUNTPROXY_PLAYWRIGHT_CORE_PATH: runtime.playwright_core_path,
      HUNTPROXY_CHROME_EXECUTABLE: runtime.chromium_path,
    },
  });
  t.after(() => { try { process.kill(-worker.pid, "SIGKILL"); } catch {} });
  const pending = new Map();
  let nextId = 1;
  let buffer = "";
  worker.stdout.on("data", (chunk) => {
    buffer += chunk;
    for (let end = buffer.indexOf("\n"); end >= 0; end = buffer.indexOf("\n")) {
      const line = buffer.slice(0, end);
      buffer = buffer.slice(end + 1);
      try {
        const message = JSON.parse(line);
        pending.get(message.id)?.(message);
      } catch {}
    }
  });
  return (method, params) => new Promise((resolve, reject) => {
    const id = nextId++;
    const timer = setTimeout(() => reject(new Error(`${method} did not answer`)), 60_000);
    pending.set(id, (message) => {
      clearTimeout(timer);
      if (message.error) reject(Object.assign(new Error(message.error.message), { code: message.error.code }));
      else resolve(message.result);
    });
    worker.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id, method, params })}\n`);
  });
}

test("the worker lists JavaScript files after a cursor and waits for events in short requests", {
  skip: available ? false : "Playwright and Chromium are required for the browser regression",
  timeout: 120_000,
}, async (t) => {
  const pages = {
    "/": '<!doctype html><title>One</title><script src="/one.js"></script>',
    "/two": '<!doctype html><title>Two</title><script src="/two.js"></script>',
    "/boom": "<!doctype html><title>Boom</title><script>setTimeout(() => { throw new Error('boom'); }, 50)</script>",
  };
  const server = http.createServer((request, response) => {
    const pathname = new URL(request.url, "http://localhost").pathname;
    if (pathname.endsWith(".js")) {
      response.writeHead(200, { "content-type": "application/javascript" });
      response.end("void 0;");
    } else if (pathname in pages) {
      response.writeHead(200, { "content-type": "text/html" });
      response.end(pages[pathname]);
    } else {
      response.writeHead(404).end();
    }
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => { server.close(resolve); server.closeAllConnections(); }));
  const base = `http://127.0.0.1:${server.address().port}`;
  const call = startWorker(t);
  await call("session.start", { session_id: 1, engine: "chromium", persistent: false, url: `${base}/` });

  const files = (after) => call("session.javascript_files", after === undefined ? { session_id: 1 } : { session_id: 1, after });
  const paths = (reply) => reply.files.map((file) => file.path);
  const first = await files();
  assert.deepEqual(paths(first), ["/one.js"]);
  assert.ok(first.cursor > 0);
  assert.deepEqual(await files(first.cursor), { files: [], cursor: first.cursor });
  await call("session.action", { session_id: 1, action: { type: "navigate", url: `${base}/two` } });
  const second = await files(first.cursor);
  assert.deepEqual(paths(second), ["/two.js"]);
  assert.ok(second.cursor > first.cursor);
  assert.deepEqual(paths(await files()), ["/one.js", "/two.js"]);
  await assert.rejects(call("session.javascript_files", { session_id: 99 }), (error) => error.code === -32001);

  const wait = (milliseconds) => call("session.events_wait", {
    session_id: 1, action: { type: "events", kinds: ["page_error"] }, wait_ms: milliseconds,
  });
  const started = Date.now();
  assert.deepEqual(await wait(150), { ready: false });
  assert.ok(Date.now() - started >= 150);
  await call("session.action", { session_id: 1, action: { type: "navigate", url: `${base}/boom` } });
  // The page fails shortly after it loads; the caller chains waits until it does.
  let outcome = await wait(1_000);
  for (let attempt = 0; attempt < 10 && !outcome.ready; attempt += 1) outcome = await wait(1_000);
  assert.deepEqual(outcome, { ready: true });
  const read = await call("session.action", { session_id: 1, action: { type: "events", kinds: ["page_error"] } });
  assert.deepEqual(read.data.events.map((event) => event.kind), ["page_error"]);
  await assert.rejects(call("session.events_wait", { session_id: 99, action: { type: "events" }, wait_ms: 10 }),
    (error) => error.code === -32001);
  await assert.rejects(call("session.events_wait", { session_id: 1, action: { type: "events", runtime_generation: 9 }, wait_ms: 10 }),
    (error) => error.code === -32001);
  await call("session.stop", { session_id: 1 });
});
