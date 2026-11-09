import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import https from "node:https";
import { createRequire } from "node:module";
import { spawn, spawnSync } from "node:child_process";
import { test } from "node:test";
import vm from "node:vm";

const workerPath = new URL("./index.js", import.meta.url).pathname;
const source = fs.readFileSync(workerPath, "utf8");
const inspect = spawnSync(process.execPath, [workerPath, "--inspect-runtime"], { encoding: "utf8", timeout: 10_000 });
const runtime = inspect.status === 0 ? JSON.parse(inspect.stdout) : {};
const available = runtime.chromium_path && runtime.playwright_core_path;

function prime() {
  const code = source.slice(source.indexOf("const PROXY_AUTH_PRIME_URL"), source.indexOf("async function launchSessionRuntime"));
  return vm.runInNewContext(`${code}\n({ primeProxyAuth, PROXY_AUTH_PRIME_URL });`, { Promise });
}

test("priming the proxy credentials is a no-op without credentials and never fails the handoff", async () => {
  const { primeProxyAuth, PROXY_AUTH_PRIME_URL } = prime();
  const calls = [];
  const context = {
    async newPage() {
      calls.push("newPage");
      return {
        async goto(url) { calls.push(`goto ${url}`); throw new Error("net::ERR_SECRET_DETAIL"); },
        async close() { calls.push("close"); },
      };
    },
  };
  await primeProxyAuth({ context }, null);
  await primeProxyAuth({ context }, { server: "http://127.0.0.1:1" });
  assert.deepEqual(calls, []);
  await primeProxyAuth({ context }, { server: "http://127.0.0.1:1", username: "u", password: "p" });
  assert.deepEqual(calls, ["newPage", `goto ${PROXY_AUTH_PRIME_URL}`, "close"]);
  assert.match(PROXY_AUTH_PRIME_URL, /^http:\/\/[^/]+\.invalid\/$/);
  await primeProxyAuth({ context: { newPage: async () => { throw new Error("no page"); } } }, { password: "p" });
});

function selfSigned(dir) {
  const key = path.join(dir, "key.pem");
  const cert = path.join(dir, "cert.pem");
  const made = spawnSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", cert,
    "-days", "2", "-subj", "/CN=target.test", "-addext", "subjectAltName=DNS:target.test"], { encoding: "utf8" });
  return made.status === 0 ? { key: fs.readFileSync(key), cert: fs.readFileSync(cert), certPath: cert } : null;
}

test("after a CDP handoff a page.route client's first navigation authenticates to the proxy, over HTTP and CONNECT", {
  skip: available ? false : "Playwright and Chromium are required for the browser regression",
  timeout: 120_000,
}, async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "huntproxy-proxyauth-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const tls = selfSigned(dir);
  const expected = `Basic ${Buffer.from("workspace:s3cret").toString("base64")}`;
  const log = [];
  const challenge = "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"test\"\r\nContent-Length: 0\r\n\r\n";
  const origin = tls && https.createServer({ key: tls.key, cert: tls.cert }, (request, response) => {
    response.setHeader("Content-Type", "text/html");
    response.end("<!doctype html><title>secure</title>secure target");
  });
  if (origin) await new Promise((resolve) => origin.listen(0, "127.0.0.1", resolve));
  const proxy = http.createServer((request, response) => {
    if (request.headers["proxy-authorization"] !== expected) { response.socket.write(challenge); response.socket.destroy(); return; }
    const url = new URL(request.url);
    log.push(url.hostname);
    if (url.hostname.endsWith(".invalid")) { response.writeHead(502); response.end("proxy error"); return; }
    response.setHeader("Content-Type", "text/html");
    response.end("<!doctype html><title>plain</title>plain target");
  });
  proxy.on("connect", (request, socket, head) => {
    if (request.headers["proxy-authorization"] !== expected) { socket.end(challenge); return; }
    log.push(request.url.split(":")[0]);
    const upstream = net.connect(origin.address().port, "127.0.0.1", () => {
      socket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      upstream.write(head);
      upstream.pipe(socket);
      socket.pipe(upstream);
    });
    upstream.on("error", () => socket.destroy());
    socket.on("error", () => upstream.destroy());
  });
  // Chromium resets idle and challenged connections; those are not test failures.
  for (const server of [proxy, origin].filter(Boolean)) {
    server.on("connection", (socket) => socket.on("error", () => {}));
    server.on("clientError", (_error, socket) => socket.destroy());
    server.on("tlsClientError", (_error, socket) => socket.destroy());
  }
  await new Promise((resolve) => proxy.listen(0, "127.0.0.1", resolve));
  t.after(() => { proxy.closeAllConnections(); proxy.close(); origin?.closeAllConnections(); origin?.close(); });

  const worker = spawn(process.execPath, [workerPath], {
    stdio: ["pipe", "pipe", "ignore"],
    env: { ...process.env, HUNTPROXY_PLAYWRIGHT_CORE_PATH: runtime.playwright_core_path, HUNTPROXY_CHROME_EXECUTABLE: runtime.chromium_path },
  });
  const pending = new Map();
  let nextId = 1;
  let buffer = "";
  worker.stdout.on("data", (chunk) => {
    buffer += chunk;
    for (let index = buffer.indexOf("\n"); index >= 0; index = buffer.indexOf("\n")) {
      const line = buffer.slice(0, index);
      buffer = buffer.slice(index + 1);
      try {
        const message = JSON.parse(line);
        pending.get(message.id)?.(message);
      } catch {}
    }
  });
  const call = (method, params) => new Promise((resolve, reject) => {
    const id = nextId++;
    pending.set(id, (message) => (message.error ? reject(new Error(message.error.message)) : resolve(message.result)));
    worker.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id, method, params })}\n`);
  });
  const require = createRequire(path.join(runtime.playwright_core_path, "package.json"));
  const { chromium } = require(runtime.playwright_core_path);
  const probe = net.createServer();
  await new Promise((resolve) => probe.listen(0, "127.0.0.1", resolve));
  const cdpPort = probe.address().port;
  await new Promise((resolve) => probe.close(resolve));
  try {
    await call("session.start", {
      session_id: 1, engine: "chromium", persistent: true, profile: "p", profile_dir: path.join(dir, "profile"),
      proxy: { server: `http://127.0.0.1:${proxy.address().port}`, username: "workspace", password: "s3cret" },
      ca_cert_path: tls?.certPath || null, url: "about:blank",
    });
    const targets = [["http", "http://target.test/app", /plain target/]];
    if (tls) targets.push(["https", "https://target.test/app", /secure target/]);
    for (let cycle = 1; cycle <= 2; cycle += 1) {
      for (const [scheme, url, text] of targets) {
        const label = `cycle ${cycle} ${scheme}`;
        const before = log.length;
        const { cdp } = await call("session.cdp_enable", { session_id: 1, cdp_port: cdpPort });
        assert.ok(!log.slice(before).some((host) => host === "target.test"), `${label}: enabling reached the target`);
        const browser = await chromium.connectOverCDP(cdp.endpoint);
        try {
          const context = browser.contexts()[0];
          const page = context.pages()[0] || await context.newPage();
          assert.equal(page.url(), "about:blank", `${label}: the tab was moved`);
          // A client that routes requests receives the proxy challenge itself.
          await page.route("**/*", (route) => route.continue());
          const response = await page.goto(url, { waitUntil: "domcontentloaded", timeout: 20_000 });
          assert.equal(response.status(), 200, label);
          assert.match(await page.evaluate(() => document.body.textContent), text, label);
          await page.unroute("**/*");
          await page.goto("about:blank");
        } finally {
          await browser.close();
        }
        await call("session.cdp_disable", { session_id: 1 });
      }
    }
  } finally {
    await call("session.stop", { session_id: 1 }).catch(() => {});
    worker.stdin.end();
    await new Promise((resolve) => { worker.once("exit", resolve); setTimeout(() => { worker.kill("SIGKILL"); resolve(); }, 8_000); });
  }
});
