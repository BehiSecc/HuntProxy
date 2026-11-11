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
const inspect = spawnSync(process.execPath, [workerPath, "--inspect-runtime"], { encoding: "utf8", timeout: 60_000 });
const runtime = inspect.status === 0 ? JSON.parse(inspect.stdout) : {};
const available = runtime.chromium_path && runtime.playwright_core_path;

// Objects built inside a vm context have another realm's prototypes.
const plain = (value) => (value === undefined ? undefined : JSON.parse(JSON.stringify(value)));

const PRIME_URL = "http://huntproxy-auth-prime.invalid/";
const PRIME_ORIGIN = "http://huntproxy-auth-prime.invalid";

// The proxy credential helpers, plus the launch paths that hand them to Chromium.
function credentialCode(logs = []) {
  const code = source.slice(source.indexOf("function chromiumProxy"), source.indexOf("function validateCdpPort"));
  return vm.runInNewContext(`${code}\n({ chromiumProxy, chromiumLaunchOptions, proxyHttpCredentials, primeProxyAuth, launchChromium, PROXY_AUTH_PRIME_URL });`, {
    URL, Promise, fs, shuttingDown: false,
    browserRuntime: { chromium_path: "/selected/chrome", headless: true, headless_compatibility: false },
    rpcError: (code, message) => Object.assign(new Error(message), { code }),
    logMeta: (event, fields) => logs.push({ event, ...fields }),
    chromium: undefined,
  });
}

function closePageCode() {
  const code = source.slice(source.indexOf("// Closing a tab can stall"), source.indexOf("async function launchSessionRuntime"));
  return vm.runInNewContext(`${code}\n({ closePageWithin });`, { Promise, setTimeout, clearTimeout });
}

test("proxy credentials are scoped to the reserved prime origin and stay out of Playwright's proxy option", () => {
  const { chromiumProxy, chromiumLaunchOptions, proxyHttpCredentials, PROXY_AUTH_PRIME_URL } = credentialCode();
  assert.equal(PROXY_AUTH_PRIME_URL, PRIME_URL);
  const proxy = { server: "http://127.0.0.1:17891", username: "workspace", password: "s3cret" };
  assert.deepEqual(plain(proxyHttpCredentials(proxy)), { username: "workspace", password: "s3cret", origin: PRIME_ORIGIN });
  assert.equal(proxyHttpCredentials(null), undefined);
  assert.equal(proxyHttpCredentials({ server: proxy.server }), undefined);
  assert.deepEqual(plain(chromiumProxy(proxy)), { server: proxy.server, bypass: "<-loopback>" });
  assert.equal(chromiumProxy(null), undefined);
  const options = chromiumLaunchOptions(proxy, null, null, "/selected/chrome");
  assert.deepEqual(plain(options.proxy), { server: proxy.server, bypass: "<-loopback>" });
  assert.deepEqual(plain(options.httpCredentials), { username: "workspace", password: "s3cret", origin: PRIME_ORIGIN });
  assert.equal(chromiumLaunchOptions(null, null, null, "/selected/chrome").httpCredentials, undefined);
});

test("priming the proxy credentials is a no-op without credentials and never fails a launch", async () => {
  const logs = [];
  const { primeProxyAuth } = credentialCode(logs);
  const calls = [];
  const failing = {
    async goto(url) { calls.push(`goto ${url}`); throw new Error("net::ERR_SECRET_DETAIL\nCall log: more detail"); },
  };
  await primeProxyAuth(failing, null);
  await primeProxyAuth(failing, { server: "http://127.0.0.1:1" });
  assert.deepEqual(calls, []);
  await primeProxyAuth(failing, { server: "http://127.0.0.1:1", username: "u", password: "p" });
  assert.deepEqual(calls, [`goto ${PRIME_URL}`]);
  // The failure is reported (first line only), not swallowed.
  assert.deepEqual(logs, [{ event: "proxy_auth_prime_failed", error: "net::ERR_SECRET_DETAIL" }]);
  assert.match(PRIME_URL, /^http:\/\/[^/]+\.invalid\/$/);
  const visits = [];
  await primeProxyAuth({ async goto(url) { visits.push(url); } }, { server: "http://127.0.0.1:1", username: "u", password: "p" });
  assert.deepEqual(visits, [PRIME_URL, "about:blank"]);
});

test("every Playwright launch path scopes the proxy credentials and authenticates to the proxy once", async (t) => {
  const proxy = { server: "http://127.0.0.1:17891", username: "workspace", password: "s3cret" };
  const profile = fs.mkdtempSync(path.join(os.tmpdir(), "huntproxy-launchpaths-"));
  t.after(() => fs.rmSync(profile, { recursive: true, force: true }));
  const calls = [];
  const pageFor = (label) => ({ async goto(url) { calls.push(`${label} goto ${url}`); } });
  const contextFor = (label) => ({ pages: () => [pageFor(label)], newPage: async () => pageFor(label) });
  const code = source.slice(source.indexOf("function chromiumProxy"), source.indexOf("function validateCdpPort"));
  const launch = (headlessCompatibility) => {
    const context = vm.createContext({
      URL, Promise, fs, shuttingDown: false,
      browserRuntime: { chromium_path: "/selected/chrome", headless: true, headless_compatibility: headlessCompatibility },
      rpcError: (c, message) => Object.assign(new Error(message), { code: c }), logMeta() {},
      chromium: {
        async launchPersistentContext(directory, options) { calls.push({ persistent: options }); return contextFor("persistent"); },
        async launch(options) {
          calls.push({ launch: options });
          return { async newContext(contextOptions) { calls.push({ newContext: contextOptions }); return contextFor("ephemeral"); } };
        },
      },
    });
    vm.runInContext(code, context);
    // The native path has its own coverage in native.test.js.
    context.launchNativeChromium = async (...args) => { calls.push({ native: args }); return { native: true }; };
    return context.launchChromium;
  };
  const credentials = { username: "workspace", password: "s3cret", origin: PRIME_ORIGIN };
  const proxyOption = { server: proxy.server, bypass: "<-loopback>" };

  // Persistent project profile without the headless compatibility layer.
  await launch(false)(proxy, null, profile, null);
  assert.deepEqual(plain(calls.splice(0)).map((call) => (call.persistent
    ? { proxy: call.persistent.proxy, httpCredentials: call.persistent.httpCredentials } : call)), [
    { proxy: proxyOption, httpCredentials: credentials },
    `persistent goto ${PRIME_URL}`, "persistent goto about:blank",
  ]);

  // Throwaway browser.
  await launch(false)(proxy, null, null, null);
  const recorded = plain(calls.splice(0));
  assert.deepEqual(recorded.find((call) => call.launch).launch.proxy, proxyOption);
  assert.equal("httpCredentials" in recorded.find((call) => call.launch).launch, false);
  assert.deepEqual(recorded.find((call) => call.newContext).newContext.httpCredentials, credentials);
  assert.deepEqual(recorded.filter((call) => typeof call === "string"), [`ephemeral goto ${PRIME_URL}`, "ephemeral goto about:blank"]);
  // The password appears only as a scoped HTTP credential.
  for (const call of recorded.filter((entry) => typeof entry !== "string")) {
    const { httpCredentials, ...rest } = call.newContext || call.launch;
    assert.equal(JSON.stringify(rest).includes("s3cret"), false);
  }

  // Native Chromium receives the proxy untouched and scopes the credentials itself.
  assert.deepEqual(plain(await launch(true)(proxy, null, profile, null)), { native: true });
  assert.deepEqual(plain(calls.splice(0)), [{ native: [proxy, null, profile, null] }]);

  // Without credentials nothing is scoped or primed.
  await launch(false)({ server: proxy.server }, null, profile, null);
  const bare = plain(calls.splice(0));
  assert.equal(bare.length, 1);
  assert.equal(bare[0].persistent.httpCredentials, undefined);
});

test("closing a tab is bounded so a stalled Page.close cannot hold up a handoff", async () => {
  const { closePageWithin } = closePageCode();
  const started = Date.now();
  await closePageWithin({ close: () => new Promise(() => {}) }, 50);
  assert.ok(Date.now() - started < 2_000);
  await closePageWithin({ close: async () => { throw new Error("already closed"); } }, 50);
  let closed = false;
  await closePageWithin({ close: async () => { closed = true; } }, 50);
  assert.ok(closed);
});

function selfSigned(dir) {
  const key = path.join(dir, "key.pem");
  const cert = path.join(dir, "cert.pem");
  const made = spawnSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", cert,
    "-days", "2", "-subj", "/CN=target.test", "-addext", "subjectAltName=DNS:target.test"], { encoding: "utf8" });
  return made.status === 0 ? { key: fs.readFileSync(key), cert: fs.readFileSync(cert), certPath: cert } : null;
}

// Every wait in the integration tests is bounded, and the worker with its Chromium
// processes is always killed, so a stalled step fails the test instead of leaving
// `node --test` waiting on live children.
function within(promise, milliseconds, label) {
  let timer;
  return Promise.race([
    promise,
    new Promise((_, reject) => { timer = setTimeout(() => reject(new Error(`${label} did not finish within ${milliseconds} ms`)), milliseconds); }),
  ]).finally(() => clearTimeout(timer));
}

function processTable() {
  const table = [];
  let entries = [];
  try { entries = fs.readdirSync("/proc").filter((name) => /^\d+$/.test(name)); } catch {}
  for (const name of entries) {
    try {
      const stat = fs.readFileSync(`/proc/${name}/stat`, "utf8");
      const parent = Number(stat.slice(stat.lastIndexOf(")") + 2).split(" ")[1]);
      const command = fs.readFileSync(`/proc/${name}/cmdline`, "utf8");
      table.push({ pid: Number(name), parent, command });
    } catch {}
  }
  return table;
}

// The worker's descendants plus anything started on this test's own directory.
function killWorkerTree(worker, dir) {
  const table = processTable();
  const doomed = new Set(table.filter((entry) => entry.command.includes(dir)).map((entry) => entry.pid));
  const queue = worker?.pid ? [worker.pid] : [];
  while (queue.length) {
    const parent = queue.pop();
    for (const entry of table) {
      if (entry.parent === parent && !doomed.has(entry.pid)) { doomed.add(entry.pid); queue.push(entry.pid); }
    }
  }
  for (const pid of doomed) { try { process.kill(pid, "SIGKILL"); } catch {} }
  try { worker?.kill("SIGKILL"); } catch {}
  worker?.stdin.destroy();
  worker?.stdout.destroy();
}

const PROXY_CREDENTIALS = "workspace:s3cret";
const SITE_CREDENTIALS = "site:pw";
const basic = (credentials) => `Basic ${Buffer.from(credentials).toString("base64")}`;

// A proxy that demands `workspace:s3cret`, plus an HTTP target and an HTTPS target
// (reached through CONNECT). Both targets challenge /basic with Basic authentication
// for `site:pw` and record the headers of every request they receive.
async function startMockNetwork(t, dir) {
  const tls = selfSigned(dir);
  const expected = basic(PROXY_CREDENTIALS);
  const proxyLog = [];
  const targetRequests = [];
  const challenge = "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"test\"\r\nContent-Length: 0\r\n\r\n";
  const target = (scheme, label) => (request, response) => {
    targetRequests.push({ scheme, url: request.url, headers: { ...request.headers } });
    response.setHeader("Content-Type", "text/html");
    if (request.url.startsWith("/basic") && request.headers.authorization !== basic(SITE_CREDENTIALS)) {
      response.writeHead(401, { "WWW-Authenticate": "Basic realm=\"site\"", "Content-Type": "text/html" });
      response.end("<!doctype html><title>denied</title>denied");
      return;
    }
    response.end(`<!doctype html><title>${label}</title>${label} target`);
  };
  const origin = tls && https.createServer({ key: tls.key, cert: tls.cert }, target("https", "secure"));
  if (origin) await new Promise((resolve) => origin.listen(0, "127.0.0.1", resolve));
  const plain = http.createServer(target("http", "plain"));
  await new Promise((resolve) => plain.listen(0, "127.0.0.1", resolve));
  const proxy = http.createServer((request, response) => {
    if (request.headers["proxy-authorization"] !== expected) { response.socket.write(challenge); response.socket.destroy(); return; }
    const url = new URL(request.url);
    proxyLog.push(url.hostname);
    if (url.hostname.endsWith(".invalid")) { response.writeHead(502); response.end("proxy error"); return; }
    // Forward like a real proxy: Proxy-Authorization is hop-by-hop and never reaches the target.
    const headers = Object.fromEntries(Object.entries(request.headers)
      .filter(([name]) => name !== "proxy-authorization" && name !== "proxy-connection"));
    const upstream = http.request({ host: "127.0.0.1", port: plain.address().port, path: url.pathname + url.search, method: request.method, headers }, (answer) => {
      response.writeHead(answer.statusCode, answer.headers);
      answer.pipe(response);
    });
    upstream.on("error", () => response.destroy());
    request.pipe(upstream);
  });
  proxy.on("connect", (request, socket, head) => {
    if (request.headers["proxy-authorization"] !== expected) { socket.end(challenge); return; }
    proxyLog.push(request.url.split(":")[0]);
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
  for (const server of [proxy, plain, origin].filter(Boolean)) {
    server.on("connection", (socket) => socket.on("error", () => {}));
    server.on("clientError", (_error, socket) => socket.destroy());
    server.on("tlsClientError", (_error, socket) => socket.destroy());
  }
  await new Promise((resolve) => proxy.listen(0, "127.0.0.1", resolve));
  t.after(() => {
    for (const server of [proxy, plain, origin].filter(Boolean)) { server.closeAllConnections(); server.close(); }
  });
  return { tls, proxyServer: `http://127.0.0.1:${proxy.address().port}`, proxyLog, targetRequests };
}

// Drives a real worker process over its JSON-RPC stdio, killing its whole tree afterwards.
function startWorker(t, dir, env = {}) {
  const worker = spawn(process.execPath, [workerPath], {
    stdio: ["pipe", "pipe", "ignore"],
    env: { ...process.env, HUNTPROXY_PLAYWRIGHT_CORE_PATH: runtime.playwright_core_path, HUNTPROXY_CHROME_EXECUTABLE: runtime.chromium_path, ...env },
  });
  // Runs even when the test's own timeout fires.
  t.after(() => killWorkerTree(worker, dir));
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
  const call = (method, params, milliseconds = 45_000) => within(new Promise((resolve, reject) => {
    const id = nextId++;
    pending.set(id, (message) => (message.error ? reject(new Error(message.error.message)) : resolve(message.result)));
    worker.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id, method, params })}\n`);
  }), milliseconds, `worker ${method}`);
  const stop = async (sessionIds) => {
    for (const session_id of sessionIds) await call("session.stop", { session_id }, 10_000).catch(() => {});
    worker.stdin.end();
    await within(new Promise((resolve) => worker.once("exit", resolve)), 5_000, "worker exit").catch(() => {});
    killWorkerTree(worker, dir);
  };
  return { call, stop };
}

test("after a CDP handoff a page.route client's first navigation authenticates to the proxy, over HTTP and CONNECT", {
  skip: available ? false : "Playwright and Chromium are required for the browser regression",
  timeout: 120_000,
}, async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "huntproxy-proxyauth-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const network = await startMockNetwork(t, dir);
  const { call, stop } = startWorker(t, dir);
  const require = createRequire(path.join(runtime.playwright_core_path, "package.json"));
  const { chromium } = require(runtime.playwright_core_path);
  const probe = net.createServer();
  await new Promise((resolve) => probe.listen(0, "127.0.0.1", resolve));
  const cdpPort = probe.address().port;
  await new Promise((resolve) => probe.close(resolve));
  try {
    await call("session.start", {
      session_id: 1, engine: "chromium", persistent: true, profile: "p", profile_dir: path.join(dir, "profile"),
      proxy: { server: network.proxyServer, username: "workspace", password: "s3cret" },
      ca_cert_path: network.tls?.certPath || null, url: "about:blank",
    }, 60_000);
    const targets = [["http", "http://target.test/app", /plain target/]];
    if (network.tls) targets.push(["https", "https://target.test/app", /secure target/]);
    for (let cycle = 1; cycle <= 2; cycle += 1) {
      for (const [scheme, url, text] of targets) {
        const label = `cycle ${cycle} ${scheme}`;
        const before = network.proxyLog.length;
        const { cdp } = await call("session.cdp_enable", { session_id: 1, cdp_port: cdpPort });
        assert.ok(!network.proxyLog.slice(before).some((host) => host === "target.test"), `${label}: enabling reached the target`);
        const browser = await within(chromium.connectOverCDP(cdp.endpoint, { timeout: 15_000 }), 20_000, `${label} connectOverCDP`);
        try {
          const context = browser.contexts()[0];
          const page = context.pages()[0] || await context.newPage();
          assert.equal(page.url(), "about:blank", `${label}: the tab was moved`);
          // A client that routes requests receives the proxy challenge itself.
          await within(page.route("**/*", (route) => route.continue()), 10_000, `${label} route`);
          const response = await page.goto(url, { waitUntil: "domcontentloaded", timeout: 20_000 });
          assert.equal(response.status(), 200, label);
          assert.match(await within(page.evaluate(() => document.body.textContent), 10_000, `${label} evaluate`), text, label);
          await within(page.unroute("**/*"), 10_000, `${label} unroute`);
          await page.goto("about:blank", { timeout: 15_000 });
        } finally {
          await within(browser.close(), 10_000, `${label} browser.close`).catch(() => {});
        }
        await call("session.cdp_disable", { session_id: 1 });
      }
    }
  } finally {
    await stop([1]);
  }
});

// The capture token is the proxy's credential. A target that answers 401 must be
// treated as it would be without any credentials: the token is never offered to it,
// on any of the ways a browser can be launched, while the proxy still authenticates.
const LAUNCH_PATHS = [
  ["native persistent project browser", {}, { persistent: true }],
  ["Playwright persistent project browser", { HUNTPROXY_BROWSER_HEADLESS_COMPAT: "false" }, { persistent: true }],
  ["throwaway browser", {}, { persistent: false }],
];

for (const [name, env, mode] of LAUNCH_PATHS) {
  test(`a target's own 401 never receives the proxy credentials (${name}) while the proxy still authenticates`, {
    skip: available ? false : "Playwright and Chromium are required for the browser regression",
    timeout: 150_000,
  }, async (t) => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "huntproxy-leak-"));
    t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
    const network = await startMockNetwork(t, dir);
    const { call, stop } = startWorker(t, dir, env);
    const navigate = (url) => call("session.action", { session_id: 1, action: { type: "navigate", url } }, 40_000);
    // A failed navigation leaves Chromium's error page committing in the background.
    const settle = () => new Promise((resolve) => setTimeout(resolve, 750));
    try {
      await call("session.start", {
        session_id: 1, engine: "chromium", ...mode, ...(mode.persistent ? { profile: "p", profile_dir: path.join(dir, "profile") } : {}),
        proxy: { server: network.proxyServer, username: "workspace", password: "s3cret" },
        ca_cert_path: network.tls?.certPath || null, url: "about:blank",
      }, 60_000);
      // Proxy authentication works for plain HTTP and for CONNECT.
      assert.equal((await navigate("http://target.test/plain")).data.status, 200);
      if (network.tls) assert.equal((await navigate("https://target.test/plain")).data.status, 200);
      // A bare 401 challenge: whatever the browser does with it, it gets no credentials.
      for (const url of ["http://target.test/basic", ...(network.tls ? ["https://target.test/basic"] : [])]) {
        await navigate(url).catch((error) => assert.match(error.message, /ERR_INVALID_AUTH_CREDENTIALS|interrupted by another navigation/));
        await settle();
      }
      const challenged = network.targetRequests.filter((request) => request.url.startsWith("/basic"));
      assert.ok(challenged.length >= (network.tls ? 2 : 1), "the targets were never challenged");
      assert.deepEqual(challenged.map((request) => request.headers.authorization), challenged.map(() => undefined));
      // Credentials that belong to the site still reach the site.
      assert.equal((await navigate(`http://${SITE_CREDENTIALS}@target.test/basic`)).data.status, 200);
      // Nothing that reached any target carries the token, in any header.
      const everything = JSON.stringify(network.targetRequests);
      for (const secret of ["s3cret", Buffer.from(PROXY_CREDENTIALS).toString("base64")]) {
        assert.equal(everything.includes(secret), false, `a target received ${secret === "s3cret" ? "the token" : "the encoded proxy credentials"}`);
      }
      // The only site credentials a target ever saw are the ones the URL supplied.
      assert.deepEqual(
        [...new Set(network.targetRequests.map((request) => request.headers.authorization).filter(Boolean))],
        [basic(SITE_CREDENTIALS)],
      );
    } finally {
      await stop([1]);
    }
  });
}
