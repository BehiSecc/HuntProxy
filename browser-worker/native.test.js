import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import net from "node:net";
import vm from "node:vm";
import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";
import { test } from "node:test";

const source = fs.readFileSync(new URL("./index.js", import.meta.url), "utf8");
const launch = source.slice(source.indexOf("function chromiumLaunchOptions"), source.indexOf("async function launchChromium"));
function fixture(t, mode = "ready", startup = {}) {
  fs.mkdirSync("/tmp/artis", { recursive: true });
  const profile = fs.mkdtempSync("/tmp/artis/huntproxy-native-");
  t.after(() => fs.rmSync(profile, { recursive: true, force: true }));
  const events = [];
  const children = [];
  const attempts = [];
  const browser = {
    contexts: () => [{
      async setHTTPCredentials(credentials) { events.push("auth"); assert.equal(credentials.username, "workspace"); if (mode === "auth-error" || mode === "auth-unkillable") throw Error("Authentication setup failed"); },
      pages() { events.push("pages"); return [{ async bringToFront() { events.push("activate"); } }]; },
    }],
    async close() { events.push("disconnect"); },
  };
  let args;
  const api = vm.runInNewContext(`${launch}; ({ launchNativeChromium, nativeIdentity, nativeDebugPort, stopOwnedChrome })`, {
    fs, path, net: startup.realNet ? net : { createServer() {
      const server = new EventEmitter();
      server.listen = (port, host, callback) => { server.port = port || 12345; queueMicrotask(callback); };
      server.address = () => ({ port: server.port });
      server.close = (callback) => queueMicrotask(callback);
      return server;
    } }, URL, ownedChromeChildren: new Set(), shuttingDown: false,
    browserRuntime: { headless: false, chromium_path: "/selected/chrome" },
    chromiumProxy: (proxy) => proxy,
    os: { tmpdir: () => "/tmp/artis" },
    inspectNativeIdentity: async () => ({ userAgent: "test" }),
    setTimeout: (fn, ms) => setTimeout(fn, Math.min(ms, 30)), clearTimeout,
    spawn(executable, supplied, options) {
      assert.equal(executable, "/selected/chrome");
      assert.equal(options.stdio[2], "pipe");
      args = Array.from(supplied);
      attempts.push(args);
      const child = new EventEmitter();
      Object.assign(child, { pid: 12345, exitCode: null, signalCode: null, stderr: new PassThrough() });
      child.kill = (signal) => {
        events.push(signal);
        child.signalCode = signal;
        child.emit("exit", null, signal);
        child.emit("close", null, signal);
        return true;
      };
      if (mode === "auth-unkillable") child.kill = () => true;
      children.push(child);
      queueMicrotask(() => {
        if (mode === "exit" || (mode === "sandbox-once" && attempts.length === 1)) {
          for (const chunk of startup.stderr || []) child.stderr.write(chunk);
          child.exitCode = startup.signal ? null : startup.code ?? 1;
          child.signalCode = startup.signal || null;
          child.emit("exit", child.exitCode, child.signalCode);
          if (startup.lateStderr) child.stderr.write(startup.lateStderr);
          child.emit("close", child.exitCode, child.signalCode);
          return;
        }
        const port = Number(args.find((value) => value.startsWith("--remote-debugging-port=")).split("=")[1]);
        child.stderr.write(`DevTools listening on ws://127.0.0.1:${mode === "wrong-port" ? port + 1 : port}/devtools/browser/owned-browser\n`);
      });
      return child;
    },
    chromium: { async connectOverCDP(endpoint, options) {
      events.push("connect");
      assert.equal(options.noDefaults, true);
      assert.equal(options.isLocal, true);
      assert.equal(options.artifactsDir, path.join(profile, "huntproxy-artifacts"));
      assert.match(endpoint, /^ws:\/\/127\.0\.0\.1:\d+\/devtools\/browser\/owned-browser$/);
      return browser;
    } },
  });
  return { api, profile, events, get child() { return children[0]; }, children, attempts, args: () => args };
}

test("native startup attaches only its emitted endpoint and retains auth and routing protections", async (t) => {
  const f = fixture(t);
  const runtime = await f.api.launchNativeChromium({ server: "http://127.0.0.1:17891", username: "workspace", password: "local-session" }, "/managed/ca.crt", f.profile, null);
  assert.equal(runtime.ownedChrome, f.child);
  assert.deepEqual(f.events, ["connect", "auth", "pages", "activate"]);
  for (const argument of ["--remote-debugging-address=127.0.0.1", "--proxy-bypass-list=<-loopback>", "--force-webrtc-ip-handling-policy=disable_non_proxied_udp", "--ignore-certificate-errors", "--disable-quic"]) assert.equal(f.args().includes(argument), true);
  for (const flag of ["--disable-back-forward-cache", "--disable-background-networking", "--disable-component-update", "--disable-sync", "--disable-default-apps", "--no-service-autorun", "--disable-client-side-phishing-detection", "--disable-breakpad", "--disable-component-extensions-with-background-pages", "--disable-popup-blocking", "--disable-prompt-on-repost", "--password-store=basic", "--use-mock-keychain", "--disable-dev-shm-usage", "--disable-background-timer-throttling", "--disable-backgrounding-occluded-windows", "--disable-renderer-backgrounding", "--disable-hang-monitor", "--metrics-recording-only", "--disable-search-engine-choice-screen", "--no-first-run", "--no-default-browser-check"]) assert.ok(f.args().includes(flag), flag);
  for (const flag of ["--enable-automation", "--disable-extensions", "--remote-debugging-pipe", "--disable-features", "--enable-features", "--disable-field-trial-config", "--force-color-profile", "--allow-pre-commit-input", "--no-sandbox"]) assert.equal(f.args().some((arg) => arg === flag || arg.startsWith(`${flag}=`)), false, flag);
  assert.equal(runtime.sandbox_state, "enabled");
  assert.equal(runtime.sandbox_reason, null);
  assert.equal(f.args().at(-1), "about:blank");
  assert.equal(f.args().some((value) => /remote-debugging-pipe|AutomationControlled|local-session/.test(value)), false);
  await f.api.stopOwnedChrome(f.child);
  assert.equal(f.child.signalCode, "SIGTERM");
});

test("identity probe uses the same behavior flags as a persistent launch", async (t) => {
  const f = fixture(t);
  const runtime = await f.api.launchNativeChromium(null, null, f.profile, null);
  const persistentArgs = f.attempts[0];
  await f.api.stopOwnedChrome(runtime.ownedChrome);
  await f.api.nativeIdentity(null, null);
  const probeArgs = f.attempts[1];
  for (const flag of persistentArgs.filter((arg) => arg.startsWith("--")
      && !arg.startsWith("--user-data-dir=") && !arg.startsWith("--remote-debugging-port="))) {
    assert.ok(probeArgs.includes(flag), flag);
  }
});

for (const mode of ["wrong-port", "exit", "auth-error"]) {
  test(`native ${mode} failure cleans up without attaching another endpoint`, async (t) => {
    const f = fixture(t, mode);
    await assert.rejects(f.api.launchNativeChromium({ username: "workspace" }, null, f.profile, null));
    assert.ok(f.child.exitCode != null || f.child.signalCode != null);
    if (mode !== "auth-error") assert.equal(f.events.includes("connect"), false);
    assert.equal(f.attempts.length, 1);
  });
}

test("sandbox startup failures retry once, retain diagnostics, and cache the decision", async (t) => {
  const f = fixture(t, "sandbox-once", { stderr: ["private startup detail\nNo usable "], lateStderr: "sandbox!\n" });
  const runtime = await f.api.launchNativeChromium(null, null, f.profile, null);
  assert.equal(f.attempts.length, 2);
  assert.equal(f.attempts[0].includes("--no-sandbox"), false);
  assert.equal(f.attempts[1].includes("--no-sandbox"), true);
  assert.equal(runtime.sandbox_state, "disabled_fallback");
  assert.match(runtime.sandbox_reason, /sandbox initialization failed.*\/selected\/chrome.*AppArmor profile/);
  assert.doesNotMatch(runtime.sandbox_reason, /private startup detail/);
  await f.api.stopOwnedChrome(runtime.ownedChrome);
  const next = await f.api.launchNativeChromium(null, null, f.profile, null);
  assert.equal(f.attempts.length, 3);
  assert.equal(f.attempts[2].includes("--no-sandbox"), true);
  await f.api.stopOwnedChrome(next.ownedChrome);
});

test("recognized startup failures survive bounded stderr truncation", async (t) => {
  const f = fixture(t, "exit", { stderr: ["No usable sandbox!\n", "private startup detail".repeat(1_000)] });
  await assert.rejects(f.api.launchNativeChromium(null, null, f.profile, null), (error) => {
    assert.match(error.message, /sandbox initialization failed/);
    assert.doesNotMatch(error.message, /private startup detail/);
    assert.ok(error.message.length < 512);
    return true;
  });
});

for (const diagnostic of ["Missing X server or $DISPLAY", "Failed to connect to Wayland display"]) {
  test(`native startup identifies display failure: ${diagnostic}`, async (t) => {
    const f = fixture(t, "exit", { stderr: [diagnostic] });
    await assert.rejects(f.api.launchNativeChromium(null, null, f.profile, null), /could not connect to a display.*HUNTPROXY_BROWSER_HEADLESS=true/);
  });
}

for (const startup of [{ code: 23 }, { signal: "SIGTRAP" }]) {
  test(`unknown native startup failures expose only ${startup.signal || "exit code"}`, async (t) => {
    const f = fixture(t, "exit", { ...startup, stderr: ["private startup detail https://workspace:secret@example.test/"] });
    await assert.rejects(f.api.launchNativeChromium(null, null, f.profile, null), (error) => {
      assert.match(error.message, startup.signal ? /signal SIGTRAP/ : /exit code 23/);
      assert.doesNotMatch(error.message, /private startup detail|workspace|secret|example\.test/);
      return true;
    });
  });
}

test("an occupied handoff port fails before launching a browser", async (t) => {
  const listener = net.createServer();
  await new Promise((resolve) => listener.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => listener.close(resolve)));
  const f = fixture(t, "ready", { realNet: true });
  await assert.rejects(f.api.launchNativeChromium(null, null, f.profile, listener.address().port), { code: "EADDRINUSE" });
  assert.equal(f.args(), undefined);
});

test("an unavailable artifacts directory fails before spawning another browser", async (t) => {
  const f = fixture(t);
  fs.writeFileSync(path.join(f.profile, "huntproxy-artifacts"), "occupied");
  await assert.rejects(f.api.launchNativeChromium(null, null, f.profile, null));
  assert.equal(f.args(), undefined);
});


test("failed native startup retains an unkillable owned runtime without serializing it", async (t) => {
  const f = fixture(t, "auth-unkillable");
  await assert.rejects(f.api.launchNativeChromium({ username: "workspace" }, null, f.profile, null), (error) => {
    assert.equal(error.ownedRuntime.ownedChrome, f.child);
    assert.equal(error.ownedRuntime.profileDir, f.profile);
    assert.equal(Object.keys(error).includes("ownedRuntime"), false);
    assert.equal(JSON.stringify(error).includes("ownedChrome"), false);
    return true;
  });
});

test("cleanup failure retains the session and shutdown closes independent browsers together", async () => {
  const sessions = new Map([[1, { ownedChrome: "first" }], [2, { ownedChrome: "second" }]]);
  const events = [];
  let finishSecond;
  const second = new Promise((resolve) => { finishSecond = resolve; });
  const close = source.slice(source.indexOf("async function closeSession("), source.indexOf("let queue ="));
  const shutdown = source.slice(source.indexOf("async function shutdown("), source.indexOf('readline.on("close"'));
  const api = vm.runInNewContext(`${close}; ${shutdown}; ({closeSession, shutdown})`, {
    sessions, shuttingDown: false, ownedChromeChildren: new Set(["first", "second", "starting"]),
    async closeRuntime(runtime) {
      events.push(runtime.ownedChrome);
      if (runtime.ownedChrome === "first") throw Error("Profile remains in use");
      await second;
    },
    async stopOwnedChrome(child) { events.push(child); },
    logMeta() {}, process: { exit: (code) => events.push(code) },
  });
  await assert.rejects(api.closeSession(1));
  assert.equal(sessions.has(1), true);
  events.length = 0;
  const pending = api.shutdown(143);
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(events, ["first", "second", "starting"]);
  finishSecond();
  await pending;
  assert.equal(sessions.has(1), true);
  assert.equal(sessions.has(2), false);
  assert.equal(events.at(-1), 1);
});


test("occupied-port errors remain numeric JSON-RPC errors and retain other profiles", async (t) => {
  const listener = net.createServer();
  await new Promise((resolve) => listener.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => listener.close(resolve)));
  const f = fixture(t, "ready", { realNet: true });
  const sessions = new Map([[1, {}], [2, {}]]);
  const messages = [];
  const handle = source.slice(source.indexOf("async function handle(req)"), source.indexOf("async function closeRuntime("));
  const api = vm.runInNewContext(`${handle}; ({handle})`, {
    sessions, PROTOCOL: 1, browserRuntime: {},
    executeAction: () => f.api.nativeDebugPort(listener.address().port),
    rpcError: (code, message) => ({ code, message }), logMeta() {},
    respond: (id, result, error) => messages.push(JSON.parse(JSON.stringify({ id, result, error }))),
  });
  await api.handle({ id: 1, method: "session.action", params: { session_id: 1 } });
  assert.equal(messages[0].error.code, -32000);
  assert.match(messages[0].error.message, /EADDRINUSE/);
  assert.equal(sessions.size, 2);
  await api.handle({ id: 2, method: "hello" });
  assert.equal(messages[1].result.protocol, 1);
});
