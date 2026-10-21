import assert from "node:assert/strict";
import { createRequire } from "node:module";
import net from "node:net";
import { test } from "node:test";
import { createIdentityRelay, inspectNativeIdentity, normalizeNativeIdentity } from "./headless.js";

const { WebSocket, WebSocketServer } = createRequire(import.meta.url)("ws");
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function nativeIdentity(version = "149.0.7827.55", platform = "Linux") {
  return {
    userAgent: `Mozilla/5.0 HeadlessChrome/${version.split(".")[0]}.0.0.0 Safari/537.36`,
    metadata: {
      brands: [{ brand: "Chromium", version: version.split(".")[0] }, { brand: "Native Brand", version: "8" }],
      fullVersionList: [{ brand: "Chromium", version }, { brand: "Native Brand", version: "8.0.0.0" }],
      uaFullVersion: version, formFactors: ["Desktop"], platform, platformVersion: "",
      architecture: "arm", bitness: "64", model: "", mobile: false, wow64: false,
    },
  };
}

async function until(predicate, label) {
  const deadline = Date.now() + 2_000;
  while (!predicate()) {
    if (Date.now() > deadline) throw new Error(`Timed out waiting for ${label}`);
    await sleep(5);
  }
}

async function openSocket(endpoint, options) {
  const socket = new WebSocket(endpoint, options);
  await new Promise((resolve, reject) => {
    socket.once("open", resolve);
    socket.once("error", reject);
  });
  socket.on("error", () => {});
  return socket;
}

async function mockChrome(t, handle = () => false) {
  const server = new WebSocketServer({ host: "127.0.0.1", port: 0, perMessageDeflate: false });
  await new Promise((resolve, reject) => { server.once("listening", resolve); server.once("error", reject); });
  const commands = [];
  let socket;
  function emit(message) { socket.send(JSON.stringify(message)); }
  function reply(message, result = {}) { emit({ id: message.id, result, ...(message.sessionId ? { sessionId: message.sessionId } : {}) }); }
  function reject(message, error = { code: -32000, message: "Session closed" }) {
    emit({ id: message.id, error, ...(message.sessionId ? { sessionId: message.sessionId } : {}) });
  }
  server.on("connection", (connected) => {
    socket = connected;
    socket.on("error", () => {});
    socket.on("message", (data) => {
      const message = JSON.parse(data.toString());
      commands.push(message);
      if (!handle(message, { emit, reply, reject })) reply(message);
    });
  });
  t.after(async () => {
    for (const client of server.clients) client.terminate();
    await new Promise((resolve) => server.close(resolve));
  });
  return {
    endpoint: `ws://127.0.0.1:${server.address().port}`,
    commands, emit, reply, reject,
    disconnect() { socket.terminate(); },
  };
}

async function relayFixture(t, handler) {
  let relay;
  const clients = new Set();
  t.after(async () => {
    if (!relay) return;
    relay.beginClose();
    for (const client of clients) client.terminate();
    await relay.close();
  });
  const chrome = await mockChrome(t, handler);
  const identity = normalizeNativeIdentity(nativeIdentity(), "149.0.7827.55");
  let failures = 0;
  relay = await createIdentityRelay(chrome.endpoint, identity, () => { failures++; });
  async function controller(onMessage = () => {}) {
    const socket = await openSocket(relay.endpoint);
    clients.add(socket);
    const messages = [];
    socket.on("message", (data) => {
      const message = JSON.parse(data.toString());
      messages.push(message);
      onMessage(message, socket);
    });
    return { socket, messages, send: (message) => socket.send(JSON.stringify(message)) };
  }
  return { chrome, identity, relay, controller, failures: () => failures };
}

test("normalization preserves the selected runtime's full metadata and branding", () => {
  for (const [version, platform] of [["149.0.7827.55", "Linux"], ["153.0.8010.36", "macOS"], ["146.0.1.2", "Windows"]]) {
    const observed = nativeIdentity(version, platform);
    const actual = normalizeNativeIdentity(observed, version);
    assert.equal(actual.userAgent, observed.userAgent.replace("HeadlessChrome/", "Chrome/"));
    assert.deepEqual(actual.userAgentMetadata, {
      ...Object.fromEntries(Object.entries(observed.metadata).filter(([key]) => key !== "uaFullVersion")),
      fullVersion: version,
    });
    assert.equal(observed.userAgent.includes("HeadlessChrome/"), true);
  }
});

test("incomplete or mismatched native identity fails rather than inventing metadata", () => {
  const mutations = [
    (value) => { value.metadata.fullVersionList = []; },
    (value) => { delete value.metadata.formFactors; },
    (value) => { delete value.metadata.bitness; },
    (value) => { value.metadata.wow64 = "false"; },
    (value) => { value.metadata.uaFullVersion = "148.0.0.1"; },
  ];
  for (const mutate of mutations) {
    const value = nativeIdentity();
    mutate(value);
    assert.throws(() => normalizeNativeIdentity(value, "149.0.7827.55"), /complete native identity/);
  }
});

test("native inspection waits for the owned local page and closes its probe browser", async (t) => {
  let evaluations = 0;
  const chrome = await mockChrome(t, (message, { reply }) => {
    if (message.method === "Target.createTarget") { assert.equal(message.params.url, "chrome://version"); reply(message, { targetId: "probe" }); return true; }
    if (message.method === "Target.attachToTarget") { reply(message, { sessionId: "probe-session" }); return true; }
    if (message.method === "Runtime.evaluate") {
      evaluations++;
      reply(message, { result: { value: evaluations === 1 ? null : nativeIdentity() } });
      return true;
    }
    return false;
  });
  const actual = await inspectNativeIdentity(chrome.endpoint, "149.0.7827.55");
  assert.equal(evaluations, 2);
  assert.equal(actual.userAgentMetadata.fullVersion, "149.0.7827.55");
  assert.equal(chrome.commands.at(-1).method, "Browser.close");
  assert.ok(chrome.commands.every((message) => new Set(["Target.createTarget", "Target.attachToTarget", "Runtime.evaluate", "Browser.close"]).has(message.method)));
});

test("relay rejects website origins and wrong paths before accepting its single controller", async (t) => {
  const f = await relayFixture(t);
  assert.equal(new URL(f.relay.endpoint).hostname, "127.0.0.1");
  for (const [endpoint, options] of [[f.relay.endpoint, { origin: "https://example.test" }], [f.relay.endpoint.replace(/\/[^/]+$/, "/unrelated"), undefined]]) {
    await assert.rejects(openSocket(endpoint, options), /Unexpected server response/);
  }
  const discovery = await fetch(f.relay.endpoint.replace(/^ws:/, "http:").replace(/\/[^/]+$/, "/json/list"));
  assert.ok([404, 426].includes(discovery.status));
  assert.doesNotMatch(await discovery.text(), /webSocketDebuggerUrl/);
  assert.equal(f.chrome.commands.length, 0);
  const controller = await f.controller();
  const second = new WebSocket(f.relay.endpoint);
  const code = await new Promise((resolve, reject) => { second.once("close", resolve); second.once("error", reject); });
  assert.equal(code, 1008);
  controller.send({ id: 21, method: "Browser.getVersion" });
  await until(() => controller.messages.some((message) => message.id === 21), "original controller response");
  assert.equal(f.failures(), 0);
});

test("page identity is acknowledged before attachment, buffered diagnostics, or Playwright resume", async (t) => {
  let metadata;
  const f = await relayFixture(t, (message) => {
    if (message.method === "Emulation.setUserAgentOverride" && !metadata) { metadata = message; return true; }
    return false;
  });
  const controller = await f.controller((message, socket) => {
    if (message.method === "Target.attachedToTarget") socket.send(JSON.stringify({ id: 31, sessionId: message.params.sessionId, method: "Runtime.runIfWaitingForDebugger" }));
  });
  const attached = { method: "Target.attachedToTarget", params: { sessionId: "page-session", targetInfo: { type: "page", targetId: "page" }, waitingForDebugger: true } };
  f.chrome.emit(attached);
  await until(() => metadata, "identity command");
  const diagnostic = { sessionId: "page-session", method: "Runtime.consoleAPICalled", params: { type: "warning", args: [{ value: "verification-ready" }] } };
  f.chrome.emit(diagnostic);
  await sleep(20);
  assert.equal(controller.messages.length, 0);
  assert.deepEqual(metadata.params, f.identity);
  f.chrome.reply(metadata);
  await until(() => f.chrome.commands.some((message) => message.method === "Runtime.runIfWaitingForDebugger"), "Playwright resume");
  assert.deepEqual(controller.messages[0], attached);
  assert.deepEqual(controller.messages[1], diagnostic);
  assert.ok(f.chrome.commands.indexOf(metadata) < f.chrome.commands.findIndex((message) => message.method === "Runtime.runIfWaitingForDebugger"));
  controller.send({ id: 32, sessionId: "page-session", method: "Emulation.setUserAgentOverride", params: { userAgent: "", acceptLanguage: "fr-FR" } });
  await until(() => controller.messages.some((message) => message.id === 32), "merged override response");
  assert.deepEqual(f.chrome.commands.at(-1).params, { ...f.identity, acceptLanguage: "fr-FR" });
  assert.equal(f.failures(), 0);
});

test("a command reply stays before its immediately following protocol event", async (t) => {
  const diagnostic = { method: "Runtime.consoleAPICalled", params: { type: "log", args: [{ value: "after-reply" }] } };
  const f = await relayFixture(t, (message, { reply, emit }) => {
    if (message.method !== "Browser.getVersion") return false;
    reply(message, { product: "Chrome/149.0.7827.55" });
    emit(diagnostic);
    return true;
  });
  const controller = await f.controller();
  controller.send({ id: 81, method: "Browser.getVersion" });
  await until(() => controller.messages.length === 2, "adjacent reply and event");
  assert.deepEqual(controller.messages, [{ id: 81, result: { product: "Chrome/149.0.7827.55" } }, diagnostic]);
  assert.equal(f.failures(), 0);
});

test("a held attach event stays before its command reply and later diagnostics", async (t) => {
  let metadata;
  const attached = { method: "Target.attachedToTarget", params: { sessionId: "manual-page", targetInfo: { type: "page", targetId: "manual" }, waitingForDebugger: false } };
  const f = await relayFixture(t, (message, { reply, emit }) => {
    if (message.method === "Target.attachToTarget") {
      emit(attached);
      reply(message, { sessionId: "manual-page" });
      return true;
    }
    if (message.method === "Emulation.setUserAgentOverride") { metadata = message; return true; }
    return false;
  });
  const controller = await f.controller();
  controller.send({ id: 82, method: "Target.attachToTarget", params: { targetId: "manual", flatten: true } });
  await until(() => metadata, "manual session identity command");
  const diagnostic = { sessionId: "manual-page", method: "Runtime.consoleAPICalled", params: { type: "log", args: [{ value: "manual-ready" }] } };
  f.chrome.emit(diagnostic);
  await sleep(20);
  assert.deepEqual(controller.messages, [], "Attach replies must not overtake their held native event");
  f.chrome.reply(metadata);
  await until(() => controller.messages.length === 3, "held attach, reply, and diagnostic");
  assert.deepEqual(controller.messages, [attached, { id: 82, result: { sessionId: "manual-page" } }, diagnostic]);
  assert.equal(f.failures(), 0);
});

test("a qualified page's secondary observer can initialize before its identity ACK", async (t) => {
  const pending = new Map();
  const f = await relayFixture(t, (message, { emit, reply }) => {
    if (message.method === "Target.attachToTarget") {
      emit({ sessionId: message.sessionId, method: "Target.attachedToTarget", params: { sessionId: "observer", targetInfo: { type: "page", targetId: "qualified" }, waitingForDebugger: false } });
      reply(message, { sessionId: "observer" });
      return true;
    }
    if (message.method === "Emulation.setUserAgentOverride" && message.sessionId !== "primary") { pending.set(message.sessionId, message); return true; }
    if (message.method === "Runtime.enable" && message.sessionId === "observer") {
      assert.ok(pending.has("observer"), "Identity must be queued before observer initialization");
      reply(pending.get("observer"));
    }
    return false;
  });
  const controller = await f.controller((message, socket) => {
    if (message.id === 91) socket.send(JSON.stringify({ id: 92, sessionId: "observer", method: "Runtime.enable" }));
  });
  f.chrome.emit({ method: "Target.attachedToTarget", params: { sessionId: "primary", targetInfo: { type: "page", targetId: "qualified" }, waitingForDebugger: true } });
  await until(() => controller.messages.some((message) => message.params?.sessionId === "primary"), "qualified primary owner");
  controller.send({ id: 91, sessionId: "client-browser", method: "Target.attachToTarget", params: { targetId: "qualified", flatten: true } });
  await until(() => controller.messages.some((message) => message.id === 92), "observer initialization releasing its identity ACK");
  assert.deepEqual(pending.get("observer").params, f.identity);
  assert.equal(f.failures(), 0);
  // Releasing initialization must not turn a later unsupported override into
  // a successful identity result for another secondary observer.
  f.chrome.emit({ sessionId: "client-browser", method: "Target.attachedToTarget", params: { sessionId: "unsupported-observer", targetInfo: { type: "page", targetId: "qualified" }, waitingForDebugger: false } });
  await until(() => pending.has("unsupported-observer"), "secondary identity verification");
  f.chrome.reject(pending.get("unsupported-observer"), { code: -32601, message: "Method unavailable" });
  await until(() => f.failures() === 1, "unsupported secondary identity failure");
  assert.throws(() => f.relay.assertHealthy(), /lost a target's identity/);
});

test("an unacknowledged primary owner cannot release a secondary attachment", async (t) => {
  const pending = new Map();
  const f = await relayFixture(t, (message) => {
    if (message.method !== "Emulation.setUserAgentOverride") return false;
    pending.set(message.sessionId, message);
    return true;
  });
  const controller = await f.controller();
  const primary = { method: "Target.attachedToTarget", params: { sessionId: "pending-primary", targetInfo: { type: "page", targetId: "pending" }, waitingForDebugger: true } };
  const observer = { sessionId: "client-browser", method: "Target.attachedToTarget", params: { sessionId: "pending-observer", targetInfo: { type: "page", targetId: "pending" }, waitingForDebugger: false } };
  f.chrome.emit(primary);
  await until(() => pending.has("pending-primary"), "primary identity command");
  f.chrome.emit(observer);
  await until(() => pending.has("pending-observer"), "secondary identity command");
  await sleep(20);
  assert.deepEqual(controller.messages, []);
  f.chrome.reply(pending.get("pending-primary"));
  await until(() => controller.messages.length === 1, "primary identity acknowledgement");
  await sleep(20);
  assert.deepEqual(controller.messages, [primary], "A secondary attached before qualification remains independently gated");
  f.chrome.reply(pending.get("pending-observer"));
  await until(() => controller.messages.length === 2, "secondary identity acknowledgement");
  assert.deepEqual(controller.messages, [primary, observer]);
  assert.equal(f.failures(), 0);
});

test("a detached identity owner cannot qualify a later attachment to the same target", async (t) => {
  let metadata;
  const f = await relayFixture(t, (message) => {
    if (message.method === "Emulation.setUserAgentOverride" && message.sessionId === "replacement") { metadata = message; return true; }
    return false;
  });
  const controller = await f.controller();
  f.chrome.emit({ method: "Target.attachedToTarget", params: { sessionId: "original", targetInfo: { type: "iframe", targetId: "retained-frame" }, waitingForDebugger: true } });
  await until(() => controller.messages.length === 1, "original frame identity owner");
  f.chrome.emit({ method: "Target.detachedFromTarget", params: { sessionId: "original", targetId: "retained-frame" } });
  await until(() => controller.messages.length === 2, "original owner removal");
  const attached = { sessionId: "client-browser", method: "Target.attachedToTarget", params: { sessionId: "replacement", targetInfo: { type: "iframe", targetId: "retained-frame" }, waitingForDebugger: false } };
  f.chrome.emit(attached);
  await until(() => metadata, "replacement identity command");
  await sleep(20);
  assert.equal(controller.messages.length, 2, "A previously qualified target must acquire a new live owner");
  f.chrome.reply(metadata);
  await until(() => controller.messages.length === 3, "replacement identity acknowledgement");
  assert.deepEqual(controller.messages[2], attached);
  assert.equal(f.failures(), 0);
});

test("service-worker identity is queued before resume without awaiting its unavailable renderer", async (t) => {
  const deferred = [];
  const f = await relayFixture(t, (message, { reply }) => {
    if (message.method === "Emulation.setUserAgentOverride") { deferred.push(message); return true; }
    if (message.method === "Runtime.runIfWaitingForDebugger") { deferred.splice(0).forEach((entry) => reply(entry)); }
    return false;
  });
  const controller = await f.controller((message, socket) => {
    if (message.method !== "Target.attachedToTarget") return;
    socket.send(JSON.stringify({ id: 40, sessionId: "service-session", method: "Emulation.setUserAgentOverride", params: { userAgent: "" } }));
    socket.send(JSON.stringify({ id: 41, sessionId: "service-session", method: "Runtime.runIfWaitingForDebugger" }));
  });
  f.chrome.emit({ method: "Target.attachedToTarget", params: { sessionId: "service-session", targetInfo: { type: "service_worker", targetId: "service" }, waitingForDebugger: true } });
  await until(() => controller.messages.some((message) => message.id === 41), "service-worker resume response");
  assert.deepEqual(f.chrome.commands.map((message) => message.method), ["Emulation.setUserAgentOverride", "Emulation.setUserAgentOverride", "Runtime.runIfWaitingForDebugger"]);
  for (const command of f.chrome.commands.slice(0, 2)) assert.deepEqual(command.params, f.identity);
  assert.equal(f.failures(), 0);
});

test("a shared worker retains an identity owner after Playwright detaches its unsupported session", async (t) => {
  const f = await relayFixture(t, (message, { emit, reply }) => {
    if (message.method === "Target.attachToTarget") {
      emit({ method: "Target.attachedToTarget", params: { sessionId: "retained-shared", targetInfo: { type: "shared_worker", targetId: "shared" }, waitingForDebugger: false } });
      reply(message, { sessionId: "retained-shared" }); return true;
    }
    if (message.method === "Target.detachFromTarget") emit({ method: "Target.detachedFromTarget", params: { sessionId: message.params.sessionId, targetId: "shared" } });
    return false;
  });
  const controller = await f.controller((message, socket) => {
    if (message.method !== "Target.attachedToTarget") return;
    socket.send(JSON.stringify({ id: 50, sessionId: message.params.sessionId, method: "Runtime.runIfWaitingForDebugger" }));
    socket.send(JSON.stringify({ id: 51, method: "Target.detachFromTarget", params: { sessionId: message.params.sessionId } }));
  });
  f.chrome.emit({ method: "Target.attachedToTarget", params: { sessionId: "pw-shared", targetInfo: { type: "shared_worker", targetId: "shared" }, waitingForDebugger: true } });
  await until(() => controller.messages.some((message) => message.id === 51), "Playwright shared-worker detach");
  assert.deepEqual(f.chrome.commands.filter((message) => message.method === "Emulation.setUserAgentOverride").map((message) => message.sessionId).sort(), ["pw-shared", "retained-shared"]);
  const resumeIndex = f.chrome.commands.findIndex((message) => message.method === "Runtime.runIfWaitingForDebugger");
  assert.ok(f.chrome.commands.filter((message) => message.method === "Emulation.setUserAgentOverride").every((message) => f.chrome.commands.indexOf(message) < resumeIndex));
  assert.equal(controller.messages.filter((message) => message.method === "Target.attachedToTarget").length, 1);
  assert.ok(f.chrome.commands.filter((message) => message.method === "Target.detachFromTarget").every((message) => message.params.sessionId !== "retained-shared"));
  assert.equal(f.failures(), 0);
});

for (const side of ["controller", "upstream"]) {
  test(`unexpected ${side} disconnect invokes owned-browser failure cleanup once`, async (t) => {
    const f = await relayFixture(t);
    const controller = await f.controller();
    if (side === "controller") controller.socket.terminate(); else f.chrome.disconnect();
    await until(() => f.failures() === 1, "failure cleanup");
    assert.throws(() => f.relay.assertHealthy(), /lost a target's identity/);
    controller.socket.terminate();
    await sleep(10);
    assert.equal(f.failures(), 1);
  });
}

test("normal shutdown closes the controller and upstream without identity failure", async (t) => {
  const f = await relayFixture(t);
  const controller = await f.controller();
  f.relay.beginClose();
  controller.socket.terminate();
  await f.relay.close();
  assert.doesNotThrow(() => f.relay.assertHealthy());
  assert.equal(f.failures(), 0);
});

test("an unfinished local HTTP request cannot hold relay shutdown open", async (t) => {
  const f = await relayFixture(t);
  const endpoint = new URL(f.relay.endpoint);
  const socket = net.connect({ host: endpoint.hostname, port: Number(endpoint.port) });
  let closing;
  let timer;
  try {
    await new Promise((resolve, reject) => { socket.once("connect", resolve); socket.once("error", reject); });
    socket.write("GET /json/list HTTP/1.1\r\nHost: 127.0.0.1\r\n");
    await sleep(10);
    f.relay.beginClose();
    closing = f.relay.close();
    const stopped = await Promise.race([closing.then(() => true), new Promise((resolve) => { timer = setTimeout(() => resolve(false), 1_000); })]);
    assert.equal(stopped, true, "Relay shutdown must close unfinished HTTP connections");
  } finally {
    clearTimeout(timer);
    socket.destroy();
    await closing;
  }
});

test("an unsupported identity command fails the session", async (t) => {
  const f = await relayFixture(t, (message, { reject }) => {
    if (message.method === "Emulation.setUserAgentOverride") { reject(message, { code: -32601, message: "Method unavailable" }); return true; }
    return false;
  });
  const controller = await f.controller();
  f.chrome.emit({ method: "Target.attachedToTarget", params: { sessionId: "page-session", targetInfo: { type: "page", targetId: "page" }, waitingForDebugger: true } });
  await until(() => f.failures() === 1, "unsupported identity failure");
  assert.equal(controller.messages.some((message) => message.method === "Target.attachedToTarget"), false);
  assert.throws(() => f.relay.assertHealthy(), /lost a target's identity/);
});

test("a service-worker identity error after FIFO resume still fails the session", async (t) => {
  let pending;
  const f = await relayFixture(t, (message) => {
    if (message.method === "Emulation.setUserAgentOverride") { pending = message; return true; }
    return false;
  });
  const controller = await f.controller((message, socket) => {
    if (message.method === "Target.attachedToTarget") socket.send(JSON.stringify({ id: 70, sessionId: message.params.sessionId, method: "Runtime.runIfWaitingForDebugger" }));
  });
  f.chrome.emit({ method: "Target.attachedToTarget", params: { sessionId: "service-session", targetInfo: { type: "service_worker", targetId: "service" }, waitingForDebugger: true } });
  await until(() => pending && controller.messages.some((message) => message.id === 70), "service-worker initial fetch release");
  f.chrome.reject(pending, { code: -32601, message: "Method unavailable" });
  await until(() => f.failures() === 1, "late service-worker identity failure");
  assert.throws(() => f.relay.assertHealthy(), /lost a target's identity/);
});

test("the exact closure error waits for its own session's detach and preserves other pages", async (t) => {
  let pending;
  const f = await relayFixture(t, (message) => {
    if (message.method === "Emulation.setUserAgentOverride" && message.sessionId === "failed-service") { pending = message; return true; }
    return false;
  });
  const controller = await f.controller();
  for (const [sessionId, targetId, type] of [["healthy-page", "healthy", "page"], ["failed-service", "failed", "service_worker"], ["other-service-session", "failed", "service_worker"]]) {
    f.chrome.emit({ method: "Target.attachedToTarget", params: { sessionId, targetInfo: { type, targetId }, waitingForDebugger: true } });
  }
  await until(() => pending && controller.messages.filter((message) => message.method === "Target.attachedToTarget").length === 3, "live page and service-worker sessions");
  f.chrome.reject(pending, { code: -32000, message: "Inspected target navigated or closed" });
  await sleep(20);
  // Even another session for the same target must not satisfy this wait.
  f.chrome.emit({ method: "Target.detachedFromTarget", params: { sessionId: "other-service-session", targetId: "failed" } });
  await sleep(20);
  assert.equal(f.failures(), 0);
  f.chrome.emit({ method: "Target.detachedFromTarget", params: { sessionId: "failed-service", targetId: "failed" } });
  await until(() => controller.messages.some((message) => message.method === "Target.detachedFromTarget" && message.params.sessionId === "failed-service"), "confirmed failed session removal");
  controller.send({ id: 101, sessionId: "healthy-page", method: "Runtime.evaluate", params: { expression: "1 + 1" } });
  await until(() => controller.messages.some((message) => message.id === 101), "unaffected page response");
  assert.equal(f.failures(), 0);
  assert.doesNotThrow(() => f.relay.assertHealthy());
});

test("the exact closure error remains fatal when its session never detaches", async (t) => {
  let pending;
  const f = await relayFixture(t, (message) => {
    if (message.method === "Emulation.setUserAgentOverride") { pending = message; return true; }
    return false;
  });
  await f.controller();
  f.chrome.emit({ method: "Target.attachedToTarget", params: { sessionId: "live-service", targetInfo: { type: "service_worker", targetId: "live" }, waitingForDebugger: true } });
  await until(() => pending, "live service-worker identity command");
  const started = Date.now();
  f.chrome.reject(pending, { code: -32000, message: "Inspected target navigated or closed" });
  f.chrome.emit({ method: "Target.detachedFromTarget", params: { sessionId: "unrelated-session", targetId: "live" } });
  await sleep(20);
  assert.equal(f.failures(), 0, "A closure error may precede the matching detach notification");
  await until(() => f.failures() === 1, "bounded live-target identity failure");
  assert.ok(Date.now() - started >= 400, "The exact closure error must allow its bounded detach window");
  assert.throws(() => f.relay.assertHealthy(), /lost a target's identity/);
});

test("normal shutdown cancels a pending target-detach wait timer", async (t) => {
  const originalSetTimeout = globalThis.setTimeout;
  const originalClearTimeout = globalThis.clearTimeout;
  const waits = new Set();
  const cancelled = new Set();
  globalThis.setTimeout = (callback, milliseconds, ...args) => {
    const timer = originalSetTimeout(callback, milliseconds, ...args);
    if (milliseconds === 500) waits.add(timer);
    return timer;
  };
  globalThis.clearTimeout = (timer) => {
    if (waits.has(timer)) cancelled.add(timer);
    return originalClearTimeout(timer);
  };
  try {
    let pending;
    const f = await relayFixture(t, (message) => {
      if (message.method === "Emulation.setUserAgentOverride") { pending = message; return true; }
      return false;
    });
    await f.controller();
    f.chrome.emit({ method: "Target.attachedToTarget", params: { sessionId: "closing-service", targetInfo: { type: "service_worker", targetId: "closing" }, waitingForDebugger: true } });
    await until(() => pending, "closing service-worker identity command");
    f.chrome.reject(pending, { code: -32000, message: "Inspected target navigated or closed" });
    await until(() => waits.size === 1, "target-detach wait timer");
    f.relay.beginClose();
    await f.relay.close();
    assert.deepEqual(cancelled, waits, "Shutdown must cancel every pending detach timer");
    assert.equal(f.failures(), 0);
    assert.doesNotThrow(() => f.relay.assertHealthy());
  } finally {
    globalThis.setTimeout = originalSetTimeout;
    globalThis.clearTimeout = originalClearTimeout;
  }
});

test("a target detached during identity setup leaves the controller usable", async (t) => {
  let pending;
  const f = await relayFixture(t, (message) => {
    if (message.method === "Emulation.setUserAgentOverride") { pending = message; return true; }
    return false;
  });
  const controller = await f.controller();
  f.chrome.emit({ method: "Target.attachedToTarget", params: { sessionId: "brief-page", targetInfo: { type: "page", targetId: "brief" }, waitingForDebugger: true } });
  await until(() => pending, "brief target identity command");
  f.chrome.emit({ method: "Target.detachedFromTarget", params: { sessionId: "brief-page", targetId: "brief" } });
  f.chrome.reject(pending);
  await until(() => controller.messages.some((message) => message.method === "Target.detachedFromTarget"), "brief target detach");
  controller.send({ id: 61, method: "Browser.getVersion" });
  await until(() => controller.messages.some((message) => message.id === 61), "controller after target close");
  assert.equal(f.failures(), 0);
  assert.doesNotThrow(() => f.relay.assertHealthy());
});
