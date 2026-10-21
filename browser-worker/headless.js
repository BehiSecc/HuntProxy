import { createRequire } from "node:module";
import { randomUUID } from "node:crypto";
import http from "node:http";

const require = createRequire(import.meta.url);
const targetTypes = new Set(["page", "iframe", "worker", "service_worker", "shared_worker"]);
const closedTarget = () => Object.assign(new Error("Browser target closed"), { code: -32000 });

export function headlessDependencyError() {
  try { require.resolve("ws"); return null; } catch {
    return "Headless compatibility requires browser-worker dependencies; run HuntProxy browser install";
  }
}

function websocketRuntime() {
  const error = headlessDependencyError();
  if (error) throw new Error(error);
  return require("ws");
}

async function connect(endpoint) {
  const { WebSocket } = websocketRuntime();
  const socket = new WebSocket(endpoint, { perMessageDeflate: false });
  const pending = new Map();
  let nextId = 0;
  let onEvent = () => {};
  let onClose = () => {};
  socket.on("message", (data) => {
    let message;
    try { message = JSON.parse(data.toString()); } catch { socket.terminate(); return; }
    if (!message || typeof message !== "object" || Array.isArray(message)) { socket.terminate(); return; }
    if (message.id == null) { onEvent(message); return; }
    const entry = pending.get(message.id);
    if (!entry) return;
    clearTimeout(entry.timer);
    pending.delete(message.id);
    if (entry.response) { entry.response(message); return; }
    if (message.error) {
      entry.reject(Object.assign(new Error(message.error.message), message.error));
    } else entry.resolve(message.result);
  });
  socket.on("error", () => {});
  socket.on("close", () => {
    for (const entry of pending.values()) { clearTimeout(entry.timer); entry.reject(closedTarget()); }
    pending.clear();
    onClose();
  });
  try {
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("Browser identity connection timed out")), 5_000);
      socket.once("open", () => { clearTimeout(timer); resolve(); });
      socket.once("error", () => { clearTimeout(timer); reject(new Error("Browser identity connection failed")); });
      socket.once("close", () => { clearTimeout(timer); reject(new Error("Browser identity connection closed")); });
    });
  } catch (error) { socket.terminate(); throw error; }
  return {
    socket,
    onEvent(callback) { onEvent = callback; },
    onClose(callback) { onClose = callback; },
    request(method, params = {}, sessionId, timeout = 30_000, onSuccess) {
      if (socket.readyState !== WebSocket.OPEN) return Promise.reject(closedTarget());
      if (socket.bufferedAmount > 64 * 1024 * 1024) return Promise.reject(new Error("Browser identity transport is backlogged"));
      if (pending.size >= 4096) return Promise.reject(new Error("Browser identity command queue is full"));
      return new Promise((resolve, reject) => {
        const id = ++nextId;
        const timer = timeout ? setTimeout(() => {
          pending.delete(id);
          reject(new Error("Browser identity command timed out"));
        }, timeout) : null;
        pending.set(id, { resolve: (result) => { onSuccess?.(); resolve(result); }, reject, timer });
        socket.send(JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) }), (error) => {
          if (!error) return;
          clearTimeout(timer); pending.delete(id); reject(error);
        });
      });
    },
    forward(message, response) {
      if (socket.readyState !== WebSocket.OPEN || pending.size >= 4096
          || socket.bufferedAmount > 64 * 1024 * 1024) return false;
      const id = ++nextId;
      const reject = (error) => response({ id, error: {
        code: Number.isSafeInteger(error.code) ? error.code : -32000, message: error.message,
      }, ...(message.sessionId ? { sessionId: message.sessionId } : {}) });
      // Replies must be forwarded synchronously with subsequent protocol
      // events. A Promise.then here changes their native arrival order.
      pending.set(id, { response, reject, timer: null });
      socket.send(JSON.stringify({ ...message, id }), (error) => {
        if (error) { pending.delete(id); reject(error); }
      });
      return true;
    },
    close() { socket.terminate(); },
  };
}

export function normalizeNativeIdentity(observed, expectedVersion) {
  const metadata = observed?.metadata;
  const brands = (value) => Array.isArray(value) && value.length > 0 && value.length <= 16
    && value.every((entry) => typeof entry.brand === "string" && typeof entry.version === "string");
  if (typeof observed?.userAgent !== "string" || !brands(metadata?.brands)
      || !brands(metadata?.fullVersionList) || metadata.uaFullVersion !== expectedVersion
      || !Array.isArray(metadata.formFactors) || metadata.formFactors.length === 0
      || !["platform", "platformVersion", "architecture", "bitness", "model"].every((field) => typeof metadata[field] === "string")
      || typeof metadata.mobile !== "boolean" || typeof metadata.wow64 !== "boolean") {
    throw new Error("Selected Chromium does not expose the complete native identity required by headless compatibility");
  }
  return {
    userAgent: observed.userAgent.replace("HeadlessChrome/", "Chrome/"),
    userAgentMetadata: {
      brands: metadata.brands, fullVersionList: metadata.fullVersionList,
      fullVersion: metadata.uaFullVersion, formFactors: metadata.formFactors,
      platform: metadata.platform, platformVersion: metadata.platformVersion,
      architecture: metadata.architecture, bitness: metadata.bitness,
      model: metadata.model, mobile: metadata.mobile, wow64: metadata.wow64,
    },
  };
}

// Only a fresh, owned probe profile visits this local browser page. No page
// content, credentials or network traffic are read; all values are native APIs.
export async function inspectNativeIdentity(endpoint, expectedVersion) {
  const channel = await connect(endpoint);
  try {
    const { targetId } = await channel.request("Target.createTarget", { url: "chrome://version" });
    const { sessionId } = await channel.request("Target.attachToTarget", { targetId, flatten: true });
    let observed;
    const deadline = Date.now() + 5_000;
    do {
      observed = await channel.request("Runtime.evaluate", {
      expression: `(async () => location.href === "chrome://version/" && navigator.userAgentData ? ({ userAgent: navigator.userAgent,
        metadata: navigator.userAgentData ? await navigator.userAgentData.getHighEntropyValues([
          "architecture", "bitness", "fullVersionList", "model", "platformVersion",
          "uaFullVersion", "wow64", "formFactors"
        ]) : null }) : null)()`,
      returnByValue: true, awaitPromise: true,
      }, sessionId, 5_000);
      if (observed.result?.value) break;
      await new Promise((resolve) => setTimeout(resolve, 25));
    } while (Date.now() < deadline);
    if (observed.exceptionDetails) throw new Error("Could not inspect the selected Chromium's native identity");
    return normalizeNativeIdentity(observed.result.value, expectedVersion);
  } finally {
    await channel.request("Browser.close", {}, undefined, 1_000).catch(() => {});
    channel.close();
  }
}

// Playwright's own paused sessions are initialized before it can resume them.
// This is a control transport only: network events pass through unchanged and
// HuntProxy remains the sole traffic interceptor/capture implementation.
export async function createIdentityRelay(endpoint, identity, onFailure) {
  const { WebSocket, WebSocketServer } = websocketRuntime();
  const channel = await connect(endpoint);
  const targets = new Map();
  const shared = new Map();
  const owned = new Set();
  const gated = new Map();
  const detachWaiters = new Map();
  const delivery = [];
  let bufferedBytes = 0;
  let client;
  let closing = false;
  let failure;
  let failureCleanup = Promise.resolve();
  let cleanupError;
  const fail = () => {
    if (closing || failure) return;
    failure = new Error("Headless compatibility lost a target's identity; stop and restart this browser session");
    // Begin terminating the owned Chrome before detaching any paused target.
    try { failureCleanup = Promise.resolve(onFailure()).catch((error) => { cleanupError = error; }); }
    catch (error) { cleanupError = error; }
    client?.terminate(); channel.close();
  };
  const forward = (message) => {
    if (client?.readyState === WebSocket.OPEN) {
      if (client.bufferedAmount > 64 * 1024 * 1024) { fail(); return; }
      client.send(JSON.stringify(message));
    }
  };
  const waitForDetach = (sessionId) => new Promise((resolve) => {
    if (!targets.has(sessionId)) { resolve(); return; }
    const finish = () => { clearTimeout(timer); detachWaiters.delete(sessionId); resolve(); };
    const timer = setTimeout(finish, 500);
    detachWaiters.set(sessionId, finish);
  });
  const apply = (sessionId) => channel.request("Emulation.setUserAgentOverride", identity, sessionId, 30_000, () => {
    const target = targets.get(sessionId);
    if (target) target.ready = true;
  })
    .catch(async (error) => {
      // A failed worker script clears pending renderer commands before Chrome
      // announces its destruction. Only confirmed target removal makes this
      // exact closure error harmless; a live or unsupported target still fails.
      if (error.code === -32000 && error.message === "Inspected target navigated or closed") {
        await waitForDetach(sessionId);
      }
      if (targets.has(sessionId)) throw error;
    });
  const flush = () => {
    while (delivery[0]?.ready) {
      const entry = delivery.shift();
      bufferedBytes -= entry.bytes;
      forward(entry.message);
    }
  };
  const enqueue = (message, ready = true) => {
    const entry = { message, ready, bytes: 0 };
    if (ready && delivery.length === 0) { forward(message); return entry; }
    entry.bytes = Buffer.byteLength(JSON.stringify(message));
    if (bufferedBytes + entry.bytes > 16 * 1024 * 1024) { fail(); return entry; }
    bufferedBytes += entry.bytes;
    delivery.push(entry);
    flush();
    return entry;
  };
  const release = (sessionId) => {
    const entry = gated.get(sessionId);
    if (!entry) return;
    gated.delete(sessionId);
    entry.ready = true;
    flush();
  };
  const attach = async (message) => {
    const { sessionId, targetInfo } = message.params;
    const type = targetInfo.type;
    const retained = shared.get(targetInfo.targetId);
    const hasOwner = [...targets.values()].some((target) => target.targetId === targetInfo.targetId && target.ready);
    targets.set(sessionId, { type, targetId: targetInfo.targetId });
    if (retained && retained.original !== sessionId) { owned.add(sessionId); return; }
    if (!targetTypes.has(type)) { enqueue(message); return; }
    if ((type === "page" || type === "iframe") && message.params.waitingForDebugger === false && hasOwner) {
      // A secondary observer attaches to an already-qualified page. Its
      // renderer ACK can depend on initialization commands from Playwright;
      // let those flow while retaining the confirmed primary identity owner.
      // Still apply and verify this session's identity before any owner transfer.
      void apply(sessionId).catch(fail);
      enqueue(message);
      return;
    }
    gated.set(sessionId, enqueue(message, false));
    if (type === "shared_worker") {
      shared.set(targetInfo.targetId, { original: sessionId });
      const extra = await channel.request("Target.attachToTarget", { targetId: targetInfo.targetId, flatten: true });
      owned.add(extra.sessionId);
      targets.set(extra.sessionId, { type, targetId: targetInfo.targetId });
      // Keep an identity owner after PW detaches its unsupported shared target.
      void apply(extra.sessionId).catch(fail);
      void apply(sessionId).catch(fail);
    } else if (type === "service_worker") {
      // No renderer exists until Chrome releases the initial script fetch.
      // Queue metadata first on this same session; never await it before resume.
      void apply(sessionId).catch(fail);
    } else await apply(sessionId);
    release(sessionId);
  };
  const detach = (message) => {
    const sessionId = message.params.sessionId;
    const target = targets.get(sessionId);
    targets.delete(sessionId);
    detachWaiters.get(sessionId)?.();
    release(sessionId);
    if (owned.delete(sessionId)) {
      if (target) shared.delete(target.targetId);
      return;
    }
    enqueue(message);
  };
  const dispatch = (message) => {
    if (message.method === "Target.detachedFromTarget") { detach(message); return; }
    if (message.method === "Target.attachedToTarget") {
      void attach(message).catch(() => {
        if (targets.has(message.params.sessionId)) fail();
        else { shared.delete(message.params.targetInfo.targetId); release(message.params.sessionId); }
      });
      return;
    }
    if (message.sessionId && owned.has(message.sessionId)) return;
    enqueue(message);
  };
  channel.onEvent(dispatch);
  channel.onClose(fail);
  const httpServer = http.createServer((_request, response) => {
    response.writeHead(404); response.end();
  });
  const httpConnections = new Set();
  httpServer.on("connection", (socket) => {
    httpConnections.add(socket);
    socket.once("close", () => httpConnections.delete(socket));
  });
  httpServer.maxConnections = 16;
  httpServer.headersTimeout = 5_000;
  httpServer.requestTimeout = 5_000;
  const server = new WebSocketServer({
    server: httpServer, path: `/${randomUUID()}`, perMessageDeflate: false,
    // A website may not acquire a control connection, even if it learns a URL.
    verifyClient: (info) => info.req.headers.origin == null,
  });
  try {
    await new Promise((resolve, reject) => {
      httpServer.once("error", reject);
      httpServer.listen(0, "127.0.0.1", resolve);
    });
    if (failure) throw failure;
  } catch (error) {
    closing = true; channel.close(); server.close();
    httpServer.close();
    for (const socket of httpConnections) socket.destroy();
    throw error;
  }
  server.on("connection", (socket) => {
    if (client) {
      socket.on("error", () => socket.terminate());
      socket.close(1008);
      return;
    }
    client = socket;
    socket.on("message", (data) => {
      let message;
      try { message = JSON.parse(data.toString()); } catch { fail(); return; }
      if (!message || !Number.isSafeInteger(message.id) || typeof message.method !== "string") { fail(); return; }
      const command = message.method === "Emulation.setUserAgentOverride"
        ? { ...message, params: { ...message.params, ...identity } } : message;
      if (!channel.forward(command, (reply) => enqueue({ ...reply, id: message.id }))) fail();
    });
    socket.on("error", fail);
    socket.on("close", fail);
  });
  return {
    endpoint: `ws://127.0.0.1:${httpServer.address().port}${server.options.path}`,
    assertHealthy() { if (failure) throw failure; },
    get cleanupError() { return cleanupError; },
    beginClose() { closing = true; },
    async close() {
      closing = true;
      for (const socket of server.clients) socket.terminate();
      channel.close();
      gated.clear(); delivery.length = 0; bufferedBytes = 0;
      targets.clear(); shared.clear(); owned.clear();
      for (const finish of detachWaiters.values()) finish();
      // An unfinished HTTP handshake must not retain an owned profile during
      // shutdown. Upgraded WebSockets are terminated separately above.
      const httpClosed = new Promise((resolve) => httpServer.close(resolve));
      for (const socket of httpConnections) socket.destroy();
      await Promise.all([failureCleanup, new Promise((resolve) => server.close(resolve)), httpClosed]);
    },
  };
}
