#!/usr/bin/env node
/**
 * HuntProxy browser worker — versioned NDJSON JSON-RPC over stdio.
 *
 * Stdout is protocol-only. Stderr contains scrubbed lifecycle metadata and
 * never request data, DOM content, cookies, credentials, or storage values.
 */
import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";

const PROTOCOL = 1;
const sessions = new Map();
const MAX_SESSION_EVENTS = 256;
const MAX_SESSION_EVENT_BYTES = 256 * 1024;
const MAX_SCREENSHOT_PIXELS = 16 * 1024 * 1024;
const MAX_SCREENSHOT_BYTES = 8 * 1024 * 1024;

function javascriptFile(response, fallbackPageUrl) {
  let parsed;
  try {
    parsed = new URL(response.url());
  } catch {
    return null;
  }
  if (!new Set(["http:", "https:"]).has(parsed.protocol)) return null;
  const headers = response.headers();
  const mime = String(headers["content-type"] || "");
  const pathname = parsed.pathname.toLowerCase();
  const isJavascriptPath = /\.(?:js|mjs|cjs)$/.test(pathname);
  const isJavascriptMime = /(?:java|ecma)script/i.test(mime);
  if (!isJavascriptPath && !isJavascriptMime) return null;
  let sourcePageUrl = fallbackPageUrl || null;
  try {
    const frameUrl = response.request().frame()?.url();
    if (frameUrl && frameUrl !== "about:blank") sourcePageUrl = frameUrl;
  } catch {
    // Some browser backends do not expose the initiating frame for every response.
  }
  return {
    url: parsed.toString(),
    path: parsed.pathname,
    host: parsed.hostname,
    mime: mime || null,
    status_code: response.status(),
    source_page_url: sourcePageUrl,
  };
}

function trackJavascriptFiles(session, page) {
  page.on("response", (response) => {
    const file = javascriptFile(response, page.url());
    if (file) session.javascriptFiles.set(file.url, file);
  });
}

function publicLocation(value) {
  try {
    const url = new URL(value);
    if (!new Set(["http:", "https:", "about:"]).has(url.protocol)) return null;
    url.username = "";
    url.password = "";
    url.search = "";
    url.hash = "";
    return url.toString().slice(0, 512);
  } catch {
    return null;
  }
}

function recordSessionEvent(session, kind, details = {}, page = null) {
  if (!session.events) return;
  const pageId = page ? session.pageIds?.get(page) ?? null : null;
  const event = {
    sequence: ++session.eventSequence,
    runtime_generation: session.runtimeGeneration,
    kind,
    page_id: pageId,
    observed_at: new Date().toISOString(),
    ...details,
  };
  const bytes = Buffer.byteLength(JSON.stringify(event));
  if (bytes > MAX_SESSION_EVENT_BYTES) return;
  session.events.push({ event, bytes });
  session.eventBytes += bytes;
  while (session.events.length > MAX_SESSION_EVENTS
      || session.eventBytes > MAX_SESSION_EVENT_BYTES) {
    const removed = session.events.shift();
    session.eventBytes -= removed?.bytes || 0;
    session.eventsDropped += 1;
  }
}

function pageIdFor(session, page) {
  const existing = session.pageIds.get(page);
  if (existing) return existing;
  const pageId = session.nextPageId++;
  session.pageIds.set(page, pageId);
  session.pages.set(pageId, page);
  return pageId;
}

function trackRuntimeErrors(session, page) {
  const record = (event) => {
    session.runtimeErrorCount += 1;
    session.runtimeErrors.push(event);
    if (session.runtimeErrors.length > 32) session.runtimeErrors.shift();
  };
  // Console/error text can contain application credentials. Retain only
  // diagnostic type and source location, never message or stack contents.
  page.on("console", (message) => {
    if (!new Set(["error", "warning"]).has(message.type())) return;
    const location = message.location();
    const event = { kind: "console", level: message.type(), url: publicLocation(location.url),
      line: location.lineNumber, column: location.columnNumber };
    record(event);
    recordSessionEvent(session, "console", {
      level: event.level, url: event.url, line: event.line, column: event.column,
    }, page);
  });
  page.on("pageerror", () => {
    record({ kind: "page_error" });
    recordSessionEvent(session, "page_error", {}, page);
  });
}

function trackPage(session, page, initial = false) {
  if (session.trackedPages.has(page)) return pageIdFor(session, page);
  session.trackedPages.add(page);
  const pageId = pageIdFor(session, page);
  trackJavascriptFiles(session, page);
  trackRuntimeErrors(session, page);
  page.on("framenavigated", (frame) => {
    if (frame !== page.mainFrame()) return;
    recordSessionEvent(session, "navigation", { url: publicLocation(frame.url()) }, page);
  });
  page.on("dialog", (dialog) => {
    recordSessionEvent(session, "dialog", {
      dialog_type: dialog.type(),
      message_length: Buffer.byteLength(dialog.message() || ""),
      default_value_length: Buffer.byteLength(dialog.defaultValue() || ""),
      disposition: "dismissed",
    }, page);
    void dialog.dismiss().catch(() => undefined);
  });
  page.on("request", (request) => recordSessionEvent(session, "request", {
    method: request.method(),
    url: publicLocation(request.url()),
    resource_type: request.resourceType(),
    navigation: request.isNavigationRequest(),
  }, page));
  page.on("response", (response) => recordSessionEvent(session, "response", {
    status: response.status(),
    url: publicLocation(response.url()),
    resource_type: response.request().resourceType(),
    navigation: response.request().isNavigationRequest(),
  }, page));
  page.on("requestfailed", (request) => recordSessionEvent(session, "request_failed", {
    method: request.method(),
    url: publicLocation(request.url()),
    resource_type: request.resourceType(),
    navigation: request.isNavigationRequest(),
  }, page));
  page.on("close", () => {
    recordSessionEvent(session, "page", { action: "closed" }, page);
    session.pages.delete(pageId);
    if (session.page === page) {
      session.page = [...session.pages.values()].find((candidate) => !candidate.isClosed()) || null;
    }
  });
  if (!initial) {
    void page.opener().then((opener) => {
      recordSessionEvent(session, opener ? "popup" : "page", {
        action: "opened",
        opener_page_id: opener ? pageIdFor(session, opener) : null,
        url: publicLocation(page.url()),
      }, page);
    }).catch(() => recordSessionEvent(session, "page", {
      action: "opened", url: publicLocation(page.url()),
    }, page));
  }
  return pageId;
}

function installWindowMessageObserver(observerKey) {
  if (Object.hasOwn(window, observerKey)) return;
  const messages = [];
  const append = Array.prototype.push.bind(messages);
  const drain = Array.prototype.splice.bind(messages, 0, 128);
  const discardFirst = Array.prototype.shift.bind(messages);
  Object.defineProperty(window, observerKey, {
    value: drain,
    enumerable: false,
    configurable: false,
    writable: false,
  });
  window.addEventListener("message", (event) => {
    let dataType = event.data === null ? "null" : typeof event.data;
    let dataSize = null;
    if (typeof event.data === "string") {
      dataSize = new TextEncoder().encode(event.data).byteLength;
    } else if (event.data instanceof ArrayBuffer) {
      dataType = "array_buffer";
      dataSize = event.data.byteLength;
    } else if (ArrayBuffer.isView(event.data)) {
      dataType = "typed_array";
      dataSize = event.data.byteLength;
    } else if (Array.isArray(event.data)) {
      dataType = "array";
      dataSize = event.data.length;
    }
    append(Object.freeze({
      origin: String(event.origin || "").slice(0, 512),
      source_relation: event.source === window ? "same_window" : event.source ? "other_window" : "none",
      data_type: dataType,
      data_size: Number.isSafeInteger(dataSize) && dataSize >= 0 ? dataSize : null,
    }));
    if (messages.length > 128) discardFirst();
  });
}

async function drainWindowMessages(session) {
  for (const page of [...session.pages.values()]) {
    if (page.isClosed()) continue;
    const messages = await page.evaluate((observerKey) => {
      const drain = window[observerKey];
      return typeof drain === "function" ? drain() : [];
    }, session.messageObserverKey).catch(() => []);
    if (!Array.isArray(messages)) continue;
    for (const message of messages.slice(0, 128)) {
      if (!message || typeof message !== "object") continue;
      recordSessionEvent(session, "window_message", {
        origin: publicLocation(message.origin),
        source_relation: ["same_window", "other_window", "none"].includes(message.source_relation)
          ? message.source_relation : "none",
        data_type: String(message.data_type || "unknown").slice(0, 32),
        data_size: Number.isSafeInteger(message.data_size) && message.data_size >= 0
          ? message.data_size : null,
      }, page);
    }
  }
}

async function initializeSessionTracking(session, existingJavascriptFiles = new Map(), generation = 1) {
  session.javascriptFiles = existingJavascriptFiles;
  session.runtimeErrors = [];
  session.runtimeErrorCount = 0;
  session.runtimeGeneration = generation;
  session.nextPageId = 1;
  session.pages = new Map();
  session.pageIds = new WeakMap();
  session.trackedPages = new WeakSet();
  session.events = [];
  session.eventSequence = 0;
  session.eventBytes = 0;
  session.eventsDropped = 0;
  session.messageObserverKey = `__huntproxy_messages_${generation}_${Date.now()}__`;
  session.context.on("page", (page) => trackPage(session, page, false));
  for (const page of session.context.pages()) trackPage(session, page, true);
  await session.context.addInitScript(installWindowMessageObserver, session.messageObserverKey);
  for (const page of session.context.pages()) {
    await page.evaluate(installWindowMessageObserver, session.messageObserverKey).catch(() => undefined);
  }
}

async function activePage(session) {
  if (session.page && !session.page.isClosed() && session.context.pages().includes(session.page)) {
    trackPage(session, session.page, true);
    return session.page;
  }
  session.page = [...session.pages.values()].find((page) => !page.isClosed()) || null;
  if (!session.page) {
    session.page = await session.context.newPage();
    trackPage(session, session.page, false);
  }
  return session.page;
}

async function browserActionContext(sessionId, session) {
  const page = await activePage(session);
  return {
    session_id: sessionId,
    profile: session.profile || null,
    runtime_generation: session.runtimeGeneration,
    page_id: pageIdFor(session, page),
  };
}

async function uploadFiles(session, action) {
  const files = action.files;
  const timeout = action.timeout_ms ?? 10_000;
  if (!Array.isArray(files) || files.length > 16 || (action.via_chooser && !files.length)
      || !Number.isInteger(timeout) || timeout < 1 || timeout > 30_000) {
    throw rpcError(-32602, "upload requires at most 16 paths and timeout_ms in 1..30000; chooser requires files");
  }
  let totalBytes = 0;
  for (const file of files) {
    if (typeof file !== "string" || !path.isAbsolute(file) || Buffer.byteLength(file) > 4096 || file.includes("\0")) {
      throw rpcError(-32602, "upload files must be absolute paths of at most 4096 bytes");
    }
    try {
      const stat = fs.statSync(file);
      if (!stat.isFile()) throw new Error("not a regular file");
      fs.accessSync(file, fs.constants.R_OK);
      totalBytes += stat.size;
    } catch {
      throw rpcError(-32602, "upload file is missing, unreadable, or not a regular file");
    }
  }
  const locator = locatorFor(session.page, action.locator);
  if (!action.via_chooser) {
    await locator.setInputFiles(files, { timeout });
  } else {
    let chooser;
    let timer;
    let click;
    let onChooser;
    const started = Date.now();
    const waiting = new Promise((resolve, reject) => {
      onChooser = (event) => { chooser = event; resolve(event); };
      session.page.once("filechooser", onChooser);
      timer = setTimeout(() => reject(rpcError(-32000, "upload file chooser timed out")), timeout);
    });
    try {
      click = locator.click({ timeout });
      const [event] = await Promise.all([waiting, click]);
      clearTimeout(timer);
      const remaining = timeout - (Date.now() - started);
      if (remaining <= 0) throw rpcError(-32000, "upload file chooser timed out");
      await event.setFiles(files, { timeout: remaining });
    } finally {
      clearTimeout(timer);
      session.page.off("filechooser", onChooser);
      // Finish the bounded click before acknowledging failure; a pending click
      // must not open a chooser after the next action takes ownership.
      if (click) await Promise.allSettled([click]);
      if (chooser) {
        // Removing the final listener disables Playwright's intercepted chooser.
        // No native dialog was opened. Do not clear an earlier file selection
        // merely because this attempted replacement failed.
        await chooser.element().dispose().catch(() => undefined);
      }
    }
  }
  return { message: files.length ? "files selected" : "file selection cleared",
    data: { file_count: files.length, files: files.map((file) => path.basename(file)),
      total_bytes: totalBytes, via_chooser: Boolean(action.via_chooser) } };
}

async function inspectRuntime(session, action) {
  const maxBytes = action.max_bytes ?? 4096;
  if (!Number.isInteger(maxBytes) || maxBytes < 1 || maxBytes > 65_536) {
    throw rpcError(-32602, "inspect max_bytes must be 1..65536");
  }
  // The expression is fixed by HuntProxy. Callers cannot execute page code,
  // dispatch requests, or inspect cookies, storage, input values, or globals.
  const connection = await session.context.newCDPSession(session.page);
  let result;
  try {
    const observed = await connection.send("Runtime.evaluate", {
      expression: `(() => ({
        ready_state: document.readyState,
        visibility_state: document.visibilityState,
        resources: performance.getEntriesByType("resource").slice(-20).map((entry) => ({
          url: entry.name, initiator_type: entry.initiatorType,
          duration_ms: Math.round(entry.duration), transfer_size: entry.transferSize,
        })),
      }))()`,
      returnByValue: true, awaitPromise: false, timeout: 1000, disableBreaks: true,
    });
    if (observed.exceptionDetails || !observed.result.value) {
      throw rpcError(-32000, "runtime inspection could not read page metadata");
    }
    result = observed.result.value;
  } finally {
    await connection.detach().catch(() => undefined);
  }
  result.url = publicLocation(session.page.url());
  result.resources = result.resources.map((entry) => ({ ...entry, url: publicLocation(entry.url) }));
  result.runtime_error_count = session.runtimeErrorCount || 0;
  result.recent_errors = (session.runtimeErrors || []).slice(-16);
  if (action.locator) {
    const locator = locatorFor(session.page, action.locator);
    const element = await locator.elementHandle({ timeout: 10_000 });
    const elementConnection = await session.context.newCDPSession(session.page);
    let termination;
    const timer = setTimeout(() => {
      termination = elementConnection.send("Runtime.terminateExecution").catch(() => undefined);
    }, 1000);
    try {
      result.element = await element.evaluate((element) => ({
        tag: element.tagName.toLowerCase(), role: element.getAttribute("role"),
        type: element.getAttribute("type"), disabled: Boolean(element.disabled),
        read_only: Boolean(element.readOnly), checked: typeof element.checked === "boolean" ? element.checked : null,
        file_count: element.files?.length ?? null,
      }));
    } finally {
      clearTimeout(timer);
      if (termination) await termination;
      await element.dispose().catch(() => undefined);
      await elementConnection.detach().catch(() => undefined);
    }
    result.element.visible = await locator.isVisible();
    result.element.enabled = await locator.isEnabled({ timeout: 10_000 });
  }
  const bytes = Buffer.from(JSON.stringify(result), "utf8");
  const content = new TextDecoder().decode(bytes.subarray(0, maxBytes), { stream: bytes.length > maxBytes });
  return { message: "runtime inspected", data: { format: "runtime", content,
    truncated: bytes.length > maxBytes, total_bytes: bytes.length } };
}

function loadPlaywright() {
  const candidates = [];
  if (process.env.HUNTPROXY_PLAYWRIGHT_CORE_PATH || process.env.BB_PLAYWRIGHT_CORE_PATH) {
    candidates.push(process.env.HUNTPROXY_PLAYWRIGHT_CORE_PATH || process.env.BB_PLAYWRIGHT_CORE_PATH);
  }
  const workerDir = path.dirname(fileURLToPath(import.meta.url));
  candidates.push(
    path.join(workerDir, "node_modules", "playwright-core"),
    path.join(process.cwd(), "node_modules", "playwright-core"),
    "playwright-core",
  );

  const requireFromWorker = createRequire(path.join(workerDir, "package.json"));
  const requireFromCwd = createRequire(path.join(process.cwd(), "package.json"));
  let lastError;
  for (const candidate of candidates) {
    try {
      if (path.isAbsolute(candidate)) {
        const packagePath = fs.statSync(candidate).isDirectory()
          ? path.join(candidate, "index.js")
          : candidate;
        return requireFromWorker(packagePath);
      }
      try {
        return requireFromWorker(candidate);
      } catch {
        return requireFromCwd(candidate);
      }
    } catch (error) {
      lastError = error;
    }
  }
  throw new Error(`playwright-core unavailable: ${lastError?.message || "not found"}`);
}

const { chromium } = loadPlaywright();

function respond(id, result, error) {
  const message = error
    ? { jsonrpc: "2.0", id, error }
    : { jsonrpc: "2.0", id, result };
  process.stdout.write(`${JSON.stringify(message)}\n`);
}

function logMeta(event, fields = {}) {
  process.stderr.write(`${JSON.stringify({ event, ...fields })}\n`);
}

function rpcError(code, message) {
  return { code, message };
}

function existingChromiumExecutable() {
  const configured = [
    process.env.HUNTPROXY_CHROME_EXECUTABLE,
    process.env.BB_CHROME_EXECUTABLE,
    process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH,
  ].find(Boolean);
  if (configured) {
    if (!fs.existsSync(configured)) {
      throw rpcError(-32003, `configured Chromium executable does not exist: ${configured}`);
    }
    return configured;
  }
  try {
    const bundled = chromium.executablePath();
    if (bundled && fs.existsSync(bundled)) return bundled;
  } catch {
    // playwright-core commonly has no downloaded browser.
  }
  return undefined;
}

function chromiumProxy(proxy) {
  if (!proxy?.server) return undefined;
  return {
    server: proxy.server,
    username: proxy.username || undefined,
    password: proxy.password || undefined,
    bypass: "<-loopback>",
  };
}

function chromiumLaunchOptions(proxy, caCertPath, cdpPort = null, executablePath = null) {
  const args = [
    "--disable-quic",
    "--disk-cache-size=52428800",
    "--media-cache-size=10485760",
    "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
    "--webrtc-ip-handling-policy=disable_non_proxied_udp",
    "--proxy-bypass-list=<-loopback>",
  ];
  if (cdpPort != null) {
    args.push(
      "--remote-debugging-address=127.0.0.1",
      `--remote-debugging-port=${cdpPort}`,
      `--remote-allow-origins=http://127.0.0.1:${cdpPort},https://chrome-devtools-frontend.appspot.com`,
    );
  }
  return {
    executablePath,
    headless: true,
    proxy: chromiumProxy(proxy),
    ignoreHTTPSErrors: Boolean(caCertPath),
    serviceWorkers: "allow",
    args,
  };
}

async function launchChromium(proxy, caCertPath, profileDir = null, cdpPort = null) {
  const executablePath = existingChromiumExecutable();
  if (!executablePath) {
    throw rpcError(
      -32003,
      "managed Chromium executable not found; prepare the browser runtime or set HUNTPROXY_CHROME_EXECUTABLE",
    );
  }
  const options = chromiumLaunchOptions(proxy, caCertPath, cdpPort, executablePath);
  options.serviceWorkers = profileDir ? "allow" : "block";
  if (profileDir) {
    fs.mkdirSync(profileDir, { recursive: true, mode: 0o700 });
    try { fs.chmodSync(profileDir, 0o700); } catch {}
    const context = await chromium.launchPersistentContext(profileDir, options);
    const page = context.pages()[0] || await context.newPage();
    return {
      browser: null,
      context,
      page,
      persistent: true,
      profileDir,
    };
  }
  const { ignoreHTTPSErrors, serviceWorkers, ...launchOptions } = options;
  const browser = await chromium.launch(launchOptions);
  const context = await browser.newContext({
    serviceWorkers,
    ignoreHTTPSErrors,
  });
  const page = await context.newPage();
  return { browser, context, page, persistent: false, profileDir: null };
}

function validateCdpPort(value) {
  const port = Number(value);
  if (!Number.isSafeInteger(port) || port < 1024 || port > 65535) {
    throw rpcError(-32602, "cdp_port must be an integer between 1024 and 65535");
  }
  return port;
}

async function discoverCdp(page, port) {
  const cdp = await page.context().newCDPSession(page);
  const targetInfo = await cdp.send("Target.getTargetInfo");
  await cdp.detach();
  const deadline = Date.now() + 5_000;
  let lastError;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(`http://127.0.0.1:${port}/json/list`, {
        signal: AbortSignal.timeout(1_000),
      });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const targets = await response.json();
      const target = targets.find((candidate) => candidate.id === targetInfo.targetInfo.targetId);
      if (target?.webSocketDebuggerUrl) {
        const websocket = new URL(target.webSocketDebuggerUrl);
        let hostedDevtoolsUrl = String(target.devtoolsFrontendUrl || "");
        if (!hostedDevtoolsUrl.startsWith("https://chrome-devtools-frontend.appspot.com/")) {
          const versionResponse = await fetch(`http://127.0.0.1:${port}/json/version`, {
            signal: AbortSignal.timeout(1_000),
          });
          const version = await versionResponse.json();
          const revision = String(version["WebKit-Version"] || "").match(/\(@([^)]+)\)/)?.[1];
          if (!revision) throw new Error("Chromium omitted its DevTools revision");
          hostedDevtoolsUrl = `https://chrome-devtools-frontend.appspot.com/serve_rev/@${revision}/inspector.html?ws=${websocket.host}${websocket.pathname}`;
        }
        return {
          port,
          endpoint: `http://127.0.0.1:${port}`,
          devtools_url: `http://127.0.0.1:${port}/devtools/inspector.html?ws=${websocket.host}${websocket.pathname}`,
          hosted_devtools_url: hostedDevtoolsUrl,
        };
      }
      lastError = new Error("debug target was not published");
    } catch (error) {
      lastError = error;
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw rpcError(-32000, `Chromium CDP endpoint did not become ready: ${lastError?.message || "unknown error"}`);
}

function isSessionCookie(cookie) {
  return cookie?.expires == null || cookie.expires === -1;
}

function cookieIdentityKey(cookie) {
  return JSON.stringify([
    String(cookie?.name || ""),
    String(cookie?.domain || ""),
    String(cookie?.path || "/"),
    cookie?.partitionKey == null ? null : cookie.partitionKey,
  ]);
}

async function checkpointRuntimePages(session) {
  const active = await activePage(session);
  const pages = [];
  let activeIndex = 0;
  for (const page of session.context.pages()) {
    if (page.isClosed()) continue;
    const url = page.url() || "about:blank";
    let parsed;
    try {
      parsed = new URL(url);
    } catch {
      throw rpcError(-32000, "CDP handoff could not preserve an open tab URL");
    }
    if (!new Set(["http:", "https:", "about:"]).has(parsed.protocol)) {
      throw rpcError(-32000, `CDP handoff cannot preserve an open ${parsed.protocol} tab`);
    }
    let sessionStorage = {};
    if (new Set(["http:", "https:"]).has(parsed.protocol)) {
      try {
        sessionStorage = await page.evaluate(() => Object.fromEntries(
          Array.from({ length: window.sessionStorage.length }, (_, index) => {
            const key = window.sessionStorage.key(index);
            return [key, window.sessionStorage.getItem(key)];
          }),
        ));
      } catch {
        throw rpcError(-32000, "CDP handoff could not preserve session storage for every open tab");
      }
    }
    if (page === active) activeIndex = pages.length;
    pages.push({ url, session_storage: sessionStorage });
  }
  if (!pages.length) pages.push({ url: "about:blank", session_storage: {} });
  return { pages, active_index: activeIndex };
}

async function restoreRuntimePages(runtime, pageState) {
  const states = Array.isArray(pageState?.pages) && pageState.pages.length
    ? pageState.pages : [{ url: "about:blank", session_storage: {} }];
  const initialPages = runtime.context.pages();
  const first = initialPages[0] || await runtime.context.newPage();
  const pages = [];
  for (let index = 0; index < states.length; index += 1) {
    const state = states[index];
    const page = index === 0 ? first : await runtime.context.newPage();
    pages.push(page);
    if (state.url && state.url !== "about:blank") {
      await page.goto(state.url, { waitUntil: "domcontentloaded", timeout: 30_000 });
      await page.evaluate((values) => {
        sessionStorage.clear();
        for (const [key, value] of Object.entries(values || {})) {
          sessionStorage.setItem(key, value);
        }
      }, state.session_storage || {});
      // Let application startup observe the restored per-tab state just as it
      // did before the runtime handoff.
      await page.reload({ waitUntil: "domcontentloaded", timeout: 30_000 });
    }
  }
  for (const page of initialPages) {
    if (!pages.includes(page) && !page.isClosed()) {
      await page.close({ runBeforeUnload: false });
    }
  }
  const activeIndex = Number.isInteger(pageState?.active_index)
    && pageState.active_index >= 0 && pageState.active_index < pages.length
    ? pageState.active_index : 0;
  runtime.page = pages[activeIndex];
  await runtime.page.bringToFront();
}

async function launchSessionRuntime(session, cdpPort, pageState, sessionCookies = []) {
  const runtime = await launchChromium(
    session.proxy || null,
    session.caCertPath || null,
    session.profileDir || null,
    cdpPort,
  );
  try {
    if (sessionCookies.length) await runtime.context.addCookies(sessionCookies);
    await restoreRuntimePages(runtime, pageState);
    const cdp = cdpPort == null ? null : await discoverCdp(runtime.page, cdpPort);
    return { runtime, cdp };
  } catch (error) {
    await closeRuntime(runtime);
    throw error;
  }
}

async function relaunchSession(session, cdpPort) {
  if (!session.persistent || !session.profileDir) {
    throw rpcError(-32602, "CDP handoff requires a persistent project browser");
  }
  const pageState = await checkpointRuntimePages(session);
  const existingJavascriptFiles = new Map(session.javascriptFiles || []);
  const nextGeneration = Number(session.runtimeGeneration || 0) + 1;
  const sessionCookies = await session.context.cookies()
    .then((cookies) => cookies.filter(isSessionCookie));
  await closeRuntime(session);
  let launched;
  try {
    launched = await launchSessionRuntime(session, cdpPort, pageState, sessionCookies);
  } catch (error) {
    try {
      const restored = await launchSessionRuntime(session, null, pageState, sessionCookies);
      Object.assign(session, restored.runtime, { cdp: null });
      await initializeSessionTracking(session, existingJavascriptFiles, nextGeneration);
    } catch (restoreError) {
      throw rpcError(
        -32000,
        `CDP handoff failed and the normal browser could not be restored: ${restoreError?.message || restoreError}`,
      );
    }
    throw error;
  }
  Object.assign(session, launched.runtime, { cdp: launched.cdp });
  await initializeSessionTracking(session, existingJavascriptFiles, nextGeneration);
  return launched.cdp;
}

async function restoreProjectState(session, state) {
  if (!state || typeof state !== "object") return;
  // Initialized Chromium profiles keep native persistent state, but session
  // cookies need the portable checkpoint because Chromium drops them on exit.
  if (Array.isArray(state.cookies) && state.cookies.length) {
    let checkpointCookies = state.cookies
      .filter((cookie) => cookie && cookie.name && cookie.domain)
      .filter((cookie) => !session.preferProfileState
        || isSessionCookie(cookie));
    if (session.preferProfileState && checkpointCookies.length) {
      const nativeIdentities = new Set(
        (await session.context.cookies()).map(cookieIdentityKey),
      );
      checkpointCookies = checkpointCookies.filter(
        (cookie) => !nativeIdentities.has(cookieIdentityKey(cookie)),
      );
    }
    const cookies = checkpointCookies
      .map((cookie) => {
        const restored = {
          name: String(cookie.name),
          value: String(cookie.value || ""),
          domain: String(cookie.domain),
          path: String(cookie.path || "/"),
          httpOnly: Boolean(cookie.httpOnly),
          secure: Boolean(cookie.secure),
          sameSite: ["Strict", "Lax", "None"].includes(cookie.sameSite)
            ? cookie.sameSite
            : "Lax",
        };
        if (typeof cookie.expires === "number" && cookie.expires > 0) {
          restored.expires = cookie.expires;
        }
        if (cookie.partitionKey) {
          restored.partitionKey = cookie.partitionKey;
        }
        return restored;
      });
    if (cookies.length) await session.context.addCookies(cookies);
  }
  session.restoreState = session.preferProfileState
    ? { session_storage: state.session_storage || {} }
    : state;
  session.restoredOrigins = new Set();
}

async function reconcileCurrentOriginStorage(session) {
  if (!session.restoreState) return;
  for (let attempt = 0; attempt < 3; attempt += 1) {
    let origin;
    try {
      const parsed = new URL(session.page.url());
      if (!new Set(["http:", "https:"]).has(parsed.protocol)) return;
      origin = parsed.origin;
    } catch {
      return;
    }
    if (session.restoredOrigins?.has(origin)) return;
    const localByOrigin = session.restoreState.local_storage || {};
    const sessionByOrigin = session.restoreState.session_storage || {};
    const hasStoredOrigin = Object.hasOwn(localByOrigin, origin)
      || Object.hasOwn(sessionByOrigin, origin);
    if (!hasStoredOrigin) {
      session.restoredOrigins?.add(origin);
      return;
    }
    const restoreLocal = !session.preferProfileState;
    const localValues = localByOrigin[origin] || {};
    const sessionValues = sessionByOrigin[origin] || {};
    const changed = await session.page.evaluate(
      ({ local, currentSession, restoreLocal }) => {
        let changed = false;
        if (restoreLocal) {
          localStorage.clear();
          sessionStorage.clear();
          for (const [key, value] of Object.entries(local)) localStorage.setItem(key, value);
          changed = true;
        }
        for (const [key, value] of Object.entries(currentSession)) {
          if (restoreLocal || sessionStorage.getItem(key) === null) {
            sessionStorage.setItem(key, value);
            changed = true;
          }
        }
        return changed;
      },
      { local: localValues, currentSession: sessionValues, restoreLocal },
    );
    session.restoredOrigins?.add(origin);
    if (changed) await session.page.reload({ waitUntil: "domcontentloaded", timeout: 30_000 });
  }
}

async function extractCheckpoint(session) {
  const page = await activePage(session);
  const url = page.url();
  const title = await page.title().catch(() => "");
  const origin = (() => {
    try {
      const parsed = new URL(url);
      return new Set(["http:", "https:"]).has(parsed.protocol) ? parsed.origin : null;
    } catch {
      return null;
    }
  })();
  const cookies = await session.context.cookies();
  const storage = await page
    .evaluate(() => {
      const collect = (source) => {
        const output = {};
        for (let index = 0; index < source.length; index += 1) {
          const key = source.key(index);
          output[key] = source.getItem(key);
        }
        return output;
      };
      return {
        local_storage: collect(localStorage),
        session_storage: collect(sessionStorage),
      };
    })
    .catch(() => ({ local_storage: {}, session_storage: {} }));
  const privateState = {
    cookies,
    origin,
    local_storage: storage.local_storage || {},
    session_storage: storage.session_storage || {},
  };
  const stateHash = createHash("sha256")
    .update(JSON.stringify(privateState))
    .digest("hex");
  return {
    url,
    title: title ? title.slice(0, 1024) : null,
    origin,
    cookie_count: cookies.length,
    local_keys: Object.keys(privateState.local_storage).length,
    session_keys: Object.keys(privateState.session_storage).length,
    state_hash: stateHash,
    _private: privateState,
  };
}

function locatorFor(page, descriptor = {}) {
  const exact = Boolean(descriptor.exact);
  if (descriptor.role) {
    const options = { exact };
    if (descriptor.name != null) options.name = descriptor.name;
    return page.getByRole(descriptor.role, options);
  }
  if (descriptor.test_id) return page.getByTestId(descriptor.test_id);
  if (descriptor.text != null) return page.getByText(descriptor.text, { exact });
  if (descriptor.css) return page.locator(descriptor.css);
  throw rpcError(-32602, "locator requires role, test_id, text, or css");
}

async function performWait(page, forWhat, value) {
  switch (forWhat) {
    case "timeout": {
      const milliseconds = Number(value);
      if (!Number.isFinite(milliseconds) || milliseconds < 0 || milliseconds > 60_000) {
        throw rpcError(-32602, "wait timeout must be between 0 and 60000 milliseconds");
      }
      await page.waitForTimeout(milliseconds);
      return { waited_ms: milliseconds };
    }
    case "url":
      await page.waitForURL(value, { timeout: 30_000 });
      return { url: page.url() };
    case "selector":
      await page.locator(value).waitFor({ state: "visible", timeout: 30_000 });
      return { selector: value, state: "visible" };
    case "text":
      await page.getByText(value).first().waitFor({ state: "visible", timeout: 30_000 });
      return { text: value, state: "visible" };
    case "load_state":
      await page.waitForLoadState(value || "domcontentloaded", { timeout: 30_000 });
      return { load_state: value || "domcontentloaded" };
    default:
      throw rpcError(-32602, "wait for_what must be timeout|url|selector|text|load_state");
  }
}

async function pageSummaries(session) {
  const active = await activePage(session);
  const summaries = [];
  for (const [pageId, page] of session.pages.entries()) {
    if (page.isClosed()) continue;
    const title = await page.title().catch(() => "");
    summaries.push({
      page_id: pageId,
      active: page === active,
      url: publicLocation(page.url()),
      title: title ? title.slice(0, 256) : null,
    });
  }
  return summaries.sort((left, right) => left.page_id - right.page_id);
}

function requireRuntimeGeneration(session, value) {
  if (!Number.isSafeInteger(value) || value !== session.runtimeGeneration) {
    throw rpcError(-32001, "page or event cursor belongs to a stale browser runtime; list pages again");
  }
}

async function performPages(session, action) {
  const op = String(action.op || "");
  if (op === "list") {
    return { message: "browser pages listed", data: {
      runtime_generation: session.runtimeGeneration,
      pages: await pageSummaries(session),
    } };
  }
  if (op === "new") {
    const page = await session.context.newPage();
    trackPage(session, page, false);
    session.page = page;
    if (action.url && action.url !== "about:blank") {
      await page.goto(action.url, { waitUntil: "domcontentloaded", timeout: 30_000 });
      await reconcileCurrentOriginStorage(session);
    }
    return { message: "browser page opened", data: {
      runtime_generation: session.runtimeGeneration,
      page_id: pageIdFor(session, page),
      pages: await pageSummaries(session),
    } };
  }
  if (!new Set(["select", "close"]).has(op)) {
    throw rpcError(-32602, "pages op must be list|select|new|close");
  }
  requireRuntimeGeneration(session, Number(action.runtime_generation));
  const pageId = Number(action.page_id);
  if (!Number.isSafeInteger(pageId) || pageId <= 0) {
    throw rpcError(-32602, "page_id must be a positive integer");
  }
  const page = session.pages.get(pageId);
  if (!page || page.isClosed()) throw rpcError(-32001, "page is no longer active");
  if (op === "select") {
    session.page = page;
    await page.bringToFront();
    return { message: "browser page selected", data: {
      runtime_generation: session.runtimeGeneration,
      page_id: pageId,
      pages: await pageSummaries(session),
    } };
  }
  if (session.pages.size <= 1) {
    const replacement = await session.context.newPage();
    trackPage(session, replacement, false);
    session.page = replacement;
  } else if (session.page === page) {
    session.page = [...session.pages.values()].find((candidate) => candidate !== page && !candidate.isClosed()) || null;
  }
  await page.close({ runBeforeUnload: false });
  await activePage(session);
  return { message: "browser page closed", data: {
    runtime_generation: session.runtimeGeneration,
    closed_page_id: pageId,
    pages: await pageSummaries(session),
  } };
}

async function performEvents(session, action) {
  const generation = action.runtime_generation == null
    ? session.runtimeGeneration : Number(action.runtime_generation);
  requireRuntimeGeneration(session, generation);
  const after = Number(action.after_sequence || 0);
  const limit = Number(action.limit || 50);
  const waitMs = Number(action.wait_ms || 0);
  const kinds = new Set(Array.isArray(action.kinds) ? action.kinds : []);
  const matching = () => session.events
    .map((entry) => entry.event)
    .filter((event) => event.sequence > after && (!kinds.size || kinds.has(event.kind)))
    .slice(0, limit);
  const deadline = Date.now() + waitMs;
  let events;
  do {
    await drainWindowMessages(session);
    events = matching();
    if (events.length || Date.now() >= deadline) break;
    await new Promise((resolve) => setTimeout(resolve, Math.min(50, deadline - Date.now())));
  } while (Date.now() < deadline);
  const oldestSequence = session.events[0]?.event.sequence ?? session.eventSequence + 1;
  return { message: "browser events read", data: {
    runtime_generation: session.runtimeGeneration,
    events,
    next_sequence: events.length ? events[events.length - 1].sequence : after,
    latest_sequence: session.eventSequence,
    oldest_sequence: oldestSequence,
    cursor_expired: after > 0 && after < oldestSequence - 1,
    dropped_events: session.eventsDropped,
  } };
}

async function performScroll(session, action) {
  const page = await activePage(session);
  if (action.locator) {
    await locatorFor(page, action.locator).scrollIntoViewIfNeeded({ timeout: 30_000 });
  }
  const deltaX = Number(action.delta_x || 0);
  const deltaY = Number(action.delta_y || 0);
  if (deltaX || deltaY) await page.mouse.wheel(deltaX, deltaY);
  const position = await page.evaluate(() => ({ x: window.scrollX, y: window.scrollY }));
  return { message: "browser page scrolled", data: position };
}

async function performScreenshot(session, action) {
  const page = await activePage(session);
  let target = page;
  let dimensions;
  if (action.locator) {
    target = locatorFor(page, action.locator);
    await target.waitFor({ state: "visible", timeout: 30_000 });
    const box = await target.boundingBox();
    if (!box) throw rpcError(-32000, "screenshot element is not visible");
    dimensions = { width: Math.ceil(box.width), height: Math.ceil(box.height) };
  } else if (action.full_page) {
    dimensions = await page.evaluate(() => ({
      width: Math.max(document.documentElement.scrollWidth, document.body?.scrollWidth || 0),
      height: Math.max(document.documentElement.scrollHeight, document.body?.scrollHeight || 0),
    }));
  } else {
    dimensions = page.viewportSize() || await page.evaluate(() => ({
      width: window.innerWidth,
      height: window.innerHeight,
    }));
  }
  const width = Math.max(0, Math.ceil(Number(dimensions.width || 0)));
  const height = Math.max(0, Math.ceil(Number(dimensions.height || 0)));
  if (!width || !height || width > 16_384 || height > 16_384
      || width * height > MAX_SCREENSHOT_PIXELS) {
    throw rpcError(-32602, "screenshot dimensions exceed the 16-megapixel limit");
  }
  const buffer = action.locator
    ? await target.screenshot({ type: "png", scale: "css", timeout: 30_000 })
    : await page.screenshot({
      type: "png", scale: "css", fullPage: Boolean(action.full_page), timeout: 30_000,
    });
  const maxBytes = Number(action.max_bytes || 4 * 1024 * 1024);
  if (buffer.length > maxBytes || buffer.length > MAX_SCREENSHOT_BYTES) {
    throw rpcError(-32000, `screenshot is ${buffer.length} bytes and exceeds max_bytes`);
  }
  return { message: "browser screenshot captured", data: {
    mime_type: "image/png",
    width,
    height,
    byte_length: buffer.length,
    sha256: createHash("sha256").update(buffer).digest("hex"),
    image_base64: buffer.toString("base64"),
  } };
}

async function browserRequestInIsolatedWorld(request) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), request.timeout_ms);
    const started = performance.now();
    const decodeBase64 = (value) => {
      const binary = atob(value);
      const bytes = new Uint8Array(binary.length);
      for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
      return bytes;
    };
    const encodeBase64 = (bytes) => {
      let binary = "";
      for (let offset = 0; offset < bytes.length; offset += 0x8000) {
        binary += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000));
      }
      return btoa(binary);
    };
    try {
      const options = {
        method: request.method,
        headers: request.headers,
        credentials: "include",
        redirect: "error",
        signal: controller.signal,
      };
      if (request.body_text !== null) options.body = request.body_text;
      if (request.body_base64 !== null) options.body = decodeBase64(request.body_base64);
      const response = await fetch(request.url, options);
      const chunks = [];
      let kept = 0;
      let received = 0;
      let truncated = false;
      const reader = response.body?.getReader();
      while (reader) {
        const { done, value } = await reader.read();
        if (done) break;
        received += value?.byteLength || 0;
        const remaining = request.max_response_bytes - kept;
        if (remaining > 0 && value?.byteLength) {
          const part = value.subarray(0, remaining);
          chunks.push(part);
          kept += part.byteLength;
        }
        if (value?.byteLength > remaining) truncated = true;
      }
      truncated ||= received > kept;
      const body = new Uint8Array(kept);
      let cursor = 0;
      for (const chunk of chunks) {
        body.set(chunk, cursor);
        cursor += chunk.byteLength;
      }
      const sensitive = /(?:authorization|cookie|token|secret|api[-_]?key)/i;
      const responseHeaders = [];
      for (const [name, value] of response.headers.entries()) {
        if (responseHeaders.length >= 64) break;
        responseHeaders.push({
          name,
          value: sensitive.test(name) ? "[redacted]" : String(value).slice(0, 4096),
        });
      }
      return {
        method: request.method,
        requested_url: request.url,
        final_url: response.url,
        status: response.status,
        status_text: response.statusText,
        response_headers: responseHeaders,
        response_body_base64: encodeBase64(body),
        response_body_bytes: kept,
        received_body_bytes: received,
        response_truncated: truncated,
        duration_ms: Math.round(performance.now() - started),
      };
    } catch (error) {
      return {
        huntproxy_error: error?.name === "AbortError" ? "timeout" : "network",
      };
    } finally {
      clearTimeout(timer);
    }
}

async function performBrowserRequest(session, action) {
  const page = await activePage(session);
  let pageOrigin;
  let target;
  try {
    pageOrigin = new URL(page.url()).origin;
    target = new URL(String(action.url || ""));
  } catch {
    throw rpcError(-32602, "request requires an absolute HTTP(S) URL and an active HTTP(S) page");
  }
  if (!new Set(["http:", "https:"]).has(target.protocol)
      || !new Set(["http:", "https:"]).has(new URL(page.url()).protocol)
      || target.origin !== pageOrigin) {
    throw rpcError(-32602, "request URL must have the active page origin");
  }
  const method = String(action.method || "").toUpperCase();
  const headers = (Array.isArray(action.headers) ? action.headers : [])
    .map((header) => [String(header.name), String(header.value)]);
  headers.push(["x-huntproxy-browser-origin", pageOrigin]);
  const timeoutMs = Number(action.timeout_ms || 15_000);
  const maxResponseBytes = Number(action.max_response_bytes || 4096);
  const payload = {
    url: target.href,
    method,
    headers,
    body_text: action.body_text ?? null,
    body_base64: action.body_base64 ?? null,
    timeout_ms: timeoutMs,
    max_response_bytes: maxResponseBytes,
  };
  const connection = await session.context.newCDPSession(page);
  let result;
  try {
    await connection.send("Page.enable");
    // The isolated world keeps native web APIs even when target JavaScript has
    // replaced window.fetch. Browser CSP and service-worker behavior remain in
    // force so this action observes the same browser policies as the page.
    const frameTree = await connection.send("Page.getFrameTree");
    const world = await connection.send("Page.createIsolatedWorld", {
      frameId: frameTree.frameTree.frame.id,
      worldName: "huntproxy-request",
      grantUniveralAccess: false,
    });
    const evaluation = await connection.send("Runtime.callFunctionOn", {
      functionDeclaration: browserRequestInIsolatedWorld.toString(),
      executionContextId: world.executionContextId,
      arguments: [{ value: payload }],
      awaitPromise: true,
      returnByValue: true,
    });
    if (evaluation.exceptionDetails || !evaluation.result?.value) {
      throw rpcError(-32000, "browser request failed in its isolated page context");
    }
    result = evaluation.result.value;
  } finally {
    await connection.detach().catch(() => undefined);
  }
  if (result.huntproxy_error === "timeout") {
    throw rpcError(-32000, "browser request timed out; it was not retried");
  }
  if (result.huntproxy_error) {
    throw rpcError(-32000, "browser request failed; redirects are disabled and it was not retried");
  }
  return { message: "browser request completed", data: result };
}

async function executeAction(session, action = {}) {
  const page = await activePage(session);
  switch (action.type) {
    case "navigate": {
      await page.goto(action.url, {
        waitUntil: "domcontentloaded",
        timeout: action.timeout_ms || 30_000,
      });
      await reconcileCurrentOriginStorage(session);
      return { message: "navigation completed", data: { url: page.url() } };
    }
    case "snapshot": {
      let content;
      if (action.format === "dom") {
        content = await page.content();
      } else if (typeof page.locator("body").ariaSnapshot === "function") {
        content = await page.locator("body").ariaSnapshot();
      } else {
        content = await page.content();
      }
      const maxBytes = Math.max(0, Math.min(Number(action.max_bytes || 200_000), 2_000_000));
      const bytes = Buffer.from(String(content), "utf8");
      return {
        message: "snapshot captured",
        data: {
          format: action.format || "accessibility",
          content: bytes.subarray(0, maxBytes).toString("utf8"),
          truncated: bytes.length > maxBytes,
          total_bytes: bytes.length,
        },
      };
    }
    case "click":
      await locatorFor(page, action.locator).click({ timeout: 30_000 });
      return { message: "element clicked", data: { url: page.url() } };
    case "fill":
      await locatorFor(page, action.locator).fill(action.value ?? "", { timeout: 30_000 });
      return { message: "field filled", data: null };
    case "select":
      await locatorFor(page, action.locator).selectOption(action.value, { timeout: 30_000 });
      return { message: "option selected", data: null };
    case "upload":
      return uploadFiles(session, action);
    case "inspect":
      return inspectRuntime(session, action);
    case "pages":
      return performPages(session, action);
    case "events":
      return performEvents(session, action);
    case "scroll":
      return performScroll(session, action);
    case "screenshot":
      return performScreenshot(session, action);
    case "request":
      return performBrowserRequest(session, action);
    case "press":
      if (action.locator) {
        await locatorFor(page, action.locator).press(action.key, { timeout: 30_000 });
      } else {
        await page.keyboard.press(action.key);
      }
      return { message: "key pressed", data: null };
    case "wait":
      return {
        message: "wait completed",
        data: await performWait(page, action.for_what, action.value),
      };
    case "back":
      await page.goBack({ waitUntil: "domcontentloaded", timeout: 30_000 });
      await reconcileCurrentOriginStorage(session);
      return { message: "went back", data: { url: page.url() } };
    case "forward":
      await page.goForward({ waitUntil: "domcontentloaded", timeout: 30_000 });
      await reconcileCurrentOriginStorage(session);
      return { message: "went forward", data: { url: page.url() } };
    default:
      throw rpcError(-32602, `unsupported browser action: ${action.type || "missing"}`);
  }
}

async function clearCookieIdentities(context, cookies, fieldName) {
  if (!Array.isArray(cookies)) return;
  for (const cookie of cookies) {
    if (!cookie || typeof cookie.name !== "string" || typeof cookie.domain !== "string" || typeof cookie.path !== "string") {
      throw rpcError(-32602, `${fieldName} entries require name, domain, and path`);
    }
    await context.clearCookies({
      name: cookie.name,
      domain: cookie.domain,
      path: cookie.path,
    });
  }
}

function sessionIdentity(sessionId, session) {
  return {
    session_id: sessionId,
    requested_profile: session.profile,
    active_profile: session.profile,
    profile_dir: session.profileDir,
    persistent: session.persistent,
  };
}

async function handle(req) {
  const { id, method, params = {} } = req;
  try {
    switch (method) {
      case "hello":
        return respond(id, {
          protocol: PROTOCOL,
          engines: ["chromium"],
          capabilities: [
            "actions", "checkpoints", "cdp_handoff", "profile_isolation",
            "pages", "events", "scroll", "screenshots", "same_origin_requests",
          ],
        });
      case "session.start": {
        const sessionId = Number(params.session_id);
        if (!Number.isSafeInteger(sessionId) || sessionId <= 0) {
          throw rpcError(-32602, "session_id must be a positive integer");
        }
        if (sessions.has(sessionId)) throw rpcError(-32602, "session_id is already active");
        const engine = params.engine || "chromium";
        if (engine !== "chromium") {
          throw rpcError(-32602, "engine must be chromium");
        }
        const caCertPath = params.ca_cert_path || null;
        let profileDir = params.persistent
          ? params.profile_dir || null
          : null;
        const profile = params.persistent ? params.profile : null;
        if (params.persistent) {
          if (typeof profile !== "string" || !/^[A-Za-z0-9_-]{1,64}$/.test(profile)
              || typeof profileDir !== "string" || !path.isAbsolute(profileDir)) {
            throw rpcError(-32602, "persistent browser requires a named profile and absolute profile_dir");
          }
          fs.mkdirSync(profileDir, { recursive: true, mode: 0o700 });
          profileDir = fs.realpathSync(profileDir);
          if ([...sessions.values()].some((session) => session.profileDir === profileDir)) {
            throw rpcError(-32602, "profile_dir is already active in another session");
          }
        }
        const runtime = await launchChromium(params.proxy || null, caCertPath, profileDir);
        const session = {
          ...runtime,
          engine,
          proxy: params.proxy || null,
          caCertPath,
          persistent: Boolean(params.persistent),
          profileDir,
          profile,
          preferProfileState: Boolean(params.prefer_profile_state),
          cdp: null,
        };
        sessions.set(sessionId, session);
        try {
          await initializeSessionTracking(session);
          await restoreProjectState(session, params.restore_state);
          await clearCookieIdentities(session.context, params.clear_cookies, "clear_cookies");
          if (Array.isArray(params.cookies) && params.cookies.length) {
            await session.context.addCookies(params.cookies);
          }
          if (params.url && params.url !== "about:blank") {
            await session.page.goto(params.url, {
              waitUntil: "domcontentloaded",
              timeout: params.timeout_ms || 30_000,
            });
            await reconcileCurrentOriginStorage(session);
          }
          const checkpoint = await extractCheckpoint(session);
          logMeta("session.start", { session_id: sessionId, engine });
          return respond(id, { ...sessionIdentity(sessionId, session), engine, checkpoint });
        } catch (error) {
          await closeSession(sessionId);
          throw error;
        }
      }
      case "session.status": {
        const sessionId = Number(params.session_id);
        const session = sessions.get(sessionId);
        if (!session) {
          throw rpcError(-32001, "requested browser profile is not active");
        }
        await activePage(session);
        return respond(id, sessionIdentity(sessionId, session));
      }
      case "session.action": {
        const sessionId = Number(params.session_id);
        const session = sessions.get(sessionId);
        if (!session) throw rpcError(-32001, "session not found");
        const result = await executeAction(session, params.action || {});
        // Every successful action is checkpointed before acknowledgement.
        const checkpoint = await extractCheckpoint(session);
        logMeta("session.action", { session_id: sessionId, action: params.action?.type });
        return respond(id, {
          ok: true,
          untrusted: true,
          message: result.message,
          data: result.data,
          browser: await browserActionContext(sessionId, session),
          checkpoint,
          engine: session.engine,
        });
      }
      case "session.csrf_probe": {
        const sessionId = Number(params.session_id);
        const session = sessions.get(sessionId);
        if (!session) throw rpcError(-32001, "session not found");
        if (session.persistent) {
          throw rpcError(-32602, "CSRF probes require an isolated browser session");
        }
        const targetUrl = new URL(String(params.target_url || ""));
        if (!['http:', 'https:'].includes(targetUrl.protocol)) {
          throw rpcError(-32602, "target_url must use HTTP or HTTPS");
        }
        const method = String(params.method || "").toUpperCase();
        if (!['GET', 'POST'].includes(method)) {
          throw rpcError(-32602, "method must be GET or POST");
        }
        const fields = Array.isArray(params.params) ? params.params : [];
        if (fields.length > 128) throw rpcError(-32602, "too many form parameters");
        const normalized = fields.map((field) => {
          const name = String(field?.name ?? "");
          const value = String(field?.value ?? "");
          if (!name || Buffer.byteLength(name) > 1024 || Buffer.byteLength(value) > 64 * 1024) {
            throw rpcError(-32602, "invalid form parameter");
          }
          return { name, value };
        });
        const navigations = [];
        const onResponse = (response) => {
          if (!response.request().isNavigationRequest()) return;
          navigations.push({
            url: response.url(),
            status: response.status(),
            method: response.request().method(),
          });
        };
        session.page.on('response', onResponse);
        try {
          // A data document is an opaque, cross-site initiator. The submitted
          // request is created by Chromium, so SameSite, Origin, Referer and
          // redirect behavior are browser decisions rather than simulations.
          await session.page.goto('data:text/html,<title>HuntProxy CSRF probe</title>', {
            waitUntil: 'domcontentloaded',
            timeout: 10_000,
          });
          const navigationTimeout = Math.max(1_000, Math.min(Number(params.timeout_ms || 15_000), 30_000));
          await Promise.all([
            session.page.waitForNavigation({
              waitUntil: 'domcontentloaded',
              timeout: navigationTimeout,
            }),
            session.page.evaluate(({ target, method, fields }) => {
              const form = document.createElement('form');
              form.method = method;
              form.action = target;
              for (const field of fields) {
                const input = document.createElement('input');
                input.name = field.name;
                input.value = field.value;
                form.appendChild(input);
              }
              document.body.appendChild(form);
              form.submit();
            }, { target: targetUrl.href, method, fields: normalized }),
          ]);
          const finalUrl = new URL(session.page.url());
          if (finalUrl.origin !== targetUrl.origin) {
            throw rpcError(-32002, "CSRF probe did not navigate to the target origin");
          }
          await reconcileCurrentOriginStorage(session);
          return respond(id, {
            final_url: finalUrl.href,
            navigations: navigations.slice(-16),
          });
        } finally {
          session.page.off('response', onResponse);
        }
      }
      case "session.set_cookies": {
        const sessionId = Number(params.session_id);
        const session = sessions.get(sessionId);
        if (!session) throw rpcError(-32001, "session not found");
        if (!Array.isArray(params.cookies) || !params.cookies.length) {
          throw rpcError(-32602, "cookies must be a non-empty array");
        }
        await clearCookieIdentities(session.context, params.clear_cookies, "clear_cookies");
        if (Array.isArray(params.clear_names) && params.clear_names.length) {
          if (typeof params.target_url !== "string") {
            throw rpcError(-32602, "target_url is required when replacing cookies");
          }
          await session.context.addCookies(params.clear_names.map((name) => ({
            name,
            value: "",
            url: params.target_url,
            expires: 1,
          })));
        }
        await session.context.addCookies(params.cookies);
        return respond(id, { checkpoint: await extractCheckpoint(session) });
      }
      case "session.clear_cookies": {
        const sessionId = Number(params.session_id);
        const session = sessions.get(sessionId);
        if (!session) throw rpcError(-32001, "session not found");
        if (typeof params.target_url !== "string" || !Array.isArray(params.names) || !Array.isArray(params.cookies)) {
          throw rpcError(-32602, "target_url, names, and cookies are required");
        }
        await clearCookieIdentities(session.context, params.cookies, "cookies");
        const expired = params.names.map((name) => ({
          name,
          value: "",
          url: params.target_url,
          expires: 1,
        }));
        if (expired.length) await session.context.addCookies(expired);
        return respond(id, { checkpoint: await extractCheckpoint(session) });
      }
      case "session.checkpoint": {
        const sessionId = Number(params.session_id);
        const session = sessions.get(sessionId);
        if (!session) throw rpcError(-32001, "session not found");
        return respond(id, { checkpoint: await extractCheckpoint(session) });
      }
      case "session.javascript_files": {
        const sessionId = Number(params.session_id);
        const session = sessions.get(sessionId);
        if (!session) throw rpcError(-32001, "session not found");
        return respond(id, { files: [...(session.javascriptFiles?.values() || [])] });
      }
      case "session.cdp_enable": {
        const sessionId = Number(params.session_id);
        const session = sessions.get(sessionId);
        if (!session) throw rpcError(-32001, "session not found");
        if (session.cdp) {
          return respond(id, { cdp: session.cdp, checkpoint: await extractCheckpoint(session) });
        }
        const cdp = await relaunchSession(session, validateCdpPort(params.cdp_port));
        const checkpoint = await extractCheckpoint(session);
        logMeta("session.cdp_enable", { session_id: sessionId, port: cdp.port });
        return respond(id, { cdp, checkpoint });
      }
      case "session.cdp_disable": {
        const sessionId = Number(params.session_id);
        const session = sessions.get(sessionId);
        if (!session) throw rpcError(-32001, "session not found");
        if (session.cdp) await relaunchSession(session, null);
        const checkpoint = await extractCheckpoint(session);
        logMeta("session.cdp_disable", { session_id: sessionId });
        return respond(id, { cdp: null, checkpoint });
      }
      case "session.authenticated_fetch": {
        const sessionId = Number(params.session_id);
        const session = sessions.get(sessionId);
        if (!session) throw rpcError(-32001, "session not found");
        let target;
        try {
          target = new URL(String(params.url || ""));
        } catch {
          throw rpcError(-32602, "url must be a valid HTTP URL");
        }
        if (!new Set(["http:", "https:"]).has(target.protocol)) {
          throw rpcError(-32602, "url must use HTTP or HTTPS");
        }
        let pageOrigin;
        try {
          pageOrigin = new URL(session.page.url()).origin;
        } catch {
          return respond(id, { used: false, cookie_count: 0 });
        }
        // Page fetch preserves the browser's actual proxy, cookies, Origin,
        // Referer, and network fingerprint. Cross-origin candidates use the
        // regular crawler transport rather than fighting CORS/preflights.
        if (pageOrigin !== target.origin) {
          return respond(id, { used: false, cookie_count: 0 });
        }
        const cookies = await session.context.cookies([target.href]);
        const status = await session.page.evaluate(async ({ url, origin }) => {
          const controller = new AbortController();
          const timeout = setTimeout(() => controller.abort(), 15_000);
          try {
            const response = await fetch(url, {
              credentials: "include",
              redirect: "follow",
              headers: {
                "x-huntproxy-internal-crawler": "1",
                "x-huntproxy-browser-origin": origin,
              },
              signal: controller.signal,
            });
            const reader = response.body?.getReader();
            let received = 0;
            let truncated = false;
            while (reader) {
              const { done, value } = await reader.read();
              if (done) break;
              received += value?.byteLength || 0;
              if (received > 8 * 1024 * 1024) {
                truncated = true;
                await reader.cancel();
                break;
              }
            }
            return { status: response.status, truncated };
          } finally {
            clearTimeout(timeout);
          }
        }, { url: target.href, origin: pageOrigin });
        return respond(id, {
          used: true,
          cookie_count: cookies.length,
          status: status.status,
          truncated: status.truncated,
        });
      }
      case "session.stop": {
        const sessionId = Number(params.session_id);
        const session = sessions.get(sessionId);
        let checkpoint = null;
        if (session) {
          try { checkpoint = await extractCheckpoint(session); } catch {}
        }
        await closeSession(sessionId);
        return respond(id, { stopped: true, checkpoint });
      }
      default:
        throw rpcError(-32601, `method not found: ${method}`);
    }
  } catch (error) {
    const normalized = error?.code
      ? error
      : rpcError(-32000, String(error?.message || error));
    logMeta("error", { method, code: normalized.code });
    return respond(id, null, normalized);
  }
}

async function closeRuntime(runtime) {
  try { await runtime.page?.close(); } catch {}
  try { await runtime.context?.close(); } catch {}
  try { await runtime.browser?.close(); } catch {}
}

async function closeSession(sessionId) {
  const session = sessions.get(sessionId);
  if (!session) return;
  sessions.delete(sessionId);
  await closeRuntime(session);
  logMeta("session.stop", { session_id: sessionId });
}

let queue = Promise.resolve();
const readline = createInterface({ input: process.stdin });
readline.on("line", (line) => {
  if (!line.trim()) return;
  let request;
  try {
    request = JSON.parse(line);
  } catch {
    respond(null, null, rpcError(-32700, "parse error"));
    return;
  }
  queue = queue.then(() => handle(request)).catch(() => undefined);
});
readline.on("close", async () => {
  await queue;
  for (const sessionId of [...sessions.keys()]) await closeSession(sessionId);
  process.exit(0);
});

for (const signal of ["SIGINT", "SIGTERM"]) {
  process.on(signal, async () => {
    for (const sessionId of [...sessions.keys()]) await closeSession(sessionId);
    process.exit(signal === "SIGINT" ? 130 : 143);
  });
}
