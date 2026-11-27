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
import { spawn, spawnSync } from "node:child_process";
import net from "node:net";
import os from "node:os";
import { headlessDependencyError, inspectNativeIdentity, createIdentityRelay } from "./headless.js";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";

const PROTOCOL = 1;
const sessions = new Map();
// Sessions the daemon gave up on before they had launched. The daemon never
// reuses a session id, so an id whose start had already failed stays harmless.
const abortedStarts = new Set();
const ownedChromeChildren = new Set();
let shuttingDown = false;
const MAX_SESSION_EVENTS = 256;
const MAX_SESSION_EVENT_BYTES = 256 * 1024;
const MAX_EVENT_WAIT_MS = 1_000;
const EVENT_POLL_MS = 50;
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
    if (file) recordJavascriptFile(session, file);
  });
}

// Every new or changed entry takes the next sequence number. The counter lives
// on the session, so it keeps counting across CDP handoffs and resumes, which
// replace the browser runtime but not the session.
function recordJavascriptFile(session, file) {
  const known = session.javascriptFiles.get(file.url);
  if (known && known.mime === file.mime && known.status_code === file.status_code
      && known.source_page_url === file.source_page_url) return;
  session.javascriptFiles.set(file.url, { ...file, sequence: ++session.javascriptSequence });
}

// The files recorded after `after`, plus the cursor to ask from next time. A
// caller without a cursor, or with one this session never issued, gets all.
function javascriptFilesSince(session, after) {
  const cursor = session.javascriptSequence ?? 0;
  const from = Number.isSafeInteger(after) && after >= 0 && after <= cursor ? after : 0;
  const files = [];
  for (const { sequence, ...file } of session.javascriptFiles?.values() ?? []) {
    if (sequence > from) files.push(file);
  }
  return { files, cursor };
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
  // Runtime inspection keeps only a diagnostic's type and source location,
  // never its message or stack. An event also carries the start of the text,
  // which is what says why a script was refused or what a payload printed;
  // that text is the page's own and can contain application credentials.
  page.on("console", (message) => {
    if (!new Set(["error", "warning"]).has(message.type())) return;
    const location = message.location();
    const event = { kind: "console", level: message.type(), url: publicLocation(location.url),
      line: location.lineNumber, column: location.columnNumber };
    record(event);
    recordSessionEvent(session, "console", {
      level: event.level, url: event.url, line: event.line, column: event.column,
      ...eventText(message.text()),
    }, page);
  });
  page.on("pageerror", (error) => {
    record({ kind: "page_error" });
    recordSessionEvent(session, "page_error", eventText(error), page);
  });
}

// Room for a CSP violation with its directive, or a framework's error text.
const MAX_EVENT_TEXT_CHARS = 1000;

// The start of what a page said, for an event. `text_length` is the whole
// text's size in bytes, given only when the text was cut.
function eventText(value) {
  const text = String(value ?? "");
  if (text.length <= MAX_EVENT_TEXT_CHARS) return { text };
  return { text: text.slice(0, MAX_EVENT_TEXT_CHARS), text_length: Buffer.byteLength(text) };
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
    // Dismissing "Leave site?" keeps the page where it is, so a document with
    // an unsaved-changes guard could never be navigated away from.
    const leave = dialog.type() === "beforeunload";
    recordSessionEvent(session, "dialog", {
      dialog_type: dialog.type(),
      // The start of what the dialog said; message_length is all of it.
      message: (dialog.message() || "").slice(0, MAX_EVENT_TEXT_CHARS),
      message_length: Buffer.byteLength(dialog.message() || ""),
      default_value_length: Buffer.byteLength(dialog.defaultValue() || ""),
      disposition: leave ? "accepted" : "dismissed",
    }, page);
    void (leave ? dialog.accept() : dialog.dismiss()).catch(() => undefined);
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
    void disposePageMessageObserver(session, page);
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
  if (session.messageObservers) startPageMessageObserver(session, page);
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

function observerFailure(session, page, operation) {
  recordSessionEvent(session, "observer_error", { observer: "window_message", operation }, page);
  return operation;
}

function startPageMessageObserver(session, page) {
  if (session.messageObservers.has(page)) return session.messageObservers.get(page);
  const state = { connection: null, contexts: new Set(), listeners: [], disposed: false, error: null };
  session.messageObservers.set(page, state);
  state.ready = (async () => {
    const connection = await session.context.newCDPSession(page);
    state.connection = connection;
    const listen = (event, listener) => {
      connection.on(event, listener);
      state.listeners.push([event, listener]);
    };
    listen("Runtime.executionContextCreated", ({ context }) => {
      if (context.name === session.messageObserverWorld
          && context.auxData?.frameId === state.mainFrameId) state.contexts.add(context.id);
    });
    listen("Runtime.executionContextDestroyed", ({ executionContextId }) => state.contexts.delete(executionContextId));
    listen("Runtime.executionContextsCleared", () => state.contexts.clear());
    await connection.send("Page.enable");
    const { frameTree } = await connection.send("Page.getFrameTree");
    state.mainFrameId = frameTree.frame.id;
    await connection.send("Runtime.enable");
    // Isolated worlds share DOM events but have their own global object. Keep
    // the queue and drain function out of the application's JavaScript world.
    // A newly opened popup can execute its first inline script before CDP is
    // attached; subsequent scripts/navigation use the registered init script.
    await connection.send("Page.addScriptToEvaluateOnNewDocument", {
      source: `(${installWindowMessageObserver.toString()})(${JSON.stringify(session.messageObserverKey)})`,
      worldName: session.messageObserverWorld,
      runImmediately: true,
    });
    if (!state.contexts.size) throw new Error("Isolated message observer context was not created");
  })().catch(() => {
    if (!state.disposed && !page.isClosed()) state.error = observerFailure(session, page, "initialization");
  });
  return state;
}

async function disposePageMessageObserver(session, page) {
  const state = session.messageObservers?.get(page);
  if (!state) return;
  session.messageObservers.delete(page);
  state.disposed = true;
  await state.ready;
  if (!state.connection) return;
  for (const [event, listener] of state.listeners) state.connection.removeListener(event, listener);
  // Target closure also detaches its CDP sessions.
  await state.connection.detach().catch(() => undefined);
  state.contexts.clear();
}

async function disposeSessionTracking(session) {
  if (session.trackingPageListener) session.context.off("page", session.trackingPageListener);
  await Promise.all([...(session.messageObservers?.keys() || [])]
    .map((page) => disposePageMessageObserver(session, page)));
}

async function drainWindowMessages(session) {
  for (const page of [...session.pages.values()]) {
    if (page.isClosed()) continue;
    const state = startPageMessageObserver(session, page);
    await state.ready;
    if (state.disposed || page.isClosed()) continue;
    // A broken observer must not hide the independently collected page and
    // console events. Its diagnostic and persistent status remain retrievable.
    if (state.error) continue;
    for (const contextId of [...state.contexts]) {
      let result;
      try {
        result = await state.connection.send("Runtime.evaluate", {
          expression: `globalThis[${JSON.stringify(session.messageObserverKey)}]()`,
          contextId,
          returnByValue: true,
        });
      } catch (error) {
        if (page.isClosed() || state.disposed
            || /Cannot find context|Execution context was destroyed|Inspected target navigated or closed/.test(String(error?.message))) {
          state.contexts.delete(contextId);
          continue;
        }
        state.error = observerFailure(session, page, "read");
        break;
      }
      if (result.exceptionDetails || !Array.isArray(result.result?.value)) {
        state.error = observerFailure(session, page, "read");
        break;
      }
      for (const message of result.result.value.slice(0, 128)) {
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
}

async function initializeSessionTracking(session, existingJavascriptFiles = new Map(), generation = 1) {
  session.javascriptFiles = existingJavascriptFiles;
  session.javascriptSequence ??= 0;
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
  session.messageObserverWorld = `huntproxy_window_messages_${generation}`;
  session.messageObservers = new Map();
  session.trackingPageListener = (page) => trackPage(session, page, false);
  session.context.on("page", session.trackingPageListener);
  for (const page of session.context.pages()) trackPage(session, page, true);
  await Promise.all([...session.messageObservers.values()].map((state) => state.ready));
}

async function activePage(session) {
  session.identityController?.assertHealthy();
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
      timer = setTimeout(() => reject(rpcError(-32000, `upload file chooser did not open within ${timeout} ms; `
        + "the locator must be the control that opens the file dialog, or target the input[type=file] itself without via_chooser")),
      timeout);
    });
    try {
      click = locator.click({ timeout });
      const [event] = await Promise.all([waiting, click]);
      clearTimeout(timer);
      const remaining = timeout - (Date.now() - started);
      if (remaining <= 0) throw rpcError(-32000, `upload file chooser timed out after ${timeout} ms`);
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
    result.element = await evaluateElement(session, session.page, locator, (element) => ({
      tag: element.tagName.toLowerCase(), role: element.getAttribute("role"),
      type: element.getAttribute("type"), disabled: Boolean(element.disabled),
      read_only: Boolean(element.readOnly), checked: typeof element.checked === "boolean" ? element.checked : null,
      file_count: element.files?.length ?? null,
    }), 10_000);
    result.element.visible = await locator.isVisible();
    result.element.enabled = await locator.isEnabled({ timeout: 10_000 });
  }
  const bytes = Buffer.from(JSON.stringify(result), "utf8");
  const content = new TextDecoder().decode(bytes.subarray(0, maxBytes), { stream: bytes.length > maxBytes });
  return { message: "runtime inspected", data: { format: "runtime", content,
    truncated: bytes.length > maxBytes, total_bytes: bytes.length } };
}

function loadPlaywright() {
  const candidates = [process.env.HUNTPROXY_PLAYWRIGHT_CORE_PATH].filter(Boolean);
  const workerDir = path.dirname(fileURLToPath(import.meta.url));
  candidates.push(
    path.join(workerDir, "node_modules", "playwright-core"),
    path.join(process.cwd(), "node_modules", "playwright-core"),
    "playwright-core",
  );

  const requireFromWorker = createRequire(path.join(workerDir, "package.json"));
  const requireFromCwd = createRequire(path.join(process.cwd(), "package.json"));
  const explicit = candidates[0] === process.env.HUNTPROXY_PLAYWRIGHT_CORE_PATH;
  const pinnedVersion = explicit ? null
    : JSON.parse(fs.readFileSync(path.join(workerDir, "package.json"), "utf8"))
      .dependencies?.["playwright-core"];
  let lastError;
  for (const candidate of explicit ? candidates.slice(0, 1) : candidates) {
    const previousBrowsersPath = process.env.PLAYWRIGHT_BROWSERS_PATH;
    try {
      let entry;
      try {
        entry = requireFromWorker.resolve(candidate);
      } catch {
        entry = requireFromCwd.resolve(candidate);
      }
      let packageDir = path.dirname(entry);
      let manifest;
      while (true) {
        try {
          const value = JSON.parse(fs.readFileSync(path.join(packageDir, "package.json"), "utf8"));
          if (value.name === "playwright-core") {
            manifest = value;
            break;
          }
        } catch {}
        const parent = path.dirname(packageDir);
        if (parent === packageDir) throw new Error("playwright-core package manifest not found");
        packageDir = parent;
      }
      if (!explicit && pinnedVersion && manifest.version !== pinnedVersion) {
        throw new Error(`playwright-core ${pinnedVersion} is required; run HuntProxy browser install`);
      }
      // `browser install` keeps the version-paired browser with its package.
      // An explicit Playwright cache location still takes precedence.
      if (previousBrowsersPath == null && fs.existsSync(path.join(packageDir, ".local-browsers"))) {
        process.env.PLAYWRIGHT_BROWSERS_PATH = "0";
      }
      const api = requireFromWorker(entry);
      let expectedChromiumVersion = null;
      try {
        const browsers = JSON.parse(fs.readFileSync(path.join(packageDir, "browsers.json"), "utf8"));
        expectedChromiumVersion = browsers.browsers.find((browser) => browser.name === "chromium")?.browserVersion || null;
      } catch {}
      return { api, packageDir, version: manifest.version, expectedChromiumVersion };
    } catch (error) {
      if (previousBrowsersPath == null) delete process.env.PLAYWRIGHT_BROWSERS_PATH;
      else process.env.PLAYWRIGHT_BROWSERS_PATH = previousBrowsersPath;
      lastError = error;
      if (explicit || error.message?.includes("is required; run HuntProxy browser install")) throw error;
    }
  }
  throw new Error(`playwright-core unavailable: ${lastError?.message || "not found"}`);
}

const inspectRuntimeOnly = process.argv.includes("--inspect-runtime");
let playwrightRuntime;
try {
  if (Number(process.versions.node.split(".")[0]) < 20) {
    throw new Error("Browser worker requires Node.js 20 or newer; rerun the HuntProxy installer for its private Node runtime, or configure node_path");
  }
  playwrightRuntime = loadPlaywright();
} catch (error) {
  if (!inspectRuntimeOnly) throw error;
  process.stdout.write(`${JSON.stringify({ compatibility_error: error.message })}\n`);
  process.exit(0);
}
const { chromium } = playwrightRuntime.api;
const browserRuntime = inspectBrowserRuntime();
if (inspectRuntimeOnly) {
  process.stdout.write(`${JSON.stringify(browserRuntime)}\n`);
  process.exit(0);
}

// A page chooses its title, its frame names and much of an error's text, and
// can put half a surrogate pair in any of them, or have one cut in half by a
// length limit. JSON writes such a half as an escape that the daemon's parser
// rejects, which it treats as a broken worker; so no string leaves with one.
function wellFormed(key, value) {
  return typeof value === "string" ? value.toWellFormed() : value;
}

function respond(id, result, error) {
  const message = error
    ? { jsonrpc: "2.0", id, error }
    : { jsonrpc: "2.0", id, result };
  process.stdout.write(`${JSON.stringify(message, wellFormed)}\n`);
}

function logMeta(event, fields = {}) {
  process.stderr.write(`${JSON.stringify({ event, ...fields })}\n`);
}

function rpcError(code, message) {
  return { code, message };
}

function existingChromiumExecutable() {
  const candidates = [
    process.env.HUNTPROXY_CHROME_EXECUTABLE,
    process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH,
  ].filter(Boolean);
  try {
    const bundled = chromium.executablePath();
    if (bundled) candidates.push(bundled);
  } catch {
    // playwright-core commonly has no downloaded browser.
  }
  for (const name of ["google-chrome-stable", "google-chrome", "chromium", "chromium-browser"]) {
    for (const directory of (process.env.PATH || "").split(path.delimiter)) {
      if (directory) candidates.push(path.join(directory, name));
    }
  }
  candidates.push(
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
  );
  return candidates.find((candidate) => {
    try {
      if (!fs.statSync(candidate).isFile()) return false;
      fs.accessSync(candidate, fs.constants.X_OK);
      return true;
    } catch {
      return false;
    }
  });
}

function inspectBrowserRuntime() {
  const executable = existingChromiumExecutable();
  const version = executable ? spawnSync(executable, ["--version"], {
    encoding: "utf8", timeout: 3_000, maxBuffer: 8_192, windowsHide: true,
  }) : null;
  return {
    playwright_core_path: playwrightRuntime.packageDir,
    playwright_version: playwrightRuntime.version,
    expected_chromium_version: playwrightRuntime.expectedChromiumVersion,
    headless: browserHeadless(),
    headless_compatibility: browserHeadlessCompatibility(),
    compatibility_error: browserHeadlessCompatibility() ? headlessDependencyError() : null,
    chromium_path: executable ? path.resolve(executable) : null,
    chromium_version: version?.status === 0
      ? version.stdout?.match(/\b\d+\.\d+\.\d+\.\d+\b/)?.[0] || null : null,
  };
}

function environmentBoolean(name, fallback) {
  const value = process.env[name]?.trim().toLowerCase();
  if (value == null || value === "") return fallback;
  if (value === "true" || value === "1") return true;
  if (value === "false" || value === "0") return false;
  throw new Error(`${name} must be true or false`);
}

function browserHeadless() {
  return environmentBoolean("HUNTPROXY_BROWSER_HEADLESS", true);
}

function browserHeadlessCompatibility() {
  const enabled = environmentBoolean("HUNTPROXY_BROWSER_HEADLESS_COMPAT", browserHeadless());
  if (enabled && !browserHeadless()) throw new Error("HUNTPROXY_BROWSER_HEADLESS_COMPAT requires headless mode");
  return enabled;
}

// Credentials are deliberately absent: Playwright would answer every HTTP
// authentication challenge with them (see proxyHttpCredentials).
function chromiumProxy(proxy) {
  if (!proxy?.server) return undefined;
  return { server: proxy.server, bypass: "<-loopback>" };
}

function chromiumLaunchOptions(proxy, caCertPath, cdpPort = null, executablePath = browserRuntime.chromium_path) {
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
    headless: browserRuntime.headless,
    proxy: chromiumProxy(proxy),
    httpCredentials: proxyHttpCredentials(proxy),
    ignoreHTTPSErrors: Boolean(caCertPath),
    serviceWorkers: "allow",
    args,
  };
}

// The capture token belongs to the proxy alone. Playwright answers every
// Fetch.authRequired whose request URL matches one of its HTTP credentials, and
// a credential without an origin matches every URL: it would also answer a
// target site's own `401 WWW-Authenticate: Basic` and hand the target the
// token. So the credential is scoped to a reserved origin that is never a real
// destination, and the proxy is authenticated once by requesting that origin
// (primeProxyAuth). Chromium keeps the credentials the proxy accepted and sends
// them with every later request, HTTP and CONNECT alike, so no other challenge
// from the proxy reaches Playwright, and a target's own challenge is answered
// as it would be without credentials. The same one-time authentication lets a
// CDP client that routes requests (Playwright's page.route enables Fetch with
// auth handling, so it receives a proxy challenge instead of this worker) make
// its first navigation. The name is reserved (.invalid never resolves):
// HuntProxy rejects it while resolving the destination, so no target is
// contacted and nothing is captured.
const PROXY_AUTH_PRIME_URL = "http://huntproxy-auth-prime.invalid/";

function proxyHttpCredentials(proxy) {
  if (!proxy?.username && !proxy?.password) return undefined;
  return {
    username: proxy.username || "",
    password: proxy.password || "",
    origin: new URL(PROXY_AUTH_PRIME_URL).origin,
  };
}

// Uses the launched tab and leaves it on about:blank: closing a throwaway tab
// stalled intermittently (Page.close never completed while the tab's proxy-auth
// request was in flight), which hung a CDP handoff. A failure is logged rather
// than raised: the first real navigation then reports the proxy problem itself.
async function primeProxyAuth(page, proxy) {
  if (!proxyHttpCredentials(proxy)) return;
  try {
    await page.goto(PROXY_AUTH_PRIME_URL, { waitUntil: "commit", timeout: 10_000 });
    await page.goto("about:blank", { waitUntil: "domcontentloaded", timeout: 10_000 });
  } catch (error) {
    logMeta("proxy_auth_prime_failed", { error: String(error?.message || error).split("\n")[0].slice(0, 200) });
  }
}

async function nativeDebugPort(preferred) {
  const listener = net.createServer();
  await new Promise((resolve, reject) => {
    listener.once("error", reject);
    listener.listen(preferred ?? 0, "127.0.0.1", resolve);
  });
  const port = listener.address().port;
  await new Promise((resolve) => listener.close(resolve));
  return port;
}

function chromeExited(child, timeout) {
  if (!child.pid || child.exitCode != null || child.signalCode != null) return Promise.resolve(true);
  return new Promise((resolve) => {
    const finish = (exited) => {
      clearTimeout(timer);
      child.removeListener("exit", onExit);
      resolve(exited);
    };
    const onExit = () => finish(true);
    const timer = setTimeout(() => finish(false), timeout);
    child.once("exit", onExit);
  });
}

async function stopOwnedChrome(child) {
  if (!child || await chromeExited(child, 1_500)) return;
  child.kill("SIGTERM");
  if (await chromeExited(child, 1_000)) return;
  child.kill("SIGKILL");
  if (!await chromeExited(child, 1_000)) throw new Error("Owned Chromium did not exit; its profile remains in use");
}

function nativeChromeStartupFailure(stderr, executablePath) {
  if (/No usable sandbox!/i.test(stderr)) {
    return `Chromium sandbox initialization failed; check host sandbox permissions. On Ubuntu, allow user namespaces for the selected Chromium executable (${executablePath}) in its AppArmor profile`;
  }
  if (/Missing X server or \$DISPLAY|Failed to connect to (?:the )?Wayland display/i.test(stderr)) {
    return "Chromium could not connect to a display; provide a working display or enable HUNTPROXY_BROWSER_HEADLESS=true";
  }
  return null;
}

const NATIVE_BEHAVIOR_ARGS = [
  "--disable-back-forward-cache", "--disable-background-networking", "--disable-component-update",
  "--disable-sync", "--disable-default-apps", "--no-service-autorun",
  "--disable-client-side-phishing-detection", "--disable-breakpad",
  "--disable-component-extensions-with-background-pages", "--disable-popup-blocking",
  "--disable-prompt-on-repost", "--password-store=basic", "--use-mock-keychain",
  "--disable-dev-shm-usage", "--disable-background-timer-throttling",
  "--disable-backgrounding-occluded-windows", "--disable-renderer-backgrounding",
  "--disable-hang-monitor", "--metrics-recording-only", "--disable-search-engine-choice-screen",
  "--no-first-run", "--no-default-browser-check",
];

let nativeSandboxReason = null;

async function spawnNativeChromeAttempt(proxy, caCertPath, profileDir, cdpPort, extraArgs = []) {
  const port = await nativeDebugPort(cdpPort);
  if (shuttingDown) throw new Error("Browser worker is shutting down");
  const args = [
    `--user-data-dir=${profileDir}`, `--remote-debugging-port=${port}`,
    "--remote-debugging-address=127.0.0.1", ...NATIVE_BEHAVIOR_ARGS,
    ...chromiumLaunchOptions(proxy, caCertPath).args,
    ...(cdpPort != null ? [`--remote-allow-origins=http://127.0.0.1:${port},https://chrome-devtools-frontend.appspot.com`] : []),
    ...(proxy?.server ? [`--proxy-server=${proxy.server}`] : []),
    ...(caCertPath ? ["--ignore-certificate-errors"] : []),
    ...extraArgs, "about:blank",
  ];
  const child = spawn(browserRuntime.chromium_path, args, { stdio: ["ignore", "ignore", "pipe"] });
  ownedChromeChildren.add(child);
  child.once("close", () => ownedChromeChildren.delete(child));
  child.once("exit", () => ownedChromeChildren.delete(child));
  const endpoint = new Promise((resolve, reject) => {
    let buffer = "";
    let startupFailure = null;
    let settled = false;
    const finish = (error, endpoint) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      child.removeListener("close", onClose);
      buffer = "";
      if (error && startupFailure?.startsWith("Chromium sandbox initialization failed")) {
        error.sandboxReason = startupFailure;
      }
      error ? reject(error) : resolve(endpoint);
    };
    const onClose = (code, signal) => {
      const status = signal ? `signal ${signal}` : code != null ? `exit code ${code}` : "unknown exit status";
      finish(new Error(`Chromium exited before startup (${status}); ${startupFailure || "check the executable, profile and selected browser mode"}`));
    };
    const timer = setTimeout(() => finish(new Error(`Chromium debugging endpoint did not become ready${startupFailure ? `; ${startupFailure}` : ""}`)), 15_000);
    child.on("error", () => finish(new Error("Could not start the selected Chromium executable")));
    // close follows stderr draining, while exit can arrive before the final diagnostic.
    child.once("close", onClose);
    child.stderr.on("data", (chunk) => {
      if (settled) return;
      buffer = (buffer + chunk.toString()).slice(-8_192);
      startupFailure ||= nativeChromeStartupFailure(buffer, browserRuntime.chromium_path);
      const match = buffer.match(/DevTools listening on (ws:\/\/127\.0\.0\.1:\d+\/devtools\/browser\/[A-Za-z0-9-]+)/);
      if (match && new URL(match[1]).port === String(port)) finish(null, match[1]);
    });
  });
  return { child, endpoint };
}

async function spawnNativeChrome(proxy, caCertPath, profileDir, cdpPort, extraArgs = []) {
  const start = async (disabled) => {
    const attempt = await spawnNativeChromeAttempt(proxy, caCertPath, profileDir, cdpPort,
      disabled ? [...extraArgs, "--no-sandbox"] : extraArgs);
    try {
      const endpoint = await attempt.endpoint;
      return { child: attempt.child, endpoint };
    } catch (error) {
      try { await stopOwnedChrome(attempt.child); } catch (cleanupError) {
        Object.defineProperty(cleanupError, "ownedRuntime", { value: {
          browser: null, context: null, page: null, ownedChrome: attempt.child,
          persistent: true, profileDir,
        } });
        throw cleanupError;
      }
      throw error;
    }
  };
  if (nativeSandboxReason) return start(true);
  try {
    return await start(false);
  } catch (error) {
    if (!error.sandboxReason) throw error;
    nativeSandboxReason = error.sandboxReason;
    return start(true);
  }
}

let nativeIdentityPromise;
function nativeIdentity(proxy, caCertPath) {
  if (!nativeIdentityPromise) {
    nativeIdentityPromise = (async () => {
      const profileDir = fs.mkdtempSync(path.join(os.tmpdir(), "huntproxy-identity-"));
      let child;
      let failedOwnedRuntime;
      try {
        const started = await spawnNativeChrome(proxy, caCertPath, profileDir, null,
          ["--headless=new", "--disable-extensions"]);
        child = started.child;
        return await inspectNativeIdentity(await started.endpoint, browserRuntime.chromium_version);
      } catch (error) {
        failedOwnedRuntime = error.ownedRuntime;
        if (failedOwnedRuntime) failedOwnedRuntime.probeProfile = true;
        throw error;
      } finally {
        try { await stopOwnedChrome(child); } catch (error) {
          Object.defineProperty(error, "ownedRuntime", { value: {
            browser: null, context: null, page: null, ownedChrome: child,
            persistent: true, profileDir, probeProfile: true,
          } });
          throw error;
        }
        if (!failedOwnedRuntime) fs.rmSync(profileDir, { recursive: true, force: true });
      }
    })().catch((error) => { nativeIdentityPromise = null; throw error; });
  }
  return nativeIdentityPromise;
}

async function launchNativeChromium(proxy, caCertPath, profileDir, cdpPort) {
  const compatibility = browserRuntime.headless_compatibility;
  const identity = compatibility ? await nativeIdentity(proxy, caCertPath) : null;
  const extraArgs = identity ? ["--headless=new", `--user-agent=${identity.userAgent}`,
    "--screen-info={1280x720}", "--window-size=1050,700", "--window-position=10,10"] : [];
  const artifactsDir = path.join(profileDir, "huntproxy-artifacts");
  fs.mkdirSync(artifactsDir, { recursive: true, mode: 0o700 });
  const { child, endpoint } = await spawnNativeChrome(proxy, caCertPath, profileDir, cdpPort, extraArgs);
  let browser;
  let identityController;
  try {
    const nativeEndpoint = await endpoint;
    identityController = identity ? await createIdentityRelay(nativeEndpoint, identity, () => {
      // Signal synchronously before the failed control transport detaches.
      child.kill("SIGTERM");
      return stopOwnedChrome(child);
    }) : null;
    browser = await chromium.connectOverCDP(identityController?.endpoint || nativeEndpoint,
      { noDefaults: true, isLocal: true, artifactsDir });
    if (identity && browser.version() !== browserRuntime.chromium_version) {
      throw new Error("Chromium changed after identity inspection; restart the browser worker");
    }
    const context = browser.contexts()[0];
    if (!context) throw new Error("Chromium default context is missing");
    const credentials = proxyHttpCredentials(proxy);
    if (credentials) await context.setHTTPCredentials(credentials);
    const page = context.pages()[0] || await context.newPage();
    await primeProxyAuth(page, proxy);
    await page.bringToFront();
    identityController?.assertHealthy();
    return { browser, context, page, persistent: true, profileDir, ownedChrome: child, identityController,
      sandbox_state: nativeSandboxReason ? "disabled_fallback" : "enabled", sandbox_reason: nativeSandboxReason };
  } catch (error) {
    identityController?.beginClose();
    try { await browser?.close(); } catch {}
    try { await stopOwnedChrome(child); } catch (cleanupError) {
      Object.defineProperty(cleanupError, "ownedRuntime", { value: {
        browser: null, context: null, page: null, ownedChrome: child, persistent: true, profileDir, identityController,
      } });
      throw cleanupError;
    }
    await identityController?.close();
    throw error;
  }
}

async function launchChromium(proxy, caCertPath, profileDir = null, cdpPort = null) {
  if (shuttingDown) throw new Error("Browser worker is shutting down");
  const executablePath = browserRuntime.chromium_path;
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
    if (!browserRuntime.headless || browserRuntime.headless_compatibility) return launchNativeChromium(proxy, caCertPath, profileDir, cdpPort);
    const context = await chromium.launchPersistentContext(profileDir, options);
    const page = context.pages()[0] || await context.newPage();
    await primeProxyAuth(page, proxy);
    return {
      browser: null,
      context,
      page,
      persistent: true,
      profileDir,
    };
  }
  const { ignoreHTTPSErrors, serviceWorkers, httpCredentials, ...launchOptions } = options;
  const browser = await chromium.launch(launchOptions);
  const context = await browser.newContext({
    serviceWorkers,
    ignoreHTTPSErrors,
    httpCredentials,
  });
  const page = await context.newPage();
  await primeProxyAuth(page, proxy);
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
  const live = [];
  let activeIndex = 0;
  for (const page of session.context.pages()) {
    if (page.isClosed()) continue;
    let url = page.url() || "about:blank";
    let parsed;
    try {
      parsed = new URL(url);
    } catch {
      throw rpcError(-32000, "CDP handoff could not preserve an open tab URL");
    }
    // A tab that ended on Chromium's error page (for example a navigation the
    // caller aborted) has nothing to restore, so it comes back as a blank tab.
    if (parsed.protocol === "chrome-error:") {
      url = "about:blank";
      parsed = new URL(url);
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
      live.push({ origin: parsed.origin, values: sessionStorage, active: page === active });
    }
    if (page === active) activeIndex = pages.length;
    pages.push({ url, session_storage: sessionStorage });
  }
  if (!pages.length) pages.push({ url: "about:blank", session_storage: {} });
  // A tab's live values replace what was saved for its origin (the active tab
  // wins when several share one), so a value the app changed or removed is
  // never brought back; origins no tab is on keep their saved values.
  const saved = savedSessionStorage(session);
  const storage = {};
  if (saved) {
    for (const entry of [...live.filter((item) => !item.active), ...live.filter((item) => item.active)]) {
      if (Object.keys(entry.values).length) saved[entry.origin] = { ...entry.values };
      else delete saved[entry.origin];
    }
    for (const [origin, values] of Object.entries(saved)) storage[origin] = { ...values };
  }
  return { pages, active_index: activeIndex, storage };
}

// Chromium drops sessionStorage on exit, and a tab sitting on about:blank has
// none to hand back, so write every other saved origin's sessionStorage into
// the tab before CDP control is returned: a helper that navigates the tab to
// the app afterwards finds it again. A tab's own origin is restored from its
// captured values instead. Best effort: nothing reaches a target, errors carry
// no values, and the seeding route is removed even when a write fails.
async function restoreSavedOrigins(runtime, page, saved, tabUrl) {
  let own = null;
  try { own = new URL(tabUrl).origin; } catch {}
  let wrote = false;
  for (const [origin, values] of Object.entries(saved || {})) {
    if (origin === own || !validStorageSeedOrigin(origin)) continue;
    const items = Object.entries(values || {}).map(([name, value]) => ({ name, value }));
    if (!items.length) continue;
    try {
      await seedBrowserStorage({ context: runtime.context, transientSeed: true },
        { origins: [{ origin, session_storage: items, keep_local: true }] }, page);
      wrote = true;
    } catch {}
  }
  if (wrote && (!tabUrl || tabUrl === "about:blank")) {
    await page.goto("about:blank", { waitUntil: "domcontentloaded", timeout: STORAGE_SEED_STEP_MS }).catch(() => {});
  }
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
    await restoreSavedOrigins(runtime, page, pageState?.storage, state.url);
    // Chromium may reopen the previous run's tab (even an error page).
    if ((!state.url || state.url === "about:blank") && page.url() !== "about:blank") {
      await page.goto("about:blank", { waitUntil: "domcontentloaded", timeout: STORAGE_SEED_STEP_MS }).catch(() => {});
    }
    if (state.url && state.url !== "about:blank") {
      // Write the tab's sessionStorage before the app's first load: an app
      // that checks it on startup would otherwise bounce to its login page.
      const items = Object.entries(state.session_storage || {}).map(([name, value]) => ({ name, value }));
      const tabOrigin = validStorageSeedOrigin(new URL(state.url).origin);
      if (tabOrigin && items.length) {
        try {
          await seedBrowserStorage({ context: runtime.context },
            { origins: [{ origin: tabOrigin, session_storage: items, keep_local: true }] }, page);
        } catch {}
      }
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
      await closePageWithin(page);
    }
  }
  const activeIndex = Number.isInteger(pageState?.active_index)
    && pageState.active_index >= 0 && pageState.active_index < pages.length
    ? pageState.active_index : 0;
  runtime.page = pages[activeIndex];
  await runtime.page.bringToFront();
}

// Closing a tab can stall in Chromium; a handoff must never wait on it.
async function closePageWithin(page, milliseconds = 5_000) {
  let timer;
  try {
    await Promise.race([
      page.close({ runBeforeUnload: false }),
      new Promise((resolve) => { timer = setTimeout(resolve, milliseconds); }),
    ]);
  } catch {} finally {
    clearTimeout(timer);
  }
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
    if (error.ownedRuntime) Object.assign(session, error.ownedRuntime, { cdp: null });
    if (error.ownedRuntime || shuttingDown) throw error;
    try {
      const restored = await launchSessionRuntime(session, null, pageState, sessionCookies);
      Object.assign(session, restored.runtime, { cdp: null });
      await initializeSessionTracking(session, existingJavascriptFiles, nextGeneration);
    } catch (restoreError) {
      if (restoreError.ownedRuntime) Object.assign(session, restoreError.ownedRuntime, { cdp: null });
      throw rpcError(
        -32000,
        `CDP handoff failed and the normal browser could not be restored: ${restoreError?.message || restoreError}`,
      );
    }
    throw error;
  }
  Object.assign(session, launched.runtime, { cdp: launched.cdp });
  const activeContext = session.context;
  activeContext.once("close", () => {
    if (session.context === activeContext) session.cdp = null;
  });
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

// The sessionStorage saved for every origin the profile has seen: the seeded
// session object, then whatever a handoff last captured from a live tab.
function savedSessionStorage(session) {
  if (session.transientSeed) return null;
  if (session.restoreState) return (session.restoreState.session_storage ??= {});
  return (session.handoffSessionStorage ??= {});
}

const STORAGE_SEED_STEP_MS = 10_000;
const STORAGE_SEED_TOTAL_MS = 60_000;

// Errors here name the origin and a fixed reason only; storage keys and values
// never appear in messages.
function storageSeedError(origin, reason) {
  return rpcError(-32000, `browser storage seed failed for ${origin}: ${reason}`);
}

function validStorageSeedOrigin(value) {
  try {
    const parsed = new URL(String(value));
    return new Set(["http:", "https:"]).has(parsed.protocol) && parsed.origin === value ? parsed.origin : null;
  } catch {
    return null;
  }
}

function storageSeedNavigationReason(error) {
  if (error?.name === "TimeoutError") return "timed out opening the origin";
  const code = String(error?.message || "").match(/net::ERR_[A-Z_]+/)?.[0];
  return code ? `could not open the origin, ${code}` : "could not open the origin";
}

// Write localStorage/sessionStorage for each origin on the session's main tab
// before the app's first real load. Every request in the window is fulfilled
// locally with an empty page, so nothing reaches the target (or its service
// worker), and the route is always removed afterwards. The tab is left on the
// last seeded origin; callers navigate on afterwards.
async function seedBrowserStorage(session, seed, pageOverride = null) {
  const origins = Array.isArray(seed?.origins) ? seed.origins : [];
  const clearOrigins = Array.isArray(seed?.clear_origins) ? seed.clear_origins : [];
  if (!origins.length && !clearOrigins.length) return null;
  const targets = [];
  const seen = new Set();
  for (const entry of origins) {
    const origin = validStorageSeedOrigin(entry?.origin);
    const pairs = (items) => (Array.isArray(items) ? items : [])
      .map((item) => [String(item?.name ?? ""), String(item?.value ?? "")]);
    if (!origin || seen.has(origin)) throw rpcError(-32602, "storage_seed origins must be unique exact http(s) origins");
    seen.add(origin);
    targets.push({
      origin,
      local: pairs(entry.local_storage),
      session: pairs(entry.session_storage),
      // Restoring a relaunched profile: Chromium already holds localStorage.
      keepLocal: Boolean(entry.keep_local),
    });
  }
  for (const value of clearOrigins) {
    const origin = validStorageSeedOrigin(value);
    if (!origin || seen.has(origin)) throw rpcError(-32602, "storage_seed clear_origins must be unique exact http(s) origins");
    seen.add(origin);
    targets.push({ origin, local: [], session: [], keepLocal: false });
  }
  const page = pageOverride || await activePage(session);
  const returnTo = page.url() || "about:blank";
  const deadline = Date.now() + STORAGE_SEED_TOTAL_MS;
  const step = (origin) => {
    const left = deadline - Date.now();
    if (left <= 0) throw storageSeedError(origin, "timed out");
    return Math.min(STORAGE_SEED_STEP_MS, left);
  };
  const fulfil = (route) => route.fulfill({
    status: 200,
    contentType: "text/html; charset=utf-8",
    body: "<!doctype html><title>storage seed</title>",
  });
  let cdp;
  let routed = false;
  let failure;
  try {
    // Leave the live document first so its background requests cannot be
    // answered by the seeding route.
    if (returnTo !== "about:blank") {
      await page.goto("about:blank", { waitUntil: "domcontentloaded", timeout: STORAGE_SEED_STEP_MS });
    }
    // A service worker already controlling the origin would answer the
    // navigation itself and the real app would load.
    // (Chromium ignores the bypass unless the session has enabled Network.)
    cdp = await session.context.newCDPSession(page);
    await cdp.send("Network.enable");
    await cdp.send("Network.setBypassServiceWorker", { bypass: true });
    await page.route("**/*", fulfil);
    routed = true;
    for (const target of targets) {
      try {
        await page.goto(`${target.origin}/`, { waitUntil: "domcontentloaded", timeout: step(target.origin) });
      } catch (error) {
        throw error?.code === -32000 ? error : storageSeedError(target.origin, storageSeedNavigationReason(error));
      }
      if (page.url() !== `${target.origin}/`) throw storageSeedError(target.origin, "the origin did not load");
      const write = page.evaluate(({ local, sessionItems, keepLocal }) => {
        try {
          if (!keepLocal) localStorage.clear();
          sessionStorage.clear();
          if (!keepLocal) for (const [key, value] of local) localStorage.setItem(key, value);
          for (const [key, value] of sessionItems) sessionStorage.setItem(key, value);
          return "ok";
        } catch (error) {
          try { if (!keepLocal) localStorage.clear(); sessionStorage.clear(); } catch {}
          return String(error?.name || "Error");
        }
      }, { local: target.local, sessionItems: target.session, keepLocal: target.keepLocal });
      write.catch(() => {});
      let timer;
      const outcome = await Promise.race([
        write,
        new Promise((resolve) => { timer = setTimeout(() => resolve("timed out"), step(target.origin)); }),
      ]).finally(() => clearTimeout(timer));
      if (outcome !== "ok") throw storageSeedError(target.origin, `storage rejected the write (${outcome})`);
    }
  } catch (error) {
    failure = typeof error?.code === "number" && typeof error?.message === "string"
      ? error
      : rpcError(-32000, "browser storage seed failed before any origin was written");
  } finally {
    if (routed) await page.unroute("**/*", fulfil).catch(() => {});
    if (cdp) {
      await cdp.send("Network.setBypassServiceWorker", { bypass: false }).catch(() => {});
      await cdp.detach().catch(() => {});
    }
  }
  if (failure) throw failure;
  // The seed wins over any older checkpoint restored for these origins.
  const state = session.restoreState;
  const savedSession = savedSessionStorage(session);
  for (const target of targets) {
    session.restoredOrigins?.add(target.origin);
    const hasValues = target.local.length || target.session.length;
    if (savedSession) {
      if (hasValues) savedSession[target.origin] = Object.fromEntries(target.session);
      else if (!target.keepLocal) delete savedSession[target.origin];
    }
    if (!state || target.keepLocal) continue;
    state.local_storage ??= {};
    if (hasValues) state.local_storage[target.origin] = Object.fromEntries(target.local);
    else delete state.local_storage[target.origin];
  }
  return { returnTo };
}

// Chromium drops sessionStorage on exit, so a relaunched profile gets it back
// from the saved checkpoint. Restoring it only after the first load lets an app
// that checks for it on startup bounce to its login page first, so write it
// (and, for a fresh Chromium directory, localStorage) before that load.
function pendingStorageRestore(session, url) {
  const state = session.restoreState;
  if (!state || !url || url === "about:blank") return null;
  let origin;
  try {
    const parsed = new URL(url);
    if (!new Set(["http:", "https:"]).has(parsed.protocol)) return null;
    origin = parsed.origin;
  } catch {
    return null;
  }
  if (session.restoredOrigins?.has(origin)) return null;
  const entries = (values) => Object.entries(values || {}).map(([name, value]) => ({ name, value }));
  const sessionItems = entries(state.session_storage?.[origin]);
  const localItems = session.preferProfileState ? [] : entries(state.local_storage?.[origin]);
  if (!sessionItems.length && !localItems.length) return null;
  return { origin, local_storage: localItems, session_storage: sessionItems, keep_local: !localItems.length };
}

// After seeding: continue to the requested url, or return to the page the tab
// was on (about:blank when there was none).
async function navigateAfterSeed(session, seeded, url) {
  const page = await activePage(session);
  const target = url && url !== "about:blank" ? url : seeded.returnTo;
  if (!target || target === "about:blank") {
    await page.goto("about:blank", { waitUntil: "domcontentloaded", timeout: STORAGE_SEED_STEP_MS });
    return;
  }
  await navigateWithProxyCheck(page, () => page.goto(target, { waitUntil: "domcontentloaded", timeout: 30_000 }));
  await reconcileCurrentOriginStorage(session);
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
  session.identityController?.assertHealthy();
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

// `frame` looks inside one frame of the page instead of its top document, and
// `nth` picks one of several matches: 0 is the first, -1 the last.
function locatorFor(page, descriptor = {}) {
  const root = descriptor.frame == null ? page
    : chooseFrame(childFrames(page).map((frame) => ({ frame, name: frame.name(), url: frame.url() })),
      descriptor.frame).frame;
  const exact = Boolean(descriptor.exact);
  let locator;
  if (descriptor.role) {
    const options = { exact };
    if (descriptor.name != null) options.name = descriptor.name;
    locator = root.getByRole(descriptor.role, options);
  } else if (descriptor.test_id) locator = root.getByTestId(descriptor.test_id);
  else if (descriptor.text != null) locator = root.getByText(descriptor.text, { exact });
  else if (descriptor.css) locator = root.locator(descriptor.css);
  else throw rpcError(-32602, "locator requires role, test_id, text, or css");
  if (descriptor.nth == null) return locator;
  if (!Number.isInteger(descriptor.nth)) throw rpcError(-32602, "locator nth must be an integer");
  return locator.nth(descriptor.nth);
}

// The one frame a selector names: its name equals the selector, or its URL
// contains it. The page's own document is never a candidate.
function chooseFrame(candidates, selector) {
  if (typeof selector !== "string" || !selector) {
    throw rpcError(-32602, "frame must be a frame name or part of its URL");
  }
  const matches = candidates.filter((frame) => frame.name === selector || frame.url.includes(selector));
  const exact = matches.filter((frame) => frame.name === selector || frame.url === selector);
  const chosen = exact.length === 1 ? exact[0] : matches.length === 1 ? matches[0] : null;
  if (chosen) return chosen;
  const listed = (matches.length ? matches : candidates).slice(0, 12)
    .map((frame) => `${publicLocation(frame.url) || "(opaque URL)"}${frame.name ? ` name=${frame.name.slice(0, 64)}` : ""}`)
    .join(", ");
  throw rpcError(-32602, matches.length
    ? `frame matches ${matches.length} frames; give its full URL or name: ${listed}`
    : `frame matches no frame of the selected page; frames: ${listed || "none"}`);
}

const MAX_LISTED_FRAMES = 12;

function childFrames(page) {
  return page.frames().filter((frame) => frame !== page.mainFrame() && !frame.isDetached());
}

async function performWait(page, forWhat, value, timeout) {
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
      await page.waitForURL(value, { timeout });
      return { url: page.url() };
    case "selector":
      await page.locator(value).waitFor({ state: "visible", timeout });
      return { selector: value, state: "visible" };
    case "text":
      await page.getByText(value).first().waitFor({ state: "visible", timeout });
      return { text: value, state: "visible" };
    case "load_state":
      await page.waitForLoadState(value || "domcontentloaded", { timeout });
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
    const summary = {
      page_id: pageId,
      active: page === active,
      url: publicLocation(page.url()),
      title: title ? title.slice(0, 256) : null,
    };
    // What the `frame` of a locator or an evaluation can name. Only the
    // selected page's are listed, and briefly: the result has a byte budget.
    if (page === active) {
      const all = childFrames(page);
      const frames = all.slice(0, MAX_LISTED_FRAMES).map((frame) => {
        const listed = { url: (publicLocation(frame.url()) || "").slice(0, 200) || null };
        if (frame.name()) listed.name = frame.name().slice(0, 64);
        return listed;
      });
      if (frames.length) summary.frames = frames;
      if (all.length > frames.length) summary.frames_omitted = all.length - frames.length;
    }
    summaries.push(summary);
  }
  return summaries.sort((left, right) => left.page_id - right.page_id);
}

function requireRuntimeGeneration(session, value) {
  if (!Number.isSafeInteger(value) || value !== session.runtimeGeneration) {
    throw rpcError(-32001, "page or event cursor belongs to a stale browser runtime; list pages again");
  }
}

async function performPages(session, action) {
  const op = String(action.op ?? "list");
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
    await page.bringToFront();
    if (action.url && action.url !== "about:blank") {
      await navigateWithProxyCheck(page, () => page.goto(action.url, { waitUntil: "domcontentloaded", timeout: 30_000 }));
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
  await (await activePage(session)).bringToFront();
  return { message: "browser page closed", data: {
    runtime_generation: session.runtimeGeneration,
    closed_page_id: pageId,
    pages: await pageSummaries(session),
  } };
}

async function performEvents(session, action) {
  const { after, matching } = eventQuery(session, action);
  await drainWindowMessages(session);
  const events = matching().map(compactEvent);
  const oldestSequence = session.events[0]?.event.sequence ?? session.eventSequence + 1;
  return { message: "browser events read", data: {
    runtime_generation: session.runtimeGeneration,
    events,
    next_sequence: events.length ? events[events.length - 1].sequence : after,
    latest_sequence: session.eventSequence,
    oldest_sequence: oldestSequence,
    cursor_expired: after > 0 && after < oldestSequence - 1,
    dropped_events: session.eventsDropped,
    observer_errors: [...session.messageObservers.entries()]
      .filter(([, state]) => state.error)
      .map(([page, state]) => ({
        page_id: pageIdFor(session, page), observer: "window_message", operation: state.error,
      })),
  } };
}

// An event row without null or empty members. Every row belongs to the
// runtime_generation reported beside the rows, so it is not repeated.
function compactEvent(event) {
  const row = {};
  for (const [key, value] of Object.entries(event)) {
    if (key === "runtime_generation" || value == null || value === "") continue;
    if (typeof value === "object" && !Object.keys(value).length) continue;
    row[key] = value;
  }
  return row;
}

function eventQuery(session, action) {
  const generation = action.runtime_generation == null
    ? session.runtimeGeneration : Number(action.runtime_generation);
  requireRuntimeGeneration(session, generation);
  const after = Number(action.after_sequence || 0);
  const limit = Number(action.limit || 50);
  const kinds = new Set(Array.isArray(action.kinds) ? action.kinds : []);
  const matching = () => session.events
    .map((entry) => entry.event)
    .filter((event) => event.sequence > after && (!kinds.size || kinds.has(event.kind)))
    .slice(0, limit);
  return { after, matching };
}

// Waits up to `waitMs` for an event the query would return, without extracting
// a checkpoint. The worker serves one request at a time, so callers chain short
// waits and the other sessions of the project are served in between.
async function waitForEvents(session, action, waitMs) {
  const { matching } = eventQuery(session, action);
  const deadline = Date.now() + Math.min(Math.max(Number(waitMs) || 0, 0), MAX_EVENT_WAIT_MS);
  for (;;) {
    await drainWindowMessages(session);
    if (matching().length) return { ready: true };
    const remaining = deadline - Date.now();
    if (remaining <= 0) return { ready: false };
    await new Promise((resolve) => setTimeout(resolve, Math.min(EVENT_POLL_MS, remaining)));
  }
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
        // "manual" stops at a redirect without following it; page fetch then
        // reports it as an opaque response with no status or body.
        redirect: request.follow_redirects ? "follow" : "manual",
        signal: controller.signal,
      };
      if (request.body_text !== null) options.body = request.body_text;
      if (request.body_base64 !== null) options.body = decodeBase64(request.body_base64);
      const response = await fetch(request.url, options);
      if (response.type === "opaqueredirect") return { huntproxy_error: "redirect" };
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
    follow_redirects: action.follow_redirects === true,
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
  if (result.huntproxy_error === "redirect") {
    throw rpcError(-32000, "browser request got a redirect, which page fetch cannot expose; pass follow_redirects:true "
      + "to follow it, or find the 3xx response in history_search or resend it with reply_send");
  }
  if (result.huntproxy_error) {
    throw rpcError(-32000, "browser request failed without a response (network error, CORS or CSP); it was not retried");
  }
  return { message: "browser request completed", data: result };
}

function proxyErrorMarker(response) {
  const marker = response?.headers()["x-huntproxy-proxy-error"];
  return typeof marker === "string" && marker.startsWith("v1:") ? marker : null;
}

async function navigateWithProxyCheck(page, operation) {
  const context = page.context();
  const workerResponses = [];
  let notify;
  const onResponse = (response) => {
    if (!response.fromServiceWorker() && response.request().serviceWorker() && proxyErrorMarker(response)) {
      workerResponses.push(response);
      notify?.();
    }
  };
  context.on("response", onResponse);
  try {
    const response = await operation();
    const marker = proxyErrorMarker(response);
    if (!marker) return response;
    let source = response;
    if (response.fromServiceWorker()) {
      const match = () => workerResponses.find((candidate) => candidate.url() === response.url()
        && candidate.request().method() === response.request().method() && proxyErrorMarker(candidate) === marker);
      source = match();
      if (!source) {
        await new Promise((resolve) => {
          const timer = setTimeout(resolve, 150);
          notify = () => { if (match()) { clearTimeout(timer); resolve(); } };
        });
        source = match();
      }
      if (!source) return response;
    }
    const message = Buffer.from(marker.slice(3), "base64").toString("utf8").trim().slice(0, 4096);
    throw rpcError(-32000, message
      ? `HuntProxy proxy error: ${message}`
      : `HuntProxy proxy error (HTTP ${source.status()})`);
  } finally {
    context.off("response", onResponse);
  }
}

// The MCP output budget. HuntProxy cuts the final result to fit exactly; a
// larger slice could never be returned, so the worker never sends one.
const MAX_SNAPSHOT_BYTES = 24_000;

// The CDP session that runs `frame`'s JavaScript: its own when it is a
// cross-process frame, otherwise its nearest such ancestor's or the page's.
async function frameSession(session, page, frame) {
  for (let current = frame; current && current !== page.mainFrame(); current = current.parentFrame()) {
    try {
      return await session.context.newCDPSession(current);
    } catch {
      // A same-process frame shares an ancestor's session.
    }
  }
  return session.context.newCDPSession(page);
}

// Runs a fixed HuntProxy function on the element `locator` resolves to. Page
// code can redefine DOM getters to never return, so the evaluation is
// terminated after one second.
async function evaluateElement(session, page, locator, fn, timeout) {
  const element = await locator.elementHandle({ timeout });
  let connection;
  let termination;
  let timer;
  try {
    connection = await frameSession(session, page, await element.ownerFrame());
    timer = setTimeout(() => {
      termination = connection.send("Runtime.terminateExecution").catch(() => undefined);
    }, 1000);
    return await element.evaluate(fn);
  } finally {
    clearTimeout(timer);
    if (termination) await termination;
    await element.dispose().catch(() => undefined);
    await connection?.detach().catch(() => undefined);
  }
}

// The UTF-8 bytes of `content` from `offset`, at most `maxBytes` of them, cut
// on character boundaries. `next_offset` continues exactly where this ends.
function snapshotSlice(content, offset, maxBytes) {
  const bytes = Buffer.from(String(content), "utf8");
  const continuation = (index) => index < bytes.length && (bytes[index] & 0xc0) === 0x80;
  let start = Math.min(offset, bytes.length);
  while (continuation(start)) start += 1;
  let end = Math.min(start + maxBytes, bytes.length);
  while (end > start && continuation(end)) end -= 1;
  // Always advance, even when one character is larger than maxBytes.
  if (end === start && start < bytes.length) {
    end += 1;
    while (continuation(end)) end += 1;
  }
  const slice = {
    content: bytes.subarray(start, end).toString("utf8"),
    truncated: end < bytes.length,
    total_bytes: bytes.length,
  };
  if (start) slice.offset = start;
  if (end < bytes.length) slice.next_offset = end;
  return slice;
}

async function performSnapshot(session, page, action) {
  // Anything but "dom" is the accessibility tree; report the format produced.
  const format = action.format === "dom" ? "dom" : "accessibility";
  const offset = Number(action.offset ?? 0);
  if (!Number.isSafeInteger(offset) || offset < 0) {
    throw rpcError(-32602, "snapshot offset must be a non-negative integer");
  }
  const maxBytes = Math.max(1, Math.min(Number(action.max_bytes) || MAX_SNAPSHOT_BYTES, MAX_SNAPSHOT_BYTES));
  const timeout = actionTimeout(action, NAVIGATION_TIMEOUT_MS);
  let content;
  if (!action.locator) {
    content = format === "dom" ? await page.content() : await page.locator("body").ariaSnapshot({ timeout });
  } else if (format === "dom") {
    content = await evaluateElement(session, page, locatorFor(page, action.locator),
      (element) => element.outerHTML, timeout);
  } else {
    content = await locatorFor(page, action.locator).ariaSnapshot({ timeout });
  }
  return { message: "snapshot captured", data: { format, ...snapshotSlice(content, offset, maxBytes) } };
}

// Characters of result data the page builds before it stops descending.
const MAX_EVALUATE_RESULT_CHARS = 1_000_000;

// `() => ...`, `async x => ...` and `function ...` sources are called, so the
// function style other browser tools take works as well as a plain expression.
const FUNCTION_SOURCE = /^\s*(?:async\s+)?(?:function\b|\([^()]*\)\s*=>|[A-Za-z_$][\w$]*\s*=>)/;

// A leading `{` or `function` is a statement to JavaScript: `{a: 1}` is a
// block that yields 1 and a function declaration yields nothing.
const STATEMENT_LOOKALIKE = /^\s*(?:\{|(?:async\s+)?function\b)/;

const EVALUATE_INTERRUPTED = /navigated or closed|context was destroyed|cannot find context|could not find object|has been closed/i;

// Runs in the page on the value an expression produced and returns it as data
// CDP can copy out. Chromium's own deep serialization hangs and then kills the
// browser when a getter throws, so every read here is guarded instead.
// Strings, DOM nodes, errors and a returned function become text; anything
// else becomes JSON data that stops at a depth and size limit.
async function describeEvaluationResult(value, call, maxChars) {
  if (call && typeof value === "function") value = value();
  // Only a promise is waited for, from any frame's realm. An object that just
  // has a then method is a value to show, as the console shows it; awaiting
  // it would wait for a call that may never come.
  let promise = false;
  try {
    promise = Object.prototype.toString.call(value) === "[object Promise]";
  } catch {
    // A cross-origin object: described below as unreadable.
  }
  if (promise) value = await value;
  const MAX_DEPTH = 8;
  const MAX_NESTED_NODE_CHARS = 400;
  let remaining = maxChars;
  const ancestors = [];
  const isNode = (item) => typeof item.nodeType === "number" && typeof item.nodeName === "string";
  // Never counts more than the JSON takes, so a result cut here is always
  // larger than what the worker goes on to return.
  const text = (string, limit) => {
    string = String(string);
    if (limit && string.length > limit) string = `${string.slice(0, limit)}…`;
    if (string.length > remaining) string = string.slice(0, Math.max(remaining, 0));
    remaining -= string.length + 2;
    return string;
  };
  const nodeText = (node) => {
    if (node.nodeType === 1) return node.outerHTML;
    if (node.nodeType === 2) return `${node.name}="${node.value}"`;
    if (node.nodeType === 9) return node.documentElement ? node.documentElement.outerHTML : "#document";
    return node.nodeValue ?? node.innerHTML ?? node.textContent ?? node.nodeName;
  };
  const describe = (item, depth) => {
    const kind = typeof item;
    if (kind === "undefined") return undefined;
    if (item === null || kind === "boolean") {
      remaining -= 4;
      return item;
    }
    if (kind === "number") {
      remaining -= 1;
      return Number.isFinite(item) ? item : String(item);
    }
    if (kind === "string") return text(item);
    if (kind === "bigint") return text(`${item}n`);
    if (kind === "symbol") return text(item.toString());
    try {
      if (kind === "function") {
        return depth
          ? text(`[Function${item.name ? `: ${item.name}` : ""}]`, 120)
          : text(Function.prototype.toString.call(item));
      }
      // A cross-origin window allows `window` and refuses nearly everything else.
      if (item.window === item) return text("[Window]");
      if (isNode(item)) return text(nodeText(item), depth ? MAX_NESTED_NODE_CHARS : 0);
      const tag = Object.prototype.toString.call(item).slice(8, -1);
      if (tag === "Error" || tag === "DOMException") return text(`${item.name}: ${item.message}`);
      if (tag === "RegExp") return text(item);
      if (ancestors.includes(item)) return text("[Circular]");
      if (typeof item.toJSON === "function") {
        const json = item.toJSON();
        if (json !== item) return describe(json, depth);
      }
      if (depth >= MAX_DEPTH) return text(`[${tag}]`);
      remaining -= 2;
      ancestors.push(item);
      try {
        if (typeof item[Symbol.iterator] === "function") {
          const list = [];
          for (const entry of item) {
            if (remaining <= 0) break;
            list.push(describe(entry, depth + 1) ?? null);
          }
          return list;
        }
        // No prototype, so a `__proto__` key is kept as an ordinary member.
        const members = Object.create(null);
        let kept = 0;
        for (const key in item) {
          if (remaining <= 0) break;
          let member;
          try {
            member = item[key];
          } catch (error) {
            member = `[Throws: ${error?.message}]`;
          }
          // Methods a platform object inherits say nothing about its state.
          if (typeof member === "function" && !Object.hasOwn(item, key)) continue;
          const described = describe(member, depth + 1);
          if (described === undefined) continue;
          remaining -= key.length + 3;
          members[key] = described;
          kept += 1;
        }
        // An object that exposes nothing is named, never shown as `{}`.
        return kept || tag === "Object" ? members : text(`[${tag}]`);
      } finally {
        ancestors.pop();
      }
    } catch (error) {
      return text(`[Unreadable: ${error?.message}]`, 200);
    }
  };
  let type = value === null ? "null" : typeof value;
  if (type === "object") {
    try {
      if (value.window !== value && isNode(value)) type = "node";
    } catch {
      // A cross-origin object: reported by describe as unreadable.
    }
  }
  return { type, value: describe(value, 0) };
}

// The CDP session and execution context an expression runs in: the selected
// page, or with `selector` the one frame of it whose name equals the selector
// or whose URL contains it. A cross-process frame has a CDP session of its
// own; a same-process frame shares its nearest such ancestor's and is reached
// through its default execution context.
async function evaluationTarget(session, page, selector) {
  if (selector == null) {
    const connection = await session.context.newCDPSession(page);
    return { connection, connections: [connection] };
  }
  const connections = [];
  try {
    const frames = [];
    for (const frame of page.frames()) {
      let connection;
      try {
        connection = await session.context.newCDPSession(frame);
      } catch {
        continue; // Listed in the frame tree of an ancestor's session.
      }
      connections.push(connection);
      const main = frame === page.mainFrame();
      const visit = (node, root) => {
        if (!(main && root)) {
          frames.push({ connection, root, id: node.frame.id, name: node.frame.name || "",
            url: `${node.frame.url}${node.frame.urlFragment || ""}` });
        }
        for (const child of node.childFrames || []) visit(child, false);
      };
      visit((await connection.send("Page.getFrameTree")).frameTree, true);
    }
    const chosen = chooseFrame(frames, selector);
    let contextId;
    if (!chosen.root) {
      const contexts = [];
      chosen.connection.on("Runtime.executionContextCreated", (event) => contexts.push(event.context));
      await chosen.connection.send("Runtime.enable");
      contextId = contexts.find((context) => context.auxData?.frameId === chosen.id && context.auxData?.isDefault)?.id;
      if (!contextId) throw rpcError(-32000, "evaluate frame has no JavaScript context yet; retry once it has loaded");
    }
    return { connection: chosen.connection, contextId, url: chosen.url, connections };
  } catch (error) {
    await Promise.all(connections.map((connection) => connection.detach().catch(() => undefined)));
    throw error;
  }
}

// The text an evaluation reports: a string as it is, anything else as JSON.
function evaluationContent(value) {
  if (typeof value === "string") return value;
  return value === undefined ? "undefined" : JSON.stringify(value);
}

// An object or array result returned as it is, so the caller reads JSON
// instead of JSON encoded in a string; undefined when it is something else or
// too large to return whole, and then it is reported as text that can be cut.
function evaluationValue(value) {
  if (value === null || typeof value !== "object") return undefined;
  return Buffer.byteLength(JSON.stringify(value)) <= MAX_SNAPSHOT_BYTES ? value : undefined;
}

// Runs agent JavaScript in the main world of the selected page, or of one of
// its frames, the way the DevTools console does: statements and top-level
// await are allowed, declarations can be repeated between calls, and the
// console helpers such as getEventListeners() are in scope. CDP evaluation is
// not subject to the page's CSP.
async function performEvaluate(session, page, action) {
  const timeout = action.timeout_ms ?? 10_000;
  if (typeof action.expression !== "string" || !action.expression.trim()
      || !Number.isInteger(timeout) || timeout < 1 || timeout > 30_000) {
    throw rpcError(-32602, "evaluate requires an expression and timeout_ms in 1..30000");
  }
  let target;
  let abandoned = false;
  const run = async () => {
    // Finding the frame is part of the work the deadline covers.
    target = await evaluationTarget(session, page, action.frame);
    if (abandoned) return null;
    const { connection } = target;
    const context = target.contextId ? { contextId: target.contextId } : {};
    let expression = action.expression;
    let call = false;
    if (STATEMENT_LOOKALIKE.test(expression) || FUNCTION_SOURCE.test(expression)) {
      // Read it as the expression it looks like when it parses as one, as the
      // DevTools console does. Compiling runs nothing and needs the domain on.
      const wrapped = `(${expression}\n)`;
      await connection.send("Runtime.enable");
      const compiled = await connection.send("Runtime.compileScript", {
        expression: wrapped, sourceURL: "", persistScript: false,
        ...(target.contextId ? { executionContextId: target.contextId } : {}),
      });
      if (!compiled.exceptionDetails) {
        expression = wrapped;
        // Only a source that is one function is called. A function that
        // statements merely end with is a value to show, not to run.
        call = FUNCTION_SOURCE.test(action.expression);
      }
    }
    const evaluated = await connection.send("Runtime.evaluate", {
      expression, replMode: true, awaitPromise: true, userGesture: true,
      includeCommandLineAPI: true, ...context,
    });
    if (evaluated.exceptionDetails) return { exception: evaluated.exceptionDetails };
    const remote = evaluated.result;
    if (!remote.objectId) {
      if (remote.type === "undefined") return { type: "undefined" };
      if (remote.subtype === "null") return { type: "null", value: null };
      return { type: remote.type, value: remote.unserializableValue ?? remote.value };
    }
    // Calls a function source, awaits a promise, and copies the result out.
    const described = await connection.send("Runtime.callFunctionOn", {
      objectId: remote.objectId,
      functionDeclaration: describeEvaluationResult.toString(),
      arguments: [{ objectId: remote.objectId }, { value: call }, { value: MAX_EVALUATE_RESULT_CHARS }],
      awaitPromise: true, returnByValue: true, userGesture: true,
    });
    if (described.exceptionDetails) return { exception: described.exceptionDetails };
    return described.result.value;
  };
  const release = () => Promise.all((target?.connections || []).map((opened) => opened.detach().catch(() => undefined)));
  let timer;
  let termination;
  let outcome;
  const work = run();
  work.catch(() => undefined); // Still pending when the deadline wins.
  try {
    outcome = await Promise.race([work, new Promise((_, reject) => {
      timer = setTimeout(() => {
        abandoned = true;
        // Stops a synchronous loop. A promise that never settles stays with the page.
        termination = target?.connection.send("Runtime.terminateExecution").catch(() => undefined);
        reject(rpcError(-32000,
          `evaluate timed out after ${timeout} ms; the expression may still be running in the page`));
      }, timeout);
    })]);
  } catch (error) {
    if (!Number.isSafeInteger(error?.code) && EVALUATE_INTERRUPTED.test(String(error?.message))) {
      throw rpcError(-32000, "evaluate was interrupted because the page or frame navigated or closed");
    }
    throw error;
  } finally {
    clearTimeout(timer);
    // The page must be responsive again before the next action; a renderer
    // that cannot stop is not waited for.
    if (termination) await Promise.race([termination, new Promise((resolve) => setTimeout(resolve, 2_000))]);
    // A frame found only after the deadline is let go of when it turns up.
    if (target) await release();
    else void work.then(release, release);
  }
  const thrown = outcome.exception;
  const native = evaluationValue(thrown ? undefined : outcome.value);
  if (native !== undefined) {
    const data = { type: outcome.type, value: native };
    if (target.url !== undefined) data.frame_url = publicLocation(target.url);
    return { message: "expression evaluated", data };
  }
  const content = thrown
    // The stack of a called function source ends in the function that called it here.
    ? String(thrown.exception?.description ?? thrown.exception?.value ?? thrown.text)
      .split("\n").filter((line) => !line.includes(describeEvaluationResult.name)).join("\n")
    : evaluationContent(outcome.value);
  const { next_offset: _unpaged, ...slice } = snapshotSlice(content, 0, MAX_SNAPSHOT_BYTES);
  const data = { type: thrown ? "exception" : outcome.type, ...slice };
  if (target.url !== undefined) data.frame_url = publicLocation(target.url);
  return { message: thrown ? "expression threw" : "expression evaluated", data };
}

// Interactions that can return the resulting page with `snapshot: true`.
const SNAPSHOT_AFTER_ACTIONS = new Set([
  "navigate", "click", "fill", "select", "press", "wait", "back", "forward", "pointer", "type",
]);

// The accessibility snapshot of the active page once the action has settled:
// Playwright has waited for any navigation the action started to commit, and
// this waits for its DOM like navigate does. A failure is reported beside the
// action result, which already happened and must not look failed.
// `maxBytes` bounds it as the snapshot action's max_bytes does.
async function snapshotAfterAction(session, maxBytes) {
  try {
    const page = await activePage(session);
    for (let attempt = 1; ; attempt += 1) {
      await page.waitForLoadState("domcontentloaded", { timeout: 30_000 });
      try {
        const content = await page.locator("body").ariaSnapshot({ timeout: 30_000 });
        return snapshotSlice(content, 0, Math.max(1, Math.min(Number(maxBytes) || MAX_SNAPSHOT_BYTES, MAX_SNAPSHOT_BYTES)));
      } catch (error) {
        // A navigation can replace the document during the capture; retry once on the new one.
        if (attempt > 1 || !/context was destroyed|navigat/i.test(String(error?.message))) throw error;
      }
    }
  } catch (error) {
    return { error: String(error?.message || error).split("\n")[0].slice(0, 512) };
  }
}

const POINTER_BUTTONS = new Set(["left", "right", "middle"]);
const POINTER_MODIFIERS = new Set(["Alt", "Control", "Meta", "Shift"]);
const MAX_POINTER_COORDINATE = 100_000;
const MAX_TYPE_BYTES = 4096;
const TYPE_TIMEOUT_MS = 30_000;

// A viewport point of the selected page, in CSS pixels, or null when neither
// coordinate was given.
function pointerPoint(x, y, label) {
  if (x == null && y == null) return null;
  const valid = (value) => Number.isFinite(value) && value >= 0 && value <= MAX_POINTER_COORDINATE;
  if (!valid(x) || !valid(y)) throw rpcError(-32602, `${label} x and y must both be 0..${MAX_POINTER_COORDINATE}`);
  return { x, y };
}

// Where a pointer action aims: the point given, or the centre of the element
// a locator resolves to once it has been scrolled into view.
async function pointerTarget(page, locator, point, label, scroll, timeout) {
  if (Boolean(locator) === Boolean(point)) {
    throw rpcError(-32602, `${label} requires either a locator or x and y`);
  }
  if (point) return point;
  const element = locatorFor(page, locator);
  if (scroll) await element.scrollIntoViewIfNeeded({ timeout });
  const box = await element.boundingBox({ timeout });
  if (!box) throw rpcError(-32000, `${label} element is not visible`);
  return { x: box.x + box.width / 2, y: box.y + box.height / 2 };
}

// What lies under a viewport point, followed through open shadow roots and
// into frames, briefly described. A click at a point has no actionability
// check, so this is how its caller learns whether it hit what was meant.
// Found before the click, which may navigate or remove the element.
async function elementAtPoint(page, point) {
  let frame = page.mainFrame();
  let { x, y } = point;
  for (let depth = 0; depth < 4; depth += 1) {
    const handle = await frame.evaluateHandle(([x, y]) => {
      let node = document.elementFromPoint(x, y);
      while (node?.shadowRoot) {
        const inner = node.shadowRoot.elementFromPoint(x, y);
        if (!inner || inner === node) break;
        node = inner;
      }
      return node;
    }, [x, y]);
    const element = handle.asElement();
    if (!element) {
      await handle.dispose();
      return null;
    }
    try {
      const found = await element.evaluate((node) => {
        const text = (node.innerText || node.getAttribute("aria-label") || node.getAttribute("placeholder")
          || node.getAttribute("alt") || node.getAttribute("title") || "").replace(/\s+/g, " ").trim();
        const box = node.getBoundingClientRect();
        const style = getComputedStyle(node);
        return {
          described: {
            tag: node.localName,
            id: node.id ? node.id.slice(0, 64) : undefined,
            role: node.getAttribute("role")?.slice(0, 32) || undefined,
            text: text ? text.slice(0, 80) : undefined,
          },
          // Where the frame's own viewport starts, inside border and padding.
          left: box.left + node.clientLeft + parseFloat(style.paddingLeft),
          top: box.top + node.clientTop + parseFloat(style.paddingTop),
        };
      });
      const child = /^i?frame$/.test(found.described.tag) ? await element.contentFrame() : null;
      if (!child) {
        return frame === page.mainFrame() ? found.described
          : { ...found.described, frame: publicLocation(frame.url()) || frame.name().slice(0, 64) || null };
      }
      frame = child;
      x -= found.left;
      y -= found.top;
    } finally {
      await handle.dispose();
    }
  }
  return null;
}

// Holds modifier keys around pointer input given as a point; Playwright only
// takes them as an option for input aimed at a locator.
async function holdingModifiers(page, modifiers, run) {
  for (const key of modifiers) await page.keyboard.down(key);
  try {
    return await run();
  } finally {
    for (const key of [...modifiers].reverse()) await page.keyboard.up(key).catch(() => undefined);
  }
}

// Mouse input the locator actions cannot express: any button, repeated
// clicks, held modifiers, hovering, dragging, and points instead of elements.
async function performPointer(page, action) {
  const button = action.button ?? "left";
  const count = action.count ?? 1;
  const modifiers = action.modifiers ?? [];
  const timeout = actionTimeout(action, LOCATOR_TIMEOUT_MS);
  if (!POINTER_BUTTONS.has(button) || !Number.isInteger(count) || count < 1 || count > 3
      || !Array.isArray(modifiers) || modifiers.some((key) => !POINTER_MODIFIERS.has(key))) {
    throw rpcError(-32602,
      "pointer button must be left|right|middle, count 1..3, and modifiers Alt|Control|Meta|Shift");
  }
  const point = pointerPoint(action.x, action.y, "pointer");
  const destination = pointerPoint(action.to_x, action.to_y, "pointer destination");
  if (action.op !== "drag" && (destination || action.to_locator)) {
    throw rpcError(-32602, "pointer destination applies to drag only");
  }
  const rounded = ({ x, y }) => ({ x: Math.round(x * 100) / 100, y: Math.round(y * 100) / 100 });
  switch (action.op) {
    case "click":
      if (Boolean(action.locator) === Boolean(point)) {
        throw rpcError(-32602, "pointer click requires either a locator or x and y");
      }
      // An element gets Playwright's actionability checks; a point is clicked
      // as it is, and the result names what it landed on.
      if (action.locator) {
        await locatorFor(page, action.locator).click({ button, clickCount: count, modifiers, timeout });
        return { message: "pointer clicked", data: { url: page.url() } };
      }
      {
        // A page busy navigating has nothing to describe; the click still goes.
        const hit = await elementAtPoint(page, point).catch(() => null);
        await holdingModifiers(page, modifiers, () => page.mouse.click(point.x, point.y, { button, clickCount: count }));
        const named = hit ? ` ${hit.tag}${hit.id ? `#${hit.id}` : ""}${hit.frame ? " in a frame" : ""}` : "";
        return { message: `pointer clicked${named}`, data: { url: page.url(), hit } };
      }
    case "hover":
      if (Boolean(action.locator) === Boolean(point)) {
        throw rpcError(-32602, "pointer hover requires either a locator or x and y");
      }
      if (action.locator) await locatorFor(page, action.locator).hover({ modifiers, timeout });
      else await holdingModifiers(page, modifiers, () => page.mouse.move(point.x, point.y));
      return { message: "pointer moved", data: null };
    case "drag": {
      // Both ends are found before the button goes down: a destination that
      // failed afterwards would release over the source, which clicks it.
      // A point is a place in the viewport, so scrolling would change what
      // lies under it: with a point at either end nothing is scrolled, and an
      // element end has to be in view already.
      const scroll = !point && !destination;
      let from = await pointerTarget(page, action.locator, point, "pointer drag", scroll, timeout);
      const to = await pointerTarget(page, action.to_locator, destination, "pointer drag destination", scroll, timeout);
      if (scroll) {
        // Bringing the destination into view may have moved the source.
        from = await pointerTarget(page, action.locator, point, "pointer drag", false, timeout);
      }
      if (action.locator || action.to_locator) {
        const view = await page.evaluate(() => ({ width: window.innerWidth, height: window.innerHeight }));
        const outside = ({ x, y }) => x < 0 || y < 0 || x > view.width || y > view.height;
        if (scroll && outside(from)) {
          throw rpcError(-32000, "pointer drag source and destination are not in view together");
        }
        for (const [end, place, element] of [["source", from, action.locator], ["destination", to, action.to_locator]]) {
          if (!scroll && element && outside(place)) {
            throw rpcError(-32000, `pointer drag ${end} element is out of view; a drag that uses x and y does not scroll, so scroll it into view first or aim both ends at elements`);
          }
        }
      }
      return holdingModifiers(page, modifiers, async () => {
        await page.mouse.move(from.x, from.y);
        await page.mouse.down({ button });
        try {
          // Drag-and-drop code follows the movement, not only where it ends.
          await page.mouse.move(to.x, to.y, { steps: 12 });
        } finally {
          await page.mouse.up({ button });
        }
        return { message: "pointer dragged", data: { from: rounded(from), to: rounded(to) } };
      });
    }
    default:
      throw rpcError(-32602, "pointer op must be click|hover|drag");
  }
}

// Sends text as keystrokes, which editors, autocomplete fields and one-character
// inputs react to; fill only replaces a value. Without a locator the keys go to
// whatever has focus, in any frame.
async function performType(page, action) {
  const text = action.text;
  if (typeof text !== "string" || !text || Buffer.byteLength(text) > MAX_TYPE_BYTES) {
    throw rpcError(-32602, `type requires text of 1..${MAX_TYPE_BYTES} bytes`);
  }
  if (action.locator) {
    const timeout = actionTimeout(action, LOCATOR_TIMEOUT_MS);
    const element = locatorFor(page, action.locator);
    await element.focus({ timeout });
    // Focusing leaves the caret at the start of what a field holds; a person
    // clicking in to add text puts it at the end, and so does this.
    const placed = await element.evaluate((node) => {
      if (node.isContentEditable) {
        const range = node.ownerDocument.createRange();
        range.selectNodeContents(node);
        range.collapse(false);
        const selection = node.ownerDocument.getSelection();
        selection.removeAllRanges();
        selection.addRange(range);
        return true;
      }
      if (typeof node.value !== "string" || typeof node.setSelectionRange !== "function") return true;
      try {
        node.setSelectionRange(node.value.length, node.value.length);
        return true;
      } catch {
        // Email and number inputs have no selection API, so End moves their
        // caret. On a slider, radio button or date field End changes the
        // value, so those keep the caret where focus put it.
        return node.type !== "email" && node.type !== "number";
      }
    }, undefined, { timeout });
    if (!placed) await page.keyboard.press("End");
  }
  // One character at a time, so a page whose key handlers are slow is given
  // up on at a deadline instead of being typed at until the worker is killed.
  const characters = [...text];
  const deadline = Date.now() + TYPE_TIMEOUT_MS;
  for (const [index, character] of characters.entries()) {
    if (Date.now() > deadline) {
      throw rpcError(-32000,
        `type timed out after ${TYPE_TIMEOUT_MS} ms; ${index} of ${characters.length} characters were sent`);
    }
    await page.keyboard.type(character);
  }
  return { message: "text typed", data: { characters: characters.length } };
}

const PAGE_ACTIONS = new Set([
  "navigate", "snapshot", "click", "fill", "select", "upload", "inspect", "evaluate",
  "pointer", "type", "scroll", "screenshot", "press", "wait", "back", "forward",
]);

const LOCATOR_TIMEOUT_MS = 10_000;
const NAVIGATION_TIMEOUT_MS = 30_000;
const CALL_LOG_LINES = 4;

// The action's timeout_ms, or `fallback` when it has none.
function actionTimeout(action, fallback) {
  const timeout = action.timeout_ms ?? fallback;
  if (!Number.isInteger(timeout) || timeout < 1 || timeout > 30_000) {
    throw rpcError(-32602, "timeout_ms must be 1..30000");
  }
  return timeout;
}

// Playwright options for navigate, back and forward.
function navigation(action) {
  const waitUntil = action.wait_until ?? "domcontentloaded";
  if (!["load", "domcontentloaded", "networkidle"].includes(waitUntil)) {
    throw rpcError(-32602, "wait_until must be load|domcontentloaded|networkidle");
  }
  return { waitUntil, timeout: actionTimeout(action, NAVIGATION_TIMEOUT_MS) };
}

// Playwright follows a failed locator action with a call log that repeats
// every retry. Say what went wrong and what to do about it instead, keeping
// only the first lines of the log.
function actionError(error, action) {
  // Playwright dims its call log with terminal escapes.
  const message = String(error?.message || "").replace(/\x1b\[[0-9;]*m/g, "");
  const located = action.locator || action.to_locator
    || (action.type === "wait" && ["selector", "text"].includes(action.for_what));
  if (Number.isSafeInteger(error?.code) || !located) return error;
  const [head, log = ""] = message.split("\nCall log:");
  const summary = head.trimEnd();
  const lines = log.split("\n").map((line) => line.trim().replace(/^-\s*/, "")).filter(Boolean);
  const target = lines.find((line) => line.startsWith("waiting for "))?.slice("waiting for ".length)
    .replace(/ to be (?:visible|hidden|attached|detached)$/, "")
    ?? JSON.stringify(action.locator || action.to_locator || action.value);
  const milliseconds = Number(/Timeout (\d+)ms exceeded/.exec(summary)?.[1] ?? action.timeout_ms);
  const blocker = lines.find((line) => line.endsWith(" intercepts pointer events"));
  let text;
  if (message.includes("strict mode violation") && (action.locator || action.to_locator)) {
    text = `${summary}\nSet nth on the locator to pick one of them: 0 is the first, -1 the last.`;
  } else if (message.includes("Element is not a <select> element")) {
    text = `${summary}\nThis is not a native <select>, so it is probably a custom listbox: click it, then click the option.`;
  } else if (message.includes("Node is not an HTMLInputElement")) {
    text = `${summary}\nupload sets files on an input[type=file]: target that input, even when it is hidden, `
      + "or pass via_chooser:true to click the control that opens the file dialog.";
  } else if (blocker) {
    const element = blocker.slice(0, -" intercepts pointer events".length).slice(0, 300);
    // A forced click would land on that element too: real input goes to
    // whatever is on top. Only a click dispatched to the element reaches it.
    text = `${target} was found, but ${element} intercepts pointer events, so the click could not land`
      + `${milliseconds ? ` within ${milliseconds} ms` : ""}. Close the overlay first (press Escape or click its close control), `
      + "or click the element itself from browser_evaluate with element.click().";
  } else if (/Timeout \d+ms exceeded/.test(summary) && !lines.some((line) => line.includes("resolved to"))) {
    text = `no element matched ${target} within ${milliseconds} ms; take a snapshot to see what is on the page`;
  } else if (lines.length) {
    text = `${summary}\nCall log:\n${lines.slice(0, CALL_LOG_LINES).map((line) => `  - ${line}`).join("\n")}`;
  } else {
    return error;
  }
  return rpcError(-32000, text);
}

const FRAME_WAIT_MS = 5_000;

// A frame that is still being added, or has not yet loaded the document its
// URL names, matches nothing for a moment. An action naming such a frame waits
// up to FRAME_WAIT_MS for it before chooseFrame reports what is there.
async function awaitNamedFrames(page, action) {
  const selectors = [action.locator?.frame, action.to_locator?.frame, action.type === "evaluate" ? action.frame : null]
    .filter((selector) => typeof selector === "string" && selector);
  const missing = () => selectors.some((selector) => !childFrames(page)
    .some((frame) => frame.name() === selector || frame.url().includes(selector)));
  for (const deadline = Date.now() + FRAME_WAIT_MS; missing() && Date.now() < deadline && !page.isClosed();) {
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
}

async function executeAction(session, action = {}) {
  let result;
  try {
    result = await performAction(session, action);
  } catch (error) {
    throw actionError(error, action);
  }
  // A fixed pause for what the action set off, such as a page that renders
  // after a click, instead of a separate wait action.
  if (action.wait_ms > 0 && WAIT_AFTER_ACTIONS.has(action.type)) {
    await new Promise((resolve) => setTimeout(resolve, action.wait_ms));
  }
  if (action.snapshot === true && SNAPSHOT_AFTER_ACTIONS.has(action.type)) {
    result.data = { ...result.data, snapshot: await snapshotAfterAction(session, action.max_bytes) };
  }
  return result;
}

const WAIT_AFTER_ACTIONS = new Set(["navigate", "click", "fill", "select", "press", "type", "back", "forward"]);

async function performAction(session, action) {
  const page = await activePage(session);
  // A popup can take foreground focus without changing the selected page.
  // Restore it before page actions so Chromium runs animation frames and
  // Playwright can complete its actionability checks.
  if (PAGE_ACTIONS.has(action.type)) await page.bringToFront();
  await awaitNamedFrames(page, action);
  switch (action.type) {
    case "navigate": {
      const response = await navigateWithProxyCheck(page, () => page.goto(action.url, navigation(action)));
      await reconcileCurrentOriginStorage(session);
      return { message: "navigation completed", data: { url: page.url(), status: response?.status() ?? null } };
    }
    case "snapshot":
      return performSnapshot(session, page, action);
    case "click":
      await locatorFor(page, action.locator).click({ timeout: actionTimeout(action, LOCATOR_TIMEOUT_MS) });
      return { message: "element clicked", data: { url: page.url() } };
    case "fill":
      await locatorFor(page, action.locator).fill(action.value ?? "", { timeout: actionTimeout(action, LOCATOR_TIMEOUT_MS) });
      return { message: "field filled", data: null };
    case "select":
      await locatorFor(page, action.locator).selectOption(action.value, { timeout: actionTimeout(action, LOCATOR_TIMEOUT_MS) });
      return { message: "option selected", data: null };
    case "upload":
      return uploadFiles(session, action);
    case "inspect":
      return inspectRuntime(session, action);
    case "evaluate":
      return performEvaluate(session, page, action);
    case "pointer":
      return performPointer(page, action);
    case "type":
      return performType(page, action);
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
        await locatorFor(page, action.locator).press(action.key, { timeout: actionTimeout(action, LOCATOR_TIMEOUT_MS) });
      } else {
        await page.keyboard.press(action.key);
      }
      return { message: "key pressed", data: null };
    case "wait":
      return {
        message: "wait completed",
        data: await performWait(page, action.for_what, action.value, actionTimeout(action, NAVIGATION_TIMEOUT_MS)),
      };
    case "back": {
      const response = await navigateWithProxyCheck(page, () => page.goBack(navigation(action)));
      await reconcileCurrentOriginStorage(session);
      return { message: "went back", data: { url: page.url(), status: response?.status() ?? null } };
    }
    case "forward": {
      const response = await navigateWithProxyCheck(page, () => page.goForward(navigation(action)));
      await reconcileCurrentOriginStorage(session);
      return { message: "went forward", data: { url: page.url(), status: response?.status() ?? null } };
    }
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
    sandbox_state: session.sandbox_state ?? null,
    sandbox_reason: session.sandbox_reason ?? null,
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
          runtime: browserRuntime,
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
        // Given up on while it waited behind other starts: never launch it.
        if (abortedStarts.delete(sessionId)) throw rpcError(-32000, "browser session was aborted while it launched");
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
        const session = {
          engine,
          proxy: params.proxy || null,
          caCertPath,
          persistent: Boolean(params.persistent),
          profileDir,
          profile,
          preferProfileState: Boolean(params.prefer_profile_state),
          cdp: null,
        };
        try {
          Object.assign(session, await launchChromium(params.proxy || null, caCertPath, profileDir));
        } catch (error) {
          if (error.ownedRuntime) {
            Object.assign(session, error.ownedRuntime);
            sessions.set(sessionId, session);
          }
          throw error;
        }
        sessions.set(sessionId, session);
        if (abortedStarts.delete(sessionId)) {
          await closeSession(sessionId);
          throw rpcError(-32000, "browser session was aborted while it launched");
        }
        try {
          await initializeSessionTracking(session);
          await restoreProjectState(session, params.restore_state);
          await clearCookieIdentities(session.context, params.clear_cookies, "clear_cookies");
          if (Array.isArray(params.cookies) && params.cookies.length) {
            await session.context.addCookies(params.cookies);
          }
          let seeded = await seedBrowserStorage(session, params.storage_seed);
          const restore = pendingStorageRestore(session, params.url);
          if (restore) {
            // Best effort: on failure the post-load reconciliation still runs.
            try { seeded = await seedBrowserStorage(session, { origins: [restore] }) || seeded; } catch {}
          }
          if (seeded && !(params.url && params.url !== "about:blank")) {
            await navigateAfterSeed(session, { returnTo: "about:blank" }, null);
          }
          if (params.url && params.url !== "about:blank") {
            await navigateWithProxyCheck(session.page, () => session.page.goto(params.url, {
              waitUntil: "domcontentloaded",
              timeout: 30_000,
            }));
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
      case "session.abort": {
        // The daemon gave up on a call of this session that may still be
        // running: close the session at once, whatever it is doing.
        const sessionId = Number(params.session_id);
        if (!Number.isSafeInteger(sessionId) || sessionId <= 0) {
          throw rpcError(-32602, "session_id must be a positive integer");
        }
        const session = sessions.get(sessionId);
        if (!session) {
          abortedStarts.add(sessionId); // Closed by session.start once it has launched.
          return respond(id, { aborted: false });
        }
        sessions.delete(sessionId);
        const closed = await Promise.race([
          closeRuntime(session).then(() => true, () => false),
          new Promise((resolve) => { const timer = setTimeout(() => resolve(false), 5_000); timer.unref(); }),
        ]);
        logMeta("session.abort", { session_id: sessionId, closed });
        // A browser left running could keep its profile locked: the daemon
        // then replaces this worker, which stops every browser it started.
        if (!closed) throw rpcError(-32000, "aborted browser session did not close");
        return respond(id, { aborted: true });
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
      case "session.events_wait": {
        const session = sessions.get(Number(params.session_id));
        if (!session) throw rpcError(-32001, "session not found");
        session.identityController?.assertHealthy();
        return respond(id, await waitForEvents(session, params.action || {}, params.wait_ms));
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
        const seedsStorage = Boolean(params.storage_seed?.origins?.length || params.storage_seed?.clear_origins?.length);
        if (!Array.isArray(params.cookies) || (!params.cookies.length && !seedsStorage)) {
          throw rpcError(-32602, "cookies must be a non-empty array unless storage_seed is provided");
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
        if (params.cookies.length) await session.context.addCookies(params.cookies);
        const seeded = await seedBrowserStorage(session, params.storage_seed);
        if (seeded) await navigateAfterSeed(session, seeded, params.url);
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
        return respond(id, javascriptFilesSince(session, params.after));
      }
      case "session.cdp_enable": {
        const sessionId = Number(params.session_id);
        const session = sessions.get(sessionId);
        if (!session) throw rpcError(-32001, "session not found");
        if (session.cdp) {
          return respond(id, { cdp: session.cdp, checkpoint: await extractCheckpoint(session) });
        }
        const checkpoint = await extractCheckpoint(session);
        const cdp = await relaunchSession(session, validateCdpPort(params.cdp_port));
        logMeta("session.cdp_enable", { session_id: sessionId, port: cdp.port });
        return respond(id, { cdp, checkpoint });
      }
      case "session.cdp_state": {
        const session = sessions.get(Number(params.session_id));
        if (!session) throw rpcError(-32001, "session not found");
        return respond(id, { cdp: session.cdp || null });
      }
      case "session.cdp_disable": {
        const sessionId = Number(params.session_id);
        const session = sessions.get(sessionId);
        if (!session) throw rpcError(-32001, "session not found");
        const checkpoint = await extractCheckpoint(session);
        if (session.cdp) await relaunchSession(session, null);
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
    const normalized = Number.isSafeInteger(error?.code) && typeof error.message === "string"
      ? error
      : rpcError(-32000, String(error?.message || error));
    logMeta("error", { method, code: normalized.code });
    return respond(id, null, normalized);
  }
}

async function closeRuntime(runtime) {
  if (runtime.ownedChrome) {
    runtime.identityController?.beginClose();
    try {
      await Promise.race([
        (async () => {
          const cdp = await runtime.browser.newBrowserCDPSession();
          await cdp.send("Browser.close");
        })(),
        new Promise((resolve) => { const timer = setTimeout(resolve, 1_000); timer.unref(); }),
      ]);
    } catch {}
    try { await stopOwnedChrome(runtime.ownedChrome); } catch (error) {
      Object.defineProperty(error, "ownedRuntime", { value: runtime });
      throw error;
    }
    await runtime.identityController?.close();
    if (runtime.probeProfile) fs.rmSync(runtime.profileDir, { recursive: true, force: true });
    await disposeSessionTracking(runtime);
    try { await runtime.browser?.close(); } catch {}
    return;
  }
  await disposeSessionTracking(runtime);
  try { await runtime.page?.close(); } catch {}
  try { await runtime.context?.close(); } catch {}
  try { await runtime.browser?.close(); } catch {}
}

async function closeSession(sessionId) {
  const session = sessions.get(sessionId);
  if (!session) return;
  await closeRuntime(session);
  sessions.delete(sessionId);
  logMeta("session.stop", { session_id: sessionId });
}

// A session's requests run in order and different sessions' side by side, so
// a slow call holds up only its own session. Starts take turns, since each
// checks that no other session holds its profile before it launches. hello
// and session.abort are answered at once: abort is how the daemon ends a
// session whose call is still running.
const lanes = new Map();
function laneOf(request) {
  const method = request?.method;
  if (method === "hello" || method === "session.abort") return null;
  if (method === "session.start") return "start";
  const sessionId = Number(request?.params?.session_id);
  return Number.isSafeInteger(sessionId) ? `session ${sessionId}` : "worker";
}
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
  const lane = laneOf(request);
  if (lane === null) {
    void handle(request);
    return;
  }
  const tail = (lanes.get(lane) ?? Promise.resolve()).then(() => handle(request)).catch(() => undefined);
  lanes.set(lane, tail);
  void tail.then(() => { if (lanes.get(lane) === tail) lanes.delete(lane); });
});
async function shutdown(exitCode) {
  if (shuttingDown) return;
  shuttingDown = true;
  const exit = (code) => {
    for (const child of ownedChromeChildren) {
      try { child.kill("SIGKILL"); } catch {}
    }
    // Playwright's exit handler also kills its detached browser groups.
    process.exit(code);
  };
  // EOF can be the only notification after the daemon is killed. Do not let
  // stalled browser control calls keep the worker and its profiles alive.
  const deadline = setTimeout(() => exit(1), 5_000);
  deadline.unref();
  const registered = new Set([...sessions.values()].map((session) => session.ownedChrome));
  // Close independent browsers together, including a native child whose
  // startup has not reached session registration yet. One failure must not
  // prevent termination of another profile's browser.
  const results = await Promise.allSettled([
    ...[...sessions.keys()].map(closeSession),
    ...[...ownedChromeChildren].filter((child) => !registered.has(child)).map(stopOwnedChrome),
  ]);
  clearTimeout(deadline);
  exit(results.some((result) => result.status === "rejected") ? 1 : exitCode);
}

readline.on("close", () => {
  void shutdown(0);
});

for (const signal of ["SIGINT", "SIGTERM"]) {
  process.on(signal, () => { void shutdown(signal === "SIGINT" ? 130 : 143); });
}
