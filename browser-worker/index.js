#!/usr/bin/env node
/**
 * HuntProxy browser worker — versioned NDJSON JSON-RPC over stdio.
 *
 * Stdout is protocol-only. Stderr contains scrubbed lifecycle metadata and
 * never request data, DOM content, cookies, credentials, or storage values.
 */
import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import { createRequire } from "node:module";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";

const PROTOCOL = 1;
const sessions = new Map();

function javascriptFile(response) {
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
  return {
    url: parsed.toString(),
    path: parsed.pathname,
    host: parsed.hostname,
    mime: mime || null,
    status_code: response.status(),
  };
}

function trackJavascriptFiles(session, existing = new Map()) {
  session.javascriptFiles = existing;
  session.page.on("response", (response) => {
    const file = javascriptFile(response);
    if (file) session.javascriptFiles.set(file.url, file);
  });
}

function loadPlaywright() {
  const candidates = [];
  if (process.env.BB_PLAYWRIGHT_CORE_PATH) {
    candidates.push(process.env.BB_PLAYWRIGHT_CORE_PATH);
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
  const candidates = [
    process.env.BB_CHROME_EXECUTABLE,
    process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH,
    "/usr/bin/google-chrome-stable",
    "/usr/bin/google-chrome",
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
  ].filter(Boolean);
  try {
    const bundled = chromium.executablePath();
    if (bundled) candidates.unshift(bundled);
  } catch {
    // playwright-core commonly has no downloaded browser.
  }
  return candidates.find((candidate) => fs.existsSync(candidate));
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

function lightpandaProxyUrl(proxy) {
  if (!proxy?.server) return null;
  const url = new URL(proxy.server);
  if (proxy.username) url.username = proxy.username;
  if (proxy.password) url.password = proxy.password;
  return url.toString();
}

function chromiumLaunchOptions(proxy, caCertPath) {
  return {
    executablePath: existingChromiumExecutable(),
    headless: true,
    proxy: chromiumProxy(proxy),
    ignoreHTTPSErrors: Boolean(caCertPath),
    serviceWorkers: "allow",
    args: [
      "--disable-quic",
      "--disk-cache-size=52428800",
      "--media-cache-size=10485760",
      "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
      "--webrtc-ip-handling-policy=disable_non_proxied_udp",
      "--proxy-bypass-list=<-loopback>",
    ],
  };
}

async function launchChromium(proxy, caCertPath, profileDir = null) {
  const executablePath = existingChromiumExecutable();
  if (!executablePath) {
    throw rpcError(
      -32003,
      "Chromium executable not found; install Chromium or set BB_CHROME_EXECUTABLE",
    );
  }
  const options = chromiumLaunchOptions(proxy, caCertPath);
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
      lightpandaProc: null,
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
  return { browser, context, page, lightpandaProc: null, persistent: false, profileDir: null };
}

async function waitForCdp(endpoint, child, timeoutMs = 15_000) {
  const deadline = Date.now() + timeoutMs;
  let lastError;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) {
      throw rpcError(-32004, "Lightpanda exited before CDP became ready");
    }
    try {
      const response = await fetch(`${endpoint}/json/version`, {
        signal: AbortSignal.timeout(750),
      });
      if (response.ok) return;
    } catch (error) {
      lastError = error;
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw rpcError(
    -32004,
    `Lightpanda CDP did not become ready: ${lastError?.message || "timeout"}`,
  );
}

async function availableLoopbackPort() {
  const server = net.createServer();
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  const port = typeof address === "object" && address ? address.port : null;
  await new Promise((resolve) => server.close(resolve));
  if (!port) throw rpcError(-32004, "could not allocate a Lightpanda CDP port");
  return port;
}

async function launchLightpanda(proxy, caCertPath) {
  const lightpanda = process.env.LIGHTPANDA_PATH || "lightpanda";
  const port = await availableLoopbackPort();
  const args = ["serve", "--host", "127.0.0.1", "--port", String(port)];
  const proxyUrl = lightpandaProxyUrl(proxy);
  if (proxyUrl) args.push("--http-proxy", proxyUrl);
  if (proxy?.bearer_token && !proxy?.username) {
    args.push("--proxy-bearer-token", proxy.bearer_token);
  }
  if (caCertPath) args.push("--ca-cert", caCertPath);

  const lightpandaProc = spawn(lightpanda, args, {
    env: {
      ...process.env,
      LIGHTPANDA_DISABLE_TELEMETRY: "true",
    },
    stdio: ["ignore", "ignore", "ignore"],
  });
  const endpoint = `http://127.0.0.1:${port}`;
  try {
    await waitForCdp(endpoint, lightpandaProc);
    const browser = await chromium.connectOverCDP(endpoint, { timeout: 15_000 });
    // Lightpanda's default CDP context is not usable; create an explicit one.
    const context = await browser.newContext();
    const page = await context.newPage();
    return { browser, context, page, lightpandaProc };
  } catch (error) {
    lightpandaProc.kill("SIGTERM");
    throw error;
  }
}

async function launchEngine(engine, proxy, caCertPath, profileDir = null) {
  return engine === "lightpanda"
    ? launchLightpanda(proxy, caCertPath)
    : launchChromium(proxy, caCertPath, profileDir);
}

async function restoreProjectState(session, state) {
  if (!state || typeof state !== "object") return;
  session.restoreState = state;
  session.restoredOrigins = new Set();
  if (session.engine === "chromium" && session.persistent) {
    await session.context.clearCookies();
  }
  if (Array.isArray(state.cookies) && state.cookies.length) {
    const cookies = state.cookies
      .filter((cookie) => cookie && cookie.name && cookie.domain)
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
        if (session.engine === "chromium" && cookie.partitionKey) {
          restored.partitionKey = cookie.partitionKey;
        }
        return restored;
      });
    if (cookies.length) await session.context.addCookies(cookies);
  }
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
    const localValues = localByOrigin[origin] || {};
    const sessionValues = sessionByOrigin[origin] || {};
    await session.page.evaluate(
      ({ local, currentSession }) => {
        localStorage.clear();
        sessionStorage.clear();
        for (const [key, value] of Object.entries(local)) localStorage.setItem(key, value);
        for (const [key, value] of Object.entries(currentSession)) {
          sessionStorage.setItem(key, value);
        }
      },
      { local: localValues, currentSession: sessionValues },
    );
    session.restoredOrigins?.add(origin);
    await session.page.reload({ waitUntil: "domcontentloaded", timeout: 30_000 });
  }
}

async function extractCheckpoint(session) {
  const url = session.page.url();
  const origin = (() => {
    try {
      const parsed = new URL(url);
      return new Set(["http:", "https:"]).has(parsed.protocol) ? parsed.origin : null;
    } catch {
      return null;
    }
  })();
  const cookies = await session.context.cookies();
  const storage = await session.page
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
    origin,
    cookie_count: cookies.length,
    local_keys: Object.keys(privateState.local_storage).length,
    session_keys: Object.keys(privateState.session_storage).length,
    state_hash: stateHash,
    _private: privateState,
  };
}

function cookieKey(cookie) {
  return `${cookie.name}\u0000${String(cookie.domain || "").replace(/^\./, "")}\u0000${cookie.path || "/"}`;
}

function cookieProjection(cookie) {
  return {
    value: cookie.value,
    httpOnly: Boolean(cookie.httpOnly),
    secure: Boolean(cookie.secure),
    sameSite: cookie.sameSite || "Lax",
  };
}

function compareCookies(expected, actual) {
  const actualMap = new Map(actual.map((cookie) => [cookieKey(cookie), cookieProjection(cookie)]));
  let matched = 0;
  for (const cookie of expected) {
    const found = actualMap.get(cookieKey(cookie));
    if (found && JSON.stringify(found) === JSON.stringify(cookieProjection(cookie))) matched += 1;
  }
  return { expected: expected.length, matched, verified: matched === expected.length };
}

function compareStorage(expected, actual) {
  const expectedEntries = Object.entries(expected || {}).sort();
  const matched = expectedEntries.filter(([key, value]) => actual?.[key] === value).length;
  return {
    expected: expectedEntries.length,
    matched,
    verified: matched === expectedEntries.length,
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

async function executeAction(session, action = {}) {
  switch (action.type) {
    case "navigate": {
      await session.page.goto(action.url, {
        waitUntil: "domcontentloaded",
        timeout: action.timeout_ms || 30_000,
      });
      await reconcileCurrentOriginStorage(session);
      return { message: "navigation completed", data: { url: session.page.url() } };
    }
    case "snapshot": {
      let content;
      if (action.format === "dom") {
        content = await session.page.content();
      } else if (typeof session.page.locator("body").ariaSnapshot === "function") {
        content = await session.page.locator("body").ariaSnapshot();
      } else {
        content = await session.page.content();
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
      await locatorFor(session.page, action.locator).click({ timeout: 30_000 });
      return { message: "element clicked", data: { url: session.page.url() } };
    case "fill":
      await locatorFor(session.page, action.locator).fill(action.value ?? "", { timeout: 30_000 });
      return { message: "field filled", data: null };
    case "select":
      await locatorFor(session.page, action.locator).selectOption(action.value, { timeout: 30_000 });
      return { message: "option selected", data: null };
    case "press":
      if (action.locator) {
        await locatorFor(session.page, action.locator).press(action.key, { timeout: 30_000 });
      } else {
        await session.page.keyboard.press(action.key);
      }
      return { message: "key pressed", data: null };
    case "wait":
      return {
        message: "wait completed",
        data: await performWait(session.page, action.for_what, action.value),
      };
    case "back":
      await session.page.goBack({ waitUntil: "domcontentloaded", timeout: 30_000 });
      await reconcileCurrentOriginStorage(session);
      return { message: "went back", data: { url: session.page.url() } };
    case "forward":
      await session.page.goForward({ waitUntil: "domcontentloaded", timeout: 30_000 });
      await reconcileCurrentOriginStorage(session);
      return { message: "went forward", data: { url: session.page.url() } };
    default:
      throw rpcError(-32602, `unsupported browser action: ${action.type || "missing"}`);
  }
}

async function migrateToChromium(sessionId, session, profileDir = null) {
  if (session.engine !== "lightpanda") {
    throw rpcError(-32602, "only Lightpanda sessions can migrate to Chromium");
  }
  const sourceCheckpoint = await extractCheckpoint(session);
  const source = sourceCheckpoint._private;
  const replacement = await launchChromium(session.proxy, session.caCertPath, profileDir);
  try {
    const migrated = {
      ...replacement,
      engine: "chromium",
      proxy: session.proxy,
      caCertPath: session.caCertPath,
      persistent: Boolean(profileDir),
      profileDir,
    };
    const localByOrigin = source.origin
      ? { [source.origin]: source.local_storage || {} }
      : {};
    const sessionByOrigin = source.origin
      ? { [source.origin]: source.session_storage || {} }
      : {};
    await restoreProjectState(migrated, {
      cookies: source.cookies,
      local_storage: localByOrigin,
      session_storage: sessionByOrigin,
    });
    if (sourceCheckpoint.url && sourceCheckpoint.url !== "about:blank") {
      await migrated.page.goto(sourceCheckpoint.url, {
        waitUntil: "domcontentloaded",
        timeout: 30_000,
      });
      await reconcileCurrentOriginStorage(migrated);
    }
    const restoredCheckpoint = await extractCheckpoint(migrated);
    const restored = restoredCheckpoint._private;
    const cookieVerification = compareCookies(source.cookies, restored.cookies);
    const localVerification = compareStorage(source.local_storage, restored.local_storage);
    const sessionVerification = compareStorage(source.session_storage, restored.session_storage);
    const verified =
      cookieVerification.verified &&
      localVerification.verified &&
      sessionVerification.verified;

    await closeRuntime(session);
    trackJavascriptFiles(migrated, new Map(session.javascriptFiles || []));
    sessions.set(sessionId, migrated);
    return {
      ok: true,
      status: verified ? "migrated" : "migrated_partial",
      verified,
      verification: {
        cookies: cookieVerification,
        local_storage: localVerification,
        session_storage: sessionVerification,
      },
      checkpoint: restoredCheckpoint,
    };
  } catch (error) {
    await closeRuntime(replacement);
    throw error;
  }
}

async function handle(req) {
  const { id, method, params = {} } = req;
  try {
    switch (method) {
      case "hello":
        return respond(id, {
          protocol: PROTOCOL,
          engines: ["lightpanda", "chromium"],
          capabilities: ["actions", "checkpoints", "lightpanda_to_chromium"],
        });
      case "session.start": {
        const sessionId = Number(params.session_id);
        if (!Number.isSafeInteger(sessionId) || sessionId <= 0) {
          throw rpcError(-32602, "session_id must be a positive integer");
        }
        if (sessions.has(sessionId)) await closeSession(sessionId);
        const engine = params.engine || "chromium";
        if (!new Set(["lightpanda", "chromium"]).has(engine)) {
          throw rpcError(-32602, "engine must be lightpanda or chromium");
        }
        const caCertPath = params.ca_cert_path || null;
        const profileDir = params.persistent && engine === "chromium"
          ? params.profile_dir || null
          : null;
        const runtime = await launchEngine(
          engine,
          params.proxy || null,
          caCertPath,
          profileDir,
        );
        const session = {
          ...runtime,
          engine,
          proxy: params.proxy || null,
          caCertPath,
          persistent: Boolean(params.persistent),
          profileDir,
        };
        trackJavascriptFiles(session);
        sessions.set(sessionId, session);
        try {
          await restoreProjectState(session, params.restore_state);
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
          return respond(id, { session_id: sessionId, engine, checkpoint });
        } catch (error) {
          await closeSession(sessionId);
          throw error;
        }
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
          checkpoint,
        });
      }
      case "session.set_cookies": {
        const sessionId = Number(params.session_id);
        const session = sessions.get(sessionId);
        if (!session) throw rpcError(-32001, "session not found");
        if (!Array.isArray(params.cookies) || !params.cookies.length) {
          throw rpcError(-32602, "cookies must be a non-empty array");
        }
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
        if (typeof params.target_url !== "string" || !Array.isArray(params.names)) {
          throw rpcError(-32602, "target_url and names are required");
        }
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
      case "session.migrate_to_chromium": {
        const sessionId = Number(params.session_id);
        const session = sessions.get(sessionId);
        if (!session) throw rpcError(-32001, "session not found");
        const result = await migrateToChromium(sessionId, session, params.profile_dir || null);
        logMeta("session.migrate", {
          session_id: sessionId,
          status: result.status,
          verified: result.verified,
        });
        return respond(id, result);
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
  try { runtime.lightpandaProc?.kill("SIGTERM"); } catch {}
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
