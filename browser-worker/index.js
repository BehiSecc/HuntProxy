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

function trackJavascriptFiles(session, existing = new Map()) {
  session.javascriptFiles = existing;
  session.page.on("response", (response) => {
    const file = javascriptFile(response, session.page.url());
    if (file) session.javascriptFiles.set(file.url, file);
  });
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
  const candidates = [
    process.env.HUNTPROXY_CHROME_EXECUTABLE,
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

function chromiumLaunchOptions(proxy, caCertPath, cdpPort = null) {
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
    executablePath: existingChromiumExecutable(),
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
      "Chromium executable not found; install Chromium or set HUNTPROXY_CHROME_EXECUTABLE",
    );
  }
  const options = chromiumLaunchOptions(proxy, caCertPath, cdpPort);
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

async function launchSessionRuntime(session, cdpPort, currentUrl) {
  const runtime = await launchChromium(
    session.proxy || null,
    session.caCertPath || null,
    session.profileDir || null,
    cdpPort,
  );
  try {
    if (currentUrl && currentUrl !== "about:blank") {
      await runtime.page.goto(currentUrl, { waitUntil: "domcontentloaded", timeout: 30_000 });
    }
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
  const currentUrl = session.page?.url() || "about:blank";
  await closeRuntime(session);
  let launched;
  try {
    launched = await launchSessionRuntime(session, cdpPort, currentUrl);
  } catch (error) {
    try {
      const restored = await launchSessionRuntime(session, null, currentUrl);
      Object.assign(session, restored.runtime, { cdp: null });
      trackJavascriptFiles(session);
    } catch (restoreError) {
      throw rpcError(
        -32000,
        `CDP handoff failed and the normal browser could not be restored: ${restoreError?.message || restoreError}`,
      );
    }
    throw error;
  }
  Object.assign(session, launched.runtime, { cdp: launched.cdp });
  trackJavascriptFiles(session);
  return launched.cdp;
}

async function restoreProjectState(session, state) {
  if (!state || typeof state !== "object") return;
  if (session.preferProfileState) return;
  session.restoreState = state;
  session.restoredOrigins = new Set();
  // For new/non-profile sessions, restore the portable checkpoint.
  // Managed cookies are applied separately after this step.
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
        if (cookie.partitionKey) {
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
  const title = await session.page.title().catch(() => "");
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

async function handle(req) {
  const { id, method, params = {} } = req;
  try {
    switch (method) {
      case "hello":
        return respond(id, {
          protocol: PROTOCOL,
          engines: ["chromium"],
          capabilities: ["actions", "checkpoints", "cdp_handoff"],
        });
      case "session.start": {
        const sessionId = Number(params.session_id);
        if (!Number.isSafeInteger(sessionId) || sessionId <= 0) {
          throw rpcError(-32602, "session_id must be a positive integer");
        }
        if (sessions.has(sessionId)) await closeSession(sessionId);
        const engine = params.engine || "chromium";
        if (engine !== "chromium") {
          throw rpcError(-32602, "engine must be chromium");
        }
        const caCertPath = params.ca_cert_path || null;
        const profileDir = params.persistent
          ? params.profile_dir || null
          : null;
        const runtime = await launchChromium(params.proxy || null, caCertPath, profileDir);
        const session = {
          ...runtime,
          engine,
          proxy: params.proxy || null,
          caCertPath,
          persistent: Boolean(params.persistent),
          profileDir,
          preferProfileState: Boolean(params.prefer_profile_state),
          cdp: null,
        };
        trackJavascriptFiles(session);
        sessions.set(sessionId, session);
        try {
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
        const status = await session.page.evaluate(async (url) => {
          const controller = new AbortController();
          const timeout = setTimeout(() => controller.abort(), 15_000);
          try {
            const response = await fetch(url, {
              credentials: "include",
              redirect: "follow",
              headers: { "x-huntproxy-internal-crawler": "1" },
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
        }, target.href);
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
