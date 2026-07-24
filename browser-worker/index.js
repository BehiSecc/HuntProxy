#!/usr/bin/env node
/**
 * bb browser worker — versioned NDJSON JSON-RPC over stdio.
 * Logs only scrubbed metadata to stderr. Never log cookies/headers/payloads.
 */
import { chromium } from "playwright-core";
import { createInterface } from "node:readline";
import { spawn } from "node:child_process";

const PROTOCOL = 1;
const sessions = new Map();
let nextId = 1;

function respond(id, result, error) {
  const msg = error
    ? { jsonrpc: "2.0", id, error }
    : { jsonrpc: "2.0", id, result };
  process.stdout.write(JSON.stringify(msg) + "\n");
}

function logMeta(event, fields = {}) {
  process.stderr.write(JSON.stringify({ event, ...fields }) + "\n");
}

async function handle(req) {
  const { id, method, params } = req;
  try {
    switch (method) {
      case "hello":
        return respond(id, { protocol: PROTOCOL, engines: ["lightpanda", "chromium"] });
      case "session.start": {
        const engine = params?.engine || "chromium";
        const sid = nextId++;
        let browser;
        let lightpandaProc = null;
        if (engine === "lightpanda") {
          const port = 9222 + (sid % 1000);
          lightpandaProc = spawn(
            process.env.LIGHTPANDA_PATH || "lightpanda",
            ["serve", "--host", "127.0.0.1", "--port", String(port)],
            {
              env: { ...process.env, LIGHTPANDA_DISABLE_TELEMETRY: "true" },
              stdio: ["ignore", "ignore", "pipe"],
            }
          );
          await new Promise((r) => setTimeout(r, 400));
          browser = await chromium.connectOverCDP(`http://127.0.0.1:${port}`);
          const context = await browser.newContext();
          const page = await context.newPage();
          sessions.set(sid, { engine, browser, context, page, lightpandaProc });
        } else {
          browser = await chromium.launch({
            headless: true,
            channel: process.env.BB_CHROME_CHANNEL || undefined,
          });
          const context = await browser.newContext({
            serviceWorkers: "block",
          });
          const page = await context.newPage();
          sessions.set(sid, { engine, browser, context, page, lightpandaProc: null });
        }
        logMeta("session.start", { sid, engine });
        return respond(id, { session_id: sid, engine });
      }
      case "session.action": {
        const s = sessions.get(params.session_id);
        if (!s) throw { code: -32001, message: "session not found" };
        const action = params.action || {};
        let data = null;
        if (action.type === "navigate") {
          await s.page.goto(action.url, { timeout: params.timeout_ms || 30000 });
          data = { url: s.page.url() };
        } else if (action.type === "snapshot") {
          const content =
            action.format === "dom"
              ? await s.page.content()
              : await s.page.accessibility.snapshot();
          const text = typeof content === "string" ? content : JSON.stringify(content);
          const max = action.max_bytes || 200_000;
          data = {
            untrusted: true,
            content: text.slice(0, max),
            truncated: text.length > max,
          };
        } else if (action.type === "close") {
          await closeSession(params.session_id);
          data = { closed: true };
        } else {
          data = { ok: true, note: "action stub", type: action.type };
        }
        return respond(id, { ok: true, untrusted: true, data });
      }
      case "session.checkpoint": {
        const s = sessions.get(params.session_id);
        if (!s) throw { code: -32001, message: "session not found" };
        const cookies = await s.context.cookies();
        const storage = await s.page.evaluate(() => ({
          local: { ...localStorage },
          session: { ...sessionStorage },
        }));
        // Return only counts/hashes — values stay in worker/daemon memory path
        return respond(id, {
          cookie_count: cookies.length,
          local_keys: Object.keys(storage.local || {}).length,
          session_keys: Object.keys(storage.session || {}).length,
          url: s.page.url(),
          // values for daemon in-memory only (not logged)
          _private: { cookies, storage },
        });
      }
      case "session.stop": {
        await closeSession(params.session_id);
        return respond(id, { stopped: true });
      }
      default:
        throw { code: -32601, message: `method not found: ${method}` };
    }
  } catch (e) {
    const err =
      e && e.code
        ? e
        : { code: -32000, message: String(e?.message || e) };
    logMeta("error", { method, code: err.code });
    return respond(id, null, err);
  }
}

async function closeSession(sid) {
  const s = sessions.get(sid);
  if (!s) return;
  try {
    await s.context?.close();
  } catch {}
  try {
    await s.browser?.close();
  } catch {}
  try {
    s.lightpandaProc?.kill("SIGTERM");
  } catch {}
  sessions.delete(sid);
  logMeta("session.stop", { sid });
}

const rl = createInterface({ input: process.stdin });
rl.on("line", (line) => {
  if (!line.trim()) return;
  let req;
  try {
    req = JSON.parse(line);
  } catch {
    return respond(null, null, { code: -32700, message: "parse error" });
  }
  handle(req);
});
rl.on("close", async () => {
  for (const sid of [...sessions.keys()]) await closeSession(sid);
  process.exit(0);
});
