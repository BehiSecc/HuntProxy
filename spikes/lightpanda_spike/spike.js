#!/usr/bin/env node
/**
 * Phase 0 spike: Lightpanda CDP control + cookie/storage transfer to Chromium.
 *
 * Proofs:
 *  1. Launch lightpanda serve, connect via playwright-core connectOverCDP
 *  2. Navigate local HTTP fixture, set cookies + localStorage + sessionStorage
 *  3. Extract state explicitly (not only storageState())
 *  4. Launch Chromium, import state, verify transfer
 *  5. Document --proxy-bearer-token / proxy flags (static + CLI smoke)
 *
 * Important Lightpanda quirk (found in this spike):
 *  - Default context from connectOverCDP is not usable (BrowserContextNotLoaded /
 *    TargetAlreadyLoaded). Use browser.newContext() + newPage() instead.
 */
'use strict';

const http = require('http');
const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const { chromium } = require('playwright-core');

const ROOT = __dirname;
const RESULT_PATH = path.join(ROOT, 'RESULT.md');
const LIGHTPANDA = process.env.LIGHTPANDA_BIN || 'lightpanda';
const CDP_HOST = '127.0.0.1';
const CDP_PORT = 9222;
const CDP_URL = `http://${CDP_HOST}:${CDP_PORT}`;

const results = [];
const children = [];

function record(name, ok, detail) {
  results.push({ name, ok: !!ok, detail: detail || '' });
  console.log(`[${ok ? 'PASS' : 'FAIL'}] ${name}${detail ? ' — ' + detail : ''}`);
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

async function waitForCdp(url, timeoutMs = 10000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      const res = await fetch(`${url}/json/version`);
      if (res.ok) return await res.json();
    } catch (_) {
      /* retry */
    }
    await sleep(150);
  }
  throw new Error(`CDP not ready at ${url} within ${timeoutMs}ms`);
}

function startLocalServer() {
  return new Promise((resolve, reject) => {
    const server = http.createServer((req, res) => {
      const url = req.url || '/';
      if (url === '/set' || url.startsWith('/set?')) {
        res.writeHead(200, {
          'Content-Type': 'text/html; charset=utf-8',
          'Set-Cookie': [
            'lp_spike_server=from_set_cookie; Path=/; SameSite=Lax',
            'lp_spike_http=http_only_val; Path=/; HttpOnly; SameSite=Lax',
          ],
        });
        res.end(`<!DOCTYPE html>
<html><head><title>Lightpanda Spike Set</title></head>
<body>
<h1 id="title">spike-set</h1>
<script>
  document.cookie = "lp_spike_js=js_cookie_val; path=/; SameSite=Lax";
  localStorage.setItem("lp_spike_ls", "local_storage_val");
  sessionStorage.setItem("lp_spike_ss", "session_storage_val");
  window.__SPIKE_READY__ = true;
</script>
</body></html>`);
        return;
      }
      if (url === '/check' || url.startsWith('/check?')) {
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(`<!DOCTYPE html>
<html><head><title>Lightpanda Spike Check</title></head>
<body>
<h1 id="title">spike-check</h1>
<pre id="out"></pre>
<script>
  const report = {
    cookies: document.cookie,
    localStorage: localStorage.getItem("lp_spike_ls"),
    sessionStorage: sessionStorage.getItem("lp_spike_ss"),
  };
  document.getElementById("out").textContent = JSON.stringify(report, null, 2);
  window.__SPIKE_REPORT__ = report;
</script>
</body></html>`);
        return;
      }
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      res.end('ok');
    });
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      resolve({ server, port, base: `http://127.0.0.1:${port}` });
    });
    server.on('error', reject);
  });
}

function launchLightpanda(port, extraArgs = []) {
  const env = {
    ...process.env,
    LIGHTPANDA_DISABLE_TELEMETRY: 'true',
    PATH: `${process.env.HOME}/.cargo/bin:${process.env.PATH || ''}`,
  };
  const args = [
    'serve',
    '--host',
    CDP_HOST,
    '--port',
    String(port),
    '--log-level',
    'info',
    ...extraArgs,
  ];
  console.log(`Starting: ${LIGHTPANDA} ${args.join(' ')}`);
  const child = spawn(LIGHTPANDA, args, {
    env,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  children.push(child);
  child.stdout.on('data', (d) => process.stderr.write(`[lp:${port}:out] ${d}`));
  child.stderr.on('data', (d) => process.stderr.write(`[lp:${port}:err] ${d}`));
  child.on('exit', (code, signal) => {
    console.error(`[lp:${port}] exited code=${code} signal=${signal}`);
  });
  return child;
}

function cleanup() {
  for (const c of children) {
    try {
      if (c && c.pid && !c.killed && c.exitCode === null) {
        try {
          process.kill(c.pid, 'SIGTERM');
        } catch (_) {
          /* already gone */
        }
      }
    } catch (_) {
      /* ignore */
    }
  }
}

process.on('exit', cleanup);
process.on('SIGINT', () => {
  cleanup();
  process.exit(130);
});
process.on('SIGTERM', () => {
  cleanup();
  process.exit(143);
});

async function extractStateExplicit(context, page, origin) {
  const cookies = await context.cookies(origin ? [origin] : undefined);
  const storage = await page.evaluate(() => {
    const ls = {};
    const ss = {};
    for (let i = 0; i < localStorage.length; i++) {
      const k = localStorage.key(i);
      ls[k] = localStorage.getItem(k);
    }
    for (let i = 0; i < sessionStorage.length; i++) {
      const k = sessionStorage.key(i);
      ss[k] = sessionStorage.getItem(k);
    }
    return {
      localStorage: ls,
      sessionStorage: ss,
      documentCookie: document.cookie,
    };
  });
  return { cookies, ...storage };
}

function normalizeCookiesForChromium(cookies, originBase) {
  // Prefer url-based cookies: Playwright requires either `url` or (`domain`+`path`).
  // Lightpanda may emit domain=".127.0.0.1" which Chromium rejects.
  return cookies.map((c) => {
    const pathPart = c.path || '/';
    let url = c.url;
    if (!url) {
      const host = (c.domain || '').replace(/^\./, '') || '127.0.0.1';
      if (host === '127.0.0.1' || host === 'localhost') {
        url = `http://127.0.0.1${pathPart === '/' ? '/' : pathPart}`;
      } else if (originBase) {
        url = originBase.replace(/\/$/, '') + (pathPart === '/' ? '/' : pathPart);
      } else {
        url = `http://${host}${pathPart === '/' ? '/' : pathPart}`;
      }
    }
    const out = {
      name: c.name,
      value: c.value,
      url,
      httpOnly: !!c.httpOnly,
      secure: !!c.secure,
      sameSite: c.sameSite === 'None' || c.sameSite === 'Strict' || c.sameSite === 'Lax'
        ? c.sameSite
        : 'Lax',
    };
    if (typeof c.expires === 'number' && c.expires > 0) {
      out.expires = c.expires;
    }
    return out;
  });
}

async function main() {
  let httpSrv;
  let lpBrowser;
  let crBrowser;
  const notes = [];

  try {
    notes.push(
      'Lightpanda serve common options include:',
      '  --http-proxy <URL>           HTTP proxy; username:password may be included for basic auth.',
      '  --proxy-bearer-token <TOKEN> Token for Proxy-Authorization: Bearer <token>.',
      '  --cookie <PATH>              Load cookies from JSON (read-only).',
      '  --cookie-jar <PATH>          Save cookies on exit (write-only).',
      'Telemetry: LIGHTPANDA_DISABLE_TELEMETRY=true (confirmed in serve logs).',
      'Quirk: after connectOverCDP, use browser.newContext()+newPage(); default context is unusable (BrowserContextNotLoaded / TargetAlreadyLoaded).',
      'Quirk: storageState().origins is empty even when localStorage is set — extract storage via page.evaluate.',
    );
    record(
      'proxy-bearer-token flag documented',
      true,
      '--proxy-bearer-token <TOKEN> → Proxy-Authorization: Bearer <token>; --http-proxy <URL> for proxy URL',
    );

    httpSrv = await startLocalServer();
    record('local HTTP fixture started', true, httpSrv.base);

    launchLightpanda(CDP_PORT);
    let version;
    try {
      version = await waitForCdp(CDP_URL, 15000);
      record(
        'lightpanda CDP ready',
        true,
        `Browser=${version.Browser} ws=${version.webSocketDebuggerUrl}`,
      );
    } catch (e) {
      record('lightpanda CDP ready', false, String(e.message || e));
      throw e;
    }

    try {
      lpBrowser = await chromium.connectOverCDP(CDP_URL, { timeout: 15000 });
      record(
        'playwright connectOverCDP',
        true,
        `contexts=${lpBrowser.contexts().length} version=${lpBrowser.version()}`,
      );
    } catch (e) {
      record('playwright connectOverCDP', false, String(e.message || e));
      throw e;
    }

    // Critical: newContext + newPage (not default context)
    let lpContext;
    let lpPage;
    try {
      lpContext = await lpBrowser.newContext();
      lpPage = await lpContext.newPage();
      record('lightpanda newContext+newPage', true, `url=${lpPage.url()}`);
    } catch (e) {
      record('lightpanda newContext+newPage', false, String(e.message || e));
      throw e;
    }

    const setUrl = `${httpSrv.base}/set`;
    try {
      await lpPage.goto(setUrl, { waitUntil: 'domcontentloaded', timeout: 20000 });
      await lpPage
        .waitForFunction(() => window.__SPIKE_READY__ === true, null, { timeout: 10000 })
        .catch(() => null);
      await lpContext.addCookies([
        {
          name: 'lp_spike_api',
          value: 'api_cookie_val',
          url: httpSrv.base + '/',
          sameSite: 'Lax',
        },
      ]);
      const ready = await lpPage.evaluate(() => window.__SPIKE_READY__ === true).catch(() => false);
      record(
        'lightpanda navigate /set',
        ready || lpPage.url().includes('/set'),
        `url=${lpPage.url()} ready=${ready}`,
      );
    } catch (e) {
      record('lightpanda navigate /set', false, String(e.message || e));
    }

    let extracted = { cookies: [], localStorage: {}, sessionStorage: {} };
    try {
      extracted = await extractStateExplicit(lpContext, lpPage, httpSrv.base);
      const cookieNames = extracted.cookies.map((c) => c.name).sort();
      const hasServer = cookieNames.includes('lp_spike_server');
      const hasJs = cookieNames.includes('lp_spike_js');
      const hasApi = cookieNames.includes('lp_spike_api');
      const hasHttpOnly = cookieNames.includes('lp_spike_http');
      record(
        'extract cookies explicitly (context.cookies)',
        extracted.cookies.length > 0 && (hasServer || hasJs || hasApi),
        `count=${extracted.cookies.length} names=[${cookieNames.join(', ')}] httpOnly=${hasHttpOnly}`,
      );
      record(
        'extract localStorage explicitly (page.evaluate)',
        extracted.localStorage && extracted.localStorage.lp_spike_ls === 'local_storage_val',
        JSON.stringify(extracted.localStorage),
      );
      record(
        'extract sessionStorage explicitly (page.evaluate)',
        extracted.sessionStorage &&
          extracted.sessionStorage.lp_spike_ss === 'session_storage_val',
        JSON.stringify(extracted.sessionStorage),
      );

      try {
        const ss = await lpContext.storageState();
        notes.push(
          `storageState() cookie count: ${(ss.cookies || []).length}`,
          `storageState() origins: ${(ss.origins || []).length} (localStorage not included by Lightpanda here)`,
        );
      } catch (e) {
        notes.push(`storageState() failed: ${e.message || e}`);
      }
    } catch (e) {
      record('extract cookies explicitly (context.cookies)', false, String(e.message || e));
      record('extract localStorage explicitly (page.evaluate)', false, String(e.message || e));
      record('extract sessionStorage explicitly (page.evaluate)', false, String(e.message || e));
    }

    try {
      await lpBrowser.close();
      lpBrowser = null;
      record('disconnect CDP (browser.close)', true, 'CDP client closed');
    } catch (e) {
      record('disconnect CDP (browser.close)', false, String(e.message || e));
    }

    // --- Chromium import path ---
    try {
      const launchOpts = { headless: true };
      try {
        const exe = chromium.executablePath();
        if (exe && fs.existsSync(exe)) launchOpts.executablePath = exe;
      } catch (_) {
        /* ignore */
      }
      if (!launchOpts.executablePath) {
        for (const p of [
          '/usr/bin/google-chrome-stable',
          '/usr/bin/google-chrome',
          '/usr/bin/chromium',
          '/usr/bin/chromium-browser',
        ]) {
          if (fs.existsSync(p)) {
            launchOpts.executablePath = p;
            break;
          }
        }
      }

      crBrowser = await chromium.launch(launchOpts);
      record(
        'chromium launch',
        true,
        `executablePath=${launchOpts.executablePath || '(playwright default)'}`,
      );

      const crContext = await crBrowser.newContext();
      const cookiesToImport = normalizeCookiesForChromium(extracted.cookies, httpSrv.base);
      if (cookiesToImport.length) {
        await crContext.addCookies(cookiesToImport);
      } else {
        notes.push('WARNING: no cookies extracted from Lightpanda; Chromium import empty.');
      }

      const lsDump = extracted.localStorage || {};
      const ssDump = extracted.sessionStorage || {};
      await crContext.addInitScript(
        ({ ls, ss }) => {
          for (const [k, v] of Object.entries(ls || {})) {
            try {
              localStorage.setItem(k, v);
            } catch (_) {}
          }
          for (const [k, v] of Object.entries(ss || {})) {
            try {
              sessionStorage.setItem(k, v);
            } catch (_) {}
          }
        },
        { ls: lsDump, ss: ssDump },
      );

      const crPage = await crContext.newPage();
      await crPage.goto(`${httpSrv.base}/check`, {
        waitUntil: 'domcontentloaded',
        timeout: 20000,
      });
      const report = await crPage.evaluate(() => window.__SPIKE_REPORT__ || null);
      const crCookies = await crContext.cookies([httpSrv.base]);
      const crCookieNames = crCookies.map((c) => c.name).sort();

      const hasCookieTransfer =
        crCookieNames.includes('lp_spike_api') ||
        crCookieNames.includes('lp_spike_js') ||
        crCookieNames.includes('lp_spike_server') ||
        crCookieNames.includes('lp_spike_http');
      record(
        'chromium cookies after import',
        hasCookieTransfer,
        `names=[${crCookieNames.join(', ')}] doc.cookie=${report ? report.cookies : 'n/a'}`,
      );

      const lsOk = report && report.localStorage === 'local_storage_val';
      const ssOk = report && report.sessionStorage === 'session_storage_val';
      record('chromium localStorage after import', lsOk, report ? String(report.localStorage) : 'n/a');
      record(
        'chromium sessionStorage after import',
        ssOk,
        report ? String(report.sessionStorage) : 'n/a',
      );

      const transferOk = hasCookieTransfer && lsOk && ssOk;
      record(
        'cookie/storage transfer Lightpanda → Chromium',
        transferOk,
        transferOk
          ? 'cookies + localStorage + sessionStorage verified in Chromium from Lightpanda extract'
          : 'one or more storage layers missing after import',
      );

      await crBrowser.close();
      crBrowser = null;
    } catch (e) {
      record('chromium launch / transfer', false, String(e.message || e));
      notes.push(
        'If chromium missing: `cd spikes/lightpanda_spike && npx playwright install chromium` or use system Chrome.',
      );
    }

    // CLI smoke: --proxy-bearer-token + --http-proxy accepted
    try {
      const probe = launchLightpanda(9233, [
        '--proxy-bearer-token',
        'spike-test-token',
        '--http-proxy',
        'http://127.0.0.1:9',
      ]);
      await sleep(800);
      const stillUp = probe.exitCode === null && !probe.killed;
      if (stillUp) {
        record(
          'proxy-bearer-token CLI accepts flag',
          true,
          'lightpanda serve started with --proxy-bearer-token and --http-proxy',
        );
        try {
          process.kill(probe.pid, 'SIGTERM');
        } catch (_) {}
      } else {
        record('proxy-bearer-token CLI accepts flag', false, 'process exited early');
      }
    } catch (e) {
      record('proxy-bearer-token CLI accepts flag', false, String(e.message || e));
    }
  } finally {
    try {
      if (lpBrowser) await lpBrowser.close();
    } catch (_) {}
    try {
      if (crBrowser) await crBrowser.close();
    } catch (_) {}
    try {
      if (httpSrv && httpSrv.server) httpSrv.server.close();
    } catch (_) {}
    cleanup();
    await sleep(300);
  }

  const passed = results.filter((r) => r.ok).length;
  const failed = results.filter((r) => !r.ok).length;
  const allOk = failed === 0;

  console.log('\n========== SUMMARY ==========');
  console.log(`PASS: ${passed}  FAIL: ${failed}  ALL: ${allOk ? 'PASS' : 'FAIL'}`);
  for (const r of results) {
    console.log(`  ${r.ok ? '✓' : '✗'} ${r.name}`);
  }

  fs.writeFileSync(RESULT_PATH, buildResultMd(results, notes, allOk, passed, failed), 'utf8');
  console.log(`\nWrote ${RESULT_PATH}`);
  process.exit(allOk ? 0 : 1);
}

function buildResultMd(results, notes, allOk, passed, failed) {
  const lines = [];
  lines.push('# Lightpanda CDP Spike — RESULT');
  lines.push('');
  lines.push(`**Overall: ${allOk ? 'PASS' : 'FAIL'}** (${passed} passed, ${failed} failed)`);
  lines.push('');
  lines.push(`Date: ${new Date().toISOString()}`);
  lines.push('');
  lines.push('## Environment');
  lines.push('');
  lines.push(
    '- lightpanda: `/home/administrator/.local/bin/lightpanda` (1.0.0-nightly.8285+de85a51d)',
  );
  lines.push('- playwright-core: 1.49.1 (Node 18 compatible)');
  lines.push('- Node: v18.19.1');
  lines.push('- `LIGHTPANDA_DISABLE_TELEMETRY=true`');
  lines.push(
    '- CDP: `lightpanda serve --host 127.0.0.1 --port 9222` → `ws://127.0.0.1:9222/`',
  );
  lines.push('');
  lines.push('## Proof checklist');
  lines.push('');
  lines.push('| Status | Proof | Detail |');
  lines.push('|--------|-------|--------|');
  for (const r of results) {
    const detail = (r.detail || '').replace(/\|/g, '\\|').replace(/\n/g, ' ');
    lines.push(`| ${r.ok ? 'PASS' : 'FAIL'} | ${r.name} | ${detail} |`);
  }
  lines.push('');
  lines.push('## Proxy / Bearer auth flags');
  lines.push('');
  lines.push('From `lightpanda serve --help` (common options):');
  lines.push('');
  lines.push('```');
  lines.push('--http-proxy <URL>');
  lines.push('        HTTP proxy for all HTTP requests.');
  lines.push('        username:password may be included for basic auth.');
  lines.push('        Defaults to none.');
  lines.push('');
  lines.push('--proxy-bearer-token <TOKEN>');
  lines.push('        Token sent for bearer authentication with the proxy:');
  lines.push('        Proxy-Authorization: Bearer <token>.');
  lines.push('```');
  lines.push('');
  lines.push('Also relevant for session fixtures:');
  lines.push('');
  lines.push('```');
  lines.push('--cookie <PATH>       Path to JSON file to load cookies from (read-only).');
  lines.push('--cookie-jar <PATH>   Path to JSON file to save cookies to on exit (write-only).');
  lines.push('```');
  lines.push('');
  lines.push(
    'CLI accepts both flags together (smoke-tested with a dummy proxy URL on port 9233).',
  );
  lines.push(
    'Full proxy auth traffic path was not exercised against a real authenticating proxy in this spike.',
  );
  lines.push('');
  lines.push('## Method');
  lines.push('');
  lines.push('1. Start Node `http` fixture on ephemeral port (`/set` and `/check`).');
  lines.push('2. Spawn `lightpanda serve` with `LIGHTPANDA_DISABLE_TELEMETRY=true`.');
  lines.push("3. `chromium.connectOverCDP('http://127.0.0.1:9222')` via playwright-core.");
  lines.push(
    '4. **`browser.newContext()` + `newPage()`** (required; default context fails on this Lightpanda build).',
  );
  lines.push(
    '5. Navigate `/set`, set cookies via page JS + `context.addCookies`, set local/sessionStorage.',
  );
  lines.push(
    '6. Extract via `context.cookies()` + `page.evaluate` for storage — do **not** rely only on `storageState()` (origins empty).',
  );
  lines.push(
    '7. Launch Chromium headless, `addCookies` + `addInitScript` for storage, navigate `/check`, verify.',
  );
  lines.push('8. Clean up child processes by PID on exit.');
  lines.push('');
  lines.push('## Findings / quirks');
  lines.push('');
  lines.push(
    '- `/json/list` returns `[]`; `/json/new` is 404. Playwright still connects and can create contexts.',
  );
  lines.push(
    '- Default context after connect is present but navigation/cookies hit `BrowserContextNotLoaded` / `TargetAlreadyLoaded`.',
  );
  lines.push(
    '- `storageState()` returns cookies but `origins: []` even when `localStorage`/`sessionStorage` are set — use explicit `page.evaluate`.',
  );
  lines.push(
    '- `Target.createBrowserContext` logs `not_implemented` for some params but still works for basic newContext.',
  );
  lines.push('');
  lines.push('## Notes');
  lines.push('');
  if (notes.length) {
    for (const n of notes) lines.push(`- ${n}`);
  } else {
    lines.push('- (none)');
  }
  lines.push('');
  lines.push('## How to re-run');
  lines.push('');
  lines.push('```bash');
  lines.push('cd /home/administrator/HuntProxy/spikes/lightpanda_spike');
  lines.push('export PATH="$HOME/.cargo/bin:$PATH"');
  lines.push('export LIGHTPANDA_DISABLE_TELEMETRY=true');
  lines.push('node spike.js');
  lines.push('```');
  lines.push('');
  return lines.join('\n');
}

main().catch((e) => {
  console.error('FATAL', e);
  cleanup();
  try {
    fs.writeFileSync(
      RESULT_PATH,
      `# Lightpanda CDP Spike — RESULT\n\n**Overall: FAIL**\n\nFatal error:\n\n\`\`\`\n${
        e && e.stack ? e.stack : e
      }\n\`\`\`\n`,
      'utf8',
    );
  } catch (_) {}
  process.exit(1);
});
