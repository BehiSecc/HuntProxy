import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { test } from "node:test";
import vm from "node:vm";

const source = fs.readFileSync(new URL("./index.js", import.meta.url), "utf8");
const overrides = ["HUNTPROXY_CHROME_EXECUTABLE", "BB_CHROME_EXECUTABLE", "PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH"];

function fixture(t) {
  fs.mkdirSync("/tmp/artis", { recursive: true });
  const root = fs.mkdtempSync("/tmp/artis/huntproxy-runtime-");
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const worker = path.join(root, "worker.mjs");
  fs.writeFileSync(worker, source);
  fs.copyFileSync(new URL("./headless.js", import.meta.url), path.join(root, "headless.js"));
  fs.writeFileSync(path.join(root, "package.json"), '{"type":"module"}');
  const bin = path.join(root, "bin");
  fs.mkdirSync(bin);
  const bundle = path.join(root, "paired-chromium");
  const packageDir = path.join(root, "playwright-core");
  fs.mkdirSync(packageDir);
  fs.writeFileSync(path.join(packageDir, "package.json"), JSON.stringify({
    name: "playwright-core", version: "1.61.1", main: "index.js",
  }));
  fs.writeFileSync(path.join(packageDir, "browsers.json"), JSON.stringify({
    browsers: [{ name: "chromium", browserVersion: "149.0.7827.55" }],
  }));
  fs.writeFileSync(path.join(packageDir, "index.js"), `module.exports = {
    chromium: { executablePath: () => process.env.PLAYWRIGHT_BROWSERS_PATH === "0"
      ? ${JSON.stringify(path.join(packageDir, ".local-browsers", "paired-chromium"))}
      : ${JSON.stringify(bundle)} }
  };`);
  const env = { ...process.env, PATH: bin, HUNTPROXY_PLAYWRIGHT_CORE_PATH: packageDir };
  for (const key of [...overrides, "BB_PLAYWRIGHT_CORE_PATH", "PLAYWRIGHT_BROWSERS_PATH", "HUNTPROXY_BROWSER_HEADLESS", "HUNTPROXY_BROWSER_HEADLESS_COMPAT"]) delete env[key];
  function executable(filename, version = "149.0.7827.55") {
    fs.writeFileSync(filename, `#!/bin/sh\nprintf 'Chromium ${version}\\n'\n`, { mode: 0o700 });
    return filename;
  }
  executable(bundle);
  function run(extra = {}, inspect = true) {
    const child = spawnSync(process.execPath, [worker, ...(inspect ? ["--inspect-runtime"] : [])], {
      cwd: root, env: { ...env, ...extra }, encoding: "utf8", timeout: 5_000,
      input: inspect ? undefined : `${JSON.stringify({ id: 1, method: "hello" })}\n`,
    });
    assert.equal(child.error, undefined);
    assert.equal(child.status, 0, child.stderr);
    const result = JSON.parse(child.stdout.trim());
    return inspect ? result : result.result.runtime;
  }
  return { root, worker, bin, bundle, packageDir, env, executable, run };
}

test("explicit executable overrides precede the paired browser and preserve version reporting", (t) => {
  const f = fixture(t);
  const explicit = f.executable(path.join(f.root, "chosen-chrome"), "153.0.8010.36");
  const other = f.executable(path.join(f.root, "other-chrome"), "152.0.0.1");
  const result = f.run({ HUNTPROXY_CHROME_EXECUTABLE: explicit, BB_CHROME_EXECUTABLE: other });
  assert.equal(result.chromium_path, explicit);
  assert.equal(result.chromium_version, "153.0.8010.36");
  assert.equal(result.playwright_core_path, f.packageDir);
  assert.equal(result.playwright_version, "1.61.1");
  assert.equal(result.expected_chromium_version, "149.0.7827.55");
  assert.equal(result.headless, true);
  assert.deepEqual(f.run({ HUNTPROXY_CHROME_EXECUTABLE: explicit }, false), result);
});

test("headed mode is explicit and inspection agrees with worker launch metadata", (t) => {
  const f = fixture(t);
  for (const value of ["false", "0", " FALSE "]) {
    const env = { HUNTPROXY_BROWSER_HEADLESS: value };
    assert.equal(f.run(env).headless, false);
    assert.equal(f.run(env).headless_compatibility, false);
    assert.equal(f.run(env, false).headless, false);
  }
  for (const value of ["true", "1", ""]) assert.equal(f.run({ HUNTPROXY_BROWSER_HEADLESS: value }).headless, true);
  const invalid = spawnSync(process.execPath, [f.worker, "--inspect-runtime"], {
    env: { ...f.env, HUNTPROXY_BROWSER_HEADLESS: "sometimes" }, encoding: "utf8", timeout: 5_000,
  });
  assert.notEqual(invalid.status, 0);
  assert.match(invalid.stderr, /HUNTPROXY_BROWSER_HEADLESS must be true or false/);
});

test("launch options retain mode and routing protections for existing probe paths", () => {
  const launchSource = source.slice(source.indexOf("function chromiumLaunchOptions"), source.indexOf("async function launchChromium"));
  for (const headless of [true, false]) {
    const options = vm.runInNewContext(`${launchSource}; chromiumLaunchOptions(null, null, 12345)`, {
      browserRuntime: { headless, chromium_path: "/selected/chrome" }, chromiumProxy: (proxy) => proxy,
    });
    assert.equal(options.headless, headless);
    assert.equal(options.executablePath, "/selected/chrome");
    assert.equal(options.args.includes("--disable-blink-features=AutomationControlled"), false);
    assert.equal(options.args.includes("--force-webrtc-ip-handling-policy=disable_non_proxied_udp"), true);
    assert.equal(options.args.includes("--remote-debugging-port=12345"), true);
    assert.equal(options.args.includes("--disable-quic"), true);
  }
});

test("all override aliases work, with missing paths, directories, and non-executable files skipped", (t) => {
  const f = fixture(t);
  const explicit = f.executable(path.join(f.root, "chosen-chrome"));
  const unusable = path.join(f.root, "not-executable");
  fs.writeFileSync(unusable, "Chromium");
  for (const alias of overrides) assert.equal(f.run({ [alias]: explicit }).chromium_path, explicit);
  assert.equal(f.run({ HUNTPROXY_CHROME_EXECUTABLE: path.join(f.root, "missing"), BB_CHROME_EXECUTABLE: explicit }).chromium_path, explicit);
  assert.equal(f.run({ HUNTPROXY_CHROME_EXECUTABLE: f.root, BB_CHROME_EXECUTABLE: unusable }).chromium_path, f.bundle);
});

test("the version-paired Chromium precedes system Chrome; missing paired Chromium falls back to PATH", (t) => {
  const f = fixture(t);
  const system = f.executable(path.join(f.bin, "google-chrome-stable"), "153.0.8010.36");
  assert.equal(f.run().chromium_path, f.bundle);
  fs.unlinkSync(f.bundle);
  const result = f.run();
  assert.equal(result.chromium_path, system);
  assert.equal(result.chromium_version, "153.0.8010.36");
});

test("package-local installs and explicit Playwright overrides use the same resolution in inspection and hello", (t) => {
  const f = fixture(t);
  const local = path.join(f.packageDir, ".local-browsers");
  fs.mkdirSync(local);
  const localBrowser = f.executable(path.join(local, "paired-chromium"));
  const result = f.run();
  assert.equal(result.chromium_path, localBrowser);
  assert.deepEqual(f.run({}, false), result);
  assert.equal(f.run({ PLAYWRIGHT_BROWSERS_PATH: path.join(f.root, "custom-cache") }).chromium_path, f.bundle);
  assert.match(f.run({ HUNTPROXY_PLAYWRIGHT_CORE_PATH: path.join(f.root, "missing"), BB_PLAYWRIGHT_CORE_PATH: f.packageDir }).compatibility_error, /missing/);
});

test("inspection reports missing Playwright without creating profiles or launching Chromium", (t) => {
  const f = fixture(t);
  fs.rmSync(f.packageDir, { recursive: true });
  assert.match(f.run().compatibility_error, /Cannot find module/);
  assert.equal(fs.existsSync(path.join(f.root, "profiles")), false);
});

test("managed SDKs must match the embedded pin; explicit SDK overrides remain intentional", (t) => {
  const f = fixture(t);
  fs.writeFileSync(path.join(f.root, "package.json"), JSON.stringify({
    type: "module", dependencies: { "playwright-core": "1.63.0" },
  }));
  const local = path.join(f.root, "node_modules", "playwright-core");
  fs.mkdirSync(path.dirname(local));
  fs.cpSync(f.packageDir, local, { recursive: true });
  const stale = f.run({ HUNTPROXY_PLAYWRIGHT_CORE_PATH: "" });
  assert.match(stale.compatibility_error, /1\.63\.0 is required; run HuntProxy browser install/);
  assert.equal(stale.playwright_core_path, undefined);
  assert.equal(f.run().playwright_version, "1.61.1");
  const manifest = JSON.parse(fs.readFileSync(path.join(local, "package.json")));
  manifest.version = "1.63.0";
  fs.writeFileSync(path.join(local, "package.json"), JSON.stringify(manifest));
  assert.equal(f.run({ HUNTPROXY_PLAYWRIGHT_CORE_PATH: "" }).playwright_version, "1.63.0");
});

test("a deliberate SDK override also supports a standalone worker without a package manifest", (t) => {
  const f = fixture(t);
  fs.unlinkSync(path.join(f.root, "package.json"));
  assert.equal(f.run().playwright_core_path, f.packageDir);
});

test("Node 18 inspection reports an actionable requirement without loading Playwright", (t) => {
  const oldNode = "/usr/bin/node";
  if (!fs.existsSync(oldNode) || !spawnSync(oldNode, ["--version"], { encoding: "utf8" }).stdout.startsWith("v18.")) {
    t.skip("Node 18 is not installed");
    return;
  }
  const f = fixture(t);
  const inspected = spawnSync(oldNode, [f.worker, "--inspect-runtime"], {
    env: f.env, encoding: "utf8", timeout: 5_000,
  });
  assert.equal(inspected.status, 0);
  assert.match(JSON.parse(inspected.stdout).compatibility_error, /Node\.js 20 or newer/);
  const launch = spawnSync(oldNode, [f.worker], { env: f.env, encoding: "utf8", timeout: 5_000 });
  assert.notEqual(launch.status, 0);
  assert.match(launch.stderr, /Node\.js 20 or newer/);
  assert.equal(fs.existsSync(path.join(f.root, "profiles")), false);
});

test("missing Chromium keeps Playwright diagnostics available", { skip: process.platform === "darwin" }, (t) => {
  const f = fixture(t);
  fs.unlinkSync(f.bundle);
  const result = f.run();
  assert.equal(result.playwright_version, "1.61.1");
  assert.equal(result.chromium_path, null);
  assert.equal(result.chromium_version, null);
});

test("headless compatibility defaults on, supports an opt-out, and inspects without launching", (t) => {
  const f = fixture(t);
  assert.equal(f.run().headless_compatibility, true);
  for (const value of ["false", "0", " FALSE "]) {
    const result = f.run({ HUNTPROXY_BROWSER_HEADLESS_COMPAT: value });
    assert.equal(result.headless, true);
    assert.equal(result.headless_compatibility, false);
    assert.equal(result.compatibility_error, null);
    assert.deepEqual(f.run({ HUNTPROXY_BROWSER_HEADLESS_COMPAT: value }, false), result);
  }
  // Exercise the runtime's dependency diagnostic independently of whether this
  // host happens to provide a system-wide ws package.
  fs.writeFileSync(path.join(f.root, "headless.js"), `export const headlessDependencyError = () => "Missing dependencies; run HuntProxy browser install";
    export const inspectNativeIdentity = () => { throw Error("Inspection must not launch"); };
    export const createIdentityRelay = () => { throw Error("Inspection must not launch"); };`);
  const result = f.run();
  assert.equal(result.headless, true);
  assert.equal(result.headless_compatibility, true);
  assert.match(result.compatibility_error, /browser install/);
  assert.deepEqual(f.run({ HUNTPROXY_BROWSER_HEADLESS_COMPAT: 'true' }), result);
  assert.deepEqual(f.run({}, false), result);
  assert.equal(fs.existsSync(path.join(f.root, 'profiles')), false);
  const conflict = spawnSync(process.execPath, [f.worker, '--inspect-runtime'], {
    env: { ...f.env, HUNTPROXY_BROWSER_HEADLESS: 'false', HUNTPROXY_BROWSER_HEADLESS_COMPAT: 'true' }, encoding: 'utf8',
  });
  assert.notEqual(conflict.status, 0);
  assert.match(conflict.stderr, /requires headless mode/);
});
