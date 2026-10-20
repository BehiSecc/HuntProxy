import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { test } from "node:test";

const source = fs.readFileSync(new URL("./index.js", import.meta.url), "utf8");
const overrides = ["HUNTPROXY_CHROME_EXECUTABLE", "BB_CHROME_EXECUTABLE", "PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH"];

function fixture(t) {
  fs.mkdirSync("/tmp/artis", { recursive: true });
  const root = fs.mkdtempSync("/tmp/artis/huntproxy-runtime-");
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const worker = path.join(root, "worker.mjs");
  fs.writeFileSync(worker, source);
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
  for (const key of [...overrides, "BB_PLAYWRIGHT_CORE_PATH", "PLAYWRIGHT_BROWSERS_PATH"]) delete env[key];
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
  assert.deepEqual(f.run({ HUNTPROXY_CHROME_EXECUTABLE: explicit }, false), result);
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
  assert.equal(f.run({ HUNTPROXY_PLAYWRIGHT_CORE_PATH: path.join(f.root, "missing"), BB_PLAYWRIGHT_CORE_PATH: f.packageDir }).playwright_core_path, f.packageDir);
});

test("inspection reports missing Playwright without creating profiles or launching Chromium", (t) => {
  const f = fixture(t);
  fs.rmSync(f.packageDir, { recursive: true });
  assert.deepEqual(f.run(), {});
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
