# Preparing a HuntProxy release

The v0.2.0 candidate is prepared on `release/v0.2.0`. Publication needs human approval. Do not push its tag or publish the GitHub release before the checks below pass.

## Source and assets

The browser worker uses Playwright Core 1.64.0 and its managed Chromium 156.0.8078.4 (revision 1248). The embedded archive and browser metadata are verified against `browser-worker/package-lock.json`. The Node manifest pins verified distribution checksums. Embedded first-party plugins use source commit `d4e1aa3f2907338d40361938deca8c4c711394e7` from HuntProxy-Plugins; the legacy ownership fingerprints use `95ad5b29cb02e8b1aa1c0ec0b6d7cb1e485f0c32`.

Publish the plugin source branch before running candidate CI so that immutable commit is fetchable. The plugin framework v0.2.0 metadata/doc changes do not change the bundled runtime files. Run its complete `npm test` suite and syntax checks.

Verify the embedded bytes against an existing checkout of that source:

```bash
python3 scripts/prepare-release-assets.py /path/to/HuntProxy-Plugins \
  --output-dir resources/release \
  --current-commit d4e1aa3f2907338d40361938deca8c4c711394e7 \
  --playwright-tgz resources/release/playwright-core-1.64.0.tgz \
  --playwright-lock browser-worker/package-lock.json \
  --check
```

## Validation

Run `scripts/check-dependencies.sh` on Linux x86_64 with an isolated
`HUNTPROXY_AUDIT_DIR`. It verifies the pinned cargo-deny download, checks the
locked Rust dependencies against the current advisory database and license
policy, and audits the browser worker's production npm dependencies. CI,
candidate builds, and tag builds require this gate to pass; unavailable audit
services fail the gate.

Run `scripts/check.sh`: formatting, locked Clippy with warnings denied, all normal tests, worker syntax, and the locked release build. Use a disposable data directory for tests, and run the ignored browser suite serially with the pinned SDK and Chromium:

```bash
cargo test --locked --test browser_profile_isolation -- --ignored --test-threads=1
```

Run the ignored upgrade fixture with `HUNTPROXY_LEGACY_BINARY` set to a verified official v0.1.1 executable. The Linux x86_64 release archive SHA-256 is `8d691a62337932db28d1203ca5d860b45b9cfd89c898ee049a627ce1f10d4ac1`.

```bash
cargo test --locked --test upgrade_workflows -- --ignored --test-threads=1
```

The fixture creates real v0.1.1 project data and a full bundle, upgrades a running installation, checks rollback assets, opens saved projects, starts Chromium, imports the old bundle, and repeats preparation. Also verify the real dashboard on desktop and mobile, including a named identity, profile restart, and an invalid-input state. Build and smoke-test Docker against an isolated volume.

The normal test gate includes `mcp_catalog_refresh`: a continuously connected bridge observes a synthetic daemon upgrade, advertises its new schemas, dispatches a call once, and retains the latest catalog while stopped. The real private metadata route must leave the daemon's idle timer unchanged.

Push only the approved candidate branches. Pushing `release/v0.2.0` automatically runs **Build release candidate** on that exact core commit. Require the source checks and all four packaged platform builds to pass: Linux x86_64/ARM64 and macOS Intel/Apple Silicon. Local Linux tests do not replace these platform checks. Record the run URL and candidate commit. Any later source change requires a new candidate run.

The push trigger lets a new candidate workflow run before it is merged. Manual dispatch remains available once the workflow is registered on the default branch, as described in [GitHub's workflow documentation](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/manually-run-a-workflow).

Candidate CI checks the immutable catalog, provisions and launches Chromium, verifies the plugin versions, checks linked libraries, and creates checked archives plus `SHA256SUMS` without making a tag or release.

## Publication checkpoint

Confirm the approved candidate is on the intended default branch, the version is 0.2.0 in Cargo and plugin metadata, the release notes describe the one-time v0.1.1 stop/reconnect requirement, and no unrelated local changes are included.

After explicit approval, create and push `v0.2.0` at that validated commit. The tag workflow validates its version, rebuilds four binaries, verifies the two-member archive contract, and creates a **draft** GitHub release. Compare its assets with the validated candidate, verify `SHA256SUMS`, add the reviewed release notes, then publish the draft only within the approved scope.

Never add a third member to an archive: v0.1.1 rejects it. The packaged `LICENSE` concatenates the project license, embedded-asset notices, and `RUST_THIRD_PARTY_NOTICES.txt`. Regenerate the Rust notices with `python3 scripts/prepare-rust-notices.py` after any `Cargo.lock` change; `scripts/check.sh` rejects stale or incomplete notices. Keep the combined file below 1 MiB so v0.1.1 can still extract it. Keep the existing v0.1.1 release and assets available.

For rollback after migration, restore the matching database/configuration/plugin snapshot together with the previous executable while the daemon is stopped. The CA and browser profiles are preserved in place and are not included in that snapshot. A newer Chromium may upgrade a profile in place, so a rollback that must reopen it in an older browser requires a complete independent backup of the data directory and any configured external paths.
