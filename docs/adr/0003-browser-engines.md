# ADR 0003: Chromium browser engine

**Status:** Accepted  
**Date:** 2026-08-03

## Context

HuntProxy needs one reliable browser engine for modern applications, persistent
authenticated profiles, complete Playwright behavior, and future user takeover.
The previous Lightpanda-first design failed too many real websites and made
browser startup, state migration, and public controls unnecessarily complex.

## Decision

- Chromium is the only supported browser engine.
- The pinned Playwright worker launches Chromium directly.
- Persistent profiles remain under each project's existing `chromium/default`
  directory so upgrades preserve manual logins and service-worker state.
- Portable checkpoints retain cookies plus local/session storage. A legacy
  checkpoint is imported when a project has no initialized Chromium profile.
- Checkpoint values stay in daemon memory only; SQLite stores version/status/hash.
- Chromium authenticates to HuntProxy's proxy with Basic user `bb` and the
  capture token as its password.
- Browser start requires no engine policy, fallback reason, or migration action.

## Compatibility

Legacy database rows and project imports are normalized to Chromium metadata.
HuntProxy does not delete previously installed unsupported browser binaries or
unknown keys in an existing user configuration.
