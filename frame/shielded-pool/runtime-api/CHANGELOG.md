# Changelog

All notable changes to `pallet-shielded-pool-runtime-api` will be documented in this file.

## [Unreleased]

## [0.4.1] - 2026-10-21

### Changed

- `authors` is inherited from the workspace (`Orbinum Technologies
  <contact@orbinum.com>`). No code change.

## [0.4.0] - 2026-10-13

**Breaking** — the relayer layer is gone. `ShieldedPoolRuntimeApi` is
`api_version(5)`.

### Removed

- `relay_config()` and its `RelayConfig` type.
- `relay_commit_hash(calldata, relayer)`.
