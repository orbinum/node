# Changelog — fp-self-contained

All notable changes to this crate are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [Unreleased]

---

## [2.0.0-dev] — 2026-10-24

Ships with runtime spec 20.

### Added

- `VerifyFullPayload<AccountId>`: a signature that opts in (`covers_full_payload`)
  is checked over the whole signing payload (`verify_full_payload`), never the
  blake2_256 that Substrate substitutes for payloads longer than 256 bytes.

### Changed

- **Breaking:** `UncheckedExtrinsic`'s `Checkable` impl requires the signature to
  implement `VerifyFullPayload`. Signatures that do not cover the full payload
  keep Substrate's check.

---

## [1.0.0-dev]

Frontier's `fp-self-contained`: self-contained calls (Ethereum transactions)
checked by the call itself instead of the extrinsic signature.
