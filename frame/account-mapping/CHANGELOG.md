# Changelog

All notable changes to `pallet-account-mapping` will be documented in this file.

## [0.2.1] - 2026-05-22

### Changed

- Updated FRAME benchmark weights measured on Hetzner CCX33 (AMD EPYC-Milan, 8 vCPU dedicated, 32 GB RAM). Steps: `50`, Repeat: `20`. All 16 extrinsics refreshed.

### Fixed

- `benchmarking.rs`: replaced `T::AccountId: From<[u8; 32]>` bound (which broke compilation in mock runtimes with `type AccountId = u64`) with a `scale_codec::Decode`-based helper. The `evm_account<T>()` function now decodes a 32-byte slice into `T::AccountId` without requiring the `From<[u8; 32]>` trait bound.

## [0.2.0] - 2026-05-14

### Added

- Initial tracked release.
- EVM ↔ Substrate account mapping via `AccountMapping` storage.
- `link_evm_address` and `unlink_evm_address` extrinsics.
- Full benchmark and weight coverage.
