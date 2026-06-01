# Changelog

All notable changes to `pallet-account-mapping` will be documented in this file.

## [0.3.1] - 2026-06-01

### Changed

- Updated FRAME benchmark weights measured on Hetzner CCX33 (AMD EPYC-Milan, 8 vCPU dedicated, 32 GB RAM). Steps: `50`, Repeat: `20`. All extrinsics refreshed.

## [0.3.0] - 2026-05-29

### Added

- **`Config::NativeEvmChainId: Get<u32>`** — new required pallet constant. Declares the native EVM chain ID of the runtime (e.g. `2700` for Orbinum testnet). Used by `dispatch_as_linked_account` to reject calls where the chain link targets the native EVM chain. **Breaking: all existing `Config` implementations must add this constant.**
- **`Config::is_implicit_evm_account(account: &Self::AccountId) -> bool`** — new optional hook with default `false`. Runtimes using `OrbinumSignature` (Fase 3) should override this to return `true` for secp256k1 accounts (where `AccountId32 = [H160 | 0x00×12]`), enabling the storage-free mapping path. Non-secp256k1 runtimes require no change.
- **`Error::UseNativeSignatureForEvmAccounts`** — returned by `dispatch_as_linked_account` when `chain_id == T::NativeEvmChainId::get()`. Secp256k1 accounts sign Substrate extrinsics directly via `OrbinumSignature`; no chain-link dispatch is needed or allowed for native EVM links.

### Changed

- **`map_account`** — for accounts where `is_implicit_evm_account` returns `true`, the call is now event-only: emits `AccountMapped` without writing to `OriginalAccounts` or `MappedAccounts` storage. The H160 mapping is structurally derivable from the `AccountId32` suffix and requires no storage entry. Sr25519/Ed25519 accounts are unaffected.
- **`unmap_account`** — for implicit secp256k1 accounts, cleans up any legacy storage entry from before Fase 3 if one exists, then emits `AccountUnmapped` and returns. If no legacy entry exists, derives the address implicitly. Sr25519/Ed25519 path is unchanged.
- **`dispatch_as_linked_account`** — added guard: rejects calls where `chain_id == T::NativeEvmChainId::get()` with `UseNativeSignatureForEvmAccounts`.
- **`benchmarking.rs`** — `evm_account<T>()` helper seed byte changed from `0x42` to `100` for consistent behavior between the production `AccountId32` and the `u64` test mock. `map_account` benchmark assertion updated: post-Fase-1, secp256k1 accounts do not write to `OriginalAccounts`, so the assertion is now `assert!(!OriginalAccounts::<T>::contains_key(&caller))`.

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
