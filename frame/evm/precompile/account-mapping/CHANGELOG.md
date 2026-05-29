# Changelog

All notable changes to `pallet-evm-precompile-account-mapping` will be documented in this file.

## [0.2.0] - 2026-05-29

### Added

- **`dispatchAsLinkedAccount` precompile selector (`0x0630cef9`)** — exposes `pallet_account_mapping::dispatch_as_linked_account` to EVM clients. Any EVM address can relay a SCALE-encoded `RuntimeCall` on behalf of a Substrate account, authorized by the external wallet registered as a chain link. The external wallet signs `eip191(keccak256(SCALE(call)))` without needing to interact with the Substrate RPC layer.
- Added `use alloc::boxed::Box` import required for `no_std` / WASM target compatibility.
- Added `use scale_codec::Decode` import and `scale-codec` dependency for decoding `AccountId32` and `RuntimeCall` from ABI input.
- Three new unit tests in `tests.rs`:
  - `dispatch_as_linked_account_short_input_returns_error` — verifies inputs shorter than 160 bytes return an ABI error.
  - `dispatch_as_linked_account_invalid_scale_call_returns_error` — verifies invalid SCALE bytes trigger a decode error.
  - `dispatch_as_linked_account_routes_to_pallet_with_valid_abi` — verifies a fully ABI-encoded call routes correctly to the pallet.

## [0.1.0] - 2026-05-14

### Added

- Initial release.
- EVM precompile for `pallet-account-mapping` at address `0x0000000000000000000000000000000000000800`.
- Selectors: `mapAccount`, `unmapAccount`, `isEvmSuffixAccount`, `toEvmAddress`, `resolveAliasFull`, `registerAlias`, `releaseAlias`, `transferAlias`, `putAliasOnSale`, `cancelSale`, `buyAlias`, `resolveAlias`, `getAliasOf`, `addChainLink`, `removeChainLink`, `registerPrivateLink`, `removePrivateLink`, `revealPrivateLink`, `hasPrivateLink`, `setAccountMetadata`.
