# Changelog

All notable changes to `pallet-relayer` will be documented in this file.

## [0.3.1] - 2026-07-09

### Changed

- Weights regenerated on the benchmark host (AMD EPYC-Genoa, 32 GB). No logic
  change — refreshed alongside the per-note circuit-version release.
  `set_allowed_selectors` no longer scales with its component (`n` → `_n`); the
  measured cost did not vary with the selector count.

## [0.3.0] - 2026-06-03

### Changed

- **`register_relayer` is now sudo/governance-only** (`ManageOrigin`). Previously it was
  a self-service call restricted to validator nodes via `T::IsValidator`. The new signature
  adds an explicit `who: T::AccountId` argument so the privileged origin can register any
  account:
  ```
  // before: register_relayer(origin, evm_address)   — signed by validator
  // after:  register_relayer(origin, who, evm_address) — ManageOrigin (sudo/gov)
  ```
- **Benchmark** for `register_relayer` updated to use `#[extrinsic_call]` with
  `RawOrigin::Root` instead of the previous manual `#[block]` storage-insert approach.
  Measured weights now reflect the real extrinsic dispatch path.
- Event doc comments updated: `RelayerRegistered` and `RelayerUnregistered` now note
  sudo/governance as the acting origin.
- Module-level doc updated: registry is "managed exclusively by sudo/governance".

### Removed

- `T::IsValidator: Contains<AccountId>` — config trait no longer needed. Validator gating
  is handled upstream by `pallet-validator-set`.
- `Error::NotValidator` — removed alongside `IsValidator`.
- `MockValidators` from `mock.rs` — no longer meaningful.

### Migration

Update runtime `Config` impl and any `register_relayer` call sites:
- Remove `type IsValidator = ...` from the `pallet_relayer::Config` impl.
- Change origin from a signed validator to `ManageOrigin` (e.g. `sudo`).
- Add `who: AccountId` as the first call argument before `evm_address`.

---

## [0.2.2] - 2026-06-01

### Changed

- Updated FRAME benchmark weights measured on Hetzner CCX33 (AMD EPYC-Milan, 8 vCPU dedicated, 32 GB RAM). Steps: `50`, Repeat: `20`. All extrinsics refreshed.

## [0.2.1] - 2026-05-22

### Changed

- Updated FRAME benchmark weights measured on Hetzner CCX33 (AMD EPYC-Milan, 8 vCPU dedicated, 32 GB RAM). Steps: `50`, Repeat: `20`. All extrinsics refreshed.

## [0.2.0] - 2026-05-14

### Added
- **`get_active_relayers()`** — new Runtime API method returning all `(evm_address, substrate_account)`
  pairs in `RelayerRegistry`. Allows clients and the RPC relay server to discover which validator
  nodes have relay active (Capa 2).
- **`is_relayer_evm(evm_address)`** — new Runtime API method returning `bool`. Used by
  `orbinum_relayerStatus` to surface on-chain registration state to relay operators (Capa 2).

### Removed
- **`claim_relay_fees` extrinsic** (call_index 4) — removed. Validators must use
  `pallet-shielded-pool::claim_shielded_fees` instead, which inserts a private note into the
  Merkle tree and requires a `value_proof` ZK proof.
- Corresponding benchmark (`fn claim_relay_fees`) and weight entry removed.
- Unit tests `claim_relay_fees_works`, `claim_relay_fees_emits_event`,
  `claim_relay_fees_insufficient_fails` removed.

### Changed
- README: updated `claim_shielded_fees` description — ZK proof requirement changed from
  *disclosure circuit* to *value_proof circuit* (CircuitId 6).
- README: comparison table updated (`ZK proof required: Yes (value_proof circuit)`).

## [0.1.0] - 2026-04-?

### Added
- Initial release: `pallet-relayer` with full relay infrastructure.
- **Storage**: `PendingRelayerFees` (`(AccountId, asset_id) → u128`) and
  `RelayerRegistry` (`H160 → AccountId32`).
- **Events**: `RelayFeeAccumulated`, `RelayFeeConsumed`, `RelayerRegistered`, `RelayerUnregistered`.
- **Errors**: `InsufficientPendingFees`, `AlreadyRegistered`, `NotRegistered`.
- **Extrinsics**: `register_relayer`, `unregister_relayer`.
- **`RelayerInterface` trait**: `accumulate_relay_fee`, `pending_relay_fees`, `consume_relay_fee`.
- Runtime API `RelayerRuntimeApi` with initial methods.
- Full benchmark and weight coverage.
