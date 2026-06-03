# Changelog — pallet-validator-set

All notable changes to this pallet are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [0.1.0] — 2026-06-03

### Added

#### Two-phase validator registration
- `register_validator` — Any candidate may self-register by locking `ValidatorBond`
  (1 000 ORB). Requires session keys (`session.setKeys`) and an EVM relay address
  (`relayer.registerRelayer`) to be registered first (`ValidatorPrerequisites` check).
- `deregister_validator` — Validator or pending candidate may exit voluntarily; bond
  is returned immediately.

#### Governance / sudo calls
- `add_validator(who)` — Directly add a trusted account to the approved set (no bond).
- `remove_validator(who)` — Force-remove from pending or approved; bond returned if held.
- `approve_validator(who)` — Move a pending candidate to the approved set; takes effect
  at the next session rotation.
- `reject_validator(who)` — Remove a pending candidate and return the bond.

#### Storage
- `ApprovedValidators` — Bounded vec of active validator `AccountId`s (drives session
  rotation via `SessionManager`).
- `PendingValidators` — Bounded vec of candidates awaiting governance approval.
- `ValidatorBondOf` — Per-account bond amount reserved at self-registration time.

#### Events
- `ValidatorAdded` — Emitted by `add_validator`.
- `ValidatorRemoved` — Emitted by `remove_validator`.
- `ValidatorRegistrationRequested` — Emitted by `register_validator`.
- `ValidatorApproved` — Emitted by `approve_validator`.
- `ValidatorRejected` — Emitted by `reject_validator`.
- `ValidatorBondReserved` — Emitted when the bond is locked.
- `ValidatorBondReleased` — Emitted when the bond is returned.

#### Errors
- `AlreadyValidator`, `AlreadyPending`, `NotValidator`, `NotPending`
- `TooManyValidators`, `TooManyPending`
- `InsufficientBond`
- `NoSessionKeys` — session keys not yet set via `session.setKeys`.
- `NoRelayer` — EVM relay address not yet registered via `relayer.registerRelayer`.

#### Config traits
- `AddRemoveOrigin` — Origin for sudo/governance calls (`EnsureRoot` in production).
- `Currency` — `ReservableCurrency` used to lock/unlock the bond.
- `MaxValidators` — Upper bound for the approved set.
- `MaxPendingValidators` — Upper bound for the pending queue.
- `ValidatorBond` — Bond amount (constant; 1 000 ORB with 18 decimals).
- `Prerequisites: ValidatorPrerequisites<AccountId>` — Pluggable prerequisite gate.
- `WeightInfo` — Benchmarked call weights.

#### SessionManager integration
- Implements `pallet_session::SessionManager<AccountId>` using `ApprovedValidators` as
  the authoritative validator set. Validator changes take effect at the next session.

#### Benchmarks
- `add_validator`, `remove_validator`, `approve_validator`, `reject_validator`,
  `register_validator`, `deregister_validator` — all benchmarked with
  `frame_benchmarking::v2`.

#### Genesis
- `GenesisConfig { initial_validators }` seeds the initial approved set without
  requiring a bond.

---

[0.1.0]: https://github.com/orbinum/orbinum-node/releases/tag/pallet-validator-set-v0.1.0
