# Changelog — pallet-validator-set

All notable changes to this pallet are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [0.3.0] — 2026-08-20

Validator onboarding moves off-chain: the two-phase self-registration flow is
gone and sudo records the decision directly. **Breaking** — three call indices
retired, so `transaction_version` must move. Ships alongside `pallet-relayer`
0.4.0, which consumes the new `ValidatorSetInterface`.

### Removed

#### Self-registration flow
`register_validator`, `approve_validator` and `reject_validator` are gone, along
with the `PendingValidators` storage item, the `MaxPendingValidators` Config
constant, the `ValidatorRegistrationRequested` / `ValidatorApproved` /
`ValidatorRejected` events, and the `AlreadyPending` / `NotPending` /
`TooManyPending` / `NoRelayer` errors.

Candidate selection moves off-chain: operators share their `AccountId` and node
details through an external service, and sudo records the decision on-chain with
`add_validator`. The pending queue existed to stage that decision on-chain, and
an on-chain queue that only sudo can drain is a slower way to reach the same
outcome.

`ValidatorPrerequisites` loses `has_relayer`, which severs the last
validator-set → relayer coupling.

**Breaking:** call indices 2, 4 and 5 are retired and must never be reassigned.

### Changed

#### Session-key gate moved to `add_validator`
The session-key check that used to guard `register_validator` now guards
`add_validator`. Without it an approved account with no keys would hold a slot in
the active set without ever authoring, leaving gaps in the slot schedule.

`remove_validator` and `deregister_validator` lose their pending-queue branches
and now share one `remove_from_approved` helper.

### Added

#### `traits` module
`ValidatorPrerequisites`, `OnValidatorRemoved` and the new
`ValidatorSetInterface` now live in `src/traits.rs`, matching the port pattern
`pallet-relayer` already uses for `RelayerInterface`.

`ValidatorSetInterface` answers "is this an active validator" and is implemented
directly on `Pallet<T>`, so a consumer binds to the trait instead of the runtime
hand-writing an adapter over `ApprovedValidators`. The next pallet that needs the
same question costs one line rather than a second adapter.

`OnValidatorRemoved` gains a tuple impl, so a runtime can wire several
subscribers without a combinator struct.

#### `OnValidatorRemoved` hook
A new Config item, notified whenever an account leaves the approved set by either
path. The runtime wires it to `pallet_relayer::clear_relayer` so an EVM relay
binding cannot outlive the validator membership that authorised it.

Deliberately infallible: leaving the set must always succeed, so failing cleanup
can never block removal.

### Fixed

#### Keyless validators no longer hold session slots
`SessionManager::new_session` now filters out approved accounts with no session
keys. `session.purge_keys` is permissionless, so a validator could pass the
`add_validator` gate and then drop its keys, keeping a slot in the Aura schedule
while producing nothing. Checking at add-time alone did not survive that.

#### `remove_validator` was under-weighted
Its benchmark removed an account with no dependent state, so `OnValidatorRemoved`
short-circuited and the recorded weight missed the cleanup writes entirely —
`RelayerByAccount` was annotated `w:0` and `RelayerRegistry` did not appear at
all. `deregister_validator` shares that weight and is user-dispatchable, so the
gap was reachable without sudo. `OnValidatorRemoved` gains a benchmark-only
`setup_removal_state` so the expensive branch is what gets measured.

#### Test isolation
The mock's thread-locals were not reset between tests, so a test that flipped the
session-key gate leaked into whichever test ran next. `ExtBuilder::build` clears
them now.

### Internal

- Section dividers now match `pallet-relayer`'s: previously they appeared only
  inside `#[pallet::call]` and at two different widths, so Config/Storage/Events
  were undivided in one pallet and divided in its sibling.

### Notes
- No migration ships with this change, on the same argument as the bond removal:
  `PendingValidators` must be verified empty on testnet before release. A chain
  with a live queue would need to drain it.
- `spec_version` moves 9 → 10 (removed storage item and Config constant change
  the metadata). `transaction_version` moves 2 → 3 — unlike the bond removal,
  this one deletes call indices.
- Benchmarks are unaffected in coverage: none of the removed calls had a weight
  function of their own. `add_validator`'s benchmark gains a `setup_session_keys`
  step so its throwaway account can pass the new gate, and `remove_validator`'s
  gains `setup_removal_state` so the hook's writes are measured.
- Genesis deliberately skips the session-key gate: this pallet's `genesis_build`
  runs before `pallet_session`'s, so `NextKeys` is still empty and the check
  would reject every account. Chain-spec authors seed both from the same list.
  Pinned by a test so the behaviour is a decision, not an accident.

## [0.2.0] — 2026-08-06

### Removed

#### Validator bond
The 1 000 ORB bond required by `register_validator` is gone, along with the
`ValidatorBond` and `Currency` Config items, the `ValidatorBondOf` storage map,
the `ValidatorBondReserved` / `ValidatorBondReleased` events, and the
`InsufficientBond` error.

Registration is now free. What still gates it is unchanged: the account needs
session keys and a registered EVM relayer, the pending queue is bounded by
`MaxPendingValidators`, and — the part that actually matters — no account enters
the active set without an explicit `approve_validator` from sudo. A bond deters
spam that governance approval already blocks, and on a testnet where operators
are onboarded by hand it only added a funding step.

Consensus is expected to change before mainnet; a staking-based scheme will
bring its own economic gate.

**Breaking:** `register_validator` no longer reserves funds and no longer fails
with `InsufficientBond`. Callers that pre-funded 1 001 ORB to register can stop.

### Notes
- No migration ships with this change: `ValidatorBondOf` was verified empty on
  testnet (0 entries, empty pending queue) before removing it, so there are no
  reserves left stranded. A chain that *had* live bonds would need one.
- `spec_version` moves 7 → 8 at release, since the removed Config constant and
  storage item change the metadata. `transaction_version` stays at 2:
  `register_validator` keeps its call index and its empty signature.

### Verification
50 pallet tests; runtime, `try-runtime` and `runtime-benchmarks` all compile. A
dev-node E2E (`ts-tests/no-bond-no-min-shield.test.cjs`, 11/11) checks that the
constant, the storage map, the events and `InsufficientBond` are all absent from
metadata, and that an account holding 1 ORB — a thousandth of the old bond —
reaches the prerequisite gate instead of failing on funds, reserving nothing on
the way.

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
- `add_validator`, `remove_validator` — benchmarked with `frame_benchmarking::v2`.
  (This entry originally claimed all six calls were benchmarked; the other four
  reused these two weight functions. Corrected in [Unreleased].)

#### Genesis
- `GenesisConfig { initial_validators }` seeds the initial approved set without
  requiring a bond.

---

[0.1.0]: https://github.com/orbinum/orbinum-node/releases/tag/pallet-validator-set-v0.1.0
