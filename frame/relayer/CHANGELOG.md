# Changelog

All notable changes to `pallet-relayer` will be documented in this file.

## [0.5.0] - 2026-08-21

Two guards on relay configuration. **Breaking** — `Config::MaxMinRelayFee` is a
new required associated type, so any runtime implementing `Config` must add it.

### Changed

#### `set_min_relay_fee` is bounded
`ManageOrigin` could previously set the minimum relay fee to any `u128`. A value
large enough would make the EVM relay unusable: every shielded call would fail
`FeeTooLow`, and the node's relay would reject the calldata before it reached the
pool — with no way back until the next runtime upgrade, since the call that would
lower it again has to run on the broken runtime.

New `Config::MaxMinRelayFee` (1 ORB in the runtime, a thousand times the default)
and error `MinRelayFeeTooHigh`. This is not a defence against an attacker —
governance is already trusted — but against a typo in a governance call.

#### `get_active_relayers` is capped
The runtime API collected the whole `RelayerRegistry` with no bound, and a
runtime API runs inside its caller's block or RPC budget.

Capped at 256 entries via `.take()`. Nothing can hit that today: the method has
no callers — the RPC trait exposes only the three O(1) methods — and
registration is gated on the validator set, so the registry cannot exceed
`MaxValidators`. The cap is headroom for whoever wires this up later, when
neither of those may still hold.

## [0.4.0] - 2026-08-20

EVM relay registration becomes self-service, gated on validator-set membership
and on a signature proving the caller holds the EVM key. **Breaking** —
`register_relayer` changes both its origin and its signature, so
`transaction_version` must move. Requires `pallet-validator-set` 0.3.0 for the
`ValidatorSetInterface` bound.

### Changed

#### `register_relayer` is now self-service
The call drops its `who` parameter and moves from `ManageOrigin` to `Signed`: an
operator registers their own EVM relay address rather than asking sudo to do it.
Since the owner is the signer, no account can bind an address on another's
behalf.

`ManageOrigin` did two jobs: it kept arbitrary accounts out, and it let
governance verify the operator actually owned the address. The new
`ValidatorSet` gate — only accounts in the approved validator set may register —
replaces the first. The second needed the ownership proof below; the gate alone
would have left a rival's public address claimable. The `AlreadyRegistered` and
`AccountAlreadyRegistered` guards are unchanged.

**Breaking:** `register_relayer(who, evm_address)` becomes
`register_relayer(evm_address, signature)`, signed by the owner. Callers using
the sudo path must invert the order: sudo approves the validator first, then the
operator registers, supplying the proof from `relayer_getRelayInfo`.

### Added

#### Proof of control over the EVM address
`register_relayer` now takes a second argument: a secp256k1 signature over a
digest binding the domain tag, the chain's genesis hash, the registering
`AccountId` and the address being claimed.

Without it the account-set gate alone was not enough. A relay address is
**public** — it is the `caller` of every relay transaction — and the registry is
first-come-first-served with no override. Any approved validator could therefore
register a rival's address, divert its relay fees, and lock the rightful owner
out permanently via `AlreadyRegistered`. The old `ManageOrigin` design blocked
this because governance reviewed each pair; the validator-set gate replaced only the
anti-Sybil half of that review, not the ownership half. The signature replaces
the other half.

The genesis hash makes a signature non-replayable across chains, and binding the
`AccountId` stops a signature observed on-chain from being reused by a different
account. No nonce is needed: a given `(account, address)` pair can only be
registered once.

`relayer_getRelayInfo` produces the signature from the node's `evmr` key, so
operators never assemble the digest by hand. See `evm_proof.rs`.

- `Config::ValidatorSet` — gate for `register_relayer`, bound to
  `pallet_validator_set::ValidatorSetInterface`. Its `()` impl denies everything
  on purpose: a permissive default would silently disable the gate in a runtime
  that forgot to wire it. (Previously a `ValidatorCheck` trait defined here; it
  now lives in `pallet-validator-set` as a provider trait, matching how
  `RelayerInterface` is defined by this pallet and consumed by shielded-pool.)
- `Error::NotValidator`, `Error::BadEvmSignature`, `Error::InvalidEvmAddress`.
- Rejection of the zero address and the reserved precompile range
  (`0x0..=0xffff`) — those "callers" originate inside the runtime, so no key
  could sign for them.
- `Pallet::clear_relayer(who)` — infallible, idempotent removal of both registry
  indices. The runtime calls it when an account leaves the validator set, so a
  relay binding cannot outlive the membership that authorised it. Emits
  `RelayerUnregistered`, so that event now has two sources.

### Node-side change (breaks running validators)

The node no longer derives its EVM relay key from the Aura mnemonic. It reads a
key of type `evmr` from the keystore instead, so the operator chooses their EVM
identity independently of their consensus identity — which is what makes the
freely-chosen address in `register_relayer` meaningful.

`evm_key_from_keystore` in `template/node/src/service.rs` now scans for `evmr`
rather than `aura`, and `template/node/src/relayer_register.rs` is deleted: it
derived the address from the Aura key and told the operator to ask sudo, both of
which are now wrong. Its startup log is replaced by a line reporting the relay
address, or a warning when no key is present.

**Every running validator is affected.** Without an `evmr` key the node still
authors blocks — only relaying stops. To keep the EVM address already registered
on-chain, recover the previously-derived key with
`scripts/vk/derive-legacy-evm-key.cjs` and insert it with `author_insertKey`.

### Migration

**None.** The new rules — registration requires validator-set membership, leaving
the set clears the binding — do not reach backwards: a binding created under the
old sudo-gated call could belong to any account, and would keep resolving in the
fee path forever.

That gap is empty on this network. The testnet runs 5 validators, all
operator-owned, all in the approved set, so every existing binding already
satisfies the invariant. Same argument as the `PendingValidators` check and the
0.2.0 bond removal: verified rather than assumed.

**A chain where that does not hold needs a migration** that iterates
`RelayerByAccount` and calls `clear_relayer` for any holder outside
`ApprovedValidators`. Verify before upgrading:

```
api.query.relayer.relayerByAccount.entries()   // every holder
api.query.validatorSet.approvedValidators()    // must be a superset
```

### Internal

Structure only, no behaviour change:

- **`evm_proof.rs` owns the whole proof scheme.** The genesis-hash lookup moved
  out of the pallet, and the EVM address derivation — which had drifted into
  three copies across the pallet, the node RPC and the test helper — is now the
  single `evm_address_from_uncompressed`. Three copies of a five-line crypto
  expression is how two of them silently stop agreeing.
- **`is_usable_relay_address`** replaces the inline address policy in `lib.rs`;
  the pallet keeps only the translation to `Error::InvalidEvmAddress`.
- **`benchmarking_support` renamed to `test_signing`** — 17 of its 18 callers are
  tests, so the old name advertised the minority case and its own doc comment had
  to correct it.
- **`registry_tests.rs` split** (563 lines) into `registry_tests`,
  `ownership_proof_tests` and `cleanup_tests`, matching the one-concern-per-file
  shape the other test modules already had.
- Dead code removed: the unused `ValidatorSetInterface` re-export, the `addr`
  mock module (hardcoded addresses can no longer be registered), and a
  single-use benchmark helper.

Node side:

- **`template/node/src/evm_relay_key.rs`** now owns the question of which key
  this node relays with — keystore scan, dev-key refusal, dev-mode fallback and
  the startup report. `service.rs` calls `resolve()` and `report_identity()`;
  it drops from 982 to 822 lines and no longer knows the keystore file format.
  The module carries 10 tests of its own, exercising a real temp keystore: a
  missing directory, an empty one, an `aura`-only entry, a dev key (refused), a
  real mnemonic (loaded deterministically) and a corrupt file (skipped, not
  fatal). None of that had test coverage before.
- **Dead hex parsing deleted from `rpc/relayer_author.rs`** — `parse_h160` and
  `hex_nibble` had no callers anywhere in the repo, yet carried 12 tests between
  them: 165 of the file's 303 lines testing something unreachable, while
  `get_relay_info` had none.

### Notes
- `PendingRelayerFees` is deliberately left untouched by `clear_relayer`. Those
  fees were already earned and stay claimable through `claim_shielded_fees`;
  clearing a binding is not confiscation.
- `RelayerRegistry` and `RelayerByAccount` keep their types, so existing entries
  survive the upgrade without migration. They do not survive the account later
  being removed from the validator set — that now clears the binding.
- The relay fee fallback to the block author is unchanged: an unregistered
  relayer still credits the block author rather than failing the transaction.
- `register_relayer`'s weight changed in substance: it loses the root origin
  check and gains an `ApprovedValidators` read (r:1 w:0, max_size 1025), now
  visible in the regenerated proof size. **Weights were regenerated on a dev
  machine (macOS ARM), not the usual benchmark host (AMD EPYC-Genoa, 32 GB) —
  rerun `scripts/run_benchmarks.sh` there before release.**
- `scripts/run_benchmarks.sh` gains `pallet_validator_set`, which was registered
  in `define_benchmarks!` but missing from the runner, so its weights were never
  regenerated.

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
