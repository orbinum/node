# Changelog — pallet-zk-verifier

All notable changes to this pallet are documented here.

---

## [Unreleased]

## [0.17.0] - 2026-10-09

### Changed

- A key is stored prepared as well (`PreparedKeys`, written and removed with it),
  and a proof is verified from that form instead of preparing the key each time:
  `verify_proof` measured 5.6 → 2.6 ms in Wasm. The prepared form is loaded
  without re-validating its points, after a layout check; a missing one falls
  back to preparing the key.
- Key storage lives in one module (`keys`): a key, its hash and its prepared
  form are written, removed and purged together, and nothing else writes
  `PreparedKeys`.
- **Storage v2:** `migrations::v2::MigrateToV2` prepares every key already
  stored, overwriting any prepared form there (a key that does not prepare loses
  it); the runtime must list it in its migrations. Under `try-runtime`,
  `post_upgrade` checks every prepared form is its key's preparation and none is
  orphaned.
- Weights need regenerating. Measured here (Apple M, `--steps 50 --repeat 20`):

  | Call | Committed (EPYC) | Regenerated |
  |---|---|---|
  | `verify_proof` | 10.37 ms, 3.9 KB proof | 2.43 ms, 38 KB proof |
  | `register_verification_key` | 2.36 ms | 4.12 ms |
  | `batch_register_verification_keys` | 0.06 + 3.5·n ms | 4.10 + 3.5·n ms |
  | `set_active_version`, `unretire_version` | 0.015 ms | 1.23 ms (they validate the key since 0.16.0) |
  | `remove_verification_key`, `purge_circuit` | ~unchanged | ~unchanged |

## [0.16.0] - 2026-10-08

### Security

- **Breaking:** a spend circuit (transfer, unshield) never takes a key of the
  base layout, at any version: such a key binds neither the memos nor the full
  recipient. The `FIRST_VERSION` exception is gone; genesis keys for spend
  circuits must be memo-bound. Shield is unchanged.
- `unretire_version` re-checks the key against the same rule, so a base spend
  key retired for being unsafe cannot come back. It now reads the key:
  `unretire_version`'s weight needs regenerating.
- A base spend key already in storage — left by an older runtime or a raw
  storage write — verifies nothing: the verifier refuses the layout on every
  path, so a proof under it cannot spend with swapped memos. `set_active_version`
  refuses such a key too; it now reads the key, so its weight needs
  regenerating as well.
- `encode_transfer` / `encode_unshield` return `None` for the base layout: the
  base encoding of a spend, and the raw-recipient path with it, is gone.
- The `verify_proof` benchmark seeds its key under an id outside the known
  table: a known circuit admits only its own arities, so most `n` would skip
  the pairing and the regenerated weight would fall far below the real cost.

## [0.15.0] - 2026-10-08

### Changed

- **Breaking:** `TransferStatement.merkle_root` → `merkle_roots: [[u8; 32]; 2]`,
  the root each input is proven against.
- `encode_transfer` emits both roots under a cross-tree key (circuit 1, v3). Under
  a v1 or v2 key, which attests to one root, a statement whose roots differ
  fails without a pairing.
- `encode_transfer` / `encode_unshield` return `Option`: `None` when the key
  cannot attest to the statement. `verify_statement` takes such an encoder.
- A transfer key of 9 inputs registers (cross-tree layout); the governance rule
  on `register_verification_key` documents the exception.
- `verification_weight` covers the 9-input layout (was 8), read from
  `max_public_inputs`.

## [0.14.0] - 2026-10-05

### Added

- `CircuitId::SHIELD` (3), `ShieldStatement` and
  `ZkVerifierPort::verify_shield_proof`. Inputs are `commitment | value | asset_id`,
  `value` as a `u128` field element.

### Changed

- **Registration's base-layout rule applies to spend circuits only.** A shield key
  takes its 3-input arity at every version; a 4-input shield key is refused.

## [0.13.0] - 2026-09-29

### Added

- `VkBytes`, the stored key type (`MAX_VK_BYTES`).

### Changed

- **v1 → v2 rotation is done by Root after the upgrade**: register each
  memo-bound key as version 2, `set_active_version(2)`, `retire_version(1)`.
  No keys are embedded in the runtime and no migration runs; `STORAGE_VERSION`
  stays 1.
- **Version ↔ layout policy.** For the transfer and unshield circuits, a key
  with the base (v1) layout is refused for any version other than 1
  (`register_verification_key`, `batch_register_verification_keys`): a v1 key
  registered as "v2" would retire the real v1 and still let memos and the
  recipient go unbound.

- **Statements and input layouts.** `verify_transfer_proof` /
  `verify_unshield_proof` take a `TransferStatement` / `UnshieldStatement` (the
  spend's domain values, the recipient's raw bytes and the memo digest) instead
  of positional field elements. The pallet now owns all public-input encoding:
  the key's arity picks `InputLayout::Base` (v1) or `MemoBound` (base + 1), and
  `encoding` builds that layout. **Breaking** for `ZkVerifierPort` implementors.
- **Memo-bound (v2) layout.** Appends `memo_hash = memo_digest mod r` and binds
  the unshield recipient as `blake2_256(recipient) mod r`, so an alias `R ± r`
  no longer verifies. v1 keys keep the old encoding until retired.
- **One key decode per proof.** `verifier::verify_statement` / `verify_raw`
  prepare the key once and verify against it; a key that does not deserialize
  fails the proof instead of silently skipping the memo binding. Inputs that do
  not fill the key's arity fail too.
- `ZkVerifierPort::verification_weight()`: the weight of one verification, for
  callers to add to their own. **Breaking** for `ZkVerifierPort` implementors.
- `set_active_version` refuses a retired version (`UnsupportedCircuitVersion`):
  wallets proving against the active version would produce proofs that always
  fail.
- The `register_verification_key` security note now allows a memo-bound
  version of an existing circuit id.
- Every registration path (both extrinsics, genesis) goes through one
  `register_vk` helper; activation through `activate`. A
  registration now emits `VerificationKeyRegistered` before `ActiveVersionSet`.
  The separate `>= 256` byte check is gone: key deserialization checks the exact
  length.
- `verification_weight()` derives the largest spend layout from the circuit
  constants instead of a literal 8.

### Removed

- `ZkVerifierPort::verify_value_proof`, `encoding::encode_value_proof` and
  `CircuitId::VALUE_PROOF`. Relay fees are now claimed publicly, so the
  value_proof circuit (id 6) has no caller. **Breaking** for `ZkVerifierPort`
  implementors.
- Circuit 6 left the live table, so `purge_circuit(6)` can clear its keys once
  this runtime is deployed.

### Internal

- Tests moved to `src/tests.rs`, grouped by call; shared mock helpers. `register_vk` takes `set_active` and is the only place a key is registered or activated; `FIRST_VERSION` names the base-layout version.

---

## [0.12.0] - 2026-08-07

### Security

- **Circuit ids that do not fit a `u8` are rejected instead of truncated.**
  `expected_public_inputs` takes a `u8`, and `ensure_vk_arity` reached it through
  `circuit_id.0 as u8` — so id 257 aliased onto 1 and a key was validated against
  TRANSFER's arity, then stored under an id no lookup could reach. Now guarded
  with `u8::try_from`, the same way `purge_circuit` already guarded the same
  table. Root-gated, so this is an operator-error amplifier rather than an attack
  primitive; what made it worth closing is that it failed silently.

  Ids inside `u8` but outside the known table are unaffected: they carry no
  expected arity, so only "deserializes as a BN254 key" applies to them.

- **Genesis validates its keys.** `build` checked length alone, so a well-sized
  but meaningless key was stored and the chain only discovered it when the first
  real proof failed to verify — at which point nothing distinguishes a bad key
  from a bad proof. Genesis now routes through the same `ensure_vk_arity` as
  `register_verification_key`, turning that into a chain that refuses to start.

  **Breaking for genesis configs carrying placeholder keys.** Two of this
  pallet's own tests were doing exactly that (`vec![0xCCu8; 300]`) and now fail;
  they were updated to real keys.

### Fixed

- A test helper's doc claimed the TRANSFER circuit has arity 5 while the constant
  it reads is 7. Rewritten to point at the constant instead of restating the
  number, which is how the two drifted apart.

### Notes

- The aliasing guard was verified by reverting it and confirming
  `register_vk_rejects_circuit_id_that_would_alias` fails.
- A dev-node E2E (`ts-tests/node/zk-verifier-input-bounds.test.cjs`, 9/9) covers
  the live path: genesis keys pass the new check at startup, all three real VKs
  register through `setup-dev-local.sh`, an 8 KiB filler key is refused with
  `InvalidVerificationKey`, id 257 is refused and stores nothing, and the chain
  keeps producing blocks throughout.

---

## [0.11.0] - 2026-08-04

### Removed
- **`migrations` module.** Every live chain is at storage version v1 (verified
  on-chain against testnet at block 283941) and a fresh chain starts there via
  genesis, so `MigrateToV1` was a no-op guarded by its version check. Removed
  alongside the shielded-pool migrations. Storage version history stays
  documented on `STORAGE_VERSION`; see git history if an old chain ever needs
  the code. `STORAGE_VERSION` itself is unchanged (still v1) — this removes the
  upgrade path, not the on-chain layout.

---

## [0.10.0] - 2026-08-03

### Added

- **`purge_circuit(circuit_id)`** (call index 7, Root) — erases every version of a
  circuit the runtime no longer implements, clearing all five maps:
  `VerificationKeys`, `VkHashes`, `VerificationStats`, `RetiredVersions` and
  `ActiveCircuitVersion`.

  It fills a gap the other calls could not: `remove_verification_key` and
  `retire_version` both refuse to touch a circuit's active version, which is what
  keeps a live circuit from ending up with no key to verify against. That same
  guard makes them unable to retire a circuit as a whole, since its last version
  is by construction the active one.

  The guard here is inverted rather than removed: a circuit is purgeable **only**
  when `expected_public_inputs` returns `None` for its id. Transfer (1), unshield
  (2) and value_proof (6) are rejected with `CircuitStillInUse` for as long as
  they remain compiled in, regardless of storage contents. Ids above `u8::MAX`
  are rejected outright rather than truncated into that lookup, so a circuit
  numbered past 255 cannot alias onto a live id.

  The call clears `ActiveCircuitVersion` instead of requiring it to be empty.
  Requiring it would make the extrinsic unreachable: the first
  `register_verification_key` for a circuit activates the version it registers,
  and no extrinsic ever clears that entry — `set_active_version` only overwrites,
  and `retire_version` and `remove_verification_key` both refuse the active
  version. An id the runtime no longer knows has no verification route whatever
  that entry says.

  New errors: `CircuitStillInUse`, `CircuitHasNoStorage`. New event:
  `CircuitPurged { circuit_id, removed }`, where `removed` counts storage entries
  across every map — not versions — so an indexer reconciling against its own
  view gets the real figure even when the maps hold different version sets. The
  weight is still charged per version, which is what the benchmark measures.

- **`STORAGE_VERSION`** and a `migrations` module — the pallet had neither.

- **`migrations::v1::MigrateToV1`** — drops the retired `private_link` circuit
  (id 5) during the runtime upgrade, so chains carrying its key from an earlier
  runtime need no manual call. The id is hardcoded rather than derived: this runs
  once, only on chains still at storage v0, where 5 can only mean `private_link`.

  Without this the key would linger and stay visible — `get_all_circuit_versions`
  iterates storage keys with no allowlist, so explorers kept listing a circuit
  the runtime could not serve.

### Fixed

- **`remove_verification_key` no longer strands satellite entries.** It cleared
  `VerificationKeys` and `RetiredVersions` but left `VkHashes` and
  `VerificationStats` behind, so a removed version kept a hash and a stats row no
  call could reach. That also skewed the version count `store_vk` uses to enforce
  `MAX_VERSIONS_PER_CIRCUIT`. All four maps are now cleared together.

### Note

`weights.rs` was regenerated for the whole pallet on reference hardware
(Hetzner CCX33, AMD EPYC-Genoa, steps 50 / repeat 20), so `purge_circuit` is
measured under the same conditions as every other extrinsic in the file rather
than extrapolated. Model: `59.5µs + 10.75µs * v`, 9 + 4v reads, 3 + 4v writes.
At the 64-version cap the call stays well under 10% of a 2000ms block, asserted
by `purge_circuit_at_the_cap_fits_in_a_block`.

---

## [0.9.0] - 2026-07-09

### Added

- **`Error::UnsupportedCircuitVersion`** — `verifier::verify` now distinguishes an
  explicit version request with no registered VK (→ `UnsupportedCircuitVersion`)
  from a `None`/active-unset resolution (→ `CircuitNotFound` /
  `VerificationKeyNotFound`), giving callers a clear "that version is not
  supported" signal instead of a generic key-not-found.
- **`ZkVerifierPort::is_supported_version(circuit_id, version) -> bool`** — returns
  whether a VK is registered for `(circuit, version)` AND not retired, so callers
  (e.g. the shielded-pool `validate_unsigned`) can reject an unsupported version early.
- **Dedicated benchmarks + `WeightInfo` for `retire_version` / `unretire_version`**
  so both weigh their own storage cost instead of borrowing
  `remove_verification_key`'s.

### Security

- **Version retirement (`retire_version` / `unretire_version`, Root only)** — a
  `RetiredVersions` set lets governance refuse proofs for a `(circuit, version)`
  whose VK is compromised/weak, WITHOUT deleting the VK (audit + stats preserved).
  `verify` and `is_supported_version` reject a retired version fail-closed. This
  closes the downgrade-to-weak-key path: superseding an active version with
  `set_active_version` does not disable the old VK, so a caller could still request
  the old version explicitly; retiring it makes notes minted under it unspendable
  (the nuclear option for a bad VK). The active version cannot be retired.
- **`MAX_VERSIONS_PER_CIRCUIT = 64` cap** on registered versions per circuit
  (`store_vk`), bounding the versions DoubleMap and the runtime-API iteration.
  Registration is Root-only, so this is operator-discipline, not an attacker limit.
- **Stored VK hash (`VkHashes`)** — `blake2_256(key_data)` is computed once at
  registration and read by the runtime API, instead of re-hashing every VK (up to
  8 KB) on each RPC call. Falls back to recompute for keys registered earlier.
- **Documented the circuit-version security invariant** on `register_verification_key`:
  a new version of an existing circuit id must be a key rotation of a semantically
  identical circuit; a semantic change must use a NEW circuit id. The note commitment
  does not bind the version (shielded-pool Limitation 1), so this is a governance-
  enforced rule that `ensure_vk_arity` (arity only) cannot check.

### Changed

- **Weights regenerated** on the benchmark host, including real measured weights
  for `retire_version` (~20.96ms) and `unretire_version` (~15.41ms).

### Fixed

- **VK registration no longer rejects valid transfer keys.** `ensure_vk_arity`
  compares a key's arity against `expected_public_inputs`, which returned 5 for
  transfer while the circuit (and every published VK) has arity 7. Registering a
  transfer VK failed with `InvalidVerificationKey`. Fixed upstream in
  `orbinum-zk-verifier` (`TRANSFER_PUBLIC_INPUTS` 5 → 7).

## [0.8.0] - 2026-07-04

### Security
- Proof-verification bypass is no longer tied to `runtime-benchmarks`. It now lives
  behind a dedicated `skip-proof-verification` feature that `runtime-benchmarks`
  does NOT enable, so a release runtime that exposes benchmarks still verifies
  proofs. An `integrity_test` panics at runtime construction if the bypass feature
  is ever compiled into a live runtime.

### Changed
- `verify_proof` now requires each public input to be exactly 32 bytes and rejects
  shorter inputs with `InvalidPublicInputs`, instead of silently zero-padding them
  into a different field element.
- `verify_proof` weight now scales with the number of public inputs
  (`WeightInfo::verify_proof(n)`) instead of a flat cost, since verification does
  one G1 scalar-mul per input. Prevents underpricing a many-input proof.
- The `verify_proof` benchmark is now parametrized by `n` (`Linear<1, 32>`): it
  builds a synthetic VK of arity `n` so the runner measures the real per-input
  slope. `weights.rs` regenerated on reference hardware — `verify_proof(n)` now
  carries the measured per-input term over the Groth16 pairing base.
- Stat recording moved into `verifier::record_stats` with a doc-comment on the
  call-path asymmetry: failed verifications persist via the Port path
  (`Ok((false, _))`) but are reverted on the `verify_proof` extrinsic (`Err`).
  Persisting Port-side failures is deliberate — it surfaces invalid proofs
  reaching the pool.

### Removed
- `CircuitId::SHIELD` (3) — shield is a direct deposit with no proof, so the
  constant was never used on-chain. IDs 3 and 4 are retired and must not be
  reused.

### Security
- `register_verification_key` and `batch_register_verification_keys` now validate
  that the verifying key deserializes as a BN254 Groth16 key and that its arity
  (`gamma_abc_g1.len() - 1`) matches the circuit's expected public-input count.
  A wrong-arity or malformed key is rejected with `InvalidVerificationKey` at
  registration instead of being accepted silently (and failing, or verifying over
  the wrong public inputs, at proof time). Genesis is unaffected — the chain-spec
  registers keys post-genesis via the extrinsic.

---

## [0.7.2] — 2026-06-01

### Changed

- Updated FRAME benchmark weights measured on Hetzner CCX33 (AMD EPYC-Milan, 8 vCPU dedicated, 32 GB RAM). Steps: `50`, Repeat: `20`. `verify_proof` refreshed with real Groth16 BN254 pairing cost.

---

## [0.7.1] — 2026-05-22

### Changed

- Updated FRAME benchmark weights measured on Hetzner CCX33 (AMD EPYC-Milan, 8 vCPU dedicated, 32 GB RAM). Steps: `50`, Repeat: `20`. `verify_proof` now reflects the real Groth16 BN254 pairing cost (~12 250 µs).

### Fixed

- `lib.rs`: `verify_proof` extrinsic no longer returns `Error::VerificationFailed` under `feature = "runtime-benchmarks"`, allowing the benchmark to complete and emit a weight for the full pairing path.

---

## [0.7.0] — 2026-05-22

### Fixed

- `do_verify`: removed `feature = "runtime-benchmarks"` from the `#[cfg]` bypass — the short-circuit `return true` now applies **only** in `#[cfg(test)]` builds. Previously the benchmark was measuring only FRAME overhead (~µs) instead of real Groth16 BN254 pairing cost (~8-10 ms), causing a severe weight underestimation and a potential DoS vector.

### Added

- `src/bench_fixtures/vk_transfer.bin` (488 B) — arkworks-compressed VerifyingKey for the transfer circuit, embedded via `include_bytes!`.
- `src/bench_fixtures/proof_transfer.bin` (128 B) — real Groth16 BN254 proof (A: G1, B: G2, C: G1, compressed).
- `src/bench_fixtures/public_inputs_transfer.bin` (224 B) — 7 × 32-byte LE field elements (merkle_root, nullifier×2, commitment×2, asset_id, fee).
- `scripts/generate-bench-fixtures.mjs` — Node.js script that regenerates the three fixture files using snarkjs + the transfer circuit WASM/zkey and the groth16-proofs WASM pkg. Run after any circuit change.

### Changed

- `benchmarking.rs` `verify_proof`: replaced mock 192-byte proof + 1 dummy input with real fixtures loaded via `include_bytes!`. The benchmark now exercises the full Groth16 pairing computation on BN254 so that generated weights reflect true on-chain cost.

---

## [0.6.0] — 2026-05-14

### Changed

- `ZkVerifierPort`: replaced `verify_disclosure_proof` and `batch_verify_disclosure_proofs` with `verify_value_proof`
- `CircuitId::VALUE_PROOF = 6` replaces the removed disclosure circuit (ID 4)
- README: updated Circuit IDs table and `ZkVerifierPort` documentation to reflect new interface

### Removed

- `ZkVerifierPort::verify_disclosure_proof` — use `verify_value_proof` instead
- `ZkVerifierPort::batch_verify_disclosure_proofs` — batch disclosure is no longer supported
- Circuit ID `4` (`disclosure`) — replaced by `6` (`value_proof`)

---

## [0.5.1] — 2026-04-14

- Initial tracked release
- `Groth16Verifier` integration via `orbinum-zk-verifier`
- `CircuitId` type with constants: `TRANSFER(1)`, `UNSHIELD(2)`, `DISCLOSURE(4)`, `PRIVATE_LINK(5)`
- `ZkVerifierPort` trait: `verify_transfer_proof`, `verify_unshield_proof`, `verify_disclosure_proof`, `batch_verify_disclosure_proofs`, `verify_private_link_proof`
- Per-version VK storage and `VerificationStats`
- `verify_proof` extrinsic (Signed origin)
