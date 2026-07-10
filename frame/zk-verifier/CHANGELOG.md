# Changelog — pallet-zk-verifier

All notable changes to this pallet are documented here.

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
