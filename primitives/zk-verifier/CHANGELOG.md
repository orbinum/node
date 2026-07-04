# Changelog — orbinum-zk-verifier

All notable changes to this crate are documented here.

---

## [1.2.0] - 2026-07-04

### Added
- `expected_public_inputs(circuit_id: u8) -> Option<usize>` and
  `VerifyingKey::num_public_inputs() -> Result<usize, VerifierError>`, so a
  registrar can check that a verifying key's arity (`gamma_abc_g1.len() - 1`)
  matches the circuit it is registered for. A wrong-arity or non-deserializable
  key can now be rejected instead of failing (or verifying over the wrong inputs)
  at proof time.

### Removed
- `Groth16Verifier::batch_verify`. It was unsound: the random linear-combination
  scalars were derived from a hash of prover-controlled data (the proof and public
  inputs), letting a prover craft a batch of individually-invalid proofs that
  satisfies the combined pairing check. It had no callers. Verify proofs one at a
  time with `verify` / `verify_with_prepared_vk`, which are sound. This also drops
  the `sha2` dependency.
- The `field_utils` module (`field_to_bytes`, `bytes_to_field`, `field_to_u64`,
  `u64_to_field`). These big-endian helpers had no callers and conflicted with the
  little-endian encoding used everywhere else.

### Fixed
- `parse_public_inputs_from_snarkjs` now encodes little-endian (via
  `PublicInputs::from_field_elements`) instead of big-endian. It previously wrote
  bytes in the opposite order to what `to_field_elements` reads, so a parsed input
  round-tripped to a different field element.
- `PublicInputs::from_field_elements` documents the 32-byte encoding invariant with
  a `debug_assert`; the existing `.min(32)` is a defensive floor, not a truncation
  of any valid BN254 element.

### Security
- The snarkjs parsers (`parse_fq`, `parse_fr`, `parse_proof_from_snarkjs`,
  `parse_public_inputs_from_snarkjs`) return `Result` instead of panicking on
  malformed input. Curve points are built with `new_unchecked` and then validated
  on-curve and in-subgroup. These are `std`-only host helpers; an RPC/offchain
  worker feeding untrusted JSON can no longer panic the process.
- The snarkjs parsers reject non-canonical field values (`>= modulus`) instead of
  silently reducing them, so a coordinate/input string outside the field range is
  an error rather than a different point/element than the caller wrote.
- `PublicInputs::to_field_elements` now rejects non-canonical little-endian
  encodings (byte strings that represent a value `>= p`) with
  `VerifierError::InvalidPublicInput`. Previously it reduced modulo `p`, so `n` and
  `n + p` produced the same field element while being different byte strings: a
  proof over the reduced element verified for both, but a layer comparing raw bytes
  (e.g. a nullifier set) treated them as distinct — a double-spend vector. Only
  canonical inputs verify now.

### Tests
- Added `to_field_elements_rejects_non_canonical` covering the `n` vs `n + p`
  collision and `0xff..ff` (`>= p`) rejection.
- Added `tests/real_proof.rs`: a real Groth16 setup + prove + verify over a small
  circuit exercises the actual pairing, covering a valid proof, a wrong public
  input, and non-canonical-input rejection against a genuine proof.

---

## [1.1.0] — 2026-05-14

### Changed

- Renamed `CIRCUIT_ID_DISCLOSURE` (4) to `CIRCUIT_ID_VALUE_PROOF` (6) — aligns with `CircuitId::VALUE_PROOF` in `pallet-zk-verifier`
- Renamed `DISCLOSURE_PUBLIC_INPUTS` (8) to `VALUE_PROOF_PUBLIC_INPUTS` (4) — reflects the 4 public signals of the value proof circuit (commitment, value, asset_id, owner_hash)

### Removed

- `CIRCUIT_ID_DISCLOSURE` — use `CIRCUIT_ID_VALUE_PROOF` instead
- `DISCLOSURE_PUBLIC_INPUTS` — use `VALUE_PROOF_PUBLIC_INPUTS` instead

---

## [1.0.0] — 2026-04-14

- `Groth16Verifier` — static `verify`, `verify_with_prepared_vk`, `batch_verify`
- `Proof`, `VerifyingKey`, `PublicInputs`, `VerifierError` types
- Circuit constants: `CIRCUIT_ID_TRANSFER`, `CIRCUIT_ID_UNSHIELD`, `CIRCUIT_ID_DISCLOSURE`, `CIRCUIT_ID_PRIVATE_LINK`
- Field utilities: `bytes_to_field`, `field_to_bytes`, `field_to_u64`, `u64_to_field`
- snarkjs adapter: `parse_proof_from_snarkjs`, `parse_public_inputs_from_snarkjs` (feature `std`)
- SCALE codec support via feature `substrate`
- `no_std` compatible

