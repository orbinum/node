# Changelog — orbinum-zk-verifier

All notable changes to this crate are documented here.

---

## [Unreleased]

### Security
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

