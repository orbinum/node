# Changelog — orbinum-zk-verifier

All notable changes to this crate are documented here.

---

## [1.0.0] — 2026-04-14

- `Groth16Verifier` — static `verify`, `verify_with_prepared_vk`, `batch_verify`
- `Proof`, `VerifyingKey`, `PublicInputs`, `VerifierError` types
- Circuit constants: `CIRCUIT_ID_TRANSFER`, `CIRCUIT_ID_UNSHIELD`, `CIRCUIT_ID_DISCLOSURE`, `CIRCUIT_ID_PRIVATE_LINK`
- Field utilities: `bytes_to_field`, `field_to_bytes`, `field_to_u64`, `u64_to_field`
- snarkjs adapter: `parse_proof_from_snarkjs`, `parse_public_inputs_from_snarkjs` (feature `std`)
- SCALE codec support via feature `substrate`
- `no_std` compatible

