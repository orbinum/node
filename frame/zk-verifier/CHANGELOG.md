# Changelog — pallet-zk-verifier

All notable changes to this pallet are documented here.

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
