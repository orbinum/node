# Changelog — orbinum-zk-core

All notable changes to this crate are documented here.

---

## [Unreleased]

### Security
- **ZKC-1** — Poseidon hashing no longer uses `.expect()` / `panic!`. All arities
  (`hash_2`, `hash_4`, `hash_5`, `poseidon_hash_1`) now route through a single
  internal `poseidon_circom` helper that returns a deterministic value instead of
  panicking. This closes a consensus-divergence risk: a native panic aborts the
  node process while a WASM panic is a recoverable trap, so the same malformed
  input could split the network. The failure path is provably unreachable (constant
  arity, reduced `Fr` inputs) and is now documented as an invariant.

### Tests
- Added `hash_no_panic_on_boundary_inputs`, `hash_boundary_inputs_are_deterministic`,
  and `poseidon_circom_core_matches_trait` covering boundary field elements
  (`0` and `p-1`) and native/WASM path equivalence.

---

## [1.0.1] — 2026-05-14

### Changed
- `poseidon_hash_1` doc comment updated: use case renamed from *disclosure circuit / viewing key*
  to *value_proof circuit / owner hash* (`owner_hash = Poseidon(owner_pubkey)`).
  README example variable renamed from `viewing_key` to `owner_hash` accordingly.

---

## [1.0.0] — 2026-04-14

- `PoseidonHasher` trait with `hash_2`, `hash_4`, `hash_5` arities
- `LightPoseidonHasher` — WASM-compatible implementation via `light-poseidon-nostd`
- `NativePoseidonHasher` — native host-function implementation (~3× faster, feature `poseidon-native`)
- `poseidon_hash_1` — single-input Poseidon for viewing-key derivation
- `FieldElement`, `Commitment`, `Nullifier`, `Blinding`, `OwnerPubkey`, `SpendingKey`, `Note` types
- `compute_commitment`, `compute_nullifier`, `merkle_hash` free functions
- `host_interface` module exposing `sp-runtime-interface` host functions
- `MERKLE_TREE_DEPTH` constant
- `no_std` compatible

