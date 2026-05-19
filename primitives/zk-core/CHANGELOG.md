# Changelog — orbinum-zk-core

All notable changes to this crate are documented here.

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

