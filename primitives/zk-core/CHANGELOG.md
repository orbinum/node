# Changelog — orbinum-zk-core

All notable changes to this crate are documented here.

---

## [Unreleased]

### Security
- Poseidon hashing no longer uses `.expect()` / `panic!`. All arities
  (`hash_2`, `hash_4`, `hash_5`, `poseidon_hash_1`) now route through a single
  internal `poseidon_circom` helper that returns a deterministic value instead of
  panicking. This closes a consensus-divergence risk: a native panic aborts the
  node process while a WASM panic is a recoverable trap, so the same malformed
  input could split the network. The failure path is provably unreachable (constant
  arity, reduced `Fr` inputs) and is now documented as an invariant. The fallback
  value is a fixed non-zero marker, never zero, so it cannot be mistaken for the
  all-zero dummy sentinel (a zero nullifier is skipped rather than marked spent).
- Poseidon host functions (`poseidon_hash_2`, `poseidon_hash_4`) no longer
  `assert_eq!` input length. A failed assert in a native host function aborts the
  node process. Inputs are now read through a `read_32_le` helper that zero-pads or
  truncates to 32 bytes deterministically and never panics.
- The 32-byte field↔bytes conversions (`field_to_bytes`, `bytes_to_field`, host
  output) now copy by length instead of slicing `[..32]`, removing a latent panic
  if a bigint ever serialized to fewer than 32 bytes.

### Changed
- `Note::is_zero` now matches the system-wide dummy definition (`value == 0`)
  instead of also requiring `asset_id`/`owner_pubkey`/`blinding` to be zero. The
  circuit and shielded-pool treat any value-zero input as dummy; the previous
  stricter check could disagree. Documented on both `is_zero` and `zero`.

### Documentation
- Documented in `Cargo.toml` that runtime/WASM consumers must depend on this crate
  with `default-features = false` (else `std` leaks into the `no_std` build), and
  added a CI feature-matrix check to enforce it.

### Added
- `FieldElement::is_canonical_le` and `FieldElement::from_canonical_le` — reject
  non-canonical little-endian byte encodings (values `>= p`). Trust boundaries that
  ingest raw bytes (nullifiers, commitments, external addresses) should use these so
  that `x` and `x + p` cannot masquerade as distinct values while hashing/proving
  identically.
- Documented the consensus invariant `Native(x) == Wasm(x) == Circuit(x)` in the
  crate docs.

### Tests
- Added `hash_no_panic_on_boundary_inputs`, `hash_boundary_inputs_are_deterministic`,
  and `poseidon_circom_core_matches_trait` covering boundary field elements
  (`0` and `p-1`) and native/WASM path equivalence.
- Added `read_32_le_pads_and_truncates`, `hash_2_no_panic_on_short_input`,
  `hash_4_no_panic_on_short_input`, and `hash_2_still_correct_for_32_bytes`
  covering non-32-byte host-function inputs.
- Added `tests/poseidon_vectors.rs`: known-answer vectors against canonical
  circomlib BN254 Poseidon outputs (arities 1/2/4/5) and native≡WASM equivalence
  checks. The vectors catch any parameter drift between `light-poseidon-nostd` and
  the compiled circuit.
- Added canonical-encoding tests including the `n` vs `n+p` collision vector.

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

