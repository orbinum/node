# Changelog — orbinum-zk-verifier

All notable changes to this crate are documented here.

---

## [Unreleased]

## [3.2.0] - 2026-10-09

### Added

- `host_interface` (feature `groth16-native`, in `default`): Groth16
  verification over BN254 as a native host function, `bn254_groth16_verify`,
  from a key in its prepared form; `verify_proof` measured 2.43 → 0.61 ms once a
  runtime uses it. Every malformed argument is `false` (proof not
  `PROOF_BYTES`, inputs not a multiple of 32 bytes or not the key's arity,
  non-canonical input, a key whose layout does not fit) and it never panics.
- It ships `#[version(1, register_only)]`: nodes register it, no runtime can
  call it yet. A later runtime drops `register_only` once every node runs a
  release with it; version 1 itself is frozen.
- `verify_prepared(prepared_vk, proof, inputs)`: verification on raw bytes from a
  prepared key, checking every argument's shape first (`false` on any
  malformation, never a panic). The host function's body, and what the runtime
  runs in Wasm meanwhile: both paths run the same code.
- `prepared_arity`: a prepared key's input count, read from its layout without
  deserializing a point.

## [3.1.0] - 2026-10-09

### Added

- `VerifyingKey::prepared_bytes`: the key validated and prepared once,
  uncompressed, for storing. `prepared_from_stored` reads it back without
  re-validating its points, after checking every length prefix against the
  bytes (`ark-serialize` reserves a `Vec` from its prefix before reading it).
  `MAX_PREPARED_VK_BYTES` bounds it: the size for `MAX_PUBLIC_INPUTS` inputs.
  The layout is fixed but for the input count: 87 line coefficients for each of
  `-gamma`, `-delta` and a clear infinity flag, so a prefix that adds up but
  differs is refused too. Lives in its own module, `prepared`.

## [3.0.0] - 2026-10-08

### Added

- `InputLayout::CrossTree`: a transfer key with 9 public inputs (the
  memo-bound layout with one Merkle root per input, `merkle_roots[0..1]` first).
  `input_layout` maps transfer arity 9 to it; an unshield or shield key of that
  arity is still refused. `CROSS_TREE_INPUTS` and `has_cross_tree_layout`.
- `max_public_inputs(circuit_id)`: the arity of a circuit's widest layout, the
  one place the layouts are added up. The compile-time arity check uses it.

### Changed

- **Breaking:** `InputLayout` gains the `CrossTree` variant; an exhaustive
  `match` on it must handle it.
- **Breaking:** `MAX_PROOF_BYTES` is removed; `PROOF_BYTES` (128) is the one
  accepted proof length.

### Security

- A proof must be exactly `PROOF_BYTES` (128) long. `deserialize_compressed`
  ignores trailing bytes, so a padded proof was a second byte string for the
  same proof — a malleability the pool and the relay op hash already tolerate
  (proofs are re-randomisable), but one encoding per proof is the contract.
  Found by a live probe. Tests: trailing bytes refused, a G2 point outside the
  subgroup refused in proofs and keys, degenerate proof bytes never verify.

## [2.1.0] - 2026-10-05

### Added

- `CIRCUIT_ID_SHIELD` (3) and `SHIELD_PUBLIC_INPUTS` (3): the shield circuit is
  known, with arity `commitment, value, asset_id`.
- `has_memo_layout(circuit_id)`: only transfer and unshield have a memo-bound
  layout.

### Changed

- `input_layout` reads base + `MEMO_HASH_INPUTS` as `MemoBound` only for a circuit
  with a memo-bound layout; for shield that arity is unusable.

## [2.0.0] - 2026-09-29

### Added

- `InputLayout` and `input_layout(circuit_id, arity)`: a known circuit's key is
  `Base` at its base arity, `MemoBound` at base + `MEMO_HASH_INPUTS`, else
  unusable.
- `to_field_le(bytes)`: reduce 32 LE bytes to the canonical field element.
- Re-export `PreparedVerifyingKey` and `MAX_VK_BYTES`.

### Security

- `VerifyingKey::to_ark_vk` checks the layout before deserializing: at most
  `MAX_PUBLIC_INPUTS + 1` `gamma_abc` points and the exact byte length (no
  trailing bytes). A short key declaring 2^25 points passed the size cap and made
  `ark-serialize` reserve gigabytes. Keys with a point at infinity are refused: an
  identity `gamma_abc` entry leaves its public input out of the verification.

### Removed

- `CIRCUIT_ID_VALUE_PROOF` and `VALUE_PROOF_PUBLIC_INPUTS`;
  `expected_public_inputs(6)` is now `None`. **Breaking.**

### Internal

- Circuit ids, arities and `InputLayout` in `circuits.rs`; paths unchanged through the crate root. `Groth16Verifier::verify` goes through `verify_with_prepared_vk`.

---

## [1.4.0] - 2026-08-07

### Security

- **Deserialization size guards moved inside the crate.** `to_ark_vk` and
  `to_ark_proof` now reject oversized input before handing it to
  `ark-serialize`.

  A verifying key's `gamma_abc_g1` is a length-prefixed vector, and
  `ark-serialize` calls `Vec::with_capacity` on that prefix **before reading a
  single element**. A key declaring 2^40 points asks the allocator for ~48 GB on
  nothing but submitted bytes: in Wasm that traps, on a native path it can take
  the node down with it.

  The two on-chain callers already bounded their argument at 8 KiB, so nothing
  was reachable today. But the bound lived in the caller, not the function:
  `to_ark_vk`, `num_public_inputs` and `prepare` are public API with no length
  precondition, so any future caller — runtime API, offchain worker, an unsigned
  path — inherited the reservation unguarded. New `MAX_VK_BYTES` (8 KiB, matching
  the extrinsic bound) and `MAX_PROOF_BYTES` (1 KiB against a fixed 128-byte
  compressed Groth16 proof). `prepare` and `num_public_inputs` route through
  `to_ark_vk`, so they inherit the check.

- **`MAX_PUBLIC_INPUTS` is now enforced.** The constant was declared and had zero
  call sites outside its own definition: `to_field_elements` accepted a
  `PublicInputs` of any length. The pallet bounds its extrinsic argument, but the
  `ZkVerifierPort` path does not go through that extrinsic. Applied in
  `to_field_elements`, the single point every input passes through. Every circuit
  in use declares 7 inputs or fewer, so the limit cannot bite a real proof.

### Fixed

- `estimate_verification_cost` uses saturating arithmetic. The release profile
  does not enable `overflow-checks`, so plain `*` and `+` would wrap silently and
  report a cost far below the real one. Indicative only — on-chain weights come
  from benchmarks — but a silently wrong number is worse than a large one.

### Notes

- Each guard was verified by removing it and confirming the test fails. Two of
  the first drafts did **not**: they used filler bytes, which also fail to
  deserialize, so the error arrived by another route and the test passed either
  way. They now use a genuine BN254 key at arity 400 (over 8 KiB, and would
  otherwise deserialize) and a real proof padded past the bound.

---

## [1.3.0] - 2026-07-09

### Fixed

- **`TRANSFER_PUBLIC_INPUTS` corrected from 5 to 7.** The constant counted the
  transfer circuit's declared public-signal names, but `nullifiers[2]` and
  `commitments[2]` are arrays, so the true arity is 7 (`merkle_root` + 2
  nullifiers + 2 commitments + `asset_id` + `fee`), matching every published
  VK's `nPublic`. The value was dead until `expected_public_inputs` began
  gating VK registration; the check then rejected every valid transfer VK.
  Proof verification was unaffected — it reads arity from the deserialized VK,
  never from this constant.

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

