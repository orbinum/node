# Changelog for `fc-rpc-v2`

## [Unreleased]

## [2.0.1-dev] - 2026-10-18

### Fixed

- `chain_isValidator` reads `pallet_session::Validators` (the validator
  accounts) instead of `pallet_aura::Authorities` (their Aura keys). An operator
  that registered its session keys from its account, with a key that is not the
  account, was reported as not a validator.
- A `Session::Validators` value that does not decode exactly, truncated or with
  trailing bytes, is an internal error instead of a partial match. The decoding
  is a pure function with unit tests.

### Documentation

- The module docs of `privacy` list `privacy_getSubtreeRoots`, state that every
  endpoint reads the best block, and describe the proof gate as it is: half the
  cores at once, a bounded queue, a bounded wait.

## [2.0.0-dev]

Orbinum's node RPC beside the Ethereum layer:

- `privacy_*`: Merkle root, proofs by leaf index and by commitment, subtree
  roots, nullifier status and pool statistics of the shielded pool, read from
  the best block; proofs run on blocking threads behind a bounded gate.
- `chain_isValidator`: whether an SS58 account is an Aura authority.
