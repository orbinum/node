# orbinum-zk-circuits

[![crates.io](https://img.shields.io/crates/v/orbinum-zk-circuits.svg)](https://crates.io/crates/orbinum-zk-circuits)
[![Documentation](https://docs.rs/orbinum-zk-circuits/badge.svg)](https://docs.rs/orbinum-zk-circuits)

R1CS circuits and constraint gadgets for off-chain ZK proof generation.

Intended for off-chain use (proof generation, testing). The runtime only needs
`orbinum-zk-verifier` for on-chain proof verification.

> **These are not the circuits Orbinum runs.**
>
> The verification keys registered on chain are generated from the Circom
> sources in [orbinum/circuits](https://github.com/orbinum/circuits). This crate
> is a separate arkworks implementation of the same ideas, and the two have
> drifted apart. Do not run a trusted setup against it, and do not treat it as a
> specification of the protocol.
>
> Known divergences from the deployed circuits, as of this writing:
>
> | | This crate | `orbinum/circuits` |
> |---|---|---|
> | Unshield public signals | 6 | 7, including `change_commitment` |
> | Unshield change note | not modelled | supported |
> | Range checks on note values | none | `Num2Bits(128)` |
>
> The missing range checks matter most. Balance conservation here is enforced as
> field arithmetic with no bound on any value, so `sum(inputs) == sum(outputs) +
> fee` can be satisfied by wrapping modulo the BN254 scalar field. A setup run
> against `TransferCircuit` or `UnshieldCircuit` would produce a verifier that
> accepts inflated notes. The deployed Circom circuits constrain every value to
> 128 bits and are not affected.

## Modules

| Module | Contents |
|--------|----------|
| `types` | Core data types: `Note`, `MerklePath`, `TreeDepth`, `CircuitValidator` |
| `gadgets` | R1CS gadgets: Poseidon hash, commitment, nullifier, Merkle verification, EdDSA |
| `circuits` | Full circuits: `TransferCircuit`, `UnshieldCircuit` |

## Installation

```toml
[dependencies]
orbinum-zk-circuits = "0.2"
ark-bn254 = "0.5"
ark-groth16 = "0.5"
orbinum-zk-core = "1.0"
```

## Supported Circuits

### TransferCircuit — 2-in / 2-out private transfer

Public inputs (7, matches `nPublic: 7` in `verification_key_transfer.json`):
`merkle_root`, `nullifiers[0]`, `nullifiers[1]`, `output_commitments[0]`, `output_commitments[1]`, `asset_id`, `fee`

Constraints enforced:
- Input commitment correctness: `Poseidon4(value, asset_id, Ax, blinding)`
- Merkle membership: `MerkleProof(commitment, path) == merkle_root`
- EdDSA ownership: `S × Base8 == R8 + Poseidon5(R8x, R8y, Ax, Ay, c) × A`
- Nullifier correctness: `Poseidon2(commitment, spending_key)`
- Output commitment correctness
- Balance conservation: `sum(inputs) == sum(outputs) + fee`
- Asset consistency across all notes

```rust
use orbinum_zk_circuits::{TransferCircuit, TransferWitness, Note};

let witness = TransferWitness::new(
    input_notes,   // [Note; 2]
    spending_keys, // [Bn254Fr; 2]
    paths,         // [MerklePath; 2]
    indices,       // [u64; 2]
    output_notes,  // [Note; 2]
    fee,           // Bn254Fr
);
witness.validate()?;

let circuit = TransferCircuit::new(witness, merkle_root);
```

### UnshieldCircuit — withdraw to public account

Public inputs (6, matches `nPublic: 6` in `verification_key_unshield.json`):
`merkle_root`, `nullifier`, `amount`, `recipient`, `asset_id`, `fee`

Constraints enforced:
- Commitment correctness: `Poseidon4(note_value, asset_id, owner_pk, blinding)`
- Merkle membership: `MerkleProof(commitment, path) == merkle_root`
- Nullifier correctness: `Poseidon2(commitment, spending_key) == nullifier`
- Balance: `note_value == amount + fee`

```rust
use orbinum_zk_circuits::{UnshieldCircuit, UnshieldWitness, Note};

let witness = UnshieldWitness::new(
    note,         // Note
    spending_key, // Bn254Fr
    path,         // MerklePath
    leaf_index,   // u64
    amount,       // Bn254Fr
    fee,          // Bn254Fr
);
witness.validate()?;

let circuit = UnshieldCircuit::new(witness, public_inputs);
```

### Validate constraints

```rust
use ark_relations::r1cs::ConstraintSystem;
use ark_bn254::Fr;

let cs = ConstraintSystem::<Fr>::new_ref();
circuit.generate_constraints(cs.clone())?;
assert!(cs.is_satisfied().unwrap());
```

## Gadgets

| Gadget | Function |
|--------|----------|
| `poseidon_hash_2` / `poseidon_hash_4` | Native Poseidon hash (non-R1CS) |
| `poseidon_hash_var` | In-circuit Poseidon gadget |
| `note_commitment` | R1CS commitment: `Poseidon4(value, asset_id, owner_pk, blinding)` |
| `nullifier` | R1CS nullifier: `Poseidon2(commitment, spending_key)` |
| `merkle_tree_verifier` / `verify_merkle_proof` | Merkle path verification gadget |
| `verify_eddsa` | Baby JubJub EdDSA-Poseidon ownership proof |

## Circom Compatibility

Circuits are aligned with the production Circom circuits used by the Orbinum shielded pool.
Public input order and count match the corresponding `verification_key_*.json` artifacts.

Proof generation reference:
- Transfer: `ts-sdk/src/proof-generator/transfer.ts`
- Unshield: `ts-sdk/src/proof-generator/unshield.ts`

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE2) or [GPL v3](LICENSE-GPL3) at your option.
