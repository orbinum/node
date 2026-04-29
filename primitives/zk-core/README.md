# orbinum-zk-core

Poseidon-based cryptographic primitives for ZK-SNARK operations in Orbinum Network.

## Modules

| Module | Contents |
|---|---|
| `types` | `FieldElement`, `Commitment`, `Nullifier`, `Blinding`, `OwnerPubkey`, `SpendingKey`, `Note`, constants |
| `hash` | `PoseidonHasher` trait, `LightPoseidonHasher` (WASM), `NativePoseidonHasher` (native), `poseidon_hash_1` |
| `ops` | `compute_commitment`, `compute_nullifier`, `merkle_hash` |
| `host_interface` | `sp-runtime-interface` host functions (requires `poseidon-native` feature) |

## Features

| Feature | Description | Default |
|---|---|---|
| `std` | Enable standard library | ✓ |
| `poseidon-native` | `NativePoseidonHasher` + host functions (~3× faster in native runtime) | ✓ |

## Usage

### Note commitment

```rust
use orbinum_zk_core::{LightPoseidonHasher, OwnerPubkey, Blinding, compute_commitment};
use ark_bn254::Fr;

let commitment = compute_commitment(
    &LightPoseidonHasher,
    1000,                                   // value
    1,                                      // asset_id
    OwnerPubkey::from(Fr::from(12345u64)),
    Blinding::from(Fr::from(67890u64)),
);
```

### Nullifier

```rust
use orbinum_zk_core::{LightPoseidonHasher, SpendingKey, compute_nullifier};
use ark_bn254::Fr;

let nullifier = compute_nullifier(
    &LightPoseidonHasher,
    commitment,
    SpendingKey::from(Fr::from(999u64)),
);
```

### Note helper

```rust
use orbinum_zk_core::{Note, OwnerPubkey, Blinding, LightPoseidonHasher};
use ark_bn254::Fr;

let hasher = LightPoseidonHasher;
let note = Note::new(1000, 1, OwnerPubkey::from(Fr::from(1u64)), Blinding::from(Fr::from(2u64)));

let commitment = note.commitment(&hasher);
let nullifier  = note.nullifier(&hasher, spending_key);
```

### Single-element hash (disclosure circuit)

```rust
use orbinum_zk_core::{poseidon_hash_1, FieldElement};

// viewing_key = Poseidon(owner_pubkey)
let viewing_key = poseidon_hash_1(FieldElement::from_u64(owner_pk));
```

### Custom hasher (testing)

```rust
use orbinum_zk_core::{PoseidonHasher, FieldElement};

struct MockHasher;
impl PoseidonHasher for MockHasher {
    fn hash_2(&self, _: [FieldElement; 2]) -> FieldElement { FieldElement::from_u64(0) }
    fn hash_4(&self, _: [FieldElement; 4]) -> FieldElement { FieldElement::from_u64(0) }
    fn hash_5(&self, _: [FieldElement; 5]) -> FieldElement { FieldElement::from_u64(0) }
}
```

## Cryptographic formulas

```
commitment  = Poseidon(value, asset_id, owner_pubkey, blinding)           // hash_4
nullifier   = Poseidon(commitment, spending_key)                           // hash_2
merkle_node = Poseidon(left, right)                                        // hash_2
eddsa_h     = Poseidon(R8x, R8y, Ax, Ay, msg)                             // hash_5
viewing_key = Poseidon(owner_pubkey)                                       // hash_1 (disclosure)
```

All hashes use circomlib-compatible Poseidon (BN254, iden3 parameters).

## License

Licensed under either of [Apache License, Version 2.0](../../LICENSE-APACHE2) or [GPL v3](../../LICENSE-GPL3) at your option.

