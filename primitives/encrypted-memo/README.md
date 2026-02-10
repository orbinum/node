# orbinum-encrypted-memo

[![crates.io](https://img.shields.io/crates/v/orbinum-encrypted-memo.svg)](https://crates.io/crates/orbinum-encrypted-memo)
[![Documentation](https://docs.rs/orbinum-encrypted-memo/badge.svg)](https://docs.rs/orbinum-encrypted-memo)

Encrypted memo primitives for private transaction metadata in Orbinum Network.

## Features

- **ChaCha20Poly1305 AEAD**: Authenticated encryption for memo data
- **Viewing key encryption**: Only recipient can decrypt note details
- **Selective disclosure**: ZK proofs for partial data revelation
- **Key derivation**: Deterministic keys from spending key
- **no_std compatible**: WASM runtime support

## Installation

```toml
[dependencies]
orbinum-encrypted-memo = "0.2"

# For selective disclosure (ZK proofs)
orbinum-encrypted-memo = { version = "0.2", features = ["disclosure"] }
```

## Usage

### Basic Encryption/Decryption

```rust
use orbinum_encrypted_memo::{
    domain::entities::types::{MemoData, ViewingKey, Commitment},
    domain::services::encryption::{encrypt_memo, decrypt_memo},
};

// Create memo data
let memo = MemoData::new(
    1000,           // value
    owner_pubkey,   // owner public key
    blinding,       // blinding factor
    0,              // asset_id
);

// Encrypt for recipient (random nonce generated automatically)
let encrypted = encrypt_memo(&memo, &commitment, &recipient_vk)?;

// Recipient decrypts
let decrypted = decrypt_memo(&encrypted, &commitment, &my_viewing_key)?;
assert_eq!(decrypted.value, 1000);
```

### Key Derivation from Spending Key

```rust
use orbinum_encrypted_memo::domain::aggregates::keyset::KeySet;

// Derive all keys from master spending key
let keys = KeySet::from_spending_key(&spending_key);

// Access derived keys
let viewing_key = &keys.viewing_key;      // For decryption
let nullifier_key = &keys.nullifier_key;  // For double-spend prevention
let eddsa_key = &keys.eddsa_key;          // For signatures

// Decrypt with viewing key
let memo = decrypt_memo(&encrypted, &commitment, viewing_key)?;
```

### Selective Disclosure with ZK Proofs

```rust
use orbinum_encrypted_memo::{
    domain::aggregates::disclosure::{DisclosureMask, DisclosureProof},
    application::disclosure::generate_disclosure_proof,
};

// Create mask (reveal only value, hide owner and blinding)
let mask = DisclosureMask::only_value();

// Load circuit artifacts (client responsibility)
let proving_key_bytes = load_artifact("disclosure_pk.ark")?;
let wasm_bytes = load_artifact("disclosure.wasm")?;

// Generate ZK proof
let proof = generate_disclosure_proof(
    &memo_data,
    &mask,
    &viewing_key,
    commitment,
    &proving_key_bytes,
    &wasm_bytes,
)?;

// Extract revealed data
let partial = proof.extract_partial_memo(&mask);
assert_eq!(partial.value, Some(1000));
assert_eq!(partial.owner_pk, None);  // Hidden
```

### Note Scanning (Wallet Use Case)

```rust
use orbinum_encrypted_memo::domain::services::encryption::decrypt_memo;

// Scan blockchain for owned notes
for (commitment, encrypted_memo) in blockchain_notes {
    // Try to decrypt with viewing key
    if let Ok(memo) = decrypt_memo(&encrypted_memo, &commitment, &my_vk) {
        println!("Found owned note: value={}, owner={}",
            memo.value, memo.owner_pk);

        // Save to wallet database
        wallet.add_note(commitment, memo);
    }
}
```

## Encryption Scheme

Uses ChaCha20Poly1305 AEAD with per-note key derivation:

```text
encryption_key = SHA256(viewing_key || commitment || domain_separator)
ciphertext = ChaCha20Poly1305(memo_data, encryption_key, nonce)
encrypted_memo = nonce(12) || ciphertext(76) || mac(16) = 104 bytes
```

## Key Derivation Hierarchy

```text
spending_key (master secret, 32 bytes)
      │
      ├── viewing_key = SHA256(spending_key || "orbinum-viewing-key-v1")
      ├── nullifier_key = SHA256(spending_key || "orbinum-nullifier-key-v1")
      └── eddsa_key = SHA256(spending_key || "orbinum-eddsa-key-v1")
```

## Memo Structure

| Field | Type | Size | Description |
|-------|------|------|-------------|
| `value` | u64 | 8 bytes | Note amount |
| `owner_pk` | FieldElement | 32 bytes | Owner public key |
| `blinding` | FieldElement | 32 bytes | Blinding factor |
| `asset_id` | u32 | 4 bytes | Asset identifier |

**Total plaintext**: 76 bytes
**Encrypted memo**: 104 bytes (with nonce + MAC)

## Selective Disclosure Features

With the `disclosure` feature flag:

| Disclosure Mask | Reveals | Use Case |
|-----------------|---------|----------|
| `only_value()` | Amount only | Prove balance without revealing identity |
| `only_owner()` | Owner only | Prove ownership without revealing amount |
| `value_and_owner()` | Amount + Owner | Compliance disclosure |
| `none()` | Nothing | Prove knowledge without revealing anything |

## Circuit Artifacts

⚠️ **Client Responsibility**: This crate does NOT bundle circuit artifacts (WASM, proving keys).

Download from: [orbinum/circuits releases](https://github.com/orbinum/circuits/releases)

```bash
# Download disclosure circuit artifacts (v0.1.0)
curl -L -o disclosure.wasm \
  https://github.com/orbinum/circuits/releases/download/v0.1.0/disclosure.wasm
curl -L -o disclosure_pk.ark \
  https://github.com/orbinum/circuits/releases/download/v0.1.0/disclosure_pk.ark

# Verify checksums
sha256sum -c checksums.txt
```

## Security Properties

- **Confidentiality**: Only viewing key holder can decrypt
- **Authenticity**: AEAD MAC prevents tampering
- **Unlinkability**: Unique encryption key per note (derived from commitment)
- **Forward Secrecy**: Compromising one key doesn't reveal others
- **Zero-Knowledge**: Selective disclosure without revealing hidden fields

## Performance

| Operation | Time | Notes |
|-----------|------|-------|
| Encrypt | 15μs | ChaCha20Poly1305 |
| Decrypt | 20μs | Includes verification |
| Key Derivation | 8μs | SHA256 hashing |
| Disclosure Proof | 150ms | ZK proof generation |

*Measured on Apple M1*

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE2) or [GPL v3](LICENSE-GPL3) at your option.
