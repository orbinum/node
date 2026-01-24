# fp-encrypted-memo

Encrypted memo primitives for Orbinum shielded transactions.

## Overview

When transferring private assets, the sender encrypts note details (value, blinding, owner public key) using the recipient's viewing key. This allows the recipient to:

1. Scan blockchain events for notes they own
2. Decrypt and recover note details
3. Spend the received funds

## Encryption Scheme

```text
encryption_key = SHA256(viewing_key || commitment || "orbinum-note-encryption-v1")
ciphertext = ChaCha20Poly1305(note_data, encryption_key, random_nonce)
encrypted_memo = nonce (12 bytes) || ciphertext (76 bytes + 16 bytes MAC)
```

## Security Properties

- **Confidentiality**: Only the recipient can decrypt (requires viewing key)
- **Authenticity**: ChaCha20Poly1305 provides AEAD (tampering detected)
- **Unlinkability**: Each memo uses unique key derived from commitment

## Architecture (3 Layers)

```text
fp-encrypted-memo
├── core/              # Layer 1: Core types and constants
│   ├── constants.rs   # Size limits, domain separators
│   ├── error.rs       # MemoError enum
│   └── types.rs       # MemoData, ViewingKey, NullifierKey, EdDSAKey
│
├── crypto/            # Layer 2: Cryptographic operations
│   ├── encryption.rs       # encrypt_memo(), decrypt_memo()
│   ├── key_derivation.rs   # derive_viewing_key(), derive_encryption_key()
│   └── validation.rs       # is_valid_encrypted_memo()
│
└── models/            # Layer 3: High-level abstractions
    └── keyset.rs      # KeySet management
```

### Layer 1: Core

Fundamental types and constants:

- **MemoData**: Plaintext note data (value, owner_pk, blinding, asset_id)
- **ViewingKey**: For memo decryption (can be shared with auditors)
- **NullifierKey**: For deriving nullifiers
- **EdDSAKey**: For circuit ownership proofs
- **MemoError**: Error types

### Layer 2: Crypto

Low-level cryptographic operations:

- **encryption**: ChaCha20Poly1305 encrypt/decrypt
- **key_derivation**: SHA-256 key derivation with domain separation
- **validation**: Size and format validation

### Layer 3: Models

High-level abstractions:

- **KeySet**: Manages all derived keys from a single spending key

## Key Hierarchy

```text
spending_key (master secret)
      │
      ├── viewing_key = SHA256(spending_key || "orbinum-viewing-key-v1")
      ├── nullifier_key = SHA256(spending_key || "orbinum-nullifier-key-v1")
      └── eddsa_key = SHA256(spending_key || "orbinum-eddsa-key-v1")
```

## Usage

### Basic Encryption/Decryption

```rust
use fp_encrypted_memo::{MemoData, encrypt_memo, decrypt_memo};

// Prepare memo data
let memo = MemoData {
    value: 1000,
    owner_pk: [1u8; 32],
    blinding: [2u8; 32],
    asset_id: 0,
};

// Encrypt (sender side)
let encrypted = encrypt_memo(&memo, &commitment, &recipient_viewing_key, &nonce)?;

// Decrypt (recipient side)
let decrypted = decrypt_memo(&encrypted, &commitment, &my_viewing_key)?;
```

### Using KeySet

```rust
use fp_encrypted_memo::KeySet;

// Derive all keys from spending key
let keys = KeySet::from_spending_key(spending_key);

// Share viewing key with auditor (read-only access)
let auditor_key = keys.export_viewing_key();

// Decrypt memos
let memo = keys.viewing_key.decrypt(&encrypted, &commitment)?;
```

### Key Derivation

```rust
use fp_encrypted_memo::{derive_viewing_key, derive_eddsa_key};

let viewing_key = derive_viewing_key(&spending_key);
let eddsa_key = derive_eddsa_key(&spending_key);
```

## Features

- **Key Derivation**: Viewing keys, nullifier keys, and EdDSA keys from spending keys
- **ChaCha20-Poly1305 Encryption**: Secure AEAD memo encryption
- **no_std Support**: Runtime-compatible
- **Domain Separation**: Prevents key confusion attacks
- **Viewing Key Support**: Read-only wallet access for auditing

### Optional Features

- `encrypt` - Enables `encrypt_memo_random()` with automatic nonce generation (requires `std`)
- `substrate` - Enables Substrate codec derives (Encode, Decode, TypeInfo)

## Security Considerations

### Nonce Management

**Critical**: When using `encrypt_memo()`, the nonce MUST be randomly generated and NEVER reused with the same key. Nonce reuse allows an attacker to recover plaintext.

```rust
use rand::RngCore;

let mut nonce = [0u8; 12];
rand::thread_rng().fill_bytes(&mut nonce);
```

For convenience, use `encrypt_memo_random()` (requires `encrypt` feature) which handles nonce generation automatically.

### Key Separation

All derived keys use domain separation to prevent key confusion:

- Viewing key cannot be used as spending key
- EdDSA key cannot be used for encryption
- Nullifier key is separate from viewing key

## Testing

```bash
cargo test
```

Tests cover:
- Encryption/decryption roundtrips
- Wrong key detection
- Tamper detection
- Key derivation determinism
- Key separation security

## License

Licensed under Apache 2.0 or GPL-3.0.