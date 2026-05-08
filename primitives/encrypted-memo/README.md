# orbinum-encrypted-memo

[![crates.io](https://img.shields.io/crates/v/orbinum-encrypted-memo.svg)](https://crates.io/crates/orbinum-encrypted-memo)
[![Documentation](https://docs.rs/orbinum-encrypted-memo/badge.svg)](https://docs.rs/orbinum-encrypted-memo)

Encrypted memo primitives for private transaction metadata in Orbinum Network.

## Features

- **ChaCha20Poly1305 AEAD**: Authenticated encryption for memo data
- **Viewing key encryption**: Only recipient can decrypt note details
- **Selective disclosure**: ZK proof structures for partial data revelation
- **Key derivation**: Deterministic keys from spending key via SHA-256
- **no_std compatible**: WASM runtime support

## Installation

```toml
[dependencies]
orbinum-encrypted-memo = "0.5"

# Enable random nonce generation (requires std/rand)
orbinum-encrypted-memo = { version = "0.5", features = ["encrypt"] }

# Enable SCALE codec + TypeInfo (Substrate runtime)
orbinum-encrypted-memo = { version = "0.5", features = ["parity-scale-codec", "scale-info"] }
```

## Usage

### Basic Encryption/Decryption

```rust
use orbinum_encrypted_memo::{MemoData, KeySet, encrypt_memo, decrypt_memo};

// Derive keys from master spending key
let keys = KeySet::from_spending_key(spending_key);

// Create memo with counterparty (private transfer)
let memo = MemoData::new(1000, owner_pubkey, blinding, 0, counterparty_pk);

// Create memo without counterparty (shield / unshield)
let memo = MemoData::new_without_counterparty(1000, owner_pubkey, blinding, 0);

// Encrypt (nonce must be unique per note)
let encrypted = encrypt_memo(&memo, &commitment, keys.viewing_key.as_bytes(), &nonce)?;

// Decrypt (symmetric mode — viewing_key as shared_secret)
let decrypted = decrypt_memo(&encrypted, &commitment, keys.viewing_key.as_bytes())?;
assert_eq!(decrypted.value, 1000);

// Decrypt (ECDH mode — derive shared_secret from ephPk appended to encrypted[136..168])
// let eph_pk = &encrypted[136..168];
// let shared_secret = bjj_ecdh(ivsk_scalar, eph_pk);
// let decrypted = decrypt_memo(&encrypted, &commitment, &shared_secret)?;
```

### Key Derivation from Spending Key

```rust
use orbinum_encrypted_memo::{KeySet, derive_viewing_key_from_spending};

// Derive all sub-keys at once
let keys = KeySet::from_spending_key(spending_key);
let vk  = keys.viewing_key.as_bytes();   // decrypt notes
let nk  = keys.nullifier_key.as_bytes(); // compute nullifiers
let ek  = keys.eddsa_key.as_bytes();     // sign transactions

// Or derive a single key
let vk = derive_viewing_key_from_spending(spending_key);
```

### Note Scanning (Wallet)

```rust
use orbinum_encrypted_memo::try_decrypt_memo;

for (commitment, encrypted_memo) in blockchain_notes {
    if let Some(memo) = try_decrypt_memo(&encrypted_memo, &commitment, viewing_key) {
        wallet.add_note(commitment, memo);
    }
}
```

### Selective Disclosure

```rust
use orbinum_encrypted_memo::{DisclosureMask, DisclosureProof, PartialMemoData};

// Build mask (reveal only value; blinding is always hidden)
let mask = DisclosureMask::only_value();

// PartialMemoData shows only disclosed fields
let partial = PartialMemoData::from_disclosure(&memo, &mask);
assert_eq!(partial.value, Some(1000));
assert!(partial.owner_pk.is_none());

// Serialize proof bundle for on-chain submission
let proof = DisclosureProof::new(groth16_proof_bytes, public_signals, mask);
proof.validate()?;
let bytes = proof.to_bytes();

// Deserialize on the other side
let proof = DisclosureProof::from_bytes(&bytes)?;
```

## Encryption Scheme

ChaCha20Poly1305 AEAD with per-note key derivation:

```text
Plaintext  (MemoData):  value_lo(8) | value_hi(8) | owner_pk(32) | blinding(32) | asset_id(4) | counterparty_pk(32) = 116 bytes
                        (value = value_lo + value_hi × 2^64, supports u128)

encryption_key = SHA256(shared_secret || commitment || "orbinum-note-encryption-v1")
ciphertext     = ChaCha20Poly1305(plaintext=116B, key=encryption_key, nonce=12B)
encrypted_memo = nonce(12) | ciphertext(132) | MAC(16) | ephPk_packed(32)  →  176 bytes total
```

`shared_secret` is either the `viewing_key` (symmetric mode) or the ECDH x-coordinate (wallet mode). See **Key Derivation Hierarchy** below.

## Key Derivation Hierarchy

### Symmetric mode (server-side / legacy)

```text
spending_key  (32 bytes, never shared)
      │
      ├── viewing_key   = SHA256(spending_key || "orbinum-viewing-key-v1")
      ├── nullifier_key = SHA256(spending_key || "orbinum-nullifier-key-v1")
      └── eddsa_key     = SHA256(spending_key || "orbinum-eddsa-key-v1")

encryption_key(commitment) = SHA256(viewing_key || commitment || "orbinum-note-encryption-v1")
```

### ECDH mode (wallet / TypeScript client)

```text
ivsk       = HKDF-SHA256(spendingKey_bytes, info="orbinum-ivk-v1")  ← secret
ivk_point  = BJJ_mul(Base8, ivsk_scalar)                            ← public, in address
ephSk      = random BJJ scalar per note
ephPk      = BJJ_mul(Base8, ephSk)                                  ← appended to encrypted[144..176]
shared_sec = BJJ_mul(ivk_point, ephSk)[0]   (x-coordinate, LE)
enc_key    = SHA256(shared_sec || commitment || "orbinum-note-encryption-v1")
```

### Stealth Address Mode (change notes)

Partial unshield creates stealth-addressed change notes:

```text
Sender generates ephSk = random() for change note
shared_secret = ECDH(ephSk, recipient_ivk_point).Ax
stealth_scalar = HKDF(shared_secret, salt=owner_pk_LE, info="orbinum-stealth-v1") % BABYJUB_ORDER
stealth_owner_pk = (stealth_scalar × Base8 + owner_pk_point).Ax  ← unique per change note

Change note commitment = Poseidon(value, asset_id, stealth_owner_pk, blinding)
Change encrypted_memo = ChaCha20Poly1305(..., ephSk, ...)
```

This ensures change note commitments are **unlinkable** — they cannot be associated with sender's other notes.

## Memo Structure

| Field | Type | Size | Description |
|-------|------|------|-------------|
| `value_lo` | `u64` LE | 8 bytes | Lower 64 bits of amount (value & 0xffff_ffff_ffff_ffff) |
| `value_hi` | `u64` LE | 8 bytes | Upper 64 bits of amount ((value >> 64) & 0xffff_ffff_ffff_ffff) |
| `owner_pk` | `[u8; 32]` | 32 bytes | Owner BabyJubJub public key (Ax, LE) |
| `blinding` | `[u8; 32]` | 32 bytes | Blinding factor |
| `asset_id` | `u32` LE | 4 bytes | Asset identifier |
| `counterparty_pk` | `[u8; 32]` | 32 bytes | Other party's Ax (LE); `[0u8;32]` for shield/unshield/change |

**Plaintext**: 116 bytes — **Encrypted wire format**: 176 bytes (`nonce(12) | ciphertext(132) | MAC(16) | ephPk_packed(32)`)

**Value range**: u128 supporting ~340 billion tokens with 18 decimals per note

Use `MemoData::new_without_counterparty(value, owner_pk, blinding, asset_id)` for shield, unshield, and change notes.

## Selective Disclosure Masks

| Constructor | Reveals | Use Case |
|---|---|---|
| `DisclosureMask::all()` | value, owner, asset_id | Full compliance disclosure |
| `DisclosureMask::only_value()` | value | Prove amount without revealing identity |
| `DisclosureMask::value_and_asset()` | value + asset_id | Asset-specific compliance |
| `DisclosureMask::none()` | nothing | Custom mask starting point |

`disclose_blinding` is always rejected by `validate()` — exposing the blinding factor breaks commitment privacy.

## Circuit Artifacts

This crate provides **data types only** — it does not generate ZK proofs. Proof generation
is done client-side using the Circom disclosure circuit. Artifacts are bundled in the
node repository under `/artifacts/`:

```
artifacts/
  disclosure.wasm           # Witness generator (client)
  disclosure.zkey            # Proving key (client)
  verification_key_disclosure.json  # Verification key (runtime)
```

## Security Properties

- **Confidentiality**: Only viewing key holder can decrypt
- **Authenticity**: AEAD MAC prevents tampering
- **Unlinkability**: Unique encryption key per note (commitment-bound)
- **Forward Secrecy**: Subkey compromise does not expose spending key
- **Zero-Knowledge**: Selective disclosure without revealing hidden fields

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE2) or [GPL v3](LICENSE-GPL3) at your option.
