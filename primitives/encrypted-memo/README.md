# orbinum-encrypted-memo

[![crates.io](https://img.shields.io/crates/v/orbinum-encrypted-memo.svg)](https://crates.io/crates/orbinum-encrypted-memo)
[![Documentation](https://docs.rs/orbinum-encrypted-memo/badge.svg)](https://docs.rs/orbinum-encrypted-memo)

Encrypted memo primitives for private transaction metadata in Orbinum Network.

## Features

- **ChaCha20Poly1305 AEAD**: Authenticated encryption for memo data
- **Viewing key encryption**: Only recipient can decrypt note details
- **Value proofs**: Public signal types for the `value_proof` circuit (CircuitId 6)
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

// With a counterparty key — only valid when it is ONE-TIME (see the field notes below)
let memo = MemoData::new(1000, owner_pubkey, blinding, 0, counterparty_pk);

// Without one: shield, unshield, and any transfer whose spent note had no
// one-time key to stamp
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

### Value Proof Types

```rust
use orbinum_encrypted_memo::{ValueProofPublicSignals, ValueProof};

// Build public signals from on-chain bytes (76 bytes, CircuitId 6)
let signals = ValueProofPublicSignals::from_bytes(&raw_76_bytes)?;
assert_eq!(signals.commitment, expected_commitment);

// Bundle proof + signals for on-chain submission
let vp = ValueProof::new(groth16_128_bytes, signals);
vp.validate()?;
let serialized = vp.to_bytes();

// Deserialize on the verifier side
let vp = ValueProof::from_bytes(&serialized)?;
```

## Encryption Scheme

ChaCha20Poly1305 AEAD with per-note key derivation:

```text
Plaintext  (MemoData):  value_lo(8) | value_hi(8) | owner_pk(32) | blinding(32) | asset_id(4) | counterparty_pk(32) | circuit_version(4) = 120 bytes
                        (value = value_lo + value_hi × 2^64, supports u128)

encryption_key = SHA256(shared_secret || commitment || "orbinum-note-encryption-v1")
ciphertext     = ChaCha20Poly1305(plaintext=120B, key=encryption_key, nonce=12B)
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
| `counterparty_pk` | `[u8; 32]` | 32 bytes | A **one-time** key of the other party (Ax, LE), or `[0u8;32]` — see below |
| `circuit_version` | `u32` LE | 4 bytes | ZK circuit version the note is spent under |

**Plaintext**: 120 bytes — **Encrypted wire format**: 180 bytes (`nonce(12) | ciphertext(132) | MAC(16) | ephPk_packed(32)`)

**Value range**: u128 supporting ~340 billion tokens with 18 decimals per note

### `counterparty_pk` — wire name vs. domain name

This is the **frozen wire name**, kept identical here and in the TypeScript SDK's
serialisation layer so both implementations agree byte for byte. Above that boundary the
SDK calls the same field **`sourcePk`**, which describes it more honestly:

- It is **not** an identity. What it carries is the `owner_pk` of the note that was
  *spent*, and only when that key is **one-time** (it came from a stealth-addressed
  transfer). Otherwise the field is zero.
- A note shielded to yourself is self-addressed with no stealth derivation, so its
  `owner_pk` **is** your permanent key. Stamping that into a recipient's note would give
  them a stable identifier for you, so on that path the field stays zero.

Zero is therefore the value for shield and unshield outputs, **and** for a transfer whose
spent note had no one-time key to offer. Use
`MemoData::new_without_counterparty(value, owner_pk, blinding, asset_id)` for those.

A transfer's **change** note is the one case that reliably carries a non-zero value: it
records the recipient's one-time stealth key, and it never leaves the sender's own wallet.

## Value Proof Public Signals

The `value_proof` circuit (CircuitId 6) always reveals exactly 4 signals (76 bytes):

| Field | Size | Description |
|-------|------|-------------|
| `commitment` | 32 bytes | On-chain note commitment |
| `value` | 8 bytes | Token amount (LE u64) |
| `asset_id` | 4 bytes | Asset identifier (LE u32) |
| `owner_hash` | 32 bytes | Poseidon hash of owner public key |

Used by `pallet-shielded-pool::claim_shielded_fees` to prove that a note commitment
encodes the exact amount and asset being claimed.

## Security Properties

- **Confidentiality**: Only viewing key holder can decrypt
- **Authenticity**: AEAD MAC prevents tampering
- **Unlinkability**: Unique encryption key per note (commitment-bound)
- **Forward Secrecy**: Subkey compromise does not expose spending key
- **Zero-Knowledge**: Value proof reveals only commitment/value/asset_id/owner_hash

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE2) or [GPL v3](LICENSE-GPL3) at your option.
