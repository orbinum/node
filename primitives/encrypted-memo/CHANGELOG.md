# Changelog

All notable changes to `orbinum-encrypted-memo` will be documented in this file.

## [0.5.0] - 2026-05-08

### Added
- **Stealth Address Mode for Change Notes** - ECDH-based ephemeral keypair derivation
  - New parameter: `ephSk` (ephemeral secret key) for stealth change note encryption
  - Stealth scalar derivation: HKDF(shared_secret, salt=owner_pk_LE, info="orbinum-stealth-v1")
  - Unlinkable change note commitments via additive tweaking of owner public key
  - Change note encrypted memos stored on-chain for wallet recovery during rescan

- **Extended Value Support** - u128 instead of u64
  - Memo now stores `value_lo` (8 bytes) + `value_hi` (8 bytes) instead of single `value`
  - Supports ~340 billion tokens per note with 18 decimals
  - Backward calculation: `value = value_lo + (value_hi << 64)`

### Changed
- **Memo Size Increase** - 168 bytes → 176 bytes total
  - Plaintext: 108 → 116 bytes (added 8 bytes for value_hi)
  - Ciphertext+MAC: 124 → 132 bytes (adjusted for plaintext size)
  - Ephemeral public key field: 32 bytes (unchanged, still packed BJJ point)
  - New layout: nonce(12) || ciphertext+MAC(132) || ephPk_packed(32)

- **ECDH Key Derivation** - Ephemeral keypair now included in stealth mode
  - Ephemeral public key appended at bytes [144..176] (was [136..168])
  - ECDH calculation uses new offset for ephPk recovery
  - Shared secret derivation: `BJJ_mul(ivk_point, ephSk)[0]` (x-coordinate, LE)

- **Documentation** - Updated README with stealth address flow and memory layout
  - Clarified difference between symmetric mode (legacy) and ECDH mode (wallet)
  - Added Stealth Address Mode section explaining change note generation
  - Updated Memo Structure table with value_lo/value_hi fields
  - Enhanced Key Derivation Hierarchy with stealth math

### Technical Details

**Memo Plaintext Structure (v0.5)**:
```
value_lo (8 LE)
value_hi (8 LE)
owner_pk (32)
blinding (32)
asset_id (4 LE)
counterparty_pk (32)
────────────────────────
Total: 116 bytes
```

**Encrypted Memo Wire Format (v0.5)**:
```
nonce (12)              bytes [0..12]
ciphertext+MAC (132)    bytes [12..144]
ephPk_packed (32)       bytes [144..176]
────────────────────────
Total: 176 bytes
```

**Stealth Change Note Flow**:
1. Sender generates random ephSk during unshield proof construction
2. Computes shared_secret = ECDH(ephSk, recipient_ivk_point).Ax
3. Derives stealth_scalar = HKDF(shared_secret, salt=owner_pk_LE, info="orbinum-stealth-v1")
4. Computes change commitment with stealth owner pk
5. Encrypts change memo with ephSk (same ephemeral key)
6. Stores encrypted memo on-chain via CommitmentMemos

**During Wallet Rescan**:
1. Extract ephPk from encrypted[144..176]
2. Compute shared_secret = ECDH(viewer_ivsk, ephPk).Ax
3. Derive stealth_scalar and stealth owner pk
4. Check if derived pk matches commitment owner pk
5. If match, decrypt memo and recover note value/blinding
6. Compute spending key for change note: HKDF(ivsk, stealth_scalar)

### Backward Compatibility

⚠️ **BREAKING CHANGES**:
- Memo size format changed (168 → 176 bytes) — old memos cannot be decrypted with new version
- Plaintext structure changed (value → value_lo + value_hi) — serialization incompatible
- Ephemeral public key offset changed (bytes [136..168] → [144..176])

✅ **Compatible**:
- Symmetric mode (legacy server-side) still supported
- ECDH mode encryption/decryption logic unchanged (only offset updates)
- Key derivation hierarchy preserved

## [0.4.0] - 2026-02-15

### Features
- ChaCha20-Poly1305 AEAD encryption/decryption
- 168-byte encrypted memo format (nonce 12 + ciphertext 108 + MAC 16 + ephPk 32)
- Viewing key encryption for privacy
- Symmetric and ECDH key derivation modes
- Selective disclosure masks
- SCALE codec support
- no_std compatible

## [0.3.0] - 2026-01-10

### Initial Release
- Basic encrypted memo types
- Deterministic key derivation
- Early selective disclosure prototypes
