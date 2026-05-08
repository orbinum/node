# Changelog

All notable changes to `pallet-shielded-pool` will be documented in this file.

## [0.7.0] - 2026-05-08

### Added
- **Stealth Address Support for Change Notes** - Enables unlinkable change note commitments during partial unshield
  - New parameter in `unshield` extrinsic: `change_encrypted_memo: &[u8]`
  - New storage map: `CommitmentMemos<T>` - stores encrypted memos keyed by commitment hash
  - Change notes now use ephemeral keypairs for recipient derivation
  - Stealth owner public key derivation via ECDH + HKDF-based tweak

- **Extended Encrypted Memo Support** - Increased from 168 to 176 bytes total
  - Plaintext memo structure: value_lo(8) || value_hi(8) || owner_pk(32) || blinding(32) || asset_id(4) || counterparty_pk(32) = 116 bytes
  - Encrypted memo structure: nonce(12) || ciphertext+MAC(132) || ephPk_packed(32) = 176 bytes
  - Supports u128 values (up to ~340 billion tokens per note with 18 decimals)
  - All memo size validations updated throughout codebase

### Changed
- **Unshield Event Enhanced** - Added change note tracking fields
  - New fields: `change_commitment: Commitment`, `change_encrypted_memo: Vec<u8>`, `change_leaf_index: u32`
  - Allows chain consumers (indexers, wallets) to track change note insertions
  - Change leaf index enables efficient Merkle path retrieval for change note spending

- **Extrinsic Signature** - `unshield` now accepts change_encrypted_memo parameter
  - From: `unshield(proof, merkle_root, nullifier, asset_id, amount, recipient, fee, change_commitment)`
  - To: `unshield(proof, merkle_root, nullifier, asset_id, amount, recipient, fee, change_commitment, change_encrypted_memo)`
  - Change_encrypted_memo can be empty (0 bytes) for full balance unshield with no change

- **Storage Updates** - New storage item for memo persistence
  - `CommitmentMemos<T>` - BTreeMap<Commitment, Vec<u8>>
  - Stores change note encrypted memos for later retrieval during rescan
  - Enables wallet privacy recovery without modifying blockchain state

- **Merkle Tree Integration** - Change notes automatically inserted into tree
  - Change commitment inserted via `insert()` when present
  - Change leaf index tracked and emitted in event
  - Merkle tree size incremented accordingly
  - Historical roots updated to support change note proof verification

### Technical Details

**Crypto Stack Unchanged**:
- Poseidon hashing (commitment = Poseidon4(value_lo, value_hi, owner_pk, blinding))
- ChaCha20-Poly1305 IETF encryption (96-bit nonce, 16-byte AEAD MAC)
- Baby JubJub curve operations for stealth derivation

**Stealth Change Note Flow**:
```
1. During unshield with partial balance:
   - Generate ephemeral keypair: ephSk = random()
   - Derive shared secret: ECDH(ephSk, recipient_ivk_point)
   - Compute stealth owner pk: recipient_pk + HKDF(shared_secret, ...)
   - Create change commitment with stealth pk
   - Encrypt memo with ephSk for later recovery

2. During rescan:
   - Try ECDH with recipient's viewing secret key
   - Derive stealth owner pk and verify it matches note commitment
   - Decrypt memo to recover change note details (value, blinding)
   - Compute spending key for note spending
```

**Backward Compatibility**:
- ❌ BREAKING: Unshield extrinsic signature changed (9 vs 8 parameters)
- ❌ BREAKING: Encrypted memo size validation now 176 bytes (was 168)
- ❌ BREAKING: Event `Unshielded` has new fields (requires event handler updates)
- ✅ Compatible: Private transfer remains unchanged (still 168/176 byte memos)
- ✅ Compatible: Shield extrinsic unchanged (memo size auto-detected)

**Test Coverage**:
- 326/326 integration tests passing
- Comprehensive Merkle tree operations validated
- Nullifier double-spend prevention verified
- Multi-asset support confirmed
- Pool balance tracking tested
- Change note storage and retrieval validated
- Stealth address derivation tested (via integration tests)

### Bug Fixes
- Fixed encrypted memo size validation to enforce 176-byte requirement
- Fixed u128 value truncation in memos (now uses two u64 LE words)
- Fixed CommitmentMemos storage key consistency

## [0.6.1] - 2026-04-15

### Minor Fixes
- Improved error messages for memo size validation
- Optimized nullifier set lookups
- Updated documentation for asset registration

## [0.6.0] - 2026-03-01

### Initial Shielded Pool Release
- Multi-asset support with asset registry
- Merkle tree (binary, depth-configurable) for commitments
- Nullifier tracking to prevent double-spending
- Private transfer with 2-in/2-out UTXO structure
- Partial unshield with change note support (non-stealth)
- ZK proof verification via pallet-zk-verifier
- Runtime API for Merkle tree queries
- Full unit test coverage
