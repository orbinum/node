# Changelog

All notable changes to `pallet-evm-precompile-shielded-pool` will be documented in this file.

## [Unreleased]

### Changed
- **ABI: added a trailing `uint32 circuitVersion` to `privateTransfer`, `unshield`
  and `claimShieldedFees`** — the circuit version the spent note was created under,
  forwarded to the pallet so the proof is verified against that version's VK. This
  changes each function's selector (**breaking**): `privateTransfer` `0x8c0f5d24` →
  `0x66ed2cd4`, `unshield` `0xcc1a3b38` → `0x4e505348`, `claimShieldedFees`
  `0x42e1e74c` → `0x88d9deba`. Callers (SDK / app) must send the new calldata.
- Fixed the stale `unshield` selector/signature in the router doc table
  (`0x47fc44a2` → the actual on-chain value).

### Security
- **`unshield` change-memo decode fails loudly for a partial unshield.** A
  malformed `change_encrypted_memo` offset pointer previously fell back to an
  empty memo (`unwrap_or_default`), silently turning a partial unshield into one
  whose change note is unrecoverable. It now errors unless the unshield is total
  (`change_commitment == [0; 32]`), where an absent memo is legitimate.

## [0.2.0] - 2026-05-08

### Changed
- **ABI: unshield function signature** - Added `change_encrypted_memo: bytes` parameter (9th parameter) to support stealth address change notes
  - Old signature: `unshield(bytes,bytes32,bytes32,uint32,uint256,bytes32,uint256,bytes32)`
  - New signature: `unshield(bytes,bytes32,bytes32,uint32,uint256,bytes32,uint256,bytes32,bytes)`
  - Selector updated: `0xd21d9a79` → `0xcc1a3b38`
  - Head layout: 256 bytes → 288 bytes (9 slots × 32 bytes)
  - Dynamic offsets for proof and memo now calculated with proper tail positioning

- **Memo size validation** - All ABI helpers updated to support 176-byte encrypted memos (previously 168 bytes)
  - Shield: `encode_shield()` now uses &[0xAB; 176]
  - Private transfer: `encode_private_transfer()` memo vectors updated to 176 bytes
  - Unshield: change_encrypted_memo supports dynamic encoding of 176-byte encrypted memos

- **Test suite** - All 42 tests passing with updated ABI signatures
  - Fixed 8 `encode_unshield()` call sites to include `&[]` change_encrypted_memo parameter
  - Updated 7 `encode_private_transfer()` call sites with 176-byte memo sizes
  - Updated `do_shield()` helper with 176-byte memo size
  - All test functions now compile and pass without errors

### Technical Details
- Selector calculation: `keccak256("unshield(bytes,bytes32,bytes32,uint32,uint256,bytes32,uint256,bytes32,bytes)")[0:4]`
- Dynamic offset calculations properly handle variable-length `bytes` proof and memo parameters
- Compatible with stealth address implementation in parent pallet
- Backward-incompatible change: Previous versions of the precompile cannot decode new ABI signatures

## [0.1.0] - 2026-04-15

### Initial Release
- Basic EVM precompile for shielded pool operations (shield, private_transfer, unshield)
- Support for Groth16 proof verification via `pallet-zk-verifier`
- 168-byte encrypted memo support
- Full test suite with comprehensive ABI validation
