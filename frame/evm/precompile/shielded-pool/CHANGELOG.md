# Changelog

All notable changes to `pallet-evm-precompile-shielded-pool` will be documented in this file.

## [0.6.0] - 2026-08-10

### Changed

- **`privateTransfer` takes a trailing `bytes` — the 56-byte OVK blob — and its
  selector changes with it.** A memo is sealed toward the recipient, so its
  sender cannot reopen it; the blob wraps that memo's shared secret under the
  sender's outgoing viewing key so a sender who loses their vault can still
  recover what they sent.

  ```
  privateTransfer(bytes,bytes32,bytes32[],bytes32[],bytes[],uint32,uint256,uint32)        0x66ed2cd4
  privateTransfer(bytes,bytes32,bytes32[],bytes32[],bytes[],uint32,uint256,uint32,bytes)  0x1ec439cf
  ```

  The ABI head grows from 8 slots (256 bytes) to 9 (288). The decoder requires
  the blob to be **exactly 56 bytes** — the SCALE route gets that from the type,
  but calldata carries a dynamic `bytes`, so the EVM route has to pin it here.

  **Breaking, in both directions.** A caller on the old selector is rejected as
  unsupported; a caller on the new one against an old runtime is too. Wallet and
  runtime must ship together. `transaction_version` is bumped 2 → 3.

- **The selectors are now exported** as `selectors::{SHIELD, PRIVATE_TRANSFER,
  UNSHIELD, CLAIM_SHIELDED_FEES}`, so the relay whitelist can be pinned against
  the decoder's own constants in a test instead of keeping a hand-copied list in
  sync. That copy drifting is ME-8, and it fails silently: a wrong selector is
  merely "unsupported", so rejection tests stay green while relaying stops
  working.

## [0.5.0] - 2026-08-07

### Security

- **ABI decoder rejects oversized words instead of truncating them.** Offsets and
  lengths are `uint256`, but `read_offset` and `read_length` narrowed them with
  `low_u32()`, which keeps the bottom 32 bits and discards the rest. An offset of
  `2^32 + 8` read back as `8`, and `2^32` as `0` — so the bounds check validated a
  value the sender never wrote and the decoder indexed somewhere else entirely.
  Every word is now checked against `usize::MAX` and refused if it does not fit.

  `decode_u32` had the same shape: the ABI declares the argument as `uint32`, so a
  wider word is a call the callee never agreed to. Keeping the low bits turned a
  malformed call into a plausible one naming a different value.

- **Offset and length arithmetic is checked.** `data_start + length >
  params.len()` wraps for a large length, and the wrapped sum passes the very
  bounds check it was meant to fail. Release builds do not enable
  `overflow-checks`, so it wrapped silently on exactly the input being guarded
  against. Same for `count * 32` in the array decoders. All now use
  `checked_add` / `checked_mul`. The wrapping-length case was worse than a
  mis-decode: it built an inverted slice range and panicked the runtime
  (`slice index starts at 128 but ends at 127` → `wasm unreachable` trap),
  reachable from an unsigned, gas-free `eth_call`.

- **Element counts are validated before allocating.** `Vec::with_capacity(count)`
  reserved from a calldata-supplied count before anything confirmed the buffer
  could hold that many elements. The span is now bounds-checked first.

- A `.unwrap()` on a slice conversion in `decode_bytes32_array_at_slot` became a
  propagated error. It was unreachable given the surrounding checks, but a panic
  in a precompile is not a failure mode worth keeping reachable-by-accident.

### Changed

- `abi.rs` and `dispatch.rs` split into directories by responsibility, no
  behaviour change. `abi/` → `guard` (checked arithmetic), `scalar` (`uint32`,
  `bytes32`), `dynamic` (`bytes`, `bytes32[]`, `bytes[]`). `dispatch/` → `mod`
  (shared call/gas/result handling in `record_and_dispatch`) and `origin` (the
  three origin modes). Tests moved alongside the code they cover.

### Notes

- No ABI change. Every selector, parameter and head layout is untouched, and
  well-formed calldata decodes exactly as before. What narrowed is the set of
  malformed inputs the decoder will act on.

### Verification
74 precompile tests (9 new), clippy clean across the workspace under the CI
feature set.

Each guard was verified by reverting it and confirming the tests fail: replacing
`word_to_usize` with `low_u32` breaks three, and turning one `checked_add` into
`wrapping_add` breaks another — that last one is the direct demonstration, since
without the check the crafted length passes the bounds check.

A dev-node run (26/26) sends hand-built calldata straight at the precompile via
`eth_call`: offsets of `2^32`, `2^64`, `2^255` and `uint256::MAX`, lengths that
would wrap the bounds check, over-wide `uint32` words, truncated heads, and a
40-call hostile burst — checking block height after each batch. Well-formed
calldata still clears the decoder and reaches the pallet's own guards.

## [0.4.0] - 2026-08-06

### Changed
- **`shield` now accepts any non-zero `msg.value`.** The pallet's `MinShieldAmount`
  (1 ORB in the runtime) is gone, so a call carrying 1 wei goes through where it
  previously reverted with `AmountTooSmall`.

  Nothing changed in this crate's own logic: the precompile never enforced the
  minimum, it only forwarded `msg.value` and let the pallet decide. The zero-value
  guard at the ABI boundary stays — it fails earlier and with a clearer message
  than the dispatch layer would.

  **No ABI change.** Every selector, parameter and head layout is untouched;
  callers need no rebuild. Only the set of calls the chain accepts widened.

## [0.3.0] - 2026-07-09

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
