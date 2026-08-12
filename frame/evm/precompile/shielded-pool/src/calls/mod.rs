//! Per-function call decoders for the shielded-pool precompile.
//!
//! Each sub-module owns:
//! - the **ABI selector** for the corresponding Solidity function,
//! - the **`decode`** function that turns raw `input` bytes into a
//!   `pallet_shielded_pool::Call<T>`.
//!
//! The precompile router in `lib.rs` only needs to match on `SELECTOR`s and
//! forward to the appropriate `decode`, then hand the call to `dispatch`.
//!
//! Each module header documents the selector and the ABI slot layout; `decode`
//! walks that layout in numbered steps. Decoding is the trust boundary, so a
//! `decode` also rejects input that is well-formed but irrecoverable — a zero
//! amount, a burn address, a memo without which a note could never be spent —
//! rather than leaving it to the pallet.

pub mod claim_shielded_fees;
pub mod private_transfer;
pub mod shield;
pub mod unshield;
