//! Per-function call decoders for the shielded-pool precompile.
//!
//! Each sub-module owns:
//! - the **ABI selector** for the corresponding Solidity function,
//! - the **`decode`** function that turns raw `input` bytes into a
//!   `pallet_shielded_pool::Call<T>`.
//!
//! The precompile router in `lib.rs` only needs to match on `SELECTOR`s and
//! forward to the appropriate `decode`, then hand the call to `dispatch`.

pub mod private_transfer;
pub mod shield;
pub mod unshield;
