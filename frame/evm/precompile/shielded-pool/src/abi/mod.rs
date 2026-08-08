//! Pure ABI decoding helpers for the shielded-pool precompile.
//!
//! All functions are stateless free functions — no FRAME generics, no pallet types.
//! They operate directly on raw ABI-encoded byte slices and return typed Rust values.
//!
//! Every input here is attacker-chosen calldata, so two rules hold throughout:
//! a 256-bit ABI word is **rejected** when it does not fit the type it is being
//! read into rather than narrowed to its low bits, and every offset and length
//! arithmetic is checked. Release builds do not enable `overflow-checks`, so an
//! unchecked sum would wrap silently and pass the very bounds check meant to
//! catch it.
//!
//! Split by responsibility:
//! - [`guard`] — the checked arithmetic and `usize` conversion every decoder relies on.
//! - [`scalar`] — fixed-width types (`uint32`, `bytes32`).
//! - [`dynamic`] — offset/length-driven types (`bytes`, `bytes32[]`, `bytes[]`).

mod dynamic;
mod guard;
mod scalar;

pub use dynamic::{decode_bytes32_array_at_slot, decode_bytes_array_at_slot, decode_bytes_at_slot};
pub use scalar::{decode_u32, read_bytes32};
