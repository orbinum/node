//! Per-pallet `Config` implementations, grouped by domain.
//!
//! These are plain `impl` items, so splitting them out of `lib.rs` changes
//! nothing about how the runtime is assembled — unlike `#[frame_support::runtime]`
//! and `impl_runtime_apis!`, which the macros must see as single blocks.
//!
//! Each module pulls the runtime's types in through `use super::*`, so a config
//! reads the same here as it did inline.

pub mod consensus;
pub mod evm;
pub mod ismp;
pub mod privacy;
pub mod system;
