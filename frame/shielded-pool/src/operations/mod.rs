//! Business operations for the shielded pool.
//!
//! This is the single application entrypoint used by the pallet extrinsics.
//! Each module owns one workflow and coordinates domain logic, repositories,
//! and infrastructure services.

pub mod assets;
pub mod fees;
pub mod private_transfer;
pub mod shield;
pub mod unshield;
