//! # Infrastructure Layer - ZK Verifier
//!
//! Concrete implementations of verification operations.
//! This layer depends on external cryptographic libraries (arkworks).

pub mod adapters;
pub mod verification;

pub use adapters::*;
pub use verification::*;
