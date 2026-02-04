//! # Infrastructure Layer - ZK Circuits
//!
//! Concrete implementations of R1CS gadgets using arkworks.
//! This layer depends on external cryptographic libraries.

pub mod gadgets;
pub mod native_crypto;

pub use gadgets::*;
pub use native_crypto::*;
