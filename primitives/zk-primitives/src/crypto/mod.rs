//! # Cryptographic Operations
//!
//! This module provides all cryptographic primitives used in the ZK system:
//! - **hash**: Poseidon hash function (ZK-friendly)
//! - **commitment**: Note commitment and nullifier generation
//! - **merkle**: Merkle tree proof verification
//!
//! All functions use strong types from the `core` module to prevent
//! accidental misuse (e.g., passing a Nullifier where a Commitment is expected).

pub mod commitment;
pub mod hash;
pub mod merkle;
