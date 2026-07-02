//! # Orbinum ZK Core
//!
//! Poseidon-based cryptographic primitives for ZK-SNARK operations in Orbinum Network.
//!
//! ## Modules
//!
//! - [`types`]: Field element newtypes (`Commitment`, `Nullifier`, `OwnerPubkey`, …) and `Note`.
//! - [`hash`]: `PoseidonHasher` trait plus `LightPoseidonHasher` (WASM) and `NativePoseidonHasher` (native).
//! - [`ops`]: Free functions — `compute_commitment`, `compute_nullifier`, `merkle_hash`.
//! - [`host_interface`]: `sp-runtime-interface` native host functions (gated on `poseidon-native`).
//!
//! ## Features
//!
//! - `std` (default): enables standard library.
//! - `poseidon-native` (default): enables `NativePoseidonHasher` and native host functions.
//!
//! ## No-std
//!
//! The crate is `no_std` compatible by default; enable `std` for standard library support.
//!
//! ## Consensus invariant
//!
//! `NativePoseidonHasher(x) == LightPoseidonHasher(x)` for all `x`, and both must
//! equal the Poseidon of the compiled Circom circuit. The native and WASM paths
//! must never diverge (a divergence forks the chain). This is enforced by the
//! known-answer vectors and native≡WASM tests in `tests/poseidon_vectors.rs`; the
//! circuit remains the source of truth for the parameters.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod hash;
pub mod ops;
pub mod types;

#[cfg(feature = "poseidon-native")]
pub mod host_interface;

// ─── Re-exports ───────────────────────────────────────────────────────────────

pub use hash::{poseidon_hash_1, LightPoseidonHasher, PoseidonHasher};

#[cfg(feature = "poseidon-native")]
pub use hash::NativePoseidonHasher;

pub use ops::{compute_commitment, compute_nullifier, merkle_hash};

pub use types::{
	Blinding, Commitment, FieldElement, Note, Nullifier, OwnerPubkey, SpendingKey,
	MAX_MERKLE_LEAVES, MERKLE_TREE_DEPTH,
};
