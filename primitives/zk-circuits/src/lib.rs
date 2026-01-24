//! # ZK Circuits Library
//!
//! This crate provides R1CS circuits and gadgets for Zero-Knowledge proofs
//! in the Orbinum blockchain. It is separate from `fp-zk-verifier` to allow
//! the runtime to compile without R1CS dependencies.
//!
//! ## Overview
//!
//! This crate is intended for:
//! - Circuit development and testing
//! - Proof generation (off-chain)
//! - Integration tests
//!
//! The runtime only needs `fp-zk-verifier` for proof verification.
//!
//! ## Modules
//!
//! - [`gadgets`]: R1CS constraint gadgets
//!   - [`gadgets::poseidon`]: Poseidon hash gadget
//!   - [`gadgets::merkle`]: Merkle tree membership gadget
//!   - [`gadgets::commitment`]: Commitment and nullifier gadgets
//!
//! - [`circuits`]: Complete circuit definitions
//!   - [`circuits::note`]: Note commitment and nullifier circuits
//!   - [`circuits::transfer`]: Private transfer circuit
//!
//! ## Usage
//!
//! ```rust,ignore
//! use fp_zk_circuits::circuits::transfer::{TransferCircuit, TransferWitness};
//! use fp_zk_circuits::circuits::note::Note;
//! use fp_zk_circuits::gadgets::poseidon::poseidon_hash_2;
//!
//! // Create a transfer circuit
//! let circuit = TransferCircuit::new(witness, merkle_root);
//!
//! // Generate proof (with `proving` feature)
//! let proof = generate_proof(&pk, circuit)?;
//! ```
//!
//! ## Feature Flags
//!
//! - `std` (default): Enables standard library support
//! - `proving`: Enables proof generation (adds ark-groth16, ark-snark)

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

// ============================================================================
// Type Aliases
// ============================================================================

/// BN254 base field element (used throughout circuits)
pub use ark_bn254::Fr as Bn254Fr;

// ============================================================================
// Modules
// ============================================================================

/// R1CS gadgets for ZK circuits
pub mod gadgets;

/// Complete ZK circuits
pub mod circuits;
