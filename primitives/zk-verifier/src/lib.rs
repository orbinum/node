//! # Zero-Knowledge Verifier Primitives
//!
//! This crate provides the core primitives for verifying Zero-Knowledge proofs
//! in the Orbinum blockchain. It uses the Groth16 proving system over the BN254
//! elliptic curve.
//!
//! ## Overview
//!
//! The ZK verifier allows the blockchain to verify proofs that certain statements
//! are true without revealing the underlying data. This is essential for:
//!
//! - **Private transactions**: Prove you have funds without revealing amounts
//! - **Nullifier verification**: Prove a note hasn't been spent before
//! - **Merkle tree membership**: Prove a note exists in the tree
//!
//! ## Features
//!
//! - `std` (default): Enable standard library support
//! - `substrate`: Enable Substrate runtime integration
//!
//! ## Usage
//!
//! ```rust,ignore
//! use fp_zk_verifier::{Groth16Verifier, Proof, VerifyingKey, PublicInputs};
//!
//! // Verify a proof
//! let result = Groth16Verifier::verify(&vk, &public_inputs, &proof);
//! assert!(result.is_ok());
//! ```
//!
//! ## Proving System
//!
//! - **Algorithm**: Groth16 (fast verification, small proofs)
//! - **Curve**: BN254 (optimal for Ethereum compatibility)
//! - **Proof size**: ~200 bytes
//! - **Verification time**: <10ms on-chain
//!
//! ## Architecture
//!
//! This crate follows a 3-layer architecture (similar to fp-zk-primitives):
//!
//! - **Layer 1: Core** ([`core`]) - Fundamental types, constants, and errors
//!   - [`core::constants`] - Circuit IDs and verification cost constants
//!   - [`core::error`] - Error types
//!   - [`core::types`] - Proof, VerifyingKey, PublicInputs types
//!
//! - **Layer 2: Crypto** ([`crypto`]) - Cryptographic verification operations
//!   - [`crypto::groth16`] - Groth16 proof verification
//!   - [`crypto::utils`] - Utility functions for field operations
//!
//! - **Layer 3: Compat** ([`compat`]) - Compatibility and interoperability
//!   - [`compat::snarkjs`] - SnarkJS format compatibility
//!
//! - **Verification Keys** ([`vk`]) - Hardcoded VKs for circuits
//!   - [`vk::transfer`] - Transfer circuit VK
//!   - [`vk::unshield`] - Unshield circuit VK
//!   - [`vk::registry`] - Runtime VK lookup by circuit ID
//!
//! ## Feature Flags
//!
//! - `std` (default): Enables standard library support
//! - `substrate`: Enables Substrate runtime integration
//!
//! ## Verification Keys
//!
//! ```rust,ignore
//! use fp_zk_verifier::vk::{get_transfer_vk, get_unshield_vk};
//! use fp_zk_verifier::vk::registry::get_vk_by_circuit_id;
//!
//! // Get VK directly
//! let transfer_vk = get_transfer_vk();
//! 
//! // Or lookup by circuit ID
//! let vk = get_vk_by_circuit_id(1)?; // Transfer
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

// ============================================================================
// Modules (3-Layer Architecture)
// ============================================================================

/// Layer 1: Core types, constants, and errors
pub mod core;

/// Layer 2: Cryptographic verification operations
pub mod crypto;

/// Layer 3: Compatibility and interoperability
pub mod compat;

/// Verification keys for ZK circuits
pub mod vk;

// ============================================================================
// Core Type Alias (always available)
// ============================================================================

/// BN254 scalar field element - the base type for all ZK computations
pub type Bn254Fr = ark_bn254::Fr;

/// BN254 pairing curve
pub use ark_bn254::Bn254;

// ============================================================================
// Re-exports for Convenience
// ============================================================================

// Re-export core types
pub use core::{
	error::VerifierError,
	types::{Proof, PublicInputs, VerifyingKey},
};

// Re-export commonly used constants
pub use core::constants::{
	BASE_VERIFICATION_COST, CIRCUIT_ID_TRANSFER, CIRCUIT_ID_UNSHIELD, PER_INPUT_COST,
	TRANSFER_PUBLIC_INPUTS, UNSHIELD_PUBLIC_INPUTS,
};

// Re-export Groth16 verifier
pub use crypto::groth16::Groth16Verifier;

// Re-export VK functions
pub use vk::{
	get_transfer_vk, get_transfer_vk_bytes, get_unshield_vk, get_unshield_vk_bytes,
	registry::{get_public_input_count, get_vk_by_circuit_id, validate_public_input_count},
};

// Re-export SnarkJS utilities (std only)
#[cfg(feature = "std")]
pub use compat::snarkjs::{
	parse_proof_from_snarkjs, parse_public_inputs_from_snarkjs, SnarkjsProofPoints,
};
