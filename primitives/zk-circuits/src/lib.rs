//! # orbinum-zk-circuits
//!
//! Zero-Knowledge R1CS circuits and gadgets for Orbinum shielded transactions.
//!
//! Provides Groth16/R1CS circuits for generating ZK proofs of private transfers.
//! Intended for off-chain use (proof generation, testing). The runtime only
//! needs `orbinum-zk-verifier` for on-chain proof verification.
//!
//! ## Modules
//!
//! - [`types`]: Core data types (Note, MerklePath, TreeDepth, CircuitValidator)
//! - [`gadgets`]: R1CS gadgets (Poseidon, commitment, nullifier, Merkle)
//! - [`circuits`]: Full circuits (TransferCircuit)
//!
//! ## Example
//!
//! ```rust,ignore
//! use orbinum_zk_circuits::{TransferCircuit, TransferWitness, Note};
//!
//! // Build witness
//! let witness = TransferWitness::new(input_notes, spending_keys, paths, indices, output_notes);
//! witness.validate()?;
//!
//! // Prove
//! let circuit = TransferCircuit::new(witness, merkle_root);
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

/// BN254 scalar field element (used throughout circuits)
pub use ark_bn254::Fr as Bn254Fr;

pub mod circuits;
pub mod gadgets;
pub(crate) mod native;
pub mod types;

pub use circuits::transfer::{
	TransferCircuit, TransferPublicInputs, TransferWitness, NUM_INPUTS, NUM_OUTPUTS, TREE_DEPTH,
};
pub use circuits::unshield::{UnshieldCircuit, UnshieldPublicInputs, UnshieldWitness};
pub use gadgets::{
	merkle_tree_verifier, note_commitment, nullifier, poseidon_hash_2, poseidon_hash_4,
	poseidon_hash_var, verify_eddsa, verify_merkle_proof,
};
pub use types::{CircuitValidator, MerklePath, Note, TreeDepth, ValidationError};
