//! # Circuits Module (Application Layer)
//!
//! Complete ZK-SNARK circuits for private transactions.
//! These are application use cases that orchestrate infrastructure gadgets.
//!
//! ## Circuits
//!
//! - `note`: Note commitment and nullifier circuits
//! - `transfer`: Complete private transfer circuit
//!
//! ## Usage
//!
//! ```rust,ignore
//! use fp_zk_circuits::circuits::transfer::TransferCircuit;
//! use fp_zk_circuits::circuits::note::Note;
//!
//! let circuit = TransferCircuit::new(witness, merkle_root);
//! ```

pub mod note;
pub mod transfer;
