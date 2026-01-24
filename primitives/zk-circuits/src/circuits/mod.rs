//! # ZK Circuits
//!
//! Complete ZK-SNARK circuits for private transactions.
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
