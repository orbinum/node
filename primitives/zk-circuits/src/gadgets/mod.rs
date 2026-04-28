//! ZK Circuit Gadgets
//!
//! R1CS constraint-generating primitives:
//! - [`poseidon`]: Poseidon hash gadgets (hash_2, hash_4, hash_var)
//! - [`commitment`]: Note commitment and nullifier gadgets
//! - [`merkle`]: Merkle tree verifier gadget
//! - [`eddsa`]: EdDSA-Poseidon signature verifier (Baby JubJub / circomlib)

pub mod commitment;
pub mod eddsa;
pub mod merkle;
pub mod poseidon;

pub use commitment::{note_commitment, nullifier};
pub use eddsa::verify_eddsa;
pub use merkle::{merkle_tree_verifier, verify_merkle_proof};
pub use poseidon::{poseidon_hash_2, poseidon_hash_4, poseidon_hash_var};
