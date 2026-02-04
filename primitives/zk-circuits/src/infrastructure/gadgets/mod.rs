//! # Gadgets Module (Infrastructure Layer)
//!
//! R1CS constraint-generating gadgets for cryptographic operations.
//! These are infrastructure adapters that implement domain abstractions using arkworks.
//!
//! Each gadget corresponds to a native primitive in `orbinum-zk-core`,
//! but generates R1CS constraints instead of computing directly.
//!
//! ## Modules
//!
//! - `poseidon`: Poseidon hash gadget
//! - `merkle`: Merkle tree membership proof gadget
//! - `commitment`: Commitment and nullifier gadgets
//!
//! ## Usage
//!
//! ```rust,ignore
//! use fp_zk_circuits::gadgets::{poseidon, merkle, commitment};
//! use ark_relations::r1cs::ConstraintSystem;
//! use ark_r1cs_std::alloc::AllocVar;
//!
//! let cs = ConstraintSystem::new_ref();
//!
//! // Allocate inputs as circuit variables
//! let value = FpVar::new_witness(cs.clone(), || Ok(Fr::from(100)))?;
//! let blinding = FpVar::new_witness(cs.clone(), || Ok(Fr::from(123)))?;
//!
//! // Create constraints for Poseidon hash
//! let hash = poseidon::poseidon_hash_2(cs.clone(), &[value, blinding])?;
//! ```
//!
//! ## Difference from Native Primitives
//!
//! | Native (`orbinum-zk-core`) | Gadget (`orbinum-zk-circuits::gadgets`) |
//! |-----------------------------|-----------------------------------|
//! | Computes result directly    | Generates R1CS constraints        |
//! | Fast (native Rust)          | Slower (constraint generation)    |
//! | Use in wallet, tests        | Use in ZK circuits                |
//! | No proof generated          | Used to create proofs             |

pub mod commitment;
pub mod merkle;
pub mod poseidon;
