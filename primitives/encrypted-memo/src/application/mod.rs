//! Application Layer (Use Cases)
//!
//! Orchestrates domain and infrastructure services to implement complete use cases.
//!
//! ## Use Cases
//!
//! - [`disclosure`] - Selective disclosure proof generation
//! - [`prover`] - Groth16 proof generation for disclosure circuit
//!
//! ## Dependencies
//!
//! Application layer depends on:
//! - Domain layer (business logic)
//! - Infrastructure layer (external adapters)
//! - Core primitives (crypto)

#[cfg(feature = "disclosure")]
pub mod disclosure;

// prover module requires both disclosure + wasm-witness features
#[cfg(all(feature = "disclosure", feature = "wasm-witness"))]
pub mod prover;
