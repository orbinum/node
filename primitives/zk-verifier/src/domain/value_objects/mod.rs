//! # Value Objects
//!
//! Immutable domain primitives.

pub mod circuit_constants;
pub mod errors;
pub mod proof_types;

// Re-export commonly used types
pub use errors::VerifierError;
pub use proof_types::{Proof, PublicInputs, VerifyingKey};
