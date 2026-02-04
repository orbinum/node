//! # Constraint System Port
//!
//! Abstract interface for R1CS constraint systems.
//! Allows domain logic to be independent of specific arkworks implementations.

use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

/// Type alias for constraint system reference
pub type ConstraintSystem<F> = ConstraintSystemRef<F>;

/// Result type for constraint operations
pub type ConstraintResult<T> = Result<T, SynthesisError>;
