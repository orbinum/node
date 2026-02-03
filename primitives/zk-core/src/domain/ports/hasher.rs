//! # Hash Function Port
//!
//! Defines the interface for hash functions in the domain layer.
//! This is a Clean Architecture "port" - an abstraction that allows
//! the domain to remain independent of infrastructure implementations.

use crate::domain::value_objects::FieldElement;

/// Port for Poseidon hash functions
///
/// ## Clean Architecture Pattern
/// This trait defines what the domain needs from hash functions,
/// without depending on any specific implementation (light-poseidon, circom, etc.).
///
/// ## Implementations
/// - Infrastructure layer provides concrete implementations
/// - Allows easy mocking for tests
/// - Enables swapping hash implementations without changing domain logic
pub trait PoseidonHasher {
	/// Hash 2 field elements
	///
	/// Used for:
	/// - Merkle tree sibling hashing
	/// - Nullifier computation: H(commitment, spending_key)
	fn hash_2(&self, inputs: [FieldElement; 2]) -> FieldElement;

	/// Hash 4 field elements
	///
	/// Used for:
	/// - Note commitment: H(value, asset_id, owner_pubkey, blinding)
	fn hash_4(&self, inputs: [FieldElement; 4]) -> FieldElement;
}
