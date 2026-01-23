//! # Core Types
//!
//! Fundamental type definitions for zero-knowledge primitives.

use ark_bn254::Fr;

// ============================================================================
// Field Element
// ============================================================================

/// Field element type for BN254 scalar field
///
/// This is the base type for all cryptographic operations in the system.
pub type Bn254Fr = Fr;

// ============================================================================
// Strong Types (New-type Pattern)
// ============================================================================

/// A note commitment (hash of note contents)
///
/// Strong type to prevent mixing up commitments with other field elements.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Commitment(pub Bn254Fr);

impl Commitment {
	/// Create from field element
	pub fn new(value: Bn254Fr) -> Self {
		Self(value)
	}

	/// Get inner field element
	pub fn inner(&self) -> Bn254Fr {
		self.0
	}
}

impl From<Bn254Fr> for Commitment {
	fn from(value: Bn254Fr) -> Self {
		Self(value)
	}
}

impl From<Commitment> for Bn254Fr {
	fn from(commitment: Commitment) -> Self {
		commitment.0
	}
}

/// A nullifier (hash that marks note as spent)
///
/// Strong type to prevent mixing up nullifiers with other field elements.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Nullifier(pub Bn254Fr);

impl Nullifier {
	/// Create from field element
	pub fn new(value: Bn254Fr) -> Self {
		Self(value)
	}

	/// Get inner field element
	pub fn inner(&self) -> Bn254Fr {
		self.0
	}
}

impl From<Bn254Fr> for Nullifier {
	fn from(value: Bn254Fr) -> Self {
		Self(value)
	}
}

impl From<Nullifier> for Bn254Fr {
	fn from(nullifier: Nullifier) -> Self {
		nullifier.0
	}
}

/// A spending key (private key for spending notes)
///
/// Strong type with zeroize for security.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpendingKey(pub Bn254Fr);

impl SpendingKey {
	/// Create from field element
	pub fn new(value: Bn254Fr) -> Self {
		Self(value)
	}

	/// Get inner field element
	pub fn inner(&self) -> Bn254Fr {
		self.0
	}
}

impl From<Bn254Fr> for SpendingKey {
	fn from(value: Bn254Fr) -> Self {
		Self(value)
	}
}

// ============================================================================
// Legacy Type Aliases (for backward compatibility)
// ============================================================================

/// A Merkle tree root
pub type MerkleRoot = Bn254Fr;

/// A blinding factor (random value for hiding)
pub type Blinding = Bn254Fr;

/// An owner's public key
pub type OwnerPubkey = Bn254Fr;
