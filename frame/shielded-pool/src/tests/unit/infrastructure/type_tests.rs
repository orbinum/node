//! Type tests
//!
//! Tests for core types and data structures.

use crate::{Commitment, Nullifier};

// ============================================================================

#[test]
fn commitment_from_bytes() {
	let bytes = [42u8; 32];
	let commitment: Commitment = bytes.into();
	assert_eq!(commitment.0, bytes);
}

#[test]
fn nullifier_from_bytes() {
	let bytes = [99u8; 32];
	let nullifier: Nullifier = bytes.into();
	assert_eq!(nullifier.0, bytes);
}

// ============================================================================
