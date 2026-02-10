//! Helper functions for tests
//!
//! This module provides common test utilities and sample data generators.

use crate::{
	domain::{Commitment, Nullifier, value_objects::Hash},
	infrastructure::frame_types::{EncryptedMemo, MAX_ENCRYPTED_MEMO_SIZE},
};
use frame_support::BoundedVec;

/// Generate a sample commitment for testing
pub fn sample_commitment() -> Commitment {
	Commitment([1u8; 32])
}

/// Generate a second different sample commitment for testing
pub fn sample_commitment_2() -> Commitment {
	Commitment([2u8; 32])
}

/// Generate a sample nullifier for testing
pub fn sample_nullifier() -> Nullifier {
	Nullifier([2u8; 32])
}

/// Generate a sample Merkle root for testing
pub fn sample_merkle_root() -> Hash {
	[0u8; 32]
}

/// Generate a sample encrypted memo with pattern data
pub fn sample_encrypted_memo() -> EncryptedMemo {
	// Create a 256-byte memo filled with test data
	let mut memo_bytes = vec![0u8; MAX_ENCRYPTED_MEMO_SIZE as usize];
	// Fill with some pattern for testing
	for (i, byte) in memo_bytes.iter_mut().enumerate() {
		*byte = (i % 256) as u8;
	}
	EncryptedMemo(BoundedVec::try_from(memo_bytes).expect("Memo size is correct; qed"))
}

/// Generate a sample encrypted memo with a specific seed
pub fn sample_encrypted_memo_with_seed(seed: u8) -> EncryptedMemo {
	// Create a 256-byte memo with a specific seed
	let memo_bytes = vec![seed; MAX_ENCRYPTED_MEMO_SIZE as usize];
	EncryptedMemo(BoundedVec::try_from(memo_bytes).expect("Memo size is correct; qed"))
}
