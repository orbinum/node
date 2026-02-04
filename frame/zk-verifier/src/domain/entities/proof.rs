//! Proof entity

use crate::domain::errors::DomainError;
use alloc::vec::Vec;

/// Zero-knowledge proof
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proof {
	data: Vec<u8>,
}

impl Proof {
	/// Maximum proof size (1KB)
	pub const MAX_SIZE: usize = 1024;

	/// Create a new proof with validation
	pub fn new(data: Vec<u8>) -> Result<Self, DomainError> {
		if data.is_empty() {
			return Err(DomainError::EmptyProof);
		}

		if data.len() > Self::MAX_SIZE {
			return Err(DomainError::ProofTooLarge);
		}

		Ok(Self { data })
	}

	/// Get the raw proof data
	pub fn data(&self) -> &[u8] {
		&self.data
	}

	/// Get the size in bytes
	pub fn size(&self) -> usize {
		self.data.len()
	}
}
