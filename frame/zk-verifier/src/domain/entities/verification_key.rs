//! Verification Key entity

use crate::domain::{errors::DomainError, value_objects::ProofSystem};
use alloc::vec::Vec;

/// Verification key for a zero-knowledge circuit
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerificationKey {
	data: Vec<u8>,
	system: ProofSystem,
}

impl VerificationKey {
	/// Maximum size for a verification key (10KB)
	pub const MAX_SIZE: usize = 10_000;

	/// Create a new verification key with validation
	pub fn new(data: Vec<u8>, system: ProofSystem) -> Result<Self, DomainError> {
		// Validate not empty
		if data.is_empty() {
			return Err(DomainError::EmptyVerificationKey);
		}

		// Validate size
		if data.len() > Self::MAX_SIZE {
			return Err(DomainError::VerificationKeyTooLarge);
		}

		// Validate size is within expected range for proof system
		let (min_size, max_size) = system.expected_vk_size_range();
		if data.len() < min_size || data.len() > max_size {
			return Err(DomainError::InvalidVerificationKeySize);
		}

		Ok(Self { data, system })
	}

	/// Get the raw data
	pub fn data(&self) -> &[u8] {
		&self.data
	}

	/// Get the proof system
	pub fn system(&self) -> ProofSystem {
		self.system
	}

	/// Get the size in bytes
	pub fn size(&self) -> usize {
		self.data.len()
	}

	/// Check if this VK is for a supported proof system
	pub fn is_supported(&self) -> bool {
		self.system.is_supported()
	}
}
