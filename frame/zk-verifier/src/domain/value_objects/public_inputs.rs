//! Public inputs value object

use crate::domain::errors::DomainError;
use alloc::vec::Vec;

/// Public inputs for a zero-knowledge proof
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicInputs {
	inputs: Vec<Vec<u8>>,
}

impl PublicInputs {
	/// Maximum number of public inputs allowed
	pub const MAX_INPUTS: usize = 16;

	/// Create new public inputs with validation
	pub fn new(inputs: Vec<Vec<u8>>) -> Result<Self, DomainError> {
		if inputs.is_empty() {
			return Err(DomainError::EmptyPublicInputs);
		}

		if inputs.len() > Self::MAX_INPUTS {
			return Err(DomainError::TooManyPublicInputs);
		}

		// Validate each input is exactly 32 bytes
		for input in &inputs {
			if input.len() != 32 {
				return Err(DomainError::InvalidPublicInputFormat);
			}
		}

		Ok(Self { inputs })
	}

	/// Create empty public inputs (for circuits with no public inputs)
	pub fn empty() -> Self {
		Self { inputs: Vec::new() }
	}

	/// Get the inputs slice
	pub fn inputs(&self) -> &[Vec<u8>] {
		&self.inputs
	}

	/// Get number of inputs
	pub fn count(&self) -> usize {
		self.inputs.len()
	}

	/// Check if empty
	pub fn is_empty(&self) -> bool {
		self.inputs.is_empty()
	}
}
