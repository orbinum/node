//! Verification Key validator service

use crate::domain::{entities::VerificationKey, errors::DomainError, value_objects::ProofSystem};

/// Trait for validating verification keys
pub trait VkValidator {
	/// Validate a verification key
	fn validate(&self, vk: &VerificationKey) -> Result<(), DomainError>;
}

/// Default validation implementation
pub struct DefaultVkValidator;

impl VkValidator for DefaultVkValidator {
	fn validate(&self, vk: &VerificationKey) -> Result<(), DomainError> {
		// Check supported system
		if !vk.is_supported() {
			return Err(DomainError::UnsupportedProofSystem);
		}

		// Size was already validated in VerificationKey::new()
		// but we double-check here as a domain service
		if vk.size() == 0 {
			return Err(DomainError::EmptyVerificationKey);
		}

		// System-specific validation
		match vk.system() {
			ProofSystem::Groth16 => Self::validate_groth16(vk),
			ProofSystem::Plonk => Err(DomainError::UnsupportedProofSystem),
			ProofSystem::Halo2 => Err(DomainError::UnsupportedProofSystem),
		}
	}
}

impl DefaultVkValidator {
	fn validate_groth16(vk: &VerificationKey) -> Result<(), DomainError> {
		// Groth16 VK should have minimum size
		// Structure: alpha_g1 (64) + beta_g2 (128) + gamma_g2 (128) + delta_g2 (128) + IC points
		const MIN_GROTH16_SIZE: usize = 256;

		if vk.size() < MIN_GROTH16_SIZE {
			return Err(DomainError::InvalidVerificationKeySize);
		}

		// Additional format validation could be added here
		// For now, basic size check is sufficient

		Ok(())
	}
}
