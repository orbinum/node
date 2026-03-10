//! Integration tests for Application Layer Use Cases
//!
//! These tests use mock repositories to test use case logic without FRAME

#[cfg(test)]
mod verify_proof_tests {
	use crate::{
		application::{commands::VerifyProofCommand, use_cases::VerifyProofUseCase},
		domain::{
			entities::{Proof, VerificationKey},
			errors::DomainError,
			services::ProofValidator,
			value_objects::PublicInputs,
			value_objects::{CircuitId, ProofSystem},
		},
		tests::mocks::{MockProofValidator, MockStatisticsRepository, MockVkRepository},
	};
	use alloc::boxed::Box;

	struct VkPrefixValidator {
		expected_first_byte: u8,
	}

	impl ProofValidator for VkPrefixValidator {
		fn verify(
			&self,
			vk: &VerificationKey,
			_proof: &Proof,
			_public_inputs: &PublicInputs,
		) -> Result<bool, DomainError> {
			Ok(vk
				.data()
				.first()
				.copied()
				.map(|value| value == self.expected_first_byte)
				.unwrap_or(false))
		}
	}

	#[test]
	fn verify_proof_works() {
		let vk = VerificationKey::new(vec![1u8; 512], ProofSystem::Groth16).unwrap();
		let vk_repo = MockVkRepository::with_vk(CircuitId::TRANSFER, vk);
		let stats = MockStatisticsRepository::new();
		let validator = Box::new(MockProofValidator::always_valid());

		let use_case = VerifyProofUseCase::new(vk_repo, stats, validator);

		let command = VerifyProofCommand {
			circuit_id: CircuitId::TRANSFER,
			version: None,
			proof: vec![1u8; 256],
			public_inputs: vec![vec![1u8; 32]],
		};

		let result = use_case.execute(command);
		assert_eq!(result, Ok(true));
	}

	#[test]
	fn verify_proof_fails_for_invalid_proof() {
		let vk = VerificationKey::new(vec![1u8; 512], ProofSystem::Groth16).unwrap();
		let vk_repo = MockVkRepository::with_vk(CircuitId::TRANSFER, vk);
		let stats = MockStatisticsRepository::new();
		let validator = Box::new(MockProofValidator::always_invalid());

		let use_case = VerifyProofUseCase::new(vk_repo, stats, validator);

		let command = VerifyProofCommand {
			circuit_id: CircuitId::TRANSFER,
			version: None,
			proof: vec![1u8; 256],
			public_inputs: vec![vec![1u8; 32]],
		};

		let result = use_case.execute(command);
		assert_eq!(result, Ok(false));
	}

	#[test]
	fn verify_proof_uses_active_version_when_not_specified() {
		let vk_repo = MockVkRepository::new();
		vk_repo.insert_vk(
			CircuitId::TRANSFER,
			1,
			VerificationKey::new(vec![1u8; 512], ProofSystem::Groth16).unwrap(),
		);
		vk_repo.insert_vk(
			CircuitId::TRANSFER,
			2,
			VerificationKey::new(vec![2u8; 512], ProofSystem::Groth16).unwrap(),
		);
		vk_repo.set_active_version(CircuitId::TRANSFER, 2);

		let stats = MockStatisticsRepository::new();
		let validator = Box::new(VkPrefixValidator {
			expected_first_byte: 2,
		});

		let use_case = VerifyProofUseCase::new(vk_repo, stats, validator);

		let command = VerifyProofCommand {
			circuit_id: CircuitId::TRANSFER,
			version: None,
			proof: vec![1u8; 256],
			public_inputs: vec![vec![1u8; 32]],
		};

		let result = use_case.execute(command);
		assert_eq!(result, Ok(true));
	}

	#[test]
	fn verify_proof_supports_legacy_version_when_explicitly_requested() {
		let vk_repo = MockVkRepository::new();
		vk_repo.insert_vk(
			CircuitId::TRANSFER,
			1,
			VerificationKey::new(vec![7u8; 512], ProofSystem::Groth16).unwrap(),
		);
		vk_repo.insert_vk(
			CircuitId::TRANSFER,
			2,
			VerificationKey::new(vec![9u8; 512], ProofSystem::Groth16).unwrap(),
		);
		vk_repo.set_active_version(CircuitId::TRANSFER, 2);

		let stats = MockStatisticsRepository::new();
		let validator = Box::new(VkPrefixValidator {
			expected_first_byte: 7,
		});

		let use_case = VerifyProofUseCase::new(vk_repo, stats, validator);

		let command = VerifyProofCommand {
			circuit_id: CircuitId::TRANSFER,
			version: Some(1),
			proof: vec![1u8; 256],
			public_inputs: vec![vec![1u8; 32]],
		};

		let result = use_case.execute(command);
		assert_eq!(result, Ok(true));
	}

	#[test]
	fn verify_proof_fails_for_unknown_version() {
		let vk_repo = MockVkRepository::new();
		vk_repo.insert_vk(
			CircuitId::TRANSFER,
			1,
			VerificationKey::new(vec![7u8; 512], ProofSystem::Groth16).unwrap(),
		);
		vk_repo.set_active_version(CircuitId::TRANSFER, 1);

		let stats = MockStatisticsRepository::new();
		let validator = Box::new(MockProofValidator::always_valid());
		let use_case = VerifyProofUseCase::new(vk_repo, stats, validator);

		let command = VerifyProofCommand {
			circuit_id: CircuitId::TRANSFER,
			version: Some(999),
			proof: vec![1u8; 256],
			public_inputs: vec![vec![1u8; 32]],
		};

		let result = use_case.execute(command);
		assert_eq!(
			result,
			Err(crate::application::errors::ApplicationError::CircuitNotFound)
		);
	}
}
