//! Integration tests for Application Layer Use Cases
//!
//! These tests use mock repositories to test use case logic without FRAME

#[cfg(test)]
mod register_vk_tests {
	use crate::{
		application::{
			commands::RegisterVkCommand, errors::ApplicationError,
			use_cases::RegisterVerificationKeyUseCase,
		},
		domain::{
			entities::VerificationKey,
			services::DefaultVkValidator,
			value_objects::{CircuitId, ProofSystem},
		},
		tests::mocks::MockVkRepository,
	};
	use alloc::boxed::Box;

	#[test]
	fn register_vk_works() {
		let repo = MockVkRepository::new();
		let validator = Box::new(DefaultVkValidator);
		let use_case = RegisterVerificationKeyUseCase::new(repo, validator);

		let data = vec![1u8; 512];
		let command = RegisterVkCommand {
			circuit_id: CircuitId::TRANSFER,
			version: 1,
			data,
			system: ProofSystem::Groth16,
		};

		let result = use_case.execute(command);
		assert!(result.is_ok());
	}

	#[test]
	fn register_vk_rejects_empty_data() {
		let repo = MockVkRepository::new();
		let validator = Box::new(DefaultVkValidator);
		let use_case = RegisterVerificationKeyUseCase::new(repo, validator);

		let command = RegisterVkCommand {
			circuit_id: CircuitId::TRANSFER,
			version: 1,
			data: vec![],
			system: ProofSystem::Groth16,
		};

		let result = use_case.execute(command);
		assert!(matches!(result, Err(ApplicationError::Domain(_))));
	}

	#[test]
	fn register_vk_rejects_too_large() {
		let repo = MockVkRepository::new();
		let validator = Box::new(DefaultVkValidator);
		let use_case = RegisterVerificationKeyUseCase::new(repo, validator);

		let command = RegisterVkCommand {
			circuit_id: CircuitId::TRANSFER,
			version: 1,
			data: vec![1u8; 100_001],
			system: ProofSystem::Groth16,
		};

		let result = use_case.execute(command);
		assert!(matches!(result, Err(ApplicationError::Domain(_))));
	}

	#[test]
	fn register_vk_rejects_duplicate() {
		let vk = VerificationKey::new(vec![1u8; 512], ProofSystem::Groth16).unwrap();
		let repo = MockVkRepository::with_vk(CircuitId::TRANSFER, vk);
		let validator = Box::new(DefaultVkValidator);
		let use_case = RegisterVerificationKeyUseCase::new(repo, validator);

		let command = RegisterVkCommand {
			circuit_id: CircuitId::TRANSFER,
			version: 1,
			data: vec![2u8; 512],
			system: ProofSystem::Groth16,
		};

		let result = use_case.execute(command);
		assert!(matches!(
			result,
			Err(ApplicationError::CircuitAlreadyExists)
		));
	}
}

#[cfg(test)]
mod remove_vk_tests {
	use crate::{
		application::{
			commands::RemoveVkCommand, errors::ApplicationError,
			use_cases::RemoveVerificationKeyUseCase,
		},
		domain::{
			entities::VerificationKey,
			value_objects::{CircuitId, ProofSystem},
		},
		tests::mocks::MockVkRepository,
	};

	#[test]
	fn remove_vk_works() {
		let vk = VerificationKey::new(vec![1u8; 512], ProofSystem::Groth16).unwrap();
		let repo = MockVkRepository::with_vk(CircuitId::TRANSFER, vk);
		let use_case = RemoveVerificationKeyUseCase::new(repo);

		let command = RemoveVkCommand {
			circuit_id: CircuitId::TRANSFER,
			version: Some(1),
		};

		let result = use_case.execute(command);
		assert!(result.is_ok());
	}

	#[test]
	fn remove_vk_rejects_nonexistent() {
		let repo = MockVkRepository::new();
		let use_case = RemoveVerificationKeyUseCase::new(repo);

		let command = RemoveVkCommand {
			circuit_id: CircuitId::TRANSFER,
			version: Some(1),
		};

		let result = use_case.execute(command);
		assert_eq!(result, Err(ApplicationError::CircuitNotFound));
	}
}

#[cfg(test)]
mod verify_proof_tests {
	use crate::{
		application::{commands::VerifyProofCommand, use_cases::VerifyProofUseCase},
		domain::{
			entities::VerificationKey,
			value_objects::{CircuitId, ProofSystem},
		},
		tests::mocks::{MockProofValidator, MockStatisticsRepository, MockVkRepository},
	};
	use alloc::boxed::Box;

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
}
