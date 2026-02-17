//! Unit tests for Domain Layer - Pure business logic tests
//!
//! These tests have NO dependencies on FRAME. They test pure domain logic.

#[cfg(test)]
mod verification_key_tests {
	use crate::domain::{
		entities::VerificationKey, errors::DomainError, value_objects::ProofSystem,
	};

	#[test]
	fn verification_key_creation_works() {
		let data = vec![1u8; 512];
		let vk = VerificationKey::new(data.clone(), ProofSystem::Groth16);

		assert!(vk.is_ok());
		let vk = vk.unwrap();
		assert_eq!(vk.data(), &data);
		assert_eq!(vk.system(), ProofSystem::Groth16);
	}

	#[test]
	fn verification_key_rejects_empty_data() {
		let result = VerificationKey::new(vec![], ProofSystem::Groth16);

		assert_eq!(result, Err(DomainError::EmptyVerificationKey));
	}

	#[test]
	fn verification_key_rejects_too_large() {
		let data = vec![1u8; 100_001]; // Max is 100KB
		let result = VerificationKey::new(data, ProofSystem::Groth16);

		assert_eq!(result, Err(DomainError::VerificationKeyTooLarge));
	}

	#[test]
	fn verification_key_validates_min_size() {
		let data = vec![1u8; 255]; // Min is 256 bytes for Groth16
		let result = VerificationKey::new(data, ProofSystem::Groth16);

		assert_eq!(result, Err(DomainError::InvalidVerificationKeySize));
	}
}

#[cfg(test)]
mod proof_tests {
	use crate::domain::{entities::Proof, errors::DomainError};

	#[test]
	fn proof_creation_works() {
		let data = vec![1u8; 256]; // Groth16 proof is 256 bytes
		let proof = Proof::new(data.clone());

		assert!(proof.is_ok());
		let proof = proof.unwrap();
		assert_eq!(proof.data(), &data);
	}

	#[test]
	fn proof_rejects_empty_data() {
		let result = Proof::new(vec![]);
		assert_eq!(result, Err(DomainError::EmptyProof));
	}

	#[test]
	fn proof_rejects_too_large() {
		let data = vec![1u8; 1025]; // Max is 1KB
		let result = Proof::new(data);
		assert_eq!(result, Err(DomainError::ProofTooLarge));
	}
}

#[cfg(test)]
mod public_inputs_tests {
	use crate::domain::{errors::DomainError, value_objects::PublicInputs};

	#[test]
	fn public_inputs_creation_works() {
		let inputs = vec![vec![1u8; 32], vec![2u8; 32]];
		let pi = PublicInputs::new(inputs.clone());

		assert!(pi.is_ok());
		let pi = pi.unwrap();
		assert_eq!(pi.inputs().len(), 2);
	}

	#[test]
	fn public_inputs_rejects_empty() {
		let result = PublicInputs::new(vec![]);
		assert_eq!(result, Err(DomainError::EmptyPublicInputs));
	}

	#[test]
	fn public_inputs_rejects_too_many() {
		let inputs = vec![vec![1u8; 32]; 17]; // Max is 16
		let result = PublicInputs::new(inputs);
		assert_eq!(result, Err(DomainError::TooManyPublicInputs));
	}

	#[test]
	fn public_inputs_rejects_invalid_size() {
		let inputs = vec![vec![1u8; 31]]; // Must be 32 bytes
		let result = PublicInputs::new(inputs);
		assert_eq!(result, Err(DomainError::InvalidPublicInputFormat));
	}
}

#[cfg(test)]
mod circuit_id_tests {
	use crate::domain::value_objects::CircuitId;

	#[test]
	fn circuit_id_constants() {
		assert_eq!(CircuitId::TRANSFER.value(), 1);
		assert_eq!(CircuitId::UNSHIELD.value(), 2);
	}

	#[test]
	fn circuit_id_creation() {
		let id = CircuitId::new(42);
		assert_eq!(id.value(), 42);
	}
}

#[cfg(test)]
mod proof_system_tests {
	use crate::domain::value_objects::ProofSystem;

	#[test]
	fn proof_system_variants() {
		let _g16 = ProofSystem::Groth16;
		let _plonk = ProofSystem::Plonk;
		let _halo2 = ProofSystem::Halo2;
	}
}
