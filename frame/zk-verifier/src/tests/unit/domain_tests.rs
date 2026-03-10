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

	#[test]
	fn verification_key_size_and_support_flags() {
		let vk = VerificationKey::new(vec![1u8; 512], ProofSystem::Groth16).unwrap();
		assert_eq!(vk.size(), 512);
		assert!(vk.is_supported());

		let plonk_vk = VerificationKey::new(vec![1u8; 1024], ProofSystem::Plonk).unwrap();
		assert!(!plonk_vk.is_supported());
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

	#[test]
	fn proof_exposes_size() {
		let proof = Proof::new(vec![9u8; 128]).unwrap();
		assert_eq!(proof.size(), 128);
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

	#[test]
	fn public_inputs_empty_helpers_work() {
		let empty = PublicInputs::empty();
		assert!(empty.is_empty());
		assert_eq!(empty.count(), 0);
	}
}

#[cfg(test)]
mod circuit_id_tests {
	use crate::domain::value_objects::CircuitId;

	#[test]
	fn circuit_id_constants() {
		assert_eq!(CircuitId::TRANSFER.value(), 1);
		assert_eq!(CircuitId::UNSHIELD.value(), 2);
		assert_eq!(CircuitId::SHIELD.value(), 3);
		assert_eq!(CircuitId::DISCLOSURE.value(), 4);
		assert_eq!(CircuitId::PRIVATE_LINK.value(), 5);
	}

	#[test]
	fn circuit_id_creation() {
		let id = CircuitId::new(42);
		assert_eq!(id.value(), 42);
	}

	#[test]
	fn circuit_id_names_and_display() {
		assert_eq!(CircuitId::TRANSFER.name(), Some("Transfer"));
		assert_eq!(CircuitId::new(999).name(), None);
		assert_eq!(CircuitId::TRANSFER.to_string(), "Transfer(1)");
		assert_eq!(CircuitId::new(999).to_string(), "Circuit(999)");
	}

	#[test]
	fn circuit_id_conversions_work() {
		let from_u32 = CircuitId::from(12u32);
		assert_eq!(from_u32.value(), 12);

		let as_u32: u32 = CircuitId::UNSHIELD.into();
		assert_eq!(as_u32, 2);
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

	#[test]
	fn proof_system_metadata_is_consistent() {
		assert_eq!(ProofSystem::Groth16.as_str(), "Groth16");
		assert_eq!(ProofSystem::Plonk.as_str(), "Plonk");
		assert_eq!(ProofSystem::Halo2.as_str(), "Halo2");

		assert!(ProofSystem::Groth16.is_supported());
		assert!(!ProofSystem::Plonk.is_supported());
		assert!(!ProofSystem::Halo2.is_supported());

		assert_eq!(ProofSystem::Groth16.expected_vk_size_range(), (256, 10_000));
		assert_eq!(ProofSystem::Plonk.expected_vk_size_range(), (1024, 20_000));
		assert_eq!(ProofSystem::Halo2.expected_proof_size(), 512);

		assert_eq!(ProofSystem::Groth16.to_string(), "Groth16");
	}
}

#[cfg(test)]
mod circuit_entity_tests {
	use crate::domain::{entities::Circuit, value_objects::CircuitId};

	#[test]
	fn known_circuit_has_name() {
		let circuit = Circuit::new(CircuitId::TRANSFER);
		assert_eq!(circuit.id(), CircuitId::TRANSFER);
		assert_eq!(circuit.name(), Some("Transfer"));
		assert!(circuit.is_known());
	}

	#[test]
	fn unknown_circuit_has_no_name() {
		let circuit = Circuit::new(CircuitId::new(999));
		assert_eq!(circuit.name(), None);
		assert!(!circuit.is_known());
	}
}
