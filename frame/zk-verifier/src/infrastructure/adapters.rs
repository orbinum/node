//! Adapters - Hexagonal Architecture Port Adapters
//!
//! Adapters convert between:
//! - Domain types (pure, independent)
//! - Primitive types (orbinum-zk-verifier, orbinum-zk-core)
//!
//! This keeps the domain free of external dependencies.

use alloc::vec::Vec;

/// Re-exports of primitives ONLY for use in infrastructure layer
pub mod primitives {
	// orbinum-zk-verifier types
	pub use orbinum_zk_verifier::{
		domain::value_objects::{
			Proof as PrimitiveProof, PublicInputs as PrimitivePublicInputs,
			VerifyingKey as PrimitiveVerifyingKey,
		},
		infrastructure::Groth16Verifier as PrimitiveGroth16Verifier,
	};

	// Verification keys
	pub use orbinum_zk_verifier::infrastructure::storage::verification_keys;

	// orbinum-zk-core types
	pub use orbinum_zk_core::{
		domain::{
			entities::Note,
			services::{CommitmentService, NullifierService},
			value_objects::{
				Blinding, Commitment, FieldElement, Nullifier, OwnerPubkey, SpendingKey,
			},
		},
		infrastructure::crypto::LightPoseidonHasher,
	};
}

/// Adapter to access Disclosure VK
pub struct DisclosureVkAdapter;

impl DisclosureVkAdapter {
	/// Retrieves the hardcoded disclosure verification key
	pub fn get_disclosure_vk() -> primitives::PrimitiveVerifyingKey {
		let ark_vk = primitives::verification_keys::get_disclosure_vk();
		primitives::PrimitiveVerifyingKey::from_ark_vk(&ark_vk)
			.expect("Failed to wrap hardcoded disclosure VK")
	}
}

/// Adapter to access Unshield VK
pub struct UnshieldVkAdapter;

impl UnshieldVkAdapter {
	/// Retrieves the hardcoded unshield verification key
	pub fn get_unshield_vk() -> primitives::PrimitiveVerifyingKey {
		let ark_vk = primitives::verification_keys::get_unshield_vk();
		primitives::PrimitiveVerifyingKey::from_ark_vk(&ark_vk)
			.expect("Failed to wrap hardcoded unshield VK")
	}
}

/// Adapter to access Transfer VK
pub struct TransferVkAdapter;

impl TransferVkAdapter {
	/// Retrieves the hardcoded transfer verification key
	pub fn get_transfer_vk() -> primitives::PrimitiveVerifyingKey {
		let ark_vk = primitives::verification_keys::get_transfer_vk();
		primitives::PrimitiveVerifyingKey::from_ark_vk(&ark_vk)
			.expect("Failed to wrap hardcoded transfer VK")
	}
}

/// Adapter to convert PublicInputs from domain to primitive
pub struct PublicInputsAdapter;

impl PublicInputsAdapter {
	/// Converts PublicInputs from domain to primitive fp-zk-verifier
	pub fn to_primitive(
		domain_inputs: &crate::domain::value_objects::PublicInputs,
	) -> primitives::PrimitivePublicInputs {
		let inputs: Vec<[u8; 32]> = domain_inputs
			.inputs()
			.iter()
			.map(|input| {
				let mut arr = [0u8; 32];
				let len = input.len().min(32);
				arr[..len].copy_from_slice(&input[..len]);
				arr
			})
			.collect();

		primitives::PrimitivePublicInputs::new(inputs)
	}

	/// Converts PublicInputs from primitive to domain
	pub fn from_primitive(
		primitive: &primitives::PrimitivePublicInputs,
	) -> Result<crate::domain::value_objects::PublicInputs, crate::domain::errors::DomainError> {
		let inputs: Vec<Vec<u8>> = primitive.inputs.iter().map(|arr| arr.to_vec()).collect();

		crate::domain::value_objects::PublicInputs::new(inputs)
	}
}

/// Adapter to convert Proof from domain to primitive
pub struct ProofAdapter;

impl ProofAdapter {
	/// Converts Proof from domain to primitive fp-zk-verifier
	pub fn to_primitive(
		domain_proof: &crate::domain::entities::Proof,
	) -> primitives::PrimitiveProof {
		primitives::PrimitiveProof::new(domain_proof.data().to_vec())
	}
}

/// Adapter to convert VerificationKey from domain to primitive
pub struct VerificationKeyAdapter;

impl VerificationKeyAdapter {
	/// Converts VerificationKey from domain to primitive fp-zk-verifier
	pub fn to_primitive(
		domain_vk: &crate::domain::entities::VerificationKey,
	) -> primitives::PrimitiveVerifyingKey {
		primitives::PrimitiveVerifyingKey::new(domain_vk.data().to_vec())
	}
}
