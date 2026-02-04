//! Adapters - Hexagonal Architecture Port Adapters
//!
//! Los adapters convierten entre:
//! - Tipos de dominio (puros, independientes)
//! - Tipos de primitivos (orbinum-zk-verifier, orbinum-zk-core)
//!
//! Esto mantiene el dominio libre de dependencias externas.

use alloc::vec::Vec;

/// Re-exports de primitivos SOLO para uso en infrastructure layer
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

/// Adapter para acceder a Disclosure VK
pub struct DisclosureVkAdapter;

impl DisclosureVkAdapter {
	/// Obtiene la verification key de disclosure hardcodeada
	pub fn get_disclosure_vk() -> primitives::PrimitiveVerifyingKey {
		let ark_vk = primitives::verification_keys::get_disclosure_vk();
		primitives::PrimitiveVerifyingKey::from_ark_vk(&ark_vk)
			.expect("Failed to wrap hardcoded disclosure VK")
	}
}

/// Adapter para convertir PublicInputs del dominio a primitivo
pub struct PublicInputsAdapter;

impl PublicInputsAdapter {
	/// Convierte PublicInputs de dominio a primitivo fp-zk-verifier
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

	/// Convierte PublicInputs de primitivo a dominio
	pub fn from_primitive(
		primitive: &primitives::PrimitivePublicInputs,
	) -> Result<crate::domain::value_objects::PublicInputs, crate::domain::errors::DomainError> {
		let inputs: Vec<Vec<u8>> = primitive.inputs.iter().map(|arr| arr.to_vec()).collect();

		crate::domain::value_objects::PublicInputs::new(inputs)
	}
}

/// Adapter para convertir Proof del dominio a primitivo
pub struct ProofAdapter;

impl ProofAdapter {
	/// Convierte Proof de dominio a primitivo fp-zk-verifier
	pub fn to_primitive(
		domain_proof: &crate::domain::entities::Proof,
	) -> primitives::PrimitiveProof {
		primitives::PrimitiveProof::new(domain_proof.data().to_vec())
	}
}

/// Adapter para convertir VerificationKey del dominio a primitivo
pub struct VerificationKeyAdapter;

impl VerificationKeyAdapter {
	/// Convierte VerificationKey de dominio a primitivo fp-zk-verifier
	pub fn to_primitive(
		domain_vk: &crate::domain::entities::VerificationKey,
	) -> primitives::PrimitiveVerifyingKey {
		primitives::PrimitiveVerifyingKey::new(domain_vk.data().to_vec())
	}
}
