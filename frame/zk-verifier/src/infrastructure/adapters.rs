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
}

/// Adapter to convert PublicInputs from domain to primitive
pub struct PublicInputsAdapter;

impl PublicInputsAdapter {
	/// Converts domain PublicInputs into primitive `orbinum-zk-verifier` inputs.
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
}

/// Adapter to convert Proof from domain to primitive
pub struct ProofAdapter;

impl ProofAdapter {
	/// Converts domain Proof into primitive `orbinum-zk-verifier` proof.
	pub fn to_primitive(
		domain_proof: &crate::domain::entities::Proof,
	) -> primitives::PrimitiveProof {
		primitives::PrimitiveProof::new(domain_proof.data().to_vec())
	}
}

/// Adapter to convert VerificationKey from domain to primitive
pub struct VerificationKeyAdapter;

impl VerificationKeyAdapter {
	/// Converts domain VerificationKey into primitive `orbinum-zk-verifier` key.
	pub fn to_primitive(
		domain_vk: &crate::domain::entities::VerificationKey,
	) -> primitives::PrimitiveVerifyingKey {
		primitives::PrimitiveVerifyingKey::new(domain_vk.data().to_vec())
	}
}
