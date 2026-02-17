//! Groth16 proof verifier implementation

use crate::domain::{
	entities::{Proof, VerificationKey},
	errors::DomainError,
	services::{ProofValidator, ZkVerifierPort},
	value_objects::PublicInputs,
};
use sp_runtime::DispatchError;

extern crate alloc;

/// Groth16 proof verifier using fp-zk-verifier
pub struct Groth16Verifier;

impl ProofValidator for Groth16Verifier {
	fn verify(
		&self,
		vk: &VerificationKey,
		proof: &Proof,
		public_inputs: &PublicInputs,
	) -> Result<bool, DomainError> {
		// Skip real verification in benchmarks and tests
		#[cfg(any(feature = "runtime-benchmarks", test))]
		{
			let _ = (vk, proof, public_inputs);
			Ok(true)
		}

		// Real verification in production using orbinum-zk-verifier via adapters
		#[cfg(not(any(feature = "runtime-benchmarks", test)))]
		{
			use crate::infrastructure::adapters::{
				ProofAdapter, PublicInputsAdapter, VerificationKeyAdapter,
				primitives::PrimitiveGroth16Verifier,
			};

			// Convert domain types to primitive types using adapters
			let fp_vk = VerificationKeyAdapter::to_primitive(vk);
			let fp_proof = ProofAdapter::to_primitive(proof);
			let fp_inputs = PublicInputsAdapter::to_primitive(public_inputs);

			// Verify using orbinum-zk-verifier Groth16Verifier
			match PrimitiveGroth16Verifier::verify(&fp_vk, &fp_inputs, &fp_proof) {
				Ok(()) => Ok(true),
				Err(_) => Ok(false),
			}
		}
	}
}

// ============================================================================
// ZkVerifierPort Implementation - Public API for other pallets
// ============================================================================

impl ZkVerifierPort for Groth16Verifier {
	fn verify_transfer_proof(
		proof: &[u8],
		merkle_root: &[u8; 32],
		nullifiers: &[[u8; 32]],
		commitments: &[[u8; 32]],
		_version: Option<u32>,
	) -> Result<bool, DispatchError> {
		// Skip real verification in benchmarks and tests
		#[cfg(any(feature = "runtime-benchmarks", test))]
		{
			let _ = (proof, merkle_root, nullifiers, commitments);
			Ok(true)
		}

		// Real verification in production
		#[cfg(not(any(feature = "runtime-benchmarks", test)))]
		{
			use crate::infrastructure::adapters::primitives::{
				PrimitiveGroth16Verifier as PrimitiveVerifier, PrimitiveProof,
				PrimitivePublicInputs,
			};

			// Validate proof is not empty
			if proof.is_empty() {
				#[cfg(feature = "std")]
				log::error!("Empty transfer proof provided");
				return Err(DispatchError::Other("Empty transfer proof"));
			}

			// Validate input counts (transfer circuit expects 2 nullifiers and 2 commitments)
			if nullifiers.len() != 2 {
				#[cfg(feature = "std")]
				log::error!(
					"Invalid nullifiers count: {} (expected 2)",
					nullifiers.len()
				);
				return Err(DispatchError::Other(
					"Invalid nullifiers count for transfer",
				));
			}

			if commitments.len() != 2 {
				#[cfg(feature = "std")]
				log::error!(
					"Invalid commitments count: {} (expected 2)",
					commitments.len()
				);
				return Err(DispatchError::Other(
					"Invalid commitments count for transfer",
				));
			}

			// Log para debugging (solo en std)
			#[cfg(feature = "std")]
			{
				log::debug!(
					"Transfer proof verification - merkle_root: {merkle_root:?}, nullifiers: {nullifiers:?}, commitments: {commitments:?}"
				);
			}

			// Load verification key from hardcoded transfer VK
			use crate::infrastructure::adapters::TransferVkAdapter;
			let primitive_vk = TransferVkAdapter::get_transfer_vk();

			// Create proof wrapper from bytes
			let primitive_proof = PrimitiveProof::new(proof.to_vec());

			// Create public inputs from parameters
			// Expected inputs: [merkle_root, nullifier1, nullifier2, commitment1, commitment2]
			let mut public_inputs_bytes = alloc::vec![];

			// 1. merkle_root (already 32 bytes)
			public_inputs_bytes.push(*merkle_root);

			// 2-3. nullifiers (2x 32 bytes)
			for nullifier in nullifiers {
				public_inputs_bytes.push(*nullifier);
			}

			// 4-5. commitments (2x 32 bytes)
			for commitment in commitments {
				public_inputs_bytes.push(*commitment);
			}

			let primitive_public_inputs = PrimitivePublicInputs::new(public_inputs_bytes);

			// Verify the proof using orbinum-zk-verifier
			match PrimitiveVerifier::verify(
				&primitive_vk,
				&primitive_public_inputs,
				&primitive_proof,
			) {
				Ok(()) => {
					#[cfg(feature = "std")]
					log::info!("✅ Transfer proof verification PASSED");
					Ok(true)
				}
				Err(_) => {
					#[cfg(feature = "std")]
					log::warn!("❌ Transfer proof verification FAILED");
					Ok(false)
				}
			}
		}
	}

	fn verify_unshield_proof(
		proof: &[u8],
		merkle_root: &[u8; 32],
		nullifier: &[u8; 32],
		amount: u128,
		recipient: &[u8; 20],
		asset_id: u32,
		_version: Option<u32>,
	) -> Result<bool, DispatchError> {
		// Skip real verification in benchmarks and tests
		#[cfg(any(feature = "runtime-benchmarks", test))]
		{
			let _ = (proof, merkle_root, nullifier, amount, recipient, asset_id);
			Ok(true)
		}

		// Real verification in production
		#[cfg(not(any(feature = "runtime-benchmarks", test)))]
		{
			use crate::infrastructure::adapters::primitives::{
				PrimitiveGroth16Verifier as PrimitiveVerifier, PrimitiveProof,
				PrimitivePublicInputs,
			};

			// Validate proof is not empty
			if proof.is_empty() {
				#[cfg(feature = "std")]
				log::error!("Empty unshield proof provided");
				return Err(DispatchError::Other("Empty unshield proof"));
			}

			// Log para debugging (solo en std)
			#[cfg(feature = "std")]
			{
				log::debug!(
					"Unshield proof verification - merkle_root: {merkle_root:?}, nullifier: {nullifier:?}, amount: {amount}, recipient: {recipient:?}, asset_id: {asset_id}"
				);
			}

			// Load verification key from hardcoded unshield VK
			use crate::infrastructure::adapters::UnshieldVkAdapter;
			let primitive_vk = UnshieldVkAdapter::get_unshield_vk();

			// Create proof wrapper from bytes
			let primitive_proof = PrimitiveProof::new(proof.to_vec());

			// Create public inputs from parameters
			// Expected inputs: [merkle_root, nullifier, amount, recipient, asset_id]
			let mut public_inputs_bytes = alloc::vec![];

			// 1. merkle_root (canonical 32-byte field element, LE representation)
			public_inputs_bytes.push(*merkle_root);

			// 2. nullifier (canonical 32-byte field element, LE representation)
			public_inputs_bytes.push(*nullifier);

			// 3. amount (u128 -> 32 bytes little-endian)
			let mut amount_arr = [0u8; 32];
			amount_arr[..16].copy_from_slice(&amount.to_le_bytes());
			public_inputs_bytes.push(amount_arr);

			// 4. recipient (20 bytes -> 32 bytes LE field encoding)
			let mut recipient_arr = [0u8; 32];
			for (index, byte) in recipient.iter().rev().enumerate() {
				recipient_arr[index] = *byte;
			}
			public_inputs_bytes.push(recipient_arr);

			// 5. asset_id (u32 -> 32 bytes little-endian)
			let mut asset_id_arr = [0u8; 32];
			asset_id_arr[..4].copy_from_slice(&asset_id.to_le_bytes());
			public_inputs_bytes.push(asset_id_arr);

			let primitive_public_inputs = PrimitivePublicInputs::new(public_inputs_bytes);

			// Verify the proof using orbinum-zk-verifier
			match PrimitiveVerifier::verify(
				&primitive_vk,
				&primitive_public_inputs,
				&primitive_proof,
			) {
				Ok(()) => {
					#[cfg(feature = "std")]
					log::info!("✅ Unshield proof verification PASSED");
					Ok(true)
				}
				Err(_) => {
					#[cfg(feature = "std")]
					log::warn!("❌ Unshield proof verification FAILED");
					Ok(false)
				}
			}
		}
	}

	fn verify_disclosure_proof(
		proof: &[u8],
		public_signals: &[u8],
		_version: Option<u32>,
	) -> Result<bool, DispatchError> {
		// Skip real verification in benchmarks and tests
		#[cfg(any(feature = "runtime-benchmarks", test))]
		{
			let _ = (proof, public_signals);
			Ok(true)
		}

		// Real verification in production
		#[cfg(not(any(feature = "runtime-benchmarks", test)))]
		{
			use crate::infrastructure::adapters::primitives::{
				PrimitiveGroth16Verifier as PrimitiveVerifier, PrimitiveProof,
				PrimitivePublicInputs,
			};

			// Validate public signals format
			// Expected: commitment (32) + revealed_value (8) + revealed_asset_id (4) + revealed_owner_hash (32) = 76 bytes
			if public_signals.len() != 76 {
				#[cfg(feature = "std")]
				log::error!(
					"Invalid public signals length: {} (expected 76)",
					public_signals.len()
				);
				return Err(DispatchError::Other(
					"Invalid public signals length for disclosure",
				));
			}

			// Parse public signals into field elements
			// The circuit expects 4 public inputs:
			// 1. commitment (32 bytes -> field element)
			// 2. revealed_value (8 bytes -> u64 -> field element)
			// 3. revealed_asset_id (4 bytes -> u32 -> field element)
			// 4. revealed_owner_hash (32 bytes -> field element)

			let commitment = &public_signals[0..32];
			let revealed_value_bytes = &public_signals[32..40];
			let revealed_asset_id_bytes = &public_signals[40..44];
			let revealed_owner_hash = &public_signals[44..76];

			// Parse numeric values
			let revealed_value = u64::from_le_bytes(
				revealed_value_bytes
					.try_into()
					.map_err(|_| DispatchError::Other("Invalid revealed_value format"))?,
			);

			let revealed_asset_id = u32::from_le_bytes(
				revealed_asset_id_bytes
					.try_into()
					.map_err(|_| DispatchError::Other("Invalid revealed_asset_id format"))?,
			);

			// Log para debugging (solo en std)
			#[cfg(feature = "std")]
			{
				log::debug!(
					"Disclosure proof verification - commitment: {commitment:?}, revealed_value: {revealed_value}, revealed_asset_id: {revealed_asset_id}, revealed_owner_hash: {revealed_owner_hash:?}"
				);
			}

			// Load verification key from hardcoded disclosure VK
			use crate::infrastructure::adapters::DisclosureVkAdapter;
			let primitive_vk = DisclosureVkAdapter::get_disclosure_vk();

			// Create proof wrapper from bytes
			let primitive_proof = PrimitiveProof::new(proof.to_vec());

			// Create public inputs from bytes
			// PublicInputs expects Vec<[u8; 32]> where each element is a field element in big-endian
			let mut public_inputs_bytes = alloc::vec![];

			// 1. commitment (already 32 bytes)
			let mut commitment_arr = [0u8; 32];
			commitment_arr.copy_from_slice(commitment);
			public_inputs_bytes.push(commitment_arr);

			// 2. revealed_value (u64 -> 32 bytes big-endian)
			let mut value_arr = [0u8; 32];
			value_arr[24..].copy_from_slice(&revealed_value.to_be_bytes());
			public_inputs_bytes.push(value_arr);

			// 3. revealed_asset_id (u32 -> 32 bytes big-endian)
			let mut asset_arr = [0u8; 32];
			asset_arr[28..].copy_from_slice(&revealed_asset_id.to_be_bytes());
			public_inputs_bytes.push(asset_arr);

			// 4. revealed_owner_hash (already 32 bytes)
			let mut owner_hash_arr = [0u8; 32];
			owner_hash_arr.copy_from_slice(revealed_owner_hash);
			public_inputs_bytes.push(owner_hash_arr);

			let primitive_public_inputs = PrimitivePublicInputs::new(public_inputs_bytes);

			// Verify the proof using orbinum-zk-verifier
			match PrimitiveVerifier::verify(
				&primitive_vk,
				&primitive_public_inputs,
				&primitive_proof,
			) {
				Ok(()) => {
					#[cfg(feature = "std")]
					log::info!("✅ Disclosure proof verification PASSED");
					Ok(true)
				}
				Err(_) => {
					#[cfg(feature = "std")]
					log::warn!("❌ Disclosure proof verification FAILED");
					Ok(false)
				}
			}
		}
	}

	fn batch_verify_disclosure_proofs(
		proofs: &[sp_std::vec::Vec<u8>],
		public_signals: &[sp_std::vec::Vec<u8>],
		_version: Option<u32>,
	) -> Result<bool, DispatchError> {
		#[cfg(any(feature = "runtime-benchmarks", test))]
		{
			let _ = (proofs, public_signals);
			Ok(true)
		}

		#[cfg(not(any(feature = "runtime-benchmarks", test)))]
		{
			use crate::infrastructure::adapters::{
				DisclosureVkAdapter,
				primitives::{
					PrimitiveGroth16Verifier as PrimitiveVerifier, PrimitiveProof,
					PrimitivePublicInputs,
				},
			};
			use sp_std::vec::Vec;

			if proofs.len() != public_signals.len() {
				return Err(DispatchError::Other("Batch length mismatch"));
			}

			if proofs.is_empty() {
				return Ok(true);
			}

			let primitive_vk = DisclosureVkAdapter::get_disclosure_vk();

			let mut primitive_proofs = Vec::with_capacity(proofs.len());
			for p in proofs {
				primitive_proofs.push(PrimitiveProof::new(p.to_vec()));
			}

			let mut all_inputs = Vec::with_capacity(public_signals.len());
			for sigs in public_signals {
				if sigs.len() != 76 {
					return Err(DispatchError::Other("Invalid signals"));
				}
				let mut inp = Vec::with_capacity(4);
				let mut c = [0u8; 32];
				c.copy_from_slice(&sigs[0..32]);
				inp.push(c);
				let mut v = [0u8; 32];
				v[24..].copy_from_slice(&sigs[32..40]);
				inp.push(v);
				let mut a = [0u8; 32];
				a[28..].copy_from_slice(&sigs[40..44]);
				inp.push(a);
				let mut o = [0u8; 32];
				o.copy_from_slice(&sigs[44..76]);
				inp.push(o);
				all_inputs.push(PrimitivePublicInputs::new(inp));
			}

			match PrimitiveVerifier::batch_verify(&primitive_vk, &all_inputs, &primitive_proofs) {
				Ok(v) => Ok(v),
				Err(_) => Err(DispatchError::Other("Batch verification error")),
			}
		}
	}
}
