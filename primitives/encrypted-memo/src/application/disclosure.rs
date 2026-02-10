//! Disclosure Proof Generation Use Case
//!
//! Generates ZK proofs for selective disclosure of encrypted memos.
//! Security: Commitment binding, selective hiding, viewing key verification, non-malleability.

use crate::domain::{
	aggregates::disclosure::{DisclosureMask, DisclosureProof, DisclosurePublicSignals},
	entities::{error::MemoError, types::MemoData},
};
use alloc::vec::Vec;

// ZK primitives
use ark_bn254::Fr as Bn254Fr;
use ark_ff::{BigInteger, PrimeField};
use orbinum_zk_core::{
	domain::{ports::PoseidonHasher, value_objects::FieldElement},
	infrastructure::crypto::LightPoseidonHasher,
};

/// Generates disclosure proof with explicit proving key and WASM
///
/// Produces ZK proof for selective field disclosure.
/// No filesystem I/O - proving key and WASM provided as parameters.
pub fn generate_disclosure_proof(
	memo_data: &MemoData,
	mask: &DisclosureMask,
	viewing_key: &[u8; 32],
	commitment: [u8; 32],
	proving_key_bytes: &[u8],
	wasm_bytes: &[u8],
) -> Result<DisclosureProof, MemoError> {
	// STEP 1: Validate mask
	mask.validate()?;

	// STEP 2: Calculate witness (circuit private inputs)
	let witness = calculate_witness(memo_data, mask, viewing_key, commitment)?;

	// STEP 3: Calculate public signals (circuit public outputs)
	let public_signals = calculate_public_signals(memo_data, mask, viewing_key, commitment)?;

	// STEP 4: Validate proving key before using it
	use crate::infrastructure::repositories::key_loader::validate_proving_key;
	validate_proving_key(proving_key_bytes)?;

	// STEP 5: Generate Groth16 proof with provided key and WASM
	let proof =
		generate_groth16_proof_with_key(&witness, &public_signals, proving_key_bytes, wasm_bytes)?;

	Ok(DisclosureProof {
		proof,
		public_signals,
		mask: mask.clone(),
	})
}

// ============================================================================
// Witness Calculation (Private Inputs)
// ============================================================================

/// Witness structure for disclosure circuit (private inputs)
#[derive(Debug, Clone)]
pub struct DisclosureWitness {
	/// value: u64 - Memo amount
	pub value: u64,
	/// owner_pubkey: [u8; 32] - Public key in bytes
	pub owner_pubkey: [u8; 32],
	/// blinding: [u8; 32] - Blinding factor
	pub blinding: [u8; 32],
	/// asset_id: u32 - Asset identifier
	pub asset_id: u32,
	/// viewing_key: [u8; 32] - Viewing key for ownership check
	pub viewing_key: [u8; 32],
}

/// Calculates witness (private inputs) for the circuit
fn calculate_witness(
	memo_data: &MemoData,
	_mask: &DisclosureMask,
	viewing_key: &[u8; 32],
	_commitment: [u8; 32],
) -> Result<DisclosureWitness, MemoError> {
	// The witness contains all private information needed for the circuit
	Ok(DisclosureWitness {
		value: memo_data.value,
		owner_pubkey: memo_data.owner_pk,
		blinding: memo_data.blinding,
		asset_id: memo_data.asset_id,
		viewing_key: *viewing_key,
	})
}

// ============================================================================
// Public Signals Calculation (Public Outputs)
// ============================================================================

/// Calculates public signals for circuit
///
/// Returns commitment and conditionally revealed fields based on mask.
fn calculate_public_signals(
	memo_data: &MemoData,
	mask: &DisclosureMask,
	_viewing_key: &[u8; 32],
	commitment: [u8; 32],
) -> Result<DisclosurePublicSignals, MemoError> {
	// SIGNAL 1: Commitment (32 bytes)
	let commitment_field = commitment;

	// SIGNAL 2: Revealed Value (value if disclosed, 0 otherwise)
	let revealed_value = if mask.disclose_value {
		memo_data.value
	} else {
		0
	};

	// SIGNAL 3: Revealed Asset ID (asset_id if disclosed, 0 otherwise)
	let revealed_asset_id = if mask.disclose_asset_id {
		memo_data.asset_id
	} else {
		0
	};

	// SIGNAL 4: Revealed Owner Hash (Poseidon if disclosed, 0 otherwise)
	let revealed_owner_hash = if mask.disclose_owner {
		hash_owner_pubkey(&memo_data.owner_pk)
	} else {
		[0u8; 32] // Zero if not revealing owner
	};

	Ok(DisclosurePublicSignals {
		commitment: commitment_field,
		revealed_value,
		revealed_asset_id,
		revealed_owner_hash,
	})
}

// ============================================================================
// Cryptographic Primitives
// ============================================================================

/// Converts field element to 32-byte array (big-endian)
fn field_to_bytes(field: Bn254Fr) -> [u8; 32] {
	let mut bytes = [0u8; 32];
	// BigInteger256 has into_repr that gives little-endian, convert to big-endian
	let le_bytes = field.into_bigint().to_bytes_le();
	// Copy in reverse to get big-endian
	for (i, &byte) in le_bytes.iter().enumerate().take(32) {
		bytes[31 - i] = byte;
	}
	bytes
}

/// Hashes owner public key using Poseidon
fn hash_owner_pubkey(owner_pk: &[u8; 32]) -> [u8; 32] {
	let pk_field = Bn254Fr::from_be_bytes_mod_order(owner_pk);
	// For single input, use hash_2 with zero as second input (circuit compatibility)
	let hasher = LightPoseidonHasher;
	let hash_field = hasher.hash_2([
		FieldElement::new(pk_field),
		FieldElement::new(Bn254Fr::from(0u64)),
	]);
	field_to_bytes(hash_field.inner())
}

// ============================================================================
// Groth16 Prover
// ============================================================================

/// Generates Groth16 proof with provided proving key and WASM
///
/// Requires wasm-witness feature. Returns serialized proof or error.
fn generate_groth16_proof_with_key(
	witness: &DisclosureWitness,
	public_signals: &DisclosurePublicSignals,
	proving_key_bytes: &[u8],
	wasm_bytes: &[u8],
) -> Result<Vec<u8>, MemoError> {
	// Generate real proof with WASM witness calculator + ark-groth16
	#[cfg(all(feature = "std", feature = "wasm-witness"))]
	{
		use crate::application::prover::prove_with_wasm;

		prove_with_wasm(wasm_bytes, witness, public_signals, Some(proving_key_bytes)).map_err(
			|_| {
				MemoError::ProofGenerationFailed(
					"Failed to generate disclosure proof with provided key",
				)
			},
		)
	}

	// If wasm-witness feature is not enabled, return error
	#[cfg(not(all(feature = "std", feature = "wasm-witness")))]
	{
		let _ = (witness, public_signals, proving_key_bytes, wasm_bytes);
		Err(MemoError::ProofGenerationFailed(
			"wasm-witness feature not enabled",
		))
	}
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
	use super::*;
	use crate::domain::{aggregates::disclosure::DisclosureMask, entities::types::MemoData};

	// ===== DisclosureWitness Tests =====

	#[test]
	fn test_witness_construction() {
		let witness = DisclosureWitness {
			value: 1000,
			owner_pubkey: [1u8; 32],
			blinding: [2u8; 32],
			asset_id: 0,
			viewing_key: [3u8; 32],
		};

		assert_eq!(witness.value, 1000);
		assert_eq!(witness.owner_pubkey, [1u8; 32]);
		assert_eq!(witness.blinding, [2u8; 32]);
		assert_eq!(witness.asset_id, 0);
		assert_eq!(witness.viewing_key, [3u8; 32]);
	}

	#[test]
	fn test_witness_clone() {
		let witness1 = DisclosureWitness {
			value: 500,
			owner_pubkey: [10u8; 32],
			blinding: [20u8; 32],
			asset_id: 1,
			viewing_key: [30u8; 32],
		};

		let witness2 = witness1.clone();

		assert_eq!(witness1.value, witness2.value);
		assert_eq!(witness1.owner_pubkey, witness2.owner_pubkey);
	}

	// ===== calculate_witness Tests =====

	#[test]
	fn test_calculate_witness_basic() {
		let memo = MemoData::new(1000, [1u8; 32], [2u8; 32], 0);
		let mask = DisclosureMask::only_value();
		let viewing_key = [3u8; 32];
		let commitment = [4u8; 32];

		let result = calculate_witness(&memo, &mask, &viewing_key, commitment);

		assert!(result.is_ok());
		let witness = result.unwrap();
		assert_eq!(witness.value, 1000);
		assert_eq!(witness.owner_pubkey, [1u8; 32]);
		assert_eq!(witness.blinding, [2u8; 32]);
		assert_eq!(witness.viewing_key, [3u8; 32]);
	}

	#[test]
	fn test_calculate_witness_zero_value() {
		let memo = MemoData::new(0, [0u8; 32], [0u8; 32], 0);
		let mask = DisclosureMask::all();
		let viewing_key = [0u8; 32];
		let commitment = [0u8; 32];

		let result = calculate_witness(&memo, &mask, &viewing_key, commitment);

		assert!(result.is_ok());
		let witness = result.unwrap();
		assert_eq!(witness.value, 0);
	}

	#[test]
	fn test_calculate_witness_different_masks() {
		let memo = MemoData::new(500, [5u8; 32], [10u8; 32], 2);
		let viewing_key = [15u8; 32];
		let commitment = [20u8; 32];

		let mask1 = DisclosureMask::only_value();
		let witness1 = calculate_witness(&memo, &mask1, &viewing_key, commitment).unwrap();

		let mask2 = DisclosureMask::from_bitmap(0b0010); // only_owner
		let witness2 = calculate_witness(&memo, &mask2, &viewing_key, commitment).unwrap();

		// Witness should be same regardless of mask (mask affects public signals)
		assert_eq!(witness1.value, witness2.value);
		assert_eq!(witness1.owner_pubkey, witness2.owner_pubkey);
	}

	#[test]
	fn test_calculate_witness_large_values() {
		let memo = MemoData::new(u64::MAX, [255u8; 32], [128u8; 32], u32::MAX);
		let mask = DisclosureMask::all();
		let viewing_key = [42u8; 32];
		let commitment = [99u8; 32];

		let result = calculate_witness(&memo, &mask, &viewing_key, commitment);

		assert!(result.is_ok());
		let witness = result.unwrap();
		assert_eq!(witness.value, u64::MAX);
		assert_eq!(witness.asset_id, u32::MAX);
	}

	// ===== calculate_public_signals Tests =====

	#[test]
	fn test_calculate_public_signals_only_value() {
		let memo = MemoData::new(1000, [1u8; 32], [2u8; 32], 0);
		let mask = DisclosureMask::only_value();
		let viewing_key = [3u8; 32];
		let commitment = [4u8; 32];

		let result = calculate_public_signals(&memo, &mask, &viewing_key, commitment);

		assert!(result.is_ok());
		let signals = result.unwrap();
		assert_eq!(signals.commitment, [4u8; 32]);
		assert_eq!(signals.revealed_value, 1000);
		assert_eq!(signals.revealed_asset_id, 0); // Not disclosed
		assert_eq!(signals.revealed_owner_hash, [0u8; 32]); // Not disclosed
	}

	#[test]
	fn test_calculate_public_signals_value_and_asset() {
		let memo = MemoData::new(500, [10u8; 32], [20u8; 32], 42);
		let mask = DisclosureMask::value_and_asset();
		let viewing_key = [30u8; 32];
		let commitment = [40u8; 32];

		let result = calculate_public_signals(&memo, &mask, &viewing_key, commitment);

		assert!(result.is_ok());
		let signals = result.unwrap();
		assert_eq!(signals.revealed_value, 500); // Disclosed
		assert_eq!(signals.revealed_asset_id, 42); // Disclosed
		assert_eq!(signals.revealed_owner_hash, [0u8; 32]); // Not disclosed
	}

	#[test]
	fn test_calculate_public_signals_only_owner() {
		let memo = MemoData::new(750, [5u8; 32], [15u8; 32], 1);
		let mask = DisclosureMask::from_bitmap(0b0010); // only_owner
		let viewing_key = [25u8; 32];
		let commitment = [35u8; 32];

		let result = calculate_public_signals(&memo, &mask, &viewing_key, commitment);

		assert!(result.is_ok());
		let signals = result.unwrap();
		assert_eq!(signals.revealed_value, 0); // Not disclosed
		assert_eq!(signals.revealed_asset_id, 0); // Not disclosed
		assert_ne!(signals.revealed_owner_hash, [0u8; 32]); // Hash disclosed
	}

	#[test]
	fn test_calculate_public_signals_all() {
		let memo = MemoData::new(2000, [7u8; 32], [14u8; 32], 5);
		let mask = DisclosureMask::all();
		let viewing_key = [21u8; 32];
		let commitment = [28u8; 32];

		let result = calculate_public_signals(&memo, &mask, &viewing_key, commitment);

		assert!(result.is_ok());
		let signals = result.unwrap();
		assert_eq!(signals.revealed_value, 2000);
		assert_eq!(signals.revealed_asset_id, 5);
		assert_ne!(signals.revealed_owner_hash, [0u8; 32]);
	}

	#[test]
	fn test_calculate_public_signals_none() {
		let memo = MemoData::new(3000, [8u8; 32], [16u8; 32], 10);
		let mask = DisclosureMask::none();
		let viewing_key = [24u8; 32];
		let commitment = [32u8; 32];

		let result = calculate_public_signals(&memo, &mask, &viewing_key, commitment);

		assert!(result.is_ok());
		let signals = result.unwrap();
		assert_eq!(signals.revealed_value, 0);
		assert_eq!(signals.revealed_asset_id, 0);
		assert_eq!(signals.revealed_owner_hash, [0u8; 32]);
	}

	#[test]
	fn test_calculate_public_signals_commitment_preserved() {
		let memo = MemoData::new(100, [1u8; 32], [2u8; 32], 0);
		let mask = DisclosureMask::all();
		let viewing_key = [3u8; 32];
		let commitment = [99u8; 32];

		let result = calculate_public_signals(&memo, &mask, &viewing_key, commitment);

		assert!(result.is_ok());
		let signals = result.unwrap();
		assert_eq!(signals.commitment, commitment);
	}

	#[test]
	fn test_calculate_public_signals_zero_value() {
		let memo = MemoData::new(0, [0u8; 32], [0u8; 32], 0);
		let mask = DisclosureMask::only_value();
		let viewing_key = [0u8; 32];
		let commitment = [0u8; 32];

		let result = calculate_public_signals(&memo, &mask, &viewing_key, commitment);

		assert!(result.is_ok());
		let signals = result.unwrap();
		assert_eq!(signals.revealed_value, 0);
	}

	// ===== field_to_bytes Tests =====

	#[test]
	fn test_field_to_bytes_zero() {
		let field = Bn254Fr::from(0u64);
		let bytes = field_to_bytes(field);

		assert_eq!(bytes, [0u8; 32]);
	}

	#[test]
	fn test_field_to_bytes_one() {
		let field = Bn254Fr::from(1u64);
		let bytes = field_to_bytes(field);

		// Big-endian: 1 should be at the last position
		assert_eq!(bytes[31], 1);
		for i in 0..31 {
			assert_eq!(bytes[i], 0);
		}
	}

	#[test]
	fn test_field_to_bytes_large_value() {
		let field = Bn254Fr::from(u64::MAX);
		let bytes = field_to_bytes(field);

		// Should not be all zeros
		assert_ne!(bytes, [0u8; 32]);
	}

	#[test]
	fn test_field_to_bytes_deterministic() {
		let field = Bn254Fr::from(12345u64);
		let bytes1 = field_to_bytes(field);
		let bytes2 = field_to_bytes(field);

		assert_eq!(bytes1, bytes2);
	}

	#[test]
	fn test_field_to_bytes_different_inputs() {
		let field1 = Bn254Fr::from(100u64);
		let field2 = Bn254Fr::from(200u64);

		let bytes1 = field_to_bytes(field1);
		let bytes2 = field_to_bytes(field2);

		assert_ne!(bytes1, bytes2);
	}

	// ===== hash_owner_pubkey Tests =====

	#[test]
	fn test_hash_owner_pubkey_basic() {
		let owner_pk = [1u8; 32];
		let hash = hash_owner_pubkey(&owner_pk);

		// Should produce non-zero hash
		assert_ne!(hash, [0u8; 32]);
	}

	#[test]
	fn test_hash_owner_pubkey_zero() {
		let owner_pk = [0u8; 32];
		let hash = hash_owner_pubkey(&owner_pk);

		// Even zero input should produce non-zero hash (Poseidon property)
		assert_ne!(hash, [0u8; 32]);
	}

	#[test]
	fn test_hash_owner_pubkey_deterministic() {
		let owner_pk = [42u8; 32];
		let hash1 = hash_owner_pubkey(&owner_pk);
		let hash2 = hash_owner_pubkey(&owner_pk);

		assert_eq!(hash1, hash2);
	}

	#[test]
	fn test_hash_owner_pubkey_different_inputs() {
		let owner_pk1 = [1u8; 32];
		let owner_pk2 = [2u8; 32];

		let hash1 = hash_owner_pubkey(&owner_pk1);
		let hash2 = hash_owner_pubkey(&owner_pk2);

		assert_ne!(hash1, hash2);
	}

	#[test]
	fn test_hash_owner_pubkey_all_bits_set() {
		let owner_pk = [255u8; 32];
		let hash = hash_owner_pubkey(&owner_pk);

		assert_ne!(hash, [0u8; 32]);
		assert_ne!(hash, [255u8; 32]);
	}

	#[test]
	fn test_hash_owner_pubkey_sequential_bytes() {
		let mut owner_pk = [0u8; 32];
		for (i, byte) in owner_pk.iter_mut().enumerate() {
			*byte = i as u8;
		}

		let hash = hash_owner_pubkey(&owner_pk);
		assert_ne!(hash, [0u8; 32]);
	}

	// ===== generate_groth16_proof_with_key Tests =====

	#[test]
	fn test_generate_proof_without_wasm_witness_feature() {
		let witness = DisclosureWitness {
			value: 1000,
			owner_pubkey: [1u8; 32],
			blinding: [2u8; 32],
			asset_id: 0,
			viewing_key: [3u8; 32],
		};

		let signals = DisclosurePublicSignals {
			commitment: [4u8; 32],
			revealed_value: 1000,
			revealed_asset_id: 0,
			revealed_owner_hash: [0u8; 32],
		};

		let proving_key_bytes = vec![0u8; 100];
		let wasm_bytes = vec![0u8; 100];

		#[cfg(not(all(feature = "std", feature = "wasm-witness")))]
		{
			let result = generate_groth16_proof_with_key(
				&witness,
				&signals,
				&proving_key_bytes,
				&wasm_bytes,
			);

			assert!(result.is_err());
			if let Err(MemoError::ProofGenerationFailed(msg)) = result {
				assert_eq!(msg, "wasm-witness feature not enabled");
			}
		}

		#[cfg(all(feature = "std", feature = "wasm-witness"))]
		{
			// With feature enabled, will fail with invalid key/wasm but different error
			let result = generate_groth16_proof_with_key(
				&witness,
				&signals,
				&proving_key_bytes,
				&wasm_bytes,
			);
			assert!(result.is_err());
		}
	}

	// ===== Integration Tests =====

	#[test]
	fn test_calculate_witness_and_signals_consistency() {
		let memo = MemoData::new(500, [10u8; 32], [20u8; 32], 2);
		let mask = DisclosureMask::only_value();
		let viewing_key = [30u8; 32];
		let commitment = [40u8; 32];

		let witness = calculate_witness(&memo, &mask, &viewing_key, commitment).unwrap();
		let signals = calculate_public_signals(&memo, &mask, &viewing_key, commitment).unwrap();

		// Witness and signals should have consistent data
		assert_eq!(witness.value, memo.value);
		assert_eq!(signals.revealed_value, memo.value);
		assert_eq!(signals.commitment, commitment);
	}

	#[test]
	fn test_different_masks_produce_different_signals() {
		let memo = MemoData::new(1000, [5u8; 32], [10u8; 32], 3);
		let viewing_key = [15u8; 32];
		let commitment = [20u8; 32];

		let signals_value = calculate_public_signals(
			&memo,
			&DisclosureMask::only_value(),
			&viewing_key,
			commitment,
		)
		.unwrap();
		let signals_value_and_asset = calculate_public_signals(
			&memo,
			&DisclosureMask::value_and_asset(),
			&viewing_key,
			commitment,
		)
		.unwrap();
		let signals_all =
			calculate_public_signals(&memo, &DisclosureMask::all(), &viewing_key, commitment)
				.unwrap();

		assert_eq!(signals_value.revealed_value, 1000);
		assert_eq!(signals_value.revealed_asset_id, 0);

		assert_eq!(signals_value_and_asset.revealed_value, 1000);
		assert_eq!(signals_value_and_asset.revealed_asset_id, 3);

		assert_eq!(signals_all.revealed_value, 1000);
		assert_eq!(signals_all.revealed_asset_id, 3);
	}
}
