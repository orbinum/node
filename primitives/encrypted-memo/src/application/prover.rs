//! Groth16 Prover Use Case
//!
//! Generates Groth16 proofs for disclosure circuit using ark-groth16 with BN254.
//! WASM witness calculator produces complete witness (~740 wires).
//! Proving keys must be in ark-serialize format (.ark).

use crate::{
	application::disclosure::DisclosureWitness,
	domain::{aggregates::disclosure::DisclosurePublicSignals, entities::error::MemoError},
};
use alloc::vec::Vec;

// Ark imports
use ark_bn254::{Bn254, Fr as Bn254Fr};
use ark_ff::PrimeField;
use ark_groth16::{Groth16, ProvingKey};
use ark_relations::r1cs::ConstraintSynthesizer;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;

// ============================================================================
// Witness Calculator
// ============================================================================

/// Converts bytes to BN254 field element (big-endian)
fn bytes_to_field(bytes: &[u8]) -> Result<Bn254Fr, MemoError> {
	// Pad to 32 bytes if necessary
	let mut padded = [0u8; 32];
	let len = bytes.len().min(32);
	padded[32 - len..].copy_from_slice(&bytes[..len]);

	// Use Big-Endian to match disclosure.rs and standard crypto conventions
	Ok(Bn254Fr::from_be_bytes_mod_order(&padded))
}

// ============================================================================
// WASM Witness Calculator Integration
// ============================================================================

/// Calculates full witness using WASM witness calculator
///
/// Executes compiled circuit to produce complete witness (~740 wires).
/// Requires wasm-witness feature.
#[cfg(feature = "wasm-witness")]
pub fn calculate_witness_wasm(
	wasm_bytes: &[u8],
	witness: &DisclosureWitness,
	public_signals: &DisclosurePublicSignals,
) -> Result<Vec<Bn254Fr>, MemoError> {
	use crate::infrastructure::repositories::wasm_witness::WasmWitnessCalculator;
	use alloc::string::ToString;

	// 1. Create calculator
	let mut calculator = WasmWitnessCalculator::new(wasm_bytes)?;

	// 2. Prepare inputs as (signal_name, value) pairs
	// Order must match disclosure.circom declaration order
	let inputs = vec![
		// Public inputs
		(
			"commitment".to_string(),
			bytes_to_field(&public_signals.commitment)?,
		),
		(
			"revealed_value".to_string(),
			Bn254Fr::from(witness.value * (public_signals.disclose_value() as u64)),
		),
		(
			"revealed_asset_id".to_string(),
			Bn254Fr::from((witness.asset_id as u64) * (public_signals.disclose_asset_id() as u64)),
		),
		(
			"revealed_owner_hash".to_string(),
			bytes_to_field(&public_signals.revealed_owner_hash)?,
		),
		// Private inputs
		("value".to_string(), Bn254Fr::from(witness.value)),
		(
			"asset_id".to_string(),
			Bn254Fr::from(witness.asset_id as u64),
		),
		(
			"owner_pubkey".to_string(),
			bytes_to_field(&witness.owner_pubkey)?,
		),
		("blinding".to_string(), bytes_to_field(&witness.blinding)?),
		(
			"viewing_key".to_string(),
			bytes_to_field(&witness.viewing_key)?,
		),
		(
			"disclose_value".to_string(),
			Bn254Fr::from(public_signals.disclose_value() as u64),
		),
		(
			"disclose_asset_id".to_string(),
			Bn254Fr::from(public_signals.disclose_asset_id() as u64),
		),
		(
			"disclose_owner".to_string(),
			Bn254Fr::from(public_signals.disclose_owner() as u64),
		),
	];

	// 3. Calculate witness
	let full_witness = calculator.calculate_witness(&inputs)?;

	Ok(full_witness)
}

/// Placeholder when wasm-witness feature is not enabled
#[cfg(not(feature = "wasm-witness"))]
pub fn calculate_witness_wasm(
	_wasm_bytes: &[u8],
	_witness: &DisclosureWitness,
	_public_signals: &DisclosurePublicSignals,
) -> Result<Vec<Bn254Fr>, MemoError> {
	Err(MemoError::WasmLoadFailed(
		"wasm-witness feature not enabled. Rebuild with --features wasm-witness",
	))
}

/// Generates disclosure proof using WASM witness calculator
///
/// High-level API for production. Proving key must be provided by caller.
#[cfg(feature = "wasm-witness")]
pub fn prove_with_wasm(
	wasm_bytes: &[u8],
	witness: &DisclosureWitness,
	public_signals: &DisclosurePublicSignals,
	proving_key: Option<&[u8]>,
) -> Result<Vec<u8>, MemoError> {
	// Step 1: Get proving key (must be provided by caller)
	let pk = match proving_key {
		Some(pk_bytes) => pk_bytes.to_vec(),
		None => {
			return Err(MemoError::KeyLoadingFailed(
				"Proving key required but not provided - caller must load and pass key bytes",
			));
		}
	};

	// Step 2: Calculate full witness using WASM
	let full_witness = calculate_witness_wasm(wasm_bytes, witness, public_signals)?;

	// Step 3: Generate proof
	generate_groth16_proof_internal(&pk, &full_witness)
}

#[cfg(not(feature = "wasm-witness"))]
pub fn prove_with_wasm(
	_wasm_bytes: &[u8],
	_witness: &DisclosureWitness,
	_public_signals: &DisclosurePublicSignals,
	_proving_key: Option<&[u8]>,
) -> Result<Vec<u8>, MemoError> {
	Err(MemoError::WasmLoadFailed(
		"wasm-witness feature not enabled",
	))
}

// ============================================================================
// Groth16 Prover (ARK Implementation)
// ============================================================================

/// Generates Groth16 proof using ark-groth16
///
/// Proving key must be ark-serialize format (.ark), not snarkjs .zkey.
/// Returns serialized proof or error.
pub fn generate_groth16_proof_internal(
	proving_key_bytes: &[u8],
	witness: &[Bn254Fr],
) -> Result<Vec<u8>, MemoError> {
	// 1. Deserializar proving key
	let pk = ProvingKey::<Bn254>::deserialize_compressed(proving_key_bytes).map_err(|e| {
		MemoError::InvalidProvingKey(
			alloc::format!("Failed to deserialize proving key: {e:?}").leak(),
		)
	})?;

	// 2. Create constraint system with the witness
	// NOTE: This requires that the witness is complete (all wires)
	// In production, use WASM witness calculator
	let circuit = WitnessCircuit {
		witness: witness.to_vec(),
	};

	// 3. Generate proof with ark-groth16
	// NOTE: In production use OsRng or ChaCha20Rng with random seed
	use ark_std::rand::{rngs::StdRng, SeedableRng};
	let mut rng = StdRng::from_entropy();

	let proof = Groth16::<Bn254>::prove(&pk, circuit, &mut rng).map_err(|e| {
		MemoError::ProofGenerationFailed(
			alloc::format!("ark-groth16 proof generation failed: {e:?}").leak(),
		)
	})?;

	// 4. Serialize proof
	let mut proof_bytes = Vec::new();
	proof.serialize_compressed(&mut proof_bytes).map_err(|e| {
		MemoError::ProofGenerationFailed(alloc::format!("Failed to serialize proof: {e:?}").leak())
	})?;

	Ok(proof_bytes)
}

/// Minimal circuit wrapper for ark-groth16
struct WitnessCircuit {
	witness: Vec<Bn254Fr>,
}

impl ConstraintSynthesizer<Bn254Fr> for WitnessCircuit {
	fn generate_constraints(
		self,
		cs: ark_relations::r1cs::ConstraintSystemRef<Bn254Fr>,
	) -> ark_relations::r1cs::Result<()> {
		// NOTE: This DisclosureCircuit is a basic implementation for testing.
		// It only assigns the witness without implementing the complete constraints of the circuit.

		// Mark public inputs
		let num_public = 4; // commitment, vk_hash, mask, revealed_owner_hash
		for i in 0..num_public.min(self.witness.len().saturating_sub(1)) {
			let _ = cs.new_input_variable(|| Ok(self.witness[i + 1]))?;
		}

		// Private witness variables
		for signal in self.witness.iter().skip(num_public + 1) {
			let _ = cs.new_witness_variable(|| Ok(*signal))?;
		}

		Ok(())
	}
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
	use super::*;
	use crate::domain::aggregates::disclosure::DisclosurePublicSignals;

	// ===== bytes_to_field Tests =====

	#[test]
	fn test_bytes_to_field_zero() {
		let bytes = [0u8; 32];
		let result = bytes_to_field(&bytes);

		assert!(result.is_ok());
		assert_eq!(result.unwrap(), Bn254Fr::from(0u64));
	}

	#[test]
	fn test_bytes_to_field_one() {
		let mut bytes = [0u8; 32];
		bytes[31] = 1; // Big-endian
		let result = bytes_to_field(&bytes);

		assert!(result.is_ok());
		assert_eq!(result.unwrap(), Bn254Fr::from(1u64));
	}

	#[test]
	fn test_bytes_to_field_small_input() {
		let bytes = [1u8; 8];
		let result = bytes_to_field(&bytes);

		assert!(result.is_ok());
		// Should pad and convert correctly
		assert_ne!(result.unwrap(), Bn254Fr::from(0u64));
	}

	#[test]
	fn test_bytes_to_field_large_input() {
		let bytes = [255u8; 32];
		let result = bytes_to_field(&bytes);

		assert!(result.is_ok());
		// Should reduce modulo field order
		assert_ne!(result.unwrap(), Bn254Fr::from(0u64));
	}

	#[test]
	fn test_bytes_to_field_deterministic() {
		let bytes = [42u8; 32];
		let result1 = bytes_to_field(&bytes);
		let result2 = bytes_to_field(&bytes);

		assert!(result1.is_ok());
		assert!(result2.is_ok());
		assert_eq!(result1.unwrap(), result2.unwrap());
	}

	#[test]
	fn test_bytes_to_field_different_inputs() {
		let bytes1 = [1u8; 32];
		let bytes2 = [2u8; 32];

		let result1 = bytes_to_field(&bytes1).unwrap();
		let result2 = bytes_to_field(&bytes2).unwrap();

		assert_ne!(result1, result2);
	}

	#[test]
	fn test_bytes_to_field_empty_padded() {
		let bytes = [];
		let result = bytes_to_field(&bytes);

		assert!(result.is_ok());
		assert_eq!(result.unwrap(), Bn254Fr::from(0u64));
	}

	#[test]
	fn test_bytes_to_field_sequential() {
		let mut bytes = [0u8; 32];
		for (i, byte) in bytes.iter_mut().enumerate() {
			*byte = i as u8;
		}

		let result = bytes_to_field(&bytes);
		assert!(result.is_ok());
		assert_ne!(result.unwrap(), Bn254Fr::from(0u64));
	}

	// ===== WitnessCircuit Tests =====

	#[test]
	fn test_witness_circuit_construction() {
		let witness = vec![
			Bn254Fr::from(0u64),
			Bn254Fr::from(1u64),
			Bn254Fr::from(2u64),
		];
		let circuit = WitnessCircuit {
			witness: witness.clone(),
		};

		assert_eq!(circuit.witness.len(), 3);
		assert_eq!(circuit.witness[0], Bn254Fr::from(0u64));
		assert_eq!(circuit.witness[1], Bn254Fr::from(1u64));
		assert_eq!(circuit.witness[2], Bn254Fr::from(2u64));
	}

	#[test]
	fn test_witness_circuit_empty() {
		let circuit = WitnessCircuit { witness: vec![] };

		assert_eq!(circuit.witness.len(), 0);
	}

	#[test]
	fn test_witness_circuit_large() {
		let witness = vec![Bn254Fr::from(42u64); 1000];
		let circuit = WitnessCircuit {
			witness: witness.clone(),
		};

		assert_eq!(circuit.witness.len(), 1000);
		assert_eq!(circuit.witness[500], Bn254Fr::from(42u64));
	}

	// ===== calculate_witness_wasm Tests (without feature) =====

	#[test]
	#[cfg(not(feature = "wasm-witness"))]
	fn test_calculate_witness_wasm_without_feature() {
		let wasm_bytes = vec![0u8; 100];
		let witness = DisclosureWitness {
			value: 1000,
			owner_pubkey: [1u8; 32],
			blinding: [2u8; 32],
			asset_id: 0,
			viewing_key: [3u8; 32],
		};
		let public_signals = DisclosurePublicSignals {
			commitment: [4u8; 32],
			revealed_value: 1000,
			revealed_asset_id: 0,
			revealed_owner_hash: [0u8; 32],
		};

		let result = calculate_witness_wasm(&wasm_bytes, &witness, &public_signals);

		assert!(result.is_err());
		if let Err(MemoError::WasmLoadFailed(msg)) = result {
			assert!(msg.contains("wasm-witness feature not enabled"));
		}
	}

	#[test]
	#[cfg(not(feature = "wasm-witness"))]
	fn test_prove_with_wasm_without_feature() {
		let wasm_bytes = vec![0u8; 100];
		let witness = DisclosureWitness {
			value: 1000,
			owner_pubkey: [1u8; 32],
			blinding: [2u8; 32],
			asset_id: 0,
			viewing_key: [3u8; 32],
		};
		let public_signals = DisclosurePublicSignals {
			commitment: [4u8; 32],
			revealed_value: 1000,
			revealed_asset_id: 0,
			revealed_owner_hash: [0u8; 32],
		};

		let result = prove_with_wasm(&wasm_bytes, &witness, &public_signals, None);

		assert!(result.is_err());
		if let Err(MemoError::WasmLoadFailed(msg)) = result {
			assert!(msg.contains("wasm-witness feature not enabled"));
		}
	}

	// ===== prove_with_wasm Tests (with feature) =====

	#[test]
	#[cfg(feature = "wasm-witness")]
	fn test_prove_with_wasm_no_proving_key() {
		let wasm_bytes = vec![0u8; 100];
		let witness = DisclosureWitness {
			value: 1000,
			owner_pubkey: [1u8; 32],
			blinding: [2u8; 32],
			asset_id: 0,
			viewing_key: [3u8; 32],
		};
		let public_signals = DisclosurePublicSignals {
			commitment: [4u8; 32],
			revealed_value: 1000,
			revealed_asset_id: 0,
			revealed_owner_hash: [0u8; 32],
		};

		let result = prove_with_wasm(&wasm_bytes, &witness, &public_signals, None);

		assert!(result.is_err());
		if let Err(MemoError::KeyLoadingFailed(msg)) = result {
			assert!(msg.contains("Proving key required"));
		}
	}

	// ===== generate_groth16_proof_internal Tests =====

	#[test]
	fn test_generate_groth16_proof_invalid_key() {
		let invalid_key = vec![0u8; 100];
		let witness = vec![Bn254Fr::from(1u64), Bn254Fr::from(2u64)];

		let result = generate_groth16_proof_internal(&invalid_key, &witness);

		assert!(result.is_err());
		if let Err(MemoError::InvalidProvingKey(msg)) = result {
			assert!(msg.contains("Failed to deserialize proving key"));
		}
	}

	#[test]
	fn test_generate_groth16_proof_empty_key() {
		let empty_key = vec![];
		let witness = vec![Bn254Fr::from(1u64)];

		let result = generate_groth16_proof_internal(&empty_key, &witness);

		assert!(result.is_err());
		if let Err(MemoError::InvalidProvingKey(_)) = result {
			// Expected
		} else {
			panic!("Expected InvalidProvingKey error");
		}
	}

	#[test]
	fn test_generate_groth16_proof_empty_witness() {
		let invalid_key = vec![1u8; 100];
		let witness = vec![];

		let result = generate_groth16_proof_internal(&invalid_key, &witness);

		assert!(result.is_err());
	}

	// ===== Integration Tests =====

	#[test]
	fn test_bytes_to_field_roundtrip_values() {
		let test_values = [0u64, 1u64, 100u64, 1000u64, u64::MAX];

		for val in test_values {
			let field = Bn254Fr::from(val);
			let mut bytes = [0u8; 32];
			let val_bytes = val.to_be_bytes();
			bytes[24..].copy_from_slice(&val_bytes);

			let result = bytes_to_field(&bytes);
			assert!(result.is_ok());
			assert_eq!(result.unwrap(), field);
		}
	}

	#[test]
	fn test_witness_circuit_constraint_synthesis() {
		use ark_relations::r1cs::ConstraintSystem;

		let witness = vec![
			Bn254Fr::from(0u64), // Wire 0 (always 1 in R1CS)
			Bn254Fr::from(1u64),
			Bn254Fr::from(2u64),
			Bn254Fr::from(3u64),
			Bn254Fr::from(4u64),
			Bn254Fr::from(5u64),
		];

		let circuit = WitnessCircuit {
			witness: witness.clone(),
		};

		let cs = ConstraintSystem::<Bn254Fr>::new_ref();
		let result = circuit.generate_constraints(cs.clone());

		assert!(result.is_ok());
		assert!(cs.num_instance_variables() > 0 || cs.num_witness_variables() > 0);
	}

	#[test]
	fn test_bytes_to_field_padding_consistency() {
		let short_bytes = [42u8; 8];
		let mut padded_bytes = [0u8; 32];
		padded_bytes[24..].copy_from_slice(&short_bytes);

		let result_short = bytes_to_field(&short_bytes).unwrap();
		let result_padded = bytes_to_field(&padded_bytes).unwrap();

		assert_eq!(result_short, result_padded);
	}

	#[test]
	fn test_witness_circuit_with_minimal_witness() {
		use ark_relations::r1cs::ConstraintSystem;

		// Minimal witness: wire 0 + 4 public + 1 private
		let witness = vec![
			Bn254Fr::from(1u64), // wire 0
			Bn254Fr::from(10u64),
			Bn254Fr::from(20u64),
			Bn254Fr::from(30u64),
			Bn254Fr::from(40u64),
			Bn254Fr::from(50u64), // private
		];

		let circuit = WitnessCircuit { witness };
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();
		let result = circuit.generate_constraints(cs.clone());

		assert!(result.is_ok());
	}
}
