//! Core ZK types: proofs, keys, inputs, errors, and circuit constants.

use alloc::vec::Vec;

use ark_bn254::{Bn254, Fr as Bn254Fr};
use ark_groth16::{PreparedVerifyingKey, Proof as ArkProof, VerifyingKey as ArkVK};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use core::fmt;

#[cfg(feature = "substrate")]
use parity_scale_codec::{Decode, Encode};
#[cfg(feature = "substrate")]
use scale_info::TypeInfo;

// ─── Circuit constants ────────────────────────────────────────────────────────

/// Circuit identifier for transfer operations.
pub const CIRCUIT_ID_TRANSFER: u8 = 1;
/// Circuit identifier for unshield (withdraw) operations.
pub const CIRCUIT_ID_UNSHIELD: u8 = 2;
/// Circuit identifier for disclosure (selective disclosure) operations.
pub const CIRCUIT_ID_DISCLOSURE: u8 = 4;
/// Circuit identifier for private link dispatch operations.
pub const CIRCUIT_ID_PRIVATE_LINK: u8 = 5;

/// Number of public inputs for the transfer circuit.
/// Public inputs: [merkle_root, nullifier1, nullifier2, commitment1, commitment2]
pub const TRANSFER_PUBLIC_INPUTS: usize = 5;
/// Number of public inputs for the unshield circuit.
/// Public inputs: [merkle_root, nullifier, recipient, amount, asset_id]
pub const UNSHIELD_PUBLIC_INPUTS: usize = 5;
/// Number of public inputs for the disclosure circuit.
/// Public inputs: [commitment, revealed_value, revealed_asset_id, revealed_owner_hash]
pub const DISCLOSURE_PUBLIC_INPUTS: usize = 4;
/// Number of public inputs for the private link circuit.
/// Public inputs: [commitment(32B LE field element), call_hash_fe(32B LE field element)]
pub const PRIVATE_LINK_PUBLIC_INPUTS: usize = 2;

/// Base cost for Groth16 verification (pairing operations).
pub const BASE_VERIFICATION_COST: u64 = 100_000;
/// Cost per public input (scalar multiplication).
pub const PER_INPUT_COST: u64 = 10_000;
/// Maximum number of public inputs supported.
pub const MAX_PUBLIC_INPUTS: usize = 32;

// ─── VerifierError ────────────────────────────────────────────────────────────

/// Errors that can occur during proof verification.
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "substrate", derive(Encode, Decode, TypeInfo))]
pub enum VerifierError {
	/// The proof is invalid or malformed.
	InvalidProof,
	/// The verifying key is invalid or malformed.
	InvalidVerifyingKey,
	/// Public input is invalid.
	InvalidPublicInput,
	/// Public input count mismatch.
	InvalidPublicInputCount { expected: u32, got: u32 },
	/// Proof verification failed (proof is incorrect).
	VerificationFailed,
	/// Serialization/deserialization error.
	SerializationError,
	/// Invalid proof size.
	InvalidProofSize,
	/// Invalid verifying key size.
	InvalidVKSize,
	/// Invalid circuit ID (not recognized).
	InvalidCircuitId(u8),
}

impl fmt::Display for VerifierError {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match self {
			VerifierError::InvalidProof => write!(f, "Invalid proof"),
			VerifierError::InvalidVerifyingKey => write!(f, "Invalid verifying key"),
			VerifierError::InvalidPublicInput => write!(f, "Invalid public input"),
			VerifierError::InvalidPublicInputCount { expected, got } => {
				write!(
					f,
					"Invalid public input count: expected {expected}, got {got}"
				)
			}
			VerifierError::VerificationFailed => write!(f, "Verification failed"),
			VerifierError::SerializationError => write!(f, "Serialization error"),
			VerifierError::InvalidProofSize => write!(f, "Invalid proof size"),
			VerifierError::InvalidVKSize => write!(f, "Invalid verifying key size"),
			VerifierError::InvalidCircuitId(id) => write!(f, "Invalid circuit ID: {id}"),
		}
	}
}

#[cfg(feature = "std")]
impl std::error::Error for VerifierError {}

// ─── Proof ────────────────────────────────────────────────────────────────────

/// A Groth16 proof in compressed serialized form.
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "substrate", derive(Encode, Decode, TypeInfo))]
pub struct Proof {
	pub bytes: Vec<u8>,
}

impl Proof {
	pub fn new(bytes: Vec<u8>) -> Self {
		Self { bytes }
	}

	pub fn as_bytes(&self) -> &[u8] {
		&self.bytes
	}

	pub fn to_ark_proof(&self) -> Result<ArkProof<Bn254>, VerifierError> {
		ArkProof::<Bn254>::deserialize_compressed(&self.bytes[..])
			.map_err(|_| VerifierError::InvalidProof)
	}

	pub fn from_ark_proof(proof: &ArkProof<Bn254>) -> Result<Self, VerifierError> {
		let mut bytes = Vec::new();
		proof
			.serialize_compressed(&mut bytes)
			.map_err(|_| VerifierError::SerializationError)?;
		Ok(Self { bytes })
	}
}

// ─── VerifyingKey ─────────────────────────────────────────────────────────────

/// A Groth16 verifying key in compressed serialized form.
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "substrate", derive(Encode, Decode, TypeInfo))]
pub struct VerifyingKey {
	pub bytes: Vec<u8>,
}

impl VerifyingKey {
	pub fn new(bytes: Vec<u8>) -> Self {
		Self { bytes }
	}

	pub fn as_bytes(&self) -> &[u8] {
		&self.bytes
	}

	pub fn to_ark_vk(&self) -> Result<ArkVK<Bn254>, VerifierError> {
		ArkVK::<Bn254>::deserialize_compressed(&self.bytes[..])
			.map_err(|_| VerifierError::InvalidVerifyingKey)
	}

	pub fn from_ark_vk(vk: &ArkVK<Bn254>) -> Result<Self, VerifierError> {
		let mut bytes = Vec::new();
		vk.serialize_compressed(&mut bytes)
			.map_err(|_| VerifierError::SerializationError)?;
		Ok(Self { bytes })
	}

	pub fn prepare(&self) -> Result<PreparedVerifyingKey<Bn254>, VerifierError> {
		let vk = self.to_ark_vk()?;
		Ok(PreparedVerifyingKey::from(vk))
	}
}

// ─── PublicInputs ─────────────────────────────────────────────────────────────

/// Public inputs for a Groth16 proof — each input is a field element in LE bytes.
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "substrate", derive(Encode, Decode, TypeInfo))]
pub struct PublicInputs {
	pub inputs: Vec<[u8; 32]>,
}

impl PublicInputs {
	pub fn new(inputs: Vec<[u8; 32]>) -> Self {
		Self { inputs }
	}

	pub fn len(&self) -> usize {
		self.inputs.len()
	}

	pub fn is_empty(&self) -> bool {
		self.inputs.is_empty()
	}

	pub fn to_field_elements(&self) -> Result<Vec<Bn254Fr>, VerifierError> {
		use ark_ff::PrimeField;
		self.inputs
			.iter()
			.map(|bytes| Ok(Bn254Fr::from_le_bytes_mod_order(bytes)))
			.collect()
	}

	pub fn from_field_elements(elements: &[Bn254Fr]) -> Self {
		use ark_ff::{BigInteger, PrimeField};
		let inputs = elements
			.iter()
			.map(|elem| {
				let mut bytes = [0u8; 32];
				let elem_bytes = elem.into_bigint().to_bytes_le();
				let len = core::cmp::min(elem_bytes.len(), 32);
				bytes[..len].copy_from_slice(&elem_bytes[..len]);
				bytes
			})
			.collect();
		Self { inputs }
	}
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
	use super::*;
	extern crate alloc;
	use alloc::vec;
	use ark_ff::PrimeField;

	// ─── VerifierError ───────────────────────────────────────────────────

	#[test]
	fn test_error_equality_and_clone() {
		let a = VerifierError::InvalidProof;
		let b = a.clone();
		assert_eq!(a, b);
		let c = VerifierError::InvalidPublicInputCount {
			expected: 5,
			got: 3,
		};
		assert_eq!(c.clone(), c);
	}

	#[test]
	fn test_display_messages() {
		assert_eq!(VerifierError::InvalidProof.to_string(), "Invalid proof");
		assert_eq!(
			VerifierError::InvalidVerifyingKey.to_string(),
			"Invalid verifying key"
		);
		assert_eq!(
			VerifierError::InvalidPublicInput.to_string(),
			"Invalid public input"
		);
		assert_eq!(
			VerifierError::VerificationFailed.to_string(),
			"Verification failed"
		);
		assert_eq!(
			VerifierError::SerializationError.to_string(),
			"Serialization error"
		);
		assert_eq!(
			VerifierError::InvalidProofSize.to_string(),
			"Invalid proof size"
		);
		assert_eq!(
			VerifierError::InvalidVKSize.to_string(),
			"Invalid verifying key size"
		);
	}

	#[test]
	fn test_display_dynamic_messages() {
		let msg = VerifierError::InvalidPublicInputCount {
			expected: 5,
			got: 2,
		}
		.to_string();
		assert_eq!(msg, "Invalid public input count: expected 5, got 2");
		let msg = VerifierError::InvalidCircuitId(9).to_string();
		assert_eq!(msg, "Invalid circuit ID: 9");
	}

	// ─── Circuit constants ───────────────────────────────────────────────

	#[test]
	fn test_circuit_ids_are_stable() {
		assert_eq!(CIRCUIT_ID_TRANSFER, 1);
		assert_eq!(CIRCUIT_ID_UNSHIELD, 2);
		assert_eq!(CIRCUIT_ID_DISCLOSURE, 4);
		assert_eq!(CIRCUIT_ID_PRIVATE_LINK, 5);
	}

	#[test]
	fn test_public_input_counts_are_expected() {
		assert_eq!(TRANSFER_PUBLIC_INPUTS, 5);
		assert_eq!(UNSHIELD_PUBLIC_INPUTS, 5);
		assert_eq!(DISCLOSURE_PUBLIC_INPUTS, 4);
		assert_eq!(PRIVATE_LINK_PUBLIC_INPUTS, 2);
	}

	// ─── Proof ──────────────────────────────────────────────────────────

	#[test]
	fn test_proof_new() {
		let bytes = vec![1, 2, 3, 4, 5];
		let proof = Proof::new(bytes.clone());
		assert_eq!(proof.bytes, bytes);
	}

	#[test]
	fn test_proof_as_bytes() {
		let bytes = vec![1, 2, 3, 4, 5];
		let proof = Proof::new(bytes.clone());
		assert_eq!(proof.as_bytes(), &bytes[..]);
	}

	#[test]
	fn test_proof_to_ark_proof_invalid() {
		let proof = Proof::new(vec![0u8; 10]);
		let result = proof.to_ark_proof();
		assert!(matches!(result, Err(VerifierError::InvalidProof)));
	}

	#[test]
	fn test_proof_clone() {
		let proof1 = Proof::new(vec![1, 2, 3]);
		assert_eq!(proof1.clone(), proof1);
	}

	#[test]
	fn test_proof_empty_bytes() {
		assert!(Proof::new(vec![]).as_bytes().is_empty());
	}

	// ─── VerifyingKey ────────────────────────────────────────────────────

	#[test]
	fn test_vk_new() {
		let bytes = vec![1, 2, 3, 4, 5];
		let vk = VerifyingKey::new(bytes.clone());
		assert_eq!(vk.bytes, bytes);
	}

	#[test]
	fn test_vk_as_bytes() {
		let bytes = vec![1, 2, 3, 4, 5];
		let vk = VerifyingKey::new(bytes.clone());
		assert_eq!(vk.as_bytes(), &bytes[..]);
	}

	#[test]
	fn test_vk_to_ark_vk_invalid() {
		let vk = VerifyingKey::new(vec![0u8; 10]);
		assert!(matches!(
			vk.to_ark_vk(),
			Err(VerifierError::InvalidVerifyingKey)
		));
	}

	#[test]
	fn test_vk_prepare_invalid() {
		assert!(VerifyingKey::new(vec![0u8; 10]).prepare().is_err());
	}

	#[test]
	fn test_vk_clone() {
		let vk1 = VerifyingKey::new(vec![1, 2, 3]);
		assert_eq!(vk1.clone(), vk1);
	}

	#[test]
	fn test_vk_empty_bytes() {
		assert!(VerifyingKey::new(vec![]).as_bytes().is_empty());
	}

	// ─── PublicInputs ────────────────────────────────────────────────────

	#[test]
	fn test_public_inputs_new() {
		let inputs = vec![[1u8; 32], [2u8; 32]];
		let pi = PublicInputs::new(inputs.clone());
		assert_eq!(pi.inputs, inputs);
	}

	#[test]
	fn test_public_inputs_len() {
		assert_eq!(PublicInputs::new(vec![[0u8; 32]; 5]).len(), 5);
	}

	#[test]
	fn test_public_inputs_is_empty() {
		assert!(PublicInputs::new(vec![]).is_empty());
		assert!(!PublicInputs::new(vec![[0u8; 32]]).is_empty());
	}

	#[test]
	fn test_public_inputs_to_field_elements() {
		let result = PublicInputs::new(vec![[1u8; 32], [2u8; 32]]).to_field_elements();
		assert_eq!(result.unwrap().len(), 2);
	}

	#[test]
	fn test_public_inputs_from_field_elements() {
		let elements = vec![Bn254Fr::from(123u64), Bn254Fr::from(456u64)];
		assert_eq!(PublicInputs::from_field_elements(&elements).len(), 2);
	}

	#[test]
	fn test_public_inputs_roundtrip_conversion() {
		let original = vec![
			Bn254Fr::from(123u64),
			Bn254Fr::from(456u64),
			Bn254Fr::from(789u64),
		];
		let converted = PublicInputs::from_field_elements(&original)
			.to_field_elements()
			.unwrap();
		assert_eq!(converted, original);
	}

	#[test]
	fn test_public_inputs_clone() {
		let pi = PublicInputs::new(vec![[1u8; 32], [2u8; 32]]);
		assert_eq!(pi.clone(), pi);
	}

	#[test]
	fn test_public_inputs_empty() {
		let empty = PublicInputs::new(vec![]);
		assert_eq!(empty.len(), 0);
		assert_eq!(empty.to_field_elements().unwrap().len(), 0);
	}

	#[test]
	fn test_public_inputs_large_values() {
		let max = Bn254Fr::from_le_bytes_mod_order(&[0xff; 32]);
		let elements = vec![max, Bn254Fr::from(0u64), max];
		let converted = PublicInputs::from_field_elements(&elements)
			.to_field_elements()
			.unwrap();
		assert_eq!(converted, elements);
	}

	#[test]
	fn test_public_inputs_many_elements() {
		let elements: Vec<Bn254Fr> = (0..32).map(|i| Bn254Fr::from(i as u64)).collect();
		let pi = PublicInputs::from_field_elements(&elements);
		assert_eq!(pi.len(), 32);
		let converted = pi.to_field_elements().unwrap();
		for (i, (orig, conv)) in elements.iter().zip(converted.iter()).enumerate() {
			assert_eq!(orig, conv, "Mismatch at index {i}");
		}
	}
}
