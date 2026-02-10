//! Proof, VerifyingKey, and PublicInputs types.

use alloc::vec::Vec;

use ark_groth16::{PreparedVerifyingKey, Proof as ArkProof, VerifyingKey as ArkVK};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

#[cfg(feature = "substrate")]
use parity_scale_codec::{Decode, Encode};
#[cfg(feature = "substrate")]
use scale_info::TypeInfo;

use crate::{domain::value_objects::errors::VerifierError, Bn254, Bn254Fr};

/// A Groth16 proof that can be serialized/deserialized for on-chain storage
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "substrate", derive(Encode, Decode, TypeInfo))]
pub struct Proof {
	/// Serialized proof bytes (compressed format)
	pub bytes: Vec<u8>,
}

impl Proof {
	/// Create a new proof from raw bytes
	pub fn new(bytes: Vec<u8>) -> Self {
		Self { bytes }
	}

	/// Get the proof bytes
	pub fn as_bytes(&self) -> &[u8] {
		&self.bytes
	}

	/// Deserialize into an arkworks Groth16 proof
	pub fn to_ark_proof(&self) -> Result<ArkProof<Bn254>, VerifierError> {
		ArkProof::<Bn254>::deserialize_compressed(&self.bytes[..])
			.map_err(|_| VerifierError::InvalidProof)
	}

	/// Create from an arkworks proof
	pub fn from_ark_proof(proof: &ArkProof<Bn254>) -> Result<Self, VerifierError> {
		let mut bytes = Vec::new();
		proof
			.serialize_compressed(&mut bytes)
			.map_err(|_| VerifierError::SerializationError)?;
		Ok(Self { bytes })
	}
}

/// A verifying key for Groth16 proofs
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "substrate", derive(Encode, Decode, TypeInfo))]
pub struct VerifyingKey {
	/// Serialized verifying key bytes (compressed format)
	pub bytes: Vec<u8>,
}

impl VerifyingKey {
	/// Create a new verifying key from raw bytes
	pub fn new(bytes: Vec<u8>) -> Self {
		Self { bytes }
	}

	/// Get the verifying key bytes
	pub fn as_bytes(&self) -> &[u8] {
		&self.bytes
	}

	/// Deserialize into an arkworks verifying key
	pub fn to_ark_vk(&self) -> Result<ArkVK<Bn254>, VerifierError> {
		ArkVK::<Bn254>::deserialize_compressed(&self.bytes[..])
			.map_err(|_| VerifierError::InvalidVerifyingKey)
	}

	/// Create from an arkworks verifying key
	pub fn from_ark_vk(vk: &ArkVK<Bn254>) -> Result<Self, VerifierError> {
		let mut bytes = Vec::new();
		vk.serialize_compressed(&mut bytes)
			.map_err(|_| VerifierError::SerializationError)?;
		Ok(Self { bytes })
	}

	/// Prepare the verifying key for efficient verification
	pub fn prepare(&self) -> Result<PreparedVerifyingKey<Bn254>, VerifierError> {
		let vk = self.to_ark_vk()?;
		Ok(PreparedVerifyingKey::from(vk))
	}
}

/// Public inputs for a zero-knowledge proof
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "substrate", derive(Encode, Decode, TypeInfo))]
pub struct PublicInputs {
	/// Field elements representing the public inputs
	pub inputs: Vec<[u8; 32]>,
}

impl PublicInputs {
	/// Create new public inputs
	pub fn new(inputs: Vec<[u8; 32]>) -> Self {
		Self { inputs }
	}

	/// Get the number of public inputs
	pub fn len(&self) -> usize {
		self.inputs.len()
	}

	/// Check if public inputs is empty
	pub fn is_empty(&self) -> bool {
		self.inputs.is_empty()
	}

	/// Convert to arkworks field elements
	pub fn to_field_elements(&self) -> Result<Vec<Bn254Fr>, VerifierError> {
		use ark_ff::PrimeField;

		self.inputs
			.iter()
			.map(|bytes| {
				// Convert bytes to field element
				// Note: We store in big-endian but arkworks expects little-endian
				let mut bytes_le = *bytes;
				bytes_le.reverse();
				Ok(Bn254Fr::from_le_bytes_mod_order(&bytes_le))
			})
			.collect()
	}

	/// Create from field elements
	pub fn from_field_elements(elements: &[Bn254Fr]) -> Self {
		use ark_ff::{BigInteger, PrimeField};

		let inputs = elements
			.iter()
			.map(|elem| {
				let mut bytes = [0u8; 32];
				let elem_bytes = elem.into_bigint().to_bytes_be();
				let start = 32 - elem_bytes.len();
				bytes[start..].copy_from_slice(&elem_bytes);
				bytes
			})
			.collect();

		Self { inputs }
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use ark_ff::PrimeField;
	extern crate alloc;
	use alloc::vec;

	// === Proof Tests ===

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
		let invalid_bytes = vec![0u8; 10]; // Too small to be a valid proof
		let proof = Proof::new(invalid_bytes);
		let result = proof.to_ark_proof();
		assert!(result.is_err());
		assert!(matches!(result, Err(VerifierError::InvalidProof)));
	}

	#[test]
	fn test_proof_clone() {
		let bytes = vec![1, 2, 3];
		let proof1 = Proof::new(bytes);
		let proof2 = proof1.clone();
		assert_eq!(proof1, proof2);
	}

	#[test]
	fn test_proof_empty_bytes() {
		let proof = Proof::new(vec![]);
		assert!(proof.as_bytes().is_empty());
	}

	// === VerifyingKey Tests ===

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
		let invalid_bytes = vec![0u8; 10]; // Too small to be a valid VK
		let vk = VerifyingKey::new(invalid_bytes);
		let result = vk.to_ark_vk();
		assert!(result.is_err());
		assert!(matches!(result, Err(VerifierError::InvalidVerifyingKey)));
	}

	#[test]
	fn test_vk_prepare_invalid() {
		let invalid_bytes = vec![0u8; 10];
		let vk = VerifyingKey::new(invalid_bytes);
		let result = vk.prepare();
		assert!(result.is_err());
	}

	#[test]
	fn test_vk_clone() {
		let bytes = vec![1, 2, 3];
		let vk1 = VerifyingKey::new(bytes);
		let vk2 = vk1.clone();
		assert_eq!(vk1, vk2);
	}

	#[test]
	fn test_vk_empty_bytes() {
		let vk = VerifyingKey::new(vec![]);
		assert!(vk.as_bytes().is_empty());
	}

	// === PublicInputs Tests ===

	#[test]
	fn test_public_inputs_new() {
		let inputs = vec![[1u8; 32], [2u8; 32]];
		let public_inputs = PublicInputs::new(inputs.clone());
		assert_eq!(public_inputs.inputs, inputs);
	}

	#[test]
	fn test_public_inputs_len() {
		let inputs = vec![[0u8; 32]; 5];
		let public_inputs = PublicInputs::new(inputs);
		assert_eq!(public_inputs.len(), 5);
	}

	#[test]
	fn test_public_inputs_is_empty() {
		let empty = PublicInputs::new(vec![]);
		assert!(empty.is_empty());

		let non_empty = PublicInputs::new(vec![[0u8; 32]]);
		assert!(!non_empty.is_empty());
	}

	#[test]
	fn test_public_inputs_to_field_elements() {
		let inputs = vec![[1u8; 32], [2u8; 32]];
		let public_inputs = PublicInputs::new(inputs);
		let result = public_inputs.to_field_elements();
		assert!(result.is_ok());
		let elements = result.unwrap();
		assert_eq!(elements.len(), 2);
	}

	#[test]
	fn test_public_inputs_from_field_elements() {
		let elements = vec![Bn254Fr::from(123u64), Bn254Fr::from(456u64)];
		let public_inputs = PublicInputs::from_field_elements(&elements);
		assert_eq!(public_inputs.len(), 2);
	}

	#[test]
	fn test_public_inputs_roundtrip_conversion() {
		// Create field elements
		let original = vec![
			Bn254Fr::from(123u64),
			Bn254Fr::from(456u64),
			Bn254Fr::from(789u64),
		];

		// Convert to PublicInputs
		let public_inputs = PublicInputs::from_field_elements(&original);
		assert_eq!(public_inputs.len(), 3);

		// Convert back to field elements
		let converted = public_inputs.to_field_elements().unwrap();
		assert_eq!(converted.len(), 3);

		// Verify values match
		for (orig, conv) in original.iter().zip(converted.iter()) {
			assert_eq!(orig, conv);
		}
	}

	#[test]
	fn test_public_inputs_clone() {
		let inputs = vec![[1u8; 32], [2u8; 32]];
		let pi1 = PublicInputs::new(inputs);
		let pi2 = pi1.clone();
		assert_eq!(pi1, pi2);
	}

	#[test]
	fn test_public_inputs_empty() {
		let empty = PublicInputs::new(vec![]);
		assert_eq!(empty.len(), 0);
		assert!(empty.is_empty());
		let elements = empty.to_field_elements().unwrap();
		assert_eq!(elements.len(), 0);
	}

	#[test]
	fn test_public_inputs_large_values() {
		// Test with maximum field values
		let max_value = Bn254Fr::from_le_bytes_mod_order(&[0xff; 32]);
		let elements = vec![max_value, Bn254Fr::from(0u64), max_value];

		let public_inputs = PublicInputs::from_field_elements(&elements);
		let converted = public_inputs.to_field_elements().unwrap();

		assert_eq!(converted.len(), 3);
		assert_eq!(converted[0], elements[0]);
		assert_eq!(converted[1], elements[1]);
		assert_eq!(converted[2], elements[2]);
	}

	#[test]
	fn test_public_inputs_single_element() {
		let element = vec![Bn254Fr::from(42u64)];
		let public_inputs = PublicInputs::from_field_elements(&element);

		assert_eq!(public_inputs.len(), 1);
		assert!(!public_inputs.is_empty());

		let converted = public_inputs.to_field_elements().unwrap();
		assert_eq!(converted.len(), 1);
		assert_eq!(converted[0], element[0]);
	}

	#[test]
	fn test_public_inputs_many_elements() {
		let elements: Vec<Bn254Fr> = (0..32).map(|i| Bn254Fr::from(i as u64)).collect();
		let public_inputs = PublicInputs::from_field_elements(&elements);

		assert_eq!(public_inputs.len(), 32);

		let converted = public_inputs.to_field_elements().unwrap();
		assert_eq!(converted.len(), 32);

		for (i, (orig, conv)) in elements.iter().zip(converted.iter()).enumerate() {
			assert_eq!(orig, conv, "Mismatch at index {i}");
		}
	}
}
