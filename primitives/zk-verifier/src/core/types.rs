//! # Common Types
//!
//! Shared types used across the ZK verifier primitives.

use alloc::vec::Vec;

use ark_groth16::{PreparedVerifyingKey, Proof as ArkProof, VerifyingKey as ArkVK};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

#[cfg(feature = "substrate")]
use parity_scale_codec::{Decode, Encode};
#[cfg(feature = "substrate")]
use scale_info::TypeInfo;
#[cfg(feature = "substrate")]
use sp_runtime::RuntimeDebug;

use crate::{Bn254, Bn254Fr, VerifierError};

/// A Groth16 proof that can be serialized/deserialized for on-chain storage
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "substrate", derive(Encode, Decode, TypeInfo, RuntimeDebug))]
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
#[cfg_attr(feature = "substrate", derive(Encode, Decode, TypeInfo, RuntimeDebug))]
pub struct PublicInputs {
	/// Field elements representing the public inputs
	pub inputs: Vec<[u8; 32]>,
}

impl PublicInputs {
	/// Create new public inputs
	pub fn new(inputs: Vec<[u8; 32]>) -> Self {
		Self { inputs }
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
