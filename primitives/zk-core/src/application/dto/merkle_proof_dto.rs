//! Merkle Proof Data Transfer Object
//!
//! This DTO represents a Merkle proof for external APIs and serialization.
//!

//! DTOs are part of the **Application Layer** for data exchange.
//!

//! - Provide serializable proof format
//! - Convert between domain and external representations
//! - Support various proof verification scenarios

use alloc::{string::String, vec::Vec};
use crate::domain::{
	repositories::MerklePath,
	value_objects::{Commitment, FieldElement},
};
use ark_bn254::Fr;

/// Data Transfer Object for Merkle Proof
///
/// This represents a Merkle proof in a format suitable for external APIs,
/// serialization, and transmission over the network.
///
/// ## Structure
/// - `leaf_index`: Position of the leaf in the tree
/// - `leaf`: The commitment being proved
/// - `siblings`: Sibling hashes along the path to root
/// - `root`: The expected Merkle root
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
pub struct MerkleProofDto {
	/// Index of the leaf in the tree
	pub leaf_index: u64,
	/// The commitment (leaf) being proved (32 bytes)
	pub leaf: [u8; 32],
	/// Sibling hashes along the path (each 32 bytes)
	pub siblings: Vec<[u8; 32]>,
	/// Expected Merkle root (32 bytes)
	pub root: [u8; 32],
}

impl MerkleProofDto {
	/// Create a new MerkleProofDto
	pub fn new(leaf_index: u64, leaf: [u8; 32], siblings: Vec<[u8; 32]>, root: [u8; 32]) -> Self {
		Self {
			leaf_index,
			leaf,
			siblings,
			root,
		}
	}

	/// Convert from domain MerklePath and commitment
	///
	/// # Arguments
	/// - `commitment`: The leaf commitment
	/// - `path`: The Merkle path from domain
	/// - `root`: The expected root
	pub fn from_domain(commitment: &Commitment, path: &MerklePath, root: &FieldElement) -> Self {
		let leaf_bytes = Self::field_to_bytes(&commitment.inner().inner());
		let siblings_bytes: Vec<[u8; 32]> = path
			.siblings
			.iter()
			.map(|s| Self::field_to_bytes(&s.inner()))
			.collect();
		let root_bytes = Self::field_to_bytes(&root.inner());

		Self {
			leaf_index: path.leaf_index,
			leaf: leaf_bytes,
			siblings: siblings_bytes,
			root: root_bytes,
		}
	}

	/// Convert to domain types
	///
	/// # Returns
	/// - `Ok((Commitment, Vec<FieldElement>, FieldElement))`: Domain types
	/// - `Err(String)`: If conversion fails
	pub fn to_domain(&self) -> Result<(Commitment, Vec<FieldElement>, FieldElement), String> {
		let commitment = Commitment::from(Self::bytes_to_field(&self.leaf)?);

		let siblings: Result<Vec<FieldElement>, String> = self
			.siblings
			.iter()
			.map(|bytes| Self::bytes_to_field(bytes).map(FieldElement::from))
			.collect();

		let root = FieldElement::from(Self::bytes_to_field(&self.root)?);

		Ok((commitment, siblings?, root))
	}

	/// Get the depth of the proof (number of siblings)
	pub fn depth(&self) -> usize {
		self.siblings.len()
	}

	/// Convert field element to bytes
	fn field_to_bytes(field: &Fr) -> [u8; 32] {
		use ark_ff::PrimeField;
		let mut bytes = [0u8; 32];
		// Use arkworks serialization API
		let bigint = field.into_bigint();
		// Extract bytes from BigInt (4 limbs of 64 bits each)
		for (i, limb) in bigint.0.iter().enumerate() {
			let start = i * 8;
			if start < 32 {
				let limb_bytes = limb.to_le_bytes();
				let len = core::cmp::min(8, 32 - start);
				bytes[start..start + len].copy_from_slice(&limb_bytes[..len]);
			}
		}
		bytes
	}

	/// Convert bytes to field element
	fn bytes_to_field(bytes: &[u8; 32]) -> Result<Fr, String> {
		use ark_ff::PrimeField;
		Ok(Fr::from_le_bytes_mod_order(bytes))
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_merkle_proof_dto_creation() {
		let leaf = [1u8; 32];
		let siblings = vec![[2u8; 32], [3u8; 32]];
		let root = [4u8; 32];

		let dto = MerkleProofDto::new(5, leaf, siblings.clone(), root);

		assert_eq!(dto.leaf_index, 5);
		assert_eq!(dto.leaf, leaf);
		assert_eq!(dto.siblings, siblings);
		assert_eq!(dto.root, root);
		assert_eq!(dto.depth(), 2);
	}

	#[test]
	fn test_from_domain() {
		let commitment = Commitment::from(Fr::from(123u64));
		let siblings = vec![
			FieldElement::from_u64(1),
			FieldElement::from_u64(2),
			FieldElement::from_u64(3),
		];
		let path = MerklePath::new(10, siblings.clone());
		let root = FieldElement::from_u64(999);

		let dto = MerkleProofDto::from_domain(&commitment, &path, &root);

		assert_eq!(dto.leaf_index, 10);
		assert_eq!(dto.depth(), 3);
	}

	#[test]
	fn test_to_domain() {
		let leaf = [1u8; 32];
		let siblings = vec![[2u8; 32], [3u8; 32]];
		let root = [4u8; 32];
		let dto = MerkleProofDto::new(5, leaf, siblings, root);

		let result = dto.to_domain();
		assert!(result.is_ok());

		let (_commitment, siblings, _root) = result.unwrap();
		assert_eq!(siblings.len(), 2);
	}

	#[test]
	fn test_round_trip() {
		let commitment = Commitment::from(Fr::from(42u64));
		let siblings = vec![FieldElement::from_u64(1), FieldElement::from_u64(2)];
		let path = MerklePath::new(7, siblings.clone());
		let root = FieldElement::from_u64(100);

		// Domain -> DTO -> Domain
		let dto = MerkleProofDto::from_domain(&commitment, &path, &root);
		let (_converted_commitment, converted_siblings, _converted_root) = dto.to_domain().unwrap();

		assert_eq!(converted_siblings.len(), siblings.len());
	}

	#[test]
	fn test_empty_siblings() {
		let leaf = [1u8; 32];
		let siblings = vec![];
		let root = [2u8; 32];

		let dto = MerkleProofDto::new(0, leaf, siblings, root);

		assert_eq!(dto.depth(), 0);
		assert!(dto.to_domain().is_ok());
	}

	#[test]
	fn test_dto_equality() {
		let leaf = [1u8; 32];
		let siblings = vec![[2u8; 32]];
		let root = [3u8; 32];

		let dto1 = MerkleProofDto::new(5, leaf, siblings.clone(), root);
		let dto2 = MerkleProofDto::new(5, leaf, siblings, root);

		assert_eq!(dto1, dto2);
	}

	#[cfg(feature = "std")]
	#[test]
	fn test_serialization() {
		let leaf = [1u8; 32];
		let siblings = vec![[2u8; 32], [3u8; 32]];
		let root = [4u8; 32];
		let dto = MerkleProofDto::new(5, leaf, siblings, root);

		// Test JSON serialization
		let json = serde_json::to_string(&dto).unwrap();
		let deserialized: MerkleProofDto = serde_json::from_str(&json).unwrap();

		assert_eq!(dto, deserialized);
	}
}
