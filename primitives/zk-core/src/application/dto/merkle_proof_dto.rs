//! Merkle Proof Data Transfer Object
//!
//! DTO representing a Merkle proof for external APIs and serialization.
//!
//! Provides serializable format for Merkle proofs, enabling conversion
//! between domain representation ([`MerklePath`]) and external formats.

use crate::domain::{
	repositories::MerklePath,
	value_objects::{Commitment, FieldElement},
};
use alloc::{string::String, vec::Vec};
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
	extern crate alloc;
	use alloc::{format, vec};

	// new() tests
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
	fn test_new_with_zero_index() {
		let leaf = [1u8; 32];
		let siblings = vec![[2u8; 32]];
		let root = [3u8; 32];

		let dto = MerkleProofDto::new(0, leaf, siblings, root);
		assert_eq!(dto.leaf_index, 0);
	}

	#[test]
	fn test_new_with_max_index() {
		let leaf = [1u8; 32];
		let siblings = vec![];
		let root = [2u8; 32];

		let dto = MerkleProofDto::new(u64::MAX, leaf, siblings, root);
		assert_eq!(dto.leaf_index, u64::MAX);
	}

	#[test]
	fn test_new_with_many_siblings() {
		let leaf = [1u8; 32];
		let siblings = vec![[2u8; 32]; 32]; // 32 siblings = depth 32
		let root = [3u8; 32];

		let dto = MerkleProofDto::new(10, leaf, siblings, root);
		assert_eq!(dto.depth(), 32);
	}

	// depth() tests
	#[test]
	fn test_depth_zero_siblings() {
		let dto = MerkleProofDto::new(0, [1u8; 32], vec![], [2u8; 32]);
		assert_eq!(dto.depth(), 0);
	}

	#[test]
	fn test_depth_one_sibling() {
		let dto = MerkleProofDto::new(0, [1u8; 32], vec![[2u8; 32]], [3u8; 32]);
		assert_eq!(dto.depth(), 1);
	}

	#[test]
	fn test_depth_multiple_siblings() {
		let dto = MerkleProofDto::new(0, [1u8; 32], vec![[2u8; 32]; 10], [3u8; 32]);
		assert_eq!(dto.depth(), 10);
	}

	// from_domain() tests
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
	fn test_from_domain_with_zero_values() {
		let commitment = Commitment::from(Fr::from(0u64));
		let siblings = vec![FieldElement::from_u64(0)];
		let path = MerklePath::new(0, siblings);
		let root = FieldElement::from_u64(0);

		let dto = MerkleProofDto::from_domain(&commitment, &path, &root);

		assert_eq!(dto.leaf_index, 0);
		assert_eq!(dto.depth(), 1);
		// Zero values should produce zero bytes
		assert!(dto.leaf.iter().all(|&b| b == 0));
		assert!(dto.root.iter().all(|&b| b == 0));
	}

	#[test]
	fn test_from_domain_with_large_values() {
		let commitment = Commitment::from(Fr::from(u64::MAX));
		let siblings = vec![
			FieldElement::from_u64(u64::MAX),
			FieldElement::from_u64(u64::MAX / 2),
		];
		let path = MerklePath::new(u64::MAX, siblings);
		let root = FieldElement::from_u64(u64::MAX);

		let dto = MerkleProofDto::from_domain(&commitment, &path, &root);

		assert_eq!(dto.leaf_index, u64::MAX);
		assert_eq!(dto.depth(), 2);
	}

	#[test]
	fn test_from_domain_empty_siblings() {
		let commitment = Commitment::from(Fr::from(42u64));
		let path = MerklePath::new(5, vec![]);
		let root = FieldElement::from_u64(100);

		let dto = MerkleProofDto::from_domain(&commitment, &path, &root);

		assert_eq!(dto.depth(), 0);
		assert_eq!(dto.siblings.len(), 0);
	}

	#[test]
	fn test_from_domain_many_siblings() {
		let commitment = Commitment::from(Fr::from(1u64));
		let siblings: Vec<FieldElement> = (0..20).map(FieldElement::from_u64).collect();
		let path = MerklePath::new(7, siblings);
		let root = FieldElement::from_u64(999);

		let dto = MerkleProofDto::from_domain(&commitment, &path, &root);

		assert_eq!(dto.depth(), 20);
		assert_eq!(dto.siblings.len(), 20);
	}

	// to_domain() tests
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
	fn test_to_domain_zero_bytes() {
		let leaf = [0u8; 32];
		let siblings = vec![[0u8; 32]];
		let root = [0u8; 32];
		let dto = MerkleProofDto::new(0, leaf, siblings, root);

		let result = dto.to_domain();
		assert!(result.is_ok());

		let (commitment, siblings, root) = result.unwrap();
		assert_eq!(commitment.inner().inner(), Fr::from(0u64));
		assert_eq!(siblings.len(), 1);
		assert_eq!(root.inner(), Fr::from(0u64));
	}

	#[test]
	fn test_to_domain_empty_siblings() {
		let leaf = [1u8; 32];
		let siblings = vec![];
		let root = [2u8; 32];
		let dto = MerkleProofDto::new(0, leaf, siblings, root);

		let result = dto.to_domain();
		assert!(result.is_ok());

		let (_commitment, siblings, _root) = result.unwrap();
		assert_eq!(siblings.len(), 0);
	}

	#[test]
	fn test_to_domain_max_bytes() {
		let leaf = [0xFFu8; 32];
		let siblings = vec![[0xFFu8; 32]];
		let root = [0xFFu8; 32];
		let dto = MerkleProofDto::new(0, leaf, siblings, root);

		let result = dto.to_domain();
		assert!(result.is_ok());
	}

	#[test]
	fn test_to_domain_many_siblings() {
		let leaf = [1u8; 32];
		let siblings = vec![[2u8; 32]; 15];
		let root = [3u8; 32];
		let dto = MerkleProofDto::new(7, leaf, siblings, root);

		let result = dto.to_domain();
		assert!(result.is_ok());

		let (_commitment, siblings, _root) = result.unwrap();
		assert_eq!(siblings.len(), 15);
	}

	// Roundtrip tests
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
	fn test_roundtrip_zero_values() {
		let commitment = Commitment::from(Fr::from(0u64));
		let siblings = vec![FieldElement::from_u64(0)];
		let path = MerklePath::new(0, siblings);
		let root = FieldElement::from_u64(0);

		let dto = MerkleProofDto::from_domain(&commitment, &path, &root);
		let (converted_commitment, converted_siblings, converted_root) = dto.to_domain().unwrap();

		assert_eq!(converted_commitment.inner().inner(), Fr::from(0u64));
		assert_eq!(converted_siblings.len(), 1);
		assert_eq!(converted_root.inner(), Fr::from(0u64));
	}

	#[test]
	fn test_roundtrip_large_values() {
		let commitment = Commitment::from(Fr::from(999999u64));
		let siblings = vec![
			FieldElement::from_u64(111111),
			FieldElement::from_u64(222222),
			FieldElement::from_u64(333333),
		];
		let path = MerklePath::new(12345, siblings.clone());
		let root = FieldElement::from_u64(888888);

		let dto = MerkleProofDto::from_domain(&commitment, &path, &root);
		let (_converted_commitment, converted_siblings, _converted_root) = dto.to_domain().unwrap();

		assert_eq!(converted_siblings.len(), siblings.len());
	}

	#[test]
	fn test_roundtrip_empty_siblings() {
		let commitment = Commitment::from(Fr::from(42u64));
		let path = MerklePath::new(7, vec![]);
		let root = FieldElement::from_u64(100);

		let dto = MerkleProofDto::from_domain(&commitment, &path, &root);
		let (_converted_commitment, converted_siblings, _converted_root) = dto.to_domain().unwrap();

		assert_eq!(converted_siblings.len(), 0);
	}

	#[test]
	fn test_roundtrip_preserves_leaf_index() {
		let commitment = Commitment::from(Fr::from(42u64));
		let siblings = vec![FieldElement::from_u64(1)];
		let path = MerklePath::new(12345, siblings);
		let root = FieldElement::from_u64(100);

		let dto = MerkleProofDto::from_domain(&commitment, &path, &root);
		assert_eq!(dto.leaf_index, 12345);
	}

	// field_to_bytes and bytes_to_field tests
	#[test]
	fn test_field_bytes_conversion_zero() {
		let field = Fr::from(0u64);
		let bytes = MerkleProofDto::field_to_bytes(&field);
		let converted = MerkleProofDto::bytes_to_field(&bytes).unwrap();
		assert_eq!(field, converted);
	}

	#[test]
	fn test_field_bytes_conversion_one() {
		let field = Fr::from(1u64);
		let bytes = MerkleProofDto::field_to_bytes(&field);
		let converted = MerkleProofDto::bytes_to_field(&bytes).unwrap();
		assert_eq!(field, converted);
	}

	#[test]
	fn test_field_bytes_conversion_large() {
		let field = Fr::from(u64::MAX);
		let bytes = MerkleProofDto::field_to_bytes(&field);
		let converted = MerkleProofDto::bytes_to_field(&bytes).unwrap();
		assert_eq!(field, converted);
	}

	#[test]
	fn test_field_bytes_conversion_random() {
		let values = [123u64, 456, 789, 1000000, 999999999];
		for value in values {
			let field = Fr::from(value);
			let bytes = MerkleProofDto::field_to_bytes(&field);
			let converted = MerkleProofDto::bytes_to_field(&bytes).unwrap();
			assert_eq!(field, converted, "Failed for value {value}");
		}
	}

	#[test]
	fn test_bytes_to_field_all_zeros() {
		let bytes = [0u8; 32];
		let field = MerkleProofDto::bytes_to_field(&bytes).unwrap();
		assert_eq!(field, Fr::from(0u64));
	}

	#[test]
	fn test_bytes_to_field_all_ones() {
		let bytes = [1u8; 32];
		let field = MerkleProofDto::bytes_to_field(&bytes);
		assert!(field.is_ok());
	}

	// Clone and PartialEq tests
	#[test]
	fn test_clone() {
		let leaf = [1u8; 32];
		let siblings = vec![[2u8; 32], [3u8; 32]];
		let root = [4u8; 32];
		let dto = MerkleProofDto::new(5, leaf, siblings, root);

		let cloned = dto.clone();
		assert_eq!(dto, cloned);
	}

	#[test]
	fn test_equality_same_values() {
		let leaf = [1u8; 32];
		let siblings = vec![[2u8; 32]];
		let root = [3u8; 32];

		let dto1 = MerkleProofDto::new(5, leaf, siblings.clone(), root);
		let dto2 = MerkleProofDto::new(5, leaf, siblings, root);

		assert_eq!(dto1, dto2);
	}

	#[test]
	fn test_inequality_different_index() {
		let leaf = [1u8; 32];
		let siblings = vec![[2u8; 32]];
		let root = [3u8; 32];

		let dto1 = MerkleProofDto::new(5, leaf, siblings.clone(), root);
		let dto2 = MerkleProofDto::new(6, leaf, siblings, root);

		assert_ne!(dto1, dto2);
	}

	#[test]
	fn test_inequality_different_leaf() {
		let siblings = vec![[2u8; 32]];
		let root = [3u8; 32];

		let dto1 = MerkleProofDto::new(5, [1u8; 32], siblings.clone(), root);
		let dto2 = MerkleProofDto::new(5, [99u8; 32], siblings, root);

		assert_ne!(dto1, dto2);
	}

	#[test]
	fn test_inequality_different_siblings() {
		let leaf = [1u8; 32];
		let root = [3u8; 32];

		let dto1 = MerkleProofDto::new(5, leaf, vec![[2u8; 32]], root);
		let dto2 = MerkleProofDto::new(5, leaf, vec![[99u8; 32]], root);

		assert_ne!(dto1, dto2);
	}

	#[test]
	fn test_inequality_different_root() {
		let leaf = [1u8; 32];
		let siblings = vec![[2u8; 32]];

		let dto1 = MerkleProofDto::new(5, leaf, siblings.clone(), [3u8; 32]);
		let dto2 = MerkleProofDto::new(5, leaf, siblings, [99u8; 32]);

		assert_ne!(dto1, dto2);
	}

	#[test]
	fn test_inequality_different_sibling_count() {
		let leaf = [1u8; 32];
		let root = [3u8; 32];

		let dto1 = MerkleProofDto::new(5, leaf, vec![[2u8; 32]], root);
		let dto2 = MerkleProofDto::new(5, leaf, vec![[2u8; 32], [4u8; 32]], root);

		assert_ne!(dto1, dto2);
	}

	// Edge cases
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

	#[test]
	fn test_large_tree_depth() {
		let leaf = [1u8; 32];
		let siblings = vec![[2u8; 32]; 32];
		let root = [3u8; 32];

		let dto = MerkleProofDto::new(0, leaf, siblings, root);
		assert_eq!(dto.depth(), 32);
		assert!(dto.to_domain().is_ok());
	}

	#[test]
	fn test_max_leaf_index() {
		let dto = MerkleProofDto::new(u64::MAX, [1u8; 32], vec![], [2u8; 32]);
		assert_eq!(dto.leaf_index, u64::MAX);
	}

	// Debug trait test
	#[test]
	fn test_debug_format() {
		let dto = MerkleProofDto::new(5, [1u8; 32], vec![[2u8; 32]], [3u8; 32]);
		let debug_str = format!("{dto:?}");
		assert!(debug_str.contains("MerkleProofDto"));
		assert!(debug_str.contains("leaf_index"));
	}

	// Serialization tests (only with std feature)
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

	#[cfg(feature = "std")]
	#[test]
	fn test_serialization_empty_siblings() {
		let dto = MerkleProofDto::new(0, [1u8; 32], vec![], [2u8; 32]);

		let json = serde_json::to_string(&dto).unwrap();
		let deserialized: MerkleProofDto = serde_json::from_str(&json).unwrap();

		assert_eq!(dto, deserialized);
	}

	#[cfg(feature = "std")]
	#[test]
	fn test_serialization_large_values() {
		let dto = MerkleProofDto::new(u64::MAX, [0xFFu8; 32], vec![[0xFFu8; 32]; 5], [0xFFu8; 32]);

		let json = serde_json::to_string(&dto).unwrap();
		let deserialized: MerkleProofDto = serde_json::from_str(&json).unwrap();

		assert_eq!(dto, deserialized);
	}
}
