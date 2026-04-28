//! Core Types for ZK Circuits
//!
//! Contains the fundamental data structures used across gadgets and circuits:
//! - [`Note`]: Private note in the shielded pool
//! - [`MerklePath`]: Merkle authentication path
//! - [`TreeDepth`]: Validated tree depth constraint
//! - [`ValidationError`]: Circuit validation errors
//! - [`CircuitValidator`]: Stateless validation helpers

use ark_bn254::Fr as Bn254Fr;

extern crate alloc;
use alloc::vec::Vec;

// ============================================================================
// Note
// ============================================================================

/// Private note in the shielded pool
///
/// `commitment = Poseidon(value, asset_id, owner_pubkey, blinding)`
/// `nullifier  = Poseidon(commitment, spending_key)`
#[derive(Clone, Debug, PartialEq)]
pub struct Note {
	/// Token amount
	pub value: Bn254Fr,
	/// Token type identifier
	pub asset_id: Bn254Fr,
	/// Public key of note owner
	pub owner_pubkey: Bn254Fr,
	/// Random blinding factor
	pub blinding: Bn254Fr,
}

impl Note {
	/// Creates a new note
	pub fn new(value: u64, asset_id: u64, owner_pubkey: Bn254Fr, blinding: Bn254Fr) -> Self {
		Self {
			value: Bn254Fr::from(value),
			asset_id: Bn254Fr::from(asset_id),
			owner_pubkey,
			blinding,
		}
	}

	/// Computes the commitment for this note
	pub fn commitment(&self) -> Bn254Fr {
		crate::native::poseidon_hash_4(&[
			self.value,
			self.asset_id,
			self.owner_pubkey,
			self.blinding,
		])
	}

	/// Computes the nullifier for this note
	pub fn nullifier(&self, spending_key: Bn254Fr) -> Bn254Fr {
		crate::native::poseidon_hash_2(&[self.commitment(), spending_key])
	}

	/// Creates a zero note (for padding in fixed-size circuits)
	pub fn zero() -> Self {
		Self {
			value: Bn254Fr::from(0u64),
			asset_id: Bn254Fr::from(0u64),
			owner_pubkey: Bn254Fr::from(0u64),
			blinding: Bn254Fr::from(0u64),
		}
	}
}

// ============================================================================
// Native helpers (pub(crate) for use in gadget tests)
// ============================================================================

/// Compute note commitment natively (non-R1CS)
///
/// `commitment = Poseidon(value, asset_id, owner_pubkey, blinding)`
#[allow(dead_code)]
pub(crate) fn note_commitment_native(
	value: Bn254Fr,
	asset_id: Bn254Fr,
	owner_pubkey: Bn254Fr,
	blinding: Bn254Fr,
) -> Bn254Fr {
	crate::native::poseidon_hash_4(&[value, asset_id, owner_pubkey, blinding])
}

/// Compute nullifier natively (non-R1CS)
///
/// `nullifier = Poseidon(commitment, spending_key)`
pub(crate) fn nullifier_native(commitment: Bn254Fr, spending_key: Bn254Fr) -> Bn254Fr {
	crate::native::poseidon_hash_2(&[commitment, spending_key])
}

// ============================================================================
// MerklePath
// ============================================================================

/// Merkle authentication path
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerklePath {
	/// Sibling hashes from leaf to root
	pub elements: Vec<Bn254Fr>,
	/// Position bits (0 = left, 1 = right)
	pub positions: Vec<bool>,
}

impl MerklePath {
	/// Create a new merkle path
	pub fn new(elements: Vec<Bn254Fr>, positions: Vec<bool>) -> Self {
		Self {
			elements,
			positions,
		}
	}

	/// Get path depth (number of levels)
	pub fn depth(&self) -> usize {
		self.elements.len()
	}

	/// Validate path consistency (elements and positions must have same length)
	pub fn validate(&self) -> Result<(), &'static str> {
		if self.elements.len() != self.positions.len() {
			return Err("Path elements and positions length mismatch");
		}
		Ok(())
	}
}

// ============================================================================
// TreeDepth
// ============================================================================

/// Merkle tree depth with validation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TreeDepth(pub usize);

impl TreeDepth {
	/// Standard depth for the shielded pool (20 levels)
	pub const STANDARD: Self = Self(20);

	/// Maximum allowed depth
	pub const MAX: Self = Self(32);

	/// Create a new depth with validation
	pub fn new(depth: usize) -> Result<Self, &'static str> {
		if depth == 0 {
			return Err("Tree depth must be positive");
		}
		if depth > Self::MAX.0 {
			return Err("Tree depth exceeds maximum");
		}
		Ok(Self(depth))
	}

	/// Get depth value
	pub fn value(&self) -> usize {
		self.0
	}
}

impl Default for TreeDepth {
	fn default() -> Self {
		Self::STANDARD
	}
}

// ============================================================================
// ValidationError
// ============================================================================

/// Circuit validation errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationError {
	/// Merkle path length does not match tree depth
	InvalidPathLength { expected: usize, got: usize },
	/// Asset ID mismatch in transfer
	AssetMismatch { input: u64, output: u64 },
	/// Value conservation violation
	ValueImbalance { inputs: u64, outputs: u64 },
	/// Nullifier already spent
	DuplicateNullifier,
}

// ============================================================================
// CircuitValidator
// ============================================================================

/// Stateless validation helpers for circuit witness data
pub struct CircuitValidator;

impl CircuitValidator {
	/// Validate that a merkle path length matches the expected tree depth
	pub fn validate_path_length(
		path_length: usize,
		tree_depth: TreeDepth,
	) -> Result<(), ValidationError> {
		if path_length != tree_depth.value() {
			return Err(ValidationError::InvalidPathLength {
				expected: tree_depth.value(),
				got: path_length,
			});
		}
		Ok(())
	}

	/// Validate that input and output assets are consistent
	pub fn validate_asset_consistency(
		input_asset: u64,
		output_asset: u64,
	) -> Result<(), ValidationError> {
		if input_asset != output_asset {
			return Err(ValidationError::AssetMismatch {
				input: input_asset,
				output: output_asset,
			});
		}
		Ok(())
	}

	/// Validate that sum(inputs) == sum(outputs)
	pub fn validate_value_balance(
		input_values: &[u64],
		output_values: &[u64],
	) -> Result<(), ValidationError> {
		let total_in: u64 = input_values.iter().sum();
		let total_out: u64 = output_values.iter().sum();

		if total_in != total_out {
			return Err(ValidationError::ValueImbalance {
				inputs: total_in,
				outputs: total_out,
			});
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
	extern crate alloc;
	use alloc::{format, vec, vec::Vec};

	// ===== Note Tests =====

	#[test]
	fn test_note_new() {
		let owner = Bn254Fr::from(12345u64);
		let blinding = Bn254Fr::from(67890u64);
		let note = Note::new(1000, 1, owner, blinding);
		assert_eq!(note.value, Bn254Fr::from(1000u64));
		assert_eq!(note.asset_id, Bn254Fr::from(1u64));
		assert_eq!(note.owner_pubkey, owner);
		assert_eq!(note.blinding, blinding);
	}

	#[test]
	fn test_note_struct() {
		let owner = Bn254Fr::from(12345u64);
		let blinding = Bn254Fr::from(67890u64);
		let spending_key = Bn254Fr::from(11111u64);
		let note = Note::new(1000, 1, owner, blinding);
		let c1 = note.commitment();
		let c2 = note.commitment();
		assert_eq!(c1, c2);
		let nf = note.nullifier(spending_key);
		let expected_nf = nullifier_native(c1, spending_key);
		assert_eq!(nf, expected_nf);
	}

	#[test]
	fn test_note_commitment_method() {
		let owner = Bn254Fr::from(100u64);
		let blinding = Bn254Fr::from(200u64);
		let note = Note::new(1000, 1, owner, blinding);
		let commitment = note.commitment();
		let expected =
			note_commitment_native(note.value, note.asset_id, note.owner_pubkey, note.blinding);
		assert_eq!(commitment, expected);
	}

	#[test]
	fn test_note_nullifier_method() {
		let owner = Bn254Fr::from(100u64);
		let blinding = Bn254Fr::from(200u64);
		let spending_key = Bn254Fr::from(300u64);
		let note = Note::new(1000, 1, owner, blinding);
		let nullifier = note.nullifier(spending_key);
		let expected = nullifier_native(note.commitment(), spending_key);
		assert_eq!(nullifier, expected);
	}

	#[test]
	fn test_note_zero() {
		let zero_note = Note::zero();
		assert_eq!(zero_note.value, Bn254Fr::from(0u64));
		assert_eq!(zero_note.asset_id, Bn254Fr::from(0u64));
		let commitment = zero_note.commitment();
		assert_ne!(commitment, Bn254Fr::from(0u64));
	}

	#[test]
	fn test_note_clone() {
		let owner = Bn254Fr::from(100u64);
		let blinding = Bn254Fr::from(200u64);
		let note1 = Note::new(1000, 1, owner, blinding);
		let note2 = note1.clone();
		assert_eq!(note1, note2);
		assert_eq!(note1.commitment(), note2.commitment());
	}

	#[test]
	fn test_note_equality() {
		let owner = Bn254Fr::from(100u64);
		let blinding = Bn254Fr::from(200u64);
		let note1 = Note::new(1000, 1, owner, blinding);
		let note2 = Note::new(1000, 1, owner, blinding);
		assert_eq!(note1, note2);
	}

	#[test]
	fn test_note_inequality() {
		let owner = Bn254Fr::from(100u64);
		let note1 = Note::new(1000, 1, owner, Bn254Fr::from(200u64));
		let note2 = Note::new(1000, 1, owner, Bn254Fr::from(300u64));
		assert_ne!(note1, note2);
	}

	#[test]
	fn test_note_debug() {
		let note = Note::new(1000, 1, Bn254Fr::from(100u64), Bn254Fr::from(200u64));
		let debug_str = format!("{note:?}");
		assert!(debug_str.contains("Note"));
	}

	#[test]
	fn test_commitment_and_nullifier_workflow() {
		let owner = Bn254Fr::from(12345u64);
		let blinding = Bn254Fr::from(67890u64);
		let spending_key = Bn254Fr::from(11111u64);
		let note = Note::new(1000, 1, owner, blinding);
		let commitment = note.commitment();
		assert_ne!(commitment, Bn254Fr::from(0u64));
		let nullifier = note.nullifier(spending_key);
		assert_ne!(nullifier, Bn254Fr::from(0u64));
		let note2 = Note::new(2000, 1, owner, blinding);
		assert_ne!(note.commitment(), note2.commitment());
	}

	#[test]
	fn test_same_note_different_spending_keys() {
		let note = Note::new(1000, 1, Bn254Fr::from(100u64), Bn254Fr::from(200u64));
		let nf1 = note.nullifier(Bn254Fr::from(100u64));
		let nf2 = note.nullifier(Bn254Fr::from(200u64));
		assert_ne!(nf1, nf2);
	}

	// ===== note_commitment_native Tests =====

	#[test]
	fn test_note_commitment_native_basic() {
		let value = Bn254Fr::from(1000u64);
		let asset_id = Bn254Fr::from(1u64);
		let owner = Bn254Fr::from(12345u64);
		let blinding = Bn254Fr::from(67890u64);
		let commitment = note_commitment_native(value, asset_id, owner, blinding);
		assert_ne!(commitment, Bn254Fr::from(0u64));
	}

	#[test]
	fn test_note_commitment_native() {
		let value = Bn254Fr::from(1000u64);
		let asset_id = Bn254Fr::from(1u64);
		let owner = Bn254Fr::from(12345u64);
		let blinding = Bn254Fr::from(67890u64);
		let c1 = note_commitment_native(value, asset_id, owner, blinding);
		let c2 = note_commitment_native(value, asset_id, owner, blinding);
		assert_eq!(c1, c2);
		let blinding2 = Bn254Fr::from(99999u64);
		let c3 = note_commitment_native(value, asset_id, owner, blinding2);
		assert_ne!(c1, c3);
	}

	#[test]
	fn test_note_commitment_native_different_values() {
		let asset_id = Bn254Fr::from(1u64);
		let owner = Bn254Fr::from(100u64);
		let blinding = Bn254Fr::from(200u64);
		let c1 = note_commitment_native(Bn254Fr::from(1000u64), asset_id, owner, blinding);
		let c2 = note_commitment_native(Bn254Fr::from(2000u64), asset_id, owner, blinding);
		assert_ne!(c1, c2);
	}

	#[test]
	fn test_note_commitment_native_different_asset_ids() {
		let value = Bn254Fr::from(1000u64);
		let owner = Bn254Fr::from(100u64);
		let blinding = Bn254Fr::from(200u64);
		let c1 = note_commitment_native(value, Bn254Fr::from(1u64), owner, blinding);
		let c2 = note_commitment_native(value, Bn254Fr::from(2u64), owner, blinding);
		assert_ne!(c1, c2);
	}

	#[test]
	fn test_note_commitment_native_different_owners() {
		let value = Bn254Fr::from(1000u64);
		let asset_id = Bn254Fr::from(1u64);
		let blinding = Bn254Fr::from(200u64);
		let c1 = note_commitment_native(value, asset_id, Bn254Fr::from(100u64), blinding);
		let c2 = note_commitment_native(value, asset_id, Bn254Fr::from(200u64), blinding);
		assert_ne!(c1, c2);
	}

	#[test]
	fn test_note_commitment_native_large_values() {
		let value = Bn254Fr::from(u64::MAX);
		let asset_id = Bn254Fr::from(u64::MAX - 1);
		let owner = Bn254Fr::from(u64::MAX - 2);
		let blinding = Bn254Fr::from(u64::MAX - 3);
		let commitment = note_commitment_native(value, asset_id, owner, blinding);
		assert_ne!(commitment, Bn254Fr::from(0u64));
	}

	// ===== nullifier_native Tests =====

	#[test]
	fn test_nullifier_native_basic() {
		let commitment = Bn254Fr::from(123456u64);
		let spending_key = Bn254Fr::from(789012u64);
		let nf = nullifier_native(commitment, spending_key);
		assert_ne!(nf, Bn254Fr::from(0u64));
	}

	#[test]
	fn test_nullifier_native() {
		let commitment = Bn254Fr::from(123456u64);
		let spending_key = Bn254Fr::from(789012u64);
		let nf1 = nullifier_native(commitment, spending_key);
		let nf2 = nullifier_native(commitment, spending_key);
		assert_eq!(nf1, nf2);
		let nf3 = nullifier_native(commitment, Bn254Fr::from(111111u64));
		assert_ne!(nf1, nf3);
	}

	#[test]
	fn test_nullifier_native_different_commitments() {
		let spending_key = Bn254Fr::from(789012u64);
		let nf1 = nullifier_native(Bn254Fr::from(100u64), spending_key);
		let nf2 = nullifier_native(Bn254Fr::from(200u64), spending_key);
		assert_ne!(nf1, nf2);
	}

	#[test]
	fn test_nullifier_native_different_spending_keys() {
		let commitment = Bn254Fr::from(123456u64);
		let nf1 = nullifier_native(commitment, Bn254Fr::from(100u64));
		let nf2 = nullifier_native(commitment, Bn254Fr::from(200u64));
		assert_ne!(nf1, nf2);
	}

	// ===== MerklePath Tests =====

	#[test]
	fn test_merkle_path_new() {
		let elements = vec![Bn254Fr::from(1u64), Bn254Fr::from(2u64)];
		let positions = vec![false, true];
		let path = MerklePath::new(elements.clone(), positions.clone());
		assert_eq!(path.elements, elements);
		assert_eq!(path.positions, positions);
	}

	#[test]
	fn test_merkle_path() {
		let path = MerklePath::new(
			vec![Bn254Fr::from(1u64), Bn254Fr::from(2u64)],
			vec![false, true],
		);
		assert_eq!(path.depth(), 2);
		assert!(path.validate().is_ok());
	}

	#[test]
	fn test_merkle_path_depth() {
		let path1 = MerklePath::new(vec![Bn254Fr::from(1u64)], vec![false]);
		assert_eq!(path1.depth(), 1);
		let path2 = MerklePath::new(
			vec![
				Bn254Fr::from(1u64),
				Bn254Fr::from(2u64),
				Bn254Fr::from(3u64),
			],
			vec![false, true, false],
		);
		assert_eq!(path2.depth(), 3);
	}

	#[test]
	fn test_merkle_path_depth_zero() {
		let path = MerklePath::new(vec![], vec![]);
		assert_eq!(path.depth(), 0);
	}

	#[test]
	fn test_merkle_path_invalid() {
		let path = MerklePath::new(vec![Bn254Fr::from(1u64)], vec![false, true]);
		assert!(path.validate().is_err());
	}

	#[test]
	fn test_merkle_path_validate_mismatch_error() {
		let path = MerklePath::new(vec![Bn254Fr::from(1u64), Bn254Fr::from(2u64)], vec![false]);
		let result = path.validate();
		assert!(result.is_err());
		assert_eq!(
			result.unwrap_err(),
			"Path elements and positions length mismatch"
		);
	}

	#[test]
	fn test_merkle_path_validate_empty() {
		let path = MerklePath::new(vec![], vec![]);
		assert!(path.validate().is_ok());
	}

	#[test]
	fn test_merkle_path_clone() {
		let path1 = MerklePath::new(
			vec![Bn254Fr::from(1u64), Bn254Fr::from(2u64)],
			vec![false, true],
		);
		let path2 = path1.clone();
		assert_eq!(path1, path2);
	}

	#[test]
	fn test_merkle_path_equality() {
		let path1 = MerklePath::new(
			vec![Bn254Fr::from(1u64), Bn254Fr::from(2u64)],
			vec![false, true],
		);
		let path2 = MerklePath::new(
			vec![Bn254Fr::from(1u64), Bn254Fr::from(2u64)],
			vec![false, true],
		);
		assert_eq!(path1, path2);
	}

	#[test]
	fn test_merkle_path_inequality_elements() {
		let path1 = MerklePath::new(
			vec![Bn254Fr::from(1u64), Bn254Fr::from(2u64)],
			vec![false, true],
		);
		let path2 = MerklePath::new(
			vec![Bn254Fr::from(999u64), Bn254Fr::from(2u64)],
			vec![false, true],
		);
		assert_ne!(path1, path2);
	}

	#[test]
	fn test_merkle_path_inequality_positions() {
		let path1 = MerklePath::new(
			vec![Bn254Fr::from(1u64), Bn254Fr::from(2u64)],
			vec![false, true],
		);
		let path2 = MerklePath::new(
			vec![Bn254Fr::from(1u64), Bn254Fr::from(2u64)],
			vec![true, false],
		);
		assert_ne!(path1, path2);
	}

	#[test]
	fn test_merkle_path_debug() {
		let path = MerklePath::new(vec![Bn254Fr::from(1u64)], vec![false]);
		let debug_str = format!("{path:?}");
		assert!(debug_str.contains("MerklePath"));
	}

	#[test]
	fn test_merkle_path_large_depth() {
		let elements: Vec<_> = (0u64..32).map(Bn254Fr::from).collect();
		let positions: Vec<_> = (0..32).map(|i| i % 2 == 0).collect();
		let path = MerklePath::new(elements, positions);
		assert_eq!(path.depth(), 32);
		assert!(path.validate().is_ok());
	}

	// ===== TreeDepth Tests =====

	#[test]
	fn test_tree_depth_standard() {
		assert_eq!(TreeDepth::STANDARD.value(), 20);
	}

	#[test]
	fn test_tree_depth_max() {
		assert_eq!(TreeDepth::MAX.value(), 32);
	}

	#[test]
	fn test_tree_depth_new_valid() {
		assert!(TreeDepth::new(10).is_ok());
		assert_eq!(TreeDepth::new(10).unwrap().value(), 10);
	}

	#[test]
	fn test_tree_depth_new_zero() {
		assert!(TreeDepth::new(0).is_err());
	}

	#[test]
	fn test_tree_depth_new_too_large() {
		assert!(TreeDepth::new(33).is_err());
	}

	#[test]
	fn test_tree_depth_default() {
		let depth = TreeDepth::default();
		assert_eq!(depth, TreeDepth::STANDARD);
	}

	// ===== ValidationError Tests =====

	#[test]
	fn test_validation_error_invalid_path_length() {
		let error = ValidationError::InvalidPathLength {
			expected: 20,
			got: 10,
		};
		match error {
			ValidationError::InvalidPathLength { expected, got } => {
				assert_eq!(expected, 20);
				assert_eq!(got, 10);
			}
			_ => panic!("Wrong error variant"),
		}
	}

	#[test]
	fn test_validation_error_asset_mismatch() {
		let error = ValidationError::AssetMismatch {
			input: 1,
			output: 2,
		};
		match error {
			ValidationError::AssetMismatch { input, output } => {
				assert_eq!(input, 1);
				assert_eq!(output, 2);
			}
			_ => panic!("Wrong error variant"),
		}
	}

	#[test]
	fn test_validation_error_value_imbalance() {
		let error = ValidationError::ValueImbalance {
			inputs: 100,
			outputs: 50,
		};
		match error {
			ValidationError::ValueImbalance { inputs, outputs } => {
				assert_eq!(inputs, 100);
				assert_eq!(outputs, 50);
			}
			_ => panic!("Wrong error variant"),
		}
	}

	#[test]
	fn test_validation_error_duplicate_nullifier() {
		let error = ValidationError::DuplicateNullifier;
		match error {
			ValidationError::DuplicateNullifier => {}
			_ => panic!("Wrong error variant"),
		}
	}

	#[test]
	fn test_validation_error_clone() {
		let error1 = ValidationError::AssetMismatch {
			input: 1,
			output: 2,
		};
		let error2 = error1.clone();
		assert_eq!(error1, error2);
	}

	#[test]
	fn test_validation_error_debug() {
		let error = ValidationError::InvalidPathLength {
			expected: 20,
			got: 10,
		};
		let debug_str = format!("{error:?}");
		assert!(debug_str.contains("InvalidPathLength"));
		assert!(debug_str.contains("20"));
		assert!(debug_str.contains("10"));
	}

	// ===== CircuitValidator Tests =====

	#[test]
	fn test_validate_path_length() {
		let depth = TreeDepth::STANDARD;
		assert!(CircuitValidator::validate_path_length(20, depth).is_ok());
		assert!(CircuitValidator::validate_path_length(10, depth).is_err());
	}

	#[test]
	fn test_validate_path_length_mismatch() {
		let depth = TreeDepth::STANDARD;
		let result = CircuitValidator::validate_path_length(15, depth);
		assert!(result.is_err());
		match result.unwrap_err() {
			ValidationError::InvalidPathLength { expected, got } => {
				assert_eq!(expected, 20);
				assert_eq!(got, 15);
			}
			_ => panic!("Wrong error type"),
		}
	}

	#[test]
	fn test_validate_path_length_shallow() {
		let depth = TreeDepth::new(10).unwrap();
		assert!(CircuitValidator::validate_path_length(10, depth).is_ok());
	}

	#[test]
	fn test_validate_path_length_deep() {
		assert!(CircuitValidator::validate_path_length(32, TreeDepth::MAX).is_ok());
	}

	#[test]
	fn test_validate_asset_consistency() {
		assert!(CircuitValidator::validate_asset_consistency(1, 1).is_ok());
		assert!(CircuitValidator::validate_asset_consistency(1, 2).is_err());
	}

	#[test]
	fn test_validate_asset_consistency_mismatch() {
		let result = CircuitValidator::validate_asset_consistency(1, 2);
		assert!(result.is_err());
		match result.unwrap_err() {
			ValidationError::AssetMismatch { input, output } => {
				assert_eq!(input, 1);
				assert_eq!(output, 2);
			}
			_ => panic!("Wrong error type"),
		}
	}

	#[test]
	fn test_validate_asset_consistency_zero_assets() {
		assert!(CircuitValidator::validate_asset_consistency(0, 0).is_ok());
	}

	#[test]
	fn test_validate_value_balance() {
		assert!(CircuitValidator::validate_value_balance(&[100, 50], &[150]).is_ok());
		assert!(CircuitValidator::validate_value_balance(&[100], &[50]).is_err());
	}

	#[test]
	fn test_validate_value_balance_imbalance() {
		let result = CircuitValidator::validate_value_balance(&[100], &[50]);
		assert!(result.is_err());
		match result.unwrap_err() {
			ValidationError::ValueImbalance { inputs, outputs } => {
				assert_eq!(inputs, 100);
				assert_eq!(outputs, 50);
			}
			_ => panic!("Wrong error type"),
		}
	}

	#[test]
	fn test_validate_value_balance_empty_inputs() {
		let result = CircuitValidator::validate_value_balance(&[], &[]);
		assert!(result.is_ok());
	}

	#[test]
	fn test_validate_value_balance_single_values() {
		assert!(CircuitValidator::validate_value_balance(&[100], &[100]).is_ok());
	}
}
