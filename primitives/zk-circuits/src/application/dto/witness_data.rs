//! Witness Data DTOs
//!
//! Data structures for circuit private witness (secret inputs).

use crate::{application::circuits::note::Note, Bn254Fr};
use alloc::vec::Vec;
use orbinum_zk_core::domain::value_objects::SpendingKey;

/// Merkle authentication path
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerklePath {
	/// Sibling hashes from leaf to root
	pub elements: Vec<Bn254Fr>,
	/// Position bits (0 = left, 1 = right)
	pub positions: Vec<bool>,
}

impl MerklePath {
	/// Create new merkle path
	pub fn new(elements: Vec<Bn254Fr>, positions: Vec<bool>) -> Self {
		Self {
			elements,
			positions,
		}
	}

	/// Get path depth
	pub fn depth(&self) -> usize {
		self.elements.len()
	}

	/// Validate path consistency
	pub fn validate(&self) -> Result<(), &'static str> {
		if self.elements.len() != self.positions.len() {
			return Err("Path elements and positions length mismatch");
		}
		Ok(())
	}
}

/// Witness data for private transfer
#[derive(Debug, Clone)]
pub struct TransferWitness {
	/// Input notes to spend
	pub input_notes: Vec<Note>,
	/// Spending keys for input notes
	pub spending_keys: Vec<SpendingKey>,
	/// Merkle paths for input notes
	pub merkle_paths: Vec<MerklePath>,
	/// Output notes to create
	pub output_notes: Vec<Note>,
}

impl TransferWitness {
	/// Create new transfer witness
	pub fn new(
		input_notes: Vec<Note>,
		spending_keys: Vec<SpendingKey>,
		merkle_paths: Vec<MerklePath>,
		output_notes: Vec<Note>,
	) -> Self {
		Self {
			input_notes,
			spending_keys,
			merkle_paths,
			output_notes,
		}
	}

	/// Validate witness data consistency
	pub fn validate(&self) -> Result<(), &'static str> {
		if self.input_notes.len() != self.spending_keys.len() {
			return Err("Input notes and spending keys count mismatch");
		}
		if self.input_notes.len() != self.merkle_paths.len() {
			return Err("Input notes and merkle paths count mismatch");
		}

		// Validate each merkle path
		for path in &self.merkle_paths {
			path.validate()?;
		}

		Ok(())
	}
}

/// Witness data for unshield (withdrawal)
#[derive(Debug, Clone)]
pub struct UnshieldWitness {
	/// Note to unshield
	pub note: Note,
	/// Spending key for note
	pub spending_key: SpendingKey,
	/// Merkle path for note
	pub merkle_path: MerklePath,
	/// Recipient address
	pub recipient: Bn254Fr,
}

impl UnshieldWitness {
	/// Create new unshield witness
	pub fn new(
		note: Note,
		spending_key: SpendingKey,
		merkle_path: MerklePath,
		recipient: Bn254Fr,
	) -> Self {
		Self {
			note,
			spending_key,
			merkle_path,
			recipient,
		}
	}

	/// Validate witness data
	pub fn validate(&self) -> Result<(), &'static str> {
		self.merkle_path.validate()
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use orbinum_zk_core::domain::value_objects::FieldElement;
	extern crate alloc;
	use alloc::{format, vec, vec::Vec};

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
		assert_eq!(path1.elements, path2.elements);
		assert_eq!(path1.positions, path2.positions);
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
		let elements: Vec<_> = (0..32).map(Bn254Fr::from).collect();
		let positions: Vec<_> = (0..32).map(|i| i % 2 == 0).collect();

		let path = MerklePath::new(elements, positions);

		assert_eq!(path.depth(), 32);
		assert!(path.validate().is_ok());
	}

	// ===== TransferWitness Tests =====

	#[test]
	fn test_transfer_witness_new() {
		let note = Note::new(100, 1, Bn254Fr::from(1u64), Bn254Fr::from(2u64));
		let key = SpendingKey::new(FieldElement::from_u64(3));
		let path = MerklePath::new(vec![Bn254Fr::from(1u64)], vec![false]);

		let witness = TransferWitness::new(
			vec![note.clone()],
			vec![key],
			vec![path.clone()],
			vec![note.clone()],
		);

		assert_eq!(witness.input_notes.len(), 1);
		assert_eq!(witness.spending_keys.len(), 1);
		assert_eq!(witness.merkle_paths.len(), 1);
		assert_eq!(witness.output_notes.len(), 1);
	}

	#[test]
	fn test_transfer_witness_validation() {
		let note = Note::new(100, 1, Bn254Fr::from(1u64), Bn254Fr::from(2u64));
		let key = SpendingKey::new(FieldElement::from_u64(3));
		let path = MerklePath::new(vec![Bn254Fr::from(1u64)], vec![false]);

		let witness = TransferWitness::new(vec![note.clone()], vec![key], vec![path], vec![note]);

		assert!(witness.validate().is_ok());
	}

	#[test]
	fn test_transfer_witness_validate_keys_mismatch() {
		let note = Note::new(100, 1, Bn254Fr::from(1u64), Bn254Fr::from(2u64));
		let key = SpendingKey::new(FieldElement::from_u64(3));
		let path = MerklePath::new(vec![Bn254Fr::from(1u64)], vec![false]);

		let witness = TransferWitness::new(
			vec![note.clone(), note.clone()],
			vec![key], // Only 1 key for 2 notes
			vec![path.clone(), path],
			vec![note],
		);

		let result = witness.validate();
		assert!(result.is_err());
		assert_eq!(
			result.unwrap_err(),
			"Input notes and spending keys count mismatch"
		);
	}

	#[test]
	fn test_transfer_witness_validate_paths_mismatch() {
		let note = Note::new(100, 1, Bn254Fr::from(1u64), Bn254Fr::from(2u64));
		let key = SpendingKey::new(FieldElement::from_u64(3));
		let path = MerklePath::new(vec![Bn254Fr::from(1u64)], vec![false]);

		let witness = TransferWitness::new(
			vec![note.clone(), note.clone()],
			vec![key, key],
			vec![path], // Only 1 path for 2 notes
			vec![note],
		);

		let result = witness.validate();
		assert!(result.is_err());
		assert_eq!(
			result.unwrap_err(),
			"Input notes and merkle paths count mismatch"
		);
	}

	#[test]
	fn test_transfer_witness_validate_invalid_path() {
		let note = Note::new(100, 1, Bn254Fr::from(1u64), Bn254Fr::from(2u64));
		let key = SpendingKey::new(FieldElement::from_u64(3));
		let invalid_path = MerklePath::new(
			vec![Bn254Fr::from(1u64)],
			vec![false, true], // Mismatched lengths
		);

		let witness = TransferWitness::new(
			vec![note.clone()],
			vec![key],
			vec![invalid_path],
			vec![note],
		);

		let result = witness.validate();
		assert!(result.is_err());
		assert_eq!(
			result.unwrap_err(),
			"Path elements and positions length mismatch"
		);
	}

	#[test]
	fn test_transfer_witness_multiple_inputs_outputs() {
		let note1 = Note::new(100, 1, Bn254Fr::from(1u64), Bn254Fr::from(2u64));
		let note2 = Note::new(200, 1, Bn254Fr::from(3u64), Bn254Fr::from(4u64));
		let key1 = SpendingKey::new(FieldElement::from_u64(5));
		let key2 = SpendingKey::new(FieldElement::from_u64(6));
		let path1 = MerklePath::new(vec![Bn254Fr::from(1u64)], vec![false]);
		let path2 = MerklePath::new(vec![Bn254Fr::from(2u64)], vec![true]);

		let witness = TransferWitness::new(
			vec![note1.clone(), note2.clone()],
			vec![key1, key2],
			vec![path1, path2],
			vec![note1, note2],
		);

		assert!(witness.validate().is_ok());
		assert_eq!(witness.input_notes.len(), 2);
		assert_eq!(witness.output_notes.len(), 2);
	}

	#[test]
	fn test_transfer_witness_clone() {
		let note = Note::new(100, 1, Bn254Fr::from(1u64), Bn254Fr::from(2u64));
		let key = SpendingKey::new(FieldElement::from_u64(3));
		let path = MerklePath::new(vec![Bn254Fr::from(1u64)], vec![false]);

		let witness1 = TransferWitness::new(
			vec![note.clone()],
			vec![key],
			vec![path.clone()],
			vec![note.clone()],
		);

		let witness2 = witness1.clone();

		assert_eq!(witness1.input_notes.len(), witness2.input_notes.len());
		assert_eq!(witness1.spending_keys.len(), witness2.spending_keys.len());
		assert_eq!(witness1.merkle_paths.len(), witness2.merkle_paths.len());
		assert_eq!(witness1.output_notes.len(), witness2.output_notes.len());
	}

	#[test]
	fn test_transfer_witness_debug() {
		let note = Note::new(100, 1, Bn254Fr::from(1u64), Bn254Fr::from(2u64));
		let key = SpendingKey::new(FieldElement::from_u64(3));
		let path = MerklePath::new(vec![Bn254Fr::from(1u64)], vec![false]);

		let witness = TransferWitness::new(vec![note.clone()], vec![key], vec![path], vec![note]);

		let debug_str = format!("{witness:?}");
		assert!(debug_str.contains("TransferWitness"));
	}

	#[test]
	fn test_transfer_witness_empty() {
		let witness = TransferWitness::new(vec![], vec![], vec![], vec![]);

		assert!(witness.validate().is_ok());
		assert_eq!(witness.input_notes.len(), 0);
	}

	#[test]
	fn test_transfer_witness_different_output_count() {
		let note1 = Note::new(100, 1, Bn254Fr::from(1u64), Bn254Fr::from(2u64));
		let note2 = Note::new(200, 1, Bn254Fr::from(3u64), Bn254Fr::from(4u64));
		let note3 = Note::new(300, 1, Bn254Fr::from(5u64), Bn254Fr::from(6u64));
		let key = SpendingKey::new(FieldElement::from_u64(7));
		let path = MerklePath::new(vec![Bn254Fr::from(1u64)], vec![false]);

		// 1 input, 3 outputs (valid scenario)
		let witness = TransferWitness::new(vec![note1], vec![key], vec![path], vec![note2, note3]);

		assert!(witness.validate().is_ok());
	}

	// ===== UnshieldWitness Tests =====

	#[test]
	fn test_unshield_witness_new() {
		let note = Note::new(100, 1, Bn254Fr::from(1u64), Bn254Fr::from(2u64));
		let key = SpendingKey::new(FieldElement::from_u64(3));
		let path = MerklePath::new(vec![Bn254Fr::from(4u64)], vec![false]);
		let recipient = Bn254Fr::from(999u64);

		let witness = UnshieldWitness::new(note.clone(), key, path.clone(), recipient);

		assert_eq!(witness.note, note);
		assert_eq!(witness.spending_key, key);
		assert_eq!(witness.merkle_path, path);
		assert_eq!(witness.recipient, recipient);
	}

	#[test]
	fn test_unshield_witness_validate() {
		let note = Note::new(100, 1, Bn254Fr::from(1u64), Bn254Fr::from(2u64));
		let key = SpendingKey::new(FieldElement::from_u64(3));
		let path = MerklePath::new(vec![Bn254Fr::from(4u64)], vec![false]);
		let recipient = Bn254Fr::from(999u64);

		let witness = UnshieldWitness::new(note, key, path, recipient);

		assert!(witness.validate().is_ok());
	}

	#[test]
	fn test_unshield_witness_validate_invalid_path() {
		let note = Note::new(100, 1, Bn254Fr::from(1u64), Bn254Fr::from(2u64));
		let key = SpendingKey::new(FieldElement::from_u64(3));
		let invalid_path = MerklePath::new(
			vec![Bn254Fr::from(4u64), Bn254Fr::from(5u64)],
			vec![false], // Length mismatch
		);
		let recipient = Bn254Fr::from(999u64);

		let witness = UnshieldWitness::new(note, key, invalid_path, recipient);

		let result = witness.validate();
		assert!(result.is_err());
		assert_eq!(
			result.unwrap_err(),
			"Path elements and positions length mismatch"
		);
	}

	#[test]
	fn test_unshield_witness_clone() {
		let note = Note::new(100, 1, Bn254Fr::from(1u64), Bn254Fr::from(2u64));
		let key = SpendingKey::new(FieldElement::from_u64(3));
		let path = MerklePath::new(vec![Bn254Fr::from(4u64)], vec![false]);
		let recipient = Bn254Fr::from(999u64);

		let witness1 = UnshieldWitness::new(note, key, path, recipient);
		let witness2 = witness1.clone();

		assert_eq!(witness1.note, witness2.note);
		assert_eq!(witness1.spending_key, witness2.spending_key);
		assert_eq!(witness1.merkle_path, witness2.merkle_path);
		assert_eq!(witness1.recipient, witness2.recipient);
	}

	#[test]
	fn test_unshield_witness_debug() {
		let note = Note::new(100, 1, Bn254Fr::from(1u64), Bn254Fr::from(2u64));
		let key = SpendingKey::new(FieldElement::from_u64(3));
		let path = MerklePath::new(vec![Bn254Fr::from(4u64)], vec![false]);
		let recipient = Bn254Fr::from(999u64);

		let witness = UnshieldWitness::new(note, key, path, recipient);

		let debug_str = format!("{witness:?}");
		assert!(debug_str.contains("UnshieldWitness"));
	}

	#[test]
	fn test_unshield_witness_zero_amount() {
		let note = Note::new(0, 1, Bn254Fr::from(1u64), Bn254Fr::from(2u64));
		let key = SpendingKey::new(FieldElement::from_u64(3));
		let path = MerklePath::new(vec![Bn254Fr::from(4u64)], vec![false]);
		let recipient = Bn254Fr::from(999u64);

		let witness = UnshieldWitness::new(note, key, path, recipient);

		assert!(witness.validate().is_ok());
		assert_eq!(witness.note.value, Bn254Fr::from(0u64));
	}

	#[test]
	fn test_unshield_witness_zero_recipient() {
		let note = Note::new(100, 1, Bn254Fr::from(1u64), Bn254Fr::from(2u64));
		let key = SpendingKey::new(FieldElement::from_u64(3));
		let path = MerklePath::new(vec![Bn254Fr::from(4u64)], vec![false]);
		let recipient = Bn254Fr::from(0u64);

		let witness = UnshieldWitness::new(note, key, path, recipient);

		assert!(witness.validate().is_ok());
		assert_eq!(witness.recipient, Bn254Fr::from(0u64));
	}

	#[test]
	fn test_unshield_witness_large_amount() {
		let note = Note::new(u64::MAX, 1, Bn254Fr::from(1u64), Bn254Fr::from(2u64));
		let key = SpendingKey::new(FieldElement::from_u64(3));
		let path = MerklePath::new(vec![Bn254Fr::from(4u64)], vec![false]);
		let recipient = Bn254Fr::from(999u64);

		let witness = UnshieldWitness::new(note, key, path, recipient);

		assert!(witness.validate().is_ok());
		assert_eq!(witness.note.value, Bn254Fr::from(u64::MAX));
	}

	#[test]
	fn test_unshield_witness_deep_path() {
		let note = Note::new(100, 1, Bn254Fr::from(1u64), Bn254Fr::from(2u64));
		let key = SpendingKey::new(FieldElement::from_u64(3));
		let elements: Vec<_> = (0..20).map(Bn254Fr::from).collect();
		let positions: Vec<_> = (0..20).map(|i| i % 2 == 0).collect();
		let path = MerklePath::new(elements, positions);
		let recipient = Bn254Fr::from(999u64);

		let witness = UnshieldWitness::new(note, key, path, recipient);

		assert!(witness.validate().is_ok());
		assert_eq!(witness.merkle_path.depth(), 20);
	}
}
