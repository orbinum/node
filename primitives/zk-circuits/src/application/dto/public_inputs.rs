//! Public Inputs DTOs
//!
//! Data structures for circuit public inputs.

use crate::Bn254Fr;
use alloc::vec;
use alloc::vec::Vec;

/// Public inputs for transfer circuit
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferPublicInputs {
	/// Merkle root of commitment tree
	pub merkle_root: Bn254Fr,
	/// Nullifiers of spent notes
	pub nullifiers: Vec<Bn254Fr>,
	/// Commitments of output notes
	pub commitments: Vec<Bn254Fr>,
}

impl TransferPublicInputs {
	/// Create new transfer public inputs
	pub fn new(merkle_root: Bn254Fr, nullifiers: Vec<Bn254Fr>, commitments: Vec<Bn254Fr>) -> Self {
		Self {
			merkle_root,
			nullifiers,
			commitments,
		}
	}

	/// Serialize to field elements for proof generation
	pub fn to_field_elements(&self) -> Vec<Bn254Fr> {
		let mut elements = vec![self.merkle_root];
		elements.extend_from_slice(&self.nullifiers);
		elements.extend_from_slice(&self.commitments);
		elements
	}

	/// Total number of public inputs
	pub fn count(&self) -> usize {
		1 + self.nullifiers.len() + self.commitments.len()
	}
}

/// Public inputs for unshield (withdrawal) circuit
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnshieldPublicInputs {
	/// Merkle root
	pub merkle_root: Bn254Fr,
	/// Nullifier of spent note
	pub nullifier: Bn254Fr,
	/// Withdrawal amount
	pub amount: Bn254Fr,
	/// Recipient address
	pub recipient: Bn254Fr,
}

impl UnshieldPublicInputs {
	/// Create new unshield public inputs
	pub fn new(
		merkle_root: Bn254Fr,
		nullifier: Bn254Fr,
		amount: Bn254Fr,
		recipient: Bn254Fr,
	) -> Self {
		Self {
			merkle_root,
			nullifier,
			amount,
			recipient,
		}
	}

	/// Serialize to field elements
	pub fn to_field_elements(&self) -> Vec<Bn254Fr> {
		vec![
			self.merkle_root,
			self.nullifier,
			self.amount,
			self.recipient,
		]
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	extern crate alloc;
	use alloc::{format, vec};

	// ===== TransferPublicInputs Tests =====

	#[test]
	fn test_transfer_public_inputs_new() {
		let merkle_root = Bn254Fr::from(100u64);
		let nullifiers = vec![Bn254Fr::from(200u64), Bn254Fr::from(300u64)];
		let commitments = vec![Bn254Fr::from(400u64), Bn254Fr::from(500u64)];

		let inputs =
			TransferPublicInputs::new(merkle_root, nullifiers.clone(), commitments.clone());

		assert_eq!(inputs.merkle_root, merkle_root);
		assert_eq!(inputs.nullifiers, nullifiers);
		assert_eq!(inputs.commitments, commitments);
	}

	#[test]
	fn test_transfer_public_inputs() {
		let inputs = TransferPublicInputs::new(
			Bn254Fr::from(1u64),
			vec![Bn254Fr::from(2u64), Bn254Fr::from(3u64)],
			vec![Bn254Fr::from(4u64), Bn254Fr::from(5u64)],
		);

		assert_eq!(inputs.count(), 5);
		assert_eq!(inputs.to_field_elements().len(), 5);
	}

	#[test]
	fn test_transfer_to_field_elements() {
		let merkle_root = Bn254Fr::from(10u64);
		let nullifiers = vec![Bn254Fr::from(20u64), Bn254Fr::from(30u64)];
		let commitments = vec![Bn254Fr::from(40u64), Bn254Fr::from(50u64)];

		let inputs = TransferPublicInputs::new(merkle_root, nullifiers, commitments);
		let elements = inputs.to_field_elements();

		assert_eq!(elements.len(), 5);
		assert_eq!(elements[0], Bn254Fr::from(10u64)); // merkle_root
		assert_eq!(elements[1], Bn254Fr::from(20u64)); // nullifiers[0]
		assert_eq!(elements[2], Bn254Fr::from(30u64)); // nullifiers[1]
		assert_eq!(elements[3], Bn254Fr::from(40u64)); // commitments[0]
		assert_eq!(elements[4], Bn254Fr::from(50u64)); // commitments[1]
	}

	#[test]
	fn test_transfer_count() {
		let inputs = TransferPublicInputs::new(
			Bn254Fr::from(1u64),
			vec![Bn254Fr::from(2u64)],
			vec![Bn254Fr::from(3u64)],
		);

		assert_eq!(inputs.count(), 3); // 1 root + 1 nullifier + 1 commitment
	}

	#[test]
	fn test_transfer_count_multiple() {
		let inputs = TransferPublicInputs::new(
			Bn254Fr::from(1u64),
			vec![
				Bn254Fr::from(2u64),
				Bn254Fr::from(3u64),
				Bn254Fr::from(4u64),
			],
			vec![Bn254Fr::from(5u64), Bn254Fr::from(6u64)],
		);

		assert_eq!(inputs.count(), 6); // 1 + 3 + 2
	}

	#[test]
	fn test_transfer_empty_vectors() {
		let inputs = TransferPublicInputs::new(Bn254Fr::from(1u64), vec![], vec![]);

		assert_eq!(inputs.count(), 1); // Only merkle_root
		assert_eq!(inputs.to_field_elements().len(), 1);
	}

	#[test]
	fn test_transfer_clone() {
		let inputs1 = TransferPublicInputs::new(
			Bn254Fr::from(1u64),
			vec![Bn254Fr::from(2u64)],
			vec![Bn254Fr::from(3u64)],
		);

		let inputs2 = inputs1.clone();

		assert_eq!(inputs1, inputs2);
		assert_eq!(inputs1.merkle_root, inputs2.merkle_root);
		assert_eq!(inputs1.nullifiers, inputs2.nullifiers);
		assert_eq!(inputs1.commitments, inputs2.commitments);
	}

	#[test]
	fn test_transfer_equality() {
		let inputs1 = TransferPublicInputs::new(
			Bn254Fr::from(1u64),
			vec![Bn254Fr::from(2u64)],
			vec![Bn254Fr::from(3u64)],
		);

		let inputs2 = TransferPublicInputs::new(
			Bn254Fr::from(1u64),
			vec![Bn254Fr::from(2u64)],
			vec![Bn254Fr::from(3u64)],
		);

		assert_eq!(inputs1, inputs2);
	}

	#[test]
	fn test_transfer_inequality_root() {
		let inputs1 = TransferPublicInputs::new(
			Bn254Fr::from(1u64),
			vec![Bn254Fr::from(2u64)],
			vec![Bn254Fr::from(3u64)],
		);

		let inputs2 = TransferPublicInputs::new(
			Bn254Fr::from(999u64), // Different root
			vec![Bn254Fr::from(2u64)],
			vec![Bn254Fr::from(3u64)],
		);

		assert_ne!(inputs1, inputs2);
	}

	#[test]
	fn test_transfer_inequality_nullifiers() {
		let inputs1 = TransferPublicInputs::new(
			Bn254Fr::from(1u64),
			vec![Bn254Fr::from(2u64)],
			vec![Bn254Fr::from(3u64)],
		);

		let inputs2 = TransferPublicInputs::new(
			Bn254Fr::from(1u64),
			vec![Bn254Fr::from(999u64)], // Different nullifiers
			vec![Bn254Fr::from(3u64)],
		);

		assert_ne!(inputs1, inputs2);
	}

	#[test]
	fn test_transfer_inequality_commitments() {
		let inputs1 = TransferPublicInputs::new(
			Bn254Fr::from(1u64),
			vec![Bn254Fr::from(2u64)],
			vec![Bn254Fr::from(3u64)],
		);

		let inputs2 = TransferPublicInputs::new(
			Bn254Fr::from(1u64),
			vec![Bn254Fr::from(2u64)],
			vec![Bn254Fr::from(999u64)], // Different commitments
		);

		assert_ne!(inputs1, inputs2);
	}

	#[test]
	fn test_transfer_debug() {
		let inputs = TransferPublicInputs::new(
			Bn254Fr::from(1u64),
			vec![Bn254Fr::from(2u64)],
			vec![Bn254Fr::from(3u64)],
		);

		let debug_str = format!("{inputs:?}");
		assert!(debug_str.contains("TransferPublicInputs"));
	}

	#[test]
	fn test_transfer_large_vectors() {
		let nullifiers: Vec<_> = (0..10).map(Bn254Fr::from).collect();
		let commitments: Vec<_> = (10..20).map(Bn254Fr::from).collect();

		let inputs = TransferPublicInputs::new(Bn254Fr::from(999u64), nullifiers, commitments);

		assert_eq!(inputs.count(), 21); // 1 + 10 + 10
		assert_eq!(inputs.to_field_elements().len(), 21);
	}

	#[test]
	fn test_transfer_zero_values() {
		let inputs = TransferPublicInputs::new(
			Bn254Fr::from(0u64),
			vec![Bn254Fr::from(0u64), Bn254Fr::from(0u64)],
			vec![Bn254Fr::from(0u64), Bn254Fr::from(0u64)],
		);

		assert_eq!(inputs.count(), 5);
		assert_eq!(inputs.merkle_root, Bn254Fr::from(0u64));
	}

	#[test]
	fn test_transfer_max_values() {
		let inputs = TransferPublicInputs::new(
			Bn254Fr::from(u64::MAX),
			vec![Bn254Fr::from(u64::MAX), Bn254Fr::from(u64::MAX - 1)],
			vec![Bn254Fr::from(u64::MAX - 2), Bn254Fr::from(u64::MAX - 3)],
		);

		assert_eq!(inputs.count(), 5);
	}

	// ===== UnshieldPublicInputs Tests =====

	#[test]
	fn test_unshield_public_inputs_new() {
		let merkle_root = Bn254Fr::from(100u64);
		let nullifier = Bn254Fr::from(200u64);
		let amount = Bn254Fr::from(1000u64);
		let recipient = Bn254Fr::from(999u64);

		let inputs = UnshieldPublicInputs::new(merkle_root, nullifier, amount, recipient);

		assert_eq!(inputs.merkle_root, merkle_root);
		assert_eq!(inputs.nullifier, nullifier);
		assert_eq!(inputs.amount, amount);
		assert_eq!(inputs.recipient, recipient);
	}

	#[test]
	fn test_unshield_public_inputs() {
		let inputs = UnshieldPublicInputs::new(
			Bn254Fr::from(1u64),
			Bn254Fr::from(2u64),
			Bn254Fr::from(100u64),
			Bn254Fr::from(999u64),
		);

		let elements = inputs.to_field_elements();
		assert_eq!(elements.len(), 4);
		assert_eq!(elements[2], Bn254Fr::from(100u64));
	}

	#[test]
	fn test_unshield_to_field_elements() {
		let inputs = UnshieldPublicInputs::new(
			Bn254Fr::from(10u64),
			Bn254Fr::from(20u64),
			Bn254Fr::from(30u64),
			Bn254Fr::from(40u64),
		);

		let elements = inputs.to_field_elements();

		assert_eq!(elements.len(), 4);
		assert_eq!(elements[0], Bn254Fr::from(10u64)); // merkle_root
		assert_eq!(elements[1], Bn254Fr::from(20u64)); // nullifier
		assert_eq!(elements[2], Bn254Fr::from(30u64)); // amount
		assert_eq!(elements[3], Bn254Fr::from(40u64)); // recipient
	}

	#[test]
	fn test_unshield_clone() {
		let inputs1 = UnshieldPublicInputs::new(
			Bn254Fr::from(1u64),
			Bn254Fr::from(2u64),
			Bn254Fr::from(100u64),
			Bn254Fr::from(999u64),
		);

		let inputs2 = inputs1.clone();

		assert_eq!(inputs1, inputs2);
		assert_eq!(inputs1.merkle_root, inputs2.merkle_root);
		assert_eq!(inputs1.nullifier, inputs2.nullifier);
		assert_eq!(inputs1.amount, inputs2.amount);
		assert_eq!(inputs1.recipient, inputs2.recipient);
	}

	#[test]
	fn test_unshield_equality() {
		let inputs1 = UnshieldPublicInputs::new(
			Bn254Fr::from(1u64),
			Bn254Fr::from(2u64),
			Bn254Fr::from(100u64),
			Bn254Fr::from(999u64),
		);

		let inputs2 = UnshieldPublicInputs::new(
			Bn254Fr::from(1u64),
			Bn254Fr::from(2u64),
			Bn254Fr::from(100u64),
			Bn254Fr::from(999u64),
		);

		assert_eq!(inputs1, inputs2);
	}

	#[test]
	fn test_unshield_inequality_root() {
		let inputs1 = UnshieldPublicInputs::new(
			Bn254Fr::from(1u64),
			Bn254Fr::from(2u64),
			Bn254Fr::from(100u64),
			Bn254Fr::from(999u64),
		);

		let inputs2 = UnshieldPublicInputs::new(
			Bn254Fr::from(999u64), // Different root
			Bn254Fr::from(2u64),
			Bn254Fr::from(100u64),
			Bn254Fr::from(999u64),
		);

		assert_ne!(inputs1, inputs2);
	}

	#[test]
	fn test_unshield_inequality_nullifier() {
		let inputs1 = UnshieldPublicInputs::new(
			Bn254Fr::from(1u64),
			Bn254Fr::from(2u64),
			Bn254Fr::from(100u64),
			Bn254Fr::from(999u64),
		);

		let inputs2 = UnshieldPublicInputs::new(
			Bn254Fr::from(1u64),
			Bn254Fr::from(999u64), // Different nullifier
			Bn254Fr::from(100u64),
			Bn254Fr::from(999u64),
		);

		assert_ne!(inputs1, inputs2);
	}

	#[test]
	fn test_unshield_inequality_amount() {
		let inputs1 = UnshieldPublicInputs::new(
			Bn254Fr::from(1u64),
			Bn254Fr::from(2u64),
			Bn254Fr::from(100u64),
			Bn254Fr::from(999u64),
		);

		let inputs2 = UnshieldPublicInputs::new(
			Bn254Fr::from(1u64),
			Bn254Fr::from(2u64),
			Bn254Fr::from(999u64), // Different amount
			Bn254Fr::from(999u64),
		);

		assert_ne!(inputs1, inputs2);
	}

	#[test]
	fn test_unshield_inequality_recipient() {
		let inputs1 = UnshieldPublicInputs::new(
			Bn254Fr::from(1u64),
			Bn254Fr::from(2u64),
			Bn254Fr::from(100u64),
			Bn254Fr::from(999u64),
		);

		let inputs2 = UnshieldPublicInputs::new(
			Bn254Fr::from(1u64),
			Bn254Fr::from(2u64),
			Bn254Fr::from(100u64),
			Bn254Fr::from(111u64), // Different recipient
		);

		assert_ne!(inputs1, inputs2);
	}

	#[test]
	fn test_unshield_debug() {
		let inputs = UnshieldPublicInputs::new(
			Bn254Fr::from(1u64),
			Bn254Fr::from(2u64),
			Bn254Fr::from(100u64),
			Bn254Fr::from(999u64),
		);

		let debug_str = format!("{inputs:?}");
		assert!(debug_str.contains("UnshieldPublicInputs"));
	}

	#[test]
	fn test_unshield_zero_amount() {
		let inputs = UnshieldPublicInputs::new(
			Bn254Fr::from(1u64),
			Bn254Fr::from(2u64),
			Bn254Fr::from(0u64),
			Bn254Fr::from(999u64),
		);

		assert_eq!(inputs.amount, Bn254Fr::from(0u64));
	}

	#[test]
	fn test_unshield_max_amount() {
		let inputs = UnshieldPublicInputs::new(
			Bn254Fr::from(1u64),
			Bn254Fr::from(2u64),
			Bn254Fr::from(u64::MAX),
			Bn254Fr::from(999u64),
		);

		assert_eq!(inputs.amount, Bn254Fr::from(u64::MAX));
	}

	#[test]
	fn test_unshield_zero_recipient() {
		let inputs = UnshieldPublicInputs::new(
			Bn254Fr::from(1u64),
			Bn254Fr::from(2u64),
			Bn254Fr::from(100u64),
			Bn254Fr::from(0u64),
		);

		assert_eq!(inputs.recipient, Bn254Fr::from(0u64));
	}

	// ===== Cross-Type Tests =====

	#[test]
	fn test_transfer_and_unshield_different_types() {
		let transfer = TransferPublicInputs::new(
			Bn254Fr::from(1u64),
			vec![Bn254Fr::from(2u64)],
			vec![Bn254Fr::from(3u64)],
		);

		let unshield = UnshieldPublicInputs::new(
			Bn254Fr::from(1u64),
			Bn254Fr::from(2u64),
			Bn254Fr::from(3u64),
			Bn254Fr::from(4u64),
		);

		// Verify both can exist independently
		assert_eq!(transfer.merkle_root, Bn254Fr::from(1u64));
		assert_eq!(unshield.merkle_root, Bn254Fr::from(1u64));
	}
}
