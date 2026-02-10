//! Transfer Circuit
//!
//! Private transfer circuit proving:
//! 1. Merkle membership of input notes
//! 2. Nullifier correctness
//! 3. Output commitment correctness
//! 4. Balance conservation: sum(inputs) == sum(outputs)
//! 5. Asset consistency (MVP: single asset)

use alloc::vec::Vec;
use ark_r1cs_std::{alloc::AllocVar, boolean::Boolean, eq::EqGadget, fields::fp::FpVar};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

use super::note::{note_commitment, nullifier, Note};
use crate::{infrastructure::gadgets::merkle::merkle_tree_verifier, Bn254Fr};
use orbinum_zk_core::domain::constants::MERKLE_TREE_DEPTH as DEFAULT_TREE_DEPTH;

/// Number of inputs in a transfer (MVP: fixed at 2)
pub const NUM_INPUTS: usize = 2;

/// Number of outputs in a transfer (MVP: fixed at 2)
pub const NUM_OUTPUTS: usize = 2;

/// Tree depth for Merkle proofs
pub const TREE_DEPTH: usize = DEFAULT_TREE_DEPTH;

// ============================================================================
// Transfer Witness
// ============================================================================

/// Private transfer witness
#[derive(Clone, Debug)]
pub struct TransferWitness {
	// Input notes (being spent)
	pub input_notes: [Note; NUM_INPUTS],
	pub spending_keys: [Bn254Fr; NUM_INPUTS],
	pub merkle_path_elements: [[Bn254Fr; TREE_DEPTH]; NUM_INPUTS],
	pub merkle_path_indices: [[bool; TREE_DEPTH]; NUM_INPUTS],

	// Output notes (being created)
	pub output_notes: [Note; NUM_OUTPUTS],
}

impl TransferWitness {
	/// Creates a new transfer witness
	pub fn new(
		input_notes: [Note; NUM_INPUTS],
		spending_keys: [Bn254Fr; NUM_INPUTS],
		merkle_path_elements: [[Bn254Fr; TREE_DEPTH]; NUM_INPUTS],
		merkle_path_indices: [[bool; TREE_DEPTH]; NUM_INPUTS],
		output_notes: [Note; NUM_OUTPUTS],
	) -> Self {
		Self {
			input_notes,
			spending_keys,
			merkle_path_elements,
			merkle_path_indices,
			output_notes,
		}
	}

	/// Computes the input commitments
	pub fn input_commitments(&self) -> [Bn254Fr; NUM_INPUTS] {
		[
			self.input_notes[0].commitment(),
			self.input_notes[1].commitment(),
		]
	}

	/// Computes the nullifiers for the inputs
	pub fn nullifiers(&self) -> [Bn254Fr; NUM_INPUTS] {
		let commitments = self.input_commitments();
		[
			super::note::nullifier_native(commitments[0], self.spending_keys[0]),
			super::note::nullifier_native(commitments[1], self.spending_keys[1]),
		]
	}

	/// Computes the output commitments
	pub fn output_commitments(&self) -> [Bn254Fr; NUM_OUTPUTS] {
		[
			self.output_notes[0].commitment(),
			self.output_notes[1].commitment(),
		]
	}

	/// Validates the witness (balance, asset consistency)
	pub fn validate(&self) -> Result<(), &'static str> {
		// Check balance conservation
		let input_sum = self.input_notes[0].value + self.input_notes[1].value;
		let output_sum = self.output_notes[0].value + self.output_notes[1].value;

		if input_sum != output_sum {
			return Err("Balance not conserved: sum(inputs) != sum(outputs)");
		}

		// Check asset consistency (MVP: all must be asset 0)
		for note in &self.input_notes {
			if note.asset_id != Bn254Fr::from(0u64) {
				return Err("Invalid asset ID in input (MVP requires asset_id = 0)");
			}
		}
		for note in &self.output_notes {
			if note.asset_id != Bn254Fr::from(0u64) {
				return Err("Invalid asset ID in output (MVP requires asset_id = 0)");
			}
		}

		Ok(())
	}
}

// ============================================================================
// Transfer Public Inputs
// ============================================================================

/// Transfer circuit public inputs
#[derive(Clone, Debug)]
pub struct TransferPublicInputs {
	/// Current Merkle tree root
	pub merkle_root: Bn254Fr,
	/// Nullifiers for spent notes
	pub nullifiers: [Bn254Fr; NUM_INPUTS],
	/// Commitments for new notes
	pub commitments: [Bn254Fr; NUM_OUTPUTS],
}

impl TransferPublicInputs {
	/// Creates public inputs from witness
	pub fn from_witness(witness: &TransferWitness, merkle_root: Bn254Fr) -> Self {
		Self {
			merkle_root,
			nullifiers: witness.nullifiers(),
			commitments: witness.output_commitments(),
		}
	}

	/// Serializes to a vector for proof verification
	pub fn to_vec(&self) -> Vec<Bn254Fr> {
		let mut inputs = Vec::with_capacity(1 + NUM_INPUTS + NUM_OUTPUTS);
		inputs.push(self.merkle_root);
		inputs.extend_from_slice(&self.nullifiers);
		inputs.extend_from_slice(&self.commitments);
		inputs
	}
}

// ============================================================================
// Transfer Circuit
// ============================================================================

/// Private transfer circuit
///
/// Uses `Option` for arkworks pattern (None during setup, Some during proving).
#[derive(Clone)]
pub struct TransferCircuit {
	/// Private witness data (None during setup)
	pub witness: Option<TransferWitness>,
	/// Public Merkle root (None during setup)
	pub merkle_root: Option<Bn254Fr>,
}

impl TransferCircuit {
	/// Creates a new transfer circuit with witness data (for proving)
	pub fn new(witness: TransferWitness, merkle_root: Bn254Fr) -> Self {
		Self {
			witness: Some(witness),
			merkle_root: Some(merkle_root),
		}
	}

	/// Creates a circuit for trusted setup (no concrete values needed)
	pub fn new_for_setup() -> Self {
		Self {
			witness: None,
			merkle_root: None,
		}
	}

	/// Gets the public inputs for this circuit (panics if witness is None)
	pub fn public_inputs(&self) -> TransferPublicInputs {
		let witness = self
			.witness
			.as_ref()
			.expect("Cannot get public inputs without witness");
		let merkle_root = self
			.merkle_root
			.expect("Cannot get public inputs without merkle_root");
		TransferPublicInputs::from_witness(witness, merkle_root)
	}
}

impl ConstraintSynthesizer<Bn254Fr> for TransferCircuit {
	fn generate_constraints(self, cs: ConstraintSystemRef<Bn254Fr>) -> Result<(), SynthesisError> {
		// Helper to get value or return AssignmentMissing (for setup mode)
		let get_or_missing = |opt: Option<Bn254Fr>| -> Result<Bn254Fr, SynthesisError> {
			opt.ok_or(SynthesisError::AssignmentMissing)
		};

		// ====================================================================
		// Allocate public inputs
		// ====================================================================

		let merkle_root_var = FpVar::new_input(cs.clone(), || get_or_missing(self.merkle_root))?;

		// Pre-compute values if witness is available
		let nullifiers = self.witness.as_ref().map(|w| w.nullifiers());
		let output_commitments = self.witness.as_ref().map(|w| w.output_commitments());

		let mut nullifier_vars = Vec::with_capacity(NUM_INPUTS);
		for i in 0..NUM_INPUTS {
			let nf = nullifiers.map(|n| n[i]);
			nullifier_vars.push(FpVar::new_input(cs.clone(), || get_or_missing(nf))?);
		}

		let mut output_commitment_vars = Vec::with_capacity(NUM_OUTPUTS);
		for i in 0..NUM_OUTPUTS {
			let cm = output_commitments.map(|c| c[i]);
			output_commitment_vars.push(FpVar::new_input(cs.clone(), || get_or_missing(cm))?);
		}

		// ====================================================================
		// Allocate private inputs
		// ====================================================================

		// Input notes
		let mut input_value_vars = Vec::with_capacity(NUM_INPUTS);
		let mut input_asset_vars = Vec::with_capacity(NUM_INPUTS);
		let mut input_owner_vars = Vec::with_capacity(NUM_INPUTS);
		let mut input_blinding_vars = Vec::with_capacity(NUM_INPUTS);
		let mut spending_key_vars = Vec::with_capacity(NUM_INPUTS);
		let mut path_element_vars = Vec::with_capacity(NUM_INPUTS);
		let mut path_index_vars = Vec::with_capacity(NUM_INPUTS);

		for i in 0..NUM_INPUTS {
			let note = self.witness.as_ref().map(|w| &w.input_notes[i]);

			input_value_vars.push(FpVar::new_witness(cs.clone(), || {
				get_or_missing(note.map(|n| n.value))
			})?);
			input_asset_vars.push(FpVar::new_witness(cs.clone(), || {
				get_or_missing(note.map(|n| n.asset_id))
			})?);
			input_owner_vars.push(FpVar::new_witness(cs.clone(), || {
				get_or_missing(note.map(|n| n.owner_pubkey))
			})?);
			input_blinding_vars.push(FpVar::new_witness(cs.clone(), || {
				get_or_missing(note.map(|n| n.blinding))
			})?);
			spending_key_vars.push(FpVar::new_witness(cs.clone(), || {
				get_or_missing(self.witness.as_ref().map(|w| w.spending_keys[i]))
			})?);

			// Merkle proof path elements
			let mut path_elements = Vec::with_capacity(TREE_DEPTH);
			for j in 0..TREE_DEPTH {
				let elem = self.witness.as_ref().map(|w| w.merkle_path_elements[i][j]);
				path_elements.push(FpVar::new_witness(cs.clone(), || get_or_missing(elem))?);
			}
			path_element_vars.push(path_elements);

			// Merkle proof path indices
			let mut path_indices = Vec::with_capacity(TREE_DEPTH);
			for j in 0..TREE_DEPTH {
				let idx = self.witness.as_ref().map(|w| w.merkle_path_indices[i][j]);
				path_indices.push(Boolean::new_witness(cs.clone(), || {
					idx.ok_or(SynthesisError::AssignmentMissing)
				})?);
			}
			path_index_vars.push(path_indices);
		}

		// Output notes
		let mut output_value_vars = Vec::with_capacity(NUM_OUTPUTS);
		let mut output_asset_vars = Vec::with_capacity(NUM_OUTPUTS);
		let mut output_owner_vars = Vec::with_capacity(NUM_OUTPUTS);
		let mut output_blinding_vars = Vec::with_capacity(NUM_OUTPUTS);

		for i in 0..NUM_OUTPUTS {
			let note = self.witness.as_ref().map(|w| &w.output_notes[i]);

			output_value_vars.push(FpVar::new_witness(cs.clone(), || {
				get_or_missing(note.map(|n| n.value))
			})?);
			output_asset_vars.push(FpVar::new_witness(cs.clone(), || {
				get_or_missing(note.map(|n| n.asset_id))
			})?);
			output_owner_vars.push(FpVar::new_witness(cs.clone(), || {
				get_or_missing(note.map(|n| n.owner_pubkey))
			})?);
			output_blinding_vars.push(FpVar::new_witness(cs.clone(), || {
				get_or_missing(note.map(|n| n.blinding))
			})?);
		}

		// ====================================================================
		// CONSTRAINT 1: Merkle Membership
		// ====================================================================

		for i in 0..NUM_INPUTS {
			// Compute input commitment
			let computed_commitment = note_commitment(
				cs.clone(),
				&input_value_vars[i],
				&input_asset_vars[i],
				&input_owner_vars[i],
				&input_blinding_vars[i],
			)?;

			// Verify Merkle membership
			let computed_root = merkle_tree_verifier(
				cs.clone(),
				&computed_commitment,
				&path_element_vars[i],
				&path_index_vars[i],
			)?;

			// Constrain: computed_root == public merkle_root
			computed_root.enforce_equal(&merkle_root_var)?;
		}

		// ====================================================================
		// CONSTRAINT 2: Nullifier Correctness
		// ====================================================================

		for i in 0..NUM_INPUTS {
			// Recompute input commitment
			let input_commitment = note_commitment(
				cs.clone(),
				&input_value_vars[i],
				&input_asset_vars[i],
				&input_owner_vars[i],
				&input_blinding_vars[i],
			)?;

			// Compute nullifier
			let computed_nullifier =
				nullifier(cs.clone(), &input_commitment, &spending_key_vars[i])?;

			// Constrain: computed_nullifier == public nullifier
			computed_nullifier.enforce_equal(&nullifier_vars[i])?;
		}

		// ====================================================================
		// CONSTRAINT 3: Output Commitments
		// ====================================================================

		for i in 0..NUM_OUTPUTS {
			// Compute output commitment
			let computed_commitment = note_commitment(
				cs.clone(),
				&output_value_vars[i],
				&output_asset_vars[i],
				&output_owner_vars[i],
				&output_blinding_vars[i],
			)?;

			// Constrain: computed_commitment == public commitment
			computed_commitment.enforce_equal(&output_commitment_vars[i])?;
		}

		// ====================================================================
		// CONSTRAINT 4: Balance Conservation
		// ====================================================================

		let input_sum = &input_value_vars[0] + &input_value_vars[1];
		let output_sum = &output_value_vars[0] + &output_value_vars[1];

		// Constrain: sum(inputs) == sum(outputs)
		input_sum.enforce_equal(&output_sum)?;

		// ====================================================================
		// CONSTRAINT 5: Asset Consistency (MVP)
		// ====================================================================

		let zero = FpVar::new_constant(cs.clone(), Bn254Fr::from(0u64))?;

		for input_asset in input_asset_vars.iter().take(NUM_INPUTS) {
			input_asset.enforce_equal(&zero)?;
		}
		for output_asset in output_asset_vars.iter().take(NUM_OUTPUTS) {
			output_asset.enforce_equal(&zero)?;
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
	use crate::infrastructure::native_crypto::poseidon_hash_2;
	use ark_relations::r1cs::ConstraintSystem;
	use orbinum_zk_core::{
		domain::{
			services::MerkleService,
			value_objects::{Commitment, FieldElement},
		},
		infrastructure::crypto::LightPoseidonHasher,
	};
	extern crate alloc;

	/// Creates test Merkle paths for TREE_DEPTH levels
	fn create_test_merkle_paths(
		leaf0: Bn254Fr,
		leaf1: Bn254Fr,
	) -> (Bn254Fr, [[Bn254Fr; TREE_DEPTH]; 2], [[bool; TREE_DEPTH]; 2]) {
		// Level 0: leaf0 and leaf1 are siblings
		let h01 = poseidon_hash_2(&[leaf0, leaf1]);

		// Build path for leaf0: sibling is leaf1
		let mut path0 = [Bn254Fr::from(0u64); TREE_DEPTH];
		let mut idx0 = [false; TREE_DEPTH];
		path0[0] = leaf1;
		idx0[0] = false;

		// Build path for leaf1: sibling is leaf0
		let mut path1 = [Bn254Fr::from(0u64); TREE_DEPTH];
		let mut idx1 = [false; TREE_DEPTH];
		path1[0] = leaf0;
		idx1[0] = true;

		// For levels 1 to TREE_DEPTH-1, siblings are zero hashes
		let mut current = h01;
		for i in 1..TREE_DEPTH {
			let zero_sibling = Bn254Fr::from(0u64);
			path0[i] = zero_sibling;
			path1[i] = zero_sibling;
			idx0[i] = false;
			idx1[i] = false;

			current = poseidon_hash_2(&[current, zero_sibling]);
		}

		// Verify paths work
		let hasher = LightPoseidonHasher;
		let service = MerkleService::new(hasher);

		let path0_field: Vec<FieldElement> = path0.iter().map(|&p| FieldElement::new(p)).collect();
		let path1_field: Vec<FieldElement> = path1.iter().map(|&p| FieldElement::new(p)).collect();

		let root0 = service.compute_root(
			&Commitment::new(FieldElement::new(leaf0)),
			&path0_field,
			&idx0,
		);
		let root1 = service.compute_root(
			&Commitment::new(FieldElement::new(leaf1)),
			&path1_field,
			&idx1,
		);

		assert_eq!(root0, root1, "Both leaves should compute to same root");

		(root0.inner(), [path0, path1], [idx0, idx1])
	}

	fn create_test_witness() -> (TransferWitness, Bn254Fr) {
		let owner1 = Bn254Fr::from(1111u64);
		let owner2 = Bn254Fr::from(2222u64);
		let blinding1 = Bn254Fr::from(3333u64);
		let blinding2 = Bn254Fr::from(4444u64);
		let blinding3 = Bn254Fr::from(5555u64);
		let blinding4 = Bn254Fr::from(6666u64);
		let spending_key1 = Bn254Fr::from(7777u64);
		let spending_key2 = Bn254Fr::from(8888u64);

		// Input notes: 600 + 400 = 1000
		let input_note1 = Note::new(600, 0, owner1, blinding1);
		let input_note2 = Note::new(400, 0, owner1, blinding2);

		// Output notes: 300 + 700 = 1000 (balanced)
		let output_note1 = Note::new(300, 0, owner2, blinding3);
		let output_note2 = Note::new(700, 0, owner2, blinding4);

		// Create Merkle tree with input commitments
		let input_commitments = [input_note1.commitment(), input_note2.commitment()];
		let (root, path_elements, path_indices) =
			create_test_merkle_paths(input_commitments[0], input_commitments[1]);

		let witness = TransferWitness::new(
			[input_note1, input_note2],
			[spending_key1, spending_key2],
			path_elements,
			path_indices,
			[output_note1, output_note2],
		);

		(witness, root)
	}

	#[test]
	fn test_witness_validation_valid() {
		let (witness, _) = create_test_witness();
		assert!(witness.validate().is_ok());
	}

	#[test]
	fn test_witness_validation_unbalanced() {
		let (mut witness, _) = create_test_witness();

		// Make outputs unbalanced
		witness.output_notes[0] = Note::new(500, 0, Bn254Fr::from(1u64), Bn254Fr::from(1u64));

		assert!(witness.validate().is_err());
	}

	#[test]
	fn test_witness_validation_wrong_asset() {
		let (mut witness, _) = create_test_witness();

		// Use wrong asset ID
		witness.input_notes[0].asset_id = Bn254Fr::from(1u64);

		assert!(witness.validate().is_err());
	}

	#[test]
	fn test_public_inputs_generation() {
		let (witness, root) = create_test_witness();
		let public_inputs = TransferPublicInputs::from_witness(&witness, root);

		assert_eq!(public_inputs.merkle_root, root);
		assert_eq!(public_inputs.nullifiers, witness.nullifiers());
		assert_eq!(public_inputs.commitments, witness.output_commitments());

		let vec = public_inputs.to_vec();
		assert_eq!(vec.len(), 1 + NUM_INPUTS + NUM_OUTPUTS); // 5 elements
	}

	#[test]
	fn test_transfer_circuit_constraints() {
		let (witness, root) = create_test_witness();
		let circuit = TransferCircuit::new(witness, root);

		let cs = ConstraintSystem::<Bn254Fr>::new_ref();
		circuit.generate_constraints(cs.clone()).unwrap();

		assert!(
			cs.is_satisfied().unwrap(),
			"Circuit should be satisfied with valid witness"
		);

		// Note: println! is not available in no_std
		// Uncomment with std feature if needed:
		// println!("Transfer circuit constraints: {}", cs.num_constraints());
	}

	#[test]
	fn test_note_struct_helpers() {
		let note = Note::new(1000, 0, Bn254Fr::from(123u64), Bn254Fr::from(456u64));

		// Commitment should be consistent
		let c1 = note.commitment();
		let c2 = note.commitment();
		assert_eq!(c1, c2);

		// Nullifier depends on spending key
		let nf1 = note.nullifier(Bn254Fr::from(789u64));
		let nf2 = note.nullifier(Bn254Fr::from(789u64));
		assert_eq!(nf1, nf2);

		let nf3 = note.nullifier(Bn254Fr::from(999u64));
		assert_ne!(nf1, nf3);
	}

	// ===== TransferWitness Tests =====

	#[test]
	fn test_transfer_witness_new() {
		let (witness, _) = create_test_witness();
		assert_eq!(witness.input_notes.len(), NUM_INPUTS);
		assert_eq!(witness.output_notes.len(), NUM_OUTPUTS);
	}

	#[test]
	fn test_input_commitments() {
		let (witness, _) = create_test_witness();
		let commitments = witness.input_commitments();
		assert_eq!(commitments.len(), NUM_INPUTS);
		assert_ne!(commitments[0], Bn254Fr::from(0u64));
		assert_ne!(commitments[1], Bn254Fr::from(0u64));
	}

	#[test]
	fn test_nullifiers() {
		let (witness, _) = create_test_witness();
		let nullifiers = witness.nullifiers();
		assert_eq!(nullifiers.len(), NUM_INPUTS);
		assert_ne!(nullifiers[0], Bn254Fr::from(0u64));
		assert_ne!(nullifiers[1], Bn254Fr::from(0u64));
		assert_ne!(nullifiers[0], nullifiers[1]);
	}

	#[test]
	fn test_output_commitments() {
		let (witness, _) = create_test_witness();
		let commitments = witness.output_commitments();
		assert_eq!(commitments.len(), NUM_OUTPUTS);
		assert_ne!(commitments[0], Bn254Fr::from(0u64));
		assert_ne!(commitments[1], Bn254Fr::from(0u64));
	}

	#[test]
	fn test_witness_balance_check() {
		let (witness, _) = create_test_witness();
		let input_sum = witness.input_notes[0].value + witness.input_notes[1].value;
		let output_sum = witness.output_notes[0].value + witness.output_notes[1].value;
		assert_eq!(input_sum, output_sum);
	}

	#[test]
	fn test_witness_validation_balanced() {
		let owner = Bn254Fr::from(100u64);
		let blinding = Bn254Fr::from(200u64);
		let spending_key = Bn254Fr::from(300u64);

		let input_notes = [
			Note::new(500, 0, owner, blinding),
			Note::new(500, 0, owner, blinding),
		];
		let output_notes = [
			Note::new(600, 0, owner, blinding),
			Note::new(400, 0, owner, blinding),
		];

		let (_, path_elements, path_indices) =
			create_test_merkle_paths(input_notes[0].commitment(), input_notes[1].commitment());

		let witness = TransferWitness::new(
			input_notes,
			[spending_key, spending_key],
			path_elements,
			path_indices,
			output_notes,
		);

		assert!(witness.validate().is_ok());
	}

	#[test]
	fn test_witness_validation_input_exceeds_output() {
		let owner = Bn254Fr::from(100u64);
		let blinding = Bn254Fr::from(200u64);
		let spending_key = Bn254Fr::from(300u64);

		let input_notes = [
			Note::new(600, 0, owner, blinding),
			Note::new(500, 0, owner, blinding),
		];
		let output_notes = [
			Note::new(400, 0, owner, blinding),
			Note::new(400, 0, owner, blinding),
		];

		let (_, path_elements, path_indices) =
			create_test_merkle_paths(input_notes[0].commitment(), input_notes[1].commitment());

		let witness = TransferWitness::new(
			input_notes,
			[spending_key, spending_key],
			path_elements,
			path_indices,
			output_notes,
		);

		assert!(witness.validate().is_err());
	}

	#[test]
	fn test_witness_validation_output_exceeds_input() {
		let owner = Bn254Fr::from(100u64);
		let blinding = Bn254Fr::from(200u64);
		let spending_key = Bn254Fr::from(300u64);

		let input_notes = [
			Note::new(400, 0, owner, blinding),
			Note::new(400, 0, owner, blinding),
		];
		let output_notes = [
			Note::new(600, 0, owner, blinding),
			Note::new(500, 0, owner, blinding),
		];

		let (_, path_elements, path_indices) =
			create_test_merkle_paths(input_notes[0].commitment(), input_notes[1].commitment());

		let witness = TransferWitness::new(
			input_notes,
			[spending_key, spending_key],
			path_elements,
			path_indices,
			output_notes,
		);

		assert!(witness.validate().is_err());
	}

	#[test]
	fn test_witness_validation_invalid_input_asset() {
		let owner = Bn254Fr::from(100u64);
		let blinding = Bn254Fr::from(200u64);
		let spending_key = Bn254Fr::from(300u64);

		let mut input_notes = [
			Note::new(500, 0, owner, blinding),
			Note::new(500, 0, owner, blinding),
		];
		input_notes[0].asset_id = Bn254Fr::from(1u64); // Invalid asset

		let output_notes = [
			Note::new(500, 0, owner, blinding),
			Note::new(500, 0, owner, blinding),
		];

		let (_, path_elements, path_indices) =
			create_test_merkle_paths(input_notes[0].commitment(), input_notes[1].commitment());

		let witness = TransferWitness::new(
			input_notes,
			[spending_key, spending_key],
			path_elements,
			path_indices,
			output_notes,
		);

		assert!(witness.validate().is_err());
	}

	#[test]
	fn test_witness_validation_invalid_output_asset() {
		let owner = Bn254Fr::from(100u64);
		let blinding = Bn254Fr::from(200u64);
		let spending_key = Bn254Fr::from(300u64);

		let input_notes = [
			Note::new(500, 0, owner, blinding),
			Note::new(500, 0, owner, blinding),
		];

		let mut output_notes = [
			Note::new(500, 0, owner, blinding),
			Note::new(500, 0, owner, blinding),
		];
		output_notes[1].asset_id = Bn254Fr::from(2u64); // Invalid asset

		let (_, path_elements, path_indices) =
			create_test_merkle_paths(input_notes[0].commitment(), input_notes[1].commitment());

		let witness = TransferWitness::new(
			input_notes,
			[spending_key, spending_key],
			path_elements,
			path_indices,
			output_notes,
		);

		assert!(witness.validate().is_err());
	}

	#[test]
	fn test_witness_zero_values() {
		let owner = Bn254Fr::from(100u64);
		let blinding = Bn254Fr::from(200u64);
		let spending_key = Bn254Fr::from(300u64);

		let input_notes = [
			Note::new(0, 0, owner, blinding),
			Note::new(0, 0, owner, blinding),
		];
		let output_notes = [
			Note::new(0, 0, owner, blinding),
			Note::new(0, 0, owner, blinding),
		];

		let (_, path_elements, path_indices) =
			create_test_merkle_paths(input_notes[0].commitment(), input_notes[1].commitment());

		let witness = TransferWitness::new(
			input_notes,
			[spending_key, spending_key],
			path_elements,
			path_indices,
			output_notes,
		);

		assert!(witness.validate().is_ok());
	}

	// ===== TransferPublicInputs Tests =====

	#[test]
	fn test_public_inputs_from_witness() {
		let (witness, root) = create_test_witness();
		let public_inputs = TransferPublicInputs::from_witness(&witness, root);

		assert_eq!(public_inputs.merkle_root, root);
		assert_eq!(public_inputs.nullifiers.len(), NUM_INPUTS);
		assert_eq!(public_inputs.commitments.len(), NUM_OUTPUTS);
	}

	#[test]
	fn test_public_inputs_to_vec() {
		let (witness, root) = create_test_witness();
		let public_inputs = TransferPublicInputs::from_witness(&witness, root);
		let vec = public_inputs.to_vec();

		assert_eq!(vec.len(), 1 + NUM_INPUTS + NUM_OUTPUTS);
		assert_eq!(vec[0], root);
		assert_eq!(vec[1], public_inputs.nullifiers[0]);
		assert_eq!(vec[2], public_inputs.nullifiers[1]);
		assert_eq!(vec[3], public_inputs.commitments[0]);
		assert_eq!(vec[4], public_inputs.commitments[1]);
	}

	#[test]
	fn test_public_inputs_nullifiers_unique() {
		let (witness, root) = create_test_witness();
		let public_inputs = TransferPublicInputs::from_witness(&witness, root);

		assert_ne!(public_inputs.nullifiers[0], public_inputs.nullifiers[1]);
	}

	#[test]
	fn test_public_inputs_clone() {
		let (witness, root) = create_test_witness();
		let public_inputs1 = TransferPublicInputs::from_witness(&witness, root);
		let public_inputs2 = public_inputs1.clone();

		assert_eq!(public_inputs1.merkle_root, public_inputs2.merkle_root);
		assert_eq!(public_inputs1.nullifiers, public_inputs2.nullifiers);
		assert_eq!(public_inputs1.commitments, public_inputs2.commitments);
	}

	// ===== TransferCircuit Tests =====

	#[test]
	fn test_transfer_circuit_new() {
		let (witness, root) = create_test_witness();
		let circuit = TransferCircuit::new(witness.clone(), root);

		assert!(circuit.witness.is_some());
		assert!(circuit.merkle_root.is_some());
		assert_eq!(circuit.merkle_root.unwrap(), root);
	}

	#[test]
	fn test_transfer_circuit_new_for_setup() {
		let circuit = TransferCircuit::new_for_setup();

		assert!(circuit.witness.is_none());
		assert!(circuit.merkle_root.is_none());
	}

	#[test]
	fn test_transfer_circuit_public_inputs() {
		let (witness, root) = create_test_witness();
		let circuit = TransferCircuit::new(witness.clone(), root);

		let public_inputs = circuit.public_inputs();
		assert_eq!(public_inputs.merkle_root, root);
		assert_eq!(public_inputs.nullifiers, witness.nullifiers());
		assert_eq!(public_inputs.commitments, witness.output_commitments());
	}

	#[test]
	#[should_panic(expected = "Cannot get public inputs without witness")]
	fn test_transfer_circuit_public_inputs_without_witness() {
		let circuit = TransferCircuit::new_for_setup();
		let _ = circuit.public_inputs();
	}

	#[test]
	fn test_transfer_circuit_clone() {
		let (witness, root) = create_test_witness();
		let circuit1 = TransferCircuit::new(witness, root);
		let circuit2 = circuit1.clone();

		assert!(circuit2.witness.is_some());
		assert_eq!(circuit2.merkle_root, circuit1.merkle_root);
	}

	#[test]
	fn test_transfer_circuit_satisfies_constraints() {
		let (witness, root) = create_test_witness();
		let circuit = TransferCircuit::new(witness, root);

		let cs = ConstraintSystem::<Bn254Fr>::new_ref();
		circuit.generate_constraints(cs.clone()).unwrap();

		assert!(cs.is_satisfied().unwrap());
	}

	#[test]
	fn test_transfer_circuit_has_constraints() {
		let (witness, root) = create_test_witness();
		let circuit = TransferCircuit::new(witness, root);

		let cs = ConstraintSystem::<Bn254Fr>::new_ref();
		circuit.generate_constraints(cs.clone()).unwrap();

		assert!(cs.num_constraints() > 0);
	}

	// ===== Integration Tests =====

	#[test]
	fn test_end_to_end_transfer() {
		let (witness, root) = create_test_witness();

		// Validate witness
		assert!(witness.validate().is_ok());

		// Create circuit
		let circuit = TransferCircuit::new(witness.clone(), root);

		// Get public inputs
		let public_inputs = circuit.public_inputs();
		assert_eq!(public_inputs.nullifiers, witness.nullifiers());

		// Generate and verify constraints
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();
		circuit.generate_constraints(cs.clone()).unwrap();
		assert!(cs.is_satisfied().unwrap());
	}

	#[test]
	fn test_different_owners() {
		let owner1 = Bn254Fr::from(1000u64);
		let owner2 = Bn254Fr::from(2000u64);
		let blinding = Bn254Fr::from(3000u64);
		let spending_key = Bn254Fr::from(4000u64);

		let input_notes = [
			Note::new(700, 0, owner1, blinding),
			Note::new(300, 0, owner1, blinding),
		];
		let output_notes = [
			Note::new(500, 0, owner2, blinding),
			Note::new(500, 0, owner2, blinding),
		];

		let (root, path_elements, path_indices) =
			create_test_merkle_paths(input_notes[0].commitment(), input_notes[1].commitment());

		let witness = TransferWitness::new(
			input_notes,
			[spending_key, spending_key],
			path_elements,
			path_indices,
			output_notes,
		);

		assert!(witness.validate().is_ok());

		let circuit = TransferCircuit::new(witness, root);
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();
		circuit.generate_constraints(cs.clone()).unwrap();
		assert!(cs.is_satisfied().unwrap());
	}

	#[test]
	fn test_asymmetric_split() {
		let owner = Bn254Fr::from(100u64);
		let blinding = Bn254Fr::from(200u64);
		let spending_key = Bn254Fr::from(300u64);

		let input_notes = [
			Note::new(900, 0, owner, blinding),
			Note::new(100, 0, owner, blinding),
		];
		let output_notes = [
			Note::new(100, 0, owner, blinding),
			Note::new(900, 0, owner, blinding),
		];

		let (root, path_elements, path_indices) =
			create_test_merkle_paths(input_notes[0].commitment(), input_notes[1].commitment());

		let witness = TransferWitness::new(
			input_notes,
			[spending_key, spending_key],
			path_elements,
			path_indices,
			output_notes,
		);

		assert!(witness.validate().is_ok());

		let circuit = TransferCircuit::new(witness, root);
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();
		circuit.generate_constraints(cs.clone()).unwrap();
		assert!(cs.is_satisfied().unwrap());
	}

	// ===== Edge Case Tests =====

	#[test]
	fn test_max_value_transfer() {
		let owner = Bn254Fr::from(100u64);
		let blinding = Bn254Fr::from(200u64);
		let spending_key = Bn254Fr::from(300u64);

		let input_notes = [
			Note::new(u64::MAX / 2, 0, owner, blinding),
			Note::new(u64::MAX / 2, 0, owner, blinding),
		];
		let output_notes = [
			Note::new(u64::MAX / 2, 0, owner, blinding),
			Note::new(u64::MAX / 2, 0, owner, blinding),
		];

		let (_root, path_elements, path_indices) =
			create_test_merkle_paths(input_notes[0].commitment(), input_notes[1].commitment());

		let witness = TransferWitness::new(
			input_notes,
			[spending_key, spending_key],
			path_elements,
			path_indices,
			output_notes,
		);

		assert!(witness.validate().is_ok());
	}

	#[test]
	fn test_merkle_path_verification() {
		let leaf0 = Bn254Fr::from(111u64);
		let leaf1 = Bn254Fr::from(222u64);

		let (root, paths, indices) = create_test_merkle_paths(leaf0, leaf1);

		// Verify both paths lead to same root
		let hasher = LightPoseidonHasher;
		let service = MerkleService::new(hasher);

		let path0_field: Vec<FieldElement> =
			paths[0].iter().map(|&p| FieldElement::new(p)).collect();
		let root0 = service.compute_root(
			&Commitment::new(FieldElement::new(leaf0)),
			&path0_field,
			&indices[0],
		);

		assert_eq!(root0.inner(), root);
	}

	// ===== Helper Function Tests =====

	#[test]
	fn test_create_test_merkle_paths() {
		let leaf0 = Bn254Fr::from(100u64);
		let leaf1 = Bn254Fr::from(200u64);

		let (root, paths, indices) = create_test_merkle_paths(leaf0, leaf1);

		// Check structure
		assert_eq!(paths.len(), 2);
		assert_eq!(indices.len(), 2);
		assert_eq!(paths[0].len(), TREE_DEPTH);
		assert_eq!(paths[1].len(), TREE_DEPTH);

		// Check root is non-zero
		assert_ne!(root, Bn254Fr::from(0u64));

		// Check siblings at level 0
		assert_eq!(paths[0][0], leaf1);
		assert_eq!(paths[1][0], leaf0);
		assert!(!indices[0][0]); // leaf0 is left
		assert!(indices[1][0]); // leaf1 is right
	}

	#[test]
	fn test_create_test_witness_structure() {
		let (witness, root) = create_test_witness();

		// Check witness structure
		assert_eq!(witness.input_notes.len(), NUM_INPUTS);
		assert_eq!(witness.output_notes.len(), NUM_OUTPUTS);
		assert_eq!(witness.spending_keys.len(), NUM_INPUTS);
		assert_eq!(witness.merkle_path_elements.len(), NUM_INPUTS);
		assert_eq!(witness.merkle_path_indices.len(), NUM_INPUTS);

		// Check root is valid
		assert_ne!(root, Bn254Fr::from(0u64));
	}

	#[test]
	fn test_constants() {
		assert_eq!(NUM_INPUTS, 2);
		assert_eq!(NUM_OUTPUTS, 2);
		// TREE_DEPTH is always > 0 by definition
	}
}
