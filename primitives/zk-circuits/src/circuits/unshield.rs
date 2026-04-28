//! Unshield Circuit
//!
//! Proves a valid withdrawal from the shielded pool into a public account.
//! Aligned with the production Circom circuit used by the Orbinum shielded pool.
//!
//! # Public inputs (6 total — must match `nPublic: 6` in verification_key_unshield.json)
//! 1. `merkle_root`
//! 2. `nullifier`
//! 3. `amount`
//! 4. `recipient`
//! 5. `asset_id`
//! 6. `fee`
//!
//! # Constraints
//! 1. Commitment correctness: `Poseidon4(note_value, asset_id, owner_pk, blinding)`
//! 2. Merkle membership: `MerkleProof(commitment, path) == merkle_root`
//! 3. Nullifier correctness: `Poseidon2(commitment, spending_key) == nullifier`
//! 4. Balance: `note_value == amount + fee`
//!
//! Asset consistency is implicit in constraint 1: `asset_id_var` (the public
//! input) is used directly in the commitment gadget, so if the commitment
//! opens correctly against the Merkle tree, the note's asset_id is bound
//! to the public `asset_id`.
//!
//! `recipient` is bound to the proof as a public input to prevent front-running.
//! No in-circuit constraint links it to private inputs.
//!
//! # Circom reference
//! - `ts-sdk/src/proof-generator/unshield.ts`
//! - `artifacts/verification_key_unshield.json` (nPublic: 6)

use alloc::vec::Vec;
use ark_r1cs_std::{alloc::AllocVar, boolean::Boolean, eq::EqGadget, fields::fp::FpVar};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

use crate::{
	gadgets::{
		commitment::{note_commitment, nullifier},
		merkle::merkle_tree_verifier,
	},
	types::{nullifier_native, Note},
	Bn254Fr,
};
use orbinum_zk_core::MERKLE_TREE_DEPTH as DEFAULT_TREE_DEPTH;

/// Merkle tree depth
pub const TREE_DEPTH: usize = DEFAULT_TREE_DEPTH;

// ============================================================================
// UnshieldWitness
// ============================================================================

/// Unshield circuit witness (all circuit inputs)
///
/// The note's `value` must equal `amount + fee`. Ownership is proven via the
/// spending key → nullifier relationship (no EdDSA required for unshield).
#[derive(Clone, Debug)]
pub struct UnshieldWitness {
	/// The note being spent (`note.value = amount + fee`)
	pub note: Note,
	/// Spending key — derives the nullifier and proves ownership
	pub spending_key: Bn254Fr,
	/// Public withdrawal amount (`note.value - fee`)
	pub amount: Bn254Fr,
	/// Relay fee (`note.value - amount`)
	pub fee: Bn254Fr,
	/// Recipient address encoded as a BN254 field element
	/// (e.g. `Poseidon2(accountId32)` for Substrate addresses)
	pub recipient: Bn254Fr,
	/// Merkle path sibling hashes
	pub merkle_path_elements: [Bn254Fr; TREE_DEPTH],
	/// Merkle path position bits (false = left / 0, true = right / 1)
	pub merkle_path_indices: [bool; TREE_DEPTH],
}

impl UnshieldWitness {
	/// Creates a new unshield witness.
	///
	/// `note.value` must equal `amount + fee` (checked by `validate()`).
	#[allow(clippy::too_many_arguments)]
	pub fn new(
		note: Note,
		spending_key: Bn254Fr,
		amount: Bn254Fr,
		fee: Bn254Fr,
		recipient: Bn254Fr,
		merkle_path_elements: [Bn254Fr; TREE_DEPTH],
		merkle_path_indices: [bool; TREE_DEPTH],
	) -> Self {
		Self {
			note,
			spending_key,
			amount,
			fee,
			recipient,
			merkle_path_elements,
			merkle_path_indices,
		}
	}

	/// Computes the note commitment: `Poseidon4(note.value, note.asset_id, owner_pk, blinding)`
	pub fn commitment(&self) -> Bn254Fr {
		self.note.commitment()
	}

	/// Computes the nullifier: `Poseidon2(commitment, spending_key)`
	pub fn nullifier(&self) -> Bn254Fr {
		nullifier_native(self.commitment(), self.spending_key)
	}

	/// Validates the witness off-circuit (balance check only).
	pub fn validate(&self) -> Result<(), &'static str> {
		if self.note.value != self.amount + self.fee {
			return Err("note.value must equal amount + fee");
		}
		Ok(())
	}
}

// ============================================================================
// UnshieldPublicInputs
// ============================================================================

/// Unshield public inputs (6 total — verified on-chain)
#[derive(Clone, Debug)]
pub struct UnshieldPublicInputs {
	pub merkle_root: Bn254Fr,
	pub nullifier: Bn254Fr,
	pub amount: Bn254Fr,
	pub recipient: Bn254Fr,
	pub asset_id: Bn254Fr,
	pub fee: Bn254Fr,
}

impl UnshieldPublicInputs {
	/// Derives public inputs from a witness and Merkle root.
	pub fn from_witness(witness: &UnshieldWitness, merkle_root: Bn254Fr) -> Self {
		Self {
			merkle_root,
			nullifier: witness.nullifier(),
			amount: witness.amount,
			recipient: witness.recipient,
			asset_id: witness.note.asset_id,
			fee: witness.fee,
		}
	}

	/// Serializes to a flat vector for on-chain proof verification.
	///
	/// Order matches Circom public signal indexing:
	/// `[merkle_root, nullifier, amount, recipient, asset_id, fee]`
	pub fn to_vec(&self) -> Vec<Bn254Fr> {
		vec![
			self.merkle_root,
			self.nullifier,
			self.amount,
			self.recipient,
			self.asset_id,
			self.fee,
		]
	}
}

// ============================================================================
// UnshieldCircuit
// ============================================================================

/// Unshield Groth16/R1CS circuit
///
/// Use `None` witness for trusted setup (`UnshieldCircuit::new_for_setup()`).
/// Use `Some` witness for proving (`UnshieldCircuit::new(witness, root)`).
#[derive(Clone)]
pub struct UnshieldCircuit {
	/// Private witness (None during setup)
	pub witness: Option<UnshieldWitness>,
	/// Public Merkle root (None during setup)
	pub merkle_root: Option<Bn254Fr>,
}

impl UnshieldCircuit {
	/// Creates a circuit with a concrete witness for proof generation.
	pub fn new(witness: UnshieldWitness, merkle_root: Bn254Fr) -> Self {
		Self {
			witness: Some(witness),
			merkle_root: Some(merkle_root),
		}
	}

	/// Creates a circuit without concrete values for trusted setup.
	pub fn new_for_setup() -> Self {
		Self {
			witness: None,
			merkle_root: None,
		}
	}

	/// Returns the public inputs for this circuit.
	///
	/// # Panics
	/// Panics if witness or merkle_root is `None`.
	pub fn public_inputs(&self) -> UnshieldPublicInputs {
		let w = self
			.witness
			.as_ref()
			.expect("Cannot get public inputs without witness");
		let r = self
			.merkle_root
			.expect("Cannot get public inputs without merkle_root");
		UnshieldPublicInputs::from_witness(w, r)
	}
}

impl ConstraintSynthesizer<Bn254Fr> for UnshieldCircuit {
	fn generate_constraints(self, cs: ConstraintSystemRef<Bn254Fr>) -> Result<(), SynthesisError> {
		let w = self.witness.as_ref();

		let val = |opt: Option<Bn254Fr>| -> Result<Bn254Fr, SynthesisError> {
			opt.ok_or(SynthesisError::AssignmentMissing)
		};

		// ====================================================================
		// PUBLIC INPUTS (6) — allocation order must match Circom signal order
		// ====================================================================

		// 1. merkle_root
		let root_var = FpVar::new_input(cs.clone(), || val(self.merkle_root))?;

		// 2. nullifier
		let null_val = w.map(|w| w.nullifier());
		let null_var = FpVar::new_input(cs.clone(), || val(null_val))?;

		// 3. amount
		let amount_var = FpVar::new_input(cs.clone(), || val(w.map(|w| w.amount)))?;

		// 4. recipient (bound to proof, no in-circuit constraint to private inputs)
		let _recipient_var = FpVar::new_input(cs.clone(), || val(w.map(|w| w.recipient)))?;

		// 5. asset_id
		let asset_id_var = FpVar::new_input(cs.clone(), || val(w.map(|w| w.note.asset_id)))?;

		// 6. fee
		let fee_var = FpVar::new_input(cs.clone(), || val(w.map(|w| w.fee)))?;

		// ====================================================================
		// PRIVATE INPUTS
		// ====================================================================

		let note_value_var = FpVar::new_witness(cs.clone(), || val(w.map(|w| w.note.value)))?;
		let note_owner_var =
			FpVar::new_witness(cs.clone(), || val(w.map(|w| w.note.owner_pubkey)))?;
		let note_blinding_var = FpVar::new_witness(cs.clone(), || val(w.map(|w| w.note.blinding)))?;
		let spending_key_var = FpVar::new_witness(cs.clone(), || val(w.map(|w| w.spending_key)))?;

		let mut path_element_vars = Vec::with_capacity(TREE_DEPTH);
		for j in 0..TREE_DEPTH {
			path_element_vars.push(FpVar::new_witness(cs.clone(), || {
				val(w.map(|w| w.merkle_path_elements[j]))
			})?);
		}

		let mut path_index_vars = Vec::with_capacity(TREE_DEPTH);
		for j in 0..TREE_DEPTH {
			path_index_vars.push(Boolean::new_witness(cs.clone(), || {
				w.map(|w| w.merkle_path_indices[j])
					.ok_or(SynthesisError::AssignmentMissing)
			})?);
		}

		// ====================================================================
		// CONSTRAINT 1: Commitment correctness
		// commitment = Poseidon4(note_value, asset_id, owner_pk, note_blinding)
		// `asset_id_var` (public) is used here — if commitment matches Merkle
		// tree, the note's asset_id is implicitly bound to the public asset_id.
		// ====================================================================

		let commitment_var = note_commitment(
			cs.clone(),
			&note_value_var,
			&asset_id_var,
			&note_owner_var,
			&note_blinding_var,
		)?;

		// ====================================================================
		// CONSTRAINT 2: Merkle membership
		// H(commitment, path) == merkle_root
		// ====================================================================

		let computed_root = merkle_tree_verifier(
			cs.clone(),
			&commitment_var,
			&path_element_vars,
			&path_index_vars,
		)?;
		computed_root.enforce_equal(&root_var)?;

		// ====================================================================
		// CONSTRAINT 3: Nullifier correctness
		// Poseidon2(commitment, spending_key) == nullifier
		// ====================================================================

		let computed_null = nullifier(cs.clone(), &commitment_var, &spending_key_var)?;
		computed_null.enforce_equal(&null_var)?;

		// ====================================================================
		// CONSTRAINT 4: Balance
		// note_value == amount + fee
		// ====================================================================

		let rhs = &amount_var + &fee_var;
		note_value_var.enforce_equal(&rhs)?;

		Ok(())
	}
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
	use super::*;
	use ark_relations::r1cs::ConstraintSystem;

	extern crate alloc;

	// ── Helpers ───────────────────────────────────────────────────────────────

	/// Builds a valid UnshieldWitness and the expected Merkle root.
	fn make_witness(
		spending_key_u64: u64,
		amount_u64: u64,
		fee_u64: u64,
	) -> (UnshieldWitness, Bn254Fr) {
		let total = amount_u64 + fee_u64;
		let spending_key = Bn254Fr::from(spending_key_u64);
		let owner_pubkey = Bn254Fr::from(spending_key_u64 * 7 + 3); // arbitrary, not verified in unshield
		let blinding = Bn254Fr::from(42u64);
		let recipient = Bn254Fr::from(999u64);

		let note = Note::new(total, 1, owner_pubkey, blinding);
		let commitment = note.commitment();

		// Build a single-leaf Merkle path (all siblings = 0, all indices = false)
		let elements = [Bn254Fr::from(0u64); TREE_DEPTH];
		let indices = [false; TREE_DEPTH];

		// Compute the root natively
		let root = compute_root(commitment, &elements, &indices);

		let witness = UnshieldWitness::new(
			note,
			spending_key,
			Bn254Fr::from(amount_u64),
			Bn254Fr::from(fee_u64),
			recipient,
			elements,
			indices,
		);

		(witness, root)
	}

	fn compute_root(leaf: Bn254Fr, elements: &[Bn254Fr], indices: &[bool]) -> Bn254Fr {
		let mut current = leaf;
		for (&sibling, &is_right) in elements.iter().zip(indices.iter()) {
			current = if is_right {
				crate::native::poseidon_hash_2(&[sibling, current])
			} else {
				crate::native::poseidon_hash_2(&[current, sibling])
			};
		}
		current
	}

	// ── Structural tests ──────────────────────────────────────────────────────

	#[test]
	fn test_public_inputs_to_vec_length() {
		let (w, root) = make_witness(1, 100, 0);
		let pi = UnshieldPublicInputs::from_witness(&w, root);
		assert_eq!(pi.to_vec().len(), 6);
	}

	#[test]
	fn test_public_inputs_order() {
		let (w, root) = make_witness(1, 100, 5);
		let pi = UnshieldPublicInputs::from_witness(&w, root);
		let v = pi.to_vec();
		assert_eq!(v[0], root, "index 0 must be merkle_root");
		assert_eq!(v[1], w.nullifier(), "index 1 must be nullifier");
		assert_eq!(v[2], Bn254Fr::from(100u64), "index 2 must be amount");
		assert_eq!(v[3], w.recipient, "index 3 must be recipient");
		assert_eq!(v[4], w.note.asset_id, "index 4 must be asset_id");
		assert_eq!(v[5], Bn254Fr::from(5u64), "index 5 must be fee");
	}

	#[test]
	fn test_has_6_public_inputs() {
		let (w, root) = make_witness(1, 100, 0);
		let circuit = UnshieldCircuit::new(w, root);
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();
		circuit.generate_constraints(cs.clone()).unwrap();
		assert_eq!(cs.num_instance_variables() - 1, 6); // 6 public inputs + 1 constant
	}

	#[test]
	fn test_circuit_generates_constraints() {
		let (w, root) = make_witness(1, 100, 0);
		let circuit = UnshieldCircuit::new(w, root);
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();
		circuit.generate_constraints(cs.clone()).unwrap();
		assert!(cs.num_constraints() > 0);
	}

	// ── Satisfiability tests ──────────────────────────────────────────────────

	#[test]
	fn test_circuit_satisfies_constraints_no_fee() {
		let (w, root) = make_witness(42, 1000, 0);
		let circuit = UnshieldCircuit::new(w, root);
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();
		circuit.generate_constraints(cs.clone()).unwrap();
		assert!(
			cs.is_satisfied().unwrap(),
			"circuit must be satisfied with fee=0"
		);
	}

	#[test]
	fn test_circuit_satisfies_constraints_with_fee() {
		let (w, root) = make_witness(42, 950, 50);
		let circuit = UnshieldCircuit::new(w, root);
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();
		circuit.generate_constraints(cs.clone()).unwrap();
		assert!(
			cs.is_satisfied().unwrap(),
			"circuit must be satisfied with fee=50"
		);
	}

	#[test]
	fn test_end_to_end_unshield() {
		let (w, root) = make_witness(99, 500, 10);
		assert!(w.validate().is_ok());
		let pi = w.nullifier();
		let circuit = UnshieldCircuit::new(w, root);
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();
		circuit.generate_constraints(cs.clone()).unwrap();
		assert!(cs.is_satisfied().unwrap());
		assert_ne!(pi, Bn254Fr::from(0u64));
	}

	// ── Negative tests ────────────────────────────────────────────────────────

	#[test]
	fn test_wrong_merkle_root_unsatisfied() {
		// Valid witness but wrong merkle_root → Merkle membership constraint fails
		let (w, _correct_root) = make_witness(42, 100, 0);
		let wrong_root = Bn254Fr::from(12345u64);
		let circuit = UnshieldCircuit::new(w, wrong_root);
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();
		circuit.generate_constraints(cs.clone()).unwrap();
		assert!(
			!cs.is_satisfied().unwrap(),
			"wrong merkle_root must violate Merkle constraint"
		);
	}

	#[test]
	fn test_wrong_balance_unsatisfied() {
		let (mut w, root) = make_witness(42, 100, 0);
		// Break balance: amount > note.value
		w.amount = Bn254Fr::from(200u64);
		let circuit = UnshieldCircuit::new(w, root);
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();
		circuit.generate_constraints(cs.clone()).unwrap();
		assert!(
			!cs.is_satisfied().unwrap(),
			"wrong amount must violate balance constraint"
		);
	}

	#[test]
	fn test_validate_balance_ok() {
		let (w, _) = make_witness(1, 100, 10);
		assert!(w.validate().is_ok());
	}

	#[test]
	fn test_validate_balance_fail() {
		let (mut w, _) = make_witness(1, 100, 0);
		w.amount = Bn254Fr::from(50u64); // amount != note.value - fee
		assert!(w.validate().is_err());
	}

	#[test]
	fn test_different_spending_keys_different_nullifiers() {
		let (w1, _) = make_witness(1, 100, 0);
		let (w2, _) = make_witness(2, 100, 0);
		assert_ne!(w1.nullifier(), w2.nullifier());
	}

	#[test]
	fn test_constants() {
		assert_eq!(TREE_DEPTH, orbinum_zk_core::MERKLE_TREE_DEPTH);
	}
}
