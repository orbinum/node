//! Private Transfer Circuit
//!
//! Proves a valid 2-input / 2-output private transfer, aligned with the
//! production Circom circuit used by the Orbinum shielded pool.
//!
//! # Public inputs (7 total — must match `nPublic: 7` in verification_key_transfer.json)
//! 1. `merkle_root`
//! 2. `nullifiers[0]`
//! 3. `nullifiers[1]`
//! 4. `output_commitments[0]`
//! 5. `output_commitments[1]`
//! 6. `asset_id`
//! 7. `fee`
//!
//! # Constraints
//! 1. Input commitment correctness: `Poseidon4(value, asset_id, Ax, blinding)`
//! 2. Merkle membership: `MerkleProof(commitment, path) == merkle_root`
//! 3. EdDSA ownership: `S × Base8 == R8 + Poseidon5(R8x, R8y, Ax, Ay, c) × A`
//! 4. Nullifier correctness: `Poseidon2(commitment, spending_key)`
//! 5. Output commitment correctness: `Poseidon4(value, asset_id, owner_pk, blinding)`
//! 6. Balance conservation: `sum(inputs) == sum(outputs) + fee`
//! 7. Asset consistency: all notes use public `asset_id`
//!
//! # Circom reference
//! - `ts-sdk/src/proof-generator/transfer.ts`
//! - `artifacts/verification_key_transfer.json` (nPublic: 7)

use alloc::vec::Vec;
use ark_r1cs_std::{alloc::AllocVar, boolean::Boolean, eq::EqGadget, fields::fp::FpVar};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

use crate::{
	gadgets::{
		commitment::{note_commitment, nullifier},
		eddsa::verify_eddsa,
		merkle::merkle_tree_verifier,
	},
	types::{nullifier_native, Note},
	Bn254Fr,
};
use orbinum_zk_core::MERKLE_TREE_DEPTH as DEFAULT_TREE_DEPTH;

/// Number of inputs in a transfer (fixed at 2)
pub const NUM_INPUTS: usize = 2;

/// Number of outputs in a transfer (fixed at 2)
pub const NUM_OUTPUTS: usize = 2;

/// Merkle tree depth
pub const TREE_DEPTH: usize = DEFAULT_TREE_DEPTH;

// ============================================================================
// TransferWitness
// ============================================================================

/// Private transfer witness (all secret inputs)
///
/// `owner_pubkey` in each `Note` is the Baby JubJub `Ax` (x-coordinate of
/// `spending_key × Base8`). The circuit proves ownership via EdDSA-Poseidon.
#[derive(Clone, Debug)]
pub struct TransferWitness {
	/// Input notes being spent
	pub input_notes: [Note; NUM_INPUTS],
	/// Spending keys (used for nullifier derivation and EdDSA signing)
	pub spending_keys: [Bn254Fr; NUM_INPUTS],
	/// Baby JubJub public key Y-coordinates (`A.y = spending_key × Base8 .y`)
	pub owner_ay: [Bn254Fr; NUM_INPUTS],
	/// EdDSA signature R8 X-coordinates (`r × Base8 .x`)
	pub sig_r8x: [Bn254Fr; NUM_INPUTS],
	/// EdDSA signature R8 Y-coordinates (`r × Base8 .y`)
	pub sig_r8y: [Bn254Fr; NUM_INPUTS],
	/// EdDSA signature scalars (`r + h × spending_key mod SUBORDER`)
	pub sig_s: [Bn254Fr; NUM_INPUTS],
	/// Merkle path sibling hashes
	pub merkle_path_elements: [[Bn254Fr; TREE_DEPTH]; NUM_INPUTS],
	/// Merkle path position bits (false = left, true = right)
	pub merkle_path_indices: [[bool; TREE_DEPTH]; NUM_INPUTS],
	/// Output notes being created
	pub output_notes: [Note; NUM_OUTPUTS],
	/// Gasless relay fee (`inputs == outputs + fee`)
	pub fee: Bn254Fr,
}

impl TransferWitness {
	/// Creates a new transfer witness
	#[allow(clippy::too_many_arguments)]
	pub fn new(
		input_notes: [Note; NUM_INPUTS],
		spending_keys: [Bn254Fr; NUM_INPUTS],
		owner_ay: [Bn254Fr; NUM_INPUTS],
		sig_r8x: [Bn254Fr; NUM_INPUTS],
		sig_r8y: [Bn254Fr; NUM_INPUTS],
		sig_s: [Bn254Fr; NUM_INPUTS],
		merkle_path_elements: [[Bn254Fr; TREE_DEPTH]; NUM_INPUTS],
		merkle_path_indices: [[bool; TREE_DEPTH]; NUM_INPUTS],
		output_notes: [Note; NUM_OUTPUTS],
		fee: Bn254Fr,
	) -> Self {
		Self {
			input_notes,
			spending_keys,
			owner_ay,
			sig_r8x,
			sig_r8y,
			sig_s,
			merkle_path_elements,
			merkle_path_indices,
			output_notes,
			fee,
		}
	}

	/// Asset ID for this transfer (taken from the first input note)
	pub fn asset_id(&self) -> Bn254Fr {
		self.input_notes[0].asset_id
	}

	/// Computes the input commitments: `Poseidon4(value, asset_id, Ax, blinding)`
	pub fn input_commitments(&self) -> [Bn254Fr; NUM_INPUTS] {
		[
			self.input_notes[0].commitment(),
			self.input_notes[1].commitment(),
		]
	}

	/// Computes the nullifiers: `Poseidon2(commitment, spending_key)`
	pub fn nullifiers(&self) -> [Bn254Fr; NUM_INPUTS] {
		let comms = self.input_commitments();
		[
			nullifier_native(comms[0], self.spending_keys[0]),
			nullifier_native(comms[1], self.spending_keys[1]),
		]
	}

	/// Computes the output commitments
	pub fn output_commitments(&self) -> [Bn254Fr; NUM_OUTPUTS] {
		[
			self.output_notes[0].commitment(),
			self.output_notes[1].commitment(),
		]
	}

	/// Validates the witness off-circuit (balance, asset consistency)
	pub fn validate(&self) -> Result<(), &'static str> {
		// Balance: sum(inputs) == sum(outputs) + fee
		let input_sum = self.input_notes[0].value + self.input_notes[1].value;
		let output_sum = self.output_notes[0].value + self.output_notes[1].value;
		if input_sum != output_sum + self.fee {
			return Err("Balance not conserved: sum(inputs) != sum(outputs) + fee");
		}

		// Asset consistency
		let asset_id = self.input_notes[0].asset_id;
		for note in &self.input_notes {
			if note.asset_id != asset_id {
				return Err("Asset mismatch in input notes");
			}
		}
		for note in &self.output_notes {
			if note.asset_id != asset_id {
				return Err("Asset mismatch in output notes");
			}
		}

		Ok(())
	}
}

// ============================================================================
// TransferPublicInputs
// ============================================================================

/// Transfer circuit public inputs (verified on-chain, 7 total)
#[derive(Clone, Debug)]
pub struct TransferPublicInputs {
	/// Current Merkle tree root
	pub merkle_root: Bn254Fr,
	/// Nullifiers for spent input notes
	pub nullifiers: [Bn254Fr; NUM_INPUTS],
	/// Commitments for new output notes
	pub commitments: [Bn254Fr; NUM_OUTPUTS],
	/// Asset identifier (same for all inputs and outputs)
	pub asset_id: Bn254Fr,
	/// Relay fee
	pub fee: Bn254Fr,
}

impl TransferPublicInputs {
	/// Derives public inputs from a witness and Merkle root
	pub fn from_witness(witness: &TransferWitness, merkle_root: Bn254Fr) -> Self {
		Self {
			merkle_root,
			nullifiers: witness.nullifiers(),
			commitments: witness.output_commitments(),
			asset_id: witness.asset_id(),
			fee: witness.fee,
		}
	}

	/// Serializes to a flat vector for proof verification
	///
	/// Order matches Circom public signal indexing:
	/// `[merkle_root, null0, null1, comm0, comm1, asset_id, fee]`
	pub fn to_vec(&self) -> Vec<Bn254Fr> {
		let mut v = Vec::with_capacity(1 + NUM_INPUTS + NUM_OUTPUTS + 2);
		v.push(self.merkle_root);
		v.extend_from_slice(&self.nullifiers);
		v.extend_from_slice(&self.commitments);
		v.push(self.asset_id);
		v.push(self.fee);
		v
	}
}

// ============================================================================
// TransferCircuit
// ============================================================================

/// Private transfer Groth16/R1CS circuit
///
/// Use `None` witness for trusted setup (`TransferCircuit::new_for_setup()`).
/// Use `Some` witness for proving (`TransferCircuit::new(witness, root)`).
#[derive(Clone)]
pub struct TransferCircuit {
	/// Private witness (None during setup)
	pub witness: Option<TransferWitness>,
	/// Public Merkle root (None during setup)
	pub merkle_root: Option<Bn254Fr>,
}

impl TransferCircuit {
	/// Creates a circuit with a concrete witness for proof generation
	pub fn new(witness: TransferWitness, merkle_root: Bn254Fr) -> Self {
		Self {
			witness: Some(witness),
			merkle_root: Some(merkle_root),
		}
	}

	/// Creates a circuit without concrete values for trusted setup
	pub fn new_for_setup() -> Self {
		Self {
			witness: None,
			merkle_root: None,
		}
	}

	/// Returns the public inputs for this circuit
	///
	/// # Panics
	/// Panics if witness or merkle_root is `None`.
	pub fn public_inputs(&self) -> TransferPublicInputs {
		let w = self
			.witness
			.as_ref()
			.expect("Cannot get public inputs without witness");
		let r = self
			.merkle_root
			.expect("Cannot get public inputs without merkle_root");
		TransferPublicInputs::from_witness(w, r)
	}
}

impl ConstraintSynthesizer<Bn254Fr> for TransferCircuit {
	fn generate_constraints(self, cs: ConstraintSystemRef<Bn254Fr>) -> Result<(), SynthesisError> {
		let w = self.witness.as_ref();

		// Helper: get Option value or return AssignmentMissing (setup mode)
		let val = |opt: Option<Bn254Fr>| -> Result<Bn254Fr, SynthesisError> {
			opt.ok_or(SynthesisError::AssignmentMissing)
		};

		// ====================================================================
		// PUBLIC INPUTS (7) — allocation order must match Circom signal order
		// ====================================================================

		// 1. merkle_root
		let root_var = FpVar::new_input(cs.clone(), || val(self.merkle_root))?;

		// 2–3. nullifiers
		let null_vals = w.map(|w| w.nullifiers());
		let mut null_vars = Vec::with_capacity(NUM_INPUTS);
		for i in 0..NUM_INPUTS {
			null_vars.push(FpVar::new_input(cs.clone(), || {
				val(null_vals.map(|n| n[i]))
			})?);
		}

		// 4–5. output commitments
		let out_comm_vals = w.map(|w| w.output_commitments());
		let mut out_comm_vars = Vec::with_capacity(NUM_OUTPUTS);
		for i in 0..NUM_OUTPUTS {
			out_comm_vars.push(FpVar::new_input(cs.clone(), || {
				val(out_comm_vals.map(|c| c[i]))
			})?);
		}

		// 6. asset_id
		let asset_id_var =
			FpVar::new_input(cs.clone(), || val(w.map(|w| w.input_notes[0].asset_id)))?;

		// 7. fee
		let fee_var = FpVar::new_input(cs.clone(), || val(w.map(|w| w.fee)))?;

		// ====================================================================
		// PRIVATE INPUTS
		// ====================================================================

		let mut in_value_vars = Vec::with_capacity(NUM_INPUTS);
		let mut in_ax_vars = Vec::with_capacity(NUM_INPUTS); // = owner_pubkey
		let mut in_ay_vars = Vec::with_capacity(NUM_INPUTS);
		let mut in_blinding_vars = Vec::with_capacity(NUM_INPUTS);
		let mut spend_key_vars = Vec::with_capacity(NUM_INPUTS);
		let mut sig_r8x_vars = Vec::with_capacity(NUM_INPUTS);
		let mut sig_r8y_vars = Vec::with_capacity(NUM_INPUTS);
		let mut sig_s_vars = Vec::with_capacity(NUM_INPUTS);
		let mut path_element_vars = Vec::with_capacity(NUM_INPUTS);
		let mut path_index_vars = Vec::with_capacity(NUM_INPUTS);

		for i in 0..NUM_INPUTS {
			let note = w.map(|w| &w.input_notes[i]);

			in_value_vars.push(FpVar::new_witness(cs.clone(), || {
				val(note.map(|n| n.value))
			})?);
			in_ax_vars.push(FpVar::new_witness(cs.clone(), || {
				val(note.map(|n| n.owner_pubkey)) // Ax = owner_pubkey
			})?);
			in_ay_vars.push(FpVar::new_witness(cs.clone(), || {
				val(w.map(|w| w.owner_ay[i]))
			})?);
			in_blinding_vars.push(FpVar::new_witness(cs.clone(), || {
				val(note.map(|n| n.blinding))
			})?);
			spend_key_vars.push(FpVar::new_witness(cs.clone(), || {
				val(w.map(|w| w.spending_keys[i]))
			})?);
			sig_r8x_vars.push(FpVar::new_witness(cs.clone(), || {
				val(w.map(|w| w.sig_r8x[i]))
			})?);
			sig_r8y_vars.push(FpVar::new_witness(cs.clone(), || {
				val(w.map(|w| w.sig_r8y[i]))
			})?);
			sig_s_vars.push(FpVar::new_witness(cs.clone(), || {
				val(w.map(|w| w.sig_s[i]))
			})?);

			let mut elems = Vec::with_capacity(TREE_DEPTH);
			for j in 0..TREE_DEPTH {
				elems.push(FpVar::new_witness(cs.clone(), || {
					val(w.map(|w| w.merkle_path_elements[i][j]))
				})?);
			}
			path_element_vars.push(elems);

			let mut idxs = Vec::with_capacity(TREE_DEPTH);
			for j in 0..TREE_DEPTH {
				idxs.push(Boolean::new_witness(cs.clone(), || {
					w.map(|w| w.merkle_path_indices[i][j])
						.ok_or(SynthesisError::AssignmentMissing)
				})?);
			}
			path_index_vars.push(idxs);
		}

		let mut out_value_vars = Vec::with_capacity(NUM_OUTPUTS);
		let mut out_owner_vars = Vec::with_capacity(NUM_OUTPUTS);
		let mut out_blinding_vars = Vec::with_capacity(NUM_OUTPUTS);

		for i in 0..NUM_OUTPUTS {
			let note = w.map(|w| &w.output_notes[i]);
			out_value_vars.push(FpVar::new_witness(cs.clone(), || {
				val(note.map(|n| n.value))
			})?);
			out_owner_vars.push(FpVar::new_witness(cs.clone(), || {
				val(note.map(|n| n.owner_pubkey))
			})?);
			out_blinding_vars.push(FpVar::new_witness(cs.clone(), || {
				val(note.map(|n| n.blinding))
			})?);
		}

		// ====================================================================
		// CONSTRAINT 1 + 2: Input commitment correctness + Merkle membership
		// ====================================================================

		for i in 0..NUM_INPUTS {
			// commitment = Poseidon4(value, asset_id, Ax, blinding)
			let commitment = note_commitment(
				cs.clone(),
				&in_value_vars[i],
				&asset_id_var,
				&in_ax_vars[i],
				&in_blinding_vars[i],
			)?;

			// Merkle proof: H(commitment, path) == merkle_root
			let computed_root = merkle_tree_verifier(
				cs.clone(),
				&commitment,
				&path_element_vars[i],
				&path_index_vars[i],
			)?;
			computed_root.enforce_equal(&root_var)?;

			// ================================================================
			// CONSTRAINT 3: EdDSA ownership proof
			// S × Base8 == R8 + Poseidon5(R8x, R8y, Ax, Ay, commitment) × A
			// ================================================================

			verify_eddsa(
				cs.clone(),
				&in_ax_vars[i],
				&in_ay_vars[i],
				&sig_r8x_vars[i],
				&sig_r8y_vars[i],
				&sig_s_vars[i],
				&commitment,
			)?;

			// ================================================================
			// CONSTRAINT 4: Nullifier correctness
			// nullifier = Poseidon2(commitment, spending_key)
			// ================================================================

			let computed_null = nullifier(cs.clone(), &commitment, &spend_key_vars[i])?;
			computed_null.enforce_equal(&null_vars[i])?;
		}

		// ====================================================================
		// CONSTRAINT 5: Output commitment correctness
		// ====================================================================

		for i in 0..NUM_OUTPUTS {
			let computed_comm = note_commitment(
				cs.clone(),
				&out_value_vars[i],
				&asset_id_var,
				&out_owner_vars[i],
				&out_blinding_vars[i],
			)?;
			computed_comm.enforce_equal(&out_comm_vars[i])?;
		}

		// ====================================================================
		// CONSTRAINT 6: Balance conservation
		// sum(inputs) == sum(outputs) + fee
		// ====================================================================

		let input_sum = &in_value_vars[0] + &in_value_vars[1];
		let output_sum = &out_value_vars[0] + &out_value_vars[1];
		let rhs = &output_sum + &fee_var;
		input_sum.enforce_equal(&rhs)?;

		// ====================================================================
		// CONSTRAINT 7: Asset consistency
		// All input and output notes must use the public asset_id
		// ====================================================================

		for in_asset in [&asset_id_var; NUM_INPUTS] {
			// input asset_id is already used in the commitment gadget above
			// (commitment uses asset_id_var directly, so if the commitment
			// matches the Merkle tree, asset_id is already constrained)
			let _ = in_asset; // suppress warning — constraint is via commitment
		}
		// Output notes: constrain their asset_id to equal the public asset_id
		// (output note asset_id is a private witness — we enforce it matches)
		for i in 0..NUM_OUTPUTS {
			// Allocate output asset_id witness and enforce it equals the public one
			let out_asset_var =
				FpVar::new_witness(cs.clone(), || val(w.map(|w| w.output_notes[i].asset_id)))?;
			out_asset_var.enforce_equal(&asset_id_var)?;
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
	use crate::gadgets::eddsa::eddsa_sign;
	use ark_relations::r1cs::ConstraintSystem;

	extern crate alloc;

	// ── Test helpers ─────────────────────────────────────────────────────────

	/// Generates (note, owner_ay, r8x, r8y, s) for a given spending_key.
	/// owner_pubkey in the note is Ax = spending_key × Base8 .x
	fn make_input(
		spending_key_u64: u64,
		value: u64,
		blinding_seed: u64,
	) -> (Note, Bn254Fr, Bn254Fr, Bn254Fr, Bn254Fr) {
		let blinding = Bn254Fr::from(blinding_seed);

		// Build a temporary note with zero owner_pubkey to get a placeholder,
		// then sign the actual commitment once we know Ax.
		// First: sign with sk=0 to get Ax
		let dummy_msg = Bn254Fr::from(0u64);
		let (ax, ay, _, _, _) = eddsa_sign(spending_key_u64, dummy_msg);

		// Build real note with Ax as owner_pubkey
		let note = Note::new(value, 0, ax, blinding);
		let commitment = note.commitment();

		// Sign the real commitment
		let (_, _, r8x, r8y, s) = eddsa_sign(spending_key_u64, commitment);
		(note, ay, r8x, r8y, s)
	}

	/// Computes the Merkle root natively (test helper)
	fn compute_root_native(leaf: Bn254Fr, elements: &[Bn254Fr], indices: &[bool]) -> Bn254Fr {
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

	/// Builds Merkle paths for two leaves positioned at indices 0 and 1.
	fn make_merkle_paths(
		leaf0: Bn254Fr,
		leaf1: Bn254Fr,
	) -> (Bn254Fr, [[Bn254Fr; TREE_DEPTH]; 2], [[bool; TREE_DEPTH]; 2]) {
		let h01 = crate::native::poseidon_hash_2(&[leaf0, leaf1]);

		let mut p0 = [Bn254Fr::from(0u64); TREE_DEPTH];
		let mut i0 = [false; TREE_DEPTH];
		p0[0] = leaf1;
		i0[0] = false;

		let mut p1 = [Bn254Fr::from(0u64); TREE_DEPTH];
		let mut i1 = [false; TREE_DEPTH];
		p1[0] = leaf0;
		i1[0] = true;

		let mut cur = h01;
		for j in 1..TREE_DEPTH {
			let z = Bn254Fr::from(0u64);
			p0[j] = z;
			p1[j] = z;
			cur = crate::native::poseidon_hash_2(&[cur, z]);
		}

		let root0 = compute_root_native(leaf0, &p0, &i0);
		let root1 = compute_root_native(leaf1, &p1, &i1);
		assert_eq!(root0, root1);

		(root0, [p0, p1], [i0, i1])
	}

	/// Creates a full valid test witness with EdDSA signatures
	fn create_test_witness() -> (TransferWitness, Bn254Fr) {
		let sk0 = 7777u64;
		let sk1 = 8888u64;

		let (in0, ay0, r8x0, r8y0, s0) = make_input(sk0, 600, 1111);
		let (in1, ay1, r8x1, r8y1, s1) = make_input(sk1, 400, 2222);

		let comms = [in0.commitment(), in1.commitment()];
		let (root, paths, indices) = make_merkle_paths(comms[0], comms[1]);

		// Output notes (600+400 = 1000, no fee)
		let out0 = Note::new(300, 0, Bn254Fr::from(99u64), Bn254Fr::from(3333u64));
		let out1 = Note::new(700, 0, Bn254Fr::from(88u64), Bn254Fr::from(4444u64));

		let witness = TransferWitness::new(
			[in0, in1],
			[Bn254Fr::from(sk0), Bn254Fr::from(sk1)],
			[ay0, ay1],
			[r8x0, r8x1],
			[r8y0, r8y1],
			[s0, s1],
			paths,
			indices,
			[out0, out1],
			Bn254Fr::from(0u64), // fee = 0
		);

		(witness, root)
	}

	// ── Witness validation tests ──────────────────────────────────────────────

	#[test]
	fn test_validate_balanced_no_fee() {
		let (witness, _) = create_test_witness();
		assert!(witness.validate().is_ok());
	}

	#[test]
	fn test_validate_balanced_with_fee() {
		let (mut witness, _) = create_test_witness();
		// input=1000, output=900, fee=100
		witness.output_notes[0] = Note::new(500, 0, Bn254Fr::from(1u64), Bn254Fr::from(1u64));
		witness.output_notes[1] = Note::new(400, 0, Bn254Fr::from(1u64), Bn254Fr::from(2u64));
		witness.fee = Bn254Fr::from(100u64);
		assert!(witness.validate().is_ok());
	}

	#[test]
	fn test_validate_unbalanced() {
		let (mut witness, _) = create_test_witness();
		witness.output_notes[0] = Note::new(999, 0, Bn254Fr::from(1u64), Bn254Fr::from(1u64));
		assert!(witness.validate().is_err());
	}

	#[test]
	fn test_validate_asset_mismatch() {
		let (mut witness, _) = create_test_witness();
		witness.output_notes[1].asset_id = Bn254Fr::from(1u64);
		assert!(witness.validate().is_err());
	}

	// ── TransferPublicInputs tests ────────────────────────────────────────────

	#[test]
	fn test_public_inputs_from_witness() {
		let (witness, root) = create_test_witness();
		let pi = TransferPublicInputs::from_witness(&witness, root);
		assert_eq!(pi.merkle_root, root);
		assert_eq!(pi.nullifiers, witness.nullifiers());
		assert_eq!(pi.commitments, witness.output_commitments());
		assert_eq!(pi.asset_id, witness.asset_id());
		assert_eq!(pi.fee, witness.fee);
	}

	#[test]
	fn test_public_inputs_to_vec_length() {
		let (witness, root) = create_test_witness();
		let pi = TransferPublicInputs::from_witness(&witness, root);
		// 1 + 2 + 2 + 1 + 1 = 7 (matches nPublic: 7)
		assert_eq!(pi.to_vec().len(), 7);
	}

	#[test]
	fn test_public_inputs_to_vec_order() {
		let (witness, root) = create_test_witness();
		let pi = TransferPublicInputs::from_witness(&witness, root);
		let v = pi.to_vec();
		assert_eq!(v[0], root);
		assert_eq!(v[1], pi.nullifiers[0]);
		assert_eq!(v[2], pi.nullifiers[1]);
		assert_eq!(v[3], pi.commitments[0]);
		assert_eq!(v[4], pi.commitments[1]);
		assert_eq!(v[5], pi.asset_id);
		assert_eq!(v[6], pi.fee);
	}

	// ── TransferCircuit tests ─────────────────────────────────────────────────

	#[test]
	fn test_circuit_new_for_setup() {
		let c = TransferCircuit::new_for_setup();
		assert!(c.witness.is_none());
		assert!(c.merkle_root.is_none());
	}

	#[test]
	fn test_circuit_new_with_witness() {
		let (witness, root) = create_test_witness();
		let c = TransferCircuit::new(witness, root);
		assert!(c.witness.is_some());
		assert_eq!(c.merkle_root.unwrap(), root);
	}

	#[test]
	#[should_panic(expected = "Cannot get public inputs without witness")]
	fn test_circuit_public_inputs_without_witness_panics() {
		let _ = TransferCircuit::new_for_setup().public_inputs();
	}

	#[test]
	fn test_circuit_satisfies_constraints() {
		let (witness, root) = create_test_witness();
		let circuit = TransferCircuit::new(witness, root);
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();
		circuit.generate_constraints(cs.clone()).unwrap();
		assert!(
			cs.is_satisfied().unwrap(),
			"All constraints should be satisfied"
		);
	}

	#[test]
	fn test_circuit_has_7_public_inputs() {
		let (witness, root) = create_test_witness();
		let circuit = TransferCircuit::new(witness, root);
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();
		circuit.generate_constraints(cs.clone()).unwrap();
		// num_instance_variables - 1 (constant) = public input count
		assert_eq!(cs.num_instance_variables() - 1, 7);
	}

	#[test]
	fn test_circuit_generates_constraints() {
		let (witness, root) = create_test_witness();
		let circuit = TransferCircuit::new(witness, root);
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();
		circuit.generate_constraints(cs.clone()).unwrap();
		assert!(cs.num_constraints() > 0);
	}

	#[test]
	fn test_end_to_end_transfer_with_fee() {
		let sk0 = 111u64;
		let sk1 = 222u64;

		let (in0, ay0, r8x0, r8y0, s0) = make_input(sk0, 1000, 10);
		let (in1, ay1, r8x1, r8y1, s1) = make_input(sk1, 500, 20);
		let comms = [in0.commitment(), in1.commitment()];
		let (root, paths, indices) = make_merkle_paths(comms[0], comms[1]);

		// outputs: 1400, fee: 100 (total in = 1500)
		let out0 = Note::new(800, 0, Bn254Fr::from(99u64), Bn254Fr::from(50u64));
		let out1 = Note::new(600, 0, Bn254Fr::from(77u64), Bn254Fr::from(60u64));
		let fee = Bn254Fr::from(100u64);

		let witness = TransferWitness::new(
			[in0, in1],
			[Bn254Fr::from(sk0), Bn254Fr::from(sk1)],
			[ay0, ay1],
			[r8x0, r8x1],
			[r8y0, r8y1],
			[s0, s1],
			paths,
			indices,
			[out0, out1],
			fee,
		);

		assert!(witness.validate().is_ok());

		let circuit = TransferCircuit::new(witness, root);
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();
		circuit.generate_constraints(cs.clone()).unwrap();
		assert!(cs.is_satisfied().unwrap());
	}

	#[test]
	fn test_different_output_owners() {
		let sk0 = 1u64;
		let sk1 = 2u64;
		let (in0, ay0, r8x0, r8y0, s0) = make_input(sk0, 500, 10);
		let (in1, ay1, r8x1, r8y1, s1) = make_input(sk1, 500, 20);
		let comms = [in0.commitment(), in1.commitment()];
		let (root, paths, indices) = make_merkle_paths(comms[0], comms[1]);

		let out0 = Note::new(500, 0, Bn254Fr::from(999u64), Bn254Fr::from(1u64));
		let out1 = Note::new(500, 0, Bn254Fr::from(888u64), Bn254Fr::from(2u64));

		let witness = TransferWitness::new(
			[in0, in1],
			[Bn254Fr::from(sk0), Bn254Fr::from(sk1)],
			[ay0, ay1],
			[r8x0, r8x1],
			[r8y0, r8y1],
			[s0, s1],
			paths,
			indices,
			[out0, out1],
			Bn254Fr::from(0u64),
		);

		assert!(witness.validate().is_ok());
		let circuit = TransferCircuit::new(witness, root);
		let cs = ConstraintSystem::<Bn254Fr>::new_ref();
		circuit.generate_constraints(cs.clone()).unwrap();
		assert!(cs.is_satisfied().unwrap());
	}

	#[test]
	fn test_constants() {
		assert_eq!(NUM_INPUTS, 2);
		assert_eq!(NUM_OUTPUTS, 2);
	}
}
