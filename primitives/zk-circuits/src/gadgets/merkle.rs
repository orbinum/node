//! # Merkle Tree Gadget (R1CS Constraints)
//!
//! This module provides R1CS constraint-generating versions of Merkle tree verification.
//! These are used inside ZK circuits to prove membership without revealing the leaf position.
//!
//! For native (non-constraint) versions, see `fp_zk_primitives::merkle`.
//!
//! ## Usage
//!
//! ```rust,ignore
//! use fp_zk_circuits::gadgets::merkle::*;
//! use ark_r1cs_std::alloc::AllocVar;
//! use ark_relations::r1cs::ConstraintSystem;
//!
//! let cs = ConstraintSystem::new_ref();
//!
//! // Allocate circuit variables
//! let leaf = FpVar::new_witness(cs.clone(), || Ok(leaf_value))?;
//! let path: Vec<FpVar<_>> = path_elements.iter()
//!     .map(|&e| FpVar::new_witness(cs.clone(), || Ok(e)))
//!     .collect::<Result<_, _>>()?;
//! let indices: Vec<Boolean<_>> = path_indices.iter()
//!     .map(|&b| Boolean::new_witness(cs.clone(), || Ok(b)))
//!     .collect::<Result<_, _>>()?;
//!
//! // Compute root with constraints
//! let computed_root = merkle_tree_verifier(cs.clone(), &leaf, &path, &indices)?;
//! ```

use ark_r1cs_std::{boolean::Boolean, eq::EqGadget, fields::fp::FpVar, select::CondSelectGadget};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

use super::poseidon::poseidon_hash_2;
use crate::Bn254Fr;

// ============================================================================
// Circuit Gadgets (with R1CS constraints)
// ============================================================================

/// Merkle tree membership verifier (in-circuit)
///
/// Equivalent to circomlib's `MerkleTreeVerifier` template.
///
/// # Arguments
///
/// * `cs` - Constraint system reference
/// * `leaf` - The leaf value (commitment) as a circuit variable
/// * `path_elements` - Sibling hashes as circuit variables
/// * `path_indices` - Direction bits as boolean circuit variables
///
/// # Returns
///
/// The computed Merkle root as a circuit variable
pub fn merkle_tree_verifier(
	cs: ConstraintSystemRef<Bn254Fr>,
	leaf: &FpVar<Bn254Fr>,
	path_elements: &[FpVar<Bn254Fr>],
	path_indices: &[Boolean<Bn254Fr>],
) -> Result<FpVar<Bn254Fr>, SynthesisError> {
	assert_eq!(
		path_elements.len(),
		path_indices.len(),
		"Path elements and indices must have same length"
	);

	let mut current = leaf.clone();

	for (sibling, is_right) in path_elements.iter().zip(path_indices.iter()) {
		// Conditional select based on path index
		// If is_right=1: left=sibling, right=current
		// If is_right=0: left=current, right=sibling
		let left = FpVar::conditionally_select(is_right, sibling, &current)?;
		let right = FpVar::conditionally_select(is_right, &current, sibling)?;

		// Hash the pair
		current = poseidon_hash_2(cs.clone(), &[left, right])?;
	}

	Ok(current)
}

/// Verifies a Merkle proof in-circuit and constrains the result
///
/// This is a convenience function that verifies the proof and enforces
/// that the computed root equals the expected root.
///
/// # Arguments
///
/// * `cs` - Constraint system reference
/// * `leaf` - The leaf value (commitment)
/// * `path_elements` - Sibling hashes
/// * `path_indices` - Direction bits
/// * `expected_root` - The expected Merkle root (public input)
pub fn verify_merkle_proof(
	cs: ConstraintSystemRef<Bn254Fr>,
	leaf: &FpVar<Bn254Fr>,
	path_elements: &[FpVar<Bn254Fr>],
	path_indices: &[Boolean<Bn254Fr>],
	expected_root: &FpVar<Bn254Fr>,
) -> Result<(), SynthesisError> {
	let computed_root = merkle_tree_verifier(cs, leaf, path_elements, path_indices)?;

	// Enforce computed root == expected root
	computed_root.enforce_equal(expected_root)?;

	Ok(())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
	use super::*;
	use ark_r1cs_std::{alloc::AllocVar, R1CSVar};
	use ark_relations::r1cs::ConstraintSystem;
	use fp_zk_primitives::core::types::Commitment;
	use fp_zk_primitives::crypto::merkle::compute_merkle_root;

	#[test]
	fn test_merkle_tree_verifier_gadget() {
		let cs = ConstraintSystem::new_ref();

		// Native values
		let leaf = Bn254Fr::from(42u64);
		let sibling = Bn254Fr::from(100u64);
		let path_elements_native = vec![sibling];
		let path_indices_native = vec![false];

		// Compute expected root natively
		let expected_root = compute_merkle_root(
			&Commitment::from(leaf),
			&path_elements_native,
			&path_indices_native,
		);

		// Allocate circuit variables
		let leaf_var = FpVar::new_witness(cs.clone(), || Ok(leaf)).unwrap();
		let path_vars = vec![FpVar::new_witness(cs.clone(), || Ok(sibling)).unwrap()];
		let index_vars = vec![Boolean::new_witness(cs.clone(), || Ok(false)).unwrap()];

		// Compute root in-circuit
		let computed_root =
			merkle_tree_verifier(cs.clone(), &leaf_var, &path_vars, &index_vars).unwrap();

		// Verify it matches native computation
		assert_eq!(computed_root.value().unwrap(), expected_root);

		// Check constraints were created
		assert!(cs.num_constraints() > 0);
	}

	#[test]
	fn test_verify_merkle_proof_gadget() {
		let cs = ConstraintSystem::new_ref();

		// Native values
		let leaf = Bn254Fr::from(123u64);
		let sibling1 = Bn254Fr::from(456u64);
		let sibling2 = Bn254Fr::from(789u64);
		let path_elements_native = vec![sibling1, sibling2];
		let path_indices_native = vec![false, true];

		// Compute root natively
		let root = compute_merkle_root(
			&Commitment::from(leaf),
			&path_elements_native,
			&path_indices_native,
		);

		// Allocate circuit variables
		let leaf_var = FpVar::new_witness(cs.clone(), || Ok(leaf)).unwrap();
		let path_vars = path_elements_native
			.iter()
			.map(|&e| FpVar::new_witness(cs.clone(), || Ok(e)).unwrap())
			.collect::<Vec<_>>();
		let index_vars = path_indices_native
			.iter()
			.map(|&i| Boolean::new_witness(cs.clone(), || Ok(i)).unwrap())
			.collect::<Vec<_>>();
		let root_var = FpVar::new_input(cs.clone(), || Ok(root)).unwrap();

		// Verify proof in-circuit
		let result = verify_merkle_proof(cs.clone(), &leaf_var, &path_vars, &index_vars, &root_var);
		assert!(result.is_ok());

		// Check constraint system is satisfied
		assert!(cs.is_satisfied().unwrap());
	}

	#[test]
	fn test_merkle_proof_different_positions() {
		let cs = ConstraintSystem::new_ref();

		let leaf = Bn254Fr::from(1u64);
		let sibling = Bn254Fr::from(2u64);

		// Test left position (is_right = false)
		let leaf_var = FpVar::new_witness(cs.clone(), || Ok(leaf)).unwrap();
		let sibling_var = FpVar::new_witness(cs.clone(), || Ok(sibling)).unwrap();
		let is_right = Boolean::new_witness(cs.clone(), || Ok(false)).unwrap();

		let root_left =
			merkle_tree_verifier(cs.clone(), &leaf_var, &[sibling_var.clone()], &[is_right])
				.unwrap();

		// Test right position (is_right = true)
		let cs2 = ConstraintSystem::new_ref();
		let leaf_var2 = FpVar::new_witness(cs2.clone(), || Ok(leaf)).unwrap();
		let sibling_var2 = FpVar::new_witness(cs2.clone(), || Ok(sibling)).unwrap();
		let is_right2 = Boolean::new_witness(cs2.clone(), || Ok(true)).unwrap();

		let root_right =
			merkle_tree_verifier(cs2.clone(), &leaf_var2, &[sibling_var2], &[is_right2]).unwrap();

		// Roots should be different for different positions
		assert_ne!(root_left.value().unwrap(), root_right.value().unwrap());
	}
}
