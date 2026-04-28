//! Merkle Tree Gadget (R1CS Constraints)
//!
//! R1CS constraint-generating Merkle tree verification.
//! Used inside ZK circuits to prove membership without revealing leaf position.

use ark_r1cs_std::{boolean::Boolean, eq::EqGadget, fields::fp::FpVar, select::CondSelectGadget};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

use super::poseidon::poseidon_hash_2;
use crate::Bn254Fr;

/// Compute Merkle root for a given leaf and path (in-circuit, R1CS)
///
/// Equivalent to circomlib's `MerkleTreeVerifier` template.
/// Returns the computed root — caller must constrain it to the expected value.
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
		// is_right = true  → leaf is right child: hash(sibling, current)
		// is_right = false → leaf is left child:  hash(current, sibling)
		let left = FpVar::conditionally_select(is_right, sibling, &current)?;
		let right = FpVar::conditionally_select(is_right, &current, sibling)?;
		current = poseidon_hash_2(cs.clone(), &[left, right])?;
	}

	Ok(current)
}

/// Verify a Merkle proof in-circuit and enforce the computed root equals `expected_root`
pub fn verify_merkle_proof(
	cs: ConstraintSystemRef<Bn254Fr>,
	leaf: &FpVar<Bn254Fr>,
	path_elements: &[FpVar<Bn254Fr>],
	path_indices: &[Boolean<Bn254Fr>],
	expected_root: &FpVar<Bn254Fr>,
) -> Result<(), SynthesisError> {
	let computed_root = merkle_tree_verifier(cs, leaf, path_elements, path_indices)?;
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
	extern crate alloc;
	use alloc::{vec, vec::Vec};

	/// Native Merkle root computation using the same logic as the circuit.
	///
	/// Replaces `MerkleService` which required old zk-core domain layer paths.
	fn compute_root_native(leaf: Bn254Fr, elements: &[Bn254Fr], indices: &[bool]) -> Bn254Fr {
		let mut current = leaf;
		for (&sibling, &is_right) in elements.iter().zip(indices.iter()) {
			current = if is_right {
				// Leaf is right child: hash(sibling, current)
				crate::native::poseidon_hash_2(&[sibling, current])
			} else {
				// Leaf is left child: hash(current, sibling)
				crate::native::poseidon_hash_2(&[current, sibling])
			};
		}
		current
	}

	// ===== merkle_tree_verifier Tests =====

	#[test]
	fn test_merkle_tree_verifier_gadget() {
		let cs = ConstraintSystem::new_ref();

		let leaf = Bn254Fr::from(42u64);
		let sibling = Bn254Fr::from(100u64);
		let path_elements_native = [sibling];
		let path_indices_native = [false];

		let expected_root = compute_root_native(leaf, &path_elements_native, &path_indices_native);

		let leaf_var = FpVar::new_witness(cs.clone(), || Ok(leaf)).unwrap();
		let path_vars = vec![FpVar::new_witness(cs.clone(), || Ok(sibling)).unwrap()];
		let index_vars = vec![Boolean::new_witness(cs.clone(), || Ok(false)).unwrap()];

		let computed_root =
			merkle_tree_verifier(cs.clone(), &leaf_var, &path_vars, &index_vars).unwrap();

		assert_eq!(computed_root.value().unwrap(), expected_root);
		assert!(cs.num_constraints() > 0);
	}

	#[test]
	fn test_merkle_tree_verifier_single_level() {
		let cs = ConstraintSystem::new_ref();

		let leaf = Bn254Fr::from(1u64);
		let sibling = Bn254Fr::from(2u64);

		let leaf_var = FpVar::new_witness(cs.clone(), || Ok(leaf)).unwrap();
		let sibling_var = FpVar::new_witness(cs.clone(), || Ok(sibling)).unwrap();
		let index_var = Boolean::new_witness(cs.clone(), || Ok(false)).unwrap();

		let root =
			merkle_tree_verifier(cs.clone(), &leaf_var, &[sibling_var], &[index_var]).unwrap();

		assert_ne!(root.value().unwrap(), Bn254Fr::from(0u64));
	}

	#[test]
	fn test_merkle_tree_verifier_multi_level() {
		let cs = ConstraintSystem::new_ref();

		let leaf = Bn254Fr::from(10u64);
		let siblings = [
			Bn254Fr::from(20u64),
			Bn254Fr::from(30u64),
			Bn254Fr::from(40u64),
		];
		let indices = [false, true, false];

		let leaf_var = FpVar::new_witness(cs.clone(), || Ok(leaf)).unwrap();
		let path_vars: Vec<_> = siblings
			.iter()
			.map(|&s| FpVar::new_witness(cs.clone(), || Ok(s)).unwrap())
			.collect();
		let index_vars: Vec<_> = indices
			.iter()
			.map(|&i| Boolean::new_witness(cs.clone(), || Ok(i)).unwrap())
			.collect();

		let root = merkle_tree_verifier(cs.clone(), &leaf_var, &path_vars, &index_vars).unwrap();

		assert_ne!(root.value().unwrap(), Bn254Fr::from(0u64));
		assert!(cs.num_constraints() > 0);
	}

	#[test]
	fn test_merkle_tree_verifier_deterministic() {
		let leaf = Bn254Fr::from(100u64);
		let sibling = Bn254Fr::from(200u64);

		let cs1 = ConstraintSystem::new_ref();
		let cs2 = ConstraintSystem::new_ref();

		let leaf1 = FpVar::new_witness(cs1.clone(), || Ok(leaf)).unwrap();
		let s1 = FpVar::new_witness(cs1.clone(), || Ok(sibling)).unwrap();
		let idx1 = Boolean::new_witness(cs1.clone(), || Ok(false)).unwrap();

		let leaf2 = FpVar::new_witness(cs2.clone(), || Ok(leaf)).unwrap();
		let s2 = FpVar::new_witness(cs2.clone(), || Ok(sibling)).unwrap();
		let idx2 = Boolean::new_witness(cs2.clone(), || Ok(false)).unwrap();

		let root1 = merkle_tree_verifier(cs1, &leaf1, &[s1], &[idx1]).unwrap();
		let root2 = merkle_tree_verifier(cs2, &leaf2, &[s2], &[idx2]).unwrap();

		assert_eq!(root1.value().unwrap(), root2.value().unwrap());
	}

	#[test]
	fn test_merkle_tree_verifier_different_leaves() {
		let cs = ConstraintSystem::new_ref();

		let leaf1 = Bn254Fr::from(100u64);
		let leaf2 = Bn254Fr::from(200u64);
		let sibling = Bn254Fr::from(300u64);

		let leaf_var1 = FpVar::new_witness(cs.clone(), || Ok(leaf1)).unwrap();
		let leaf_var2 = FpVar::new_witness(cs.clone(), || Ok(leaf2)).unwrap();
		let s1 = FpVar::new_witness(cs.clone(), || Ok(sibling)).unwrap();
		let s2 = FpVar::new_witness(cs.clone(), || Ok(sibling)).unwrap();
		let idx1 = Boolean::new_witness(cs.clone(), || Ok(false)).unwrap();
		let idx2 = Boolean::new_witness(cs.clone(), || Ok(false)).unwrap();

		let root1 = merkle_tree_verifier(cs.clone(), &leaf_var1, &[s1], &[idx1]).unwrap();
		let root2 = merkle_tree_verifier(cs.clone(), &leaf_var2, &[s2], &[idx2]).unwrap();

		assert_ne!(root1.value().unwrap(), root2.value().unwrap());
	}

	#[test]
	fn test_merkle_proof_different_positions() {
		let cs = ConstraintSystem::new_ref();

		let leaf = Bn254Fr::from(1u64);
		let sibling = Bn254Fr::from(2u64);

		let leaf_var = FpVar::new_witness(cs.clone(), || Ok(leaf)).unwrap();
		let sibling_var = FpVar::new_witness(cs.clone(), || Ok(sibling)).unwrap();
		let is_right = Boolean::new_witness(cs.clone(), || Ok(false)).unwrap();

		let root_left = merkle_tree_verifier(
			cs.clone(),
			&leaf_var,
			core::slice::from_ref(&sibling_var),
			&[is_right],
		)
		.unwrap();

		let cs2 = ConstraintSystem::new_ref();
		let leaf_var2 = FpVar::new_witness(cs2.clone(), || Ok(leaf)).unwrap();
		let sibling_var2 = FpVar::new_witness(cs2.clone(), || Ok(sibling)).unwrap();
		let is_right2 = Boolean::new_witness(cs2.clone(), || Ok(true)).unwrap();

		let root_right =
			merkle_tree_verifier(cs2.clone(), &leaf_var2, &[sibling_var2], &[is_right2]).unwrap();

		assert_ne!(root_left.value().unwrap(), root_right.value().unwrap());
	}

	#[test]
	fn test_merkle_tree_verifier_zero_leaf() {
		let cs = ConstraintSystem::new_ref();

		let leaf_var = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(0u64))).unwrap();
		let sibling_var = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(100u64))).unwrap();
		let index_var = Boolean::new_witness(cs.clone(), || Ok(false)).unwrap();

		let root =
			merkle_tree_verifier(cs.clone(), &leaf_var, &[sibling_var], &[index_var]).unwrap();

		assert_ne!(root.value().unwrap(), Bn254Fr::from(0u64));
	}

	#[test]
	fn test_merkle_tree_verifier_large_values() {
		let cs = ConstraintSystem::new_ref();

		let leaf_var = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(u64::MAX))).unwrap();
		let sibling_var =
			FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(u64::MAX - 1))).unwrap();
		let index_var = Boolean::new_witness(cs.clone(), || Ok(true)).unwrap();

		let root =
			merkle_tree_verifier(cs.clone(), &leaf_var, &[sibling_var], &[index_var]).unwrap();

		assert_ne!(root.value().unwrap(), Bn254Fr::from(0u64));
	}

	#[test]
	fn test_merkle_tree_verifier_constants() {
		let cs = ConstraintSystem::new_ref();

		let leaf = Bn254Fr::from(50u64);
		let sibling = Bn254Fr::from(150u64);

		let leaf_var = FpVar::new_constant(cs.clone(), leaf).unwrap();
		let sibling_var = FpVar::new_constant(cs.clone(), sibling).unwrap();
		let index_var = Boolean::constant(false);

		let root =
			merkle_tree_verifier(cs.clone(), &leaf_var, &[sibling_var], &[index_var]).unwrap();

		assert_ne!(root.value().unwrap(), Bn254Fr::from(0u64));
	}

	#[test]
	fn test_merkle_tree_verifier_deep_tree() {
		let cs = ConstraintSystem::new_ref();

		let leaf = Bn254Fr::from(1u64);
		let path_vars: Vec<_> = (0..20u64)
			.map(|i| FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(i + 10))).unwrap())
			.collect();
		let index_vars: Vec<_> = (0..20)
			.map(|i| Boolean::new_witness(cs.clone(), || Ok(i % 2 == 0)).unwrap())
			.collect();

		let leaf_var = FpVar::new_witness(cs.clone(), || Ok(leaf)).unwrap();
		let root = merkle_tree_verifier(cs.clone(), &leaf_var, &path_vars, &index_vars).unwrap();

		assert_ne!(root.value().unwrap(), Bn254Fr::from(0u64));
	}

	// ===== verify_merkle_proof Tests =====

	#[test]
	fn test_verify_merkle_proof_gadget() {
		let cs = ConstraintSystem::new_ref();

		let leaf = Bn254Fr::from(123u64);
		let siblings = [Bn254Fr::from(456u64), Bn254Fr::from(789u64)];
		let indices = [false, true];

		let root = compute_root_native(leaf, &siblings, &indices);

		let leaf_var = FpVar::new_witness(cs.clone(), || Ok(leaf)).unwrap();
		let path_vars: Vec<_> = siblings
			.iter()
			.map(|&s| FpVar::new_witness(cs.clone(), || Ok(s)).unwrap())
			.collect();
		let index_vars: Vec<_> = indices
			.iter()
			.map(|&i| Boolean::new_witness(cs.clone(), || Ok(i)).unwrap())
			.collect();
		let root_var = FpVar::new_input(cs.clone(), || Ok(root)).unwrap();

		let result = verify_merkle_proof(cs.clone(), &leaf_var, &path_vars, &index_vars, &root_var);
		assert!(result.is_ok());
		assert!(cs.is_satisfied().unwrap());
	}

	#[test]
	fn test_verify_merkle_proof_valid() {
		let cs = ConstraintSystem::new_ref();

		let leaf = Bn254Fr::from(1u64);
		let sibling = Bn254Fr::from(2u64);
		let root = compute_root_native(leaf, &[sibling], &[false]);

		let leaf_var = FpVar::new_witness(cs.clone(), || Ok(leaf)).unwrap();
		let sibling_var = FpVar::new_witness(cs.clone(), || Ok(sibling)).unwrap();
		let index_var = Boolean::new_witness(cs.clone(), || Ok(false)).unwrap();
		let root_var = FpVar::new_input(cs.clone(), || Ok(root)).unwrap();

		let result = verify_merkle_proof(
			cs.clone(),
			&leaf_var,
			&[sibling_var],
			&[index_var],
			&root_var,
		);

		assert!(result.is_ok());
		assert!(cs.is_satisfied().unwrap());
	}

	#[test]
	fn test_verify_merkle_proof_invalid_root() {
		let cs = ConstraintSystem::new_ref();

		let leaf = Bn254Fr::from(1u64);
		let sibling = Bn254Fr::from(2u64);
		let wrong_root = Bn254Fr::from(999u64);

		let leaf_var = FpVar::new_witness(cs.clone(), || Ok(leaf)).unwrap();
		let sibling_var = FpVar::new_witness(cs.clone(), || Ok(sibling)).unwrap();
		let index_var = Boolean::new_witness(cs.clone(), || Ok(false)).unwrap();
		let root_var = FpVar::new_input(cs.clone(), || Ok(wrong_root)).unwrap();

		let result = verify_merkle_proof(
			cs.clone(),
			&leaf_var,
			&[sibling_var],
			&[index_var],
			&root_var,
		);

		assert!(result.is_ok()); // constraints created OK
		assert!(!cs.is_satisfied().unwrap()); // but NOT satisfied
	}

	#[test]
	fn test_verify_merkle_proof_multi_level() {
		let cs = ConstraintSystem::new_ref();

		let leaf = Bn254Fr::from(10u64);
		let siblings = [
			Bn254Fr::from(20u64),
			Bn254Fr::from(30u64),
			Bn254Fr::from(40u64),
		];
		let indices = vec![false, true, false];

		let root = compute_root_native(leaf, &siblings, &indices);

		let leaf_var = FpVar::new_witness(cs.clone(), || Ok(leaf)).unwrap();
		let path_vars: Vec<_> = siblings
			.iter()
			.map(|&s| FpVar::new_witness(cs.clone(), || Ok(s)).unwrap())
			.collect();
		let index_vars: Vec<_> = indices
			.iter()
			.map(|&i| Boolean::new_witness(cs.clone(), || Ok(i)).unwrap())
			.collect();
		let root_var = FpVar::new_input(cs.clone(), || Ok(root)).unwrap();

		let result = verify_merkle_proof(cs.clone(), &leaf_var, &path_vars, &index_vars, &root_var);

		assert!(result.is_ok());
		assert!(cs.is_satisfied().unwrap());
	}

	#[test]
	fn test_verify_merkle_proof_zero_leaf() {
		let cs = ConstraintSystem::new_ref();

		let leaf = Bn254Fr::from(0u64);
		let sibling = Bn254Fr::from(100u64);
		let root = compute_root_native(leaf, &[sibling], &[false]);

		let leaf_var = FpVar::new_witness(cs.clone(), || Ok(leaf)).unwrap();
		let sibling_var = FpVar::new_witness(cs.clone(), || Ok(sibling)).unwrap();
		let index_var = Boolean::new_witness(cs.clone(), || Ok(false)).unwrap();
		let root_var = FpVar::new_input(cs.clone(), || Ok(root)).unwrap();

		let result = verify_merkle_proof(
			cs.clone(),
			&leaf_var,
			&[sibling_var],
			&[index_var],
			&root_var,
		);

		assert!(result.is_ok());
		assert!(cs.is_satisfied().unwrap());
	}

	// ===== Edge Cases & Integration Tests =====

	#[test]
	#[should_panic(expected = "Path elements and indices must have same length")]
	fn test_merkle_tree_verifier_mismatched_lengths() {
		let cs = ConstraintSystem::new_ref();
		let leaf_var = FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(1u64))).unwrap();
		let path_vars = vec![
			FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(2u64))).unwrap(),
			FpVar::new_witness(cs.clone(), || Ok(Bn254Fr::from(3u64))).unwrap(),
		];
		let index_vars = vec![Boolean::new_witness(cs.clone(), || Ok(false)).unwrap()];
		let _ = merkle_tree_verifier(cs.clone(), &leaf_var, &path_vars, &index_vars);
	}

	#[test]
	fn test_merkle_tree_all_left_path() {
		let cs = ConstraintSystem::new_ref();

		let leaf = Bn254Fr::from(1u64);
		let siblings = [
			Bn254Fr::from(2u64),
			Bn254Fr::from(3u64),
			Bn254Fr::from(4u64),
		];

		let leaf_var = FpVar::new_witness(cs.clone(), || Ok(leaf)).unwrap();
		let path_vars: Vec<_> = siblings
			.iter()
			.map(|&s| FpVar::new_witness(cs.clone(), || Ok(s)).unwrap())
			.collect();
		let index_vars = vec![
			Boolean::new_witness(cs.clone(), || Ok(false)).unwrap(),
			Boolean::new_witness(cs.clone(), || Ok(false)).unwrap(),
			Boolean::new_witness(cs.clone(), || Ok(false)).unwrap(),
		];

		let root = merkle_tree_verifier(cs.clone(), &leaf_var, &path_vars, &index_vars).unwrap();

		assert_ne!(root.value().unwrap(), Bn254Fr::from(0u64));
		assert!(cs.is_satisfied().unwrap());
	}

	#[test]
	fn test_merkle_tree_all_right_path() {
		let cs = ConstraintSystem::new_ref();

		let leaf = Bn254Fr::from(1u64);
		let siblings = [
			Bn254Fr::from(2u64),
			Bn254Fr::from(3u64),
			Bn254Fr::from(4u64),
		];

		let leaf_var = FpVar::new_witness(cs.clone(), || Ok(leaf)).unwrap();
		let path_vars: Vec<_> = siblings
			.iter()
			.map(|&s| FpVar::new_witness(cs.clone(), || Ok(s)).unwrap())
			.collect();
		let index_vars = vec![
			Boolean::new_witness(cs.clone(), || Ok(true)).unwrap(),
			Boolean::new_witness(cs.clone(), || Ok(true)).unwrap(),
			Boolean::new_witness(cs.clone(), || Ok(true)).unwrap(),
		];

		let root = merkle_tree_verifier(cs.clone(), &leaf_var, &path_vars, &index_vars).unwrap();

		assert_ne!(root.value().unwrap(), Bn254Fr::from(0u64));
		assert!(cs.is_satisfied().unwrap());
	}

	#[test]
	fn test_merkle_integration_with_native() {
		let cs = ConstraintSystem::new_ref();

		let leaf = Bn254Fr::from(42u64);
		let siblings = [Bn254Fr::from(10u64), Bn254Fr::from(20u64)];
		let indices = [false, true];

		let native_root = compute_root_native(leaf, &siblings, &indices);

		let leaf_var = FpVar::new_witness(cs.clone(), || Ok(leaf)).unwrap();
		let path_vars: Vec<_> = siblings
			.iter()
			.map(|&s| FpVar::new_witness(cs.clone(), || Ok(s)).unwrap())
			.collect();
		let index_vars: Vec<_> = indices
			.iter()
			.map(|&i| Boolean::new_witness(cs.clone(), || Ok(i)).unwrap())
			.collect();

		let circuit_root =
			merkle_tree_verifier(cs.clone(), &leaf_var, &path_vars, &index_vars).unwrap();

		assert_eq!(circuit_root.value().unwrap(), native_root);
	}
}
