//! Integration tests for commitment and nullifier functions

use ark_bn254::Fr as Bn254Fr;
use fp_zk_primitives::core::types::{Commitment, Nullifier, SpendingKey};
use fp_zk_primitives::crypto::commitment::{compute_nullifier, create_commitment};

#[test]
fn test_create_commitment_deterministic() {
	let value = Bn254Fr::from(100u64);
	let asset_id = Bn254Fr::from(1u64);
	let pubkey = Bn254Fr::from(12345u64);
	let blinding = Bn254Fr::from(67890u64);

	let commitment1 = create_commitment(value, asset_id, pubkey, blinding);
	let commitment2 = create_commitment(value, asset_id, pubkey, blinding);

	// Same inputs should produce same commitment (determinism)
	assert_eq!(commitment1.0, commitment2.0);
}

#[test]
fn test_create_commitment_hiding() {
	let value = Bn254Fr::from(100u64);
	let asset_id = Bn254Fr::from(1u64);
	let pubkey = Bn254Fr::from(12345u64);
	let blinding1 = Bn254Fr::from(11111u64);
	let blinding2 = Bn254Fr::from(22222u64);

	let commitment1 = create_commitment(value, asset_id, pubkey, blinding1);
	let commitment2 = create_commitment(value, asset_id, pubkey, blinding2);

	// Different blindings should produce different commitments (hiding)
	assert_ne!(commitment1.0, commitment2.0);
}

#[test]
fn test_create_commitment_binding() {
	let asset_id = Bn254Fr::from(1u64);
	let pubkey = Bn254Fr::from(12345u64);
	let blinding = Bn254Fr::from(67890u64);

	let value1 = Bn254Fr::from(100u64);
	let value2 = Bn254Fr::from(200u64);

	let commitment1 = create_commitment(value1, asset_id, pubkey, blinding);
	let commitment2 = create_commitment(value2, asset_id, pubkey, blinding);

	// Different values should produce different commitments (binding)
	assert_ne!(commitment1.0, commitment2.0);
}

#[test]
fn test_create_commitment_asset_id_matters() {
	let value = Bn254Fr::from(100u64);
	let pubkey = Bn254Fr::from(12345u64);
	let blinding = Bn254Fr::from(67890u64);

	let commitment1 = create_commitment(value, Bn254Fr::from(0u64), pubkey, blinding);
	let commitment2 = create_commitment(value, Bn254Fr::from(1u64), pubkey, blinding);

	// Different asset IDs should produce different commitments
	assert_ne!(commitment1.0, commitment2.0);
}

#[test]
fn test_create_commitment_owner_matters() {
	let value = Bn254Fr::from(100u64);
	let asset_id = Bn254Fr::from(0u64);
	let blinding = Bn254Fr::from(67890u64);

	let commitment1 = create_commitment(value, asset_id, Bn254Fr::from(11111u64), blinding);
	let commitment2 = create_commitment(value, asset_id, Bn254Fr::from(22222u64), blinding);

	// Different owners should produce different commitments
	assert_ne!(commitment1.0, commitment2.0);
}

#[test]
fn test_compute_nullifier_deterministic() {
	let commitment = Commitment(Bn254Fr::from(12345u64));
	let spending_key = SpendingKey(Bn254Fr::from(67890u64));

	let nullifier1 = compute_nullifier(&commitment, &spending_key);
	let nullifier2 = compute_nullifier(&commitment, &spending_key);

	// Same inputs should produce same nullifier (determinism)
	assert_eq!(nullifier1.0, nullifier2.0);
}

#[test]
fn test_compute_nullifier_unique() {
	let commitment1 = Commitment(Bn254Fr::from(11111u64));
	let commitment2 = Commitment(Bn254Fr::from(22222u64));
	let spending_key = SpendingKey(Bn254Fr::from(67890u64));

	let nullifier1 = compute_nullifier(&commitment1, &spending_key);
	let nullifier2 = compute_nullifier(&commitment2, &spending_key);

	// Different commitments should produce different nullifiers
	assert_ne!(nullifier1.0, nullifier2.0);
}

#[test]
fn test_compute_nullifier_different_keys() {
	let commitment = Commitment(Bn254Fr::from(12345u64));
	let key1 = SpendingKey(Bn254Fr::from(11111u64));
	let key2 = SpendingKey(Bn254Fr::from(22222u64));

	let nullifier1 = compute_nullifier(&commitment, &key1);
	let nullifier2 = compute_nullifier(&commitment, &key2);

	// Different keys should produce different nullifiers
	assert_ne!(nullifier1.0, nullifier2.0);
}

#[test]
fn test_nullifier_different_from_commitment() {
	let value = Bn254Fr::from(100u64);
	let asset_id = Bn254Fr::from(0u64);
	let owner = Bn254Fr::from(12345u64);
	let blinding = Bn254Fr::from(67890u64);
	let spending_key = SpendingKey(Bn254Fr::from(99999u64));

	let commitment = create_commitment(value, asset_id, owner, blinding);
	let nullifier = compute_nullifier(&commitment, &spending_key);

	// Nullifier should be different from commitment
	assert_ne!(nullifier.0, commitment.0);
}

#[test]
fn test_strong_types_are_distinct() {
	// Verify that strong types are distinct at type level
	let commitment = Commitment(Bn254Fr::from(123u64));
	let nullifier = Nullifier(Bn254Fr::from(456u64));
	let spending_key = SpendingKey(Bn254Fr::from(789u64));

	// We can access underlying values
	assert_eq!(commitment.0, Bn254Fr::from(123u64));
	assert_eq!(nullifier.0, Bn254Fr::from(456u64));
	assert_eq!(spending_key.0, Bn254Fr::from(789u64));

	// But they're different types (enforced at compile time)
	assert_ne!(commitment.0, nullifier.0);
	assert_ne!(commitment.0, spending_key.0);
	assert_ne!(nullifier.0, spending_key.0);
}

#[test]
fn test_commitment_nullifier_workflow() {
	// Simulate complete workflow: create commitment, then compute nullifier
	let value = Bn254Fr::from(1000u64);
	let asset_id = Bn254Fr::from(0u64);
	let owner = Bn254Fr::from(55555u64);
	let blinding = Bn254Fr::from(77777u64);
	let spending_key = SpendingKey(Bn254Fr::from(88888u64));

	// Step 1: Create commitment
	let commitment = create_commitment(value, asset_id, owner, blinding);
	assert_ne!(commitment.0, Bn254Fr::from(0u64));

	// Step 2: Compute nullifier when spending
	let nullifier = compute_nullifier(&commitment, &spending_key);
	assert_ne!(nullifier.0, Bn254Fr::from(0u64));
	assert_ne!(nullifier.0, commitment.0);

	// Step 3: Verify same inputs produce same outputs
	let commitment2 = create_commitment(value, asset_id, owner, blinding);
	let nullifier2 = compute_nullifier(&commitment2, &spending_key);
	assert_eq!(commitment.0, commitment2.0);
	assert_eq!(nullifier.0, nullifier2.0);
}
