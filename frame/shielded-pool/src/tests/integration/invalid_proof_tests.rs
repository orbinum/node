//! Tests for invalid ZK proof handling
//!
//! These tests validate error paths when ZK proofs are invalid.
//!
//! NOTE: These tests demonstrate HOW to test invalid proofs, but they cannot run with the current
//! mock setup because the main test runtime uses MockZkVerifier everywhere.
//!
//! To actually test invalid proof scenarios, you would need:
//! 1. A separate test configuration with FailingZkVerifier
//! 2. Or integration with real pallet-zk-verifier
//! 3. Or parameterize the Config to accept different verifiers per test

use crate::{Commitment, Error, Nullifier, mock::*, tests::helpers::*};
use frame_support::{BoundedVec, assert_noop, assert_ok, pallet_prelude::ConstU32};

/// Demonstrates how unshield should behave with invalid ZK proof
///
/// Currently marked as #[ignore] because it requires a different test setup
/// with FailingZkVerifier or real pallet-zk-verifier.
#[test]
#[ignore = "Requires test configuration with FailingZkVerifier - see invalid_proof_tests.rs header"]
fn unshield_should_fail_with_invalid_proof() {
	new_test_ext().execute_with(|| {
		// Setup: Create valid state with a shielded commitment
		let commitment = sample_commitment();
		let alice = 1u64;
		let initial_balance = 10_000u128;

		// Shield some tokens first
		assert_ok!(ShieldedPool::shield(
			RuntimeOrigin::signed(alice),
			0, // native asset
			initial_balance,
			commitment,
			sample_encrypted_memo(),
		));

		// Get current merkle root
		let root = crate::PoseidonRoot::<Test>::get();
		let nullifier = sample_nullifier();

		// Create an obviously invalid proof (random bytes)
		let invalid_proof = vec![0x42u8; 192]; // Wrong data

		// EXPECTED: This should fail with InvalidProof error
		// ACTUAL: With MockZkVerifier, this would pass because it always returns Ok(true)
		//
		// To properly test this:
		// - Configure test runtime with FailingZkVerifier
		// - Or use real pallet-zk-verifier with intentionally malformed proof
		assert_noop!(
			ShieldedPool::unshield(
				RuntimeOrigin::signed(alice),
				invalid_proof.try_into().unwrap(),
				root,
				nullifier,
				0, // asset_id
				5_000u128,
				alice,
			),
			Error::<Test>::InvalidProof
		);
	});
}

/// Demonstrates how private transfer should fail with corrupted proof
#[test]
#[ignore = "Requires test configuration with FailingZkVerifier - see invalid_proof_tests.rs header"]
fn private_transfer_should_fail_with_corrupted_proof() {
	new_test_ext().execute_with(|| {
		// Setup valid state
		let commitment1 = sample_commitment();
		let commitment2 = sample_commitment();

		assert_ok!(ShieldedPool::shield(
			RuntimeOrigin::signed(1),
			0,
			1000u128,
			commitment1,
			sample_encrypted_memo(),
		));

		assert_ok!(ShieldedPool::shield(
			RuntimeOrigin::signed(2),
			0,
			1000u128,
			commitment2,
			sample_encrypted_memo(),
		));

		let root = crate::PoseidonRoot::<Test>::get();
		let nullifiers: BoundedVec<Nullifier, ConstU32<2>> =
			vec![sample_nullifier(), sample_nullifier()]
				.try_into()
				.unwrap();
		let output_commitments: BoundedVec<Commitment, ConstU32<2>> =
			vec![sample_commitment(), sample_commitment()]
				.try_into()
				.unwrap();
		let memos: BoundedVec<_, ConstU32<2>> =
			vec![sample_encrypted_memo(), sample_encrypted_memo()]
				.try_into()
				.unwrap();

		// Corrupted proof (wrong length, wrong data)
		let corrupted_proof = vec![0xFF; 100]; // Wrong size

		// EXPECTED: Should fail with InvalidProof
		// ACTUAL: MockZkVerifier would accept this
		assert_noop!(
			ShieldedPool::private_transfer(
				RuntimeOrigin::signed(1),
				corrupted_proof.try_into().unwrap(),
				root,
				nullifiers,
				output_commitments,
				memos,
			),
			Error::<Test>::InvalidProof
		);
	});
}

/// Demonstrates disclosure with tampered public signals
#[test]
#[ignore = "Requires test configuration with FailingZkVerifier - see invalid_proof_tests.rs header"]
fn disclosure_should_fail_with_tampered_public_signals() {
	new_test_ext().execute_with(|| {
		let commitment = sample_commitment();

		// Valid proof but tampered public signals
		let valid_looking_proof = vec![0xAA; 192];

		// Create public signals that don't match the proof
		let mut tampered_signals = sp_std::vec![0xFFu8; 76];
		tampered_signals[0..32].copy_from_slice(&[0xDE; 32]); // Wrong commitment

		let partial_data = vec![0u8; 128];

		// EXPECTED: Should fail because public signals don't match proof
		// ACTUAL: MockZkVerifier doesn't verify cryptographic correctness
		assert_noop!(
			ShieldedPool::submit_disclosure(
				RuntimeOrigin::signed(1),
				commitment,
				valid_looking_proof.try_into().unwrap(),
				tampered_signals.try_into().unwrap(),
				partial_data.try_into().unwrap(),
				None,
			),
			Error::<Test>::InvalidProof
		);
	});
}

// ============================================================================
// Documentation and Guidelines
// ============================================================================

/// Example of how to create a test configuration with FailingZkVerifier
///
/// This is a template showing what would be needed:
///
/// ```ignore
/// use frame_support::construct_runtime;
///
/// construct_runtime!(
///     pub enum TestRuntimeWithFailingVerifier {
///         System: frame_system,
///         Balances: pallet_balances,
///         ShieldedPool: pallet_shielded_pool,
///     }
/// );
///
/// impl pallet_shielded_pool::Config for TestRuntimeWithFailingVerifier {
///     type Currency = Balances;
///     type ZkVerifier = FailingZkVerifier; // ← Key difference
///     // ... other config
/// }
///
/// #[test]
/// fn test_with_failing_verifier() {
///     TestExternalities::new().execute_with(|| {
///         // Any ZK proof verification will return Ok(false)
///         // Allowing you to test error paths
///     });
/// }
/// ```
#[allow(dead_code)]
fn example_failing_verifier_setup() {
	// This is documentation only
}
