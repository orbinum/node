//! Encrypted memo tests
//!
//! Tests for encrypted memo functionality.

use crate::{
	Commitment, Error,
	infrastructure::frame_types::{EncryptedMemo, MAX_ENCRYPTED_MEMO_SIZE},
	mock::*,
	tests::helpers::*,
};
use frame_support::{BoundedVec, assert_noop, assert_ok};

// ============================================================================

#[test]
fn encrypted_memo_creation_works() {
	let memo = sample_encrypted_memo();
	assert_eq!(memo.0.len(), MAX_ENCRYPTED_MEMO_SIZE as usize);
}

#[test]
fn encrypted_memo_from_bytes_works() {
	let bytes = vec![42u8; MAX_ENCRYPTED_MEMO_SIZE as usize];
	let memo = EncryptedMemo::from_bytes(&bytes).unwrap();
	assert_eq!(memo.as_bytes(), &bytes[..]);
}

#[test]
fn encrypted_memo_from_bytes_fails_wrong_size() {
	let bytes_short = vec![42u8; 50]; // Too short
	assert!(EncryptedMemo::from_bytes(&bytes_short).is_err());

	let bytes_long = vec![42u8; 300]; // Too long
	assert!(EncryptedMemo::from_bytes(&bytes_long).is_err());
}

#[test]
fn encrypted_memo_accessors_work() {
	let memo = sample_encrypted_memo();

	// Check nonce (first 24 bytes)
	assert_eq!(memo.nonce().len(), 24);

	// Check ciphertext (bytes 24-87, length 64)
	assert_eq!(memo.ciphertext().len(), 64);

	// Check tag (last 16 bytes)
	assert_eq!(memo.tag().len(), 16);
}

#[test]
fn shield_stores_encrypted_memo() {
	new_test_ext().execute_with(|| {
		let depositor = 1;
		let amount = 1000u128;
		let commitment = sample_commitment();
		let encrypted_memo = sample_encrypted_memo();

		assert_ok!(ShieldedPool::shield(
			RuntimeOrigin::signed(depositor),
			0, // native asset
			amount,
			commitment,
			encrypted_memo.clone(),
		));

		// Verify memo was stored correctly
		let stored_memo = crate::CommitmentMemos::<Test>::get(commitment);
		assert_eq!(stored_memo, Some(encrypted_memo));
	});
}

#[test]
fn shield_fails_with_invalid_memo_size() {
	new_test_ext().execute_with(|| {
		let depositor = 1;
		let amount = 1000u128;
		let commitment = sample_commitment();

		// Create invalid memo (wrong size)
		let invalid_memo_bytes = vec![42u8; 50]; // Not 104 bytes
		let invalid_memo = EncryptedMemo(BoundedVec::try_from(invalid_memo_bytes).unwrap());

		assert_noop!(
			ShieldedPool::shield(
				RuntimeOrigin::signed(depositor),
				0, // native asset
				amount,
				commitment,
				invalid_memo,
			),
			Error::<Test>::InvalidMemoSize
		);
	});
}

#[test]
fn multiple_shield_operations_store_different_memos() {
	new_test_ext().execute_with(|| {
		let depositor = 1;
		let amount = 1000u128;

		// First shield with memo 1
		let commitment1 = Commitment([1u8; 32]);
		let memo1 = sample_encrypted_memo_with_seed(1);
		assert_ok!(ShieldedPool::shield(
			RuntimeOrigin::signed(depositor),
			0, // native asset
			amount,
			commitment1,
			memo1.clone(),
		));

		// Second shield with memo 2
		let commitment2 = Commitment([2u8; 32]);
		let memo2 = sample_encrypted_memo_with_seed(2);
		assert_ok!(ShieldedPool::shield(
			RuntimeOrigin::signed(depositor),
			0, // native asset
			amount,
			commitment2,
			memo2.clone(),
		));

		// Verify both memos are stored correctly
		assert_eq!(
			crate::CommitmentMemos::<Test>::get(commitment1),
			Some(memo1)
		);
		assert_eq!(
			crate::CommitmentMemos::<Test>::get(commitment2),
			Some(memo2)
		);
	});
}

// ============================================================================
