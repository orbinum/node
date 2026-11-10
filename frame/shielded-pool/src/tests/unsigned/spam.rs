//! Anti-spam: the fee floor and the circuit-version guard.

use super::*;

// ── fee floor (anti-spam) ────────────────────────────────────────────────────
//
// Both validate_private_transfer and validate_unshield enforce the minimum
// spend fee set by T::MinSpendFee.
// The mock returns 0 by default; mock_set_min_spend_fee lets individual
// tests raise the floor to exercise the Payment rejection path.

#[test]
fn private_transfer_fee_below_minimum_rejected() {
	new_test_ext().execute_with(|| {
		crate::tests::mock::mock_set_min_spend_fee(100);
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
		// fee=50 < MinSpendFee=100 → InvalidTransaction::Payment
		let result = validate_private_transfer(&KNOWN_ROOT, &nullifiers_of(&[0x01]), &50u128, 1);
		assert!(result.is_err(), "fee below minimum must be rejected");
		assert_eq!(
			result.unwrap_err(),
			sp_runtime::transaction_validity::TransactionValidityError::Invalid(
				sp_runtime::transaction_validity::InvalidTransaction::Payment
			),
		);
	});
}

#[test]
fn private_transfer_fee_at_minimum_accepted() {
	new_test_ext().execute_with(|| {
		crate::tests::mock::mock_set_min_spend_fee(100);
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
		// fee == MinSpendFee → accept
		let result = validate_private_transfer(&KNOWN_ROOT, &nullifiers_of(&[0x01]), &100u128, 1);
		assert!(result.is_ok(), "fee equal to minimum must be accepted");
	});
}

#[test]
fn unshield_fee_below_minimum_rejected() {
	new_test_ext().execute_with(|| {
		crate::tests::mock::mock_set_min_spend_fee(200);
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
		PoolBalanceRepository::set_asset_balance::<Test>(0, 10_000u128);
		// fee=50 < MinSpendFee=200 → InvalidTransaction::Payment
		let result = validate_unshield(&KNOWN_ROOT, &nullifier(0x60), &0u32, &100u128, &50u128, 1);
		assert!(result.is_err(), "fee below minimum must be rejected");
		assert_eq!(
			result.unwrap_err(),
			sp_runtime::transaction_validity::TransactionValidityError::Invalid(
				sp_runtime::transaction_validity::InvalidTransaction::Payment
			),
		);
	});
}

#[test]
fn unshield_fee_at_minimum_accepted() {
	new_test_ext().execute_with(|| {
		crate::tests::mock::mock_set_min_spend_fee(200);
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
		PoolBalanceRepository::set_asset_balance::<Test>(0, 10_000u128);
		// fee == MinSpendFee → accept (pool has enough for amount+fee)
		let result = validate_unshield(&KNOWN_ROOT, &nullifier(0x60), &0u32, &100u128, &200u128, 1);
		assert!(result.is_ok(), "fee equal to minimum must be accepted");
	});
}
// ── circuit-version guard (anti-spam) ────────────────────────────────────────
//
// The mock's `is_supported_version` treats version 0 as unsupported; a
// supported version passes the guard, an unsupported one is rejected before
// any other check.

#[test]
fn private_transfer_unsupported_version_rejected() {
	new_test_ext().execute_with(|| {
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
		let result = validate_private_transfer(&KNOWN_ROOT, &nullifiers_of(&[0x01]), &0u128, 0);
		assert_eq!(
			result.unwrap_err(),
			sp_runtime::transaction_validity::TransactionValidityError::Invalid(
				sp_runtime::transaction_validity::InvalidTransaction::Custom(10)
			),
		);
	});
}

#[test]
fn unshield_unsupported_version_rejected() {
	new_test_ext().execute_with(|| {
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
		PoolBalanceRepository::set_asset_balance::<Test>(0, 1_000u128);
		let result = validate_unshield(&KNOWN_ROOT, &nullifier(0x10), &0u32, &500u128, &0u128, 0);
		assert_eq!(
			result.unwrap_err(),
			sp_runtime::transaction_validity::TransactionValidityError::Invalid(
				sp_runtime::transaction_validity::InvalidTransaction::Custom(10)
			),
		);
	});
}

/// Inside a block (`pre_dispatch`, no proof) the version guard still runs.
#[test]
#[allow(deprecated)] // `ValidateUnsigned`, which the pallet still implements
fn pre_dispatch_rejects_an_unsupported_version() {
	use frame_support::unsigned::ValidateUnsigned;
	new_test_ext().execute_with(|| {
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
		PoolBalanceRepository::set_asset_balance::<Test>(0, 1_000u128);
		let call = crate::Call::<Test>::unshield {
			proof: proof(),
			merkle_root: KNOWN_ROOT,
			nullifier: nullifier(0x10),
			asset_id: 0,
			amount: 500,
			recipient: acc(2),
			fee: 0,
			change_commitment: [0u8; 32],
			change_encrypted_memo: Default::default(),
			circuit_version: 0,
		};
		assert_eq!(
			crate::Pallet::<Test>::pre_dispatch(&call).unwrap_err(),
			codes::reject(codes::UNSUPPORTED_CIRCUIT_VERSION).into()
		);
	});
}
