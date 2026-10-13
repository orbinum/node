//! Spend fees: crediting the block author, the fee floor, and claims.

use super::{KNOWN_ROOT, fund_pool, nullifier, proof, register_asset, setup_asset};
use crate::{
	Error,
	mock::{
		Balances, RuntimeOrigin, ShieldedPool, System, Test, acc, mock_clear_block_author,
		mock_pending_fees_get, mock_pending_fees_set, mock_set_min_spend_fee, new_test_ext,
	},
	operations::{assets::AssetOperation, fees::*},
	pallet::{Event as PalletEvent, PendingFees, PoolBalancePerAsset},
	storage::MerkleRepository,
	types::EncryptedMemo,
};
use frame_support::{assert_noop, assert_ok, traits::UnfilteredDispatchable};

fn pool_physical() -> u128 {
	Balances::free_balance(crate::Pallet::<Test>::pool_account_id())
}

// ── credit_fee ───────────────────────────────────────────────────────────────

#[test]
fn fee_is_credited_to_the_block_author() {
	new_test_ext().execute_with(|| {
		assert_ok!(credit_fee::<Test>(0, 30));
		assert_ok!(credit_fee::<Test>(0, 12));
		assert_eq!(mock_pending_fees_get(acc(1), 0), 42);
		System::assert_last_event(
			PalletEvent::FeeCredited {
				validator: acc(1),
				asset_id: 0,
				amount: 12,
			}
			.into(),
		);
	});
}

#[test]
fn fee_follows_the_author_of_each_block() {
	new_test_ext().execute_with(|| {
		assert_ok!(credit_fee::<Test>(0, 30));
		crate::mock::BlockAuthorAccount::set(Some(acc(2)));
		assert_ok!(credit_fee::<Test>(0, 20));
		assert_eq!(mock_pending_fees_get(acc(1), 0), 30);
		assert_eq!(mock_pending_fees_get(acc(2), 0), 20);
	});
}

#[test]
fn fee_without_a_block_author_is_rejected() {
	new_test_ext().execute_with(|| {
		mock_clear_block_author();
		assert!(matches!(
			credit_fee::<Test>(0, 30),
			Err(Error::<Test>::FeeRecipientUnavailable)
		));
		assert!(PendingFees::<Test>::iter().next().is_none());
	});
}

// ── MinSpendFee ──────────────────────────────────────────────────────────────

fn unshield_call(fee: u128) -> crate::Call<Test> {
	crate::Call::<Test>::unshield {
		proof: proof(),
		merkle_root: KNOWN_ROOT,
		nullifier: nullifier(0x41),
		asset_id: 0,
		amount: 500,
		recipient: acc(2),
		fee,
		change_commitment: [0u8; 32],
		change_encrypted_memo: EncryptedMemo::default(),
		circuit_version: 1,
	}
}

#[test]
fn a_spend_below_the_fee_floor_is_refused() {
	new_test_ext().execute_with(|| {
		fund_pool(setup_asset(), 1_000);
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
		mock_set_min_spend_fee(50);

		assert_noop!(
			unshield_call(49).dispatch_bypass_filter(RuntimeOrigin::none()),
			Error::<Test>::FeeTooLow
		);
		assert_ok!(unshield_call(50).dispatch_bypass_filter(RuntimeOrigin::none()));
		assert_eq!(mock_pending_fees_get(acc(1), 0), 50);
	});
}

// ── claim_fees ───────────────────────────────────────────────────────────────

#[test]
fn claim_pays_the_validator_and_updates_every_ledger() {
	new_test_ext().execute_with(|| {
		let asset_id = setup_asset();
		fund_pool(asset_id, 500);
		mock_pending_fees_set(acc(7), asset_id, 200);

		assert_ok!(ShieldedPool::claim_fees(
			RuntimeOrigin::signed(acc(7)),
			asset_id,
			150
		));

		assert_eq!(Balances::free_balance(acc(7)), 150);
		assert_eq!(PoolBalancePerAsset::<Test>::get(asset_id), 350);
		assert_eq!(pool_physical(), 350);
		assert_eq!(mock_pending_fees_get(acc(7), asset_id), 50);
		System::assert_last_event(
			PalletEvent::FeesClaimed {
				validator: acc(7),
				asset_id,
				amount: 150,
			}
			.into(),
		);
	});
}

#[test]
fn a_full_claim_clears_the_pending_entry() {
	new_test_ext().execute_with(|| {
		let asset_id = setup_asset();
		fund_pool(asset_id, 500);
		mock_pending_fees_set(acc(7), asset_id, 200);

		assert_ok!(ShieldedPool::claim_fees(
			RuntimeOrigin::signed(acc(7)),
			asset_id,
			200
		));
		assert!(!PendingFees::<Test>::contains_key(acc(7), asset_id));
	});
}

#[test]
fn claim_is_bounded_by_the_callers_own_pending_fees() {
	new_test_ext().execute_with(|| {
		let asset_id = setup_asset();
		fund_pool(asset_id, 500);
		mock_pending_fees_set(acc(7), asset_id, 100);
		mock_pending_fees_set(acc(8), asset_id, 400);

		assert_noop!(
			ShieldedPool::claim_fees(RuntimeOrigin::signed(acc(7)), asset_id, 101),
			Error::<Test>::InsufficientPendingFees
		);
		// Another account's balance is not reachable.
		assert_noop!(
			ShieldedPool::claim_fees(RuntimeOrigin::signed(acc(9)), asset_id, 1),
			Error::<Test>::InsufficientPendingFees
		);
		assert_eq!(mock_pending_fees_get(acc(8), asset_id), 400);
	});
}

#[test]
fn claim_rejects_zero_unknown_asset_and_an_underfunded_ledger() {
	new_test_ext().execute_with(|| {
		let asset_id = setup_asset();
		fund_pool(asset_id, 50);
		mock_pending_fees_set(acc(7), asset_id, 100);

		assert_noop!(
			FeeOperation::claim::<Test>(acc(7), asset_id, 0),
			Error::<Test>::InvalidAmount
		);
		assert_noop!(
			FeeOperation::claim::<Test>(acc(7), 999, 10),
			Error::<Test>::InvalidAssetId
		);
		assert_noop!(
			FeeOperation::claim::<Test>(acc(7), asset_id, 60),
			Error::<Test>::InsufficientPoolBalance
		);
	});
}

#[test]
fn claim_reverts_the_pending_debit_when_the_payout_fails() {
	new_test_ext().execute_with(|| {
		let asset_id = setup_asset();
		// Ledger says funded, the account is not: the transfer fails.
		PoolBalancePerAsset::<Test>::insert(asset_id, 500);
		mock_pending_fees_set(acc(7), asset_id, 200);

		assert!(ShieldedPool::claim_fees(RuntimeOrigin::signed(acc(7)), asset_id, 100).is_err());
		assert_eq!(mock_pending_fees_get(acc(7), asset_id), 200);
	});
}

#[test]
fn unsigned_and_root_claims_are_rejected() {
	new_test_ext().execute_with(|| {
		let asset_id = setup_asset();
		for origin in [RuntimeOrigin::none(), RuntimeOrigin::root()] {
			assert_noop!(
				ShieldedPool::claim_fees(origin, asset_id, 1),
				sp_runtime::traits::BadOrigin
			);
		}
	});
}

/// Unverifying an asset freezes every outflow, fees included.
#[test]
fn claims_of_a_frozen_asset_are_refused() {
	new_test_ext().execute_with(|| {
		let asset_id = setup_asset();
		fund_pool(asset_id, 500);
		mock_pending_fees_set(acc(7), asset_id, 100);
		AssetOperation::unverify::<Test>(asset_id).unwrap();
		assert_noop!(
			ShieldedPool::claim_fees(RuntimeOrigin::signed(acc(7)), asset_id, 10),
			Error::<Test>::AssetNotVerified
		);
		AssetOperation::verify::<Test>(asset_id).unwrap();
		assert_ok!(ShieldedPool::claim_fees(
			RuntimeOrigin::signed(acc(7)),
			asset_id,
			10
		));
	});
}

/// A verified non-native asset is not backed: claiming it would pay native funds.
#[test]
fn claims_of_a_non_native_asset_are_refused() {
	new_test_ext().execute_with(|| {
		let asset_id = register_asset();
		AssetOperation::verify::<Test>(asset_id).unwrap();
		fund_pool(asset_id, 500);
		mock_pending_fees_set(acc(7), asset_id, 100);
		assert_noop!(
			ShieldedPool::claim_fees(RuntimeOrigin::signed(acc(7)), asset_id, 10),
			Error::<Test>::AssetNotSupported
		);
	});
}
