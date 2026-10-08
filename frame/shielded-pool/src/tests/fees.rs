//! Relay fees: op hashes, crediting the committed relayer, and claims.

use super::{commit, evm, fund_pool, register_asset, setup_asset};
use crate::{
	Call, Commitment, Error, Nullifier, RawOrigin,
	mock::{
		Balances, MirrorAccount, RuntimeOrigin, ShieldedPool, System, Test, acc,
		mock_clear_block_author, mock_pending_fees_get, mock_pending_fees_set,
		mock_register_relayer, new_test_ext,
	},
	operations::{
		assets::AssetOperation, fees::*, private_transfer::TransferRequest,
		unshield::UnshieldRequest,
	},
	origin::RelayCaller,
	pallet::{Event as PalletEvent, PoolBalancePerAsset},
	types::EncryptedMemo,
};
use frame_support::{assert_noop, assert_ok};
use pallet_zk_verifier::{TransferStatement, UnshieldStatement};
use sp_runtime::traits::Convert;

const ROOT: [u8; 32] = [0x01; 32];
const NULL: [u8; 32] = [0x02; 32];
const CHANGE: [u8; 32] = [0x03; 32];

fn mirror(b: u8) -> crate::mock::AccountId {
	MirrorAccount::convert(evm(b))
}

fn unshield() -> UnshieldStatement {
	UnshieldStatement {
		merkle_root: ROOT,
		nullifier: NULL,
		amount: 100,
		recipient: acc(9).into(),
		asset_id: 0,
		fee: 5,
		change_commitment: CHANGE,
		memo_digest: [0xEE; 32],
	}
}

fn transfer() -> TransferStatement {
	TransferStatement {
		merkle_roots: [ROOT; 2],
		nullifiers: vec![NULL],
		commitments: vec![CHANGE],
		asset_id: 0,
		fee: 5,
		memo_digest: [0xEE; 32],
	}
}

// ── operation hashes ─────────────────────────────────────────────────────────

#[test]
fn every_public_value_changes_the_unshield_hash() {
	let base = unshield_op_hash(&unshield(), 1);
	assert_eq!(base, unshield_op_hash(&unshield(), 1));
	let variants = [
		UnshieldStatement {
			merkle_root: [0xFF; 32],
			..unshield()
		},
		UnshieldStatement {
			nullifier: [0xFF; 32],
			..unshield()
		},
		UnshieldStatement {
			asset_id: 1,
			..unshield()
		},
		UnshieldStatement {
			amount: 101,
			..unshield()
		},
		UnshieldStatement {
			recipient: acc(8).into(),
			..unshield()
		},
		UnshieldStatement {
			fee: 6,
			..unshield()
		},
		UnshieldStatement {
			change_commitment: [0xFF; 32],
			..unshield()
		},
	];
	for v in variants {
		assert_ne!(unshield_op_hash(&v, 1), base, "{v:?}");
	}
	assert_ne!(unshield_op_hash(&unshield(), 2), base, "circuit version");
}

/// The roots are bound in input order: a commit to one order is not a commit
/// to the swapped one, so a relayer cannot claim a spend it did not commit to
/// by reordering its roots.
#[test]
fn the_transfer_hash_binds_the_order_of_the_roots() {
	let ab = TransferStatement {
		merkle_roots: [[0x0A; 32], [0x0B; 32]],
		..transfer()
	};
	let ba = TransferStatement {
		merkle_roots: [[0x0B; 32], [0x0A; 32]],
		..transfer()
	};
	assert_ne!(transfer_op_hash(&ab, 3), transfer_op_hash(&ba, 3));
}

#[test]
fn every_public_value_changes_the_transfer_hash() {
	let base = transfer_op_hash(&transfer(), 1);
	let variants = [
		TransferStatement {
			merkle_roots: [[0xFF; 32], ROOT],
			..transfer()
		},
		TransferStatement {
			merkle_roots: [ROOT, [0xFF; 32]],
			..transfer()
		},
		TransferStatement {
			nullifiers: vec![[0xFF; 32]],
			..transfer()
		},
		TransferStatement {
			commitments: vec![[0xFF; 32]],
			..transfer()
		},
		TransferStatement {
			nullifiers: vec![NULL, NULL],
			commitments: vec![CHANGE, CHANGE],
			..transfer()
		},
		TransferStatement {
			asset_id: 1,
			..transfer()
		},
		TransferStatement {
			fee: 6,
			..transfer()
		},
	];
	for v in variants {
		assert_ne!(transfer_op_hash(&v, 1), base, "{v:?}");
	}
	assert_ne!(transfer_op_hash(&transfer(), 2), base, "circuit version");
}

/// Memos stay out of the identity: a v1 proof does not bind them, and a copier
/// swapping them must not escape the original relayer's commit.
#[test]
fn memos_do_not_change_either_hash() {
	assert_eq!(
		unshield_op_hash(
			&UnshieldStatement {
				memo_digest: [0x11; 32],
				..unshield()
			},
			1
		),
		unshield_op_hash(&unshield(), 1)
	);
	assert_eq!(
		transfer_op_hash(
			&TransferStatement {
				memo_digest: [0x11; 32],
				..transfer()
			},
			1
		),
		transfer_op_hash(&transfer(), 1)
	);
}

fn unshield_call(proof_byte: u8, memo: EncryptedMemo) -> Call<Test> {
	Call::<Test>::unshield {
		proof: vec![proof_byte; 64].try_into().unwrap(),
		merkle_root: ROOT,
		nullifier: Nullifier(NULL),
		asset_id: 0,
		amount: 100,
		recipient: acc(9),
		fee: 5,
		change_commitment: CHANGE,
		change_encrypted_memo: memo,
		circuit_version: 1,
	}
}

#[test]
fn relay_op_hash_is_the_extrinsics_own_hash() {
	let request = UnshieldRequest::<Test> {
		merkle_root: ROOT,
		nullifier: Nullifier(NULL),
		asset_id: 0,
		amount: 100,
		recipient: acc(9),
		fee: 5,
		change_commitment: CHANGE,
		change_memo: Default::default(),
		circuit_version: 1,
	};
	let expected = request.op_hash().unwrap();
	assert_eq!(expected, unshield_op_hash(&request.statement().unwrap(), 1));
	assert_eq!(
		relay_op_hash(&unshield_call(0xAB, Default::default())),
		Some(expected)
	);
	// Neither a re-randomised proof nor another memo escapes the commit.
	assert_eq!(
		relay_op_hash(&unshield_call(0xCD, Default::default())),
		Some(expected)
	);
	let other_memo = EncryptedMemo::from_bytes(&[7; 180]).unwrap();
	assert_eq!(
		relay_op_hash(&unshield_call(0xAB, other_memo)),
		Some(expected)
	);

	let transfer_call = Call::<Test>::private_transfer {
		proof: vec![0xAB; 64].try_into().unwrap(),
		merkle_roots: [ROOT; 2],
		nullifiers: vec![Nullifier(NULL)].try_into().unwrap(),
		commitments: vec![Commitment(CHANGE)].try_into().unwrap(),
		encrypted_memos: vec![Default::default()].try_into().unwrap(),
		asset_id: 0,
		fee: 5,
		circuit_version: 1,
	};
	let request = TransferRequest::<Test> {
		merkle_roots: [ROOT; 2],
		nullifiers: vec![Nullifier(NULL)].try_into().unwrap(),
		commitments: vec![Commitment(CHANGE)].try_into().unwrap(),
		memos: vec![Default::default()].try_into().unwrap(),
		asset_id: 0,
		fee: 5,
		circuit_version: 1,
	};
	assert_eq!(relay_op_hash(&transfer_call), Some(request.op_hash()));
}

#[test]
fn non_relayable_calls_have_no_op_hash() {
	assert_eq!(
		relay_op_hash(&Call::<Test>::verify_asset { asset_id: 0 }),
		None
	);
}

// ── credit_relay_fee ─────────────────────────────────────────────────────────

#[test]
fn fee_goes_to_the_committed_relayer() {
	new_test_ext().execute_with(|| {
		mock_register_relayer(acc(7), evm(0xAA));
		let op = unshield_op_hash(&unshield(), 1);
		commit(evm(0xAA), &op);
		System::set_block_number(2);

		assert_ok!(credit_relay_fee::<Test>(&op, 0, 30));
		assert_eq!(mock_pending_fees_get(acc(7), 0), 30);
		assert_eq!(mock_pending_fees_get(acc(1), 0), 0);
	});
}

#[test]
fn fee_without_a_commit_goes_to_the_block_author() {
	new_test_ext().execute_with(|| {
		assert_ok!(credit_relay_fee::<Test>(
			&unshield_op_hash(&unshield(), 1),
			0,
			30
		));
		assert_eq!(mock_pending_fees_get(acc(1), 0), 30);
	});
}

#[test]
fn fee_with_no_recipient_at_all_is_rejected() {
	new_test_ext().execute_with(|| {
		mock_clear_block_author();
		assert!(matches!(
			credit_relay_fee::<Test>(&unshield_op_hash(&unshield(), 1), 0, 30),
			Err(Error::<Test>::FeeRecipientUnavailable)
		));
	});
}

/// A commit lives `CommitTtl` blocks: pruned at expiry, it earns nothing and
/// the fee falls back to the block author.
#[test]
fn an_expired_commit_earns_nothing() {
	use frame_support::traits::{Get, Hooks};
	new_test_ext().execute_with(|| {
		mock_register_relayer(acc(7), evm(0xAA));
		let op = unshield_op_hash(&unshield(), 1);
		commit(evm(0xAA), &op);
		let expiry: u64 = 1 + <<Test as pallet_relayer::Config>::CommitTtl as Get<u64>>::get();
		System::set_block_number(expiry);
		pallet_relayer::Pallet::<Test>::on_initialize(expiry);

		assert_ok!(credit_relay_fee::<Test>(&op, 0, 30));
		assert_eq!(mock_pending_fees_get(acc(7), 0), 0);
		assert_eq!(mock_pending_fees_get(acc(1), 0), 30);
	});
}

// ── FeeOperation::claim ──────────────────────────────────────────────────────

#[test]
fn claim_pays_the_destination_and_updates_every_ledger() {
	new_test_ext().execute_with(|| {
		let asset_id = setup_asset();
		fund_pool(asset_id, 500);
		mock_pending_fees_set(acc(7), asset_id, 200);

		assert_ok!(FeeOperation::claim::<Test>(acc(7), acc(9), asset_id, 150));

		assert_eq!(Balances::free_balance(acc(9)), 150);
		assert_eq!(PoolBalancePerAsset::<Test>::get(asset_id), 350);
		assert_eq!(
			Balances::free_balance(crate::Pallet::<Test>::pool_account_id()),
			350
		);
		assert_eq!(mock_pending_fees_get(acc(7), asset_id), 50);
		System::assert_last_event(
			PalletEvent::RelayFeesClaimed {
				who: acc(7),
				to: acc(9),
				asset_id,
				amount: 150,
			}
			.into(),
		);
	});
}

#[test]
fn claim_is_bounded_by_the_claimants_own_pending_fees() {
	new_test_ext().execute_with(|| {
		let asset_id = setup_asset();
		fund_pool(asset_id, 500);
		mock_pending_fees_set(acc(7), asset_id, 100);
		mock_pending_fees_set(acc(8), asset_id, 400);

		assert_noop!(
			FeeOperation::claim::<Test>(acc(7), acc(7), asset_id, 101),
			pallet_relayer::Error::<Test>::InsufficientPendingFees
		);
		// Another account's balance is not reachable.
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
			FeeOperation::claim::<Test>(acc(7), acc(7), asset_id, 0),
			Error::<Test>::InvalidAmount
		);
		assert_noop!(
			FeeOperation::claim::<Test>(acc(7), acc(7), 999, 10),
			Error::<Test>::InvalidAssetId
		);
		assert_noop!(
			FeeOperation::claim::<Test>(acc(7), acc(7), asset_id, 60),
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

		assert!(
			ShieldedPool::claim_relay_fees(RuntimeOrigin::signed(acc(7)), asset_id, 100).is_err()
		);
		assert_eq!(mock_pending_fees_get(acc(7), asset_id), 200);
	});
}

// ── claim_relay_fees: who pays whom ──────────────────────────────────────────

#[test]
fn signed_claim_pays_the_registered_evm_mirror() {
	new_test_ext().execute_with(|| {
		let asset_id = setup_asset();
		fund_pool(asset_id, 500);
		mock_register_relayer(acc(7), evm(0xAA));
		mock_pending_fees_set(acc(7), asset_id, 100);

		assert_ok!(ShieldedPool::claim_relay_fees(
			RuntimeOrigin::signed(acc(7)),
			asset_id,
			100
		));
		assert_eq!(Balances::free_balance(mirror(0xAA)), 100);
	});
}

#[test]
fn signed_claim_without_registration_pays_the_account_itself() {
	new_test_ext().execute_with(|| {
		let asset_id = setup_asset();
		fund_pool(asset_id, 500);
		mock_pending_fees_set(acc(4), asset_id, 100);

		assert_ok!(ShieldedPool::claim_relay_fees(
			RuntimeOrigin::signed(acc(4)),
			asset_id,
			100
		));
		assert_eq!(Balances::free_balance(acc(4)), 100);
	});
}

#[test]
fn evm_claim_spends_the_registered_accounts_fees_into_the_callers_mirror() {
	new_test_ext().execute_with(|| {
		let asset_id = setup_asset();
		fund_pool(asset_id, 500);
		mock_register_relayer(acc(7), evm(0xAA));
		mock_pending_fees_set(acc(7), asset_id, 100);

		assert_ok!(ShieldedPool::claim_relay_fees(
			RawOrigin::Relayed(evm(0xAA)).into(),
			asset_id,
			100
		));
		assert_eq!(mock_pending_fees_get(acc(7), asset_id), 0);
		assert_eq!(Balances::free_balance(mirror(0xAA)), 100);
	});
}

#[test]
fn evm_claim_is_bounded_by_the_pool_ledger() {
	new_test_ext().execute_with(|| {
		let asset_id = setup_asset();
		fund_pool(asset_id, 50);
		mock_register_relayer(acc(7), evm(0xAA));
		mock_pending_fees_set(acc(7), asset_id, 100);
		assert_noop!(
			ShieldedPool::claim_relay_fees(RawOrigin::Relayed(evm(0xAA)).into(), asset_id, 100),
			Error::<Test>::InsufficientPoolBalance
		);
	});
}

#[test]
fn evm_claim_from_an_unregistered_address_is_rejected() {
	new_test_ext().execute_with(|| {
		let asset_id = setup_asset();
		fund_pool(asset_id, 500);
		assert_noop!(
			ShieldedPool::claim_relay_fees(RawOrigin::Relayed(evm(0xBB)).into(), asset_id, 100),
			Error::<Test>::RelayerNotRegistered
		);
	});
}

#[test]
fn unsigned_claim_is_rejected() {
	new_test_ext().execute_with(|| {
		let asset_id = setup_asset();
		assert_noop!(
			ShieldedPool::claim_relay_fees(RuntimeOrigin::none(), asset_id, 1),
			sp_runtime::traits::BadOrigin
		);
	});
}

#[test]
fn claimant_and_payee_follow_the_caller() {
	new_test_ext().execute_with(|| {
		mock_register_relayer(acc(7), evm(0xAA));
		let who = |c| FeeOperation::claimant_and_payee::<Test>(c);
		assert_eq!(
			who(RelayCaller::Evm(evm(0xAA))).unwrap(),
			(acc(7), mirror(0xAA))
		);
		assert_eq!(
			who(RelayCaller::Signed(acc(7))).unwrap(),
			(acc(7), mirror(0xAA))
		);
		assert_eq!(who(RelayCaller::Signed(acc(4))).unwrap(), (acc(4), acc(4)));
		assert!(matches!(
			who(RelayCaller::Evm(evm(0xBB))),
			Err(Error::<Test>::RelayerNotRegistered)
		));
	});
}

/// Unverifying an asset freezes every outflow, relay fees included.
#[test]
fn claims_of_a_frozen_asset_are_refused() {
	new_test_ext().execute_with(|| {
		let asset_id = setup_asset();
		fund_pool(asset_id, 500);
		mock_pending_fees_set(acc(7), asset_id, 100);
		AssetOperation::unverify::<Test>(asset_id).unwrap();
		assert_noop!(
			FeeOperation::claim::<Test>(acc(7), acc(7), asset_id, 10),
			Error::<Test>::AssetNotVerified
		);
		AssetOperation::verify::<Test>(asset_id).unwrap();
		assert_ok!(FeeOperation::claim::<Test>(acc(7), acc(7), asset_id, 10));
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
			FeeOperation::claim::<Test>(acc(7), acc(7), asset_id, 10),
			Error::<Test>::AssetNotSupported
		);
	});
}
