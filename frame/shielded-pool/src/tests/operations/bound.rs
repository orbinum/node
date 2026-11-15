// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: GPL-3.0-or-later

//! Bound spends and minted notes: the proof binds the action, executors are
//! paid only by bound spends, pallet-backed assets stay inside the pool, and a
//! minted note is the commitment the circuits expect.

use crate::{
	Error,
	operations::{
		assets::AssetOperation,
		bound::{BoundSpendOperation, BoundSpendRequest, note_commitment},
		statement,
		unshield::{UnshieldOperation, UnshieldRequest},
	},
	pallet::{Call, Event as PalletEvent, PendingFees, PoolBalancePerAsset},
	storage::{MerkleRepository, NullifierRepository},
	tests::{
		mock::{
			Balances, RuntimeCall, RuntimeOrigin, ShieldedPool, System, TEST_ACTIONS_PALLET, Test,
			TestAction, acc, actions_run_before_redeems, executed_actions, executor,
			mock_refuse_redeem, mock_set_min_spend_fee, new_test_ext, redeemed_fees,
			verified_statements,
		},
		util::{KNOWN_ROOT, canonical_bytes, fund_pool, memo, nullifier, proof},
	},
	types::{AssetBackend, EncryptedMemo, Funding, NATIVE_ASSET_ID},
};
use frame_support::{
	BoundedVec, assert_noop, assert_ok,
	traits::{Currency, UnfilteredDispatchable},
};
use parity_scale_codec::Encode;
use sp_runtime::traits::Dispatchable;

fn spend(asset_id: u32, amount: u128, fee: u128, seed: u8) -> UnshieldRequest<Test> {
	UnshieldRequest {
		merkle_root: KNOWN_ROOT,
		nullifier: nullifier(seed),
		asset_id,
		amount,
		recipient: executor(),
		fee,
		change_commitment: [0u8; 32],
		change_memo: EncryptedMemo::default(),
		circuit_version: 1,
	}
}

fn bound(
	asset_id: u32,
	amount: u128,
	fee: u128,
	seed: u8,
	action: TestAction,
) -> BoundSpendRequest<Test> {
	BoundSpendRequest {
		spend: spend(asset_id, amount, fee, seed),
		action,
	}
}

fn bound_call(req: &BoundSpendRequest<Test>) -> Call<Test> {
	Call::bound_spend {
		proof: proof(),
		merkle_root: req.spend.merkle_root,
		nullifier: req.spend.nullifier,
		asset_id: req.spend.asset_id,
		amount: req.spend.amount,
		fee: req.spend.fee,
		change_commitment: req.spend.change_commitment,
		change_encrypted_memo: req.spend.change_memo.clone(),
		circuit_version: req.spend.circuit_version,
		action: req.action.clone(),
	}
}

fn pallet_asset() -> u32 {
	ShieldedPool::register_pallet_asset(
		BoundedVec::try_from(b"Staked ORB".to_vec()).unwrap(),
		BoundedVec::try_from(b"sORB".to_vec()).unwrap(),
		18,
		TEST_ACTIONS_PALLET,
	)
	.unwrap()
}

fn mint_to(seed: u8, asset_id: u32) -> TestAction {
	TestAction::Mint {
		asset_id,
		owner_pk: canonical_bytes(seed),
		blinding: canonical_bytes(seed ^ 0x55),
	}
}

// ── Binding ──────────────────────────────────────────────────────────────────

/// The proof commits to the action and the change memo under the bound domain,
/// names the executor as recipient, and the executor is paid.
#[test]
fn a_bound_spend_commits_to_its_action_and_pays_the_executor() {
	new_test_ext().execute_with(|| {
		fund_pool(NATIVE_ASSET_ID, 1_000);
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
		let req = bound(NATIVE_ASSET_ID, 400, 0, 0x01, TestAction::Keep);

		// What the verifier is asked to check, whether or not it runs.
		let statement = req.statement().unwrap();
		assert_ok!(BoundSpendOperation::execute::<Test>(&proof(), req.clone()));
		#[cfg(not(feature = "skip-proof-verification"))]
		assert_eq!(
			verified_statements(),
			vec![crate::tests::mock::VerifiedStatement::Unshield(
				statement,
				Some(1)
			)]
		);

		let bound_digest =
			statement::bound_digest::<Test>(&TestAction::Keep.encode(), &EncryptedMemo::default());
		assert_eq!(statement.memo_digest, bound_digest);
		assert_ne!(
			statement.memo_digest,
			statement::memo_digest(&[EncryptedMemo::default()]),
			"a plain unshield commits to something else"
		);
		assert_eq!(statement.recipient, <[u8; 32]>::from(executor()));
		assert_eq!(Balances::free_balance(executor()), 400);
		assert_eq!(PoolBalancePerAsset::<Test>::get(NATIVE_ASSET_ID), 600);
		assert!(NullifierRepository::is_used::<Test>(&nullifier(0x01)));
		assert_eq!(
			executed_actions(),
			vec![(TestAction::Keep, NATIVE_ASSET_ID, 400)]
		);
		assert!(System::events().iter().any(|r| matches!(
			&r.event,
			crate::tests::mock::RuntimeEvent::ShieldedPool(PalletEvent::BoundSpent {
				amount: 400,
				..
			})
		)));
	});
}

/// Any change to the action, its outputs included, changes what the proof
/// must commit to: a copier cannot swap them.
#[test]
fn the_digest_covers_every_byte_of_the_action() {
	new_test_ext().execute_with(|| {
		let keep = bound(NATIVE_ASSET_ID, 400, 0, 0x01, TestAction::Keep);
		let mint = bound(
			NATIVE_ASSET_ID,
			400,
			0,
			0x01,
			mint_to(0x10, NATIVE_ASSET_ID),
		);
		let other_owner = bound(
			NATIVE_ASSET_ID,
			400,
			0,
			0x01,
			mint_to(0x11, NATIVE_ASSET_ID),
		);
		let digests: Vec<_> = [keep, mint, other_owner]
			.iter()
			.map(|r| r.statement().unwrap().memo_digest)
			.collect();
		assert_ne!(digests[0], digests[1]);
		assert_ne!(digests[1], digests[2]);
	});
}

/// A plain unshield cannot pay an executor: a bound proof cannot be replayed
/// as one to strand the note's value in the executor's account.
#[test]
fn plain_unshield_refuses_an_executor() {
	new_test_ext().execute_with(|| {
		fund_pool(NATIVE_ASSET_ID, 1_000);
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
		assert_noop!(
			UnshieldOperation::execute::<Test>(&proof(), spend(NATIVE_ASSET_ID, 400, 0, 0x01)),
			Error::<Test>::InvalidRecipient
		);
	});
}

#[test]
fn a_refused_action_spends_nothing() {
	new_test_ext().execute_with(|| {
		fund_pool(NATIVE_ASSET_ID, 1_000);
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
		assert_noop!(
			BoundSpendOperation::execute::<Test>(
				&proof(),
				bound(NATIVE_ASSET_ID, 400, 0, 0x01, TestAction::Refuse)
			),
			Error::<Test>::InvalidBoundAction
		);
		assert!(verified_statements().is_empty(), "refused before the proof");
	});
}

#[test]
#[allow(deprecated)] // `ValidateUnsigned`, as the pallet still uses it
fn an_action_without_an_executor_is_refused() {
	new_test_ext().execute_with(|| {
		fund_pool(NATIVE_ASSET_ID, 1_000);
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
		let call = bound_call(&bound(NATIVE_ASSET_ID, 400, 0, 0x01, TestAction::Orphan));
		assert_noop!(
			call.clone().dispatch_bypass_filter(RuntimeOrigin::none()),
			Error::<Test>::InvalidBoundAction
		);
		use sp_runtime::traits::ValidateUnsigned;
		assert_eq!(
			ShieldedPool::validate_unsigned(
				sp_runtime::transaction_validity::TransactionSource::External,
				&call
			),
			sp_runtime::transaction_validity::InvalidTransaction::Call.into()
		);
	});
}

/// A failure inside the action after the spend settled reverts the spend too:
/// the nullifier stays unspent.
#[test]
fn an_action_failing_after_settlement_reverts_the_spend() {
	new_test_ext().execute_with(|| {
		fund_pool(NATIVE_ASSET_ID, 1_000);
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
		// A non-canonical owner key: the mint inside the action fails.
		let action = TestAction::Mint {
			asset_id: NATIVE_ASSET_ID,
			owner_pk: [0xFF; 32],
			blinding: canonical_bytes(1),
		};
		let call =
			RuntimeCall::ShieldedPool(bound_call(&bound(NATIVE_ASSET_ID, 400, 0, 0x01, action)));
		assert_noop!(
			call.dispatch(RuntimeOrigin::none()),
			Error::<Test>::InvalidPublicSignals
		);
		assert!(!NullifierRepository::is_used::<Test>(&nullifier(0x01)));
	});
}

#[test]
fn signed_bound_spends_are_refused() {
	new_test_ext().execute_with(|| {
		let call = bound_call(&bound(NATIVE_ASSET_ID, 400, 0, 0x01, TestAction::Keep));
		assert_noop!(
			call.dispatch_bypass_filter(RuntimeOrigin::signed(acc(2))),
			sp_runtime::DispatchError::BadOrigin
		);
	});
}

// ── Admission ────────────────────────────────────────────────────────────────

#[test]
#[allow(deprecated)] // `ValidateUnsigned`, as the pallet still uses it
fn admission_mirrors_dispatch() {
	new_test_ext().execute_with(|| {
		use sp_runtime::{
			traits::ValidateUnsigned,
			transaction_validity::{InvalidTransaction, TransactionSource},
		};
		fund_pool(NATIVE_ASSET_ID, 1_000);
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
		let ok = bound_call(&bound(NATIVE_ASSET_ID, 400, 0, 0x01, TestAction::Keep));
		let valid = ShieldedPool::validate_unsigned(TransactionSource::External, &ok).unwrap();
		assert!(!valid.provides.is_empty(), "tagged by its nullifier");

		let refused = bound_call(&bound(NATIVE_ASSET_ID, 400, 0, 0x02, TestAction::Refuse));
		assert_eq!(
			ShieldedPool::validate_unsigned(TransactionSource::External, &refused),
			InvalidTransaction::Custom(crate::validate_unsigned::codes::INVALID_ACTION).into()
		);
	});
}

// ── Minted notes ─────────────────────────────────────────────────────────────

/// The chain computes the same commitment the circuits and wallets do.
#[test]
fn a_minted_commitment_is_the_circuit_commitment() {
	use orbinum_zk_core::{
		Blinding, FieldElement, LightPoseidonHasher, OwnerPubkey, compute_commitment,
	};
	let (owner, blinding) = (canonical_bytes(0x21), canonical_bytes(0x22));
	let expected = compute_commitment(
		&LightPoseidonHasher,
		1_234_567,
		7,
		OwnerPubkey::from(FieldElement::from_canonical_le(&owner).unwrap()),
		Blinding::from(FieldElement::from_canonical_le(&blinding).unwrap()),
	);
	let ours = note_commitment(1_234_567, 7, &owner, &blinding).unwrap();
	assert_eq!(
		FieldElement::from_canonical_le(&ours).unwrap(),
		expected.inner()
	);
	assert_eq!(
		note_commitment(1, 0, &[0xFF; 32], &blinding),
		None,
		"non-canonical key"
	);
}

#[test]
fn a_native_note_is_paid_in_by_its_funder() {
	new_test_ext().execute_with(|| {
		Balances::make_free_balance_be(&executor(), 1_000);
		let (owner, blinding) = (canonical_bytes(0x31), canonical_bytes(0x32));
		let payer = executor();
		let mint = |value| {
			ShieldedPool::mint_note(
				NATIVE_ASSET_ID,
				value,
				owner,
				blinding,
				Funding::From(&payer),
			)
		};
		let note = mint(300).unwrap();
		assert_eq!(note.value, 300);
		assert_eq!(
			note.commitment.0,
			note_commitment(300, NATIVE_ASSET_ID, &owner, &blinding).unwrap()
		);
		assert_eq!(Balances::free_balance(executor()), 700);
		assert_eq!(PoolBalancePerAsset::<Test>::get(NATIVE_ASSET_ID), 300);
		// The same key and value again: the next value down, which the owner still
		// finds from `NoteMinted`; the unit not minted stays with the payer.
		assert_eq!(mint(300).unwrap().value, 299);
		assert_eq!(mint(300).unwrap().value, 298);
		assert_eq!(Balances::free_balance(executor()), 103);
		assert_noop!(
			mint(300).map(|_| ()),
			Error::<Test>::CommitmentAlreadyExists
		);
	});
}

#[test]
fn a_note_is_issued_only_by_its_asset_s_pallet() {
	new_test_ext().execute_with(|| {
		let asset = pallet_asset();
		let (owner, blinding) = (canonical_bytes(0x41), canonical_bytes(0x42));
		let other = frame_support::PalletId(*b"py/other");
		assert_noop!(
			ShieldedPool::mint_note(asset, 5, owner, blinding, Funding::Issued(other)).map(|_| ()),
			Error::<Test>::AssetNotSupported
		);
		assert_noop!(
			ShieldedPool::mint_note(NATIVE_ASSET_ID, 5, owner, blinding, Funding::Issued(other))
				.map(|_| ()),
			Error::<Test>::AssetNotSupported
		);
		assert_eq!(
			ShieldedPool::mint_note(
				asset,
				5,
				owner,
				blinding,
				Funding::Issued(TEST_ACTIONS_PALLET)
			)
			.unwrap()
			.value,
			5
		);
	});
}

// ── Pallet-backed assets ─────────────────────────────────────────────────────

#[test]
fn governance_cannot_freeze_a_pallet_asset() {
	new_test_ext().execute_with(|| {
		let id = pallet_asset();
		let asset = crate::Assets::<Test>::get(id).unwrap();
		assert!(asset.is_verified);
		assert_eq!(asset.backend, AssetBackend::Pallet(TEST_ACTIONS_PALLET.0));
		assert_noop!(
			ShieldedPool::unverify_asset(RuntimeOrigin::root(), id),
			Error::<Test>::AssetManagedByPallet
		);
		assert_noop!(
			ShieldedPool::verify_asset(RuntimeOrigin::root(), id),
			Error::<Test>::AssetManagedByPallet
		);
	});
}

/// Issue → spend for an action → fees redeemed by the pallet: the asset never
/// moves currency, and plain shield/unshield refuse it.
#[test]
fn a_pallet_asset_lives_and_dies_inside_the_pool() {
	new_test_ext().execute_with(|| {
		let id = pallet_asset();
		fund_pool(NATIVE_ASSET_ID, 1_000);
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);

		// A native bound spend whose action mints 400 of the pallet asset.
		assert_ok!(BoundSpendOperation::execute::<Test>(
			&proof(),
			bound(NATIVE_ASSET_ID, 400, 0, 0x01, mint_to(0x40, id))
		));
		assert_eq!(PoolBalancePerAsset::<Test>::get(id), 400);
		assert!(System::events().iter().any(|r| matches!(
			&r.event,
			crate::tests::mock::RuntimeEvent::ShieldedPool(PalletEvent::NoteMinted {
				value: 400,
				..
			})
		)));

		// Spending it burns it; its fee is redeemed for the author at once by the
		// issuing pallet, and leaves the ledger: no currency moves.
		mock_set_min_spend_fee(5);
		let pool_native = Balances::free_balance(ShieldedPool::pool_account_id());
		assert_ok!(BoundSpendOperation::execute::<Test>(
			&proof(),
			bound(id, 300, 5, 0x02, TestAction::Keep)
		));
		assert_eq!(redeemed_fees(), vec![(acc(1), id, 5)]);
		// The action ran on the state admission saw, before the fee was redeemed.
		assert_eq!(actions_run_before_redeems(), vec![executed_actions().len()]);
		assert_eq!(PoolBalancePerAsset::<Test>::get(id), 95);
		assert_eq!(PendingFees::<Test>::get(acc(1), id), 0);
		assert_eq!(
			Balances::free_balance(ShieldedPool::pool_account_id()),
			pool_native
		);

		// Below the pallet's floor: refused.
		assert_noop!(
			BoundSpendOperation::execute::<Test>(
				&proof(),
				bound(id, 10, 4, 0x03, TestAction::Keep)
			),
			Error::<Test>::FeeTooLow
		);

		// When the pallet cannot redeem it now, the fee waits in `PendingFees` and
		// the author claims it later.
		mock_refuse_redeem(true);
		assert_ok!(BoundSpendOperation::execute::<Test>(
			&proof(),
			bound(id, 10, 5, 0x06, TestAction::Keep)
		));
		assert_eq!(PendingFees::<Test>::get(acc(1), id), 5);
		assert_eq!(PoolBalancePerAsset::<Test>::get(id), 85);
		mock_refuse_redeem(false);
		assert_ok!(ShieldedPool::claim_fees(
			RuntimeOrigin::signed(acc(1)),
			id,
			5
		));
		assert_eq!(redeemed_fees(), vec![(acc(1), id, 5), (acc(1), id, 5)]);
		assert_eq!(PoolBalancePerAsset::<Test>::get(id), 80);
		assert_eq!(PendingFees::<Test>::get(acc(1), id), 0);

		// Plain moves refuse it; in-pool spends accept it.
		assert!(matches!(
			AssetOperation::ensure_movable::<Test>(id),
			Err(Error::<Test>::AssetNotSupported)
		));
		assert!(AssetOperation::ensure_spendable::<Test>(id).is_ok());
		let mut plain = spend(id, 10, 5, 0x04);
		plain.recipient = acc(2);
		assert_noop!(
			UnshieldOperation::execute::<Test>(&proof(), plain),
			Error::<Test>::AssetNotSupported
		);
		assert_ok!(BoundSpendOperation::execute::<Test>(
			&proof(),
			bound(id, 70, 5, 0x05, TestAction::Keep)
		));
		let _ = memo(0);
	});
}

// ── Migration ────────────────────────────────────────────────────────────────

/// v3 assets had no backend: the migration makes each `Native`.
#[test]
fn v4_migration_gives_every_asset_a_backend() {
	new_test_ext().execute_with(|| {
		use frame_support::traits::{GetStorageVersion, OnRuntimeUpgrade, StorageVersion};
		#[derive(Encode)]
		struct V3 {
			id: u32,
			name: BoundedVec<u8, frame_support::traits::ConstU32<64>>,
			symbol: BoundedVec<u8, frame_support::traits::ConstU32<16>>,
			decimals: u8,
			is_verified: bool,
			contract_address: Option<[u8; 20]>,
			created_at: u64,
			creator: sp_runtime::AccountId32,
		}
		let key = crate::Assets::<Test>::hashed_key_for(9u32);
		frame_support::storage::unhashed::put(
			&key,
			&V3 {
				id: 9,
				name: BoundedVec::try_from(b"Old".to_vec()).unwrap(),
				symbol: BoundedVec::try_from(b"OLD".to_vec()).unwrap(),
				decimals: 6,
				is_verified: true,
				contract_address: None,
				created_at: 3,
				creator: acc(7),
			},
		);
		// The native asset genesis wrote is in the v4 shape already; rewrite it
		// as v3 too, as a v3 chain stores it.
		let native = crate::Assets::<Test>::get(NATIVE_ASSET_ID).unwrap();
		frame_support::storage::unhashed::put(
			&crate::Assets::<Test>::hashed_key_for(NATIVE_ASSET_ID),
			&V3 {
				id: native.id,
				name: native.name,
				symbol: native.symbol,
				decimals: native.decimals,
				is_verified: native.is_verified,
				contract_address: native.contract_address,
				created_at: 0,
				creator: native.creator,
			},
		);
		StorageVersion::new(3).put::<ShieldedPool>();

		crate::migrations::v4::MigrateToV4::<Test>::on_runtime_upgrade();

		assert_eq!(ShieldedPool::on_chain_storage_version(), 4);
		let old = crate::Assets::<Test>::get(9).unwrap();
		assert_eq!(
			(old.backend, old.decimals, old.creator),
			(AssetBackend::Native, 6, acc(7))
		);
		assert_eq!(
			crate::Assets::<Test>::get(NATIVE_ASSET_ID).unwrap().backend,
			AssetBackend::Native
		);
		// A second run does nothing.
		crate::migrations::v4::MigrateToV4::<Test>::on_runtime_upgrade();
		assert_eq!(crate::Assets::<Test>::iter().count(), 2);
	});
}

/// The v4 migration runs only from storage v3: from any other version it leaves the
/// assets alone rather than decode them as v3.
#[test]
fn the_v4_migration_runs_only_from_v3() {
	use frame_support::traits::{GetStorageVersion, OnRuntimeUpgrade, StorageVersion};
	new_test_ext().execute_with(|| {
		let before = crate::Assets::<Test>::get(NATIVE_ASSET_ID).unwrap();
		StorageVersion::new(2).put::<ShieldedPool>();
		crate::migrations::v4::MigrateToV4::<Test>::on_runtime_upgrade();
		assert_eq!(ShieldedPool::on_chain_storage_version(), 2);
		assert_eq!(crate::Assets::<Test>::get(NATIVE_ASSET_ID).unwrap(), before);
	});
}

/// A fee buys pool priority by its native value: a fee in a pallet asset whose floor
/// is twice `MinSpendFee` (each unit worth half) buys half the priority.
#[test]
fn spend_priority_is_the_fee_s_native_value() {
	new_test_ext().execute_with(|| {
		let id = pallet_asset();
		mock_set_min_spend_fee(10);
		assert_eq!(
			crate::operations::fees::priority::<Test>(NATIVE_ASSET_ID, 40),
			40
		);
		assert_eq!(crate::operations::fees::priority::<Test>(id, 40), 40);
		crate::tests::mock::mock_set_pallet_floor(20);
		assert_eq!(crate::operations::fees::priority::<Test>(id, 40), 20);
		assert_eq!(crate::operations::fees::priority::<Test>(999, 40), 0);
	});
}
