//! `ShieldOperation`: validation, settlement, queries, the proof and the batch
//! guard.

use crate::{
	operations::assets::AssetOperation,
	operations::shield::*,
	pallet::Event as PalletEvent,
	storage::{CommitmentRepository, PoolBalanceRepository},
	tests::{
		mock::{Test, acc, new_test_ext},
		util::{commitment, memo, register_asset, setup_asset, short_memo},
	},
	types::Commitment,
	types::EncryptedMemo,
};
use frame_support::{assert_noop, assert_ok, pallet_prelude::DispatchResult};
#[cfg(not(feature = "skip-proof-verification"))]
use pallet_zk_verifier::ShieldStatement;
use sp_runtime::AccountId32;

fn memo_valid() -> EncryptedMemo {
	memo(0x01)
}

fn request(
	asset_id: u32,
	amount: u128,
	commitment: Commitment,
	encrypted_memo: EncryptedMemo,
) -> ShieldRequest<Test> {
	ShieldRequest {
		asset_id,
		amount,
		commitment,
		encrypted_memo,
		circuit_version: 1,
	}
}

/// `ShieldOperation::execute` with a well-formed shield proof at version 1.
fn execute(
	depositor: AccountId32,
	asset_id: u32,
	amount: u128,
	commitment: Commitment,
	encrypted_memo: EncryptedMemo,
) -> DispatchResult {
	ShieldOperation::execute::<Test>(
		depositor,
		&[0x01; 128],
		request(asset_id, amount, commitment, encrypted_memo),
	)
}

// ── execute ──────────────────────────────────────────────────────────────

#[test]
fn execute_works() {
	new_test_ext().execute_with(|| {
		let asset_id = setup_asset();
		let c = commitment(0x01);

		assert_ok!(execute(acc(1), asset_id, 500u128, c, memo_valid(),));
	});
}

#[test]
fn execute_invalid_asset_fails() {
	new_test_ext().execute_with(|| {
		assert_noop!(
			execute(acc(1), 99u32, 500u128, commitment(1), memo_valid()),
			crate::pallet::Error::<Test>::InvalidAssetId
		);
	});
}

/// A verified non-native asset would be shielded out of the native balance.
#[test]
fn execute_non_native_asset_fails() {
	new_test_ext().execute_with(|| {
		let id = register_asset();
		AssetOperation::verify::<Test>(id).unwrap();
		assert_noop!(
			execute(acc(1), id, 500u128, commitment(1), memo_valid()),
			crate::pallet::Error::<Test>::AssetNotSupported
		);
	});
}

#[test]
fn execute_asset_not_verified_fails() {
	new_test_ext().execute_with(|| {
		let id = register_asset();

		assert_noop!(
			execute(acc(1), id, 500u128, commitment(1), memo_valid()),
			crate::pallet::Error::<Test>::AssetNotVerified
		);
	});
}

/// A zero commitment is refused even though zero is a canonical field value.
///
/// The tree represents an absent leaf with `[0u8; 32]`, so a stored zero is
/// indistinguishable from an empty slot when `subtree_root` rebuilds a pruned
/// level — and nobody can prove a preimage for it, so it would sit in the
/// tree forever as dead weight. The canonicity check alone lets it through;
/// this needs its own guard, which a dev-node probe caught missing.
#[test]
fn execute_zero_commitment_fails() {
	new_test_ext().execute_with(|| {
		let asset_id = setup_asset();
		let zero = Commitment::new([0u8; 32]);
		assert!(zero.is_canonical(), "zero is canonical — that is the trap");

		assert_noop!(
			execute(acc(1), asset_id, 500u128, zero, memo_valid()),
			crate::pallet::Error::<Test>::InvalidPublicSignals
		);
	});
}

/// The modular twin of a value must not be storable alongside it: both reduce
/// to the same field element, so accepting each would give one note two
/// identities in the tree and in the reverse index.
#[test]
fn execute_non_canonical_commitment_fails() {
	new_test_ext().execute_with(|| {
		let asset_id = setup_asset();

		let mut canonical = [0u8; 32];
		canonical[0] = 7;
		let twin = crate::tests::util::field_twin(canonical);

		assert_ok!(execute(
			acc(1),
			asset_id,
			500u128,
			Commitment::new(canonical),
			memo_valid(),
		));
		assert_noop!(
			execute(
				acc(1),
				asset_id,
				500u128,
				Commitment::new(twin),
				memo_valid()
			),
			crate::pallet::Error::<Test>::InvalidPublicSignals
		);
	});
}

#[test]
fn execute_zero_amount_fails() {
	new_test_ext().execute_with(|| {
		let asset_id = setup_asset();
		assert_noop!(
			execute(acc(1), asset_id, 0u128, commitment(1), memo_valid()),
			crate::pallet::Error::<Test>::InvalidAmount
		);
	});
}

/// There is no minimum: a 1-unit shield is accepted.
#[test]
fn execute_accepts_smallest_non_zero_amount() {
	new_test_ext().execute_with(|| {
		let asset_id = setup_asset();
		assert_ok!(execute(
			acc(1),
			asset_id,
			1u128,
			commitment(1),
			memo_valid(),
		));
	});
}

#[test]
fn execute_invalid_memo_size_fails() {
	new_test_ext().execute_with(|| {
		let asset_id = setup_asset();
		assert_noop!(
			execute(acc(1), asset_id, 500u128, commitment(1), short_memo()),
			crate::pallet::Error::<Test>::InvalidMemoSize
		);
	});
}

#[test]
fn execute_increases_pool_balance() {
	new_test_ext().execute_with(|| {
		let asset_id = setup_asset();
		let before = PoolBalanceRepository::get_asset_balance::<Test>(asset_id);
		assert_ok!(execute(
			acc(1),
			asset_id,
			500u128,
			commitment(0x02),
			memo_valid(),
		));
		let after = PoolBalanceRepository::get_asset_balance::<Test>(asset_id);
		assert_eq!(after - before, 500u128);
	});
}

#[test]
fn execute_stores_commitment_memo() {
	new_test_ext().execute_with(|| {
		let asset_id = setup_asset();
		let c = commitment(0x03);
		assert_ok!(execute(acc(1), asset_id, 200u128, c, memo_valid(),));
		assert!(CommitmentRepository::exists::<Test>(&c));
	});
}

#[test]
fn execute_emits_shielded_event() {
	new_test_ext().execute_with(|| {
		let asset_id = setup_asset();
		let c = commitment(0x04);
		assert_ok!(execute(acc(1), asset_id, 300u128, c, memo_valid(),));
		let events = frame_system::Pallet::<Test>::events();
		let found = events.iter().any(|r| {
			matches!(
				r.event,
				crate::tests::mock::RuntimeEvent::ShieldedPool(PalletEvent::Shielded {
					depositor: ref ed,
					amount: 300,
					commitment: ec,
					..
				}) if ec == c && *ed == acc(1)
			)
		});
		assert!(found, "Shielded event not emitted");
	});
}

#[test]
fn execute_transfers_currency_to_pool() {
	new_test_ext().execute_with(|| {
		let asset_id = setup_asset();
		let sender = acc(1);
		let pool = crate::Pallet::<Test>::pool_account_id();
		let balance_before = <pallet_balances::Pallet<Test> as frame_support::traits::Currency<
			AccountId32,
		>>::free_balance(&sender);

		assert_ok!(execute(
			sender.clone(),
			asset_id,
			1_000u128,
			commitment(0x05),
			memo_valid(),
		));

		let balance_after = <pallet_balances::Pallet<Test> as frame_support::traits::Currency<
			AccountId32,
		>>::free_balance(&sender);
		let pool_balance = <pallet_balances::Pallet<Test> as frame_support::traits::Currency<
			AccountId32,
		>>::free_balance(&pool);

		assert_eq!(balance_before - balance_after, 1_000u128);
		assert_eq!(pool_balance, 1_000u128);
	});
}

// ── query helpers ────────────────────────────────────────────────────────

#[test]
fn commitment_exists_false_before_shield() {
	new_test_ext().execute_with(|| {
		assert!(!ShieldOperation::commitment_exists::<Test>(&commitment(
			0xAA
		)));
	});
}

#[test]
fn commitment_exists_true_after_shield() {
	new_test_ext().execute_with(|| {
		let asset_id = setup_asset();
		let c = commitment(0xBB);
		assert_ok!(execute(acc(1), asset_id, 200u128, c, memo_valid(),));
		assert!(ShieldOperation::commitment_exists::<Test>(&c));
	});
}

#[test]
fn asset_exists_returns_correct_values() {
	new_test_ext().execute_with(|| {
		let id = setup_asset();
		assert!(ShieldOperation::asset_exists::<Test>(id));
		assert!(!ShieldOperation::asset_exists::<Test>(99u32));
	});
}

#[test]
fn is_asset_verified_returns_correct_values() {
	new_test_ext().execute_with(|| {
		let id = setup_asset();
		assert!(ShieldOperation::is_asset_verified::<Test>(id));
		// Unverified asset
		let name = frame_support::BoundedVec::try_from(b"Other".to_vec()).unwrap();
		let sym = frame_support::BoundedVec::try_from(b"OTH".to_vec()).unwrap();
		let id2 = AssetOperation::register_asset::<Test>(name, sym, 6, None, acc(2)).unwrap();
		assert!(!ShieldOperation::is_asset_verified::<Test>(id2));
	});
}

#[test]
fn execute_duplicate_commitment_fails() {
	// A second shield call with the same commitment bytes must be rejected to prevent
	// Merkle-tree spam: an attacker could flood the tree with duplicate leaves,
	// consuming tree capacity while the associated notes remain unspendable (a single
	// nullifier can only be used once).
	new_test_ext().execute_with(|| {
		let asset_id = setup_asset();
		let c = commitment(0xDE);

		assert_ok!(execute(acc(1), asset_id, 500u128, c, memo_valid(),));

		assert_noop!(
			execute(acc(1), asset_id, 500u128, c, memo_valid()),
			crate::pallet::Error::<Test>::CommitmentAlreadyExists
		);
	});
}

// ── proof ────────────────────────────────────────────────────────────────

/// The verifier is asked about the deposit as the call states it: the
/// inserted commitment, the amount actually transferred and its asset.
#[cfg(not(feature = "skip-proof-verification"))]
#[test]
fn the_proof_is_checked_against_the_deposited_amount_and_asset() {
	use crate::tests::mock::{VerifiedStatement, verified_statements};
	new_test_ext().execute_with(|| {
		let asset_id = setup_asset();
		let c = commitment(0x07);
		assert_ok!(execute(acc(1), asset_id, 750u128, c, memo_valid()));
		assert_eq!(
			verified_statements(),
			vec![VerifiedStatement::Shield(
				ShieldStatement {
					commitment: c.0,
					value: 750,
					asset_id
				},
				Some(1),
			)]
		);
	});
}

/// A commitment worth more than the deposit fails the proof, and nothing moves:
/// no transfer, no leaf, no ledger credit.
#[cfg(not(feature = "skip-proof-verification"))]
#[test]
fn an_invalid_proof_moves_no_funds() {
	use crate::tests::mock::set_mock_proof_valid;
	new_test_ext().execute_with(|| {
		let asset_id = setup_asset();
		set_mock_proof_valid(false);
		assert_noop!(
			execute(acc(1), asset_id, 1u128, commitment(0x08), memo_valid()),
			crate::pallet::Error::<Test>::ProofVerificationFailed
		);
	});
}

#[cfg(not(feature = "skip-proof-verification"))]
#[test]
fn an_empty_proof_is_rejected() {
	new_test_ext().execute_with(|| {
		let asset_id = setup_asset();
		assert!(
			ShieldOperation::execute::<Test>(
				acc(1),
				&[],
				request(asset_id, 500u128, commitment(0x09), memo_valid()),
			)
			.is_err()
		);
		assert!(!CommitmentRepository::exists::<Test>(&commitment(0x09)));
	});
}

/// Each batch entry is proved on its own: its commitment, amount, asset and
/// version, in order.
#[cfg(not(feature = "skip-proof-verification"))]
#[test]
fn shield_batch_checks_each_entry_against_its_own_deposit() {
	use crate::tests::mock::{RuntimeOrigin, ShieldedPool, VerifiedStatement, verified_statements};
	new_test_ext().execute_with(|| {
		let asset_id = setup_asset();
		let entry = |c: u8, amount: u128, version: u32| {
			(
				asset_id,
				amount,
				commitment(c),
				memo_valid(),
				frame_support::BoundedVec::try_from(vec![0x01; 128]).unwrap(),
				version,
			)
		};
		let batch =
			frame_support::BoundedVec::try_from(vec![entry(0x0C, 100, 1), entry(0x0D, 250, 2)])
				.unwrap();
		assert_ok!(ShieldedPool::shield_batch(
			RuntimeOrigin::signed(acc(1)),
			batch
		));
		let deposit = |c: u8, value: u128, version: u32| {
			VerifiedStatement::Shield(
				ShieldStatement {
					commitment: commitment(c).0,
					value,
					asset_id,
				},
				Some(version),
			)
		};
		assert_eq!(
			verified_statements(),
			vec![deposit(0x0C, 100, 1), deposit(0x0D, 250, 2)]
		);
	});
}

/// One unprovable entry reverts the whole batch, the valid ones included.
#[cfg(not(feature = "skip-proof-verification"))]
#[test]
fn shield_batch_with_one_bad_proof_reverts_everything() {
	use crate::tests::mock::{RuntimeOrigin, ShieldedPool};
	new_test_ext().execute_with(|| {
		let asset_id = setup_asset();
		let entry = |c: u8, proof: &[u8]| {
			(
				asset_id,
				500u128,
				commitment(c),
				memo_valid(),
				frame_support::BoundedVec::try_from(proof.to_vec()).unwrap(),
				1u32,
			)
		};
		let batch =
			frame_support::BoundedVec::try_from(vec![entry(0x0A, &[0x01; 128]), entry(0x0B, &[])])
				.unwrap();
		assert!(ShieldedPool::shield_batch(RuntimeOrigin::signed(acc(1)), batch).is_err());
		assert!(!CommitmentRepository::exists::<Test>(&commitment(0x0A)));
		assert_eq!(
			PoolBalanceRepository::get_asset_balance::<Test>(asset_id),
			0
		);
	});
}

// ── batch guard ──────────────────────────────────────────────────────────

/// An empty `shield_batch` is rejected instead of dispatching at zero weight.
#[test]
fn shield_batch_empty_fails() {
	use crate::tests::mock::{RuntimeOrigin, ShieldedPool};
	new_test_ext().execute_with(|| {
		let empty = frame_support::BoundedVec::default();
		assert_noop!(
			ShieldedPool::shield_batch(RuntimeOrigin::signed(acc(1)), empty),
			crate::pallet::Error::<Test>::EmptyBatch
		);
	});
}

/// The benchmarked `shield_batch(n)` weight has a non-zero base and scales
/// with n (guards against the old ad-hoc `shield()*n*0.8` that hit zero at n=0).
#[test]
fn shield_batch_weight_has_base_and_scales() {
	use crate::weights::WeightInfo;
	let zero = <() as WeightInfo>::shield_batch(0);
	let one = <() as WeightInfo>::shield_batch(1);
	assert!(
		zero.ref_time() > 0,
		"empty batch must still carry a base weight"
	);
	assert!(one.ref_time() > zero.ref_time(), "weight must scale with n");
}
