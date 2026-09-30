//! `UnshieldOperation`: validation, settlement, the ledger and relay-fee routing.

use super::{
	KNOWN_ROOT, canonical_bytes, commit, evm, fund_pool, memo, nullifier, proof, register_asset,
	setup_asset,
};
use crate::{
	mock::{System, Test, acc, new_test_ext},
	operations::{assets::AssetOperation, unshield::*},
	pallet::{Error, Event as PalletEvent},
	storage::{MerkleRepository, NullifierRepository, PoolBalanceRepository},
	types::{Commitment, EncryptedMemo},
};
use frame_support::{assert_err, assert_noop, assert_ok, traits::Currency};
use sp_runtime::AccountId32;

// ── execute ──────────────────────────────────────────────────────────────────

#[test]
fn execute_works() {
	new_test_ext().execute_with(|| {
		let asset_id = setup_asset();
		let amount = 500u128;
		let fee = 0u128;
		fund_pool(asset_id, amount + fee);
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);

		assert_ok!(UnshieldOperation::execute::<Test>(
			&proof(),
			UnshieldRequest {
				merkle_root: KNOWN_ROOT,
				nullifier: nullifier(0x01),
				asset_id,
				amount,
				recipient: acc(2), // recipient
				fee: 0u128,
				change_commitment: [0u8; 32],
				change_memo: EncryptedMemo::default(),
				circuit_version: 1,
			},
		));
	});
}

#[test]
fn execute_invalid_asset_fails() {
	new_test_ext().execute_with(|| {
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
		// Solvency is checked first; fund the ledger so the asset check is reached.
		fund_pool(99, 1_000u128);
		assert_noop!(
			UnshieldOperation::execute::<Test>(
				&proof(),
				UnshieldRequest {
					merkle_root: KNOWN_ROOT,
					nullifier: nullifier(1),
					asset_id: 99u32,
					amount: 100u128,
					recipient: acc(2),
					fee: 0u128,
					change_commitment: [0u8; 32],
					change_memo: EncryptedMemo::default(),
					circuit_version: 1,
				},
			),
			Error::<Test>::InvalidAssetId
		);
	});
}

#[test]
fn execute_asset_not_verified_fails() {
	new_test_ext().execute_with(|| {
		let id = register_asset();
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
		fund_pool(id, 1_000u128);

		assert_noop!(
			UnshieldOperation::execute::<Test>(
				&proof(),
				UnshieldRequest {
					merkle_root: KNOWN_ROOT,
					nullifier: nullifier(1),
					asset_id: id,
					amount: 100u128,
					recipient: acc(2),
					fee: 0u128,
					change_commitment: [0u8; 32],
					change_memo: EncryptedMemo::default(),
					circuit_version: 1,
				},
			),
			Error::<Test>::AssetNotVerified
		);
	});
}

#[test]
fn execute_zero_amount_fails() {
	// amount == 0 must be rejected before any ZK check so that benchmark mode
	// (which skips the verifier) cannot mark a nullifier as spent without moving
	// any funds.
	new_test_ext().execute_with(|| {
		let asset_id = setup_asset();
		fund_pool(asset_id, 1_000u128);
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);

		assert_noop!(
			UnshieldOperation::execute::<Test>(
				&proof(),
				UnshieldRequest {
					merkle_root: KNOWN_ROOT,
					nullifier: nullifier(0x77),
					asset_id,
					amount: 0u128,
					recipient: acc(2),
					fee: 0u128,
					change_commitment: [0u8; 32],
					change_memo: EncryptedMemo::default(),
					circuit_version: 1,
				},
			),
			Error::<Test>::InvalidAmount
		);
	});
}

#[test]
fn execute_invalid_recipient_pool_account_fails() {
	new_test_ext().execute_with(|| {
		let asset_id = setup_asset();
		fund_pool(asset_id, 1_000u128);
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);

		let pool = crate::Pallet::<Test>::pool_account_id();
		assert_noop!(
			UnshieldOperation::execute::<Test>(
				&proof(),
				UnshieldRequest {
					merkle_root: KNOWN_ROOT,
					nullifier: nullifier(1),
					asset_id,
					amount: 100u128,
					recipient: pool, // recipient == pool → rejected
					fee: 0u128,
					change_commitment: [0u8; 32],
					change_memo: EncryptedMemo::default(),
					circuit_version: 1,
				},
			),
			Error::<Test>::InvalidRecipient
		);
	});
}

#[test]
fn execute_unknown_root_fails() {
	new_test_ext().execute_with(|| {
		let asset_id = setup_asset();
		fund_pool(asset_id, 1_000u128);
		// Root never added

		assert_noop!(
			UnshieldOperation::execute::<Test>(
				&proof(),
				UnshieldRequest {
					merkle_root: [0xBBu8; 32],
					nullifier: nullifier(1),
					asset_id,
					amount: 100u128,
					recipient: acc(2),
					fee: 0u128,
					change_commitment: [0u8; 32],
					change_memo: EncryptedMemo::default(),
					circuit_version: 1,
				},
			),
			Error::<Test>::UnknownMerkleRoot
		);
	});
}

#[test]
fn execute_nullifier_already_used_fails() {
	new_test_ext().execute_with(|| {
		let asset_id = setup_asset();
		fund_pool(asset_id, 2_000u128);
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);

		let n = nullifier(0x02);
		NullifierRepository::mark_as_used::<Test>(n, 1u64);

		assert_noop!(
			UnshieldOperation::execute::<Test>(
				&proof(),
				UnshieldRequest {
					merkle_root: KNOWN_ROOT,
					nullifier: n,
					asset_id,
					amount: 500u128,
					recipient: acc(2),
					fee: 0u128,
					change_commitment: [0u8; 32],
					change_memo: EncryptedMemo::default(),
					circuit_version: 1,
				},
			),
			Error::<Test>::NullifierAlreadyUsed
		);
	});
}

#[test]
fn execute_insufficient_pool_balance_fails() {
	new_test_ext().execute_with(|| {
		let asset_id = setup_asset();
		// Pool has 50 but we want 100 + 0 = 100
		fund_pool(asset_id, 50u128);
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);

		assert_noop!(
			UnshieldOperation::execute::<Test>(
				&proof(),
				UnshieldRequest {
					merkle_root: KNOWN_ROOT,
					nullifier: nullifier(1),
					asset_id,
					amount: 100u128,
					recipient: acc(2),
					fee: 0u128,
					change_commitment: [0u8; 32],
					change_memo: EncryptedMemo::default(),
					circuit_version: 1,
				},
			),
			Error::<Test>::InsufficientPoolBalance
		);
	});
}

#[test]
fn execute_marks_nullifier_used() {
	new_test_ext().execute_with(|| {
		let asset_id = setup_asset();
		let n = nullifier(0x05);
		fund_pool(asset_id, 1_000u128);
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);

		assert!(!NullifierRepository::is_used::<Test>(&n));
		assert_ok!(UnshieldOperation::execute::<Test>(
			&proof(),
			UnshieldRequest {
				merkle_root: KNOWN_ROOT,
				nullifier: n,
				asset_id,
				amount: 300u128,
				recipient: acc(2),
				fee: 0u128,
				change_commitment: [0u8; 32],
				change_memo: EncryptedMemo::default(),
				circuit_version: 1,
			},
		));
		assert!(NullifierRepository::is_used::<Test>(&n));
	});
}

#[test]
fn execute_decreases_pool_balance() {
	new_test_ext().execute_with(|| {
		let asset_id = setup_asset();
		let amount = 400u128;
		fund_pool(asset_id, 1_000u128);
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);

		assert_ok!(UnshieldOperation::execute::<Test>(
			&proof(),
			UnshieldRequest {
				merkle_root: KNOWN_ROOT,
				nullifier: nullifier(0x06),
				asset_id,
				amount,
				recipient: acc(2),
				fee: 0u128,
				change_commitment: [0u8; 32],
				change_memo: EncryptedMemo::default(),
				circuit_version: 1,
			},
		));

		let remaining = PoolBalanceRepository::get_asset_balance::<Test>(asset_id);
		assert_eq!(remaining, 1_000u128 - amount);
	});
}

#[test]
fn execute_transfers_currency_to_recipient() {
	new_test_ext().execute_with(|| {
		let asset_id = setup_asset();
		let recipient = acc(2);
		let amount = 300u128;
		fund_pool(asset_id, 1_000u128);
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);

		let before =
			<pallet_balances::Pallet<Test> as Currency<AccountId32>>::free_balance(&recipient);

		assert_ok!(UnshieldOperation::execute::<Test>(
			&proof(),
			UnshieldRequest {
				merkle_root: KNOWN_ROOT,
				nullifier: nullifier(0x07),
				asset_id,
				amount,
				recipient: recipient.clone(),
				fee: 0u128,
				change_commitment: [0u8; 32],
				change_memo: EncryptedMemo::default(),
				circuit_version: 1,
			},
		));

		let after =
			<pallet_balances::Pallet<Test> as Currency<AccountId32>>::free_balance(&recipient);
		assert_eq!(after - before, amount);
	});
}

#[test]
fn execute_emits_unshielded_event() {
	new_test_ext().execute_with(|| {
		let asset_id = setup_asset();
		let n = nullifier(0x08);
		fund_pool(asset_id, 1_000u128);
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);

		assert_ok!(UnshieldOperation::execute::<Test>(
			&proof(),
			UnshieldRequest {
				merkle_root: KNOWN_ROOT,
				nullifier: n,
				asset_id,
				amount: 200u128,
				recipient: acc(2),
				fee: 0u128,
				change_commitment: [0u8; 32],
				change_memo: EncryptedMemo::default(),
				circuit_version: 1,
			},
		));

		let events = frame_system::Pallet::<Test>::events();
		let found = events.iter().any(|r| {
			matches!(
				r.event,
				crate::mock::RuntimeEvent::ShieldedPool(PalletEvent::Unshielded {
					nullifier: en,
					amount: 200,
					recipient: ref er,
					change_commitment: None,
					change_encrypted_memo: None,
					change_leaf_index: None,
				}) if en == n && *er == acc(2)
			)
		});
		assert!(found, "Unshielded event not emitted");
	});
}

#[test]
fn execute_accumulates_relay_fee_to_block_author() {
	new_test_ext().execute_with(|| {
		let asset_id = setup_asset();
		let amount = 500u128;
		let fee = 50u128;
		fund_pool(asset_id, amount + fee);
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);

		assert_ok!(UnshieldOperation::execute::<Test>(
			&proof(),
			UnshieldRequest {
				merkle_root: KNOWN_ROOT,
				nullifier: nullifier(0x09),
				asset_id,
				amount,
				recipient: acc(2),
				fee,
				change_commitment: [0u8; 32],
				change_memo: EncryptedMemo::default(),
				circuit_version: 1,
			},
		));

		// MockRelayer block_author returns Some(1); fee should be accumulated there
		let pending = crate::mock::mock_pending_fees_get(acc(1), asset_id);
		assert_eq!(pending, fee);
	});
}

// ── partial unshield ─────────────────────────────────────────────────────────

#[test]
fn execute_partial_unshield_creates_change_note() {
	new_test_ext().execute_with(|| {
		let asset_id = setup_asset();
		// Fund pool with the full note value (amount + change_value).
		fund_pool(asset_id, 1_000u128);
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);

		let change_comm_bytes = canonical_bytes(0xCC);
		let amount = 600u128;

		assert_ok!(UnshieldOperation::execute::<Test>(
			&proof(),
			UnshieldRequest {
				merkle_root: KNOWN_ROOT,
				nullifier: nullifier(0x10),
				asset_id,
				amount,
				recipient: acc(2),
				fee: 0u128,
				change_commitment: change_comm_bytes,
				change_memo: change_memo(),
				circuit_version: 1,
			},
		));

		// The change commitment must now exist as a leaf in the Merkle tree.
		assert_eq!(
			MerkleRepository::get_tree_size::<Test>(),
			1,
			"change commitment should have been inserted as a Merkle leaf"
		);
		assert!(
			MerkleRepository::find_leaf_index::<Test>(&Commitment::new(change_comm_bytes))
				.is_some(),
			"change commitment not found in Merkle tree leaves"
		);

		// Pool balance must have decreased only by `amount`, not by the full note value.
		let pool_bal = PoolBalanceRepository::get_asset_balance::<Test>(asset_id);
		assert_eq!(
			pool_bal,
			1_000u128 - amount,
			"pool balance should only decrease by amount"
		);

		// Event must carry the change_commitment.
		let events = frame_system::Pallet::<Test>::events();
		let found = events.iter().any(|r| {
			matches!(
				&r.event,
				crate::mock::RuntimeEvent::ShieldedPool(PalletEvent::Unshielded {
					change_commitment: Some(cc),
					..
				}) if cc == &change_comm_bytes
			)
		});
		assert!(found, "Unshielded event did not carry change_commitment");
	});
}

#[test]
fn execute_total_unshield_with_zero_change_works() {
	new_test_ext().execute_with(|| {
		let asset_id = setup_asset();
		let amount = 800u128;
		fund_pool(asset_id, amount);
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);

		assert_ok!(UnshieldOperation::execute::<Test>(
			&proof(),
			UnshieldRequest {
				merkle_root: KNOWN_ROOT,
				nullifier: nullifier(0x11),
				asset_id,
				amount,
				recipient: acc(2),
				fee: 0u128,
				change_commitment: [0u8; 32], // zero change_commitment = total unshield
				change_memo: EncryptedMemo::default(),
				circuit_version: 1,
			},
		));

		// Pool balance must be zero.
		let pool_bal = PoolBalanceRepository::get_asset_balance::<Test>(asset_id);
		assert_eq!(pool_bal, 0u128, "pool balance should be fully drained");

		// No change commitment in tree (tree size remains 0 since no insert happened).
		assert_eq!(
			MerkleRepository::get_tree_size::<Test>(),
			0,
			"tree should have no leaves for total unshield"
		);

		// Event carries change_commitment: None.
		let events = frame_system::Pallet::<Test>::events();
		let found = events.iter().any(|r| {
			matches!(
				r.event,
				crate::mock::RuntimeEvent::ShieldedPool(PalletEvent::Unshielded {
					change_commitment: None,
					..
				})
			)
		});
		assert!(
			found,
			"Unshielded event should have change_commitment: None"
		);
	});
}

#[test]
fn execute_change_commitment_duplicate_fails() {
	new_test_ext().execute_with(|| {
		let asset_id = setup_asset();
		fund_pool(asset_id, 2_000u128);
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);

		let change_comm_bytes = canonical_bytes(0xDD);
		let change_comm = Commitment::new(change_comm_bytes);

		// Put the commitment in the tree, with no memo: it still exists.
		crate::merkle::MerkleTreeService::insert_leaf::<Test>(change_comm).unwrap();

		// Attempting to reuse the same commitment as a change note must fail.
		assert_noop!(
			UnshieldOperation::execute::<Test>(
				&proof(),
				UnshieldRequest {
					merkle_root: KNOWN_ROOT,
					nullifier: nullifier(0x12),
					asset_id,
					amount: 500u128,
					recipient: acc(2),
					fee: 0u128,
					change_commitment: change_comm_bytes,
					change_memo: memo(0x01),
					circuit_version: 1,
				},
			),
			Error::<Test>::CommitmentAlreadyExists
		);
	});
}

// ── query helpers ────────────────────────────────────────────────────────────

#[test]
fn is_nullifier_used_false_by_default() {
	new_test_ext().execute_with(|| {
		assert!(!NullifierRepository::is_used::<Test>(&nullifier(0xCC)));
	});
}

#[test]
fn is_merkle_root_known_returns_correct_values() {
	new_test_ext().execute_with(|| {
		assert!(!MerkleRepository::is_known_root::<Test>(&KNOWN_ROOT));
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
		assert!(MerkleRepository::is_known_root::<Test>(&KNOWN_ROOT));
	});
}

// ── ledger-solvency invariant ────────────────────────────────────────────────
// PoolBalancePerAsset[a] == Currency::free_balance(pool) for the native asset.
// A spend's fee stays in the pool until the relayer claims it, so the tracked
// and physical balances always move together.

fn pool_physical() -> u128 {
	<pallet_balances::Pallet<Test> as Currency<AccountId32>>::free_balance(
		&crate::Pallet::<Test>::pool_account_id(),
	)
}

fn tracked(asset_id: u32) -> u128 {
	PoolBalanceRepository::get_asset_balance::<Test>(asset_id)
}

/// Unshield with a fee decrements the ledger by `amount` only (the fee
/// stays physical as backing), and ledger == physical afterwards.
#[test]
fn unshield_with_fee_decrements_amount_only() {
	new_test_ext().execute_with(|| {
		let asset_id = setup_asset();
		let (amount, fee) = (500u128, 50u128);
		fund_pool(asset_id, amount + fee);
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);

		assert_ok!(UnshieldOperation::execute::<Test>(
			&proof(),
			UnshieldRequest {
				merkle_root: KNOWN_ROOT,
				nullifier: nullifier(0x21),
				asset_id,
				amount,
				recipient: acc(2),
				fee,
				change_commitment: [0u8; 32],
				change_memo: EncryptedMemo::default(),
				circuit_version: 1,
			},
		));

		// Only `amount` left the pool; `fee` stays as backing for pending fees.
		assert_eq!(tracked(asset_id), fee);
		assert_eq!(pool_physical(), fee);
		assert_eq!(tracked(asset_id), pool_physical());
		assert_eq!(crate::mock::mock_pending_fees_get(acc(1), asset_id), fee);
	});
}

/// The guard requires `>= amount + fee`: a pool covering only `amount`
/// (fee unbacked) must be rejected; covering `amount + fee` must succeed.
#[test]
fn unshield_guard_requires_amount_plus_fee() {
	new_test_ext().execute_with(|| {
		let asset_id = setup_asset();
		let (amount, fee) = (500u128, 50u128);
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);

		// Pool covers only `amount` → rejected.
		fund_pool(asset_id, amount);
		assert_noop!(
			UnshieldOperation::execute::<Test>(
				&proof(),
				UnshieldRequest {
					merkle_root: KNOWN_ROOT,
					nullifier: nullifier(0x22),
					asset_id,
					amount,
					recipient: acc(2),
					fee,
					change_commitment: [0u8; 32],
					change_memo: EncryptedMemo::default(),
					circuit_version: 1,
				},
			),
			Error::<Test>::InsufficientPoolBalance
		);

		// Pool covers `amount + fee` → accepted.
		fund_pool(asset_id, amount + fee);
		assert_ok!(UnshieldOperation::execute::<Test>(
			&proof(),
			UnshieldRequest {
				merkle_root: KNOWN_ROOT,
				nullifier: nullifier(0x23),
				asset_id,
				amount,
				recipient: acc(2),
				fee,
				change_commitment: [0u8; 32],
				change_memo: EncryptedMemo::default(),
				circuit_version: 1,
			},
		));
	});
}

/// The full fee lifecycle keeps ledger == physical at every step:
/// shield → unshield(with fee) → claim_relay_fees (fee paid out publicly).
#[test]
fn fee_lifecycle_preserves_ledger_invariant() {
	use crate::operations::{fees::FeeOperation, shield::ShieldOperation};

	new_test_ext().execute_with(|| {
		let asset_id = setup_asset();
		let depositor = acc(7);
		// Fund above the shield amount so KeepAlive leaves the ED intact.
		let _ = <pallet_balances::Pallet<Test> as Currency<AccountId32>>::deposit_creating(
			&depositor, 2000,
		);
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);

		// Step 1: shield 1000. Ledger and physical both +1000.
		assert_ok!(ShieldOperation::execute::<Test>(
			depositor,
			asset_id,
			1000u128,
			Commitment::new(canonical_bytes(0x31)),
			memo(0x00),
		));
		assert_eq!(tracked(asset_id), pool_physical());
		assert_eq!(tracked(asset_id), 1000);

		// Step 2: unshield amount=700 fee=50. Only `amount` leaves; fee stays.
		assert_ok!(UnshieldOperation::execute::<Test>(
			&proof(),
			UnshieldRequest {
				merkle_root: KNOWN_ROOT,
				nullifier: nullifier(0x32),
				asset_id,
				amount: 700u128,
				recipient: acc(2),
				fee: 50u128,
				change_commitment: [0u8; 32],
				change_memo: EncryptedMemo::default(),
				circuit_version: 1,
			},
		));
		assert_eq!(tracked(asset_id), 300);
		assert_eq!(tracked(asset_id), pool_physical());
		assert_eq!(crate::mock::mock_pending_fees_get(acc(1), asset_id), 50);

		// Step 3: claim the 50 fee publicly. Ledger and physical both −50.
		assert_ok!(FeeOperation::claim::<Test>(
			acc(1),
			acc(3),
			asset_id,
			50u128
		));
		assert_eq!(tracked(asset_id), 250);
		assert_eq!(tracked(asset_id), pool_physical());
		assert_eq!(crate::mock::mock_pending_fees_get(acc(1), asset_id), 0);
	});
}

// ── relay-fee attribution (relay commits) ────────────────────────────────────
// The fee follows the relay commit, never the submitter: a copy of a spend
// submitted by anyone still credits the relayer that committed to it.

fn block_author() -> sp_runtime::AccountId32 {
	acc(1)
}

const AMOUNT: u128 = 500;
const FEE: u128 = 50;

fn spend_hash(seed: u8, asset_id: u32) -> [u8; 32] {
	UnshieldRequest::<Test> {
		merkle_root: KNOWN_ROOT,
		nullifier: nullifier(seed),
		asset_id,
		amount: AMOUNT,
		recipient: acc(2),
		fee: FEE,
		change_commitment: [0u8; 32],
		change_memo: EncryptedMemo::default(),
		circuit_version: 1,
	}
	.op_hash()
	.unwrap()
}

fn unshield_call(seed: u8, asset_id: u32) -> crate::Call<Test> {
	crate::Call::<Test>::unshield {
		proof: proof(),
		merkle_root: KNOWN_ROOT,
		nullifier: nullifier(seed),
		asset_id,
		amount: AMOUNT,
		recipient: acc(2),
		fee: FEE,
		change_commitment: [0u8; 32],
		change_encrypted_memo: EncryptedMemo::default(),
		circuit_version: 1,
	}
}

fn setup_spend() -> u32 {
	let asset_id = setup_asset();
	fund_pool(asset_id, AMOUNT + FEE);
	MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
	asset_id
}

/// The relayer that committed in an earlier block receives the fee.
#[test]
fn unshield_fee_lands_at_the_committed_relayer() {
	new_test_ext().execute_with(|| {
		let asset_id = setup_spend();
		crate::mock::mock_register_relayer(acc(7), evm(0xAA));
		commit(evm(0xAA), &spend_hash(0x51, asset_id));
		System::set_block_number(2);

		assert_ok!(UnshieldOperation::execute::<Test>(
			&proof(),
			UnshieldRequest {
				merkle_root: KNOWN_ROOT,
				nullifier: nullifier(0x51),
				asset_id,
				amount: AMOUNT,
				recipient: acc(2),
				fee: FEE,
				change_commitment: [0u8; 32],
				change_memo: EncryptedMemo::default(),
				circuit_version: 1,
			},
		));

		assert_eq!(crate::mock::mock_pending_fees_get(acc(7), asset_id), FEE);
		assert_eq!(
			crate::mock::mock_pending_fees_get(block_author(), asset_id),
			0
		);
	});
}

/// Another relayer copies the spend and submits it under its own key:
/// the fee still goes to the relayer that committed.
#[test]
fn a_copied_spend_still_credits_the_committed_relayer() {
	use frame_support::traits::UnfilteredDispatchable;
	new_test_ext().execute_with(|| {
		let asset_id = setup_spend();
		crate::mock::mock_register_relayer(acc(7), evm(0xAA));
		crate::mock::mock_register_relayer(acc(8), evm(0xBB));
		commit(evm(0xAA), &spend_hash(0x52, asset_id));
		System::set_block_number(2);

		assert_ok!(
			unshield_call(0x52, asset_id)
				.dispatch_bypass_filter(crate::RawOrigin::Relayed(evm(0xBB)).into())
		);

		assert_eq!(crate::mock::mock_pending_fees_get(acc(7), asset_id), FEE);
		assert_eq!(crate::mock::mock_pending_fees_get(acc(8), asset_id), 0);
	});
}

/// A commit placed in the same block as the spend is ignored, so an
/// author cannot commit after seeing a spend and include both.
#[test]
fn a_same_block_commit_does_not_capture_the_fee() {
	use frame_support::traits::UnfilteredDispatchable;
	new_test_ext().execute_with(|| {
		let asset_id = setup_spend();
		crate::mock::mock_register_relayer(acc(8), evm(0xBB));
		commit(evm(0xBB), &spend_hash(0x53, asset_id));

		assert_ok!(
			unshield_call(0x53, asset_id)
				.dispatch_bypass_filter(crate::RawOrigin::Relayed(evm(0xBB)).into())
		);

		assert_eq!(crate::mock::mock_pending_fees_get(acc(8), asset_id), 0);
		assert_eq!(
			crate::mock::mock_pending_fees_get(block_author(), asset_id),
			FEE
		);
	});
}

/// With no commit, the fee goes to the block author, whoever submits.
#[test]
fn an_uncommitted_spend_pays_the_block_author() {
	use frame_support::traits::UnfilteredDispatchable;
	new_test_ext().execute_with(|| {
		let asset_id = setup_spend();
		crate::mock::mock_register_relayer(acc(8), evm(0xBB));

		assert_ok!(
			unshield_call(0x54, asset_id)
				.dispatch_bypass_filter(crate::RawOrigin::Relayed(evm(0xBB)).into())
		);

		assert_eq!(crate::mock::mock_pending_fees_get(acc(8), asset_id), 0);
		assert_eq!(
			crate::mock::mock_pending_fees_get(block_author(), asset_id),
			FEE
		);
	});
}

/// A commit covers one exact spend: a different spend of the same note
/// (here, another fee) is not credited to it.
#[test]
fn a_commit_does_not_cover_a_different_spend_of_the_same_note() {
	new_test_ext().execute_with(|| {
		let asset_id = setup_spend();
		crate::mock::mock_register_relayer(acc(7), evm(0xAA));
		commit(evm(0xAA), &spend_hash(0x55, asset_id));
		System::set_block_number(2);

		assert_ok!(UnshieldOperation::execute::<Test>(
			&proof(),
			UnshieldRequest {
				merkle_root: KNOWN_ROOT,
				nullifier: nullifier(0x55),
				asset_id,
				amount: AMOUNT - 10,
				recipient: acc(2),
				fee: FEE + 10,
				change_commitment: [0u8; 32],
				change_memo: EncryptedMemo::default(),
				circuit_version: 1,
			},
		));

		assert_eq!(crate::mock::mock_pending_fees_get(acc(7), asset_id), 0);
	});
}

/// A non-zero fee with no resolvable recipient (no relayer, no block author)
/// errors instead of stranding the fee tokens in the pool.
#[test]
fn unshield_nonzero_fee_without_recipient_errors() {
	new_test_ext().execute_with(|| {
		let asset_id = setup_asset();
		let (amount, fee) = (500u128, 50u128);
		fund_pool(asset_id, amount + fee);
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
		crate::mock::mock_clear_block_author();

		// assert_err (not assert_noop): the fee attribution runs after currency
		// effects; in a real extrinsic the dispatch rolls those back on Err. Here
		// we assert the error itself — the transactional rollback is Substrate's.
		assert_err!(
			UnshieldOperation::execute::<Test>(
				&proof(),
				UnshieldRequest {
					merkle_root: KNOWN_ROOT,
					nullifier: nullifier(0x60),
					asset_id,
					amount,
					recipient: acc(2),
					fee,
					change_commitment: [0u8; 32],
					change_memo: EncryptedMemo::default(),
					circuit_version: 1,
				},
			),
			Error::<Test>::FeeRecipientUnavailable
		);
	});
}

/// A zero fee with no recipient is fine — nothing to attribute.
#[test]
fn unshield_zero_fee_without_recipient_ok() {
	new_test_ext().execute_with(|| {
		let asset_id = setup_asset();
		let amount = 500u128;
		fund_pool(asset_id, amount);
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
		crate::mock::mock_clear_block_author();

		assert_ok!(UnshieldOperation::execute::<Test>(
			&proof(),
			UnshieldRequest {
				merkle_root: KNOWN_ROOT,
				nullifier: nullifier(0x61),
				asset_id,
				amount,
				recipient: acc(2),
				fee: 0u128,
				change_commitment: [0u8; 32],
				change_memo: EncryptedMemo::default(),
				circuit_version: 1,
			},
		));
	});
}

/// Unverifying an asset freezes existing notes too: an unshield of a
/// previously-verified asset fails once it is unverified (emergency kill-switch).
#[test]
fn unverifying_asset_freezes_existing_note_unshield() {
	new_test_ext().execute_with(|| {
		let asset_id = setup_asset(); // registered + verified
		fund_pool(asset_id, 1_000u128);
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);

		// Freeze the asset via governance.
		AssetOperation::unverify::<Test>(asset_id).unwrap();

		assert_noop!(
			UnshieldOperation::execute::<Test>(
				&proof(),
				UnshieldRequest {
					merkle_root: KNOWN_ROOT,
					nullifier: nullifier(0x70),
					asset_id,
					amount: 100u128,
					recipient: acc(2),
					fee: 0u128,
					change_commitment: [0u8; 32],
					change_memo: EncryptedMemo::default(),
					circuit_version: 1,
				},
			),
			Error::<Test>::AssetNotVerified
		);
	});
}

// ── the statement handed to the verifier ─────────────────────────────────────

fn request(seed: u8, asset_id: u32) -> UnshieldRequest<Test> {
	UnshieldRequest {
		merkle_root: KNOWN_ROOT,
		nullifier: nullifier(seed),
		asset_id,
		amount: AMOUNT,
		recipient: acc(2),
		fee: FEE,
		change_commitment: [0u8; 32],
		change_memo: EncryptedMemo::default(),
		circuit_version: 2,
	}
}

fn change_memo() -> EncryptedMemo {
	memo(0x5C)
}

#[test]
fn a_total_unshield_with_a_memo_is_rejected_before_verification() {
	new_test_ext().execute_with(|| {
		let asset_id = setup_spend();
		let req = UnshieldRequest {
			change_memo: change_memo(),
			..request(0x73, asset_id)
		};
		assert_noop!(
			UnshieldOperation::execute::<Test>(&proof(), req),
			Error::<Test>::InvalidMemoSize
		);
		assert!(crate::mock::verified_statements().is_empty());
	});
}

/// What reaches the verifier; nothing does under `skip-proof-verification`.
#[cfg(not(feature = "skip-proof-verification"))]
mod verified {
	use super::*;
	use crate::operations::statement::memo_digest;
	use pallet_zk_verifier::UnshieldStatement;

	fn verified_unshield() -> (UnshieldStatement, Option<u32>) {
		match crate::mock::verified_statements().pop() {
			Some(crate::mock::VerifiedStatement::Unshield(s, v)) => (s, v),
			other => panic!("expected an unshield statement, got {other:?}"),
		}
	}

	#[test]
	fn the_verifier_gets_every_public_value_the_raw_recipient_and_the_version() {
		new_test_ext().execute_with(|| {
			let asset_id = setup_spend();
			assert_ok!(UnshieldOperation::execute::<Test>(
				&proof(),
				request(0x70, asset_id)
			));

			let (statement, version) = verified_unshield();
			assert_eq!(version, Some(2));
			assert_eq!(
				statement,
				UnshieldStatement {
					merkle_root: KNOWN_ROOT,
					nullifier: nullifier(0x70).0,
					amount: AMOUNT,
					recipient: acc(2).into(),
					asset_id,
					fee: FEE,
					change_commitment: [0u8; 32],
					memo_digest: memo_digest(&[EncryptedMemo::default()]),
				}
			);
		});
	}

	#[test]
	fn a_partial_unshield_binds_its_change_memo() {
		new_test_ext().execute_with(|| {
			let asset_id = setup_spend();
			let req = UnshieldRequest {
				amount: AMOUNT - 100,
				change_commitment: canonical_bytes(0x90),
				change_memo: change_memo(),
				..request(0x71, asset_id)
			};
			assert_ok!(UnshieldOperation::execute::<Test>(&proof(), req));
			assert_eq!(
				verified_unshield().0.memo_digest,
				memo_digest(&[change_memo()])
			);
		});
	}
}

/// The change note is recoverable from the chain only through its memo, so a
/// partial unshield carries a full one — never an empty or truncated one.
#[test]
fn a_partial_unshield_without_a_full_change_memo_is_rejected() {
	new_test_ext().execute_with(|| {
		let asset_id = setup_spend();
		for memo in [
			EncryptedMemo::default(),
			EncryptedMemo::new(vec![0x07; 7]).unwrap(),
		] {
			let req = UnshieldRequest {
				amount: AMOUNT - 100,
				change_commitment: canonical_bytes(0x91),
				change_memo: memo,
				..request(0x72, asset_id)
			};
			assert_noop!(
				UnshieldOperation::execute::<Test>(&proof(), req),
				Error::<Test>::InvalidMemoSize
			);
		}
	});
}

/// The zero account has no known key: an unshield to it burns the withdrawal.
#[test]
fn an_unshield_to_the_zero_account_is_refused() {
	new_test_ext().execute_with(|| {
		let asset_id = setup_spend();
		let req = UnshieldRequest {
			recipient: AccountId32::new([0u8; 32]),
			..request(0x74, asset_id)
		};
		assert_noop!(
			UnshieldOperation::execute::<Test>(&proof(), req),
			Error::<Test>::InvalidRecipient
		);
	});
}

/// The declared weight pays for the proof verification the dispatchable runs;
/// without it a junk-proof spend costs far more than it pays.
#[test]
fn the_unshield_weight_includes_one_proof_verification() {
	use frame_support::dispatch::GetDispatchInfo;
	use pallet_zk_verifier::ZkVerifierPort;
	let call = crate::Call::<Test>::unshield {
		proof: proof(),
		merkle_root: KNOWN_ROOT,
		nullifier: nullifier(0x75),
		asset_id: 0,
		amount: 1,
		recipient: acc(2),
		fee: 0,
		change_commitment: [0u8; 32],
		change_encrypted_memo: EncryptedMemo::default(),
		circuit_version: 1,
	};
	let verification = <crate::mock::MockZkVerifier as ZkVerifierPort>::verification_weight();
	assert!(call.get_dispatch_info().call_weight.all_gte(verification));
}

/// A proof that does not verify pays nobody and spends nothing.
// Under `skip-proof-verification` every proof is accepted.
#[cfg(not(feature = "skip-proof-verification"))]
#[test]
fn an_invalid_proof_fails_at_dispatch_and_changes_nothing() {
	new_test_ext().execute_with(|| {
		let asset_id = setup_asset();
		fund_pool(asset_id, 1_000u128);
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
		crate::mock::set_mock_proof_valid(false);
		assert_noop!(
			UnshieldOperation::execute::<Test>(
				&proof(),
				UnshieldRequest {
					merkle_root: KNOWN_ROOT,
					nullifier: nullifier(0x31),
					asset_id,
					amount: 100u128,
					recipient: acc(2),
					fee: 5u128,
					change_commitment: [0u8; 32],
					change_memo: EncryptedMemo::default(),
					circuit_version: 1,
				},
			),
			Error::<Test>::ProofVerificationFailed
		);
	});
}
