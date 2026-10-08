//! `PrivateTransferOperation`: validation, settlement, the ledger and relay-fee
//! routing, plus an adversarial battery against its non-cryptographic checks.

use super::{
	KNOWN_ROOT, canonical_bytes, commit, commitment, commitments_of, evm, fund_pool, memo,
	nullifier, nullifiers_of, proof, short_memo,
};
use crate::{
	mock::{System, Test, acc, new_test_ext},
	operations::private_transfer::*,
	pallet::{Config, Error, Event as PalletEvent},
	storage::{CommitmentRepository, MerkleRepository, NullifierRepository},
	types::{Commitment, EncryptedMemo, MAX_ENCRYPTED_MEMO_SIZE, Nullifier},
};
use frame_support::{BoundedVec, assert_err, assert_noop, assert_ok, pallet_prelude::ConstU32};
use pallet_relayer::RelayerInterface as _;

// ── helpers ──────────────────────────────────────────────────────────────────

/// A one-input spend: the circuit takes two inputs, the second a dummy.
fn one_input(seed: u8) -> BoundedVec<Nullifier, ConstU32<2>> {
	BoundedVec::try_from(vec![nullifier(seed), Nullifier::new([0u8; 32])]).unwrap()
}

/// Two distinct outputs derived from `seed`.
fn two_outputs(seed: u8) -> BoundedVec<Commitment, ConstU32<2>> {
	let mut second = canonical_bytes(seed);
	second[2] = 0x5A;
	BoundedVec::try_from(vec![commitment(seed), Commitment::new(second)]).unwrap()
}

/// `count` full memos.
fn memos_of(count: usize) -> BoundedVec<EncryptedMemo, ConstU32<2>> {
	vec![memo(0x01); count].try_into().unwrap()
}

// ── execute ──────────────────────────────────────────────────────────────────

#[test]
fn execute_works_single_note() {
	new_test_ext().execute_with(|| {
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);

		assert_ok!(PrivateTransferOperation::execute::<Test>(
			&proof(),
			TransferRequest {
				merkle_roots: [KNOWN_ROOT, KNOWN_ROOT],
				nullifiers: one_input(0x01),
				commitments: two_outputs(0x02),
				memos: memos_of(2),
				asset_id: 0u32,
				fee: 0u128,
				circuit_version: 1,
			},
		));
	});
}

#[test]
fn execute_works_two_notes() {
	new_test_ext().execute_with(|| {
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);

		assert_ok!(PrivateTransferOperation::execute::<Test>(
			&proof(),
			TransferRequest {
				merkle_roots: [KNOWN_ROOT, KNOWN_ROOT],
				nullifiers: nullifiers_of(&[0xA1, 0xA2]),
				commitments: commitments_of(&[0xB1, 0xB2]),
				memos: memos_of(2),
				asset_id: 0u32,
				fee: 0u128,
				circuit_version: 1,
			},
		));
	});
}

/// Two notes from two trees: one proven against a sealed tree's final root, the
/// other against the active tree. Both roots reach the verifier, in input order.
#[test]
fn execute_spends_notes_from_two_trees() {
	new_test_ext().execute_with(|| {
		use crate::mock::{VerifiedStatement, verified_statements};
		let sealed = [0x5E; 32];
		MerkleRepository::insert_sealed_root::<Test>(0, sealed);
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);

		assert_ok!(PrivateTransferOperation::execute::<Test>(
			&proof(),
			TransferRequest {
				merkle_roots: [sealed, KNOWN_ROOT],
				nullifiers: nullifiers_of(&[0xA1, 0xA2]),
				commitments: commitments_of(&[0xB1, 0xB2]),
				memos: memos_of(2),
				asset_id: 0u32,
				fee: 0u128,
				circuit_version: 3,
			},
		));
		let Some(VerifiedStatement::Transfer(statement, Some(3))) = verified_statements().pop()
		else {
			panic!("the transfer statement was not verified");
		};
		assert_eq!(statement.merkle_roots, [sealed, KNOWN_ROOT]);
	});
}

/// Two real inputs may come from two trees, but each root must be known.
#[test]
fn execute_rejects_an_unknown_root_in_either_slot() {
	new_test_ext().execute_with(|| {
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
		for roots in [[KNOWN_ROOT, [0xFF; 32]], [[0xFF; 32], KNOWN_ROOT]] {
			assert_noop!(
				PrivateTransferOperation::execute::<Test>(
					&proof(),
					TransferRequest {
						merkle_roots: roots,
						nullifiers: nullifiers_of(&[0xA1, 0xA2]),
						commitments: two_outputs(0x02),
						memos: memos_of(2),
						asset_id: 0u32,
						fee: 0u128,
						circuit_version: 3,
					},
				),
				Error::<Test>::UnknownMerkleRoot
			);
		}
	});
}

/// The circuit leaves a dummy input's root free, so the pallet pins it to the
/// real input's: neither another known root (a sealed tree's) nor an unknown
/// one is accepted, whichever slot the dummy takes.
#[test]
fn execute_rejects_a_dummy_root_that_differs_from_the_real_one() {
	new_test_ext().execute_with(|| {
		let sealed = [0x5E; 32];
		MerkleRepository::insert_sealed_root::<Test>(0, sealed);
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
		let dummy_second = one_input(0x01);
		let dummy_first: BoundedVec<Nullifier, ConstU32<2>> =
			BoundedVec::try_from(vec![Nullifier::new([0u8; 32]), nullifier(0x01)]).unwrap();
		for (nullifiers, roots) in [
			(dummy_second.clone(), [KNOWN_ROOT, sealed]),
			(dummy_second, [KNOWN_ROOT, [0xFF; 32]]),
			(dummy_first.clone(), [sealed, KNOWN_ROOT]),
			(dummy_first, [[0xFF; 32], KNOWN_ROOT]),
		] {
			assert_noop!(
				PrivateTransferOperation::execute::<Test>(
					&proof(),
					TransferRequest {
						merkle_roots: roots,
						nullifiers,
						commitments: two_outputs(0x02),
						memos: memos_of(2),
						asset_id: 0u32,
						fee: 0u128,
						circuit_version: 3,
					},
				),
				Error::<Test>::InvalidPublicSignals
			);
		}
	});
}

/// `ensure_roots` over every shape: which slot is the dummy, equal or distinct
/// roots, known or unknown, and two dummies.
#[test]
fn ensure_roots_covers_every_shape() {
	new_test_ext().execute_with(|| {
		let sealed = [0x5E; 32];
		let unknown = [0xFF; 32];
		MerkleRepository::insert_sealed_root::<Test>(0, sealed);
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
		let dummy = Nullifier::new([0u8; 32]);
		let shape = |nullifiers: [Nullifier; 2], merkle_roots| TransferRequest::<Test> {
			merkle_roots,
			nullifiers: BoundedVec::try_from(nullifiers.to_vec()).unwrap(),
			commitments: two_outputs(0x02),
			memos: memos_of(2),
			asset_id: 0u32,
			fee: 0u128,
			circuit_version: 3,
		};
		let (a, b) = (nullifier(0x01), nullifier(0x02));
		for (nullifiers, roots, expected) in [
			([a, b], [KNOWN_ROOT, KNOWN_ROOT], Ok(())),
			([a, b], [sealed, KNOWN_ROOT], Ok(())),
			(
				[a, b],
				[KNOWN_ROOT, unknown],
				Err(Error::<Test>::UnknownMerkleRoot),
			),
			(
				[a, b],
				[unknown, unknown],
				Err(Error::<Test>::UnknownMerkleRoot),
			),
			([a, dummy], [KNOWN_ROOT, KNOWN_ROOT], Ok(())),
			([dummy, b], [sealed, sealed], Ok(())),
			(
				[a, dummy],
				[KNOWN_ROOT, sealed],
				Err(Error::<Test>::InvalidPublicSignals),
			),
			(
				[dummy, b],
				[unknown, KNOWN_ROOT],
				Err(Error::<Test>::InvalidPublicSignals),
			),
			(
				[a, dummy],
				[unknown, unknown],
				Err(Error::<Test>::UnknownMerkleRoot),
			),
			(
				[dummy, dummy],
				[KNOWN_ROOT, sealed],
				Err(Error::<Test>::InvalidPublicSignals),
			),
		] {
			let expected: Result<(), Error<Test>> = expected;
			assert_eq!(
				shape(nullifiers, roots)
					.ensure_roots()
					.map_err(sp_runtime::DispatchError::from),
				expected.map_err(sp_runtime::DispatchError::from),
				"{nullifiers:?} {roots:?}"
			);
		}
	});
}

#[test]
fn execute_unknown_root_fails() {
	new_test_ext().execute_with(|| {
		// root never added
		assert_noop!(
			PrivateTransferOperation::execute::<Test>(
				&proof(),
				TransferRequest {
					merkle_roots: [[0xFFu8; 32], [0xFFu8; 32]],
					nullifiers: one_input(0x01),
					commitments: two_outputs(0x02),
					memos: memos_of(2),
					asset_id: 0u32,
					fee: 0u128,
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
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
		let n = nullifier(0x20);
		NullifierRepository::mark_as_used::<Test>(n, 1u64);

		assert_noop!(
			PrivateTransferOperation::execute::<Test>(
				&proof(),
				TransferRequest {
					merkle_roots: [KNOWN_ROOT, KNOWN_ROOT],
					nullifiers: one_input(0x20),
					commitments: two_outputs(0x30),
					memos: memos_of(2),
					asset_id: 0u32,
					fee: 0u128,
					circuit_version: 1,
				},
			),
			Error::<Test>::NullifierAlreadyUsed
		);
	});
}

#[test]
fn execute_two_equal_nullifiers_fails() {
	new_test_ext().execute_with(|| {
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);

		// The same non-dummy nullifier in both slots would spend one input
		// twice: neither is in the used set yet, so both clear that check.
		assert_noop!(
			PrivateTransferOperation::execute::<Test>(
				&proof(),
				TransferRequest {
					merkle_roots: [KNOWN_ROOT, KNOWN_ROOT],
					nullifiers: nullifiers_of(&[0x20, 0x20]),
					commitments: commitments_of(&[0x30, 0x31]),
					memos: memos_of(2),
					asset_id: 0u32,
					fee: 0u128,
					circuit_version: 1,
				},
			),
			Error::<Test>::NullifierAlreadyUsed
		);
	});
}

#[test]
fn execute_memo_commitment_mismatch_fails() {
	new_test_ext().execute_with(|| {
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);

		// 2 nullifiers + commitments but only 1 memo
		assert_noop!(
			PrivateTransferOperation::execute::<Test>(
				&proof(),
				TransferRequest {
					merkle_roots: [KNOWN_ROOT, KNOWN_ROOT],
					nullifiers: nullifiers_of(&[0xA1, 0xA2]),
					commitments: commitments_of(&[0xB1, 0xB2]),
					memos: memos_of(1), // mismatch: 1 ≠ 2
					asset_id: 0u32,
					fee: 0u128,
					circuit_version: 1,
				},
			),
			Error::<Test>::MemoCommitmentMismatch
		);
	});
}

#[test]
fn execute_invalid_memo_size_fails() {
	new_test_ext().execute_with(|| {
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);

		let mut memos: BoundedVec<EncryptedMemo, ConstU32<2>> = BoundedVec::new();
		memos.try_push(short_memo()).unwrap(); // 32 bytes, not 180
		memos.try_push(memo(0x01)).unwrap();

		assert_noop!(
			PrivateTransferOperation::execute::<Test>(
				&proof(),
				TransferRequest {
					merkle_roots: [KNOWN_ROOT, KNOWN_ROOT],
					nullifiers: one_input(0x01),
					commitments: two_outputs(0x02),
					memos,
					asset_id: 0u32,
					fee: 0u128,
					circuit_version: 1,
				},
			),
			Error::<Test>::InvalidMemoSize
		);
	});
}

#[test]
fn execute_marks_nullifiers_used() {
	new_test_ext().execute_with(|| {
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
		let n1 = nullifier(0xC1);
		let n2 = nullifier(0xC2);

		assert!(!NullifierRepository::is_used::<Test>(&n1));
		assert!(!NullifierRepository::is_used::<Test>(&n2));

		assert_ok!(PrivateTransferOperation::execute::<Test>(
			&proof(),
			TransferRequest {
				merkle_roots: [KNOWN_ROOT, KNOWN_ROOT],
				nullifiers: nullifiers_of(&[0xC1, 0xC2]),
				commitments: commitments_of(&[0xD1, 0xD2]),
				memos: memos_of(2),
				asset_id: 0u32,
				fee: 0u128,
				circuit_version: 1,
			},
		));

		assert!(NullifierRepository::is_used::<Test>(&n1));
		assert!(NullifierRepository::is_used::<Test>(&n2));
	});
}

#[test]
fn execute_stores_commitment_memos() {
	new_test_ext().execute_with(|| {
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
		let c = commitment(0xE1);

		assert!(!CommitmentRepository::exists::<Test>(&c));

		assert_ok!(PrivateTransferOperation::execute::<Test>(
			&proof(),
			TransferRequest {
				merkle_roots: [KNOWN_ROOT, KNOWN_ROOT],
				nullifiers: one_input(0xE0),
				commitments: two_outputs(0xE1),
				memos: memos_of(2),
				asset_id: 0u32,
				fee: 0u128,
				circuit_version: 1,
			},
		));

		assert!(CommitmentRepository::exists::<Test>(&c));
	});
}

#[test]
fn execute_emits_private_transfer_event() {
	new_test_ext().execute_with(|| {
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);

		let nullifiers = one_input(0xF1);
		let commitments = two_outputs(0xF2);

		assert_ok!(PrivateTransferOperation::execute::<Test>(
			&proof(),
			TransferRequest {
				merkle_roots: [KNOWN_ROOT, KNOWN_ROOT],
				nullifiers: nullifiers.clone(),
				commitments: commitments.clone(),
				memos: memos_of(2),
				asset_id: 0u32,
				fee: 0u128,
				circuit_version: 1,
			},
		));

		let events = frame_system::Pallet::<Test>::events();
		let found_nullifiers = events.iter().any(|r| {
			matches!(
				&r.event,
				crate::mock::RuntimeEvent::ShieldedPool(PalletEvent::NullifiersSpent {
					nullifiers: en,
				}) if en == &nullifiers
			)
		});
		assert!(found_nullifiers, "NullifiersSpent event not emitted");

		let found_commitments = events.iter().any(|r| {
			matches!(
				&r.event,
				crate::mock::RuntimeEvent::ShieldedPool(PalletEvent::CommitmentsInserted {
					commitments: ec,
					..
				}) if ec == &commitments
			)
		});
		assert!(found_commitments, "CommitmentsInserted event not emitted");
	});
}

#[test]
fn execute_accumulates_fee_to_block_author_when_nonzero() {
	new_test_ext().execute_with(|| {
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
		let fee = 25u128;

		assert_ok!(PrivateTransferOperation::execute::<Test>(
			&proof(),
			TransferRequest {
				merkle_roots: [KNOWN_ROOT, KNOWN_ROOT],
				nullifiers: one_input(0x10),
				commitments: two_outputs(0x11),
				memos: memos_of(2),
				asset_id: 0u32,
				fee,
				circuit_version: 1,
			},
		));

		// MockRelayer block_author = Some(1)
		let pending = crate::mock::mock_pending_fees_get(acc(1), 0u32);
		assert_eq!(pending, fee);
	});
}

#[test]
fn execute_no_fee_accumulated_when_zero() {
	new_test_ext().execute_with(|| {
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);

		assert_ok!(PrivateTransferOperation::execute::<Test>(
			&proof(),
			TransferRequest {
				merkle_roots: [KNOWN_ROOT, KNOWN_ROOT],
				nullifiers: one_input(0x12),
				commitments: two_outputs(0x13),
				memos: memos_of(2),
				asset_id: 0u32,
				fee: 0u128,
				circuit_version: 1,
			},
		));

		let pending = crate::mock::mock_pending_fees_get(acc(1), 0u32);
		assert_eq!(pending, 0u128);
	});
}

// ── query helpers ────────────────────────────────────────────────────────────

#[test]
fn is_nullifier_used_false_by_default() {
	new_test_ext().execute_with(|| {
		assert!(!NullifierRepository::is_used::<Test>(&nullifier(0xAB)));
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

#[test]
fn execute_with_dummy_nullifier_only_real_inserted() {
	// A transfer with 1 real note + 1 dummy (nullifier = [0u8;32]) must succeed
	// and only insert the real nullifier into the set.
	new_test_ext().execute_with(|| {
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
		let real = nullifier(0x55);
		let dummy = Nullifier::new([0u8; 32]);

		let mut nullifiers: BoundedVec<Nullifier, ConstU32<2>> = BoundedVec::new();
		nullifiers.try_push(real).ok();
		nullifiers.try_push(dummy).ok();

		assert!(!NullifierRepository::is_used::<Test>(&real));

		assert_ok!(PrivateTransferOperation::execute::<Test>(
			&proof(),
			TransferRequest {
				merkle_roots: [KNOWN_ROOT, KNOWN_ROOT],
				nullifiers,
				commitments: commitments_of(&[0x56, 0x57]),
				memos: memos_of(2),
				asset_id: 0u32,
				fee: 0u128,
				circuit_version: 1,
			},
		));

		// Real nullifier must be marked used
		assert!(NullifierRepository::is_used::<Test>(&real));
		// Dummy nullifier [0;32] must NOT be inserted
		assert!(!NullifierRepository::is_used::<Test>(&dummy));
	});
}

#[test]
fn execute_dummy_nullifier_not_rejected_as_double_spend() {
	// Two transactions, both with dummy nullifier [0u8;32] in slot 1.
	// The second must not be rejected as double-spend of the dummy.
	new_test_ext().execute_with(|| {
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);

		let mut nullifiers_tx1: BoundedVec<Nullifier, ConstU32<2>> = BoundedVec::new();
		nullifiers_tx1.try_push(nullifier(0x61)).ok();
		nullifiers_tx1.try_push(Nullifier::new([0u8; 32])).ok();

		let mut nullifiers_tx2: BoundedVec<Nullifier, ConstU32<2>> = BoundedVec::new();
		nullifiers_tx2.try_push(nullifier(0x71)).ok();
		nullifiers_tx2.try_push(Nullifier::new([0u8; 32])).ok();

		assert_ok!(PrivateTransferOperation::execute::<Test>(
			&proof(),
			TransferRequest {
				merkle_roots: [KNOWN_ROOT, KNOWN_ROOT],
				nullifiers: nullifiers_tx1,
				commitments: commitments_of(&[0x62, 0x63]),
				memos: memos_of(2),
				asset_id: 0u32,
				fee: 0u128,
				circuit_version: 1,
			},
		));

		// Second tx with a different real nullifier but same dummy — must succeed
		assert_ok!(PrivateTransferOperation::execute::<Test>(
			&proof(),
			TransferRequest {
				merkle_roots: [KNOWN_ROOT, KNOWN_ROOT],
				nullifiers: nullifiers_tx2,
				commitments: commitments_of(&[0x72, 0x73]),
				memos: memos_of(2),
				asset_id: 0u32,
				fee: 0u128,
				circuit_version: 1,
			},
		));
	});
}

#[test]
fn execute_rejects_all_dummy_nullifiers() {
	// Both nullifiers are [0u8;32] → total value = 0, no real input note.
	// Must be rejected as InvalidAmount to prevent free Merkle tree spam.
	new_test_ext().execute_with(|| {
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);

		let mut nullifiers: BoundedVec<Nullifier, ConstU32<2>> = BoundedVec::new();
		nullifiers.try_push(Nullifier::new([0u8; 32])).ok();
		nullifiers.try_push(Nullifier::new([0u8; 32])).ok();

		assert_noop!(
			PrivateTransferOperation::execute::<Test>(
				&proof(),
				TransferRequest {
					merkle_roots: [KNOWN_ROOT, KNOWN_ROOT],
					nullifiers,
					commitments: commitments_of(&[0x10, 0x11]),
					memos: memos_of(2),
					asset_id: 0u32,
					fee: 0u128,
					circuit_version: 1,
				},
			),
			Error::<Test>::InvalidAmount
		);
	});
}

#[test]
fn execute_nullifier_commitment_count_mismatch_fails() {
	// 1 nullifier but 2 output commitments: structurally inconsistent with the
	// fixed 2-in/2-out circuit. Must be rejected by the pallet before the ZK check
	// so that benchmark mode (no verifier) cannot break value conservation.
	new_test_ext().execute_with(|| {
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);

		assert_noop!(
			PrivateTransferOperation::execute::<Test>(
				&proof(),
				TransferRequest {
					merkle_roots: [KNOWN_ROOT, KNOWN_ROOT],
					nullifiers: nullifiers_of(&[0xF1]),         // 1 nullifier
					commitments: commitments_of(&[0xF2, 0xF3]), // 2 commitments
					memos: memos_of(2),
					asset_id: 0u32,
					fee: 0u128,
					circuit_version: 1,
				},
			),
			Error::<Test>::TooManyInputsOrOutputs
		);
	});
}

// ── private_transfer must leave the pool ledger untouched ────────────────────

/// A transfer moves value note-to-note; nothing enters or leaves the pool
/// physically, so PoolBalancePerAsset must not change. The fee becomes a
/// pending number backed by tokens already inside the pool.
#[test]
fn transfer_preserves_pool_ledger() {
	use crate::storage::PoolBalanceRepository;
	use frame_support::traits::Currency;
	use sp_runtime::AccountId32;

	new_test_ext().execute_with(|| {
		let asset_id = 0u32;
		// Seed a pool ledger/physical balance the transfer must not disturb.
		let pool = crate::Pallet::<Test>::pool_account_id();
		fund_pool(asset_id, 1000);
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);

		let ledger_before = PoolBalanceRepository::get_asset_balance::<Test>(asset_id);
		let physical_before =
			<pallet_balances::Pallet<Test> as Currency<AccountId32>>::free_balance(&pool);
		let fee = 25u128;

		assert_ok!(PrivateTransferOperation::execute::<Test>(
			&proof(),
			TransferRequest {
				merkle_roots: [KNOWN_ROOT, KNOWN_ROOT],
				nullifiers: one_input(0x40),
				commitments: two_outputs(0x41),
				memos: memos_of(2),
				asset_id,
				fee,
				circuit_version: 1,
			},
		));

		assert_eq!(
			PoolBalanceRepository::get_asset_balance::<Test>(asset_id),
			ledger_before,
			"transfer must not change the pool ledger"
		);
		assert_eq!(
			<pallet_balances::Pallet<Test> as Currency<AccountId32>>::free_balance(&pool),
			physical_before,
			"transfer must not move physical pool tokens"
		);
		assert_eq!(crate::mock::mock_pending_fees_get(acc(1), asset_id), fee);
	});
}

// ── relay-fee attribution (relay commits) ────────────────────────────────────

/// The relayer that committed to the transfer in an earlier block receives
/// its fee; without a commit the block author does.
#[test]
fn transfer_fee_follows_the_relay_commit() {
	new_test_ext().execute_with(|| {
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
		let relayer = evm(0xAA);
		crate::mock::mock_register_relayer(acc(7), relayer);

		let nullifiers = one_input(0x70);
		let commitments = two_outputs(0x71);
		let op_hash = TransferRequest::<Test> {
			merkle_roots: [KNOWN_ROOT, KNOWN_ROOT],
			nullifiers: nullifiers.clone(),
			commitments: commitments.clone(),
			memos: memos_of(2),
			asset_id: 0,
			fee: 30,
			circuit_version: 1,
		}
		.op_hash();
		commit(relayer, &op_hash);
		System::set_block_number(2);

		assert_ok!(PrivateTransferOperation::execute::<Test>(
			&proof(),
			TransferRequest {
				merkle_roots: [KNOWN_ROOT, KNOWN_ROOT],
				nullifiers,
				commitments,
				memos: memos_of(2),
				asset_id: 0u32,
				fee: 30u128,
				circuit_version: 1,
			},
		));
		assert_eq!(crate::mock::mock_pending_fees_get(acc(7), 0u32), 30);

		// Uncommitted transfer → block author.
		assert_ok!(PrivateTransferOperation::execute::<Test>(
			&proof(),
			TransferRequest {
				merkle_roots: [KNOWN_ROOT, KNOWN_ROOT],
				nullifiers: one_input(0x72),
				commitments: two_outputs(0x73),
				memos: memos_of(2),
				asset_id: 0u32,
				fee: 20u128,
				circuit_version: 1,
			},
		));
		assert_eq!(crate::mock::mock_pending_fees_get(acc(1), 0u32), 20);
	});
}

/// A non-zero fee with no resolvable recipient errors, mirroring unshield.
#[test]
fn transfer_nonzero_fee_without_recipient_errors() {
	new_test_ext().execute_with(|| {
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
		crate::mock::mock_clear_block_author();

		assert_err!(
			PrivateTransferOperation::execute::<Test>(
				&proof(),
				TransferRequest {
					merkle_roots: [KNOWN_ROOT, KNOWN_ROOT],
					nullifiers: one_input(0x80),
					commitments: two_outputs(0x81),
					memos: memos_of(2),
					asset_id: 0u32,
					fee: 25u128,
					circuit_version: 1,
				},
			),
			Error::<Test>::FeeRecipientUnavailable
		);
	});
}

// ── asset state-machine gate ─────────────────────────────────────────────────

/// Unverifying an asset freezes in-pool transfers too, mirroring the
/// shield/unshield freeze (no path escapes the emergency kill-switch).
#[test]
fn transfer_frozen_asset_fails() {
	new_test_ext().execute_with(|| {
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
		crate::operations::assets::AssetOperation::unverify::<Test>(0u32).unwrap();

		assert_noop!(
			PrivateTransferOperation::execute::<Test>(
				&proof(),
				TransferRequest {
					merkle_roots: [KNOWN_ROOT, KNOWN_ROOT],
					nullifiers: one_input(0x90),
					commitments: two_outputs(0x91),
					memos: memos_of(2),
					asset_id: 0u32,
					fee: 0u128,
					circuit_version: 1,
				},
			),
			Error::<Test>::AssetNotVerified
		);
	});
}

/// A transfer on an unregistered asset id is rejected before any effect.
#[test]
fn transfer_unknown_asset_fails() {
	new_test_ext().execute_with(|| {
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);

		assert_noop!(
			PrivateTransferOperation::execute::<Test>(
				&proof(),
				TransferRequest {
					merkle_roots: [KNOWN_ROOT, KNOWN_ROOT],
					nullifiers: one_input(0x92),
					commitments: two_outputs(0x93),
					memos: memos_of(2),
					asset_id: 999u32,
					fee: 0u128,
					circuit_version: 1,
				},
			),
			Error::<Test>::InvalidAssetId
		);
	});
}

// ── adversarial battery ──────────────────────────────────────────────────────
//
// Each of these is an attempt to BREAK an invariant, not a demonstration
// that it holds. They are written from the attacker's side: assume the ZK
// proof is satisfiable (the mock accepts every proof) and ask what the
// non-cryptographic checks still have to stop on their own.

/// Double-spend inside ONE extrinsic, same nullifier twice.
///
/// The set check cannot catch this: neither nullifier is in storage yet when
/// the loop runs, so only the explicit pairwise comparison stands between
/// this and spending one note twice in a single call.
#[test]
fn attack_same_nullifier_twice_in_one_extrinsic_is_refused() {
	new_test_ext().execute_with(|| {
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);

		let mut nulls: BoundedVec<Nullifier, ConstU32<2>> = BoundedVec::new();
		nulls.try_push(nullifier(0x77)).unwrap();
		nulls.try_push(nullifier(0x77)).unwrap(); // same note, twice

		assert_err!(
			PrivateTransferOperation::execute::<Test>(
				&proof(),
				TransferRequest {
					merkle_roots: [KNOWN_ROOT, KNOWN_ROOT],
					nullifiers: nulls,
					commitments: commitments_of(&[0xC1, 0xC2]),
					memos: memos_of(2),
					asset_id: 0u32,
					fee: 0u128,
					circuit_version: 1,
				},
			),
			Error::<Test>::NullifierAlreadyUsed
		);
	});
}

/// The dummy nullifier is exempt from the "already used" check by design.
/// Two dummies in one call must therefore NOT be readable as a duplicate
/// pair — but the all-dummy guard has to reject the call outright, or a
/// transfer with no real input mints two free leaves.
#[test]
fn attack_two_dummy_nullifiers_cannot_mint_free_leaves() {
	new_test_ext().execute_with(|| {
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);

		let mut nulls: BoundedVec<Nullifier, ConstU32<2>> = BoundedVec::new();
		nulls.try_push(Nullifier::new([0u8; 32])).unwrap();
		nulls.try_push(Nullifier::new([0u8; 32])).unwrap();

		assert_err!(
			PrivateTransferOperation::execute::<Test>(
				&proof(),
				TransferRequest {
					merkle_roots: [KNOWN_ROOT, KNOWN_ROOT],
					nullifiers: nulls,
					commitments: commitments_of(&[0xD1, 0xD2]),
					memos: memos_of(2),
					asset_id: 0u32,
					fee: 0u128,
					circuit_version: 1,
				},
			),
			Error::<Test>::InvalidAmount
		);
	});
}

/// Replay of a nullifier already spent in an EARLIER block.
#[test]
fn attack_replaying_a_spent_nullifier_is_refused() {
	new_test_ext().execute_with(|| {
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);

		assert_ok!(PrivateTransferOperation::execute::<Test>(
			&proof(),
			TransferRequest {
				merkle_roots: [KNOWN_ROOT, KNOWN_ROOT],
				nullifiers: one_input(0x51),
				commitments: two_outputs(0x52),
				memos: memos_of(2),
				asset_id: 0u32,
				fee: 0u128,
				circuit_version: 1,
			},
		));

		// Same nullifier, different outputs — the note is already gone.
		assert_err!(
			PrivateTransferOperation::execute::<Test>(
				&proof(),
				TransferRequest {
					merkle_roots: [KNOWN_ROOT, KNOWN_ROOT],
					nullifiers: one_input(0x51),
					commitments: two_outputs(0x53),
					memos: memos_of(2),
					asset_id: 0u32,
					fee: 0u128,
					circuit_version: 1,
				},
			),
			Error::<Test>::NullifierAlreadyUsed
		);
	});
}

/// Non-canonical field elements: bytes above the BN254 modulus that reduce
/// to a DIFFERENT, already-spent value. Accepting them would give every
/// nullifier a second spelling and defeat the double-spend set entirely.
#[test]
fn attack_non_canonical_nullifier_is_refused() {
	new_test_ext().execute_with(|| {
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);

		// modulus + 1, little-endian — reduces to 1, which is canonical.
		let mut over = [0u8; 32];
		over[0] = 0x02;
		over[31] = 0xFF;
		assert!(
			!Nullifier::new(over).is_canonical(),
			"fixture must actually be non-canonical or the test proves nothing"
		);

		let mut nulls: BoundedVec<Nullifier, ConstU32<2>> = BoundedVec::new();
		nulls.try_push(Nullifier::new(over)).unwrap();
		nulls.try_push(Nullifier::new([0u8; 32])).unwrap();

		assert_err!(
			PrivateTransferOperation::execute::<Test>(
				&proof(),
				TransferRequest {
					merkle_roots: [KNOWN_ROOT, KNOWN_ROOT],
					nullifiers: nulls,
					commitments: two_outputs(0xE1),
					memos: memos_of(2),
					asset_id: 0u32,
					fee: 0u128,
					circuit_version: 1,
				},
			),
			Error::<Test>::InvalidPublicSignals
		);
	});
}

/// Same, on the output side: a non-canonical commitment would land a leaf
/// whose second spelling could collide with a real one.
#[test]
fn attack_non_canonical_commitment_is_refused() {
	new_test_ext().execute_with(|| {
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);

		let mut over = [0u8; 32];
		over[0] = 0x02;
		over[31] = 0xFF;
		assert!(!Commitment::new(over).is_canonical());

		let mut comms: BoundedVec<Commitment, ConstU32<2>> = BoundedVec::new();
		comms.try_push(Commitment::new(over)).unwrap();
		comms.try_push(commitment(0x62)).unwrap();

		assert_err!(
			PrivateTransferOperation::execute::<Test>(
				&proof(),
				TransferRequest {
					merkle_roots: [KNOWN_ROOT, KNOWN_ROOT],
					nullifiers: one_input(0x61),
					commitments: comms,
					memos: memos_of(2),
					asset_id: 0u32,
					fee: 0u128,
					circuit_version: 1,
				},
			),
			Error::<Test>::InvalidPublicSignals
		);
	});
}

/// A forged Merkle root the attacker made up: it lets them prove membership
/// of a note that was never in the tree.
#[test]
fn attack_unknown_merkle_root_is_refused() {
	new_test_ext().execute_with(|| {
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);

		assert_err!(
			PrivateTransferOperation::execute::<Test>(
				&proof(),
				TransferRequest {
					merkle_roots: [[0xEEu8; 32], [0xEEu8; 32]], // never added
					nullifiers: one_input(0x71),
					commitments: two_outputs(0x72),
					memos: memos_of(2),
					asset_id: 0u32,
					fee: 0u128,
					circuit_version: 1,
				},
			),
			Error::<Test>::UnknownMerkleRoot
		);
	});
}

/// Array-length confusion: more commitments than nullifiers would insert an
/// output nothing paid for.
#[test]
fn attack_more_commitments_than_nullifiers_is_refused() {
	new_test_ext().execute_with(|| {
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);

		assert_err!(
			PrivateTransferOperation::execute::<Test>(
				&proof(),
				TransferRequest {
					merkle_roots: [KNOWN_ROOT, KNOWN_ROOT],
					nullifiers: nullifiers_of(&[0x81]),         // 1 input
					commitments: commitments_of(&[0x82, 0x83]), // 2 outputs
					memos: memos_of(2),
					asset_id: 0u32,
					fee: 0u128,
					circuit_version: 1,
				},
			),
			Error::<Test>::TooManyInputsOrOutputs
		);
	});
}

/// Memo count out of step with the outputs: a missing memo would leave a
/// commitment nobody can ever open, and the zip() that stores them would
/// silently drop the extra output.
#[test]
fn attack_memo_count_mismatch_is_refused() {
	new_test_ext().execute_with(|| {
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);

		assert_err!(
			PrivateTransferOperation::execute::<Test>(
				&proof(),
				TransferRequest {
					merkle_roots: [KNOWN_ROOT, KNOWN_ROOT],
					nullifiers: nullifiers_of(&[0x91, 0x92]),
					commitments: commitments_of(&[0x93, 0x94]),
					memos: memos_of(1), // one memo for two outputs
					asset_id: 0u32,
					fee: 0u128,
					circuit_version: 1,
				},
			),
			Error::<Test>::MemoCommitmentMismatch
		);
	});
}

/// A wrong-sized memo must not reach storage: the wallet's decrypt path
/// slices fixed offsets, so a short memo is a note nobody can open.
#[test]
fn attack_undersized_memo_is_refused() {
	new_test_ext().execute_with(|| {
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);

		let mut memos: BoundedVec<EncryptedMemo, ConstU32<2>> = BoundedVec::new();
		memos.try_push(short_memo()).unwrap();
		memos.try_push(memo(0x01)).unwrap();

		assert_err!(
			PrivateTransferOperation::execute::<Test>(
				&proof(),
				TransferRequest {
					merkle_roots: [KNOWN_ROOT, KNOWN_ROOT],
					nullifiers: one_input(0xA9),
					commitments: two_outputs(0xAA),
					memos,
					asset_id: 0u32,
					fee: 0u128,
					circuit_version: 1,
				},
			),
			Error::<Test>::InvalidMemoSize
		);
	});
}

/// The zero commitment is the tree's empty-leaf sentinel. Inserting it as a
/// real output would corrupt the Merkle structure.
#[test]
fn attack_zero_commitment_is_refused() {
	new_test_ext().execute_with(|| {
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);

		let mut comms: BoundedVec<Commitment, ConstU32<2>> = BoundedVec::new();
		comms.try_push(Commitment::new([0u8; 32])).unwrap();
		comms.try_push(commitment(0x63)).unwrap();

		assert_err!(
			PrivateTransferOperation::execute::<Test>(
				&proof(),
				TransferRequest {
					merkle_roots: [KNOWN_ROOT, KNOWN_ROOT],
					nullifiers: one_input(0xB9),
					commitments: comms,
					memos: memos_of(2),
					asset_id: 0u32,
					fee: 0u128,
					circuit_version: 1,
				},
			),
			Error::<Test>::InvalidPublicSignals
		);
	});
}

/// A fee below the relay minimum must be refused BEFORE any state changes —
/// otherwise the pool subsidizes the spam it is meant to price out.
#[test]
fn attack_fee_below_minimum_is_refused_without_spending_the_nullifier() {
	new_test_ext().execute_with(|| {
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
		let min = <Test as Config>::Relayer::min_relay_fee();
		if min == 0 {
			return; // mock has no minimum; nothing to prove here
		}

		let n = nullifier(0xC9);
		assert_err!(
			PrivateTransferOperation::execute::<Test>(
				&proof(),
				TransferRequest {
					merkle_roots: [KNOWN_ROOT, KNOWN_ROOT],
					nullifiers: one_input(0xC9),
					commitments: two_outputs(0xCA),
					memos: memos_of(2),
					asset_id: 0u32,
					fee: min.saturating_sub(1),
					circuit_version: 1,
				},
			),
			Error::<Test>::FeeTooLow
		);
		// And the note must still be spendable — a rejected call that burned
		// the nullifier would destroy funds.
		assert!(!NullifierRepository::is_used::<Test>(&n));
	});
}

/// Duplicate commitments inside ONE call, checked for real.
///
/// The duplicate guard reads `CommitmentMemos`, which is only populated
/// AFTER each insert by `store_memo`. Within a single call the loop runs
/// insert→store_memo per output, so by the time the second (identical)
/// output is inserted the first one's memo IS stored and the guard fires.
/// If that ordering ever changes, one note would take two leaves in one
/// transaction — this pins the outcome, not the mechanism.
#[test]
fn attack_duplicate_commitments_in_one_call_cannot_take_two_leaves() {
	new_test_ext().execute_with(|| {
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);

		let mut comms: BoundedVec<Commitment, ConstU32<2>> = BoundedVec::new();
		comms.try_push(commitment(0xF1)).unwrap();
		comms.try_push(commitment(0xF1)).unwrap(); // same leaf twice

		let before = MerkleRepository::get_tree_size::<Test>();

		// Run inside a storage transaction, the way a dispatchable executes:
		// FRAME rolls the whole extrinsic back on error, so the partial leaf
		// from the first (accepted) output must not survive. Calling
		// `execute` bare would leave that write in place — an artefact of the
		// test harness, not of the runtime.
		let result = frame_support::storage::with_storage_layer(|| {
			PrivateTransferOperation::execute::<Test>(
				&proof(),
				TransferRequest {
					merkle_roots: [KNOWN_ROOT, KNOWN_ROOT],
					nullifiers: nullifiers_of(&[0xF2, 0xF3]),
					commitments: comms,
					memos: memos_of(2),
					asset_id: 0u32,
					fee: 0u128,
					circuit_version: 1,
				},
			)
		});

		assert!(result.is_err(), "a duplicated output must not be accepted");
		let after = MerkleRepository::get_tree_size::<Test>();
		assert_eq!(
			before, after,
			"the rejected call must leave no leaf behind once rolled back"
		);
	});
}

/// The memo is opaque to the chain, and must stay that way.
///
/// `sourcePk` lives at plaintext bytes [84,116) INSIDE the ciphertext — the
/// pallet holds no key and must never gate on memo contents. This pins that:
/// two transfers whose memos differ only in those bytes are equally valid on
/// chain. A pallet that could tell them apart would mean the memo was not
/// actually encrypted.
#[test]
fn attack_memo_contents_never_gate_admission() {
	new_test_ext().execute_with(|| {
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);

		// Two memos, same length, different bytes where sourcePk would sit.
		let mut a = [0x01u8; MAX_ENCRYPTED_MEMO_SIZE as usize];
		let mut b = [0x01u8; MAX_ENCRYPTED_MEMO_SIZE as usize];
		for byte in a[84..116].iter_mut() {
			*byte = 0x00;
		}
		for byte in b[84..116].iter_mut() {
			*byte = 0xAB;
		}

		for (i, bytes) in [a, b].into_iter().enumerate() {
			let mut memos: BoundedVec<EncryptedMemo, ConstU32<2>> = BoundedVec::new();
			memos
				.try_push(EncryptedMemo::from_bytes(&bytes).unwrap())
				.unwrap();
			memos.try_push(memo(0x01)).unwrap();
			let seed = 0x80 + i as u8 * 2;
			assert_ok!(PrivateTransferOperation::execute::<Test>(
				&proof(),
				TransferRequest {
					merkle_roots: [KNOWN_ROOT, KNOWN_ROOT],
					nullifiers: one_input(seed),
					commitments: two_outputs(seed + 1),
					memos,
					asset_id: 0u32,
					fee: 0u128,
					circuit_version: 1,
				},
			));
		}
	});
}

// ── the statement handed to the verifier, and copies of a relayed transfer ───

fn request(seeds: [u8; 2]) -> TransferRequest<Test> {
	TransferRequest {
		merkle_roots: [KNOWN_ROOT, KNOWN_ROOT],
		nullifiers: nullifiers_of(&[seeds[0], seeds[0] + 1]),
		commitments: commitments_of(&[seeds[1], seeds[1] + 1]),
		memos: vec![memo(0xA1), memo(0xA2)].try_into().unwrap(),
		asset_id: 0,
		fee: 30,
		circuit_version: 2,
	}
}

fn transfer_call(req: &TransferRequest<Test>) -> crate::Call<Test> {
	crate::Call::<Test>::private_transfer {
		proof: proof(),
		merkle_roots: req.merkle_roots,
		nullifiers: req.nullifiers.clone(),
		commitments: req.commitments.clone(),
		encrypted_memos: req.memos.clone(),
		asset_id: req.asset_id,
		fee: req.fee,
		circuit_version: req.circuit_version,
	}
}

#[test]
fn a_copied_transfer_still_credits_the_committed_relayer() {
	use frame_support::traits::UnfilteredDispatchable;
	new_test_ext().execute_with(|| {
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
		let (honest, copier) = (evm(0xAA), evm(0xBB));
		crate::mock::mock_register_relayer(acc(7), honest);
		crate::mock::mock_register_relayer(acc(8), copier);
		let req = request([0xC4, 0xD4]);
		commit(honest, &req.op_hash());
		System::set_block_number(2);

		assert_ok!(
			transfer_call(&req).dispatch_bypass_filter(crate::RawOrigin::Relayed(copier).into())
		);
		assert_eq!(crate::mock::mock_pending_fees_get(acc(7), 0), 30);
		assert_eq!(crate::mock::mock_pending_fees_get(acc(8), 0), 0);
	});
}

#[test]
fn a_same_block_commit_does_not_capture_the_transfer_fee() {
	new_test_ext().execute_with(|| {
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
		let relayer = evm(0xBB);
		crate::mock::mock_register_relayer(acc(8), relayer);
		let req = request([0xC8, 0xD8]);
		commit(relayer, &req.op_hash());

		assert_ok!(PrivateTransferOperation::execute::<Test>(&proof(), req));
		assert_eq!(crate::mock::mock_pending_fees_get(acc(8), 0), 0);
		assert_eq!(crate::mock::mock_pending_fees_get(acc(1), 0), 30);
	});
}

/// What reaches the verifier; nothing does under `skip-proof-verification`.
#[cfg(not(feature = "skip-proof-verification"))]
mod verified {
	use super::*;
	use crate::operations::statement::memo_digest;

	#[test]
	fn the_verifier_gets_the_memos_in_output_order_and_the_version() {
		new_test_ext().execute_with(|| {
			MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
			let req = request([0xC0, 0xD0]);
			assert_ok!(PrivateTransferOperation::execute::<Test>(
				&proof(),
				req.clone()
			));

			let Some(crate::mock::VerifiedStatement::Transfer(statement, version)) =
				crate::mock::verified_statements().pop()
			else {
				panic!("expected a transfer statement");
			};
			assert_eq!(version, Some(2));
			assert_eq!(statement, req.statement());
			assert_eq!(
				statement.memo_digest,
				memo_digest(&[memo(0xA1), memo(0xA2)])
			);
			assert_ne!(
				statement.memo_digest,
				memo_digest(&[memo(0xA2), memo(0xA1)])
			);
			assert_eq!(
				statement.nullifiers,
				vec![canonical_bytes(0xC0), canonical_bytes(0xC1)]
			);
			assert_eq!(
				statement.commitments,
				vec![canonical_bytes(0xD0), canonical_bytes(0xD1)]
			);
		});
	}
}

/// The dispatch refuses what admission refuses: duplicate outputs and outputs
/// already in the tree fail before the proof, not inside `insert_leaf`. A leaf
/// counts as existing even without a stored memo.
#[test]
fn duplicate_or_existing_outputs_are_refused_before_the_proof() {
	new_test_ext().execute_with(|| {
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
		let twins = TransferRequest {
			commitments: commitments_of(&[0xE1, 0xE1]),
			..request([0xE0, 0xE1])
		};
		assert_noop!(
			PrivateTransferOperation::execute::<Test>(&proof(), twins),
			Error::<Test>::CommitmentAlreadyExists
		);

		crate::merkle::MerkleTreeService::insert_leaf::<Test>(commitment(0xE5)).unwrap();
		let existing = TransferRequest {
			commitments: commitments_of(&[0xE5, 0xE6]),
			..request([0xE4, 0xE5])
		};
		assert_noop!(
			PrivateTransferOperation::execute::<Test>(&proof(), existing),
			Error::<Test>::CommitmentAlreadyExists
		);
	});
}

#[test]
fn the_transfer_weight_includes_one_proof_verification() {
	use frame_support::dispatch::GetDispatchInfo;
	use pallet_zk_verifier::ZkVerifierPort;
	let call = transfer_call(&request([0xF0, 0xF8]));
	let verification = <crate::mock::MockZkVerifier as ZkVerifierPort>::verification_weight();
	assert!(call.get_dispatch_info().call_weight.all_gte(verification));
}

// ── shape and proof at dispatch ──────────────────────────────────────────────

/// The circuit is two in, two out: a one-in, one-out request can never verify,
/// so it is refused before any proof work.
#[test]
fn a_one_in_one_out_transfer_is_refused() {
	new_test_ext().execute_with(|| {
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
		assert_noop!(
			PrivateTransferOperation::execute::<Test>(
				&proof(),
				TransferRequest {
					merkle_roots: [KNOWN_ROOT, KNOWN_ROOT],
					nullifiers: nullifiers_of(&[0x01]),
					commitments: commitments_of(&[0x02]),
					memos: memos_of(1),
					asset_id: 0u32,
					fee: 0u128,
					circuit_version: 1,
				},
			),
			Error::<Test>::TooManyInputsOrOutputs
		);
	});
}

/// A proof that does not verify leaves nothing behind: no spent nullifier, no
/// leaf, no fee.
// Under `skip-proof-verification` every proof is accepted.
#[cfg(not(feature = "skip-proof-verification"))]
#[test]
fn an_invalid_proof_fails_at_dispatch_and_changes_nothing() {
	new_test_ext().execute_with(|| {
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
		crate::mock::set_mock_proof_valid(false);
		assert_noop!(
			PrivateTransferOperation::execute::<Test>(
				&proof(),
				TransferRequest {
					merkle_roots: [KNOWN_ROOT, KNOWN_ROOT],
					nullifiers: one_input(0x01),
					commitments: two_outputs(0x02),
					memos: memos_of(2),
					asset_id: 0u32,
					fee: 5u128,
					circuit_version: 1,
				},
			),
			Error::<Test>::ProofVerificationFailed
		);
	});
}

/// A verified non-native asset is not backed, so its notes cannot move.
#[test]
fn transfer_of_a_non_native_asset_is_refused() {
	new_test_ext().execute_with(|| {
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
		let id = crate::tests::register_asset();
		crate::operations::assets::AssetOperation::verify::<Test>(id).unwrap();
		assert_noop!(
			PrivateTransferOperation::execute::<Test>(
				&proof(),
				TransferRequest {
					asset_id: id,
					..request([0x72, 0x74])
				},
			),
			Error::<Test>::AssetNotSupported
		);
	});
}
