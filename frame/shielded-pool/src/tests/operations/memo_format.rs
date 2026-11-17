// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: GPL-3.0-or-later

//! The memo format rule: scheduling, the leaf it records, and the check at
//! every call that stores a memo.

use crate::{
	operations::{
		bound::{BoundSpendOperation, BoundSpendRequest},
		memo_format,
		private_transfer::{PrivateTransferOperation, TransferRequest},
		shield::{ShieldOperation, ShieldRequest},
		unshield::{UnshieldOperation, UnshieldRequest},
	},
	pallet::{Error, Event as PalletEvent, TaggedMemosFrom, TaggedMemosFromLeaf},
	storage::MerkleRepository,
	tests::{
		mock::{
			RuntimeEvent, RuntimeOrigin, ShieldedPool, System, Test, TestAction, acc, executor,
			new_test_ext,
		},
		util::{
			KNOWN_ROOT, canonical_bytes, commitment, fund_pool, memo, nullifier, proof, setup_asset,
		},
	},
	types::{
		Commitment, EncryptedMemo, MAX_ENCRYPTED_MEMO_SIZE, MEMO_FORMAT_BYTE_INDEX,
		MEMO_FORMAT_HANDSHAKE, MEMO_FORMAT_TAGGED, MemoFormat, Nullifier,
	},
	validate_unsigned::{self as admit, codes},
};
use frame_support::{BoundedVec, assert_noop, assert_ok, traits::Hooks};
use sp_runtime::{
	DispatchError,
	transaction_validity::{InvalidTransaction, TransactionValidity, TransactionValidityError},
};

/// A full memo whose format byte is `format`; the rest is filler.
fn memo_as(format: u8) -> EncryptedMemo {
	let mut bytes = memo(0x33).as_bytes().to_vec();
	bytes[MEMO_FORMAT_BYTE_INDEX] = format;
	EncryptedMemo::from_bytes(&bytes).unwrap()
}

/// A memo from a wallet that predates the format: a random byte there.
fn legacy() -> EncryptedMemo {
	memo_as(0x9E)
}

fn schedule(from: u64) -> sp_runtime::DispatchResult {
	ShieldedPool::schedule_tagged_memos(RuntimeOrigin::root(), from)
}

/// Moves to block `n` and runs its `on_initialize`, as block import does.
fn run_to(n: u64) {
	System::set_block_number(n);
	ShieldedPool::on_initialize(n);
}

/// Schedules the rule at `from` and runs that block's `on_initialize`.
fn activate_at(from: u64) {
	assert_ok!(schedule(from));
	run_to(from);
}

/// Pool admission's answer for a refusal with `code`.
fn refused(code: u8) -> TransactionValidity {
	Err(TransactionValidityError::Invalid(
		InvalidTransaction::Custom(code),
	))
}

fn shield(seed: u8, memo: EncryptedMemo) -> sp_runtime::DispatchResult {
	ShieldOperation::execute::<Test>(
		acc(1),
		&[0x01; 128],
		ShieldRequest {
			asset_id: setup_asset(),
			amount: 500u128,
			commitment: commitment(seed),
			encrypted_memo: memo,
			circuit_version: 1,
		},
	)
}

/// What a spend needs in place: a known root and a funded pool. Kept out of
/// the spend helpers so `assert_noop` sees only the spend's own writes.
fn prepare_spends() {
	MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
	fund_pool(setup_asset(), 1_000u128);
}

fn transfer(seed: u8, memos: [EncryptedMemo; 2]) -> sp_runtime::DispatchResult {
	let mut second = canonical_bytes(seed);
	second[2] = 0x5A;
	PrivateTransferOperation::execute::<Test>(
		&proof(),
		TransferRequest {
			merkle_roots: [KNOWN_ROOT, KNOWN_ROOT],
			nullifiers: BoundedVec::try_from(vec![nullifier(seed), Nullifier::new([0u8; 32])])
				.unwrap(),
			commitments: BoundedVec::try_from(vec![commitment(seed), Commitment::new(second)])
				.unwrap(),
			memos: BoundedVec::try_from(memos.to_vec()).unwrap(),
			asset_id: 0u32,
			fee: 0u128,
			circuit_version: 1,
		},
	)
}

fn unshield(seed: u8, change_memo: EncryptedMemo) -> sp_runtime::DispatchResult {
	let asset_id = setup_asset();
	UnshieldOperation::execute::<Test>(
		&proof(),
		UnshieldRequest {
			merkle_root: KNOWN_ROOT,
			nullifier: nullifier(seed),
			asset_id,
			amount: 600u128,
			recipient: acc(2),
			fee: 0u128,
			change_commitment: canonical_bytes(seed.wrapping_add(0x40)),
			change_memo,
			circuit_version: 1,
		},
	)
}

// ── scheduling ───────────────────────────────────────────────────────────────

#[test]
fn only_the_admin_schedules() {
	new_test_ext().execute_with(|| {
		System::set_block_number(1);
		assert_noop!(
			ShieldedPool::schedule_tagged_memos(RuntimeOrigin::signed(acc(1)), 5),
			DispatchError::BadOrigin
		);
	});
}

#[test]
fn the_start_must_be_a_future_block() {
	new_test_ext().execute_with(|| {
		System::set_block_number(5);
		assert_noop!(
			ShieldedPool::schedule_tagged_memos(RuntimeOrigin::root(), 5),
			Error::<Test>::TaggedMemosStartInPast
		);
		assert_ok!(ShieldedPool::schedule_tagged_memos(
			RuntimeOrigin::root(),
			6
		));
		System::assert_last_event(RuntimeEvent::ShieldedPool(
			PalletEvent::TaggedMemosScheduled { from: 6 },
		));
	});
}

#[test]
fn the_start_moves_until_the_rule_is_in_force_and_never_after() {
	new_test_ext().execute_with(|| {
		System::set_block_number(1);
		assert_ok!(ShieldedPool::schedule_tagged_memos(
			RuntimeOrigin::root(),
			10
		));
		assert_ok!(ShieldedPool::schedule_tagged_memos(
			RuntimeOrigin::root(),
			4
		));
		assert_eq!(TaggedMemosFrom::<Test>::get(), Some(4));

		System::set_block_number(4);
		ShieldedPool::on_initialize(4);

		assert_noop!(
			ShieldedPool::schedule_tagged_memos(RuntimeOrigin::root(), 20),
			Error::<Test>::TaggedMemosAlreadyActive
		);
	});
}

// ── the recorded leaf ────────────────────────────────────────────────────────

#[test]
fn the_first_leaf_is_recorded_once_at_the_start_block() {
	new_test_ext().execute_with(|| {
		System::set_block_number(1);
		assert_ok!(shield(1, legacy()));
		assert_ok!(shield(2, legacy()));
		assert_ok!(ShieldedPool::schedule_tagged_memos(
			RuntimeOrigin::root(),
			3
		));

		System::set_block_number(2);
		ShieldedPool::on_initialize(2);
		assert_eq!(TaggedMemosFromLeaf::<Test>::get(), None);

		System::set_block_number(3);
		ShieldedPool::on_initialize(3);
		// Two leaves before it: the first leaf under the rule is index 2.
		assert_eq!(TaggedMemosFromLeaf::<Test>::get(), Some(2));
		System::assert_last_event(RuntimeEvent::ShieldedPool(
			PalletEvent::TaggedMemosActivated { from_leaf: 2 },
		));

		assert_ok!(shield(3, memo_as(MEMO_FORMAT_TAGGED)));
		System::set_block_number(4);
		ShieldedPool::on_initialize(4);
		assert_eq!(
			TaggedMemosFromLeaf::<Test>::get(),
			Some(2),
			"never moves once recorded"
		);
	});
}

#[test]
fn a_start_reached_late_records_the_leaf_at_the_first_block_past_it() {
	new_test_ext().execute_with(|| {
		System::set_block_number(1);
		assert_ok!(ShieldedPool::schedule_tagged_memos(
			RuntimeOrigin::root(),
			3
		));
		System::set_block_number(7);
		ShieldedPool::on_initialize(7);
		assert_eq!(TaggedMemosFromLeaf::<Test>::get(), Some(0));
	});
}

// ── the check ────────────────────────────────────────────────────────────────

#[test]
fn before_the_start_any_memo_is_accepted() {
	new_test_ext().execute_with(|| {
		System::set_block_number(1);
		assert_ok!(ShieldedPool::schedule_tagged_memos(
			RuntimeOrigin::root(),
			10
		));
		prepare_spends();
		assert_ok!(shield(1, legacy()));
		assert_ok!(transfer(2, [legacy(), legacy()]));
		assert_ok!(unshield(3, legacy()));
	});
}

#[test]
fn a_shield_must_declare_its_format() {
	new_test_ext().execute_with(|| {
		activate_at(2);
		assert_noop!(shield(1, legacy()), Error::<Test>::MemoFormatOutdated);
		assert_ok!(shield(2, memo_as(MEMO_FORMAT_TAGGED)));
		assert_ok!(shield(3, memo_as(MEMO_FORMAT_HANDSHAKE)));
	});
}

#[test]
fn a_transfer_must_declare_the_format_of_both_memos() {
	new_test_ext().execute_with(|| {
		activate_at(2);
		prepare_spends();
		assert_noop!(
			transfer(1, [memo_as(MEMO_FORMAT_HANDSHAKE), legacy()]),
			Error::<Test>::MemoFormatOutdated
		);
		assert_ok!(transfer(
			2,
			[memo_as(MEMO_FORMAT_HANDSHAKE), memo_as(MEMO_FORMAT_TAGGED)]
		));
	});
}

#[test]
fn an_unshield_change_must_declare_its_format() {
	new_test_ext().execute_with(|| {
		activate_at(2);
		prepare_spends();
		assert_noop!(unshield(1, legacy()), Error::<Test>::MemoFormatOutdated);
		assert_ok!(unshield(2, memo_as(MEMO_FORMAT_TAGGED)));
	});
}

#[test]
fn the_rule_binds_from_the_start_block_even_before_its_hook() {
	// Pool admission validates against the next block on the parent's state,
	// before that block's `on_initialize` records the leaf.
	new_test_ext().execute_with(|| {
		System::set_block_number(1);
		assert_ok!(ShieldedPool::schedule_tagged_memos(
			RuntimeOrigin::root(),
			2
		));
		System::set_block_number(2);
		assert_eq!(TaggedMemosFromLeaf::<Test>::get(), None);
		assert_noop!(shield(1, legacy()), Error::<Test>::MemoFormatOutdated);
	});
}

// ── scheduling rules ─────────────────────────────────────────────────────────

#[test]
fn a_start_in_the_past_is_refused() {
	new_test_ext().execute_with(|| {
		System::set_block_number(5);
		for from in [0, 1, 4, 5] {
			assert_noop!(schedule(from), Error::<Test>::TaggedMemosStartInPast);
		}
		assert_eq!(TaggedMemosFrom::<Test>::get(), None);
	});
}

#[test]
fn the_same_start_can_be_scheduled_twice() {
	new_test_ext().execute_with(|| {
		System::set_block_number(1);
		assert_ok!(schedule(6));
		assert_ok!(schedule(6));
		assert_eq!(TaggedMemosFrom::<Test>::get(), Some(6));
		System::assert_last_event(RuntimeEvent::ShieldedPool(
			PalletEvent::TaggedMemosScheduled { from: 6 },
		));
	});
}

/// No upper bound: a start far ahead binds nothing, and moving it back is how a
/// pending start is called off or corrected.
#[test]
fn a_far_start_binds_nothing_and_can_be_moved_back() {
	new_test_ext().execute_with(|| {
		System::set_block_number(1);
		assert_ok!(schedule(u64::MAX));
		run_to(1_000);
		assert!(!memo_format::is_active::<Test>());
		assert_eq!(TaggedMemosFromLeaf::<Test>::get(), None);
		assert_ok!(shield(1, legacy()));

		assert_ok!(schedule(1_001));
		run_to(1_001);
		assert_eq!(TaggedMemosFromLeaf::<Test>::get(), Some(1));
	});
}

/// The start is fixed from the start block on, even before that block's hook
/// recorded the leaf (another pallet's hook running first, say): admission has
/// been enforcing the rule for that block already.
#[test]
fn the_start_is_fixed_once_its_block_is_reached() {
	new_test_ext().execute_with(|| {
		System::set_block_number(1);
		assert_ok!(schedule(5));
		System::set_block_number(5);
		assert!(memo_format::is_active::<Test>());
		assert_noop!(schedule(9), Error::<Test>::TaggedMemosAlreadyActive);
		assert_noop!(schedule(u64::MAX), Error::<Test>::TaggedMemosAlreadyActive);
	});
}

#[test]
fn a_refused_schedule_emits_nothing() {
	new_test_ext().execute_with(|| {
		System::set_block_number(5);
		let _ = schedule(3);
		let _ = ShieldedPool::schedule_tagged_memos(RuntimeOrigin::signed(acc(1)), 9);
		assert!(System::events().is_empty());
	});
}

// ── the recorded leaf against multi-output calls ─────────────────────────────

/// The rule is per block and the leaf is recorded before any extrinsic of the
/// start block, so a two-output transfer never straddles it: in block `from-1`
/// both outputs land below the leaf under the old rules, from block `from` on
/// both land at or past it and both are checked.
#[test]
fn a_two_output_transfer_never_straddles_the_recorded_leaf() {
	new_test_ext().execute_with(|| {
		let declared = || [memo_as(MEMO_FORMAT_TAGGED), memo_as(MEMO_FORMAT_HANDSHAKE)];
		let leaf_of = |c: Commitment| crate::Pallet::<Test>::get_leaf_index(&c);
		System::set_block_number(1);
		prepare_spends();
		assert_ok!(schedule(3));

		// from - 1: undeclared memos still go in, at leaves 0 and 1.
		run_to(2);
		assert_ok!(transfer(1, [legacy(), legacy()]));
		assert_eq!(TaggedMemosFromLeaf::<Test>::get(), None);

		// from: the leaf is the next one, 2.
		run_to(3);
		assert_eq!(TaggedMemosFromLeaf::<Test>::get(), Some(2));
		// Its first output would be the recorded leaf, its second the one after:
		// either undeclared refuses the whole call.
		assert_noop!(
			transfer(2, [legacy(), memo_as(MEMO_FORMAT_TAGGED)]),
			Error::<Test>::MemoFormatOutdated
		);
		assert_noop!(
			transfer(2, [memo_as(MEMO_FORMAT_TAGGED), legacy()]),
			Error::<Test>::MemoFormatOutdated
		);
		assert_ok!(transfer(2, declared()));
		assert_eq!(leaf_of(commitment(2)), Some(2));

		// from + 1: the same, and the recorded leaf never moves.
		run_to(4);
		assert_noop!(
			transfer(3, [legacy(), legacy()]),
			Error::<Test>::MemoFormatOutdated
		);
		assert_ok!(transfer(3, declared()));
		assert_eq!(leaf_of(commitment(3)), Some(4));
		assert_eq!(TaggedMemosFromLeaf::<Test>::get(), Some(2));
	});
}

/// Every leaf from the recorded one on carries a declared memo.
#[test]
fn every_memo_from_the_recorded_leaf_on_is_declared() {
	new_test_ext().execute_with(|| {
		System::set_block_number(1);
		prepare_spends();
		assert_ok!(shield(1, legacy()));
		assert_ok!(transfer(2, [legacy(), legacy()]));
		activate_at(2);
		assert_ok!(shield(3, memo_as(MEMO_FORMAT_HANDSHAKE)));
		assert_ok!(transfer(
			4,
			[memo_as(MEMO_FORMAT_TAGGED), memo_as(MEMO_FORMAT_TAGGED)]
		));
		assert_ok!(unshield(5, memo_as(MEMO_FORMAT_TAGGED)));

		let from_leaf = TaggedMemosFromLeaf::<Test>::get().unwrap();
		assert_eq!(from_leaf, 3);
		let size = MerkleRepository::get_tree_size::<Test>();
		assert_eq!(size, 7);
		for index in 0..size {
			let leaf = MerkleRepository::get_leaf::<Test>(index).unwrap();
			let memo = crate::pallet::CommitmentMemos::<Test>::get(leaf).unwrap();
			assert_eq!(memo.format().is_some(), index >= from_leaf, "leaf {index}");
		}
	});
}

// ── bound spends and admission ───────────────────────────────────────────────

fn bound_with_change(seed: u8, change_memo: EncryptedMemo) -> BoundSpendRequest<Test> {
	BoundSpendRequest {
		spend: UnshieldRequest {
			merkle_root: KNOWN_ROOT,
			nullifier: nullifier(seed),
			asset_id: setup_asset(),
			amount: 300u128,
			recipient: executor(),
			fee: 0u128,
			change_commitment: canonical_bytes(seed.wrapping_add(0x40)),
			change_memo,
			circuit_version: 1,
		},
		action: TestAction::Keep,
	}
}

#[test]
fn a_bound_spend_change_must_declare_its_format() {
	new_test_ext().execute_with(|| {
		activate_at(2);
		prepare_spends();
		assert_eq!(
			admit::validate_bound_spend::<Test>(Some(&proof()), &bound_with_change(1, legacy())),
			refused(codes::MEMO_FORMAT_OUTDATED)
		);
		assert_noop!(
			BoundSpendOperation::execute::<Test>(&proof(), bound_with_change(1, legacy())),
			Error::<Test>::MemoFormatOutdated
		);
		let declared = bound_with_change(2, memo_as(MEMO_FORMAT_HANDSHAKE));
		assert!(admit::validate_bound_spend::<Test>(Some(&proof()), &declared).is_ok());
		assert_ok!(BoundSpendOperation::execute::<Test>(&proof(), declared));
	});
}

/// A spend admitted in block `from - 1` is checked again when the start block
/// includes it (`pre_dispatch`, no proof), so it never reaches the dispatch.
#[test]
fn a_spend_admitted_before_the_start_is_refused_in_the_start_block() {
	new_test_ext().execute_with(|| {
		System::set_block_number(1);
		prepare_spends();
		assert_ok!(schedule(3));
		let legacy_unshield = UnshieldRequest::<Test> {
			merkle_root: KNOWN_ROOT,
			nullifier: nullifier(1),
			asset_id: setup_asset(),
			amount: 100u128,
			recipient: acc(2),
			fee: 0u128,
			change_commitment: canonical_bytes(0x41),
			change_memo: legacy(),
			circuit_version: 1,
		};
		// Admission for block 2 runs on block 1's state, with the number bumped.
		System::set_block_number(2);
		assert!(admit::validate_unshield::<Test>(Some(&proof()), &legacy_unshield).is_ok());

		run_to(3);
		assert_eq!(
			admit::validate_unshield::<Test>(None, &legacy_unshield),
			refused(codes::MEMO_FORMAT_OUTDATED)
		);
	});
}

#[test]
fn one_undeclared_memo_refuses_a_whole_shield_batch() {
	new_test_ext().execute_with(|| {
		use frame_support::traits::Currency;
		activate_at(2);
		crate::tests::mock::Balances::make_free_balance_be(&acc(1), 10_000);
		let item = |seed: u8, memo: EncryptedMemo| {
			(
				setup_asset(),
				500u128,
				commitment(seed),
				memo,
				BoundedVec::try_from(vec![0x01u8; 128]).unwrap(),
				1u32,
			)
		};
		let batch = BoundedVec::try_from(vec![
			item(1, memo_as(MEMO_FORMAT_TAGGED)),
			item(2, legacy()),
		])
		.unwrap();
		assert_noop!(
			ShieldedPool::shield_batch(RuntimeOrigin::signed(acc(1)), batch),
			Error::<Test>::MemoFormatOutdated
		);
	});
}

// ── what a memo declares ─────────────────────────────────────────────────────

/// A public memo (zero ephemeral key) gets no exemption; a dummy memo carries
/// the TAGGED byte, as `@orbinum/protocol`'s `MemoFormat.dummy()` builds it,
/// while the all-zero dummy of older wallets is refused like any undeclared memo.
#[test]
fn public_and_dummy_memos_declare_a_format_like_any_other() {
	new_test_ext().execute_with(|| {
		activate_at(2);
		let size = MAX_ENCRYPTED_MEMO_SIZE as usize;

		let mut public = memo_as(MEMO_FORMAT_TAGGED).as_bytes().to_vec();
		public[size - 32..].fill(0);
		assert_ok!(shield(1, EncryptedMemo::from_bytes(&public).unwrap()));

		let mut undeclared_public = public.clone();
		undeclared_public[MEMO_FORMAT_BYTE_INDEX] = 0x9E;
		assert_noop!(
			shield(2, EncryptedMemo::from_bytes(&undeclared_public).unwrap()),
			Error::<Test>::MemoFormatOutdated
		);

		let mut dummy = vec![0u8; size];
		dummy[MEMO_FORMAT_BYTE_INDEX] = MEMO_FORMAT_TAGGED;
		assert_ok!(shield(3, EncryptedMemo::from_bytes(&dummy).unwrap()));

		let old_dummy = EncryptedMemo::from_bytes(&vec![0u8; size]).unwrap();
		assert_noop!(shield(4, old_dummy), Error::<Test>::MemoFormatOutdated);
	});
}

/// A memo that is not full size is refused as such, whatever its second byte
/// holds, before and after the start.
#[test]
fn a_short_memo_is_refused_for_its_size_not_its_format() {
	new_test_ext().execute_with(|| {
		let short = EncryptedMemo::new(vec![MEMO_FORMAT_TAGGED; 32]).unwrap();
		assert_eq!(short.format(), None);
		System::set_block_number(1);
		assert_noop!(shield(1, short.clone()), Error::<Test>::InvalidMemoSize);
		activate_at(2);
		assert_noop!(shield(1, short.clone()), Error::<Test>::InvalidMemoSize);
		assert!(matches!(
			memo_format::ensure_storable::<Test>(&[memo_as(MEMO_FORMAT_TAGGED), short]),
			Err(Error::<Test>::InvalidMemoSize)
		));
		assert!(matches!(
			memo_format::ensure_storable::<Test>(&[EncryptedMemo::default()]),
			Err(Error::<Test>::InvalidMemoSize)
		));
		assert!(memo_format::ensure_storable::<Test>(&[]).is_ok());
	});
}

#[test]
fn only_the_two_known_bytes_declare_a_format() {
	for byte in 0..=u8::MAX {
		let expected = match byte {
			MEMO_FORMAT_TAGGED => Some(MemoFormat::Tagged),
			MEMO_FORMAT_HANDSHAKE => Some(MemoFormat::Handshake),
			_ => None,
		};
		assert_eq!(MemoFormat::from_byte(byte), expected, "byte {byte:#04x}");
		assert_eq!(memo_as(byte).format(), expected, "byte {byte:#04x}");
		if let Some(format) = expected {
			assert_eq!(format.byte(), byte);
		}
	}
}

/// The memo layout is wire format shared with `@orbinum/protocol`
/// (`MEMO_FORMAT_OFFSET`, `MEMO_FORMAT_TAGGED`, `MEMO_FORMAT_HANDSHAKE`,
/// `ENCRYPTED_MEMO_SIZE`), which pins the same values: change both or neither.
#[test]
fn the_memo_format_constants_are_stable() {
	assert_eq!(MAX_ENCRYPTED_MEMO_SIZE, 180);
	assert_eq!(MEMO_FORMAT_BYTE_INDEX, 1);
	assert_eq!(MEMO_FORMAT_TAGGED, 0x01);
	assert_eq!(MEMO_FORMAT_HANDSHAKE, 0x02);
	assert_eq!(crate::validate_unsigned::codes::MEMO_FORMAT_OUTDATED, 15);
}
