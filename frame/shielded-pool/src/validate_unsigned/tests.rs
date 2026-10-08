//! Pool admission of `private_transfer` and `unshield`: rejection codes, pool
//! tags, the fee floor, solvency, memo shape and the proof.

use super::{TX_LONGEVITY, codes};
use crate::{
	mock::{Test, acc, new_test_ext},
	operations::{private_transfer::TransferRequest, unshield::UnshieldRequest},
	storage::{MerkleRepository, NullifierRepository, PoolBalanceRepository},
	tests::{KNOWN_ROOT, memo, nullifier, nullifiers_of, proof},
	types::{Commitment, EncryptedMemo, Hash, Nullifier},
};
use frame_support::{BoundedVec, pallet_prelude::ConstU32};
use sp_runtime::transaction_validity::TransactionValidity;

/// A full memo, the only shape a spend's outputs accept.
fn full_memo() -> EncryptedMemo {
	memo(0x0A)
}

/// A well-formed transfer with the given public values: two canonical
/// commitments with a full memo each, and a dummy second input when only one
/// nullifier is given.
fn transfer_request(
	merkle_root: &Hash,
	nullifiers: &BoundedVec<Nullifier, ConstU32<2>>,
	fee: u128,
	circuit_version: u32,
) -> TransferRequest<Test> {
	let mut nullifiers = nullifiers.clone();
	while nullifiers.len() < 2 {
		nullifiers.try_push(Nullifier::new([0u8; 32])).unwrap();
	}
	let commitment = |i: u8| {
		let mut bytes = [0u8; 32];
		bytes[0] = i + 1;
		bytes[1] = 0xC0;
		Commitment::new(bytes)
	};
	TransferRequest {
		merkle_roots: [*merkle_root; 2],
		nullifiers,
		commitments: vec![commitment(0), commitment(1)].try_into().unwrap(),
		memos: vec![full_memo(); 2].try_into().unwrap(),
		asset_id: 0,
		fee,
		circuit_version,
	}
}

/// A well-formed total unshield with the given public values.
fn unshield_request(
	merkle_root: &Hash,
	nullifier: &Nullifier,
	asset_id: u32,
	amount: u128,
	fee: u128,
	circuit_version: u32,
) -> UnshieldRequest<Test> {
	UnshieldRequest {
		merkle_root: *merkle_root,
		nullifier: *nullifier,
		asset_id,
		amount,
		recipient: acc(2),
		fee,
		change_commitment: [0u8; 32],
		change_memo: EncryptedMemo::default(),
		circuit_version,
	}
}

/// Pool admission, proof included.
fn validate_private_transfer(
	merkle_root: &Hash,
	nullifiers: &BoundedVec<Nullifier, ConstU32<2>>,
	fee: &u128,
	circuit_version: u32,
) -> TransactionValidity {
	let req = transfer_request(merkle_root, nullifiers, *fee, circuit_version);
	super::validate_private_transfer(Some(&proof()), &req)
}

/// Pool admission, proof included.
fn validate_unshield(
	merkle_root: &Hash,
	nullifier: &Nullifier,
	asset_id: &u32,
	amount: &u128,
	fee: &u128,
	circuit_version: u32,
) -> TransactionValidity {
	let req = unshield_request(
		merkle_root,
		nullifier,
		*asset_id,
		*amount,
		*fee,
		circuit_version,
	);
	super::validate_unshield(Some(&proof()), &req)
}

/// Rejection codes reach wallets and relayers as bare `Custom(N)`, so they are
/// part of the observable interface: pin them here, and retire a number rather
/// than reuse it for a new meaning.
#[test]
fn rejection_codes_are_stable() {
	assert_eq!(codes::UNKNOWN_ROOT, 1);
	assert_eq!(codes::ALL_INPUTS_DUMMY, 2);
	assert_eq!(codes::INSUFFICIENT_POOL_BALANCE, 3);
	assert_eq!(codes::AMOUNT_OVERFLOW, 4);
	assert_eq!(codes::UNSUPPORTED_CIRCUIT_VERSION, 10);
	assert_eq!(codes::INVALID_MEMO, 11);
	assert_eq!(codes::INVALID_PROOF, 12);
	assert_eq!(codes::INVALID_SPEND, 13);
}

// ── validate_private_transfer ────────────────────────────────────────────────

#[test]
fn private_transfer_valid_transaction() {
	new_test_ext().execute_with(|| {
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
		let result = validate_private_transfer(&KNOWN_ROOT, &nullifiers_of(&[0x01]), &0u128, 1);
		assert!(result.is_ok());
	});
}

#[test]
fn private_transfer_unknown_root_rejected() {
	new_test_ext().execute_with(|| {
		let result = validate_private_transfer(&[0xFFu8; 32], &nullifiers_of(&[0x01]), &0u128, 1);
		assert!(result.is_err());
	});
}

/// A dummy slot must repeat the real input's root: another known root (a sealed
/// tree's) or an unknown one is turned away before the proof is checked.
#[test]
fn private_transfer_dummy_root_that_differs_rejected() {
	use sp_runtime::transaction_validity::{InvalidTransaction, TransactionValidityError};
	new_test_ext().execute_with(|| {
		MerkleRepository::insert_sealed_root::<Test>(0, [0x5E; 32]);
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
		for dummy_root in [[0x5E; 32], [0xFF; 32]] {
			let mut req = transfer_request(&KNOWN_ROOT, &nullifiers_of(&[0x01]), 0, 3);
			req.merkle_roots[1] = dummy_root;
			assert_eq!(
				super::validate_private_transfer(Some(&proof()), &req),
				Err(TransactionValidityError::Invalid(
					InvalidTransaction::Custom(codes::INVALID_SPEND)
				))
			);
		}
	});
}

/// Two real inputs from two trees: an unknown root in either slot gets the
/// unknown-root code.
#[test]
fn private_transfer_unknown_root_in_either_real_slot_rejected() {
	use sp_runtime::transaction_validity::{InvalidTransaction, TransactionValidityError};
	new_test_ext().execute_with(|| {
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
		for slot in 0..2 {
			let mut req = transfer_request(&KNOWN_ROOT, &nullifiers_of(&[0x01, 0x02]), 0, 3);
			req.merkle_roots[slot] = [0xFF; 32];
			assert_eq!(
				super::validate_private_transfer(Some(&proof()), &req),
				Err(TransactionValidityError::Invalid(
					InvalidTransaction::Custom(codes::UNKNOWN_ROOT)
				))
			);
		}
	});
}

#[test]
fn private_transfer_nullifier_used_rejected() {
	new_test_ext().execute_with(|| {
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
		let n = nullifier(0x05);
		NullifierRepository::mark_as_used::<Test>(n, 1u64);
		let result = validate_private_transfer(&KNOWN_ROOT, &nullifiers_of(&[0x05]), &0u128, 1);
		assert!(result.is_err());
	});
}

#[test]
fn private_transfer_two_nullifiers_one_used_rejected() {
	new_test_ext().execute_with(|| {
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
		let used = nullifier(0x10);
		NullifierRepository::mark_as_used::<Test>(used, 1u64);
		// 0x10 is used, 0x11 is fresh — full list should still fail
		let result =
			validate_private_transfer(&KNOWN_ROOT, &nullifiers_of(&[0x10, 0x11]), &0u128, 1);
		assert!(result.is_err());
	});
}

#[test]
fn private_transfer_with_fee_builds_valid_transaction() {
	new_test_ext().execute_with(|| {
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
		let result = validate_private_transfer(
			&KNOWN_ROOT,
			&nullifiers_of(&[0xA1, 0xA2]),
			&100u128, // non-zero fee,
			1,
		);
		assert!(result.is_ok());
	});
}

#[test]
fn private_transfer_dummy_nullifier_zero_not_stale() {
	// A dummy input carries nullifier = [0u8; 32].
	// It must never be treated as "already used" even if [0u8;32] happened to
	// appear in the set (it cannot be inserted from mark_as_used, but this
	// confirms the skip logic).
	new_test_ext().execute_with(|| {
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
		// [0u8;32] is the dummy sentinel — should be ignored by validation
		let mut nullifiers: BoundedVec<Nullifier, ConstU32<2>> = BoundedVec::new();
		nullifiers.try_push(nullifier(0x01)).ok();
		nullifiers.try_push(Nullifier::new([0u8; 32])).ok(); // dummy
		let result = validate_private_transfer(&KNOWN_ROOT, &nullifiers, &0u128, 1);
		assert!(
			result.is_ok(),
			"dummy nullifier should not cause Stale rejection"
		);
	});
}

#[test]
fn private_transfer_real_nullifier_still_checked_alongside_dummy() {
	// When the real nullifier (non-zero) is already used, the tx must be
	// rejected even if the second slot contains a dummy.
	new_test_ext().execute_with(|| {
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
		let real = nullifier(0xBB);
		NullifierRepository::mark_as_used::<Test>(real, 1u64);
		let mut nullifiers: BoundedVec<Nullifier, ConstU32<2>> = BoundedVec::new();
		nullifiers.try_push(real).ok();
		nullifiers.try_push(Nullifier::new([0u8; 32])).ok(); // dummy
		let result = validate_private_transfer(&KNOWN_ROOT, &nullifiers, &0u128, 1);
		assert!(
			result.is_err(),
			"used real nullifier must still be rejected"
		);
	});
}

#[test]
fn private_transfer_all_dummy_nullifiers_rejected() {
	// Both nullifiers are [0u8;32] → no real input note → must be rejected
	// as anti-spam (Custom(2)) before entering the tx pool.
	new_test_ext().execute_with(|| {
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
		let mut nullifiers: BoundedVec<Nullifier, ConstU32<2>> = BoundedVec::new();
		nullifiers.try_push(Nullifier::new([0u8; 32])).ok();
		nullifiers.try_push(Nullifier::new([0u8; 32])).ok();
		let result = validate_private_transfer(&KNOWN_ROOT, &nullifiers, &0u128, 1);
		assert!(result.is_err(), "all-dummy-nullifier tx must be rejected");
	});
}

// ── validate_unshield ────────────────────────────────────────────────────────

#[test]
fn unshield_valid_transaction() {
	new_test_ext().execute_with(|| {
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
		PoolBalanceRepository::set_asset_balance::<Test>(0, 1_000u128);
		let result = validate_unshield(&KNOWN_ROOT, &nullifier(0x10), &0u32, &500u128, &0u128, 1);
		assert!(result.is_ok());
	});
}

#[test]
fn unshield_unknown_root_rejected() {
	new_test_ext().execute_with(|| {
		PoolBalanceRepository::set_asset_balance::<Test>(0, 1_000u128);
		let result = validate_unshield(&[0xEEu8; 32], &nullifier(0x10), &0u32, &500u128, &0u128, 1);
		assert!(result.is_err());
	});
}

#[test]
fn unshield_nullifier_used_rejected() {
	new_test_ext().execute_with(|| {
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
		PoolBalanceRepository::set_asset_balance::<Test>(0, 1_000u128);
		let n = nullifier(0x20);
		NullifierRepository::mark_as_used::<Test>(n, 1u64);
		let result = validate_unshield(&KNOWN_ROOT, &n, &0u32, &500u128, &0u128, 1);
		assert!(result.is_err());
	});
}

#[test]
fn unshield_insufficient_pool_balance_rejected() {
	new_test_ext().execute_with(|| {
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
		PoolBalanceRepository::set_asset_balance::<Test>(0, 50u128); // only 50
		let result = validate_unshield(
			&KNOWN_ROOT,
			&nullifier(0x30),
			&0u32,
			&100u128, // 100 > 50
			&0u128,
			1,
		);
		assert!(result.is_err());
	});
}

#[test]
fn unshield_amount_plus_fee_checked_against_pool_balance() {
	new_test_ext().execute_with(|| {
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
		// pool has 150; amount=100 + fee=60 = 160 > 150 → reject
		PoolBalanceRepository::set_asset_balance::<Test>(0, 150u128);
		let result = validate_unshield(&KNOWN_ROOT, &nullifier(0x40), &0u32, &100u128, &60u128, 1);
		assert!(result.is_err());
	});
}

#[test]
fn unshield_exact_pool_balance_accepted() {
	new_test_ext().execute_with(|| {
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
		// amount=100 + fee=50 = 150 == pool → accept
		PoolBalanceRepository::set_asset_balance::<Test>(0, 150u128);
		let result = validate_unshield(&KNOWN_ROOT, &nullifier(0x50), &0u32, &100u128, &50u128, 1);
		assert!(result.is_ok());
	});
}

// ── fee floor (anti-spam) ────────────────────────────────────────────────────
//
// Both validate_private_transfer and validate_unshield enforce the minimum
// relay fee set by T::Relayer::min_relay_fee().
// The mock returns 0 by default; mock_set_min_relay_fee lets individual
// tests raise the floor to exercise the Payment rejection path.

#[test]
fn private_transfer_fee_below_minimum_rejected() {
	new_test_ext().execute_with(|| {
		crate::mock::mock_set_min_relay_fee(100);
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
		// fee=50 < min_relay_fee=100 → InvalidTransaction::Payment
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
		crate::mock::mock_set_min_relay_fee(100);
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
		// fee == min_relay_fee → accept
		let result = validate_private_transfer(&KNOWN_ROOT, &nullifiers_of(&[0x01]), &100u128, 1);
		assert!(result.is_ok(), "fee equal to minimum must be accepted");
	});
}

#[test]
fn unshield_fee_below_minimum_rejected() {
	new_test_ext().execute_with(|| {
		crate::mock::mock_set_min_relay_fee(200);
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
		PoolBalanceRepository::set_asset_balance::<Test>(0, 10_000u128);
		// fee=50 < min_relay_fee=200 → InvalidTransaction::Payment
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
		crate::mock::mock_set_min_relay_fee(200);
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
		PoolBalanceRepository::set_asset_balance::<Test>(0, 10_000u128);
		// fee == min_relay_fee → accept (pool has enough for amount+fee)
		let result = validate_unshield(&KNOWN_ROOT, &nullifier(0x60), &0u32, &100u128, &200u128, 1);
		assert!(result.is_ok(), "fee equal to minimum must be accepted");
	});
}

// ── one note, one pool entry ─────────────────────────────────────────────────

/// Two submissions of the same spend collide in the pool, whoever sends them.
///
/// The tag is the nullifier alone. The fee recipient is not a call argument, so
/// a "spoofed copy pointed at my own account" is not expressible: resubmitting
/// someone else's spend produces a byte-identical call that collides with the
/// original instead of racing it.
#[test]
fn resubmitting_the_same_spend_collides_with_the_original() {
	new_test_ext().execute_with(|| {
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
		PoolBalanceRepository::set_asset_balance::<Test>(0, 1000u128);
		let n = nullifier(0x61);

		let a = validate_unshield(&KNOWN_ROOT, &n, &0u32, &100u128, &10u128, 1).unwrap();
		let b = validate_unshield(&KNOWN_ROOT, &n, &0u32, &100u128, &10u128, 1).unwrap();

		assert_eq!(
			a.provides, b.provides,
			"the same note being spent must occupy one pool entry"
		);
		assert_eq!(a.priority, b.priority, "priority comes from the fee alone");
	});
}

/// Same property for `private_transfer`: one note, one pool entry.
#[test]
fn resubmitting_the_same_transfer_collides_with_the_original() {
	new_test_ext().execute_with(|| {
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
		let ns = nullifiers_of(&[0x63]);

		let a = validate_private_transfer(&KNOWN_ROOT, &ns, &10u128, 1).unwrap();
		let b = validate_private_transfer(&KNOWN_ROOT, &ns, &10u128, 1).unwrap();
		assert_eq!(a.provides, b.provides);
	});
}

/// Unsigned transactions carry a bounded longevity (not `MAX`), so an
/// un-included transaction does not persist in the pool indefinitely.
#[test]
fn unsigned_txs_have_bounded_longevity() {
	new_test_ext().execute_with(|| {
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
		PoolBalanceRepository::set_asset_balance::<Test>(0, 1000u128);

		let t =
			validate_private_transfer(&KNOWN_ROOT, &nullifiers_of(&[0x90]), &10u128, 1).unwrap();
		assert_eq!(t.longevity, TX_LONGEVITY);
		assert!(t.longevity < sp_runtime::transaction_validity::TransactionLongevity::MAX);

		let u =
			validate_unshield(&KNOWN_ROOT, &nullifier(0x91), &0u32, &100u128, &10u128, 1).unwrap();
		assert_eq!(u.longevity, TX_LONGEVITY);
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

// ── adversarial: mempool tag manipulation ────────────────────────────────────
//
// The `provides` tag decides which pool entries are mutually exclusive.
// Getting it wrong is not a crash — it is censorship or fee theft: an
// attacker who can mint a colliding variant of someone else's transaction
// can displace it, and one who can mint NON-colliding variants of the same
// spend can flood the pool with entries that all spend one note.

/// Two transactions spending the SAME note must be mutually exclusive in the
/// pool. If their tags differ, both sit in the pool and the second is dead
/// weight the node still gossips and validates.
#[test]
fn attack_same_nullifier_different_root_still_collides_in_the_pool() {
	new_test_ext().execute_with(|| {
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
		let other_root = [0x22u8; 32];
		MerkleRepository::add_historic_poseidon_root::<Test>(other_root);

		let nulls = nullifiers_of(&[0x42]);
		let a = validate_private_transfer(&KNOWN_ROOT, &nulls, &0u128, 1).unwrap();
		let b = validate_private_transfer(&other_root, &nulls, &0u128, 1).unwrap();

		assert_eq!(
			a.provides, b.provides,
			"same note spent twice must produce the same tag, whatever the root"
		);
	});
}

/// Dummy nullifiers carry no identity. Two DIFFERENT real spends that each
/// pad with a dummy must not be forced to collide through the dummy.
#[test]
fn attack_dummy_padding_does_not_make_unrelated_spends_collide() {
	new_test_ext().execute_with(|| {
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);

		let mut a_nulls: BoundedVec<Nullifier, ConstU32<2>> = BoundedVec::new();
		a_nulls.try_push(nullifier(0x51)).unwrap();
		a_nulls.try_push(Nullifier::new([0u8; 32])).unwrap();

		let mut b_nulls: BoundedVec<Nullifier, ConstU32<2>> = BoundedVec::new();
		b_nulls.try_push(nullifier(0x52)).unwrap();
		b_nulls.try_push(Nullifier::new([0u8; 32])).unwrap();

		let a = validate_private_transfer(&KNOWN_ROOT, &a_nulls, &0u128, 1).unwrap();
		let b = validate_private_transfer(&KNOWN_ROOT, &b_nulls, &0u128, 1).unwrap();

		assert_ne!(
			a.provides, b.provides,
			"unrelated spends must not collide just because both padded with a dummy"
		);
	});
}

/// Reordering the two inputs of the SAME spend must not mint a second pool
/// entry — otherwise one note yields two admissible transactions.
#[test]
fn attack_reordering_inputs_does_not_mint_a_second_pool_entry() {
	new_test_ext().execute_with(|| {
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);

		let ab = nullifiers_of(&[0x61, 0x62]);
		let ba = nullifiers_of(&[0x62, 0x61]);

		let a = validate_private_transfer(&KNOWN_ROOT, &ab, &0u128, 1).unwrap();
		let b = validate_private_transfer(&KNOWN_ROOT, &ba, &0u128, 1).unwrap();

		let mut a_tags = a.provides.clone();
		let mut b_tags = b.provides.clone();
		a_tags.sort();
		b_tags.sort();
		assert_eq!(
			a_tags, b_tags,
			"the same pair of notes must produce the same tag set in any order"
		);
	});
}

/// Priority is the fee. An attacker must not be able to outrank an honest
/// transaction without actually paying more.
#[test]
fn attack_priority_tracks_the_fee_and_cannot_be_forged() {
	new_test_ext().execute_with(|| {
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
		let nulls = nullifiers_of(&[0x71]);

		let cheap = validate_private_transfer(&KNOWN_ROOT, &nulls, &10u128, 1).unwrap();
		let rich = validate_private_transfer(&KNOWN_ROOT, &nulls, &1_000u128, 1).unwrap();

		assert!(
			rich.priority > cheap.priority,
			"a higher fee must buy higher priority, or fee bidding is broken"
		);
		assert_eq!(
			cheap.longevity, TX_LONGEVITY,
			"longevity must not vary with fee"
		);
		assert_eq!(rich.longevity, TX_LONGEVITY);
	});
}

/// A spent note must be refused at ADMISSION, not merely at execution:
/// otherwise every node re-validates and gossips a transaction that can
/// never succeed.
#[test]
fn attack_spent_note_is_refused_at_pool_admission() {
	new_test_ext().execute_with(|| {
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
		let n = nullifier(0x81);
		NullifierRepository::mark_as_used::<Test>(n, 1u64);

		let result = validate_private_transfer(&KNOWN_ROOT, &nullifiers_of(&[0x81]), &0u128, 1);
		assert_eq!(
			result.unwrap_err(),
			sp_runtime::transaction_validity::TransactionValidityError::Invalid(
				sp_runtime::transaction_validity::InvalidTransaction::Stale
			),
		);
	});
}

/// Two transfers that share only ONE input note (A+B and A+C) must be
/// mutually exclusive: note A can back exactly one pool entry. With a single
/// tag over the whole nullifier set these would not collide, so one note could
/// back unboundedly many admissible transactions — free mempool amplification,
/// since the fee is only charged on execution.
#[test]
fn attack_transfers_sharing_one_note_are_mutually_exclusive() {
	new_test_ext().execute_with(|| {
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);

		let ab = nullifiers_of(&[0x61, 0x62]);
		let ac = nullifiers_of(&[0x61, 0x63]);

		let a = validate_private_transfer(&KNOWN_ROOT, &ab, &0u128, 1).unwrap();
		let b = validate_private_transfer(&KNOWN_ROOT, &ac, &0u128, 1).unwrap();

		let shared = a.provides.iter().any(|t| b.provides.contains(t));
		assert!(
			shared,
			"spends sharing note A must share a tag, or A backs two pool entries"
		);
	});
}

/// Each real nullifier contributes its OWN tag — the property every
/// exclusion guarantee above rests on. A single concatenated tag silently
/// breaks all of them, so pin the cardinality directly.
#[test]
fn attack_each_nullifier_contributes_an_independent_tag() {
	new_test_ext().execute_with(|| {
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);

		let one =
			validate_private_transfer(&KNOWN_ROOT, &nullifiers_of(&[0x91]), &0u128, 1).unwrap();
		assert_eq!(one.provides.len(), 1, "one real input → one tag");

		let two = validate_private_transfer(&KNOWN_ROOT, &nullifiers_of(&[0x92, 0x93]), &0u128, 1)
			.unwrap();
		assert_eq!(
			two.provides.len(),
			2,
			"two real inputs → two independent tags"
		);

		// A dummy-padded single input must still yield exactly one tag.
		let mut padded: BoundedVec<Nullifier, ConstU32<2>> = BoundedVec::new();
		padded.try_push(nullifier(0x94)).unwrap();
		padded.try_push(Nullifier::new([0u8; 32])).unwrap();
		let p = validate_private_transfer(&KNOWN_ROOT, &padded, &0u128, 1).unwrap();
		assert_eq!(p.provides.len(), 1, "the dummy must not contribute a tag");
	});
}

/// A transfer and an unshield spending the SAME note must be mutually
/// exclusive in the pool.
///
/// With a tag prefix per operation, one of each could sit in the pool for a
/// single note: both propagate and get revalidated by every node, while at
/// most one can execute. A nullifier names a NOTE, not an operation, so both
/// share one tag namespace.
#[test]
fn attack_transfer_and_unshield_of_the_same_note_are_mutually_exclusive() {
	new_test_ext().execute_with(|| {
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
		PoolBalanceRepository::set_asset_balance::<Test>(0, 100_000u128);
		let n = nullifier(0x77);

		let transfer =
			validate_private_transfer(&KNOWN_ROOT, &nullifiers_of(&[0x77]), &10u128, 1).unwrap();
		let unshield = validate_unshield(&KNOWN_ROOT, &n, &0u32, &100u128, &10u128, 1).unwrap();

		assert_eq!(
			transfer.provides, unshield.provides,
			"one note must back one pool entry, whichever operation spends it"
		);
	});
}

// ── Solvency arithmetic ──────────────────────────────────────────────────────
//
// `amount + fee` is attacker-chosen and summed before the balance compare.
// A wrapping sum comes out SMALL, which passes the compare — so the overflow
// branch is what stops an unbackable spend from being gossiped.

/// `amount + fee` overflowing `Balance` must be refused, not wrapped.
///
/// Both operands come from the caller, so the sum is reachable: picking
/// `amount = MAX` and any non-zero fee wraps to a tiny total that clears the
/// pool-balance check. The result must be AMOUNT_OVERFLOW, never admission.
#[test]
fn attack_amount_plus_fee_overflow_is_refused_not_wrapped() {
	new_test_ext().execute_with(|| {
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
		// A pool holding almost nothing — a wrapped total would still clear it.
		PoolBalanceRepository::set_asset_balance::<Test>(0, 1u128);
		let n = nullifier(0x99);

		let got = validate_unshield(
			&KNOWN_ROOT,
			&n,
			&0u32,
			&u128::MAX,
			&1u128, // MAX + 1 wraps
			1,
		);

		assert_eq!(
			got,
			Err(codes::reject(codes::AMOUNT_OVERFLOW).into()),
			"a wrapping sum would admit a spend the pool cannot cover"
		);
	});
}

/// The solvency check is `>=`, so a spend of exactly the pool balance is
/// admissible and one planck more is not. Pins the boundary an attacker
/// probes for free, since admission costs nothing until execution.
#[test]
fn attack_solvency_boundary_is_exact() {
	new_test_ext().execute_with(|| {
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
		PoolBalanceRepository::set_asset_balance::<Test>(0, 1_000u128);

		// amount + fee == balance exactly.
		let exact = validate_unshield(&KNOWN_ROOT, &nullifier(0xA1), &0u32, &900u128, &100u128, 1);
		assert!(
			exact.is_ok(),
			"draining the pool exactly must be admissible"
		);

		// One planck over.
		let over = validate_unshield(&KNOWN_ROOT, &nullifier(0xA2), &0u32, &901u128, &100u128, 1);
		assert_eq!(
			over,
			Err(codes::reject(codes::INSUFFICIENT_POOL_BALANCE).into())
		);
	});
}

/// The fee counts against the pool, not just the amount.
///
/// Both leave the pool on execution, so a spend whose amount alone fits but
/// whose amount+fee does not must be refused — otherwise the fee is paid out
/// of a balance that was never there.
#[test]
fn attack_fee_counts_against_pool_solvency() {
	new_test_ext().execute_with(|| {
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
		PoolBalanceRepository::set_asset_balance::<Test>(0, 1_000u128);

		// amount == balance, leaving nothing for the fee.
		let got = validate_unshield(
			&KNOWN_ROOT,
			&nullifier(0xA3),
			&0u32,
			&1_000u128,
			&100u128,
			1,
		);
		assert_eq!(
			got,
			Err(codes::reject(codes::INSUFFICIENT_POOL_BALANCE).into()),
			"amount alone fits, but the fee also leaves the pool"
		);
	});
}

/// Solvency is tracked per asset: a rich asset must not underwrite a spend
/// against an empty one.
#[test]
fn attack_other_asset_balance_does_not_underwrite_this_one() {
	new_test_ext().execute_with(|| {
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
		PoolBalanceRepository::set_asset_balance::<Test>(0, u128::MAX / 2);
		// Asset 1 holds nothing.

		let got = validate_unshield(
			&KNOWN_ROOT,
			&nullifier(0xA4),
			&1u32,
			&1_000u128,
			&100u128,
			1,
		);
		assert_eq!(
			got,
			Err(codes::reject(codes::INSUFFICIENT_POOL_BALANCE).into())
		);
	});
}

// ── adversarial: spends across two trees ─────────────────────────────────────

/// A two-tree spend: two real notes, one proven against a sealed tree's root,
/// the other against the active window.
fn cross_tree_request(nullifiers: &[u8], roots: [Hash; 2]) -> TransferRequest<Test> {
	let mut req = transfer_request(&roots[0], &nullifiers_of(nullifiers), 0, 3);
	req.merkle_roots = roots;
	req
}

const SEALED_ROOT: Hash = [0x5E; 32];

fn register_two_trees() {
	MerkleRepository::insert_sealed_root::<Test>(0, SEALED_ROOT);
	MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
}

/// A copy of a pending two-tree spend with re-randomised proof bytes (Groth16
/// proofs are malleable without the witness) shares its tags and priority, so
/// it can neither sit beside the original nor displace it.
#[test]
fn attack_a_rerandomised_copy_of_a_two_tree_spend_cannot_displace_it() {
	new_test_ext().execute_with(|| {
		register_two_trees();
		let req = cross_tree_request(&[0x81, 0x82], [SEALED_ROOT, KNOWN_ROOT]);
		let other_proof: BoundedVec<u8, ConstU32<512>> = vec![0x02u8; 72].try_into().unwrap();
		let original = super::validate_private_transfer(Some(&proof()), &req).unwrap();
		let copy = super::validate_private_transfer(Some(&other_proof), &req).unwrap();
		assert_eq!(original.provides, copy.provides);
		assert_eq!(original.priority, copy.priority);
	});
}

/// Swapping the inputs together with their roots names the same two notes:
/// one tag set, so no second pool entry.
#[test]
fn attack_swapping_inputs_and_roots_does_not_mint_a_second_pool_entry() {
	new_test_ext().execute_with(|| {
		register_two_trees();
		let ab = cross_tree_request(&[0x83, 0x84], [SEALED_ROOT, KNOWN_ROOT]);
		let ba = cross_tree_request(&[0x84, 0x83], [KNOWN_ROOT, SEALED_ROOT]);
		let mut a = super::validate_private_transfer(Some(&proof()), &ab)
			.unwrap()
			.provides;
		let mut b = super::validate_private_transfer(Some(&proof()), &ba)
			.unwrap()
			.provides;
		a.sort();
		b.sort();
		assert_eq!(a, b);
	});
}

/// The same note in both slots, each slot naming a different tree's root:
/// one note cannot be spent twice in one transfer.
#[test]
fn attack_one_note_in_both_slots_across_two_roots_is_refused() {
	new_test_ext().execute_with(|| {
		register_two_trees();
		let req = cross_tree_request(&[0x85, 0x85], [SEALED_ROOT, KNOWN_ROOT]);
		assert!(super::validate_private_transfer(Some(&proof()), &req).is_err());
	});
}

/// A note already spent from one tree cannot be spent again naming another
/// tree's root: nullifiers do not depend on the tree.
#[test]
fn attack_a_spent_note_cannot_be_respent_from_another_tree() {
	new_test_ext().execute_with(|| {
		register_two_trees();
		NullifierRepository::mark_as_used::<Test>(nullifier(0x86), 1u64);
		let req = cross_tree_request(&[0x86, 0x87], [KNOWN_ROOT, SEALED_ROOT]);
		assert_eq!(
			super::validate_private_transfer(Some(&proof()), &req),
			Err(sp_runtime::transaction_validity::InvalidTransaction::Stale.into())
		);
	});
}

/// A root's non-canonical alias (`root + r`, the same field element) is not
/// a known root: roots compare as bytes, and only canonical ones are stored.
#[test]
fn attack_a_non_canonical_alias_of_a_known_root_is_unknown() {
	new_test_ext().execute_with(|| {
		let root = crate::tests::canonical_bytes(0x33);
		MerkleRepository::add_historic_poseidon_root::<Test>(root);
		let alias = crate::tests::field_twin(root);
		assert_ne!(alias, root);
		for roots in [[alias, root], [root, alias]] {
			let req = cross_tree_request(&[0x88, 0x89], roots);
			assert!(rejected_with(
				super::validate_private_transfer(Some(&proof()), &req),
				codes::UNKNOWN_ROOT
			));
		}
	});
}

/// An unshield's nullifier or change commitment given as its modular twin
/// (`x + r`): the same field element, so the proof would verify, but another
/// 32-byte identity on chain. Refused before the proof is checked.
#[test]
fn attack_a_non_canonical_unshield_nullifier_or_change_is_refused() {
	new_test_ext().execute_with(|| {
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
		PoolBalanceRepository::set_asset_balance::<Test>(0, 1_000u128);
		let base = unshield_request(&KNOWN_ROOT, &nullifier(0x8B), 0, 500, 0, 2);

		let mut aliased_nullifier = base.clone();
		aliased_nullifier.nullifier = Nullifier::new(crate::tests::field_twin(nullifier(0x8B).0));
		assert!(rejected_with(
			super::validate_unshield(Some(&proof()), &aliased_nullifier),
			codes::INVALID_SPEND
		));

		let change = crate::tests::canonical_bytes(0x8C);
		let mut aliased_change = base;
		aliased_change.amount = 400;
		aliased_change.change_commitment = crate::tests::field_twin(change);
		aliased_change.change_memo = full_memo();
		assert!(rejected_with(
			super::validate_unshield(Some(&proof()), &aliased_change),
			codes::INVALID_SPEND
		));
	});
}

/// Two dummy inputs naming two roots spend nothing: refused, nothing inserted.
#[test]
fn attack_two_dummies_with_differing_roots_are_refused() {
	new_test_ext().execute_with(|| {
		register_two_trees();
		let mut req = cross_tree_request(&[0x8A], [SEALED_ROOT, KNOWN_ROOT]);
		req.nullifiers = vec![Nullifier::new([0u8; 32]); 2].try_into().unwrap();
		assert!(super::validate_private_transfer(Some(&proof()), &req).is_err());
	});
}

// ── memo shape ───────────────────────────────────────────────────────────────

fn rejected_with(result: TransactionValidity, code: u8) -> bool {
	use sp_runtime::transaction_validity::{InvalidTransaction, TransactionValidityError};
	result
		== Err(TransactionValidityError::Invalid(
			InvalidTransaction::Custom(code),
		))
}

#[test]
fn transfer_memos_must_be_one_full_memo_per_output() {
	new_test_ext().execute_with(|| {
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
		let base = transfer_request(&KNOWN_ROOT, &nullifiers_of(&[0x01, 0x02]), 0, 1);
		let short = EncryptedMemo::new(vec![0x0A; 179]).unwrap();
		for memos in [vec![full_memo()], vec![full_memo(), short]] {
			let req = TransferRequest {
				memos: memos.try_into().unwrap(),
				..base.clone()
			};
			assert!(rejected_with(
				super::validate_private_transfer::<Test>(Some(&proof()), &req),
				codes::INVALID_MEMO
			));
		}
		assert!(super::validate_private_transfer::<Test>(Some(&proof()), &base).is_ok());
	});
}

#[test]
fn unshield_change_memo_is_absent_for_total_and_full_for_partial() {
	new_test_ext().execute_with(|| {
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
		PoolBalanceRepository::set_asset_balance::<Test>(0, 1_000);
		let total = unshield_request(&KNOWN_ROOT, &nullifier(0x31), 0, 100, 0, 1);
		let mut change = [0u8; 32];
		change[1] = 0xCC;
		let partial = UnshieldRequest {
			change_commitment: change,
			..total.clone()
		};
		let short = EncryptedMemo::new(vec![0x0A; 7]).unwrap();

		let cases = [
			(
				UnshieldRequest {
					change_memo: full_memo(),
					..total.clone()
				},
				false,
			),
			(partial.clone(), false),
			(
				UnshieldRequest {
					change_memo: short,
					..partial.clone()
				},
				false,
			),
			(
				UnshieldRequest {
					change_memo: full_memo(),
					..partial
				},
				true,
			),
			(total, true),
		];
		for (req, ok) in cases {
			let result = super::validate_unshield::<Test>(Some(&proof()), &req);
			if ok {
				assert!(result.is_ok(), "{req:?}");
			} else {
				assert!(rejected_with(result, codes::INVALID_MEMO), "{req:?}");
			}
		}
	});
}

// ── proof at admission, not in the block ─────────────────────────────────────

#[test]
#[cfg(not(feature = "skip-proof-verification"))]
fn an_invalid_proof_is_refused_at_admission() {
	new_test_ext().execute_with(|| {
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
		PoolBalanceRepository::set_asset_balance::<Test>(0, 1_000);
		crate::mock::set_mock_proof_valid(false);
		assert!(rejected_with(
			validate_private_transfer(&KNOWN_ROOT, &nullifiers_of(&[0x01]), &0u128, 1),
			codes::INVALID_PROOF
		));
		assert!(rejected_with(
			validate_unshield(&KNOWN_ROOT, &nullifier(0x41), &0, &100, &0, 1),
			codes::INVALID_PROOF
		));
	});
}

#[test]
#[cfg(not(feature = "skip-proof-verification"))]
fn admission_verifies_the_statement_the_extrinsic_would() {
	use crate::mock::{VerifiedStatement, verified_statements};
	new_test_ext().execute_with(|| {
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
		PoolBalanceRepository::set_asset_balance::<Test>(0, 1_000);
		let transfer = transfer_request(&KNOWN_ROOT, &nullifiers_of(&[0x01]), 0, 2);
		let unshield = unshield_request(&KNOWN_ROOT, &nullifier(0x42), 0, 100, 0, 2);
		assert!(super::validate_private_transfer::<Test>(Some(&proof()), &transfer).is_ok());
		assert!(super::validate_unshield::<Test>(Some(&proof()), &unshield).is_ok());
		assert_eq!(
			verified_statements(),
			vec![
				VerifiedStatement::Transfer(transfer.statement(), Some(2)),
				VerifiedStatement::Unshield(unshield.statement().unwrap(), Some(2)),
			]
		);
	});
}

/// In a block the dispatchable verifies; `pre_dispatch` must not pay a second
/// pairing the extrinsic weight does not cover.
#[test]
#[cfg(not(feature = "skip-proof-verification"))]
#[allow(deprecated)] // `ValidateUnsigned`, see `lib.rs`
fn pre_dispatch_runs_the_cheap_checks_only() {
	use crate::{Call, Pallet, mock::verified_statements};
	use sp_runtime::traits::ValidateUnsigned;
	new_test_ext().execute_with(|| {
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
		PoolBalanceRepository::set_asset_balance::<Test>(0, 1_000);
		crate::mock::set_mock_proof_valid(false);
		let call = Call::<Test>::unshield {
			proof: proof(),
			merkle_root: KNOWN_ROOT,
			nullifier: nullifier(0x43),
			asset_id: 0,
			amount: 100,
			recipient: acc(2),
			fee: 0,
			change_commitment: [0u8; 32],
			change_encrypted_memo: EncryptedMemo::default(),
			circuit_version: 1,
		};
		assert!(Pallet::<Test>::pre_dispatch(&call).is_ok());
		assert!(verified_statements().is_empty());
		assert!(rejected_with(
			Pallet::<Test>::validate_unsigned(
				sp_runtime::transaction_validity::TransactionSource::External,
				&call
			),
			codes::INVALID_PROOF
		));
	});
}

// ── nothing admitted may fail at dispatch ────────────────────────────────────

/// A spend that passes admission but fails in the block keeps its nullifier
/// unspent and pays nothing: free, repeatable block filler.
#[test]
fn transfers_the_dispatch_would_refuse_are_refused_at_admission() {
	new_test_ext().execute_with(|| {
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
		let base = transfer_request(&KNOWN_ROOT, &nullifiers_of(&[0x01, 0x02]), 0, 1);
		let twins = TransferRequest {
			commitments: vec![base.commitments[0]; 2].try_into().unwrap(),
			..base.clone()
		};
		assert!(rejected_with(
			super::validate_private_transfer::<Test>(Some(&proof()), &twins),
			codes::INVALID_SPEND
		));

		crate::merkle::MerkleTreeService::insert_leaf::<Test>(base.commitments[1]).unwrap();
		assert!(rejected_with(
			super::validate_private_transfer::<Test>(Some(&proof()), &base),
			codes::INVALID_SPEND
		));
	});
}

#[test]
fn unshields_the_dispatch_would_refuse_are_refused_at_admission() {
	use crate::Pallet;
	new_test_ext().execute_with(|| {
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
		PoolBalanceRepository::set_asset_balance::<Test>(0, 1_000);
		let base = unshield_request(&KNOWN_ROOT, &nullifier(0x51), 0, 100, 0, 1);
		let mut existing = [0u8; 32];
		existing[1] = 0xEE;
		crate::merkle::MerkleTreeService::insert_leaf::<Test>(Commitment::new(existing)).unwrap();

		let dead = [
			UnshieldRequest {
				amount: 0,
				fee: 100,
				..base.clone()
			},
			UnshieldRequest {
				recipient: Pallet::<Test>::pool_account_id(),
				..base.clone()
			},
			UnshieldRequest {
				recipient: sp_runtime::AccountId32::new([0u8; 32]),
				..base.clone()
			},
			UnshieldRequest {
				change_commitment: existing,
				change_memo: full_memo(),
				..base.clone()
			},
			UnshieldRequest {
				asset_id: 99,
				..base.clone()
			},
		];
		for req in dead {
			let result = super::validate_unshield::<Test>(Some(&proof()), &req);
			assert!(result.is_err(), "{req:?} was admitted");
		}
		assert!(super::validate_unshield::<Test>(Some(&proof()), &base).is_ok());
	});
}
