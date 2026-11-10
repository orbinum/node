//! Pool tags: one pool entry per note, and tags an attacker cannot game.

use super::*;

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

		// Plus one tag per output note, two in every transfer.
		let one =
			validate_private_transfer(&KNOWN_ROOT, &nullifiers_of(&[0x91]), &0u128, 1).unwrap();
		assert_eq!(one.provides.len(), 1 + 2, "one real input → one tag");

		let two = validate_private_transfer(&KNOWN_ROOT, &nullifiers_of(&[0x92, 0x93]), &0u128, 1)
			.unwrap();
		assert_eq!(
			two.provides.len(),
			2 + 2,
			"two real inputs → two independent tags"
		);

		// A dummy-padded single input must still yield exactly one tag.
		let mut padded: BoundedVec<Nullifier, ConstU32<2>> = BoundedVec::new();
		padded.try_push(nullifier(0x94)).unwrap();
		padded.try_push(Nullifier::new([0u8; 32])).unwrap();
		let p = validate_private_transfer(&KNOWN_ROOT, &padded, &0u128, 1).unwrap();
		assert_eq!(
			p.provides.len(),
			1 + 2,
			"the dummy must not contribute a tag"
		);
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

		assert!(
			unshield
				.provides
				.iter()
				.all(|t| transfer.provides.contains(t)),
			"one note must back one pool entry, whichever operation spends it"
		);
	});
}
// ── one note created, one pool entry ─────────────────────────────────────────
//
// A commitment is inserted once, so two spends creating the same note cannot
// both execute. Without a tag per output both would sit in the pool, propagate
// and be revalidated, and the loser would fail in the block for free.

/// Two transfers spending different notes into the same output note are
/// mutually exclusive in the pool.
#[test]
fn transfers_creating_the_same_note_are_mutually_exclusive() {
	new_test_ext().execute_with(|| {
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
		let first = transfer_request(&KNOWN_ROOT, &nullifiers_of(&[0xA1]), 0, 1);
		let mut second = transfer_request(&KNOWN_ROOT, &nullifiers_of(&[0xA2]), 0, 1);
		second.commitments[1] = first.commitments[0];

		let a = admit::validate_private_transfer(Some(&proof()), &first).unwrap();
		let b = admit::validate_private_transfer(Some(&proof()), &second).unwrap();
		let shared: Vec<_> = a
			.provides
			.iter()
			.filter(|t| b.provides.contains(t))
			.collect();
		assert_eq!(shared.len(), 1, "exactly the shared output note's tag");
	});
}

/// A partial unshield's change note collides with a transfer creating the same
/// note; a total unshield creates none and tags its nullifier alone.
#[test]
fn an_unshield_change_note_is_tagged_like_a_transfer_output() {
	new_test_ext().execute_with(|| {
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
		PoolBalanceRepository::set_asset_balance::<Test>(0, 1_000);
		let transfer = transfer_request(&KNOWN_ROOT, &nullifiers_of(&[0xB1]), 0, 1);
		let total = unshield_request(&KNOWN_ROOT, &nullifier(0xB2), 0, 100, 0, 1);
		let partial = UnshieldRequest {
			change_commitment: transfer.commitments[0].0,
			change_memo: full_memo(),
			..total.clone()
		};

		let t = admit::validate_private_transfer(Some(&proof()), &transfer).unwrap();
		let total = admit::validate_unshield(Some(&proof()), &total).unwrap();
		let partial = admit::validate_unshield(Some(&proof()), &partial).unwrap();
		assert_eq!(total.provides.len(), 1);
		assert_eq!(partial.provides.len(), 2);
		assert!(partial.provides.iter().any(|tag| t.provides.contains(tag)));
		assert!(!total.provides.iter().any(|tag| t.provides.contains(tag)));
	});
}

/// An output tag never equals a nullifier tag, even for the same 32 bytes: a
/// note created by one spend must not block an unrelated spend of a note.
#[test]
fn an_output_tag_never_collides_with_a_nullifier_tag() {
	new_test_ext().execute_with(|| {
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
		PoolBalanceRepository::set_asset_balance::<Test>(0, 1_000);
		let transfer = transfer_request(&KNOWN_ROOT, &nullifiers_of(&[0xC1]), 0, 1);
		let unshield = unshield_request(
			&KNOWN_ROOT,
			&Nullifier::new(transfer.commitments[0].0),
			0,
			100,
			0,
			1,
		);

		let t = admit::validate_private_transfer(Some(&proof()), &transfer).unwrap();
		let u = admit::validate_unshield(Some(&proof()), &unshield).unwrap();
		assert!(!u.provides.iter().any(|tag| t.provides.contains(tag)));
	});
}
