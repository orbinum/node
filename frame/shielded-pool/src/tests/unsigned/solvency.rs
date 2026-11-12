// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: GPL-3.0-or-later

//! Solvency at admission: what a spend may take, also across two trees.

use super::*;

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
		let original = admit::validate_private_transfer(Some(&proof()), &req).unwrap();
		let copy = admit::validate_private_transfer(Some(&other_proof), &req).unwrap();
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
		let mut a = admit::validate_private_transfer(Some(&proof()), &ab)
			.unwrap()
			.provides;
		let mut b = admit::validate_private_transfer(Some(&proof()), &ba)
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
		assert!(admit::validate_private_transfer(Some(&proof()), &req).is_err());
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
			admit::validate_private_transfer(Some(&proof()), &req),
			Err(sp_runtime::transaction_validity::InvalidTransaction::Stale.into())
		);
	});
}

/// A root's non-canonical alias (`root + r`, the same field element) is not
/// a known root: roots compare as bytes, and only canonical ones are stored.
#[test]
fn attack_a_non_canonical_alias_of_a_known_root_is_unknown() {
	new_test_ext().execute_with(|| {
		let root = crate::tests::util::canonical_bytes(0x33);
		MerkleRepository::add_historic_poseidon_root::<Test>(root);
		let alias = crate::tests::util::field_twin(root);
		assert_ne!(alias, root);
		for roots in [[alias, root], [root, alias]] {
			let req = cross_tree_request(&[0x88, 0x89], roots);
			assert!(rejected_with(
				admit::validate_private_transfer(Some(&proof()), &req),
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
		aliased_nullifier.nullifier =
			Nullifier::new(crate::tests::util::field_twin(nullifier(0x8B).0));
		assert!(rejected_with(
			admit::validate_unshield(Some(&proof()), &aliased_nullifier),
			codes::INVALID_SPEND
		));

		let change = crate::tests::util::canonical_bytes(0x8C);
		let mut aliased_change = base;
		aliased_change.amount = 400;
		aliased_change.change_commitment = crate::tests::util::field_twin(change);
		aliased_change.change_memo = full_memo();
		assert!(rejected_with(
			admit::validate_unshield(Some(&proof()), &aliased_change),
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
		assert!(admit::validate_private_transfer(Some(&proof()), &req).is_err());
	});
}
