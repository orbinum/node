//! Unsigned transaction validation for `private_transfer` and `unshield`.
//!
//! These are lightweight anti-spam checks that run before a transaction enters
//! the pool. Full ZK proof verification happens inside each extrinsic — doing it
//! here would let anyone burn a node's CPU for free, since unsigned submissions
//! cost nothing to make.
//!
//! Every check here is also re-done in the dispatchable. That is deliberate: a
//! check performed only at admission could be skipped by a malicious block
//! author, so admission may reject more than execution but never less.
//!
//! - [`codes`] — named pool-rejection codes shared by both validators.
//! - [`transfer`] — admission for `private_transfer`.
//! - [`unshield`] — admission for `unshield`.

pub mod codes;
pub mod transfer;
pub mod unshield;

pub use transfer::validate_private_transfer;
pub use unshield::validate_unshield;

/// How long an unsigned transaction stays valid in the pool, in blocks. Bounded
/// so a transaction that never gets included does not linger indefinitely.
///
/// `Config::RootRetentionBlocks` must exceed this (checked in `integrity_test`):
/// a root has to outlive every transaction admitted against it, or a spend can
/// pass admission, propagate, and only then revert with `UnknownMerkleRoot`.
pub(crate) const TX_LONGEVITY: u64 = 64;

/// ONE tag namespace for every operation that spends a note.
///
/// A nullifier identifies a NOTE, not an operation, and the on-chain rule is
/// simply "each note is spent once" — whether by a transfer or an unshield.
/// While transfer and unshield used separate prefixes, the same note could back
/// one of each in the pool at the same time: both propagate and get revalidated
/// network-wide, only one can ever execute. Sharing the namespace makes pool
/// admission mirror the chain: one note, one entry.
pub(crate) const SPEND_TAG_PREFIX: &str = "ShieldedPoolSpend";

#[cfg(test)]
mod tests {
	use super::{TX_LONGEVITY, validate_private_transfer, validate_unshield};
	use crate::{
		mock::{Test, new_test_ext},
		storage::{MerkleRepository, NullifierRepository, PoolBalanceRepository},
		types::Nullifier,
	};
	use frame_support::{BoundedVec, pallet_prelude::ConstU32};

	/// Rejection codes reach wallets and relayers as bare `Custom(N)`, so they are
	/// part of the observable interface: pin them here, and retire a number rather
	/// than reuse it for a new meaning.
	#[test]
	fn rejection_codes_are_stable() {
		use super::codes;
		assert_eq!(codes::UNKNOWN_ROOT, 1);
		assert_eq!(codes::ALL_INPUTS_DUMMY, 2);
		assert_eq!(codes::INSUFFICIENT_POOL_BALANCE, 3);
		assert_eq!(codes::AMOUNT_OVERFLOW, 4);
		assert_eq!(codes::UNSUPPORTED_CIRCUIT_VERSION, 10);
	}

	const KNOWN_ROOT: [u8; 32] = [0x11u8; 32];

	fn make_nullifier(seed: u8) -> Nullifier {
		Nullifier::new([seed; 32])
	}

	fn nullifiers_of(seeds: &[u8]) -> BoundedVec<Nullifier, ConstU32<2>> {
		let mut v: BoundedVec<Nullifier, ConstU32<2>> = BoundedVec::new();
		for &s in seeds {
			v.try_push(make_nullifier(s)).ok();
		}
		v
	}

	// ── validate_private_transfer ─────────────────────────────────────────────

	#[test]
	fn private_transfer_valid_transaction() {
		new_test_ext().execute_with(|| {
			MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
			let result = validate_private_transfer::<Test>(
				&KNOWN_ROOT,
				&nullifiers_of(&[0x01]),
				&0u128,
				&None,
				1,
			);
			assert!(result.is_ok());
		});
	}

	#[test]
	fn private_transfer_unknown_root_rejected() {
		new_test_ext().execute_with(|| {
			let result = validate_private_transfer::<Test>(
				&[0xFFu8; 32],
				&nullifiers_of(&[0x01]),
				&0u128,
				&None,
				1,
			);
			assert!(result.is_err());
		});
	}

	#[test]
	fn private_transfer_nullifier_used_rejected() {
		new_test_ext().execute_with(|| {
			MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
			let n = make_nullifier(0x05);
			NullifierRepository::mark_as_used::<Test>(n, 1u64);
			let result = validate_private_transfer::<Test>(
				&KNOWN_ROOT,
				&nullifiers_of(&[0x05]),
				&0u128,
				&None,
				1,
			);
			assert!(result.is_err());
		});
	}

	#[test]
	fn private_transfer_two_nullifiers_one_used_rejected() {
		new_test_ext().execute_with(|| {
			MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
			let used = make_nullifier(0x10);
			NullifierRepository::mark_as_used::<Test>(used, 1u64);
			// 0x10 is used, 0x11 is fresh — full list should still fail
			let result = validate_private_transfer::<Test>(
				&KNOWN_ROOT,
				&nullifiers_of(&[0x10, 0x11]),
				&0u128,
				&None,
				1,
			);
			assert!(result.is_err());
		});
	}

	#[test]
	fn private_transfer_with_fee_builds_valid_transaction() {
		new_test_ext().execute_with(|| {
			MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
			let result = validate_private_transfer::<Test>(
				&KNOWN_ROOT,
				&nullifiers_of(&[0xA1, 0xA2]),
				&100u128, // non-zero fee,
				&None,
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
			nullifiers.try_push(make_nullifier(0x01)).ok();
			nullifiers.try_push(Nullifier::new([0u8; 32])).ok(); // dummy
			let result =
				validate_private_transfer::<Test>(&KNOWN_ROOT, &nullifiers, &0u128, &None, 1);
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
			let real = make_nullifier(0xBB);
			NullifierRepository::mark_as_used::<Test>(real, 1u64);
			let mut nullifiers: BoundedVec<Nullifier, ConstU32<2>> = BoundedVec::new();
			nullifiers.try_push(real).ok();
			nullifiers.try_push(Nullifier::new([0u8; 32])).ok(); // dummy
			let result =
				validate_private_transfer::<Test>(&KNOWN_ROOT, &nullifiers, &0u128, &None, 1);
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
			let result =
				validate_private_transfer::<Test>(&KNOWN_ROOT, &nullifiers, &0u128, &None, 1);
			assert!(result.is_err(), "all-dummy-nullifier tx must be rejected");
		});
	}

	// ── validate_unshield ─────────────────────────────────────────────────────

	#[test]
	fn unshield_valid_transaction() {
		new_test_ext().execute_with(|| {
			MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
			PoolBalanceRepository::set_asset_balance::<Test>(0, 1_000u128);
			let result = validate_unshield::<Test>(
				&KNOWN_ROOT,
				&make_nullifier(0x10),
				&0u32,
				&500u128,
				&0u128,
				&None,
				1,
			);
			assert!(result.is_ok());
		});
	}

	#[test]
	fn unshield_unknown_root_rejected() {
		new_test_ext().execute_with(|| {
			PoolBalanceRepository::set_asset_balance::<Test>(0, 1_000u128);
			let result = validate_unshield::<Test>(
				&[0xEEu8; 32],
				&make_nullifier(0x10),
				&0u32,
				&500u128,
				&0u128,
				&None,
				1,
			);
			assert!(result.is_err());
		});
	}

	#[test]
	fn unshield_nullifier_used_rejected() {
		new_test_ext().execute_with(|| {
			MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
			PoolBalanceRepository::set_asset_balance::<Test>(0, 1_000u128);
			let n = make_nullifier(0x20);
			NullifierRepository::mark_as_used::<Test>(n, 1u64);
			let result =
				validate_unshield::<Test>(&KNOWN_ROOT, &n, &0u32, &500u128, &0u128, &None, 1);
			assert!(result.is_err());
		});
	}

	#[test]
	fn unshield_insufficient_pool_balance_rejected() {
		new_test_ext().execute_with(|| {
			MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
			PoolBalanceRepository::set_asset_balance::<Test>(0, 50u128); // only 50
			let result = validate_unshield::<Test>(
				&KNOWN_ROOT,
				&make_nullifier(0x30),
				&0u32,
				&100u128, // 100 > 50
				&0u128,
				&None,
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
			let result = validate_unshield::<Test>(
				&KNOWN_ROOT,
				&make_nullifier(0x40),
				&0u32,
				&100u128,
				&60u128,
				&None,
				1,
			);
			assert!(result.is_err());
		});
	}

	#[test]
	fn unshield_exact_pool_balance_accepted() {
		new_test_ext().execute_with(|| {
			MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
			// amount=100 + fee=50 = 150 == pool → accept
			PoolBalanceRepository::set_asset_balance::<Test>(0, 150u128);
			let result = validate_unshield::<Test>(
				&KNOWN_ROOT,
				&make_nullifier(0x50),
				&0u32,
				&100u128,
				&50u128,
				&None,
				1,
			);
			assert!(result.is_ok());
		});
	}

	// ── fee floor (anti-spam) ─────────────────────────────────────────────────
	//
	// T2: Verify that both validate_private_transfer and validate_unshield
	// enforce the minimum relay fee set by T::Relayer::min_relay_fee().
	// The mock returns 0 by default; mock_set_min_relay_fee lets individual
	// tests raise the floor to exercise the Payment rejection path.

	#[test]
	fn private_transfer_fee_below_minimum_rejected() {
		new_test_ext().execute_with(|| {
			crate::mock::mock_set_min_relay_fee(100);
			MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
			// fee=50 < min_relay_fee=100 → InvalidTransaction::Payment
			let result = validate_private_transfer::<Test>(
				&KNOWN_ROOT,
				&nullifiers_of(&[0x01]),
				&50u128,
				&None,
				1,
			);
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
			let result = validate_private_transfer::<Test>(
				&KNOWN_ROOT,
				&nullifiers_of(&[0x01]),
				&100u128,
				&None,
				1,
			);
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
			let result = validate_unshield::<Test>(
				&KNOWN_ROOT,
				&make_nullifier(0x60),
				&0u32,
				&100u128,
				&50u128,
				&None,
				1,
			);
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
			let result = validate_unshield::<Test>(
				&KNOWN_ROOT,
				&make_nullifier(0x60),
				&0u32,
				&100u128,
				&200u128,
				&None,
				1,
			);
			assert!(result.is_ok(), "fee equal to minimum must be accepted");
		});
	}

	// ── relayer bound into the provides tag ──────────────────────────────────

	fn evm(byte: u8) -> sp_core::H160 {
		sp_core::H160::from([byte; 20])
	}

	/// Two unshield variants differing only in `relayer` COLLIDE — they are the
	/// same spend of the same note.
	///
	/// This inverts the earlier expectation on purpose. Binding the relayer into
	/// the tag made a spoofed copy a SEPARATE pool entry, so anyone could
	/// rebroadcast an honest unshield pointed at their own account and have both
	/// live in the pool: duplicate propagation and revalidation across the whole
	/// network, for a copy that cost the attacker nothing. Keyed on the nullifier
	/// alone the two are mutually exclusive, and taking the fee requires
	/// out-bidding — which means actually paying it.
	#[test]
	fn unshield_relayer_swap_collides_with_the_original() {
		new_test_ext().execute_with(|| {
			MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
			PoolBalanceRepository::set_asset_balance::<Test>(0, 1000u128);
			let n = make_nullifier(0x61);

			let a = validate_unshield::<Test>(
				&KNOWN_ROOT,
				&n,
				&0u32,
				&100u128,
				&10u128,
				&Some(evm(0xAA)),
				1,
			)
			.unwrap();
			let b = validate_unshield::<Test>(
				&KNOWN_ROOT,
				&n,
				&0u32,
				&100u128,
				&10u128,
				&Some(evm(0xBB)),
				1,
			)
			.unwrap();
			let none =
				validate_unshield::<Test>(&KNOWN_ROOT, &n, &0u32, &100u128, &10u128, &None, 1)
					.unwrap();

			assert_eq!(
				a.provides, b.provides,
				"a relayer-swapped copy is the same spend and must collide"
			);
			assert_eq!(
				a.provides, none.provides,
				"Some vs None relayer is still the same note being spent"
			);
			// Fee steers priority, not the relayer field.
			assert_eq!(a.priority, b.priority);
		});
	}

	/// Identical relayer + nullifier yields identical provides (honest re-gossip
	/// is idempotent, first-seen wins at equal fee).
	#[test]
	fn unshield_same_relayer_same_provides() {
		new_test_ext().execute_with(|| {
			MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
			PoolBalanceRepository::set_asset_balance::<Test>(0, 1000u128);
			let n = make_nullifier(0x62);

			let a = validate_unshield::<Test>(
				&KNOWN_ROOT,
				&n,
				&0u32,
				&100u128,
				&10u128,
				&Some(evm(0xAA)),
				1,
			)
			.unwrap();
			let b = validate_unshield::<Test>(
				&KNOWN_ROOT,
				&n,
				&0u32,
				&100u128,
				&10u128,
				&Some(evm(0xAA)),
				1,
			)
			.unwrap();
			assert_eq!(a.provides, b.provides);
		});
	}

	/// A relayer-swapped copy of a transfer COLLIDES with the original.
	///
	/// This inverts the earlier expectation, deliberately. Binding the relayer
	/// into the tag made a copy with a different fee recipient a *separate* pool
	/// entry, so a third party could rebroadcast someone else's spend pointed at
	/// their own account and have both sit in the pool at once — duplicate load,
	/// and a race for the fee that cost the attacker nothing.
	///
	/// Tagging per nullifier makes the two mutually exclusive: the higher fee
	/// wins (first-seen at equal fee), so out-bidding is the only way to take
	/// the fee, and out-bidding means actually paying it. The pool now mirrors
	/// the on-chain rule — one note, one spend.
	#[test]
	fn transfer_relayer_swap_collides_with_the_original() {
		new_test_ext().execute_with(|| {
			MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
			let ns = nullifiers_of(&[0x63]);

			let a =
				validate_private_transfer::<Test>(&KNOWN_ROOT, &ns, &10u128, &Some(evm(0xAA)), 1)
					.unwrap();
			let b =
				validate_private_transfer::<Test>(&KNOWN_ROOT, &ns, &10u128, &Some(evm(0xBB)), 1)
					.unwrap();
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

			let t = validate_private_transfer::<Test>(
				&KNOWN_ROOT,
				&nullifiers_of(&[0x90]),
				&10u128,
				&None,
				1,
			)
			.unwrap();
			assert_eq!(t.longevity, TX_LONGEVITY);
			assert!(t.longevity < sp_runtime::transaction_validity::TransactionLongevity::MAX);

			let u = validate_unshield::<Test>(
				&KNOWN_ROOT,
				&make_nullifier(0x91),
				&0u32,
				&100u128,
				&10u128,
				&None,
				1,
			)
			.unwrap();
			assert_eq!(u.longevity, TX_LONGEVITY);
		});
	}

	// ── circuit-version guard (anti-spam) ─────────────────────────────────────
	//
	// The mock's `is_supported_version` treats version 0 as unsupported; a
	// supported version passes the guard, an unsupported one is rejected before
	// any other check.

	#[test]
	fn private_transfer_unsupported_version_rejected() {
		new_test_ext().execute_with(|| {
			MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
			let result = validate_private_transfer::<Test>(
				&KNOWN_ROOT,
				&nullifiers_of(&[0x01]),
				&0u128,
				&None,
				0,
			);
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
			let result = validate_unshield::<Test>(
				&KNOWN_ROOT,
				&make_nullifier(0x10),
				&0u32,
				&500u128,
				&0u128,
				&None,
				0,
			);
			assert_eq!(
				result.unwrap_err(),
				sp_runtime::transaction_validity::TransactionValidityError::Invalid(
					sp_runtime::transaction_validity::InvalidTransaction::Custom(10)
				),
			);
		});
	}

	// ── adversarial: mempool tag manipulation ────────────────────────────────
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
			let a =
				validate_private_transfer::<Test>(&KNOWN_ROOT, &nulls, &0u128, &None, 1).unwrap();
			let b =
				validate_private_transfer::<Test>(&other_root, &nulls, &0u128, &None, 1).unwrap();

			assert_eq!(
				a.provides, b.provides,
				"same note spent twice must produce the same tag, whatever the root"
			);
		});
	}

	/// Fee-hijack attempt: a third party rebroadcasts someone else's spend with
	/// the relayer swapped to themselves. The two must be MUTUALLY EXCLUSIVE in
	/// the pool (same nullifier tag) so both can never sit there at once —
	/// otherwise the network carries a duplicate of every transfer.
	#[test]
	fn attack_swapping_the_relayer_cannot_add_a_second_pool_entry() {
		new_test_ext().execute_with(|| {
			MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
			let nulls = nullifiers_of(&[0x43]);

			let honest =
				validate_private_transfer::<Test>(&KNOWN_ROOT, &nulls, &0u128, &None, 1).unwrap();
			let hijacked = validate_private_transfer::<Test>(
				&KNOWN_ROOT,
				&nulls,
				&0u128,
				&Some(sp_core::H160::repeat_byte(0xEE)),
				1,
			)
			.unwrap();

			assert_eq!(
				honest.provides, hijacked.provides,
				"a relayer-swapped copy must collide with the original, not coexist"
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
			a_nulls.try_push(make_nullifier(0x51)).unwrap();
			a_nulls.try_push(Nullifier::new([0u8; 32])).unwrap();

			let mut b_nulls: BoundedVec<Nullifier, ConstU32<2>> = BoundedVec::new();
			b_nulls.try_push(make_nullifier(0x52)).unwrap();
			b_nulls.try_push(Nullifier::new([0u8; 32])).unwrap();

			let a =
				validate_private_transfer::<Test>(&KNOWN_ROOT, &a_nulls, &0u128, &None, 1).unwrap();
			let b =
				validate_private_transfer::<Test>(&KNOWN_ROOT, &b_nulls, &0u128, &None, 1).unwrap();

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

			let a = validate_private_transfer::<Test>(&KNOWN_ROOT, &ab, &0u128, &None, 1).unwrap();
			let b = validate_private_transfer::<Test>(&KNOWN_ROOT, &ba, &0u128, &None, 1).unwrap();

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

			let cheap =
				validate_private_transfer::<Test>(&KNOWN_ROOT, &nulls, &10u128, &None, 1).unwrap();
			let rich = validate_private_transfer::<Test>(&KNOWN_ROOT, &nulls, &1_000u128, &None, 1)
				.unwrap();

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
			let n = make_nullifier(0x81);
			NullifierRepository::mark_as_used::<Test>(n, 1u64);

			let result = validate_private_transfer::<Test>(
				&KNOWN_ROOT,
				&nullifiers_of(&[0x81]),
				&0u128,
				&None,
				1,
			);
			assert_eq!(
				result.unwrap_err(),
				sp_runtime::transaction_validity::TransactionValidityError::Invalid(
					sp_runtime::transaction_validity::InvalidTransaction::Stale
				),
			);
		});
	}

	/// THE REGRESSION THIS SUITE EXISTS FOR.
	///
	/// Two transfers that share only ONE input note (A+B and A+C) must be
	/// mutually exclusive: note A can back exactly one pool entry. When the tag
	/// was a single blob over the whole nullifier set, these did not collide,
	/// so one note could back unboundedly many admissible transactions — free
	/// mempool amplification, since the fee is only charged on execution.
	#[test]
	fn attack_transfers_sharing_one_note_are_mutually_exclusive() {
		new_test_ext().execute_with(|| {
			MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);

			let ab = nullifiers_of(&[0x61, 0x62]);
			let ac = nullifiers_of(&[0x61, 0x63]);

			let a = validate_private_transfer::<Test>(&KNOWN_ROOT, &ab, &0u128, &None, 1).unwrap();
			let b = validate_private_transfer::<Test>(&KNOWN_ROOT, &ac, &0u128, &None, 1).unwrap();

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

			let one = validate_private_transfer::<Test>(
				&KNOWN_ROOT,
				&nullifiers_of(&[0x91]),
				&0u128,
				&None,
				1,
			)
			.unwrap();
			assert_eq!(one.provides.len(), 1, "one real input → one tag");

			let two = validate_private_transfer::<Test>(
				&KNOWN_ROOT,
				&nullifiers_of(&[0x92, 0x93]),
				&0u128,
				&None,
				1,
			)
			.unwrap();
			assert_eq!(
				two.provides.len(),
				2,
				"two real inputs → two independent tags"
			);

			// A dummy-padded single input must still yield exactly one tag.
			let mut padded: BoundedVec<Nullifier, ConstU32<2>> = BoundedVec::new();
			padded.try_push(make_nullifier(0x94)).unwrap();
			padded.try_push(Nullifier::new([0u8; 32])).unwrap();
			let p =
				validate_private_transfer::<Test>(&KNOWN_ROOT, &padded, &0u128, &None, 1).unwrap();
			assert_eq!(p.provides.len(), 1, "the dummy must not contribute a tag");
		});
	}
	/// A transfer and an unshield spending the SAME note must be mutually
	/// exclusive in the pool.
	///
	/// They used to carry different tag prefixes, so one of each could sit in
	/// the pool for a single note: both propagate and get revalidated by every
	/// node, while at most one can execute. A nullifier names a NOTE, not an
	/// operation, so both now share one tag namespace.
	#[test]
	fn attack_transfer_and_unshield_of_the_same_note_are_mutually_exclusive() {
		new_test_ext().execute_with(|| {
			MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
			PoolBalanceRepository::set_asset_balance::<Test>(0, 100_000u128);
			let n = make_nullifier(0x77);

			let transfer = validate_private_transfer::<Test>(
				&KNOWN_ROOT,
				&nullifiers_of(&[0x77]),
				&10u128,
				&None,
				1,
			)
			.unwrap();
			let unshield =
				validate_unshield::<Test>(&KNOWN_ROOT, &n, &0u32, &100u128, &10u128, &None, 1)
					.unwrap();

			assert_eq!(
				transfer.provides, unshield.provides,
				"one note must back one pool entry, whichever operation spends it"
			);
		});
	}
}
