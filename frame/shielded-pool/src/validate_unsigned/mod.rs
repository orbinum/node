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

	/// Two unshield variants differing only in `relayer` produce different
	/// `provides` tag sets, so a spoofed variant is a distinct pool entry and
	/// cannot silently replace the honest one.
	#[test]
	fn unshield_relayer_changes_provides_tag() {
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

			assert_ne!(a.provides, b.provides, "different relayer → different tags");
			assert_ne!(a.provides, none.provides, "Some vs None → different tags");
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

	/// Same for private_transfer.
	#[test]
	fn transfer_relayer_changes_provides_tag() {
		new_test_ext().execute_with(|| {
			MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
			let ns = nullifiers_of(&[0x63]);

			let a =
				validate_private_transfer::<Test>(&KNOWN_ROOT, &ns, &10u128, &Some(evm(0xAA)), 1)
					.unwrap();
			let b =
				validate_private_transfer::<Test>(&KNOWN_ROOT, &ns, &10u128, &Some(evm(0xBB)), 1)
					.unwrap();
			assert_ne!(a.provides, b.provides);
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
}
