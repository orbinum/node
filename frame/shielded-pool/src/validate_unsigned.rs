//! Unsigned transaction validation for `private_transfer` and `unshield`.
//!
//! These are lightweight anti-spam checks that run before the transaction
//! enters the pool.  Full ZK proof verification happens inside each extrinsic.
//!
//! Splitting this out of `lib.rs` makes the validation logic independently
//! testable without needing the full pallet mock environment.

use crate::{
	pallet::{BalanceOf, Config, NullifierSet, PoolBalancePerAsset},
	storage::MerkleRepository,
	types::{Hash, Nullifier},
};
use frame_support::pallet_prelude::*;
use pallet_relayer::RelayerInterface as _;
use parity_scale_codec::Encode;
use sp_runtime::{
	SaturatedConversion,
	transaction_validity::{
		InvalidTransaction, TransactionLongevity, TransactionValidity, ValidTransaction,
	},
};

/// Validate an incoming `private_transfer` unsigned transaction.
pub fn validate_private_transfer<T: Config>(
	merkle_root: &Hash,
	nullifiers: &BoundedVec<Nullifier, ConstU32<2>>,
	fee: &BalanceOf<T>,
) -> TransactionValidity {
	// Anti-spam: fee must meet minimum relay fee
	let min_fee: BalanceOf<T> = T::Relayer::min_relay_fee().saturated_into();
	if *fee < min_fee {
		return InvalidTransaction::Payment.into();
	}

	// Reject unknown Merkle roots
	if !MerkleRepository::is_known_root::<T>(merkle_root) {
		return InvalidTransaction::Custom(1).into();
	}

	// Reject already-spent nullifiers (skip dummy nullifiers — value zero, forced by circuit)
	for nullifier in nullifiers.iter() {
		if nullifier.0 == [0u8; 32] {
			continue; // dummy input — never inserted in the set, cannot be stale
		}
		if NullifierSet::<T>::contains_key(nullifier) {
			return InvalidTransaction::Stale.into();
		}
	}

	// Reject transactions where all nullifiers are dummy (both inputs value=0).
	// This prevents free Merkle tree spam (2 commitments inserted at zero cost).
	if nullifiers.iter().all(|n| n.0 == [0u8; 32]) {
		return InvalidTransaction::Custom(2).into();
	}

	// Exclude dummy nullifiers (zero) from provides — they carry no identity
	let provides: alloc::vec::Vec<alloc::vec::Vec<u8>> = nullifiers
		.iter()
		.filter(|n| n.0 != [0u8; 32])
		.map(|n| n.encode())
		.collect();

	ValidTransaction::with_tag_prefix("ShieldedPoolTransfer")
		.priority((*fee).saturated_into())
		.longevity(TransactionLongevity::MAX)
		.and_provides(provides)
		.propagate(true)
		.build()
}

/// Validate an incoming `unshield` unsigned transaction.
pub fn validate_unshield<T: Config>(
	merkle_root: &Hash,
	nullifier: &Nullifier,
	asset_id: &u32,
	amount: &BalanceOf<T>,
	fee: &BalanceOf<T>,
) -> TransactionValidity {
	// Anti-spam: fee must meet minimum relay fee
	let min_fee: BalanceOf<T> = T::Relayer::min_relay_fee().saturated_into();
	if *fee < min_fee {
		return InvalidTransaction::Payment.into();
	}

	// Reject unknown Merkle roots
	if !MerkleRepository::is_known_root::<T>(merkle_root) {
		return InvalidTransaction::Custom(1).into();
	}

	// Reject already-spent nullifier
	if NullifierSet::<T>::contains_key(nullifier) {
		return InvalidTransaction::Stale.into();
	}

	// Reject if pool balance is insufficient
	let total = amount
		.checked_add(fee)
		.ok_or(InvalidTransaction::Custom(2))?;
	if PoolBalancePerAsset::<T>::get(asset_id) < total {
		return InvalidTransaction::Custom(3).into();
	}

	ValidTransaction::with_tag_prefix("ShieldedPoolUnshield")
		.priority((*fee).saturated_into())
		.longevity(TransactionLongevity::MAX)
		.and_provides([nullifier.encode()])
		.propagate(true)
		.build()
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::{
		mock::{Test, new_test_ext},
		storage::{MerkleRepository, NullifierRepository, PoolBalanceRepository},
		types::Nullifier,
	};

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
			let result =
				validate_private_transfer::<Test>(&KNOWN_ROOT, &nullifiers_of(&[0x01]), &0u128);
			assert!(result.is_ok());
		});
	}

	#[test]
	fn private_transfer_unknown_root_rejected() {
		new_test_ext().execute_with(|| {
			let result =
				validate_private_transfer::<Test>(&[0xFFu8; 32], &nullifiers_of(&[0x01]), &0u128);
			assert!(result.is_err());
		});
	}

	#[test]
	fn private_transfer_nullifier_used_rejected() {
		new_test_ext().execute_with(|| {
			MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
			let n = make_nullifier(0x05);
			NullifierRepository::mark_as_used::<Test>(n, 1u64);
			let result =
				validate_private_transfer::<Test>(&KNOWN_ROOT, &nullifiers_of(&[0x05]), &0u128);
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
				&100u128, // non-zero fee
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
			let result = validate_private_transfer::<Test>(&KNOWN_ROOT, &nullifiers, &0u128);
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
			let result = validate_private_transfer::<Test>(&KNOWN_ROOT, &nullifiers, &0u128);
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
			let result = validate_private_transfer::<Test>(&KNOWN_ROOT, &nullifiers, &0u128);
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
			let result = validate_unshield::<Test>(&KNOWN_ROOT, &n, &0u32, &500u128, &0u128);
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
			let result =
				validate_private_transfer::<Test>(&KNOWN_ROOT, &nullifiers_of(&[0x01]), &50u128);
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
			let result =
				validate_private_transfer::<Test>(&KNOWN_ROOT, &nullifiers_of(&[0x01]), &100u128);
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
			);
			assert!(result.is_ok(), "fee equal to minimum must be accepted");
		});
	}
}
