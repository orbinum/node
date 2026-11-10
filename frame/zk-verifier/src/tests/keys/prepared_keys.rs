//! Prepared keys, stored and dropped with their key, and removed versions,
//! which can hold only their own key again.

use crate::tests::util::*;
use crate::{
	ActiveCircuitVersion, CircuitId, Error, PreparedKeys, RemovedVkHashes, RetiredVersions,
	VerificationKeys, VerificationStatistics, VerificationStats, VkBytes, VkEntry, VkHashes,
	tests::mock::*,
};
use frame_support::{BoundedVec, assert_noop, assert_ok, traits::ConstU32};
use orbinum_zk_verifier::TRANSFER_PUBLIC_INPUTS;

#[test]
fn registration_stores_the_prepared_key() {
	new_test_ext().execute_with(|| {
		let key = memo_bound_transfer_key();
		assert_ok!(register(CircuitId::TRANSFER, 2, key.clone()));
		assert_eq!(
			PreparedKeys::<Test>::get(CircuitId::TRANSFER, 2),
			Some(ZkVerifier::prepare_vk(&key).unwrap())
		);
	});
}

#[test]
fn removing_or_purging_a_key_drops_its_prepared_form() {
	new_test_ext().execute_with(|| {
		assert_ok!(register(CircuitId::TRANSFER, 2, memo_bound_transfer_key()));
		assert_ok!(register(CircuitId::TRANSFER, 3, memo_bound_transfer_key()));
		activate(CircuitId::TRANSFER, 3);
		assert_ok!(ZkVerifier::remove_verification_key(
			root().into(),
			CircuitId::TRANSFER,
			2
		));
		assert!(!PreparedKeys::<Test>::contains_key(CircuitId::TRANSFER, 2));

		let retired = CircuitId(99);
		ZkVerifier::store_vk(retired, 1, real_vk(3)).unwrap();
		activate(retired, 1);
		assert_ok!(ZkVerifier::purge_circuit(root().into(), retired));
		assert_eq!(PreparedKeys::<Test>::iter_key_prefix(retired).count(), 0);
	});
}

/// Every entry any map holds for `circuit_id`.
fn entries_of(circuit_id: CircuitId) -> usize {
	ZkVerifier::circuit_entries(circuit_id)
		.iter()
		.sum::<usize>()
		+ usize::from(ActiveCircuitVersion::<Test>::contains_key(circuit_id))
}

/// Register `first` as transfer v2 next to an active v3, then remove v2.
fn remove_transfer_v2(first: VkBytes) {
	assert_ok!(register(CircuitId::TRANSFER, 2, first));
	assert_ok!(register(CircuitId::TRANSFER, 3, memo_bound_transfer_key()));
	activate(CircuitId::TRANSFER, 3);
	assert_ok!(ZkVerifier::remove_verification_key(
		root().into(),
		CircuitId::TRANSFER,
		2
	));
}

/// A removed version cannot take another key: a client that cached what v2 means
/// would be served a different circuit under the same number.
#[test]
fn a_removed_version_cannot_hold_another_key() {
	new_test_ext().execute_with(|| {
		let (first, second) = (memo_bound_transfer_key(), other_transfer_key());
		assert_ne!(first, second);
		remove_transfer_v2(first.clone());
		assert_eq!(
			RemovedVkHashes::<Test>::get(CircuitId::TRANSFER, 2),
			Some(sp_io::hashing::blake2_256(&first))
		);
		assert_noop!(
			register(CircuitId::TRANSFER, 2, second.clone()),
			Error::<Test>::VersionReused
		);
		// Another version number is free.
		assert_ok!(register(CircuitId::TRANSFER, 4, second));
	});
}

/// The same key may come back under its old number, with a fresh prepared form.
#[test]
fn a_removed_version_takes_its_own_key_back() {
	new_test_ext().execute_with(|| {
		let first = memo_bound_transfer_key();
		remove_transfer_v2(first.clone());
		assert_ok!(register(CircuitId::TRANSFER, 2, first.clone()));
		assert_eq!(
			PreparedKeys::<Test>::get(CircuitId::TRANSFER, 2),
			Some(ZkVerifier::prepare_vk(&first).unwrap())
		);
		// Removed again, it still remembers the same key.
		assert_ok!(ZkVerifier::remove_verification_key(
			root().into(),
			CircuitId::TRANSFER,
			2
		));
		assert_noop!(
			register(CircuitId::TRANSFER, 2, other_transfer_key()),
			Error::<Test>::VersionReused
		);
	});
}

#[test]
fn batch_register_refuses_a_reused_version() {
	new_test_ext().execute_with(|| {
		remove_transfer_v2(memo_bound_transfer_key());
		let entries: BoundedVec<VkEntry, ConstU32<10>> = vec![VkEntry {
			circuit_id: CircuitId::TRANSFER,
			version: 2,
			verification_key: other_transfer_key(),
			set_active: false,
		}]
		.try_into()
		.unwrap();
		assert_noop!(
			ZkVerifier::batch_register_verification_keys(root().into(), entries),
			Error::<Test>::VersionReused
		);
	});
}

#[test]
fn a_purged_circuit_registered_again_gets_the_new_keys_prepared_form() {
	new_test_ext().execute_with(|| {
		let retired = CircuitId(99);
		ZkVerifier::store_vk(retired, 1, real_vk(3)).unwrap();
		activate(retired, 1);
		assert_ok!(ZkVerifier::purge_circuit(root().into(), retired));
		assert_eq!(entries_of(retired), 0);
		// A new key needs a new version: the purged one keeps its hash.
		assert_ok!(register(retired, 2, real_vk(5)));
		assert_eq!(
			PreparedKeys::<Test>::get(retired, 2),
			Some(ZkVerifier::prepare_vk(&real_vk(5)).unwrap())
		);
	});
}

/// Removing a version leaves nothing of it in any map, and the versions next
/// to it untouched.
#[test]
fn removing_a_version_leaves_no_orphan() {
	new_test_ext().execute_with(|| {
		assert_ok!(register(CircuitId::TRANSFER, 2, memo_bound_transfer_key()));
		assert_ok!(register(CircuitId::TRANSFER, 3, memo_bound_transfer_key()));
		activate(CircuitId::TRANSFER, 3);
		RetiredVersions::<Test>::insert(CircuitId::TRANSFER, 2, ());
		VerificationStats::<Test>::insert(
			CircuitId::TRANSFER,
			2,
			VerificationStatistics::default(),
		);
		assert_ok!(ZkVerifier::remove_verification_key(
			root().into(),
			CircuitId::TRANSFER,
			2
		));
		assert!(!VerificationKeys::<Test>::contains_key(
			CircuitId::TRANSFER,
			2
		));
		assert!(!PreparedKeys::<Test>::contains_key(CircuitId::TRANSFER, 2));
		assert!(!VkHashes::<Test>::contains_key(CircuitId::TRANSFER, 2));
		assert!(!RetiredVersions::<Test>::contains_key(
			CircuitId::TRANSFER,
			2
		));
		assert!(!VerificationStats::<Test>::contains_key(
			CircuitId::TRANSFER,
			2
		));
		assert!(PreparedKeys::<Test>::contains_key(CircuitId::TRANSFER, 3));
	});
}

/// A batch is all or nothing: one bad key leaves no key and no prepared form.
#[test]
fn a_batch_with_one_bad_key_stores_nothing() {
	new_test_ext().execute_with(|| {
		let mut entries: Vec<VkEntry> = (1..=9)
			.map(|v| make_vk_entry(CircuitId::TRANSFER, v, false))
			.collect();
		entries.push(VkEntry {
			circuit_id: CircuitId::TRANSFER,
			version: 10,
			verification_key: real_vk(TRANSFER_PUBLIC_INPUTS),
			set_active: false,
		});
		assert_noop!(
			ZkVerifier::batch_register_verification_keys(root().into(), batch(entries)),
			Error::<Test>::InvalidVerificationKey
		);
		assert_eq!(PreparedKeys::<Test>::iter().count(), 0);
	});
}

#[test]
fn a_full_batch_stores_every_prepared_form() {
	new_test_ext().execute_with(|| {
		let entries = (1..=10)
			.map(|v| make_vk_entry(CircuitId::TRANSFER, v, false))
			.collect();
		assert_ok!(ZkVerifier::batch_register_verification_keys(
			root().into(),
			batch(entries)
		));
		for v in 1..=10 {
			assert!(
				PreparedKeys::<Test>::contains_key(CircuitId::TRANSFER, v),
				"v{v}"
			);
		}
	});
}
