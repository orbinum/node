//! The v1 → v2 migration: every stored key gets its prepared form.

use crate::tests::util::*;
use crate::{CircuitId, PreparedKeys, VkBytes, migrations::v2::MigrateToV2, tests::mock::*};
use frame_support::traits::{GetStorageVersion, OnRuntimeUpgrade, StorageVersion};
use orbinum_zk_verifier::SHIELD_PUBLIC_INPUTS;

/// Keys stored before v2: only the raw key, no prepared form.
fn v1_chain(keys: &[(CircuitId, u32, VkBytes)]) {
	StorageVersion::new(1).put::<ZkVerifier>();
	for (circuit_id, version, key) in keys {
		insert_key(*circuit_id, *version, key.clone());
	}
}

#[test]
fn prepares_every_stored_key_and_bumps_the_version() {
	new_test_ext().execute_with(|| {
		let transfer = memo_bound_transfer_key();
		let shield = real_vk(SHIELD_PUBLIC_INPUTS);
		v1_chain(&[
			(CircuitId::TRANSFER, 3, transfer.clone()),
			(CircuitId::SHIELD, 1, shield.clone()),
		]);
		MigrateToV2::<Test>::on_runtime_upgrade();
		assert_eq!(
			PreparedKeys::<Test>::get(CircuitId::TRANSFER, 3),
			Some(ZkVerifier::prepare_vk(&transfer).unwrap())
		);
		assert_eq!(
			PreparedKeys::<Test>::get(CircuitId::SHIELD, 1),
			Some(ZkVerifier::prepare_vk(&shield).unwrap())
		);
		assert_eq!(ZkVerifier::on_chain_storage_version(), 2);
	});
}

/// Once at v2 it does nothing, whatever storage holds.
#[test]
fn runs_once() {
	new_test_ext().execute_with(|| {
		v1_chain(&[(CircuitId::TRANSFER, 3, memo_bound_transfer_key())]);
		MigrateToV2::<Test>::on_runtime_upgrade();
		insert_key(CircuitId::TRANSFER, 4, memo_bound_transfer_key());
		MigrateToV2::<Test>::on_runtime_upgrade();
		assert!(!PreparedKeys::<Test>::contains_key(CircuitId::TRANSFER, 4));
	});
}

/// A prepared form already there is replaced by the key's own preparation:
/// a stale or wrong one does not survive the upgrade.
#[test]
fn overwrites_a_stale_prepared_form() {
	new_test_ext().execute_with(|| {
		let key = memo_bound_transfer_key();
		v1_chain(&[(CircuitId::TRANSFER, 3, key.clone())]);
		let stale = ZkVerifier::prepare_vk(&other_transfer_key()).unwrap();
		PreparedKeys::<Test>::insert(CircuitId::TRANSFER, 3, stale);
		MigrateToV2::<Test>::on_runtime_upgrade();
		assert_eq!(
			PreparedKeys::<Test>::get(CircuitId::TRANSFER, 3),
			Some(ZkVerifier::prepare_vk(&key).unwrap())
		);
	});
}

/// A key that does not prepare loses any prepared form it had: verifying
/// under it falls back to the key itself.
#[test]
fn drops_the_prepared_form_of_a_key_that_does_not_prepare() {
	new_test_ext().execute_with(|| {
		v1_chain(&[(CircuitId::TRANSFER, 3, vec![0x01; 100].try_into().unwrap())]);
		let stale = ZkVerifier::prepare_vk(&memo_bound_transfer_key()).unwrap();
		PreparedKeys::<Test>::insert(CircuitId::TRANSFER, 3, stale);
		MigrateToV2::<Test>::on_runtime_upgrade();
		assert!(!PreparedKeys::<Test>::contains_key(CircuitId::TRANSFER, 3));
	});
}

#[cfg(feature = "try-runtime")]
#[test]
fn post_upgrade_accepts_the_migrated_state_and_refuses_a_tampered_one() {
	use crate::migrations::v2::PrepareKeys;
	use frame_support::traits::UncheckedOnRuntimeUpgrade;
	new_test_ext().execute_with(|| {
		let key = memo_bound_transfer_key();
		v1_chain(&[(CircuitId::TRANSFER, 3, key.clone())]);
		MigrateToV2::<Test>::on_runtime_upgrade();
		assert!(PrepareKeys::<Test>::post_upgrade(Vec::new()).is_ok());

		let wrong = ZkVerifier::prepare_vk(&other_transfer_key()).unwrap();
		PreparedKeys::<Test>::insert(CircuitId::TRANSFER, 3, wrong.clone());
		assert!(
			PrepareKeys::<Test>::post_upgrade(Vec::new()).is_err(),
			"a wrong form"
		);

		PreparedKeys::<Test>::insert(
			CircuitId::TRANSFER,
			3,
			ZkVerifier::prepare_vk(&key).unwrap(),
		);
		PreparedKeys::<Test>::insert(CircuitId::TRANSFER, 4, wrong);
		assert!(
			PrepareKeys::<Test>::post_upgrade(Vec::new()).is_err(),
			"an orphan"
		);
	});
}

/// A key that does not prepare is skipped, not fatal: the others still are.
#[test]
fn skips_a_key_that_does_not_prepare() {
	new_test_ext().execute_with(|| {
		v1_chain(&[
			(CircuitId::TRANSFER, 3, vec![0x01; 100].try_into().unwrap()),
			(CircuitId::SHIELD, 1, real_vk(SHIELD_PUBLIC_INPUTS)),
		]);
		MigrateToV2::<Test>::on_runtime_upgrade();
		assert!(!PreparedKeys::<Test>::contains_key(CircuitId::TRANSFER, 3));
		assert!(PreparedKeys::<Test>::contains_key(CircuitId::SHIELD, 1));
		assert_eq!(ZkVerifier::on_chain_storage_version(), 2);
	});
}
