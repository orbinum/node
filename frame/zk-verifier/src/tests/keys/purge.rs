//! `purge_circuit`: what it clears and the circuits it refuses.

use crate::tests::util::*;
use crate::{
	ActiveCircuitVersion, CircuitId, Config, Error, Event, Pallet, RetiredVersions,
	VerificationKeys, VerificationStatistics, VerificationStats, VkHashes, tests::mock::*,
};
use frame_support::{assert_err, assert_noop, assert_ok};
use orbinum_zk_verifier::TRANSFER_PUBLIC_INPUTS;

#[test]
fn purge_circuit_clears_every_map() {
	new_test_ext().execute_with(|| {
		let retired = CircuitId(5);
		seed_circuit(retired, 1, 2);
		RetiredVersions::<Test>::insert(retired, 1, ());

		assert_ok!(ZkVerifier::purge_circuit(root().into(), retired));

		assert!(VerificationKeys::<Test>::get(retired, 1).is_none());
		assert!(VkHashes::<Test>::get(retired, 1).is_none());
		assert!(!VerificationStats::<Test>::contains_key(retired, 1));
		assert!(!RetiredVersions::<Test>::contains_key(retired, 1));
		assert!(ActiveCircuitVersion::<Test>::get(retired).is_none());
	});
}

/// The retired value_proof circuit (id 6) is not in the live table, so the keys
/// a chain registered for it can be purged.
#[test]
fn purge_circuit_accepts_the_removed_value_proof_circuit() {
	new_test_ext().execute_with(|| {
		let value_proof = CircuitId(6);
		seed_circuit(value_proof, 1, 4);

		assert_ok!(ZkVerifier::purge_circuit(root().into(), value_proof));

		assert!(VerificationKeys::<Test>::get(value_proof, 1).is_none());
		assert!(ActiveCircuitVersion::<Test>::get(value_proof).is_none());
	});
}

/// The guard that makes this call safe: a circuit the runtime still
/// implements can never be purged, no matter what storage holds.
#[test]
fn purge_circuit_rejects_live_circuits() {
	new_test_ext().execute_with(|| {
		for cid in [CircuitId::TRANSFER, CircuitId::UNSHIELD] {
			seed_circuit(cid, 1, TRANSFER_PUBLIC_INPUTS);
			assert_noop!(
				ZkVerifier::purge_circuit(root().into(), cid),
				Error::<Test>::CircuitStillInUse
			);
			assert!(VerificationKeys::<Test>::get(cid, 1).is_some());
		}
	});
}

/// `circuit_id.0 as u8` would alias 257 onto TRANSFER(1). Ids past `u8::MAX`
/// must be rejected outright rather than truncated into the lookup.
#[test]
fn purge_circuit_rejects_ids_above_u8_max() {
	new_test_ext().execute_with(|| {
		for id in [256u32, 257, 261, 262, u32::MAX] {
			let cid = CircuitId(id);
			seed_circuit(cid, 1, 2);
			assert_noop!(
				ZkVerifier::purge_circuit(root().into(), cid),
				Error::<Test>::CircuitStillInUse
			);
			assert!(VerificationKeys::<Test>::get(cid, 1).is_some());
		}
	});
}

/// Purging must work on a circuit reached the only way an operator can reach
/// one: through the extrinsics. `register_verification_key` activates the
/// first version it stores and nothing else ever clears that pointer, so a
/// call that required `ActiveCircuitVersion` to be empty could never fire.
#[test]
fn purge_circuit_works_on_a_circuit_built_through_extrinsics() {
	new_test_ext().execute_with(|| {
		let retired = CircuitId(5);
		assert_ok!(register(retired, 1, real_vk(2)));
		// The registration activated version 1, and no extrinsic can undo that:
		// `retire_version` and `remove_verification_key` both refuse the active
		// version, and `set_active_version` only ever overwrites.
		assert_eq!(ActiveCircuitVersion::<Test>::get(retired), Some(1));
		assert_noop!(
			ZkVerifier::retire_version(root().into(), retired, 1),
			Error::<Test>::CannotRetireActiveVersion
		);
		assert_noop!(
			ZkVerifier::remove_verification_key(root().into(), retired, 1),
			Error::<Test>::CannotRemoveActiveVersion
		);

		assert_ok!(ZkVerifier::purge_circuit(root().into(), retired));

		assert!(VerificationKeys::<Test>::get(retired, 1).is_none());
		assert!(ActiveCircuitVersion::<Test>::get(retired).is_none());
	});
}

#[test]
fn purge_circuit_requires_root() {
	new_test_ext().execute_with(|| {
		let retired = CircuitId(5);
		seed_circuit(retired, 1, 2);
		assert_err!(
			ZkVerifier::purge_circuit(signed().into(), retired),
			sp_runtime::DispatchError::BadOrigin
		);
		assert!(VerificationKeys::<Test>::get(retired, 1).is_some());
	});
}

#[test]
fn purge_circuit_fails_when_nothing_stored() {
	new_test_ext().execute_with(|| {
		assert_noop!(
			ZkVerifier::purge_circuit(root().into(), CircuitId(5)),
			Error::<Test>::CircuitHasNoStorage
		);
	});
}

/// The declared weight is charged upfront, so a purge at the version cap must
/// leave room for the rest of the block. The runtime allows 2s of compute and
/// this call currently costs ~33ms of it; the 10% bound is loose enough not to
/// break on a re-benchmark but tight enough to catch a coefficient that grows
/// by an order of magnitude.
#[test]
fn purge_circuit_at_the_cap_fits_in_a_block() {
	use crate::weights::WeightInfo;
	use frame_support::weights::constants::WEIGHT_REF_TIME_PER_MILLIS;

	let worst =
		<Test as Config>::WeightInfo::purge_circuit(Pallet::<Test>::MAX_VERSIONS_PER_CIRCUIT);
	// Matches MAXIMUM_BLOCK_WEIGHT in the runtime.
	let block = 2_000u64 * WEIGHT_REF_TIME_PER_MILLIS;
	assert!(
		worst.ref_time() < block / 10,
		"purge_circuit at the cap costs {}ms of a 2000ms block",
		worst.ref_time() / WEIGHT_REF_TIME_PER_MILLIS
	);
}

/// An active pointer with no versions behind it is the one thing left to
/// clear, so the "nothing stored" guard must not treat it as nothing — and
/// the event must not report it as having cleared nothing either.
#[test]
fn purge_circuit_clears_a_stranded_active_pointer() {
	new_test_ext().execute_with(|| {
		let retired = CircuitId(5);
		ActiveCircuitVersion::<Test>::insert(retired, 1);

		assert_ok!(ZkVerifier::purge_circuit(root().into(), retired));

		assert!(ActiveCircuitVersion::<Test>::get(retired).is_none());
		assert!(has_event(Event::CircuitPurged {
			circuit_id: retired,
			removed: 1
		}));
	});
}

/// `removed` counts entries across every map, not versions. Maps whose
/// version sets differ would under-report if the count were a max, leaving an
/// indexer reconciling against a figure smaller than what actually went away.
#[test]
fn purge_circuit_reports_entries_not_versions() {
	new_test_ext().execute_with(|| {
		let retired = CircuitId(5);
		// One version with a key + hash, plus an orphan hash at another version
		// and a retired marker at a third: 2 + 1 + 1 entries, spread over three
		// distinct versions, none of which is a max of the per-map counts.
		seed_circuit(retired, 1, 2);
		VkHashes::<Test>::insert(retired, 2, [0x22u8; 32]);
		RetiredVersions::<Test>::insert(retired, 3, ());

		assert_ok!(ZkVerifier::purge_circuit(root().into(), retired));

		// keys(1) + hashes(2) + stats(0) + retired(1) + active pointer(1)
		assert!(has_event(Event::CircuitPurged {
			circuit_id: retired,
			removed: 5
		}));
	});
}

#[test]
fn purge_circuit_removes_every_version() {
	new_test_ext().execute_with(|| {
		let retired = CircuitId(5);
		for version in 1..=3u32 {
			seed_circuit(retired, version, 2);
		}

		assert_ok!(ZkVerifier::purge_circuit(root().into(), retired));

		assert!(
			VerificationKeys::<Test>::iter_key_prefix(retired)
				.next()
				.is_none()
		);
	});
}

/// Hashes and stats can sit in storage with no `VerificationKeys` row to
/// enumerate them. Clearing by prefix collects them; iterating one map's
/// versions would not.
#[test]
fn purge_circuit_clears_orphaned_satellite_entries() {
	new_test_ext().execute_with(|| {
		let retired = CircuitId(5);
		VkHashes::<Test>::insert(retired, 1, [0x11u8; 32]);
		VerificationStats::<Test>::insert(retired, 1, VerificationStatistics::default());
		RetiredVersions::<Test>::insert(retired, 1, ());
		// Deliberately no VerificationKeys entry.

		assert_ok!(ZkVerifier::purge_circuit(root().into(), retired));

		assert!(VkHashes::<Test>::get(retired, 1).is_none());
		assert!(!VerificationStats::<Test>::contains_key(retired, 1));
		assert!(!RetiredVersions::<Test>::contains_key(retired, 1));
	});
}

/// After a purge the circuit must be invisible to the runtime API, which is
/// what keeps explorers from listing a circuit the runtime cannot serve.
#[test]
fn purged_circuit_disappears_from_runtime_api() {
	new_test_ext().execute_with(|| {
		let retired = CircuitId(5);
		seed_circuit(retired, 1, 2);
		seed_circuit(CircuitId::TRANSFER, 1, TRANSFER_PUBLIC_INPUTS);

		assert_ok!(ZkVerifier::purge_circuit(root().into(), retired));

		let ids: Vec<u32> = ZkVerifier::runtime_api_get_all_circuit_versions()
			.into_iter()
			.map(|info| info.circuit_id)
			.collect();
		assert!(!ids.contains(&5));
		assert!(ids.contains(&CircuitId::TRANSFER.0));
	});
}

/// A purged version keeps its hash, as after `remove_verification_key`.
#[test]
fn purge_circuit_records_the_removed_hashes() {
	new_test_ext().execute_with(|| {
		let retired = CircuitId(5);
		assert_ok!(register(retired, 1, real_vk(2)));
		let hash = VkHashes::<Test>::get(retired, 1).expect("registration stores the hash");

		assert_ok!(ZkVerifier::purge_circuit(root().into(), retired));

		assert_eq!(crate::RemovedVkHashes::<Test>::get(retired, 1), Some(hash));
		assert_noop!(
			register(retired, 1, denied_vk_of(2)),
			Error::<Test>::VersionReused
		);
	});
}
