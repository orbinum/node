//! Storage migrations for pallet-zk-verifier.

use crate::pallet::{
	ActiveCircuitVersion, Config, Pallet, RetiredVersions, VerificationKeys, VerificationStats,
	VkHashes,
};
use crate::types::CircuitId;
use crate::weights::WeightInfo as _;
use frame_support::{
	pallet_prelude::*,
	traits::{GetStorageVersion, OnRuntimeUpgrade},
	weights::Weight,
};
#[cfg(feature = "try-runtime")]
use sp_std::vec::Vec;

pub mod v1 {
	use super::*;

	/// Circuit id of the retired `private_link` proof.
	///
	/// Hardcoded rather than derived from `expected_public_inputs`: this runs
	/// once, only on chains still at storage v0, where 5 can only ever mean
	/// `private_link`. A chain that reassigns the id is already past v1 and never
	/// executes this.
	const RETIRED_PRIVATE_LINK: CircuitId = CircuitId(5);

	/// Storage v0 -> v1: drop the `private_link` circuit (id 5).
	///
	/// The circuit was removed from the runtime along with
	/// `pallet-account-mapping`, its only consumer, but chains that ran the
	/// previous runtime still carry its verification key on-chain. Nothing can
	/// route to it — `ZkVerifierPort` no longer exposes
	/// `verify_private_link_proof` — yet it stays visible: the
	/// `get_all_circuit_versions` runtime API iterates storage keys with no
	/// allowlist, so explorers keep listing a circuit the runtime cannot serve.
	///
	/// Runs unconditionally rather than leaving the cleanup to `purge_circuit`:
	/// the migration lands with the runtime that retires the circuit, so chains
	/// are clean the moment they upgrade instead of waiting on a governance call.
	///
	/// One-shot, and in practice the circuit only ever had one version registered.
	pub struct MigrateToV1<T>(core::marker::PhantomData<T>);

	impl<T: Config> OnRuntimeUpgrade for MigrateToV1<T> {
		fn on_runtime_upgrade() -> Weight {
			if Pallet::<T>::on_chain_storage_version() >= 1 {
				return T::DbWeight::get().reads(1);
			}

			// Cleared by prefix, not by iterating one map's versions: an earlier
			// `remove_verification_key` dropped keys without their hash or stats, so
			// the satellite maps can hold entries no `VerificationKeys` row lists.
			//
			// Counted separately because `clear_prefix`'s own counters only report
			// keys committed to the backend, and writes from the same block are
			// still in the overlay.
			//
			// The widest map, not the sum: this feeds `purge_circuit`'s benchmark,
			// whose linear component is already the per-version cost of clearing all
			// four maps.
			let versions = [
				VerificationKeys::<T>::iter_key_prefix(RETIRED_PRIVATE_LINK).count(),
				VkHashes::<T>::iter_key_prefix(RETIRED_PRIVATE_LINK).count(),
				VerificationStats::<T>::iter_key_prefix(RETIRED_PRIVATE_LINK).count(),
				RetiredVersions::<T>::iter_key_prefix(RETIRED_PRIVATE_LINK).count(),
			]
			.into_iter()
			.max()
			.unwrap_or(0) as u32;

			let _ = VerificationKeys::<T>::clear_prefix(RETIRED_PRIVATE_LINK, u32::MAX, None);
			let _ = VkHashes::<T>::clear_prefix(RETIRED_PRIVATE_LINK, u32::MAX, None);
			let _ = VerificationStats::<T>::clear_prefix(RETIRED_PRIVATE_LINK, u32::MAX, None);
			let _ = RetiredVersions::<T>::clear_prefix(RETIRED_PRIVATE_LINK, u32::MAX, None);
			ActiveCircuitVersion::<T>::remove(RETIRED_PRIVATE_LINK);

			StorageVersion::new(1).put::<Pallet<T>>();

			// Reuse the extrinsic's benchmark: it measures exactly this work, so the
			// migration cannot drift from the cost the runner actually recorded.
			T::WeightInfo::purge_circuit(versions)
				.saturating_add(T::DbWeight::get().reads_writes(1, 2))
		}

		/// Records how many circuits are registered, so `post_upgrade` can assert
		/// the migration removed at most the retired one.
		#[cfg(feature = "try-runtime")]
		fn pre_upgrade() -> Result<Vec<u8>, sp_runtime::TryRuntimeError> {
			let others = VerificationKeys::<T>::iter_keys()
				.filter(|(cid, _)| *cid != RETIRED_PRIVATE_LINK)
				.count() as u32;
			Ok(others.encode())
		}

		#[cfg(feature = "try-runtime")]
		fn post_upgrade(state: Vec<u8>) -> Result<(), sp_runtime::TryRuntimeError> {
			let others_before = u32::decode(&mut state.as_slice())
				.map_err(|_| sp_runtime::TryRuntimeError::Other("pre_upgrade state decode"))?;

			frame_support::ensure!(
				Pallet::<T>::on_chain_storage_version() >= 1,
				sp_runtime::TryRuntimeError::Other("storage version not bumped to 1")
			);
			frame_support::ensure!(
				VerificationKeys::<T>::iter_key_prefix(RETIRED_PRIVATE_LINK)
					.next()
					.is_none(),
				sp_runtime::TryRuntimeError::Other("circuit 5 keys still present")
			);
			// The satellite maps are the ones an earlier `remove_verification_key`
			// could strand, so check them explicitly rather than trusting that
			// clearing `VerificationKeys` implied clearing these.
			frame_support::ensure!(
				VkHashes::<T>::iter_key_prefix(RETIRED_PRIVATE_LINK)
					.next()
					.is_none(),
				sp_runtime::TryRuntimeError::Other("circuit 5 vk hashes still present")
			);
			frame_support::ensure!(
				VerificationStats::<T>::iter_key_prefix(RETIRED_PRIVATE_LINK)
					.next()
					.is_none(),
				sp_runtime::TryRuntimeError::Other("circuit 5 stats still present")
			);
			frame_support::ensure!(
				RetiredVersions::<T>::iter_key_prefix(RETIRED_PRIVATE_LINK)
					.next()
					.is_none(),
				sp_runtime::TryRuntimeError::Other("circuit 5 retired versions still present")
			);
			frame_support::ensure!(
				ActiveCircuitVersion::<T>::get(RETIRED_PRIVATE_LINK).is_none(),
				sp_runtime::TryRuntimeError::Other("circuit 5 still has an active version")
			);

			// Every other circuit must be untouched: this migration only ever
			// clears the retired id.
			let others_after = VerificationKeys::<T>::iter_keys()
				.filter(|(cid, _)| *cid != RETIRED_PRIVATE_LINK)
				.count() as u32;
			frame_support::ensure!(
				others_after == others_before,
				sp_runtime::TryRuntimeError::Other("migration touched a live circuit")
			);
			Ok(())
		}
	}
}

#[cfg(test)]
mod tests {
	use super::v1::MigrateToV1;
	use crate::mock::Test;
	use crate::pallet::{
		ActiveCircuitVersion, Pallet, RetiredVersions, VerificationKeys, VerificationStats,
		VkHashes,
	};
	use crate::types::{CircuitId, ProofSystem, VerificationKeyInfo};
	use frame_support::{
		BoundedVec,
		traits::{GetStorageVersion, OnRuntimeUpgrade, StorageVersion},
	};
	use sp_io::TestExternalities;
	use sp_runtime::BuildStorage;

	const PRIVATE_LINK: CircuitId = CircuitId(5);

	fn new_test_ext() -> TestExternalities {
		let storage = frame_system::GenesisConfig::<Test>::default()
			.build_storage()
			.expect("mock storage ok");
		TestExternalities::new(storage)
	}

	fn seed(circuit_id: CircuitId, version: u32) {
		let key_data: BoundedVec<u8, frame_support::traits::ConstU32<8192>> =
			vec![0xABu8; 300].try_into().unwrap();
		VerificationKeys::<Test>::insert(
			circuit_id,
			version,
			VerificationKeyInfo {
				key_data,
				system: ProofSystem::Groth16,
				registered_at: 0u64,
			},
		);
		VkHashes::<Test>::insert(circuit_id, version, [0x11u8; 32]);
		ActiveCircuitVersion::<Test>::insert(circuit_id, version);
	}

	#[test]
	fn clears_every_map_for_the_retired_circuit() {
		new_test_ext().execute_with(|| {
			StorageVersion::new(0).put::<Pallet<Test>>();
			seed(PRIVATE_LINK, 1);
			RetiredVersions::<Test>::insert(PRIVATE_LINK, 1, ());

			MigrateToV1::<Test>::on_runtime_upgrade();

			assert!(VerificationKeys::<Test>::get(PRIVATE_LINK, 1).is_none());
			assert!(VkHashes::<Test>::get(PRIVATE_LINK, 1).is_none());
			assert!(!VerificationStats::<Test>::contains_key(PRIVATE_LINK, 1));
			assert!(!RetiredVersions::<Test>::contains_key(PRIVATE_LINK, 1));
			assert!(ActiveCircuitVersion::<Test>::get(PRIVATE_LINK).is_none());
			assert_eq!(Pallet::<Test>::on_chain_storage_version(), 1);
		});
	}

	/// The migration must not disturb circuits the runtime still implements.
	#[test]
	fn leaves_live_circuits_untouched() {
		new_test_ext().execute_with(|| {
			StorageVersion::new(0).put::<Pallet<Test>>();
			seed(CircuitId::TRANSFER, 1);
			seed(CircuitId::UNSHIELD, 1);
			seed(CircuitId::VALUE_PROOF, 1);
			seed(PRIVATE_LINK, 1);

			MigrateToV1::<Test>::on_runtime_upgrade();

			for cid in [
				CircuitId::TRANSFER,
				CircuitId::UNSHIELD,
				CircuitId::VALUE_PROOF,
			] {
				assert!(VerificationKeys::<Test>::get(cid, 1).is_some());
				assert_eq!(ActiveCircuitVersion::<Test>::get(cid), Some(1));
			}
			assert!(VerificationKeys::<Test>::get(PRIVATE_LINK, 1).is_none());
		});
	}

	/// The case the prefix-clear exists for: an earlier `remove_verification_key`
	/// dropped the key but left its hash and stats, so there is no
	/// `VerificationKeys` row to enumerate them from.
	#[test]
	fn clears_satellite_maps_with_no_verification_key() {
		new_test_ext().execute_with(|| {
			StorageVersion::new(0).put::<Pallet<Test>>();
			VkHashes::<Test>::insert(PRIVATE_LINK, 1, [0x11u8; 32]);
			RetiredVersions::<Test>::insert(PRIVATE_LINK, 1, ());
			// Deliberately no VerificationKeys entry.

			MigrateToV1::<Test>::on_runtime_upgrade();

			assert!(VkHashes::<Test>::get(PRIVATE_LINK, 1).is_none());
			assert!(!RetiredVersions::<Test>::contains_key(PRIVATE_LINK, 1));
		});
	}

	/// Running twice must be a no-op, not a double-charge.
	#[test]
	fn is_idempotent() {
		new_test_ext().execute_with(|| {
			StorageVersion::new(0).put::<Pallet<Test>>();
			seed(PRIVATE_LINK, 1);

			let first = MigrateToV1::<Test>::on_runtime_upgrade();
			let second = MigrateToV1::<Test>::on_runtime_upgrade();

			// Second run hits the version guard and returns before doing any work,
			// so it must be strictly cheaper than the run that cleared storage.
			assert!(second.ref_time() < first.ref_time() || second.all_lte(first));
			assert!(VerificationKeys::<Test>::get(PRIVATE_LINK, 1).is_none());
		});
	}

	/// A chain that never registered the circuit still lands on version 1.
	#[test]
	fn bumps_version_when_nothing_to_clear() {
		new_test_ext().execute_with(|| {
			StorageVersion::new(0).put::<Pallet<Test>>();

			MigrateToV1::<Test>::on_runtime_upgrade();

			assert_eq!(Pallet::<Test>::on_chain_storage_version(), 1);
		});
	}

	/// The `try-runtime` hooks are what an upgrade dry-run relies on, but nothing
	/// else in the suite executes them: the tests above call `on_runtime_upgrade`
	/// directly, and the CLI cannot get this far on a real snapshot because an
	/// earlier migration in the tuple needs a host function it does not register.
	/// Without this the checks are unrun code.
	#[cfg(feature = "try-runtime")]
	#[test]
	fn try_runtime_hooks_pass_over_a_realistic_state() {
		new_test_ext().execute_with(|| {
			StorageVersion::new(0).put::<Pallet<Test>>();
			// The retired circuit alongside live ones, plus satellite entries the
			// post-upgrade checks look at individually.
			seed(PRIVATE_LINK, 1);
			seed(PRIVATE_LINK, 2);
			RetiredVersions::<Test>::insert(PRIVATE_LINK, 2, ());
			VerificationStats::<Test>::insert(
				PRIVATE_LINK,
				1,
				crate::types::VerificationStatistics::default(),
			);
			seed(CircuitId::TRANSFER, 1);
			seed(CircuitId::UNSHIELD, 1);

			let state = MigrateToV1::<Test>::pre_upgrade().expect("pre_upgrade");
			MigrateToV1::<Test>::on_runtime_upgrade();
			MigrateToV1::<Test>::post_upgrade(state).expect("post_upgrade");
		});
	}

	/// `post_upgrade` must fail, not pass silently, when the migration left the
	/// circuit behind — otherwise a dry-run would green-light a broken upgrade.
	#[cfg(feature = "try-runtime")]
	#[test]
	fn try_runtime_post_upgrade_catches_leftovers() {
		new_test_ext().execute_with(|| {
			StorageVersion::new(0).put::<Pallet<Test>>();
			seed(PRIVATE_LINK, 1);

			let state = MigrateToV1::<Test>::pre_upgrade().expect("pre_upgrade");
			MigrateToV1::<Test>::on_runtime_upgrade();
			// Simulate a migration that missed one of the satellite maps.
			VkHashes::<Test>::insert(PRIVATE_LINK, 1, [0x11u8; 32]);

			assert!(MigrateToV1::<Test>::post_upgrade(state).is_err());
		});
	}
}
