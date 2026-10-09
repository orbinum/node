//! Storage migrations.

/// v1 → v2: store every key prepared ([`crate::pallet::PreparedKeys`]).
pub mod v2 {
	use crate::{
		Pallet, WeightInfo,
		pallet::{Config, PreparedKeys, VerificationKeys},
	};
	use frame_support::{
		migrations::VersionedMigration,
		traits::{Get, UncheckedOnRuntimeUpgrade},
		weights::Weight,
	};

	/// Prepare every stored key, overwriting any prepared form already there, so
	/// one written by an older or partial run is replaced too.
	///
	/// Bounded: at most `MAX_VERSIONS_PER_CIRCUIT` keys per circuit, and only the
	/// few circuits Root registered. A key that fails to prepare is skipped and
	/// logged, and any prepared form left for it is dropped: verifying under it
	/// falls back to preparing per proof.
	pub struct PrepareKeys<T>(core::marker::PhantomData<T>);

	impl<T: Config> UncheckedOnRuntimeUpgrade for PrepareKeys<T> {
		fn on_runtime_upgrade() -> Weight {
			let mut keys = 0u64;
			for (circuit_id, version, info) in VerificationKeys::<T>::iter() {
				keys = keys.saturating_add(1);
				match Pallet::<T>::prepare_vk(&info.key_data) {
					Ok(bytes) => PreparedKeys::<T>::insert(circuit_id, version, bytes),
					Err(_) => {
						PreparedKeys::<T>::remove(circuit_id, version);
						frame_support::__private::log::warn!(
							target: "runtime::zk-verifier",
							"key {circuit_id:?} v{version} does not prepare; left to the per-proof path",
						);
					}
				}
			}
			// Preparing is the cost a registration pays, so charge one per key.
			T::DbWeight::get()
				.reads_writes(keys, keys)
				.saturating_add(T::WeightInfo::register_verification_key().saturating_mul(keys))
		}

		/// Every key has the prepared form `prepare_vk` gives it, and no prepared
		/// form is left without its key.
		#[cfg(feature = "try-runtime")]
		fn post_upgrade(_: alloc::vec::Vec<u8>) -> Result<(), sp_runtime::TryRuntimeError> {
			for (circuit_id, version, info) in VerificationKeys::<T>::iter() {
				let expected = Pallet::<T>::prepare_vk(&info.key_data).ok();
				frame_support::ensure!(
					PreparedKeys::<T>::get(circuit_id, version) == expected,
					"a key's prepared form is not its preparation"
				);
			}
			frame_support::ensure!(
				PreparedKeys::<T>::iter_keys()
					.all(|(c, v)| VerificationKeys::<T>::contains_key(c, v)),
				"a prepared form has no key"
			);
			Ok(())
		}
	}

	/// [`PrepareKeys`], run once when the pallet's storage is at v1.
	pub type MigrateToV2<T> =
		VersionedMigration<1, 2, PrepareKeys<T>, Pallet<T>, <T as frame_system::Config>::DbWeight>;
}
