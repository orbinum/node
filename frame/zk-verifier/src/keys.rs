//! Key storage: a key, its hash and its prepared form are written and removed
//! together, and only here.
//!
//! [`PreparedKeys`] is read without re-validating its points, which is sound only
//! while its one writer is [`Pallet::store_vk`] (and the migration, through
//! [`Pallet::prepare_vk`]): every entry is the preparation of a key that passed
//! validation.

use crate::{
	Pallet,
	pallet::{
		ActiveCircuitVersion, Config, Error, PreparedKeys, RetiredVersions, VerificationKeys,
		VerificationStats, VkHashes,
	},
	types::{CircuitId, PreparedVkBytes, ProofSystem, VerificationKeyInfo, VkBytes},
};
use alloc::vec::Vec;
use frame_support::{dispatch::DispatchResult, ensure};

/// A key as storage holds it.
pub(crate) enum StoredKey {
	/// Prepared at registration ([`PreparedKeys`]): loaded without re-validation.
	Prepared(Vec<u8>),
	/// Only the key itself, prepared per proof: a key with no prepared form,
	/// which only storage written outside this module can leave.
	Raw(Vec<u8>),
}

impl<T: Config> Pallet<T> {
	/// Insert a validated key for `(circuit_id, version)` with its hash and its
	/// prepared form, within the per-circuit version cap.
	pub(crate) fn store_vk(
		circuit_id: CircuitId,
		version: u32,
		key_data: VkBytes,
	) -> DispatchResult {
		let count = VerificationKeys::<T>::iter_key_prefix(circuit_id).count() as u32;
		ensure!(
			count < Self::MAX_VERSIONS_PER_CIRCUIT,
			Error::<T>::TooManyVersions
		);
		let prepared = Self::prepare_vk(&key_data)?;
		let hash = sp_io::hashing::blake2_256(key_data.as_slice());
		VerificationKeys::<T>::insert(
			circuit_id,
			version,
			VerificationKeyInfo {
				key_data,
				system: ProofSystem::Groth16,
				registered_at: frame_system::Pallet::<T>::block_number(),
			},
		);
		VkHashes::<T>::insert(circuit_id, version, hash);
		PreparedKeys::<T>::insert(circuit_id, version, prepared);
		Ok(())
	}

	/// `key_data` validated and prepared, as [`PreparedKeys`] holds it.
	pub(crate) fn prepare_vk(key_data: &[u8]) -> Result<PreparedVkBytes, Error<T>> {
		orbinum_zk_verifier::VerifyingKey::new(key_data.to_vec())
			.prepared_bytes()
			.ok()
			.and_then(|bytes| bytes.try_into().ok())
			.ok_or(Error::<T>::InvalidVerificationKey)
	}

	/// The key to verify `(circuit_id, version)` against: its prepared form, else
	/// the key itself.
	pub(crate) fn load_vk(circuit_id: CircuitId, version: u32) -> Option<StoredKey> {
		if let Some(prepared) = PreparedKeys::<T>::get(circuit_id, version) {
			return Some(StoredKey::Prepared(prepared.into_inner()));
		}
		VerificationKeys::<T>::get(circuit_id, version)
			.map(|info| StoredKey::Raw(info.key_data.into_inner()))
	}

	/// Remove everything stored for one version.
	pub(crate) fn remove_vk(circuit_id: CircuitId, version: u32) {
		VerificationKeys::<T>::remove(circuit_id, version);
		PreparedKeys::<T>::remove(circuit_id, version);
		VkHashes::<T>::remove(circuit_id, version);
		VerificationStats::<T>::remove(circuit_id, version);
		RetiredVersions::<T>::remove(circuit_id, version);
	}

	/// Entries each per-version map holds for `circuit_id`, counted by iterating:
	/// `clear_prefix`'s counters miss this block's overlay writes.
	pub(crate) fn circuit_entries(circuit_id: CircuitId) -> [usize; 5] {
		[
			VerificationKeys::<T>::iter_key_prefix(circuit_id).count(),
			PreparedKeys::<T>::iter_key_prefix(circuit_id).count(),
			VkHashes::<T>::iter_key_prefix(circuit_id).count(),
			VerificationStats::<T>::iter_key_prefix(circuit_id).count(),
			RetiredVersions::<T>::iter_key_prefix(circuit_id).count(),
		]
	}

	/// Clear every map of `circuit_id`, its active pointer included.
	///
	/// `u32::MAX` as the limit: callers bound the prefixes first
	/// ([`Self::circuit_entries`]), so this clears everything in one pass.
	pub(crate) fn clear_circuit(circuit_id: CircuitId) {
		let _ = VerificationKeys::<T>::clear_prefix(circuit_id, u32::MAX, None);
		let _ = PreparedKeys::<T>::clear_prefix(circuit_id, u32::MAX, None);
		let _ = VkHashes::<T>::clear_prefix(circuit_id, u32::MAX, None);
		let _ = VerificationStats::<T>::clear_prefix(circuit_id, u32::MAX, None);
		let _ = RetiredVersions::<T>::clear_prefix(circuit_id, u32::MAX, None);
		ActiveCircuitVersion::<T>::remove(circuit_id);
	}
}
