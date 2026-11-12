// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: GPL-3.0-or-later

//! Registering and activating keys, and the rule every stored key is held to.

use super::verifier::admitted_layout;
use crate::{
	ActiveCircuitVersion, CircuitId, Config, DeniedVkHashes, Error, Event, Pallet, RemovedVkHashes,
	VerificationKeys, VkBytes,
};
use frame_support::{dispatch::DispatchResult, ensure};

impl<T: Config> Pallet<T> {
	/// Validate and store a new key for `(circuit_id, version)`, then activate
	/// it if `set_active` or the circuit has no active version yet. Every
	/// registration path (extrinsics, genesis) goes through here.
	pub(crate) fn register_vk(
		circuit_id: CircuitId,
		version: u32,
		key_data: VkBytes,
		set_active: bool,
	) -> DispatchResult {
		ensure!(!key_data.is_empty(), Error::<T>::EmptyVerificationKey);
		Self::ensure_vk_admitted(circuit_id, &key_data)?;
		// Never overwrite: a replaced key would silently change what verifies.
		ensure!(
			!VerificationKeys::<T>::contains_key(circuit_id, version),
			Error::<T>::CircuitAlreadyExists
		);
		// Nor reuse a removed version for another key.
		ensure!(
			RemovedVkHashes::<T>::get(circuit_id, version)
				.is_none_or(|h| h == sp_io::hashing::blake2_256(&key_data)),
			Error::<T>::VersionReused
		);
		Self::store_vk(circuit_id, version, key_data)?;
		Self::deposit_event(Event::VerificationKeyRegistered {
			circuit_id,
			version,
		});
		if set_active || ActiveCircuitVersion::<T>::get(circuit_id).is_none() {
			Self::activate(circuit_id, version);
		}
		Ok(())
	}

	/// Make `version` the one new spends of `circuit_id` are verified under.
	pub(crate) fn activate(circuit_id: CircuitId, version: u32) {
		ActiveCircuitVersion::<T>::insert(circuit_id, version);
		Self::deposit_event(Event::ActiveVersionSet {
			circuit_id,
			version,
		});
	}

	/// Whether `hash` is in `DeniedVkHashes`.
	pub(crate) fn is_denied(hash: &[u8; 32]) -> bool {
		DeniedVkHashes::<T>::contains_key(hash)
	}

	/// The rule every stored key is held to: it is not denied, it deserializes as
	/// a BN254 Groth16 key, and its arity gives an admitted layout
	/// ([`admitted_layout`]). Ids outside the known table are only checked to
	/// deserialize.
	pub(crate) fn ensure_vk_admitted(circuit_id: CircuitId, key_data: &[u8]) -> DispatchResult {
		ensure!(
			!Self::is_denied(&sp_io::hashing::blake2_256(key_data)),
			Error::<T>::DeniedVerificationKey
		);
		let arity = orbinum_zk_verifier::VerifyingKey::new(key_data.to_vec())
			.num_public_inputs()
			.map_err(|_| Error::<T>::InvalidVerificationKey)?;
		admitted_layout(circuit_id, arity)
			.map(|_| ())
			.ok_or(Error::<T>::InvalidVerificationKey.into())
	}
}
