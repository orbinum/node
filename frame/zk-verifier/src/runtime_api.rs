//! Runtime API query helpers for `pallet-zk-verifier`.
//!
//! Read-only functions called by the runtime API implementation in
//! `template/runtime`. They never modify state.

extern crate alloc;

use crate::{
	CircuitVersionInfo, VkVersionHash,
	pallet::{ActiveCircuitVersion, Config, VerificationKeys},
	types::CircuitId,
};

impl<T: Config> crate::Pallet<T> {
	/// Return version info for one circuit, or `None` if it has no registered keys.
	pub fn runtime_api_get_circuit_version_info(circuit_id: u32) -> Option<CircuitVersionInfo> {
		let cid = CircuitId(circuit_id);

		let mut supported: alloc::vec::Vec<u32> = VerificationKeys::<T>::iter_prefix(cid)
			.map(|(v, _)| v)
			.collect();
		if supported.is_empty() {
			return None;
		}
		supported.sort_unstable();

		let active_version = ActiveCircuitVersion::<T>::get(cid)?;

		let vk_hashes = supported
			.iter()
			.filter_map(|v| {
				VerificationKeys::<T>::get(cid, v).map(|vk| VkVersionHash {
					version: *v,
					vk_hash: sp_io::hashing::blake2_256(vk.key_data.as_slice()),
				})
			})
			.collect();

		Some(CircuitVersionInfo {
			circuit_id,
			active_version,
			supported_versions: supported,
			vk_hashes,
		})
	}

	/// Return version info for all circuits that have at least one registered key.
	pub fn runtime_api_get_all_circuit_versions() -> alloc::vec::Vec<CircuitVersionInfo> {
		use alloc::collections::BTreeSet;

		let ids: BTreeSet<u32> = VerificationKeys::<T>::iter_keys()
			.map(|(cid, _)| cid.0)
			.collect();

		ids.into_iter()
			.filter_map(Self::runtime_api_get_circuit_version_info)
			.collect()
	}
}
