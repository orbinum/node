// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

//! `pallet-zk-verifier`'s values as its runtime API returns them.

/// A circuit's version info from `pallet-zk-verifier`, in the runtime API's type.
pub(super) fn circuit_version_info(
	info: pallet_zk_verifier::CircuitVersionInfo,
) -> pallet_zk_verifier_runtime_api::CircuitVersionInfo {
	pallet_zk_verifier_runtime_api::CircuitVersionInfo {
		circuit_id: info.circuit_id,
		active_version: info.active_version,
		supported_versions: info.supported_versions,
		vk_hashes: info
			.vk_hashes
			.into_iter()
			.map(|item| pallet_zk_verifier_runtime_api::VkVersionHash {
				version: item.version,
				vk_hash: item.vk_hash,
			})
			.collect(),
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn every_field_and_hash_carries_over() {
		let info = pallet_zk_verifier::CircuitVersionInfo {
			circuit_id: 3,
			active_version: 2,
			supported_versions: vec![1, 2],
			vk_hashes: vec![
				pallet_zk_verifier::VkVersionHash {
					version: 1,
					vk_hash: [0x11; 32],
				},
				pallet_zk_verifier::VkVersionHash {
					version: 2,
					vk_hash: [0x22; 32],
				},
			],
		};
		let out = circuit_version_info(info);
		assert_eq!((out.circuit_id, out.active_version), (3, 2));
		assert_eq!(out.supported_versions, vec![1, 2]);
		let hashes: Vec<_> = out
			.vk_hashes
			.iter()
			.map(|h| (h.version, h.vk_hash))
			.collect();
		assert_eq!(hashes, vec![(1, [0x11; 32]), (2, [0x22; 32])]);
	}
}
