// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: GPL-3.0-or-later

//! What the runtime API returns: each circuit's versions and their key hashes.
//! The runtime maps these onto `pallet-zk-verifier-runtime-api`'s own types.

/// (version, VK hash) pair used in [`CircuitVersionInfo`].
#[derive(
	Clone,
	PartialEq,
	Eq,
	parity_scale_codec::Encode,
	parity_scale_codec::Decode,
	scale_info::TypeInfo,
	Debug
)]
pub struct VkVersionHash {
	pub version: u32,
	pub vk_hash: [u8; 32],
}

/// Versioning summary for one circuit, returned by runtime API queries.
#[derive(
	Clone,
	PartialEq,
	Eq,
	parity_scale_codec::Encode,
	parity_scale_codec::Decode,
	scale_info::TypeInfo,
	Debug
)]
pub struct CircuitVersionInfo {
	pub circuit_id: u32,
	pub active_version: u32,
	pub supported_versions: alloc::vec::Vec<u32>,
	pub vk_hashes: alloc::vec::Vec<VkVersionHash>,
}
