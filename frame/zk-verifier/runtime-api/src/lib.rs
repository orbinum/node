#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::vec::Vec;
use scale_info::TypeInfo;

#[derive(
	scale_codec::Encode,
	scale_codec::Decode,
	Clone,
	PartialEq,
	Eq,
	Debug,
	TypeInfo
)]
#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
pub struct VkVersionHash {
	pub version: u32,
	pub vk_hash: [u8; 32],
}

#[derive(
	scale_codec::Encode,
	scale_codec::Decode,
	Clone,
	PartialEq,
	Eq,
	Debug,
	TypeInfo
)]
#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
pub struct CircuitVersionInfo {
	pub circuit_id: u32,
	pub active_version: u32,
	pub supported_versions: Vec<u32>,
	pub vk_hashes: Vec<VkVersionHash>,
}

sp_api::decl_runtime_apis! {
	pub trait ZkVerifierRuntimeApi {
		fn get_circuit_version_info(circuit_id: u32) -> Option<CircuitVersionInfo>;
		fn get_all_circuit_versions() -> Vec<CircuitVersionInfo>;
	}
}
