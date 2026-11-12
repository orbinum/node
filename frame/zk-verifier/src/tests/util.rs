// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: GPL-3.0-or-later

//! Helpers the tests share: origins, keys, batches, proofs and seeded circuits.

use crate::{CircuitId, Event, VkBytes, VkEntry, VkHashes, tests::mock::*};
use frame_support::{BoundedVec, traits::ConstU32};
use orbinum_zk_verifier::{MEMO_HASH_INPUTS, TRANSFER_PUBLIC_INPUTS};
use sp_runtime::DispatchResult;

pub type Proof = BoundedVec<u8, MaxProofSize>;
pub type PublicInputs = BoundedVec<BoundedVec<u8, ConstU32<32>>, MaxPublicInputs>;
pub type BatchEntries = BoundedVec<VkEntry, ConstU32<10>>;

pub fn root() -> frame_system::Origin<Test> {
	frame_system::RawOrigin::Root
}

pub fn signed() -> frame_system::Origin<Test> {
	frame_system::RawOrigin::Signed(1u64)
}

pub fn has_event(expected: Event<Test>) -> bool {
	frame_system::Pallet::<Test>::events()
		.iter()
		.any(|rec| rec.event == RuntimeEvent::ZkVerifier(expected.clone()))
}

/// `register_verification_key` as Root.
pub fn register(circuit_id: CircuitId, version: u32, key: VkBytes) -> DispatchResult {
	ZkVerifier::register_verification_key(root().into(), circuit_id, version, key)
}

/// A transfer key registration accepts: the memo-bound layout.
pub fn vk_bytes() -> VkBytes {
	real_vk(TRANSFER_PUBLIC_INPUTS + MEMO_HASH_INPUTS)
}

pub fn vk_too_short() -> VkBytes {
	vec![0x01u8; 100].try_into().unwrap()
}

pub fn vk_empty() -> VkBytes {
	BoundedVec::default()
}

/// A key registration accepts for `circuit_id`: memo-bound for a spend
/// circuit, the base layout for shield and unknown ids. The version does not
/// matter.
pub fn vk_for(circuit_id: CircuitId, _version: u32) -> VkBytes {
	let id = circuit_id.0 as u8;
	let arity = match orbinum_zk_verifier::expected_public_inputs(id) {
		Some(base) if orbinum_zk_verifier::has_memo_layout(id) => base + MEMO_HASH_INPUTS,
		Some(base) => base,
		None => TRANSFER_PUBLIC_INPUTS,
	};
	real_vk(arity)
}

pub fn make_vk_entry(circuit_id: CircuitId, version: u32, set_active: bool) -> VkEntry {
	VkEntry {
		circuit_id,
		version,
		verification_key: vk_for(circuit_id, version),
		set_active,
	}
}

pub fn batch(entries: Vec<VkEntry>) -> BatchEntries {
	entries.try_into().unwrap()
}

pub fn proof_bytes() -> Proof {
	vec![0x01u8; 128].try_into().unwrap()
}

/// One valid 32-byte public input.
pub fn one_public_input() -> PublicInputs {
	let inner: BoundedVec<u8, ConstU32<32>> = vec![0x02u8; 32].try_into().unwrap();
	vec![inner].try_into().unwrap()
}

/// Seeds `VerificationKeys` and `VkHashes` for `(circuit_id, version)` and marks
/// the version active.
pub fn seed_circuit(circuit_id: CircuitId, version: u32, arity: usize) {
	insert_vk(circuit_id, version, arity);
	VkHashes::<Test>::insert(circuit_id, version, [0x11u8; 32]);
	activate(circuit_id, version);
}

pub fn memo_bound_transfer_key() -> VkBytes {
	real_vk(TRANSFER_PUBLIC_INPUTS + MEMO_HASH_INPUTS)
}

/// A memo-bound transfer key distinct from [`memo_bound_transfer_key`].
pub fn other_transfer_key() -> VkBytes {
	use ark_bn254::{Bn254, G1Affine, G2Affine};
	use ark_ec::{AffineRepr, CurveGroup};
	let g = G1Affine::generator();
	let vk = ark_groth16::VerifyingKey::<Bn254> {
		alpha_g1: (g + g).into_affine(),
		beta_g2: G2Affine::generator(),
		gamma_g2: G2Affine::generator(),
		delta_g2: (G2Affine::generator() + G2Affine::generator()).into_affine(),
		gamma_abc_g1: vec![g; TRANSFER_PUBLIC_INPUTS + MEMO_HASH_INPUTS + 1],
	};
	orbinum_zk_verifier::VerifyingKey::from_ark_vk(&vk)
		.unwrap()
		.bytes
		.try_into()
		.unwrap()
}
