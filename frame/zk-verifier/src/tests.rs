//! Extrinsic, genesis and runtime-API tests for the pallet.

use super::*;
use crate::{
	mock::{
		MaxProofSize, MaxPublicInputs, RuntimeEvent, Test, ZkVerifier, activate, insert_vk,
		new_test_ext, real_vk,
	},
	pallet::{
		ActiveCircuitVersion, Event, RetiredVersions, VerificationKeys, VerificationStats, VkHashes,
	},
	types::VkEntry,
};
use frame_support::{BoundedVec, assert_err, assert_noop, assert_ok, traits::ConstU32};
use orbinum_zk_verifier::{
	MEMO_HASH_INPUTS, SHIELD_PUBLIC_INPUTS, TRANSFER_PUBLIC_INPUTS, UNSHIELD_PUBLIC_INPUTS,
};
use sp_io::TestExternalities;
use sp_runtime::{BuildStorage, DispatchResult};

// ── Helpers ───────────────────────────────────────────────────────────────────

type Proof = BoundedVec<u8, MaxProofSize>;
type PublicInputs = BoundedVec<BoundedVec<u8, ConstU32<32>>, MaxPublicInputs>;
type BatchEntries = BoundedVec<VkEntry, ConstU32<10>>;

fn root() -> frame_system::Origin<Test> {
	frame_system::RawOrigin::Root
}

fn signed() -> frame_system::Origin<Test> {
	frame_system::RawOrigin::Signed(1u64)
}

fn has_event(expected: Event<Test>) -> bool {
	frame_system::Pallet::<Test>::events()
		.iter()
		.any(|rec| rec.event == RuntimeEvent::ZkVerifier(expected.clone()))
}

/// `register_verification_key` as Root.
fn register(circuit_id: CircuitId, version: u32, key: VkBytes) -> DispatchResult {
	ZkVerifier::register_verification_key(root().into(), circuit_id, version, key)
}

fn vk_bytes() -> VkBytes {
	real_vk(TRANSFER_PUBLIC_INPUTS)
}

fn vk_too_short() -> VkBytes {
	vec![0x01u8; 100].try_into().unwrap()
}

fn vk_empty() -> VkBytes {
	BoundedVec::default()
}

/// A key registration accepts for `(circuit_id, version)`: the base layout for
/// the first version, the memo-bound one for any later version of a spend circuit.
fn vk_for(circuit_id: CircuitId, version: u32) -> VkBytes {
	let id = circuit_id.0 as u8;
	let arity = match orbinum_zk_verifier::expected_public_inputs(id) {
		Some(base)
			if version > Pallet::<Test>::FIRST_VERSION
				&& orbinum_zk_verifier::has_memo_layout(id) =>
		{
			base + MEMO_HASH_INPUTS
		}
		Some(base) => base,
		None => TRANSFER_PUBLIC_INPUTS,
	};
	real_vk(arity)
}

fn make_vk_entry(circuit_id: CircuitId, version: u32, set_active: bool) -> VkEntry {
	VkEntry {
		circuit_id,
		version,
		verification_key: vk_for(circuit_id, version),
		set_active,
	}
}

fn batch(entries: Vec<VkEntry>) -> BatchEntries {
	entries.try_into().unwrap()
}

fn proof_bytes() -> Proof {
	vec![0x01u8; 128].try_into().unwrap()
}

/// One valid 32-byte public input.
fn one_public_input() -> PublicInputs {
	let inner: BoundedVec<u8, ConstU32<32>> = vec![0x02u8; 32].try_into().unwrap();
	vec![inner].try_into().unwrap()
}

/// Seeds `VerificationKeys` and `VkHashes` for `(circuit_id, version)` and marks
/// the version active.
fn seed_circuit(circuit_id: CircuitId, version: u32, arity: usize) {
	insert_vk(circuit_id, version, arity);
	VkHashes::<Test>::insert(circuit_id, version, [0x11u8; 32]);
	activate(circuit_id, version);
}

// ── register_verification_key ─────────────────────────────────────────────────

#[test]
fn register_vk_requires_root() {
	new_test_ext().execute_with(|| {
		assert_noop!(
			ZkVerifier::register_verification_key(
				signed().into(),
				CircuitId::TRANSFER,
				1,
				vk_bytes(),
			),
			sp_runtime::DispatchError::BadOrigin
		);
	});
}

#[test]
fn register_vk_rejects_empty_key() {
	new_test_ext().execute_with(|| {
		assert_noop!(
			register(CircuitId::TRANSFER, 1, vk_empty()),
			Error::<Test>::EmptyVerificationKey
		);
	});
}

#[test]
fn register_vk_rejects_key_shorter_than_256_bytes() {
	new_test_ext().execute_with(|| {
		assert_noop!(
			register(CircuitId::TRANSFER, 1, vk_too_short()),
			Error::<Test>::InvalidVerificationKey
		);
	});
}

/// A version that binds its memos takes one input more; it registers
/// alongside the base version, which keeps verifying until retired.
#[test]
fn register_vk_accepts_the_memo_bound_arity_next_to_the_base_one() {
	new_test_ext().execute_with(|| {
		assert_ok!(register(
			CircuitId::TRANSFER,
			1,
			real_vk(TRANSFER_PUBLIC_INPUTS)
		));
		assert_ok!(register(
			CircuitId::TRANSFER,
			2,
			real_vk(TRANSFER_PUBLIC_INPUTS + MEMO_HASH_INPUTS)
		));
		assert_ok!(register(
			CircuitId::UNSHIELD,
			2,
			real_vk(UNSHIELD_PUBLIC_INPUTS + MEMO_HASH_INPUTS)
		));
	});
}

/// A transfer that proves each input against its own root takes one input more
/// than the memo-bound layout; an unshield has a single input and no such layout.
#[test]
fn register_vk_accepts_the_cross_tree_arity_for_a_transfer_only() {
	new_test_ext().execute_with(|| {
		assert_ok!(register(
			CircuitId::TRANSFER,
			3,
			real_vk(TRANSFER_PUBLIC_INPUTS + MEMO_HASH_INPUTS + 1)
		));
		assert_noop!(
			register(
				CircuitId::UNSHIELD,
				3,
				real_vk(UNSHIELD_PUBLIC_INPUTS + MEMO_HASH_INPUTS + 1)
			),
			Error::<Test>::InvalidVerificationKey
		);
	});
}

/// A rotation that keeps the layout: unshield v3 (canonical spending key) has
/// the same 8 inputs as v2, so it registers and activates like any later
/// memo-bound version.
#[test]
fn register_vk_accepts_a_memo_bound_rotation_at_the_same_arity() {
	new_test_ext().execute_with(|| {
		let arity = UNSHIELD_PUBLIC_INPUTS + MEMO_HASH_INPUTS;
		assert_ok!(register(CircuitId::UNSHIELD, 2, real_vk(arity)));
		assert_ok!(register(CircuitId::UNSHIELD, 3, real_vk(arity)));
		assert_ok!(ZkVerifier::set_active_version(
			root().into(),
			CircuitId::UNSHIELD,
			3
		));
		assert_ok!(ZkVerifier::retire_version(
			root().into(),
			CircuitId::UNSHIELD,
			2
		));
	});
}

/// An identity `gamma_abc` point would leave its public input unbound.
#[test]
fn register_vk_rejects_a_point_at_infinity() {
	use ark_bn254::{Bn254, G1Affine, G2Affine};
	use ark_ec::AffineRepr;
	new_test_ext().execute_with(|| {
		let mut abc: Vec<G1Affine> = (0..=TRANSFER_PUBLIC_INPUTS)
			.map(|_| G1Affine::generator())
			.collect();
		abc[4] = G1Affine::zero();
		let vk = ark_groth16::VerifyingKey::<Bn254> {
			alpha_g1: G1Affine::generator(),
			beta_g2: G2Affine::generator(),
			gamma_g2: G2Affine::generator(),
			delta_g2: G2Affine::generator(),
			gamma_abc_g1: abc,
		};
		let bytes = orbinum_zk_verifier::VerifyingKey::from_ark_vk(&vk)
			.unwrap()
			.bytes;
		assert_noop!(
			register(CircuitId::TRANSFER, 1, bytes.try_into().unwrap()),
			Error::<Test>::InvalidVerificationKey
		);
	});
}

/// A later version of a known circuit must be memo-bound: re-registering a
/// base (v1-layout) key as "v2" would rotate nothing but the number.
#[test]
fn register_vk_refuses_the_base_layout_past_version_one() {
	new_test_ext().execute_with(|| {
		for (version, key) in [
			(2, real_vk(TRANSFER_PUBLIC_INPUTS)),
			(7, real_vk(TRANSFER_PUBLIC_INPUTS)),
		] {
			assert_noop!(
				register(CircuitId::TRANSFER, version, key),
				Error::<Test>::InvalidVerificationKey
			);
		}
		assert_ok!(register(
			CircuitId::TRANSFER,
			2,
			vk_for(CircuitId::TRANSFER, 2)
		));
	});
}

/// Shield has no memo-bound layout: every version takes the base arity, and one
/// input more — memo-bound for a spend circuit — is refused.
#[test]
fn register_vk_takes_shield_at_its_base_arity_for_every_version() {
	new_test_ext().execute_with(|| {
		assert_ok!(register(
			CircuitId::SHIELD,
			1,
			real_vk(SHIELD_PUBLIC_INPUTS)
		));
		assert_ok!(register(
			CircuitId::SHIELD,
			2,
			real_vk(SHIELD_PUBLIC_INPUTS)
		));
		for version in [1, 3] {
			assert_noop!(
				register(
					CircuitId::SHIELD,
					version,
					real_vk(SHIELD_PUBLIC_INPUTS + MEMO_HASH_INPUTS)
				),
				Error::<Test>::InvalidVerificationKey
			);
		}
	});
}

/// The v1 → v2 rotation, done by Root extrinsics after the upgrade: register
/// the memo-bound keys as version 2, make them active, retire version 1.
#[test]
fn v1_rotates_to_memo_bound_v2_by_extrinsic() {
	new_test_ext().execute_with(|| {
		for (cid, base) in [
			(CircuitId::TRANSFER, TRANSFER_PUBLIC_INPUTS),
			(CircuitId::UNSHIELD, UNSHIELD_PUBLIC_INPUTS),
		] {
			assert_ok!(register(cid, 1, real_vk(base)));
			assert_ok!(register(cid, 2, vk_for(cid, 2)));
			// Registering v2 leaves v1 active until Root switches.
			assert_eq!(ActiveCircuitVersion::<Test>::get(cid), Some(1));
			assert_ok!(ZkVerifier::set_active_version(root().into(), cid, 2));
			assert_ok!(ZkVerifier::retire_version(root().into(), cid, 1));

			assert_eq!(ActiveCircuitVersion::<Test>::get(cid), Some(2));
			assert!(RetiredVersions::<Test>::contains_key(cid, 1));
			// A retired v1 can never be made active again.
			assert_noop!(
				ZkVerifier::set_active_version(root().into(), cid, 1),
				Error::<Test>::UnsupportedCircuitVersion
			);
		}
	});
}

#[test]
fn register_vk_rejects_wrong_arity() {
	new_test_ext().execute_with(|| {
		// TRANSFER takes its base arity, memo-bound (+1) or cross-tree (+2);
		// anything else is rejected.
		assert_noop!(
			register(CircuitId::TRANSFER, 1, real_vk(TRANSFER_PUBLIC_INPUTS + 3)),
			Error::<Test>::InvalidVerificationKey
		);
		assert_noop!(
			register(CircuitId::UNSHIELD, 1, real_vk(UNSHIELD_PUBLIC_INPUTS + 2)),
			Error::<Test>::InvalidVerificationKey
		);
		// The matching arity is accepted.
		assert_ok!(register(
			CircuitId::TRANSFER,
			1,
			real_vk(TRANSFER_PUBLIC_INPUTS)
		));
	});
}

/// A circuit id past 255 must be refused, not truncated.
///
/// `expected_public_inputs` takes a `u8`, so `circuit_id.0 as u8` maps 257
/// onto 1: a key would be validated against TRANSFER's arity and stored under
/// an id that no lookup can reach. Root-gated, so this is an operator-error
/// amplifier rather than an attack, but it fails silently — which is the part
/// worth closing. `purge_circuit` guards the same lookup this way.
#[test]
fn register_vk_rejects_circuit_id_that_would_alias() {
	new_test_ext().execute_with(|| {
		// 257 & 0xFF == 1 == CircuitId::TRANSFER.
		let aliasing = CircuitId(257);
		assert_eq!(aliasing.0 as u8, CircuitId::TRANSFER.0 as u8);

		assert_noop!(
			register(aliasing, 1, real_vk(TRANSFER_PUBLIC_INPUTS)),
			Error::<Test>::InvalidVerificationKey
		);
	});
}

/// Ids inside `u8` but outside the known table keep working: they carry no
/// expected arity, so only "deserializes as a BN254 key" applies.
#[test]
fn register_vk_allows_unmapped_ids_within_u8() {
	new_test_ext().execute_with(|| {
		let unmapped = CircuitId(200);
		assert!(orbinum_zk_verifier::expected_public_inputs(200).is_none());

		assert_ok!(register(unmapped, 1, real_vk(TRANSFER_PUBLIC_INPUTS)));
	});
}

#[test]
fn register_vk_stores_key_and_emits_event() {
	new_test_ext().execute_with(|| {
		assert_ok!(register(CircuitId::TRANSFER, 1, vk_bytes()));
		assert!(VerificationKeys::<Test>::contains_key(
			CircuitId::TRANSFER,
			1u32
		));
		assert!(has_event(Event::VerificationKeyRegistered {
			circuit_id: CircuitId::TRANSFER,
			version: 1
		}));
	});
}

#[test]
fn register_vk_auto_activates_when_no_active_version_exists() {
	new_test_ext().execute_with(|| {
		assert_ok!(register(CircuitId::TRANSFER, 1, vk_bytes()));
		assert_eq!(
			ActiveCircuitVersion::<Test>::get(CircuitId::TRANSFER),
			Some(1u32)
		);
		assert!(has_event(Event::ActiveVersionSet {
			circuit_id: CircuitId::TRANSFER,
			version: 1
		}));
	});
}

#[test]
fn register_vk_does_not_override_existing_active_version() {
	new_test_ext().execute_with(|| {
		// Register and auto-activate v1, then register v2: v1 stays active.
		assert_ok!(register(CircuitId::TRANSFER, 1, vk_bytes()));
		assert_ok!(register(
			CircuitId::TRANSFER,
			2,
			vk_for(CircuitId::TRANSFER, 2)
		));
		assert_eq!(
			ActiveCircuitVersion::<Test>::get(CircuitId::TRANSFER),
			Some(1u32),
			"active version must stay at 1"
		);
	});
}

#[test]
fn register_vk_different_circuits_are_independent() {
	new_test_ext().execute_with(|| {
		assert_ok!(register(CircuitId::TRANSFER, 1, vk_bytes()));
		assert_ok!(register(
			CircuitId::UNSHIELD,
			1,
			real_vk(UNSHIELD_PUBLIC_INPUTS)
		));
		assert!(VerificationKeys::<Test>::contains_key(
			CircuitId::TRANSFER,
			1u32
		));
		assert!(VerificationKeys::<Test>::contains_key(
			CircuitId::UNSHIELD,
			1u32
		));
	});
}

#[test]
fn register_vk_rejects_duplicate_circuit_version() {
	// A second Root call with the same (circuit_id, version) is rejected.
	// Overwriting would desync VerificationStats from the key in use and could
	// replace a live key without an on-chain trace.
	new_test_ext().execute_with(|| {
		assert_ok!(register(CircuitId::TRANSFER, 1, vk_bytes()));
		assert_noop!(
			register(CircuitId::TRANSFER, 1, vk_bytes()),
			Error::<Test>::CircuitAlreadyExists
		);
	});
}

#[test]
fn register_stores_the_vk_hash() {
	new_test_ext().execute_with(|| {
		let vk = real_vk(TRANSFER_PUBLIC_INPUTS);
		assert_ok!(register(CircuitId::TRANSFER, 1, vk.clone()));
		let expected = sp_io::hashing::blake2_256(vk.as_slice());
		assert_eq!(
			VkHashes::<Test>::get(CircuitId::TRANSFER, 1),
			Some(expected)
		);
	});
}

#[test]
fn register_rejects_beyond_max_versions_per_circuit() {
	new_test_ext().execute_with(|| {
		// Fill the circuit up to the cap with direct inserts (versions 1..=MAX).
		let max = Pallet::<Test>::MAX_VERSIONS_PER_CIRCUIT;
		for v in 1..=max {
			insert_vk(CircuitId::TRANSFER, v, TRANSFER_PUBLIC_INPUTS);
		}
		// One more via the real path must be rejected by the cap.
		assert_noop!(
			register(
				CircuitId::TRANSFER,
				max + 1,
				vk_for(CircuitId::TRANSFER, max + 1)
			),
			Error::<Test>::TooManyVersions
		);
	});
}

// ── set_active_version ────────────────────────────────────────────────────────

#[test]
fn set_active_version_requires_root() {
	new_test_ext().execute_with(|| {
		assert_noop!(
			ZkVerifier::set_active_version(signed().into(), CircuitId::TRANSFER, 1),
			sp_runtime::DispatchError::BadOrigin
		);
	});
}

#[test]
fn set_active_version_rejects_a_retired_version() {
	new_test_ext().execute_with(|| {
		insert_vk(CircuitId::TRANSFER, 1, TRANSFER_PUBLIC_INPUTS);
		insert_vk(CircuitId::TRANSFER, 2, TRANSFER_PUBLIC_INPUTS);
		RetiredVersions::<Test>::insert(CircuitId::TRANSFER, 1, ());
		assert_noop!(
			ZkVerifier::set_active_version(root().into(), CircuitId::TRANSFER, 1),
			Error::<Test>::UnsupportedCircuitVersion
		);
		assert_ok!(ZkVerifier::set_active_version(
			root().into(),
			CircuitId::TRANSFER,
			2
		));
	});
}

#[test]
fn set_active_version_rejects_non_existent_vk() {
	new_test_ext().execute_with(|| {
		assert_noop!(
			ZkVerifier::set_active_version(root().into(), CircuitId::TRANSFER, 99),
			Error::<Test>::VerificationKeyNotFound
		);
	});
}

#[test]
fn set_active_version_updates_storage_and_emits_event() {
	new_test_ext().execute_with(|| {
		insert_vk(CircuitId::TRANSFER, 1, TRANSFER_PUBLIC_INPUTS);
		insert_vk(CircuitId::TRANSFER, 2, TRANSFER_PUBLIC_INPUTS);
		activate(CircuitId::TRANSFER, 1);

		assert_ok!(ZkVerifier::set_active_version(
			root().into(),
			CircuitId::TRANSFER,
			2
		));
		assert_eq!(
			ActiveCircuitVersion::<Test>::get(CircuitId::TRANSFER),
			Some(2u32)
		);
		assert!(has_event(Event::ActiveVersionSet {
			circuit_id: CircuitId::TRANSFER,
			version: 2
		}));
	});
}

#[test]
fn set_active_version_can_downgrade() {
	new_test_ext().execute_with(|| {
		insert_vk(CircuitId::TRANSFER, 1, TRANSFER_PUBLIC_INPUTS);
		insert_vk(CircuitId::TRANSFER, 2, TRANSFER_PUBLIC_INPUTS);
		activate(CircuitId::TRANSFER, 2);

		assert_ok!(ZkVerifier::set_active_version(
			root().into(),
			CircuitId::TRANSFER,
			1
		));
		assert_eq!(
			ActiveCircuitVersion::<Test>::get(CircuitId::TRANSFER),
			Some(1u32)
		);
	});
}

// ── remove_verification_key ───────────────────────────────────────────────────

#[test]
fn remove_vk_requires_root() {
	new_test_ext().execute_with(|| {
		assert_noop!(
			ZkVerifier::remove_verification_key(signed().into(), CircuitId::TRANSFER, 1),
			sp_runtime::DispatchError::BadOrigin
		);
	});
}

#[test]
fn remove_vk_rejects_non_existent_key() {
	new_test_ext().execute_with(|| {
		assert_noop!(
			ZkVerifier::remove_verification_key(root().into(), CircuitId::TRANSFER, 99),
			Error::<Test>::VerificationKeyNotFound
		);
	});
}

#[test]
fn remove_vk_cannot_remove_active_version() {
	new_test_ext().execute_with(|| {
		insert_vk(CircuitId::TRANSFER, 1, TRANSFER_PUBLIC_INPUTS);
		activate(CircuitId::TRANSFER, 1);
		assert_noop!(
			ZkVerifier::remove_verification_key(root().into(), CircuitId::TRANSFER, 1),
			Error::<Test>::CannotRemoveActiveVersion
		);
	});
}

#[test]
fn remove_vk_returns_active_version_not_set_when_no_active_exists() {
	new_test_ext().execute_with(|| {
		// VK exists but no active version is set.
		insert_vk(CircuitId::TRANSFER, 1, TRANSFER_PUBLIC_INPUTS);
		assert_noop!(
			ZkVerifier::remove_verification_key(root().into(), CircuitId::TRANSFER, 1),
			Error::<Test>::ActiveVersionNotSet
		);
	});
}

#[test]
fn remove_vk_happy_path_removes_key_and_emits_event() {
	new_test_ext().execute_with(|| {
		insert_vk(CircuitId::TRANSFER, 1, TRANSFER_PUBLIC_INPUTS);
		insert_vk(CircuitId::TRANSFER, 2, TRANSFER_PUBLIC_INPUTS);
		activate(CircuitId::TRANSFER, 1);

		assert_ok!(ZkVerifier::remove_verification_key(
			root().into(),
			CircuitId::TRANSFER,
			2
		));
		assert!(!VerificationKeys::<Test>::contains_key(
			CircuitId::TRANSFER,
			2u32
		));
		assert!(has_event(Event::VerificationKeyRemoved {
			circuit_id: CircuitId::TRANSFER,
			version: 2
		}));
	});
}

#[test]
fn remove_vk_active_version_is_preserved_after_removal() {
	new_test_ext().execute_with(|| {
		insert_vk(CircuitId::TRANSFER, 1, TRANSFER_PUBLIC_INPUTS);
		insert_vk(CircuitId::TRANSFER, 2, TRANSFER_PUBLIC_INPUTS);
		activate(CircuitId::TRANSFER, 1);

		assert_ok!(ZkVerifier::remove_verification_key(
			root().into(),
			CircuitId::TRANSFER,
			2
		));
		// Active version must still be 1.
		assert_eq!(
			ActiveCircuitVersion::<Test>::get(CircuitId::TRANSFER),
			Some(1u32)
		);
	});
}

#[test]
fn removing_a_vk_clears_its_retirement_flag() {
	new_test_ext().execute_with(|| {
		insert_vk(CircuitId::TRANSFER, 1, TRANSFER_PUBLIC_INPUTS);
		insert_vk(CircuitId::TRANSFER, 2, TRANSFER_PUBLIC_INPUTS);
		activate(CircuitId::TRANSFER, 1);
		assert_ok!(ZkVerifier::retire_version(
			root().into(),
			CircuitId::TRANSFER,
			2
		));
		assert_ok!(ZkVerifier::remove_verification_key(
			root().into(),
			CircuitId::TRANSFER,
			2
		));
		assert!(!RetiredVersions::<Test>::contains_key(
			CircuitId::TRANSFER,
			2
		));
	});
}

/// `remove_verification_key` clears the satellite maps with the key, so it
/// leaves no orphans behind for `purge_circuit` to collect.
#[test]
fn remove_vk_also_clears_hash_and_stats() {
	new_test_ext().execute_with(|| {
		let cid = CircuitId::TRANSFER;
		seed_circuit(cid, 1, TRANSFER_PUBLIC_INPUTS);
		seed_circuit(cid, 2, TRANSFER_PUBLIC_INPUTS);
		activate(cid, 1);
		VerificationStats::<Test>::insert(cid, 2, VerificationStatistics::default());

		assert_ok!(ZkVerifier::remove_verification_key(root().into(), cid, 2));

		assert!(VkHashes::<Test>::get(cid, 2).is_none());
		assert!(!VerificationStats::<Test>::contains_key(cid, 2));
		// The active version is untouched.
		assert!(VerificationKeys::<Test>::get(cid, 1).is_some());
		assert!(VkHashes::<Test>::get(cid, 1).is_some());
	});
}

// ── verify_proof ──────────────────────────────────────────────────────────────

#[test]
fn verify_proof_requires_signed_origin() {
	new_test_ext().execute_with(|| {
		assert_err!(
			ZkVerifier::verify_proof(
				root().into(),
				CircuitId::TRANSFER,
				proof_bytes(),
				one_public_input()
			),
			sp_runtime::DispatchError::BadOrigin
		);
	});
}

#[test]
fn verify_proof_weight_grows_with_inputs() {
	use crate::weights::WeightInfo;
	type W = crate::weights::SubstrateWeight<Test>;
	assert!(W::verify_proof(8).ref_time() > W::verify_proof(1).ref_time());
	assert!(W::verify_proof(32).ref_time() > W::verify_proof(8).ref_time());
}

#[test]
fn verify_proof_no_active_version_returns_circuit_not_found() {
	new_test_ext().execute_with(|| {
		assert_noop!(
			ZkVerifier::verify_proof(
				signed().into(),
				CircuitId::TRANSFER,
				proof_bytes(),
				one_public_input()
			),
			Error::<Test>::CircuitNotFound
		);
	});
}

#[test]
fn verify_proof_missing_vk_returns_not_found() {
	new_test_ext().execute_with(|| {
		activate(CircuitId::TRANSFER, 99);
		assert_noop!(
			ZkVerifier::verify_proof(
				signed().into(),
				CircuitId::TRANSFER,
				proof_bytes(),
				one_public_input()
			),
			Error::<Test>::VerificationKeyNotFound
		);
	});
}

#[test]
fn verify_proof_empty_proof_returns_empty_proof_error() {
	new_test_ext().execute_with(|| {
		insert_vk(CircuitId::TRANSFER, 1, TRANSFER_PUBLIC_INPUTS);
		activate(CircuitId::TRANSFER, 1);
		let empty: Proof = BoundedVec::default();
		assert_noop!(
			ZkVerifier::verify_proof(
				signed().into(),
				CircuitId::TRANSFER,
				empty,
				one_public_input()
			),
			Error::<Test>::EmptyProof
		);
	});
}

#[test]
fn verify_proof_empty_public_inputs_returns_error() {
	new_test_ext().execute_with(|| {
		insert_vk(CircuitId::TRANSFER, 1, TRANSFER_PUBLIC_INPUTS);
		activate(CircuitId::TRANSFER, 1);
		let no_inputs: PublicInputs = BoundedVec::default();
		assert_noop!(
			ZkVerifier::verify_proof(
				signed().into(),
				CircuitId::TRANSFER,
				proof_bytes(),
				no_inputs
			),
			Error::<Test>::EmptyPublicInputs
		);
	});
}

#[test]
fn verify_proof_happy_path_emits_proof_verified_event() {
	// In test cfg, do_verify always returns true.
	new_test_ext().execute_with(|| {
		insert_vk(CircuitId::TRANSFER, 1, TRANSFER_PUBLIC_INPUTS);
		activate(CircuitId::TRANSFER, 1);
		assert_ok!(ZkVerifier::verify_proof(
			signed().into(),
			CircuitId::TRANSFER,
			proof_bytes(),
			one_public_input(),
		));
		assert!(has_event(Event::ProofVerified {
			circuit_id: CircuitId::TRANSFER,
			version: 1
		}));
	});
}

#[test]
fn verify_proof_rejects_short_public_input() {
	new_test_ext().execute_with(|| {
		insert_vk(CircuitId::UNSHIELD, 1, UNSHIELD_PUBLIC_INPUTS);
		activate(CircuitId::UNSHIELD, 1);
		let short: BoundedVec<u8, ConstU32<32>> = vec![0xFFu8; 4].try_into().unwrap();
		let inputs: PublicInputs = vec![short].try_into().unwrap();
		assert_noop!(
			ZkVerifier::verify_proof(signed().into(), CircuitId::UNSHIELD, proof_bytes(), inputs),
			Error::<Test>::InvalidPublicInputs
		);
	});
}

// ── batch_register_verification_keys ──────────────────────────────────────────

#[test]
fn batch_register_requires_root() {
	new_test_ext().execute_with(|| {
		let entry = make_vk_entry(CircuitId::TRANSFER, 1, false);
		let entries = batch(vec![entry]);
		assert_noop!(
			ZkVerifier::batch_register_verification_keys(signed().into(), entries),
			sp_runtime::DispatchError::BadOrigin
		);
	});
}

#[test]
fn batch_register_rejects_empty_entries() {
	new_test_ext().execute_with(|| {
		let entries = batch(vec![]);
		assert_noop!(
			ZkVerifier::batch_register_verification_keys(root().into(), entries),
			Error::<Test>::InvalidBatchSize
		);
	});
}

#[test]
fn batch_register_rejects_empty_vk() {
	new_test_ext().execute_with(|| {
		let bad = VkEntry {
			circuit_id: CircuitId::TRANSFER,
			version: 1,
			verification_key: vk_empty(),
			set_active: false,
		};
		let entries = batch(vec![bad]);
		assert_noop!(
			ZkVerifier::batch_register_verification_keys(root().into(), entries),
			Error::<Test>::EmptyVerificationKey
		);
	});
}

#[test]
fn batch_register_refuses_the_base_layout_past_version_one() {
	new_test_ext().execute_with(|| {
		let bad = VkEntry {
			circuit_id: CircuitId::TRANSFER,
			version: 2,
			verification_key: real_vk(TRANSFER_PUBLIC_INPUTS),
			set_active: true,
		};
		let entries = batch(vec![bad]);
		assert_noop!(
			ZkVerifier::batch_register_verification_keys(root().into(), entries),
			Error::<Test>::InvalidVerificationKey
		);
	});
}

#[test]
fn batch_register_rejects_short_vk() {
	new_test_ext().execute_with(|| {
		let bad = VkEntry {
			circuit_id: CircuitId::TRANSFER,
			version: 1,
			verification_key: vk_too_short(),
			set_active: false,
		};
		let entries = batch(vec![bad]);
		assert_noop!(
			ZkVerifier::batch_register_verification_keys(root().into(), entries),
			Error::<Test>::InvalidVerificationKey
		);
	});
}

#[test]
fn batch_register_stores_all_keys_and_emits_count() {
	new_test_ext().execute_with(|| {
		let entries = batch(vec![
			make_vk_entry(CircuitId::TRANSFER, 1, false),
			make_vk_entry(CircuitId::UNSHIELD, 1, false),
		]);
		assert_ok!(ZkVerifier::batch_register_verification_keys(
			root().into(),
			entries
		));
		assert!(VerificationKeys::<Test>::contains_key(
			CircuitId::TRANSFER,
			1u32
		));
		assert!(VerificationKeys::<Test>::contains_key(
			CircuitId::UNSHIELD,
			1u32
		));
		assert!(has_event(Event::BatchVerificationKeysRegistered {
			count: 2
		}));
	});
}

#[test]
fn batch_register_auto_activates_when_no_active_version_exists() {
	new_test_ext().execute_with(|| {
		let entries = batch(vec![make_vk_entry(CircuitId::TRANSFER, 1, false)]);
		assert_ok!(ZkVerifier::batch_register_verification_keys(
			root().into(),
			entries
		));
		assert_eq!(
			ActiveCircuitVersion::<Test>::get(CircuitId::TRANSFER),
			Some(1u32)
		);
	});
}

#[test]
fn batch_register_set_active_true_overrides_existing_active_version() {
	new_test_ext().execute_with(|| {
		insert_vk(CircuitId::TRANSFER, 1, TRANSFER_PUBLIC_INPUTS);
		activate(CircuitId::TRANSFER, 1);

		let entries = batch(vec![make_vk_entry(CircuitId::TRANSFER, 2, true)]);
		assert_ok!(ZkVerifier::batch_register_verification_keys(
			root().into(),
			entries
		));
		assert_eq!(
			ActiveCircuitVersion::<Test>::get(CircuitId::TRANSFER),
			Some(2u32)
		);
	});
}

#[test]
fn batch_register_set_active_false_does_not_override_existing_active_version() {
	new_test_ext().execute_with(|| {
		insert_vk(CircuitId::TRANSFER, 1, TRANSFER_PUBLIC_INPUTS);
		activate(CircuitId::TRANSFER, 1);

		let entries = batch(vec![make_vk_entry(CircuitId::TRANSFER, 2, false)]);
		assert_ok!(ZkVerifier::batch_register_verification_keys(
			root().into(),
			entries
		));
		// Active must remain v1.
		assert_eq!(
			ActiveCircuitVersion::<Test>::get(CircuitId::TRANSFER),
			Some(1u32)
		);
	});
}

#[test]
fn batch_register_up_to_ten_entries_is_accepted() {
	new_test_ext().execute_with(|| {
		// Use different versions of the same circuit to fill 10 slots.
		let entries = batch(
			(1u32..=10)
				.map(|v| make_vk_entry(CircuitId::TRANSFER, v, false))
				.collect(),
		);
		assert_ok!(ZkVerifier::batch_register_verification_keys(
			root().into(),
			entries
		));
		assert!(has_event(Event::BatchVerificationKeysRegistered {
			count: 10
		}));
	});
}

#[test]
fn batch_register_rejects_duplicate_circuit_version() {
	// An entry that would overwrite an existing (circuit_id, version) fails the
	// whole batch atomically — no partial state changes.
	new_test_ext().execute_with(|| {
		insert_vk(CircuitId::TRANSFER, 1, TRANSFER_PUBLIC_INPUTS);

		// Version 1 already exists.
		let entries = batch(vec![make_vk_entry(CircuitId::TRANSFER, 1, false)]);
		assert_noop!(
			ZkVerifier::batch_register_verification_keys(root().into(), entries),
			Error::<Test>::CircuitAlreadyExists
		);
	});
}

// ── retire_version / unretire_version ─────────────────────────────────────────

#[test]
fn retire_version_requires_root() {
	new_test_ext().execute_with(|| {
		insert_vk(CircuitId::TRANSFER, 1, TRANSFER_PUBLIC_INPUTS);
		insert_vk(CircuitId::TRANSFER, 2, TRANSFER_PUBLIC_INPUTS);
		activate(CircuitId::TRANSFER, 1);
		assert_noop!(
			ZkVerifier::retire_version(signed().into(), CircuitId::TRANSFER, 2),
			sp_runtime::DispatchError::BadOrigin
		);
	});
}

#[test]
fn retire_version_rejects_active_and_unknown() {
	new_test_ext().execute_with(|| {
		insert_vk(CircuitId::TRANSFER, 1, TRANSFER_PUBLIC_INPUTS);
		activate(CircuitId::TRANSFER, 1);
		// active version cannot be retired
		assert_noop!(
			ZkVerifier::retire_version(root().into(), CircuitId::TRANSFER, 1),
			Error::<Test>::CannotRetireActiveVersion
		);
		// unknown version cannot be retired
		assert_noop!(
			ZkVerifier::retire_version(root().into(), CircuitId::TRANSFER, 9),
			Error::<Test>::VerificationKeyNotFound
		);
	});
}

#[test]
fn retire_then_unretire_toggles_the_flag() {
	new_test_ext().execute_with(|| {
		insert_vk(CircuitId::TRANSFER, 1, TRANSFER_PUBLIC_INPUTS);
		insert_vk(CircuitId::TRANSFER, 2, TRANSFER_PUBLIC_INPUTS);
		activate(CircuitId::TRANSFER, 1);

		assert_ok!(ZkVerifier::retire_version(
			root().into(),
			CircuitId::TRANSFER,
			2
		));
		assert!(RetiredVersions::<Test>::contains_key(
			CircuitId::TRANSFER,
			2
		));
		assert!(has_event(Event::VersionRetired {
			circuit_id: CircuitId::TRANSFER,
			version: 2
		}));
		// double-retire rejected
		assert_noop!(
			ZkVerifier::retire_version(root().into(), CircuitId::TRANSFER, 2),
			Error::<Test>::VersionAlreadyRetired
		);

		assert_ok!(ZkVerifier::unretire_version(
			root().into(),
			CircuitId::TRANSFER,
			2
		));
		assert!(!RetiredVersions::<Test>::contains_key(
			CircuitId::TRANSFER,
			2
		));
		// unretire of a non-retired version rejected
		assert_noop!(
			ZkVerifier::unretire_version(root().into(), CircuitId::TRANSFER, 2),
			Error::<Test>::VersionNotRetired
		);
	});
}

// ── purge_circuit ─────────────────────────────────────────────────────────────

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

// ── Runtime API ───────────────────────────────────────────────────────────────

#[test]
fn runtime_api_circuit_version_info_returns_none_for_unknown_circuit() {
	new_test_ext().execute_with(|| {
		assert!(
			Pallet::<Test>::runtime_api_get_circuit_version_info(CircuitId::TRANSFER.0).is_none()
		);
	});
}

#[test]
fn runtime_api_circuit_version_info_returns_none_when_no_active_version() {
	// VK registered but active version never set.
	new_test_ext().execute_with(|| {
		insert_vk(CircuitId::TRANSFER, 1, TRANSFER_PUBLIC_INPUTS);
		assert!(
			Pallet::<Test>::runtime_api_get_circuit_version_info(CircuitId::TRANSFER.0).is_none()
		);
	});
}

#[test]
fn runtime_api_circuit_version_info_returns_correct_fields() {
	new_test_ext().execute_with(|| {
		insert_vk(CircuitId::TRANSFER, 1, TRANSFER_PUBLIC_INPUTS);
		insert_vk(CircuitId::TRANSFER, 2, TRANSFER_PUBLIC_INPUTS);
		activate(CircuitId::TRANSFER, 1);
		let info = Pallet::<Test>::runtime_api_get_circuit_version_info(CircuitId::TRANSFER.0)
			.expect("should be Some");
		assert_eq!(info.circuit_id, CircuitId::TRANSFER.0);
		assert_eq!(info.active_version, 1u32);
		assert_eq!(info.supported_versions, vec![1u32, 2u32]);
		assert_eq!(info.vk_hashes.len(), 2);
	});
}

#[test]
fn runtime_api_circuit_version_info_supported_versions_are_sorted() {
	new_test_ext().execute_with(|| {
		// Insert in reverse order — result must still be sorted.
		insert_vk(CircuitId::TRANSFER, 3, TRANSFER_PUBLIC_INPUTS);
		insert_vk(CircuitId::TRANSFER, 1, TRANSFER_PUBLIC_INPUTS);
		insert_vk(CircuitId::TRANSFER, 2, TRANSFER_PUBLIC_INPUTS);
		activate(CircuitId::TRANSFER, 1);
		let info =
			Pallet::<Test>::runtime_api_get_circuit_version_info(CircuitId::TRANSFER.0).unwrap();
		assert_eq!(info.supported_versions, vec![1u32, 2u32, 3u32]);
	});
}

#[test]
fn runtime_api_circuit_version_info_vk_hashes_are_blake2_256_of_key_data() {
	new_test_ext().execute_with(|| {
		insert_vk(CircuitId::TRANSFER, 1, TRANSFER_PUBLIC_INPUTS);
		activate(CircuitId::TRANSFER, 1);
		let info =
			Pallet::<Test>::runtime_api_get_circuit_version_info(CircuitId::TRANSFER.0).unwrap();
		let expected_hash = sp_io::hashing::blake2_256(&vk_bytes());
		assert_eq!(info.vk_hashes[0].vk_hash, expected_hash);
		assert_eq!(info.vk_hashes[0].version, 1u32);
	});
}

#[test]
fn runtime_api_all_circuit_versions_empty_when_nothing_registered() {
	new_test_ext().execute_with(|| {
		assert!(Pallet::<Test>::runtime_api_get_all_circuit_versions().is_empty());
	});
}

#[test]
fn runtime_api_all_circuit_versions_returns_all_active_circuits() {
	new_test_ext().execute_with(|| {
		insert_vk(CircuitId::TRANSFER, 1, TRANSFER_PUBLIC_INPUTS);
		insert_vk(CircuitId::UNSHIELD, 1, UNSHIELD_PUBLIC_INPUTS);
		activate(CircuitId::TRANSFER, 1);
		activate(CircuitId::UNSHIELD, 1);

		let all = Pallet::<Test>::runtime_api_get_all_circuit_versions();
		assert_eq!(all.len(), 2);
		let ids: Vec<u32> = all.iter().map(|i| i.circuit_id).collect();
		assert!(ids.contains(&CircuitId::TRANSFER.0));
		assert!(ids.contains(&CircuitId::UNSHIELD.0));
	});
}

#[test]
fn runtime_api_all_circuit_versions_excludes_circuits_with_no_active_version() {
	new_test_ext().execute_with(|| {
		// TRANSFER has a VK but no active version → excluded.
		insert_vk(CircuitId::TRANSFER, 1, TRANSFER_PUBLIC_INPUTS);
		insert_vk(CircuitId::UNSHIELD, 1, UNSHIELD_PUBLIC_INPUTS);
		activate(CircuitId::UNSHIELD, 1);

		let all = Pallet::<Test>::runtime_api_get_all_circuit_versions();
		assert_eq!(all.len(), 1);
		assert_eq!(all[0].circuit_id, CircuitId::UNSHIELD.0);
	});
}

// ── Genesis ───────────────────────────────────────────────────────────────────

#[test]
fn genesis_registers_vk_at_version_1_and_activates_it() {
	let storage = pallet::GenesisConfig::<Test> {
		// Genesis runs the registration checks, so the key must be a real one.
		verification_keys: vec![(
			CircuitId::TRANSFER,
			real_vk(TRANSFER_PUBLIC_INPUTS).into_inner(),
		)],
		_phantom: Default::default(),
	}
	.build_storage()
	.unwrap();

	TestExternalities::new(storage).execute_with(|| {
		assert!(VerificationKeys::<Test>::contains_key(
			CircuitId::TRANSFER,
			1u32
		));
		assert_eq!(
			ActiveCircuitVersion::<Test>::get(CircuitId::TRANSFER),
			Some(1u32)
		);
	});
}

#[test]
fn genesis_multiple_circuits_are_all_registered() {
	let storage = pallet::GenesisConfig::<Test> {
		verification_keys: vec![
			(
				CircuitId::TRANSFER,
				real_vk(TRANSFER_PUBLIC_INPUTS).into_inner(),
			),
			(
				CircuitId::UNSHIELD,
				real_vk(UNSHIELD_PUBLIC_INPUTS).into_inner(),
			),
		],
		_phantom: Default::default(),
	}
	.build_storage()
	.unwrap();

	TestExternalities::new(storage).execute_with(|| {
		assert!(VerificationKeys::<Test>::contains_key(
			CircuitId::TRANSFER,
			1u32
		));
		assert!(VerificationKeys::<Test>::contains_key(
			CircuitId::UNSHIELD,
			1u32
		));
		assert_eq!(
			ActiveCircuitVersion::<Test>::get(CircuitId::TRANSFER),
			Some(1u32)
		);
		assert_eq!(
			ActiveCircuitVersion::<Test>::get(CircuitId::UNSHIELD),
			Some(1u32)
		);
	});
}

/// Genesis must not accept a key that only passes the length check.
///
/// A well-sized but meaningless key would surface only when the first real
/// proof failed to verify — at which point nothing distinguishes a bad key
/// from a bad proof. Failing at genesis makes it a chain that refuses to start.
#[test]
#[should_panic(expected = "Genesis VK must deserialize")]
fn genesis_rejects_a_key_that_only_passes_the_length_check() {
	let _ = pallet::GenesisConfig::<Test> {
		verification_keys: vec![(CircuitId::TRANSFER, vec![0xCCu8; 300])],
		_phantom: Default::default(),
	}
	.build_storage();
}

/// A real key of the wrong arity is rejected too — deserializing is not
/// enough when the circuit declares how many inputs it takes.
#[test]
#[should_panic(expected = "Genesis VK must deserialize")]
fn genesis_rejects_a_valid_key_with_the_wrong_arity() {
	let _ = pallet::GenesisConfig::<Test> {
		verification_keys: vec![(
			CircuitId::TRANSFER,
			real_vk(TRANSFER_PUBLIC_INPUTS + 3).into_inner(),
		)],
		_phantom: Default::default(),
	}
	.build_storage();
}

// ── integrity_test ────────────────────────────────────────────────────────────

/// The integrity_test must abort when verification is compiled out WITHOUT the
/// benchmark feature — i.e. a would-be release runtime with no verification. Only
/// compiles in that exact combination (skip on, benchmarks off).
#[cfg(all(
	feature = "skip-proof-verification",
	not(feature = "runtime-benchmarks")
))]
#[test]
#[should_panic(expected = "skip-proof-verification")]
fn integrity_test_panics_when_verification_disabled() {
	use frame_support::traits::Hooks;
	<ZkVerifier as Hooks<frame_system::pallet_prelude::BlockNumberFor<Test>>>::integrity_test();
}
