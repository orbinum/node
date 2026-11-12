// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: GPL-3.0-or-later

//! `register_verification_key`: the rules a key is admitted under and what a
//! registration stores.

use crate::tests::util::*;
use crate::{
	ActiveCircuitVersion, CircuitId, Error, Event, Pallet, RetiredVersions, VerificationKeys,
	VkHashes, tests::mock::*,
};
use frame_support::{assert_noop, assert_ok};
use orbinum_zk_verifier::{
	MEMO_HASH_INPUTS, SHIELD_PUBLIC_INPUTS, TRANSFER_PUBLIC_INPUTS, UNSHIELD_PUBLIC_INPUTS,
};

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

/// A spend circuit's key must bind its memos at every version, the first
/// included: a base key would let a copier swap memos or alias the recipient.
#[test]
fn register_vk_refuses_a_base_spend_key_at_every_version() {
	new_test_ext().execute_with(|| {
		for (cid, base) in [
			(CircuitId::TRANSFER, TRANSFER_PUBLIC_INPUTS),
			(CircuitId::UNSHIELD, UNSHIELD_PUBLIC_INPUTS),
		] {
			for version in [1, 2] {
				assert_noop!(
					register(cid, version, real_vk(base)),
					Error::<Test>::InvalidVerificationKey
				);
				assert_ok!(register(cid, version, real_vk(base + MEMO_HASH_INPUTS)));
			}
		}
		// Shield has only the base layout.
		assert_ok!(register(
			CircuitId::SHIELD,
			1,
			real_vk(SHIELD_PUBLIC_INPUTS)
		));
	});
}

/// A key retired for being unsafe cannot come back: `unretire_version` holds
/// it to the rules a new registration faces.
#[test]
fn unretire_refuses_a_base_spend_key() {
	new_test_ext().execute_with(|| {
		insert_vk(CircuitId::TRANSFER, 1, TRANSFER_PUBLIC_INPUTS);
		insert_vk(
			CircuitId::TRANSFER,
			2,
			TRANSFER_PUBLIC_INPUTS + MEMO_HASH_INPUTS,
		);
		activate(CircuitId::TRANSFER, 2);
		assert_ok!(ZkVerifier::retire_version(
			root().into(),
			CircuitId::TRANSFER,
			1
		));
		assert_noop!(
			ZkVerifier::unretire_version(root().into(), CircuitId::TRANSFER, 1),
			Error::<Test>::InvalidVerificationKey
		);
		assert!(RetiredVersions::<Test>::contains_key(
			CircuitId::TRANSFER,
			1
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
	use ark_ec::{AffineRepr, CurveGroup};
	new_test_ext().execute_with(|| {
		let mut abc: Vec<G1Affine> = (0..=TRANSFER_PUBLIC_INPUTS)
			.map(|_| G1Affine::generator())
			.collect();
		abc[4] = G1Affine::zero();
		let vk = ark_groth16::VerifyingKey::<Bn254> {
			alpha_g1: G1Affine::generator(),
			beta_g2: G2Affine::generator(),
			gamma_g2: G2Affine::generator(),
			delta_g2: (G2Affine::generator() + G2Affine::generator()).into_affine(),
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

/// A key whose `delta` is `gamma` (snarkjs without phase 2) lets anyone forge proofs.
#[test]
fn register_vk_rejects_a_key_without_phase_2() {
	use ark_bn254::{Bn254, G1Affine, G2Affine};
	use ark_ec::AffineRepr;
	new_test_ext().execute_with(|| {
		let vk = ark_groth16::VerifyingKey::<Bn254> {
			alpha_g1: G1Affine::generator(),
			beta_g2: G2Affine::generator(),
			gamma_g2: G2Affine::generator(),
			delta_g2: G2Affine::generator(),
			gamma_abc_g1: vec![
				G1Affine::generator();
				TRANSFER_PUBLIC_INPUTS + MEMO_HASH_INPUTS + 1
			],
		};
		let bytes = orbinum_zk_verifier::VerifyingKey::from_ark_vk(&vk)
			.unwrap()
			.bytes;
		assert_noop!(
			register(CircuitId::TRANSFER, 2, bytes.try_into().unwrap()),
			Error::<Test>::InvalidVerificationKey
		);
		// The same key with an independent delta registers.
		assert_ok!(register(CircuitId::TRANSFER, 2, vk_bytes()));
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
/// the memo-bound keys as version 2, make them active, retire version 1. The v1
/// key is one registered under the old rules, so it is placed in storage.
#[test]
fn v1_rotates_to_memo_bound_v2_by_extrinsic() {
	new_test_ext().execute_with(|| {
		for (cid, base) in [
			(CircuitId::TRANSFER, TRANSFER_PUBLIC_INPUTS),
			(CircuitId::UNSHIELD, UNSHIELD_PUBLIC_INPUTS),
		] {
			insert_vk(cid, 1, base);
			activate(cid, 1);
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
		// TRANSFER takes memo-bound (+1) or cross-tree (+2); anything else,
		// the base arity included, is rejected.
		assert_noop!(
			register(CircuitId::TRANSFER, 1, real_vk(TRANSFER_PUBLIC_INPUTS + 3)),
			Error::<Test>::InvalidVerificationKey
		);
		assert_noop!(
			register(CircuitId::UNSHIELD, 1, real_vk(UNSHIELD_PUBLIC_INPUTS + 2)),
			Error::<Test>::InvalidVerificationKey
		);
		// A matching arity is accepted.
		assert_ok!(register(CircuitId::TRANSFER, 1, vk_bytes()));
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
			real_vk(UNSHIELD_PUBLIC_INPUTS + MEMO_HASH_INPUTS)
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
		let vk = vk_bytes();
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
