//! Genesis: the keys and denied hashes a chain starts with.

use crate::{
	ActiveCircuitVersion, CircuitId, PreparedKeys, VerificationKeys, pallet, tests::mock::*,
};
use orbinum_zk_verifier::{MEMO_HASH_INPUTS, TRANSFER_PUBLIC_INPUTS, UNSHIELD_PUBLIC_INPUTS};
use sp_io::TestExternalities;
use sp_runtime::BuildStorage;

#[test]
fn genesis_registers_vk_at_version_1_and_activates_it() {
	let storage = pallet::GenesisConfig::<Test> {
		// Genesis runs the registration checks, so the key must be a real one.
		verification_keys: vec![(
			CircuitId::TRANSFER,
			real_vk(TRANSFER_PUBLIC_INPUTS + MEMO_HASH_INPUTS).into_inner(),
		)],
		..Default::default()
	}
	.build_storage()
	.unwrap();

	TestExternalities::new(storage).execute_with(|| {
		assert!(VerificationKeys::<Test>::contains_key(
			CircuitId::TRANSFER,
			1u32
		));
		assert!(PreparedKeys::<Test>::contains_key(
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
				real_vk(TRANSFER_PUBLIC_INPUTS + MEMO_HASH_INPUTS).into_inner(),
			),
			(
				CircuitId::UNSHIELD,
				real_vk(UNSHIELD_PUBLIC_INPUTS + MEMO_HASH_INPUTS).into_inner(),
			),
		],
		..Default::default()
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
		..Default::default()
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
		..Default::default()
	}
	.build_storage();
}

/// Genesis with one key of `arity` inputs for `circuit_id`.
fn genesis_with(circuit_id: CircuitId, arity: usize) {
	let _ = pallet::GenesisConfig::<Test> {
		verification_keys: vec![(circuit_id, real_vk(arity).into_inner())],
		..Default::default()
	}
	.build_storage();
}

/// A network cannot start with a spend key that binds no memo.
#[test]
#[should_panic(expected = "Genesis VK must deserialize")]
fn genesis_rejects_a_base_transfer_key() {
	genesis_with(CircuitId::TRANSFER, TRANSFER_PUBLIC_INPUTS);
}

#[test]
#[should_panic(expected = "Genesis VK must deserialize")]
fn genesis_rejects_a_base_unshield_key() {
	genesis_with(CircuitId::UNSHIELD, UNSHIELD_PUBLIC_INPUTS);
}
