//! Denied keys: `deny_version`, and a denied key refused or inert on every
//! path.

use crate::tests::util::*;
use crate::{
	CircuitId, DeniedVkHashes, Error, Event, RetiredVersions, VkBytes, VkEntry, VkHashes,
	tests::mock::*,
};
use frame_support::{BoundedVec, assert_err, assert_noop, assert_ok, traits::ConstU32};
use orbinum_zk_verifier::{MEMO_HASH_INPUTS, UNSHIELD_PUBLIC_INPUTS};
use sp_io::TestExternalities;
use sp_runtime::BuildStorage;

/// Store `key` for `(circuit_id, version)` with its hash, as a registration would.
fn insert_with_hash(circuit_id: CircuitId, version: u32, key: VkBytes) {
	insert_key(circuit_id, version, key.clone());
	VkHashes::<Test>::insert(circuit_id, version, sp_io::hashing::blake2_256(&key));
}

fn deny_hash_of(key: &VkBytes) {
	DeniedVkHashes::<Test>::insert(sp_io::hashing::blake2_256(key), ());
}

#[test]
fn deny_version_retires_and_records_the_hash() {
	new_test_ext().execute_with(|| {
		let key = denied_vk();
		insert_with_hash(CircuitId::UNSHIELD, 2, key.clone());
		insert_vk(
			CircuitId::UNSHIELD,
			3,
			UNSHIELD_PUBLIC_INPUTS + MEMO_HASH_INPUTS,
		);
		activate(CircuitId::UNSHIELD, 3);

		assert_ok!(ZkVerifier::deny_version(
			root().into(),
			CircuitId::UNSHIELD,
			2
		));
		let vk_hash = sp_io::hashing::blake2_256(&key);
		assert!(DeniedVkHashes::<Test>::contains_key(vk_hash));
		assert!(RetiredVersions::<Test>::contains_key(
			CircuitId::UNSHIELD,
			2
		));
		frame_system::Pallet::<Test>::assert_last_event(
			Event::VerificationKeyDenied {
				circuit_id: CircuitId::UNSHIELD,
				version: 2,
				vk_hash,
			}
			.into(),
		);
	});
}

#[test]
fn deny_version_requires_root() {
	new_test_ext().execute_with(|| {
		insert_with_hash(CircuitId::UNSHIELD, 2, denied_vk());
		assert_noop!(
			ZkVerifier::deny_version(signed().into(), CircuitId::UNSHIELD, 2),
			sp_runtime::DispatchError::BadOrigin
		);
	});
}

#[test]
fn deny_version_refuses_the_active_version_and_a_missing_one() {
	new_test_ext().execute_with(|| {
		insert_with_hash(CircuitId::UNSHIELD, 3, denied_vk());
		activate(CircuitId::UNSHIELD, 3);
		assert_noop!(
			ZkVerifier::deny_version(root().into(), CircuitId::UNSHIELD, 3),
			Error::<Test>::CannotRetireActiveVersion
		);
		assert_noop!(
			ZkVerifier::deny_version(root().into(), CircuitId::UNSHIELD, 9),
			Error::<Test>::VerificationKeyNotFound
		);
	});
}

#[test]
fn a_denied_key_cannot_be_denied_twice() {
	new_test_ext().execute_with(|| {
		insert_with_hash(CircuitId::UNSHIELD, 2, denied_vk());
		insert_with_hash(CircuitId::UNSHIELD, 4, denied_vk());
		assert_ok!(ZkVerifier::deny_version(
			root().into(),
			CircuitId::UNSHIELD,
			2
		));
		// The same key under another version is the same record.
		assert_noop!(
			ZkVerifier::deny_version(root().into(), CircuitId::UNSHIELD, 4),
			Error::<Test>::KeyAlreadyDenied
		);
	});
}

#[test]
fn register_refuses_a_denied_key() {
	new_test_ext().execute_with(|| {
		deny_hash_of(&denied_vk());
		assert_noop!(
			register(CircuitId::UNSHIELD, 2, denied_vk()),
			Error::<Test>::DeniedVerificationKey
		);
		// Under any id or version: the hash decides, not the slot.
		assert_noop!(
			register(CircuitId::UNSHIELD, 9, denied_vk()),
			Error::<Test>::DeniedVerificationKey
		);
	});
}

#[test]
fn batch_register_refuses_a_denied_key() {
	new_test_ext().execute_with(|| {
		deny_hash_of(&denied_vk());
		let entries: BoundedVec<VkEntry, ConstU32<10>> = vec![VkEntry {
			circuit_id: CircuitId::UNSHIELD,
			version: 2,
			verification_key: denied_vk(),
			set_active: true,
		}]
		.try_into()
		.unwrap();
		assert_noop!(
			ZkVerifier::batch_register_verification_keys(root().into(), entries),
			Error::<Test>::DeniedVerificationKey
		);
	});
}

#[test]
fn unretire_refuses_a_denied_key() {
	new_test_ext().execute_with(|| {
		insert_with_hash(CircuitId::UNSHIELD, 2, denied_vk());
		insert_vk(
			CircuitId::UNSHIELD,
			3,
			UNSHIELD_PUBLIC_INPUTS + MEMO_HASH_INPUTS,
		);
		activate(CircuitId::UNSHIELD, 3);
		assert_ok!(ZkVerifier::deny_version(
			root().into(),
			CircuitId::UNSHIELD,
			2
		));
		assert_noop!(
			ZkVerifier::unretire_version(root().into(), CircuitId::UNSHIELD, 2),
			Error::<Test>::DeniedVerificationKey
		);
	});
}

#[test]
fn set_active_refuses_a_denied_key() {
	new_test_ext().execute_with(|| {
		insert_with_hash(CircuitId::UNSHIELD, 2, denied_vk());
		deny_hash_of(&denied_vk());
		assert_noop!(
			ZkVerifier::set_active_version(root().into(), CircuitId::UNSHIELD, 2),
			Error::<Test>::DeniedVerificationKey
		);
	});
}

/// The record outlives the key: removing the version, or purging, does not let the
/// same key back in.
#[test]
fn the_denial_survives_removing_the_version() {
	new_test_ext().execute_with(|| {
		let key = denied_vk();
		insert_with_hash(CircuitId::UNSHIELD, 2, key.clone());
		insert_vk(
			CircuitId::UNSHIELD,
			3,
			UNSHIELD_PUBLIC_INPUTS + MEMO_HASH_INPUTS,
		);
		activate(CircuitId::UNSHIELD, 3);
		assert_ok!(ZkVerifier::deny_version(
			root().into(),
			CircuitId::UNSHIELD,
			2
		));
		assert_ok!(ZkVerifier::remove_verification_key(
			root().into(),
			CircuitId::UNSHIELD,
			2
		));
		assert!(DeniedVkHashes::<Test>::contains_key(
			sp_io::hashing::blake2_256(&key)
		));
		assert_noop!(
			register(CircuitId::UNSHIELD, 2, key),
			Error::<Test>::DeniedVerificationKey
		);
	});
}

/// A denied key already in storage verifies nothing, even active and never retired.
#[test]
fn a_stored_denied_key_verifies_nothing() {
	use crate::ZkVerifierPort;
	new_test_ext().execute_with(|| {
		insert_with_hash(CircuitId::UNSHIELD, 2, denied_vk());
		deny_hash_of(&denied_vk());
		activate(CircuitId::UNSHIELD, 2);
		assert!(!<ZkVerifier as ZkVerifierPort>::is_supported_version(
			CircuitId::UNSHIELD.0,
			2
		));
		assert_err!(
			ZkVerifier::verify_proof(
				signed().into(),
				CircuitId::UNSHIELD,
				proof_bytes(),
				one_public_input()
			),
			Error::<Test>::UnsupportedCircuitVersion
		);

		// The same slot with an admitted key is supported: the hash decides.
		insert_with_hash(
			CircuitId::UNSHIELD,
			2,
			real_vk(UNSHIELD_PUBLIC_INPUTS + MEMO_HASH_INPUTS),
		);
		assert!(<ZkVerifier as ZkVerifierPort>::is_supported_version(
			CircuitId::UNSHIELD.0,
			2
		));
	});
}

#[test]
fn genesis_records_denied_hashes_before_any_key() {
	let key = denied_vk();
	let storage = RuntimeGenesisConfig {
		zk_verifier: crate::GenesisConfig {
			denied_vk_hashes: vec![sp_core::H256(sp_io::hashing::blake2_256(&key))],
			..Default::default()
		},
		..Default::default()
	}
	.build_storage()
	.unwrap();
	TestExternalities::new(storage).execute_with(|| {
		frame_system::Pallet::<Test>::set_block_number(1);
		assert_noop!(
			register(CircuitId::UNSHIELD, 2, key),
			Error::<Test>::DeniedVerificationKey
		);
	});
}

/// A chain spec writes the hashes as `0x…` strings, like every other hash in it.
#[test]
fn genesis_denied_hashes_read_as_hex_strings() {
	let config: crate::GenesisConfig<Test> = serde_json::from_str(
		r#"{"verificationKeys":[],"deniedVkHashes":["0x8eb9dbb295ce10498fbe7088a4b0f327a675094d657170725d02770711634525"]}"#,
	)
	.unwrap();
	assert_eq!(config.denied_vk_hashes[0].0[..4], [0x8e, 0xb9, 0xdb, 0xb2]);
}
