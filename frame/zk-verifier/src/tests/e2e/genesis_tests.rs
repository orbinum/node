//! Tests for GenesisConfig
//!
//! These tests verify the genesis configuration and initialization

use crate::{
	ActiveCircuitVersion, VerificationKeys,
	mock::{RuntimeOrigin, ZkVerifier},
	pallet::GenesisConfig,
	types::{CircuitId, ProofSystem},
};
use frame_support::traits::BuildGenesisConfig;
use frame_support::{assert_noop, assert_ok};
use sp_io::TestExternalities;
use sp_runtime::BuildStorage;

// ============================================================================
// Helper Functions
// ============================================================================

fn sample_vk_1() -> Vec<u8> {
	let mut vk = Vec::with_capacity(512);
	vk.extend_from_slice(&[1u8; 64]);
	vk.extend_from_slice(&[2u8; 128]);
	vk.extend_from_slice(&[3u8; 128]);
	vk.extend_from_slice(&[4u8; 128]);
	vk.extend_from_slice(&[5u8; 64]);
	vk
}

fn sample_vk_2() -> Vec<u8> {
	let mut vk = Vec::with_capacity(512);
	vk.extend_from_slice(&[10u8; 64]);
	vk.extend_from_slice(&[20u8; 128]);
	vk.extend_from_slice(&[30u8; 128]);
	vk.extend_from_slice(&[40u8; 128]);
	vk.extend_from_slice(&[50u8; 64]);
	vk
}

fn sample_vk_3() -> Vec<u8> {
	let mut vk = Vec::with_capacity(512);
	vk.extend_from_slice(&[100u8; 64]);
	vk.extend_from_slice(&[200u8; 128]);
	vk.extend_from_slice(&[111u8; 128]);
	vk.extend_from_slice(&[222u8; 128]);
	vk.extend_from_slice(&[123u8; 64]);
	vk
}

// ============================================================================
// Empty Genesis Tests
// ============================================================================

#[test]
fn empty_genesis_works() {
	let genesis_config: GenesisConfig<crate::mock::Test> = GenesisConfig {
		verification_keys: vec![],
		_phantom: Default::default(),
	};

	let storage = frame_system::GenesisConfig::<crate::mock::Test>::default()
		.build_storage()
		.unwrap();

	let mut ext = TestExternalities::new(storage);

	ext.execute_with(|| {
		genesis_config.build();

		// Empty config does not seed VKs automatically
		assert!(!VerificationKeys::<crate::mock::Test>::contains_key(
			CircuitId::TRANSFER,
			1
		));
		assert!(!VerificationKeys::<crate::mock::Test>::contains_key(
			CircuitId::UNSHIELD,
			1
		));
	});
}

#[test]
fn root_can_register_and_set_active_version() {
	let storage = frame_system::GenesisConfig::<crate::mock::Test>::default()
		.build_storage()
		.unwrap();

	let mut ext = TestExternalities::new(storage);
	ext.execute_with(|| {
		let vk_bytes = vec![9u8; 512];
		let bounded_vk: frame_support::BoundedVec<u8, frame_support::traits::ConstU32<8192>> =
			vk_bytes.try_into().unwrap();

		assert_ok!(ZkVerifier::register_verification_key(
			RuntimeOrigin::root(),
			CircuitId::TRANSFER,
			2,
			bounded_vk
		));
		assert!(VerificationKeys::<crate::mock::Test>::contains_key(
			CircuitId::TRANSFER,
			2
		));

		assert_ok!(ZkVerifier::set_active_version(
			RuntimeOrigin::root(),
			CircuitId::TRANSFER,
			2
		));
		assert_eq!(
			ActiveCircuitVersion::<crate::mock::Test>::get(CircuitId::TRANSFER),
			Some(2)
		);
	});
}

#[test]
fn non_root_cannot_register_verification_key() {
	let storage = frame_system::GenesisConfig::<crate::mock::Test>::default()
		.build_storage()
		.unwrap();

	let mut ext = TestExternalities::new(storage);
	ext.execute_with(|| {
		let bounded_vk: frame_support::BoundedVec<u8, frame_support::traits::ConstU32<8192>> =
			vec![7u8; 512].try_into().unwrap();
		assert_noop!(
			ZkVerifier::register_verification_key(
				RuntimeOrigin::signed(1),
				CircuitId::TRANSFER,
				3,
				bounded_vk
			),
			sp_runtime::DispatchError::BadOrigin
		);
	});
}

#[test]
fn non_root_cannot_set_active_version() {
	let storage = frame_system::GenesisConfig::<crate::mock::Test>::default()
		.build_storage()
		.unwrap();

	let mut ext = TestExternalities::new(storage);
	ext.execute_with(|| {
		assert_noop!(
			ZkVerifier::set_active_version(RuntimeOrigin::signed(1), CircuitId::TRANSFER, 1),
			sp_runtime::DispatchError::BadOrigin
		);
	});
}

#[test]
fn non_root_cannot_remove_verification_key() {
	let storage = frame_system::GenesisConfig::<crate::mock::Test>::default()
		.build_storage()
		.unwrap();

	let mut ext = TestExternalities::new(storage);
	ext.execute_with(|| {
		assert_noop!(
			ZkVerifier::remove_verification_key(RuntimeOrigin::signed(1), CircuitId::TRANSFER, 1),
			sp_runtime::DispatchError::BadOrigin
		);
	});
}

#[test]
fn set_active_version_requires_existing_vk() {
	let storage = frame_system::GenesisConfig::<crate::mock::Test>::default()
		.build_storage()
		.unwrap();

	let mut ext = TestExternalities::new(storage);
	ext.execute_with(|| {
		assert_noop!(
			ZkVerifier::set_active_version(RuntimeOrigin::root(), CircuitId::TRANSFER, 99),
			crate::Error::<crate::mock::Test>::VerificationKeyNotFound
		);
	});
}

#[test]
fn remove_nonexistent_vk_fails() {
	let storage = frame_system::GenesisConfig::<crate::mock::Test>::default()
		.build_storage()
		.unwrap();

	let mut ext = TestExternalities::new(storage);
	ext.execute_with(|| {
		assert_noop!(
			ZkVerifier::remove_verification_key(RuntimeOrigin::root(), CircuitId::TRANSFER, 99),
			crate::Error::<crate::mock::Test>::VerificationKeyNotFound
		);
	});
}

#[test]
fn register_rejects_empty_vk() {
	let storage = frame_system::GenesisConfig::<crate::mock::Test>::default()
		.build_storage()
		.unwrap();

	let mut ext = TestExternalities::new(storage);
	ext.execute_with(|| {
		let empty_vk: frame_support::BoundedVec<u8, frame_support::traits::ConstU32<8192>> =
			vec![].try_into().unwrap();

		assert_noop!(
			ZkVerifier::register_verification_key(
				RuntimeOrigin::root(),
				CircuitId::TRANSFER,
				1,
				empty_vk
			),
			crate::Error::<crate::mock::Test>::EmptyVerificationKey
		);
	});
}

#[test]
fn cannot_remove_active_version() {
	let storage = frame_system::GenesisConfig::<crate::mock::Test>::default()
		.build_storage()
		.unwrap();

	let mut ext = TestExternalities::new(storage);
	ext.execute_with(|| {
		let bounded_vk: frame_support::BoundedVec<u8, frame_support::traits::ConstU32<8192>> =
			vec![5u8; 512].try_into().unwrap();
		assert_ok!(ZkVerifier::register_verification_key(
			RuntimeOrigin::root(),
			CircuitId::TRANSFER,
			1,
			bounded_vk
		));
		assert_noop!(
			ZkVerifier::remove_verification_key(RuntimeOrigin::root(), CircuitId::TRANSFER, 1),
			crate::Error::<crate::mock::Test>::CannotRemoveActiveVersion
		);
	});
}

// ============================================================================
// Single VK Genesis Tests
// ============================================================================

#[test]
fn genesis_with_single_vk_works() {
	let vk = sample_vk_1();
	let genesis_config: GenesisConfig<crate::mock::Test> = GenesisConfig {
		verification_keys: vec![(CircuitId::TRANSFER, vk.clone())],
		_phantom: Default::default(),
	};

	let storage = frame_system::GenesisConfig::<crate::mock::Test>::default()
		.build_storage()
		.unwrap();

	let mut ext = TestExternalities::new(storage);

	ext.execute_with(|| {
		genesis_config.build();

		// Verify key is registered
		assert!(VerificationKeys::<crate::mock::Test>::contains_key(
			CircuitId::TRANSFER,
			1
		));

		let stored = VerificationKeys::<crate::mock::Test>::get(CircuitId::TRANSFER, 1).unwrap();
		assert_eq!(stored.system, ProofSystem::Groth16);
		assert_eq!(stored.key_data.to_vec(), vk);
		assert_eq!(stored.registered_at, 0u64);
	});
}

// ============================================================================
// Multiple VKs Genesis Tests
// ============================================================================

#[test]
fn genesis_with_multiple_vks_works() {
	let vk1 = sample_vk_1();
	let vk2 = sample_vk_2();
	let vk3 = sample_vk_3();

	let genesis_config: GenesisConfig<crate::mock::Test> = GenesisConfig {
		verification_keys: vec![
			(CircuitId::TRANSFER, vk1.clone()),
			(CircuitId::UNSHIELD, vk2.clone()),
			(CircuitId::SHIELD, vk3.clone()),
		],
		_phantom: Default::default(),
	};

	let storage = frame_system::GenesisConfig::<crate::mock::Test>::default()
		.build_storage()
		.unwrap();

	let mut ext = TestExternalities::new(storage);

	ext.execute_with(|| {
		genesis_config.build();

		// Verify all keys are registered
		assert!(VerificationKeys::<crate::mock::Test>::contains_key(
			CircuitId::TRANSFER,
			1
		));
		assert!(VerificationKeys::<crate::mock::Test>::contains_key(
			CircuitId::UNSHIELD,
			1
		));
		assert!(VerificationKeys::<crate::mock::Test>::contains_key(
			CircuitId::SHIELD,
			1
		));

		// Verify key data
		let stored1 = VerificationKeys::<crate::mock::Test>::get(CircuitId::TRANSFER, 1).unwrap();
		assert_eq!(stored1.key_data.to_vec(), vk1);

		let stored2 = VerificationKeys::<crate::mock::Test>::get(CircuitId::UNSHIELD, 1).unwrap();
		assert_eq!(stored2.key_data.to_vec(), vk2);

		let stored3 = VerificationKeys::<crate::mock::Test>::get(CircuitId::SHIELD, 1).unwrap();
		assert_eq!(stored3.key_data.to_vec(), vk3);
	});
}

// ============================================================================
// Standard Circuits Genesis Tests
// ============================================================================

#[test]
fn genesis_with_standard_circuits() {
	let transfer_vk = sample_vk_1();
	let unshield_vk = sample_vk_2();

	let genesis_config: GenesisConfig<crate::mock::Test> = GenesisConfig {
		verification_keys: vec![
			(CircuitId(1), transfer_vk.clone()), // TRANSFER
			(CircuitId(2), unshield_vk.clone()), // UNSHIELD
		],
		_phantom: Default::default(),
	};

	let storage = frame_system::GenesisConfig::<crate::mock::Test>::default()
		.build_storage()
		.unwrap();

	let mut ext = TestExternalities::new(storage);

	ext.execute_with(|| {
		genesis_config.build();

		// Verify standard circuit IDs match
		assert_eq!(CircuitId::TRANSFER.0, 1);
		assert_eq!(CircuitId::UNSHIELD.0, 2);

		// Verify keys are accessible via standard constants
		assert!(VerificationKeys::<crate::mock::Test>::contains_key(
			CircuitId::TRANSFER,
			1
		));
		assert!(VerificationKeys::<crate::mock::Test>::contains_key(
			CircuitId::UNSHIELD,
			1
		));
	});
}

// ============================================================================
// Custom Circuit IDs Genesis Tests
// ============================================================================

#[test]
fn genesis_with_custom_circuit_ids() {
	let vk = sample_vk_1();

	let genesis_config: GenesisConfig<crate::mock::Test> = GenesisConfig {
		verification_keys: vec![
			(CircuitId(100), vk.clone()),
			(CircuitId(200), vk.clone()),
			(CircuitId(999), vk.clone()),
		],
		_phantom: Default::default(),
	};

	let storage = frame_system::GenesisConfig::<crate::mock::Test>::default()
		.build_storage()
		.unwrap();

	let mut ext = TestExternalities::new(storage);

	ext.execute_with(|| {
		genesis_config.build();

		// Verify custom IDs work
		assert!(VerificationKeys::<crate::mock::Test>::contains_key(
			CircuitId(100),
			1
		));
		assert!(VerificationKeys::<crate::mock::Test>::contains_key(
			CircuitId(200),
			1
		));
		assert!(VerificationKeys::<crate::mock::Test>::contains_key(
			CircuitId(999),
			1
		));
	});
}

// ============================================================================
// Genesis Overwrite Tests
// ============================================================================

#[test]
fn genesis_last_entry_wins_on_duplicate() {
	let vk1 = sample_vk_1();
	let vk2 = sample_vk_2();

	let genesis_config: GenesisConfig<crate::mock::Test> = GenesisConfig {
		verification_keys: vec![
			(CircuitId::TRANSFER, vk1.clone()),
			(CircuitId::TRANSFER, vk2.clone()), // Duplicate
		],
		_phantom: Default::default(),
	};

	let storage = frame_system::GenesisConfig::<crate::mock::Test>::default()
		.build_storage()
		.unwrap();

	let mut ext = TestExternalities::new(storage);

	ext.execute_with(|| {
		genesis_config.build();

		// Last entry should win
		let stored = VerificationKeys::<crate::mock::Test>::get(CircuitId::TRANSFER, 1).unwrap();
		assert_eq!(stored.key_data.to_vec(), vk2);
	});
}

// ============================================================================
// Genesis Data Validation Tests
// ============================================================================

#[test]
fn genesis_accepts_valid_vk_sizes() {
	let vk = sample_vk_1(); // 512 bytes

	let genesis_config: GenesisConfig<crate::mock::Test> = GenesisConfig {
		verification_keys: vec![(CircuitId::TRANSFER, vk)],
		_phantom: Default::default(),
	};

	let storage = frame_system::GenesisConfig::<crate::mock::Test>::default()
		.build_storage()
		.unwrap();

	let mut ext = TestExternalities::new(storage);

	ext.execute_with(|| {
		genesis_config.build();
		assert!(VerificationKeys::<crate::mock::Test>::contains_key(
			CircuitId::TRANSFER,
			1
		));
	});
}

#[test]
#[should_panic(expected = "Invalid zk_verifier genesis VK")]
fn genesis_rejects_empty_vk() {
	let genesis_config: GenesisConfig<crate::mock::Test> = GenesisConfig {
		verification_keys: vec![(CircuitId::TRANSFER, vec![])],
		_phantom: Default::default(),
	};

	let storage = frame_system::GenesisConfig::<crate::mock::Test>::default()
		.build_storage()
		.unwrap();

	let mut ext = TestExternalities::new(storage);

	ext.execute_with(|| {
		// Empty VK must fail fast in genesis
		genesis_config.build();
	});
}

#[test]
fn runtime_api_lists_dynamic_circuit_ids_from_storage() {
	let storage = frame_system::GenesisConfig::<crate::mock::Test>::default()
		.build_storage()
		.unwrap();

	let mut ext = TestExternalities::new(storage);
	ext.execute_with(|| {
		let vk_a: frame_support::BoundedVec<u8, frame_support::traits::ConstU32<8192>> =
			vec![1u8; 512].try_into().unwrap();
		let vk_b: frame_support::BoundedVec<u8, frame_support::traits::ConstU32<8192>> =
			vec![2u8; 512].try_into().unwrap();

		assert_ok!(ZkVerifier::register_verification_key(
			RuntimeOrigin::root(),
			CircuitId(77),
			1,
			vk_a
		));
		assert_ok!(ZkVerifier::register_verification_key(
			RuntimeOrigin::root(),
			CircuitId(88),
			1,
			vk_b
		));

		let all = crate::Pallet::<crate::mock::Test>::runtime_api_get_all_circuit_versions();
		assert!(all.iter().any(|info| info.circuit_id == 77));
		assert!(all.iter().any(|info| info.circuit_id == 88));
	});
}

// ============================================================================
// Block Number Tests
// ============================================================================

#[test]
fn genesis_vks_registered_at_block_zero() {
	let vk = sample_vk_1();

	let genesis_config: GenesisConfig<crate::mock::Test> = GenesisConfig {
		verification_keys: vec![(CircuitId::TRANSFER, vk)],
		_phantom: Default::default(),
	};

	let storage = frame_system::GenesisConfig::<crate::mock::Test>::default()
		.build_storage()
		.unwrap();

	let mut ext = TestExternalities::new(storage);

	ext.execute_with(|| {
		genesis_config.build();

		let stored = VerificationKeys::<crate::mock::Test>::get(CircuitId::TRANSFER, 1).unwrap();
		assert_eq!(stored.registered_at, 0u64);
	});
}

// ============================================================================
// Integration with Runtime Tests
// ============================================================================

#[test]
fn genesis_vks_usable_immediately() {
	let vk = sample_vk_1();

	let genesis_config: GenesisConfig<crate::mock::Test> = GenesisConfig {
		verification_keys: vec![(CircuitId::TRANSFER, vk)],
		_phantom: Default::default(),
	};

	let storage = frame_system::GenesisConfig::<crate::mock::Test>::default()
		.build_storage()
		.unwrap();

	let mut ext = TestExternalities::new(storage);

	ext.execute_with(|| {
		genesis_config.build();

		// Should be able to verify immediately (in test mode returns Ok)
		let proof = vec![1u8; 256];
		let proof_bounded: frame_support::BoundedVec<u8, crate::mock::MaxProofSize> =
			proof.try_into().expect("proof too large");
		let inputs_bounded: frame_support::BoundedVec<
			frame_support::BoundedVec<u8, frame_support::pallet_prelude::ConstU32<32>>,
			crate::mock::MaxPublicInputs,
		> = vec![[1u8; 32].to_vec().try_into().unwrap()]
			.try_into()
			.unwrap();

		let result = crate::mock::ZkVerifier::verify_proof(
			crate::mock::RuntimeOrigin::signed(1),
			CircuitId::TRANSFER,
			proof_bounded,
			inputs_bounded,
		);

		assert!(result.is_ok());
	});
}

// ============================================================================
// Large Scale Genesis Tests
// ============================================================================

#[test]
fn genesis_with_many_circuits() {
	let vk = sample_vk_1();
	let mut circuits = vec![];

	// Register 50 circuits
	for i in 1..=50 {
		circuits.push((CircuitId(i), vk.clone()));
	}

	let genesis_config: GenesisConfig<crate::mock::Test> = GenesisConfig {
		verification_keys: circuits,
		_phantom: Default::default(),
	};

	let storage = frame_system::GenesisConfig::<crate::mock::Test>::default()
		.build_storage()
		.unwrap();

	let mut ext = TestExternalities::new(storage);

	ext.execute_with(|| {
		genesis_config.build();

		// Verify all circuits are registered
		for i in 1..=50 {
			assert!(VerificationKeys::<crate::mock::Test>::contains_key(
				CircuitId(i),
				1
			));
		}
	});
}
