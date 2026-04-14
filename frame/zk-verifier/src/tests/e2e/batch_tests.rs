//! Tests para batch_register_verification_keys
//!
//! Cubre toda la funcionalidad de la extrinsic call_index(4):
//!
//! - Happy paths: registro de 1 a 10 entradas válidas
//! - Activación automática (auto_activate) cuando no existe versión activa
//! - set_active: true fuerza la activación aunque ya exista versión activa
//! - set_active: false no sobreescribe una versión activa existente
//! - Registro de múltiples versiones del mismo circuito
//! - Registro de múltiples circuitos distintos en un solo batch
//! - Eventos emitidos: uno por entrada + BatchVerificationKeysRegistered al final
//! - Errores de guardiana: batch vacío, origen no-root, VK vacía
//!
//! NOTA sobre atomicidad:
//! La extrinsic garantiza atomicidad a nivel de Executive (el runtime envuelve
//! cada extrinsic en una transacción de storage). En tests que invocan la función
//! directamente (sin Executive), los writes anteriores al error SÍ persisten.
//! Por eso los tests de error solo cubren casos en los que el fallo ocurre
//! ANTES de cualquier escritura (guardias iniciales).

use crate::{
	ActiveCircuitVersion, Error, VerificationKeys,
	mock::{RuntimeOrigin, Test, ZkVerifier},
	pallet::Event,
	types::{CircuitId, VkEntry},
};
use frame_support::{BoundedVec, assert_noop, assert_ok, pallet_prelude::ConstU32};
use sp_io::TestExternalities;
use sp_runtime::BuildStorage;

// ============================================================================
// Helpers
// ============================================================================

/// Crea un VK válido de 512 bytes (suficiente para Groth16 / longitud aceptada
/// por VerificationKey::new con el rango esperado del proof system).
fn sample_vk() -> BoundedVec<u8, ConstU32<8192>> {
	let mut vk = Vec::with_capacity(512);
	vk.extend_from_slice(&[1u8; 64]);
	vk.extend_from_slice(&[2u8; 128]);
	vk.extend_from_slice(&[3u8; 128]);
	vk.extend_from_slice(&[4u8; 128]);
	vk.extend_from_slice(&[5u8; 64]);
	vk.try_into().unwrap()
}

/// Crea un VK válido de tamaño diferente para distinguir datos entre entradas.
fn sample_vk_alt() -> BoundedVec<u8, ConstU32<8192>> {
	let mut vk = Vec::with_capacity(512);
	vk.extend_from_slice(&[10u8; 64]);
	vk.extend_from_slice(&[20u8; 128]);
	vk.extend_from_slice(&[30u8; 128]);
	vk.extend_from_slice(&[40u8; 128]);
	vk.extend_from_slice(&[50u8; 64]);
	vk.try_into().unwrap()
}

fn make_entry(circuit_id: CircuitId, version: u32, set_active: bool) -> VkEntry {
	VkEntry {
		circuit_id,
		version,
		verification_key: sample_vk(),
		set_active,
	}
}

fn bounded_entries(entries: Vec<VkEntry>) -> BoundedVec<VkEntry, ConstU32<10>> {
	entries
		.try_into()
		.expect("batch no puede superar 10 entradas")
}

fn new_ext() -> TestExternalities {
	let storage = frame_system::GenesisConfig::<Test>::default()
		.build_storage()
		.unwrap();
	TestExternalities::new(storage)
}

// ============================================================================
// Happy paths: registro exitoso
// ============================================================================

#[test]
fn batch_with_single_entry_works() {
	new_ext().execute_with(|| {
		let entries = bounded_entries(vec![make_entry(CircuitId::TRANSFER, 1, true)]);
		assert_ok!(ZkVerifier::batch_register_verification_keys(
			RuntimeOrigin::root(),
			entries
		));

		assert!(VerificationKeys::<Test>::contains_key(
			CircuitId::TRANSFER,
			1
		));
		assert_eq!(
			ActiveCircuitVersion::<Test>::get(CircuitId::TRANSFER),
			Some(1)
		);
	});
}

#[test]
fn batch_with_multiple_distinct_circuits_works() {
	new_ext().execute_with(|| {
		let entries = bounded_entries(vec![
			make_entry(CircuitId::TRANSFER, 1, true),
			make_entry(CircuitId::UNSHIELD, 1, true),
			make_entry(CircuitId::DISCLOSURE, 1, true),
		]);
		assert_ok!(ZkVerifier::batch_register_verification_keys(
			RuntimeOrigin::root(),
			entries
		));

		assert!(VerificationKeys::<Test>::contains_key(
			CircuitId::TRANSFER,
			1
		));
		assert!(VerificationKeys::<Test>::contains_key(
			CircuitId::UNSHIELD,
			1
		));
		assert!(VerificationKeys::<Test>::contains_key(
			CircuitId::DISCLOSURE,
			1
		));
	});
}

#[test]
fn batch_preserves_key_data_correctly() {
	new_ext().execute_with(|| {
		let vk_data = sample_vk();
		let entry = VkEntry {
			circuit_id: CircuitId::TRANSFER,
			version: 3,
			verification_key: vk_data.clone(),
			set_active: true,
		};

		assert_ok!(ZkVerifier::batch_register_verification_keys(
			RuntimeOrigin::root(),
			bounded_entries(vec![entry])
		));

		let stored = VerificationKeys::<Test>::get(CircuitId::TRANSFER, 3).unwrap();
		assert_eq!(stored.key_data.to_vec(), vk_data.to_vec());
	});
}

#[test]
fn batch_up_to_max_size_ten_works() {
	new_ext().execute_with(|| {
		let entries: Vec<VkEntry> = (0u32..10)
			.map(|i| make_entry(CircuitId(100 + i), 1, true))
			.collect();

		assert_ok!(ZkVerifier::batch_register_verification_keys(
			RuntimeOrigin::root(),
			bounded_entries(entries)
		));

		for i in 0..10u32 {
			assert!(VerificationKeys::<Test>::contains_key(
				CircuitId(100 + i),
				1
			));
			assert_eq!(
				ActiveCircuitVersion::<Test>::get(CircuitId(100 + i)),
				Some(1)
			);
		}
	});
}

// ============================================================================
// Lógica de activación
// ============================================================================

#[test]
fn batch_auto_activates_when_no_active_version_exists() {
	new_ext().execute_with(|| {
		// set_active: false, pero no hay versión activa → debe activarse igualmente
		let entries = bounded_entries(vec![make_entry(CircuitId::TRANSFER, 1, false)]);
		assert_ok!(ZkVerifier::batch_register_verification_keys(
			RuntimeOrigin::root(),
			entries
		));

		assert_eq!(
			ActiveCircuitVersion::<Test>::get(CircuitId::TRANSFER),
			Some(1)
		);
	});
}

#[test]
fn batch_set_active_false_does_not_override_existing_active() {
	new_ext().execute_with(|| {
		// Registrar versión 1 como activa
		let first = bounded_entries(vec![make_entry(CircuitId::TRANSFER, 1, true)]);
		assert_ok!(ZkVerifier::batch_register_verification_keys(
			RuntimeOrigin::root(),
			first
		));
		assert_eq!(
			ActiveCircuitVersion::<Test>::get(CircuitId::TRANSFER),
			Some(1)
		);

		// Registrar versión 2 con set_active: false → versión activa no debe cambiar
		let second = bounded_entries(vec![make_entry(CircuitId::TRANSFER, 2, false)]);
		assert_ok!(ZkVerifier::batch_register_verification_keys(
			RuntimeOrigin::root(),
			second
		));

		assert!(VerificationKeys::<Test>::contains_key(
			CircuitId::TRANSFER,
			2
		));
		assert_eq!(
			ActiveCircuitVersion::<Test>::get(CircuitId::TRANSFER),
			Some(1), // sigue siendo 1
		);
	});
}

#[test]
fn batch_set_active_true_overrides_existing_active() {
	new_ext().execute_with(|| {
		// Registrar versión 1 como activa
		let first = bounded_entries(vec![make_entry(CircuitId::TRANSFER, 1, true)]);
		assert_ok!(ZkVerifier::batch_register_verification_keys(
			RuntimeOrigin::root(),
			first
		));

		// Registrar versión 2 con set_active: true → debe convertirse en activa
		let second = bounded_entries(vec![make_entry(CircuitId::TRANSFER, 2, true)]);
		assert_ok!(ZkVerifier::batch_register_verification_keys(
			RuntimeOrigin::root(),
			second
		));

		assert_eq!(
			ActiveCircuitVersion::<Test>::get(CircuitId::TRANSFER),
			Some(2)
		);
	});
}

#[test]
fn batch_same_circuit_two_entries_first_auto_activates_second_does_not() {
	new_ext().execute_with(|| {
		// Primera entrada: no hay activo → auto_activate
		// Segunda entrada: ya existe activo (puesto por la primera) y set_active: false → sin cambio
		let entries = bounded_entries(vec![
			make_entry(CircuitId::TRANSFER, 1, false),
			make_entry(CircuitId::TRANSFER, 2, false),
		]);
		assert_ok!(ZkVerifier::batch_register_verification_keys(
			RuntimeOrigin::root(),
			entries
		));

		assert!(VerificationKeys::<Test>::contains_key(
			CircuitId::TRANSFER,
			1
		));
		assert!(VerificationKeys::<Test>::contains_key(
			CircuitId::TRANSFER,
			2
		));
		// Activo es la versión 1 (la que fue auto-activada)
		assert_eq!(
			ActiveCircuitVersion::<Test>::get(CircuitId::TRANSFER),
			Some(1)
		);
	});
}

#[test]
fn batch_same_circuit_two_entries_second_set_active_true_overrides() {
	new_ext().execute_with(|| {
		// Primera entrada: auto_activate → version 1 activa
		// Segunda entrada: set_active: true → version 2 pasa a activa
		let entries = bounded_entries(vec![
			make_entry(CircuitId::TRANSFER, 1, false),
			make_entry(CircuitId::TRANSFER, 2, true),
		]);
		assert_ok!(ZkVerifier::batch_register_verification_keys(
			RuntimeOrigin::root(),
			entries
		));

		assert_eq!(
			ActiveCircuitVersion::<Test>::get(CircuitId::TRANSFER),
			Some(2)
		);
	});
}

#[test]
fn batch_each_circuit_activates_independently() {
	new_ext().execute_with(|| {
		// Dos circuitos distintos, ninguno con versión activa previa → ambos auto-activan
		let entries = bounded_entries(vec![
			make_entry(CircuitId::TRANSFER, 5, false),
			make_entry(CircuitId::UNSHIELD, 3, false),
		]);
		assert_ok!(ZkVerifier::batch_register_verification_keys(
			RuntimeOrigin::root(),
			entries
		));

		assert_eq!(
			ActiveCircuitVersion::<Test>::get(CircuitId::TRANSFER),
			Some(5)
		);
		assert_eq!(
			ActiveCircuitVersion::<Test>::get(CircuitId::UNSHIELD),
			Some(3)
		);
	});
}

// ============================================================================
// Múltiples versiones del mismo circuito
// ============================================================================

#[test]
fn batch_registers_multiple_versions_for_same_circuit() {
	new_ext().execute_with(|| {
		let entries = bounded_entries(vec![
			make_entry(CircuitId::TRANSFER, 1, true),
			make_entry(CircuitId::TRANSFER, 2, false),
			make_entry(CircuitId::TRANSFER, 3, false),
		]);
		assert_ok!(ZkVerifier::batch_register_verification_keys(
			RuntimeOrigin::root(),
			entries
		));

		assert!(VerificationKeys::<Test>::contains_key(
			CircuitId::TRANSFER,
			1
		));
		assert!(VerificationKeys::<Test>::contains_key(
			CircuitId::TRANSFER,
			2
		));
		assert!(VerificationKeys::<Test>::contains_key(
			CircuitId::TRANSFER,
			3
		));
		// Solo la primera es la activa
		assert_eq!(
			ActiveCircuitVersion::<Test>::get(CircuitId::TRANSFER),
			Some(1)
		);
	});
}

// ============================================================================
// Eventos
// ============================================================================

#[test]
fn batch_emits_per_entry_events_and_summary_event() {
	new_ext().execute_with(|| {
		frame_system::Pallet::<Test>::set_block_number(1);

		let entries = bounded_entries(vec![
			make_entry(CircuitId::TRANSFER, 1, true),
			make_entry(CircuitId::UNSHIELD, 1, true),
		]);
		assert_ok!(ZkVerifier::batch_register_verification_keys(
			RuntimeOrigin::root(),
			entries
		));

		let events: Vec<_> = frame_system::Pallet::<Test>::events()
			.into_iter()
			.map(|r| r.event)
			.collect();

		// Debe haber ActiveVersionSet para cada entrada, VerificationKeyRegistered para
		// cada entrada, y BatchVerificationKeysRegistered al final.
		let active_set_count = events
			.iter()
			.filter(|e| {
				matches!(
					e,
					crate::mock::RuntimeEvent::ZkVerifier(Event::ActiveVersionSet { .. })
				)
			})
			.count();

		let vk_registered_count = events
			.iter()
			.filter(|e| {
				matches!(
					e,
					crate::mock::RuntimeEvent::ZkVerifier(Event::VerificationKeyRegistered { .. })
				)
			})
			.count();

		let batch_summary_count = events
			.iter()
			.filter(|e| {
				matches!(
					e,
					crate::mock::RuntimeEvent::ZkVerifier(Event::BatchVerificationKeysRegistered {
						count: 2
					})
				)
			})
			.count();

		assert_eq!(active_set_count, 2, "debe haber 2 eventos ActiveVersionSet");
		assert_eq!(
			vk_registered_count, 2,
			"debe haber 2 eventos VerificationKeyRegistered"
		);
		assert_eq!(
			batch_summary_count, 1,
			"debe haber 1 evento BatchVerificationKeysRegistered"
		);
	});
}

#[test]
fn batch_emits_single_entry_events_correctly() {
	new_ext().execute_with(|| {
		frame_system::Pallet::<Test>::set_block_number(1);

		let entries = bounded_entries(vec![make_entry(CircuitId::DISCLOSURE, 7, true)]);
		assert_ok!(ZkVerifier::batch_register_verification_keys(
			RuntimeOrigin::root(),
			entries
		));

		let events: Vec<_> = frame_system::Pallet::<Test>::events()
			.into_iter()
			.map(|r| r.event)
			.collect();

		// Verificar evento específico de registro
		let registered = events.iter().any(|e| {
			matches!(
				e,
				crate::mock::RuntimeEvent::ZkVerifier(Event::VerificationKeyRegistered {
					circuit_id: CircuitId::DISCLOSURE,
					version: 7,
				})
			)
		});
		assert!(
			registered,
			"debe emitir VerificationKeyRegistered para DISCLOSURE v7"
		);

		// Verificar evento de resumen final
		let summary = events.iter().any(|e| {
			matches!(
				e,
				crate::mock::RuntimeEvent::ZkVerifier(Event::BatchVerificationKeysRegistered {
					count: 1
				})
			)
		});
		assert!(
			summary,
			"debe emitir BatchVerificationKeysRegistered con count=1"
		);
	});
}

#[test]
fn batch_no_active_version_event_when_set_active_false_with_existing_active() {
	new_ext().execute_with(|| {
		// Pre-registrar versión activa
		let first = bounded_entries(vec![make_entry(CircuitId::TRANSFER, 1, true)]);
		assert_ok!(ZkVerifier::batch_register_verification_keys(
			RuntimeOrigin::root(),
			first
		));

		frame_system::Pallet::<Test>::reset_events();

		// Segunda vuelta: set_active: false con activo existente → sin evento ActiveVersionSet
		let second = bounded_entries(vec![make_entry(CircuitId::TRANSFER, 2, false)]);
		assert_ok!(ZkVerifier::batch_register_verification_keys(
			RuntimeOrigin::root(),
			second
		));

		let events: Vec<_> = frame_system::Pallet::<Test>::events()
			.into_iter()
			.map(|r| r.event)
			.collect();

		let active_set_count = events
			.iter()
			.filter(|e| {
				matches!(
					e,
					crate::mock::RuntimeEvent::ZkVerifier(Event::ActiveVersionSet { .. })
				)
			})
			.count();

		assert_eq!(
			active_set_count, 0,
			"no debe emitir ActiveVersionSet cuando set_active es false y ya existe versión activa"
		);
	});
}

// ============================================================================
// Errores de guardiana (ocurren antes de cualquier escritura)
// ============================================================================

#[test]
fn batch_empty_reverts_with_invalid_batch_size() {
	new_ext().execute_with(|| {
		let empty: BoundedVec<VkEntry, ConstU32<10>> = BoundedVec::new();
		assert_noop!(
			ZkVerifier::batch_register_verification_keys(RuntimeOrigin::root(), empty),
			Error::<Test>::InvalidBatchSize
		);
	});
}

#[test]
fn batch_non_root_fails_with_bad_origin() {
	new_ext().execute_with(|| {
		let entries = bounded_entries(vec![make_entry(CircuitId::TRANSFER, 1, true)]);
		assert_noop!(
			ZkVerifier::batch_register_verification_keys(RuntimeOrigin::signed(1), entries),
			sp_runtime::DispatchError::BadOrigin
		);
	});
}

#[test]
fn batch_first_entry_empty_vk_fails() {
	new_ext().execute_with(|| {
		let empty_vk: BoundedVec<u8, ConstU32<8192>> = BoundedVec::new();
		let entry = VkEntry {
			circuit_id: CircuitId::TRANSFER,
			version: 1,
			verification_key: empty_vk,
			set_active: true,
		};
		let entries = bounded_entries(vec![entry]);

		// El primer elemento falla la validación de dominio → error antes de cualquier write
		assert_noop!(
			ZkVerifier::batch_register_verification_keys(RuntimeOrigin::root(), entries),
			Error::<Test>::EmptyVerificationKey
		);
	});
}

// ============================================================================
// Idempotencia / sobreescritura
// ============================================================================

#[test]
fn batch_overwrites_existing_key_data_for_same_version() {
	new_ext().execute_with(|| {
		// Registrar circuito version 1 con datos A
		let entry_a = VkEntry {
			circuit_id: CircuitId::TRANSFER,
			version: 1,
			verification_key: sample_vk(),
			set_active: true,
		};
		assert_ok!(ZkVerifier::batch_register_verification_keys(
			RuntimeOrigin::root(),
			bounded_entries(vec![entry_a])
		));

		// Sobrescribir version 1 con datos B
		let entry_b = VkEntry {
			circuit_id: CircuitId::TRANSFER,
			version: 1,
			verification_key: sample_vk_alt(),
			set_active: false,
		};
		assert_ok!(ZkVerifier::batch_register_verification_keys(
			RuntimeOrigin::root(),
			bounded_entries(vec![entry_b])
		));

		let stored = VerificationKeys::<Test>::get(CircuitId::TRANSFER, 1).unwrap();
		assert_eq!(stored.key_data.to_vec(), sample_vk_alt().to_vec());
	});
}

// ============================================================================
// Circuitos personalizados (IDs fuera de las constantes predefinidas)
// ============================================================================

#[test]
fn batch_works_with_custom_circuit_ids() {
	new_ext().execute_with(|| {
		let entries = bounded_entries(vec![
			make_entry(CircuitId(42), 1, true),
			make_entry(CircuitId(999), 2, true),
		]);
		assert_ok!(ZkVerifier::batch_register_verification_keys(
			RuntimeOrigin::root(),
			entries
		));

		assert!(VerificationKeys::<Test>::contains_key(CircuitId(42), 1));
		assert!(VerificationKeys::<Test>::contains_key(CircuitId(999), 2));
		assert_eq!(ActiveCircuitVersion::<Test>::get(CircuitId(42)), Some(1));
		assert_eq!(ActiveCircuitVersion::<Test>::get(CircuitId(999)), Some(2));
	});
}
