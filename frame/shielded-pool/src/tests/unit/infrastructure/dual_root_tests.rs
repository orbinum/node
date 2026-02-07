//! Dual-Root Storage Tests (Fase 3 & 4)
//!
//! Tests for Blake2 + Poseidon dual root computation and validation.

use crate::tests::helpers::*;
use crate::{Commitment, Event, mock::*};
use frame_support::assert_ok;

// ============================================================================
// Tests sin poseidon-wasm (Blake2 solo)
// ============================================================================

#[test]
fn blake2_root_stored_correctly() {
	new_test_ext().execute_with(|| {
		let commitment = Commitment([1u8; 32]);

		assert_ok!(ShieldedPool::shield(
			RuntimeOrigin::signed(1),
			0,
			100u128,
			commitment,
			sample_encrypted_memo(),
		));

		// Debe tener MerkleRoot (puede ser zero hash del árbol con 1 hoja)
		let _root = crate::MerkleRoot::<Test>::get();
		// El root existe en storage
		let stored = crate::MerkleRoot::<Test>::exists();
		assert!(stored);

		// Sin poseidon-wasm, PoseidonRoot debe ser None
		#[cfg(not(feature = "poseidon-wasm"))]
		{
			let poseidon_root = crate::PoseidonRoot::<Test>::get();
			assert!(poseidon_root.is_none());
		}
	});
}

#[test]
fn blake2_historic_roots_maintained() {
	new_test_ext().execute_with(|| {
		// Shield múltiples veces
		for i in 0..3u8 {
			let commitment = Commitment([i + 1; 32]);
			assert_ok!(ShieldedPool::shield(
				RuntimeOrigin::signed(1),
				0,
				100u128,
				commitment,
				sample_encrypted_memo_with_seed(i),
			));
		}

		// Obtener roots
		let root1 = crate::MerkleRoot::<Test>::get();

		// Verificar que las raíces históricas Blake2 existen
		let is_known = crate::HistoricRoots::<Test>::get(root1);
		assert!(is_known);
	});
}

// ============================================================================
// Tests con poseidon-wasm (Dual-Root)
// ============================================================================

#[cfg(feature = "poseidon-wasm")]
#[test]
fn dual_roots_computed_correctly() {
	new_test_ext().execute_with(|| {
		let commitment = Commitment([1u8; 32]);

		assert_ok!(ShieldedPool::shield(
			RuntimeOrigin::signed(1),
			0,
			100u128,
			commitment,
			sample_encrypted_memo(),
		));

		// Ambas raíces deben existir y ser diferentes
		let blake2_root = crate::MerkleRoot::<Test>::get();
		let poseidon_root = crate::PoseidonRoot::<Test>::get();

		assert_ne!(blake2_root, [0u8; 32], "Blake2 root should not be zero");
		assert!(poseidon_root.is_some(), "Poseidon root should exist");

		let poseidon_root = poseidon_root.unwrap();
		assert_ne!(poseidon_root, [0u8; 32], "Poseidon root should not be zero");

		// Las raíces deben ser diferentes (Blake2 != Poseidon)
		assert_ne!(blake2_root, poseidon_root);
	});
}

#[cfg(feature = "poseidon-wasm")]
#[test]
fn dual_historic_roots_maintained() {
	new_test_ext().execute_with(|| {
		// Shield múltiples veces
		for i in 0..3u8 {
			let commitment = Commitment([i + 1; 32]);
			assert_ok!(ShieldedPool::shield(
				RuntimeOrigin::signed(1),
				0,
				100u128,
				commitment,
				sample_encrypted_memo_with_seed(i),
			));
		}

		// Obtener ambas raíces
		let blake2_root = crate::MerkleRoot::<Test>::get();
		let poseidon_root = crate::PoseidonRoot::<Test>::get().expect("Poseidon root should exist");

		// Verificar que ambas raíces históricas existen
		let blake2_known = crate::HistoricRoots::<Test>::get(blake2_root);
		let poseidon_known = crate::HistoricPoseidonRoots::<Test>::get(poseidon_root);

		assert!(blake2_known);
		assert!(poseidon_known);
	});
}

#[cfg(feature = "poseidon-wasm")]
#[test]
fn poseidon_roots_are_deterministic() {
	new_test_ext().execute_with(|| {
		let commitment = Commitment([42u8; 32]);

		// Primer shield
		assert_ok!(ShieldedPool::shield(
			RuntimeOrigin::signed(1),
			0,
			100u128,
			commitment,
			sample_encrypted_memo(),
		));

		let root1 = crate::PoseidonRoot::<Test>::get().unwrap();

		// Reset y shield de nuevo con mismo commitment
		crate::MerkleRoot::<Test>::kill();
		crate::PoseidonRoot::<Test>::kill();
		crate::MerkleTreeSize::<Test>::kill();
		let _ = crate::MerkleLeaves::<Test>::clear(u32::MAX, None);

		assert_ok!(ShieldedPool::shield(
			RuntimeOrigin::signed(1),
			0,
			100u128,
			commitment,
			sample_encrypted_memo(),
		));

		let root2 = crate::PoseidonRoot::<Test>::get().unwrap();

		// Deben ser iguales (determinístico)
		assert_eq!(root1, root2);
	});
}

#[cfg(feature = "poseidon-wasm")]
#[test]
fn poseidon_roots_change_with_different_commitments() {
	new_test_ext().execute_with(|| {
		let commitment1 = Commitment([1u8; 32]);

		assert_ok!(ShieldedPool::shield(
			RuntimeOrigin::signed(1),
			0,
			100u128,
			commitment1,
			sample_encrypted_memo(),
		));

		let root1 = crate::PoseidonRoot::<Test>::get().unwrap();

		let commitment2 = Commitment([2u8; 32]);

		assert_ok!(ShieldedPool::shield(
			RuntimeOrigin::signed(1),
			0,
			100u128,
			commitment2,
			sample_encrypted_memo(),
		));

		let root2 = crate::PoseidonRoot::<Test>::get().unwrap();

		// Raíces deben ser diferentes
		assert_ne!(root1, root2);
	});
}

// ============================================================================
// Tests de Validación Root (Fase 4)
// ============================================================================

#[test]
fn is_known_root_accepts_blake2_roots() {
	new_test_ext().execute_with(|| {
		let commitment = Commitment([1u8; 32]);

		assert_ok!(ShieldedPool::shield(
			RuntimeOrigin::signed(1),
			0,
			100u128,
			commitment,
			sample_encrypted_memo(),
		));

		let root = crate::MerkleRoot::<Test>::get();

		// Debe reconocer la raíz Blake2
		use crate::infrastructure::repositories::MerkleRepository;
		assert!(MerkleRepository::is_known_root::<Test>(&root));
	});
}

#[cfg(feature = "poseidon-wasm")]
#[test]
fn is_known_root_accepts_poseidon_roots() {
	new_test_ext().execute_with(|| {
		let commitment = Commitment([1u8; 32]);

		assert_ok!(ShieldedPool::shield(
			RuntimeOrigin::signed(1),
			0,
			100u128,
			commitment,
			sample_encrypted_memo(),
		));

		let poseidon_root = crate::PoseidonRoot::<Test>::get().unwrap();

		// Debe reconocer la raíz Poseidon
		use crate::infrastructure::repositories::MerkleRepository;
		assert!(MerkleRepository::is_known_root::<Test>(&poseidon_root));
	});
}

#[cfg(feature = "poseidon-wasm")]
#[test]
fn is_known_root_accepts_both_roots() {
	new_test_ext().execute_with(|| {
		let commitment = Commitment([1u8; 32]);

		assert_ok!(ShieldedPool::shield(
			RuntimeOrigin::signed(1),
			0,
			100u128,
			commitment,
			sample_encrypted_memo(),
		));

		let blake2_root = crate::MerkleRoot::<Test>::get();
		let poseidon_root = crate::PoseidonRoot::<Test>::get().unwrap();

		// Debe reconocer ambas raíces
		use crate::infrastructure::repositories::MerkleRepository;
		assert!(MerkleRepository::is_known_root::<Test>(&blake2_root));
		assert!(MerkleRepository::is_known_root::<Test>(&poseidon_root));
	});
}

#[test]
fn is_known_root_rejects_unknown_roots() {
	new_test_ext().execute_with(|| {
		let fake_root = [99u8; 32];

		// No debe reconocer raíces falsas
		use crate::infrastructure::repositories::MerkleRepository;
		assert!(!MerkleRepository::is_known_root::<Test>(&fake_root));
	});
}

#[cfg(feature = "poseidon-wasm")]
#[test]
fn historic_poseidon_roots_maintained_after_multiple_shields() {
	new_test_ext().execute_with(|| {
		let mut poseidon_roots = sp_std::vec::Vec::new();

		// Shield múltiples veces y recolectar raíces Poseidon
		for i in 0..5u8 {
			let commitment = Commitment([i + 1; 32]);
			assert_ok!(ShieldedPool::shield(
				RuntimeOrigin::signed(1),
				0,
				100u128,
				commitment,
				sample_encrypted_memo_with_seed(i),
			));

			let root = crate::PoseidonRoot::<Test>::get().unwrap();
			poseidon_roots.push(root);
		}

		// Verificar que todas las raíces Poseidon están en histórico
		use crate::infrastructure::repositories::MerkleRepository;
		for root in poseidon_roots {
			assert!(MerkleRepository::is_known_poseidon_root::<Test>(&root));
		}
	});
}

// ============================================================================
// Tests de Backward Compatibility
// ============================================================================

#[test]
fn backward_compatibility_blake2_always_works() {
	new_test_ext().execute_with(|| {
		// Shield funciona sin importar el feature flag
		let commitment = Commitment([1u8; 32]);

		assert_ok!(ShieldedPool::shield(
			RuntimeOrigin::signed(1),
			0,
			100u128,
			commitment,
			sample_encrypted_memo(),
		));

		// Blake2 root siempre debe existir
		let root = crate::MerkleRoot::<Test>::get();
		// Verificar que existe en storage (no que sea != 0)
		let stored = crate::MerkleRoot::<Test>::exists();
		assert!(stored);

		// Historic roots siempre mantienen Blake2
		let is_known = crate::HistoricRoots::<Test>::get(root);
		assert!(is_known);
	});
}

#[cfg(feature = "poseidon-wasm")]
#[test]
fn active_root_returns_poseidon_when_available() {
	new_test_ext().execute_with(|| {
		let commitment = Commitment([1u8; 32]);

		assert_ok!(ShieldedPool::shield(
			RuntimeOrigin::signed(1),
			0,
			100u128,
			commitment,
			sample_encrypted_memo(),
		));

		use crate::infrastructure::repositories::MerkleRepository;
		let active_root = MerkleRepository::get_active_root::<Test>();
		let poseidon_root = crate::PoseidonRoot::<Test>::get().unwrap();

		// Active root debe ser Poseidon cuando está disponible
		assert_eq!(active_root, poseidon_root);
	});
}

#[cfg(not(feature = "poseidon-wasm"))]
#[test]
fn active_root_returns_blake2_when_poseidon_unavailable() {
	new_test_ext().execute_with(|| {
		let commitment = Commitment([1u8; 32]);

		assert_ok!(ShieldedPool::shield(
			RuntimeOrigin::signed(1),
			0,
			100u128,
			commitment,
			sample_encrypted_memo(),
		));

		use crate::infrastructure::repositories::MerkleRepository;
		let active_root = MerkleRepository::get_active_root::<Test>();
		let blake2_root = crate::MerkleRoot::<Test>::get();

		// Active root debe ser Blake2 cuando Poseidon no está disponible
		assert_eq!(active_root, blake2_root);
	});
}

// ============================================================================
// Tests de Eventos
// ============================================================================

#[cfg(feature = "poseidon-wasm")]
#[test]
fn merkle_root_updated_event_emits_poseidon_root() {
	new_test_ext().execute_with(|| {
		let commitment = Commitment([1u8; 32]);

		assert_ok!(ShieldedPool::shield(
			RuntimeOrigin::signed(1),
			0,
			100u128,
			commitment,
			sample_encrypted_memo(),
		));

		// Verificar que el evento emitido usa Poseidon root
		let poseidon_root = crate::PoseidonRoot::<Test>::get().unwrap();

		System::assert_has_event(
			Event::MerkleRootUpdated {
				old_root: [0u8; 32],
				new_root: poseidon_root,
				tree_size: 1,
			}
			.into(),
		);
	});
}

#[cfg(not(feature = "poseidon-wasm"))]
#[test]
fn merkle_root_updated_event_emits_blake2_root() {
	new_test_ext().execute_with(|| {
		let commitment = Commitment([1u8; 32]);

		assert_ok!(ShieldedPool::shield(
			RuntimeOrigin::signed(1),
			0,
			100u128,
			commitment,
			sample_encrypted_memo(),
		));

		// Verificar que el evento emitido usa Blake2 root
		let blake2_root = crate::MerkleRoot::<Test>::get();

		System::assert_has_event(
			Event::MerkleRootUpdated {
				old_root: [0u8; 32],
				new_root: blake2_root,
				tree_size: 1,
			}
			.into(),
		);
	});
}
