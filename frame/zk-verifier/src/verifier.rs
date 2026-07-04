//! Core Groth16 proof verification.
//!
//! Single entry point for all verification logic used by [`crate::ZkVerifierPort`].
//! Resolves the circuit version, loads the VK from storage, calls
//! `orbinum-zk-verifier`, and updates statistics — all in one place.

use crate::{
	Error,
	pallet::{ActiveCircuitVersion, Config, VerificationKeys, VerificationStats},
	types::CircuitId,
};
use alloc::vec::Vec;

/// Verify a Groth16 proof against a circuit's stored verification key.
///
/// Returns `(valid, resolved_version)` so callers can emit events with the
/// exact version that was used.
///
/// * `circuit_id`  — target circuit
/// * `version`     — explicit version, or `None` to use the active version
/// * `proof_bytes` — compressed Groth16 proof bytes
/// * `raw_inputs`  — public inputs, each exactly 32 bytes (LE BN254 field element)
pub fn verify<T: Config>(
	circuit_id: CircuitId,
	version: Option<u32>,
	proof_bytes: &[u8],
	raw_inputs: Vec<[u8; 32]>,
) -> Result<(bool, u32), sp_runtime::DispatchError> {
	frame_support::ensure!(!proof_bytes.is_empty(), Error::<T>::EmptyProof);
	frame_support::ensure!(!raw_inputs.is_empty(), Error::<T>::EmptyPublicInputs);

	let resolved = version
		.or_else(|| ActiveCircuitVersion::<T>::get(circuit_id))
		.ok_or(Error::<T>::CircuitNotFound)?;

	let vk_info = VerificationKeys::<T>::get(circuit_id, resolved)
		.ok_or(Error::<T>::VerificationKeyNotFound)?;

	let result = do_verify(vk_info.key_data.as_slice(), proof_bytes, raw_inputs);
	record_stats::<T>(circuit_id, resolved, result);

	Ok((result, resolved))
}

/// Record a verification outcome into `VerificationStats`.
///
/// Failed attempts are counted too. Note the asymmetry between call paths:
/// the `verify_proof` extrinsic returns `Err` on failure, so the runtime
/// reverts this write; the Port path returns `Ok((false, _))`, so the write
/// **persists**. This is deliberate — persisting Port-side failures gives
/// observability into invalid proofs reaching the pool (client bugs / attacks).
fn record_stats<T: Config>(circuit_id: CircuitId, version: u32, result: bool) {
	VerificationStats::<T>::mutate(circuit_id, version, |s| {
		s.total_verifications = s.total_verifications.saturating_add(1);
		if result {
			s.successful_verifications = s.successful_verifications.saturating_add(1);
		} else {
			s.failed_verifications = s.failed_verifications.saturating_add(1);
		}
	});
}

/// Actual cryptographic verification.
///
/// Returns `true` unconditionally in **test** builds (no real VK/proof available in unit tests).
/// In **benchmarking** builds the full Groth16 pairing computation runs so that
/// `verify_proof` weights reflect real on-chain cost.
fn do_verify(vk_bytes: &[u8], proof_bytes: &[u8], raw_inputs: Vec<[u8; 32]>) -> bool {
	#[cfg(test)]
	{
		let _ = (vk_bytes, proof_bytes, raw_inputs);
		true
	}

	#[cfg(not(test))]
	{
		use orbinum_zk_verifier::{Groth16Verifier, Proof, PublicInputs, VerifyingKey};

		let vk = VerifyingKey::new(vk_bytes.to_vec());
		let proof = Proof::new(proof_bytes.to_vec());
		let inputs = PublicInputs::new(raw_inputs);

		Groth16Verifier::verify(&vk, &inputs, &proof)
			.map(|_| true)
			.unwrap_or(false)
	}
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
	use super::*;
	use crate::{
		mock::Test,
		pallet::{ActiveCircuitVersion, VerificationKeys, VerificationStats},
		types::{ProofSystem, VerificationKeyInfo},
	};
	use frame_support::{BoundedVec, assert_err};
	use sp_io::TestExternalities;
	use sp_runtime::BuildStorage;

	fn vk_bytes() -> BoundedVec<u8, frame_support::traits::ConstU32<8192>> {
		vec![0xAB; 300].try_into().unwrap()
	}

	fn proof_bytes() -> Vec<u8> {
		vec![0x01; 128]
	}

	fn inputs() -> Vec<[u8; 32]> {
		vec![[0x02u8; 32]]
	}

	fn new_test_ext() -> TestExternalities {
		let storage = frame_system::GenesisConfig::<Test>::default()
			.build_storage()
			.expect("mock storage ok");
		TestExternalities::new(storage)
	}

	fn insert_vk(circuit_id: CircuitId, version: u32) {
		VerificationKeys::<Test>::insert(
			circuit_id,
			version,
			VerificationKeyInfo {
				key_data: vk_bytes(),
				system: ProofSystem::Groth16,
				registered_at: 0u64,
			},
		);
	}

	// ── Error paths ───────────────────────────────────────────────────────────

	#[test]
	fn empty_proof_is_rejected() {
		new_test_ext().execute_with(|| {
			assert_err!(
				verify::<Test>(CircuitId::TRANSFER, Some(1), &[], inputs()),
				crate::Error::<Test>::EmptyProof
			);
		});
	}

	#[test]
	fn empty_public_inputs_is_rejected() {
		new_test_ext().execute_with(|| {
			assert_err!(
				verify::<Test>(CircuitId::TRANSFER, Some(1), &proof_bytes(), vec![]),
				crate::Error::<Test>::EmptyPublicInputs
			);
		});
	}

	#[test]
	fn no_active_version_returns_circuit_not_found() {
		new_test_ext().execute_with(|| {
			assert_err!(
				verify::<Test>(CircuitId::TRANSFER, None, &proof_bytes(), inputs()),
				crate::Error::<Test>::CircuitNotFound
			);
		});
	}

	#[test]
	fn explicit_version_without_vk_returns_not_found() {
		new_test_ext().execute_with(|| {
			assert_err!(
				verify::<Test>(CircuitId::TRANSFER, Some(99), &proof_bytes(), inputs()),
				crate::Error::<Test>::VerificationKeyNotFound
			);
		});
	}

	// ── Happy paths ───────────────────────────────────────────────────────────

	#[test]
	fn verify_resolves_active_version() {
		new_test_ext().execute_with(|| {
			insert_vk(CircuitId::TRANSFER, 1);
			ActiveCircuitVersion::<Test>::insert(CircuitId::TRANSFER, 1u32);

			let (ok, version) =
				verify::<Test>(CircuitId::TRANSFER, None, &proof_bytes(), inputs()).unwrap();
			assert!(ok);
			assert_eq!(version, 1);
		});
	}

	#[test]
	fn verify_uses_explicit_version_over_active() {
		new_test_ext().execute_with(|| {
			insert_vk(CircuitId::TRANSFER, 1);
			insert_vk(CircuitId::TRANSFER, 2);
			ActiveCircuitVersion::<Test>::insert(CircuitId::TRANSFER, 1u32);

			let (ok, version) =
				verify::<Test>(CircuitId::TRANSFER, Some(2), &proof_bytes(), inputs()).unwrap();
			assert!(ok);
			assert_eq!(version, 2, "debe usar la versión explícita, no la activa");
		});
	}

	#[test]
	fn verify_updates_stats_on_success() {
		new_test_ext().execute_with(|| {
			insert_vk(CircuitId::UNSHIELD, 1);
			ActiveCircuitVersion::<Test>::insert(CircuitId::UNSHIELD, 1u32);

			verify::<Test>(CircuitId::UNSHIELD, None, &proof_bytes(), inputs()).unwrap();
			verify::<Test>(CircuitId::UNSHIELD, None, &proof_bytes(), inputs()).unwrap();

			let stats = VerificationStats::<Test>::get(CircuitId::UNSHIELD, 1u32);
			assert_eq!(stats.total_verifications, 2);
			assert_eq!(stats.successful_verifications, 2);
			assert_eq!(stats.failed_verifications, 0);
		});
	}

	#[test]
	fn record_stats_persists_failures() {
		new_test_ext().execute_with(|| {
			record_stats::<Test>(CircuitId::TRANSFER, 1, false);
			record_stats::<Test>(CircuitId::TRANSFER, 1, false);
			record_stats::<Test>(CircuitId::TRANSFER, 1, true);

			let stats = VerificationStats::<Test>::get(CircuitId::TRANSFER, 1u32);
			assert_eq!(stats.total_verifications, 3);
			assert_eq!(stats.successful_verifications, 1);
			assert_eq!(stats.failed_verifications, 2);
		});
	}

	#[test]
	fn verify_works_for_each_circuit_independently() {
		new_test_ext().execute_with(|| {
			for cid in [
				CircuitId::TRANSFER,
				CircuitId::UNSHIELD,
				CircuitId::PRIVATE_LINK,
				CircuitId::VALUE_PROOF,
			] {
				insert_vk(cid, 1);
				ActiveCircuitVersion::<Test>::insert(cid, 1u32);

				let (ok, v) = verify::<Test>(cid, None, &proof_bytes(), inputs()).unwrap();
				assert!(ok, "circuit {cid:?} debería verificar");
				assert_eq!(v, 1);
			}
		});
	}

	#[test]
	fn stats_accumulate_across_multiple_circuits() {
		new_test_ext().execute_with(|| {
			insert_vk(CircuitId::TRANSFER, 1);
			insert_vk(CircuitId::UNSHIELD, 1);
			ActiveCircuitVersion::<Test>::insert(CircuitId::TRANSFER, 1u32);
			ActiveCircuitVersion::<Test>::insert(CircuitId::UNSHIELD, 1u32);

			verify::<Test>(CircuitId::TRANSFER, None, &proof_bytes(), inputs()).unwrap();
			verify::<Test>(CircuitId::UNSHIELD, None, &proof_bytes(), inputs()).unwrap();
			verify::<Test>(CircuitId::UNSHIELD, None, &proof_bytes(), inputs()).unwrap();

			let t = VerificationStats::<Test>::get(CircuitId::TRANSFER, 1u32);
			assert_eq!(t.total_verifications, 1);

			let u = VerificationStats::<Test>::get(CircuitId::UNSHIELD, 1u32);
			assert_eq!(u.total_verifications, 2);
		});
	}
}
