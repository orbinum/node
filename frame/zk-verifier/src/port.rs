//! [`ZkVerifierPort`] — public interface for cross-pallet ZK proof verification.
//!
//! Other pallets (e.g. `pallet-shielded-pool`, `pallet-account-mapping`) depend
//! only on this trait, never on the concrete pallet internals.
//!
//! Each method delegates public-input encoding to [`crate::encoding`] and the
//! cryptographic work to [`crate::verifier::verify`].

use crate::{
	Pallet, encoding,
	pallet::{ActiveCircuitVersion, Config, Error, VerificationKeys},
	types::CircuitId,
	verifier,
};

// ─── Trait ────────────────────────────────────────────────────────────────────

/// Cross-pallet interface for zero-knowledge proof verification.
pub trait ZkVerifierPort {
	/// Verify a private transfer proof (2-in / 2-out UTXO).
	fn verify_transfer_proof(
		proof: &[u8],
		merkle_root: &[u8; 32],
		nullifiers: &[[u8; 32]],
		commitments: &[[u8; 32]],
		asset_id: u32,
		fee: u128,
		version: Option<u32>,
	) -> Result<bool, sp_runtime::DispatchError>;

	/// Verify an unshield (pool withdrawal) proof.
	#[allow(clippy::too_many_arguments)]
	fn verify_unshield_proof(
		proof: &[u8],
		merkle_root: &[u8; 32],
		nullifier: &[u8; 32],
		amount: u128,
		recipient: &[u8; 32],
		asset_id: u32,
		fee: u128,
		version: Option<u32>,
	) -> Result<bool, sp_runtime::DispatchError>;

	/// Verify a selective disclosure proof.
	///
	/// `public_signals` must be exactly 76 bytes:
	/// `commitment[0..32] | value[32..40] | asset_id[40..44] | owner_hash[44..76]`
	fn verify_disclosure_proof(
		proof: &[u8],
		public_signals: &[u8],
		version: Option<u32>,
	) -> Result<bool, sp_runtime::DispatchError>;

	/// Batch-verify multiple disclosure proofs (optimised path via `ark-groth16`).
	///
	/// All `public_signals` slices must be exactly 76 bytes each.
	/// Batch size is limited to 10.
	fn batch_verify_disclosure_proofs(
		proofs: &[sp_std::vec::Vec<u8>],
		public_signals: &[sp_std::vec::Vec<u8>],
		version: Option<u32>,
	) -> Result<bool, sp_runtime::DispatchError>;

	/// Verify a private-link dispatch proof.
	fn verify_private_link_proof(
		proof: &[u8],
		commitment: &[u8; 32],
		call_hash_fe: &[u8; 32],
		version: Option<u32>,
	) -> Result<bool, sp_runtime::DispatchError>;
}

// ─── impl ─────────────────────────────────────────────────────────────────────

impl<T: Config> ZkVerifierPort for Pallet<T> {
	fn verify_transfer_proof(
		proof: &[u8],
		merkle_root: &[u8; 32],
		nullifiers: &[[u8; 32]],
		commitments: &[[u8; 32]],
		asset_id: u32,
		fee: u128,
		version: Option<u32>,
	) -> Result<bool, sp_runtime::DispatchError> {
		let raw = encoding::encode_transfer(merkle_root, nullifiers, commitments, asset_id, fee);
		verifier::verify::<T>(CircuitId::TRANSFER, version, proof, raw).map(|(ok, _)| ok)
	}

	fn verify_unshield_proof(
		proof: &[u8],
		merkle_root: &[u8; 32],
		nullifier: &[u8; 32],
		amount: u128,
		recipient: &[u8; 32],
		asset_id: u32,
		fee: u128,
		version: Option<u32>,
	) -> Result<bool, sp_runtime::DispatchError> {
		let raw =
			encoding::encode_unshield(merkle_root, nullifier, amount, recipient, asset_id, fee);
		verifier::verify::<T>(CircuitId::UNSHIELD, version, proof, raw).map(|(ok, _)| ok)
	}

	fn verify_disclosure_proof(
		proof: &[u8],
		public_signals: &[u8],
		version: Option<u32>,
	) -> Result<bool, sp_runtime::DispatchError> {
		let raw = encoding::decode_disclosure_signals(public_signals)?;
		verifier::verify::<T>(CircuitId::DISCLOSURE, version, proof, raw).map(|(ok, _)| ok)
	}

	fn batch_verify_disclosure_proofs(
		proofs: &[sp_std::vec::Vec<u8>],
		public_signals: &[sp_std::vec::Vec<u8>],
		version: Option<u32>,
	) -> Result<bool, sp_runtime::DispatchError> {
		use orbinum_zk_verifier::{Groth16Verifier, Proof, PublicInputs, VerifyingKey};

		const MAX_BATCH: usize = 10;

		frame_support::ensure!(
			!proofs.is_empty() && proofs.len() <= MAX_BATCH,
			Error::<T>::InvalidBatchSize
		);
		frame_support::ensure!(
			proofs.len() == public_signals.len(),
			Error::<T>::BatchLengthMismatch
		);

		let resolved = version
			.or_else(|| ActiveCircuitVersion::<T>::get(CircuitId::DISCLOSURE))
			.ok_or(Error::<T>::CircuitNotFound)?;

		let vk_info = VerificationKeys::<T>::get(CircuitId::DISCLOSURE, resolved)
			.ok_or(Error::<T>::VerificationKeyNotFound)?;

		let vk = VerifyingKey::new(vk_info.key_data.to_vec());

		let batch_proofs: sp_std::vec::Vec<Proof> =
			proofs.iter().map(|p| Proof::new(p.clone())).collect();

		let all_inputs = public_signals
			.iter()
			.map(|s| encoding::decode_disclosure_signals(s).map(PublicInputs::new))
			.collect::<Result<sp_std::vec::Vec<_>, _>>()?;

		Groth16Verifier::batch_verify(&vk, &all_inputs, &batch_proofs)
			.map_err(|_| Error::<T>::BatchVerificationFailed)?;

		Ok(true)
	}

	fn verify_private_link_proof(
		proof: &[u8],
		commitment: &[u8; 32],
		call_hash_fe: &[u8; 32],
		version: Option<u32>,
	) -> Result<bool, sp_runtime::DispatchError> {
		let raw = encoding::encode_private_link(commitment, call_hash_fe);
		verifier::verify::<T>(CircuitId::PRIVATE_LINK, version, proof, raw).map(|(ok, _)| ok)
	}
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
	use super::*;
	use crate::{
		Error,
		mock::Test,
		pallet::{ActiveCircuitVersion, VerificationKeys},
		types::{ProofSystem, VerificationKeyInfo},
	};
	use frame_support::{BoundedVec, assert_err};
	use sp_io::TestExternalities;
	use sp_runtime::BuildStorage;

	// ── Shared helpers ────────────────────────────────────────────────────────

	fn new_test_ext() -> TestExternalities {
		let storage = frame_system::GenesisConfig::<Test>::default()
			.build_storage()
			.expect("mock storage ok");
		TestExternalities::new(storage)
	}

	fn vk_bytes() -> BoundedVec<u8, frame_support::traits::ConstU32<8192>> {
		vec![0xABu8; 300].try_into().unwrap()
	}

	fn proof() -> alloc::vec::Vec<u8> {
		vec![0x01u8; 128]
	}

	fn merkle_root() -> [u8; 32] {
		[0x03u8; 32]
	}

	fn commitment() -> [u8; 32] {
		[0x01u8; 32]
	}

	fn nullifier() -> [u8; 32] {
		[0x02u8; 32]
	}

	/// 76-byte buffer accepted by `decode_disclosure_signals`.
	fn valid_signals() -> alloc::vec::Vec<u8> {
		vec![0xAAu8; 76]
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

	fn activate(circuit_id: CircuitId, version: u32) {
		ActiveCircuitVersion::<Test>::insert(circuit_id, version);
	}

	// ── decode_disclosure_signals (via verify_disclosure_proof) ───────────────
	//
	// The helper is private, so we exercise it through the public trait method.
	// decode_disclosure_signals is called BEFORE verifier::verify, so VK setup
	// is not required to hit the length check.

	#[test]
	fn signals_too_short_returns_dispatch_error_other() {
		new_test_ext().execute_with(|| {
			let err = <Pallet<Test> as ZkVerifierPort>::verify_disclosure_proof(
				&proof(),
				&vec![0u8; 75],
				None,
			)
			.unwrap_err();
			assert!(matches!(err, sp_runtime::DispatchError::Other(_)));
		});
	}

	#[test]
	fn signals_too_long_returns_dispatch_error_other() {
		new_test_ext().execute_with(|| {
			let err = <Pallet<Test> as ZkVerifierPort>::verify_disclosure_proof(
				&proof(),
				&vec![0u8; 77],
				None,
			)
			.unwrap_err();
			assert!(matches!(err, sp_runtime::DispatchError::Other(_)));
		});
	}

	#[test]
	fn signals_empty_returns_dispatch_error_other() {
		new_test_ext().execute_with(|| {
			let err =
				<Pallet<Test> as ZkVerifierPort>::verify_disclosure_proof(&proof(), &[], None)
					.unwrap_err();
			assert!(matches!(err, sp_runtime::DispatchError::Other(_)));
		});
	}

	#[test]
	fn signals_exactly_76_bytes_passes_decode() {
		// Confirms decode succeeds. CircuitNotFound fires next (no VK), not a
		// length error.
		new_test_ext().execute_with(|| {
			assert_err!(
				<Pallet<Test> as ZkVerifierPort>::verify_disclosure_proof(
					&proof(),
					&valid_signals(),
					None,
				),
				Error::<Test>::CircuitNotFound
			);
		});
	}

	// ── verify_transfer_proof ──────────────────────────────────────────────────

	#[test]
	fn transfer_empty_proof_is_rejected() {
		// EmptyProof guard fires inside verifier::verify before version resolution.
		new_test_ext().execute_with(|| {
			assert_err!(
				<Pallet<Test> as ZkVerifierPort>::verify_transfer_proof(
					&[],
					&merkle_root(),
					&[],
					&[],
					0,
					0,
					Some(1),
				),
				Error::<Test>::EmptyProof
			);
		});
	}

	#[test]
	fn transfer_no_active_version_returns_circuit_not_found() {
		new_test_ext().execute_with(|| {
			assert_err!(
				<Pallet<Test> as ZkVerifierPort>::verify_transfer_proof(
					&proof(),
					&merkle_root(),
					&[],
					&[],
					0,
					0,
					None,
				),
				Error::<Test>::CircuitNotFound
			);
		});
	}

	#[test]
	fn transfer_missing_vk_returns_not_found() {
		new_test_ext().execute_with(|| {
			assert_err!(
				<Pallet<Test> as ZkVerifierPort>::verify_transfer_proof(
					&proof(),
					&merkle_root(),
					&[],
					&[],
					0,
					0,
					Some(99),
				),
				Error::<Test>::VerificationKeyNotFound
			);
		});
	}

	#[test]
	fn transfer_happy_path_returns_true() {
		new_test_ext().execute_with(|| {
			insert_vk(CircuitId::TRANSFER, 1);
			activate(CircuitId::TRANSFER, 1);
			let ok = <Pallet<Test> as ZkVerifierPort>::verify_transfer_proof(
				&proof(),
				&merkle_root(),
				&[nullifier()],
				&[commitment()],
				42,
				1000,
				None,
			)
			.unwrap();
			assert!(ok);
		});
	}

	#[test]
	fn transfer_explicit_version_overrides_active() {
		new_test_ext().execute_with(|| {
			insert_vk(CircuitId::TRANSFER, 1);
			insert_vk(CircuitId::TRANSFER, 2);
			activate(CircuitId::TRANSFER, 1);
			let ok = <Pallet<Test> as ZkVerifierPort>::verify_transfer_proof(
				&proof(),
				&merkle_root(),
				&[],
				&[],
				0,
				0,
				Some(2),
			)
			.unwrap();
			assert!(ok);
		});
	}

	#[test]
	fn transfer_multiple_nullifiers_and_commitments_are_accepted() {
		new_test_ext().execute_with(|| {
			insert_vk(CircuitId::TRANSFER, 1);
			activate(CircuitId::TRANSFER, 1);
			let ok = <Pallet<Test> as ZkVerifierPort>::verify_transfer_proof(
				&proof(),
				&merkle_root(),
				&[[0xAAu8; 32], [0xBBu8; 32]],
				&[[0xCCu8; 32], [0xDDu8; 32]],
				1,
				500,
				None,
			)
			.unwrap();
			assert!(ok);
		});
	}

	// ── verify_unshield_proof ──────────────────────────────────────────────────

	#[test]
	fn unshield_empty_proof_is_rejected() {
		new_test_ext().execute_with(|| {
			assert_err!(
				<Pallet<Test> as ZkVerifierPort>::verify_unshield_proof(
					&[],
					&merkle_root(),
					&nullifier(),
					0,
					&[0u8; 32],
					0,
					0,
					Some(1),
				),
				Error::<Test>::EmptyProof
			);
		});
	}

	#[test]
	fn unshield_no_active_version_returns_circuit_not_found() {
		new_test_ext().execute_with(|| {
			assert_err!(
				<Pallet<Test> as ZkVerifierPort>::verify_unshield_proof(
					&proof(),
					&merkle_root(),
					&nullifier(),
					100,
					&[0u8; 32],
					0,
					0,
					None,
				),
				Error::<Test>::CircuitNotFound
			);
		});
	}

	#[test]
	fn unshield_missing_vk_returns_not_found() {
		new_test_ext().execute_with(|| {
			assert_err!(
				<Pallet<Test> as ZkVerifierPort>::verify_unshield_proof(
					&proof(),
					&merkle_root(),
					&nullifier(),
					100,
					&[0u8; 32],
					0,
					0,
					Some(99),
				),
				Error::<Test>::VerificationKeyNotFound
			);
		});
	}

	#[test]
	fn unshield_happy_path_returns_true() {
		new_test_ext().execute_with(|| {
			insert_vk(CircuitId::UNSHIELD, 1);
			activate(CircuitId::UNSHIELD, 1);
			let ok = <Pallet<Test> as ZkVerifierPort>::verify_unshield_proof(
				&proof(),
				&merkle_root(),
				&nullifier(),
				1000,
				&[0xFFu8; 32],
				0,
				50,
				None,
			)
			.unwrap();
			assert!(ok);
		});
	}

	#[test]
	fn unshield_explicit_version_overrides_active() {
		new_test_ext().execute_with(|| {
			insert_vk(CircuitId::UNSHIELD, 1);
			insert_vk(CircuitId::UNSHIELD, 2);
			activate(CircuitId::UNSHIELD, 1);
			let ok = <Pallet<Test> as ZkVerifierPort>::verify_unshield_proof(
				&proof(),
				&merkle_root(),
				&nullifier(),
				500,
				&[0u8; 32],
				2,
				10,
				Some(2),
			)
			.unwrap();
			assert!(ok);
		});
	}

	#[test]
	fn unshield_non_trivial_recipient_is_accepted() {
		// Verifies recipient BE→LE reversal does not panic for asymmetric data.
		new_test_ext().execute_with(|| {
			insert_vk(CircuitId::UNSHIELD, 1);
			activate(CircuitId::UNSHIELD, 1);
			let mut recipient = [0u8; 32];
			recipient[0] = 0x01; // MSB in AccountId32 big-endian
			recipient[31] = 0xFF;
			let ok = <Pallet<Test> as ZkVerifierPort>::verify_unshield_proof(
				&proof(),
				&merkle_root(),
				&nullifier(),
				500,
				&recipient,
				2,
				10,
				None,
			)
			.unwrap();
			assert!(ok);
		});
	}

	// ── verify_disclosure_proof ────────────────────────────────────────────────

	#[test]
	fn disclosure_empty_proof_is_rejected() {
		// EmptyProof fires after successful signals decode, before VK lookup.
		new_test_ext().execute_with(|| {
			assert_err!(
				<Pallet<Test> as ZkVerifierPort>::verify_disclosure_proof(
					&[],
					&valid_signals(),
					Some(1),
				),
				Error::<Test>::EmptyProof
			);
		});
	}

	#[test]
	fn disclosure_no_active_version_returns_circuit_not_found() {
		new_test_ext().execute_with(|| {
			assert_err!(
				<Pallet<Test> as ZkVerifierPort>::verify_disclosure_proof(
					&proof(),
					&valid_signals(),
					None,
				),
				Error::<Test>::CircuitNotFound
			);
		});
	}

	#[test]
	fn disclosure_missing_vk_returns_not_found() {
		new_test_ext().execute_with(|| {
			assert_err!(
				<Pallet<Test> as ZkVerifierPort>::verify_disclosure_proof(
					&proof(),
					&valid_signals(),
					Some(99),
				),
				Error::<Test>::VerificationKeyNotFound
			);
		});
	}

	#[test]
	fn disclosure_happy_path_returns_true() {
		new_test_ext().execute_with(|| {
			insert_vk(CircuitId::DISCLOSURE, 1);
			activate(CircuitId::DISCLOSURE, 1);
			let ok = <Pallet<Test> as ZkVerifierPort>::verify_disclosure_proof(
				&proof(),
				&valid_signals(),
				None,
			)
			.unwrap();
			assert!(ok);
		});
	}

	#[test]
	fn disclosure_explicit_version_overrides_active() {
		new_test_ext().execute_with(|| {
			insert_vk(CircuitId::DISCLOSURE, 1);
			insert_vk(CircuitId::DISCLOSURE, 2);
			activate(CircuitId::DISCLOSURE, 1);
			let ok = <Pallet<Test> as ZkVerifierPort>::verify_disclosure_proof(
				&proof(),
				&valid_signals(),
				Some(2),
			)
			.unwrap();
			assert!(ok);
		});
	}

	// ── batch_verify_disclosure_proofs ─────────────────────────────────────────

	#[test]
	fn batch_empty_proofs_returns_invalid_batch_size() {
		new_test_ext().execute_with(|| {
			assert_err!(
				<Pallet<Test> as ZkVerifierPort>::batch_verify_disclosure_proofs(&[], &[], None,),
				Error::<Test>::InvalidBatchSize
			);
		});
	}

	#[test]
	fn batch_over_limit_returns_invalid_batch_size() {
		new_test_ext().execute_with(|| {
			let proofs: alloc::vec::Vec<_> = (0..11).map(|_| proof()).collect();
			let signals: alloc::vec::Vec<_> = (0..11).map(|_| valid_signals()).collect();
			assert_err!(
				<Pallet<Test> as ZkVerifierPort>::batch_verify_disclosure_proofs(
					&proofs, &signals, None,
				),
				Error::<Test>::InvalidBatchSize
			);
		});
	}

	#[test]
	fn batch_length_mismatch_returns_error() {
		new_test_ext().execute_with(|| {
			let proofs = alloc::vec![proof(), proof()];
			let signals = alloc::vec![valid_signals()]; // 2 vs 1
			assert_err!(
				<Pallet<Test> as ZkVerifierPort>::batch_verify_disclosure_proofs(
					&proofs, &signals, None,
				),
				Error::<Test>::BatchLengthMismatch
			);
		});
	}

	#[test]
	fn batch_no_active_version_returns_circuit_not_found() {
		new_test_ext().execute_with(|| {
			assert_err!(
				<Pallet<Test> as ZkVerifierPort>::batch_verify_disclosure_proofs(
					&[proof()],
					&[valid_signals()],
					None,
				),
				Error::<Test>::CircuitNotFound
			);
		});
	}

	#[test]
	fn batch_missing_vk_returns_not_found() {
		new_test_ext().execute_with(|| {
			assert_err!(
				<Pallet<Test> as ZkVerifierPort>::batch_verify_disclosure_proofs(
					&[proof()],
					&[valid_signals()],
					Some(99),
				),
				Error::<Test>::VerificationKeyNotFound
			);
		});
	}

	#[test]
	fn batch_invalid_signals_length_returns_dispatch_error_other() {
		// decode_disclosure_signals runs during input collection, after VK is resolved.
		new_test_ext().execute_with(|| {
			insert_vk(CircuitId::DISCLOSURE, 1);
			activate(CircuitId::DISCLOSURE, 1);
			let err = <Pallet<Test> as ZkVerifierPort>::batch_verify_disclosure_proofs(
				&[proof()],
				&[vec![0u8; 50]],
				Some(1),
			)
			.unwrap_err();
			assert!(matches!(err, sp_runtime::DispatchError::Other(_)));
		});
	}

	#[test]
	fn batch_at_exact_limit_of_ten_is_accepted() {
		// Validates upper bound is inclusive (10 items is still valid).
		// batch_verify calls real Groth16 crypto (not mocked in port.rs),
		// so with bogus VK/proof data it returns BatchVerificationFailed —
		// confirming all guard conditions were passed.
		new_test_ext().execute_with(|| {
			insert_vk(CircuitId::DISCLOSURE, 1);
			activate(CircuitId::DISCLOSURE, 1);
			let proofs: alloc::vec::Vec<_> = (0..10).map(|_| proof()).collect();
			let signals: alloc::vec::Vec<_> = (0..10).map(|_| valid_signals()).collect();
			assert_err!(
				<Pallet<Test> as ZkVerifierPort>::batch_verify_disclosure_proofs(
					&proofs,
					&signals,
					Some(1),
				),
				Error::<Test>::BatchVerificationFailed
			);
		});
	}

	#[test]
	fn batch_with_valid_setup_reaches_crypto_and_fails_on_bogus_data() {
		// All storage guards pass; Groth16Verifier rejects the bogus VK/proof bytes.
		new_test_ext().execute_with(|| {
			insert_vk(CircuitId::DISCLOSURE, 1);
			activate(CircuitId::DISCLOSURE, 1);
			assert_err!(
				<Pallet<Test> as ZkVerifierPort>::batch_verify_disclosure_proofs(
					&[proof()],
					&[valid_signals()],
					Some(1),
				),
				Error::<Test>::BatchVerificationFailed
			);
		});
	}

	// ── verify_private_link_proof ──────────────────────────────────────────────

	#[test]
	fn private_link_empty_proof_is_rejected() {
		new_test_ext().execute_with(|| {
			assert_err!(
				<Pallet<Test> as ZkVerifierPort>::verify_private_link_proof(
					&[],
					&commitment(),
					&[0u8; 32],
					Some(1),
				),
				Error::<Test>::EmptyProof
			);
		});
	}

	#[test]
	fn private_link_no_active_version_returns_circuit_not_found() {
		new_test_ext().execute_with(|| {
			assert_err!(
				<Pallet<Test> as ZkVerifierPort>::verify_private_link_proof(
					&proof(),
					&commitment(),
					&[0u8; 32],
					None,
				),
				Error::<Test>::CircuitNotFound
			);
		});
	}

	#[test]
	fn private_link_missing_vk_returns_not_found() {
		new_test_ext().execute_with(|| {
			assert_err!(
				<Pallet<Test> as ZkVerifierPort>::verify_private_link_proof(
					&proof(),
					&commitment(),
					&[0u8; 32],
					Some(99),
				),
				Error::<Test>::VerificationKeyNotFound
			);
		});
	}

	#[test]
	fn private_link_happy_path_returns_true() {
		new_test_ext().execute_with(|| {
			insert_vk(CircuitId::PRIVATE_LINK, 1);
			activate(CircuitId::PRIVATE_LINK, 1);
			let ok = <Pallet<Test> as ZkVerifierPort>::verify_private_link_proof(
				&proof(),
				&commitment(),
				&[0xFFu8; 32],
				None,
			)
			.unwrap();
			assert!(ok);
		});
	}

	#[test]
	fn private_link_explicit_version_overrides_active() {
		new_test_ext().execute_with(|| {
			insert_vk(CircuitId::PRIVATE_LINK, 1);
			insert_vk(CircuitId::PRIVATE_LINK, 2);
			activate(CircuitId::PRIVATE_LINK, 1);
			let ok = <Pallet<Test> as ZkVerifierPort>::verify_private_link_proof(
				&proof(),
				&commitment(),
				&[0u8; 32],
				Some(2),
			)
			.unwrap();
			assert!(ok);
		});
	}
}
