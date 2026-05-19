//! [`ZkVerifierPort`] — public interface for cross-pallet ZK proof verification.
//!
//! Other pallets (e.g. `pallet-shielded-pool`, `pallet-account-mapping`) depend
//! only on this trait, never on the concrete pallet internals.
//!
//! Each method delegates public-input encoding to [`crate::encoding`] and the
//! cryptographic work to [`crate::verifier::verify`].

use crate::{
	Pallet, encoding,
	pallet::{Config, Error},
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
		change_commitment: &[u8; 32],
		version: Option<u32>,
	) -> Result<bool, sp_runtime::DispatchError>;

	/// Verify a value proof (76-byte layout: commitment | value | asset_id | owner_hash).
	/// Used for gasless fee claiming.
	fn verify_value_proof(
		proof: &[u8],
		public_signals: &[u8],
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
		// The 2-in/2-out circuit encodes one nullifier per input note and one
		// commitment per output note. A mismatch produces garbage public inputs
		// that pass in benchmark/test mode (do_verify returns true unconditionally)
		// but would represent a structurally invalid proof in production.
		frame_support::ensure!(
			nullifiers.len() == commitments.len(),
			Error::<T>::InvalidPublicInputs
		);
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
		change_commitment: &[u8; 32],
		version: Option<u32>,
	) -> Result<bool, sp_runtime::DispatchError> {
		let raw = encoding::encode_unshield(
			merkle_root,
			nullifier,
			amount,
			recipient,
			asset_id,
			fee,
			change_commitment,
		);
		verifier::verify::<T>(CircuitId::UNSHIELD, version, proof, raw).map(|(ok, _)| ok)
	}

	fn verify_value_proof(
		proof: &[u8],
		public_signals: &[u8],
		version: Option<u32>,
	) -> Result<bool, sp_runtime::DispatchError> {
		if public_signals.len() != 76 {
			return Err(sp_runtime::DispatchError::Other(
				"Invalid value proof signals length (expected 76 bytes)",
			));
		}
		let signals: &[u8; 76] = public_signals
			.try_into()
			.map_err(|_| sp_runtime::DispatchError::Other("value proof signals slice error"))?;
		let raw = encoding::encode_value_proof(signals);
		verifier::verify::<T>(CircuitId::VALUE_PROOF, version, proof, raw).map(|(ok, _)| ok)
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

	#[test]
	fn transfer_nullifier_commitment_count_mismatch_is_rejected() {
		// The 2-in/2-out circuit requires an equal number of nullifiers and
		// commitments. A mismatch produces structurally invalid public inputs that
		// in benchmark/test mode would still "verify" because do_verify returns true
		// unconditionally. The guard in verify_transfer_proof catches this before
		// reaching the verifier.
		new_test_ext().execute_with(|| {
			assert_err!(
				<Pallet<Test> as ZkVerifierPort>::verify_transfer_proof(
					&proof(),
					&merkle_root(),
					&[[0xAAu8; 32]],               // 1 nullifier
					&[[0xBBu8; 32], [0xCCu8; 32]], // 2 commitments
					0,
					0,
					Some(1),
				),
				Error::<Test>::InvalidPublicInputs
			);
		});
	}

	#[test]
	fn transfer_empty_nullifiers_with_empty_commitments_is_accepted_by_guard() {
		// 0 nullifiers == 0 commitments satisfies the count guard. EmptyPublicInputs
		// fires next inside verifier::verify (merkle_root is the only remaining
		// element but that still gives 1 input after encode_transfer, so actually
		// EmptyProof doesn't fire — but CircuitNotFound does if no VK). Let's just
		// confirm the count guard itself doesn't reject the 0==0 case.
		new_test_ext().execute_with(|| {
			// No VK registered → CircuitNotFound, not InvalidPublicInputs.
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
					&[0u8; 32],
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
					&[0u8; 32],
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
					&[0u8; 32],
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
				&[0u8; 32],
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
				&[0u8; 32],
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
				&[0u8; 32],
				None,
			)
			.unwrap();
			assert!(ok);
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
