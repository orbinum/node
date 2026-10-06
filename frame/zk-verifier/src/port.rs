//! [`ZkVerifierPort`] — public interface for cross-pallet ZK proof verification.
//!
//! Other pallets (e.g. `pallet-shielded-pool`) depend only on this trait, never
//! on the concrete pallet internals. They describe a spend as a statement of
//! domain values; turning it into field elements is [`crate::encoding`]'s job,
//! and the cryptographic work is [`crate::verifier`]'s.

use crate::{
	Pallet, encoding,
	pallet::{Config, Error, RetiredVersions, VerificationKeys},
	types::CircuitId,
	verifier,
};
use alloc::vec::Vec;

// ─── Statements ───────────────────────────────────────────────────────────────

/// What a private-transfer proof attests to, as the pallet submits it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TransferStatement {
	pub merkle_root: [u8; 32],
	/// One per input note.
	pub nullifiers: Vec<[u8; 32]>,
	/// One per output note, in the order their memos are submitted.
	pub commitments: Vec<[u8; 32]>,
	pub asset_id: u32,
	pub fee: u128,
	/// `blake2_256` of the SCALE-encoded output memos. Bound by memo-bound versions.
	pub memo_digest: [u8; 32],
}

/// What an unshield proof attests to, as the pallet submits it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct UnshieldStatement {
	pub merkle_root: [u8; 32],
	pub nullifier: [u8; 32],
	pub amount: u128,
	/// The recipient account's raw 32 bytes. See [`encoding::encode_unshield`].
	pub recipient: [u8; 32],
	pub asset_id: u32,
	pub fee: u128,
	/// Zero for a total unshield.
	pub change_commitment: [u8; 32],
	/// `blake2_256` of the SCALE-encoded `[change_memo]`. Bound by memo-bound versions.
	pub memo_digest: [u8; 32],
}

/// What a shield proof attests to: the inserted commitment opens to the
/// deposited value and asset.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ShieldStatement {
	pub commitment: [u8; 32],
	pub value: u128,
	pub asset_id: u32,
}

// ─── Trait ────────────────────────────────────────────────────────────────────

/// Cross-pallet interface for zero-knowledge proof verification.
///
/// `version` selects the verifying key; `None` means the circuit's active one.
/// `Ok(false)` is an invalid proof, `Err` a request that cannot be checked.
pub trait ZkVerifierPort {
	/// Verify a private transfer proof (2-in / 2-out).
	fn verify_transfer_proof(
		proof: &[u8],
		statement: &TransferStatement,
		version: Option<u32>,
	) -> Result<bool, sp_runtime::DispatchError>;

	/// Verify an unshield (pool withdrawal) proof.
	fn verify_unshield_proof(
		proof: &[u8],
		statement: &UnshieldStatement,
		version: Option<u32>,
	) -> Result<bool, sp_runtime::DispatchError>;

	/// Verify a shield (pool deposit) proof.
	fn verify_shield_proof(
		proof: &[u8],
		statement: &ShieldStatement,
		version: Option<u32>,
	) -> Result<bool, sp_runtime::DispatchError>;

	/// Whether `version` is registered for `circuit_id` and not retired.
	fn is_supported_version(circuit_id: u32, version: u32) -> bool;

	/// Weight of one `verify_*_proof` call: key read, preparation and the
	/// pairing. A caller that verifies a proof must add it to its own weight.
	fn verification_weight() -> frame_support::weights::Weight;
}

// ─── Implementation ───────────────────────────────────────────────────────────

/// Public inputs of the largest spend layout: a memo-bound transfer or unshield.
const MAX_SPEND_PUBLIC_INPUTS: u32 = {
	use orbinum_zk_verifier::{MEMO_HASH_INPUTS, TRANSFER_PUBLIC_INPUTS, UNSHIELD_PUBLIC_INPUTS};
	let base = if TRANSFER_PUBLIC_INPUTS > UNSHIELD_PUBLIC_INPUTS {
		TRANSFER_PUBLIC_INPUTS
	} else {
		UNSHIELD_PUBLIC_INPUTS
	};
	(base + MEMO_HASH_INPUTS) as u32
};

impl<T: Config> ZkVerifierPort for Pallet<T> {
	fn verify_transfer_proof(
		proof: &[u8],
		statement: &TransferStatement,
		version: Option<u32>,
	) -> Result<bool, sp_runtime::DispatchError> {
		// One nullifier per input and one commitment per output, and the circuit
		// has as many outputs as inputs.
		frame_support::ensure!(
			statement.nullifiers.len() == statement.commitments.len(),
			Error::<T>::InvalidPublicInputs
		);
		verifier::verify_statement::<T>(CircuitId::TRANSFER, version, proof, |layout| {
			encoding::encode_transfer(statement, layout)
		})
		.map(|(ok, _)| ok)
	}

	fn verify_unshield_proof(
		proof: &[u8],
		statement: &UnshieldStatement,
		version: Option<u32>,
	) -> Result<bool, sp_runtime::DispatchError> {
		verifier::verify_statement::<T>(CircuitId::UNSHIELD, version, proof, |layout| {
			encoding::encode_unshield(statement, layout)
		})
		.map(|(ok, _)| ok)
	}

	fn verify_shield_proof(
		proof: &[u8],
		statement: &ShieldStatement,
		version: Option<u32>,
	) -> Result<bool, sp_runtime::DispatchError> {
		// Shield has a single layout; a key of another arity fails the length check.
		verifier::verify_statement::<T>(CircuitId::SHIELD, version, proof, |_| {
			encoding::encode_shield(statement)
		})
		.map(|(ok, _)| ok)
	}

	fn is_supported_version(circuit_id: u32, version: u32) -> bool {
		let cid = CircuitId(circuit_id);
		VerificationKeys::<T>::contains_key(cid, version)
			&& !RetiredVersions::<T>::contains_key(cid, version)
	}

	fn verification_weight() -> frame_support::weights::Weight {
		use crate::weights::WeightInfo;
		T::WeightInfo::verify_proof(MAX_SPEND_PUBLIC_INPUTS)
	}
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
	use super::*;
	use crate::mock::{Test, activate, insert_vk, new_test_ext};
	use frame_support::assert_err;
	use orbinum_zk_verifier::{
		MEMO_HASH_INPUTS, SHIELD_PUBLIC_INPUTS, TRANSFER_PUBLIC_INPUTS, UNSHIELD_PUBLIC_INPUTS,
	};

	// ── Helpers ───────────────────────────────────────────────────────────────

	const NULLIFIERS: [[u8; 32]; 2] = [[0xAA; 32], [0xBB; 32]];
	const COMMITMENTS: [[u8; 32]; 2] = [[0xCC; 32], [0xDD; 32]];

	fn proof() -> alloc::vec::Vec<u8> {
		vec![0x01u8; 128]
	}

	fn transfer() -> TransferStatement {
		TransferStatement {
			merkle_root: [0x03; 32],
			nullifiers: NULLIFIERS.to_vec(),
			commitments: COMMITMENTS.to_vec(),
			asset_id: 1,
			fee: 500,
			memo_digest: [0x04; 32],
		}
	}

	fn unshield() -> UnshieldStatement {
		UnshieldStatement {
			merkle_root: [0x03; 32],
			nullifier: [0x02; 32],
			amount: 1000,
			recipient: [0xFF; 32],
			asset_id: 0,
			fee: 50,
			change_commitment: [0; 32],
			memo_digest: [0x04; 32],
		}
	}

	fn verify_transfer(
		s: &TransferStatement,
		version: Option<u32>,
	) -> Result<bool, sp_runtime::DispatchError> {
		<Pallet<Test> as ZkVerifierPort>::verify_transfer_proof(&proof(), s, version)
	}

	fn verify_unshield(
		s: &UnshieldStatement,
		version: Option<u32>,
	) -> Result<bool, sp_runtime::DispatchError> {
		<Pallet<Test> as ZkVerifierPort>::verify_unshield_proof(&proof(), s, version)
	}

	fn shield() -> ShieldStatement {
		ShieldStatement {
			commitment: [0x05; 32],
			value: 1000,
			asset_id: 0,
		}
	}

	fn verify_shield(
		s: &ShieldStatement,
		version: Option<u32>,
	) -> Result<bool, sp_runtime::DispatchError> {
		<Pallet<Test> as ZkVerifierPort>::verify_shield_proof(&proof(), s, version)
	}

	// ── verify_transfer_proof ─────────────────────────────────────────────────

	#[test]
	fn transfer_empty_proof_is_rejected() {
		new_test_ext().execute_with(|| {
			assert_err!(
				<Pallet<Test> as ZkVerifierPort>::verify_transfer_proof(&[], &transfer(), Some(1)),
				Error::<Test>::EmptyProof
			);
		});
	}

	#[test]
	fn transfer_without_an_active_version_is_circuit_not_found() {
		new_test_ext().execute_with(|| {
			assert_err!(
				verify_transfer(&transfer(), None),
				Error::<Test>::CircuitNotFound
			);
		});
	}

	#[test]
	fn transfer_unknown_explicit_version_is_unsupported() {
		new_test_ext().execute_with(|| {
			assert_err!(
				verify_transfer(&transfer(), Some(99)),
				Error::<Test>::UnsupportedCircuitVersion
			);
		});
	}

	#[test]
	fn transfer_verifies_under_the_base_and_the_memo_bound_key() {
		new_test_ext().execute_with(|| {
			insert_vk(CircuitId::TRANSFER, 1, TRANSFER_PUBLIC_INPUTS);
			insert_vk(
				CircuitId::TRANSFER,
				2,
				TRANSFER_PUBLIC_INPUTS + MEMO_HASH_INPUTS,
			);
			activate(CircuitId::TRANSFER, 1);
			assert_eq!(verify_transfer(&transfer(), None), Ok(true));
			assert_eq!(verify_transfer(&transfer(), Some(2)), Ok(true));
		});
	}

	#[test]
	fn transfer_with_one_input_does_not_fit_the_two_input_key() {
		new_test_ext().execute_with(|| {
			insert_vk(CircuitId::TRANSFER, 1, TRANSFER_PUBLIC_INPUTS);
			activate(CircuitId::TRANSFER, 1);
			let s = TransferStatement {
				nullifiers: NULLIFIERS[..1].to_vec(),
				commitments: COMMITMENTS[..1].to_vec(),
				..transfer()
			};
			assert_eq!(verify_transfer(&s, None), Ok(false));
		});
	}

	#[test]
	fn transfer_nullifier_commitment_count_mismatch_is_rejected() {
		new_test_ext().execute_with(|| {
			let s = TransferStatement {
				nullifiers: NULLIFIERS[..1].to_vec(),
				..transfer()
			};
			assert_err!(
				verify_transfer(&s, Some(1)),
				Error::<Test>::InvalidPublicInputs
			);
		});
	}

	#[test]
	fn a_retired_version_is_unsupported_and_does_not_fall_back() {
		new_test_ext().execute_with(|| {
			insert_vk(CircuitId::TRANSFER, 1, TRANSFER_PUBLIC_INPUTS);
			insert_vk(CircuitId::TRANSFER, 2, TRANSFER_PUBLIC_INPUTS);
			activate(CircuitId::TRANSFER, 1);
			RetiredVersions::<Test>::insert(CircuitId::TRANSFER, 2, ());

			assert!(!<Pallet<Test> as ZkVerifierPort>::is_supported_version(
				CircuitId::TRANSFER.0,
				2
			));
			assert_err!(
				verify_transfer(&transfer(), Some(2)),
				Error::<Test>::UnsupportedCircuitVersion
			);
		});
	}

	// ── verify_unshield_proof ─────────────────────────────────────────────────

	#[test]
	fn unshield_empty_proof_is_rejected() {
		new_test_ext().execute_with(|| {
			assert_err!(
				<Pallet<Test> as ZkVerifierPort>::verify_unshield_proof(&[], &unshield(), Some(1)),
				Error::<Test>::EmptyProof
			);
		});
	}

	#[test]
	fn unshield_without_an_active_version_is_circuit_not_found() {
		new_test_ext().execute_with(|| {
			assert_err!(
				verify_unshield(&unshield(), None),
				Error::<Test>::CircuitNotFound
			);
		});
	}

	#[test]
	fn unshield_unknown_explicit_version_is_unsupported() {
		new_test_ext().execute_with(|| {
			assert_err!(
				verify_unshield(&unshield(), Some(99)),
				Error::<Test>::UnsupportedCircuitVersion
			);
		});
	}

	#[test]
	fn unshield_verifies_under_the_base_and_the_memo_bound_key() {
		new_test_ext().execute_with(|| {
			insert_vk(CircuitId::UNSHIELD, 1, UNSHIELD_PUBLIC_INPUTS);
			insert_vk(
				CircuitId::UNSHIELD,
				2,
				UNSHIELD_PUBLIC_INPUTS + MEMO_HASH_INPUTS,
			);
			activate(CircuitId::UNSHIELD, 1);
			assert_eq!(verify_unshield(&unshield(), None), Ok(true));
			assert_eq!(verify_unshield(&unshield(), Some(2)), Ok(true));
		});
	}

	#[test]
	fn unshield_under_a_key_of_foreign_arity_fails() {
		new_test_ext().execute_with(|| {
			insert_vk(CircuitId::UNSHIELD, 1, UNSHIELD_PUBLIC_INPUTS + 2);
			activate(CircuitId::UNSHIELD, 1);
			assert_eq!(verify_unshield(&unshield(), None), Ok(false));
		});
	}

	// ── verify_shield_proof ───────────────────────────────────────────────────

	#[test]
	fn shield_empty_proof_is_rejected() {
		new_test_ext().execute_with(|| {
			assert_err!(
				<Pallet<Test> as ZkVerifierPort>::verify_shield_proof(&[], &shield(), Some(1)),
				Error::<Test>::EmptyProof
			);
		});
	}

	#[test]
	fn shield_without_an_active_version_is_circuit_not_found() {
		new_test_ext().execute_with(|| {
			assert_err!(
				verify_shield(&shield(), None),
				Error::<Test>::CircuitNotFound
			);
		});
	}

	#[test]
	fn shield_verifies_under_its_three_input_key() {
		new_test_ext().execute_with(|| {
			insert_vk(CircuitId::SHIELD, 1, SHIELD_PUBLIC_INPUTS);
			activate(CircuitId::SHIELD, 1);
			assert_eq!(verify_shield(&shield(), None), Ok(true));
		});
	}

	#[test]
	fn shield_under_a_key_of_foreign_arity_fails() {
		new_test_ext().execute_with(|| {
			insert_vk(
				CircuitId::SHIELD,
				1,
				SHIELD_PUBLIC_INPUTS + MEMO_HASH_INPUTS,
			);
			activate(CircuitId::SHIELD, 1);
			assert_eq!(verify_shield(&shield(), None), Ok(false));
		});
	}

	#[test]
	fn shield_under_a_retired_or_unregistered_version_is_unsupported() {
		new_test_ext().execute_with(|| {
			insert_vk(CircuitId::SHIELD, 1, SHIELD_PUBLIC_INPUTS);
			insert_vk(CircuitId::SHIELD, 2, SHIELD_PUBLIC_INPUTS);
			activate(CircuitId::SHIELD, 2);
			RetiredVersions::<Test>::insert(CircuitId::SHIELD, 1, ());

			// A retired version does not fall back to the active one.
			assert_err!(
				verify_shield(&shield(), Some(1)),
				Error::<Test>::UnsupportedCircuitVersion
			);
			assert_err!(
				verify_shield(&shield(), Some(3)),
				Error::<Test>::UnsupportedCircuitVersion
			);
			assert_eq!(verify_shield(&shield(), Some(2)), Ok(true));
		});
	}

	// ── is_supported_version ──────────────────────────────────────────────────

	#[test]
	fn is_supported_version_reflects_registered_keys() {
		new_test_ext().execute_with(|| {
			let supported =
				|id: CircuitId, v| <Pallet<Test> as ZkVerifierPort>::is_supported_version(id.0, v);
			assert!(!supported(CircuitId::TRANSFER, 1));
			insert_vk(CircuitId::TRANSFER, 1, TRANSFER_PUBLIC_INPUTS);
			assert!(supported(CircuitId::TRANSFER, 1));
			assert!(!supported(CircuitId::TRANSFER, 2));
			assert!(!supported(CircuitId::UNSHIELD, 1));
		});
	}

	#[test]
	fn verification_weight_covers_the_largest_spend_layout() {
		use crate::weights::WeightInfo;
		assert_eq!(MAX_SPEND_PUBLIC_INPUTS, 8);
		assert_eq!(
			<Pallet<Test> as ZkVerifierPort>::verification_weight(),
			<Test as crate::Config>::WeightInfo::verify_proof(MAX_SPEND_PUBLIC_INPUTS)
		);
	}
}
