//! Disclosure Validation Service
//!
//! Validation logic for selective disclosure proofs: ZK proof verification,
//! public signals validation, access control and rate limiting.

use crate::{
	pallet::{
		AuditPolicies, CommitmentMemos, Config, DisclosureRequests, Error, LastDisclosureTimestamp,
	},
	types::Auditor,
	types::Commitment,
};
use frame_support::{ensure, pallet_prelude::*};
use frame_system;
use pallet_zk_verifier::ZkVerifierPort;
use sp_runtime::traits::Saturating;

pub struct DisclosureValidationService;

impl DisclosureValidationService {
	/// Verify disclosure proof using ZK verifier (internal validation)
	pub fn verify_proof_internal<T: Config>(
		proof_bytes: &[u8],
		public_signals: &[u8],
	) -> DispatchResult {
		ensure!(proof_bytes.len() == 128, Error::<T>::InvalidProof);
		ensure!(public_signals.len() == 76, Error::<T>::InvalidPublicSignals);

		let is_valid = T::ZkVerifier::verify_disclosure_proof(proof_bytes, public_signals, None)?;
		ensure!(is_valid, Error::<T>::InvalidProof);

		Ok(())
	}

	/// Validate public signals consistency
	pub fn validate_public_signals<T: Config>(
		commitment: &Commitment,
		public_signals: &[u8],
	) -> DispatchResult {
		ensure!(public_signals.len() == 76, Error::<T>::InvalidPublicSignals);

		let commitment_from_signals = &public_signals[0..32];
		let revealed_value_bytes = &public_signals[32..40];
		let revealed_asset_id_bytes = &public_signals[40..44];
		let _revealed_owner_hash = &public_signals[44..76];

		ensure!(
			commitment_from_signals == commitment.0,
			Error::<T>::InvalidPublicSignals
		);

		let _revealed_value = u64::from_le_bytes(
			revealed_value_bytes
				.try_into()
				.map_err(|_| Error::<T>::InvalidPublicSignals)?,
		);

		let _revealed_asset_id = u32::from_le_bytes(
			revealed_asset_id_bytes
				.try_into()
				.map_err(|_| Error::<T>::InvalidPublicSignals)?,
		);

		Ok(())
	}

	/// Validate disclosure access control and rate limiting
	///
	/// # SAFETY
	/// Commitment ownership is implicitly enforced by the ZK proof verified in
	/// `verify_disclosure_proof`: the Groth16 circuit binds the proof to the
	/// commitment and the caller's viewing key.
	pub fn validate_disclosure_access<T: Config>(
		who: &<T as frame_system::Config>::AccountId,
		commitment: &Commitment,
		auditor: Option<&<T as frame_system::Config>::AccountId>,
	) -> DispatchResult {
		if let Some(policy) = AuditPolicies::<T>::get(who) {
			if let Some(valid_until) = policy.valid_until {
				let current_block = frame_system::Pallet::<T>::block_number();
				ensure!(current_block <= valid_until, Error::<T>::AuditPolicyExpired);
			}

			if let Some(auditor_id) = auditor {
				let is_authorized = policy
					.auditors
					.iter()
					.any(|a| matches!(a, Auditor::Account(acc) if acc == auditor_id));
				ensure!(is_authorized, Error::<T>::UnauthorizedAuditor);

				let request = DisclosureRequests::<T>::get(who, auditor_id)
					.ok_or(Error::<T>::DisclosureRequestNotFound)?;
				let current_block = frame_system::Pallet::<T>::block_number();
				ensure!(
					current_block <= request.expires_at,
					Error::<T>::DisclosureRequestExpired
				);
			}

			if let Some(max_frequency) = policy.max_frequency {
				let current_block = frame_system::Pallet::<T>::block_number();

				if let Some(last_disclosure) = LastDisclosureTimestamp::<T>::get(who, commitment) {
					let blocks_since_last = current_block.saturating_sub(last_disclosure);
					ensure!(
						blocks_since_last >= max_frequency,
						Error::<T>::DisclosureFrequencyExceeded
					);
				}
			}
		} else {
			ensure!(auditor.is_none(), Error::<T>::UnauthorizedAuditor);
		}

		Ok(())
	}

	/// Verify disclosure proof (cryptographic verification with full context)
	pub fn verify_disclosure_proof<T: Config>(
		proof: &[u8],
		public_signals: &[u8],
		commitment: &Commitment,
	) -> Result<(), DispatchError> {
		ensure!(proof.len() == 128, Error::<T>::InvalidDisclosureRecord);
		ensure!(
			public_signals.len() == 76,
			Error::<T>::InvalidDisclosureRecord
		);

		ensure!(
			CommitmentMemos::<T>::contains_key(commitment),
			Error::<T>::CommitmentNotFound
		);

		ensure!(
			public_signals[0..32] == commitment.0,
			Error::<T>::InvalidDisclosureRecord
		);

		let is_valid = T::ZkVerifier::verify_disclosure_proof(proof, public_signals, None)?;

		ensure!(is_valid, Error::<T>::InvalidDisclosureRecord);

		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::{
		mock::{Test, new_test_ext},
		operations::disclosure::policy,
		pallet::{DisclosureRequests, LastDisclosureTimestamp},
		storage::CommitmentRepository,
		types::{Auditor, Commitment, DisclosureCondition, DisclosureRequest},
	};
	use frame_support::{assert_noop, assert_ok};

	// ── helpers ──────────────────────────────────────────────────────────────

	fn valid_proof() -> [u8; 128] {
		[0x01u8; 128]
	}

	/// 76-byte public signals where signals[0..32] == commitment bytes.
	fn valid_signals(commitment: &Commitment) -> [u8; 76] {
		let mut buf = [0u8; 76];
		buf[0..32].copy_from_slice(&commitment.0);
		// non-zero value so parse gives Some
		buf[32..40].copy_from_slice(&100u64.to_le_bytes());
		buf[40..44].copy_from_slice(&1u32.to_le_bytes());
		buf
	}

	fn commitment(seed: u8) -> Commitment {
		Commitment::new([seed; 32])
	}

	fn set_policy_simple(owner: u64, auditor: u64) {
		let auditors = BoundedVec::try_from(vec![Auditor::Account(auditor)]).unwrap();
		let conditions: BoundedVec<DisclosureCondition<u128, u64>, ConstU32<10>> =
			BoundedVec::default();
		policy::set_audit_policy::<Test>(&owner, auditors, conditions, None, None).unwrap();
	}

	fn store_request(target: u64, auditor: u64, expires_at: u64) {
		use frame_support::BoundedVec;
		let req = DisclosureRequest {
			auditor,
			target,
			requested_at: 1u64,
			expires_at,
			reason: BoundedVec::default(),
		};
		DisclosureRequests::<Test>::insert(target, auditor, req);
	}

	// ── verify_proof_internal ────────────────────────────────────────────────

	#[test]
	fn verify_proof_internal_valid_works() {
		new_test_ext().execute_with(|| {
			let c = commitment(1);
			assert_ok!(DisclosureValidationService::verify_proof_internal::<Test>(
				&valid_proof(),
				&valid_signals(&c),
			));
		});
	}

	#[test]
	fn verify_proof_internal_wrong_proof_len_fails() {
		new_test_ext().execute_with(|| {
			let c = commitment(1);
			assert_noop!(
				DisclosureValidationService::verify_proof_internal::<Test>(
					&[0x01u8; 64],
					&valid_signals(&c),
				),
				crate::pallet::Error::<Test>::InvalidProof
			);
		});
	}

	#[test]
	fn verify_proof_internal_wrong_signals_len_fails() {
		new_test_ext().execute_with(|| {
			assert_noop!(
				DisclosureValidationService::verify_proof_internal::<Test>(
					&valid_proof(),
					&[0x01u8; 32],
				),
				crate::pallet::Error::<Test>::InvalidPublicSignals
			);
		});
	}

	#[test]
	fn verify_proof_internal_empty_proof_fails() {
		new_test_ext().execute_with(|| {
			let c = commitment(1);
			// MockZkVerifier returns Err for empty proof
			assert!(
				DisclosureValidationService::verify_proof_internal::<Test>(
					&[],
					&valid_signals(&c),
				)
				.is_err()
			);
		});
	}

	// ── validate_public_signals ──────────────────────────────────────────────

	#[test]
	fn validate_public_signals_valid_works() {
		new_test_ext().execute_with(|| {
			let c = commitment(0x42);
			assert_ok!(
				DisclosureValidationService::validate_public_signals::<Test>(
					&c,
					&valid_signals(&c),
				)
			);
		});
	}

	#[test]
	fn validate_public_signals_wrong_len_fails() {
		new_test_ext().execute_with(|| {
			let c = commitment(1);
			assert_noop!(
				DisclosureValidationService::validate_public_signals::<Test>(&c, &[0u8; 40]),
				crate::pallet::Error::<Test>::InvalidPublicSignals
			);
		});
	}

	#[test]
	fn validate_public_signals_commitment_mismatch_fails() {
		new_test_ext().execute_with(|| {
			let c = commitment(0xAA);
			let signals = valid_signals(&commitment(0xBB)); // different seed
			assert_noop!(
				DisclosureValidationService::validate_public_signals::<Test>(&c, &signals),
				crate::pallet::Error::<Test>::InvalidPublicSignals
			);
		});
	}

	// ── validate_disclosure_access ───────────────────────────────────────────

	#[test]
	fn access_no_policy_no_auditor_works() {
		new_test_ext().execute_with(|| {
			let c = commitment(1);
			// No policy set → auditor must be None (self-disclosure is allowed)
			assert_ok!(DisclosureValidationService::validate_disclosure_access::<
				Test,
			>(&1u64, &c, None,));
		});
	}

	#[test]
	fn access_no_policy_with_auditor_fails() {
		new_test_ext().execute_with(|| {
			let c = commitment(1);
			assert_noop!(
				DisclosureValidationService::validate_disclosure_access::<Test>(
					&1u64,
					&c,
					Some(&2u64),
				),
				crate::pallet::Error::<Test>::UnauthorizedAuditor
			);
		});
	}

	#[test]
	fn access_policy_expired_fails() {
		new_test_ext().execute_with(|| {
			// Policy with valid_until = 0 (already past block 1)
			let owner: u64 = 1;
			let auditors = BoundedVec::try_from(vec![Auditor::Account(2u64)]).unwrap();
			let conditions: BoundedVec<DisclosureCondition<u128, u64>, ConstU32<10>> =
				BoundedVec::default();
			policy::set_audit_policy::<Test>(&owner, auditors, conditions, None, Some(0u64))
				.unwrap();

			let c = commitment(1);
			assert_noop!(
				DisclosureValidationService::validate_disclosure_access::<Test>(&owner, &c, None,),
				crate::pallet::Error::<Test>::AuditPolicyExpired
			);
		});
	}

	#[test]
	fn access_unauthorized_auditor_fails() {
		new_test_ext().execute_with(|| {
			let owner: u64 = 1;
			// Policy only authorizes auditor 2
			set_policy_simple(owner, 2u64);
			let c = commitment(1);

			assert_noop!(
				DisclosureValidationService::validate_disclosure_access::<Test>(
					&owner,
					&c,
					Some(&3u64), // auditor 3 not in policy
				),
				crate::pallet::Error::<Test>::UnauthorizedAuditor
			);
		});
	}

	#[test]
	fn access_request_not_found_fails() {
		new_test_ext().execute_with(|| {
			let owner: u64 = 1;
			set_policy_simple(owner, 2u64);
			let c = commitment(1);
			// No DisclosureRequest stored → DisclosureRequestNotFound
			assert_noop!(
				DisclosureValidationService::validate_disclosure_access::<Test>(
					&owner,
					&c,
					Some(&2u64),
				),
				crate::pallet::Error::<Test>::DisclosureRequestNotFound
			);
		});
	}

	#[test]
	fn access_request_expired_fails() {
		new_test_ext().execute_with(|| {
			let owner: u64 = 1;
			set_policy_simple(owner, 2u64);
			// Request expired at block 0 (current block is 1)
			store_request(owner, 2u64, 0u64);
			let c = commitment(1);

			assert_noop!(
				DisclosureValidationService::validate_disclosure_access::<Test>(
					&owner,
					&c,
					Some(&2u64),
				),
				crate::pallet::Error::<Test>::DisclosureRequestExpired
			);
		});
	}

	#[test]
	fn access_valid_request_with_auditor_works() {
		new_test_ext().execute_with(|| {
			let owner: u64 = 1;
			set_policy_simple(owner, 2u64);
			store_request(owner, 2u64, 9999u64);
			let c = commitment(1);

			assert_ok!(DisclosureValidationService::validate_disclosure_access::<
				Test,
			>(&owner, &c, Some(&2u64),));
		});
	}

	#[test]
	fn access_frequency_exceeded_fails() {
		new_test_ext().execute_with(|| {
			let owner: u64 = 1;
			let auditors = BoundedVec::try_from(vec![Auditor::Account(2u64)]).unwrap();
			let conditions: BoundedVec<DisclosureCondition<u128, u64>, ConstU32<10>> =
				BoundedVec::default();
			// max_frequency = 100 blocks
			policy::set_audit_policy::<Test>(&owner, auditors, conditions, Some(100u64), None)
				.unwrap();

			let c = commitment(1);
			// Simulate last disclosure at block 1 (same as current)
			LastDisclosureTimestamp::<Test>::insert(owner, c, 1u64);

			// blocks_since_last = 1 - 1 = 0 < 100 → should fail
			assert_noop!(
				DisclosureValidationService::validate_disclosure_access::<Test>(&owner, &c, None,),
				crate::pallet::Error::<Test>::DisclosureFrequencyExceeded
			);
		});
	}

	#[test]
	fn access_frequency_ok_after_enough_blocks() {
		new_test_ext().execute_with(|| {
			let owner: u64 = 1;
			let auditors = BoundedVec::try_from(vec![Auditor::Account(2u64)]).unwrap();
			let conditions: BoundedVec<DisclosureCondition<u128, u64>, ConstU32<10>> =
				BoundedVec::default();
			policy::set_audit_policy::<Test>(&owner, auditors, conditions, Some(5u64), None)
				.unwrap();

			let c = commitment(1);
			// Last disclosure 10 blocks ago — 10 >= 5 → allowed
			LastDisclosureTimestamp::<Test>::insert(owner, c, 0u64);
			frame_system::Pallet::<Test>::set_block_number(10);

			assert_ok!(DisclosureValidationService::validate_disclosure_access::<
				Test,
			>(&owner, &c, None,));
		});
	}

	// ── verify_disclosure_proof ──────────────────────────────────────────────

	#[test]
	fn verify_disclosure_proof_works() {
		new_test_ext().execute_with(|| {
			let c = commitment(0xCC);
			// Register commitment memo so the lookup passes
			CommitmentRepository::store_memo::<Test>(c, crate::types::EncryptedMemo::default());

			assert_ok!(
				DisclosureValidationService::verify_disclosure_proof::<Test>(
					&valid_proof(),
					&valid_signals(&c),
					&c,
				)
			);
		});
	}

	#[test]
	fn verify_disclosure_proof_commitment_not_found_fails() {
		new_test_ext().execute_with(|| {
			let c = commitment(0xDD);
			// No memo stored → CommitmentNotFound
			assert_noop!(
				DisclosureValidationService::verify_disclosure_proof::<Test>(
					&valid_proof(),
					&valid_signals(&c),
					&c,
				),
				crate::pallet::Error::<Test>::CommitmentNotFound
			);
		});
	}

	#[test]
	fn verify_disclosure_proof_wrong_commitment_in_signals_fails() {
		new_test_ext().execute_with(|| {
			let c = commitment(0xEE);
			CommitmentRepository::store_memo::<Test>(c, crate::types::EncryptedMemo::default());

			// Signals encode a different commitment
			let signals = valid_signals(&commitment(0xFF));
			assert_noop!(
				DisclosureValidationService::verify_disclosure_proof::<Test>(
					&valid_proof(),
					&signals,
					&c,
				),
				crate::pallet::Error::<Test>::InvalidDisclosureRecord
			);
		});
	}

	#[test]
	fn verify_disclosure_proof_wrong_proof_len_fails() {
		new_test_ext().execute_with(|| {
			let c = commitment(1);
			CommitmentRepository::store_memo::<Test>(c, crate::types::EncryptedMemo::default());

			assert_noop!(
				DisclosureValidationService::verify_disclosure_proof::<Test>(
					&[0x01u8; 64],
					&valid_signals(&c),
					&c,
				),
				crate::pallet::Error::<Test>::InvalidDisclosureRecord
			);
		});
	}
}
