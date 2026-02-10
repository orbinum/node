//! Disclosure service - Handles selective disclosure operations

use crate::{
	domain::{
		Commitment,
		entities::audit::{AuditPolicy, AuditTrail, DisclosureProof, DisclosureRequest},
		value_objects::audit::{Auditor, DisclosureCondition},
	},
	pallet::{
		AuditPolicies, AuditTrailStorage, BalanceOf, CommitmentMemos, Config, DisclosureProofs,
		DisclosureRequests, DisclosureVerifyingKey, Error, Event, LastDisclosureTimestamp,
		NextAuditTrailId, Pallet,
	},
};
use frame_support::{BoundedVec, ensure, pallet_prelude::*};
use frame_system;
use sp_runtime::traits::Saturating;

pub struct DisclosureService;

impl DisclosureService {
	/// Set or update the disclosure verifying key
	pub fn set_verifying_key<T: Config>(
		vk_bytes: BoundedVec<u8, ConstU32<4096>>,
	) -> DispatchResult {
		// Basic validation: VK should be at least 100 bytes
		ensure!(vk_bytes.len() >= 100, Error::<T>::InvalidVerifyingKey);

		// Store VK
		DisclosureVerifyingKey::<T>::put(vk_bytes.clone());

		// Emit event
		Pallet::<T>::deposit_event(Event::DisclosureVerifyingKeyUpdated {
			vk_size: vk_bytes.len() as u32,
		});

		Ok(())
	}

	/// Set or update audit policy for selective disclosure
	pub fn set_audit_policy<T: Config>(
		who: &<T as frame_system::Config>::AccountId,
		auditors: BoundedVec<Auditor<<T as frame_system::Config>::AccountId>, ConstU32<10>>,
		conditions: BoundedVec<
			DisclosureCondition<BalanceOf<T>, frame_system::pallet_prelude::BlockNumberFor<T>>,
			ConstU32<10>,
		>,
		max_frequency: Option<frame_system::pallet_prelude::BlockNumberFor<T>>,
	) -> DispatchResult {
		// Validate policy constraints
		ensure!(!auditors.is_empty(), Error::<T>::TooManyAuditors);
		ensure!(auditors.len() <= 10, Error::<T>::TooManyAuditors);
		ensure!(conditions.len() <= 10, Error::<T>::TooManyConditions);

		// Get current policy version
		let current_version = AuditPolicies::<T>::get(who)
			.map(|policy| policy.version)
			.unwrap_or(0);

		let new_version = current_version + 1;

		// Create new policy
		let policy = AuditPolicy {
			auditors,
			conditions,
			max_frequency,
			version: new_version,
		};

		// Store policy
		AuditPolicies::<T>::insert(who, policy);

		Pallet::<T>::deposit_event(Event::AuditPolicySet {
			account: who.clone(),
			version: new_version,
		});

		Ok(())
	}

	/// Request disclosure from a target account
	pub fn request_disclosure<T: Config>(
		auditor: &<T as frame_system::Config>::AccountId,
		target: &<T as frame_system::Config>::AccountId,
		reason: BoundedVec<u8, ConstU32<256>>,
		evidence: Option<BoundedVec<u8, ConstU32<1024>>>,
	) -> DispatchResult {
		// Check that request doesn't already exist
		ensure!(
			!DisclosureRequests::<T>::contains_key(target, auditor),
			Error::<T>::DisclosureRequestAlreadyExists
		);

		// Check that target has an audit policy
		let policy = AuditPolicies::<T>::get(target).ok_or(Error::<T>::AuditPolicyNotFound)?;

		// Verify auditor is authorized
		let is_authorized = policy
			.auditors
			.iter()
			.any(|auditor_type| match auditor_type {
				Auditor::Account(account) => account == auditor,
				Auditor::CredentialHolder { credential: _ } => true,
				Auditor::Role { role: _ } => true,
			});
		ensure!(is_authorized, Error::<T>::AuditorNotAuthorized);

		// Check frequency limits if set
		if let Some(max_freq) = policy.max_frequency {
			let current_block = frame_system::Pallet::<T>::block_number();
			let cutoff_block = current_block.saturating_sub(max_freq);

			let recent_count = AuditTrailStorage::<T>::iter()
				.filter(|(_, trail)| {
					trail.account == *target
						&& trail.auditor == *auditor
						&& trail.timestamp >= cutoff_block
				})
				.count();

			let max_freq_u32: u32 = TryInto::<u32>::try_into(max_freq).unwrap_or(u32::MAX);

			ensure!(
				recent_count < max_freq_u32 as usize,
				Error::<T>::TooManyDisclosureRequests
			);
		}

		let reason_clone = reason.clone();
		let request = DisclosureRequest {
			auditor: auditor.clone(),
			target: target.clone(),
			requested_at: frame_system::Pallet::<T>::block_number(),
			reason,
			evidence,
		};

		DisclosureRequests::<T>::insert(target, auditor, request);

		Pallet::<T>::deposit_event(Event::DisclosureRequested {
			target: target.clone(),
			auditor: auditor.clone(),
			reason: reason_clone,
		});

		Ok(())
	}

	/// Approve disclosure request and submit proof
	pub fn approve_disclosure<T: Config>(
		target: &<T as frame_system::Config>::AccountId,
		auditor: &<T as frame_system::Config>::AccountId,
		commitment: Commitment,
		zk_proof: BoundedVec<u8, ConstU32<2048>>,
		disclosed_data: BoundedVec<u8, ConstU32<512>>,
	) -> DispatchResult {
		// Check that disclosure request exists
		let _request = DisclosureRequests::<T>::get(target, auditor)
			.ok_or(Error::<T>::DisclosureRequestNotFound)?;

		// Get audit policy
		let policy = AuditPolicies::<T>::get(target).ok_or(Error::<T>::AuditPolicyNotFound)?;

		// Verify disclosure conditions are met
		let current_block = frame_system::Pallet::<T>::block_number();
		let conditions_met = policy.conditions.iter().any(|condition| match condition {
			DisclosureCondition::Always => true,
			DisclosureCondition::TimeDelay { after_block } => current_block >= *after_block,
			DisclosureCondition::AmountThreshold { min_amount: _ } => {
				CommitmentMemos::<T>::contains_key(commitment)
			}
			DisclosureCondition::JudicialOrder {
				court_id: _,
				case_id: _,
			} => _request.evidence.is_some(),
			DisclosureCondition::Custom {
				condition_id: _,
				params: _,
			} => CommitmentMemos::<T>::contains_key(commitment),
		});
		ensure!(conditions_met, Error::<T>::DisclosureConditionsNotMet);

		// Verify ZK proof of disclosure compliance
		Pallet::<T>::verify_disclosure_proof(&zk_proof, &commitment, &disclosed_data)?;

		// Create disclosure proof
		let proof = DisclosureProof {
			commitment,
			zk_proof,
			disclosed_data,
			timestamp: current_block.try_into().unwrap_or(0),
		};

		// Store proof
		DisclosureProofs::<T>::insert(commitment, proof);

		// Remove request
		DisclosureRequests::<T>::remove(target, auditor);

		// Create audit trail entry
		let trail_id = NextAuditTrailId::<T>::mutate(|id| {
			*id += 1;
			*id
		});

		let trail_hash = sp_io::hashing::blake2_256(&trail_id.to_le_bytes());
		let audit_trail = AuditTrail {
			account: target.clone(),
			auditor: auditor.clone(),
			timestamp: current_block,
			disclosure_type: b"selective_disclosure"
				.to_vec()
				.try_into()
				.unwrap_or_default(),
			trail_hash,
		};

		AuditTrailStorage::<T>::insert(trail_hash, audit_trail);

		Pallet::<T>::deposit_event(Event::DisclosureApproved {
			target: target.clone(),
			auditor: auditor.clone(),
			commitment,
			trail_hash,
		});

		Ok(())
	}

	/// Reject disclosure request
	pub fn reject_disclosure<T: Config>(
		target: &<T as frame_system::Config>::AccountId,
		auditor: &<T as frame_system::Config>::AccountId,
		reason: BoundedVec<u8, ConstU32<256>>,
	) -> DispatchResult {
		// Check that disclosure request exists
		ensure!(
			DisclosureRequests::<T>::contains_key(target, auditor),
			Error::<T>::DisclosureRequestNotFound
		);

		// Remove request
		DisclosureRequests::<T>::remove(target, auditor);

		Pallet::<T>::deposit_event(Event::DisclosureRejected {
			target: target.clone(),
			auditor: auditor.clone(),
			reason,
		});

		Ok(())
	}

	/// Submit disclosure proof on-chain for verification
	pub fn submit_disclosure<T: Config>(
		who: &<T as frame_system::Config>::AccountId,
		commitment: Commitment,
		proof_bytes: BoundedVec<u8, ConstU32<256>>,
		public_signals: BoundedVec<u8, ConstU32<97>>,
		partial_data: BoundedVec<u8, ConstU32<256>>,
		auditor: Option<&<T as frame_system::Config>::AccountId>,
	) -> DispatchResult {
		// Validar que commitment existe
		ensure!(
			CommitmentMemos::<T>::contains_key(commitment),
			Error::<T>::CommitmentNotFound
		);

		// Validar que VK está configurado
		ensure!(
			DisclosureVerifyingKey::<T>::get().is_some(),
			Error::<T>::VerifyingKeyNotSet
		);

		// Validar access control y rate limiting
		Pallet::<T>::validate_disclosure_access(who, &commitment, auditor)?;

		// Validar proof con ZK verifier
		Pallet::<T>::verify_disclosure_proof_internal(&proof_bytes, &public_signals)?;

		// Validar public signals
		Pallet::<T>::validate_public_signals(&commitment, &public_signals)?;

		// Store proof verificado
		let current_block = frame_system::Pallet::<T>::block_number();
		let proof = DisclosureProof {
			commitment,
			zk_proof: proof_bytes.to_vec().try_into().unwrap_or_default(),
			disclosed_data: partial_data.to_vec().try_into().unwrap_or_default(),
			timestamp: current_block.try_into().unwrap_or(0),
		};

		DisclosureProofs::<T>::insert(commitment, proof);

		// Update rate limiting timestamp
		LastDisclosureTimestamp::<T>::insert(who, commitment, current_block);

		// Emit verification event
		Pallet::<T>::deposit_event(Event::DisclosureVerified {
			who: who.clone(),
			commitment,
			verified: true,
		});

		// Create audit trail for verified disclosure
		if let Some(auditor_account) = auditor {
			let trail_id = NextAuditTrailId::<T>::mutate(|id| {
				*id += 1;
				*id
			});

			let trail_hash = sp_io::hashing::blake2_256(&trail_id.to_le_bytes());
			let audit_trail = AuditTrail {
				account: who.clone(),
				auditor: auditor_account.clone(),
				timestamp: current_block,
				disclosure_type: b"verified_disclosure"
					.to_vec()
					.try_into()
					.unwrap_or_default(),
				trail_hash,
			};

			AuditTrailStorage::<T>::insert(trail_hash, audit_trail);
		}

		Ok(())
	}

	/// Submit multiple disclosure proofs in a single transaction (batch optimization)
	pub fn batch_submit_proofs<T: Config>(
		who: &<T as frame_system::Config>::AccountId,
		submissions: BoundedVec<crate::pallet::BatchDisclosureSubmission, ConstU32<10>>,
	) -> DispatchResult {
		// 1. Basic checks
		ensure!(
			DisclosureVerifyingKey::<T>::get().is_some(),
			Error::<T>::VerifyingKeyNotSet
		);

		if submissions.is_empty() {
			return Ok(());
		}

		// 2. Prepare data for batch verification and validate business rules
		let mut proofs_raw = alloc::vec::Vec::with_capacity(submissions.len());
		let mut signals_raw = alloc::vec::Vec::with_capacity(submissions.len());

		for sub in submissions.iter() {
			// Ensure commitment exists
			ensure!(
				CommitmentMemos::<T>::contains_key(sub.commitment),
				Error::<T>::CommitmentNotFound
			);

			// Check access control and rate limiting
			Pallet::<T>::validate_disclosure_access(who, &sub.commitment, None)?;

			// Validate public signals consistency off-chain (commitment matching)
			Pallet::<T>::validate_public_signals(&sub.commitment, &sub.public_signals)?;

			proofs_raw.push(sub.proof.to_vec());
			signals_raw.push(sub.public_signals.to_vec());
		}

		// 3. Perform optimized batch verification via ZK Verifier Port
		use pallet_zk_verifier::ZkVerifierPort;
		let all_valid =
			T::ZkVerifier::batch_verify_disclosure_proofs(&proofs_raw, &signals_raw, None)?;
		ensure!(all_valid, Error::<T>::InvalidDisclosureProof);

		// 4. Persistence and side effects
		let current_block = frame_system::Pallet::<T>::block_number();
		let timestamp = current_block.try_into().unwrap_or(0);

		for sub in submissions {
			let proof = DisclosureProof {
				commitment: sub.commitment,
				zk_proof: sub.proof,
				disclosed_data: sub.disclosed_data,
				timestamp,
			};

			// Store verified proof
			DisclosureProofs::<T>::insert(sub.commitment, proof);

			// Update rate limiting
			LastDisclosureTimestamp::<T>::insert(who, sub.commitment, current_block);

			// Emit event per verified disclosure
			Pallet::<T>::deposit_event(Event::DisclosureVerified {
				who: who.clone(),
				commitment: sub.commitment,
				verified: true,
			});
		}

		Ok(())
	}
}
