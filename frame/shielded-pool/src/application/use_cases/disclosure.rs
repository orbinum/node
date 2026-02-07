//! Disclosure use cases
//!
//! Handles selective disclosure and auditing functionality.
//!
//! # Use Cases
//!
//! - **Set Audit Policy**: Configure disclosure rules and authorized auditors
//! - **Request Disclosure**: Auditor requests disclosure of encrypted transaction
//! - **Approve Disclosure**: Target approves request and submits ZK proof
//! - **Reject Disclosure**: Target rejects disclosure request
//! - **Submit Disclosure**: Submit ZK proof for on-chain verification
//! - **Verify Disclosure Conditions**: Check if disclosure conditions are met

use crate::{
	domain::{
		Commitment,
		entities::audit::{AuditPolicy, DisclosureProof, DisclosureRequest},
		value_objects::audit::{Auditor, DisclosureCondition},
	},
	infrastructure::repositories::audit_repository::AuditRepository,
	pallet::{BalanceOf, Config, Error, Event, Pallet},
};
use frame_support::{BoundedVec, pallet_prelude::*};
use frame_system::pallet_prelude::BlockNumberFor;
use sp_runtime::traits::Saturating;

/// Disclosure-related use cases for auditing and compliance
pub struct DisclosureUseCase;

impl DisclosureUseCase {
	/// Set or update audit policy
	///
	/// Configures who can request disclosure and under what conditions.
	///
	/// # Arguments
	/// * `who` - Account setting the policy
	/// * `auditors` - List of authorized auditors
	/// * `conditions` - Conditions that must be met for disclosure
	/// * `max_frequency` - Optional rate limit (blocks between disclosures)
	///
	/// # Returns
	/// * `Ok(())` - Policy was set successfully
	/// * `Err` - Validation failed
	///
	/// # Domain Rules
	/// - At least one auditor required
	/// - Maximum 10 auditors
	/// - Maximum 10 conditions
	/// - Policy version increments on update
	pub fn set_audit_policy<T: Config>(
		who: &T::AccountId,
		auditors: BoundedVec<Auditor<T::AccountId>, ConstU32<10>>,
		conditions: BoundedVec<DisclosureCondition<BalanceOf<T>, BlockNumberFor<T>>, ConstU32<10>>,
		max_frequency: Option<BlockNumberFor<T>>,
	) -> DispatchResult {
		// Validate inputs
		ensure!(!auditors.is_empty(), Error::<T>::TooManyAuditors);
		ensure!(auditors.len() <= 10, Error::<T>::TooManyAuditors);
		ensure!(conditions.len() <= 10, Error::<T>::TooManyConditions);

		// Get current version
		let current_version = AuditRepository::get_policy::<T>(who)
			.map(|policy| policy.version)
			.unwrap_or(0);

		// Create new policy
		let policy = AuditPolicy {
			auditors,
			conditions,
			max_frequency,
			version: current_version + 1,
		};

		// Store policy
		AuditRepository::store_policy::<T>(who, policy.clone());

		// Emit event
		Pallet::<T>::deposit_event(Event::AuditPolicySet {
			account: who.clone(),
			version: policy.version,
		});

		Ok(())
	}

	/// Request disclosure of transaction details
	///
	/// Auditor requests disclosure from a target account.
	///
	/// # Arguments
	/// * `auditor` - Account requesting disclosure
	/// * `target` - Account to audit
	/// * `reason` - Justification for the request
	/// * `evidence` - Optional supporting evidence (court orders, etc.)
	///
	/// # Errors
	/// * `AuditPolicyNotFound` - Target has no audit policy
	/// * `AuditorNotAuthorized` - Auditor not in target's policy
	/// * `DisclosureRequestAlreadyExists` - Duplicate request
	/// * `TooManyDisclosureRequests` - Rate limit exceeded
	///
	/// # Domain Rules
	/// - Target must have audit policy
	/// - Auditor must be authorized
	/// - No duplicate requests
	/// - Respects rate limiting
	pub fn request_disclosure<T: Config>(
		auditor: &T::AccountId,
		target: &T::AccountId,
		reason: BoundedVec<u8, ConstU32<256>>,
		evidence: Option<BoundedVec<u8, ConstU32<1024>>>,
	) -> DispatchResult {
		// Check no duplicate request
		ensure!(
			!AuditRepository::has_disclosure_request::<T>(target, auditor),
			Error::<T>::DisclosureRequestAlreadyExists
		);

		// Get target's audit policy
		let policy =
			AuditRepository::get_policy::<T>(target).ok_or(Error::<T>::AuditPolicyNotFound)?;

		// Verify auditor is authorized
		Self::verify_auditor_authorized::<T>(&policy, auditor)?;

		// Check rate limits
		Self::verify_rate_limits::<T>(&policy, target, auditor)?;

		// Create request
		let request = DisclosureRequest {
			auditor: auditor.clone(),
			target: target.clone(),
			requested_at: frame_system::Pallet::<T>::block_number(),
			reason: reason.clone(),
			evidence,
		};

		// Store request
		AuditRepository::store_disclosure_request::<T>(target.clone(), auditor.clone(), request);

		// Emit event
		Pallet::<T>::deposit_event(Event::DisclosureRequested {
			target: target.clone(),
			auditor: auditor.clone(),
			reason,
		});

		Ok(())
	}

	/// Approve a disclosure request
	///
	/// Target approves disclosure and submits ZK proof.
	///
	/// # Arguments
	/// * `target` - Account approving the request
	/// * `auditor` - Auditor who made the request
	/// * `commitment` - Commitment to disclose
	/// * `zk_proof` - Zero-knowledge proof
	/// * `disclosed_data` - Data to disclose to auditor
	///
	/// # Errors
	/// * `DisclosureRequestNotFound` - No pending request
	/// * `AuditPolicyNotFound` - Target has no policy
	/// * `DisclosureConditionsNotMet` - Conditions not satisfied
	/// * `InvalidDisclosureProof` - Invalid ZK proof
	///
	/// # Domain Rules
	/// - Request must exist
	/// - Conditions must be met
	/// - Proof must be valid
	/// - Audit trail is created
	pub fn approve_disclosure<T: Config>(
		target: &T::AccountId,
		auditor: &T::AccountId,
		commitment: Commitment,
		zk_proof: BoundedVec<u8, ConstU32<2048>>,
		disclosed_data: BoundedVec<u8, ConstU32<512>>,
	) -> DispatchResult {
		// Verify request exists
		let _request = AuditRepository::get_disclosure_request::<T>(target, auditor)
			.ok_or(Error::<T>::DisclosureRequestNotFound)?;

		// Get policy
		let policy =
			AuditRepository::get_policy::<T>(target).ok_or(Error::<T>::AuditPolicyNotFound)?;

		// Verify disclosure conditions
		Self::verify_disclosure_conditions::<T>(&policy, &commitment)?;

		// Verify ZK proof
		Pallet::<T>::verify_disclosure_proof(&zk_proof, &commitment, &disclosed_data)?;

		// Create proof
		let current_block = frame_system::Pallet::<T>::block_number();
		let proof = DisclosureProof {
			commitment,
			zk_proof,
			disclosed_data,
			timestamp: current_block.try_into().unwrap_or(0),
		};

		// Store proof
		AuditRepository::store_disclosure_proof::<T>(commitment, proof);

		// Remove request
		AuditRepository::remove_disclosure_request::<T>(target, auditor);

		// Create audit trail
		let trail_hash = Self::create_audit_trail::<T>(target, auditor, commitment)?;

		// Emit event
		Pallet::<T>::deposit_event(Event::DisclosureApproved {
			target: target.clone(),
			auditor: auditor.clone(),
			commitment,
			trail_hash,
		});

		Ok(())
	}

	/// Reject a disclosure request
	///
	/// Target rejects disclosure request with reason.
	///
	/// # Arguments
	/// * `target` - Account rejecting the request
	/// * `auditor` - Auditor who made the request
	/// * `reason` - Reason for rejection
	///
	/// # Errors
	/// * `DisclosureRequestNotFound` - No pending request
	///
	/// # Domain Rules
	/// - Request must exist
	/// - Request is removed after rejection
	pub fn reject_disclosure<T: Config>(
		target: &T::AccountId,
		auditor: &T::AccountId,
		reason: BoundedVec<u8, ConstU32<256>>,
	) -> DispatchResult {
		// Verify request exists
		ensure!(
			AuditRepository::has_disclosure_request::<T>(target, auditor),
			Error::<T>::DisclosureRequestNotFound
		);

		// Remove request
		AuditRepository::remove_disclosure_request::<T>(target, auditor);

		// Emit event
		Pallet::<T>::deposit_event(Event::DisclosureRejected {
			target: target.clone(),
			auditor: auditor.clone(),
			reason,
		});

		Ok(())
	}

	/// Submit disclosure with proof
	///
	/// Submit ZK proof for on-chain verification.
	///
	/// # Arguments
	/// * `who` - Account submitting disclosure
	/// * `commitment` - Commitment to disclose
	/// * `proof_bytes` - Groth16 proof (256 bytes)
	/// * `public_signals` - Public signals (97 bytes)
	/// * `partial_data` - Disclosed data
	/// * `auditor` - Optional auditor account
	///
	/// # Errors
	/// * `CommitmentNotFound` - Commitment not on-chain
	/// * `VerifyingKeyNotSet` - VK not configured
	/// * `InvalidDisclosureProof` - Proof verification failed
	/// * `UnauthorizedAuditor` - Auditor not authorized
	/// * `DisclosureFrequencyExceeded` - Rate limit exceeded
	///
	/// # Domain Rules
	/// - Commitment must exist
	/// - VK must be set
	/// - Proof must verify
	/// - Access control enforced
	/// - Rate limiting applied
	pub fn submit_disclosure<T: Config>(
		who: &T::AccountId,
		commitment: Commitment,
		proof_bytes: BoundedVec<u8, ConstU32<256>>,
		public_signals: BoundedVec<u8, ConstU32<97>>,
		partial_data: BoundedVec<u8, ConstU32<256>>,
		auditor: Option<&T::AccountId>,
	) -> DispatchResult {
		// Validate commitment exists
		ensure!(
			AuditRepository::has_commitment_memo::<T>(commitment),
			Error::<T>::CommitmentNotFound
		);

		// Validate VK is set
		ensure!(
			AuditRepository::has_verifying_key::<T>(),
			Error::<T>::VerifyingKeyNotSet
		);

		// Validate access control
		Self::validate_disclosure_access::<T>(who, commitment, auditor)?;

		// Verify ZK proof
		Pallet::<T>::verify_disclosure_proof_internal(&proof_bytes, &public_signals)?;

		// Validate public signals match commitment
		Pallet::<T>::validate_public_signals(&commitment, &public_signals)?;

		// Create and store proof
		let current_block = frame_system::Pallet::<T>::block_number();
		let proof = DisclosureProof {
			commitment,
			zk_proof: proof_bytes.to_vec().try_into().unwrap_or_default(),
			disclosed_data: partial_data.to_vec().try_into().unwrap_or_default(),
			timestamp: current_block.try_into().unwrap_or(0),
		};

		AuditRepository::store_disclosure_proof::<T>(commitment, proof);

		// Update rate limiting
		AuditRepository::update_disclosure_timestamp::<T>(who, commitment, current_block);

		// Emit event
		Pallet::<T>::deposit_event(Event::DisclosureVerified {
			who: who.clone(),
			commitment,
			verified: true,
		});

		// Create audit trail if auditor present
		if let Some(auditor_account) = auditor {
			let _trail_hash = Self::create_audit_trail::<T>(who, auditor_account, commitment)?;
		}

		Ok(())
	}

	// ========================================================================
	// Helper Functions (Private)
	// ========================================================================

	/// Verify auditor is authorized in policy
	fn verify_auditor_authorized<T: Config>(
		policy: &AuditPolicy<T::AccountId, BalanceOf<T>, BlockNumberFor<T>>,
		auditor: &T::AccountId,
	) -> DispatchResult {
		let is_authorized = policy
			.auditors
			.iter()
			.any(|auditor_type| match auditor_type {
				Auditor::Account(account) => account == auditor,
				Auditor::CredentialHolder { .. } => true,
				Auditor::Role { .. } => true,
			});

		ensure!(is_authorized, Error::<T>::AuditorNotAuthorized);
		Ok(())
	}

	/// Verify rate limits are not exceeded
	fn verify_rate_limits<T: Config>(
		policy: &AuditPolicy<T::AccountId, BalanceOf<T>, BlockNumberFor<T>>,
		target: &T::AccountId,
		auditor: &T::AccountId,
	) -> DispatchResult {
		if let Some(max_freq) = policy.max_frequency {
			let current_block = frame_system::Pallet::<T>::block_number();
			let cutoff_block = current_block.saturating_sub(max_freq);

			let recent_count =
				AuditRepository::count_recent_disclosures::<T>(target, auditor, cutoff_block);

			let max_freq_u32: u32 = TryInto::<u32>::try_into(max_freq).unwrap_or(u32::MAX);

			ensure!(
				recent_count < max_freq_u32 as usize,
				Error::<T>::TooManyDisclosureRequests
			);
		}

		Ok(())
	}

	/// Verify disclosure conditions are met
	fn verify_disclosure_conditions<T: Config>(
		policy: &AuditPolicy<T::AccountId, BalanceOf<T>, BlockNumberFor<T>>,
		commitment: &Commitment,
	) -> DispatchResult {
		let current_block = frame_system::Pallet::<T>::block_number();

		let conditions_met = policy.conditions.iter().any(|condition| match condition {
			DisclosureCondition::Always => true,
			DisclosureCondition::TimeDelay { after_block } => current_block >= *after_block,
			DisclosureCondition::AmountThreshold { .. } => {
				AuditRepository::has_commitment_memo::<T>(*commitment)
			}
			DisclosureCondition::JudicialOrder { .. } => {
				AuditRepository::has_commitment_memo::<T>(*commitment)
			}
			DisclosureCondition::Custom { .. } => {
				AuditRepository::has_commitment_memo::<T>(*commitment)
			}
		});

		ensure!(conditions_met, Error::<T>::DisclosureConditionsNotMet);
		Ok(())
	}

	/// Validate disclosure access permissions
	fn validate_disclosure_access<T: Config>(
		who: &T::AccountId,
		commitment: Commitment,
		auditor: Option<&T::AccountId>,
	) -> DispatchResult {
		// If auditor present, verify authorization
		if let Some(auditor_id) = auditor {
			if let Some(policy) = AuditRepository::get_policy::<T>(who) {
				// Verify auditor authorized
				Self::verify_auditor_authorized::<T>(&policy, auditor_id)?;

				// Check rate limits
				if let Some(max_freq) = policy.max_frequency {
					let last_disclosure =
						AuditRepository::get_last_disclosure_timestamp::<T>(who, commitment);

					if let Some(last_block) = last_disclosure {
						let current_block = frame_system::Pallet::<T>::block_number();
						let elapsed = current_block.saturating_sub(last_block);

						ensure!(elapsed >= max_freq, Error::<T>::DisclosureFrequencyExceeded);
					}
				}
			} else {
				// No policy means no authorized auditors
				return Err(Error::<T>::AuditPolicyNotFound.into());
			}
		}

		Ok(())
	}

	/// Create audit trail entry
	fn create_audit_trail<T: Config>(
		account: &T::AccountId,
		auditor: &T::AccountId,
		commitment: Commitment,
	) -> Result<[u8; 32], DispatchError> {
		let trail_hash = AuditRepository::create_audit_trail::<T>(
			account,
			auditor,
			commitment,
			b"selective_disclosure",
		)?;

		Ok(trail_hash)
	}

	/// Get disclosure request
	///
	/// Retrieves a pending disclosure request.
	pub fn get_disclosure_request<T: Config>(
		target: &T::AccountId,
		auditor: &T::AccountId,
	) -> Option<DisclosureRequest<T::AccountId, BlockNumberFor<T>>> {
		AuditRepository::get_disclosure_request::<T>(target, auditor)
	}

	/// Get audit policy
	///
	/// Retrieves the audit policy for an account.
	pub fn get_audit_policy<T: Config>(
		who: &T::AccountId,
	) -> Option<AuditPolicy<T::AccountId, BalanceOf<T>, BlockNumberFor<T>>> {
		AuditRepository::get_policy::<T>(who)
	}

	/// Get disclosure proof
	///
	/// Retrieves a stored disclosure proof.
	pub fn get_disclosure_proof<T: Config>(commitment: Commitment) -> Option<DisclosureProof> {
		AuditRepository::get_disclosure_proof::<T>(commitment)
	}

	/// Check if commitment has proof
	///
	/// Checks if a disclosure proof exists for a commitment.
	pub fn has_disclosure_proof<T: Config>(commitment: Commitment) -> bool {
		AuditRepository::has_disclosure_proof::<T>(commitment)
	}
}
