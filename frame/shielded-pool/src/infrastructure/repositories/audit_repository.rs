//! Audit Repository - Encapsulates audit and disclosure storage access

use crate::{
	domain::value_objects::Hash,
	domain::{
		Commitment,
		entities::audit::{AuditPolicy, AuditTrail, DisclosureProof, DisclosureRequest},
	},
	pallet::{
		AuditPolicies, AuditTrailStorage, BalanceOf, Config, DisclosureProofs, DisclosureRequests,
		DisclosureVerifyingKey, LastDisclosureTimestamp, NextAuditTrailId,
	},
};
use frame_support::pallet_prelude::*;
use frame_system::pallet_prelude::BlockNumberFor;

/// Repository for audit and disclosure operations
pub struct AuditRepository;

impl AuditRepository {
	// Audit Policies

	pub fn get_policy<T: Config>(
		account: &T::AccountId,
	) -> Option<AuditPolicy<T::AccountId, BalanceOf<T>, BlockNumberFor<T>>> {
		AuditPolicies::<T>::get(account)
	}

	pub fn store_policy<T: Config>(
		account: &T::AccountId,
		policy: AuditPolicy<T::AccountId, BalanceOf<T>, BlockNumberFor<T>>,
	) {
		AuditPolicies::<T>::insert(account, policy);
	}

	pub fn get_audit_policy<T: Config>(
		account: &T::AccountId,
	) -> Option<AuditPolicy<T::AccountId, BalanceOf<T>, BlockNumberFor<T>>> {
		AuditPolicies::<T>::get(account)
	}

	pub fn set_audit_policy<T: Config>(
		account: T::AccountId,
		policy: AuditPolicy<T::AccountId, BalanceOf<T>, BlockNumberFor<T>>,
	) {
		AuditPolicies::<T>::insert(account, policy);
	}

	pub fn remove_audit_policy<T: Config>(account: &T::AccountId) {
		AuditPolicies::<T>::remove(account);
	}

	// Disclosure Requests

	pub fn get_disclosure_request<T: Config>(
		target: &T::AccountId,
		auditor: &T::AccountId,
	) -> Option<DisclosureRequest<T::AccountId, BlockNumberFor<T>>> {
		DisclosureRequests::<T>::get(target, auditor)
	}

	pub fn store_disclosure_request<T: Config>(
		target: T::AccountId,
		auditor: T::AccountId,
		request: DisclosureRequest<T::AccountId, BlockNumberFor<T>>,
	) {
		DisclosureRequests::<T>::insert(target, auditor, request);
	}

	pub fn remove_disclosure_request<T: Config>(target: &T::AccountId, auditor: &T::AccountId) {
		DisclosureRequests::<T>::remove(target, auditor);
	}

	pub fn has_disclosure_request<T: Config>(
		target: &T::AccountId,
		auditor: &T::AccountId,
	) -> bool {
		DisclosureRequests::<T>::contains_key(target, auditor)
	}

	// Disclosure Proofs

	pub fn get_disclosure_proof<T: Config>(commitment: Commitment) -> Option<DisclosureProof> {
		DisclosureProofs::<T>::get(commitment)
	}

	pub fn store_disclosure_proof<T: Config>(commitment: Commitment, proof: DisclosureProof) {
		DisclosureProofs::<T>::insert(commitment, proof);
	}

	pub fn has_disclosure_proof<T: Config>(commitment: Commitment) -> bool {
		DisclosureProofs::<T>::contains_key(commitment)
	}

	// Audit Trail

	pub fn get_audit_trail<T: Config>(
		trail_hash: &Hash,
	) -> Option<AuditTrail<T::AccountId, BlockNumberFor<T>>> {
		AuditTrailStorage::<T>::get(trail_hash)
	}

	pub fn store_audit_trail<T: Config>(
		trail_hash: Hash,
		trail: AuditTrail<T::AccountId, BlockNumberFor<T>>,
	) {
		AuditTrailStorage::<T>::insert(trail_hash, trail);
	}

	pub fn get_next_audit_trail_id<T: Config>() -> u64 {
		NextAuditTrailId::<T>::get()
	}

	pub fn increment_audit_trail_id<T: Config>() -> u64 {
		let current = Self::get_next_audit_trail_id::<T>();
		NextAuditTrailId::<T>::put(current.saturating_add(1));
		current
	}

	// Rate Limiting

	pub fn get_last_disclosure_timestamp<T: Config>(
		account: &T::AccountId,
		commitment: Commitment,
	) -> Option<BlockNumberFor<T>> {
		LastDisclosureTimestamp::<T>::get(account, commitment)
	}

	pub fn update_disclosure_timestamp<T: Config>(
		account: &T::AccountId,
		commitment: Commitment,
		block: BlockNumberFor<T>,
	) {
		LastDisclosureTimestamp::<T>::insert(account, commitment, block);
	}

	pub fn set_last_disclosure_timestamp<T: Config>(
		account: T::AccountId,
		commitment: Commitment,
		block: BlockNumberFor<T>,
	) {
		LastDisclosureTimestamp::<T>::insert(account, commitment, block);
	}

	/// Count recent disclosures within time window
	pub fn has_verifying_key<T: Config>() -> bool {
		DisclosureVerifyingKey::<T>::get().is_some()
	}

	// Commitment Memos

	pub fn has_commitment_memo<T: Config>(commitment: Commitment) -> bool {
		crate::pallet::CommitmentMemos::<T>::contains_key(commitment)
	}

	// Audit Trail Creation

	pub fn create_audit_trail<T: Config>(
		account: &T::AccountId,
		auditor: &T::AccountId,
		_commitment: Commitment,
		disclosure_type: &[u8],
	) -> Result<[u8; 32], sp_runtime::DispatchError> {
		let trail_id = Self::increment_audit_trail_id::<T>();
		let trail_hash = sp_io::hashing::blake2_256(&trail_id.to_le_bytes());

		let current_block = frame_system::Pallet::<T>::block_number();
		let trail = AuditTrail {
			account: account.clone(),
			auditor: auditor.clone(),
			timestamp: current_block,
			disclosure_type: disclosure_type.to_vec().try_into().unwrap_or_default(),
			trail_hash,
		};

		Self::store_audit_trail::<T>(trail_hash, trail);

		Ok(trail_hash)
	}
	pub fn count_recent_disclosures<T: Config>(
		target: &T::AccountId,
		auditor: &T::AccountId,
		cutoff_block: BlockNumberFor<T>,
	) -> usize {
		AuditTrailStorage::<T>::iter()
			.filter(|(_, trail)| {
				trail.account == *target
					&& trail.auditor == *auditor
					&& trail.timestamp >= cutoff_block
			})
			.count()
	}

	// Verifying Key

	pub fn get_disclosure_verifying_key<T: Config>() -> Option<BoundedVec<u8, ConstU32<4096>>> {
		DisclosureVerifyingKey::<T>::get()
	}

	pub fn set_disclosure_verifying_key<T: Config>(vk: BoundedVec<u8, ConstU32<4096>>) {
		DisclosureVerifyingKey::<T>::put(vk);
	}
}
