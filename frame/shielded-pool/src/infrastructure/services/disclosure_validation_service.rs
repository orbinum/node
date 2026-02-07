//! Disclosure Validation Service - Handles disclosure proof validation
//!
//! This service provides comprehensive validation for selective disclosure proofs,
//! including cryptographic verification, access control, and rate limiting.

use crate::{
	domain::Commitment,
	domain::value_objects::audit::Auditor,
	pallet::{
		AuditPolicies, CommitmentMemos, DisclosureRequests, DisclosureVerifyingKey,
		LastDisclosureTimestamp,
	},
	pallet::{Config, Error},
};
use frame_support::{ensure, pallet_prelude::*};
use frame_system::{self, pallet_prelude::BlockNumberFor};
use pallet_zk_verifier::ZkVerifierPort;
use sp_runtime::traits::Saturating;

/// Disclosure Validation Service
///
/// Provides validation logic for selective disclosure operations:
/// - ZK proof verification
/// - Public signals validation
/// - Access control (audit policies)
/// - Rate limiting
pub struct DisclosureValidationService;

impl DisclosureValidationService {
	/// Verify disclosure proof using ZK verifier (internal validation)
	pub fn verify_proof_internal<T: Config>(
		proof_bytes: &[u8],
		public_signals: &[u8],
	) -> DispatchResult {
		// Validate sizes
		ensure!(proof_bytes.len() == 256, Error::<T>::InvalidProof);
		ensure!(public_signals.len() == 97, Error::<T>::InvalidPublicSignals);

		// Call the ZK verifier (using None for active version)
		let is_valid = T::ZkVerifier::verify_disclosure_proof(proof_bytes, public_signals, None)?;

		ensure!(is_valid, Error::<T>::InvalidProof);

		Ok(())
	}

	/// Validate public signals consistency
	pub fn validate_public_signals<T: Config>(
		commitment: &Commitment,
		public_signals: &[u8],
	) -> DispatchResult {
		ensure!(public_signals.len() == 97, Error::<T>::InvalidPublicSignals);

		// Extract components
		let commitment_from_signals = &public_signals[0..32];
		let vk_hash = &public_signals[32..64];
		let mask_bitmap = public_signals[64];
		let _revealed_owner_hash = &public_signals[65..97];

		// 1. Commitment must match
		ensure!(
			commitment_from_signals == commitment.0,
			Error::<T>::InvalidPublicSignals
		);

		// 2. Viewing key hash must NOT be zero
		let zero_hash = [0u8; 32];
		ensure!(vk_hash != zero_hash, Error::<T>::InvalidPublicSignals);

		// 3. Mask bitmap must be valid (bits 0-3 for value, asset_id, owner, blinding)
		// The blinding bit (bit 3) must NOT be set (blinding is not revealed)
		// At least 1 of the other bits must be set
		let reveals_blinding = (mask_bitmap & 0x08) != 0;
		let reveals_anything = (mask_bitmap & 0x07) != 0;

		ensure!(!reveals_blinding, Error::<T>::InvalidPublicSignals);
		ensure!(reveals_anything, Error::<T>::InvalidPublicSignals);

		Ok(())
	}

	/// Validate disclosure access control and rate limiting
	pub fn validate_disclosure_access<T: Config>(
		who: &<T as frame_system::Config>::AccountId,
		commitment: &Commitment,
		auditor: Option<&<T as frame_system::Config>::AccountId>,
	) -> DispatchResult {
		// 1. Check AuditPolicy if exists
		if let Some(policy) = AuditPolicies::<T>::get(who) {
			// If auditor is specified, validate it is authorized
			if let Some(auditor_id) = auditor {
				let is_authorized = policy
					.auditors
					.iter()
					.any(|a| matches!(a, Auditor::Account(acc) if acc == auditor_id));
				ensure!(is_authorized, Error::<T>::UnauthorizedAuditor);

				// Verify DisclosureRequest exists if formal audit
				ensure!(
					DisclosureRequests::<T>::contains_key(who, auditor_id),
					Error::<T>::DisclosureRequestNotFound
				);
			}

			// 2. Validate rate limiting (max_frequency)
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
			// Without AuditPolicy: only owner can do voluntary disclosure (without auditor)
			ensure!(auditor.is_none(), Error::<T>::UnauthorizedAuditor);
		}

		Ok(())
	}

	/// Verify disclosure proof (cryptographic verification with full context)
	pub fn verify_disclosure_proof<T: Config>(
		proof: &BoundedVec<u8, ConstU32<2048>>,
		commitment: &Commitment,
		disclosed_data: &BoundedVec<u8, ConstU32<512>>,
	) -> Result<(), DispatchError> {
		// Basic structural validation
		ensure!(proof.len() >= 256, Error::<T>::InvalidDisclosureProof);
		ensure!(proof.len() <= 2048, Error::<T>::InvalidDisclosureProof);

		// Verify commitment exists in the tree
		ensure!(
			CommitmentMemos::<T>::contains_key(commitment),
			Error::<T>::InvalidDisclosureProof
		);

		// Attempt to load verifying key
		let _vk_bytes = DisclosureVerifyingKey::<T>::get().ok_or(Error::<T>::VerifyingKeyNotSet)?;

		// VK is configured - perform full cryptographic verification

		// Reconstruct public signals from disclosed_data
		let mut public_signals = sp_std::vec::Vec::new();

		// 1. Commitment (32 bytes)
		public_signals.extend_from_slice(&commitment.0);

		// 2. Viewing key hash (32 bytes) - use dummy hash in test mode
		let vk_hash = sp_io::hashing::blake2_256(disclosed_data.as_slice());
		public_signals.extend_from_slice(&vk_hash);

		// 3. Mask bitmap (1 byte) - 0x07 reveals value, asset_id, owner (not blinding)
		public_signals.push(0x07);

		// 4. Revealed owner hash (32 bytes)
		let owner_hash = sp_io::hashing::blake2_256(disclosed_data.as_slice());
		public_signals.extend_from_slice(&owner_hash);

		// Convert to bounded vec (97 bytes total)
		let public_signals_bounded: BoundedVec<u8, ConstU32<97>> = public_signals
			.try_into()
			.map_err(|_| Error::<T>::InvalidPublicSignals)?;

		// Call the ZK verifier
		let is_valid = T::ZkVerifier::verify_disclosure_proof(
			proof.as_slice(),
			public_signals_bounded.as_slice(),
			None, // Use active version
		)?;

		ensure!(is_valid, Error::<T>::InvalidDisclosureProof);

		Ok(())
	}

	/// Check if verifying key is configured
	pub fn has_verifying_key<T: Config>() -> bool {
		DisclosureVerifyingKey::<T>::get().is_some()
	}

	/// Validate mask bitmap (selective disclosure bitmap)
	///
	/// # Bitmap Layout (4 bits):
	/// - Bit 0: reveals value
	/// - Bit 1: reveals asset_id
	/// - Bit 2: reveals owner
	/// - Bit 3: reveals blinding (MUST be 0)
	///
	/// Returns (reveals_value, reveals_asset_id, reveals_owner, is_valid)
	pub fn decode_mask_bitmap(mask: u8) -> (bool, bool, bool, bool) {
		let reveals_value = (mask & 0x01) != 0;
		let reveals_asset_id = (mask & 0x02) != 0;
		let reveals_owner = (mask & 0x04) != 0;
		let reveals_blinding = (mask & 0x08) != 0;

		// Valid if: not revealing blinding AND revealing at least one field
		let is_valid = !reveals_blinding && (reveals_value || reveals_asset_id || reveals_owner);

		(reveals_value, reveals_asset_id, reveals_owner, is_valid)
	}

	/// Check if a disclosure request exists and is pending
	pub fn has_pending_disclosure_request<T: Config>(
		target: &T::AccountId,
		auditor: &T::AccountId,
	) -> bool {
		DisclosureRequests::<T>::contains_key(target, auditor)
	}

	/// Get time since last disclosure (in blocks)
	pub fn blocks_since_last_disclosure<T: Config>(
		account: &T::AccountId,
		commitment: &Commitment,
	) -> Option<BlockNumberFor<T>> {
		let current_block = frame_system::Pallet::<T>::block_number();
		LastDisclosureTimestamp::<T>::get(account, commitment)
			.map(|last| current_block.saturating_sub(last))
	}

	/// Validate disclosed data structure
	///
	/// Disclosed data should contain:
	/// - value (optional, 16 bytes)
	/// - asset_id (optional, 4 bytes)
	/// - owner pubkey (optional, 32 bytes)
	pub fn validate_disclosed_data_structure(data: &[u8], mask: u8) -> Result<(), &'static str> {
		let (reveals_value, reveals_asset_id, reveals_owner, is_valid) =
			Self::decode_mask_bitmap(mask);

		if !is_valid {
			return Err("Invalid mask bitmap");
		}

		let mut expected_size = 0usize;
		if reveals_value {
			expected_size += 16; // u128 value
		}
		if reveals_asset_id {
			expected_size += 4; // u32 asset_id
		}
		if reveals_owner {
			expected_size += 32; // 32-byte owner pubkey
		}

		if data.len() < expected_size {
			return Err("Disclosed data too short");
		}

		Ok(())
	}
}
