//! Selective Disclosure
//!
//! Structures for selective disclosure of encrypted memo fields.
//! Allows revealing specific fields while maintaining privacy.

use crate::domain::entities::error::MemoError;
use alloc::vec::Vec;

#[cfg(feature = "parity-scale-codec")]
use parity_scale_codec::{Decode, Encode};
#[cfg(feature = "scale-info")]
use scale_info::TypeInfo;

/// Disclosure mask defining which memo fields to reveal
///
/// Controls which fields are revealed. `blinding` must always be false.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
	all(feature = "parity-scale-codec", feature = "scale-info"),
	derive(Encode, Decode, TypeInfo)
)]
pub struct DisclosureMask {
	/// Reveal the value/amount of the memo
	pub disclose_value: bool,

	/// Reveal the owner public key (or hash of it)
	pub disclose_owner: bool,

	/// Reveal the blinding factor (SHOULD ALWAYS BE FALSE)
	pub disclose_blinding: bool,

	/// Reveal the asset ID
	pub disclose_asset_id: bool,
}

impl DisclosureMask {
	/// Creates mask revealing all fields except blinding
	pub fn all() -> Self {
		Self {
			disclose_value: true,
			disclose_owner: true,
			disclose_blinding: false, // NEVER reveal blinding
			disclose_asset_id: true,
		}
	}

	/// Creates mask revealing only value
	pub fn only_value() -> Self {
		Self {
			disclose_value: true,
			disclose_owner: false,
			disclose_blinding: false,
			disclose_asset_id: false,
		}
	}

	/// Creates mask revealing value and asset ID
	pub fn value_and_asset() -> Self {
		Self {
			disclose_value: true,
			disclose_owner: false,
			disclose_blinding: false,
			disclose_asset_id: true,
		}
	}

	/// Creates mask revealing nothing
	pub fn none() -> Self {
		Self {
			disclose_value: false,
			disclose_owner: false,
			disclose_blinding: false,
			disclose_asset_id: false,
		}
	}

	/// Converts mask to 4-bit bitmap for circuit encoding
	pub fn to_bitmap(&self) -> u8 {
		(self.disclose_value as u8)
			| (self.disclose_owner as u8) << 1
			| (self.disclose_blinding as u8) << 2
			| (self.disclose_asset_id as u8) << 3
	}

	/// Creates mask from bitmap (inverse of `to_bitmap`)
	pub fn from_bitmap(bits: u8) -> Self {
		Self {
			disclose_value: (bits & 0b0001) != 0,
			disclose_owner: (bits & 0b0010) != 0,
			disclose_blinding: (bits & 0b0100) != 0,
			disclose_asset_id: (bits & 0b1000) != 0,
		}
	}

	/// Validates mask safety: no blinding, at least one field
	pub fn validate(&self) -> Result<(), MemoError> {
		// RULE 1: NEVER reveal blinding
		if self.disclose_blinding {
			return Err(MemoError::InvalidDisclosureMask(
				"Cannot disclose blinding factor - compromises commitment privacy",
			));
		}

		// RULE 2: At least ONE field must be revealed
		if !self.disclose_value && !self.disclose_owner && !self.disclose_asset_id {
			return Err(MemoError::InvalidDisclosureMask(
				"Must disclose at least one field (value, owner, or asset_id)",
			));
		}

		Ok(())
	}

	/// Counts how many fields will be revealed
	pub fn disclosed_field_count(&self) -> usize {
		let mut count = 0;
		if self.disclose_value {
			count += 1;
		}
		if self.disclose_owner {
			count += 1;
		}
		if self.disclose_blinding {
			count += 1;
		}
		if self.disclose_asset_id {
			count += 1;
		}
		count
	}
}

/// Partially revealed memo data
///
/// Only disclosed fields are Some, others are None.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
	all(feature = "parity-scale-codec", feature = "scale-info"),
	derive(Encode, Decode, TypeInfo)
)]
pub struct PartialMemoData {
	/// Revealed value (None if not disclosed)
	pub value: Option<u64>,

	/// Revealed owner public key (None if not disclosed)
	pub owner_pk: Option<[u8; 32]>,

	/// Revealed blinding factor (None if not disclosed)
	/// This field should normally be None to preserve privacy
	pub blinding: Option<[u8; 32]>,

	/// Revealed asset ID (None if not disclosed)
	pub asset_id: Option<u32>,
}

impl PartialMemoData {
	/// Creates empty partial memo (nothing revealed)
	pub fn empty() -> Self {
		Self {
			value: None,
			owner_pk: None,
			blinding: None,
			asset_id: None,
		}
	}

	/// Creates partial memo by applying disclosure mask to complete memo data
	pub fn from_disclosure(
		memo: &crate::domain::entities::types::MemoData,
		mask: &DisclosureMask,
	) -> Self {
		Self {
			value: if mask.disclose_value {
				Some(memo.value)
			} else {
				None
			},
			owner_pk: if mask.disclose_owner {
				Some(memo.owner_pk)
			} else {
				None
			},
			blinding: if mask.disclose_blinding {
				Some(memo.blinding)
			} else {
				None
			},
			asset_id: if mask.disclose_asset_id {
				Some(memo.asset_id)
			} else {
				None
			},
		}
	}

	/// Checks if no fields are revealed
	pub fn is_empty(&self) -> bool {
		self.value.is_none()
			&& self.owner_pk.is_none()
			&& self.blinding.is_none()
			&& self.asset_id.is_none()
	}

	/// Serializes to bytes: [flags(1)] || [optional fields...]
	pub fn to_bytes(&self) -> Vec<u8> {
		let mut bytes = Vec::new();

		// Flags byte: bitmap of present fields
		let flags = (self.value.is_some() as u8)
			| (self.owner_pk.is_some() as u8) << 1
			| (self.blinding.is_some() as u8) << 2
			| (self.asset_id.is_some() as u8) << 3;
		bytes.push(flags);

		// Append present fields in order
		if let Some(v) = self.value {
			bytes.extend_from_slice(&v.to_le_bytes());
		}
		if let Some(pk) = self.owner_pk {
			bytes.extend_from_slice(&pk);
		}
		if let Some(b) = self.blinding {
			bytes.extend_from_slice(&b);
		}
		if let Some(aid) = self.asset_id {
			bytes.extend_from_slice(&aid.to_le_bytes());
		}

		bytes
	}

	/// Deserializes from bytes
	pub fn from_bytes(bytes: &[u8]) -> Result<Self, MemoError> {
		if bytes.is_empty() {
			return Err(MemoError::InvalidDisclosureData);
		}

		let flags = bytes[0];
		let mut offset = 1;

		// Parse value if present
		let value = if (flags & 0b0001) != 0 {
			if bytes.len() < offset + 8 {
				return Err(MemoError::InvalidDisclosureData);
			}
			let v = u64::from_le_bytes(
				bytes[offset..offset + 8]
					.try_into()
					.map_err(|_| MemoError::InvalidDisclosureData)?,
			);
			offset += 8;
			Some(v)
		} else {
			None
		};

		// Parse owner_pk if present
		let owner_pk = if (flags & 0b0010) != 0 {
			if bytes.len() < offset + 32 {
				return Err(MemoError::InvalidDisclosureData);
			}
			let mut pk = [0u8; 32];
			pk.copy_from_slice(&bytes[offset..offset + 32]);
			offset += 32;
			Some(pk)
		} else {
			None
		};

		// Parse blinding if present
		let blinding = if (flags & 0b0100) != 0 {
			if bytes.len() < offset + 32 {
				return Err(MemoError::InvalidDisclosureData);
			}
			let mut b = [0u8; 32];
			b.copy_from_slice(&bytes[offset..offset + 32]);
			offset += 32;
			Some(b)
		} else {
			None
		};

		// Parse asset_id if present
		let asset_id = if (flags & 0b1000) != 0 {
			if bytes.len() < offset + 4 {
				return Err(MemoError::InvalidDisclosureData);
			}
			let aid = u32::from_le_bytes(
				bytes[offset..offset + 4]
					.try_into()
					.map_err(|_| MemoError::InvalidDisclosureData)?,
			);
			Some(aid)
		} else {
			None
		};

		Ok(Self {
			value,
			owner_pk,
			blinding,
			asset_id,
		})
	}

	/// Validates data consistency
	pub fn validate(&self) -> Result<(), MemoError> {
		// At least one field must be present
		if self.is_empty() {
			return Err(MemoError::InvalidDisclosureData);
		}

		Ok(())
	}
}

impl Default for PartialMemoData {
	fn default() -> Self {
		Self::empty()
	}
}

/// Selective disclosure proof
///
/// Contains Groth16 proof and public signals verified on-chain.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
	all(feature = "parity-scale-codec", feature = "scale-info"),
	derive(Encode, Decode, TypeInfo)
)]
pub struct DisclosureProof {
	/// Groth16 proof (points a, b, c in BN254)
	/// Format: 2*G1 (64 bytes) + 1*G2 (128 bytes) = 192 bytes compressed
	pub proof: Vec<u8>,

	/// Public signals of the circuit (commitment, vk_hash, mask, revealed_owner_hash)
	pub public_signals: DisclosurePublicSignals,

	/// Original mask (for reference and validation)
	pub mask: DisclosureMask,
}

impl DisclosureProof {
	/// Creates new proof
	pub fn new(
		proof: Vec<u8>,
		public_signals: DisclosurePublicSignals,
		mask: DisclosureMask,
	) -> Self {
		Self {
			proof,
			public_signals,
			mask,
		}
	}

	/// Serializes complete proof for on-chain storage
	pub fn to_bytes(&self) -> Vec<u8> {
		let mut bytes = Vec::new();

		// 1. Proof bytes (variable size, prefixed with length)
		let proof_len = self.proof.len() as u16;
		bytes.extend_from_slice(&proof_len.to_le_bytes());
		bytes.extend_from_slice(&self.proof);

		// 2. Public signals
		bytes.extend_from_slice(&self.public_signals.to_bytes());

		// 3. Mask bitmap (1 byte)
		bytes.push(self.mask.to_bitmap());

		bytes
	}

	/// Deserializes proof from bytes
	pub fn from_bytes(bytes: &[u8]) -> Result<Self, MemoError> {
		if bytes.len() < 2 {
			return Err(MemoError::InvalidProof("Proof too short"));
		}

		let mut offset = 0;

		// 1. Parse proof length
		let proof_len = u16::from_le_bytes(
			bytes[offset..offset + 2]
				.try_into()
				.map_err(|_| MemoError::InvalidProof("Invalid proof length"))?,
		) as usize;
		offset += 2;

		// 2. Parse proof bytes
		if bytes.len() < offset + proof_len {
			return Err(MemoError::InvalidProof("Proof bytes truncated"));
		}
		let proof = bytes[offset..offset + proof_len].to_vec();
		offset += proof_len;

		// 3. Parse public signals (76 bytes: 32+8+4+32)
		if bytes.len() < offset + 76 {
			return Err(MemoError::InvalidProof("Public signals truncated"));
		}
		let public_signals = DisclosurePublicSignals::from_bytes(&bytes[offset..offset + 76])?;
		offset += 76;

		// 4. Parse mask bitmap
		if bytes.len() < offset + 1 {
			return Err(MemoError::InvalidProof("Mask bitmap missing"));
		}
		let mask = DisclosureMask::from_bitmap(bytes[offset]);

		Ok(Self {
			proof,
			public_signals,
			mask,
		})
	}

	/// Validates proof consistency before on-chain verification
	pub fn validate(&self) -> Result<(), MemoError> {
		// Validate mask
		self.mask.validate()?;

		// Validate proof not empty
		if self.proof.is_empty() {
			return Err(MemoError::InvalidProof("Proof is empty"));
		}

		// Validate public signals consistency
		self.public_signals.validate(&self.mask)?;

		Ok(())
	}
}

/// Public signals verified on-chain
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
	all(feature = "parity-scale-codec", feature = "scale-info"),
	derive(Encode, Decode, TypeInfo)
)]
pub struct DisclosurePublicSignals {
	/// Commitment of the memo (binds proof to a specific commitment)
	pub commitment: [u8; 32],

	/// Revealed value (value if disclosed, 0 otherwise)
	pub revealed_value: u64,

	/// Revealed asset ID (asset_id if disclosed, 0 otherwise)
	pub revealed_asset_id: u32,

	/// Hash of owner public key (if disclosed), zero otherwise
	pub revealed_owner_hash: [u8; 32],
}

impl DisclosurePublicSignals {
	/// Creates new public signals
	pub fn new(
		commitment: [u8; 32],
		revealed_value: u64,
		revealed_asset_id: u32,
		revealed_owner_hash: [u8; 32],
	) -> Self {
		Self {
			commitment,
			revealed_value,
			revealed_asset_id,
			revealed_owner_hash,
		}
	}

	/// Serializes public signals (76 bytes)
	pub fn to_bytes(&self) -> Vec<u8> {
		let mut bytes = Vec::with_capacity(76);
		bytes.extend_from_slice(&self.commitment);
		bytes.extend_from_slice(&self.revealed_value.to_le_bytes());
		bytes.extend_from_slice(&self.revealed_asset_id.to_le_bytes());
		bytes.extend_from_slice(&self.revealed_owner_hash);
		bytes
	}

	/// Deserializes public signals
	pub fn from_bytes(bytes: &[u8]) -> Result<Self, MemoError> {
		if bytes.len() != 76 {
			return Err(MemoError::InvalidProof("Invalid public signals length"));
		}

		let mut commitment = [0u8; 32];
		commitment.copy_from_slice(&bytes[0..32]);

		let revealed_value = u64::from_le_bytes(
			bytes[32..40]
				.try_into()
				.map_err(|_| MemoError::InvalidProof("Invalid revealed_value"))?,
		);

		let revealed_asset_id = u32::from_le_bytes(
			bytes[40..44]
				.try_into()
				.map_err(|_| MemoError::InvalidProof("Invalid revealed_asset_id"))?,
		);

		let mut revealed_owner_hash = [0u8; 32];
		revealed_owner_hash.copy_from_slice(&bytes[44..76]);

		Ok(Self {
			commitment,
			revealed_value,
			revealed_asset_id,
			revealed_owner_hash,
		})
	}

	/// Validates consistency with the mask
	pub fn validate(&self, mask: &DisclosureMask) -> Result<(), MemoError> {
		// If value revealed, it must be non-zero (or we can't tell)
		if mask.disclose_value && self.revealed_value == 0 {
			// Note: This could also happen if the real value is 0.
		}

		// If owner NOT revealed, hash must be zero
		if !mask.disclose_owner && self.revealed_owner_hash != [0u8; 32] {
			return Err(MemoError::InvalidProof(
				"Owner hash should be zero when owner not disclosed",
			));
		}

		Ok(())
	}

	/// Helper for prover logic
	pub fn disclose_value(&self) -> bool {
		self.revealed_value != 0
	}

	/// Helper for prover logic
	pub fn disclose_asset_id(&self) -> bool {
		self.revealed_asset_id != 0
	}

	/// Helper for prover logic
	pub fn disclose_owner(&self) -> bool {
		self.revealed_owner_hash != [0u8; 32]
	}
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
	use super::*;
	use crate::domain::entities::types::MemoData;
	extern crate alloc;
	use alloc::vec;

	// ===== DisclosureMask Tests =====

	#[test]
	fn test_mask_all() {
		let mask = DisclosureMask::all();
		assert!(mask.disclose_value);
		assert!(mask.disclose_owner);
		assert!(!mask.disclose_blinding); // Never reveal
		assert!(mask.disclose_asset_id);
	}

	#[test]
	fn test_mask_only_value() {
		let mask = DisclosureMask::only_value();
		assert!(mask.disclose_value);
		assert!(!mask.disclose_owner);
		assert!(!mask.disclose_blinding);
		assert!(!mask.disclose_asset_id);
	}

	#[test]
	fn test_mask_value_and_asset() {
		let mask = DisclosureMask::value_and_asset();
		assert!(mask.disclose_value);
		assert!(!mask.disclose_owner);
		assert!(!mask.disclose_blinding);
		assert!(mask.disclose_asset_id);
	}

	#[test]
	fn test_mask_none() {
		let mask = DisclosureMask::none();
		assert!(!mask.disclose_value);
		assert!(!mask.disclose_owner);
		assert!(!mask.disclose_blinding);
		assert!(!mask.disclose_asset_id);
	}

	#[test]
	fn test_mask_to_bitmap() {
		assert_eq!(DisclosureMask::only_value().to_bitmap(), 0b0001);
		assert_eq!(DisclosureMask::value_and_asset().to_bitmap(), 0b1001);
		assert_eq!(DisclosureMask::all().to_bitmap(), 0b1011);
		assert_eq!(DisclosureMask::none().to_bitmap(), 0b0000);
	}

	#[test]
	fn test_mask_from_bitmap() {
		let mask = DisclosureMask::from_bitmap(0b1001);
		assert!(mask.disclose_value);
		assert!(!mask.disclose_owner);
		assert!(!mask.disclose_blinding);
		assert!(mask.disclose_asset_id);
	}

	#[test]
	fn test_mask_bitmap_roundtrip() {
		let original = DisclosureMask::value_and_asset();
		let bitmap = original.to_bitmap();
		let recovered = DisclosureMask::from_bitmap(bitmap);
		assert_eq!(original, recovered);
	}

	#[test]
	fn test_mask_validate_ok() {
		assert!(DisclosureMask::only_value().validate().is_ok());
		assert!(DisclosureMask::all().validate().is_ok());
		assert!(DisclosureMask::value_and_asset().validate().is_ok());
	}

	#[test]
	fn test_mask_validate_blinding_error() {
		let mask = DisclosureMask {
			disclose_value: true,
			disclose_owner: false,
			disclose_blinding: true, // Invalid!
			disclose_asset_id: false,
		};
		assert!(mask.validate().is_err());
	}

	#[test]
	fn test_mask_validate_empty_error() {
		let mask = DisclosureMask::none();
		assert!(mask.validate().is_err());
	}

	#[test]
	fn test_mask_disclosed_field_count() {
		assert_eq!(DisclosureMask::only_value().disclosed_field_count(), 1);
		assert_eq!(DisclosureMask::value_and_asset().disclosed_field_count(), 2);
		assert_eq!(DisclosureMask::all().disclosed_field_count(), 3);
		assert_eq!(DisclosureMask::none().disclosed_field_count(), 0);
	}

	#[test]
	fn test_mask_clone() {
		let mask1 = DisclosureMask::only_value();
		let mask2 = mask1.clone();
		assert_eq!(mask1, mask2);
	}

	// ===== PartialMemoData Tests =====

	#[test]
	fn test_partial_empty() {
		let partial = PartialMemoData::empty();
		assert!(partial.is_empty());
		assert_eq!(partial.value, None);
		assert_eq!(partial.owner_pk, None);
		assert_eq!(partial.blinding, None);
		assert_eq!(partial.asset_id, None);
	}

	#[test]
	fn test_partial_from_disclosure_value_only() {
		let memo = MemoData::new(1000, [1u8; 32], [2u8; 32], 0);
		let mask = DisclosureMask::only_value();
		let partial = PartialMemoData::from_disclosure(&memo, &mask);

		assert_eq!(partial.value, Some(1000));
		assert_eq!(partial.owner_pk, None);
		assert_eq!(partial.blinding, None);
		assert_eq!(partial.asset_id, None);
	}

	#[test]
	fn test_partial_from_disclosure_all() {
		let memo = MemoData::new(500, [5u8; 32], [10u8; 32], 2);
		let mask = DisclosureMask::all();
		let partial = PartialMemoData::from_disclosure(&memo, &mask);

		assert_eq!(partial.value, Some(500));
		assert_eq!(partial.owner_pk, Some([5u8; 32]));
		assert_eq!(partial.blinding, None); // Never disclosed by all()
		assert_eq!(partial.asset_id, Some(2));
	}

	#[test]
	fn test_partial_is_empty() {
		let empty = PartialMemoData::empty();
		assert!(empty.is_empty());

		let not_empty = PartialMemoData {
			value: Some(100),
			owner_pk: None,
			blinding: None,
			asset_id: None,
		};
		assert!(!not_empty.is_empty());
	}

	#[test]
	fn test_partial_to_bytes_value_only() {
		let partial = PartialMemoData {
			value: Some(1000),
			owner_pk: None,
			blinding: None,
			asset_id: None,
		};

		let bytes = partial.to_bytes();
		assert_eq!(bytes[0], 0b0001); // Only value flag
		assert_eq!(bytes.len(), 9); // 1 flag + 8 value
	}

	#[test]
	fn test_partial_to_bytes_all() {
		let partial = PartialMemoData {
			value: Some(500),
			owner_pk: Some([5u8; 32]),
			blinding: Some([10u8; 32]),
			asset_id: Some(2),
		};

		let bytes = partial.to_bytes();
		assert_eq!(bytes[0], 0b1111); // All flags
		assert_eq!(bytes.len(), 77); // 1 + 8 + 32 + 32 + 4
	}

	#[test]
	fn test_partial_from_bytes_value_only() {
		let original = PartialMemoData {
			value: Some(1000),
			owner_pk: None,
			blinding: None,
			asset_id: None,
		};

		let bytes = original.to_bytes();
		let recovered = PartialMemoData::from_bytes(&bytes).unwrap();

		assert_eq!(recovered, original);
	}

	#[test]
	fn test_partial_from_bytes_all() {
		let original = PartialMemoData {
			value: Some(500),
			owner_pk: Some([5u8; 32]),
			blinding: Some([10u8; 32]),
			asset_id: Some(2),
		};

		let bytes = original.to_bytes();
		let recovered = PartialMemoData::from_bytes(&bytes).unwrap();

		assert_eq!(recovered, original);
	}

	#[test]
	fn test_partial_from_bytes_empty_error() {
		let result = PartialMemoData::from_bytes(&[]);
		assert!(result.is_err());
	}

	#[test]
	fn test_partial_from_bytes_truncated_error() {
		let bytes = vec![0b0001]; // Flag says value present, but no value bytes
		let result = PartialMemoData::from_bytes(&bytes);
		assert!(result.is_err());
	}

	#[test]
	fn test_partial_validate_ok() {
		let partial = PartialMemoData {
			value: Some(100),
			owner_pk: None,
			blinding: None,
			asset_id: None,
		};
		assert!(partial.validate().is_ok());
	}

	#[test]
	fn test_partial_validate_empty_error() {
		let partial = PartialMemoData::empty();
		assert!(partial.validate().is_err());
	}

	#[test]
	fn test_partial_default() {
		let partial = PartialMemoData::default();
		assert!(partial.is_empty());
	}

	// ===== DisclosureProof Tests =====

	#[test]
	fn test_proof_new() {
		let proof_bytes = vec![1u8; 192];
		let signals = DisclosurePublicSignals::new([0u8; 32], 1000, 0, [0u8; 32]);
		let mask = DisclosureMask::only_value();

		let proof = DisclosureProof::new(proof_bytes.clone(), signals.clone(), mask.clone());

		assert_eq!(proof.proof, proof_bytes);
		assert_eq!(proof.public_signals, signals);
		assert_eq!(proof.mask, mask);
	}

	#[test]
	fn test_proof_to_bytes() {
		let proof_bytes = vec![1u8; 192];
		let signals = DisclosurePublicSignals::new([0u8; 32], 1000, 0, [0u8; 32]);
		let mask = DisclosureMask::only_value();
		let proof = DisclosureProof::new(proof_bytes, signals, mask);

		let bytes = proof.to_bytes();
		assert!(bytes.len() > 100); // Should have proof + signals + mask
	}

	#[test]
	fn test_proof_from_bytes_roundtrip() {
		let proof_bytes = vec![2u8; 192];
		let signals = DisclosurePublicSignals::new([3u8; 32], 500, 1, [0u8; 32]);
		let mask = DisclosureMask::value_and_asset();
		let original = DisclosureProof::new(proof_bytes, signals, mask);

		let bytes = original.to_bytes();
		let recovered = DisclosureProof::from_bytes(&bytes).unwrap();

		assert_eq!(recovered.proof, original.proof);
		assert_eq!(recovered.public_signals, original.public_signals);
		assert_eq!(recovered.mask, original.mask);
	}

	#[test]
	fn test_proof_from_bytes_too_short() {
		let result = DisclosureProof::from_bytes(&[0u8]);
		assert!(result.is_err());
	}

	#[test]
	fn test_proof_validate_ok() {
		let proof_bytes = vec![1u8; 192];
		let signals = DisclosurePublicSignals::new([0u8; 32], 1000, 0, [0u8; 32]);
		let mask = DisclosureMask::only_value();
		let proof = DisclosureProof::new(proof_bytes, signals, mask);

		assert!(proof.validate().is_ok());
	}

	#[test]
	fn test_proof_validate_empty_proof_error() {
		let signals = DisclosurePublicSignals::new([0u8; 32], 1000, 0, [0u8; 32]);
		let mask = DisclosureMask::only_value();
		let proof = DisclosureProof::new(vec![], signals, mask);

		assert!(proof.validate().is_err());
	}

	#[test]
	fn test_proof_validate_invalid_mask() {
		let proof_bytes = vec![1u8; 192];
		let signals = DisclosurePublicSignals::new([0u8; 32], 0, 0, [0u8; 32]);
		let mask = DisclosureMask::none(); // Invalid: reveals nothing
		let proof = DisclosureProof::new(proof_bytes, signals, mask);

		assert!(proof.validate().is_err());
	}

	#[test]
	fn test_proof_clone() {
		let proof_bytes = vec![1u8; 192];
		let signals = DisclosurePublicSignals::new([0u8; 32], 1000, 0, [0u8; 32]);
		let mask = DisclosureMask::only_value();
		let proof1 = DisclosureProof::new(proof_bytes, signals, mask);
		let proof2 = proof1.clone();

		assert_eq!(proof1, proof2);
	}

	// ===== DisclosurePublicSignals Tests =====

	#[test]
	fn test_signals_new() {
		let signals = DisclosurePublicSignals::new([1u8; 32], 1000, 5, [2u8; 32]);

		assert_eq!(signals.commitment, [1u8; 32]);
		assert_eq!(signals.revealed_value, 1000);
		assert_eq!(signals.revealed_asset_id, 5);
		assert_eq!(signals.revealed_owner_hash, [2u8; 32]);
	}

	#[test]
	fn test_signals_to_bytes() {
		let signals = DisclosurePublicSignals::new([1u8; 32], 500, 2, [3u8; 32]);
		let bytes = signals.to_bytes();

		assert_eq!(bytes.len(), 76); // Fixed size
	}

	#[test]
	fn test_signals_from_bytes_roundtrip() {
		let original = DisclosurePublicSignals::new([10u8; 32], 1234, 56, [20u8; 32]);
		let bytes = original.to_bytes();
		let recovered = DisclosurePublicSignals::from_bytes(&bytes).unwrap();

		assert_eq!(recovered, original);
	}

	#[test]
	fn test_signals_from_bytes_invalid_length() {
		let result = DisclosurePublicSignals::from_bytes(&[0u8; 50]);
		assert!(result.is_err());
	}

	#[test]
	fn test_signals_validate_ok() {
		let signals = DisclosurePublicSignals::new([0u8; 32], 1000, 0, [0u8; 32]);
		let mask = DisclosureMask::only_value();
		assert!(signals.validate(&mask).is_ok());
	}

	#[test]
	fn test_signals_validate_owner_hash_error() {
		let signals = DisclosurePublicSignals::new([0u8; 32], 1000, 0, [1u8; 32]); // Non-zero hash
		let mask = DisclosureMask::only_value(); // Owner not disclosed
		assert!(signals.validate(&mask).is_err());
	}

	#[test]
	fn test_signals_disclose_value() {
		let signals1 = DisclosurePublicSignals::new([0u8; 32], 1000, 0, [0u8; 32]);
		assert!(signals1.disclose_value());

		let signals2 = DisclosurePublicSignals::new([0u8; 32], 0, 0, [0u8; 32]);
		assert!(!signals2.disclose_value());
	}

	#[test]
	fn test_signals_disclose_asset_id() {
		let signals1 = DisclosurePublicSignals::new([0u8; 32], 0, 5, [0u8; 32]);
		assert!(signals1.disclose_asset_id());

		let signals2 = DisclosurePublicSignals::new([0u8; 32], 0, 0, [0u8; 32]);
		assert!(!signals2.disclose_asset_id());
	}

	#[test]
	fn test_signals_disclose_owner() {
		let signals1 = DisclosurePublicSignals::new([0u8; 32], 0, 0, [1u8; 32]);
		assert!(signals1.disclose_owner());

		let signals2 = DisclosurePublicSignals::new([0u8; 32], 0, 0, [0u8; 32]);
		assert!(!signals2.disclose_owner());
	}

	#[test]
	fn test_signals_clone() {
		let signals1 = DisclosurePublicSignals::new([5u8; 32], 999, 7, [10u8; 32]);
		let signals2 = signals1.clone();
		assert_eq!(signals1, signals2);
	}

	// ===== Integration Tests =====

	#[test]
	fn test_full_disclosure_flow() {
		let memo = MemoData::new(1000, [1u8; 32], [2u8; 32], 0);
		let mask = DisclosureMask::only_value();

		// Create partial data
		let partial = PartialMemoData::from_disclosure(&memo, &mask);
		assert_eq!(partial.value, Some(1000));
		assert!(partial.owner_pk.is_none());

		// Serialize and deserialize
		let bytes = partial.to_bytes();
		let recovered = PartialMemoData::from_bytes(&bytes).unwrap();
		assert_eq!(recovered, partial);
	}

	#[test]
	fn test_mask_bitmap_all_combinations() {
		for i in 0..16u8 {
			let mask = DisclosureMask::from_bitmap(i);
			let bitmap = mask.to_bitmap();
			assert_eq!(bitmap, i);
		}
	}

	#[test]
	fn test_partial_memo_different_masks() {
		let memo = MemoData::new(500, [10u8; 32], [20u8; 32], 3);

		let partial1 = PartialMemoData::from_disclosure(&memo, &DisclosureMask::only_value());
		let partial2 = PartialMemoData::from_disclosure(&memo, &DisclosureMask::value_and_asset());
		let partial3 = PartialMemoData::from_disclosure(&memo, &DisclosureMask::all());

		assert_eq!(partial1.value, Some(500));
		assert_eq!(partial1.asset_id, None);

		assert_eq!(partial2.value, Some(500));
		assert_eq!(partial2.asset_id, Some(3));

		assert_eq!(partial3.value, Some(500));
		assert_eq!(partial3.owner_pk, Some([10u8; 32]));
		assert_eq!(partial3.asset_id, Some(3));
	}
}
