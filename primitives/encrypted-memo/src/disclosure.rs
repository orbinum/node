//! Selective disclosure types for Orbinum ZK proofs.
//!
//! These types model the output of the disclosure circuit:
//! a Groth16 proof that selectively reveals fields from an encrypted note
//! without exposing the full plaintext.
//!
//! # Types
//!
//! - [`DisclosureMask`] — which fields to reveal
//! - [`DisclosurePublicSignals`] — on-chain verified disclosure output (76 bytes)
//! - [`DisclosureProof`] — proof + signals + mask bundled for submission
//! - [`PartialMemoData`] — client-side partially revealed memo fields

use alloc::vec::Vec;

use crate::memo::MemoError;

#[cfg(all(feature = "parity-scale-codec", feature = "scale-info"))]
use parity_scale_codec::{Decode, Encode};
#[cfg(all(feature = "parity-scale-codec", feature = "scale-info"))]
use scale_info::TypeInfo;

// ─── DisclosureMask ───────────────────────────────────────────────────────────

/// Controls which note fields are revealed in a selective disclosure proof.
///
/// `disclose_blinding` MUST always be `false` to preserve commitment privacy.
///
/// # Memo v2 (future)
/// `counterparty_pk` disclosure is planned for a future circuit update. When the
/// disclosure circuit is recompiled with the new field, add `disclose_counterparty: bool`
/// here and update `to_bitmap()` / `from_bitmap()` to expose bit 4.
// TODO(memo-v2): add disclose_counterparty field when disclosure circuit is updated
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
	all(feature = "parity-scale-codec", feature = "scale-info"),
	derive(Encode, Decode, TypeInfo)
)]
pub struct DisclosureMask {
	/// Reveal the token amount.
	pub disclose_value: bool,
	/// Reveal the owner public key (or its hash).
	pub disclose_owner: bool,
	/// Reveal the blinding factor — MUST ALWAYS BE FALSE.
	pub disclose_blinding: bool,
	/// Reveal the asset ID.
	pub disclose_asset_id: bool,
	// TODO(memo-v2): add `pub disclose_counterparty: bool` when disclosure circuit is updated
}

impl DisclosureMask {
	/// Reveals all fields except `blinding`.
	pub fn all() -> Self {
		Self {
			disclose_value: true,
			disclose_owner: true,
			disclose_blinding: false,
			disclose_asset_id: true,
		}
	}

	/// Reveals only the token amount.
	pub fn only_value() -> Self {
		Self {
			disclose_value: true,
			disclose_owner: false,
			disclose_blinding: false,
			disclose_asset_id: false,
		}
	}

	/// Reveals the token amount and asset ID.
	pub fn value_and_asset() -> Self {
		Self {
			disclose_value: true,
			disclose_owner: false,
			disclose_blinding: false,
			disclose_asset_id: true,
		}
	}

	/// Reveals nothing (invalid for proof generation — useful for custom mask construction).
	pub fn none() -> Self {
		Self {
			disclose_value: false,
			disclose_owner: false,
			disclose_blinding: false,
			disclose_asset_id: false,
		}
	}

	/// Converts to a 4-bit bitmap. Bit layout (LSB first): `[value | owner | blinding | asset_id]`
	pub fn to_bitmap(&self) -> u8 {
		(self.disclose_value as u8)
			| (self.disclose_owner as u8) << 1
			| (self.disclose_blinding as u8) << 2
			| (self.disclose_asset_id as u8) << 3
	}

	/// Creates from a 4-bit bitmap (inverse of [`to_bitmap`]).
	pub fn from_bitmap(bits: u8) -> Self {
		Self {
			disclose_value: (bits & 0b0001) != 0,
			disclose_owner: (bits & 0b0010) != 0,
			disclose_blinding: (bits & 0b0100) != 0,
			disclose_asset_id: (bits & 0b1000) != 0,
		}
	}

	/// Validates the mask. Fails if blinding is set or no field is selected.
	pub fn validate(&self) -> Result<(), MemoError> {
		if self.disclose_blinding {
			return Err(MemoError::InvalidDisclosureMask(
				"Cannot disclose blinding factor — compromises commitment privacy",
			));
		}
		if !self.disclose_value && !self.disclose_owner && !self.disclose_asset_id {
			return Err(MemoError::InvalidDisclosureMask(
				"Must disclose at least one field (value, owner, or asset_id)",
			));
		}
		Ok(())
	}

	/// Returns the number of fields that will be revealed.
	pub fn disclosed_field_count(&self) -> usize {
		[
			self.disclose_value,
			self.disclose_owner,
			self.disclose_blinding,
			self.disclose_asset_id,
		]
		.iter()
		.filter(|&&v| v)
		.count()
	}
}

// ─── DisclosurePublicSignals ──────────────────────────────────────────────────

/// Public signals produced by the disclosure circuit and verified on-chain.
///
/// Fixed serialized size: 76 bytes
/// `commitment(32) | value(8) | asset_id(4) | owner_hash(32)`
///
/// # Memo v2 (future)
/// When the disclosure circuit is updated to support `counterparty_pk`, this struct will
/// gain a `revealed_counterparty_hash: [u8; 32]` field and the serialized size will grow
/// to 108 bytes: `commitment(32) | value(8) | asset_id(4) | owner_hash(32) | counterparty_hash(32)`.
// TODO(memo-v2): add revealed_counterparty_hash field and update to_bytes/from_bytes to 108 bytes
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
	all(feature = "parity-scale-codec", feature = "scale-info"),
	derive(Encode, Decode, TypeInfo)
)]
pub struct DisclosurePublicSignals {
	/// Commitment binding the proof to a specific note.
	pub commitment: [u8; 32],
	/// Revealed token amount (0 when not disclosed).
	pub revealed_value: u64,
	/// Revealed asset ID (0 when not disclosed).
	pub revealed_asset_id: u32,
	/// Hash of owner public key (zero when owner not disclosed).
	pub revealed_owner_hash: [u8; 32],
}

impl DisclosurePublicSignals {
	/// Creates new public signals.
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

	/// Serializes to exactly 76 bytes.
	pub fn to_bytes(&self) -> Vec<u8> {
		let mut bytes = Vec::with_capacity(76);
		bytes.extend_from_slice(&self.commitment);
		bytes.extend_from_slice(&self.revealed_value.to_le_bytes());
		bytes.extend_from_slice(&self.revealed_asset_id.to_le_bytes());
		bytes.extend_from_slice(&self.revealed_owner_hash);
		bytes
	}

	/// Deserializes from exactly 76 bytes.
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

	/// Validates consistency against the disclosure mask.
	///
	/// If the owner is NOT disclosed, `revealed_owner_hash` must be zero.
	pub fn validate(&self, mask: &DisclosureMask) -> Result<(), MemoError> {
		if !mask.disclose_owner && self.revealed_owner_hash != [0u8; 32] {
			return Err(MemoError::InvalidProof(
				"revealed_owner_hash must be zero when owner is not disclosed",
			));
		}
		Ok(())
	}
}

// ─── DisclosureProof ──────────────────────────────────────────────────────────

/// Selective disclosure proof ready for on-chain verification.
///
/// Serialized layout: `proof_len(2) || proof(n) || public_signals(76) || mask_bitmap(1)`
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
	all(feature = "parity-scale-codec", feature = "scale-info"),
	derive(Encode, Decode, TypeInfo)
)]
pub struct DisclosureProof {
	/// Raw Groth16 proof bytes (BN254: up to 192 bytes compressed).
	pub proof: Vec<u8>,
	/// Public signals verified on-chain.
	pub public_signals: DisclosurePublicSignals,
	/// Disclosure mask used when generating this proof.
	pub mask: DisclosureMask,
}

impl DisclosureProof {
	/// Creates a new disclosure proof.
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

	/// Serializes for on-chain storage: `proof_len(2) || proof(n) || signals(76) || mask_bitmap(1)`
	pub fn to_bytes(&self) -> Vec<u8> {
		let mut bytes = Vec::new();
		bytes.extend_from_slice(&(self.proof.len() as u16).to_le_bytes());
		bytes.extend_from_slice(&self.proof);
		bytes.extend_from_slice(&self.public_signals.to_bytes());
		bytes.push(self.mask.to_bitmap());
		bytes
	}

	/// Deserializes from bytes.
	pub fn from_bytes(bytes: &[u8]) -> Result<Self, MemoError> {
		if bytes.len() < 2 {
			return Err(MemoError::InvalidProof("Proof too short"));
		}
		let mut off = 0;
		let proof_len = u16::from_le_bytes(
			bytes[off..off + 2]
				.try_into()
				.map_err(|_| MemoError::InvalidProof("Invalid proof length"))?,
		) as usize;
		off += 2;
		if bytes.len() < off + proof_len {
			return Err(MemoError::InvalidProof("Proof bytes truncated"));
		}
		let proof = bytes[off..off + proof_len].to_vec();
		off += proof_len;
		if bytes.len() < off + 76 {
			return Err(MemoError::InvalidProof("Public signals truncated"));
		}
		let public_signals = DisclosurePublicSignals::from_bytes(&bytes[off..off + 76])?;
		off += 76;
		if bytes.len() < off + 1 {
			return Err(MemoError::InvalidProof("Mask bitmap missing"));
		}
		let mask = DisclosureMask::from_bitmap(bytes[off]);
		Ok(Self {
			proof,
			public_signals,
			mask,
		})
	}

	/// Validates proof consistency before on-chain submission.
	pub fn validate(&self) -> Result<(), MemoError> {
		self.mask.validate()?;
		if self.proof.is_empty() {
			return Err(MemoError::InvalidProof("Proof is empty"));
		}
		self.public_signals.validate(&self.mask)?;
		Ok(())
	}
}

// ─── PartialMemoData ──────────────────────────────────────────────────────────

/// Partially revealed memo data. Only disclosed fields are `Some`.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
	all(feature = "parity-scale-codec", feature = "scale-info"),
	derive(Encode, Decode, TypeInfo)
)]
pub struct PartialMemoData {
	/// Revealed token amount (`None` when not disclosed).
	pub value: Option<u128>,
	/// Revealed owner public key (`None` when not disclosed).
	pub owner_pk: Option<[u8; 32]>,
	/// Revealed blinding factor — should always be `None`.
	pub blinding: Option<[u8; 32]>,
	/// Revealed asset ID (`None` when not disclosed).
	pub asset_id: Option<u32>,
}

impl PartialMemoData {
	/// Creates empty partial memo (nothing revealed).
	pub fn empty() -> Self {
		Self {
			value: None,
			owner_pk: None,
			blinding: None,
			asset_id: None,
		}
	}

	/// Applies a disclosure mask to full memo data.
	pub fn from_disclosure(memo: &crate::memo::MemoData, mask: &DisclosureMask) -> Self {
		Self {
			value: mask.disclose_value.then_some(memo.value),
			owner_pk: mask.disclose_owner.then_some(memo.owner_pk),
			blinding: mask.disclose_blinding.then_some(memo.blinding),
			asset_id: mask.disclose_asset_id.then_some(memo.asset_id),
		}
	}

	/// Returns `true` when no fields are revealed.
	pub fn is_empty(&self) -> bool {
		self.value.is_none()
			&& self.owner_pk.is_none()
			&& self.blinding.is_none()
			&& self.asset_id.is_none()
	}

	/// Serializes: `flags(1) || [optional fields...]`
	pub fn to_bytes(&self) -> Vec<u8> {
		let mut bytes = Vec::new();
		let flags = (self.value.is_some() as u8)
			| (self.owner_pk.is_some() as u8) << 1
			| (self.blinding.is_some() as u8) << 2
			| (self.asset_id.is_some() as u8) << 3;
		bytes.push(flags);
		if let Some(v) = self.value {
			bytes.extend_from_slice(&v.to_le_bytes());
		}
		if let Some(pk) = self.owner_pk {
			bytes.extend_from_slice(&pk);
		}
		if let Some(b) = self.blinding {
			bytes.extend_from_slice(&b);
		}
		if let Some(id) = self.asset_id {
			bytes.extend_from_slice(&id.to_le_bytes());
		}
		bytes
	}

	/// Deserializes from bytes produced by [`to_bytes`].
	pub fn from_bytes(bytes: &[u8]) -> Result<Self, MemoError> {
		if bytes.is_empty() {
			return Err(MemoError::InvalidDisclosureData);
		}
		let flags = bytes[0];
		let mut off = 1;

		let value = if (flags & 0b0001) != 0 {
			if bytes.len() < off + 16 {
				return Err(MemoError::InvalidDisclosureData);
			}
			let v = u128::from_le_bytes(
				bytes[off..off + 16]
					.try_into()
					.map_err(|_| MemoError::InvalidDisclosureData)?,
			);
			off += 16;
			Some(v)
		} else {
			None
		};

		let owner_pk = if (flags & 0b0010) != 0 {
			if bytes.len() < off + 32 {
				return Err(MemoError::InvalidDisclosureData);
			}
			let mut pk = [0u8; 32];
			pk.copy_from_slice(&bytes[off..off + 32]);
			off += 32;
			Some(pk)
		} else {
			None
		};

		let blinding = if (flags & 0b0100) != 0 {
			if bytes.len() < off + 32 {
				return Err(MemoError::InvalidDisclosureData);
			}
			let mut b = [0u8; 32];
			b.copy_from_slice(&bytes[off..off + 32]);
			off += 32;
			Some(b)
		} else {
			None
		};

		let asset_id = if (flags & 0b1000) != 0 {
			if bytes.len() < off + 4 {
				return Err(MemoError::InvalidDisclosureData);
			}
			let id = u32::from_le_bytes(
				bytes[off..off + 4]
					.try_into()
					.map_err(|_| MemoError::InvalidDisclosureData)?,
			);
			Some(id)
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
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
	use super::*;
	use crate::memo::MemoData;

	fn sample_signals() -> DisclosurePublicSignals {
		DisclosurePublicSignals::new([1u8; 32], 500, 3, [2u8; 32])
	}

	fn valid_mask() -> DisclosureMask {
		DisclosureMask::all()
	}

	// ── DisclosureMask ────────────────────────────────────────────────────────

	#[test]
	fn mask_bitmap_roundtrip() {
		for bits in 0u8..=15 {
			assert_eq!(DisclosureMask::from_bitmap(bits).to_bitmap(), bits);
		}
	}

	#[test]
	fn mask_all_excludes_blinding() {
		let m = DisclosureMask::all();
		assert!(m.disclose_value && m.disclose_owner && m.disclose_asset_id);
		assert!(!m.disclose_blinding);
	}

	#[test]
	fn mask_validate_rejects_blinding() {
		let m = DisclosureMask {
			disclose_value: true,
			disclose_owner: false,
			disclose_blinding: true,
			disclose_asset_id: false,
		};
		assert!(m.validate().is_err());
	}

	#[test]
	fn mask_validate_rejects_all_false() {
		assert!(DisclosureMask::none().validate().is_err());
	}

	#[test]
	fn mask_validate_ok_with_one_field() {
		assert!(DisclosureMask::only_value().validate().is_ok());
	}

	#[test]
	fn mask_disclosed_field_count() {
		assert_eq!(DisclosureMask::all().disclosed_field_count(), 3);
		assert_eq!(DisclosureMask::only_value().disclosed_field_count(), 1);
		assert_eq!(DisclosureMask::none().disclosed_field_count(), 0);
	}

	// ── DisclosurePublicSignals ───────────────────────────────────────────────

	#[test]
	fn signals_roundtrip() {
		let s = sample_signals();
		assert_eq!(
			DisclosurePublicSignals::from_bytes(&s.to_bytes()).unwrap(),
			s
		);
	}

	#[test]
	fn signals_wrong_length() {
		assert!(DisclosurePublicSignals::from_bytes(&[0u8; 75]).is_err());
		assert!(DisclosurePublicSignals::from_bytes(&[0u8; 77]).is_err());
	}

	#[test]
	fn signals_validate_owner_hash_must_be_zero_when_not_disclosed() {
		let s = DisclosurePublicSignals::new([0u8; 32], 0, 0, [1u8; 32]);
		let mask = DisclosureMask::only_value();
		assert!(s.validate(&mask).is_err());

		let s_ok = DisclosurePublicSignals::new([0u8; 32], 0, 0, [0u8; 32]);
		assert!(s_ok.validate(&mask).is_ok());
	}

	// ── DisclosureProof ───────────────────────────────────────────────────────

	#[test]
	fn proof_roundtrip() {
		let proof = DisclosureProof::new(vec![0xABu8; 128], sample_signals(), valid_mask());
		assert_eq!(
			DisclosureProof::from_bytes(&proof.to_bytes()).unwrap(),
			proof
		);
	}

	#[test]
	fn proof_too_short() {
		assert!(DisclosureProof::from_bytes(&[0u8; 1]).is_err());
	}

	#[test]
	fn proof_validate_rejects_empty_proof_bytes() {
		let p = DisclosureProof::new(vec![], sample_signals(), valid_mask());
		assert!(p.validate().is_err());
	}

	#[test]
	fn proof_validate_ok() {
		let p = DisclosureProof::new(vec![1u8; 64], sample_signals(), valid_mask());
		assert!(p.validate().is_ok());
	}

	// ── PartialMemoData ───────────────────────────────────────────────────────

	#[test]
	fn partial_empty_is_empty() {
		assert!(PartialMemoData::empty().is_empty());
	}

	#[test]
	fn partial_from_disclosure_respects_mask() {
		let memo = MemoData::new(100, [1u8; 32], [2u8; 32], 5, [0u8; 32]);
		let mask = DisclosureMask::only_value();
		let partial = PartialMemoData::from_disclosure(&memo, &mask);
		assert_eq!(partial.value, Some(100));
		assert!(partial.owner_pk.is_none());
		assert!(partial.blinding.is_none());
		assert!(partial.asset_id.is_none());
	}

	#[test]
	fn partial_roundtrip() {
		let memo = MemoData::new(42, [3u8; 32], [4u8; 32], 7, [0u8; 32]);
		let p = PartialMemoData::from_disclosure(&memo, &DisclosureMask::all());
		assert_eq!(PartialMemoData::from_bytes(&p.to_bytes()).unwrap(), p);
	}

	#[test]
	fn partial_from_bytes_empty_input() {
		assert!(PartialMemoData::from_bytes(&[]).is_err());
	}
}
