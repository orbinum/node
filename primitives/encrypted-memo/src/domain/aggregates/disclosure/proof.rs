//! Disclosure Proof.
//!
//! Groth16 proof bundled with its public signals and the disclosure mask.

use alloc::vec::Vec;

use crate::domain::entities::error::MemoError;
#[cfg(all(feature = "parity-scale-codec", feature = "scale-info"))]
use parity_scale_codec::{Decode, Encode};
#[cfg(all(feature = "parity-scale-codec", feature = "scale-info"))]
use scale_info::TypeInfo;

use super::{mask::DisclosureMask, signals::DisclosurePublicSignals};

/// Selective disclosure proof ready for on-chain verification.
///
/// Serialized layout:
/// `proof_len(2) || proof(n) || public_signals(76) || mask_bitmap(1)`
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
	all(feature = "parity-scale-codec", feature = "scale-info"),
	derive(Encode, Decode, TypeInfo)
)]
pub struct DisclosureProof {
	/// Raw Groth16 proof bytes (BN254: 2×G1 + 1×G2 = up to 192 bytes compressed)
	pub proof: Vec<u8>,
	/// Public signals verified on-chain
	pub public_signals: DisclosurePublicSignals,
	/// Disclosure mask used when generating this proof
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

	/// Serializes the full proof for on-chain storage.
	pub fn to_bytes(&self) -> Vec<u8> {
		let mut bytes = Vec::new();
		let proof_len = self.proof.len() as u16;
		bytes.extend_from_slice(&proof_len.to_le_bytes());
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

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
	use super::*;
	extern crate alloc;
	use alloc::vec;

	fn make_proof() -> DisclosureProof {
		DisclosureProof::new(
			vec![1u8; 192],
			DisclosurePublicSignals::new([0u8; 32], 1000, 0, [0u8; 32]),
			DisclosureMask::only_value(),
		)
	}

	#[test]
	fn test_proof_roundtrip() {
		let original = make_proof();
		let recovered = DisclosureProof::from_bytes(&original.to_bytes()).unwrap();
		assert_eq!(recovered.proof, original.proof);
		assert_eq!(recovered.public_signals, original.public_signals);
		assert_eq!(recovered.mask, original.mask);
	}

	#[test]
	fn test_proof_validate_ok() {
		assert!(make_proof().validate().is_ok());
	}

	#[test]
	fn test_proof_validate_empty_proof_error() {
		let p = DisclosureProof::new(
			vec![],
			DisclosurePublicSignals::new([0u8; 32], 1000, 0, [0u8; 32]),
			DisclosureMask::only_value(),
		);
		assert!(p.validate().is_err());
	}

	#[test]
	fn test_proof_validate_invalid_mask() {
		let p = DisclosureProof::new(
			vec![1u8; 192],
			DisclosurePublicSignals::new([0u8; 32], 0, 0, [0u8; 32]),
			DisclosureMask::none(),
		);
		assert!(p.validate().is_err());
	}

	#[test]
	fn test_proof_from_bytes_too_short() {
		assert!(DisclosureProof::from_bytes(&[0u8]).is_err());
	}

	#[test]
	fn test_proof_new_fields() {
		let proof_bytes = vec![7u8; 192];
		let signals = DisclosurePublicSignals::new([1u8; 32], 500, 2, [0u8; 32]);
		let mask = DisclosureMask::value_and_asset();
		let p = DisclosureProof::new(proof_bytes.clone(), signals.clone(), mask.clone());
		assert_eq!(p.proof, proof_bytes);
		assert_eq!(p.public_signals, signals);
		assert_eq!(p.mask, mask);
	}

	#[test]
	fn test_proof_to_bytes_minimum_size() {
		// proof_len(2) + proof(192) + signals(76) + mask(1) = 271
		let p = make_proof();
		assert_eq!(p.to_bytes().len(), 2 + 192 + 76 + 1);
	}

	#[test]
	fn test_proof_from_bytes_truncated_proof() {
		// proof_len says 192 bytes but we only provide 10
		let mut bytes = vec![0u8; 2 + 10];
		bytes[0..2].copy_from_slice(&192u16.to_le_bytes());
		assert!(DisclosureProof::from_bytes(&bytes).is_err());
	}

	#[test]
	fn test_proof_from_bytes_truncated_signals() {
		// valid proof but signals are cut short
		let mut bytes = Vec::new();
		let proof = vec![1u8; 192];
		bytes.extend_from_slice(&(192u16).to_le_bytes());
		bytes.extend_from_slice(&proof);
		// append only 40 bytes of signals instead of 76
		bytes.extend_from_slice(&[0u8; 40]);
		assert!(DisclosureProof::from_bytes(&bytes).is_err());
	}

	#[test]
	fn test_proof_clone() {
		let p1 = make_proof();
		let p2 = p1.clone();
		assert_eq!(p1, p2);
	}
}
