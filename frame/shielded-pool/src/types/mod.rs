//! Pallet types — every struct, newtype and alias defined by the pallet.
//!
//! Split by domain, but re-exported flat so consumers keep reaching them through
//! `crate::types::*` regardless of which module they live in:
//!
//! - [`ids`] — `Commitment`, `Nullifier`, `AssetId`.
//! - [`note`] — the off-chain shielded note.
//! - [`merkle`] — Merkle path plus the tree-depth constants.
//! - [`memo`] — the fixed-size encrypted memo.
//! - [`asset`] — registered asset metadata.

pub mod asset;
pub mod ids;
pub mod memo;
pub mod merkle;
pub mod note;

pub use asset::AssetMetadata;
pub use ids::{AssetId, Commitment, Nullifier};
pub use memo::{EncryptedMemo, MAX_ENCRYPTED_MEMO_SIZE};
pub use merkle::{DEFAULT_TREE_DEPTH, DefaultMerklePath, MAX_TREE_DEPTH, MerklePath};
pub use note::Note;

/// A 32-byte hash used for Merkle roots, cryptographic hashes and identifiers.
///
/// Deliberately a bare alias, not a newtype: it names a shape, not a role. The
/// roles that must not be interchanged — commitments and nullifiers — get real
/// newtypes in [`ids`].
pub type Hash = [u8; 32];

#[cfg(test)]
mod tests {
	use super::*;
	use frame_support::{BoundedVec, pallet_prelude::ConstU32};

	// ── Commitment ──────────────────────────────────────────────────────────

	#[test]
	fn commitment_new_stores_bytes() {
		let c = Commitment::new([0x01u8; 32]);
		assert_eq!(c.0, [0x01u8; 32]);
	}

	#[test]
	fn commitment_is_valid_non_zero_only() {
		assert!(Commitment::new([0x01u8; 32]).is_valid());
		assert!(!Commitment::new([0x00u8; 32]).is_valid());
	}

	#[test]
	fn commitment_is_zero_checks_all_zero_bytes() {
		assert!(Commitment::new([0x00u8; 32]).is_zero());
		assert!(!Commitment::new([0x01u8; 32]).is_zero());
	}

	#[test]
	fn commitment_as_bytes_and_into_bytes() {
		let bytes = [0x42u8; 32];
		let c = Commitment::new(bytes);
		assert_eq!(c.as_bytes(), &bytes);
		assert_eq!(c.into_bytes(), bytes);
	}

	#[test]
	fn commitment_from_array() {
		let bytes = [0x99u8; 32];
		let c: Commitment = bytes.into();
		assert_eq!(c.0, bytes);
	}

	#[test]
	fn commitment_default_is_zero() {
		assert_eq!(Commitment::default(), Commitment::new([0u8; 32]));
	}

	// ── Nullifier ───────────────────────────────────────────────────────────

	#[test]
	fn nullifier_new_and_accessors() {
		let bytes = [0x10u8; 32];
		let n = Nullifier::new(bytes);
		assert_eq!(n.as_bytes(), &bytes);
		assert_eq!(n.into_bytes(), bytes);
	}

	#[test]
	fn nullifier_validate_non_zero_only() {
		assert!(Nullifier::new([0x01u8; 32]).validate());
		assert!(!Nullifier::new([0x00u8; 32]).validate());
	}

	#[test]
	fn nullifier_from_array() {
		let bytes = [0xAAu8; 32];
		let n: Nullifier = bytes.into();
		assert_eq!(n.0, bytes);
	}

	#[test]
	fn nullifier_default_is_zero() {
		assert_eq!(Nullifier::default(), Nullifier::new([0u8; 32]));
	}

	// ── AssetId ─────────────────────────────────────────────────────────────

	#[test]
	fn asset_id_new_and_inner() {
		let a = AssetId::new(42);
		assert_eq!(a.inner(), 42);
		assert_eq!(a.0, 42);
	}

	#[test]
	fn asset_id_native_is_zero() {
		let n = AssetId::native();
		assert!(n.is_native());
		assert_eq!(n.inner(), 0);
	}

	#[test]
	fn asset_id_not_native_when_nonzero() {
		assert!(!AssetId::new(1).is_native());
		assert!(!AssetId::new(99).is_native());
	}

	#[test]
	fn asset_id_from_and_into_u32() {
		let a: AssetId = 7u32.into();
		assert_eq!(a.inner(), 7);
		let v: u32 = AssetId::new(13).into();
		assert_eq!(v, 13);
	}

	#[test]
	fn asset_id_is_valid_always_true() {
		assert!(AssetId::new(0).is_valid());
		assert!(AssetId::new(u32::MAX).is_valid());
	}

	// ── Note ────────────────────────────────────────────────────────────────

	#[test]
	fn note_new_valid_sets_all_fields() {
		let pk = [0x01u8; 32];
		let bl = [0x02u8; 32];
		let note = Note::new(100, pk, bl).unwrap();
		assert_eq!(note.value(), 100);
		assert_eq!(note.owner_pubkey(), &pk);
		assert_eq!(note.blinding(), &bl);
		assert_eq!(note.asset_id(), 0);
		assert!(note.is_valid());
	}

	#[test]
	fn note_new_zero_value_fails() {
		assert!(Note::new(0, [0x01u8; 32], [0x02u8; 32]).is_err());
	}

	#[test]
	fn note_new_zero_pubkey_fails() {
		assert!(Note::new(100, [0u8; 32], [0x02u8; 32]).is_err());
	}

	#[test]
	fn note_new_zero_blinding_fails() {
		assert!(Note::new(100, [0x01u8; 32], [0u8; 32]).is_err());
	}

	#[test]
	fn note_new_with_asset_sets_asset_id() {
		let note = Note::new_with_asset(50, [0x01u8; 32], [0x02u8; 32], 5).unwrap();
		assert_eq!(note.asset_id(), 5);
		assert_eq!(note.value(), 50);
	}

	#[test]
	fn note_to_bytes_has_correct_length() {
		let note = Note::new(100, [0x01u8; 32], [0x02u8; 32]).unwrap();
		// 16 (value u128) + 4 (asset_id u32) + 32 (pubkey) + 32 (blinding) = 84
		assert_eq!(note.to_bytes().len(), 84);
	}

	#[test]
	fn note_asset_id_serializes_as_4_bytes() {
		// asset_id must be 4 LE bytes to match the circuit's public signal
		// (commitment[0..32] | value[32..40] | asset_id[40..44] | ...).
		let note = Note::new_with_asset(100, [0x01u8; 32], [0x02u8; 32], 0x01020304).unwrap();
		let bytes = note.to_bytes();
		assert_eq!(&bytes[16..20], &0x01020304u32.to_le_bytes());
	}

	// ── MerklePath ──────────────────────────────────────────────────────────

	#[test]
	fn merkle_path_default_all_zeros() {
		let path = DefaultMerklePath::default();
		assert_eq!(path.siblings, [[0u8; 32]; DEFAULT_TREE_DEPTH]);
		assert_eq!(path.indices, [0u8; DEFAULT_TREE_DEPTH]);
	}

	#[test]
	fn merkle_path_generic_depth() {
		let path = MerklePath::<5>::default();
		assert_eq!(path.siblings.len(), 5);
		assert_eq!(path.indices.len(), 5);
	}

	// ── EncryptedMemo ────────────────────────────────────────────────────────

	#[test]
	fn encrypted_memo_new_valid_size() {
		let data = vec![0x01u8; MAX_ENCRYPTED_MEMO_SIZE as usize];
		let memo = EncryptedMemo::new(data).unwrap();
		assert_eq!(memo.len(), MAX_ENCRYPTED_MEMO_SIZE as usize);
	}

	#[test]
	fn encrypted_memo_new_exceeds_max_fails() {
		let data = vec![0x01u8; (MAX_ENCRYPTED_MEMO_SIZE + 1) as usize];
		assert!(EncryptedMemo::new(data).is_err());
	}

	#[test]
	fn encrypted_memo_from_bytes_exact_size() {
		let bytes = [0x03u8; MAX_ENCRYPTED_MEMO_SIZE as usize];
		let memo = EncryptedMemo::from_bytes(&bytes).unwrap();
		assert_eq!(memo.len(), MAX_ENCRYPTED_MEMO_SIZE as usize);
	}

	#[test]
	fn encrypted_memo_from_bytes_wrong_size_fails() {
		assert!(EncryptedMemo::from_bytes(&[0x01u8; 32]).is_err());
		assert!(EncryptedMemo::from_bytes(&[0x01u8; 50]).is_err());
	}

	#[test]
	fn encrypted_memo_nonce_ciphertext_tag_slices() {
		let bytes = [0x01u8; MAX_ENCRYPTED_MEMO_SIZE as usize];
		let memo = EncryptedMemo::from_bytes(&bytes).unwrap();
		assert_eq!(memo.nonce().len(), 12);
		assert_eq!(memo.ciphertext().len(), 120);
		assert_eq!(memo.tag().len(), 16);
		assert_eq!(memo.eph_pk().len(), 32);
	}

	#[test]
	fn encrypted_memo_default_is_empty() {
		let empty = EncryptedMemo::default();
		assert!(empty.is_empty());
		assert!(!empty.is_valid_size());
	}

	#[test]
	fn encrypted_memo_full_is_not_empty() {
		let full = EncryptedMemo::from_bytes(&[0x01u8; MAX_ENCRYPTED_MEMO_SIZE as usize]).unwrap();
		assert!(!full.is_empty());
		assert!(full.is_valid_size());
	}

	// ── AssetMetadata ───────────────────────────────────────────────────────

	#[test]
	fn asset_metadata_new_not_verified_by_default() {
		let name: BoundedVec<u8, ConstU32<64>> = BoundedVec::try_from(b"Test".to_vec()).unwrap();
		let sym: BoundedVec<u8, ConstU32<16>> = BoundedVec::try_from(b"TST".to_vec()).unwrap();
		let meta: AssetMetadata<u64, u64> = AssetMetadata::new(1, name, sym, 18, 0u64, 99u64);
		assert!(!meta.is_verified());
		assert_eq!(meta.id, 1);
		assert_eq!(meta.decimals, 18);
		assert_eq!(meta.contract_address, None);
	}

	#[test]
	fn asset_metadata_verify_unverify() {
		let name: BoundedVec<u8, ConstU32<64>> = BoundedVec::try_from(b"Token".to_vec()).unwrap();
		let sym: BoundedVec<u8, ConstU32<16>> = BoundedVec::try_from(b"TKN".to_vec()).unwrap();
		let mut meta: AssetMetadata<u64, u64> = AssetMetadata::new(2, name, sym, 8, 10u64, 1u64);
		assert!(!meta.is_verified());
		meta.verify();
		assert!(meta.is_verified());
		meta.unverify();
		assert!(!meta.is_verified());
	}

	#[test]
	fn asset_metadata_set_contract_address() {
		let name: BoundedVec<u8, ConstU32<64>> = BoundedVec::try_from(b"ERC20".to_vec()).unwrap();
		let sym: BoundedVec<u8, ConstU32<16>> = BoundedVec::try_from(b"ERC".to_vec()).unwrap();
		let mut meta: AssetMetadata<u64, u64> = AssetMetadata::new(3, name, sym, 18, 0u64, 1u64);
		let addr = [0xABu8; 20];
		meta.set_contract_address(addr);
		assert_eq!(meta.contract_address, Some(addr));
	}
}
