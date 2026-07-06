//! Pallet types — all structs, enums, newtypes and type aliases.
//!
//! Concentrates every type defined by `pallet-shielded-pool` in a single file
//! so that any consumer (operations, storage, tests) can reach them with
//! `use crate::types::*`.

// ── Codec & FRAME imports ──────────────────────────────────────────────────
use frame_support::{BoundedVec, pallet_prelude::*};
use parity_scale_codec::{Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};
use scale_info::TypeInfo;
use sp_core::H256;
use sp_runtime::RuntimeDebug;
use sp_std::vec::Vec;

// ════════════════════════════════════════════════════════════════════════════
// Primitive value types
// ════════════════════════════════════════════════════════════════════════════

/// A 32-byte hash used for Merkle roots, cryptographic hashes and identifiers.
pub type Hash = [u8; 32];

// ════════════════════════════════════════════════════════════════════════════
// Commitment
// ════════════════════════════════════════════════════════════════════════════

/// A commitment to a private note.
///
/// Computed as: `Poseidon(value, asset_id, owner_pubkey, blinding)`
#[derive(
	Clone,
	Copy,
	PartialEq,
	Eq,
	Encode,
	Decode,
	DecodeWithMemTracking,
	MaxEncodedLen,
	TypeInfo,
	RuntimeDebug,
	Default
)]
pub struct Commitment(pub [u8; 32]);

impl Commitment {
	pub fn new(bytes: [u8; 32]) -> Self {
		Self(bytes)
	}
	pub fn is_valid(&self) -> bool {
		self.0 != [0u8; 32]
	}
	pub fn is_zero(&self) -> bool {
		self.0 == [0u8; 32]
	}
	pub fn as_bytes(&self) -> &[u8; 32] {
		&self.0
	}
	pub fn into_bytes(self) -> [u8; 32] {
		self.0
	}
}

impl From<[u8; 32]> for Commitment {
	fn from(b: [u8; 32]) -> Self {
		Self::new(b)
	}
}
impl From<H256> for Commitment {
	fn from(h: H256) -> Self {
		Self::new(h.0)
	}
}
impl AsRef<[u8]> for Commitment {
	fn as_ref(&self) -> &[u8] {
		&self.0
	}
}

// ════════════════════════════════════════════════════════════════════════════
// Nullifier
// ════════════════════════════════════════════════════════════════════════════

/// A nullifier identifying a spent note.
///
/// Computed as: `Poseidon(commitment, spending_key)`
#[derive(
	Clone,
	Copy,
	PartialEq,
	Eq,
	Encode,
	Decode,
	DecodeWithMemTracking,
	MaxEncodedLen,
	TypeInfo,
	RuntimeDebug,
	Default
)]
pub struct Nullifier(pub [u8; 32]);

impl Nullifier {
	pub fn new(bytes: [u8; 32]) -> Self {
		Self(bytes)
	}
	pub fn validate(&self) -> bool {
		self.0 != [0u8; 32]
	}
	pub fn as_bytes(&self) -> &[u8; 32] {
		&self.0
	}
	pub fn into_bytes(self) -> [u8; 32] {
		self.0
	}
}

impl From<[u8; 32]> for Nullifier {
	fn from(b: [u8; 32]) -> Self {
		Self::new(b)
	}
}
impl From<H256> for Nullifier {
	fn from(h: H256) -> Self {
		Self::new(h.0)
	}
}
impl AsRef<[u8]> for Nullifier {
	fn as_ref(&self) -> &[u8] {
		&self.0
	}
}

// ════════════════════════════════════════════════════════════════════════════
// AssetId
// ════════════════════════════════════════════════════════════════════════════

/// Identifier for an asset in the shielded pool.
///
/// `0` = native (ORB), `1+` = registered external assets.
#[derive(
	Clone,
	Copy,
	PartialEq,
	Eq,
	Encode,
	Decode,
	MaxEncodedLen,
	TypeInfo,
	RuntimeDebug,
	Default,
	PartialOrd,
	Ord
)]
pub struct AssetId(pub u32);

impl AssetId {
	pub fn new(id: u32) -> Self {
		Self(id)
	}
	pub fn native() -> Self {
		Self(0)
	}
	pub fn is_native(&self) -> bool {
		self.0 == 0
	}
	pub fn inner(&self) -> u32 {
		self.0
	}
	pub fn is_valid(&self) -> bool {
		true
	}
}

impl From<u32> for AssetId {
	fn from(id: u32) -> Self {
		Self(id)
	}
}
impl From<AssetId> for u32 {
	fn from(a: AssetId) -> Self {
		a.0
	}
}

impl core::fmt::Display for AssetId {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		if self.is_native() {
			write!(f, "Native Asset (0)")
		} else {
			write!(f, "Asset {}", self.0)
		}
	}
}

// ════════════════════════════════════════════════════════════════════════════
// Note (off-chain type, used by wallets)
// ════════════════════════════════════════════════════════════════════════════

/// A private note in the shielded pool (UTXO).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Note {
	value: u128,
	owner_pubkey: Hash,
	blinding: Hash,
	asset_id: u32,
}

impl Note {
	pub fn new(value: u128, owner_pubkey: Hash, blinding: Hash) -> Result<Self, &'static str> {
		if value == 0 {
			return Err("Note value cannot be zero");
		}
		if owner_pubkey == [0u8; 32] {
			return Err("Owner public key cannot be zero");
		}
		if blinding == [0u8; 32] {
			return Err("Blinding factor cannot be zero");
		}
		Ok(Self {
			value,
			owner_pubkey,
			blinding,
			asset_id: 0,
		})
	}

	pub fn new_with_asset(
		value: u128,
		owner_pubkey: Hash,
		blinding: Hash,
		asset_id: u32,
	) -> Result<Self, &'static str> {
		let mut note = Self::new(value, owner_pubkey, blinding)?;
		note.asset_id = asset_id;
		Ok(note)
	}

	pub fn value(&self) -> u128 {
		self.value
	}
	pub fn owner_pubkey(&self) -> &Hash {
		&self.owner_pubkey
	}
	pub fn blinding(&self) -> &Hash {
		&self.blinding
	}
	pub fn asset_id(&self) -> u32 {
		self.asset_id
	}

	pub fn to_bytes(&self) -> Vec<u8> {
		let mut bytes = Vec::new();
		bytes.extend_from_slice(&self.value.to_le_bytes());
		bytes.extend_from_slice(&self.asset_id.to_le_bytes());
		bytes.extend_from_slice(&self.owner_pubkey);
		bytes.extend_from_slice(&self.blinding);
		bytes
	}

	pub fn is_valid(&self) -> bool {
		self.value > 0 && self.owner_pubkey != [0u8; 32] && self.blinding != [0u8; 32]
	}
}

// ════════════════════════════════════════════════════════════════════════════
// MerklePath
// ════════════════════════════════════════════════════════════════════════════

pub const DEFAULT_TREE_DEPTH: usize = 20;
pub const MAX_TREE_DEPTH: u32 = 20;

/// A Merkle path (siblings from leaf to root).
#[derive(Clone, Encode, Decode, TypeInfo, MaxEncodedLen, Debug, PartialEq, Eq)]
pub struct MerklePath<const DEPTH: usize> {
	pub siblings: [[u8; 32]; DEPTH],
	pub indices: [u8; DEPTH],
}

impl<const DEPTH: usize> Default for MerklePath<DEPTH> {
	fn default() -> Self {
		Self {
			siblings: [[0u8; 32]; DEPTH],
			indices: [0u8; DEPTH],
		}
	}
}

pub type DefaultMerklePath = MerklePath<DEFAULT_TREE_DEPTH>;

// ════════════════════════════════════════════════════════════════════════════
// EncryptedMemo (concrete, FRAME-compatible — used in storage & extrinsics)
// ════════════════════════════════════════════════════════════════════════════

/// Max encrypted memo size: `nonce(12) + ciphertext(116) + MAC(16) + ephPk(32) = 176`.
pub const MAX_ENCRYPTED_MEMO_SIZE: u32 = 176;

/// Encrypted memo attached to a commitment (ChaCha20-Poly1305).
#[derive(
	Clone,
	PartialEq,
	Eq,
	Encode,
	Decode,
	DecodeWithMemTracking,
	MaxEncodedLen,
	TypeInfo,
	RuntimeDebug,
	Default
)]
pub struct EncryptedMemo(pub BoundedVec<u8, ConstU32<MAX_ENCRYPTED_MEMO_SIZE>>);

impl EncryptedMemo {
	pub fn new(data: Vec<u8>) -> Result<Self, &'static str> {
		BoundedVec::try_from(data)
			.map(Self)
			.map_err(|_| "Memo size exceeds maximum")
	}
	pub fn as_bytes(&self) -> &[u8] {
		&self.0
	}
	pub fn is_valid_size(&self) -> bool {
		!self.0.is_empty()
	}
	pub fn len(&self) -> usize {
		self.0.len()
	}
	pub fn is_empty(&self) -> bool {
		self.0.is_empty()
	}
	pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
		if bytes.len() != MAX_ENCRYPTED_MEMO_SIZE as usize {
			return Err("Invalid memo size");
		}
		Self::new(bytes.to_vec())
	}
	pub fn nonce(&self) -> &[u8] {
		// Invariant: EncryptedMemo is always exactly MAX_ENCRYPTED_MEMO_SIZE bytes after
		// construction. from_bytes() enforces this; the else branch is unreachable in practice.
		debug_assert_eq!(
			self.0.len(),
			MAX_ENCRYPTED_MEMO_SIZE as usize,
			"EncryptedMemo invariant violated: expected {} bytes, got {}",
			MAX_ENCRYPTED_MEMO_SIZE,
			self.0.len()
		);
		if self.0.len() >= 12 {
			&self.0[..12]
		} else {
			&[]
		}
	}
	pub fn ciphertext(&self) -> &[u8] {
		// Invariant: see nonce(). ciphertext occupies bytes 12..128.
		debug_assert_eq!(
			self.0.len(),
			MAX_ENCRYPTED_MEMO_SIZE as usize,
			"EncryptedMemo invariant violated: expected {} bytes, got {}",
			MAX_ENCRYPTED_MEMO_SIZE,
			self.0.len()
		);
		if self.0.len() >= 128 {
			&self.0[12..128]
		} else {
			&[]
		}
	}
	pub fn tag(&self) -> &[u8] {
		// Layout: nonce(0..12) | ciphertext(12..128) | tag/MAC(128..144) | ephPk(144..176)
		debug_assert_eq!(
			self.0.len(),
			MAX_ENCRYPTED_MEMO_SIZE as usize,
			"EncryptedMemo invariant violated: expected {} bytes, got {}",
			MAX_ENCRYPTED_MEMO_SIZE,
			self.0.len()
		);
		if self.0.len() >= 144 {
			&self.0[128..144]
		} else {
			&[]
		}
	}
	pub fn eph_pk(&self) -> &[u8] {
		// Ephemeral BabyJubJub public key (packed, LE) occupies bytes 144..176.
		debug_assert_eq!(
			self.0.len(),
			MAX_ENCRYPTED_MEMO_SIZE as usize,
			"EncryptedMemo invariant violated: expected {} bytes, got {}",
			MAX_ENCRYPTED_MEMO_SIZE,
			self.0.len()
		);
		if self.0.len() >= 176 {
			&self.0[144..176]
		} else {
			&[]
		}
	}
}

// ════════════════════════════════════════════════════════════════════════════
// AssetMetadata
// ════════════════════════════════════════════════════════════════════════════

/// Asset metadata for multi-asset shielded pool.
#[derive(
	Clone,
	PartialEq,
	Eq,
	Encode,
	Decode,
	MaxEncodedLen,
	TypeInfo,
	RuntimeDebug
)]
pub struct AssetMetadata<AccountId, BlockNumber> {
	pub id: u32,
	pub name: BoundedVec<u8, ConstU32<64>>,
	pub symbol: BoundedVec<u8, ConstU32<16>>,
	pub decimals: u8,
	pub is_verified: bool,
	pub contract_address: Option<[u8; 20]>,
	pub created_at: BlockNumber,
	pub creator: AccountId,
}

impl<AccountId, BlockNumber> AssetMetadata<AccountId, BlockNumber> {
	pub fn new(
		id: u32,
		name: BoundedVec<u8, ConstU32<64>>,
		symbol: BoundedVec<u8, ConstU32<16>>,
		decimals: u8,
		created_at: BlockNumber,
		creator: AccountId,
	) -> Self {
		Self {
			id,
			name,
			symbol,
			decimals,
			is_verified: false,
			contract_address: None,
			created_at,
			creator,
		}
	}
	pub fn verify(&mut self) {
		self.is_verified = true;
	}
	pub fn unverify(&mut self) {
		self.is_verified = false;
	}
	pub fn is_verified(&self) -> bool {
		self.is_verified
	}
	pub fn set_contract_address(&mut self, address: [u8; 20]) {
		self.contract_address = Some(address);
	}
}

#[cfg(test)]
mod tests {
	use super::*;

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
		assert_eq!(memo.ciphertext().len(), 116);
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
