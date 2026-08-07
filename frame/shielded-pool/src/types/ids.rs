//! Newtypes over the 32-byte field elements and the asset id.
//!
//! `Commitment` and `Nullifier` are both `[u8; 32]` underneath, and confusing
//! one for the other would be a silent correctness bug — the newtypes make that
//! a compile error instead.
//!
//! Both are stored as **raw bytes**, so byte equality is identity. Callers
//! feeding untrusted input must reject non-canonical encodings before they reach
//! storage; the ZK verifier does this today for anything backed by a proof.

use parity_scale_codec::{Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};
use scale_info::TypeInfo;
use sp_core::H256;
use sp_runtime::RuntimeDebug;

// Commitment

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
	pub fn is_canonical(&self) -> bool {
		orbinum_zk_core::FieldElement::is_canonical_le(&self.0)
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

// Nullifier

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
	pub fn is_canonical(&self) -> bool {
		orbinum_zk_core::FieldElement::is_canonical_le(&self.0)
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

// AssetId

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

#[cfg(test)]
mod tests {
	use super::*;

	/// Little-endian encoding of `value + p`, which reduces to `value` but is a
	/// different byte string — the shape a malleability attempt takes.
	fn plus_modulus(value: u8) -> [u8; 32] {
		use ark_bn254::Fr;
		use ark_ff::{BigInteger, PrimeField};

		// p as bytes: encode p-1, then add 1 with carry.
		let p_minus_1 = (-Fr::from(1u64)).into_bigint().to_bytes_le();
		let mut out = [0u8; 32];
		out[..p_minus_1.len()].copy_from_slice(&p_minus_1);
		let mut carry = 1u16 + value as u16;
		for b in out.iter_mut() {
			let v = *b as u16 + carry;
			*b = (v & 0xff) as u8;
			carry = v >> 8;
		}
		out
	}

	/// The property the guard exists for: `n` and `n + p` are the same field
	/// element but different bytes. Both are stored raw and keyed raw, so
	/// accepting both would give one note two identities — and two spends.
	#[test]
	fn a_nullifier_and_its_modular_twin_are_not_both_accepted() {
		use ark_bn254::Fr;
		use ark_ff::PrimeField;

		let mut canonical = [0u8; 32];
		canonical[0] = 7;
		let twin = plus_modulus(7);

		assert_ne!(canonical, twin, "the two encodings must differ as bytes");
		assert_eq!(
			Fr::from_le_bytes_mod_order(&canonical),
			Fr::from_le_bytes_mod_order(&twin),
			"but they must be the same field element — otherwise this proves nothing"
		);

		assert!(Nullifier::new(canonical).is_canonical());
		assert!(
			!Nullifier::new(twin).is_canonical(),
			"n + p must be refused, or it becomes a second key for a spent note"
		);
	}

	#[test]
	fn a_commitment_and_its_modular_twin_are_not_both_accepted() {
		let mut canonical = [0u8; 32];
		canonical[0] = 9;
		assert!(Commitment::new(canonical).is_canonical());
		assert!(!Commitment::new(plus_modulus(9)).is_canonical());
	}

	/// Zero is canonical and must stay usable: an all-zero nullifier marks a
	/// dummy input slot, which the circuit skips. Folding canonicity into
	/// `validate` would have rejected it.
	#[test]
	fn zero_is_canonical_but_not_a_real_value() {
		let zero_n = Nullifier::new([0u8; 32]);
		assert!(zero_n.is_canonical(), "dummy inputs must survive the guard");
		assert!(!zero_n.validate(), "but zero is not a real nullifier");

		let zero_c = Commitment::new([0u8; 32]);
		assert!(zero_c.is_canonical());
		assert!(!zero_c.is_valid());
	}

	/// The modulus itself reduces to zero, so it would alias the dummy marker.
	#[test]
	fn the_modulus_itself_is_refused() {
		let p = plus_modulus(0);
		assert!(!Nullifier::new(p).is_canonical());
		assert!(!Commitment::new(p).is_canonical());
	}

	/// All-ones is the largest possible 32-byte string and far above p.
	#[test]
	fn all_ones_is_refused() {
		assert!(!Nullifier::new([0xffu8; 32]).is_canonical());
		assert!(!Commitment::new([0xffu8; 32]).is_canonical());
	}

	/// Values the chain actually uses must pass, or the guard breaks real spends.
	#[test]
	fn ordinary_values_are_accepted() {
		for seed in [1u8, 42, 0x7f, 0xaa] {
			let mut b = [0u8; 32];
			b[0] = seed;
			assert!(Nullifier::new(b).is_canonical(), "seed {seed} rejected");
			assert!(Commitment::new(b).is_canonical(), "seed {seed} rejected");
		}
	}
}
