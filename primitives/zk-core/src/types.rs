//! Cryptographic types for ZK-SNARK operations.
//!
//! Constants, field element newtypes (Commitment, Nullifier, etc.), and the Note struct.

use ark_bn254::Fr;

// ─── Constants ────────────────────────────────────────────────────────────────

/// Depth of the Merkle commitment tree (matches Circom circuit).
pub const MERKLE_TREE_DEPTH: usize = 20;

/// Maximum number of leaves in the Merkle tree (2^MERKLE_TREE_DEPTH).
pub const MAX_MERKLE_LEAVES: usize = 1 << MERKLE_TREE_DEPTH;

// ─── FieldElement ─────────────────────────────────────────────────────────────

/// BN254 scalar field element. Base type for all value objects in this crate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FieldElement(Fr);

impl FieldElement {
	/// Create from an arkworks `Fr` value.
	pub fn new(value: Fr) -> Self {
		Self(value)
	}

	/// Return the inner `Fr` value.
	pub fn inner(&self) -> Fr {
		self.0
	}

	/// Create from a `u64` value.
	pub fn from_u64(value: u64) -> Self {
		Self(Fr::from(value))
	}

	/// The additive identity.
	pub fn zero() -> Self {
		Self(Fr::from(0u64))
	}

	/// Returns `true` if this element is zero.
	pub fn is_zero(&self) -> bool {
		self.0 == Fr::from(0u64)
	}

	/// Returns `true` if `bytes` is the canonical little-endian encoding of a
	/// field element, i.e. it represents a value strictly less than the modulus `p`.
	///
	/// Because byte-to-field conversion reduces modulo `p`, non-canonical encodings
	/// (`>= p`) map to the same element as their reduced form. Callers that store or
	/// compare raw bytes should reject non-canonical inputs at the trust boundary.
	pub fn is_canonical_le(bytes: &[u8; 32]) -> bool {
		use ark_ff::{BigInteger, PrimeField};
		let fe = Fr::from_le_bytes_mod_order(bytes);
		// Canonical iff re-encoding the reduced element is byte-identical.
		fe.into_bigint().to_bytes_le().as_slice() == &bytes[..]
	}

	/// Builds a field element from its canonical little-endian encoding, returning
	/// `None` for non-canonical byte strings (`>= p`). See [`Self::is_canonical_le`].
	pub fn from_canonical_le(bytes: &[u8; 32]) -> Option<Self> {
		use ark_ff::PrimeField;
		if Self::is_canonical_le(bytes) {
			Some(Self(Fr::from_le_bytes_mod_order(bytes)))
		} else {
			None
		}
	}
}

impl From<Fr> for FieldElement {
	fn from(v: Fr) -> Self {
		Self(v)
	}
}

impl From<FieldElement> for Fr {
	fn from(e: FieldElement) -> Self {
		e.0
	}
}

impl From<u64> for FieldElement {
	fn from(v: u64) -> Self {
		Self::from_u64(v)
	}
}

// ─── Newtype macro for value objects ─────────────────────────────────────────

macro_rules! field_newtype {
	($Name:ident, $doc:literal) => {
		#[doc = $doc]
		#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
		pub struct $Name(FieldElement);

		impl $Name {
			/// Create directly from a field element.
			pub fn new(inner: FieldElement) -> Self {
				Self(inner)
			}

			/// Return the inner `FieldElement`.
			pub fn inner(&self) -> FieldElement {
				self.0
			}
		}

		impl From<FieldElement> for $Name {
			fn from(v: FieldElement) -> Self {
				Self(v)
			}
		}

		impl From<$Name> for FieldElement {
			fn from(v: $Name) -> Self {
				v.0
			}
		}

		impl From<Fr> for $Name {
			fn from(v: Fr) -> Self {
				Self(FieldElement::new(v))
			}
		}

		impl From<$Name> for Fr {
			fn from(v: $Name) -> Self {
				v.0.inner()
			}
		}
	};
}

field_newtype!(
	Commitment,
	"Pedersen-style commitment to a note: `Poseidon(value, asset_id, owner_pubkey, blinding)`."
);
field_newtype!(
	Nullifier,
	"Spend nullifier that prevents double-spending: `Poseidon(commitment, spending_key)`."
);
field_newtype!(Blinding, "Random blinding factor that hides note contents.");
field_newtype!(
	OwnerPubkey,
	"Owner's public key (kept private, embedded in commitment)."
);
field_newtype!(
	SpendingKey,
	"Spending key used to derive nullifiers. Must remain secret."
);

// ─── Note ─────────────────────────────────────────────────────────────────────

use crate::{hash::PoseidonHasher, ops};

/// A private note in the shielded pool.
///
/// Notes are the UTXO equivalent for ZK transactions. The commitment is inserted
/// into the Merkle tree; the nullifier is published when the note is spent.
#[derive(Clone, Debug, PartialEq)]
pub struct Note {
	pub value: u64,
	pub asset_id: u64,
	pub owner_pubkey: OwnerPubkey,
	pub blinding: Blinding,
}

impl Note {
	pub fn new(value: u64, asset_id: u64, owner_pubkey: OwnerPubkey, blinding: Blinding) -> Self {
		Self {
			value,
			asset_id,
			owner_pubkey,
			blinding,
		}
	}

	/// A canonical dummy note used to pad circuit inputs: every field is zero.
	///
	/// Use this to construct dummies so their commitment/nullifier are stable.
	pub fn zero() -> Self {
		Self {
			value: 0,
			asset_id: 0,
			owner_pubkey: OwnerPubkey::from(FieldElement::zero()),
			blinding: Blinding::from(FieldElement::zero()),
		}
	}

	/// Returns `true` if this is a dummy (padding) note.
	///
	/// A note is dummy iff `value == 0`, matching the circuit and shielded-pool.
	/// `asset_id`, `owner_pubkey`, and `blinding` are not part of the predicate.
	/// Use [`Self::zero`] to build the canonical dummy.
	pub fn is_zero(&self) -> bool {
		self.value == 0
	}

	/// Compute the Merkle commitment for this note.
	pub fn commitment<H: PoseidonHasher>(&self, hasher: &H) -> Commitment {
		ops::compute_commitment(
			hasher,
			self.value,
			self.asset_id,
			self.owner_pubkey,
			self.blinding,
		)
	}

	/// Compute the spend nullifier for this note.
	pub fn nullifier<H: PoseidonHasher>(&self, hasher: &H, spending_key: SpendingKey) -> Nullifier {
		let commitment = self.commitment(hasher);
		ops::compute_nullifier(hasher, commitment, spending_key)
	}
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
	use super::*;
	use crate::hash::PoseidonHasher;

	// Minimal mock hasher used only in tests.
	#[derive(Clone)]
	struct MockHasher;
	impl PoseidonHasher for MockHasher {
		fn hash_2(&self, _: [FieldElement; 2]) -> FieldElement {
			FieldElement::from_u64(42)
		}
		fn hash_4(&self, _: [FieldElement; 4]) -> FieldElement {
			FieldElement::from_u64(100)
		}
		fn hash_5(&self, _: [FieldElement; 5]) -> FieldElement {
			FieldElement::from_u64(200)
		}
	}

	// --- FieldElement basics ---

	#[test]
	fn field_element_from_u64_roundtrip() {
		let e = FieldElement::from_u64(999);
		assert_eq!(e.inner(), Fr::from(999u64));
	}

	#[test]
	fn field_element_zero_is_zero() {
		assert!(FieldElement::zero().is_zero());
		assert!(!FieldElement::from_u64(1).is_zero());
	}

	// --- canonical encoding ---

	/// Little-endian 32-byte encoding of the field modulus `p`.
	fn modulus_le() -> [u8; 32] {
		use ark_ff::{BigInteger, PrimeField};
		// p as bytes: encode -1 (= p-1) then add 1 with carry.
		let p_minus_1 = (-Fr::from(1u64)).into_bigint().to_bytes_le();
		let mut p = [0u8; 32];
		p[..p_minus_1.len()].copy_from_slice(&p_minus_1);
		let mut carry = 1u16;
		for b in p.iter_mut() {
			let v = *b as u16 + carry;
			*b = (v & 0xff) as u8;
			carry = v >> 8;
		}
		p
	}

	#[test]
	fn canonical_accepts_small_values() {
		let mut b = [0u8; 32];
		b[0] = 5; // little-endian 5
		assert!(FieldElement::is_canonical_le(&b));
		assert!(FieldElement::from_canonical_le(&b).is_some());
	}

	#[test]
	fn canonical_accepts_zero() {
		assert!(FieldElement::is_canonical_le(&[0u8; 32]));
	}

	#[test]
	fn canonical_rejects_modulus_and_above() {
		let p = modulus_le();
		// p itself is non-canonical (reduces to 0).
		assert!(!FieldElement::is_canonical_le(&p));
		assert!(FieldElement::from_canonical_le(&p).is_none());
		// All-ones (0xff..ff) is way above p → non-canonical.
		assert!(!FieldElement::is_canonical_le(&[0xff; 32]));
		assert!(FieldElement::from_canonical_le(&[0xff; 32]).is_none());
	}

	#[test]
	fn canonical_n_and_n_plus_p_differ() {
		// n and n+p are different byte strings but reduce to the same field element.
		use ark_ff::{BigInteger, PrimeField};
		let n = 7u64;
		let n_bytes = {
			let mut b = [0u8; 32];
			let le = Fr::from(n).into_bigint().to_bytes_le();
			b[..le.len()].copy_from_slice(&le);
			b
		};
		// n+p as bytes = modulus + n (may overflow 32 bytes; if so, skip — but for
		// small n it fits since p < 2^254).
		let p = modulus_le();
		let mut n_plus_p = [0u8; 32];
		let mut carry = 0u16;
		for i in 0..32 {
			let v = p[i] as u16 + n_bytes[i] as u16 + carry;
			n_plus_p[i] = (v & 0xff) as u8;
			carry = v >> 8;
		}
		assert_eq!(carry, 0, "n+p must fit in 32 bytes for this test");
		// Same reduced field element...
		assert_eq!(
			Fr::from_le_bytes_mod_order(&n_bytes),
			Fr::from_le_bytes_mod_order(&n_plus_p)
		);
		// ...but n is canonical and n+p is NOT.
		assert!(FieldElement::is_canonical_le(&n_bytes));
		assert!(!FieldElement::is_canonical_le(&n_plus_p));
	}

	#[test]
	fn field_element_from_fr_roundtrip() {
		let fr = Fr::from(123u64);
		let e = FieldElement::from(fr);
		assert_eq!(Fr::from(e), fr);
	}

	// --- Value objects ---

	#[test]
	fn commitment_inner_roundtrip() {
		let fe = FieldElement::from_u64(7);
		let c = Commitment::from(fe);
		assert_eq!(c.inner(), fe);
	}

	#[test]
	fn nullifier_from_fr() {
		let fr = Fr::from(55u64);
		let n = Nullifier::from(fr);
		assert_eq!(Fr::from(n), fr);
	}

	#[test]
	fn value_objects_inequality() {
		let a = SpendingKey::from(FieldElement::from_u64(1));
		let b = SpendingKey::from(FieldElement::from_u64(2));
		assert_ne!(a, b);
	}

	// --- Note ---

	#[test]
	fn note_zero_is_zero() {
		assert!(Note::zero().is_zero());
	}

	#[test]
	fn note_is_dummy_by_value_only() {
		// A value-zero note is dummy even with non-zero asset/pubkey/blinding.
		let dummy = Note::new(
			0,
			7,
			OwnerPubkey::from(Fr::from(123u64)),
			Blinding::from(Fr::from(456u64)),
		);
		assert!(dummy.is_zero());
		// A non-zero value is never dummy, regardless of the other fields.
		let real = Note::new(
			1,
			0,
			OwnerPubkey::from(Fr::from(0u64)),
			Blinding::from(Fr::from(0u64)),
		);
		assert!(!real.is_zero());
	}

	#[test]
	fn note_new_preserves_fields() {
		let pk = OwnerPubkey::from(Fr::from(10u64));
		let bl = Blinding::from(Fr::from(20u64));
		let n = Note::new(100, 5, pk, bl);
		assert_eq!(n.value, 100);
		assert_eq!(n.asset_id, 5);
		assert_eq!(n.owner_pubkey, pk);
		assert_eq!(n.blinding, bl);
		assert!(!n.is_zero());
	}

	#[test]
	fn note_commitment_uses_hash_4() {
		let n = Note::new(
			50,
			0,
			OwnerPubkey::from(Fr::from(1u64)),
			Blinding::from(Fr::from(2u64)),
		);
		// MockHasher.hash_4 always returns 100
		let expected = Commitment::from(FieldElement::from_u64(100));
		assert_eq!(n.commitment(&MockHasher), expected);
	}

	#[test]
	fn note_nullifier_uses_hash_2() {
		let n = Note::new(
			50,
			0,
			OwnerPubkey::from(Fr::from(1u64)),
			Blinding::from(Fr::from(2u64)),
		);
		let sk = SpendingKey::from(Fr::from(99u64));
		// MockHasher.hash_2 always returns 42
		let expected = Nullifier::from(FieldElement::from_u64(42));
		assert_eq!(n.nullifier(&MockHasher, sk), expected);
	}

	#[test]
	fn note_commitment_deterministic() {
		let n = Note::new(
			1,
			2,
			OwnerPubkey::from(Fr::from(3u64)),
			Blinding::from(Fr::from(4u64)),
		);
		assert_eq!(n.commitment(&MockHasher), n.commitment(&MockHasher));
	}
}
