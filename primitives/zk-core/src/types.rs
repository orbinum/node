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

	/// A zero / dummy note used to pad circuit inputs.
	pub fn zero() -> Self {
		Self {
			value: 0,
			asset_id: 0,
			owner_pubkey: OwnerPubkey::from(FieldElement::zero()),
			blinding: Blinding::from(FieldElement::zero()),
		}
	}

	pub fn is_zero(&self) -> bool {
		self.value == 0
			&& self.asset_id == 0
			&& self.owner_pubkey.inner().is_zero()
			&& self.blinding.inner().is_zero()
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
