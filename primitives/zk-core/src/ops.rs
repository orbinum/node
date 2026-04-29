//! Core ZK cryptographic operations as free functions.
//!
//! These functions encode the Poseidon-based formulas that the Circom circuits
//! implement as constraints. Keeping them as free functions (rather than methods
//! on domain services) removes the indirection layers while preserving the
//! separation between "what to hash" and "how to hash".

use crate::{
	hash::PoseidonHasher,
	types::{Blinding, Commitment, FieldElement, Nullifier, OwnerPubkey, SpendingKey},
};

// ─── Commitment ───────────────────────────────────────────────────────────────

/// Compute a note commitment.
///
/// ```text
/// commitment = Poseidon(value, asset_id, owner_pubkey, blinding)
/// ```
pub fn compute_commitment<H: PoseidonHasher>(
	hasher: &H,
	value: u64,
	asset_id: u64,
	owner_pubkey: OwnerPubkey,
	blinding: Blinding,
) -> Commitment {
	hasher
		.hash_4([
			FieldElement::from_u64(value),
			FieldElement::from_u64(asset_id),
			owner_pubkey.inner(),
			blinding.inner(),
		])
		.into()
}

// ─── Nullifier ────────────────────────────────────────────────────────────────

/// Compute a spend nullifier.
///
/// ```text
/// nullifier = Poseidon(commitment, spending_key)
/// ```
pub fn compute_nullifier<H: PoseidonHasher>(
	hasher: &H,
	commitment: Commitment,
	spending_key: SpendingKey,
) -> Nullifier {
	hasher
		.hash_2([commitment.inner(), spending_key.inner()])
		.into()
}

// ─── Merkle ───────────────────────────────────────────────────────────────────

/// Hash two Merkle sibling nodes into their parent.
///
/// ```text
/// parent = Poseidon(left, right)
/// ```
pub fn merkle_hash<H: PoseidonHasher>(
	hasher: &H,
	left: FieldElement,
	right: FieldElement,
) -> FieldElement {
	hasher.hash_2([left, right])
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
	use super::*;
	use crate::hash::PoseidonHasher;
	use ark_bn254::Fr;

	#[derive(Clone)]
	struct ConstHasher;
	impl PoseidonHasher for ConstHasher {
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

	// Hasher that sums inputs so we can verify the right fields are passed.
	struct SumHasher;
	impl PoseidonHasher for SumHasher {
		fn hash_2(&self, inputs: [FieldElement; 2]) -> FieldElement {
			let s = inputs[0].inner() + inputs[1].inner();
			FieldElement::new(s)
		}
		fn hash_4(&self, inputs: [FieldElement; 4]) -> FieldElement {
			let s = inputs[0].inner() + inputs[1].inner() + inputs[2].inner() + inputs[3].inner();
			FieldElement::new(s)
		}
		fn hash_5(&self, inputs: [FieldElement; 5]) -> FieldElement {
			let s = inputs[0].inner()
				+ inputs[1].inner()
				+ inputs[2].inner()
				+ inputs[3].inner()
				+ inputs[4].inner();
			FieldElement::new(s)
		}
	}

	// --- compute_commitment ---

	#[test]
	fn commitment_returns_hash_4_output() {
		let c = compute_commitment(
			&ConstHasher,
			100,
			0,
			OwnerPubkey::from(Fr::from(1u64)),
			Blinding::from(Fr::from(2u64)),
		);
		assert_eq!(c, Commitment::from(FieldElement::from_u64(100)));
	}

	#[test]
	fn commitment_encodes_value() {
		let c1 = compute_commitment(
			&SumHasher,
			10,
			0,
			OwnerPubkey::from(Fr::from(0u64)),
			Blinding::from(Fr::from(0u64)),
		);
		let c2 = compute_commitment(
			&SumHasher,
			20,
			0,
			OwnerPubkey::from(Fr::from(0u64)),
			Blinding::from(Fr::from(0u64)),
		);
		assert_ne!(c1, c2);
	}

	#[test]
	fn commitment_deterministic() {
		let pk = OwnerPubkey::from(Fr::from(5u64));
		let bl = Blinding::from(Fr::from(6u64));
		assert_eq!(
			compute_commitment(&ConstHasher, 1, 2, pk, bl),
			compute_commitment(&ConstHasher, 1, 2, pk, bl),
		);
	}

	// --- compute_nullifier ---

	#[test]
	fn nullifier_returns_hash_2_output() {
		let c = Commitment::from(FieldElement::from_u64(10));
		let sk = SpendingKey::from(Fr::from(20u64));
		let n = compute_nullifier(&ConstHasher, c, sk);
		assert_eq!(n, Nullifier::from(FieldElement::from_u64(42)));
	}

	#[test]
	fn nullifier_changes_with_spending_key() {
		let c = Commitment::from(FieldElement::from_u64(5));
		let n1 = compute_nullifier(&SumHasher, c, SpendingKey::from(Fr::from(1u64)));
		let n2 = compute_nullifier(&SumHasher, c, SpendingKey::from(Fr::from(2u64)));
		assert_ne!(n1, n2);
	}

	// --- merkle_hash ---

	#[test]
	fn merkle_hash_returns_hash_2() {
		let left = FieldElement::from_u64(3);
		let right = FieldElement::from_u64(7);
		let h = merkle_hash(&ConstHasher, left, right);
		assert_eq!(h, FieldElement::from_u64(42));
	}

	#[test]
	fn merkle_hash_order_matters() {
		let a = FieldElement::from_u64(1);
		let b = FieldElement::from_u64(2);
		use crate::hash::LightPoseidonHasher;
		let h = LightPoseidonHasher;
		assert_ne!(merkle_hash(&h, a, b), merkle_hash(&h, b, a));
	}
}
