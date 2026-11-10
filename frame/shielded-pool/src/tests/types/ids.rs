//! Field-element identifiers: only canonical encodings are accepted.

use crate::types::ids::*;

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
