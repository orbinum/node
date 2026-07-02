#![allow(unexpected_cfgs)]
//! Native Poseidon host functions via `sp-runtime-interface`.
//!
//! Exposes Poseidon hashing as native host functions, bypassing the WASM
//! interpreter for ~3× performance. Used by [`crate::hash::NativePoseidonHasher`].

use alloc::vec::Vec;
use sp_runtime_interface::{
	pass_by::{AllocateAndReturnFatPointer, PassFatPointerAndRead},
	runtime_interface,
};

/// Read an input slice into a fixed 32-byte little-endian array.
///
/// Copies at most 32 bytes; a shorter input is zero-padded, a longer one is
/// truncated. This NEVER panics — critical because these functions run as native
/// host functions, where a panic aborts the node process (whereas in WASM it is a
/// recoverable trap), which would break consensus. Callers already pass exactly
/// 32 bytes, so this is purely defensive and deterministic across native/WASM.
#[inline]
fn read_32_le(bytes: &[u8]) -> [u8; 32] {
	let mut arr = [0u8; 32];
	let n = bytes.len().min(32);
	arr[..n].copy_from_slice(&bytes[..n]);
	arr
}

/// Native runtime interface for Poseidon hash operations.
#[runtime_interface]
pub trait PoseidonHostInterface {
	/// Hash two 32-byte inputs (Merkle node, nullifier).
	fn poseidon_hash_2(
		left: PassFatPointerAndRead<&[u8]>,
		right: PassFatPointerAndRead<&[u8]>,
	) -> AllocateAndReturnFatPointer<Vec<u8>> {
		use crate::{
			hash::{LightPoseidonHasher, PoseidonHasher},
			types::FieldElement,
		};
		use ark_bn254::Fr;
		use ark_ff::{BigInteger, PrimeField};

		let left_arr = super::read_32_le(left);
		let right_arr = super::read_32_le(right);

		let left_fr = Fr::from_le_bytes_mod_order(&left_arr);
		let right_fr = Fr::from_le_bytes_mod_order(&right_arr);

		let hasher = LightPoseidonHasher;
		let result = hasher.hash_2([FieldElement::new(left_fr), FieldElement::new(right_fr)]);

		let bytes = result.inner().into_bigint().to_bytes_le();
		super::read_32_le(&bytes).to_vec()
	}

	/// Hash four 32-byte inputs (note commitment).
	fn poseidon_hash_4(
		input1: PassFatPointerAndRead<&[u8]>,
		input2: PassFatPointerAndRead<&[u8]>,
		input3: PassFatPointerAndRead<&[u8]>,
		input4: PassFatPointerAndRead<&[u8]>,
	) -> AllocateAndReturnFatPointer<Vec<u8>> {
		use crate::{
			hash::{LightPoseidonHasher, PoseidonHasher},
			types::FieldElement,
		};
		use ark_bn254::Fr;
		use ark_ff::{BigInteger, PrimeField};

		let arr1 = super::read_32_le(input1);
		let arr2 = super::read_32_le(input2);
		let arr3 = super::read_32_le(input3);
		let arr4 = super::read_32_le(input4);

		let frs = [
			Fr::from_le_bytes_mod_order(&arr1),
			Fr::from_le_bytes_mod_order(&arr2),
			Fr::from_le_bytes_mod_order(&arr3),
			Fr::from_le_bytes_mod_order(&arr4),
		];

		let hasher = LightPoseidonHasher;
		let result = hasher.hash_4([
			FieldElement::new(frs[0]),
			FieldElement::new(frs[1]),
			FieldElement::new(frs[2]),
			FieldElement::new(frs[3]),
		]);

		let bytes = result.inner().into_bigint().to_bytes_le();
		super::read_32_le(&bytes).to_vec()
	}
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
	use super::*;
	use ark_bn254::Fr;
	use ark_ff::{BigInteger, PrimeField, Zero};

	fn u64_to_bytes(value: u64) -> Vec<u8> {
		let fr = Fr::from(value);
		let bytes = fr.into_bigint().to_bytes_le();
		bytes[..32].to_vec()
	}

	fn bytes_to_fr(bytes: &[u8]) -> Fr {
		let mut arr = [0u8; 32];
		arr.copy_from_slice(&bytes[..32]);
		Fr::from_le_bytes_mod_order(&arr)
	}

	#[test]
	fn hash_2_non_zero() {
		let result =
			poseidon_host_interface::poseidon_hash_2(&u64_to_bytes(42), &u64_to_bytes(100));
		assert_eq!(result.len(), 32);
		assert!(!bytes_to_fr(&result).is_zero());
	}

	#[test]
	fn hash_2_deterministic() {
		let a = poseidon_host_interface::poseidon_hash_2(&u64_to_bytes(42), &u64_to_bytes(100));
		let b = poseidon_host_interface::poseidon_hash_2(&u64_to_bytes(42), &u64_to_bytes(100));
		assert_eq!(a, b);
	}

	#[test]
	fn hash_2_order_matters() {
		let a = poseidon_host_interface::poseidon_hash_2(&u64_to_bytes(1), &u64_to_bytes(2));
		let b = poseidon_host_interface::poseidon_hash_2(&u64_to_bytes(2), &u64_to_bytes(1));
		assert_ne!(a, b);
	}

	#[test]
	fn hash_4_non_zero() {
		let result = poseidon_host_interface::poseidon_hash_4(
			&u64_to_bytes(1),
			&u64_to_bytes(2),
			&u64_to_bytes(3),
			&u64_to_bytes(4),
		);
		assert_eq!(result.len(), 32);
		assert!(!bytes_to_fr(&result).is_zero());
	}

	#[test]
	fn hash_4_deterministic() {
		let a = poseidon_host_interface::poseidon_hash_4(
			&u64_to_bytes(1),
			&u64_to_bytes(2),
			&u64_to_bytes(3),
			&u64_to_bytes(4),
		);
		let b = poseidon_host_interface::poseidon_hash_4(
			&u64_to_bytes(1),
			&u64_to_bytes(2),
			&u64_to_bytes(3),
			&u64_to_bytes(4),
		);
		assert_eq!(a, b);
	}

	#[test]
	fn hash_2_matches_light_hasher() {
		use crate::{hash::LightPoseidonHasher, hash::PoseidonHasher, types::FieldElement};
		use ark_ff::PrimeField;

		let a = FieldElement::from_u64(10);
		let b = FieldElement::from_u64(20);

		let from_trait = LightPoseidonHasher.hash_2([a, b]);
		let bytes_a = {
			let bytes = a.inner().into_bigint().to_bytes_le();
			bytes[..32].to_vec()
		};
		let bytes_b = {
			let bytes = b.inner().into_bigint().to_bytes_le();
			bytes[..32].to_vec()
		};
		let from_host = poseidon_host_interface::poseidon_hash_2(&bytes_a, &bytes_b);

		let mut arr = [0u8; 32];
		arr.copy_from_slice(&from_host[..32]);
		let from_host_fe = FieldElement::new(Fr::from_le_bytes_mod_order(&arr));
		assert_eq!(from_trait, from_host_fe);
	}

	// ─── No panic on non-32-byte inputs (host functions must never panic) ──────

	#[test]
	fn read_32_le_pads_and_truncates() {
		// Shorter input is zero-padded on the right.
		assert_eq!(super::read_32_le(&[1, 2, 3]), {
			let mut e = [0u8; 32];
			e[..3].copy_from_slice(&[1, 2, 3]);
			e
		});
		// Exact length is copied verbatim.
		assert_eq!(super::read_32_le(&[0xAB; 32]), [0xAB; 32]);
		// Longer input is truncated to the first 32 bytes.
		assert_eq!(super::read_32_le(&[0xCD; 40]), [0xCD; 32]);
		// Empty input yields all zeros.
		assert_eq!(super::read_32_le(&[]), [0u8; 32]);
	}

	#[test]
	fn hash_2_no_panic_on_short_input() {
		// Previously asserted len == 32 and would panic (aborting a native node).
		let short = alloc::vec![7u8; 10];
		let long = alloc::vec![9u8; 40];
		let _ = poseidon_host_interface::poseidon_hash_2(&short, &u64_to_bytes(1));
		let _ = poseidon_host_interface::poseidon_hash_2(&u64_to_bytes(1), &long);
		let _ = poseidon_host_interface::poseidon_hash_2(&[], &[]);
	}

	#[test]
	fn hash_4_no_panic_on_short_input() {
		let short = alloc::vec![7u8; 5];
		let _ = poseidon_host_interface::poseidon_hash_4(
			&short,
			&u64_to_bytes(2),
			&u64_to_bytes(3),
			&alloc::vec![9u8; 33],
		);
	}

	#[test]
	fn hash_2_still_correct_for_32_bytes() {
		// The 32-byte path must be unchanged (no regression).
		let a = poseidon_host_interface::poseidon_hash_2(&u64_to_bytes(42), &u64_to_bytes(100));
		let b = poseidon_host_interface::poseidon_hash_2(&u64_to_bytes(42), &u64_to_bytes(100));
		assert_eq!(a, b);
		assert_eq!(a.len(), 32);
		assert!(!bytes_to_fr(&a).is_zero());
	}
}
