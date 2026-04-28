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

		assert_eq!((*left).len(), 32, "Left input must be 32 bytes");
		assert_eq!((*right).len(), 32, "Right input must be 32 bytes");

		let mut left_arr = [0u8; 32];
		let mut right_arr = [0u8; 32];
		left_arr.copy_from_slice(left);
		right_arr.copy_from_slice(right);

		let left_fr = Fr::from_le_bytes_mod_order(&left_arr);
		let right_fr = Fr::from_le_bytes_mod_order(&right_arr);

		let hasher = LightPoseidonHasher;
		let result = hasher.hash_2([FieldElement::new(left_fr), FieldElement::new(right_fr)]);

		let bytes = result.inner().into_bigint().to_bytes_le();
		bytes[..32].to_vec()
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

		assert_eq!((*input1).len(), 32, "Input1 must be 32 bytes");
		assert_eq!((*input2).len(), 32, "Input2 must be 32 bytes");
		assert_eq!((*input3).len(), 32, "Input3 must be 32 bytes");
		assert_eq!((*input4).len(), 32, "Input4 must be 32 bytes");

		let mut arr1 = [0u8; 32];
		let mut arr2 = [0u8; 32];
		let mut arr3 = [0u8; 32];
		let mut arr4 = [0u8; 32];
		arr1.copy_from_slice(input1);
		arr2.copy_from_slice(input2);
		arr3.copy_from_slice(input3);
		arr4.copy_from_slice(input4);

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
		bytes[..32].to_vec()
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
}
