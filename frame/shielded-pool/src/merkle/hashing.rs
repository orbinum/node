//! Poseidon hashing for Merkle nodes.
//!
//! Pure functions over 32-byte field elements — no storage, no `Config`. The
//! zero-hash ladder is cached because every path read and every insert needs the
//! empty-subtree digest for each level.

use alloc::boxed::Box;
use ark_ff::BigInteger;

/// Default hash for empty nodes at each level.
pub fn zero_hash_at_level(level: usize) -> [u8; 32] {
	if level == 0 {
		return [0u8; 32];
	}
	let prev = zero_hash_at_level(level - 1);
	hash_pair(&prev, &prev)
}

/// Cached zero hashes for Poseidon (lazy-initialized, thread-safe).
static ZERO_HASHES_POSEIDON: once_cell::race::OnceBox<[[u8; 32]; 21]> =
	once_cell::race::OnceBox::new();

/// Get precomputed zero hash at level (optimized with cache).
#[inline]
pub fn get_zero_hash_cached(level: usize) -> [u8; 32] {
	if level < 21 {
		let cache = ZERO_HASHES_POSEIDON.get_or_init(|| {
			let mut hashes = [[0u8; 32]; 21];
			hashes[0] = [0u8; 32];
			for i in 1..21 {
				hashes[i] = hash_pair_poseidon(&hashes[i - 1], &hashes[i - 1]);
			}
			Box::new(hashes)
		});
		return cache[level];
	}
	zero_hash_at_level(level)
}

/// Hash two nodes together using Poseidon (ZK-friendly, ~300 constraints).
#[inline]
pub fn hash_pair_poseidon(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
	use ark_bn254::Fr as Bn254Fr;
	use ark_ff::PrimeField;
	use orbinum_zk_core::{FieldElement, PoseidonHasher};

	let left_fr = Bn254Fr::from_le_bytes_mod_order(left);
	let right_fr = Bn254Fr::from_le_bytes_mod_order(right);

	#[cfg(feature = "poseidon-native")]
	let hasher = orbinum_zk_core::NativePoseidonHasher;
	#[cfg(not(feature = "poseidon-native"))]
	let hasher = orbinum_zk_core::LightPoseidonHasher;

	let hash_fr = hasher.hash_2([FieldElement::new(left_fr), FieldElement::new(right_fr)]);

	let mut hash_bytes = [0u8; 32];
	let bigint = hash_fr.inner().into_bigint();
	let bytes = bigint.to_bytes_le();
	hash_bytes.copy_from_slice(&bytes[..32]);
	hash_bytes
}

/// Hash pair — always uses Poseidon.
pub fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
	hash_pair_poseidon(left, right)
}
