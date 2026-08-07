//! Poseidon hashing for Merkle nodes.
//!
//! Pure functions over 32-byte field elements — no storage, no `Config`. The
//! zero-hash ladder is cached because every path read and every insert needs the
//! empty-subtree digest for each level.

use alloc::boxed::Box;
use ark_ff::BigInteger;

/// Digest of an empty subtree rooted at `level`.
///
/// Iterative rather than recursive. The recursion this replaces spent one stack
/// frame per level, and `get_zero_hash_cached` falls through to here for any
/// level past its 21-entry table — with `usize` being 32 bits under Wasm, a
/// caller passing a large level would exhaust the runtime's fixed 1 MB stack.
/// A stack overflow there takes the node down rather than failing a call, while
/// a loop just runs long: slow is recoverable, overflowing is not.
pub fn zero_hash_at_level(level: usize) -> [u8; 32] {
	let mut current = [0u8; 32];
	for _ in 0..level {
		current = hash_pair(&current, &current);
	}
	current
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

	// BN254 `Fr` always yields 32 bytes, so the clamp never binds today. It is
	// here because this runs on the block-import path, where slicing past the
	// end would panic the node rather than fail a call — the same reason
	// `recipient_to_field` is written this way.
	let mut hash_bytes = [0u8; 32];
	let bigint = hash_fr.inner().into_bigint();
	let bytes = bigint.to_bytes_le();
	let n = bytes.len().min(32);
	hash_bytes[..n].copy_from_slice(&bytes[..n]);
	hash_bytes
}

/// Hash pair — always uses Poseidon.
pub fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
	hash_pair_poseidon(left, right)
}
