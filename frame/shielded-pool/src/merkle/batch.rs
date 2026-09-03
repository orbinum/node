//! Whole-tree root computation from a leaf set.
//!
//! O(n) in the number of leaves, so it is **not** used on any dispatchable path
//! — the on-chain insert walks the frontier in O(depth) instead. Kept for tests
//! and off-chain tooling that need to rebuild a root from scratch.

use super::hashing::{hash_pair, hash_pair_poseidon};
use crate::types::Hash;
use sp_std::vec::Vec;

pub fn compute_root_from_leaves_poseidon<const DEPTH: usize>(leaves: &[Hash]) -> Hash {
	if leaves.is_empty() {
		return [0u8; 32];
	}

	let mut zero_hashes = [[0u8; 32]; 21];
	zero_hashes[0] = [0u8; 32];
	for i in 1..=20 {
		zero_hashes[i] = hash_pair_poseidon(&zero_hashes[i - 1], &zero_hashes[i - 1]);
	}

	let mut current_level: Vec<Hash> = leaves.to_vec();

	for level in 0..DEPTH {
		if !current_level.len().is_multiple_of(2) {
			current_level.push(zero_hashes[level]);
		}
		let mut next_level = Vec::new();
		for i in (0..current_level.len()).step_by(2) {
			next_level.push(hash_pair_poseidon(&current_level[i], &current_level[i + 1]));
		}
		current_level = next_level;
		if current_level.len() == 1 && level + 1 < DEPTH {
			let mut root = current_level[0];
			for zero_hash in zero_hashes.iter().skip(level + 1).take(DEPTH - level - 1) {
				root = hash_pair_poseidon(&root, zero_hash);
			}
			return root;
		}
	}
	current_level.first().copied().unwrap_or([0u8; 32])
}

pub fn compute_root_from_leaves<const DEPTH: usize>(leaves: &[Hash]) -> Hash {
	if leaves.is_empty() {
		let mut current = [0u8; 32];
		for _ in 0..DEPTH {
			current = hash_pair(&current, &current);
		}
		return current;
	}
	let mut current_level: Vec<Hash> = leaves.to_vec();
	for level in 0..DEPTH {
		if !current_level.len().is_multiple_of(2) {
			let mut zero = [0u8; 32];
			for _ in 0..level {
				zero = hash_pair(&zero, &zero);
			}
			current_level.push(zero);
		}
		let mut next_level = Vec::new();
		for chunk in current_level.chunks(2) {
			let left = chunk[0];
			let right = if chunk.len() > 1 {
				chunk[1]
			} else {
				let mut zero = [0u8; 32];
				for _ in 0..level {
					zero = hash_pair(&zero, &zero);
				}
				zero
			};
			next_level.push(hash_pair(&left, &right));
		}
		current_level = next_level;
		if current_level.len() == 1 && level + 1 < DEPTH {
			let mut zero = [0u8; 32];
			for _ in 0..=level {
				zero = hash_pair(&zero, &zero);
			}
			for _ in (level + 1)..DEPTH {
				current_level[0] = hash_pair(&current_level[0], &zero);
				zero = hash_pair(&zero, &zero);
			}
			break;
		}
	}
	current_level.first().copied().unwrap_or([0u8; 32])
}
