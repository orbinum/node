//! Sparse Merkle Tree implementation for the Shielded Pool
//!
//! This module provides an incremental Merkle tree optimized for on-chain storage.
//! Uses Poseidon hash with native host functions (ZK-friendly).
//!
//! ## Design
//!
//! The tree is append-only and stores:
//! - Leaves: commitment hashes
//! - Internal nodes: computed lazily during proof generation
//!
//! ```text
//!                    Root (depth 0)
//!                   /              \
//!          H(0,0)                    H(0,1)
//!         /      \                  /      \
//!     H(1,0)    H(1,1)          H(1,2)    H(1,3)
//!     /    \    /    \          /    \    /    \
//!   L0    L1  L2    L3        L4    L5  L6    L7
//! ```

use crate::domain::value_objects::{Hash, MerklePath};
use alloc::boxed::Box;
use ark_ff::BigInteger;
use frame_support::pallet_prelude::*;
use sp_std::vec::Vec;

/// Default hash for empty nodes at each level
/// These are precomputed as H(zero, zero) for each level
pub fn zero_hash_at_level(level: usize) -> [u8; 32] {
	// Level 0 is empty leaf
	if level == 0 {
		return [0u8; 32];
	}
	// Each subsequent level is H(zero[n-1], zero[n-1])
	let prev = zero_hash_at_level(level - 1);
	hash_pair(&prev, &prev)
}

/// Precomputed zero hashes for common depths (up to 20)
///
/// For Poseidon: These are computed at runtime and cached for efficiency
///
/// ## Structure
/// - Level 0: empty leaf (0x00...00)
/// - Level n: H(zero[n-1], zero[n-1])
pub const ZERO_HASHES: [[u8; 32]; 21] = compute_zero_hashes();

const fn compute_zero_hashes() -> [[u8; 32]; 21] {
	// Note: Cannot use hash_pair in const context due to feature flags
	// Zero hashes must be computed at runtime on first access
	// This is acceptable as they're cached after first computation
	[[0u8; 32]; 21]
}

/// Cached zero hashes for Poseidon (lazy-initialized, thread-safe)
///
/// Uses `once_cell::race::OnceBox` which works in no-std with alloc feature.
/// The first call computes all hashes, subsequent calls return cached values.
static ZERO_HASHES_POSEIDON: once_cell::race::OnceBox<[[u8; 32]; 21]> =
	once_cell::race::OnceBox::new();

/// Get precomputed zero hash at level (optimized with cache)
///
/// Uses lazy-initialized cache with Poseidon (computed once, reused)
#[inline]
pub fn get_zero_hash_cached(level: usize) -> [u8; 32] {
	if level < 21 {
		let cache = ZERO_HASHES_POSEIDON.get_or_init(|| {
			let mut hashes = [[0u8; 32]; 21];
			hashes[0] = [0u8; 32]; // empty leaf
			for i in 1..21 {
				hashes[i] = hash_pair_poseidon(&hashes[i - 1], &hashes[i - 1]);
			}
			Box::new(hashes)
		});
		return cache[level];
	}

	// Fallback: direct computation for deep levels
	zero_hash_at_level(level)
}

/// Hash two nodes together using Poseidon
///
/// Uses Poseidon hash (ZK-friendly, ~300 constraints)
/// Compatible with circomlib Poseidon(2) used in ZK circuits.
#[inline]
/// Hash pair usando Poseidon con implementación nativa
///
/// Clean Architecture: Usa NativePoseidonHasher port (~3x más rápido vía host functions)
pub fn hash_pair_poseidon(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
	use ark_bn254::Fr as Bn254Fr;
	use ark_ff::PrimeField;
	use orbinum_zk_core::domain::{ports::PoseidonHasher, value_objects::FieldElement};

	// Convert bytes to field elements (little-endian mod order)
	let left_fr = Bn254Fr::from_le_bytes_mod_order(left);
	let right_fr = Bn254Fr::from_le_bytes_mod_order(right);

	// Usa siempre NativePoseidonHasher (~3x faster via host functions)
	let hasher = orbinum_zk_core::NativePoseidonHasher;

	// Hash using the domain port (Clean Architecture)
	let hash_fr = hasher.hash_2([FieldElement::new(left_fr), FieldElement::new(right_fr)]);

	// Convert back to bytes (little-endian)
	let mut hash_bytes = [0u8; 32];
	let bigint = hash_fr.inner().into_bigint();
	let bytes = bigint.to_bytes_le();
	hash_bytes.copy_from_slice(&bytes[..32]);
	hash_bytes
}

/// Hash pair - siempre usa Poseidon nativo
pub fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
	hash_pair_poseidon(left, right)
}

/// Incremental Merkle Tree
///
/// This implementation stores only the "frontier" - the rightmost nodes at each level
/// that are needed to compute the root when a new leaf is added.
///
/// Storage: O(depth) instead of O(2^depth)
#[derive(Clone, Encode, Decode, TypeInfo, MaxEncodedLen, Debug)]
pub struct IncrementalMerkleTree<const DEPTH: usize> {
	/// The rightmost node at each level (frontier)
	pub frontier: [[u8; 32]; DEPTH],
	/// Current number of leaves
	pub next_index: u32,
	/// Current root hash
	pub root: [u8; 32],
}

impl<const DEPTH: usize> Default for IncrementalMerkleTree<DEPTH> {
	fn default() -> Self {
		Self::new()
	}
}

impl<const DEPTH: usize> IncrementalMerkleTree<DEPTH> {
	/// Create a new empty tree
	pub fn new() -> Self {
		// Initialize with empty tree root
		let root = Self::compute_empty_root();
		Self {
			frontier: [[0u8; 32]; DEPTH],
			next_index: 0,
			root,
		}
	}

	/// Compute the root of an empty tree
	fn compute_empty_root() -> [u8; 32] {
		let mut current = [0u8; 32]; // empty leaf
		for _ in 0..DEPTH {
			current = hash_pair(&current, &current);
		}
		current
	}

	/// Get the zero hash for a given level
	fn zero_hash(level: usize) -> [u8; 32] {
		// Use cached version when available (Poseidon optimization)
		get_zero_hash_cached(level)
	}

	/// Get the maximum capacity of the tree
	pub fn capacity(&self) -> u32 {
		1u32 << DEPTH
	}

	/// Check if the tree is full
	pub fn is_full(&self) -> bool {
		self.next_index >= self.capacity()
	}

	/// Insert a new leaf and return its index
	pub fn insert(&mut self, leaf: [u8; 32]) -> Result<u32, &'static str> {
		if self.is_full() {
			return Err("Merkle tree is full");
		}

		let index = self.next_index;
		let mut current_hash = leaf;
		let mut current_index = index;

		// Update frontier and compute new root
		for level in 0..DEPTH {
			if current_index % 2 == 0 {
				// Left child - store in frontier and hash with zero
				self.frontier[level] = current_hash;
				let zero = Self::zero_hash(level);
				current_hash = hash_pair(&current_hash, &zero);
			} else {
				// Right child - hash with frontier
				current_hash = hash_pair(&self.frontier[level], &current_hash);
			}
			current_index /= 2;
		}

		self.root = current_hash;
		self.next_index += 1;

		Ok(index)
	}

	/// Get the current root
	pub fn root(&self) -> [u8; 32] {
		self.root
	}

	/// Get the number of leaves in the tree
	pub fn size(&self) -> u32 {
		self.next_index
	}

	/// Generate a Merkle path for a given leaf index
	///
	/// This uses a simple algorithm that rebuilds the tree from leaves
	pub fn generate_proof(
		&self,
		leaf_index: u32,
		leaves: &[[u8; 32]],
	) -> Result<MerklePath<DEPTH>, &'static str> {
		if leaf_index >= self.next_index {
			return Err("Leaf index out of bounds");
		}
		if leaves.len() != self.next_index as usize {
			return Err("Leaves count mismatch");
		}

		let mut siblings = [[0u8; 32]; DEPTH];
		let mut indices = [0u8; DEPTH];

		// Build the tree level by level and extract siblings
		let mut current_level = leaves.to_vec();
		let mut target_index = leaf_index as usize;

		for level in 0..DEPTH {
			// Pad current level to even length with zero hashes
			if current_level.len() % 2 != 0 {
				current_level.push(Self::zero_hash(level));
			}

			// Determine sibling
			let sibling_index = if target_index % 2 == 0 {
				indices[level] = 0; // We're on the left
				target_index + 1
			} else {
				indices[level] = 1; // We're on the right
				target_index - 1
			};

			siblings[level] = if sibling_index < current_level.len() {
				current_level[sibling_index]
			} else {
				Self::zero_hash(level)
			};

			// Compute next level
			let mut next_level = Vec::new();
			for chunk in current_level.chunks(2) {
				let left = chunk[0];
				let right = if chunk.len() > 1 {
					chunk[1]
				} else {
					Self::zero_hash(level)
				};
				next_level.push(hash_pair(&left, &right));
			}

			current_level = next_level;
			target_index /= 2;
		}

		Ok(MerklePath { siblings, indices })
	}

	/// Verify a Merkle proof
	pub fn verify_proof(root: &[u8; 32], leaf: &[u8; 32], path: &MerklePath<DEPTH>) -> bool {
		let mut current = *leaf;

		for level in 0..DEPTH {
			let sibling = &path.siblings[level];
			current = if path.indices[level] == 0 {
				// We're on the left, sibling is on the right
				hash_pair(&current, sibling)
			} else {
				// We're on the right, sibling is on the left
				hash_pair(sibling, &current)
			};
		}

		&current == root
	}
}

/// Compute the Merkle root from a set of leaves using Poseidon
pub fn compute_root_from_leaves_poseidon<const DEPTH: usize>(leaves: &[Hash]) -> Hash {
	if leaves.is_empty() {
		// Return empty tree root
		let mut current = [0u8; 32];
		for _ in 0..DEPTH {
			current = hash_pair_poseidon(&current, &current);
		}
		return current;
	}

	let mut current_level: Vec<Hash> = leaves.to_vec();

	// Compute up the tree
	for level in 0..DEPTH {
		// Pad to even length
		if current_level.len() % 2 != 0 {
			let mut zero = [0u8; 32];
			for _ in 0..level {
				zero = hash_pair_poseidon(&zero, &zero);
			}
			current_level.push(zero);
		}

		// Compute next level
		let mut next_level = Vec::new();
		for chunk in current_level.chunks(2) {
			let left = chunk[0];
			let right = if chunk.len() > 1 {
				chunk[1]
			} else {
				let mut zero = [0u8; 32];
				for _ in 0..level {
					zero = hash_pair_poseidon(&zero, &zero);
				}
				zero
			};
			next_level.push(hash_pair_poseidon(&left, &right));
		}
		current_level = next_level;

		if current_level.len() == 1 {
			// We might have reached the root early, but we need to continue
			// hashing with zeros to reach the correct depth
			if level + 1 < DEPTH {
				let mut zero = [0u8; 32];
				for _ in 0..=level {
					zero = hash_pair_poseidon(&zero, &zero);
				}
				for _ in (level + 1)..DEPTH {
					current_level[0] = hash_pair_poseidon(&current_level[0], &zero);
					zero = hash_pair_poseidon(&zero, &zero);
				}
				break;
			}
		}
	}

	current_level.first().copied().unwrap_or([0u8; 32])
}

/// Compute the Merkle root from a set of leaves (legacy - usa hash_pair)
pub fn compute_root_from_leaves<const DEPTH: usize>(leaves: &[Hash]) -> Hash {
	if leaves.is_empty() {
		// Return empty tree root
		let mut current = [0u8; 32];
		for _ in 0..DEPTH {
			current = hash_pair(&current, &current);
		}
		return current;
	}

	let mut current_level: Vec<Hash> = leaves.to_vec();

	// Compute up the tree
	for level in 0..DEPTH {
		// Pad to even length
		if current_level.len() % 2 != 0 {
			let mut zero = [0u8; 32];
			for _ in 0..level {
				zero = hash_pair(&zero, &zero);
			}
			current_level.push(zero);
		}

		// Compute next level
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

		if current_level.len() == 1 {
			// We might have reached the root early, but we need to continue
			// hashing with zeros to reach the correct depth
			if level + 1 < DEPTH {
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
	}

	current_level.first().copied().unwrap_or([0u8; 32])
}
