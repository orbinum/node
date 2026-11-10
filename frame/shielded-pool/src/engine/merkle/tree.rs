//! `IncrementalMerkleTree` — the in-memory frontier structure.
//!
//! Holds no storage handles and knows nothing about `Config`: it is the pure
//! data structure, used by tests and by off-chain callers. The on-chain tree
//! lives in [`super::service`], which keeps the same frontier in storage.

use super::hashing::{get_zero_hash_cached, hash_pair};
use crate::types::MerklePath;
use frame_support::pallet_prelude::*;
use sp_std::vec::Vec;

/// An append-only Merkle tree of depth `DEPTH`, kept as its frontier: the last
/// left child seen at each level is all an insert needs.
#[derive(Clone, Encode, Decode, TypeInfo, MaxEncodedLen, Debug)]
pub struct IncrementalMerkleTree<const DEPTH: usize> {
	/// The last left child at each level, waiting for its right sibling.
	pub frontier: [[u8; 32]; DEPTH],
	/// Index the next leaf takes; also the number of leaves.
	pub next_index: u32,
	/// Current root.
	pub root: [u8; 32],
}

impl<const DEPTH: usize> Default for IncrementalMerkleTree<DEPTH> {
	fn default() -> Self {
		Self::new()
	}
}

impl<const DEPTH: usize> IncrementalMerkleTree<DEPTH> {
	/// `capacity()` shifts into a `u32`, so a depth of 32 or more would wrap. The
	/// bound sits on the type, not in the runtime config, because the struct is
	/// public and generic: instantiating it past the limit fails to compile.
	const _DEPTH_FITS_IN_U32: () = assert!(
		DEPTH < 32,
		"IncrementalMerkleTree DEPTH must be below 32: capacity() shifts into a u32"
	);

	/// An empty tree.
	pub fn new() -> Self {
		let root = Self::compute_empty_root();
		Self {
			frontier: [[0u8; 32]; DEPTH],
			next_index: 0,
			root,
		}
	}

	/// Root of the tree with no leaves.
	fn compute_empty_root() -> [u8; 32] {
		let mut current = [0u8; 32];
		for _ in 0..DEPTH {
			current = hash_pair(&current, &current);
		}
		current
	}

	/// Digest of an empty subtree at `level`.
	fn zero_hash(level: usize) -> [u8; 32] {
		get_zero_hash_cached(level)
	}

	/// Leaves the tree can hold: `2^DEPTH`.
	pub fn capacity(&self) -> u32 {
		let () = Self::_DEPTH_FITS_IN_U32;
		1u32 << DEPTH
	}
	/// Whether no further leaf fits.
	pub fn is_full(&self) -> bool {
		self.next_index >= self.capacity()
	}

	/// Append `leaf` and return its index: O(DEPTH), one walk up the frontier.
	pub fn insert(&mut self, leaf: [u8; 32]) -> Result<u32, &'static str> {
		if self.is_full() {
			return Err("Merkle tree is full");
		}
		let index = self.next_index;
		let mut current_hash = leaf;
		let mut current_index = index;

		for level in 0..DEPTH {
			if current_index.is_multiple_of(2) {
				self.frontier[level] = current_hash;
				let zero = Self::zero_hash(level);
				current_hash = hash_pair(&current_hash, &zero);
			} else {
				current_hash = hash_pair(&self.frontier[level], &current_hash);
			}
			current_index /= 2;
		}

		self.root = current_hash;
		self.next_index += 1;
		Ok(index)
	}

	/// Current root.
	pub fn root(&self) -> [u8; 32] {
		self.root
	}
	/// Number of leaves inserted.
	pub fn size(&self) -> u32 {
		self.next_index
	}

	/// The path of `leaf_index`, rebuilt from every leaf: O(n), for tests and
	/// off-chain use. `leaves` must be exactly the leaves inserted so far.
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
		let mut current_level = leaves.to_vec();
		let mut target_index = leaf_index as usize;

		for level in 0..DEPTH {
			if !current_level.len().is_multiple_of(2) {
				current_level.push(Self::zero_hash(level));
			}
			let sibling_index = if target_index.is_multiple_of(2) {
				indices[level] = 0;
				target_index + 1
			} else {
				indices[level] = 1;
				target_index - 1
			};
			siblings[level] = if sibling_index < current_level.len() {
				current_level[sibling_index]
			} else {
				Self::zero_hash(level)
			};
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

	/// Whether `path` takes `leaf` to `root`; `indices[level]` is 1 when the
	/// node is a right child.
	pub fn verify_proof(root: &[u8; 32], leaf: &[u8; 32], path: &MerklePath<DEPTH>) -> bool {
		let mut current = *leaf;
		for level in 0..DEPTH {
			let sibling = &path.siblings[level];
			current = if path.indices[level] == 0 {
				hash_pair(&current, sibling)
			} else {
				hash_pair(sibling, &current)
			};
		}
		&current == root
	}
}
