//! Merkle tree — data structures, Poseidon hashing, and tree service.
//!
//! Merges the former `infrastructure/merkle_tree.rs` (IncrementalMerkleTree,
//! hash functions) with `infrastructure/services/merkle_tree_service.rs`
//! (on-chain tree management using repositories).

use crate::{
	pallet::{CommitmentMemos, Config, Error, Event, Pallet},
	storage::{MerkleRepository, PoolStatsRepository},
	types::{Commitment, DefaultMerklePath, Hash, MerklePath},
};
use alloc::boxed::Box;
use ark_ff::BigInteger;
use frame_support::{ensure, pallet_prelude::*, traits::Get};
use sp_std::vec::Vec;

// ════════════════════════════════════════════════════════════════════════════
// Hash helpers
// ════════════════════════════════════════════════════════════════════════════

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

// ════════════════════════════════════════════════════════════════════════════
// IncrementalMerkleTree (data structure, no storage access)
// ════════════════════════════════════════════════════════════════════════════

#[derive(Clone, Encode, Decode, TypeInfo, MaxEncodedLen, Debug)]
pub struct IncrementalMerkleTree<const DEPTH: usize> {
	pub frontier: [[u8; 32]; DEPTH],
	pub next_index: u32,
	pub root: [u8; 32],
}

impl<const DEPTH: usize> Default for IncrementalMerkleTree<DEPTH> {
	fn default() -> Self {
		Self::new()
	}
}

impl<const DEPTH: usize> IncrementalMerkleTree<DEPTH> {
	pub fn new() -> Self {
		let root = Self::compute_empty_root();
		Self {
			frontier: [[0u8; 32]; DEPTH],
			next_index: 0,
			root,
		}
	}

	fn compute_empty_root() -> [u8; 32] {
		let mut current = [0u8; 32];
		for _ in 0..DEPTH {
			current = hash_pair(&current, &current);
		}
		current
	}

	fn zero_hash(level: usize) -> [u8; 32] {
		get_zero_hash_cached(level)
	}

	pub fn capacity(&self) -> u32 {
		1u32 << DEPTH
	}
	pub fn is_full(&self) -> bool {
		self.next_index >= self.capacity()
	}

	pub fn insert(&mut self, leaf: [u8; 32]) -> Result<u32, &'static str> {
		if self.is_full() {
			return Err("Merkle tree is full");
		}
		let index = self.next_index;
		let mut current_hash = leaf;
		let mut current_index = index;

		for level in 0..DEPTH {
			if current_index % 2 == 0 {
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

	pub fn root(&self) -> [u8; 32] {
		self.root
	}
	pub fn size(&self) -> u32 {
		self.next_index
	}

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
			if current_level.len() % 2 != 0 {
				current_level.push(Self::zero_hash(level));
			}
			let sibling_index = if target_index % 2 == 0 {
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

// ════════════════════════════════════════════════════════════════════════════
// Root computation helpers
// ════════════════════════════════════════════════════════════════════════════

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
		if current_level.len() % 2 != 0 {
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
		if current_level.len() % 2 != 0 {
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

// ════════════════════════════════════════════════════════════════════════════
// MerkleTreeService (on-chain tree management, uses repositories)
// ════════════════════════════════════════════════════════════════════════════

pub struct MerkleTreeService;

impl MerkleTreeService {
	/// Insert a new leaf into the Merkle tree.
	///
	/// Uses an incremental frontier algorithm: O(depth) hashes per insert,
	/// replacing the former O(n) full recomputation from all leaves.
	pub fn insert_leaf<T: Config>(commitment: Commitment) -> Result<u32, DispatchError> {
		let index = MerkleRepository::get_tree_size::<T>();
		let max_leaves = 2u32.saturating_pow(crate::types::MAX_TREE_DEPTH);
		ensure!(index < max_leaves, Error::<T>::MerkleTreeFull);
		ensure!(
			!CommitmentMemos::<T>::contains_key(commitment),
			Error::<T>::CommitmentAlreadyExists
		);

		// Load frontier from storage and run one incremental update.
		// Depth is always DEFAULT_TREE_DEPTH (20) — matches the fixed-size frontier array.
		let mut frontier = MerkleRepository::get_frontier::<T>();
		let mut current_hash = commitment.0;
		let mut current_index = index;

		for (level, frontier_slot) in frontier.iter_mut().enumerate() {
			if current_index % 2 == 0 {
				// Left node: save in frontier, pair with zero-sibling
				*frontier_slot = current_hash;
				let zero = get_zero_hash_cached(level);
				current_hash = hash_pair(&current_hash, &zero);
			} else {
				// Right node: combine with stored left sibling
				current_hash = hash_pair(frontier_slot, &current_hash);
			}
			current_index /= 2;
		}

		let new_poseidon_root = current_hash;
		let old_poseidon_root = MerkleRepository::get_poseidon_root::<T>();

		MerkleRepository::insert_leaf::<T>(index, commitment);
		MerkleRepository::set_commitment_leaf_index::<T>(commitment, index);
		MerkleRepository::set_tree_size::<T>(index.saturating_add(1));
		PoolStatsRepository::increment_commitments_inserted::<T>();
		MerkleRepository::set_frontier::<T>(frontier);
		MerkleRepository::set_poseidon_root::<T>(new_poseidon_root);
		Self::add_poseidon_historic_root::<T>(new_poseidon_root);

		Pallet::<T>::deposit_event(Event::MerkleRootUpdated {
			old_root: old_poseidon_root,
			new_root: new_poseidon_root,
			tree_size: index.saturating_add(1),
		});
		Ok(index)
	}

	pub(crate) fn add_poseidon_historic_root<T: Config>(poseidon_root: Hash) {
		let mut order = MerkleRepository::get_historic_roots_order::<T>();
		if order.len() >= T::MaxHistoricRoots::get() as usize {
			if let Some(oldest_root) = order.first().copied() {
				order.remove(0);
				if !order.contains(&oldest_root) {
					MerkleRepository::remove_poseidon_historic_root::<T>(&oldest_root);
				}
			}
		}
		if order.try_push(poseidon_root).is_ok() {
			MerkleRepository::add_historic_poseidon_root::<T>(poseidon_root);
			MerkleRepository::set_historic_roots_order::<T>(order);
		}
	}

	pub fn is_known_root<T: Config>(root: &Hash) -> bool {
		MerkleRepository::is_known_root::<T>(root)
	}

	pub fn get_merkle_path<T: Config>(leaf_index: u32) -> Option<DefaultMerklePath> {
		let size = MerkleRepository::get_tree_size::<T>();
		if leaf_index >= size {
			return None;
		}
		let leaves = MerkleRepository::get_all_leaves::<T>();
		if leaves.is_empty() {
			return None;
		}

		let mut siblings = [[0u8; 32]; 20];
		let mut indices = [0u8; 20];
		let mut current_level: sp_std::vec::Vec<Hash> = leaves;
		let mut target_index = leaf_index as usize;

		for level in 0..20 {
			if current_level.len() % 2 != 0 {
				current_level.push(zero_hash_at_level(level));
			}
			let sibling_index = if target_index % 2 == 0 {
				indices[level] = 0;
				target_index + 1
			} else {
				indices[level] = 1;
				target_index - 1
			};
			siblings[level] = if sibling_index < current_level.len() {
				current_level[sibling_index]
			} else {
				zero_hash_at_level(level)
			};
			let mut next_level = sp_std::vec::Vec::new();
			for i in (0..current_level.len()).step_by(2) {
				let left = current_level[i];
				let right = if i + 1 < current_level.len() {
					current_level[i + 1]
				} else {
					zero_hash_at_level(level)
				};
				next_level.push(hash_pair_poseidon(&left, &right));
			}
			current_level = next_level;
			target_index /= 2;
		}
		Some(DefaultMerklePath { siblings, indices })
	}

	pub fn verify_merkle_proof(root: &Hash, leaf: &Hash, path: &DefaultMerklePath) -> bool {
		IncrementalMerkleTree::<20>::verify_proof(root, leaf, path)
	}

	pub fn find_leaf_index<T: Config>(commitment: &Commitment) -> Option<u32> {
		MerkleRepository::find_leaf_index::<T>(commitment)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::{
		mock::{Test, new_test_ext},
		types::Commitment,
	};

	// ── hash functions ──────────────────────────────────────────────────────

	#[test]
	fn hash_pair_poseidon_deterministic() {
		let left = [0x01u8; 32];
		let right = [0x02u8; 32];
		let h1 = hash_pair_poseidon(&left, &right);
		let h2 = hash_pair_poseidon(&left, &right);
		assert_eq!(h1, h2);
		assert_ne!(h1, [0u8; 32]);
	}

	#[test]
	fn hash_pair_poseidon_not_commutative() {
		let left = [0x01u8; 32];
		let right = [0x02u8; 32];
		let h1 = hash_pair_poseidon(&left, &right);
		let h2 = hash_pair_poseidon(&right, &left);
		assert_ne!(h1, h2);
	}

	#[test]
	fn hash_pair_delegates_to_poseidon() {
		let left = [0x03u8; 32];
		let right = [0x04u8; 32];
		assert_eq!(hash_pair(&left, &right), hash_pair_poseidon(&left, &right));
	}

	#[test]
	fn zero_hash_level_0_is_all_zeros() {
		assert_eq!(zero_hash_at_level(0), [0u8; 32]);
	}

	#[test]
	fn zero_hash_level_1_is_hash_of_zeros() {
		let expected = hash_pair(&[0u8; 32], &[0u8; 32]);
		assert_eq!(zero_hash_at_level(1), expected);
	}

	#[test]
	fn zero_hash_levels_are_distinct() {
		let h0 = zero_hash_at_level(0);
		let h1 = zero_hash_at_level(1);
		let h2 = zero_hash_at_level(2);
		assert_ne!(h0, h1);
		assert_ne!(h1, h2);
	}

	#[test]
	fn get_zero_hash_cached_matches_uncached() {
		for level in 0..5usize {
			assert_eq!(get_zero_hash_cached(level), zero_hash_at_level(level));
		}
	}

	// ── IncrementalMerkleTree ────────────────────────────────────────────────

	#[test]
	fn tree_new_has_zero_size() {
		let tree = IncrementalMerkleTree::<4>::new();
		assert_eq!(tree.size(), 0);
	}

	#[test]
	fn tree_new_root_is_non_zero() {
		let tree = IncrementalMerkleTree::<4>::new();
		assert_ne!(tree.root(), [0u8; 32]);
	}

	#[test]
	fn tree_capacity_is_power_of_two() {
		assert_eq!(IncrementalMerkleTree::<4>::new().capacity(), 16);
		assert_eq!(IncrementalMerkleTree::<2>::new().capacity(), 4);
	}

	#[test]
	fn tree_insert_returns_sequential_indices() {
		let mut tree = IncrementalMerkleTree::<4>::new();
		assert_eq!(tree.insert([0x01u8; 32]).unwrap(), 0);
		assert_eq!(tree.insert([0x02u8; 32]).unwrap(), 1);
		assert_eq!(tree.insert([0x03u8; 32]).unwrap(), 2);
		assert_eq!(tree.size(), 3);
	}

	#[test]
	fn tree_root_changes_after_insert() {
		let mut tree = IncrementalMerkleTree::<4>::new();
		let root_before = tree.root();
		tree.insert([0xAAu8; 32]).unwrap();
		assert_ne!(tree.root(), root_before);
	}

	#[test]
	fn tree_full_rejects_further_inserts() {
		let mut tree = IncrementalMerkleTree::<2>::new();
		for i in 0u8..4 {
			tree.insert([i; 32]).unwrap();
		}
		assert!(tree.is_full());
		assert!(tree.insert([0xFFu8; 32]).is_err());
	}

	#[test]
	fn tree_default_equals_new() {
		let t1 = IncrementalMerkleTree::<4>::new();
		let t2 = IncrementalMerkleTree::<4>::default();
		assert_eq!(t1.root(), t2.root());
		assert_eq!(t1.size(), t2.size());
	}

	#[test]
	fn tree_generate_and_verify_proof_passes() {
		let mut tree = IncrementalMerkleTree::<4>::new();
		let leaves = [[0x01u8; 32], [0x02u8; 32], [0x03u8; 32]];
		for &leaf in &leaves {
			tree.insert(leaf).unwrap();
		}
		let proof = tree.generate_proof(0, &leaves).unwrap();
		assert!(IncrementalMerkleTree::<4>::verify_proof(
			&tree.root(),
			&leaves[0],
			&proof
		));
	}

	#[test]
	fn tree_proof_fails_for_wrong_leaf() {
		let mut tree = IncrementalMerkleTree::<4>::new();
		let leaves = [[0x01u8; 32], [0x02u8; 32]];
		for &l in &leaves {
			tree.insert(l).unwrap();
		}
		let proof = tree.generate_proof(0, &leaves).unwrap();
		assert!(!IncrementalMerkleTree::<4>::verify_proof(
			&tree.root(),
			&[0xFFu8; 32],
			&proof
		));
	}

	#[test]
	fn tree_generate_proof_out_of_bounds_fails() {
		let mut tree = IncrementalMerkleTree::<4>::new();
		tree.insert([0x01u8; 32]).unwrap();
		let leaves = [[0x01u8; 32]];
		assert!(tree.generate_proof(5, &leaves).is_err());
	}

	// ── compute_root_from_leaves_poseidon ────────────────────────────────────

	#[test]
	fn compute_root_poseidon_empty_is_zero() {
		assert_eq!(compute_root_from_leaves_poseidon::<4>(&[]), [0u8; 32]);
	}

	#[test]
	fn compute_root_poseidon_single_leaf_nonzero() {
		let root = compute_root_from_leaves_poseidon::<4>(&[[0x01u8; 32]]);
		assert_ne!(root, [0u8; 32]);
		assert_ne!(root, [0x01u8; 32]);
	}

	#[test]
	fn compute_root_poseidon_same_leaves_same_root() {
		let leaves = [[0x01u8; 32], [0x02u8; 32]];
		let r1 = compute_root_from_leaves_poseidon::<4>(&leaves);
		let r2 = compute_root_from_leaves_poseidon::<4>(&leaves);
		assert_eq!(r1, r2);
	}

	#[test]
	fn compute_root_poseidon_different_leaves_different_roots() {
		let r1 = compute_root_from_leaves_poseidon::<4>(&[[0x01u8; 32]]);
		let r2 = compute_root_from_leaves_poseidon::<4>(&[[0x02u8; 32]]);
		assert_ne!(r1, r2);
	}

	// ── MerkleTreeService (FRAME-backed) ─────────────────────────────────────

	#[test]
	fn service_insert_leaf_returns_sequential_indices() {
		new_test_ext().execute_with(|| {
			let c0 = Commitment::new([0x01u8; 32]);
			let c1 = Commitment::new([0x02u8; 32]);
			assert_eq!(MerkleTreeService::insert_leaf::<Test>(c0).unwrap(), 0);
			assert_eq!(MerkleTreeService::insert_leaf::<Test>(c1).unwrap(), 1);
		});
	}

	#[test]
	fn service_insert_duplicate_fails() {
		new_test_ext().execute_with(|| {
			let c = Commitment::new([0x01u8; 32]);
			MerkleTreeService::insert_leaf::<Test>(c).unwrap();
			// Duplicate detection is based on CommitmentMemos; simulate a prior memo insert
			// (operations layer stores the memo when shielding/transferring)
			use crate::storage::CommitmentRepository;
			use crate::types::{EncryptedMemo, MAX_ENCRYPTED_MEMO_SIZE};
			CommitmentRepository::store_memo::<Test>(
				c,
				EncryptedMemo::from_bytes(&[0x01u8; MAX_ENCRYPTED_MEMO_SIZE as usize]).unwrap(),
			);
			assert!(MerkleTreeService::insert_leaf::<Test>(c).is_err());
		});
	}

	#[test]
	fn service_insert_updates_poseidon_root() {
		new_test_ext().execute_with(|| {
			use crate::storage::MerkleRepository;
			let root_before = MerkleRepository::get_poseidon_root::<Test>();
			MerkleTreeService::insert_leaf::<Test>(Commitment::new([0xAAu8; 32])).unwrap();
			let root_after = MerkleRepository::get_poseidon_root::<Test>();
			assert_ne!(root_before, root_after);
		});
	}

	#[test]
	fn service_insert_adds_root_to_historic() {
		new_test_ext().execute_with(|| {
			MerkleTreeService::insert_leaf::<Test>(Commitment::new([0xBBu8; 32])).unwrap();
			use crate::storage::MerkleRepository;
			let root = MerkleRepository::get_poseidon_root::<Test>();
			assert!(MerkleTreeService::is_known_root::<Test>(&root));
		});
	}

	#[test]
	fn service_get_merkle_path_none_for_empty_tree() {
		new_test_ext().execute_with(|| {
			assert!(MerkleTreeService::get_merkle_path::<Test>(0).is_none());
		});
	}

	#[test]
	fn service_get_merkle_path_some_after_insert() {
		new_test_ext().execute_with(|| {
			MerkleTreeService::insert_leaf::<Test>(Commitment::new([0x01u8; 32])).unwrap();
			assert!(MerkleTreeService::get_merkle_path::<Test>(0).is_some());
		});
	}

	#[test]
	fn service_get_merkle_path_none_out_of_bounds() {
		new_test_ext().execute_with(|| {
			MerkleTreeService::insert_leaf::<Test>(Commitment::new([0x01u8; 32])).unwrap();
			assert!(MerkleTreeService::get_merkle_path::<Test>(99).is_none());
		});
	}

	#[test]
	fn service_verify_merkle_proof_valid_round_trip() {
		new_test_ext().execute_with(|| {
			let leaf = [0x11u8; 32];
			MerkleTreeService::insert_leaf::<Test>(Commitment::new(leaf)).unwrap();
			use crate::storage::MerkleRepository;
			let root = MerkleRepository::get_poseidon_root::<Test>();
			let path = MerkleTreeService::get_merkle_path::<Test>(0).unwrap();
			assert!(MerkleTreeService::verify_merkle_proof(&root, &leaf, &path));
		});
	}

	#[test]
	fn service_verify_merkle_proof_fails_for_wrong_root() {
		new_test_ext().execute_with(|| {
			let leaf = [0x12u8; 32];
			MerkleTreeService::insert_leaf::<Test>(Commitment::new(leaf)).unwrap();
			let path = MerkleTreeService::get_merkle_path::<Test>(0).unwrap();
			assert!(!MerkleTreeService::verify_merkle_proof(
				&[0xFFu8; 32],
				&leaf,
				&path
			));
		});
	}

	#[test]
	fn service_find_leaf_index_none_for_unknown() {
		new_test_ext().execute_with(|| {
			let c = Commitment::new([0xCCu8; 32]);
			assert!(MerkleTreeService::find_leaf_index::<Test>(&c).is_none());
		});
	}

	#[test]
	fn service_find_leaf_index_correct_after_multiple_inserts() {
		new_test_ext().execute_with(|| {
			let c0 = Commitment::new([0x01u8; 32]);
			let c1 = Commitment::new([0x02u8; 32]);
			MerkleTreeService::insert_leaf::<Test>(c0).unwrap();
			MerkleTreeService::insert_leaf::<Test>(c1).unwrap();
			assert_eq!(MerkleTreeService::find_leaf_index::<Test>(&c0), Some(0));
			assert_eq!(MerkleTreeService::find_leaf_index::<Test>(&c1), Some(1));
		});
	}

	#[test]
	fn insert_leaf_populates_commitment_to_leaf_index() {
		use crate::storage::MerkleRepository;
		new_test_ext().execute_with(|| {
			let c0 = Commitment::new([0xD0u8; 32]);
			let c1 = Commitment::new([0xD1u8; 32]);
			let c2 = Commitment::new([0xD2u8; 32]);
			MerkleTreeService::insert_leaf::<Test>(c0).unwrap();
			MerkleTreeService::insert_leaf::<Test>(c1).unwrap();
			MerkleTreeService::insert_leaf::<Test>(c2).unwrap();
			// Reverse index must be populated for every inserted commitment
			assert_eq!(
				MerkleRepository::get_commitment_leaf_index::<Test>(&c0),
				Some(0)
			);
			assert_eq!(
				MerkleRepository::get_commitment_leaf_index::<Test>(&c1),
				Some(1)
			);
			assert_eq!(
				MerkleRepository::get_commitment_leaf_index::<Test>(&c2),
				Some(2)
			);
			// Unknown commitment returns None
			assert_eq!(
				MerkleRepository::get_commitment_leaf_index::<Test>(&Commitment::new([0xFFu8; 32])),
				None
			);
		});
	}

	#[test]
	fn insert_leaf_increments_total_commitments_counter() {
		use crate::storage::PoolStatsRepository;
		new_test_ext().execute_with(|| {
			assert_eq!(
				PoolStatsRepository::get_total_commitments_inserted::<Test>(),
				0
			);
			MerkleTreeService::insert_leaf::<Test>(Commitment::new([0xF0u8; 32])).unwrap();
			assert_eq!(
				PoolStatsRepository::get_total_commitments_inserted::<Test>(),
				1
			);
			MerkleTreeService::insert_leaf::<Test>(Commitment::new([0xF1u8; 32])).unwrap();
			MerkleTreeService::insert_leaf::<Test>(Commitment::new([0xF2u8; 32])).unwrap();
			assert_eq!(
				PoolStatsRepository::get_total_commitments_inserted::<Test>(),
				3
			);
		});
	}

	// ── Incremental frontier vs batch consistency ────────────────────────────

	#[test]
	fn incremental_root_matches_batch_root_after_single_insert() {
		new_test_ext().execute_with(|| {
			let leaf = [0x11u8; 32];
			MerkleTreeService::insert_leaf::<Test>(Commitment::new(leaf)).unwrap();

			let incremental_root = crate::storage::MerkleRepository::get_poseidon_root::<Test>();
			let batch_root = compute_root_from_leaves_poseidon::<20>(&[leaf]);
			assert_eq!(
				incremental_root, batch_root,
				"incremental and batch roots must agree after 1 insert"
			);
		});
	}

	#[test]
	fn incremental_root_matches_batch_root_after_multiple_inserts() {
		new_test_ext().execute_with(|| {
			let leaves = [
				[0x01u8; 32],
				[0x02u8; 32],
				[0x03u8; 32],
				[0x04u8; 32],
				[0x05u8; 32],
			];
			for &leaf in &leaves {
				MerkleTreeService::insert_leaf::<Test>(Commitment::new(leaf)).unwrap();
			}

			let incremental_root = crate::storage::MerkleRepository::get_poseidon_root::<Test>();
			let batch_root = compute_root_from_leaves_poseidon::<20>(&leaves);
			assert_eq!(
				incremental_root, batch_root,
				"incremental and batch roots must agree after multiple inserts"
			);
		});
	}

	#[test]
	fn incremental_proof_verifies_against_incremental_root() {
		new_test_ext().execute_with(|| {
			let leaves = [[0x0Au8; 32], [0x0Bu8; 32], [0x0Cu8; 32]];
			for &leaf in &leaves {
				MerkleTreeService::insert_leaf::<Test>(Commitment::new(leaf)).unwrap();
			}

			// Proof computed from all leaves (batch), root stored incrementally.
			// Both must be consistent.
			let root = crate::storage::MerkleRepository::get_poseidon_root::<Test>();
			for (i, &leaf) in leaves.iter().enumerate() {
				let path = MerkleTreeService::get_merkle_path::<Test>(i as u32).unwrap();
				assert!(
					MerkleTreeService::verify_merkle_proof(&root, &leaf, &path),
					"proof for leaf {i} must verify against incremental root"
				);
			}
		});
	}

	#[test]
	fn merkle_root_updated_event_carries_correct_old_root() {
		use crate::mock::RuntimeEvent;
		new_test_ext().execute_with(|| {
			let c0 = Commitment::new([0xA0u8; 32]);
			let c1 = Commitment::new([0xA1u8; 32]);
			MerkleTreeService::insert_leaf::<Test>(c0).unwrap();
			let root_after_first = crate::storage::MerkleRepository::get_poseidon_root::<Test>();
			MerkleTreeService::insert_leaf::<Test>(c1).unwrap();

			// The second MerkleRootUpdated event must carry the root stored after the first insert.
			let found = frame_system::Pallet::<Test>::events().into_iter().any(|r| {
				matches!(
					&r.event,
					RuntimeEvent::ShieldedPool(crate::Event::MerkleRootUpdated {
						old_root, ..
					}) if *old_root == root_after_first
				)
			});
			assert!(
				found,
				"MerkleRootUpdated event must carry the previous root as old_root"
			);
		});
	}

	// Simulates storage round-trip across multiple separate execute_with calls,
	// mimicking the frontier being persisted between blocks.
	// Verifies SCALE serialization of [[u8; 32]; 20] survives storage read/write cycles.
	#[test]
	fn frontier_survives_storage_round_trip_across_separate_calls() {
		use crate::pallet::MerkleTreeFrontier;

		let mut ext = new_test_ext();

		// Block 1: insert first leaf
		let root_b1 = ext.execute_with(|| {
			MerkleTreeService::insert_leaf::<Test>(Commitment::new([0x01u8; 32])).unwrap();
			MerkleRepository::get_poseidon_root::<Test>()
		});

		// Block 2: insert second leaf — frontier must be correctly recovered from storage
		let root_b2 = ext.execute_with(|| {
			// Frontier was written in block 1; verify it is non-zero (was persisted)
			let frontier = MerkleTreeFrontier::<Test>::get();
			assert_ne!(
				frontier[0], [0u8; 32],
				"frontier slot 0 must be set after first insert"
			);

			MerkleTreeService::insert_leaf::<Test>(Commitment::new([0x02u8; 32])).unwrap();
			MerkleRepository::get_poseidon_root::<Test>()
		});

		assert_ne!(root_b1, root_b2, "root must change with each insert");

		// Block 3: the root after 2 incremental inserts must equal the batch root for same leaves
		let expected = ext.execute_with(|| {
			compute_root_from_leaves_poseidon::<20>(&[[0x01u8; 32], [0x02u8; 32]])
		});

		assert_eq!(
			root_b2, expected,
			"frontier root after 2 round-trips must match batch root"
		);
	}

	// ── tree-depth consistency ────────────────────────────────────────────────

	/// integrity_test passes when MaxTreeDepth equals the fixed tree depth. The
	/// mock is aligned to MAX_TREE_DEPTH, so construction must not panic; a
	/// divergent config would abort at runtime construction.
	#[test]
	fn integrity_test_accepts_aligned_tree_depth() {
		use frame_support::traits::Hooks;
		new_test_ext().execute_with(|| {
			<crate::Pallet<Test> as Hooks<frame_system::pallet_prelude::BlockNumberFor<Test>>>::integrity_test();
		});
	}

	/// The capacity guard is bound by the real tree depth, not the config, so it
	/// fires at exactly 2^MAX_TREE_DEPTH regardless of MaxTreeDepth.
	#[test]
	fn capacity_guard_uses_fixed_depth() {
		use crate::types::MAX_TREE_DEPTH;
		assert_eq!(MAX_TREE_DEPTH, 20);
		// insert_leaf's max_leaves is 2^MAX_TREE_DEPTH; confirm the constant the
		// guard reads matches the frontier depth (20 levels).
		assert_eq!(2u32.saturating_pow(MAX_TREE_DEPTH), 1 << 20);
	}

	// ── historic-root window ──────────────────────────────────────────────────

	/// integrity_test rejects a zero root window (checked via the mock's non-zero
	/// MaxHistoricRoots passing construction).
	#[test]
	fn integrity_test_accepts_nonzero_root_window() {
		use frame_support::traits::Hooks;
		new_test_ext().execute_with(|| {
			assert!(<Test as crate::Config>::MaxHistoricRoots::get() > 0);
			<crate::Pallet<Test> as Hooks<frame_system::pallet_prelude::BlockNumberFor<Test>>>::integrity_test();
		});
	}

	/// Once the window is full, the oldest root is evicted from both the order
	/// vector and the known-root map, and the map/order stay in sync (SP-15).
	#[test]
	fn historic_root_window_evicts_oldest() {
		new_test_ext().execute_with(|| {
			let cap = <Test as crate::Config>::MaxHistoricRoots::get();
			// Fill the window with `cap` distinct roots.
			for i in 0..cap {
				let mut root = [0u8; 32];
				root[..4].copy_from_slice(&i.to_le_bytes());
				MerkleTreeService::add_poseidon_historic_root::<Test>(root);
			}
			let mut oldest = [0u8; 32];
			oldest[..4].copy_from_slice(&0u32.to_le_bytes());
			assert!(MerkleTreeService::is_known_root::<Test>(&oldest));

			// One more root evicts the oldest.
			let mut newest = [0u8; 32];
			newest[..4].copy_from_slice(&cap.to_le_bytes());
			MerkleTreeService::add_poseidon_historic_root::<Test>(newest);

			assert!(
				!MerkleTreeService::is_known_root::<Test>(&oldest),
				"oldest must be evicted"
			);
			assert!(
				MerkleTreeService::is_known_root::<Test>(&newest),
				"newest must be known"
			);
			// Order vector holds exactly `cap` entries — no unbounded growth.
			assert_eq!(
				MerkleRepository::get_historic_roots_order::<Test>().len(),
				cap as usize
			);
		});
	}

	/// A duplicate root value is not removed from the map while another copy of it
	/// still sits in the window (guards the map/order multiplicity mismatch).
	#[test]
	fn historic_root_duplicate_survives_partial_eviction() {
		new_test_ext().execute_with(|| {
			let dup = [0x77u8; 32];
			// Two copies of `dup` plus fillers spanning the window.
			MerkleTreeService::add_poseidon_historic_root::<Test>(dup);
			MerkleTreeService::add_poseidon_historic_root::<Test>(dup);
			let cap = <Test as crate::Config>::MaxHistoricRoots::get();
			for i in 0..(cap - 1) {
				let mut root = [0u8; 32];
				root[..4].copy_from_slice(&i.to_le_bytes());
				root[31] = 1; // distinct namespace from `dup`
				MerkleTreeService::add_poseidon_historic_root::<Test>(root);
			}
			// The first `dup` was evicted, but the second copy keeps it known.
			assert!(
				MerkleTreeService::is_known_root::<Test>(&dup),
				"duplicate root must stay known while a copy remains in the window"
			);
		});
	}
}
