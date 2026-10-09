//! On-chain Merkle tree: leaf insertion, tree sealing, and the historic-root
//! window.
//!
//! This is the only part of the Merkle code that touches storage. Everything it
//! needs from the pure layers comes through [`super::hashing`].

use super::{
	MAX_ROOTS_PRUNED_PER_INSERT,
	hashing::{get_zero_hash_cached, hash_pair},
	tree::IncrementalMerkleTree,
};
use crate::{
	pallet::{Config, Error, Event, Pallet},
	storage::{CommitmentRepository, MerkleRepository, PoolStatsRepository},
	types::{Commitment, DefaultMerklePath, Hash},
};
use frame_support::{ensure, pallet_prelude::*, traits::Get};
use sp_runtime::traits::Saturating;
use sp_std::vec::Vec;

/// The forest's storage operations. Stateless: every method reads and writes
/// through [`MerkleRepository`].
pub struct MerkleTreeService;

impl MerkleTreeService {
	// ── Leaves and sealing ──────────────────────────────────────────────────

	/// Insert a leaf into the active tree and return its global index.
	///
	/// 1. Bounds: the global index fits a `u32`, the commitment is new.
	/// 2. Walk up the stored frontier — O(depth) — persisting each new node so
	///    path reads stay point lookups.
	/// 3. Store the leaf, the new root and its historic entry; emit the update.
	/// 4. Seal the tree if this leaf filled it.
	pub fn insert_leaf<T: Config>(commitment: Commitment) -> Result<u32, DispatchError> {
		let index = MerkleRepository::get_tree_size::<T>();
		// 1. Bounds. Only the forest has a ceiling (4096 trees at depth 20); a
		// full tree rolls over to a fresh one in step 4.
		ensure!(index < u32::MAX, Error::<T>::MerkleTreeFull);
		ensure!(
			!CommitmentRepository::exists::<T>(&commitment),
			Error::<T>::CommitmentAlreadyExists
		);

		let cap = T::MaxLeavesPerTree::get();
		let tree_id = index / cap;
		let local = index % cap;

		// 2. Frontier walk, at the depth the frontier array is sized for.
		let mut frontier = MerkleRepository::get_frontier::<T>();
		let mut current_hash = commitment.0;
		let mut current_index = local;

		for (level, frontier_slot) in frontier.iter_mut().enumerate() {
			if current_index.is_multiple_of(2) {
				// Left child: remember it, pair it with the empty right subtree.
				*frontier_slot = current_hash;
				let zero = get_zero_hash_cached(level);
				current_hash = hash_pair(&current_hash, &zero);
			} else {
				// Right child: pair it with the stored left sibling.
				current_hash = hash_pair(frontier_slot, &current_hash);
			}
			current_index /= 2;
			// `current_hash` is now node (level + 1, current_index). Levels 1..=19
			// are stored; level 20 is `PoseidonRoot`.
			if level + 1 < crate::types::DEFAULT_TREE_DEPTH {
				MerkleRepository::set_node::<T>(
					tree_id,
					(level + 1) as u8,
					current_index,
					current_hash,
				);
			}
		}

		// 3. Store.
		let new_poseidon_root = current_hash;
		let old_poseidon_root = MerkleRepository::get_poseidon_root::<T>();

		MerkleRepository::insert_leaf::<T>(index, commitment);
		MerkleRepository::set_commitment_leaf_index::<T>(commitment, index);
		MerkleRepository::set_tree_size::<T>(index.saturating_add(1));
		PoolStatsRepository::increment_commitments_inserted::<T>();
		MerkleRepository::set_frontier::<T>(frontier);
		MerkleRepository::set_poseidon_root::<T>(new_poseidon_root);
		Self::add_poseidon_historic_root::<T>(new_poseidon_root);

		// Emitted before any seal resets the active root: the leaf belongs to this one.
		Pallet::<T>::deposit_event(Event::MerkleRootUpdated {
			old_root: old_poseidon_root,
			new_root: new_poseidon_root,
			tree_size: index.saturating_add(1),
		});

		// 4. Seal.
		if local + 1 == cap {
			Self::seal_tree::<T>(tree_id, new_poseidon_root, cap);
		}
		Ok(index)
	}

	/// Seal a full tree and open a fresh one, in the same insert.
	///
	/// 1. The final root becomes a permanent anchor (`SealedTreeRoots`,
	///    `SealedRootIndex`): it never expires, so the tree's notes stay
	///    spendable forever.
	/// 2. The active tree resets to empty, and the empty root joins the historic
	///    window so `PoseidonRoot` is always a known root.
	fn seal_tree<T: Config>(tree_id: u32, final_root: Hash, cap: u32) {
		MerkleRepository::insert_sealed_root::<T>(tree_id, final_root);
		MerkleRepository::set_frontier::<T>([[0u8; 32]; crate::types::DEFAULT_TREE_DEPTH]);
		let empty_root = get_zero_hash_cached(crate::types::DEFAULT_TREE_DEPTH);
		MerkleRepository::set_poseidon_root::<T>(empty_root);
		Self::add_poseidon_historic_root::<T>(empty_root);

		Pallet::<T>::deposit_event(Event::TreeSealed {
			tree_id,
			final_root,
			first_leaf_index: tree_id.saturating_mul(cap),
			leaf_count: cap,
		});
	}

	// ── Historic roots ──────────────────────────────────────────────────────

	/// Record a new root, dropping the ones whose retention window has passed.
	///
	/// The window is measured in blocks (`RootRetentionBlocks`); the queue only
	/// orders roots by expiry.
	///
	/// 1. Drain expired slots from the tail, at most `MAX_ROOTS_PRUNED_PER_INSERT`.
	/// 2. If the queue still reaches `MaxHistoricRoots` — a safety cap, not the
	///    window — evict the oldest and log the misconfiguration.
	/// 3. Append the new root.
	pub(crate) fn add_poseidon_historic_root<T: Config>(poseidon_root: Hash) {
		let now = frame_system::Pallet::<T>::block_number();
		let expires_at = now.saturating_add(T::RootRetentionBlocks::get());

		let mut head = MerkleRepository::get_historic_roots_head::<T>();
		let mut tail = MerkleRepository::get_historic_roots_tail::<T>();

		// 1. Drain. Slots are in expiry order (each stores `now + retention`), so
		// the first live one ends the scan.
		let mut pruned = 0usize;
		while tail < head && pruned < MAX_ROOTS_PRUNED_PER_INSERT {
			let Some((root, slot_expiry)) = MerkleRepository::get_historic_root_slot::<T>(tail)
			else {
				// A hole, which this code never leaves: skip it, and count it so the
				// scan stays bounded.
				tail = tail.saturating_add(1);
				pruned = pruned.saturating_add(1);
				continue;
			};
			if slot_expiry >= now {
				break; // live, and so is every slot after it
			}
			MerkleRepository::remove_historic_root_slot::<T>(tail);
			tail = tail.saturating_add(1);
			pruned = pruned.saturating_add(1);

			// A root can sit in several slots; its map entry holds the latest expiry
			// and decides whether it is still spendable.
			match MerkleRepository::get_historic_root_expiry::<T>(&root) {
				Some(expiry) if expiry >= now => {}
				_ => MerkleRepository::remove_poseidon_historic_root::<T>(&root),
			}
		}

		// 2. Cap. Reaching it means the window holds more roots than allowed:
		// evict the oldest so inserts keep working, and say so.
		if head.saturating_sub(tail) >= T::MaxHistoricRoots::get() as u64 {
			// A log, not `defensive!`: that panics in debug builds, and this state
			// is reachable.
			frame_support::__private::log::warn!(
				target: "runtime::shielded-pool",
				"historic-root cap reached before retention elapsed; \
				 MaxHistoricRoots is too small for RootRetentionBlocks",
			);
			if let Some((root, slot_expiry)) = MerkleRepository::get_historic_root_slot::<T>(tail) {
				MerkleRepository::remove_historic_root_slot::<T>(tail);
				match MerkleRepository::get_historic_root_expiry::<T>(&root) {
					Some(expiry) if expiry >= now => {
						// Still live: re-queue it. Dropping only the slot would leave the
						// entry unprunable; dropping both would refuse valid spends.
						MerkleRepository::set_historic_root_slot::<T>(head, root, slot_expiry);
						head = head.saturating_add(1);
					}
					_ => MerkleRepository::remove_poseidon_historic_root::<T>(&root),
				}
			}
			tail = tail.saturating_add(1);
		}

		// 3. Append.
		MerkleRepository::set_historic_root_slot::<T>(head, poseidon_root, expires_at);
		head = head.saturating_add(1);

		MerkleRepository::add_historic_poseidon_root_until::<T>(poseidon_root, expires_at);
		MerkleRepository::set_historic_roots_head::<T>(head);
		MerkleRepository::set_historic_roots_tail::<T>(tail);
	}

	// ── Roots and paths ─────────────────────────────────────────────────────

	/// Whether a spend may be proven against `root`: the active root, a root
	/// still in its retention window, or a sealed tree's final root.
	pub fn is_known_root<T: Config>(root: &Hash) -> bool {
		MerkleRepository::is_known_root::<T>(root)
	}

	/// Build the sibling path for `leaf_index`.
	///
	/// The active tree is O(depth) point reads: level-0 siblings come from
	/// `MerkleLeaves`, upper siblings from `MerkleNodes`. A missing entry means an
	/// empty subtree, so the canonical zero hash for that level is used.
	///
	/// A **sealed** tree has its levels below `SealedTreePrunedBelowLevel` dropped
	/// (see [`Self::prune_sealed_nodes`]), so those siblings are rebuilt from the
	/// leaves: only each sibling subtree, `2^cut − 2` leaf reads in all. A node
	/// missing at or above the cut — pruned under an earlier, higher cut — is
	/// rebuilt the same way.
	pub fn get_merkle_path<T: Config>(leaf_index: u32) -> Option<DefaultMerklePath> {
		let size = MerkleRepository::get_tree_size::<T>();
		if leaf_index >= size {
			return None;
		}

		let depth = crate::types::DEFAULT_TREE_DEPTH;
		let cap = T::MaxLeavesPerTree::get();
		let tree_id = leaf_index / cap;
		let local = leaf_index % cap;
		let mut siblings = [[0u8; 32]; crate::types::DEFAULT_TREE_DEPTH];
		let mut indices = [0u8; crate::types::DEFAULT_TREE_DEPTH];

		// Only sealed trees are pruned; the active one keeps every node.
		let is_sealed = tree_id < size / cap;
		let cut = T::SealedTreePrunedBelowLevel::get() as usize;

		for level in 0..depth {
			let node_index = local >> level;
			indices[level] = (node_index & 1) as u8;
			let sibling_index = node_index ^ 1;
			let sibling = if level == 0 {
				// Leaves: the tree-local sibling, at its global index.
				MerkleRepository::get_leaf::<T>(tree_id * cap + sibling_index).map(|c| c.0)
			} else if is_sealed && level < cut {
				// Pruned level of a sealed tree: rebuilt from the leaves.
				Some(Self::subtree_root::<T>(tree_id, level, sibling_index, cap))
			} else if is_sealed {
				// Kept level of a sealed tree. A node pruned under an earlier, higher
				// cut is rebuilt; past the capacity that yields the zero hash.
				MerkleRepository::get_node::<T>(tree_id, level as u8, sibling_index)
					.or_else(|| Some(Self::subtree_root::<T>(tree_id, level, sibling_index, cap)))
			} else {
				// Active tree: a missing node is an empty subtree.
				MerkleRepository::get_node::<T>(tree_id, level as u8, sibling_index)
			};
			siblings[level] = sibling.unwrap_or_else(|| get_zero_hash_cached(level));
		}
		Some(DefaultMerklePath { siblings, indices })
	}

	/// Rebuild the node at `(level, node_index)` from the leaves beneath it.
	///
	/// Reads the `2^level` leaves the node spans and folds them pairwise. Used only
	/// for pruned nodes of sealed trees, whose leaves are immutable, so the result
	/// is exactly what was stored before pruning.
	fn subtree_root<T: Config>(tree_id: u32, level: usize, node_index: u32, cap: u32) -> Hash {
		// Callers stay below the tree depth; past 31 the shift would wrap into a
		// plausible but wrong root, so fail to the zero hash instead.
		if level >= 32 {
			return get_zero_hash_cached(level);
		}
		let span = 1u32 << level;
		// Past the tree's capacity the span is the next tree's leaves: empty here.
		let offset = node_index.saturating_mul(span);
		if offset >= cap {
			return get_zero_hash_cached(level);
		}
		let base = tree_id.saturating_mul(cap).saturating_add(offset);

		// Read the span, none past the capacity; a gap is an empty leaf.
		let in_tree = span.min(cap - offset);
		let mut nodes: Vec<Hash> = (0..span)
			.map(|i| {
				(i < in_tree)
					.then(|| MerkleRepository::get_leaf::<T>(base.saturating_add(i)))
					.flatten()
					.map(|c| c.0)
					.unwrap_or_else(|| get_zero_hash_cached(0))
			})
			.collect();

		// Fold pairwise up to `level`; a missing right sibling is that level's
		// zero hash, as `insert_leaf` stored it.
		for lvl in 0..level {
			let zero = get_zero_hash_cached(lvl);
			nodes = nodes
				.chunks(2)
				.map(|pair| hash_pair(&pair[0], pair.get(1).unwrap_or(&zero)))
				.collect();
		}
		nodes
			.first()
			.copied()
			.unwrap_or_else(|| get_zero_hash_cached(level))
	}

	/// Whether `path` takes `leaf` to `root`.
	pub fn verify_merkle_proof(root: &Hash, leaf: &Hash, path: &DefaultMerklePath) -> bool {
		IncrementalMerkleTree::<20>::verify_proof(root, leaf, path)
	}

	/// The global leaf index of `commitment`, if it is in the forest.
	pub fn find_leaf_index<T: Config>(commitment: &Commitment) -> Option<u32> {
		MerkleRepository::find_leaf_index::<T>(commitment)
	}

	// ── Sealed-tree pruning ─────────────────────────────────────────────────

	/// Drop sealed trees' nodes below the cut, at most `budget` probes per call;
	/// returns how many were removed.
	///
	/// Safe: `MerkleNodes` serves paths only — no dispatchable reads it — and a
	/// sealed tree's leaves never change, so [`Self::subtree_root`] rebuilds
	/// anything dropped. A full tree holds ~1M prunable nodes, so the sweep parks
	/// in `SealedPruneCursor` and resumes on the next call.
	pub(crate) fn prune_sealed_nodes<T: Config>(budget: u32) -> u32 {
		if budget == 0 {
			return 0;
		}
		let cap = T::MaxLeavesPerTree::get();
		let active_tree = MerkleRepository::get_tree_size::<T>() / cap;
		if active_tree == 0 {
			return 0; // nothing has sealed yet
		}
		let cut = T::SealedTreePrunedBelowLevel::get();

		let (mut tree, mut level, mut index) = Self::prune_resume_point::<T>();

		let mut removed = 0u32;
		// Every probe counts against the budget, hit or miss, so an already swept
		// level cannot turn into an unbounded scan.
		let mut probed = 0u32;

		while probed < budget {
			if tree >= active_tree {
				// Caught up: the active tree is never pruned.
				crate::pallet::SealedPruneCursor::<T>::kill();
				return removed;
			}
			if level >= cut {
				// This tree is done: everything below the cut is gone.
				crate::pallet::LastPrunedTree::<T>::put(tree);
				tree = tree.saturating_add(1);
				level = 1;
				index = 0;
				continue;
			}
			// Level done: it holds cap >> level nodes. Levels above the tree's height
			// hold none here; their nodes lead to the forest root and are kept.
			if index >= (cap >> level) {
				level = level.saturating_add(1);
				index = 0;
				continue;
			}

			if MerkleRepository::get_node::<T>(tree, level, index).is_some() {
				MerkleRepository::remove_node::<T>(tree, level, index);
				removed = removed.saturating_add(1);
			}
			probed = probed.saturating_add(1);
			index = index.saturating_add(1);
		}

		crate::pallet::SealedPruneCursor::<T>::put((tree, level, index));
		removed
	}

	/// Where the next sweep starts: the parked cursor, or the tree after the last
	/// one fully swept, so a restart never re-walks clean trees.
	fn prune_resume_point<T: Config>() -> (u32, u8, u32) {
		crate::pallet::SealedPruneCursor::<T>::get().unwrap_or_else(|| {
			let next = crate::pallet::LastPrunedTree::<T>::get()
				.map(|t| t.saturating_add(1))
				.unwrap_or(0);
			(next, 1u8, 0u32)
		})
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::mock::{Test, new_test_ext};

	/// A sealed tree pruned under an earlier, higher cut is missing nodes at
	/// levels the current cut keeps. Its paths must still verify against the
	/// sealed root: the missing siblings are rebuilt from the leaves. This is what
	/// makes lowering `SealedTreePrunedBelowLevel` safe on a live chain.
	#[test]
	fn a_tree_pruned_under_a_higher_cut_still_serves_valid_paths() {
		new_test_ext().execute_with(|| {
			let cap = <Test as Config>::MaxLeavesPerTree::get();
			let leaves: Vec<Commitment> = (0..cap)
				.map(|i| Commitment::new([i as u8 + 1; 32]))
				.collect();
			for leaf in &leaves {
				MerkleTreeService::insert_leaf::<Test>(*leaf).unwrap();
			}
			MerkleTreeService::insert_leaf::<Test>(Commitment::new([0xEE; 32])).unwrap();
			let sealed = MerkleRepository::get_sealed_root::<Test>(0).expect("tree 0 sealed");

			// Prune as a cut one level above the mock's would have: the mock keeps
			// this level, so only the fallback can supply it.
			let kept = <Test as Config>::SealedTreePrunedBelowLevel::get();
			for index in 0..(cap >> kept) {
				crate::pallet::MerkleNodes::<Test>::remove((0u32, kept, index));
			}

			for (i, leaf) in leaves.iter().enumerate() {
				let path = MerkleTreeService::get_merkle_path::<Test>(i as u32).unwrap();
				assert!(
					MerkleTreeService::verify_merkle_proof(&sealed, &leaf.0, &path),
					"leaf {i}"
				);
			}
		});
	}

	/// With `MaxLeavesPerTree` below 2^depth, a sealed tree's sibling subtree past
	/// its capacity spans global leaf indices of the NEXT tree. It must still read
	/// as empty: those leaves are not this tree's.
	#[test]
	fn a_sibling_subtree_past_the_tree_capacity_is_empty() {
		new_test_ext().execute_with(|| {
			let cap = <Test as Config>::MaxLeavesPerTree::get();
			for i in 0..(2 * cap) {
				MerkleTreeService::insert_leaf::<Test>(Commitment::new([i as u8 + 1; 32])).unwrap();
			}
			// Level log2(cap) node 1 of tree 0 would cover global leaves cap..2·cap,
			// all of them tree 1's.
			let level = cap.trailing_zeros() as usize;
			assert_eq!(
				MerkleTreeService::subtree_root::<Test>(0, level, 1, cap),
				get_zero_hash_cached(level)
			);
			// Inside the tree the subtree is the leaves' own fold, not zero.
			assert_ne!(
				MerkleTreeService::subtree_root::<Test>(0, level, 0, cap),
				get_zero_hash_cached(level)
			);
		});
	}
}
