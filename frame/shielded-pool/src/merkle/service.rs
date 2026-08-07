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
	pallet::{CommitmentMemos, Config, Error, Event, Pallet},
	storage::{MerkleRepository, PoolStatsRepository},
	types::{Commitment, DefaultMerklePath, Hash},
};
use frame_support::{ensure, pallet_prelude::*, traits::Get};
use sp_runtime::traits::Saturating;
use sp_std::vec::Vec;

pub struct MerkleTreeService;

impl MerkleTreeService {
	/// Insert a new leaf into the Merkle tree.
	///
	/// Uses an incremental frontier algorithm: O(depth) hashes per insert,
	/// replacing the former O(n) full recomputation from all leaves.
	pub fn insert_leaf<T: Config>(commitment: Commitment) -> Result<u32, DispatchError> {
		let index = MerkleRepository::get_tree_size::<T>();
		// Absolute forest ceiling: the global u32 leaf index must stay
		// representable (4096 trees at depth 20). Per-tree fullness rolls
		// over to a fresh tree below instead of erroring.
		ensure!(index < u32::MAX, Error::<T>::MerkleTreeFull);
		ensure!(
			!CommitmentMemos::<T>::contains_key(commitment),
			Error::<T>::CommitmentAlreadyExists
		);

		let cap = T::MaxLeavesPerTree::get();
		let tree_id = index / cap;
		let local = index % cap;

		// Load frontier from storage and run one incremental update.
		// Depth is always DEFAULT_TREE_DEPTH (20) — matches the fixed-size frontier array.
		let mut frontier = MerkleRepository::get_frontier::<T>();
		let mut current_hash = commitment.0;
		let mut current_index = local;

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
			// current_hash is now the node at (level + 1, current_index). Persist
			// levels 1..=19 so proof reads are O(depth); level 20 is PoseidonRoot.
			if level + 1 < crate::types::DEFAULT_TREE_DEPTH {
				MerkleRepository::set_node::<T>(
					tree_id,
					(level + 1) as u8,
					current_index,
					current_hash,
				);
			}
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

		// The freshly inserted leaf belongs to `new_poseidon_root`, so this
		// event fires before any seal resets the active root.
		Pallet::<T>::deposit_event(Event::MerkleRootUpdated {
			old_root: old_poseidon_root,
			new_root: new_poseidon_root,
			tree_size: index.saturating_add(1),
		});

		if local + 1 == cap {
			Self::seal_tree::<T>(tree_id, new_poseidon_root, cap);
		}
		Ok(index)
	}

	/// Seal a full tree and open a fresh one, eagerly in the same insert.
	///
	/// The final root becomes a permanent anchor (`SealedTreeRoots` /
	/// `SealedRootIndex`) — unlike the historic ring it never expires, so
	/// notes in sealed trees stay spendable forever. The active tree resets
	/// to the empty state; the empty root joins the historic ring to keep
	/// the `PoseidonRoot ∈ known roots` invariant.
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

	/// Record the new root and drop the ones whose retention window has passed.
	///
	/// Retention is measured in blocks (`RootRetentionBlocks`), so the window
	/// always outlives the mempool longevity a transaction was admitted with.
	/// `MaxHistoricRoots` is only a safety cap on queue length.
	pub(crate) fn add_poseidon_historic_root<T: Config>(poseidon_root: Hash) {
		let now = frame_system::Pallet::<T>::block_number();
		let expires_at = now.saturating_add(T::RootRetentionBlocks::get());

		let mut head = MerkleRepository::get_historic_roots_head::<T>();
		let mut tail = MerkleRepository::get_historic_roots_tail::<T>();

		// Drain expired slots from the tail. Slots sit in expiry order because
		// every insert stores `now + retention` with a non-decreasing `now`, so
		// the first live slot ends the scan.
		let mut pruned = 0usize;
		while tail < head && pruned < MAX_ROOTS_PRUNED_PER_INSERT {
			let Some((root, slot_expiry)) = MerkleRepository::get_historic_root_slot::<T>(tail)
			else {
				// Defensive: this path never leaves holes, but skipping keeps the
				// queue draining instead of wedging on one forever. Counted against
				// the cap so a long run of holes cannot turn into an unbounded read
				// loop inside a dispatchable.
				tail = tail.saturating_add(1);
				pruned = pruned.saturating_add(1);
				continue;
			};
			if slot_expiry >= now {
				break; // still live — and so is every slot behind it
			}
			MerkleRepository::remove_historic_root_slot::<T>(tail);
			tail = tail.saturating_add(1);
			pruned = pruned.saturating_add(1);

			// A root can occupy several slots (re-inserted, or an insert that left
			// the root unchanged). The map holds one expiry per root — the latest,
			// since `add_historic_poseidon_root_until` only extends it — so it is
			// the authority on whether the root is still spendable. O(1) per slot,
			// which keeps this loop linear.
			match MerkleRepository::get_historic_root_expiry::<T>(&root) {
				Some(expiry) if expiry >= now => {}
				_ => MerkleRepository::remove_poseidon_historic_root::<T>(&root),
			}
		}

		// The cap is a backstop, not the window: reaching it means the window
		// holds more roots than `MaxHistoricRoots` allows, which would silently
		// shorten it. Evict the oldest so inserts keep working, and log the
		// misconfiguration rather than failing quietly.
		if head.saturating_sub(tail) >= T::MaxHistoricRoots::get() as u64 {
			// Not `defensive!`: that expands to `debug_assert!(false)` and panics in
			// any debug-assertions build. This branch is a reachable operational
			// state, so a validator on a debug build must not halt where a release
			// build keeps producing.
			frame_support::__private::log::warn!(
				target: "runtime::shielded-pool",
				"historic-root cap reached before retention elapsed; \
				 MaxHistoricRoots is too small for RootRetentionBlocks",
			);
			if let Some((root, slot_expiry)) = MerkleRepository::get_historic_root_slot::<T>(tail) {
				MerkleRepository::remove_historic_root_slot::<T>(tail);
				match MerkleRepository::get_historic_root_expiry::<T>(&root) {
					Some(expiry) if expiry >= now => {
						// Still live: re-queue at the head rather than drop it.
						// Deleting the slot while keeping the map entry would strand
						// that entry outside `[tail, head)` — unreachable by the drain
						// loop, so never prunable and permanently spendable. Forgetting
						// it instead would reject spends that are still valid.
						MerkleRepository::set_historic_root_slot::<T>(head, root, slot_expiry);
						head = head.saturating_add(1);
					}
					_ => MerkleRepository::remove_poseidon_historic_root::<T>(&root),
				}
			}
			tail = tail.saturating_add(1);
		}

		MerkleRepository::set_historic_root_slot::<T>(head, poseidon_root, expires_at);
		head = head.saturating_add(1);

		MerkleRepository::add_historic_poseidon_root_until::<T>(poseidon_root, expires_at);
		MerkleRepository::set_historic_roots_head::<T>(head);
		MerkleRepository::set_historic_roots_tail::<T>(tail);
	}

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
	/// (see [`Self::prune_sealed_nodes`]), so those siblings are recomputed from
	/// the leaves instead. Only the sibling subtree is rebuilt, not the whole
	/// tree: at a cut of 10 that is 2^10 leaf reads and 1_023 hashes.
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

		// Only sealed trees are pruned; the active one always has every node.
		let is_sealed = tree_id < size / cap;
		let cut = T::SealedTreePrunedBelowLevel::get() as usize;

		for level in 0..depth {
			let node_index = local >> level;
			indices[level] = (node_index & 1) as u8;
			let sibling_index = node_index ^ 1;
			let sibling = if level == 0 {
				// Level-0 nodes are the leaves; map the tree-local sibling
				// back to its global MerkleLeaves index.
				MerkleRepository::get_leaf::<T>(tree_id * cap + sibling_index).map(|c| c.0)
			} else if is_sealed && level < cut {
				Some(Self::subtree_root::<T>(tree_id, level, sibling_index, cap))
			} else {
				MerkleRepository::get_node::<T>(tree_id, level as u8, sibling_index)
			};
			siblings[level] = sibling.unwrap_or_else(|| get_zero_hash_cached(level));
		}
		Some(DefaultMerklePath { siblings, indices })
	}

	/// Rebuild the node at `(level, node_index)` from the leaves beneath it.
	///
	/// Reads the `2^level` leaves the node spans and folds them pairwise. Used only
	/// for pruned levels of sealed trees, where the leaves are immutable, so the
	/// result is exactly what was stored before pruning.
	fn subtree_root<T: Config>(tree_id: u32, level: usize, node_index: u32, cap: u32) -> Hash {
		// `level` is bounded by DEFAULT_TREE_DEPTH at every call site, but the
		// shift below would overflow if that ever changed, so fail soft instead of
		// wrapping into a wrong-but-plausible root.
		if level >= 32 {
			return get_zero_hash_cached(level);
		}
		let span = 1u32 << level;
		let base = tree_id
			.saturating_mul(cap)
			.saturating_add(node_index.saturating_mul(span));

		// Read the leaves this node spans. A gap means an empty slot, which the
		// tree represents with the level-0 zero hash.
		let mut nodes: Vec<Hash> = (0..span)
			.map(|i| {
				MerkleRepository::get_leaf::<T>(base.saturating_add(i))
					.map(|c| c.0)
					.unwrap_or_else(|| get_zero_hash_cached(0))
			})
			.collect();

		// Fold pairwise up to `level`; the vector halves each round, so one node
		// remains. A missing right sibling pairs with its level's zero hash,
		// matching what `insert_leaf` stored.
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

	pub fn verify_merkle_proof(root: &Hash, leaf: &Hash, path: &DefaultMerklePath) -> bool {
		IncrementalMerkleTree::<20>::verify_proof(root, leaf, path)
	}

	pub fn find_leaf_index<T: Config>(commitment: &Commitment) -> Option<u32> {
		MerkleRepository::find_leaf_index::<T>(commitment)
	}

	/// Drop internal nodes below the cut level for trees that have already sealed.
	///
	/// Returns the number of keys removed. Bounded by `budget`: a full tree holds
	/// ~1M prunable nodes, far past what one block can absorb, so the sweep parks
	/// its position in `SealedPruneCursor` and resumes on the next call.
	///
	/// Safe because `MerkleNodes` serves Merkle paths only — no dispatchable reads
	/// it — and a sealed tree's leaves never change, so anything dropped here is
	/// reproducible by [`Self::subtree_root`].
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
		// Every probe is charged, not just the ones that remove something: a level
		// already swept is all misses, and an uncharged scan could walk hundreds of
		// thousands of keys inside one block.
		let mut probed = 0u32;

		while probed < budget {
			if tree >= active_tree {
				// Caught up with the active tree — which is never pruned. Nothing
				// more to do until another tree seals.
				crate::pallet::SealedPruneCursor::<T>::kill();
				return removed;
			}
			if level >= cut {
				crate::pallet::LastPrunedTree::<T>::put(tree);
				tree = tree.saturating_add(1);
				level = 1;
				index = 0;
				continue;
			}
			// A node at `level` spans 2^level leaves, so the level holds cap >> level.
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
	/// one fully swept. Starting past `LastPrunedTree` keeps a restart from
	/// re-walking trees that are already clean.
	fn prune_resume_point<T: Config>() -> (u32, u8, u32) {
		crate::pallet::SealedPruneCursor::<T>::get().unwrap_or_else(|| {
			let next = crate::pallet::LastPrunedTree::<T>::get()
				.map(|t| t.saturating_add(1))
				.unwrap_or(0);
			(next, 1u8, 0u32)
		})
	}
}
