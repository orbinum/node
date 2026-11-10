//! Merkle tree and historic-root storage.
//!
//! Covers the live tree (root, size, leaves, frontier, internal nodes), the
//! sealed-tree anchors, and the historic-root window.
//!
//! The window is the subtle part: a root carries the block at which it stops
//! being accepted, and pruning is lazy, so an expired entry can outlive its
//! window in storage. Spendability is therefore decided by the stored expiry —
//! never by queue membership.

use crate::{
	pallet::{
		CommitmentToLeafIndex, Config, HistoricPoseidonRoots, HistoricRootsHead,
		HistoricRootsQueue, HistoricRootsTail, MerkleLeaves, MerkleNodes, MerkleTreeFrontier,
		MerkleTreeSize, PoseidonRoot, SealedRootIndex, SealedTreeRoots,
	},
	types::{Commitment, Hash},
};
use frame_support::traits::Get;
use frame_system::pallet_prelude::BlockNumberFor;
use sp_runtime::traits::Saturating;

// MerkleRepository

pub struct MerkleRepository;

impl MerkleRepository {
	pub fn get_poseidon_root<T: Config>() -> Hash {
		PoseidonRoot::<T>::get()
	}
	pub fn set_poseidon_root<T: Config>(root: Hash) {
		PoseidonRoot::<T>::put(root);
	}
	pub fn get_tree_size<T: Config>() -> u32 {
		MerkleTreeSize::<T>::get()
	}
	pub fn set_tree_size<T: Config>(size: u32) {
		MerkleTreeSize::<T>::put(size);
	}
	pub fn get_leaf<T: Config>(index: u32) -> Option<Commitment> {
		MerkleLeaves::<T>::get(index)
	}
	pub fn insert_leaf<T: Config>(index: u32, commitment: Commitment) {
		MerkleLeaves::<T>::insert(index, commitment);
	}
	/// A historic root is spendable until its expiry block, inclusive.
	///
	/// Checked against the expiry stored at insert time rather than pruned
	/// eagerly: pruning is lazy (see `MerkleTreeService::add_poseidon_historic_root`),
	/// so an expired entry can outlive its window in storage. Reading the
	/// expiry here makes that harmless.
	pub fn is_known_poseidon_root<T: Config>(root: &Hash) -> bool {
		match HistoricPoseidonRoots::<T>::get(root) {
			Some(expires_at) => frame_system::Pallet::<T>::block_number() <= expires_at,
			None => false,
		}
	}
	/// A root is spendable if it is the active root, is still inside its
	/// retention window, or anchors a sealed tree.
	///
	/// The active root is accepted unconditionally. Expiries are only refreshed
	/// by a leaf insert, so on a chain that goes quiet for a full retention
	/// window the current root would otherwise expire while still being the one
	/// every wallet proves against — wedging the pool, since `private_transfer`
	/// and `unshield` both need a known root and only a funded `shield` could
	/// mint a new one.
	pub fn is_known_root<T: Config>(root: &Hash) -> bool {
		*root == PoseidonRoot::<T>::get()
			|| Self::is_known_poseidon_root::<T>(root)
			|| SealedRootIndex::<T>::contains_key(root)
	}
	pub fn insert_sealed_root<T: Config>(tree_id: u32, root: Hash) {
		SealedTreeRoots::<T>::insert(tree_id, root);
		SealedRootIndex::<T>::insert(root, tree_id);
	}
	pub fn get_sealed_root<T: Config>(tree_id: u32) -> Option<Hash> {
		SealedTreeRoots::<T>::get(tree_id)
	}
	/// Record `root` as spendable for one full retention window from now.
	pub fn add_historic_poseidon_root<T: Config>(root: Hash) {
		let expires_at =
			frame_system::Pallet::<T>::block_number().saturating_add(T::RootRetentionBlocks::get());
		Self::add_historic_poseidon_root_until::<T>(root, expires_at);
	}

	/// Record `root` as spendable until `expires_at` (inclusive).
	///
	/// A root re-inserted at a later block extends its expiry; it never shortens
	/// it, so a duplicate root cannot cut short the window of the earlier entry.
	pub fn add_historic_poseidon_root_until<T: Config>(root: Hash, expires_at: BlockNumberFor<T>) {
		HistoricPoseidonRoots::<T>::mutate(root, |slot| match slot {
			Some(current) if *current >= expires_at => {}
			_ => *slot = Some(expires_at),
		});
	}
	pub fn remove_poseidon_historic_root<T: Config>(root: &Hash) {
		HistoricPoseidonRoots::<T>::remove(root);
	}
	pub fn get_historic_root_expiry<T: Config>(root: &Hash) -> Option<BlockNumberFor<T>> {
		HistoricPoseidonRoots::<T>::get(root)
	}
	pub fn get_historic_root_slot<T: Config>(slot: u64) -> Option<(Hash, BlockNumberFor<T>)> {
		HistoricRootsQueue::<T>::get(slot)
	}
	pub fn set_historic_root_slot<T: Config>(slot: u64, root: Hash, expires_at: BlockNumberFor<T>) {
		HistoricRootsQueue::<T>::insert(slot, (root, expires_at));
	}
	pub fn remove_historic_root_slot<T: Config>(slot: u64) {
		HistoricRootsQueue::<T>::remove(slot);
	}
	pub fn get_historic_roots_head<T: Config>() -> u64 {
		HistoricRootsHead::<T>::get()
	}
	pub fn set_historic_roots_head<T: Config>(head: u64) {
		HistoricRootsHead::<T>::put(head);
	}
	pub fn get_historic_roots_tail<T: Config>() -> u64 {
		HistoricRootsTail::<T>::get()
	}
	pub fn set_historic_roots_tail<T: Config>(tail: u64) {
		HistoricRootsTail::<T>::put(tail);
	}
	/// Number of slots still queued. Bounded by the retention window in practice
	/// and hard-capped by `MaxHistoricRoots`.
	pub fn historic_roots_queued<T: Config>() -> u64 {
		HistoricRootsHead::<T>::get().saturating_sub(HistoricRootsTail::<T>::get())
	}
	pub fn get_frontier<T: Config>() -> [[u8; 32]; 20] {
		MerkleTreeFrontier::<T>::get()
	}
	pub fn set_frontier<T: Config>(frontier: [[u8; 32]; 20]) {
		MerkleTreeFrontier::<T>::put(frontier);
	}
	pub fn get_commitment_leaf_index<T: Config>(commitment: &Commitment) -> Option<u32> {
		CommitmentToLeafIndex::<T>::get(commitment)
	}
	pub fn set_commitment_leaf_index<T: Config>(commitment: Commitment, index: u32) {
		CommitmentToLeafIndex::<T>::insert(commitment, index);
	}
	pub fn find_leaf_index<T: Config>(commitment: &Commitment) -> Option<u32> {
		Self::get_commitment_leaf_index::<T>(commitment)
	}
	pub fn get_node<T: Config>(tree_id: u32, level: u8, index: u32) -> Option<Hash> {
		MerkleNodes::<T>::get((tree_id, level, index))
	}
	pub fn set_node<T: Config>(tree_id: u32, level: u8, index: u32, node: Hash) {
		MerkleNodes::<T>::insert((tree_id, level, index), node);
	}

	/// Drop a stored internal node.
	///
	/// Only used by the sealed-tree sweep: the node is recomputed from the leaves
	/// when a path needs it, so removing it loses no information.
	pub fn remove_node<T: Config>(tree_id: u32, level: u8, index: u32) {
		MerkleNodes::<T>::remove((tree_id, level, index));
	}
}
