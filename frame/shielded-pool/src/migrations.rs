//! Storage migrations for pallet-shielded-pool.

use crate::{
	merkle::{get_zero_hash_cached, hash_pair_poseidon},
	pallet::{Config, Pallet},
	storage::MerkleRepository,
};
use frame_support::{
	pallet_prelude::*,
	traits::{GetStorageVersion, OnRuntimeUpgrade},
	weights::Weight,
};
use sp_std::vec::Vec;

pub mod v1 {
	use super::*;

	/// Backfill `MerkleNodes` from `MerkleLeaves` (storage v0 -> v1).
	///
	/// Rebuilds every internal node (levels 1..=19) that `insert_leaf` would
	/// have written had `MerkleNodes` existed from genesis. One-shot cost:
	/// O(n) Poseidon hashes plus O(n) storage writes for n existing leaves —
	/// sized for the runtime-upgrade block, which tolerates overweight.
	pub struct MigrateToV1<T>(core::marker::PhantomData<T>);

	impl<T: Config> OnRuntimeUpgrade for MigrateToV1<T> {
		fn on_runtime_upgrade() -> Weight {
			let onchain = Pallet::<T>::on_chain_storage_version();
			if onchain >= 1 {
				return T::DbWeight::get().reads(1);
			}

			let size = MerkleRepository::get_tree_size::<T>();
			let mut reads: u64 = 2; // storage version + tree size
			let mut writes: u64 = 1; // storage version bump

			let mut level_nodes: Vec<[u8; 32]> = (0..size)
				.filter_map(|i| MerkleRepository::get_leaf::<T>(i).map(|c| c.0))
				.collect();
			reads = reads.saturating_add(size as u64);

			// Pair-hash upward, mirroring the frontier walk: a missing right
			// sibling is the zero hash of the child level. Every level up to 19
			// gets written, matching what per-insert writes would have produced.
			for level in 0..(crate::types::DEFAULT_TREE_DEPTH - 1) {
				let mut next: Vec<[u8; 32]> = Vec::with_capacity(level_nodes.len().div_ceil(2));
				for pair in level_nodes.chunks(2) {
					let left = pair[0];
					let right = pair
						.get(1)
						.copied()
						.unwrap_or_else(|| get_zero_hash_cached(level));
					next.push(hash_pair_poseidon(&left, &right));
				}
				for (i, node) in next.iter().enumerate() {
					MerkleRepository::set_node::<T>(0, (level + 1) as u8, i as u32, *node);
				}
				writes = writes.saturating_add(next.len() as u64);
				level_nodes = next;
				if level_nodes.is_empty() {
					break;
				}
			}

			StorageVersion::new(1).put::<Pallet<T>>();
			T::DbWeight::get().reads_writes(reads, writes)
		}

		#[cfg(feature = "try-runtime")]
		fn pre_upgrade() -> Result<Vec<u8>, sp_runtime::TryRuntimeError> {
			Ok(MerkleRepository::get_tree_size::<T>().encode())
		}

		#[cfg(feature = "try-runtime")]
		fn post_upgrade(state: Vec<u8>) -> Result<(), sp_runtime::TryRuntimeError> {
			let size = u32::decode(&mut &state[..])
				.map_err(|_| sp_runtime::TryRuntimeError::Other("pre_upgrade state must decode"))?;
			frame_support::ensure!(
				Pallet::<T>::on_chain_storage_version() >= 1,
				sp_runtime::TryRuntimeError::Other("storage version not bumped")
			);
			if size > 0 {
				let top = (crate::types::DEFAULT_TREE_DEPTH - 1) as u8; // 19
				let left = MerkleRepository::get_node::<T>(0, top, 0).ok_or(
					sp_runtime::TryRuntimeError::Other("top-left node missing after backfill"),
				)?;
				let right = MerkleRepository::get_node::<T>(0, top, 1)
					.unwrap_or_else(|| get_zero_hash_cached(top as usize));
				frame_support::ensure!(
					hash_pair_poseidon(&left, &right) == MerkleRepository::get_poseidon_root::<T>(),
					sp_runtime::TryRuntimeError::Other(
						"backfilled nodes do not derive PoseidonRoot"
					)
				);
			}
			Ok(())
		}
	}
}

#[cfg(test)]
mod tests {
	use super::v1::MigrateToV1;
	use crate::{
		merkle::MerkleTreeService,
		mock::{Test, new_test_ext},
		pallet::{MerkleNodes, Pallet},
		storage::MerkleRepository,
		types::Commitment,
	};
	use frame_support::traits::{GetStorageVersion, OnRuntimeUpgrade, StorageVersion};

	fn insert_leaves(n: u8) {
		for i in 0..n {
			MerkleTreeService::insert_leaf::<Test>(Commitment::new([i + 1; 32])).unwrap();
		}
	}

	#[test]
	fn backfill_rebuilds_nodes_and_proofs_verify() {
		new_test_ext().execute_with(|| {
			insert_leaves(37);
			let root = MerkleRepository::get_poseidon_root::<Test>();

			// Simulate a v0 chain: leaves exist but internal nodes were never stored.
			let _ = MerkleNodes::<Test>::clear(u32::MAX, None);
			StorageVersion::new(0).put::<Pallet<Test>>();

			MigrateToV1::<Test>::on_runtime_upgrade();

			assert_eq!(Pallet::<Test>::on_chain_storage_version(), 1);
			for i in 0..37u32 {
				let leaf = MerkleRepository::get_leaf::<Test>(i).unwrap();
				let path = MerkleTreeService::get_merkle_path::<Test>(i).unwrap();
				assert!(
					MerkleTreeService::verify_merkle_proof(&root, &leaf.0, &path),
					"leaf {i} proof must verify after backfill"
				);
			}
		});
	}

	#[test]
	fn migration_is_idempotent_once_versioned() {
		new_test_ext().execute_with(|| {
			insert_leaves(4);
			StorageVersion::new(1).put::<Pallet<Test>>();
			let node_before = MerkleRepository::get_node::<Test>(0, 1, 0);
			MigrateToV1::<Test>::on_runtime_upgrade();
			assert_eq!(MerkleRepository::get_node::<Test>(0, 1, 0), node_before);
		});
	}

	#[test]
	fn empty_tree_migration_only_bumps_version() {
		new_test_ext().execute_with(|| {
			StorageVersion::new(0).put::<Pallet<Test>>();
			MigrateToV1::<Test>::on_runtime_upgrade();
			assert_eq!(Pallet::<Test>::on_chain_storage_version(), 1);
			assert_eq!(MerkleNodes::<Test>::iter().count(), 0);
		});
	}
}
