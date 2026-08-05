//! Storage migrations for `pallet-shielded-pool`.
//!
//! Only migrations that still have a chain to run on live here. Once every
//! deployment has passed a version, its code is removed — see the git history
//! for the v1 and v2 migrations.

use crate::{
	pallet::{
		Config, HistoricPoseidonRoots, HistoricRootsHead, HistoricRootsQueue, HistoricRootsTail,
		Pallet,
	},
	types::Hash,
};
use frame_support::{
	pallet_prelude::*,
	traits::{GetStorageVersion, OnRuntimeUpgrade},
	weights::Weight,
};
use sp_runtime::traits::Saturating;
use sp_std::vec::Vec;

pub mod v3 {
	use super::*;

	/// Storage key of the v2 `HistoricRootsOrder` value, which no longer exists
	/// as a type. Read through the raw key so the old `Vec<Hash>` can be decoded
	/// and cleared without keeping a dead definition around.
	fn old_order_key() -> Vec<u8> {
		[
			sp_io::hashing::twox_128(b"ShieldedPool").as_slice(),
			sp_io::hashing::twox_128(b"HistoricRootsOrder").as_slice(),
		]
		.concat()
	}

	/// Storage prefix of `HistoricPoseidonRoots`. Enumerated by raw key so the
	/// old 1-byte `bool` values can be rewritten without `translate`, which
	/// leaves undecodable entries in place rather than clearing them.
	///
	/// The pallet name must match the `construct_runtime!` identifier
	/// (`ShieldedPool`); a mismatch would make every read here return nothing.
	fn historic_roots_prefix() -> Vec<u8> {
		[
			sp_io::hashing::twox_128(b"ShieldedPool").as_slice(),
			sp_io::hashing::twox_128(b"HistoricPoseidonRoots").as_slice(),
		]
		.concat()
	}

	/// Count raw keys under a prefix. Typed `iter()` silently skips entries whose
	/// value fails to decode, which is exactly the failure this migration must be
	/// able to observe, so the try-runtime checks count keys instead.
	#[cfg(feature = "try-runtime")]
	fn count_raw_keys(prefix: &[u8]) -> u32 {
		let mut count: u32 = 0;
		let mut key = prefix.to_vec();
		while let Some(next) = sp_io::storage::next_key(&key) {
			if !next.starts_with(prefix) {
				break;
			}
			count = count.saturating_add(1);
			key = next;
		}
		count
	}

	/// Re-anchor the historic-root window from insert counts to block numbers
	/// (storage v2 -> v3).
	///
	/// Before: `HistoricPoseidonRoots: Hash -> bool` plus a single
	/// `HistoricRootsOrder: BoundedVec<Hash>`, evicted purely by how many roots
	/// had been inserted. After: the map carries the block at which each root
	/// stops being accepted, and the queue is a slot-indexed map so a leaf
	/// insert touches a couple of entries instead of rewriting the whole vector.
	///
	/// Both value types changed, so old entries cannot be decoded by the new
	/// definitions and must be rewritten here. Every existing root is kept and
	/// given a full window from the upgrade block rather than dropped: a root on
	/// chain backs proofs wallets may be about to submit, and voiding them would
	/// be a worse failure than the one this fixes. The extra window costs one
	/// retention period once and never rejects a spend that used to be valid.
	pub struct MigrateToV3<T>(core::marker::PhantomData<T>);

	impl<T: Config> OnRuntimeUpgrade for MigrateToV3<T> {
		fn on_runtime_upgrade() -> Weight {
			if Pallet::<T>::on_chain_storage_version() >= 3 {
				return T::DbWeight::get().reads(1);
			}

			let now = frame_system::Pallet::<T>::block_number();
			let expires_at = now.saturating_add(T::RootRetentionBlocks::get());
			let cap = T::MaxHistoricRoots::get() as u64;

			let mut reads: u64 = 2; // storage version + old order vector
			let mut writes: u64 = 4; // version + head + tail + old order kill

			// Collect the surviving roots in their original insertion order.
			//
			// The old order vector is the source of truth: it preserves the order
			// the drain loop relies on. It was a `BoundedVec<Hash, MaxHistoricRoots>`,
			// which encodes exactly like `Vec<Hash>`, and is read through its raw key
			// because the type no longer exists. Reading it raw also sidesteps the
			// bound check a typed read would apply with the *new* constant.
			let old_key = old_order_key();
			let ordered: Option<Vec<Hash>> =
				sp_io::storage::get(&old_key).and_then(|raw| Decode::decode(&mut &raw[..]).ok());

			// Enumerate the old map by raw key rather than `translate`.
			//
			// `translate` does NOT delete an entry whose old value fails to decode:
			// it logs, skips, and leaves the bytes in place (see
			// `frame_support::storage::generator::map::translate_next`). Here the old
			// value was a 1-byte `bool` and the new one is a 4-byte block number, so
			// a skipped entry would stay as an undecodable blob under a live key —
			// unreadable by `is_known_poseidon_root` and invisible to `iter()`, hence
			// impossible to ever prune. Rewriting every key unconditionally leaves no
			// such residue.
			let map_prefix = historic_roots_prefix();
			let mut raw_roots: Vec<Hash> = Vec::new();
			let mut key = map_prefix.clone();
			while let Some(next) = sp_io::storage::next_key(&key) {
				if !next.starts_with(&map_prefix) {
					break;
				}
				reads = reads.saturating_add(1);
				// Key layout: prefix ++ Blake2_128Concat(root) = prefix ++ 16-byte
				// hash ++ the 32-byte root itself. Recover the root from the concat
				// tail; anything of an unexpected shape is not a root we can honour,
				// so drop the key rather than leave it dangling.
				match next.len().checked_sub(32) {
					Some(start) if start >= map_prefix.len().saturating_add(16) => {
						let mut root = [0u8; 32];
						root.copy_from_slice(&next[start..]);
						raw_roots.push(root);
					}
					_ => {
						sp_io::storage::clear(&next);
						writes = writes.saturating_add(1);
					}
				}
				key = next;
			}

			// Prefer the recorded order; fall back to key order when the vector is
			// unreadable. Both are safe for the drain loop because every entry gets
			// the same expiry here — if per-root expiries are ever introduced, this
			// fallback must sort by expiry or the loop's early `break` would strand
			// live roots behind an expired one.
			let roots = match ordered {
				Some(mut v) => {
					// Anything present in the map but missing from the vector would
					// otherwise be written to the map and never queued, so it could
					// never be pruned. Append the strays.
					for root in &raw_roots {
						if !v.contains(root) {
							v.push(*root);
						}
					}
					v
				}
				None => {
					frame_support::__private::log::warn!(
						target: "runtime::shielded-pool",
						"MigrateToV3: HistoricRootsOrder undecodable; rebuilding the queue from map key order",
					);
					raw_roots.clone()
				}
			};

			// Clear the whole old map before rewriting: every key is re-created
			// below, so nothing survives that the queue does not also track. This is
			// what makes map membership and queue membership impossible to diverge.
			for root in &raw_roots {
				HistoricPoseidonRoots::<T>::remove(root);
				writes = writes.saturating_add(1);
			}
			sp_io::storage::clear(&old_key);

			// Write map and queue together, one slot per root, so the two can never
			// disagree. Past the cap a root is dropped from *both* — never left in
			// the map alone, which would leak an unprunable spendable root.
			let mut slot: u64 = 0;
			let mut seen: Vec<Hash> = Vec::new();
			for root in roots {
				if slot >= cap {
					frame_support::__private::log::warn!(
						target: "runtime::shielded-pool",
						"MigrateToV3: historic-root cap reached; dropping the remaining roots",
					);
					break;
				}
				if seen.contains(&root) {
					continue; // one slot per distinct root; expiries are identical
				}
				seen.push(root);
				HistoricPoseidonRoots::<T>::insert(root, expires_at);
				HistoricRootsQueue::<T>::insert(slot, (root, expires_at));
				slot = slot.saturating_add(1);
				writes = writes.saturating_add(2);
			}

			// The active root must always be provable against, even if the old state
			// was empty or unreadable. Evict the oldest slot if the cap leaves no
			// room — an unprovable active root would halt every spend.
			let active = crate::storage::MerkleRepository::get_poseidon_root::<T>();
			let mut tail: u64 = 0;
			if !seen.contains(&active) {
				if slot >= cap {
					// Evict the oldest slot to make room. Shift the tail rather than
					// rewriting every slot: the drain loop reads from tail forward,
					// so a moved tail is all it needs.
					if let Some((evicted, _)) = HistoricRootsQueue::<T>::get(tail) {
						HistoricPoseidonRoots::<T>::remove(evicted);
					}
					HistoricRootsQueue::<T>::remove(tail);
					tail = tail.saturating_add(1);
					writes = writes.saturating_add(2);
				}
				HistoricPoseidonRoots::<T>::insert(active, expires_at);
				HistoricRootsQueue::<T>::insert(slot, (active, expires_at));
				slot = slot.saturating_add(1);
				writes = writes.saturating_add(2);
			}

			HistoricRootsTail::<T>::put(tail);
			HistoricRootsHead::<T>::put(slot);
			StorageVersion::new(3).put::<Pallet<T>>();

			T::DbWeight::get().reads_writes(reads, writes)
		}

		#[cfg(feature = "try-runtime")]
		fn pre_upgrade() -> Result<Vec<u8>, sp_runtime::TryRuntimeError> {
			// Count raw keys, not typed entries: the new definition cannot decode
			// the old 1-byte `bool` values, so `iter()` would skip every one.
			Ok(count_raw_keys(&historic_roots_prefix()).encode())
		}

		#[cfg(feature = "try-runtime")]
		fn post_upgrade(state: Vec<u8>) -> Result<(), sp_runtime::TryRuntimeError> {
			// Propagate a decode failure instead of defaulting to zero, which would
			// make the count check below trivially pass.
			let before = u32::decode(&mut state.as_slice()).map_err(|_| {
				sp_runtime::TryRuntimeError::Other("MigrateToV3: pre_upgrade state must decode")
			})?;

			// Compare raw key counts on both sides. A typed count here would hide
			// exactly the failure this migration exists to avoid: an entry left with
			// an undecodable value is invisible to `iter()` but still occupies a key.
			let raw_after = count_raw_keys(&historic_roots_prefix());
			let typed_after = HistoricPoseidonRoots::<T>::iter().count() as u32;
			ensure!(
				raw_after == typed_after,
				sp_runtime::TryRuntimeError::Other(
					"MigrateToV3 left an undecodable entry in HistoricPoseidonRoots"
				)
			);

			// The migration may add the active root, and drops duplicates and
			// anything past the cap — so the count can move either way by a bounded
			// amount, but must never collapse.
			ensure!(
				raw_after <= before.saturating_add(1),
				sp_runtime::TryRuntimeError::Other("MigrateToV3 created unexpected roots")
			);
			ensure!(
				before == 0 || raw_after > 0,
				sp_runtime::TryRuntimeError::Other("MigrateToV3 lost every historic root")
			);
			ensure!(
				Pallet::<T>::on_chain_storage_version() == 3,
				sp_runtime::TryRuntimeError::Other("MigrateToV3 did not set storage version 3")
			);

			// Every migrated root must still be spendable.
			let now = frame_system::Pallet::<T>::block_number();
			for (_root, expiry) in HistoricPoseidonRoots::<T>::iter() {
				ensure!(
					expiry > now,
					sp_runtime::TryRuntimeError::Other(
						"MigrateToV3 produced an already-expired root"
					)
				);
			}

			// Queue and map must agree in BOTH directions. A root in the map but not
			// in the queue can never be pruned — a permanent leak of a spendable
			// root — and a queued root missing from the map would be drained as if
			// it had expired.
			let head = HistoricRootsHead::<T>::get();
			let tail = HistoricRootsTail::<T>::get();
			ensure!(
				head >= tail,
				sp_runtime::TryRuntimeError::Other("MigrateToV3 left head behind tail")
			);
			ensure!(
				head.saturating_sub(tail) <= T::MaxHistoricRoots::get() as u64,
				sp_runtime::TryRuntimeError::Other(
					"MigrateToV3 overfilled the historic-root queue"
				)
			);
			ensure!(
				head.saturating_sub(tail) == typed_after as u64,
				sp_runtime::TryRuntimeError::Other(
					"MigrateToV3 left the map and queue with different lengths"
				)
			);
			for s in tail..head {
				let Some((root, _)) = HistoricRootsQueue::<T>::get(s) else {
					return Err(sp_runtime::TryRuntimeError::Other(
						"MigrateToV3 left a hole in the queue",
					));
				};
				ensure!(
					HistoricPoseidonRoots::<T>::contains_key(root),
					sp_runtime::TryRuntimeError::Other(
						"MigrateToV3 queued a root that is not in the map"
					)
				);
			}

			// The old value must be gone, and the active root provable against.
			ensure!(
				sp_io::storage::get(&old_order_key()).is_none(),
				sp_runtime::TryRuntimeError::Other("MigrateToV3 left HistoricRootsOrder behind")
			);
			let active = crate::storage::MerkleRepository::get_poseidon_root::<T>();
			ensure!(
				crate::storage::MerkleRepository::is_known_root::<T>(&active),
				sp_runtime::TryRuntimeError::Other("MigrateToV3 left the active root unprovable")
			);
			Ok(())
		}
	}
}

#[cfg(test)]
mod tests {
	use super::v3::MigrateToV3;
	use crate::{
		Config,
		mock::{Test, new_test_ext},
		pallet::{
			HistoricPoseidonRoots, HistoricRootsHead, HistoricRootsQueue, HistoricRootsTail,
			PoseidonRoot,
		},
		storage::MerkleRepository,
		types::Hash,
	};
	use frame_support::traits::{GetStorageVersion, OnRuntimeUpgrade, StorageVersion};
	use parity_scale_codec::Encode;

	fn old_order_key() -> Vec<u8> {
		[
			sp_io::hashing::twox_128(b"ShieldedPool").as_slice(),
			sp_io::hashing::twox_128(b"HistoricRootsOrder").as_slice(),
		]
		.concat()
	}

	/// Write a `HistoricPoseidonRoots` entry the way storage v2 did: a raw
	/// 1-byte `bool` under a `Blake2_128Concat` key.
	fn write_v2_root(root: Hash, value: bool) {
		let prefix = [
			sp_io::hashing::twox_128(b"ShieldedPool").as_slice(),
			sp_io::hashing::twox_128(b"HistoricPoseidonRoots").as_slice(),
		]
		.concat();
		let mut key = prefix;
		key.extend_from_slice(&sp_io::hashing::blake2_128(&root.encode()));
		key.extend_from_slice(&root.encode());
		sp_io::storage::set(&key, &value.encode());
	}

	fn seed_v2_state(roots: &[Hash]) {
		StorageVersion::new(2).put::<crate::Pallet<Test>>();
		// Genesis already seeded v3-shaped state; clear it so the fixture is
		// purely v2.
		let _ = HistoricRootsQueue::<Test>::clear(u32::MAX, None);
		HistoricRootsHead::<Test>::kill();
		HistoricRootsTail::<Test>::kill();
		let _ = HistoricPoseidonRoots::<Test>::clear(u32::MAX, None);

		for root in roots {
			write_v2_root(*root, true);
		}
		sp_io::storage::set(&old_order_key(), &roots.to_vec().encode());
	}

	fn root_of(n: u8) -> Hash {
		[n; 32]
	}

	#[test]
	fn migrates_roots_and_preserves_order() {
		new_test_ext().execute_with(|| {
			let roots = [root_of(1), root_of(2), root_of(3)];
			PoseidonRoot::<Test>::put(root_of(3));
			seed_v2_state(&roots);

			MigrateToV3::<Test>::on_runtime_upgrade();

			assert_eq!(crate::Pallet::<Test>::on_chain_storage_version(), 3);
			assert_eq!(HistoricRootsTail::<Test>::get(), 0);
			assert_eq!(HistoricRootsHead::<Test>::get(), 3);

			// Insertion order preserved, map and queue agree.
			for (slot, root) in roots.iter().enumerate() {
				let (queued, _) =
					HistoricRootsQueue::<Test>::get(slot as u64).expect("slot filled");
				assert_eq!(queued, *root);
				assert!(MerkleRepository::is_known_root::<Test>(root));
			}
			// The old value is gone.
			assert!(sp_io::storage::get(&old_order_key()).is_none());
		});
	}

	/// The value type changed from 1-byte `bool` to a 4-byte block number.
	/// `translate` would leave an undecodable entry in place; the raw rewrite
	/// must not.
	#[test]
	fn rewrites_every_entry_leaving_no_undecodable_residue() {
		new_test_ext().execute_with(|| {
			let roots = [root_of(7), root_of(8)];
			PoseidonRoot::<Test>::put(root_of(7));
			seed_v2_state(&roots);

			MigrateToV3::<Test>::on_runtime_upgrade();

			// Every raw key must now decode under the new type: raw count and
			// typed count agree.
			let prefix = [
				sp_io::hashing::twox_128(b"ShieldedPool").as_slice(),
				sp_io::hashing::twox_128(b"HistoricPoseidonRoots").as_slice(),
			]
			.concat();
			let mut raw = 0u32;
			let mut key = prefix.clone();
			while let Some(next) = sp_io::storage::next_key(&key) {
				if !next.starts_with(&prefix) {
					break;
				}
				raw += 1;
				key = next;
			}
			let typed = HistoricPoseidonRoots::<Test>::iter().count() as u32;
			assert_eq!(raw, typed, "no key may be left with an undecodable value");
			assert_eq!(typed, 2);
		});
	}

	/// A root in the map but missing from the order vector must still be queued,
	/// or it could never be pruned — a permanent leak of a spendable root.
	#[test]
	fn strays_missing_from_the_order_vector_are_queued() {
		new_test_ext().execute_with(|| {
			let ordered = [root_of(1)];
			PoseidonRoot::<Test>::put(root_of(1));
			seed_v2_state(&ordered);
			// A root the order vector never listed.
			write_v2_root(root_of(9), true);

			MigrateToV3::<Test>::on_runtime_upgrade();

			let head = HistoricRootsHead::<Test>::get();
			assert_eq!(head, 2, "the stray must occupy a slot too");
			assert_eq!(
				HistoricPoseidonRoots::<Test>::iter().count() as u64,
				head,
				"map and queue must have equal length"
			);
			assert!(MerkleRepository::is_known_root::<Test>(&root_of(9)));
		});
	}

	/// An unreadable order vector must still produce a usable window rather than
	/// leaving the chain with no provable root.
	#[test]
	fn falls_back_to_key_order_when_the_vector_is_undecodable() {
		new_test_ext().execute_with(|| {
			let roots = [root_of(4), root_of(5)];
			PoseidonRoot::<Test>::put(root_of(4));
			seed_v2_state(&roots);
			sp_io::storage::set(&old_order_key(), &[0xFFu8; 3]);

			MigrateToV3::<Test>::on_runtime_upgrade();

			assert_eq!(HistoricRootsHead::<Test>::get(), 2);
			for root in &roots {
				assert!(MerkleRepository::is_known_root::<Test>(root));
			}
		});
	}

	/// The active root must always be provable, even from empty v2 state.
	#[test]
	fn seeds_the_active_root_from_empty_state() {
		new_test_ext().execute_with(|| {
			PoseidonRoot::<Test>::put(root_of(42));
			seed_v2_state(&[]);

			MigrateToV3::<Test>::on_runtime_upgrade();

			assert!(MerkleRepository::is_known_root::<Test>(&root_of(42)));
			assert_eq!(HistoricRootsHead::<Test>::get(), 1);
			assert_eq!(HistoricRootsTail::<Test>::get(), 0);
		});
	}

	/// Migrated roots get a full retention window, so nothing arrives expired.
	///
	/// Uses a non-active root: the active one is accepted unconditionally by
	/// `is_known_root`, which would mask the expiry this test checks.
	#[test]
	fn migrated_roots_are_spendable_for_a_full_window() {
		new_test_ext().execute_with(|| {
			let migrated = root_of(1);
			let active = root_of(2);
			PoseidonRoot::<Test>::put(active);
			seed_v2_state(&[migrated, active]);
			let start = frame_system::Pallet::<Test>::block_number();

			MigrateToV3::<Test>::on_runtime_upgrade();

			let retention: u64 = <Test as Config>::RootRetentionBlocks::get();
			frame_system::Pallet::<Test>::set_block_number(start + retention);
			assert!(
				MerkleRepository::is_known_root::<Test>(&migrated),
				"must stay spendable through the final block of the window"
			);
			frame_system::Pallet::<Test>::set_block_number(start + retention + 1);
			assert!(
				!MerkleRepository::is_known_root::<Test>(&migrated),
				"must expire once the window elapses"
			);
			assert!(
				MerkleRepository::is_known_root::<Test>(&active),
				"the active root stays provable regardless of its window"
			);
		});
	}

	#[test]
	fn is_idempotent_and_skips_a_v3_chain() {
		new_test_ext().execute_with(|| {
			let roots = [root_of(1), root_of(2)];
			PoseidonRoot::<Test>::put(root_of(2));
			seed_v2_state(&roots);

			MigrateToV3::<Test>::on_runtime_upgrade();
			let head = HistoricRootsHead::<Test>::get();
			let tail = HistoricRootsTail::<Test>::get();

			// A second run must change nothing.
			MigrateToV3::<Test>::on_runtime_upgrade();
			assert_eq!(HistoricRootsHead::<Test>::get(), head);
			assert_eq!(HistoricRootsTail::<Test>::get(), tail);
			assert_eq!(crate::Pallet::<Test>::on_chain_storage_version(), 3);
		});
	}

	/// A chain built from genesis is already at v3; the migration must leave its
	/// seeded queue untouched.
	#[test]
	fn leaves_a_genesis_chain_untouched() {
		new_test_ext().execute_with(|| {
			let head_before = HistoricRootsHead::<Test>::get();
			let tail_before = HistoricRootsTail::<Test>::get();

			MigrateToV3::<Test>::on_runtime_upgrade();

			assert_eq!(HistoricRootsHead::<Test>::get(), head_before);
			assert_eq!(HistoricRootsTail::<Test>::get(), tail_before);
		});
	}
}
