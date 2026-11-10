//! Nullifier set — the double-spend guard.
//!
//! Insert-only by design: there is no removal path, and a nullifier maps to the
//! block it was spent in. Every spend checks membership before taking effect and
//! inserts within the same dispatch, so a rollback undoes both together.

use super::stats::PoolStatsRepository;
use crate::pallet::{Config, NullifierSet};
use frame_system::pallet_prelude::BlockNumberFor;

// NullifierRepository

pub struct NullifierRepository;

impl NullifierRepository {
	pub fn is_used<T: Config>(nullifier: &crate::types::Nullifier) -> bool {
		NullifierSet::<T>::contains_key(nullifier)
	}
	pub fn mark_as_used<T: Config>(nullifier: crate::types::Nullifier, block: BlockNumberFor<T>) {
		NullifierSet::<T>::insert(nullifier, block);
		PoolStatsRepository::increment_nullifiers_spent::<T>();
	}
	pub fn get_usage_block<T: Config>(
		nullifier: &crate::types::Nullifier,
	) -> Option<BlockNumberFor<T>> {
		NullifierSet::<T>::get(nullifier)
	}
}
