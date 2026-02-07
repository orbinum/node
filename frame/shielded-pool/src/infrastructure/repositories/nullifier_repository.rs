//! Nullifier Repository - Encapsulates nullifier set storage access

use crate::{
	domain::Nullifier,
	pallet::{Config, NullifierSet},
};
use frame_system::pallet_prelude::BlockNumberFor;

/// Repository for nullifier set storage operations
pub struct NullifierRepository;

impl NullifierRepository {
	/// Check if a nullifier has been used
	pub fn is_used<T: Config>(nullifier: &Nullifier) -> bool {
		NullifierSet::<T>::contains_key(nullifier)
	}

	/// Mark a nullifier as used at current block
	pub fn mark_as_used<T: Config>(nullifier: Nullifier, block: BlockNumberFor<T>) {
		NullifierSet::<T>::insert(nullifier, block);
	}

	/// Get block number when nullifier was used (if any)
	pub fn get_usage_block<T: Config>(nullifier: &Nullifier) -> Option<BlockNumberFor<T>> {
		NullifierSet::<T>::get(nullifier)
	}
}
