//! Pool counters.
//!
//! Monotonic totals for commitments inserted and nullifiers spent. Saturating
//! throughout — a stalled counter is preferable to a wrapped one, and neither is
//! reachable at any realistic chain lifetime.

use crate::pallet::{Config, TotalCommitmentsInserted, TotalNullifiersSpent};

// PoolStatsRepository

pub struct PoolStatsRepository;

impl PoolStatsRepository {
	pub fn increment_commitments_inserted<T: Config>() {
		TotalCommitmentsInserted::<T>::mutate(|n| *n = n.saturating_add(1));
	}
	pub fn get_total_commitments_inserted<T: Config>() -> u64 {
		TotalCommitmentsInserted::<T>::get()
	}
	pub fn increment_nullifiers_spent<T: Config>() {
		TotalNullifiersSpent::<T>::mutate(|n| *n = n.saturating_add(1));
	}
	pub fn get_total_nullifiers_spent<T: Config>() -> u64 {
		TotalNullifiersSpent::<T>::get()
	}
}
