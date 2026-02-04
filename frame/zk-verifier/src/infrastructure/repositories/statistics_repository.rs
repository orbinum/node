//! FRAME statistics repository implementation

use crate::{
	domain::{
		repositories::{Statistics, StatisticsRepository},
		value_objects::CircuitId,
	},
	pallet::{self as pallet, Config},
	types::CircuitId as StorageCircuitId,
};
use core::marker::PhantomData;

/// FRAME-based repository for verification statistics
pub struct FrameStatisticsRepository<T: Config> {
	_phantom: PhantomData<T>,
}

impl<T: Config> FrameStatisticsRepository<T> {
	/// Create a new repository instance
	pub fn new() -> Self {
		Self {
			_phantom: PhantomData,
		}
	}
}

impl<T: Config> StatisticsRepository for FrameStatisticsRepository<T> {
	type Error = StatisticsError;

	fn increment_verifications(&self, id: CircuitId, version: u32) -> Result<(), Self::Error> {
		let storage_id = StorageCircuitId(id.value());
		pallet::VerificationStats::<T>::mutate(storage_id, version, |stats| {
			stats.total_verifications = stats.total_verifications.saturating_add(1);
		});
		Ok(())
	}

	fn increment_successes(&self, id: CircuitId, version: u32) -> Result<(), Self::Error> {
		let storage_id = StorageCircuitId(id.value());
		pallet::VerificationStats::<T>::mutate(storage_id, version, |stats| {
			stats.successful_verifications = stats.successful_verifications.saturating_add(1);
		});
		Ok(())
	}

	fn increment_failures(&self, id: CircuitId, version: u32) -> Result<(), Self::Error> {
		let storage_id = StorageCircuitId(id.value());
		pallet::VerificationStats::<T>::mutate(storage_id, version, |stats| {
			stats.failed_verifications = stats.failed_verifications.saturating_add(1);
		});
		Ok(())
	}

	fn get_stats(&self, id: CircuitId, version: u32) -> Result<Statistics, Self::Error> {
		let storage_id = StorageCircuitId(id.value());
		let stats = pallet::VerificationStats::<T>::get(storage_id, version);

		Ok(Statistics {
			total_verifications: stats.total_verifications,
			successful_verifications: stats.successful_verifications,
			failed_verifications: stats.failed_verifications,
		})
	}
}

impl<T: Config> Default for FrameStatisticsRepository<T> {
	fn default() -> Self {
		Self::new()
	}
}

/// Statistics repository errors
#[derive(Debug)]
pub enum StatisticsError {
	StorageError,
}
