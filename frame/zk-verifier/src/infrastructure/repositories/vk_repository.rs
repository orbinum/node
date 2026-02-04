//! FRAME verification key repository implementation

use crate::{
	domain::{
		entities::VerificationKey, repositories::VerificationKeyRepository,
		value_objects::CircuitId,
	},
	infrastructure::mappers::VkMapper,
	pallet::{self as pallet, Config},
	types::CircuitId as StorageCircuitId,
};
use alloc::vec::Vec;
use core::marker::PhantomData;

/// FRAME-based repository for verification keys
pub struct FrameVkRepository<T: Config> {
	_phantom: PhantomData<T>,
}

impl<T: Config> FrameVkRepository<T> {
	/// Create a new repository instance
	pub fn new() -> Self {
		Self {
			_phantom: PhantomData,
		}
	}
}

impl<T: Config> VerificationKeyRepository for FrameVkRepository<T> {
	type Error = RepositoryError;

	fn save(&self, id: CircuitId, version: u32, vk: VerificationKey) -> Result<(), Self::Error> {
		let block_number = frame_system::Pallet::<T>::block_number();
		let storage_vk = VkMapper::to_storage::<T>(vk, block_number);

		// Convert domain CircuitId to storage CircuitId
		let storage_id = StorageCircuitId(id.value());
		pallet::VerificationKeys::<T>::insert(storage_id, version, storage_vk);

		Ok(())
	}

	fn find(&self, id: CircuitId, version: u32) -> Result<Option<VerificationKey>, Self::Error> {
		let storage_id = StorageCircuitId(id.value());
		pallet::VerificationKeys::<T>::get(storage_id, version)
			.map(|s| VkMapper::to_domain::<T>(s))
			.transpose()
			.map_err(|_| RepositoryError::MappingFailed)
	}

	fn get_active_version(&self, id: CircuitId) -> Result<u32, Self::Error> {
		let storage_id = StorageCircuitId(id.value());
		pallet::ActiveCircuitVersion::<T>::get(storage_id).ok_or(RepositoryError::NotFound)
	}

	fn set_active_version(&self, id: CircuitId, version: u32) -> Result<(), Self::Error> {
		let storage_id = StorageCircuitId(id.value());
		// Verify key exists before setting as active
		if !pallet::VerificationKeys::<T>::contains_key(storage_id, version) {
			return Err(RepositoryError::NotFound);
		}
		pallet::ActiveCircuitVersion::<T>::insert(storage_id, version);
		Ok(())
	}

	fn exists(&self, id: CircuitId, version: u32) -> bool {
		let storage_id = StorageCircuitId(id.value());
		pallet::VerificationKeys::<T>::contains_key(storage_id, version)
	}

	fn delete(&self, id: CircuitId, version: u32) -> Result<(), Self::Error> {
		let storage_id = StorageCircuitId(id.value());
		pallet::VerificationKeys::<T>::remove(storage_id, version);
		Ok(())
	}

	fn list_all(&self) -> Result<Vec<(CircuitId, u32, VerificationKey)>, Self::Error> {
		let mut result = Vec::new();
		for (storage_id, version, storage_vk) in pallet::VerificationKeys::<T>::iter() {
			let id = CircuitId::new(storage_id.0);
			let vk =
				VkMapper::to_domain::<T>(storage_vk).map_err(|_| RepositoryError::MappingFailed)?;
			result.push((id, version, vk));
		}
		Ok(result)
	}
}

impl<T: Config> Default for FrameVkRepository<T> {
	fn default() -> Self {
		Self::new()
	}
}

/// Repository operation errors
#[derive(Debug)]
pub enum RepositoryError {
	NotFound,
	MappingFailed,
	StorageError,
}
