//! FRAME verification key repository implementation

use crate::{
	domain::{
		entities::VerificationKey,
		repositories::VerificationKeyRepository,
		value_objects::{CircuitId, ProofSystem},
	},
	pallet::{ActiveCircuitVersion, Config, VerificationKeys},
};
use alloc::vec::Vec;
use core::marker::PhantomData;
use sp_io::hashing::blake2_256;

pub fn runtime_supported_versions<T: Config>(circuit_id_raw: u32) -> Vec<u32> {
	let mut versions: Vec<u32> =
		VerificationKeys::<T>::iter_prefix(crate::types::CircuitId(circuit_id_raw))
			.map(|(version, _)| version)
			.collect();
	versions.sort_unstable();
	versions
}

pub fn runtime_active_version<T: Config>(circuit_id_raw: u32) -> Option<u32> {
	ActiveCircuitVersion::<T>::get(crate::types::CircuitId(circuit_id_raw))
}

pub fn runtime_vk_hash<T: Config>(circuit_id_raw: u32, version: u32) -> Option<[u8; 32]> {
	VerificationKeys::<T>::get(crate::types::CircuitId(circuit_id_raw), version)
		.map(|vk| blake2_256(vk.key_data.as_slice()))
}

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
		let key_data = vk
			.data()
			.to_vec()
			.try_into()
			.map_err(|_| RepositoryError::MappingFailed)?;

		VerificationKeys::<T>::insert(
			crate::types::CircuitId(id.value()),
			version,
			crate::types::VerificationKeyInfo {
				key_data,
				system: crate::types::ProofSystem::Groth16,
				registered_at: frame_system::Pallet::<T>::block_number(),
			},
		);
		Ok(())
	}

	fn find(&self, id: CircuitId, version: u32) -> Result<Option<VerificationKey>, Self::Error> {
		VerificationKeys::<T>::get(crate::types::CircuitId(id.value()), version)
			.map(|stored| {
				VerificationKey::new(stored.key_data.to_vec(), ProofSystem::Groth16)
					.map_err(|_| RepositoryError::MappingFailed)
			})
			.transpose()
	}

	fn get_active_version(&self, id: CircuitId) -> Result<u32, Self::Error> {
		ActiveCircuitVersion::<T>::get(crate::types::CircuitId(id.value()))
			.ok_or(RepositoryError::NotFound)
	}

	fn exists(&self, id: CircuitId, version: u32) -> bool {
		VerificationKeys::<T>::contains_key(crate::types::CircuitId(id.value()), version)
	}

	fn delete(&self, id: CircuitId, version: u32) -> Result<(), Self::Error> {
		VerificationKeys::<T>::remove(crate::types::CircuitId(id.value()), version);
		Ok(())
	}

	fn list_all(&self) -> Result<Vec<(CircuitId, u32, VerificationKey)>, Self::Error> {
		let mut result = Vec::new();
		for (circuit_id, version, stored) in VerificationKeys::<T>::iter() {
			let vk = VerificationKey::new(stored.key_data.to_vec(), ProofSystem::Groth16)
				.map_err(|_| RepositoryError::MappingFailed)?;
			result.push((CircuitId::new(circuit_id.0), version, vk));
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

#[cfg(test)]
mod tests {
	use super::*;
	use crate::mock::Test;
	use sp_io::TestExternalities;

	fn with_ext(test: impl FnOnce()) {
		TestExternalities::default().execute_with(test);
	}

	#[test]
	fn active_version_exists_for_registered_circuit() {
		with_ext(|| {
			crate::ActiveCircuitVersion::<Test>::insert(crate::types::CircuitId::TRANSFER, 1);
			let repo = FrameVkRepository::<Test>::new();
			assert!(matches!(
				repo.get_active_version(CircuitId::TRANSFER),
				Ok(1)
			));
		});
	}

	#[test]
	fn find_returns_stored_vk_for_registered_version() {
		with_ext(|| {
			let key_data: frame_support::BoundedVec<u8, frame_support::traits::ConstU32<8192>> =
				vec![1u8; 512].try_into().unwrap();
			crate::VerificationKeys::<Test>::insert(
				crate::types::CircuitId::TRANSFER,
				1,
				crate::types::VerificationKeyInfo {
					key_data,
					system: crate::types::ProofSystem::Groth16,
					registered_at: 0,
				},
			);
			let repo = FrameVkRepository::<Test>::new();
			let vk = repo
				.find(CircuitId::TRANSFER, 1)
				.expect("repository call should succeed")
				.expect("transfer v1 should exist");
			assert!(!vk.data().is_empty());
		});
	}

	#[test]
	fn find_returns_none_for_unsupported_version() {
		with_ext(|| {
			let repo = FrameVkRepository::<Test>::new();
			assert_eq!(repo.find(CircuitId::TRANSFER, 2).unwrap(), None);
		});
	}

	#[test]
	fn list_all_returns_all_stored_keys() {
		with_ext(|| {
			let key_data: frame_support::BoundedVec<u8, frame_support::traits::ConstU32<8192>> =
				vec![1u8; 512].try_into().unwrap();
			crate::VerificationKeys::<Test>::insert(
				crate::types::CircuitId::TRANSFER,
				1,
				crate::types::VerificationKeyInfo {
					key_data,
					system: crate::types::ProofSystem::Groth16,
					registered_at: 0,
				},
			);
			let repo = FrameVkRepository::<Test>::new();
			let all = repo.list_all().expect("list_all should work");
			assert_eq!(all.len(), 1);
			assert!(
				all.iter()
					.any(|(id, version, _)| *id == CircuitId::TRANSFER && *version == 1)
			);
		});
	}

	#[test]
	fn write_operations_use_storage() {
		with_ext(|| {
			let repo = FrameVkRepository::<Test>::new();
			let vk = VerificationKey::new(vec![1u8; 512], ProofSystem::Groth16).unwrap();
			repo.save(CircuitId::TRANSFER, 1, vk).unwrap();
			assert!(repo.exists(CircuitId::TRANSFER, 1));
			repo.delete(CircuitId::TRANSFER, 1).unwrap();
			assert!(!repo.exists(CircuitId::TRANSFER, 1));
		});
	}
}
