//! Mappers - Convert between domain and storage types

use crate::{
	domain::{entities::VerificationKey, value_objects::ProofSystem},
	types::{ProofSystem as StorageProofSystem, VerificationKeyInfo},
};
use frame_system::pallet_prelude::BlockNumberFor;

/// Mapper for verification keys
pub struct VkMapper;

impl VkMapper {
	/// Convert domain VerificationKey to storage type
	pub fn to_storage<T: frame_system::Config>(
		vk: VerificationKey,
		block_number: BlockNumberFor<T>,
	) -> VerificationKeyInfo<BlockNumberFor<T>> {
		VerificationKeyInfo {
			key_data: vk.data().to_vec().try_into().unwrap_or_default(),
			system: Self::map_proof_system(vk.system()),
			registered_at: block_number,
		}
	}

	/// Convert storage type to domain VerificationKey
	pub fn to_domain<T: frame_system::Config>(
		storage: VerificationKeyInfo<BlockNumberFor<T>>,
	) -> Result<VerificationKey, MapperError> {
		let system = Self::map_from_storage_system(storage.system)?;
		VerificationKey::new(storage.key_data.to_vec(), system)
			.map_err(|_| MapperError::InvalidDomainData)
	}

	fn map_proof_system(system: ProofSystem) -> StorageProofSystem {
		match system {
			ProofSystem::Groth16 => StorageProofSystem::Groth16,
			ProofSystem::Plonk => StorageProofSystem::Plonk,
			ProofSystem::Halo2 => StorageProofSystem::Halo2,
		}
	}

	fn map_from_storage_system(system: StorageProofSystem) -> Result<ProofSystem, MapperError> {
		match system {
			StorageProofSystem::Groth16 => Ok(ProofSystem::Groth16),
			StorageProofSystem::Plonk => Ok(ProofSystem::Plonk),
			StorageProofSystem::Halo2 => Ok(ProofSystem::Halo2),
		}
	}
}

/// Mapper errors
#[derive(Debug)]
pub enum MapperError {
	InvalidDomainData,
	InvalidStorageData,
	ConversionFailed,
}
