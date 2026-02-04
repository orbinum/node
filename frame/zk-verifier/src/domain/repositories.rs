//! Repository trait definitions

use crate::domain::{entities::VerificationKey, value_objects::CircuitId};
use alloc::vec::Vec;

/// Repository for verification keys
pub trait VerificationKeyRepository {
	/// Error type for repository operations
	type Error;

	/// Save a verification key with a specific version
	fn save(&self, id: CircuitId, version: u32, vk: VerificationKey) -> Result<(), Self::Error>;

	/// Find a verification key by circuit ID and version
	fn find(&self, id: CircuitId, version: u32) -> Result<Option<VerificationKey>, Self::Error>;

	/// Get the active version for a circuit
	fn get_active_version(&self, id: CircuitId) -> Result<u32, Self::Error>;

	/// Set the active version for a circuit
	fn set_active_version(&self, id: CircuitId, version: u32) -> Result<(), Self::Error>;

	/// Check if a verification key version exists
	fn exists(&self, id: CircuitId, version: u32) -> bool;

	/// Delete a verification key version
	fn delete(&self, id: CircuitId, version: u32) -> Result<(), Self::Error>;

	/// List all verification keys (CircuitId, Version, VK)
	fn list_all(&self) -> Result<Vec<(CircuitId, u32, VerificationKey)>, Self::Error>;
}

/// Repository for verification statistics
pub trait StatisticsRepository {
	/// Error type for repository operations
	type Error;

	/// Increment total verifications counter for a version
	fn increment_verifications(&self, id: CircuitId, version: u32) -> Result<(), Self::Error>;

	/// Increment successful verifications counter for a version
	fn increment_successes(&self, id: CircuitId, version: u32) -> Result<(), Self::Error>;

	/// Increment failed verifications counter for a version
	fn increment_failures(&self, id: CircuitId, version: u32) -> Result<(), Self::Error>;

	/// Get statistics for a circuit version
	fn get_stats(&self, id: CircuitId, version: u32) -> Result<Statistics, Self::Error>;
}

/// Verification statistics
#[derive(Clone, Debug, Default)]
pub struct Statistics {
	pub total_verifications: u64,
	pub successful_verifications: u64,
	pub failed_verifications: u64,
}
