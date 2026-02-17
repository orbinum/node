//! Domain layer - Pure business rules for the Orbinum RPC
//!
//! This layer does NOT depend on:
//! - FRAME (`sp_runtime`, `frame_support`, etc.)
//! - Substrate (`sp_blockchain`, `sc_client_api`, etc.)
//! - `jsonrpsee` (RPC framework)
//!
//! It only contains:
//! - RPC domain entities
//! - Value objects
//! - Ports (traits) for external services
//! - Pure business logic

pub mod entities;
pub mod ports;
pub mod value_objects;

// Re-exports of pallet entities (reuse shared domain)
// Note: Commitment, Nullifier, and AssetId come from pallet-shielded-pool
pub use pallet_shielded_pool::domain::{AssetId, Commitment, Nullifier};

// Re-exports of RPC-specific entities
pub use entities::{MerkleProofPath, PoolStatistics};
pub use value_objects::{BlockHash, TreeDepth, TreeSize};

// Re-exports of ports
pub use ports::{BlockchainQuery, MerkleTreeQuery, NullifierQuery, PoolQuery};

/// RPC domain error type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DomainError {
	/// Storage is not available.
	StorageNotAvailable,
	/// Block was not found.
	BlockNotFound,
	/// Leaf index is out of bounds.
	LeafIndexOutOfBounds { index: u32, tree_size: u32 },
	/// Merkle tree is not initialized.
	MerkleTreeNotInitialized,
	/// Nullifier was not found.
	NullifierNotFound,
	/// Pool is not initialized.
	PoolNotInitialized,
	/// Storage decoding error.
	StorageDecodeError(String),
	/// Calculation error.
	CalculationError(String),
}

impl core::fmt::Display for DomainError {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		match self {
			Self::StorageNotAvailable => write!(f, "Storage not available"),
			Self::BlockNotFound => write!(f, "Block not found"),
			Self::LeafIndexOutOfBounds { index, tree_size } => {
				write!(
					f,
					"Leaf index {index} out of bounds (tree size: {tree_size})"
				)
			}
			Self::MerkleTreeNotInitialized => write!(f, "Merkle tree not initialized"),
			Self::NullifierNotFound => write!(f, "Nullifier not found"),
			Self::PoolNotInitialized => write!(f, "Pool not initialized"),
			Self::StorageDecodeError(msg) => write!(f, "Storage decode error: {msg}"),
			Self::CalculationError(msg) => write!(f, "Calculation error: {msg}"),
		}
	}
}

/// Domain result type.
pub type DomainResult<T> = Result<T, DomainError>;

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn should_render_display_messages_for_domain_errors() {
		assert_eq!(
			DomainError::StorageNotAvailable.to_string(),
			"Storage not available"
		);
		assert_eq!(DomainError::BlockNotFound.to_string(), "Block not found");
		assert_eq!(
			DomainError::LeafIndexOutOfBounds {
				index: 9,
				tree_size: 3,
			}
			.to_string(),
			"Leaf index 9 out of bounds (tree size: 3)"
		);
		assert_eq!(
			DomainError::MerkleTreeNotInitialized.to_string(),
			"Merkle tree not initialized"
		);
		assert_eq!(
			DomainError::NullifierNotFound.to_string(),
			"Nullifier not found"
		);
		assert_eq!(
			DomainError::PoolNotInitialized.to_string(),
			"Pool not initialized"
		);
		assert_eq!(
			DomainError::StorageDecodeError("bad scale".to_string()).to_string(),
			"Storage decode error: bad scale"
		);
		assert_eq!(
			DomainError::CalculationError("overflow".to_string()).to_string(),
			"Calculation error: overflow"
		);
	}

	#[test]
	fn should_support_domain_result_alias() {
		let ok_value: DomainResult<u32> = Ok(7);
		let err_value: DomainResult<u32> = Err(DomainError::PoolNotInitialized);

		assert_eq!(ok_value, Ok(7));
		assert!(matches!(err_value, Err(DomainError::PoolNotInitialized)));
	}
}
