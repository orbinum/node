//! Privacy RPC Server implementation
//!
//! Implements `PrivacyApiServer` by delegating to application services.

use std::sync::Arc;

use jsonrpsee::core::RpcResult;

use crate::orbinum::{
	application::{
		MerkleProofResponse, MerkleProofService, NullifierService, NullifierStatusResponse,
		PoolQueryService, PoolStatsResponse,
	},
	presentation::{
		api::PrivacyApiServer,
		handlers::{
			MerkleProofHandler, MerkleRootHandler, NullifierStatusHandler, PoolStatsHandler,
		},
	},
};

/// Privacy RPC Server
///
/// Server that implements the shielded-pool privacy API.
/// Delegates all business logic to application services.
///
/// # Architecture
/// ```text
/// JSON-RPC Request
///   ↓
/// PrivacyRpcServer (presentation)
///   ↓
/// Handler (presentation/handlers)
///   ↓
/// Service (application/services)
///   ↓
/// Port (domain/ports)
///   ↓
/// Adapter (infrastructure/adapters)
///   ↓
/// Substrate Storage
/// ```
///
/// # Generics
/// - `Q`: Query port implementing all required traits
pub struct PrivacyRpcServer<Q> {
	/// Handler for Merkle root endpoint.
	merkle_root_handler: MerkleRootHandler<Q>,
	/// Handler for Merkle proof endpoint.
	merkle_proof_handler: MerkleProofHandler<Q>,
	/// Handler for nullifier status endpoint.
	nullifier_handler: NullifierStatusHandler<Q>,
	/// Handler for pool stats endpoint.
	pool_stats_handler: PoolStatsHandler<Q>,
}

impl<Q> PrivacyRpcServer<Q>
where
	Q: crate::orbinum::domain::BlockchainQuery
		+ crate::orbinum::domain::MerkleTreeQuery
		+ crate::orbinum::domain::NullifierQuery
		+ crate::orbinum::domain::PoolQuery
		+ Clone
		+ 'static,
{
	/// Creates a new `PrivacyRpcServer`.
	///
	/// # Parameters
	/// - `query`: Implementation of all required ports (typically `SubstrateStorageAdapter`)
	pub fn new(query: Q) -> Self {
		// Build services
		let merkle_service = Arc::new(MerkleProofService::new(query.clone()));
		let nullifier_service = Arc::new(NullifierService::new(query.clone()));
		let pool_service = Arc::new(PoolQueryService::new(query.clone()));

		// Build handlers
		let merkle_root_handler = MerkleRootHandler::new(pool_service.clone());
		let merkle_proof_handler = MerkleProofHandler::new(merkle_service);
		let nullifier_handler = NullifierStatusHandler::new(nullifier_service);
		let pool_stats_handler = PoolStatsHandler::new(pool_service);

		Self {
			merkle_root_handler,
			merkle_proof_handler,
			nullifier_handler,
			pool_stats_handler,
		}
	}
}

impl<Q> PrivacyApiServer for PrivacyRpcServer<Q>
where
	Q: crate::orbinum::domain::BlockchainQuery
		+ crate::orbinum::domain::MerkleTreeQuery
		+ crate::orbinum::domain::NullifierQuery
		+ crate::orbinum::domain::PoolQuery
		+ Clone
		+ 'static,
{
	fn get_merkle_root(&self) -> RpcResult<String> {
		self.merkle_root_handler.handle()
	}

	fn get_merkle_proof(&self, leaf_index: u32) -> RpcResult<MerkleProofResponse> {
		self.merkle_proof_handler.handle(leaf_index)
	}

	fn get_nullifier_status(&self, nullifier: String) -> RpcResult<NullifierStatusResponse> {
		self.nullifier_handler.handle(nullifier)
	}

	fn get_pool_stats(&self) -> RpcResult<PoolStatsResponse> {
		self.pool_stats_handler.handle()
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::orbinum::domain::{
		AssetId, BlockHash, BlockchainQuery, Commitment, DomainError, DomainResult,
		MerkleTreeQuery, Nullifier, NullifierQuery, PoolQuery, TreeSize,
	};

	#[derive(Clone, Copy)]
	struct MockQuery {
		root: Commitment,
		tree_size: u32,
		total_balance: u128,
		nullifier_spent: bool,
		sibling: Commitment,
	}

	impl BlockchainQuery for MockQuery {
		fn best_hash(&self) -> DomainResult<BlockHash> {
			Ok(BlockHash::new([9u8; 32]))
		}

		fn storage_at(
			&self,
			_block_hash: BlockHash,
			_storage_key: &[u8],
		) -> DomainResult<Option<Vec<u8>>> {
			Ok(None)
		}
	}

	impl MerkleTreeQuery for MockQuery {
		fn get_merkle_root(&self, _block_hash: BlockHash) -> DomainResult<Commitment> {
			Ok(self.root)
		}

		fn get_tree_size(&self, _block_hash: BlockHash) -> DomainResult<TreeSize> {
			Ok(TreeSize::new(self.tree_size))
		}

		fn get_leaf(&self, _block_hash: BlockHash, leaf_index: u32) -> DomainResult<Commitment> {
			if leaf_index == 1 {
				Ok(self.sibling)
			} else {
				Err(DomainError::LeafIndexOutOfBounds {
					index: leaf_index,
					tree_size: self.tree_size,
				})
			}
		}
	}

	impl NullifierQuery for MockQuery {
		fn is_nullifier_spent(
			&self,
			_block_hash: BlockHash,
			_nullifier: Nullifier,
		) -> DomainResult<bool> {
			Ok(self.nullifier_spent)
		}
	}

	impl PoolQuery for MockQuery {
		fn get_total_balance(&self, _block_hash: BlockHash) -> DomainResult<u128> {
			Ok(self.total_balance)
		}

		fn get_asset_balance(
			&self,
			_block_hash: BlockHash,
			_asset_id: AssetId,
		) -> DomainResult<u128> {
			Ok(0)
		}
	}

	#[test]
	fn should_delegate_all_endpoints_successfully() {
		let server = PrivacyRpcServer::new(MockQuery {
			root: Commitment::new([0x11u8; 32]),
			tree_size: 2,
			total_balance: 777,
			nullifier_spent: true,
			sibling: Commitment::new([0x22u8; 32]),
		});

		let root = server
			.get_merkle_root()
			.expect("get_merkle_root should succeed");
		let proof = server
			.get_merkle_proof(0)
			.expect("get_merkle_proof should succeed");
		let nullifier = server
			.get_nullifier_status(format!("0x{}", "11".repeat(32)))
			.expect("get_nullifier_status should succeed");
		let stats = server
			.get_pool_stats()
			.expect("get_pool_stats should succeed");

		assert_eq!(root, format!("0x{}", "11".repeat(32)));
		assert_eq!(proof.leaf_index, 0);
		assert_eq!(proof.tree_depth, 20);
		assert!(nullifier.is_spent);
		assert_eq!(stats.total_balance, 777);
	}

	#[test]
	fn should_fail_merkle_proof_when_leaf_index_is_invalid() {
		let server = PrivacyRpcServer::new(MockQuery {
			root: Commitment::new([0x11u8; 32]),
			tree_size: 1,
			total_balance: 777,
			nullifier_spent: false,
			sibling: Commitment::new([0x22u8; 32]),
		});

		let result = server.get_merkle_proof(1);

		assert!(result.is_err());
	}
}
