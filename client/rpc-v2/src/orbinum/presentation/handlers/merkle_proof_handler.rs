//! MerkleProofHandler - Handler to generate Merkle proofs

use std::sync::Arc;

use jsonrpsee::core::RpcResult;

use crate::orbinum::{
	application::{MerkleProofResponse, MerkleProofService},
	infrastructure::mappers::CommitmentMapper,
	presentation::validation::{RequestValidator, RpcError},
};

/// Handler for `privacy_getMerkleProof` and `privacy_getMerkleProofByCommitment`.
pub struct MerkleProofHandler<Q> {
	merkle_service: Arc<MerkleProofService<Q>>,
}

impl<Q> MerkleProofHandler<Q>
where
	Q: crate::orbinum::domain::BlockchainQuery + crate::orbinum::domain::MerkleTreeQuery,
{
	/// Creates a new `MerkleProofHandler`.
	pub fn new(merkle_service: Arc<MerkleProofService<Q>>) -> Self {
		Self { merkle_service }
	}

	/// Handles request to generate a Merkle proof by leaf index.
	///
	/// # Parameters
	/// - `leaf_index`: Leaf index (0-indexed)
	///
	/// # Returns
	/// - `MerkleProofResponse`: DTO with path, leaf index, and tree depth
	///
	/// # Errors
	/// - `InvalidLeafIndex`: If `leaf_index >= tree_size`
	/// - `MerkleTreeNotInitialized`: If tree is not initialized
	pub fn handle(&self, leaf_index: u32) -> RpcResult<MerkleProofResponse> {
		// 1. Validate input
		RequestValidator::validate_leaf_index(leaf_index)?;

		// 2. Generate proof + root atomically from the same best_block
		let (proof_path, root) = self
			.merkle_service
			.generate_proof_with_root(leaf_index)
			.map_err(RpcError::from_application_error)?;

		// 3. Map domain entities to DTO
		let (path, leaf_idx, tree_depth) = proof_path.into_parts();
		let path_hex: Vec<String> = path
			.into_iter()
			.map(CommitmentMapper::to_hex_string)
			.collect();
		let root_hex = CommitmentMapper::to_hex_string(root);

		let response = MerkleProofResponse::new(root_hex, path_hex, leaf_idx, tree_depth.value());

		Ok(response)
	}

	/// Handles request to generate a Merkle proof by commitment hex.
	///
	/// # Parameters
	/// - `commitment_hex`: Commitment as 0x-prefixed hex string
	///
	/// # Returns
	/// - `MerkleProofResponse`: DTO with path, leaf index, and tree depth
	///
	/// # Errors
	/// - `InvalidCommitment`: If the hex string is malformed
	/// - `CalculationError`: If the commitment is not found in the tree
	/// - `MerkleTreeNotInitialized`: If tree is not initialized
	pub fn handle_by_commitment(&self, commitment_hex: String) -> RpcResult<MerkleProofResponse> {
		// 1. Parse commitment hex
		let commitment = CommitmentMapper::from_hex_string(&commitment_hex)
			.map_err(RpcError::invalid_commitment)?;

		// 2. Generate proof + root atomically from the same best_block
		let (proof_path, root) = self
			.merkle_service
			.generate_proof_by_commitment_with_root(commitment)
			.map_err(RpcError::from_application_error)?;

		// 3. Map domain entities to DTO
		let (path, leaf_idx, tree_depth) = proof_path.into_parts();
		let path_hex: Vec<String> = path
			.into_iter()
			.map(CommitmentMapper::to_hex_string)
			.collect();
		let root_hex = CommitmentMapper::to_hex_string(root);

		Ok(MerkleProofResponse::new(
			root_hex,
			path_hex,
			leaf_idx,
			tree_depth.value(),
		))
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::orbinum::domain::{
		BlockHash, BlockchainQuery, Commitment, DomainError, DomainResult, MerkleTreeQuery,
		TreeSize,
	};

	#[derive(Clone, Copy)]
	struct MockQuery {
		tree_size: u32,
		sibling: Commitment,
	}

	impl BlockchainQuery for MockQuery {
		fn best_hash(&self) -> DomainResult<BlockHash> {
			Ok(BlockHash::new([2u8; 32]))
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
			Ok(Commitment::new([3u8; 32]))
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

	#[test]
	fn should_return_merkle_proof_response() {
		let query = MockQuery {
			tree_size: 2,
			sibling: Commitment::new([0xBBu8; 32]),
		};
		let service = Arc::new(MerkleProofService::new(query));
		let handler = MerkleProofHandler::new(service);

		let response = handler.handle(0).expect("handler should succeed");

		assert_eq!(response.leaf_index, 0);
		assert_eq!(response.tree_depth, 20);
		assert_eq!(response.path.len(), 20);
		assert_eq!(response.path[0], format!("0x{}", "bb".repeat(32)));
	}

	#[test]
	fn should_fail_for_invalid_leaf_index() {
		let query = MockQuery {
			tree_size: 1,
			sibling: Commitment::new([0xBBu8; 32]),
		};
		let service = Arc::new(MerkleProofService::new(query));
		let handler = MerkleProofHandler::new(service);

		let result = handler.handle(1);

		assert!(result.is_err());
	}
}
