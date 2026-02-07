use jsonrpsee::{core::RpcResult, proc_macros::rpc, types::ErrorObjectOwned};
use pallet_shielded_pool_runtime_api::ShieldedPoolRuntimeApi;
use serde::{Deserialize, Serialize};
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_runtime::traits::Block as BlockT;
use std::sync::Arc;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MerkleTreeInfo {
	pub root: String,
	pub tree_size: u32,
	pub depth: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MerkleProof {
	pub root: String,
	pub leaf_index: u32,
	pub siblings: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ShieldedEvent {
	pub block_number: u64,
	pub extrinsic_index: u32,
	pub event_type: ShieldedEventType,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "type")]
pub enum ShieldedEventType {
	Shield {
		depositor: String,
		amount: u128,
		commitment: String,
		leaf_index: u32,
		encrypted_memo: Option<String>,
	},
	PrivateTransfer {
		nullifiers: Vec<String>,
		commitments: Vec<String>,
		leaf_indices: Vec<u32>,
		encrypted_memos: Option<Vec<String>>,
	},
	Unshield {
		nullifier: String,
		amount: u128,
		recipient: String,
	},
}

#[rpc(client, server)]
pub trait ShieldedPoolApi<BlockHash> {
	#[method(name = "shieldedPool_getMerkleTreeInfo")]
	fn get_merkle_tree_info(&self) -> RpcResult<MerkleTreeInfo>;

	#[method(name = "shieldedPool_getMerkleProof")]
	fn get_merkle_proof(&self, commitment: String) -> RpcResult<MerkleProof>;

	#[method(name = "shieldedPool_scanEvents")]
	fn scan_events(&self, from_block: u64, to_block: u64) -> RpcResult<Vec<ShieldedEvent>>;
}

pub struct ShieldedPool<C, B> {
	client: Arc<C>, // We keep client generic, but implement for specific bounds
	_marker: std::marker::PhantomData<B>,
}

impl<C, B> ShieldedPool<C, B> {
	pub fn new(client: Arc<C>) -> Self {
		Self {
			client,
			_marker: Default::default(),
		}
	}
}

impl<C, B> ShieldedPoolApiServer<B::Hash> for ShieldedPool<C, B>
where
	C: ProvideRuntimeApi<B> + HeaderBackend<B> + 'static,
	C::Api: ShieldedPoolRuntimeApi<B>,
	B: BlockT,
{
	fn get_merkle_tree_info(&self) -> RpcResult<MerkleTreeInfo> {
		let api = self.client.runtime_api();
		let best_block = self.client.info().best_hash;

		// Call runtime API
		let (root, tree_size, depth) = api
			.get_merkle_tree_info(best_block)
			.map_err(|e| ErrorObjectOwned::owned(1, format!("Runtime error: {e}"), None::<()>))?;

		Ok(MerkleTreeInfo {
			root: format!("0x{}", hex::encode(root)),
			tree_size,
			depth,
		})
	}

	fn get_merkle_proof(&self, commitment_hex: String) -> RpcResult<MerkleProof> {
		let commitment_bytes = hex::decode(commitment_hex.trim_start_matches("0x"))
			.map_err(|e| ErrorObjectOwned::owned(1, format!("Invalid hex: {e}"), None::<()>))?;

		let mut commitment = [0u8; 32];
		if commitment_bytes.len() != 32 {
			return Err(ErrorObjectOwned::owned(
				1,
				"Commitment must be 32 bytes",
				None::<()>,
			));
		}
		commitment.copy_from_slice(&commitment_bytes);

		let api = self.client.runtime_api();
		let best_block = self.client.info().best_hash;

		let (leaf_index, proof) = api
			.get_merkle_proof_for_commitment(best_block, commitment)
			.map_err(|e| ErrorObjectOwned::owned(1, format!("Runtime error: {e}"), None::<()>))?
			.ok_or_else(|| {
				ErrorObjectOwned::owned(1, "Commitment not found in tree", None::<()>)
			})?;

		let root_hash = api
			.get_merkle_tree_info(best_block)
			.map(|(root, _, _)| root)
			.unwrap_or([0u8; 32]);

		Ok(MerkleProof {
			root: format!("0x{}", hex::encode(root_hash)),
			leaf_index,
			siblings: proof
				.siblings
				.iter()
				.map(|h| format!("0x{}", hex::encode(h)))
				.collect(),
		})
	}

	fn scan_events(&self, _from_block: u64, _to_block: u64) -> RpcResult<Vec<ShieldedEvent>> {
		// Event scanning is not implemented via runtime API
		// This functionality should be implemented by:
		// 1. Indexing events in an off-chain database (recommended)
		// 2. Using Substrate's archive node with state queries
		// 3. Implementing a custom indexer service
		//
		// Returning empty list as placeholder.
		// TODO: Implement proper event indexing strategy

		log::warn!("scan_events called but not implemented - use event indexer instead");
		Ok(Vec::new())
	}
}
