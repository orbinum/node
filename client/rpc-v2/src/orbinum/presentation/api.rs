//! Privacy RPC API definition (jsonrpsee trait)
//!
//! Defines RPC endpoints for shielded pool privacy.

use jsonrpsee::{core::RpcResult, proc_macros::rpc};

use crate::orbinum::application::{
	MerkleProofResponse, NullifierStatusResponse, PoolStatsResponse,
};

/// Privacy RPC API
///
/// JSON-RPC endpoints for shielded pool queries:
/// - `privacy_getMerkleRoot`: Fetch current Merkle root
/// - `privacy_getMerkleProof`: Fetch Merkle proof for a commitment leaf
/// - `privacy_getNullifierStatus`: Check whether a nullifier is spent
/// - `privacy_getPoolStats`: Fetch pool statistics
#[rpc(server)]
pub trait PrivacyApi {
	/// Returns the current Merkle tree root.
	///
	/// # Returns
	/// - `String`: Root hash as hex string (`0x`-prefixed)
	///
	/// # Example
	/// ```json
	/// {
	///   "jsonrpc": "2.0",
	///   "method": "privacy_getMerkleRoot",
	///   "params": [],
	///   "id": 1
	/// }
	/// ```
	///
	/// # Response
	/// ```json
	/// {
	///   "jsonrpc": "2.0",
	///   "result": "0x1234...abcd",
	///   "id": 1
	/// }
	/// ```
	#[method(name = "privacy_getMerkleRoot")]
	fn get_merkle_root(&self) -> RpcResult<String>;

	/// Returns a Merkle proof for a leaf at the given index.
	///
	/// # Parameters
	/// - `leaf_index`: Leaf index (0-indexed)
	///
	/// # Returns
	/// - `MerkleProofResponse`: Proof with path, leaf index, and tree depth
	///
	/// # Example
	/// ```json
	/// {
	///   "jsonrpc": "2.0",
	///   "method": "privacy_getMerkleProof",
	///   "params": [5],
	///   "id": 1
	/// }
	/// ```
	///
	/// # Response
	/// ```json
	/// {
	///   "jsonrpc": "2.0",
	///   "result": {
	///     "path": ["0x1234...", "0x5678..."],
	///     "leaf_index": 5,
	///     "tree_depth": 10
	///   },
	///   "id": 1
	/// }
	/// ```
	#[method(name = "privacy_getMerkleProof")]
	fn get_merkle_proof(&self, leaf_index: u32) -> RpcResult<MerkleProofResponse>;

	/// Checks whether a nullifier has been spent.
	///
	/// # Parameters
	/// - `nullifier`: Nullifier hash hex string (with or without `0x`)
	///
	/// # Returns
	/// - `NullifierStatusResponse`: Nullifier status (`is_spent`)
	///
	/// # Example
	/// ```json
	/// {
	///   "jsonrpc": "2.0",
	///   "method": "privacy_getNullifierStatus",
	///   "params": ["0xabcd...1234"],
	///   "id": 1
	/// }
	/// ```
	///
	/// # Response
	/// ```json
	/// {
	///   "jsonrpc": "2.0",
	///   "result": {
	///     "nullifier": "0xabcd...1234",
	///     "is_spent": true
	///   },
	///   "id": 1
	/// }
	/// ```
	#[method(name = "privacy_getNullifierStatus")]
	fn get_nullifier_status(&self, nullifier: String) -> RpcResult<NullifierStatusResponse>;

	/// Returns complete shielded pool statistics.
	///
	/// # Returns
	/// - `PoolStatsResponse`: Pool stats (root, count, balance, depth)
	///
	/// # Example
	/// ```json
	/// {
	///   "jsonrpc": "2.0",
	///   "method": "privacy_getPoolStats",
	///   "params": [],
	///   "id": 1
	/// }
	/// ```
	///
	/// # Response
	/// ```json
	/// {
	///   "jsonrpc": "2.0",
	///   "result": {
	///     "merkle_root": "0x1234...abcd",
	///     "commitment_count": 100,
	///     "total_balance": "1000000000000000000",
	///     "tree_depth": 10
	///   },
	///   "id": 1
	/// }
	/// ```
	#[method(name = "privacy_getPoolStats")]
	fn get_pool_stats(&self) -> RpcResult<PoolStatsResponse>;
}
