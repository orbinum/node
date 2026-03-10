use jsonrpsee::{core::RpcResult, proc_macros::rpc, types::ErrorObjectOwned};
use pallet_zk_verifier_runtime_api::{CircuitVersionInfo, ZkVerifierRuntimeApi};
use serde::{Deserialize, Serialize};
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_runtime::traits::Block as BlockT;
use std::sync::Arc;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VkVersionHashResponse {
	pub version: u32,
	pub vk_hash: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CircuitVersionInfoResponse {
	pub circuit_id: u32,
	pub active_version: u32,
	pub supported_versions: Vec<u32>,
	pub vk_hashes: Vec<VkVersionHashResponse>,
}

fn to_response(info: CircuitVersionInfo) -> CircuitVersionInfoResponse {
	CircuitVersionInfoResponse {
		circuit_id: info.circuit_id,
		active_version: info.active_version,
		supported_versions: info.supported_versions,
		vk_hashes: info
			.vk_hashes
			.into_iter()
			.map(|item| VkVersionHashResponse {
				version: item.version,
				vk_hash: format!("0x{}", hex::encode(item.vk_hash)),
			})
			.collect(),
	}
}

#[rpc(client, server)]
pub trait ZkVerifierApi<BlockHash> {
	#[method(name = "zkVerifier_getCircuitVersionInfo")]
	fn get_circuit_version_info(
		&self,
		circuit_id: u32,
	) -> RpcResult<Option<CircuitVersionInfoResponse>>;

	#[method(name = "zkVerifier_getAllCircuitVersions")]
	fn get_all_circuit_versions(&self) -> RpcResult<Vec<CircuitVersionInfoResponse>>;
}

pub struct ZkVerifier<C, B> {
	client: Arc<C>,
	_marker: std::marker::PhantomData<B>,
}

impl<C, B> ZkVerifier<C, B> {
	pub fn new(client: Arc<C>) -> Self {
		Self {
			client,
			_marker: Default::default(),
		}
	}
}

impl<C, B> ZkVerifierApiServer<B::Hash> for ZkVerifier<C, B>
where
	B: BlockT,
	C: ProvideRuntimeApi<B> + HeaderBackend<B> + 'static,
	C::Api: ZkVerifierRuntimeApi<B>,
{
	fn get_circuit_version_info(
		&self,
		circuit_id: u32,
	) -> RpcResult<Option<CircuitVersionInfoResponse>> {
		let api = self.client.runtime_api();
		let best_block = self.client.info().best_hash;

		let info = api
			.get_circuit_version_info(best_block, circuit_id)
			.map_err(|e| ErrorObjectOwned::owned(1, format!("Runtime error: {e}"), None::<()>))?;

		Ok(info.map(to_response))
	}

	fn get_all_circuit_versions(&self) -> RpcResult<Vec<CircuitVersionInfoResponse>> {
		let api = self.client.runtime_api();
		let best_block = self.client.info().best_hash;

		let info = api
			.get_all_circuit_versions(best_block)
			.map_err(|e| ErrorObjectOwned::owned(1, format!("Runtime error: {e}"), None::<()>))?;

		Ok(info.into_iter().map(to_response).collect())
	}
}
