// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

//! RPC trait definition and response types for the Orbinum relay.

use ethereum_types::{H160, H256};
use fc_rpc_core::types::Bytes;
use jsonrpsee::{core::RpcResult, proc_macros::rpc};
use serde::{Deserialize, Serialize};

#[rpc(server)]
pub trait OrbinumRelayApi {
	/// Relay a shielded-pool call (unshield or privateTransfer) on behalf of a user.
	///
	/// `calldata` must be ABI-encoded EVM calldata for the ShieldedPool precompile,
	/// including the 4-byte selector. The fee in ABI slot index 6 must be ≥ MIN_RELAY_FEE_WEI.
	///
	/// Returns the Ethereum transaction hash.
	#[method(name = "orbinum_relayShieldedCall")]
	async fn relay_shielded_call(&self, calldata: Bytes) -> RpcResult<H256>;

	/// Returns the relay status: EVM address, minimum fee, current balance, and whether
	/// the relay has sufficient funds to process at least one transaction.
	#[method(name = "orbinum_relayerStatus")]
	async fn relayer_status(&self) -> RpcResult<RelayerStatus>;
}

/// Relay status returned by `orbinum_relayerStatus`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayerStatus {
	pub address: H160,
	pub min_fee: String,
	/// Current EVM balance of the relay wallet (wei). Lets callers verify the relay is funded.
	pub balance_wei: String,
	/// True only when balance ≥ effective min fee (enough to cover at least one relay tx).
	pub enabled: bool,
	/// True when this relay's EVM address is registered on-chain via `register_relayer`.
	/// Unregistered relays still forward transactions but fees are attributed to the block author
	/// instead of the intended validator. Capa 2 of the relay architecture.
	pub is_registered: bool,
}
