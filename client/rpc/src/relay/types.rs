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
	/// including the 4-byte selector. Its fee must reach the effective minimum:
	/// the governance fee or twice the relay's gas cost, whichever is higher.
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
	/// True when the relay can relay: registered (on a runtime with relay
	/// commits) and funded for the worst case of a commit plus a spend.
	pub enabled: bool,
	/// True when this relay's EVM address is registered on-chain via `register_relayer`.
	/// Relaying needs it: only a registered address can record the relay commit
	/// that earns a spend's fee.
	pub is_registered: bool,
}
