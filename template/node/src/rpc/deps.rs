//! What the node's RPC methods are built from.

use std::sync::Arc;

use fc_rpc::EthBlockDataCacheTask;
use fc_rpc_core::types::{FeeHistoryCache, FeeHistoryCacheLimit, FilterPool};
use fc_storage::StorageOverride;
use futures::channel::mpsc;
use sc_consensus_grandpa::{
	FinalityProofProvider, GrandpaJustificationStream, SharedAuthoritySet, SharedVoterState,
};
use sc_consensus_manual_seal::rpc::EngineCommand;
use sc_network::service::traits::NetworkService;
use sc_network_sync::SyncingService;

pub use fc_rpc::LogsJournalConfig;

use crate::client::{Backend, Client, TransactionPool};
use orbinum_runtime::{opaque::Block, BlockNumber, Hash};

/// Everything the node's RPC methods are built from. `CIDP` creates the pending block's
/// inherent data providers.
pub struct FullDeps<CIDP> {
	pub client: Arc<Client>,
	pub pool: Arc<TransactionPool>,
	/// The ISMP RPC reads outgoing requests from the backend's offchain storage.
	pub backend: Arc<Backend>,
	/// Manual seal's command channel; `Some` adds the `engine_*` methods.
	pub command_sink: Option<mpsc::Sender<EngineCommand<Hash>>>,
	pub eth: EthDeps<CIDP>,
	pub grandpa: GrandpaDeps,
	/// Most blocks one `ismp_queryEvents*` call may span.
	pub ismp_max_event_blocks: u32,
}

/// GRANDPA finality RPC dependencies.
///
/// Hyperbridge's relayer builds Orbinum finality proofs through `grandpa_proveFinality`.
/// Everything here serves finality data for blocks already final: public, verifiable
/// against the authority set, no keys. None of the methods is `unsafe`, so they are served
/// under `--rpc-methods safe`.
#[derive(Clone)]
pub struct GrandpaDeps {
	/// The voter's own state: a detached one makes `grandpa_roundState` answer zeroed
	/// rounds instead of failing.
	pub shared_voter_state: SharedVoterState,
	/// Current authority set, for `grandpa_roundState`.
	pub shared_authority_set: SharedAuthoritySet<Hash, BlockNumber>,
	/// Justification notifications, for `grandpa_subscribeJustifications`.
	pub justification_stream: GrandpaJustificationStream<Block>,
	/// Serves `grandpa_proveFinality`.
	pub finality_provider: Arc<FinalityProofProvider<Backend, Block>>,
}

/// Ethereum-compatibility dependencies.
pub struct EthDeps<CIDP> {
	/// Whether this node is an authority.
	pub is_authority: bool,
	/// Sign `eth_sendTransaction` with the well-known development keys.
	pub enable_dev_signer: bool,
	pub network: Arc<dyn NetworkService>,
	pub sync: Arc<SyncingService<Block>>,
	/// Frontier's mapping database.
	pub frontier_backend: Arc<dyn fc_api::Backend<Block>>,
	/// Reads Ethereum data from runtime storage.
	pub storage_override: Arc<dyn StorageOverride<Block>>,
	/// Cache for Ethereum block data.
	pub block_data_cache: Arc<EthBlockDataCacheTask<Block>>,
	/// `eth_newFilter` filters; `None` disables the filter methods.
	pub filter_pool: Option<FilterPool>,
	/// Maximum number of logs in a query.
	pub max_past_logs: u32,
	/// Maximum block range for `eth_getLogs`.
	pub max_block_range: u32,
	/// Reorg journal limits for log filters and subscriptions.
	pub logs_journal_config: LogsJournalConfig,
	/// Fee history cache.
	pub fee_history_cache: FeeHistoryCache,
	/// Maximum fee history cache size, in blocks.
	pub fee_history_cache_limit: FeeHistoryCacheLimit,
	/// `eth_call` / `eth_estimateGas` may use up to `block.gas_limit` times this.
	pub execute_gas_limit_multiplier: u64,
	/// Allow RPC submission of unprotected legacy transactions.
	pub rpc_allow_unprotected_txs: bool,
	/// Inherent data providers for the pending block.
	pub pending_create_inherent_data_providers: CIDP,
}
