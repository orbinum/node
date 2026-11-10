//! The RPC builder `spawn_tasks` calls for each RPC server.

use std::sync::Arc;

use futures::channel::mpsc;
use jsonrpsee::RpcModule;
use sc_consensus_manual_seal::rpc::EngineCommand;
use sc_network::service::traits::NetworkService;
use sc_network_sync::SyncingService;
use sc_rpc::SubscriptionTaskExecutor;
use sc_service::{error::Error as ServiceError, TaskManager};

use crate::service::{consensus::inherents::AuraInherents, setup::types::TransactionPool};
use crate::{
	client::{Backend, Client},
	frontier::{EthConfiguration, FrontierParts},
	rpc::{EthDeps, FullDeps, GrandpaDeps, LogsJournalConfig},
};
use orbinum_runtime::{opaque::Block, Hash};

/// Builds the node's RPC module; [`sc_service::spawn_tasks`] merges it with Substrate's.
pub type RpcBuilder = Box<dyn Fn(SubscriptionTaskExecutor) -> Result<RpcModule<()>, ServiceError>>;

/// What the RPC methods are served from.
pub struct RpcParams {
	pub client: Arc<Client>,
	pub backend: Arc<Backend>,
	pub transaction_pool: Arc<TransactionPool>,
	pub network: Arc<dyn NetworkService>,
	pub sync_service: Arc<SyncingService<Block>>,
	pub frontier: FrontierParts,
	pub grandpa: GrandpaDeps,
	/// Manual seal's command channel; `Some` adds the `engine_*` methods.
	pub command_sink: Option<mpsc::Sender<EngineCommand<Hash>>>,
	pub is_authority: bool,
	/// Most blocks one `ismp_queryEvents*` call may span.
	pub ismp_max_event_blocks: u32,
}

/// Builds the RPC builder. Every server gets its own module from the same state.
pub fn builder(
	params: RpcParams,
	eth_config: &EthConfiguration,
	task_manager: &TaskManager,
	prometheus_registry: Option<prometheus_endpoint::Registry>,
) -> Result<RpcBuilder, ServiceError> {
	let RpcParams {
		client,
		backend,
		transaction_pool,
		network,
		sync_service,
		frontier,
		grandpa,
		command_sink,
		is_authority,
		ismp_max_event_blocks,
	} = params;

	let block_data_cache = Arc::new(fc_rpc::EthBlockDataCacheTask::new(
		task_manager.spawn_handle(),
		frontier.storage_override.clone(),
		eth_config.eth_log_block_cache,
		eth_config.eth_statuses_cache,
		prometheus_registry,
	));
	let pending_inherents = AuraInherents::next_slot(sc_consensus_aura::slot_duration(&*client)?);
	let eth_config = eth_config.clone();

	Ok(Box::new(move |subscription_task_executor| {
		let eth = EthDeps {
			is_authority,
			enable_dev_signer: eth_config.enable_dev_signer,
			network: network.clone(),
			sync: sync_service.clone(),
			frontier_backend: match &*frontier.backend {
				fc_db::Backend::KeyValue(b) => b.clone(),
				fc_db::Backend::Sql(b) => b.clone(),
			},
			storage_override: frontier.storage_override.clone(),
			block_data_cache: block_data_cache.clone(),
			filter_pool: frontier.filter_pool.clone(),
			max_past_logs: eth_config.max_past_logs,
			max_block_range: eth_config.max_block_range,
			logs_journal_config: LogsJournalConfig::from_max_total_bytes(
				eth_config.logs_journal_max_total_bytes,
			),
			fee_history_cache: frontier.fee_history_cache.clone(),
			fee_history_cache_limit: frontier.fee_history_cache_limit,
			execute_gas_limit_multiplier: eth_config.execute_gas_limit_multiplier,
			rpc_allow_unprotected_txs: eth_config.rpc_allow_unprotected_txs,
			pending_create_inherent_data_providers: pending_inherents,
		};
		let deps = FullDeps {
			client: client.clone(),
			pool: transaction_pool.clone(),
			backend: backend.clone(),
			command_sink: command_sink.clone(),
			eth,
			grandpa: grandpa.clone(),
			ismp_max_event_blocks,
		};
		crate::rpc::create_full(
			deps,
			subscription_task_executor,
			frontier.pubsub_notification_sinks.clone(),
		)
		.map_err(Into::into)
	}))
}
