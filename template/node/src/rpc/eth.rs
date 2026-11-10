//! Ethereum RPCs: `eth_*`, `net_*`, `web3_*`, `debug_*` and, with `txpool`, `txpool_*`.

use std::sync::Arc;

use fc_rpc::{
	pending::AuraConsensusDataProvider, Debug, DebugApiServer, Eth, EthApiServer, EthDevSigner,
	EthFilter, EthFilterApiServer, EthPubSub, EthPubSubApiServer, EthSigner, LogsJournal, Net,
	NetApiServer, Web3, Web3ApiServer,
};
#[cfg(feature = "txpool")]
use fc_rpc::{TxPool, TxPoolApiServer};
use jsonrpsee::RpcModule;
use sc_rpc::SubscriptionTaskExecutor;
use sp_inherents::CreateInherentDataProviders;

use super::{storage_override::EeSuffixStorageOverride, EthDeps, MergeResult};
use crate::{
	client::{Backend, Client, TransactionPool},
	frontier::PubSubNotificationSinks,
};
use orbinum_runtime::{opaque::Block, TransactionConverter};

/// Filters `eth_newFilter` keeps at once.
const MAX_STORED_FILTERS: usize = 500;

/// Frontier's RPC configuration for this runtime.
pub struct EthConfig;

impl fc_rpc::EthConfig<Block, Client> for EthConfig {
	type EstimateGasAdapter = ();
	// Frontier's stock overrides assume either AccountId20 or HashedAddressMapping;
	// this runtime is AccountId32 with EeSuffixAddressMapping.
	type RuntimeStorageOverride = EeSuffixStorageOverride<Block, Client, Backend>;
}

/// Merges the Ethereum RPCs into `io`.
pub fn merge<CIDP>(
	io: &mut RpcModule<()>,
	client: &Arc<Client>,
	pool: &Arc<TransactionPool>,
	deps: EthDeps<CIDP>,
	subscription_task_executor: SubscriptionTaskExecutor,
	pubsub_notification_sinks: Arc<PubSubNotificationSinks>,
) -> MergeResult
where
	CIDP: CreateInherentDataProviders<Block, ()> + Send + 'static,
{
	let EthDeps {
		is_authority,
		enable_dev_signer,
		network,
		sync,
		frontier_backend,
		storage_override,
		block_data_cache,
		filter_pool,
		max_past_logs,
		max_block_range,
		logs_journal_config,
		fee_history_cache,
		fee_history_cache_limit,
		execute_gas_limit_multiplier,
		rpc_allow_unprotected_txs,
		pending_create_inherent_data_providers,
	} = deps;

	let mut signers = Vec::new();
	if enable_dev_signer {
		signers.push(Box::new(EthDevSigner::new()) as Box<dyn EthSigner>);
	}

	let logs_journal = Arc::new(LogsJournal::with_config(
		subscription_task_executor.clone(),
		storage_override.clone(),
		pubsub_notification_sinks.clone(),
		logs_journal_config,
	));

	io.merge(
		Eth::<Block, Client, TransactionPool, TransactionConverter<Block>, Backend, CIDP, EthConfig>::new(
			client.clone(),
			pool.clone(),
			Some(TransactionConverter::<Block>::default()),
			sync.clone(),
			signers,
			storage_override.clone(),
			frontier_backend.clone(),
			is_authority,
			block_data_cache.clone(),
			fee_history_cache,
			fee_history_cache_limit,
			execute_gas_limit_multiplier,
			rpc_allow_unprotected_txs,
			None,
			pending_create_inherent_data_providers,
			Some(Box::new(AuraConsensusDataProvider::new(client.clone()))),
		)
		.replace_config::<EthConfig>()
		.into_rpc(),
	)?;

	if let Some(filter_pool) = filter_pool {
		io.merge(
			EthFilter::new(
				client.clone(),
				frontier_backend.clone(),
				pool.clone(),
				filter_pool,
				MAX_STORED_FILTERS,
				max_past_logs,
				max_block_range,
				block_data_cache.clone(),
				logs_journal.clone(),
			)
			.into_rpc(),
		)?;
	}

	io.merge(
		EthPubSub::new(
			pool.clone(),
			client.clone(),
			sync,
			subscription_task_executor,
			storage_override.clone(),
			pubsub_notification_sinks,
			logs_journal,
		)
		.into_rpc(),
	)?;

	// `true`: `net_peerCount` answers in hex.
	io.merge(Net::new(client.clone(), network, true).into_rpc())?;
	io.merge(Web3::new(client.clone()).into_rpc())?;
	io.merge(
		Debug::new(
			client.clone(),
			frontier_backend,
			storage_override,
			block_data_cache,
		)
		.into_rpc(),
	)?;

	#[cfg(feature = "txpool")]
	io.merge(TxPool::new(client.clone(), pool.clone()).into_rpc())?;

	Ok(())
}
