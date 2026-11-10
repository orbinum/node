//! Frontier's background tasks: the mapping-sync worker and cache maintenance.

use std::{sync::Arc, time::Duration};

use futures::{future, StreamExt};
use sc_client_api::BlockchainEvents;
use sc_network_sync::SyncingService;
use sc_service::{Configuration, PruningMode, TaskManager};

use super::FrontierParts;
use crate::client::{Backend, Client};
use fc_rpc::EthTask;
use orbinum_runtime::opaque::Block;

/// How long the KV mapping-sync worker waits for an import before polling anyway.
const KV_SYNC_TIMEOUT: Duration = Duration::from_secs(6);
/// Attempts the KV mapping-sync worker makes on a block before it moves on.
const KV_SYNC_RETRY_TIMES: usize = 3;
/// How long the SQL worker waits for an import notification.
const SQL_READ_NOTIFICATION_TIMEOUT: Duration = Duration::from_secs(30);
/// How often the SQL worker checks for blocks it has not indexed.
const SQL_CHECK_INDEXED_BLOCKS_INTERVAL: Duration = Duration::from_secs(60);
/// Blocks an `eth_newFilter` filter stays in the pool without being polled.
const FILTER_RETAIN_THRESHOLD: u64 = 100;

/// Blocks the state is kept for under `--state-pruning`, so the KV mapping-sync worker
/// skips past pruned blocks while catching up.
pub fn state_pruning_blocks(config: &Configuration) -> Option<u64> {
	match &config.state_pruning {
		Some(PruningMode::Constrained(c)) => c.max_blocks.map(u64::from),
		_ => None,
	}
}

/// Spawns the mapping-sync worker for the configured backend, the filter pool and the
/// fee history maintenance tasks.
pub fn spawn(
	task_manager: &TaskManager,
	client: Arc<Client>,
	backend: Arc<Backend>,
	frontier: FrontierParts,
	state_pruning_blocks: Option<u64>,
	sync: Arc<SyncingService<Block>>,
) {
	let spawner = task_manager.spawn_essential_handle();
	match &*frontier.backend {
		fc_db::Backend::KeyValue(b) => spawner.spawn(
			"frontier-mapping-sync-worker",
			Some("frontier"),
			fc_mapping_sync::kv::MappingSyncWorker::new(
				client.import_notification_stream(),
				KV_SYNC_TIMEOUT,
				client.clone(),
				backend,
				frontier.storage_override.clone(),
				b.clone(),
				KV_SYNC_RETRY_TIMES,
				0u32,
				state_pruning_blocks,
				fc_mapping_sync::SyncStrategy::Normal,
				sync,
				frontier.pubsub_notification_sinks,
			)
			.for_each(|()| future::ready(())),
		),
		fc_db::Backend::Sql(b) => spawner.spawn_blocking(
			"frontier-mapping-sync-worker",
			Some("frontier"),
			fc_mapping_sync::sql::SyncWorker::run(
				client.clone(),
				backend,
				b.clone(),
				client.import_notification_stream(),
				fc_mapping_sync::sql::SyncWorkerConfig {
					read_notification_timeout: SQL_READ_NOTIFICATION_TIMEOUT,
					check_indexed_blocks_interval: SQL_CHECK_INDEXED_BLOCKS_INTERVAL,
				},
				// Unused by the SQL worker.
				fc_mapping_sync::SyncStrategy::Normal,
				sync,
				frontier.pubsub_notification_sinks,
			),
		),
	}

	if let Some(filter_pool) = frontier.filter_pool {
		spawner.spawn(
			"frontier-filter-pool",
			Some("frontier"),
			EthTask::filter_pool_task(client.clone(), filter_pool, FILTER_RETAIN_THRESHOLD),
		);
	}

	spawner.spawn(
		"frontier-fee-history",
		Some("frontier"),
		EthTask::fee_history_task(
			client,
			frontier.storage_override,
			frontier.fee_history_cache,
			frontier.fee_history_cache_limit,
		),
	);
}
