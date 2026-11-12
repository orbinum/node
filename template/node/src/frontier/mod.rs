// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

//! Ethereum compatibility (Frontier).
//!
//! - `config`: the command-line settings.
//! - `backend`: the mapping database, opened or purged.
//! - `tasks`: the mapping-sync worker and the cache maintenance tasks.

pub mod backend;
mod config;
pub mod tasks;

use std::{
	collections::BTreeMap,
	sync::{Arc, Mutex},
};

pub use fc_rpc_core::types::{FeeHistoryCache, FilterPool};
use fc_storage::StorageOverride;

pub use self::config::{BackendType, EthConfiguration};
use crate::client::Client;
use orbinum_runtime::opaque::Block;

/// Frontier's mapping database.
pub type FrontierBackend = fc_db::Backend<Block, Client>;

/// Subscribers to the Ethereum blocks the mapping-sync worker indexes.
pub type PubSubNotificationSinks = fc_mapping_sync::EthereumBlockNotificationSinks<
	fc_mapping_sync::EthereumBlockNotification<Block>,
>;

/// Frontier state shared by the RPC and the background tasks.
#[derive(Clone)]
pub struct FrontierParts {
	/// The mapping database.
	pub backend: Arc<FrontierBackend>,
	/// Reads Ethereum data from runtime storage.
	pub storage_override: Arc<dyn StorageOverride<Block>>,
	/// `eth_newFilter` filters.
	pub filter_pool: Option<FilterPool>,
	/// `eth_feeHistory` cache.
	pub fee_history_cache: FeeHistoryCache,
	/// Blocks kept in the fee history cache.
	pub fee_history_cache_limit: u64,
	/// Subscriptions fed on import by the mapping-sync worker rather than by the client's
	/// import stream, so a subscriber never sees a block before it is indexed.
	pub pubsub_notification_sinks: Arc<PubSubNotificationSinks>,
}

impl FrontierParts {
	/// Sets up the caches and sinks around an opened `backend`.
	pub fn new(
		eth_config: &EthConfiguration,
		backend: FrontierBackend,
		storage_override: Arc<dyn StorageOverride<Block>>,
	) -> Self {
		fc_mapping_sync::set_max_pending_notifications_per_subscriber(
			eth_config.pubsub_max_pending_notifications,
		);
		Self {
			backend: Arc::new(backend),
			storage_override,
			filter_pool: Some(Arc::new(Mutex::new(BTreeMap::new()))),
			fee_history_cache: Arc::new(Mutex::new(BTreeMap::new())),
			fee_history_cache_limit: eth_config.fee_history_limit,
			pubsub_notification_sinks: Default::default(),
		}
	}
}
