// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

//! The network, with GRANDPA's protocol and warp sync unless manual seal is on.

use std::sync::Arc;

use sc_client_api::HeaderBackend;
use sc_consensus::BasicQueue;
use sc_network::{
	config::FullNetworkConfiguration, service::traits::NetworkService, NetworkBackend,
	NotificationService, ProtocolName,
};
use sc_network_sync::{
	strategy::warp::{WarpSyncConfig, WarpSyncProvider},
	SyncingService,
};
use sc_network_transactions::TransactionsHandlerController;
use sc_service::{error::Error as ServiceError, Configuration, TaskManager};
use sc_utils::mpsc::TracingUnboundedSender;

use crate::client::{Backend, Client};
use crate::service::setup::types::{GrandpaLinkHalf, Network, TransactionPool};
use orbinum_runtime::{opaque::Block, Hash};

/// What [`build`] starts.
pub struct NetworkParts {
	pub network: Arc<dyn NetworkService>,
	pub system_rpc_tx: TracingUnboundedSender<sc_rpc::system::Request<Block>>,
	pub tx_handler_controller: TransactionsHandlerController<Hash>,
	pub sync_service: Arc<SyncingService<Block>>,
	/// GRANDPA's gossip protocol, for the voter.
	pub grandpa_protocol_name: ProtocolName,
	pub grandpa_notification_service: Box<dyn NotificationService>,
}

/// Builds and spawns the network. With `manual_seal` neither GRANDPA's protocol nor warp
/// sync is registered: there is no finality to gossip or to sync from.
pub fn build(
	config: &Configuration,
	client: &Arc<Client>,
	backend: &Arc<Backend>,
	transaction_pool: &Arc<TransactionPool>,
	import_queue: BasicQueue<Block>,
	grandpa_link: &GrandpaLinkHalf,
	task_manager: &TaskManager,
	manual_seal: bool,
) -> Result<NetworkParts, ServiceError> {
	let registry = config.prometheus_config.as_ref().map(|cfg| &cfg.registry);
	let mut net_config =
		FullNetworkConfiguration::<_, _, Network>::new(&config.network, registry.cloned());
	let peer_store_handle = net_config.peer_store_handle();
	let metrics = Network::register_notification_metrics(registry);

	let grandpa_protocol_name = sc_consensus_grandpa::protocol_standard_name(
		&client.info().genesis_hash,
		&config.chain_spec,
	);
	let (grandpa_protocol_config, grandpa_notification_service) =
		sc_consensus_grandpa::grandpa_peers_set_config::<_, Network>(
			grandpa_protocol_name.clone(),
			metrics.clone(),
			peer_store_handle,
		);

	let warp_sync_config = if manual_seal {
		None
	} else {
		net_config.add_notification_protocol(grandpa_protocol_config);
		let warp_sync: Arc<dyn WarpSyncProvider<Block>> =
			Arc::new(sc_consensus_grandpa::warp_proof::NetworkProvider::new(
				backend.clone(),
				grandpa_link.shared_authority_set().clone(),
				Vec::new(),
			));
		Some(WarpSyncConfig::WithProvider(warp_sync))
	};

	let (network, system_rpc_tx, tx_handler_controller, sync_service) =
		sc_service::build_network(sc_service::BuildNetworkParams {
			config,
			spawn_essential_handle: task_manager.spawn_essential_handle(),
			net_config,
			client: client.clone(),
			transaction_pool: transaction_pool.clone(),
			spawn_handle: task_manager.spawn_handle(),
			import_queue,
			block_announce_validator_builder: None,
			warp_sync_config,
			block_relay: None,
			metrics,
		})?;

	Ok(NetworkParts {
		network,
		system_rpc_tx,
		tx_handler_controller,
		sync_service,
		grandpa_protocol_name,
		grandpa_notification_service,
	})
}
