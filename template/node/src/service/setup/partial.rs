// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

//! The parts of the node every command shares: client, databases, import queue and
//! transaction pool.

use std::sync::Arc;

use fc_storage::{StorageOverride, StorageOverrideHandler};
use sc_consensus::{BasicQueue, BoxBlockImport};
use sc_service::{error::Error as ServiceError, Configuration, KeystoreContainer, TaskManager};
use sc_telemetry::{Telemetry, TelemetryWorker};

use super::types::{GrandpaLinkHalf, SelectChain, TransactionPool, GRANDPA_JUSTIFICATION_PERIOD};
use crate::service::consensus::import_queue;
use crate::{
	client::{Backend, Client},
	frontier::{self, EthConfiguration, FrontierBackend},
};
use orbinum_runtime::opaque::Block;

/// Telemetry worker queue size.
const TELEMETRY_BUFFER: usize = 16;

/// What [`new_partial`] builds.
pub struct Partial {
	pub client: Arc<Client>,
	pub backend: Arc<Backend>,
	pub keystore_container: KeystoreContainer,
	pub task_manager: TaskManager,
	pub select_chain: SelectChain,
	pub import_queue: BasicQueue<Block>,
	pub transaction_pool: Arc<TransactionPool>,
	pub telemetry: Option<Telemetry>,
	/// The block import authoring hands its blocks to.
	pub block_import: BoxBlockImport<Block>,
	pub grandpa_link: GrandpaLinkHalf,
	pub frontier_backend: FrontierBackend,
	pub storage_override: Arc<dyn StorageOverride<Block>>,
}

/// Builds the client and everything around it short of the network. `manual_seal` picks
/// the manual-seal import queue over Aura + GRANDPA's.
pub fn new_partial(
	config: &Configuration,
	eth_config: &EthConfiguration,
	manual_seal: bool,
) -> Result<Partial, ServiceError> {
	let telemetry = config
		.telemetry_endpoints
		.clone()
		.filter(|x| !x.is_empty())
		.map(|endpoints| -> Result<_, sc_telemetry::Error> {
			let worker = TelemetryWorker::new(TELEMETRY_BUFFER)?;
			let telemetry = worker.handle().new_telemetry(endpoints);
			Ok((worker, telemetry))
		})
		.transpose()?;

	let executor = sc_service::new_wasm_executor(&config.executor);

	// Import must not record proofs: the proposer does not, and the EVM meters PoV gas
	// with `get_proof_size()`, so recording only on import makes importers compute a
	// different gas (and Ethereum block hash) than the author and reject the block.
	let (client, backend, keystore_container, task_manager) =
		sc_service::new_full_parts_record_import::<Block, orbinum_runtime::RuntimeApi, _>(
			config,
			telemetry.as_ref().map(|(_, telemetry)| telemetry.handle()),
			executor,
			false,
			Vec::new(),
		)?;
	let client = Arc::new(client);

	let telemetry = telemetry.map(|(worker, telemetry)| {
		task_manager
			.spawn_handle()
			.spawn("telemetry", None, worker.run());
		telemetry
	});

	let select_chain = sc_consensus::LongestChain::new(backend.clone());
	let (grandpa_block_import, grandpa_link) = sc_consensus_grandpa::block_import(
		client.clone(),
		GRANDPA_JUSTIFICATION_PERIOD,
		&client,
		select_chain.clone(),
		telemetry.as_ref().map(|x| x.handle()),
	)?;

	let storage_override: Arc<dyn StorageOverride<Block>> =
		Arc::new(StorageOverrideHandler::<Block, _, _>::new(client.clone()));
	let frontier_backend =
		frontier::backend::open(config, eth_config, client.clone(), storage_override.clone())?;

	let (import_queue, block_import) = if manual_seal {
		import_queue::manual_seal(client.clone(), config, &task_manager)
	} else {
		import_queue::aura_grandpa(
			client.clone(),
			config,
			&task_manager,
			telemetry.as_ref().map(|x| x.handle()),
			grandpa_block_import,
		)?
	};

	let transaction_pool = Arc::from(
		sc_transaction_pool::Builder::new(
			task_manager.spawn_essential_handle(),
			client.clone(),
			config.role.is_authority().into(),
		)
		.with_options(config.transaction_pool.clone())
		.with_prometheus(config.prometheus_registry())
		.build(),
	);

	Ok(Partial {
		client,
		backend,
		keystore_container,
		task_manager,
		select_chain,
		import_queue,
		transaction_pool,
		telemetry,
		block_import,
		grandpa_link,
		frontier_backend,
		storage_override,
	})
}
