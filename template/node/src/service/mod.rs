//! Node assembly: `new_full` puts the parts together.
//!
//! - `setup`: the service's types, and the client, databases, import queue and
//!   transaction pool every command shares (`new_partial`).
//! - `consensus`: Aura authoring and the GRANDPA voter, or manual seal; the import
//!   queues and the inherents blocks carry.
//! - `components`: what a full node runs besides consensus: network, offchain workers,
//!   RPC and the hardware benchmark.

mod components;
mod consensus;
mod setup;
#[cfg(test)]
mod tests;

use futures::channel::mpsc;
use sc_consensus_grandpa::SharedVoterState;
use sc_service::{error::Error as ServiceError, Configuration, TaskManager};

pub use self::setup::{new_partial, Partial};
use self::{
	components::{
		hwbench, network, offchain,
		rpc::{self, RpcParams},
	},
	consensus::grandpa,
};
use crate::{
	author_version,
	cli::Sealing,
	frontier::{self, EthConfiguration, FrontierParts},
};

/// Queued `engine_*` commands before the RPC waits for manual seal.
const ENGINE_COMMAND_BUFFER: usize = 1000;

/// Builds and starts a full node.
pub async fn new_full(
	mut config: Configuration,
	eth_config: EthConfiguration,
	sealing: Option<Sealing>,
	hardware_benchmarks: bool,
	ismp_max_event_blocks: u32,
) -> Result<TaskManager, ServiceError> {
	let Partial {
		client,
		backend,
		mut task_manager,
		import_queue,
		keystore_container,
		select_chain,
		transaction_pool,
		mut telemetry,
		block_import,
		grandpa_link,
		frontier_backend,
		storage_override,
	} = new_partial(&config, &eth_config, sealing.is_some())?;
	if config.role.is_authority() {
		author_version::warn_if_below_minimum(&client);
	}
	let hwbench = hwbench::gather(&config, hardware_benchmarks);

	let net = network::build(
		&config,
		&client,
		&backend,
		&transaction_pool,
		import_queue,
		&grandpa_link,
		&task_manager,
		sealing.is_some(),
	)?;
	offchain::spawn(
		&config,
		&task_manager,
		&client,
		&backend,
		&keystore_container,
		&transaction_pool,
		&net.network,
	)?;

	// `spawn_tasks` consumes `config`: read what is needed later first.
	let role = config.role;
	let force_authoring = config.force_authoring;
	let node_name = config.network.node_name.clone();
	let enable_grandpa = !config.disable_grandpa && sealing.is_none();
	let prometheus_registry = config.prometheus_registry().cloned();
	let state_pruning_blocks = frontier::tasks::state_pruning_blocks(&config);
	config.rpc.id_provider = Some(Box::new(fc_rpc::EthereumSubIdProvider));

	let frontier = FrontierParts::new(&eth_config, frontier_backend, storage_override);
	let (command_sink, commands_stream) = mpsc::channel(ENGINE_COMMAND_BUFFER);
	// Shared by the voter and the RPC.
	let shared_voter_state = SharedVoterState::empty();
	let rpc_builder = rpc::builder(
		RpcParams {
			client: client.clone(),
			backend: backend.clone(),
			transaction_pool: transaction_pool.clone(),
			network: net.network.clone(),
			sync_service: net.sync_service.clone(),
			frontier: frontier.clone(),
			grandpa: grandpa::rpc_deps(&grandpa_link, &backend, shared_voter_state.clone()),
			command_sink: sealing.map(|_| command_sink),
			is_authority: role.is_authority(),
			ismp_max_event_blocks,
		},
		&eth_config,
		&task_manager,
		prometheus_registry.clone(),
	)?;

	sc_service::spawn_tasks(sc_service::SpawnTasksParams {
		config,
		client: client.clone(),
		backend: backend.clone(),
		task_manager: &mut task_manager,
		keystore: keystore_container.keystore(),
		transaction_pool: transaction_pool.clone(),
		rpc_builder,
		network: net.network.clone(),
		system_rpc_tx: net.system_rpc_tx,
		tx_handler_controller: net.tx_handler_controller,
		sync_service: net.sync_service.clone(),
		telemetry: telemetry.as_mut(),
		tracing_execute_block: None,
	})?;
	frontier::tasks::spawn(
		&task_manager,
		client.clone(),
		backend,
		frontier,
		state_pruning_blocks,
		net.sync_service.clone(),
	);
	if let Some(hwbench) = hwbench {
		hwbench::report(hwbench, &role, telemetry.as_ref(), &task_manager);
	}

	if role.is_authority() {
		let authoring = consensus::Authoring {
			task_manager: &task_manager,
			client,
			transaction_pool: transaction_pool.clone(),
			select_chain,
			block_import,
			prometheus_registry: prometheus_registry.as_ref(),
			telemetry: telemetry.as_ref(),
		};
		match sealing {
			Some(sealing) => consensus::manual_seal::start(authoring, sealing, commands_stream),
			None => consensus::aura::start(
				authoring,
				net.sync_service.clone(),
				&keystore_container,
				force_authoring,
			)?,
		}
	}

	if enable_grandpa {
		grandpa::start(grandpa::VoterParams {
			task_manager: &task_manager,
			grandpa_link,
			shared_voter_state,
			network: net.network,
			sync_service: net.sync_service,
			protocol_name: net.grandpa_protocol_name,
			notification_service: net.grandpa_notification_service,
			transaction_pool,
			keystore_container: &keystore_container,
			role,
			node_name,
			prometheus_registry,
			telemetry: telemetry.as_ref(),
		})?;
	}

	Ok(task_manager)
}
