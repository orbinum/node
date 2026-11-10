//! Import queues: Aura + GRANDPA, or manual seal.

use std::sync::Arc;

use fc_consensus::FrontierBlockImport;
use sc_consensus::{BasicQueue, BoxBlockImport};
use sc_service::{error::Error as ServiceError, Configuration, TaskManager};
use sc_telemetry::TelemetryHandle;
use sp_consensus_aura::sr25519::AuthorityPair as AuraPair;

use super::inherents::AuraInherents;
use crate::client::Client;
use crate::service::setup::types::GrandpaBlockImport;
use orbinum_runtime::opaque::Block;

/// The queue and the block import authoring hands its blocks to.
pub type ImportQueue = (BasicQueue<Block>, BoxBlockImport<Block>);

/// Aura checks each block's author and slot; GRANDPA imports justifications.
pub fn aura_grandpa(
	client: Arc<Client>,
	config: &Configuration,
	task_manager: &TaskManager,
	telemetry: Option<TelemetryHandle>,
	grandpa_block_import: GrandpaBlockImport,
) -> Result<ImportQueue, ServiceError> {
	let frontier_block_import =
		FrontierBlockImport::new(grandpa_block_import.clone(), client.clone());
	let slot_duration = sc_consensus_aura::slot_duration(&*client)?;

	let import_queue = sc_consensus_aura::import_queue::<AuraPair, _, _, _, _, _>(
		sc_consensus_aura::ImportQueueParams {
			block_import: frontier_block_import.clone(),
			justification_import: Some(Box::new(grandpa_block_import)),
			client,
			create_inherent_data_providers: AuraInherents::now(slot_duration),
			spawner: &task_manager.spawn_essential_handle(),
			registry: config.prometheus_registry(),
			check_for_equivocation: Default::default(),
			telemetry,
			compatibility_mode: sc_consensus_aura::CompatibilityMode::None,
		},
	)?;

	Ok((import_queue, Box::new(frontier_block_import)))
}

/// Manual seal: imports without checking the author. Development chains only.
pub fn manual_seal(
	client: Arc<Client>,
	config: &Configuration,
	task_manager: &TaskManager,
) -> ImportQueue {
	let frontier_block_import = FrontierBlockImport::new(client.clone(), client);
	(
		sc_consensus_manual_seal::import_queue(
			Box::new(frontier_block_import.clone()),
			&task_manager.spawn_essential_handle(),
			config.prometheus_registry(),
		),
		Box::new(frontier_block_import),
	)
}
