//! Manual and instant seal. Development chains only.

use futures::{channel::mpsc, future};
use sc_consensus_manual_seal::{rpc::EngineCommand, InstantSealParams, ManualSealParams};

use super::inherents::ManualSealInherents;
use super::Authoring;
use crate::cli::Sealing;
use orbinum_runtime::Hash;

/// Spawns the sealing task: on `engine_createBlock` ([`Sealing::Manual`]) or on every
/// transaction ([`Sealing::Instant`]).
pub fn start(
	authoring: Authoring,
	sealing: Sealing,
	commands_stream: mpsc::Receiver<EngineCommand<Hash>>,
) {
	let env = authoring.proposer_factory();
	let Authoring {
		task_manager,
		client,
		transaction_pool: pool,
		select_chain,
		block_import,
		..
	} = authoring;
	let create_inherent_data_providers = ManualSealInherents;

	let manual_seal = match sealing {
		Sealing::Manual => future::Either::Left(sc_consensus_manual_seal::run_manual_seal(
			ManualSealParams {
				block_import,
				env,
				client,
				pool,
				commands_stream,
				select_chain,
				consensus_data_provider: None,
				create_inherent_data_providers,
			},
		)),
		Sealing::Instant => future::Either::Right(sc_consensus_manual_seal::run_instant_seal(
			InstantSealParams {
				block_import,
				env,
				client,
				pool,
				select_chain,
				consensus_data_provider: None,
				create_inherent_data_providers,
			},
		)),
	};

	task_manager
		.spawn_essential_handle()
		.spawn_blocking("manual-seal", None, manual_seal);
	log::info!("Manual Seal Ready");
}
