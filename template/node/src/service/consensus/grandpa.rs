// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

//! GRANDPA: the voter and what its RPC reads.

use std::{sync::Arc, time::Duration};

use sc_consensus_grandpa::{FinalityProofProvider, SharedVoterState};
use sc_network::{service::traits::NetworkService, NotificationService, ProtocolName};
use sc_network_sync::SyncingService;
use sc_service::{error::Error as ServiceError, KeystoreContainer, Role, TaskManager};
use sc_telemetry::Telemetry;
use sc_transaction_pool_api::OffchainTransactionPoolFactory;

use crate::{
	client::Backend,
	rpc::GrandpaDeps,
	service::setup::types::{GrandpaLinkHalf, TransactionPool, GRANDPA_JUSTIFICATION_PERIOD},
};
use orbinum_runtime::opaque::Block;

/// How often the voter gossips.
const GOSSIP_DURATION: Duration = Duration::from_millis(333);

/// What the GRANDPA RPC serves. `shared_voter_state` must be the voter's own: a detached
/// one makes `grandpa_roundState` answer zeroed rounds instead of failing.
pub fn rpc_deps(
	grandpa_link: &GrandpaLinkHalf,
	backend: &Arc<Backend>,
	shared_voter_state: SharedVoterState,
) -> GrandpaDeps {
	let shared_authority_set = grandpa_link.shared_authority_set().clone();
	GrandpaDeps {
		shared_voter_state,
		finality_provider: FinalityProofProvider::new_for_service(
			backend.clone(),
			Some(shared_authority_set.clone()),
		),
		shared_authority_set,
		justification_stream: grandpa_link.justification_stream(),
	}
}

/// Everything [`start`] needs.
pub struct VoterParams<'a> {
	pub task_manager: &'a TaskManager,
	pub grandpa_link: GrandpaLinkHalf,
	pub shared_voter_state: SharedVoterState,
	pub network: Arc<dyn NetworkService>,
	pub sync_service: Arc<SyncingService<Block>>,
	pub protocol_name: ProtocolName,
	pub notification_service: Box<dyn NotificationService>,
	pub transaction_pool: Arc<TransactionPool>,
	pub keystore_container: &'a KeystoreContainer,
	pub role: Role,
	pub node_name: String,
	pub prometheus_registry: Option<prometheus_endpoint::Registry>,
	pub telemetry: Option<&'a Telemetry>,
}

/// Spawns the full GRANDPA voter as an essential task. Non-authorities run it too, without
/// a keystore: the observer protocol is less tested and could stall finality if most nodes
/// ran it.
pub fn start(params: VoterParams) -> Result<(), ServiceError> {
	let VoterParams {
		task_manager,
		grandpa_link,
		shared_voter_state,
		network,
		sync_service,
		protocol_name,
		notification_service,
		transaction_pool,
		keystore_container,
		role,
		node_name,
		prometheus_registry,
		telemetry,
	} = params;

	let config = sc_consensus_grandpa::Config {
		gossip_duration: GOSSIP_DURATION,
		justification_generation_period: GRANDPA_JUSTIFICATION_PERIOD,
		name: Some(node_name),
		observer_enabled: false,
		keystore: role.is_authority().then(|| keystore_container.keystore()),
		local_role: role,
		telemetry: telemetry.map(|x| x.handle()),
		protocol_name,
	};

	let voter = sc_consensus_grandpa::run_grandpa_voter(sc_consensus_grandpa::GrandpaParams {
		config,
		link: grandpa_link,
		network,
		sync: sync_service,
		notification_service,
		voting_rule: sc_consensus_grandpa::VotingRulesBuilder::default().build(),
		prometheus_registry,
		shared_voter_state,
		telemetry: telemetry.map(|x| x.handle()),
		offchain_tx_pool_factory: OffchainTransactionPoolFactory::new(transaction_pool),
	})?;
	task_manager
		.spawn_essential_handle()
		.spawn_blocking("grandpa-voter", None, voter);
	Ok(())
}
