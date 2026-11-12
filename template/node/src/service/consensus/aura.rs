// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

//! Aura block authoring.

use std::sync::Arc;

use sc_network_sync::SyncingService;
use sc_service::{error::Error as ServiceError, KeystoreContainer};
use sp_consensus_aura::sr25519::AuthorityPair as AuraPair;

use super::inherents::AuraInherents;
use super::Authoring;
use orbinum_runtime::opaque::Block;

/// Share of the slot the proposer may spend building a block.
const BLOCK_PROPOSAL_SLOT_PORTION: f32 = 2.0 / 3.0;

/// Spawns Aura authoring as an essential task.
pub fn start(
	authoring: Authoring,
	sync_service: Arc<SyncingService<Block>>,
	keystore_container: &KeystoreContainer,
	force_authoring: bool,
) -> Result<(), ServiceError> {
	let proposer_factory = authoring.proposer_factory();
	let Authoring {
		task_manager,
		client,
		select_chain,
		block_import,
		telemetry,
		..
	} = authoring;
	let slot_duration = sc_consensus_aura::slot_duration(&*client)?;

	let aura = sc_consensus_aura::start_aura::<AuraPair, _, _, _, _, _, _, _, _, _, _>(
		sc_consensus_aura::StartAuraParams {
			slot_duration,
			client,
			select_chain,
			block_import,
			proposer_factory,
			sync_oracle: sync_service.clone(),
			justification_sync_link: sync_service,
			create_inherent_data_providers: AuraInherents::now(slot_duration),
			force_authoring,
			backoff_authoring_blocks: Option::<()>::None,
			keystore: keystore_container.keystore(),
			block_proposal_slot_portion: sc_consensus_aura::SlotProportion::new(
				BLOCK_PROPOSAL_SLOT_PORTION,
			),
			max_block_proposal_slot_portion: None,
			telemetry: telemetry.map(|x| x.handle()),
			compatibility_mode: sc_consensus_aura::CompatibilityMode::None,
		},
	)?;
	task_manager
		.spawn_essential_handle()
		.spawn_blocking("aura", Some("block-authoring"), aura);
	Ok(())
}
