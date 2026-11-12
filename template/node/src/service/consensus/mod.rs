// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

//! Block authoring and finality: Aura + GRANDPA, or manual seal on development chains,
//! with their import queues (`import_queue`) and the inherents both sides provide
//! (`inherents`).

pub mod aura;
pub mod grandpa;
pub mod import_queue;
pub mod inherents;
pub mod manual_seal;

use std::sync::Arc;

use sc_basic_authorship::ProposerFactory;
use sc_consensus::BoxBlockImport;
use sc_service::TaskManager;
use sc_telemetry::Telemetry;

use crate::client::Client;
use crate::service::setup::types::{SelectChain, TransactionPool};
use orbinum_runtime::opaque::Block;

/// What block authoring needs, under Aura or manual seal.
pub struct Authoring<'a> {
	pub task_manager: &'a TaskManager,
	pub client: Arc<Client>,
	pub transaction_pool: Arc<TransactionPool>,
	pub select_chain: SelectChain,
	pub block_import: BoxBlockImport<Block>,
	pub prometheus_registry: Option<&'a prometheus_endpoint::Registry>,
	pub telemetry: Option<&'a Telemetry>,
}

impl Authoring<'_> {
	/// Builds blocks from the transaction pool.
	fn proposer_factory(&self) -> ProposerFactory<TransactionPool, Client> {
		ProposerFactory::new(
			self.task_manager.spawn_handle(),
			self.client.clone(),
			self.transaction_pool.clone(),
			self.prometheus_registry,
			self.telemetry.map(|x| x.handle()),
		)
	}
}
