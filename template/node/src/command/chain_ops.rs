// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

//! What the chain subcommands (check, import, export, revert, benchmark, frontier-db) run
//! on: the node's partial components with an in-memory keystore.

use std::sync::Arc;

use sc_consensus::BasicQueue;
use sc_service::{error::Error as ServiceError, Configuration, TaskManager};

use crate::{
	client::{Backend, Client},
	frontier::{EthConfiguration, FrontierBackend},
	service::{new_partial, Partial},
};
use orbinum_runtime::opaque::Block;

pub struct ChainOps {
	pub client: Arc<Client>,
	pub backend: Arc<Backend>,
	pub import_queue: BasicQueue<Block>,
	pub task_manager: TaskManager,
	pub frontier_backend: FrontierBackend,
}

impl ChainOps {
	/// Builds the components with the Aura + GRANDPA import queue.
	pub fn new(
		config: &mut Configuration,
		eth_config: &EthConfiguration,
	) -> Result<Self, ServiceError> {
		config.keystore = sc_service::config::KeystoreConfig::InMemory;
		let Partial {
			client,
			backend,
			import_queue,
			task_manager,
			frontier_backend,
			..
		} = new_partial(config, eth_config, false)?;
		Ok(Self {
			client,
			backend,
			import_queue,
			task_manager,
			frontier_backend,
		})
	}
}
