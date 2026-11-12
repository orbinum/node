// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

//! The RPC methods the node serves on top of Substrate's own.
//!
//! - `deps`: what the methods are built from.
//! - `substrate`: account nonce and dry run, GRANDPA, fees, manual seal.
//! - `orbinum`: ZK verifier, privacy, chain and ISMP.
//! - `eth`: Ethereum compatibility.
//! - `storage_override`: `eth_call` state overrides for Orbinum's address mapping.

mod deps;
mod eth;
mod orbinum;
mod storage_override;
mod substrate;

use std::sync::Arc;

use jsonrpsee::RpcModule;
use sc_rpc::SubscriptionTaskExecutor;
use sp_inherents::CreateInherentDataProviders;

pub use self::deps::{EthDeps, FullDeps, GrandpaDeps, LogsJournalConfig};
use crate::frontier::PubSubNotificationSinks;
use orbinum_runtime::opaque::Block;

type Error = Box<dyn std::error::Error + Send + Sync>;
type MergeResult = Result<(), Error>;

/// Builds the node's RPC module. Fails if two methods share a name.
pub fn create_full<CIDP>(
	deps: FullDeps<CIDP>,
	subscription_task_executor: SubscriptionTaskExecutor,
	pubsub_notification_sinks: Arc<PubSubNotificationSinks>,
) -> Result<RpcModule<()>, Error>
where
	CIDP: CreateInherentDataProviders<Block, ()> + Send + 'static,
{
	let FullDeps {
		client,
		pool,
		backend,
		command_sink,
		eth,
		grandpa,
		ismp_max_event_blocks,
	} = deps;

	let mut io = RpcModule::new(());
	substrate::merge(
		&mut io,
		&client,
		&pool,
		grandpa,
		command_sink,
		subscription_task_executor.clone(),
	)?;
	orbinum::merge(&mut io, &client, &backend, ismp_max_event_blocks)?;
	eth::merge(
		&mut io,
		&client,
		&pool,
		eth,
		subscription_task_executor,
		pubsub_notification_sinks,
	)?;
	Ok(io)
}
