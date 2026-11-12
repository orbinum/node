// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

//! Substrate RPCs beyond `spawn_tasks`' own: account nonce and dry run, GRANDPA finality,
//! fees, and manual seal.

use std::sync::Arc;

use futures::channel::mpsc;
use jsonrpsee::RpcModule;
use pallet_transaction_payment_rpc::{TransactionPayment, TransactionPaymentApiServer};
use sc_consensus_grandpa_rpc::{Grandpa, GrandpaApiServer};
use sc_consensus_manual_seal::rpc::{EngineCommand, ManualSeal, ManualSealApiServer};
use sc_rpc::SubscriptionTaskExecutor;
use substrate_frame_rpc_system::{System, SystemApiServer};

use super::{GrandpaDeps, MergeResult};
use crate::client::{Client, TransactionPool};
use orbinum_runtime::Hash;

/// `system_accountNextIndex`, `system_dryRun*`, `grandpa_*` and `payment_*`; `engine_*`
/// with a manual seal `command_sink`.
pub fn merge(
	io: &mut RpcModule<()>,
	client: &Arc<Client>,
	pool: &Arc<TransactionPool>,
	grandpa: GrandpaDeps,
	command_sink: Option<mpsc::Sender<EngineCommand<Hash>>>,
	subscription_task_executor: SubscriptionTaskExecutor,
) -> MergeResult {
	io.merge(System::new(client.clone(), pool.clone()).into_rpc())?;
	io.merge(
		Grandpa::new(
			subscription_task_executor,
			grandpa.shared_authority_set,
			grandpa.shared_voter_state,
			grandpa.justification_stream,
			grandpa.finality_provider,
		)
		.into_rpc(),
	)?;
	io.merge(TransactionPayment::new(client.clone()).into_rpc())?;
	if let Some(command_sink) = command_sink {
		io.merge(ManualSeal::new(command_sink).into_rpc())?;
	}
	Ok(())
}
