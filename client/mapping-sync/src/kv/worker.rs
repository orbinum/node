// This file is part of Frontier.

// Copyright (C) Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use std::{collections::HashMap, pin::Pin, sync::Arc, time::Duration};

use futures::{
	prelude::*,
	task::{Context, Poll},
};
use futures_timer::Delay;
use log::debug;
// Substrate
use sc_client_api::{
	backend::{Backend, StorageProvider},
	client::ImportNotifications,
};
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_consensus::SyncOracle;
use sp_runtime::traits::{Block as BlockT, Header as HeaderT};
// Frontier
use fc_storage::StorageOverride;
use fp_rpc::EthereumRuntimeRPCApi;

use crate::{ReorgInfo, SyncStrategy};

/// Information tracked at import time for a block that was `is_new_best`.
pub struct BestBlockInfo<Block: BlockT> {
	/// The block number (for pruning purposes).
	pub block_number: <Block::Header as HeaderT>::Number,
	/// Reorg info if this block became best as part of a reorganization.
	pub reorg_info: Option<Arc<ReorgInfo<Block>>>,
}

pub struct MappingSyncWorker<Block: BlockT, C, BE> {
	import_notifications: ImportNotifications<Block>,
	timeout: Duration,
	inner_delay: Option<Delay>,

	client: Arc<C>,
	substrate_backend: Arc<BE>,
	storage_override: Arc<dyn StorageOverride<Block>>,
	frontier_backend: Arc<fc_db::kv::Backend<Block, C>>,

	have_next: bool,
	retry_times: usize,
	sync_from: <Block::Header as HeaderT>::Number,
	/// If set, blocks below the live state window (finalized_number - state_pruning_blocks)
	/// are skipped during catch-up so the sync tip does not get stuck behind pruned state.
	/// Must match the node's state pruning depth (e.g. from config.state_pruning).
	state_pruning_blocks: Option<u64>,
	strategy: SyncStrategy,

	sync_oracle: Arc<dyn SyncOracle + Send + Sync + 'static>,
	pubsub_notification_sinks:
		Arc<crate::EthereumBlockNotificationSinks<crate::EthereumBlockNotification<Block>>>,

	/// Tracks block hashes that were `is_new_best` at the time of their import notification,
	/// along with their block number for pruning purposes and optional reorg info.
	/// This is used to correctly determine `is_new_best` when syncing blocks, avoiding race
	/// conditions where the best hash may have changed between import and sync time.
	/// Entries are pruned when blocks become finalized to prevent unbounded growth.
	best_at_import: HashMap<Block::Hash, BestBlockInfo<Block>>,
}

impl<Block: BlockT, C, BE> Unpin for MappingSyncWorker<Block, C, BE> {}

impl<Block: BlockT, C, BE> MappingSyncWorker<Block, C, BE> {
	pub fn new(
		import_notifications: ImportNotifications<Block>,
		timeout: Duration,
		client: Arc<C>,
		substrate_backend: Arc<BE>,
		storage_override: Arc<dyn StorageOverride<Block>>,
		frontier_backend: Arc<fc_db::kv::Backend<Block, C>>,
		retry_times: usize,
		sync_from: <Block::Header as HeaderT>::Number,
		state_pruning_blocks: Option<u64>,
		strategy: SyncStrategy,
		sync_oracle: Arc<dyn SyncOracle + Send + Sync + 'static>,
		pubsub_notification_sinks: Arc<
			crate::EthereumBlockNotificationSinks<crate::EthereumBlockNotification<Block>>,
		>,
	) -> Self {
		Self {
			import_notifications,
			timeout,
			inner_delay: None,

			client,
			substrate_backend,
			storage_override,
			frontier_backend,

			have_next: true,
			retry_times,
			sync_from,
			state_pruning_blocks,
			strategy,

			sync_oracle,
			pubsub_notification_sinks,
			best_at_import: HashMap::new(),
		}
	}
}

impl<Block, C, BE> Stream for MappingSyncWorker<Block, C, BE>
where
	Block: BlockT,
	C: ProvideRuntimeApi<Block>,
	C::Api: EthereumRuntimeRPCApi<Block>,
	C: HeaderBackend<Block> + StorageProvider<Block, BE>,
	BE: Backend<Block>,
{
	type Item = ();

	fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<()>> {
		let mut fire = false;

		loop {
			match Stream::poll_next(Pin::new(&mut self.import_notifications), cx) {
				Poll::Pending => break,
				Poll::Ready(Some(notification)) => {
					fire = true;
					// Track blocks that were `is_new_best` at import time to avoid race
					// conditions when determining `is_new_best` at sync time.
					// We store the block number to enable pruning of old entries,
					// and reorg info if this block became best as part of a reorg.
					if notification.is_new_best {
						// For notification: include new_best_hash per Ethereum spec.
						let reorg_info = notification.tree_route.as_ref().map(|tree_route| {
							Arc::new(ReorgInfo::from_tree_route(tree_route, notification.hash))
						});
						self.best_at_import.insert(
							notification.hash,
							BestBlockInfo {
								block_number: *notification.header.number(),
								reorg_info,
							},
						);
					}
				}
				Poll::Ready(None) => return Poll::Ready(None),
			}
		}

		let timeout = self.timeout;
		let inner_delay = self.inner_delay.get_or_insert_with(|| Delay::new(timeout));

		match Future::poll(Pin::new(inner_delay), cx) {
			Poll::Pending => (),
			Poll::Ready(()) => {
				fire = true;
			}
		}

		if self.have_next {
			fire = true;
		}

		if fire {
			self.inner_delay = None;

			// Temporarily take ownership of best_at_import to avoid borrow checker issues
			// (we can't have both an immutable borrow of self.client and a mutable borrow
			// of self.best_at_import at the same time)
			let mut best_at_import = std::mem::take(&mut self.best_at_import);

			let result = crate::kv::sync_blocks(
				self.client.as_ref(),
				self.substrate_backend.as_ref(),
				self.storage_override.clone(),
				self.frontier_backend.as_ref(),
				self.retry_times,
				self.sync_from,
				self.state_pruning_blocks,
				self.strategy,
				self.sync_oracle.clone(),
				self.pubsub_notification_sinks.clone(),
				&mut best_at_import,
			);

			// Restore the best_at_import set
			self.best_at_import = best_at_import;

			match result {
				Ok(have_next) => {
					if !have_next {
						if let Err(e) = super::canonical_reconciler::reconcile_recent_window(
							self.client.as_ref(),
							self.storage_override.as_ref(),
							self.frontier_backend.as_ref(),
							self.sync_from,
							super::PERIODIC_RECONCILE_WINDOW,
						) {
							debug!(
								target: "reconcile",
								"Recent window reconcile failed: {e:?}",
							);
						}
						if let Err(e) = super::repair_canonical_number_mappings_batch(
							self.client.as_ref(),
							self.storage_override.as_ref(),
							self.frontier_backend.as_ref(),
							self.sync_from,
							super::CURSOR_REPAIR_IDLE_BATCH,
						) {
							debug!(
								target: "reconcile",
								"Cursor repair batch failed: {e:?}",
							);
						}
					}
					self.have_next = have_next;
					Poll::Ready(Some(()))
				}
				Err(e) => {
					self.have_next = false;
					debug!(target: "mapping-sync", "Syncing failed with error {e:?}, retrying.");
					Poll::Ready(Some(()))
				}
			}
		} else {
			Poll::Pending
		}
	}
}
