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

#![allow(clippy::too_many_arguments)]

mod canonical_reconciler;
mod worker;

pub use worker::MappingSyncWorker;

use std::{collections::HashMap, sync::Arc};

// Substrate
use sc_client_api::backend::{Backend, StorageProvider};
use sp_api::{ApiExt, ProvideRuntimeApi};
use sp_blockchain::{Backend as _, HeaderBackend};
use sp_consensus::SyncOracle;
use sp_runtime::traits::{
	Block as BlockT, Header as HeaderT, SaturatedConversion, UniqueSaturatedInto, Zero,
};
// Frontier
use fc_storage::StorageOverride;
use fp_consensus::{FindLogError, Hashes, Log, PostLog, PreLog};
use fp_rpc::EthereumRuntimeRPCApi;

use crate::{
	emit_block_notification, BlockNotificationContext, EthereumBlockNotification,
	EthereumBlockNotificationSinks, SyncStrategy,
};
use worker::BestBlockInfo;

pub const CANONICAL_NUMBER_REPAIR_BATCH_SIZE: u64 = 2048;

/// Max blocks to backfill in one skip-path call to avoid unbounded stall on heavily pruned nodes.
const BACKFILL_ON_SKIP_MAX_BLOCKS: u64 = 1024;

/// Number of recent blocks to reconcile on every mapping-sync worker tick.
/// Small enough to be cheap per-tick, large enough to cover typical reorg depth.
pub const PERIODIC_RECONCILE_WINDOW: u64 = 16;

/// Max blocks to repair per idle tick via the cursor-driven full-history sweep.
/// Keeps per-tick cost bounded while ensuring eventual consistency across the entire chain.
pub const CURSOR_REPAIR_IDLE_BATCH: u64 = 128;

/// Sync a single block's Ethereum mapping from its consensus digest into the Frontier DB.
pub fn sync_block<Block: BlockT, C: HeaderBackend<Block>>(
	client: &C,
	storage_override: Arc<dyn StorageOverride<Block>>,
	backend: &fc_db::kv::Backend<Block, C>,
	header: &Block::Header,
) -> Result<(), String> {
	let substrate_block_hash = header.hash();
	let block_number: u64 = (*header.number()).unique_saturated_into();

	// Write BLOCK_NUMBER_MAPPING when this block is canonical at this number, so
	// latest_block_hash() / indexed_canonical_hash_at() find it during catch-up.
	// Uses only HeaderBackend::hash() — no state access, pruning-safe.
	// Ok(None) (block number unknown) falls back to Skip; Err is propagated so
	// the block stays unsynced and fetch_header retries it on the next tick.
	let canonical_hash_at_number = client
		.hash(*header.number())
		.map_err(|e| format!("failed to resolve canonical hash at #{block_number}: {e:?}"))?;
	let number_mapping_write = if canonical_hash_at_number == Some(substrate_block_hash) {
		fc_db::kv::NumberMappingWrite::Write
	} else {
		fc_db::kv::NumberMappingWrite::Skip
	};

	match fp_consensus::find_log(header.digest()) {
		Ok(log) => {
			let gen_from_hashes = |hashes: Hashes| -> fc_db::kv::MappingCommitment<Block> {
				fc_db::kv::MappingCommitment {
					block_hash: substrate_block_hash,
					ethereum_block_hash: hashes.block_hash,
					ethereum_transaction_hashes: hashes.transaction_hashes,
				}
			};
			let gen_from_block = |block| -> fc_db::kv::MappingCommitment<Block> {
				let hashes = Hashes::from_block(block);
				gen_from_hashes(hashes)
			};

			match log {
				Log::Pre(PreLog::Block(block)) => {
					let mapping_commitment = gen_from_block(block);
					backend.mapping().write_hashes(
						mapping_commitment,
						block_number,
						number_mapping_write,
					)
				}
				Log::Post(post_log) => match post_log {
					PostLog::Hashes(hashes) => {
						let mapping_commitment = gen_from_hashes(hashes);
						backend.mapping().write_hashes(
							mapping_commitment,
							block_number,
							number_mapping_write,
						)
					}
					PostLog::Block(block) => {
						let mapping_commitment = gen_from_block(block);
						backend.mapping().write_hashes(
							mapping_commitment,
							block_number,
							number_mapping_write,
						)
					}
					PostLog::BlockHash(expect_eth_block_hash) => {
						let ethereum_block = storage_override.current_block(substrate_block_hash);
						match ethereum_block {
							Some(block) => {
								let got_eth_block_hash = block.header.hash();
								if got_eth_block_hash != expect_eth_block_hash {
									log::warn!(
										target: "mapping-sync",
										"Ethereum block hash mismatch: \
										frontier consensus digest ({expect_eth_block_hash:?}), \
										db state ({got_eth_block_hash:?}); \
										writing digest block mapping with db state tx hashes."
									);
									let mapping_commitment = fc_db::kv::MappingCommitment::<Block> {
										block_hash: substrate_block_hash,
										ethereum_block_hash: expect_eth_block_hash,
										ethereum_transaction_hashes: block
											.transactions
											.iter()
											.map(|tx| tx.hash())
											.collect(),
									};
									backend.mapping().write_hashes(
										mapping_commitment,
										block_number,
										number_mapping_write,
									)
								} else {
									let mapping_commitment = gen_from_block(block);
									backend.mapping().write_hashes(
										mapping_commitment,
										block_number,
										number_mapping_write,
									)
								}
							}
							None => {
								// State is unavailable — likely pruned. Write a minimal
								// commitment so BLOCK_MAPPING and BLOCK_NUMBER_MAPPING are
								// populated and indexed_canonical_hash_at() can resolve
								// this block. Transaction hashes are unavailable without state.
								log::warn!(
									target: "mapping-sync",
									"State unavailable for block #{block_number} ({substrate_block_hash:?}); \
									writing minimal mapping (no tx hashes). \
									This may indicate the pruning window is too narrow.",
								);
								let mapping_commitment = fc_db::kv::MappingCommitment::<Block> {
									block_hash: substrate_block_hash,
									ethereum_block_hash: expect_eth_block_hash,
									ethereum_transaction_hashes: vec![],
								};
								backend.mapping().write_hashes(
									mapping_commitment,
									block_number,
									number_mapping_write,
								)
							}
						}
					}
				},
			}
		}
		Err(FindLogError::NotFound) => backend.mapping().write_none(substrate_block_hash),
		Err(FindLogError::MultipleLogs) => Err("Multiple logs found".to_string()),
	}
}

pub fn sync_genesis_block<Block: BlockT, C>(
	client: &C,
	backend: &fc_db::kv::Backend<Block, C>,
	header: &Block::Header,
) -> Result<(), String>
where
	C: HeaderBackend<Block> + ProvideRuntimeApi<Block>,
	C::Api: EthereumRuntimeRPCApi<Block>,
{
	let substrate_block_hash = header.hash();
	let block_number: u64 = (*header.number()).unique_saturated_into();

	if let Some(api_version) = client
		.runtime_api()
		.api_version::<dyn EthereumRuntimeRPCApi<Block>>(substrate_block_hash)
		.map_err(|e| format!("{e:?}"))?
	{
		let block = if api_version > 1 {
			client
				.runtime_api()
				.current_block(substrate_block_hash)
				.map_err(|e| format!("{e:?}"))?
		} else {
			#[allow(deprecated)]
			let legacy_block = client
				.runtime_api()
				.current_block_before_version_2(substrate_block_hash)
				.map_err(|e| format!("{e:?}"))?;
			legacy_block.map(|block| block.into())
		};
		let block_hash = block
			.ok_or_else(|| "Ethereum genesis block not found".to_string())?
			.header
			.hash();
		let mapping_commitment = fc_db::kv::MappingCommitment::<Block> {
			block_hash: substrate_block_hash,
			ethereum_block_hash: block_hash,
			ethereum_transaction_hashes: Vec::new(),
		};
		backend.mapping().write_hashes(
			mapping_commitment,
			block_number,
			fc_db::kv::NumberMappingWrite::Write,
		)?;
	} else {
		backend.mapping().write_none(substrate_block_hash)?;
	};

	Ok(())
}

/// Backfill BLOCK_NUMBER_MAPPING for already-synced canonical blocks in `[from..=to]`.
/// Uses only `HeaderBackend` and consensus digests — no state access, pruning-safe.
/// Stops after writing `max_blocks` mappings to avoid unbounded stall on heavily pruned nodes.
/// Returns the count of mappings written.
fn backfill_number_mappings<Block: BlockT, C, BE>(
	client: &C,
	substrate_backend: &BE,
	frontier_backend: &fc_db::kv::Backend<Block, C>,
	from: u64,
	to: u64,
	max_blocks: u64,
) -> Result<u64, String>
where
	C: HeaderBackend<Block>,
	BE: sp_blockchain::Backend<Block>,
{
	let mut written = 0u64;
	for number in from..=to {
		if written >= max_blocks {
			break;
		}
		if frontier_backend
			.mapping()
			.block_hash_by_number(number)?
			.is_some()
		{
			continue;
		}
		let block_number_native = number.saturated_into::<<Block::Header as HeaderT>::Number>();
		let canonical_hash = match client.hash(block_number_native) {
			Ok(Some(hash)) => hash,
			Ok(None) => continue,
			Err(e) => {
				return Err(format!(
					"failed to resolve canonical hash at #{number}: {e:?}"
				))
			}
		};
		if !frontier_backend.mapping().is_synced(&canonical_hash)? {
			continue;
		}
		let header = match substrate_backend.header(canonical_hash) {
			Ok(Some(header)) => header,
			Ok(None) => continue,
			Err(e) => {
				return Err(format!(
					"failed to load canonical header {canonical_hash:?} at #{number}: {e:?}"
				))
			}
		};
		let eth_block_hash = match fp_consensus::find_post_log(header.digest()) {
			Ok(PostLog::Hashes(h)) => Some(h.block_hash),
			Ok(PostLog::Block(block)) => Some(block.header.hash()),
			Ok(PostLog::BlockHash(hash)) => Some(hash),
			Err(_) => match fp_consensus::find_pre_log(header.digest()) {
				Ok(PreLog::Block(block)) => Some(block.header.hash()),
				Err(_) => None,
			},
		};
		if let Some(eth_hash) = eth_block_hash {
			frontier_backend
				.mapping()
				.set_block_hash_by_number(number, eth_hash)?;

			let has_block_mapping = frontier_backend
				.mapping()
				.block_hash(&eth_hash)?
				.map(|hashes| hashes.contains(&canonical_hash))
				.unwrap_or(false);
			if !has_block_mapping {
				let commitment = fc_db::kv::MappingCommitment::<Block> {
					block_hash: canonical_hash,
					ethereum_block_hash: eth_hash,
					ethereum_transaction_hashes: vec![],
				};
				frontier_backend.mapping().write_hashes(
					commitment,
					number,
					fc_db::kv::NumberMappingWrite::Skip,
				)?;
			}

			written += 1;
		}
	}
	if written > 0 {
		log::debug!(
			target: "mapping-sync",
			"Backfilled BLOCK_NUMBER_MAPPING for {written} blocks in #{from}..#{to}",
		);
	}
	Ok(written)
}

pub fn repair_canonical_number_mappings_batch<Block: BlockT, C: HeaderBackend<Block>>(
	client: &C,
	storage_override: &dyn StorageOverride<Block>,
	frontier_backend: &fc_db::kv::Backend<Block, C>,
	sync_from: <Block::Header as HeaderT>::Number,
	max_blocks: u64,
) -> Result<(), String> {
	if let Some(stats) = canonical_reconciler::reconcile_from_cursor_batch(
		client,
		storage_override,
		frontier_backend,
		sync_from,
		max_blocks,
	)? {
		log::debug!(
			target: "reconcile",
			"batch reconcile scanned {}, updated {}, lag {}",
			stats.scanned,
			stats.updated,
			stats.lag_blocks,
		);
	}

	Ok(())
}

pub fn sync_one_block<Block: BlockT, C, BE>(
	client: &C,
	substrate_backend: &BE,
	storage_override: Arc<dyn StorageOverride<Block>>,
	frontier_backend: &fc_db::kv::Backend<Block, C>,
	sync_from: <Block::Header as HeaderT>::Number,
	state_pruning_blocks: Option<u64>,
	strategy: SyncStrategy,
	sync_oracle: Arc<dyn SyncOracle + Send + Sync + 'static>,
	pubsub_notification_sinks: Arc<
		EthereumBlockNotificationSinks<EthereumBlockNotification<Block>>,
	>,
	best_at_import: &mut HashMap<Block::Hash, BestBlockInfo<Block>>,
) -> Result<bool, String>
where
	C: ProvideRuntimeApi<Block>,
	C::Api: EthereumRuntimeRPCApi<Block>,
	C: HeaderBackend<Block> + StorageProvider<Block, BE>,
	BE: Backend<Block>,
{
	let mut current_syncing_tips = frontier_backend.meta().current_syncing_tips()?;

	if current_syncing_tips.is_empty() {
		let mut leaves = substrate_backend
			.blockchain()
			.leaves()
			.map_err(|e| format!("{e:?}"))?;
		if leaves.is_empty() {
			return Ok(false);
		}
		current_syncing_tips.append(&mut leaves);
	}

	let best_hash = client.info().best_hash;
	if SyncStrategy::Parachain == strategy && !frontier_backend.mapping().is_synced(&best_hash)? {
		// Add best block to current_syncing_tips
		current_syncing_tips.push(best_hash);
	}

	let mut operating_header = None;
	while let Some(checking_tip) = current_syncing_tips.pop() {
		if let Some(checking_header) = fetch_header(
			substrate_backend.blockchain(),
			frontier_backend,
			checking_tip,
			sync_from,
		)? {
			operating_header = Some(checking_header);
			break;
		}
	}
	let operating_header = match operating_header {
		Some(operating_header) => operating_header,
		None => {
			frontier_backend
				.meta()
				.write_current_syncing_tips(current_syncing_tips)?;
			return Ok(false);
		}
	};

	if operating_header.number() == &Zero::zero() {
		sync_genesis_block(client, frontier_backend, &operating_header)?;

		frontier_backend
			.meta()
			.write_current_syncing_tips(current_syncing_tips)?;
	} else {
		if SyncStrategy::Parachain == strategy
			&& operating_header.number() > &client.info().best_number
		{
			return Ok(false);
		}

		// On pruned nodes: live state window is derived from finalized_number (not best),
		// so we skip blocks below (finalized_number - pruning_blocks). That avoids
		// depending on unfinalized chain and matches typical state-pruning semantics.
		// Jump the syncing tip forward to the window floor, retaining any queued tips
		// that are already within the live window (fork/reorg catch-up).
		if let Some(pruning_blocks) = state_pruning_blocks {
			let finalized_number_u64: u64 = client.info().finalized_number.unique_saturated_into();
			let live_window_start_u64 = finalized_number_u64.saturating_sub(pruning_blocks);
			let sync_from_u64: u64 = sync_from.unique_saturated_into();
			let skip_to_u64 = live_window_start_u64.max(sync_from_u64);
			let current_number_u64: u64 = (*operating_header.number()).unique_saturated_into();

			if current_number_u64 < skip_to_u64 {
				let skip_to_number =
					skip_to_u64.saturated_into::<<Block::Header as HeaderT>::Number>();
				match client.hash(skip_to_number) {
					Ok(Some(skip_hash)) => {
						log::warn!(
							target: "mapping-sync",
							"Pruned node: skipping blocks #{}..#{} (outside live state window), \
							jumping tip to #{}",
							current_number_u64,
							skip_to_u64.saturating_sub(1),
							skip_to_u64,
						);
						// Retain any tips still within the live window rather than
						// discarding them — they may be unsynced fork branches that
						// need indexing. Replace only the out-of-window tip with
						// the skip target.
						let mut retained = Vec::with_capacity(current_syncing_tips.len());
						for tip in current_syncing_tips.drain(..) {
							match substrate_backend.blockchain().header(tip) {
								Ok(Some(h)) => {
									let n: u64 = (*h.number()).unique_saturated_into();
									if n >= skip_to_u64 {
										retained.push(tip);
									}
								}
								Ok(None) | Err(_) => {
									retained.push(tip);
								}
							}
						}
						current_syncing_tips = retained;
						current_syncing_tips.push(skip_hash);
						frontier_backend
							.meta()
							.write_current_syncing_tips(current_syncing_tips)?;

						// Backfill BLOCK_NUMBER_MAPPING for already-synced
						// canonical blocks in the live window so
						// latest_block_hash() can find them (handles upgrade
						// from old logic that always used Skip). Capped per
						// call to avoid unbounded stall on heavily pruned nodes.
						let best_number_u64: u64 =
							client.info().best_number.unique_saturated_into();
						backfill_number_mappings(
							client,
							substrate_backend.blockchain(),
							frontier_backend,
							skip_to_u64,
							best_number_u64,
							BACKFILL_ON_SKIP_MAX_BLOCKS,
						)?;

						return Ok(true);
					}
					Ok(None) => {
						// Target block not yet known to the client (e.g. node still
						// syncing headers). Return false to back off and retry later
						// rather than falling through to sync a pruned block.
						current_syncing_tips.push(operating_header.hash());
						frontier_backend
							.meta()
							.write_current_syncing_tips(current_syncing_tips)?;
						return Ok(false);
					}
					Err(e) => {
						// Transient client error. Back off and retry rather than
						// falling through to sync a pruned block.
						log::warn!(
							target: "mapping-sync",
							"Pruned node: failed to resolve skip target #{skip_to_u64}: {e:?}; will retry.",
						);
						current_syncing_tips.push(operating_header.hash());
						frontier_backend
							.meta()
							.write_current_syncing_tips(current_syncing_tips)?;
						return Ok(false);
					}
				}
			}
		}

		sync_block(
			client,
			storage_override.clone(),
			frontier_backend,
			&operating_header,
		)?;

		current_syncing_tips.push(*operating_header.parent_hash());
		frontier_backend
			.meta()
			.write_current_syncing_tips(current_syncing_tips)?;
	}

	// Reconcile the most recent window of blocks.
	canonical_reconciler::reconcile_recent_window(
		client,
		storage_override.as_ref(),
		frontier_backend,
		sync_from,
		PERIODIC_RECONCILE_WINDOW,
	)?;

	// Notify on import and remove closed channels using the unified notification mechanism.
	let hash = operating_header.hash();
	// Use the `is_new_best` status from import time if available.
	// This avoids race conditions where the best hash may have changed
	// between import and sync time (e.g., during rapid reorgs).
	// Fall back to current best hash check for blocks synced during catch-up.
	let best_info = best_at_import.remove(&hash);
	let is_new_best = best_info.is_some() || client.info().best_hash == hash;
	let reorg_info = best_info.and_then(|info| info.reorg_info);

	// Reorg-aware reconcile only when this block was actually new-best at import.
	if is_new_best {
		let reconcile_stats = canonical_reconciler::reconcile_reorg_window(
			client,
			storage_override.as_ref(),
			frontier_backend,
			reorg_info.as_deref(),
			hash,
			sync_from,
		)?;
		log::debug!(
			target: "reconcile",
			"new-best reconcile at {hash:?}: {reconcile_stats:?}",
		);
	}

	emit_block_notification(
		pubsub_notification_sinks.as_ref(),
		sync_oracle.as_ref(),
		BlockNotificationContext {
			hash,
			is_new_best,
			reorg_info,
		},
	);

	Ok(true)
}

pub fn sync_blocks<Block: BlockT, C, BE>(
	client: &C,
	substrate_backend: &BE,
	storage_override: Arc<dyn StorageOverride<Block>>,
	frontier_backend: &fc_db::kv::Backend<Block, C>,
	limit: usize,
	sync_from: <Block::Header as HeaderT>::Number,
	state_pruning_blocks: Option<u64>,
	strategy: SyncStrategy,
	sync_oracle: Arc<dyn SyncOracle + Send + Sync + 'static>,
	pubsub_notification_sinks: Arc<
		EthereumBlockNotificationSinks<EthereumBlockNotification<Block>>,
	>,
	best_at_import: &mut HashMap<Block::Hash, BestBlockInfo<Block>>,
) -> Result<bool, String>
where
	C: ProvideRuntimeApi<Block>,
	C::Api: EthereumRuntimeRPCApi<Block>,
	C: HeaderBackend<Block> + StorageProvider<Block, BE>,
	BE: Backend<Block>,
{
	let mut synced_any = false;

	for _ in 0..limit {
		synced_any = synced_any
			|| sync_one_block(
				client,
				substrate_backend,
				storage_override.clone(),
				frontier_backend,
				sync_from,
				state_pruning_blocks,
				strategy,
				sync_oracle.clone(),
				pubsub_notification_sinks.clone(),
				best_at_import,
			)?;
	}

	// Prune old entries from best_at_import to prevent unbounded growth.
	// Entries for finalized blocks are no longer needed since finalized blocks
	// cannot be reorged and their is_new_best status is irrelevant.
	let finalized_number = client.info().finalized_number;
	best_at_import.retain(|_, info| info.block_number > finalized_number);

	Ok(synced_any)
}

pub fn fetch_header<Block: BlockT, C, BE>(
	substrate_backend: &BE,
	frontier_backend: &fc_db::kv::Backend<Block, C>,
	checking_tip: Block::Hash,
	sync_from: <Block::Header as HeaderT>::Number,
) -> Result<Option<Block::Header>, String>
where
	C: HeaderBackend<Block>,
	BE: HeaderBackend<Block>,
{
	if frontier_backend.mapping().is_synced(&checking_tip)? {
		return Ok(None);
	}

	match substrate_backend.header(checking_tip) {
		Ok(Some(checking_header)) if checking_header.number() >= &sync_from => {
			Ok(Some(checking_header))
		}
		Ok(Some(_)) => Ok(None),
		Ok(None) | Err(_) => Err("Header not found".to_string()),
	}
}
