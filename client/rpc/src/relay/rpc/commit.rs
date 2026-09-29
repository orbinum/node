// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

//! Relay commits: queued per call, sent in batches, awaited until recorded.
//!
//! A spend's fee goes to the relayer whose commit for it sits in an earlier
//! block, so each relay call records its commit and waits for it to land before
//! the spend goes out. Calls arriving together share one `commitRelay`
//! transaction.

use ethereum_types::H256;
use fp_rpc::{ConvertTransactionRuntimeApi, EthereumRuntimeRPCApi};
use jsonrpsee::core::RpcResult;
use pallet_relayer_runtime_api::RelayerRuntimeApi;
use pallet_shielded_pool_runtime_api::ShieldedPoolRuntimeApi;
use sc_client_api::backend::{Backend, StorageProvider};
use sc_transaction_pool_api::TransactionPool;
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_runtime::traits::Block as BlockT;

use crate::internal_err;

use super::OrbinumRelay;
use crate::relay::{
	config::{COMMIT_BATCH_WINDOW, COMMIT_POLL_INTERVAL, COMMIT_WAIT_TIMEOUT},
	operations::commit_relay_calldata,
};

/// A queued relay commit and the channel its caller waits on for the result
/// of submitting it.
pub(super) type PendingCommit = (H256, tokio::sync::oneshot::Sender<Result<(), String>>);

impl<B, C, P, BE> OrbinumRelay<B, C, P, BE>
where
	B: BlockT,
	C: ProvideRuntimeApi<B> + HeaderBackend<B> + StorageProvider<B, BE> + 'static,
	C::Api: EthereumRuntimeRPCApi<B>
		+ ConvertTransactionRuntimeApi<B>
		+ ShieldedPoolRuntimeApi<B>
		+ RelayerRuntimeApi<B>,
	BE: Backend<B> + 'static,
	P: TransactionPool<Block = B, Hash = B::Hash> + 'static,
{
	/// Record `commit` on-chain and wait until it is in the best chain, so the
	/// spend sent afterwards lands in a later block — the only kind that counts.
	///
	/// Commits queued within `COMMIT_BATCH_WINDOW` of each other go out together:
	/// the first call to wake sends the whole queue and tells every queued caller
	/// how its chunk fared, so a failed submission is reported to all of them
	/// rather than surfacing later as a timeout.
	pub(super) async fn commit(&self, commit: H256) -> RpcResult<()> {
		let (sent, submitted) = tokio::sync::oneshot::channel();
		self.pending_commits.lock().await.push((commit, sent));
		tokio::time::sleep(COMMIT_BATCH_WINDOW).await;

		// Sent from a task of its own: if this caller disconnects, the batch it
		// drained still goes out for everyone else in it.
		let batch = std::mem::take(&mut *self.pending_commits.lock().await);
		if !batch.is_empty() {
			let relay = self.clone();
			tokio::spawn(async move { relay.send_commits(batch).await });
		}
		tokio::time::timeout(COMMIT_WAIT_TIMEOUT, submitted)
			.await
			.map_err(|_| internal_err("relay commit was not submitted in time"))?
			.map_err(|_| internal_err("relay commit batch was dropped"))?
			.map_err(internal_err)?;

		if self.wait_recorded(commit).await? {
			Ok(())
		} else {
			Err(internal_err("relay commit was not included in time"))
		}
	}

	/// Poll the best block until `commit` is recorded; `false` on timeout.
	async fn wait_recorded(&self, commit: H256) -> RpcResult<bool> {
		let deadline = tokio::time::Instant::now() + COMMIT_WAIT_TIMEOUT;
		loop {
			if self
				.commit_rank(self.client.info().best_hash, commit)?
				.is_some()
			{
				return Ok(true);
			}
			if tokio::time::Instant::now() >= deadline {
				return Ok(false);
			}
			tokio::time::sleep(COMMIT_POLL_INTERVAL).await;
		}
	}

	/// Submit `batch` in `commitRelay` calls of at most the per-block quota
	/// (`MAX_RELAY_COMMITS_PER_CALL` equals `MaxCommitsPerRelayerPerBlock`),
	/// reporting each chunk's result to its callers.
	///
	/// The quota applies to the block a chunk lands in, not the one it was sent
	/// at, so the next chunk goes out only once the previous one is recorded;
	/// one sender at a time keeps concurrent batches from sharing a block.
	async fn send_commits(&self, batch: Vec<PendingCommit>) {
		let per_block = pallet_evm_precompile_shielded_pool::MAX_RELAY_COMMITS_PER_CALL as usize;
		let _sender = self.commit_sender.lock().await;
		let mut batch = batch.into_iter().peekable();
		while batch.peek().is_some() {
			let chunk: Vec<PendingCommit> = batch.by_ref().take(per_block).collect();
			let commits: Vec<H256> = chunk.iter().map(|(c, _)| *c).collect();
			let result = self
				.sign_and_submit(commit_relay_calldata(&commits))
				.await
				.map(|_| ())
				.map_err(|e| e.to_string());
			for (_, caller) in chunk {
				let _ = caller.send(result.clone());
			}
			if result.is_ok() && batch.peek().is_some() {
				if let Some(last) = commits.last() {
					let _ = self.wait_recorded(*last).await;
				}
			}
		}
	}
}
