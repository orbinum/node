// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

//! The RPC server itself: everything that needs chain state.
//!
//! [`super::validation`] decides whether calldata is admissible from the bytes
//! alone. What is left here is the part that cannot be answered offline —
//! querying governance config, simulating the call, recording the relay commit,
//! allocating a nonce, signing, and submitting to the pool.
//!
//! The relay commit is what makes the fee ours: the spend's fee goes to the
//! relayer whose commit for it sits in an earlier block, whoever submits the
//! spend. So the commit goes out first, and the spend only once it is included
//! and still outranks every rival commit.
//!
//! Both handlers read `relay_config()` on every call rather than caching it, so
//! a governance change takes effect without restarting the node.
//!
//! [`commit`] batches relay commits into `commitRelay` transactions.

use std::sync::Arc;

use ethereum::TransactionAction;
use ethereum_types::{H160, H256, U256};
use jsonrpsee::core::RpcResult;
// Substrate
use sc_client_api::backend::{Backend, StorageProvider};
use sc_transaction_pool_api::{TransactionPool, TransactionSource};
use sp_api::ApiExt;
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_runtime::traits::Block as BlockT;
// Frontier
use fc_rpc_core::types::{Bytes, TransactionMessage};
use fp_rpc::{ConvertTransactionRuntimeApi, EthereumRuntimeRPCApi};
// Orbinum
use pallet_relayer_runtime_api::RelayerRuntimeApi;
use pallet_shielded_pool_runtime_api::ShieldedPoolRuntimeApi;

use crate::{internal_err, signer::EthValidatorSigner};

mod commit;
use commit::PendingCommit;

use super::{
	config::{
		MAX_FEE_PER_GAS_WEI, MIN_RELAY_FEE_FALLBACK, NONCE_STALL_BLOCKS, RELAY_GAS_LIMIT,
		SELECTORS_FALLBACK, SHIELDED_POOL_PRECOMPILE,
	},
	guard::{rival_wins, spend_nullifiers, ClaimGuard, CommitRank, InFlight, NonceTracker},
	types::{OrbinumRelayApiServer, RelayerStatus},
	validation::{check_dry_run_exit, compute_effective_min_fee, validate_relay_calldata},
};

// ---------------------------------------------------------------------------
// Server struct
// ---------------------------------------------------------------------------

pub struct OrbinumRelay<B: BlockT, C, P, BE> {
	client: Arc<C>,
	pool: Arc<P>,
	signer: Arc<EthValidatorSigner>,
	/// Serializes signing and submission, and tracks the nonce across them.
	submit_lock: Arc<tokio::sync::Mutex<NonceTracker>>,
	/// Relay commits waiting to be sent in the next `commitRelay` transaction,
	/// each with the channel its caller waits on for the submission result.
	pending_commits: Arc<tokio::sync::Mutex<Vec<PendingCommit>>>,
	/// One commit sender at a time, so chunks land in successive blocks.
	commit_sender: Arc<tokio::sync::Mutex<()>>,
	/// Nullifiers of spends in progress or submitted: one relay per spend.
	in_flight: Arc<std::sync::Mutex<InFlight>>,
	_phantom: std::marker::PhantomData<(B, BE)>,
}

// Manual: every field is shared, so a clone is a second handle on the same relay,
// which sends a commit batch from a task no caller can cancel.
impl<B: BlockT, C, P, BE> Clone for OrbinumRelay<B, C, P, BE> {
	fn clone(&self) -> Self {
		Self {
			client: self.client.clone(),
			pool: self.pool.clone(),
			signer: self.signer.clone(),
			submit_lock: self.submit_lock.clone(),
			pending_commits: self.pending_commits.clone(),
			commit_sender: self.commit_sender.clone(),
			in_flight: self.in_flight.clone(),
			_phantom: Default::default(),
		}
	}
}

impl<B, C, P, BE> OrbinumRelay<B, C, P, BE>
where
	B: BlockT,
{
	pub fn new(client: Arc<C>, pool: Arc<P>, signer: EthValidatorSigner) -> Self {
		Self {
			client,
			pool,
			signer: Arc::new(signer),
			submit_lock: Default::default(),
			pending_commits: Default::default(),
			commit_sender: Default::default(),
			in_flight: Default::default(),
			_phantom: Default::default(),
		}
	}
}

// ---------------------------------------------------------------------------
// RPC handlers
// ---------------------------------------------------------------------------

#[jsonrpsee::core::async_trait]
impl<B, C, P, BE> OrbinumRelayApiServer for OrbinumRelay<B, C, P, BE>
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
	async fn relay_shielded_call(&self, calldata: Bytes) -> RpcResult<H256> {
		let data = calldata.into_vec();

		let best_hash = self.client.info().best_hash;
		let (effective_min_fee, allowed_selectors) = self.fee_policy(best_hash);

		if let Err(e) = validate_relay_calldata(&data, effective_min_fee, &allowed_selectors) {
			log::warn!(
				target: "orbinum-relay",
				"relay rejected: {e} (effective minimum fee {effective_min_fee})"
			);
			return Err(internal_err(e));
		}
		let nullifiers = spend_nullifiers(&data)
			.ok_or_else(|| internal_err("calldata does not name the notes it spends"))?;
		// Before claiming: calldata that cannot execute must not hold its notes'
		// claim, or junk naming someone else's nullifier could block their relay.
		self.dry_run(best_hash, &data)?;

		// One relay per spend: copies sent before the first lands would each pass
		// the dry-run (it cannot see the pool) and each cost the relayer its gas.
		let claim = ClaimGuard::take(&self.in_flight, nullifiers)
			.ok_or_else(|| internal_err("this spend is already being relayed"))?;
		let tx_hash = self.relay(data).await?;
		claim.submitted();
		Ok(tx_hash)
	}

	async fn relayer_status(&self) -> RpcResult<RelayerStatus> {
		let best_hash = self.client.info().best_hash;
		let (min_fee, _) = self.fee_policy(best_hash);
		let api = self.client.runtime_api();
		let balance = api
			.account_basic(best_hash, self.signer.address())
			.map_err(|e| internal_err(format!("account_basic: {e}")))?
			.balance;
		// Only a registered address can record relay commits.
		let is_registered = api
			.is_relayer_evm(best_hash, self.signer.address().0)
			.unwrap_or(false);
		let needs_registration = self.relay_commits_supported(best_hash)?;
		// A relay sends a commit and then the spend, each paying up to
		// `RELAY_GAS_LIMIT × MAX_FEE_PER_GAS_WEI`; the pool refuses less.
		let worst_case = U256::from(RELAY_GAS_LIMIT) * U256::from(MAX_FEE_PER_GAS_WEI) * 2;
		Ok(RelayerStatus {
			address: self.signer.address(),
			min_fee: format!("{min_fee}"),
			balance_wei: format!("{balance}"),
			enabled: (is_registered || !needs_registration) && balance >= worst_case,
			is_registered,
		})
	}
}

// ---------------------------------------------------------------------------
// Relay flow: chain reads, dry-run, rival check, submission
// ---------------------------------------------------------------------------

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
	/// The effective minimum fee and the selector whitelist, read on every call
	/// so a governance change applies without a restart. The fallbacks cover
	/// only a runtime without the API.
	fn fee_policy(&self, at: B::Hash) -> (u128, Vec<[u8; 4]>) {
		let api = self.client.runtime_api();
		let (min_fee_planck, allowed_selectors) = match api.relay_config(at) {
			Ok(cfg) => (cfg.min_fee_planck, cfg.allowed_selectors),
			Err(e) => {
				log::warn!(
					target: "orbinum-relay",
					"relay_config Runtime API unavailable, using fallback: {e}"
				);
				(MIN_RELAY_FEE_FALLBACK, SELECTORS_FALLBACK.to_vec())
			}
		};
		// The relay must earn at least twice what it spends on gas (1 wei = 1
		// planck). Saturate: `as_u128()` would panic on a gas price ≥ 2^128.
		let base_fee_wei: u128 = api
			.gas_price(at)
			.map(|p| p.try_into().unwrap_or(u128::MAX))
			.unwrap_or(0);
		(
			compute_effective_min_fee(min_fee_planck, base_fee_wei),
			allowed_selectors,
		)
	}

	/// Commit, dry-run again, check no rival outranks our commit, submit. The
	/// second dry-run runs against the block the commit landed in: the spend may
	/// have been included, or its note spent, while the commit was waiting.
	async fn relay(&self, data: Vec<u8>) -> RpcResult<H256> {
		let at = self.client.info().best_hash;
		if let Some(commit) = self.relay_commit_for(at, &data)? {
			let ours = self.commit_rank(at, commit)?;
			self.ensure_no_rival_commit(at, &data, ours)?;
			if ours.is_none() {
				self.commit(commit).await?;
			}
			let at = self.client.info().best_hash;
			self.dry_run(at, &data)?;
			// A rival recorded in our commit's block with a lower hash takes the fee.
			self.ensure_no_rival_commit(at, &data, self.commit_rank(at, commit)?)?;
		}
		self.sign_and_submit(data).await
	}

	/// Where `commit` ranks, if it is recorded and live at `at`.
	fn commit_rank(&self, at: B::Hash, commit: H256) -> RpcResult<Option<CommitRank>> {
		Ok(self
			.client
			.runtime_api()
			.relay_commit_block(at, commit.0)
			.map_err(|e| internal_err(format!("relay_commit_block: {e}")))?
			.map(|block| (block, commit.0)))
	}

	/// Simulate the EVM call without broadcasting a transaction. Catches invalid
	/// proofs, spent nullifiers and any other on-chain rejection BEFORE the
	/// relayer signs and pays gas.
	fn dry_run(&self, at: B::Hash, data: &[u8]) -> RpcResult<()> {
		let dry_result = self.client.runtime_api().call(
			at,
			self.signer.address(),
			H160::from(SHIELDED_POOL_PRECOMPILE),
			data.to_vec(),
			U256::zero(),
			U256::from(RELAY_GAS_LIMIT),
			Some(U256::from(MAX_FEE_PER_GAS_WEI)),
			Some(U256::from(1_000_000_000u64)),
			None,  // nonce — not needed for simulation
			false, // estimate = false: real execution semantics
			None,  // access_list
			None,  // authorization_list
		);
		match dry_result {
			Err(e) => {
				log::warn!(target: "orbinum-relay", "dry-run Runtime API error: {e}");
				Err(internal_err(format!("dry-run runtime error: {e}")))
			}
			Ok(Err(dispatch_err)) => {
				log::warn!(target: "orbinum-relay", "dry-run dispatch error: {dispatch_err:?}");
				Err(internal_err(format!(
					"calldata rejected by runtime: {dispatch_err:?}"
				)))
			}
			Ok(Ok(info)) => check_dry_run_exit(&info.exit_reason).map_err(|e| {
				log::warn!(
					target: "orbinum-relay",
					"dry-run EVM execution failed — exit={:?} revert_data={:?}",
					info.exit_reason,
					info.value
				);
				internal_err(e)
			}),
		}
	}

	/// Refuse a spend whose fee a rival's live commit would take (see
	/// [`rival_wins`]): relaying it would pay this relayer's gas for their fee.
	/// The caller can retry once that commit expires (`CommitTtl` blocks).
	fn ensure_no_rival_commit(
		&self,
		at: B::Hash,
		data: &[u8],
		ours: Option<CommitRank>,
	) -> RpcResult<()> {
		let api = self.client.runtime_api();
		let own = self.signer.address().0;
		let relayers = api
			.get_active_relayers(at)
			.map_err(|e| internal_err(format!("get_active_relayers: {e}")))?;
		for (address, _) in relayers.into_iter().filter(|(a, _)| *a != own) {
			let Some(commit) = api
				.relay_commit_hash(at, data.to_vec(), address)
				.map_err(|e| internal_err(format!("relay_commit_hash: {e}")))?
			else {
				continue;
			};
			if let Some(rival) = self.commit_rank(at, H256(commit))? {
				if rival_wins(ours, rival) {
					return Err(internal_err(format!(
						"relayer {:?} committed to this spend first; retry after its commit expires",
						H160::from(address)
					)));
				}
			}
		}
		Ok(())
	}

	/// Whether the runtime attributes fees by relay commit: `ShieldedPoolRuntimeApi`
	/// ≥ 3 and `RelayerRuntimeApi` ≥ 2. An older one attributes them by origin —
	/// the node binary ships before the runtime upgrade.
	fn relay_commits_supported(&self, at: B::Hash) -> RpcResult<bool> {
		let api = self.client.runtime_api();
		let pool = api
			.api_version::<dyn ShieldedPoolRuntimeApi<B>>(at)
			.map_err(|e| internal_err(format!("api_version: {e}")))?
			.unwrap_or(0);
		let relayer = api
			.api_version::<dyn RelayerRuntimeApi<B>>(at)
			.map_err(|e| internal_err(format!("api_version: {e}")))?
			.unwrap_or(0);
		Ok(pool >= 3 && relayer >= 2)
	}

	/// The relay commit for `calldata`, or `None` on a runtime without relay
	/// commits.
	fn relay_commit_for(&self, at: B::Hash, calldata: &[u8]) -> RpcResult<Option<H256>> {
		if !self.relay_commits_supported(at)? {
			return Ok(None);
		}
		let api = self.client.runtime_api();
		// Fail fast: an unregistered address cannot record the commit, and the
		// caller would otherwise only see it time out.
		if !api
			.is_relayer_evm(at, self.signer.address().0)
			.unwrap_or(false)
		{
			return Err(internal_err("relay address is not registered on-chain"));
		}
		let commit = api
			.relay_commit_hash(at, calldata.to_vec(), self.signer.address().0)
			.map_err(|e| internal_err(format!("relay_commit_hash: {e}")))?
			.ok_or_else(|| internal_err("calldata is not a relayable spend"))?;
		Ok(Some(H256(commit)))
	}

	/// Sign `input` as a call to the ShieldedPool precompile and submit it.
	async fn sign_and_submit(&self, input: Vec<u8>) -> RpcResult<H256> {
		use sp_runtime::traits::UniqueSaturatedInto;
		// Held for the whole sequence, and the chain read under it, so no two
		// submissions sign with the same nonce.
		let mut nonces = self.submit_lock.lock().await;
		let info = self.client.info();
		let best_hash = info.best_hash;
		let best: u64 = info.best_number.unique_saturated_into();

		let relayer_addr = self.signer.address();

		let (chain_id, nonce) = {
			let api = self.client.runtime_api();
			let chain_id = api
				.chain_id(best_hash)
				.map_err(|e| internal_err(format!("chain_id: {e}")))?;
			let confirmed = api
				.account_basic(best_hash, relayer_addr)
				.map_err(|e| internal_err(format!("account_basic: {e}")))?
				.nonce;
			(chain_id, nonces.nonce(confirmed, best, NONCE_STALL_BLOCKS))
		};

		let message = TransactionMessage::EIP1559(ethereum::EIP1559TransactionMessage {
			chain_id,
			nonce,
			max_priority_fee_per_gas: U256::from(1_000_000_000u64),
			max_fee_per_gas: U256::from(MAX_FEE_PER_GAS_WEI),
			gas_limit: U256::from(RELAY_GAS_LIMIT),
			action: TransactionAction::Call(H160::from(SHIELDED_POOL_PRECOMPILE)),
			value: U256::zero(),
			input,
			access_list: vec![],
		});

		use crate::signer::EthSigner as _;
		let transaction = self.signer.sign(message, &relayer_addr)?;
		let tx_hash = transaction.hash();

		let extrinsic = {
			let api = self.client.runtime_api();
			api.convert_transaction(best_hash, transaction)
				.map_err(|e| internal_err(format!("convert_transaction: {e}")))?
		};

		let submit_result = self
			.pool
			.submit_one(best_hash, TransactionSource::Local, extrinsic)
			.await
			.map(|_| tx_hash)
			.map_err(|e| internal_err(format!("pool submit: {e}")));

		// Only a submission the pool accepted takes the nonce.
		if submit_result.is_ok() {
			nonces.submitted(nonce);
		}

		submit_result
	}
}
