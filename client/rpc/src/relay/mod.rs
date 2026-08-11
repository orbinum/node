// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

//! Node-native EVM relay RPC.
//!
//! When the node is started with `--evm-relayer-key <hex>`, it exposes:
//!
//! - `orbinum_relayShieldedCall(calldata: "0x...")` → `txHash`
//! - `orbinum_relayerStatus()` → `{ address, minFee, balanceWei, enabled, isRegistered }`
//!
//! The relay only accepts calls to the ShieldedPool precompile
//! (`0x0000000000000000000000000000000000000801`) with selector
//! `0x4e505348` (unshield) or `0x1ec439cf` (privateTransfer).
//! It checks the fee embedded in ABI slot 6 is ≥ the current `min_relay_fee` from
//! `pallet-relayer` (queried dynamically via Runtime API so forkless upgrades take effect immediately).
//!
//! # Module layout
//!
//! | Sub-module      | Responsibility                                              |
//! |-----------------|-------------------------------------------------------------|
//! | [`operations`]  | `RelayableOperation` trait + `UnshieldOp` + `PrivateTransferOp` (Capa 3) |
//! | [`types`]       | `OrbinumRelayApi` RPC trait + `RelayerStatus` response type |
//! | [`validation`]  | Pure calldata validation + fee-floor computation + tests    |

pub mod operations;
pub mod types;
pub mod validation;

pub use types::{OrbinumRelayApiServer, RelayerStatus};

use std::sync::Arc;

use ethereum::TransactionAction;
use ethereum_types::{H160, H256, U256};
use jsonrpsee::core::RpcResult;
// Substrate
use sc_client_api::backend::{Backend, StorageProvider};
use sc_transaction_pool_api::{TransactionPool, TransactionSource};
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

use validation::{
	check_dry_run_exit, compute_effective_min_fee, validate_relay_calldata, MAX_FEE_PER_GAS_WEI,
	MIN_RELAY_FEE_FALLBACK, RELAY_GAS_LIMIT, SELECTORS_FALLBACK, SHIELDED_POOL_PRECOMPILE,
};

// ---------------------------------------------------------------------------
// Server struct
// ---------------------------------------------------------------------------

pub struct OrbinumRelay<B: BlockT, C, P, BE> {
	client: Arc<C>,
	pool: Arc<P>,
	signer: EthValidatorSigner,
	/// Serializes relay submissions AND tracks the optimistic next-nonce.
	///
	/// Why `Option<U256>` instead of `()`:
	///
	/// Each submission is: (1) read confirmed nonce, (2) sign, (3) submit. With a plain
	/// Mutex<()> two requests in the same block both read `confirmed = N`, sign with N,
	/// and the second submission fails with "nonce already used", burning gas for nothing.
	///
	/// By storing the last submitted nonce we can compute:
	///   actual_nonce = max(confirmed_nonce, memory_nonce)
	/// which allows multiple submissions within the same block to use N, N+1, N+2…
	/// On the next block `confirmed_nonce` catches up and `memory_nonce` resets naturally.
	///
	/// `None` = no submission has been made yet; read from runtime.
	submit_lock: Arc<tokio::sync::Mutex<Option<U256>>>,
	_phantom: std::marker::PhantomData<(B, BE)>,
}

impl<B, C, P, BE> OrbinumRelay<B, C, P, BE>
where
	B: BlockT,
{
	pub fn new(client: Arc<C>, pool: Arc<P>, signer: EthValidatorSigner) -> Self {
		Self {
			client,
			pool,
			signer,
			submit_lock: Arc::new(tokio::sync::Mutex::new(None)),
			_phantom: Default::default(),
		}
	}
}

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

		// Load fee/selector config from the runtime on every call so governance changes
		// (set_min_relay_fee extrinsic) take immediate effect without a node restart.
		// MIN_RELAY_FEE_FALLBACK is only used when the Runtime API call fails entirely.
		let best_hash = self.client.info().best_hash;
		let (min_fee_planck, allowed_selectors) = {
			match self.client.runtime_api().relay_config(best_hash) {
				Ok(cfg) => (cfg.min_fee_planck, cfg.allowed_selectors),
				Err(e) => {
					log::warn!(
						target: "orbinum-relay",
						"relay_config Runtime API unavailable, using fallback: {e}"
					);
					(MIN_RELAY_FEE_FALLBACK, SELECTORS_FALLBACK.to_vec())
				}
			}
		};

		// Compute 2× gas floor: the relay must earn at least twice what it spends on EVM gas.
		// 1 wei == 1 plank in Orbinum, so no unit conversion is required.
		// Saturate rather than `as_u128()`, which panics on a gas_price ≥ 2^128.
		// The value comes from the runtime, not calldata, but a panic here would
		// still take down the relay RPC — mirror the fee-word hardening in
		// operations.rs::fee_at_slot_6.
		let base_fee_wei: u128 = self
			.client
			.runtime_api()
			.gas_price(best_hash)
			.map(|p| p.try_into().unwrap_or(u128::MAX))
			.unwrap_or(0);
		let effective_min_fee = compute_effective_min_fee(min_fee_planck, base_fee_wei);

		if let Err(e) = validate_relay_calldata(&data, effective_min_fee, &allowed_selectors) {
			if e == "fee below minimum" {
				// Extract the fee from slot 6 for the log (validated length already).
				let provided_fee = if data.len() >= 228 {
					U256::from_big_endian(&data[196..228])
				} else {
					U256::zero()
				};
				log::warn!(
					target: "orbinum-relay",
					"relay rejected: fee below minimum — provided={provided_fee} required={effective_min_fee} (base_fee={base_fee_wei} governance={min_fee_planck})",
				);
			}
			return Err(internal_err(e));
		}

		// Dry-run: simulate the EVM call without broadcasting a transaction.
		// This catches invalid ZK proofs, already-spent nullifiers, and any other
		// on-chain rejection BEFORE the relayer signs and pays gas.
		{
			let relayer_addr = self.signer.address();
			let dry_result = self.client.runtime_api().call(
				best_hash,
				relayer_addr,
				H160::from(SHIELDED_POOL_PRECOMPILE),
				data.clone(),
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
					log::warn!(
						target: "orbinum-relay",
						"dry-run Runtime API error: {e}"
					);
					return Err(internal_err(format!("dry-run runtime error: {e}")));
				}
				Ok(Err(dispatch_err)) => {
					log::warn!(
						target: "orbinum-relay",
						"dry-run dispatch error: {dispatch_err:?}"
					);
					return Err(internal_err(format!(
						"calldata rejected by runtime: {dispatch_err:?}"
					)));
				}
				Ok(Ok(info)) => {
					if let Err(e) = check_dry_run_exit(&info.exit_reason) {
						log::warn!(
							target: "orbinum-relay",
							"dry-run EVM execution failed — exit={:?} revert_data={:?}",
							info.exit_reason,
							info.value
						);
						return Err(internal_err(e));
					}
				}
			}
		}

		// Hold the lock for the full sign-and-submit sequence.
		// The lock also carries the optimistic next-nonce so multiple submissions
		// within the same block don't collide on the same confirmed nonce.
		let mut nonce_guard = self.submit_lock.lock().await;

		let relayer_addr = self.signer.address();

		let (chain_id, nonce) = {
			let api = self.client.runtime_api();
			let chain_id = api
				.chain_id(best_hash)
				.map_err(|e| internal_err(format!("chain_id: {e}")))?;
			let confirmed_nonce = api
				.account_basic(best_hash, relayer_addr)
				.map_err(|e| internal_err(format!("account_basic: {e}")))?
				.nonce;
			// Use the in-memory nonce when it's ahead of the confirmed one.
			// This lets us submit N txs within a single block using nonces N, N+1, N+2…
			// Once the block is imported the confirmed nonce catches up naturally.
			let nonce = match *nonce_guard {
				Some(mem) if mem > confirmed_nonce => mem,
				_ => confirmed_nonce,
			};
			(chain_id, nonce)
		};

		let message = TransactionMessage::EIP1559(ethereum::EIP1559TransactionMessage {
			chain_id,
			nonce,
			max_priority_fee_per_gas: U256::from(1_000_000_000u64),
			max_fee_per_gas: U256::from(MAX_FEE_PER_GAS_WEI),
			gas_limit: U256::from(RELAY_GAS_LIMIT),
			action: TransactionAction::Call(H160::from(SHIELDED_POOL_PRECOMPILE)),
			value: U256::zero(),
			input: data,
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

		// Advance the in-memory nonce only after a successful submit.
		// On failure the nonce slot is still free and the next call will retry with
		// the same (or a freshly confirmed) nonce.
		if submit_result.is_ok() {
			*nonce_guard = Some(nonce + U256::one());
		}

		submit_result
	}

	async fn relayer_status(&self) -> RpcResult<RelayerStatus> {
		let best_hash = self.client.info().best_hash;
		let api = self.client.runtime_api();

		let min_fee_planck = api
			.relay_config(best_hash)
			.map(|cfg| cfg.min_fee_planck)
			.unwrap_or(MIN_RELAY_FEE_FALLBACK);

		// Saturate rather than `as_u128()` (panics ≥ 2^128) — see the sibling
		// call above; runtime-sourced, but a panic still kills the relay RPC.
		let base_fee_wei: u128 = api
			.gas_price(best_hash)
			.map(|p| p.try_into().unwrap_or(u128::MAX))
			.unwrap_or(0);
		let min_fee = compute_effective_min_fee(min_fee_planck, base_fee_wei);

		let balance = {
			api.account_basic(best_hash, self.signer.address())
				.map_err(|e| internal_err(format!("account_basic: {e}")))?
				.balance
		};
		// Capa 2: check whether this relay's EVM address is registered on-chain.
		let is_registered = api
			.is_relayer_evm(best_hash, self.signer.address().0)
			.unwrap_or(false);
		// Consider relay operational when it can cover at least one worst-case tx.
		let min_operational = U256::from(min_fee);
		Ok(RelayerStatus {
			address: self.signer.address(),
			min_fee: format!("{min_fee}"),
			balance_wei: format!("{balance}"),
			enabled: balance >= min_operational,
			is_registered,
		})
	}
}
