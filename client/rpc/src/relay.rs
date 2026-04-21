// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

//! Node-native EVM relay RPC.
//!
//! When the node is started with `--evm-relayer-key <hex>`, it exposes:
//!
//! - `orbinum_relayShieldedCall(calldata: "0x...")` → `txHash`
//! - `orbinum_relayerStatus()` → `{ address, minFee, balanceWei, enabled }`
//!
//! The relay only accepts calls to the ShieldedPool precompile
//! (`0x0000000000000000000000000000000000000801`) with selector
//! `0x47fc44a2` (unshield) or `0x8c0f5d24` (privateTransfer).
//! It checks the fee embedded in ABI slot 6 is ≥ the current `min_relay_fee` from
//! `pallet-relayer` (queried dynamically via Runtime API so forkless upgrades take effect immediately).

use std::sync::Arc;

use ethereum::TransactionAction;
use ethereum_types::{H160, H256, U256};
use jsonrpsee::core::RpcResult;
use jsonrpsee::proc_macros::rpc;
use serde::{Deserialize, Serialize};
// Substrate
use sc_client_api::backend::{Backend, StorageProvider};
use sc_transaction_pool_api::{TransactionPool, TransactionSource};
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_runtime::traits::Block as BlockT;
// Frontier
use fc_rpc_core::types::{Bytes, TransactionMessage};
use fp_evm::ExitReason;
use fp_rpc::{ConvertTransactionRuntimeApi, EthereumRuntimeRPCApi};
// Orbinum
use pallet_shielded_pool_runtime_api::ShieldedPoolRuntimeApi;

use crate::{internal_err, signer::EthValidatorSigner};

/// Maximum fee per gas paid by the relay tx (10 gwei).
/// Used when building the EIP-1559 transaction.
const MAX_FEE_PER_GAS_WEI: u64 = 10_000_000_000;

/// Gas limit used for relay transactions.
const RELAY_GAS_LIMIT: u64 = 2_000_000;

/// Last-resort fallback minimum fee used ONLY when the Runtime API call fails entirely.
///
/// The authoritative value lives in `pallet-relayer::MinRelayFee` storage and is
/// modifiable by governance via `set_min_relay_fee`. This constant is never used in
/// normal operation — it only kicks in if the node runs a pre-API runtime that does
/// not expose `relay_config()`.
///
/// Set to the same default as `pallet-relayer::DefaultMinRelayFee` (0.001 ORB) so all
/// three sources are identical out of the box.
const MIN_RELAY_FEE_FALLBACK: u128 = 1_000_000_000_000_000; // 0.001 ORB in planck

/// Static fallback selector whitelist for when the Runtime API is unavailable.
const SELECTORS_FALLBACK: [[u8; 4]; 2] = [
	[0x47, 0xfc, 0x44, 0xa2], // unshield
	[0x8c, 0x0f, 0x5d, 0x24], // privateTransfer
];

/// Maximum calldata size accepted by the relay (32 KB).
///
/// A realistic shielded-pool calldata is ~2–5 KB (256 B Groth16 proof + ABI head + Merkle path).
/// This cap prevents DoS: an attacker could craft calldata that passes selector/fee checks
/// but carries megabytes of data the relayer would have to pay calldata gas for.
const MAX_CALLDATA_BYTES: usize = 32_768;

/// ShieldedPool precompile: 0x0000000000000000000000000000000000000801
const SHIELDED_POOL_PRECOMPILE: [u8; 20] = [
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x08, 0x01,
];

// Keep the static selector names as test helpers (used in build_calldata).
#[cfg(test)]
const SELECTOR_UNSHIELD: [u8; 4] = [0x47, 0xfc, 0x44, 0xa2];
#[cfg(test)]
const SELECTOR_PRIVATE_TRANSFER: [u8; 4] = [0x8c, 0x0f, 0x5d, 0x24];

// ---------------------------------------------------------------------------
// Calldata validation (pure, no runtime deps — unit-testable)
// ---------------------------------------------------------------------------

/// Validates relay calldata against a runtime-provided minimum fee and selector whitelist.
///
/// `min_fee_wei`       — from `ShieldedPoolRuntimeApi::relay_config().min_fee_planck`
///                       (or `MIN_RELAY_FEE_FALLBACK` if the API is unavailable).
/// `allowed_selectors` — from `relay_config().allowed_selectors`.
///
/// Both `unshield` and `privateTransfer` share the same ABI head layout:
/// ```text
///  bytes [0..4]     selector
///  bytes [4..36]    slot 0  — offset pointer for proof (bytes/dynamic)
///  bytes [36..68]   slot 1  — bytes32  root
///  bytes [68..100]  slot 2  — bytes32  nullifier  / bytes32[] nullifiers offset
///  bytes [100..132] slot 3  — uint32   asset_id   / bytes32[] commits offset
///  bytes [132..164] slot 4  — uint256  amount     / bytes[]   memos offset
///  bytes [164..196] slot 5  — bytes32  recipient  / uint32    asset_id
///  bytes [196..228] slot 6  — uint256  fee        ← checked here
/// ```
/// Minimum head size = 4 + 7 × 32 = 228 bytes.
/// Computes the effective minimum fee the user must include in their calldata.
///
/// The relay must earn at least twice what it spends on EVM gas, so the floor is:
///   `2 × RELAY_GAS_LIMIT × base_fee_per_gas`
///
/// The governance-set `min_fee_planck` is the absolute lower bound; the 2× gas floor
/// applies on top whenever network gas prices are high enough to make it exceed governance.
/// Both values are in plank (= wei in Orbinum's 1:1 mapping).
pub(crate) fn compute_effective_min_fee(min_fee_planck: u128, base_fee_wei: u128) -> u128 {
	let two_x_gas_floor = (RELAY_GAS_LIMIT as u128)
		.saturating_mul(2)
		.saturating_mul(base_fee_wei);
	min_fee_planck.max(two_x_gas_floor)
}

pub(crate) fn validate_relay_calldata(
	data: &[u8],
	min_fee_wei: u128,
	allowed_selectors: &[[u8; 4]],
) -> Result<(), &'static str> {
	if data.len() < 228 {
		return Err("calldata too short");
	}
	if data.len() > MAX_CALLDATA_BYTES {
		return Err("calldata too large");
	}

	let selector: [u8; 4] = data[..4].try_into().unwrap();
	if !allowed_selectors.contains(&selector) {
		return Err("unsupported selector");
	}

	// Fee is in ABI slot 6 (7th param, 0-indexed): data[196..228].
	let fee_bytes: [u8; 32] = data[196..228].try_into().unwrap();
	let fee = U256::from_big_endian(&fee_bytes);
	if fee < U256::from(min_fee_wei) {
		return Err("fee below minimum");
	}

	Ok(())
}

/// Interprets the `exit_reason` from an EVM dry-run and returns whether the call
/// would succeed on-chain.
///
/// Returns `Ok(())` only when `exit_reason` is `ExitReason::Succeed(_)`.
/// All other outcomes (revert, error, fatal) return `Err` with a human-readable
/// description so callers can surface it to the user without paying gas.
pub(crate) fn check_dry_run_exit(exit_reason: &ExitReason) -> Result<(), String> {
	match exit_reason {
		ExitReason::Succeed(_) => Ok(()),
		other => Err(format!("calldata would fail on-chain: {other:?}")),
	}
}

// ---------------------------------------------------------------------------
// RPC trait
// ---------------------------------------------------------------------------

#[rpc(server)]
pub trait OrbinumRelayApi {
	/// Relay a shielded-pool call (unshield or privateTransfer) on behalf of a user.
	///
	/// `calldata` must be ABI-encoded EVM calldata for the ShieldedPool precompile,
	/// including the 4-byte selector. The fee in ABI slot index 6 must be ≥ MIN_RELAY_FEE_WEI.
	///
	/// Returns the Ethereum transaction hash.
	#[method(name = "orbinum_relayShieldedCall")]
	async fn relay_shielded_call(&self, calldata: Bytes) -> RpcResult<H256>;

	/// Returns the relay status: EVM address, minimum fee, current balance, and whether
	/// the relay has sufficient funds to process at least one transaction.
	#[method(name = "orbinum_relayerStatus")]
	async fn relayer_status(&self) -> RpcResult<RelayerStatus>;
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayerStatus {
	pub address: H160,
	pub min_fee: String,
	/// Current EVM balance of the relay wallet (wei). Lets callers verify the relay is funded.
	pub balance_wei: String,
	/// True only when balance ≥ MIN_RELAY_FEE_WEI (enough to cover at least one relay tx).
	pub enabled: bool,
}

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
	C::Api: EthereumRuntimeRPCApi<B> + ConvertTransactionRuntimeApi<B> + ShieldedPoolRuntimeApi<B>,
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
		let base_fee_wei: u128 = self
			.client
			.runtime_api()
			.gas_price(best_hash)
			.map(|p| p.as_u128())
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
				None, // nonce — not needed for simulation
				false, // estimate = false: real execution semantics
				None, // access_list
				None, // authorization_list
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

		let base_fee_wei: u128 = api
			.gas_price(best_hash)
			.map(|p| p.as_u128())
			.unwrap_or(0);
		let min_fee = compute_effective_min_fee(min_fee_planck, base_fee_wei);

		let balance = {
			api.account_basic(best_hash, self.signer.address())
				.map_err(|e| internal_err(format!("account_basic: {e}")))?
				.balance
		};
		// Consider relay operational when it can cover at least one worst-case tx.
		let min_operational = U256::from(min_fee);
		Ok(RelayerStatus {
			address: self.signer.address(),
			min_fee: format!("{min_fee}"),
			balance_wei: format!("{balance}"),
			enabled: balance >= min_operational,
		})
	}
}

// ---------------------------------------------------------------------------
// Unit tests — pure validation logic, no runtime required
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
	use super::*;

	/// Build minimal valid calldata for the given selector and fee.
	///
	/// Head layout (228 bytes total):
	/// ```text
	///  [0..4]     selector
	///  [4..36]    slot 0  — proof offset: 0xE0 (= 7×32 = 224, past all head slots)
	///  [36..68]   slot 1  — bytes32 zeroes (root)
	///  [68..100]  slot 2  — bytes32 zeroes (nullifier / nullifiers offset)
	///  [100..132] slot 3  — uint32  zeroes (assetId / commitments offset)
	///  [132..164] slot 4  — uint256 zeroes (amount / memos offset)
	///  [164..196] slot 5  — bytes32 zeroes (recipient / assetId)
	///  [196..228] slot 6  — uint256 fee
	/// ```
	fn build_calldata(selector: [u8; 4], fee_wei: u128) -> Vec<u8> {
		let mut data = vec![0u8; 228];
		data[..4].copy_from_slice(&selector);
		// Proof-bytes offset: 7×32 = 224 = 0xE0 (big-endian U256 → only last byte set)
		data[35] = 0xE0;
		// Fee at slot 6 = data[196..228]
		data[196..228].copy_from_slice(&U256::from(fee_wei).to_big_endian());
		data
	}

	// ── Length checks ──────────────────────────────────────────────────────

	#[test]
	fn rejects_empty_calldata() {
		assert_eq!(
			validate_relay_calldata(&[], MIN_RELAY_FEE_FALLBACK, &SELECTORS_FALLBACK),
			Err("calldata too short")
		);
	}

	#[test]
	fn rejects_calldata_227_bytes() {
		assert_eq!(
			validate_relay_calldata(&[0u8; 227], MIN_RELAY_FEE_FALLBACK, &SELECTORS_FALLBACK),
			Err("calldata too short")
		);
	}

	#[test]
	fn rejects_calldata_196_bytes_old_wrong_limit() {
		// Ensure the old (incorrect) limit of 196 is no longer accepted
		let data = vec![0u8; 196];
		assert_eq!(
			validate_relay_calldata(&data, MIN_RELAY_FEE_FALLBACK, &SELECTORS_FALLBACK),
			Err("calldata too short")
		);
	}

	// ── Selector checks ────────────────────────────────────────────────────

	#[test]
	fn rejects_unknown_selector() {
		let mut data = build_calldata(SELECTOR_UNSHIELD, MIN_RELAY_FEE_FALLBACK);
		data[..4].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
		assert_eq!(
			validate_relay_calldata(&data, MIN_RELAY_FEE_FALLBACK, &SELECTORS_FALLBACK),
			Err("unsupported selector")
		);
	}

	#[test]
	fn rejects_shield_selector() {
		// shield = 0x781442b9 — NOT in relay whitelist
		let mut data = build_calldata(SELECTOR_UNSHIELD, MIN_RELAY_FEE_FALLBACK);
		data[..4].copy_from_slice(&[0x78, 0x14, 0x42, 0xb9]);
		assert_eq!(
			validate_relay_calldata(&data, MIN_RELAY_FEE_FALLBACK, &SELECTORS_FALLBACK),
			Err("unsupported selector")
		);
	}

	// ── Fee checks ─────────────────────────────────────────────────────────

	#[test]
	fn rejects_zero_fee() {
		let data = build_calldata(SELECTOR_UNSHIELD, 0);
		assert_eq!(
			validate_relay_calldata(&data, MIN_RELAY_FEE_FALLBACK, &SELECTORS_FALLBACK),
			Err("fee below minimum")
		);
	}

	#[test]
	fn rejects_fee_one_wei_below_minimum() {
		let data = build_calldata(SELECTOR_UNSHIELD, MIN_RELAY_FEE_FALLBACK - 1);
		assert_eq!(
			validate_relay_calldata(&data, MIN_RELAY_FEE_FALLBACK, &SELECTORS_FALLBACK),
			Err("fee below minimum")
		);
	}

	#[test]
	fn rejects_fee_one_wei_below_minimum_private_transfer() {
		let data = build_calldata(SELECTOR_PRIVATE_TRANSFER, MIN_RELAY_FEE_FALLBACK - 1);
		assert_eq!(
			validate_relay_calldata(&data, MIN_RELAY_FEE_FALLBACK, &SELECTORS_FALLBACK),
			Err("fee below minimum")
		);
	}

	// ── Valid calldata ─────────────────────────────────────────────────────

	#[test]
	fn accepts_unshield_with_exact_minimum_fee() {
		let data = build_calldata(SELECTOR_UNSHIELD, MIN_RELAY_FEE_FALLBACK);
		assert_eq!(
			validate_relay_calldata(&data, MIN_RELAY_FEE_FALLBACK, &SELECTORS_FALLBACK),
			Ok(())
		);
	}

	#[test]
	fn accepts_private_transfer_with_exact_minimum_fee() {
		let data = build_calldata(SELECTOR_PRIVATE_TRANSFER, MIN_RELAY_FEE_FALLBACK);
		assert_eq!(
			validate_relay_calldata(&data, MIN_RELAY_FEE_FALLBACK, &SELECTORS_FALLBACK),
			Ok(())
		);
	}

	#[test]
	fn accepts_large_fee() {
		let data = build_calldata(SELECTOR_UNSHIELD, u128::MAX);
		assert_eq!(
			validate_relay_calldata(&data, MIN_RELAY_FEE_FALLBACK, &SELECTORS_FALLBACK),
			Ok(())
		);
	}

	#[test]
	fn accepts_calldata_longer_than_228_bytes() {
		let mut data = build_calldata(SELECTOR_UNSHIELD, MIN_RELAY_FEE_FALLBACK);
		// Append tail bytes (proof data and dynamic arrays)
		data.extend_from_slice(&[0xaa; 128]);
		assert_eq!(
			validate_relay_calldata(&data, MIN_RELAY_FEE_FALLBACK, &SELECTORS_FALLBACK),
			Ok(())
		);
	}

	// ── Fee is read from the correct position ──────────────────────────────

	#[test]
	fn fee_at_slot_5_is_not_read_as_fee() {
		// Put a value >= MIN_RELAY_FEE_FALLBACK in slot 5 (data[164..196]) but zero in slot 6
		let mut data = build_calldata(SELECTOR_UNSHIELD, 0);
		// Overwrite slot 5 with MIN_RELAY_FEE_FALLBACK (this is recipient in unshield — NOT the fee)
		data[164..196].copy_from_slice(&U256::from(MIN_RELAY_FEE_FALLBACK).to_big_endian());
		// Fee (slot 6, data[196..228]) is still zero → should reject
		assert_eq!(
			validate_relay_calldata(&data, MIN_RELAY_FEE_FALLBACK, &SELECTORS_FALLBACK),
			Err("fee below minimum")
		);
	}

	#[test]
	fn fee_at_slot_6_is_correctly_read() {
		// Slot 5 = zero, slot 6 = MIN_RELAY_FEE_FALLBACK → should accept
		let data = build_calldata(SELECTOR_UNSHIELD, MIN_RELAY_FEE_FALLBACK);
		assert_eq!(
			validate_relay_calldata(&data, MIN_RELAY_FEE_FALLBACK, &SELECTORS_FALLBACK),
			Ok(())
		);
	}

	// ── Calldata size upper bound ──────────────────────────────────────────

	#[test]
	fn rejects_calldata_above_max_size() {
		let mut data = build_calldata(SELECTOR_UNSHIELD, MIN_RELAY_FEE_FALLBACK);
		data.resize(MAX_CALLDATA_BYTES + 1, 0u8);
		assert_eq!(
			validate_relay_calldata(&data, MIN_RELAY_FEE_FALLBACK, &SELECTORS_FALLBACK),
			Err("calldata too large")
		);
	}

	#[test]
	fn accepts_calldata_at_exact_max_size() {
		let mut data = build_calldata(SELECTOR_UNSHIELD, MIN_RELAY_FEE_FALLBACK);
		data.resize(MAX_CALLDATA_BYTES, 0u8);
		assert_eq!(
			validate_relay_calldata(&data, MIN_RELAY_FEE_FALLBACK, &SELECTORS_FALLBACK),
			Ok(())
		);
	}

	// ── compute_effective_min_fee ──────────────────────────────────────────

	/// At zero base_fee the governance floor must win.
	#[test]
	fn effective_min_fee_zero_base_fee_returns_governance_floor() {
		assert_eq!(compute_effective_min_fee(MIN_RELAY_FEE_FALLBACK, 0), MIN_RELAY_FEE_FALLBACK);
	}

	/// At 10 gwei the 2× gas floor (40_000_000_000_000_000) must beat governance (0.001 ORB).
	#[test]
	fn effective_min_fee_gas_floor_dominates_at_10_gwei() {
		let base_fee = 10_000_000_000u128; // 10 gwei
		let expected = (RELAY_GAS_LIMIT as u128) * 2 * base_fee;
		assert!(expected > MIN_RELAY_FEE_FALLBACK, "test precondition: gas floor must exceed governance");
		assert_eq!(compute_effective_min_fee(MIN_RELAY_FEE_FALLBACK, base_fee), expected);
	}

	/// At 1 wei base_fee the gas floor (4_000_000) is far below governance (0.001 ORB).
	#[test]
	fn effective_min_fee_governance_floor_dominates_at_negligible_base_fee() {
		let base_fee = 1u128;
		let gas_floor = (RELAY_GAS_LIMIT as u128) * 2 * base_fee;
		assert!(MIN_RELAY_FEE_FALLBACK > gas_floor, "test precondition: governance must exceed gas floor");
		assert_eq!(compute_effective_min_fee(MIN_RELAY_FEE_FALLBACK, base_fee), MIN_RELAY_FEE_FALLBACK);
	}

	/// The crossover point is at base_fee = governance / (gas_limit × 2) = 250_000_000 (0.25 gwei).
	/// Below this threshold governance wins; at or above, the gas floor wins.
	#[test]
	fn effective_min_fee_crossover_at_250_mwei() {
		// threshold = 1_000_000_000_000_000 / (2_000_000 × 2) = 250_000_000
		let threshold = MIN_RELAY_FEE_FALLBACK / (RELAY_GAS_LIMIT as u128 * 2);
		// At threshold: 2×gas == governance, max returns governance.
		let at = compute_effective_min_fee(MIN_RELAY_FEE_FALLBACK, threshold);
		// One wei above: 2×gas > governance.
		let above = compute_effective_min_fee(MIN_RELAY_FEE_FALLBACK, threshold + 1);
		assert_eq!(at, MIN_RELAY_FEE_FALLBACK);
		assert!(above > MIN_RELAY_FEE_FALLBACK);
	}

	/// A governance floor higher than the gas floor must win regardless of base_fee.
	#[test]
	fn effective_min_fee_custom_high_governance_beats_gas_floor() {
		let governance = 100_000_000_000_000_000u128; // 0.1 ORB
		let base_fee = 1_000_000_000u128; // 1 gwei
		let gas_floor = (RELAY_GAS_LIMIT as u128) * 2 * base_fee;
		assert!(governance > gas_floor, "test precondition: governance must exceed gas floor");
		assert_eq!(compute_effective_min_fee(governance, base_fee), governance);
	}

	/// Saturating arithmetic must not panic on u128::MAX inputs.
	#[test]
	fn effective_min_fee_saturates_without_panic() {
		let result = compute_effective_min_fee(u128::MAX, u128::MAX);
		assert_eq!(result, u128::MAX);
	}

	/// The calldata fee must be validated against `effective_min_fee`, not raw `min_fee_planck`.
	/// Simulates the scenario where the gas floor is the active minimum.
	#[test]
	fn validate_calldata_rejects_fee_below_gas_floor_even_above_governance() {
		let governance = MIN_RELAY_FEE_FALLBACK;
		let base_fee = 10_000_000_000u128; // 10 gwei
		let gas_floor = (RELAY_GAS_LIMIT as u128) * 2 * base_fee; // 40_000_000_000_000_000
		assert!(gas_floor > governance);
		let effective = compute_effective_min_fee(governance, base_fee);
		// A fee that clears governance but not the gas floor is rejected.
		let below_gas_floor = gas_floor - 1;
		let data = build_calldata(SELECTOR_UNSHIELD, below_gas_floor);
		assert_eq!(
			validate_relay_calldata(&data, effective, &SELECTORS_FALLBACK),
			Err("fee below minimum")
		);
	}

	/// Fee that exactly equals the gas floor (when it dominates) must be accepted.
	#[test]
	fn validate_calldata_accepts_exact_gas_floor() {
		let governance = MIN_RELAY_FEE_FALLBACK;
		let base_fee = 10_000_000_000u128; // 10 gwei
		let effective = compute_effective_min_fee(governance, base_fee);
		let data = build_calldata(SELECTOR_UNSHIELD, effective);
		assert_eq!(
			validate_relay_calldata(&data, effective, &SELECTORS_FALLBACK),
			Ok(())
		);
	}

	// ── check_dry_run_exit ─────────────────────────────────────────────────

	/// A successful EVM execution must pass the dry-run check.
	#[test]
	fn dry_run_exit_succeed_returns_ok() {
		use evm::ExitSucceed;
		assert!(check_dry_run_exit(&ExitReason::Succeed(ExitSucceed::Returned)).is_ok());
		assert!(check_dry_run_exit(&ExitReason::Succeed(ExitSucceed::Stopped)).is_ok());
		assert!(check_dry_run_exit(&ExitReason::Succeed(ExitSucceed::Suicided)).is_ok());
	}

	/// A revert (invalid ZK proof, double-spend nullifier, etc.) must be rejected.
	#[test]
	fn dry_run_exit_revert_returns_err() {
		use evm::ExitRevert;
		let result = check_dry_run_exit(&ExitReason::Revert(ExitRevert::Reverted));
		assert!(result.is_err());
		let msg = result.unwrap_err();
		assert!(
			msg.contains("calldata would fail on-chain"),
			"expected 'calldata would fail on-chain' in: {msg}"
		);
		assert!(msg.contains("Revert"), "expected 'Revert' in: {msg}");
	}

	/// An EVM error (OutOfGas, etc.) must be rejected.
	#[test]
	fn dry_run_exit_error_out_of_gas_returns_err() {
		use evm::ExitError;
		let result = check_dry_run_exit(&ExitReason::Error(ExitError::OutOfGas));
		assert!(result.is_err());
		let msg = result.unwrap_err();
		assert!(msg.contains("calldata would fail on-chain"), "{msg}");
		assert!(msg.contains("OutOfGas"), "expected 'OutOfGas' in: {msg}");
	}

	/// A call-too-deep EVM error (stack overflow) must be rejected.
	#[test]
	fn dry_run_exit_error_call_too_deep_returns_err() {
		use evm::ExitError;
		let result = check_dry_run_exit(&ExitReason::Error(ExitError::CallTooDeep));
		assert!(result.is_err());
		assert!(result.unwrap_err().contains("CallTooDeep"));
	}

	/// A fatal EVM error must be rejected.
	#[test]
	fn dry_run_exit_fatal_returns_err() {
		use evm::ExitFatal;
		let result = check_dry_run_exit(&ExitReason::Fatal(ExitFatal::NotSupported));
		assert!(result.is_err());
		let msg = result.unwrap_err();
		assert!(msg.contains("calldata would fail on-chain"), "{msg}");
		assert!(msg.contains("Fatal"), "expected 'Fatal' in: {msg}");
	}

	/// The error message must embed the exit reason so callers can surface it to users.
	#[test]
	fn dry_run_exit_error_message_includes_reason() {
		use evm::ExitError;
		let reason = ExitReason::Error(ExitError::OutOfFund);
		let err = check_dry_run_exit(&reason).unwrap_err();
		// The message should contain both the prefix and the specific variant.
		assert!(err.starts_with("calldata would fail on-chain:"), "{err}");
		assert!(err.contains("OutOfFund"), "{err}");
	}
}
