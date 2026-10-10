//! Privacy RPC — Orbinum shielded pool.
//!
//! Endpoints:
//! - `privacy_getMerkleRoot`              — current Merkle root as hex
//! - `privacy_getMerkleProof`             — sibling path for a leaf index
//! - `privacy_getMerkleProofByCommitment` — sibling path for a commitment
//! - `privacy_getNullifierStatus`         — whether a nullifier has been spent
//! - `privacy_getPoolStats`               — aggregate pool statistics
//!
//! The two proof endpoints run on blocking threads and at most
//! `MAX_CONCURRENT_PROOFS` at once: a sealed tree's path is rebuilt from
//! leaves, and inline on the connection task a few of them would stall every
//! other RPC.

use jsonrpsee::{
	core::RpcResult,
	proc_macros::rpc,
	types::error::{ErrorCode, ErrorObject},
};
use pallet_shielded_pool::DEFAULT_TREE_DEPTH;
use pallet_shielded_pool_runtime_api::ShieldedPoolRuntimeApi;
use sc_client_api::StorageProvider as ScStorageProvider;
use scale_codec::Decode;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sp_api::{ApiExt, ProvideRuntimeApi};

/// `u128` serde helper: serialises as a decimal string so JavaScript clients
/// can parse values larger than `Number.MAX_SAFE_INTEGER` without precision loss.
mod serde_u128_str {
	use super::*;

	pub fn serialize<S: Serializer>(v: &u128, s: S) -> Result<S::Ok, S::Error> {
		s.serialize_str(&v.to_string())
	}

	pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<u128, D::Error> {
		String::deserialize(d)?
			.parse::<u128>()
			.map_err(serde::de::Error::custom)
	}
}
use sp_blockchain::HeaderBackend;
use sp_core::{storage::StorageKey, H256};
use sp_crypto_hashing::{blake2_128, twox_128};
use sp_runtime::traits::Block as BlockT;
use std::{
	marker::PhantomData,
	sync::{Arc, Condvar, Mutex, MutexGuard},
	time::{Duration, Instant},
};

// ============================================================================
// Storage key helpers
// ============================================================================

const PALLET: &[u8] = b"ShieldedPool";

/// Builds `twox_128(pallet) ++ twox_128(item)` (32 bytes — `StorageValue` key).
fn value_key(item: &[u8]) -> Vec<u8> {
	[twox_128(PALLET), twox_128(item)].concat()
}

/// Builds `twox_128(pallet) ++ twox_128(item) ++ blake2_128_concat(map_key)`
/// (standard `StorageMap` key with `Blake2_128Concat` hasher).
fn map_key(item: &[u8], k: &[u8]) -> Vec<u8> {
	let mut key = value_key(item);
	key.extend_from_slice(&blake2_128(k)); // 16-byte hash
	key.extend_from_slice(k); // original key
	key
}

// ============================================================================
// Response types
// ============================================================================

/// Level-6 subtree roots of one tree (`privacy_getSubtreeRoots`).
///
/// Every root but the last of an active tree is final. Past the last block the
/// nodes are the zero hash; the response omits them.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubtreeRootsResponse {
	pub tree_id: u32,
	/// Level of the roots: each covers `2^level` leaves.
	pub level: u8,
	/// Leaves in the tree: the capacity once sealed.
	pub tree_leaves: u32,
	pub sealed: bool,
	/// Root the tree anchors to at the same state (`0x`-prefixed hex).
	pub root: String,
	/// Index of `roots[0]` within the level.
	pub start: u32,
	/// `0x`-prefixed hex, little-endian field elements.
	pub roots: Vec<String>,
}

/// Response for `privacy_getMerkleProof`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleProofResponse {
	/// Root the leaf's tree anchors to, read at the same block as the proof
	/// (`0x`-prefixed hex): the permanent sealed root for completed trees,
	/// the live root for the active tree.
	pub root: String,
	/// Sibling path — 20 `0x`-prefixed hex strings.
	pub path: Vec<String>,
	/// Leaf index used to generate this proof.
	pub leaf_index: u32,
	/// Tree depth (always 20 for circuit compatibility).
	pub tree_depth: u32,
	/// Forest tree the leaf belongs to (0 until the first tree seals).
	pub tree_id: u32,
}

/// Response for `privacy_getNullifierStatus`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NullifierStatusResponse {
	/// Nullifier as `0x`-prefixed hex.
	pub nullifier: String,
	/// `true` if the nullifier has been spent.
	pub is_spent: bool,
}

/// Per-asset balance entry for `privacy_getPoolStats`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetBalanceResponse {
	pub asset_id: u32,
	/// Serialised as a decimal string to preserve precision in JS (u128 can exceed
	/// `Number.MAX_SAFE_INTEGER` for large balances with 18 decimals).
	#[serde(with = "serde_u128_str")]
	pub balance: u128,
}

/// Response for `privacy_getPoolStats`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PoolStatsResponse {
	pub merkle_root: String,
	pub commitment_count: u32,
	pub nullifier_count: u64,
	/// Serialised as a decimal string to preserve precision in JS.
	#[serde(with = "serde_u128_str")]
	pub total_balance: u128,
	pub asset_balances: Vec<AssetBalanceResponse>,
	pub tree_depth: u32,
}

// ============================================================================
// RPC trait
// ============================================================================

#[rpc(server)]
pub trait PrivacyApi {
	/// Returns the current Merkle tree root as a `0x`-prefixed hex string.
	#[method(name = "privacy_getMerkleRoot")]
	fn get_merkle_root(&self) -> RpcResult<String>;

	/// Returns a Merkle sibling-path proof for the leaf at `leaf_index`.
	#[method(name = "privacy_getMerkleProof", blocking)]
	fn get_merkle_proof(&self, leaf_index: u32) -> RpcResult<MerkleProofResponse>;

	/// Returns a Merkle sibling-path proof for the given commitment (`0x`-prefixed hex, 32 bytes).
	/// Resolves the leaf index via the on-chain reverse index (O(1)), then reads
	/// the stored siblings, rebuilding a sealed tree's pruned ones from its
	/// leaves. Root and path come from the same block. Returns an error if the
	/// commitment is not found in the tree.
	#[method(name = "privacy_getMerkleProofByCommitment", blocking)]
	fn get_merkle_proof_by_commitment(&self, commitment: String) -> RpcResult<MerkleProofResponse>;

	/// Up to `count` (at most 4096) level-6 subtree roots of tree `tree_id` from
	/// `start`, with the root the tree anchors to, so a wallet can build Merkle
	/// paths itself. Needs runtime API v4.
	#[method(name = "privacy_getSubtreeRoots", blocking)]
	fn get_subtree_roots(
		&self,
		tree_id: u32,
		start: u32,
		count: u32,
	) -> RpcResult<SubtreeRootsResponse>;

	/// Returns whether the nullifier (`0x`-prefixed hex, 32 bytes) has been spent.
	#[method(name = "privacy_getNullifierStatus")]
	fn get_nullifier_status(&self, nullifier: String) -> RpcResult<NullifierStatusResponse>;

	/// Returns aggregate statistics for the shielded pool.
	#[method(name = "privacy_getPoolStats")]
	fn get_pool_stats(&self) -> RpcResult<PoolStatsResponse>;
}

// ============================================================================
// RPC server
// ============================================================================

/// Merkle proofs a request may wait behind before it is refused as busy.
///
/// Each waiting request holds a thread of the RPC's blocking pool (512 by
/// default), so this stays well below it. Full, the queue drains in a fraction
/// of a second; more than this at once is abuse, not load.
const MAX_QUEUED_PROOFS: usize = 128;

/// The longest a request waits for a slot. A full queue drains far sooner, so
/// running out of time means the node itself is saturated.
const MAX_PROOF_WAIT: Duration = Duration::from_secs(2);

/// Merkle proofs computed at once on a machine of `cores` cores: half of them,
/// at least one. A proof is pure CPU (Poseidon over a sealed tree's leaves), and
/// the other half stays free for importing and authoring blocks, GRANDPA,
/// networking and the rest of the RPC.
fn proof_slots(cores: usize) -> usize {
	(cores / 2).max(1)
}

/// Privacy RPC server for the Orbinum shielded pool.
pub struct PrivacyRpc<C, B, BE> {
	client: Arc<C>,
	proofs: ProofGate,
	_ph: PhantomData<(B, BE)>,
}

impl<C, B, BE> PrivacyRpc<C, B, BE> {
	pub fn new(client: Arc<C>) -> Self {
		Self {
			client,
			proofs: ProofGate::new(
				proof_slots(std::thread::available_parallelism().map_or(1, |n| n.get())),
				MAX_QUEUED_PROOFS,
				MAX_PROOF_WAIT,
			),
			_ph: PhantomData,
		}
	}
}

/// Caps how many proofs run at once, queueing the rest.
///
/// A request takes a free slot, or waits for one behind at most `max_queued`
/// others and for at most `max_wait`; it is refused only when the queue is full
/// or the wait runs out. Both proof RPCs are `blocking`, so each waits on its own
/// thread. A slot is freed when its permit drops, even if the proof panics.
struct ProofGate {
	state: Mutex<GateState>,
	freed: Condvar,
	slots: usize,
	max_queued: usize,
	max_wait: Duration,
}

#[derive(Default)]
struct GateState {
	in_flight: usize,
	waiting: usize,
}

struct ProofPermit<'a>(&'a ProofGate);

impl ProofGate {
	fn new(slots: usize, max_queued: usize, max_wait: Duration) -> Self {
		Self {
			state: Mutex::default(),
			freed: Condvar::new(),
			slots: slots.max(1),
			max_queued,
			max_wait,
		}
	}

	/// The state, recovered if a holder panicked: two counters cannot be left
	/// inconsistent by a panic between lock and unlock.
	fn lock(&self) -> MutexGuard<'_, GateState> {
		self.state.lock().unwrap_or_else(|e| e.into_inner())
	}

	/// A permit, waiting for a slot if needed; `None` when the queue is full or
	/// no slot frees up within `max_wait`.
	fn enter(&self) -> Option<ProofPermit<'_>> {
		let mut state = self.lock();
		if state.in_flight < self.slots {
			state.in_flight += 1;
			return Some(ProofPermit(self));
		}
		if state.waiting >= self.max_queued {
			return None;
		}
		state.waiting += 1;
		let deadline = Instant::now() + self.max_wait;
		let got_slot = loop {
			if state.in_flight < self.slots {
				break true;
			}
			let Some(left) = deadline.checked_duration_since(Instant::now()) else {
				break false;
			};
			state = self
				.freed
				.wait_timeout(state, left)
				.unwrap_or_else(|e| e.into_inner())
				.0;
		};
		state.waiting -= 1;
		if got_slot {
			state.in_flight += 1;
		}
		got_slot.then(|| ProofPermit(self))
	}
}

impl Drop for ProofPermit<'_> {
	fn drop(&mut self) {
		self.0.lock().in_flight -= 1;
		self.0.freed.notify_one();
	}
}

// ============================================================================
// Error helpers
// ============================================================================

fn internal_error(msg: impl std::fmt::Display) -> ErrorObject<'static> {
	ErrorObject::owned(
		ErrorCode::InternalError.code(),
		format!("Internal error: {msg}"),
		None::<()>,
	)
}

fn invalid_params(msg: impl std::fmt::Display) -> ErrorObject<'static> {
	ErrorObject::owned(
		ErrorCode::InvalidParams.code(),
		format!("Invalid params: {msg}"),
		None::<()>,
	)
}

fn pool_not_initialized() -> ErrorObject<'static> {
	ErrorObject::owned(
		ErrorCode::InternalError.code(),
		"Shielded pool is not initialized",
		None::<()>,
	)
}

/// The proof queue is full, or no slot freed up in time.
fn busy() -> ErrorObject<'static> {
	ErrorObject::owned(
		ErrorCode::ServerIsBusy.code(),
		"Merkle proof queue is full, try again later",
		None::<()>,
	)
}

fn pool_is_empty() -> ErrorObject<'static> {
	ErrorObject::owned(
		ErrorCode::InternalError.code(),
		"Shielded pool has no commitments",
		None::<()>,
	)
}

// ============================================================================
// Storage helper — shared across all handler methods
// ============================================================================

fn read_storage<B: BlockT, C: ScStorageProvider<B, BE>, BE: sc_client_api::Backend<B>>(
	client: &C,
	hash: B::Hash,
	key: Vec<u8>,
) -> RpcResult<Option<Vec<u8>>> {
	ScStorageProvider::storage(client, hash, &StorageKey(key))
		.map_err(internal_error)
		.map(|opt| opt.map(|data| data.0))
}

// ============================================================================
// PrivacyApiServer implementation
// ============================================================================

impl<C, B, BE> PrivacyApiServer for PrivacyRpc<C, B, BE>
where
	C: HeaderBackend<B> + ScStorageProvider<B, BE> + ProvideRuntimeApi<B> + Send + Sync + 'static,
	C::Api: ShieldedPoolRuntimeApi<B>,
	B: BlockT,
	BE: sc_client_api::Backend<B> + Send + Sync + 'static,
{
	fn get_merkle_root(&self) -> RpcResult<String> {
		let best_hash = self.client.info().best_hash;

		let data = read_storage(&*self.client, best_hash, value_key(b"PoseidonRoot"))?
			.ok_or_else(pool_not_initialized)?;

		let root = H256::decode(&mut &data[..]).map_err(internal_error)?;
		Ok(format!("0x{}", hex::encode(root.as_bytes())))
	}

	fn get_merkle_proof(&self, leaf_index: u32) -> RpcResult<MerkleProofResponse> {
		let _permit = self.proofs.enter().ok_or_else(busy)?;
		// Both runtime-API calls execute at the same block, so root and path
		// can never mismatch.
		let best_hash = self.client.info().best_hash;
		let api = self.client.runtime_api();

		let (_, tree_size, tree_depth) = api
			.get_merkle_tree_info(best_hash)
			.map_err(internal_error)?;

		if tree_size == 0 {
			return Err(pool_is_empty());
		}
		if leaf_index >= tree_size {
			return Err(invalid_params(format!(
				"leaf_index {leaf_index} >= tree_size {tree_size}"
			)));
		}

		let proof = api
			.get_merkle_proof(best_hash, leaf_index)
			.map_err(internal_error)?
			.ok_or_else(|| internal_error(format!("no proof for leaf_index {leaf_index}")))?;

		// Sealed trees anchor to their permanent root, not the active one.
		// A missing entry for an existing leaf means broken sealed-root state;
		// erroring beats silently serving the wrong anchor.
		let (root, tree_id) = api
			.get_root_for_leaf(best_hash, leaf_index)
			.map_err(internal_error)?
			.ok_or_else(|| {
				internal_error(format!("no anchoring root for leaf_index {leaf_index}"))
			})?;

		Ok(MerkleProofResponse {
			root: format!("0x{}", hex::encode(root)),
			path: proof
				.siblings
				.iter()
				.map(|s| format!("0x{}", hex::encode(s)))
				.collect(),
			leaf_index,
			tree_depth,
			tree_id,
		})
	}

	fn get_merkle_proof_by_commitment(&self, commitment: String) -> RpcResult<MerkleProofResponse> {
		let _permit = self.proofs.enter().ok_or_else(busy)?;
		let best_hash = self.client.info().best_hash;
		let api = self.client.runtime_api();

		// Parse commitment hex
		let hex_str = commitment.trim_start_matches("0x");
		let bytes =
			hex::decode(hex_str).map_err(|_| invalid_params("commitment must be valid hex"))?;
		if bytes.len() != 32 {
			return Err(invalid_params(
				"commitment must be exactly 32 bytes (64 hex chars)",
			));
		}
		let target = H256::from_slice(&bytes);

		let (_, tree_size, tree_depth) = api
			.get_merkle_tree_info(best_hash)
			.map_err(internal_error)?;

		if tree_size == 0 {
			return Err(pool_is_empty());
		}

		let (leaf_index, proof) = api
			.get_merkle_proof_for_commitment(best_hash, target.into())
			.map_err(internal_error)?
			.ok_or_else(|| {
				invalid_params(format!(
					"commitment 0x{hex_str} not found in the Merkle tree"
				))
			})?;

		// Sealed trees anchor to their permanent root, not the active one.
		// A missing entry for an existing leaf means broken sealed-root state;
		// erroring beats silently serving the wrong anchor.
		let (root, tree_id) = api
			.get_root_for_leaf(best_hash, leaf_index)
			.map_err(internal_error)?
			.ok_or_else(|| {
				internal_error(format!("no anchoring root for leaf_index {leaf_index}"))
			})?;

		Ok(MerkleProofResponse {
			root: format!("0x{}", hex::encode(root)),
			path: proof
				.siblings
				.iter()
				.map(|s| format!("0x{}", hex::encode(s)))
				.collect(),
			leaf_index,
			tree_depth,
			tree_id,
		})
	}

	fn get_subtree_roots(
		&self,
		tree_id: u32,
		start: u32,
		count: u32,
	) -> RpcResult<SubtreeRootsResponse> {
		let _permit = self.proofs.enter().ok_or_else(busy)?;
		let best_hash = self.client.info().best_hash;
		let api = self.client.runtime_api();
		let version = api
			.api_version::<dyn ShieldedPoolRuntimeApi<B>>(best_hash)
			.map_err(internal_error)?
			.unwrap_or(0);
		if version < 4 {
			return Err(internal_error("subtree roots need runtime API v4"));
		}
		let found = api
			.get_subtree_roots(best_hash, tree_id, start, count)
			.map_err(internal_error)?
			.ok_or_else(|| invalid_params(format!("tree {tree_id} does not exist")))?;
		let hex32 = |h: [u8; 32]| format!("0x{}", hex::encode(h));
		Ok(SubtreeRootsResponse {
			tree_id: found.tree_id,
			level: pallet_shielded_pool::SUBTREE_LEVEL,
			tree_leaves: found.tree_leaves,
			sealed: found.sealed,
			root: hex32(found.root),
			start: found.start,
			roots: found.roots.into_iter().map(hex32).collect(),
		})
	}

	fn get_nullifier_status(&self, nullifier: String) -> RpcResult<NullifierStatusResponse> {
		let best_hash = self.client.info().best_hash;

		let hex_str = nullifier.trim_start_matches("0x");
		let bytes =
			hex::decode(hex_str).map_err(|_| invalid_params("nullifier must be valid hex"))?;
		if bytes.len() != 32 {
			return Err(invalid_params(
				"nullifier must be exactly 32 bytes (64 hex chars)",
			));
		}
		let null_h256 = H256::from_slice(&bytes);

		let data = read_storage(
			&*self.client,
			best_hash,
			map_key(b"NullifierSet", null_h256.as_bytes()),
		)?;

		Ok(NullifierStatusResponse {
			nullifier: format!("0x{}", hex::encode(&bytes)),
			is_spent: data.is_some(),
		})
	}

	fn get_pool_stats(&self) -> RpcResult<PoolStatsResponse> {
		let best_hash = self.client.info().best_hash;

		// Merkle root
		let root_data = read_storage(&*self.client, best_hash, value_key(b"PoseidonRoot"))?
			.ok_or_else(pool_not_initialized)?;
		let root = H256::decode(&mut &root_data[..]).map_err(internal_error)?;

		// Tree size
		let size_data = read_storage(&*self.client, best_hash, value_key(b"MerkleTreeSize"))?
			.ok_or_else(pool_not_initialized)?;
		let commitment_count = u32::decode(&mut &size_data[..]).map_err(internal_error)?;

		if commitment_count == 0 {
			return Err(pool_is_empty());
		}

		// Next asset ID — drives the per-asset balance scan
		let next_id_data = read_storage(&*self.client, best_hash, value_key(b"NextAssetId"))?
			.ok_or_else(pool_not_initialized)?;
		let next_asset_id = u32::decode(&mut &next_id_data[..]).map_err(internal_error)?;

		// Aggregate per-asset balances
		let mut asset_balances: Vec<AssetBalanceResponse> = Vec::new();
		let mut total_balance: u128 = 0;

		for asset_id in 0..next_asset_id {
			let data = read_storage(
				&*self.client,
				best_hash,
				map_key(b"PoolBalancePerAsset", &asset_id.to_le_bytes()),
			)?;
			if let Some(raw) = data {
				let balance = u128::decode(&mut &raw[..]).map_err(internal_error)?;
				if balance > 0 {
					total_balance = total_balance
						.checked_add(balance)
						.ok_or_else(|| internal_error("pool balance overflow"))?;
					asset_balances.push(AssetBalanceResponse { asset_id, balance });
				}
			}
		}

		// Nullifier count — O(1) read of TotalNullifiersSpent counter.
		// Defaults to 0 if the storage item is absent (pool with no spent notes yet).
		let nullifier_count =
			match read_storage(&*self.client, best_hash, value_key(b"TotalNullifiersSpent"))? {
				Some(raw) => u64::decode(&mut &raw[..]).unwrap_or(0),
				None => 0,
			};

		Ok(PoolStatsResponse {
			merkle_root: format!("0x{}", hex::encode(root.as_bytes())),
			commitment_count,
			nullifier_count,
			total_balance,
			asset_balances,
			tree_depth: DEFAULT_TREE_DEPTH as u32,
		})
	}
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
	use super::*;
	use sp_crypto_hashing::twox_128;

	// -------------------------------------------------------------------------
	// Proof concurrency gate
	// -------------------------------------------------------------------------

	mod proof_gate {
		use super::*;

		use std::{
			sync::atomic::{AtomicUsize, Ordering},
			thread,
		};

		fn counters(gate: &ProofGate) -> (usize, usize) {
			let s = gate.lock();
			(s.in_flight, s.waiting)
		}

		#[test]
		fn half_the_cores_at_least_one() {
			for (cores, slots) in [
				(0, 1),
				(1, 1),
				(2, 1),
				(3, 1),
				(4, 2),
				(8, 4),
				(16, 8),
				(64, 32),
			] {
				assert_eq!(proof_slots(cores), slots, "{cores} cores");
			}
		}

		#[test]
		fn a_free_slot_is_taken_without_waiting() {
			let gate = ProofGate::new(2, 0, Duration::ZERO);
			let a = gate.enter().expect("first slot");
			let b = gate.enter().expect("second slot");
			assert_eq!(counters(&gate), (2, 0));
			drop((a, b));
			assert_eq!(counters(&gate), (0, 0));
		}

		/// With no queue, a request past the slots is refused at once.
		#[test]
		fn a_full_queue_refuses_at_once() {
			let gate = ProofGate::new(1, 0, Duration::from_secs(60));
			let _held = gate.enter().unwrap();
			let start = Instant::now();
			assert!(gate.enter().is_none());
			assert!(
				start.elapsed() < Duration::from_millis(100),
				"it must not wait"
			);
		}

		#[test]
		fn a_waiter_takes_the_slot_a_permit_frees() {
			let gate = Arc::new(ProofGate::new(1, 4, Duration::from_secs(10)));
			let held = gate.enter().unwrap();
			let waiter = {
				let gate = gate.clone();
				thread::spawn(move || gate.enter().map(drop).is_some())
			};
			while counters(&gate).1 == 0 {
				thread::yield_now();
			}
			drop(held);
			assert!(waiter.join().unwrap(), "the waiter gets the freed slot");
			assert_eq!(counters(&gate), (0, 0));
		}

		#[test]
		fn a_wait_past_the_deadline_is_refused() {
			let gate = ProofGate::new(1, 4, Duration::from_millis(50));
			let _held = gate.enter().unwrap();
			let start = Instant::now();
			assert!(gate.enter().is_none());
			assert!(start.elapsed() >= Duration::from_millis(50));
			assert_eq!(counters(&gate), (1, 0), "the waiter leaves the queue");
		}

		/// A burst far larger than the slots, within the queue: every request is
		/// served, never more than `slots` at once.
		#[test]
		fn a_burst_within_the_queue_is_all_served() {
			let gate = Arc::new(ProofGate::new(3, 64, Duration::from_secs(10)));
			let running = Arc::new(AtomicUsize::new(0));
			let peak = Arc::new(AtomicUsize::new(0));
			let served: usize = (0..64)
				.map(|_| {
					let (gate, running, peak) = (gate.clone(), running.clone(), peak.clone());
					thread::spawn(move || {
						let Some(_permit) = gate.enter() else {
							return 0;
						};
						let now = running.fetch_add(1, Ordering::SeqCst) + 1;
						peak.fetch_max(now, Ordering::SeqCst);
						thread::sleep(Duration::from_millis(2));
						running.fetch_sub(1, Ordering::SeqCst);
						1
					})
				})
				.collect::<Vec<_>>()
				.into_iter()
				.map(|h| h.join().unwrap())
				.sum();
			assert_eq!(served, 64);
			assert_eq!(peak.load(Ordering::SeqCst), 3);
			assert_eq!(counters(&gate), (0, 0));
		}

		/// Past slots + queue, the excess is refused and the rest served.
		#[test]
		fn a_burst_past_the_queue_refuses_only_the_excess() {
			let gate = Arc::new(ProofGate::new(2, 8, Duration::from_secs(10)));
			let held: Vec<_> = (0..2).map(|_| gate.enter().unwrap()).collect();
			let waiters: Vec<_> = (0..8)
				.map(|_| {
					let gate = gate.clone();
					thread::spawn(move || gate.enter().map(drop).is_some())
				})
				.collect();
			while counters(&gate).1 < 8 {
				thread::yield_now();
			}
			assert!(gate.enter().is_none(), "the queue is full");
			drop(held);
			assert!(waiters.into_iter().all(|w| w.join().unwrap()));
			assert_eq!(counters(&gate), (0, 0));
		}

		#[test]
		fn a_panicking_proof_frees_its_slot() {
			let gate = Arc::new(ProofGate::new(1, 0, Duration::ZERO));
			let g = gate.clone();
			let _ = thread::spawn(move || {
				let _permit = g.enter().unwrap();
				panic!("proof failed");
			})
			.join();
			assert!(gate.enter().is_some(), "the slot came back");
		}

		#[test]
		fn the_busy_error_is_the_standard_server_busy_code() {
			assert_eq!(busy().code(), ErrorCode::ServerIsBusy.code());
		}
	}

	// -------------------------------------------------------------------------
	// Storage key helpers
	// -------------------------------------------------------------------------

	mod storage_keys {
		use super::*;

		#[test]
		fn value_key_is_32_bytes() {
			assert_eq!(value_key(b"PoseidonRoot").len(), 32);
			assert_eq!(value_key(b"MerkleTreeSize").len(), 32);
			assert_eq!(value_key(b"NextAssetId").len(), 32);
		}

		#[test]
		fn value_key_is_deterministic() {
			assert_eq!(value_key(b"PoseidonRoot"), value_key(b"PoseidonRoot"));
		}

		#[test]
		fn value_key_starts_with_pallet_prefix() {
			let pallet_prefix = twox_128(b"ShieldedPool");
			let key = value_key(b"PoseidonRoot");
			assert_eq!(&key[..16], &pallet_prefix);
		}

		#[test]
		fn value_key_differs_per_item() {
			assert_ne!(value_key(b"PoseidonRoot"), value_key(b"MerkleTreeSize"));
			assert_ne!(value_key(b"MerkleTreeSize"), value_key(b"NextAssetId"));
		}

		#[test]
		fn map_key_for_u32_is_52_bytes() {
			// 32 prefix + 16 blake2_128 hash + 4 LE bytes
			let key = map_key(b"MerkleLeaves", &0u32.to_le_bytes());
			assert_eq!(key.len(), 52);
		}

		#[test]
		fn map_key_for_h256_is_80_bytes() {
			// 32 prefix + 16 blake2_128 hash + 32 H256 bytes
			let key = map_key(b"NullifierSet", &[0u8; 32]);
			assert_eq!(key.len(), 80);
		}

		#[test]
		fn map_key_shares_prefix_with_value_key_of_same_item() {
			let vk = value_key(b"MerkleLeaves");
			let mk = map_key(b"MerkleLeaves", &0u32.to_le_bytes());
			assert_eq!(&mk[..32], &vk[..]);
		}

		#[test]
		fn map_key_differs_for_different_map_keys() {
			let k0 = map_key(b"MerkleLeaves", &0u32.to_le_bytes());
			let k1 = map_key(b"MerkleLeaves", &1u32.to_le_bytes());
			assert_ne!(k0, k1);
			// Pallet+item prefix must be identical
			assert_eq!(&k0[..32], &k1[..32]);
		}

		#[test]
		fn map_key_encodes_original_bytes_after_hash() {
			let raw = 42u32.to_le_bytes();
			let key = map_key(b"MerkleLeaves", &raw);
			// Last 4 bytes must be the original LE-encoded key
			assert_eq!(&key[key.len() - 4..], &raw);
		}
	}

	// -------------------------------------------------------------------------
	// Response type serialization
	// -------------------------------------------------------------------------

	mod response_types {
		use super::*;

		#[test]
		fn merkle_proof_response_json_fields() {
			let resp = MerkleProofResponse {
				root: "0xaabb".to_string(),
				path: vec!["0x1111".to_string(), "0x2222".to_string()],
				leaf_index: 7,
				tree_depth: 20,
				tree_id: 0,
			};
			let json = serde_json::to_value(&resp).unwrap();
			assert_eq!(json["root"], "0xaabb");
			assert_eq!(json["leaf_index"], 7);
			assert_eq!(json["tree_depth"], 20);
			assert_eq!(json["tree_id"], 0);
			assert_eq!(json["path"].as_array().unwrap().len(), 2);
		}

		#[test]
		fn merkle_proof_response_round_trips_serde() {
			let orig = MerkleProofResponse {
				root: "0x00".to_string(),
				path: vec!["0xaa".to_string()],
				leaf_index: 3,
				tree_depth: 20,
				tree_id: 0,
			};
			let back: MerkleProofResponse =
				serde_json::from_str(&serde_json::to_string(&orig).unwrap()).unwrap();
			assert_eq!(orig, back);
		}

		#[test]
		fn nullifier_status_response_json_fields() {
			let resp = NullifierStatusResponse {
				nullifier: "0xdeadbeef".to_string(),
				is_spent: true,
			};
			let json = serde_json::to_value(&resp).unwrap();
			assert_eq!(json["nullifier"], "0xdeadbeef");
			assert_eq!(json["is_spent"], true);
		}

		#[test]
		fn nullifier_status_response_round_trips_serde() {
			let orig = NullifierStatusResponse {
				nullifier: "0x1234".to_string(),
				is_spent: false,
			};
			let back: NullifierStatusResponse =
				serde_json::from_str(&serde_json::to_string(&orig).unwrap()).unwrap();
			assert_eq!(orig, back);
		}

		#[test]
		fn pool_stats_response_json_structure() {
			let resp = PoolStatsResponse {
				merkle_root: "0x01".to_string(),
				commitment_count: 5,
				nullifier_count: 3,
				total_balance: 1_000,
				asset_balances: vec![
					AssetBalanceResponse {
						asset_id: 0,
						balance: 600,
					},
					AssetBalanceResponse {
						asset_id: 1,
						balance: 400,
					},
				],
				tree_depth: 20,
			};
			let json = serde_json::to_value(&resp).unwrap();
			assert_eq!(json["commitment_count"], 5u64);
			assert_eq!(json["nullifier_count"], 3u64);
			// balance fields are serialised as decimal strings to preserve JS precision.
			assert_eq!(json["total_balance"].as_str().unwrap(), "1000");
			let ab = json["asset_balances"].as_array().unwrap();
			assert_eq!(ab.len(), 2);
			assert_eq!(ab[0]["asset_id"], 0u64);
			assert_eq!(ab[0]["balance"].as_str().unwrap(), "600");
		}

		#[test]
		fn pool_stats_response_round_trips_serde() {
			let orig = PoolStatsResponse {
				merkle_root: "0xff".to_string(),
				commitment_count: 1,
				nullifier_count: 0,
				total_balance: 42,
				asset_balances: vec![AssetBalanceResponse {
					asset_id: 0,
					balance: 42,
				}],
				tree_depth: 20,
			};
			let back: PoolStatsResponse =
				serde_json::from_str(&serde_json::to_string(&orig).unwrap()).unwrap();
			assert_eq!(orig, back);
		}

		#[test]
		fn pool_stats_response_nullifier_count_field_present() {
			let resp = PoolStatsResponse {
				merkle_root: "0xab".to_string(),
				commitment_count: 10,
				nullifier_count: 4,
				total_balance: 0,
				asset_balances: vec![],
				tree_depth: 20,
			};
			let json = serde_json::to_value(&resp).unwrap();
			// nullifier_count must be present and correctly serialised
			assert_eq!(json["nullifier_count"], 4u64);
			// active notes estimate: commitment_count - nullifier_count
			let active = json["commitment_count"].as_u64().unwrap()
				- json["nullifier_count"].as_u64().unwrap();
			assert_eq!(active, 6);
		}
	}

	// -------------------------------------------------------------------------
	// Nullifier parameter validation (pure parsing logic)
	// -------------------------------------------------------------------------

	mod nullifier_validation {
		use super::*;

		/// Mirrors the hex-parsing guard in `get_nullifier_status`.
		fn parse_nullifier_hex(s: &str) -> Result<H256, ErrorObject<'static>> {
			let hex_str = s.trim_start_matches("0x");
			let bytes =
				hex::decode(hex_str).map_err(|_| invalid_params("nullifier must be valid hex"))?;
			if bytes.len() != 32 {
				return Err(invalid_params(
					"nullifier must be exactly 32 bytes (64 hex chars)",
				));
			}
			Ok(H256::from_slice(&bytes))
		}

		#[test]
		fn rejects_non_hex_input() {
			assert!(parse_nullifier_hex("not-hex").is_err());
			assert!(parse_nullifier_hex("0xnothex").is_err());
		}

		#[test]
		fn rejects_too_short_hex() {
			assert!(parse_nullifier_hex("0x1234").is_err());
			assert!(parse_nullifier_hex(&"ab".repeat(31)).is_err());
		}

		#[test]
		fn rejects_too_long_hex() {
			assert!(parse_nullifier_hex(&format!("0x{}", "ab".repeat(33))).is_err());
		}

		#[test]
		fn accepts_32_byte_hex_with_0x_prefix() {
			assert!(parse_nullifier_hex(&format!("0x{}", "ab".repeat(32))).is_ok());
		}

		#[test]
		fn accepts_32_byte_hex_without_prefix() {
			assert!(parse_nullifier_hex(&"cd".repeat(32)).is_ok());
		}

		#[test]
		fn parsed_bytes_match_input_exactly() {
			let input: Vec<u8> = (0..32).collect();
			let hex_str = format!("0x{}", hex::encode(&input));
			let h256 = parse_nullifier_hex(&hex_str).unwrap();
			assert_eq!(h256.as_bytes(), input.as_slice());
		}

		#[test]
		fn zero_nullifier_is_accepted() {
			let zero = format!("0x{}", "00".repeat(32));
			let h256 = parse_nullifier_hex(&zero).unwrap();
			assert_eq!(h256, H256::zero());
		}
	}

	// -------------------------------------------------------------------------
	// Commitment parameter validation (pure parsing logic)
	// -------------------------------------------------------------------------

	mod commitment_validation {
		use super::*;

		/// Mirrors the hex-parsing guard in `get_merkle_proof_by_commitment`.
		fn parse_commitment_hex(s: &str) -> Result<H256, ErrorObject<'static>> {
			let hex_str = s.trim_start_matches("0x");
			let bytes =
				hex::decode(hex_str).map_err(|_| invalid_params("commitment must be valid hex"))?;
			if bytes.len() != 32 {
				return Err(invalid_params(
					"commitment must be exactly 32 bytes (64 hex chars)",
				));
			}
			Ok(H256::from_slice(&bytes))
		}

		#[test]
		fn rejects_non_hex_input() {
			assert!(parse_commitment_hex("not-hex").is_err());
			assert!(parse_commitment_hex("0xnothex").is_err());
		}

		#[test]
		fn rejects_too_short_hex() {
			assert!(parse_commitment_hex("0x1234").is_err());
			assert!(parse_commitment_hex(&"ab".repeat(31)).is_err());
		}

		#[test]
		fn rejects_too_long_hex() {
			assert!(parse_commitment_hex(&format!("0x{}", "ab".repeat(33))).is_err());
		}

		#[test]
		fn accepts_32_byte_hex_with_0x_prefix() {
			assert!(parse_commitment_hex(&format!("0x{}", "ab".repeat(32))).is_ok());
		}

		#[test]
		fn accepts_32_byte_hex_without_prefix() {
			assert!(parse_commitment_hex(&"cd".repeat(32)).is_ok());
		}

		#[test]
		fn parsed_bytes_match_input_exactly() {
			let input: Vec<u8> = (0..32).collect();
			let hex_str = format!("0x{}", hex::encode(&input));
			let h256 = parse_commitment_hex(&hex_str).unwrap();
			assert_eq!(h256.as_bytes(), input.as_slice());
		}

		#[test]
		fn zero_commitment_is_accepted() {
			let zero = format!("0x{}", "00".repeat(32));
			let h256 = parse_commitment_hex(&zero).unwrap();
			assert_eq!(h256, H256::zero());
		}
	}

	// -------------------------------------------------------------------------
	// Error constructors
	// -------------------------------------------------------------------------

	mod error_constructors {
		use super::*;
		use jsonrpsee::types::error::ErrorCode;

		#[test]
		fn pool_not_initialized_uses_internal_error_code() {
			let e = pool_not_initialized();
			assert_eq!(e.code(), ErrorCode::InternalError.code());
		}

		#[test]
		fn pool_is_empty_uses_internal_error_code() {
			let e = pool_is_empty();
			assert_eq!(e.code(), ErrorCode::InternalError.code());
		}

		#[test]
		fn pool_is_empty_message_differs_from_not_initialized() {
			let empty = pool_is_empty();
			let uninit = pool_not_initialized();
			// Must produce distinct messages so callers can distinguish the two states.
			assert_ne!(empty.message(), uninit.message());
		}
	}
}
