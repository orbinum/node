//! # Shielded Pool Pallet
//!
//! A pallet for private transactions using Zero-Knowledge proofs.
//!
//! ## Overview
//!
//! This pallet implements a privacy pool based on the UTXO model with
//! commitments and nullifiers. It enables:
//!
//! - **Shield**: Deposit public tokens into the private pool
//! - **Private Transfer**: Transfer privately within the pool using ZK proofs
//! - **Unshield**: Withdraw tokens from the pool to a public account
//! - **Relay fees**: Relayers commit to spends (`commit_relay`) and claim the
//!   fees credited to them (`claim_relay_fees`)
//!
//! ## Architecture
//!
//! The shielded pool uses a Merkle tree of commitments and a set of nullifiers
//! to track private notes while preventing double-spending.
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    SHIELDED POOL                            │
//! ├─────────────────────────────────────────────────────────────┤
//! │                                                             │
//! │   PUBLIC SIDE              │        PRIVATE SIDE            │
//! │   ──────────               │        ────────────            │
//! │                            │                                │
//! │   AccountId                │        Note                    │
//! │   Balance: 1000 ORB   ───shield──►  Commitment              │
//! │                            │        (hidden value)          │
//! │                            │              │                 │
//! │                            │              │ transfer        │
//! │                            │              ▼                 │
//! │   AccountId                │        Note                    │
//! │   Balance: +500 ORB  ◄──unshield──  Commitment              │
//! │                            │                                │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Usage
//!
//! ```rust,ignore
//! // Deposit into the pool
//! ShieldedPool::shield(origin, asset_id, amount, commitment, encrypted_memo)?;
//!
//! // Transfer privately
//! ShieldedPool::private_transfer(
//!     origin, proof, merkle_root, nullifiers, commitments, encrypted_memos,
//!     asset_id, fee, circuit_version,
//! )?;
//!
//! // Withdraw from the pool
//! ShieldedPool::unshield(
//!     origin, proof, merkle_root, nullifier, asset_id, amount, recipient, fee,
//!     change_commitment, change_encrypted_memo, circuit_version,
//! )?;
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod genesis;
pub mod helpers;
pub mod merkle;
pub mod operations;
pub mod origin;
pub mod storage;
pub mod types;
pub mod validate_unsigned;
pub mod weights;

mod runtime_api_impl;

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;
#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;

pub use origin::{RelayCaller, ensure_relay_caller, ensure_spend_origin};
pub use pallet::*;
pub use types::{
	AssetId, AssetMetadata, Commitment, DEFAULT_TREE_DEPTH, DefaultMerklePath,
	EncryptedMemo as FrameEncryptedMemo, Hash, MAX_ENCRYPTED_MEMO_SIZE, MAX_PROOF_SIZE,
	MAX_SUBTREE_ROOTS, MAX_TREE_DEPTH, MerklePath, Note, Nullifier, Proof, SUBTREE_LEVEL,
	SubtreeRoots,
};
pub use weights::WeightInfo;

use frame_support::pallet_prelude::{Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};
use scale_info::TypeInfo;

/// Who submitted a call through the EVM precompile, as established by the
/// dispatch path itself.
///
/// An origin cannot be forged — the EVM executor sets it from the transaction
/// signature. It identifies the relayer for `commit_relay` and the claimant for
/// `claim_relay_fees`. It does NOT decide who a spend's fee is credited to:
/// that is the relay commit, since a spend can be copied and resubmitted by
/// anyone.
#[derive(
	PartialEq,
	Eq,
	Clone,
	Debug,
	Encode,
	Decode,
	DecodeWithMemTracking,
	TypeInfo,
	MaxEncodedLen
)]
pub enum RawOrigin {
	/// Submitted through the EVM precompile by this address, which signed the
	/// transaction and paid its gas.
	///
	/// The only variant: an unrelayed submission arrives as `frame_system`'s
	/// `None` origin, so there is nothing for this enum to say about it. A second
	/// variant meaning "nobody" would be constructible by anyone able to build an
	/// origin, and would then be indistinguishable from the real thing.
	Relayed(sp_core::H160),
}

#[frame_support::pallet]
#[allow(clippy::too_many_arguments)]
pub mod pallet {
	use super::*;
	use frame_support::{
		PalletId,
		pallet_prelude::*,
		traits::{Currency, ReservableCurrency},
	};
	use frame_system::pallet_prelude::*;
	use pallet_zk_verifier::ZkVerifierPort;

	/// The balance type for this pallet
	pub type BalanceOf<T> =
		<<T as Config>::Currency as Currency<<T as frame_system::Config>::AccountId>>::Balance;

	/// One `shield_batch` entry: `(asset_id, amount, commitment, encrypted_memo, proof,
	/// circuit_version)`, the arguments of a single `shield`.
	pub type ShieldBatchItem<T> = (
		u32,
		BalanceOf<T>,
		Commitment,
		FrameEncryptedMemo,
		Proof,
		u32,
	);

	/// Storage version history:
	/// - v1: `MerkleNodes` (internal Merkle tree nodes), backfilled from `MerkleLeaves`.
	///   Migration removed once every live chain reached v2 — see git history.
	/// - v2: multi-tree forest — `SealedTreeRoots` / `SealedRootIndex` (start empty).
	///   Migration removed once every live chain reached v2 — see git history.
	/// - v3: historic-root window re-anchored from insert counts to block numbers;
	///   both historic-root items carry an expiry. Migration removed once every
	///   live chain reached v3 — see git history.
	pub const STORAGE_VERSION: StorageVersion = StorageVersion::new(3);

	/// How many sealed-tree nodes each block sweeps.
	///
	/// Fixed, never derived from the block's leftover weight — see `on_initialize`
	/// for why that distinction is a consensus matter and not a tuning knob. At
	/// ~12.7 µs of ref_time per node this costs ~6.5 ms of a 2 s block, and clears
	/// a sealed 1 M-node tree in roughly 2 048 blocks (~3.4 hours at 6 s).
	pub(crate) const PRUNED_NODES_PER_BLOCK: u32 = 512;

	/// Most relay commits a single `commit_relay` call carries. Only bounds the
	/// call's size; the per-block quota is
	/// `pallet_relayer::Config::MaxCommitsPerRelayerPerBlock`.
	pub const MAX_RELAY_COMMITS_PER_CALL: u32 = 64;

	#[pallet::pallet]
	#[pallet::storage_version(STORAGE_VERSION)]
	pub struct Pallet<T>(_);

	#[pallet::origin]
	pub type Origin = RawOrigin;

	/// Configuration trait for the pallet
	#[pallet::config]
	pub trait Config:
		frame_system::Config<
			RuntimeEvent: From<Event<Self>>,
			// Spends and relayer calls read the precompile's `Relayed` origin, so
			// the outer origin must convert back to this pallet's own variant.
			RuntimeOrigin: Into<Result<Origin, <Self as frame_system::Config>::RuntimeOrigin>>,
		>
	{
		/// The currency mechanism
		type Currency: Currency<Self::AccountId> + ReservableCurrency<Self::AccountId>;

		/// ZK proof verifier (domain port)
		type ZkVerifier: ZkVerifierPort;

		/// Relay configuration, relay commits, fee accounting and block-author lookup.
		///
		/// In production: `pallet_relayer::Pallet<Runtime>`.
		/// In tests: a lightweight mock struct in `mock.rs`.
		type Relayer: pallet_relayer::RelayerInterface<AccountId = Self::AccountId>;

		/// The account an EVM address controls. Relay fees claimed by an EVM
		/// relayer are paid there. Must match the runtime's EVM address mapping.
		type EvmAccount: sp_runtime::traits::Convert<sp_core::H160, Self::AccountId>;

		/// The pallet's ID, used for deriving the pool account
		#[pallet::constant]
		type PalletId: Get<PalletId>;

		/// Maximum depth of the Merkle tree (2^depth leaves)
		#[pallet::constant]
		type MaxTreeDepth: Get<u32>;

		/// Leaves per tree before it seals and the forest rolls over to a new
		/// tree. Must be a power of two ≤ 2^MaxTreeDepth. Production pins
		/// 2^20; changing it on a live chain would re-map every note's
		/// tree_id and is forbidden (see `integrity_test`).
		#[pallet::constant]
		type MaxLeavesPerTree: Get<u32>;

		/// Safety cap on the historic-root queue: the most roots kept at once,
		/// and the most a single insert may prune. This bounds worst-case work
		/// and storage — the retention *window* is [`Self::RootRetentionBlocks`].
		/// Size it above the roots produced in one window, or it becomes the
		/// binding constraint and the window silently shortens.
		#[pallet::constant]
		type MaxHistoricRoots: Get<u32>;

		/// How long a historic root stays spendable, in blocks.
		///
		/// Must exceed the mempool longevity of an unsigned transaction
		/// (`TX_LONGEVITY`), otherwise a transaction can be admitted against a
		/// root that expires before it is included — it would propagate, reach a
		/// block, and only then revert with `UnknownMerkleRoot`. Enforced by
		/// `integrity_test`.
		#[pallet::constant]
		type RootRetentionBlocks: Get<BlockNumberFor<Self>>;

		/// Merkle level below which a **sealed** tree's internal nodes are pruned.
		///
		/// `MerkleNodes` exists only to serve Merkle paths to wallets — no
		/// dispatchable reads it, so pruning cannot affect spendability. A sealed
		/// tree is immutable, so anything dropped here is recomputed from
		/// `MerkleLeaves` on demand.
		///
		/// The trade is storage against query latency. A cut `c` keeps
		/// 2^(21−c) − 2 nodes per tree and makes a path read 2^c − 2 leaves:
		/// nodes concentrate at the bottom, so each level less halves the reads and
		/// doubles what is stored. Paths are served by the public RPC, so the read
		/// cost is also what an attacker can make a node pay per request.
		///
		/// Lowering it on a live chain is safe: a sealed tree's node pruned under an
		/// earlier, higher cut is rebuilt from the leaves when a path needs it.
		/// Must be non-zero and below the tree depth (`integrity_test`).
		#[pallet::constant]
		type SealedTreePrunedBelowLevel: Get<u8>;

		/// Weight information for extrinsics in this pallet
		type WeightInfo: WeightInfo;
	}

	// ========================================================================
	// Storage
	// ========================================================================

	/// Current Poseidon Merkle root (canonical root)
	#[pallet::storage]
	#[pallet::getter(fn poseidon_root)]
	pub type PoseidonRoot<T> = StorageValue<_, Hash, ValueQuery>;

	/// Number of leaves in the Merkle tree
	#[pallet::storage]
	#[pallet::getter(fn merkle_tree_size)]
	pub type MerkleTreeSize<T> = StorageValue<_, u32, ValueQuery>;

	/// Incremental Merkle tree frontier for O(depth) root updates.
	///
	/// Stores the last left-sibling at each of the 20 levels of the tree and is
	/// updated in O(depth) on every `insert_leaf`, so the root never needs a
	/// recomputation from all leaves. Depth is fixed at `DEFAULT_TREE_DEPTH = 20`.
	#[pallet::storage]
	pub type MerkleTreeFrontier<T> = StorageValue<_, [[u8; 32]; 20], ValueQuery>;

	/// Merkle tree leaves (index -> commitment)
	#[pallet::storage]
	pub type MerkleLeaves<T> = StorageMap<_, Blake2_128Concat, u32, Commitment, OptionQuery>;

	/// Reverse index: commitment -> leaf index.
	///
	/// Populated on every `insert_leaf`. Gives O(1) lookup for Merkle proof
	/// generation and duplicate-commitment checks, instead of a scan over
	/// `MerkleLeaves`.
	#[pallet::storage]
	pub type CommitmentToLeafIndex<T> =
		StorageMap<_, Blake2_128Concat, Commitment, u32, OptionQuery>;

	/// Internal Merkle tree nodes: `(tree_id, level, index) -> node hash`.
	///
	/// Written during the frontier walk of `insert_leaf`, which computes these
	/// values anyway. Turns Merkle proof generation into O(depth) point reads
	/// instead of an O(n) recomputation from all leaves.
	///
	/// Levels run 1..=19: level 0 is `MerkleLeaves`, level 20 is the tree's root.
	/// A missing entry means the subtree below it is empty (zero hash), or that
	/// it belongs to a sealed tree and was pruned (see
	/// `Config::SealedTreePrunedBelowLevel`).
	#[pallet::storage]
	pub type MerkleNodes<T> = StorageNMap<
		_,
		(
			NMapKey<Twox64Concat, u32>, // tree_id
			NMapKey<Twox64Concat, u8>,  // level (1..=19)
			NMapKey<Twox64Concat, u32>, // node index within the level
		),
		Hash,
		OptionQuery,
	>;

	/// Resume point for the sealed-tree node sweep: `(tree_id, level, index)`.
	///
	/// Pruning a sealed tree touches ~1M keys, far more than one block can absorb,
	/// so `on_initialize` walks it in bounded batches and parks the cursor here. `None`
	/// means the sweep is idle — either nothing has sealed yet, or every sealed
	/// tree is already pruned.
	#[pallet::storage]
	pub type SealedPruneCursor<T> = StorageValue<_, (u32, u8, u32), OptionQuery>;

	/// Highest `tree_id` whose prunable levels have been fully swept.
	///
	/// `None` before the first sweep completes. The sweep starts at the tree after
	/// this one, so a restart never re-walks finished trees.
	#[pallet::storage]
	pub type LastPrunedTree<T> = StorageValue<_, u32, OptionQuery>;

	/// Set of used nullifiers (nullifier -> block number when used)
	#[pallet::storage]
	pub type NullifierSet<T: Config> =
		StorageMap<_, Blake2_128Concat, Nullifier, BlockNumberFor<T>, OptionQuery>;

	/// Final root of each sealed tree, keyed by tree_id. Permanent — a sealed
	/// tree is immutable forever, so its root must never expire or every note
	/// still inside it would become unspendable. Bounded by tree count
	/// (max 4096), not by activity.
	#[pallet::storage]
	pub type SealedTreeRoots<T> = StorageMap<_, Twox64Concat, u32, Hash, OptionQuery>;

	/// Reverse index of `SealedTreeRoots`: sealed root -> tree_id. Gives
	/// `is_known_root` an O(1) membership check alongside the historic ring.
	#[pallet::storage]
	pub type SealedRootIndex<T> = StorageMap<_, Blake2_128Concat, Hash, u32, OptionQuery>;

	/// Historic Poseidon Merkle roots (for proving against recent states),
	/// mapped to the block at which each stops being accepted.
	///
	/// Expiry is measured in **blocks**, not in insertions, so the window
	/// always outlives the mempool longevity a transaction was admitted with.
	/// A window counted in insertions rotates faster than transactions expire
	/// under load, and honest spends would revert with `UnknownMerkleRoot`
	/// after propagating.
	#[pallet::storage]
	pub type HistoricPoseidonRoots<T: Config> =
		StorageMap<_, Blake2_128Concat, Hash, BlockNumberFor<T>, OptionQuery>;

	/// Expiry queue for historic roots: monotonic slot -> `(root, expires_at)`.
	///
	/// A map rather than one vector on purpose. The window has to hold a full
	/// `RootRetentionBlocks` worth of roots — thousands under load — and a
	/// `StorageValue` would be read and rewritten in full on every single leaf
	/// insert, turning a hot path into hundreds of KiB of I/O. Keyed by slot,
	/// each insert touches exactly one entry plus the few it prunes.
	///
	/// Slots are handed out by [`HistoricRootsHead`] and consumed from
	/// [`HistoricRootsTail`], so the queue drains in insertion order, which is
	/// also expiry order (every insert stores `now + retention` with a
	/// non-decreasing `now`).
	#[pallet::storage]
	pub type HistoricRootsQueue<T: Config> =
		StorageMap<_, Twox64Concat, u64, (Hash, BlockNumberFor<T>), OptionQuery>;

	/// Next slot to write in [`HistoricRootsQueue`]. Monotonic; never reset.
	#[pallet::storage]
	pub type HistoricRootsHead<T> = StorageValue<_, u64, ValueQuery>;

	/// Oldest slot still queued in [`HistoricRootsQueue`]. Monotonic; never reset.
	///
	/// `head - tail` is the number of live entries, bounded in practice by the
	/// retention window and hard-capped by `MaxHistoricRoots`.
	#[pallet::storage]
	pub type HistoricRootsTail<T> = StorageValue<_, u64, ValueQuery>;

	/// Encrypted memos for commitments
	///
	/// Maps each commitment to its associated encrypted memo.
	/// Memos enable note recovery by scanning the blockchain.
	/// Only the note owner (with the correct decryption key) can decrypt the memo.
	#[pallet::storage]
	pub type CommitmentMemos<T> =
		StorageMap<_, Blake2_128Concat, Commitment, FrameEncryptedMemo, OptionQuery>;

	// ========================================================================
	// Multi-Asset Support Storage
	// ========================================================================

	/// Asset registry for multi-asset shielded pool
	///
	/// Maps asset_id to asset metadata including name, symbol, and verification status.
	/// Only verified assets can be used in shield/unshield operations.
	#[pallet::storage]
	pub type Assets<T: Config> = StorageMap<
		_,
		Blake2_128Concat,
		u32, // asset_id
		AssetMetadata<T::AccountId, BlockNumberFor<T>>,
		OptionQuery,
	>;

	/// Next available asset_id for registration
	#[pallet::storage]
	pub type NextAssetId<T: Config> = StorageValue<_, u32, ValueQuery>;

	/// Pool balance per asset
	///
	/// Tracks the total balance of each asset in the shielded pool
	#[pallet::storage]
	pub type PoolBalancePerAsset<T: Config> = StorageMap<
		_,
		Blake2_128Concat,
		u32, // asset_id
		BalanceOf<T>,
		ValueQuery,
	>;

	/// Total number of commitments ever inserted into the Merkle tree.
	///
	/// Monotonically increasing counter. Incremented once per successful
	/// `insert_leaf` (shield, private_transfer outputs, unshield change).
	/// Enables O(1) pool stats without scanning `MerkleLeaves` key prefixes.
	#[pallet::storage]
	pub type TotalCommitmentsInserted<T> = StorageValue<_, u64, ValueQuery>;

	/// Total number of nullifiers ever spent (notes consumed).
	///
	/// Monotonically increasing counter. Incremented once per
	/// `NullifierRepository::mark_as_used` (unshield, private_transfer input).
	/// Enables O(1) pool stats without scanning `NullifierSet` key prefixes.
	#[pallet::storage]
	pub type TotalNullifiersSpent<T> = StorageValue<_, u64, ValueQuery>;

	// ========================================================================
	// Genesis Config
	// ========================================================================

	#[pallet::genesis_config]
	#[derive(frame_support::DefaultNoBound)]
	pub struct GenesisConfig<T: Config> {
		/// Initial Merkle root (empty tree)
		pub initial_root: Hash,
		#[serde(skip)]
		pub _phantom: PhantomData<T>,
	}

	#[pallet::genesis_build]
	impl<T: Config> BuildGenesisConfig for GenesisConfig<T> {
		fn build(&self) {
			// Delegate to genesis module for initialization
			crate::genesis::initialize_genesis::<T>(self.initial_root);
		}
	}

	// ========================================================================
	// Hooks
	// ========================================================================

	#[pallet::hooks]
	impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
		/// Reclaim internal Merkle nodes from sealed trees, a fixed batch per block.
		///
		/// A sealed tree holds ~1M prunable nodes — orders of magnitude past one
		/// block — so the sweep runs in bounded batches and parks its position in
		/// `SealedPruneCursor`.
		///
		/// The batch size is a constant and must stay one. Sizing it from the
		/// block's leftover weight looks free, but leftover weight is not
		/// consensus: an author and an importer measure the same block slightly
		/// differently once post-dispatch refunds are in play, so each would prune
		/// a different number of nodes and their state roots would diverge. That
		/// halted the testnet at block 406997.
		fn on_initialize(_now: BlockNumberFor<T>) -> Weight {
			crate::merkle::MerkleTreeService::prune_sealed_nodes::<T>(PRUNED_NODES_PER_BLOCK);
			// The full batch is charged, not the removals: the sweep probes
			// `PRUNED_NODES_PER_BLOCK` keys either way, and a miss costs the same
			// read as a hit. Charging removals would under-declare an all-miss
			// pass and let the block admit extrinsics it cannot pay for.
			T::WeightInfo::prune_sealed_nodes(PRUNED_NODES_PER_BLOCK)
		}

		fn integrity_test() {
			// `const` block: both operands are `cfg!`, so this resolves at compile time
			// and a bad feature combination fails the build rather than the runtime's
			// integrity check. Strictly stronger than asserting at runtime, and it is
			// what clippy::assertions_on_constants asks for.
			const {
				assert!(
					!cfg!(feature = "skip-proof-verification")
						|| cfg!(feature = "runtime-benchmarks"),
					"pallet-shielded-pool compiled with `skip-proof-verification` but without \
					 `runtime-benchmarks`: shield/unshield/transfer proofs are NOT verified \
					 outside a benchmark build. This must never run on a live chain."
				);
			}

			assert_eq!(
				T::MaxTreeDepth::get(),
				crate::types::MAX_TREE_DEPTH,
				"MaxTreeDepth config must equal the fixed tree depth (MAX_TREE_DEPTH)"
			);

			assert!(
				T::MaxHistoricRoots::get() > 0,
				"MaxHistoricRoots must be non-zero, otherwise no root can ever be stored"
			);

			// The retention window must outlive the mempool longevity an unsigned
			// transaction is admitted with, or a spend can pass validation, get
			// gossiped, and only revert once included.
			let retention: u64 =
				sp_runtime::traits::UniqueSaturatedInto::<u64>::unique_saturated_into(
					T::RootRetentionBlocks::get(),
				);
			assert!(
				retention > crate::validate_unsigned::TX_LONGEVITY,
				"RootRetentionBlocks must exceed TX_LONGEVITY, otherwise a root can \
				 expire while a transaction admitted against it is still valid in the pool"
			);

			// Level 0 is `MerkleLeaves` and never prunable; the top level is the
			// root itself. A cut outside that range would either prune nothing or
			// leave `get_merkle_path` with no stored node to start from.
			let cut = T::SealedTreePrunedBelowLevel::get();
			assert!(
				cut > 0 && (cut as usize) < crate::types::DEFAULT_TREE_DEPTH,
				"SealedTreePrunedBelowLevel must be in 1..DEFAULT_TREE_DEPTH"
			);

			let cap = T::MaxLeavesPerTree::get();
			assert!(
				cap.is_power_of_two() && cap <= (1u32 << crate::types::MAX_TREE_DEPTH),
				"MaxLeavesPerTree must be a power of two <= 2^MAX_TREE_DEPTH; \
				 clients derive tree_id from the global leaf index using this \
				 constant, so it must never change on a live chain"
			);
		}

		/// Ledger-solvency invariant: the tracked native-asset pool balance must
		/// equal the pool account's physical free balance. Fees stay physical in
		/// the pool until `claim_relay_fees` pays them out, so both move together.
		/// Only the native asset (0) is backed by `Currency`; other assets live in
		/// external backends — TODO: extend when a per-asset balance reader exists.
		#[cfg(feature = "try-runtime")]
		fn try_state(_: BlockNumberFor<T>) -> Result<(), sp_runtime::TryRuntimeError> {
			let pool = Self::pool_account_id();
			let physical = T::Currency::free_balance(&pool);
			let tracked = PoolBalancePerAsset::<T>::get(0u32);
			frame_support::ensure!(
				tracked == physical,
				sp_runtime::TryRuntimeError::Other(
					"shielded-pool native ledger drifted from physical pool balance"
				)
			);

			// Forest invariants: the active root must always be provable
			// against; one sealed root per completed tree; the sealed maps
			// are a bijection.
			use crate::storage::MerkleRepository;
			frame_support::ensure!(
				MerkleRepository::is_known_root::<T>(&MerkleRepository::get_poseidon_root::<T>()),
				sp_runtime::TryRuntimeError::Other("PoseidonRoot not in known-roots set")
			);
			let sealed = SealedTreeRoots::<T>::iter().count() as u32;
			frame_support::ensure!(
				sealed == MerkleRepository::get_tree_size::<T>() / T::MaxLeavesPerTree::get(),
				sp_runtime::TryRuntimeError::Other("sealed-tree count != tree_size / cap")
			);
			for (tree_id, root) in SealedTreeRoots::<T>::iter() {
				frame_support::ensure!(
					SealedRootIndex::<T>::get(root) == Some(tree_id),
					sp_runtime::TryRuntimeError::Other("SealedRootIndex out of sync")
				);
			}
			Ok(())
		}
	}

	// ========================================================================
	// Events
	// ========================================================================

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		/// Tokens were deposited into the shielded pool
		Shielded {
			/// Who made the deposit
			depositor: T::AccountId,
			/// Amount deposited
			amount: BalanceOf<T>,
			/// Commitment created
			commitment: Commitment,
			/// Encrypted memo for note recovery and audit
			encrypted_memo: FrameEncryptedMemo,
			/// Index in the Merkle tree
			leaf_index: u32,
		},

		/// Input nullifiers were spent in a private transfer.
		/// Emitted independently of CommitmentsInserted to prevent graph correlation.
		NullifiersSpent {
			/// Input nullifiers consumed — max 2.
			nullifiers: BoundedVec<Nullifier, ConstU32<2>>,
		},

		/// Output commitments were inserted into the Merkle tree in a private transfer.
		/// Emitted independently of NullifiersSpent to prevent graph correlation.
		CommitmentsInserted {
			/// New commitments created — max 2.
			commitments: BoundedVec<Commitment, ConstU32<2>>,
			/// Encrypted memos for each output commitment — max 2.
			encrypted_memos: BoundedVec<FrameEncryptedMemo, ConstU32<2>>,
			/// Leaf indices assigned in the Merkle tree — max 2.
			leaf_indices: BoundedVec<u32, ConstU32<2>>,
		},

		/// Tokens were withdrawn from the shielded pool
		Unshielded {
			/// Nullifier of the spent note
			nullifier: Nullifier,
			/// Amount withdrawn
			amount: BalanceOf<T>,
			/// Recipient account
			recipient: T::AccountId,
			/// Change note commitment inserted into the Merkle tree (None for total unshield)
			change_commitment: Option<Hash>,
			/// Encrypted memo for the change note (None for total unshield)
			change_encrypted_memo: Option<FrameEncryptedMemo>,
			/// Leaf index of the change commitment in the Merkle tree (None for total unshield)
			change_leaf_index: Option<u32>,
		},

		/// Merkle root was updated
		MerkleRootUpdated {
			/// Previous root
			old_root: Hash,
			/// New root
			new_root: Hash,
			/// Total leaves ever inserted, global across the whole forest —
			/// never per-tree. Indexer chunking and wallet scan cursors rely
			/// on this being dense and monotonic; per-tree size is derivable
			/// as `tree_size % MaxLeavesPerTree`.
			tree_size: u32,
		},

		/// A tree reached `MaxLeavesPerTree` and was sealed; inserts continue
		/// in a fresh tree. The final root stays valid forever via
		/// `SealedTreeRoots`.
		TreeSealed {
			/// Id of the sealed tree (global_leaf_index >> log2(MaxLeavesPerTree))
			tree_id: u32,
			/// Final root of the sealed tree — permanently spendable anchor
			final_root: Hash,
			/// Global index of the sealed tree's first leaf
			first_leaf_index: u32,
			/// Leaves in the sealed tree (always MaxLeavesPerTree)
			leaf_count: u32,
		},

		/// Asset was registered in the registry
		AssetRegistered {
			/// The asset ID
			asset_id: u32,
		},

		/// Asset was verified for use
		AssetVerified {
			/// The asset ID
			asset_id: u32,
		},

		/// Asset was unverified
		AssetUnverified {
			/// The asset ID
			asset_id: u32,
		},

		/// A relayer claimed its pending relay fees out of the pool.
		RelayFeesClaimed {
			/// Account whose pending fees were spent
			who: T::AccountId,
			/// Account that received them
			to: T::AccountId,
			asset_id: u32,
			amount: BalanceOf<T>,
		},
	}

	// ========================================================================
	// Errors
	// ========================================================================

	#[pallet::error]
	pub enum Error<T> {
		/// The commitment already exists in the tree
		CommitmentAlreadyExists,
		/// The nullifier has already been used (double-spend attempt)
		NullifierAlreadyUsed,
		/// The Merkle root is not recognized
		UnknownMerkleRoot,
		/// Absolute forest capacity reached (u32 leaf-index space exhausted:
		/// 4096 trees × MaxLeavesPerTree). Practically unreachable.
		MerkleTreeFull,
		/// Insufficient balance in the pool
		InsufficientPoolBalance,
		/// The amount is invalid (zero or overflow)
		InvalidAmount,
		/// A transfer does not have exactly two inputs and two outputs
		TooManyInputsOrOutputs,
		/// Proof verification failed
		ProofVerificationFailed,
		/// Invalid encrypted memo size
		InvalidMemoSize,
		/// Mismatch between number of memos and commitments
		MemoCommitmentMismatch,
		/// Asset ID does not exist in the registry
		InvalidAssetId,
		/// Asset is not verified for use
		AssetNotVerified,
		/// Recipient address is zero (burn address)
		InvalidRecipient,
		/// Gasless fee is below the required minimum
		FeeTooLow,
		/// A public value is not a canonical field element
		InvalidPublicSignals,
		/// The caller has no registered relay address.
		RelayerNotRegistered,
		/// A non-zero fee could not be attributed to any recipient (no relay
		/// commit and no block author). The fee tokens would otherwise be stranded.
		FeeRecipientUnavailable,
		/// Batch operation submitted with no operations.
		EmptyBatch,
		/// Asset id counter collided with an existing asset (would overwrite it).
		AssetIdAlreadyExists,
		/// The asset is registered and verified but not backed: the pool moves
		/// the native currency for every asset, so only the native asset can be
		/// shielded, spent, withdrawn or claimed.
		AssetNotSupported,
	}

	// ========================================================================
	// Extrinsics
	// ========================================================================

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		/// Deposit tokens into the shielded pool.
		///
		/// This converts public tokens into a private note represented by a commitment.
		/// The commitment is added to the Merkle tree, and an encrypted memo is stored
		/// for note recovery.
		///
		/// # Arguments
		/// * `origin` - The account depositing tokens
		/// * `amount` - Amount of tokens to shield
		/// * `commitment` - The commitment for the new note (computed off-chain)
		/// * `encrypted_memo` - Encrypted metadata for note recovery and audit
		/// * `proof` - Shield proof: `commitment` opens to `amount` of `asset_id`
		/// * `circuit_version` - Shield circuit version the proof was built for
		///
		/// # Errors
		/// * `InvalidAmount` - Amount is zero
		/// * `MerkleTreeFull` - No more space in the tree
		/// * `CommitmentAlreadyExists` - Duplicate commitment
		/// * `InvalidMemoSize` - Encrypted memo is not exactly 180 bytes
		/// * `ProofVerificationFailed` - The proof does not bind the commitment to the deposit
		#[pallet::call_index(0)]
		#[pallet::weight(T::WeightInfo::shield().saturating_add(T::ZkVerifier::verification_weight()))]
		pub fn shield(
			origin: OriginFor<T>,
			asset_id: u32,
			amount: BalanceOf<T>,
			commitment: Commitment,
			encrypted_memo: FrameEncryptedMemo,
			proof: Proof,
			circuit_version: u32,
		) -> DispatchResult {
			let who = ensure_signed(origin)?;
			use crate::operations::shield::{ShieldOperation, ShieldRequest};
			ShieldOperation::execute::<T>(
				who,
				&proof,
				ShieldRequest {
					asset_id,
					amount,
					commitment,
					encrypted_memo,
					circuit_version,
				},
			)
		}

		/// Deposit into the shielded pool several times in a single transaction.
		///
		/// Each operation runs exactly as `shield()` would, in order; the first
		/// failure reverts the whole batch. Saves the per-transaction overhead of
		/// submitting each shield separately.
		///
		/// # Arguments
		/// * `origin` - The account depositing tokens
		/// * `operations` - Up to 20 (asset_id, amount, commitment, encrypted_memo, proof,
		///   circuit_version) tuples, one shield proof each
		///
		/// # Errors
		/// * Same as `shield()` for any individual operation
		/// * `EmptyBatch` - Batch submitted with no operations
		///
		/// # Events
		/// * `Shielded` - Emitted for each successful shield in the batch
		///
		/// # Weight
		/// Benchmarked per operation count via `shield_batch(n)`.
		#[pallet::call_index(12)]
		#[pallet::weight(
			T::WeightInfo::shield_batch(operations.len() as u32)
				.saturating_add(T::ZkVerifier::verification_weight().saturating_mul(operations.len() as u64))
		)]
		pub fn shield_batch(
			origin: OriginFor<T>,
			operations: BoundedVec<ShieldBatchItem<T>, ConstU32<20>>,
		) -> DispatchResult {
			let who = ensure_signed(origin)?;
			ensure!(!operations.is_empty(), Error::<T>::EmptyBatch);
			use crate::operations::shield::{ShieldOperation, ShieldRequest};
			for item in operations {
				let (proof, req) = ShieldRequest::from_batch_item(item);
				ShieldOperation::execute::<T>(who.clone(), &proof, req)?;
			}
			Ok(())
		}

		/// Execute a private transfer within the shielded pool.
		///
		/// This spends existing notes (via nullifiers) and creates new notes
		/// (via commitments). A ZK proof verifies the transfer is valid without
		/// revealing amounts or participants. The fee is embedded in the ZK proof
		/// (input_sum == output_sum + fee) and credited to the relayer that
		/// committed to this transfer (see `commit_relay`), else the block author.
		///
		/// # Arguments
		/// * `origin` - Unsigned, signed, or the precompile's relayed origin
		/// * `proof` - The ZK proof of valid transfer
		/// * `merkle_roots` - The root each input is proven against, in input order.
		///   Equal unless the notes come from different trees (circuit v3); a
		///   dummy input's slot repeats the real root
		/// * `nullifiers` - Nullifiers for notes being spent
		/// * `commitments` - Commitments for new notes being created
		/// * `encrypted_memos` - Encrypted metadata for each new note
		/// * `asset_id` - Asset being transferred (public input of the proof)
		/// * `fee` - Gasless fee (must match proof's fee public input)
		/// * `circuit_version` - Version whose key the proof is verified against
		///
		/// # Errors
		/// * `TooManyInputsOrOutputs` - Not two nullifiers and two commitments
		/// * `UnknownMerkleRoot` - Any root is not a known one (active, recent or sealed)
		/// * `NullifierAlreadyUsed` - Double-spend attempt
		/// * `ProofVerificationFailed` - ZK proof verification failed
		/// * `FeeTooLow` - Fee is below `T::Relayer::min_relay_fee()`
		/// * `InvalidMemoSize` - Any encrypted memo is not exactly 180 bytes
		/// * `MemoCommitmentMismatch` - Number of memos does not match number of commitments
		#[pallet::call_index(1)]
		#[pallet::weight(
			T::WeightInfo::private_transfer().saturating_add(T::ZkVerifier::verification_weight())
		)]
		#[allow(clippy::too_many_arguments)]
		pub fn private_transfer(
			origin: OriginFor<T>,
			proof: Proof,
			merkle_roots: [Hash; 2],
			nullifiers: BoundedVec<Nullifier, ConstU32<2>>,
			commitments: BoundedVec<Commitment, ConstU32<2>>,
			encrypted_memos: BoundedVec<FrameEncryptedMemo, ConstU32<2>>,
			asset_id: u32,
			fee: BalanceOf<T>,
			circuit_version: u32,
		) -> DispatchResult {
			ensure_spend_origin::<T, _>(origin)?;
			use crate::operations::private_transfer::{PrivateTransferOperation, TransferRequest};
			PrivateTransferOperation::execute::<T>(
				&proof,
				TransferRequest {
					merkle_roots,
					nullifiers,
					commitments,
					memos: encrypted_memos,
					asset_id,
					fee,
					circuit_version,
				},
			)
		}

		/// Withdraw tokens from the shielded pool to a public account.
		///
		/// This spends a private note and transfers the tokens to a public recipient.
		/// A ZK proof verifies ownership of the note without revealing which note.
		/// The fee is embedded in the ZK proof (note_value == amount + fee) and
		/// credited to the relayer that committed to this unshield (see
		/// `commit_relay`), else the block author.
		///
		/// # Arguments
		/// * `origin` - Unsigned, signed, or the precompile's relayed origin
		/// * `proof` - The ZK proof of valid withdrawal
		/// * `merkle_root` - The Merkle root the proof was computed against
		/// * `nullifier` - Nullifier for the note being spent
		/// * `asset_id` - Asset being unshielded
		/// * `amount` - Net amount to withdraw (recipient receives this)
		/// * `recipient` - Public account to receive tokens
		/// * `fee` - Gasless fee (must match proof's fee public input)
		/// * `change_commitment` - Commitment of the change note (empty [0u8; 32] for total unshield)
		/// * `change_encrypted_memo` - Empty for a total unshield; exactly 180 bytes for a partial one
		/// * `circuit_version` - Version whose key the proof is verified against
		///
		/// # Errors
		/// * `UnknownMerkleRoot` - Root is not in historic roots
		/// * `NullifierAlreadyUsed` - Double-spend attempt
		/// * `ProofVerificationFailed` - ZK proof verification failed
		/// * `InsufficientPoolBalance` - Pool doesn't have enough tokens
		/// * `FeeTooLow` - Fee is below `T::Relayer::min_relay_fee()`
		/// * `InvalidMemoSize` - Memo present on a total unshield, or not exactly 180 bytes on a partial one
		#[pallet::call_index(2)]
		#[pallet::weight(T::WeightInfo::unshield().saturating_add(T::ZkVerifier::verification_weight()))]
		#[allow(clippy::too_many_arguments)]
		pub fn unshield(
			origin: OriginFor<T>,
			proof: Proof,
			merkle_root: Hash,
			nullifier: Nullifier,
			asset_id: u32,
			amount: BalanceOf<T>,
			recipient: T::AccountId,
			fee: BalanceOf<T>,
			// Commitment of the change note. Must be [0u8; 32] for total unshield.
			// For partial unshield, must equal NoteCommitment(change_value, asset_id, change_owner_pk, change_blinding).
			change_commitment: Hash,
			// Encrypted memo for the change note: empty for a total unshield, a full
			// 180-byte memo for a partial one (the only on-chain copy of its secrets).
			change_encrypted_memo: FrameEncryptedMemo,
			// Circuit version the spent notes were created under; the proof is
			// verified against this version's VK (not merely the active one).
			circuit_version: u32,
		) -> DispatchResult {
			ensure_spend_origin::<T, _>(origin)?;
			use crate::operations::unshield::{UnshieldOperation, UnshieldRequest};
			UnshieldOperation::execute::<T>(
				&proof,
				UnshieldRequest {
					merkle_root,
					nullifier,
					asset_id,
					amount,
					recipient,
					fee,
					change_commitment,
					change_memo: change_encrypted_memo,
					circuit_version,
				},
			)
		}

		/// Register a new asset in the registry.
		///
		/// Allows governance to register new assets that can be privately transferred.
		/// Assets must be verified before they can be used in shield/unshield operations.
		///
		/// # Arguments
		/// * `origin` - Must be root (governance)
		/// * `name` - Human-readable asset name (max 64 bytes)
		/// * `symbol` - Asset symbol (max 16 bytes, e.g. "USDT")
		/// * `decimals` - Number of decimal places (e.g. 18 for most ERC20)
		/// * `contract_address` - Optional ERC20 contract address for bridged tokens
		///
		/// # Errors
		/// * `BadOrigin` - Caller is not root
		///
		/// # Events
		/// * `AssetRegistered` - Asset was successfully registered
		#[pallet::call_index(9)]
		#[pallet::weight(T::WeightInfo::register_asset())]
		pub fn register_asset(
			origin: OriginFor<T>,
			name: BoundedVec<u8, ConstU32<64>>,
			symbol: BoundedVec<u8, ConstU32<16>>,
			decimals: u8,
			contract_address: Option<[u8; 20]>,
		) -> DispatchResult {
			ensure_root(origin)?;

			let _asset_id = crate::operations::assets::AssetOperation::register::<T>(
				name,
				symbol,
				decimals,
				contract_address,
			)?;

			Ok(())
		}

		/// Verify an asset for use in shield/unshield operations
		///
		/// Marks an asset as verified, allowing it to be used in private transactions.
		/// Only verified assets can be shielded/unshielded.
		///
		/// # Arguments
		/// * `origin` - Must be root (governance)
		/// * `asset_id` - The asset to verify
		///
		/// # Errors
		/// * `BadOrigin` - Caller is not root
		/// * `InvalidAssetId` - Asset does not exist
		///
		/// # Events
		/// * `AssetVerified` - Asset was successfully verified
		#[pallet::call_index(10)]
		#[pallet::weight(T::WeightInfo::verify_asset())]
		pub fn verify_asset(origin: OriginFor<T>, asset_id: u32) -> DispatchResult {
			ensure_root(origin)?;

			crate::operations::assets::AssetOperation::verify::<T>(asset_id)
		}

		/// Unverify an asset — an emergency freeze for a compromised asset.
		///
		/// Marks an asset as unverified. This freezes ALL activity for the asset:
		/// both new shields AND unshields of existing notes require `is_verified`,
		/// so governance can halt inflows and outflows if the asset is compromised.
		/// Note: this also traps legitimate notes until the asset is re-verified —
		/// a deliberate trade-off for a fund-holding pool.
		///
		/// # Arguments
		/// * `origin` - Must be root (governance)
		/// * `asset_id` - The asset to unverify
		///
		/// # Errors
		/// * `BadOrigin` - Caller is not root
		/// * `InvalidAssetId` - Asset does not exist
		///
		/// # Events
		/// * `AssetUnverified` - Asset was successfully unverified
		#[pallet::call_index(11)]
		#[pallet::weight(T::WeightInfo::unverify_asset())]
		pub fn unverify_asset(origin: OriginFor<T>, asset_id: u32) -> DispatchResult {
			ensure_root(origin)?;

			crate::operations::assets::AssetOperation::unverify::<T>(asset_id)
		}

		/// Record relay commits for spends the caller is about to submit.
		///
		/// Each commit is `pallet_relayer::relay_commit_hash(op_hash, relayer)`,
		/// with `op_hash` from `operations::fees::relay_op_hash`. A spend included
		/// in a later block credits its fee to the relayer that committed to it,
		/// whoever submits the spend. The caller must have a registered relay
		/// address; commits expire after `pallet_relayer::Config::CommitTtl`.
		///
		/// # Errors
		/// * `BadOrigin` - Unsigned or Root
		/// * `EmptyBatch` - No commits
		/// * `RelayerNotRegistered` - Signer has no registered relay address
		/// * `pallet_relayer::Error::NotRegistered` - EVM caller is not registered
		/// * `pallet_relayer::Error::TooManyCommits` - Per-block quota exhausted
		#[pallet::call_index(18)]
		#[pallet::weight(T::WeightInfo::commit_relay(commits.len() as u32))]
		pub fn commit_relay(
			origin: OriginFor<T>,
			commits: BoundedVec<sp_core::H256, ConstU32<MAX_RELAY_COMMITS_PER_CALL>>,
		) -> DispatchResult {
			crate::operations::fees::FeeOperation::commit::<T>(
				ensure_relay_caller::<T, _>(origin)?,
				&commits,
			)
		}

		/// Pay the caller's pending relay fees out of the pool, publicly.
		///
		/// | Origin | Fees spent | Paid to |
		/// |---|---|---|
		/// | Signed(who) | `who`'s | mirror of `who`'s registered address, else `who` |
		/// | `Relayed(addr)` (precompile) | those of the account registered to `addr` | mirror of `addr` |
		///
		/// Bounded by the claimant's own pending balance; no proof is needed
		/// because no note is created.
		///
		/// # Errors
		/// * `BadOrigin` - Unsigned or Root
		/// * `RelayerNotRegistered` - EVM caller has no registration
		/// * `InvalidAssetId` / `InvalidAmount` / `InsufficientPoolBalance`
		/// * `pallet_relayer::Error::InsufficientPendingFees` - `amount` exceeds pending fees
		#[pallet::call_index(19)]
		#[pallet::weight(T::WeightInfo::claim_relay_fees())]
		pub fn claim_relay_fees(
			origin: OriginFor<T>,
			asset_id: u32,
			amount: BalanceOf<T>,
		) -> DispatchResult {
			use crate::operations::fees::FeeOperation;
			let (claimant, to) =
				FeeOperation::claimant_and_payee::<T>(ensure_relay_caller::<T, _>(origin)?)?;
			FeeOperation::claim::<T>(claimant, to, asset_id, amount)
		}
	}

	// ========================================================================
	// Unsigned Transaction Validation
	// ========================================================================

	/// Admit unsigned `private_transfer` and `unshield` calls to the transaction
	/// pool: every check the dispatchable runs, plus the proof at admission. The
	/// logic lives in `crate::validate_unsigned`.
	// `ValidateUnsigned` is deprecated in favour of `#[pallet::authorize]` (removal
	// slated for 2027); migrating is a behavioural change scheduled separately. The
	// extra allows cover the macro-expanded code, which trips `-D warnings` on its own.
	#[pallet::validate_unsigned]
	#[allow(deprecated)]
	impl<T: Config> sp_runtime::traits::ValidateUnsigned for Pallet<T> {
		type Call = Call<T>;

		fn validate_unsigned(
			_source: sp_runtime::transaction_validity::TransactionSource,
			call: &Self::Call,
		) -> sp_runtime::transaction_validity::TransactionValidity {
			Self::validate_spend(call, true)
		}

		/// Inside a block the dispatchable verifies the proof itself, and its
		/// weight includes one verification (`verification_weight`): re-run only
		/// the cheap checks here.
		fn pre_dispatch(
			call: &Self::Call,
		) -> Result<(), sp_runtime::transaction_validity::TransactionValidityError> {
			Self::validate_spend(call, false).map(|_| ())
		}
	}

	impl<T: Config> Pallet<T> {
		/// Admission of an unsigned spend; `with_proof` also verifies its proof.
		fn validate_spend(
			call: &Call<T>,
			with_proof: bool,
		) -> sp_runtime::transaction_validity::TransactionValidity {
			use crate::{operations::SpendRequest, validate_unsigned as admit};
			use sp_runtime::transaction_validity::InvalidTransaction;

			let Some((proof, request)) = SpendRequest::from_call(call) else {
				return InvalidTransaction::Call.into();
			};
			let proof = with_proof.then_some(proof.as_slice());
			match request {
				SpendRequest::Transfer(req) => admit::validate_private_transfer(proof, &req),
				SpendRequest::Unshield(req) => admit::validate_unshield(proof, &req),
			}
		}
	}
}
