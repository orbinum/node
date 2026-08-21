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
//! ShieldedPool::shield(origin, amount, commitment)?;
//!
//! // Transfer privately
//! ShieldedPool::private_transfer(origin, proof)?;
//!
//! // Withdraw from the pool
//! ShieldedPool::unshield(origin, proof, nullifier, amount, recipient)?;
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub use pallet::*;

#[cfg(test)]
mod mock;

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;

// Business layers
pub mod genesis;
pub mod helpers;
pub mod merkle;
pub mod operations;
pub mod storage;
pub mod types;
pub mod validate_unsigned;

// Pallet weights
pub mod weights;

pub use weights::WeightInfo;

// Runtime API implementation
mod runtime_api_impl;

// Re-export types for external use
pub use types::{
	AssetId, AssetMetadata, Commitment, DEFAULT_TREE_DEPTH, DefaultMerklePath,
	EncryptedMemo as FrameEncryptedMemo, Hash, MAX_ENCRYPTED_MEMO_SIZE, MAX_TREE_DEPTH, MerklePath,
	Note, Nullifier,
};

use frame_support::pallet_prelude::{Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};
use scale_info::TypeInfo;
use sp_runtime::RuntimeDebug;

/// Who submitted a relayed spend, as established by the dispatch path itself.
///
/// Relay fees are paid to whoever *submitted* the operation, never to an
/// address named in the call. The distinction is the whole point: a ZK proof
/// authenticates the spend but says nothing about who relayed it, so a
/// recipient carried as a call argument is an unauthenticated claim that any
/// resubmitter can rewrite. An origin cannot be forged — the EVM executor
/// sets it from the transaction signature.
#[derive(
	PartialEq,
	Eq,
	Clone,
	RuntimeDebug,
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
	use sp_runtime::traits::BadOrigin;

	/// The balance type for this pallet
	pub type BalanceOf<T> =
		<<T as Config>::Currency as Currency<<T as frame_system::Config>::AccountId>>::Balance;

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

	#[pallet::pallet]
	#[pallet::storage_version(STORAGE_VERSION)]
	pub struct Pallet<T>(_);

	#[pallet::origin]
	pub type Origin = RawOrigin;

	/// Extracts the relaying address from `origin`, if the dispatch path
	/// established one.
	///
	/// Three accepted shapes, all of them authenticated or deliberately anonymous:
	///
	/// | Origin | Relayer | Why |
	/// |---|---|---|
	/// | `Relayed(addr)` | `Some(addr)` | EVM precompile; `addr` signed the transaction |
	/// | Signed(who) | `who`'s registered address | the signature proves who submitted |
	/// | `None` | `None` | no relayer named; fee goes to the block author |
	///
	/// A signed submitter with no registered address resolves to `None` rather
	/// than failing: relaying is not gated on registration, so its fee falls back
	/// to the block author exactly as an unregistered EVM caller's would.
	pub fn ensure_relayed<T: Config, OuterOrigin>(
		o: OuterOrigin,
	) -> Result<Option<sp_core::H160>, BadOrigin>
	where
		OuterOrigin: Into<Result<Origin, OuterOrigin>>
			+ Into<Result<frame_system::RawOrigin<T::AccountId>, OuterOrigin>>,
	{
		use pallet_relayer::RelayerInterface;

		match Into::<Result<Origin, OuterOrigin>>::into(o) {
			Ok(RawOrigin::Relayed(who)) => Ok(Some(who)),
			Err(other) => match other.into() {
				Ok(frame_system::RawOrigin::None) => Ok(None),
				Ok(frame_system::RawOrigin::Signed(who)) => {
					Ok(T::Relayer::registered_evm_address(&who))
				}
				_ => Err(BadOrigin),
			},
		}
	}

	/// Configuration trait for the pallet
	#[pallet::config]
	pub trait Config:
		frame_system::Config<
			RuntimeEvent: From<Event<Self>>,
			// Relay attribution reads the origin rather than a call argument, so the
			// outer origin must be convertible back to this pallet's own variant.
			RuntimeOrigin: Into<Result<Origin, <Self as frame_system::Config>::RuntimeOrigin>>,
		>
	{
		/// The currency mechanism
		type Currency: Currency<Self::AccountId> + ReservableCurrency<Self::AccountId>;

		/// ZK proof verifier (domain port)
		type ZkVerifier: ZkVerifierPort;

		/// Relay configuration, fee accounting and block-author lookup.
		///
		/// In production: `pallet_relayer::Pallet<Runtime>`.
		/// In tests: a lightweight mock struct in `mock.rs`.
		type Relayer: pallet_relayer::RelayerInterface<AccountId = Self::AccountId>;

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
		/// The trade is storage against query latency, and it is lopsided: nodes
		/// concentrate at the bottom, so cutting at level 10 drops 99.8% of the
		/// entries (1_048_574 -> 2_046 per tree) while a path costs 2^10 leaf
		/// reads and 1_023 Poseidon hashes — about 60ms native, ~180ms in Wasm.
		/// Cutting at 12 frees only 0.15% more for four times the work.
		///
		/// Configurable rather than fixed: the recompute cost tracks validator
		/// hardware. Must be non-zero and below the tree depth (`integrity_test`).
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
	/// Stores the last left-sibling at each of the 20 levels of the tree.
	/// Updated in O(depth) on every `insert_leaf`, replacing the former
	/// O(n) full recomputation from all leaves.
	/// Depth is fixed at `DEFAULT_TREE_DEPTH = 20`.
	#[pallet::storage]
	pub type MerkleTreeFrontier<T> = StorageValue<_, [[u8; 32]; 20], ValueQuery>;

	/// Merkle tree leaves (index -> commitment)
	#[pallet::storage]
	pub type MerkleLeaves<T> = StorageMap<_, Blake2_128Concat, u32, Commitment, OptionQuery>;

	/// Reverse index: commitment -> leaf index.
	///
	/// Populated on every `insert_leaf`. Enables O(1) lookup for Merkle proof
	/// generation and duplicate-commitment checks, replacing the former O(n)
	/// linear scan over `MerkleLeaves`.
	#[pallet::storage]
	pub type CommitmentToLeafIndex<T> =
		StorageMap<_, Blake2_128Concat, Commitment, u32, OptionQuery>;

	/// Internal Merkle tree nodes: `(tree_id, level, index) -> node hash`.
	///
	/// Written during the frontier walk of `insert_leaf` (the values were already
	/// computed there and formerly discarded). Turns Merkle proof generation into
	/// O(depth) point reads instead of an O(n) recomputation from all leaves.
	///
	/// Levels run 1..=19: level 0 is `MerkleLeaves`, level 20 is `PoseidonRoot`.
	/// A missing entry means the subtree below it is empty (zero hash).
	/// `tree_id` is fixed at 0 while the pool runs a single tree; the key shape
	/// is `(tree_id, level, index)` so a multi-tree forest needs no remapping.
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
	/// Counting insertions instead made the window rotate faster than
	/// transactions expire under load, so honest spends reverted with
	/// `UnknownMerkleRoot` after propagating.
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
	/// `insert_leaf` (shield, private_transfer output, claim_shielded_fees).
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
			assert!(
				!cfg!(feature = "skip-proof-verification") || cfg!(feature = "runtime-benchmarks"),
				"pallet-shielded-pool compiled with `skip-proof-verification` but without \
				 `runtime-benchmarks`: shield/unshield/transfer proofs are NOT verified \
				 outside a benchmark build. This must never run on a live chain."
			);

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
		/// the pool until their note is unshielded, so both move together.
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

		/// A relay fee went to the block author instead of the address the call
		/// named, because that address resolves to no registered relayer.
		///
		/// Not an error — the fallback is deliberate, since relaying is not gated
		/// on registration and failing here would reject a user's transaction over
		/// someone else's misconfiguration. The event exists so the diversion is
		/// visible: a relayer that forgot to register can see where its fees went,
		/// and the redirection leaves an on-chain trace either way.
		///
		/// This does not flag fee substitution by a registered relayer: such a
		/// caller is an approved validator with a registered address, so the fee
		/// resolves normally and no diversion is recorded.
		RelayFeeDiverted {
			/// The address the call asked to credit.
			requested: sp_core::H160,
			/// Who was credited instead.
			credited: T::AccountId,
			asset_id: u32,
			amount: u128,
		},

		/// A relay fee was credited to a relayer that also authored the block it
		/// landed in.
		///
		/// Only fires when an authenticated relayer *resolved* and turned out to be
		/// the author. The fallback path — no relayer named, fee to the author —
		/// does not emit: it happens on every unrelayed call and carries no claim
		/// about who relayed anything, so reporting it would bury the signal.
		///
		/// Legitimate and expected: with N authors in rotation this occurs about
		/// 1/N of the time on its own. It is published because it is the only
		/// on-chain trace of the one attack the origin-based attribution does not
		/// prevent — an author may ignore its own pool ordering and include a copy
		/// of another node's spend pointed at itself. A single event proves
		/// nothing; a self-relay rate materially above 1/N sustained over many
		/// sessions does. Adjudication is off-chain, enforcement is
		/// `validatorSet.removeValidator`.
		SelfRelayedFee {
			author: T::AccountId,
			asset_id: u32,
			amount: u128,
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

		/// Validator claimed their accumulated fees as a private shielded note
		ValidatorFeesClaimed {
			/// The validator account that claimed
			validator: T::AccountId,
			/// Asset ID of the fees claimed
			asset_id: u32,
			/// Amount claimed
			amount: BalanceOf<T>,
			/// Commitment inserted into the Merkle tree
			commitment: Commitment,
			/// Leaf index of the new note
			leaf_index: u32,
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
		/// The ZK proof is invalid
		InvalidProof,
		/// Insufficient balance in the pool
		InsufficientPoolBalance,
		/// The amount is invalid (zero or overflow)
		InvalidAmount,
		/// Too many inputs or outputs
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
		/// Asset ID mismatch between parameters
		AssetIdMismatch,
		/// Recipient address is zero (burn address)
		InvalidRecipient,
		/// Gasless fee is below the required minimum
		FeeTooLow,
		/// Invalid public signals (length or consistency)
		InvalidPublicSignals,
		/// Commitment not found on-chain
		CommitmentNotFound,
		/// Pending validator fees are less than the requested claim amount
		InsufficientPendingFees,
		/// A non-zero fee could not be attributed to any recipient (no resolved
		/// relayer and no block author). The fee tokens would otherwise be stranded.
		FeeRecipientUnavailable,
		/// Batch operation submitted with no operations.
		EmptyBatch,
		/// Asset id counter collided with an existing asset (would overwrite it).
		AssetIdAlreadyExists,
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
		///
		/// # Errors
		/// * `InvalidAmount` - Amount is zero
		/// * `MerkleTreeFull` - No more space in the tree
		/// * `CommitmentAlreadyExists` - Duplicate commitment
		/// * `InvalidMemoSize` - Encrypted memo is not exactly 180 bytes
		#[pallet::call_index(0)]
		#[pallet::weight(T::WeightInfo::shield())]
		pub fn shield(
			origin: OriginFor<T>,
			asset_id: u32,
			amount: BalanceOf<T>,
			commitment: Commitment,
			encrypted_memo: FrameEncryptedMemo,
		) -> DispatchResult {
			let who = ensure_signed(origin)?;

			// Delegate to business operation
			crate::operations::shield::ShieldOperation::execute::<T>(
				who,
				asset_id,
				amount,
				commitment,
				encrypted_memo,
			)
		}

		/// Deposit multiple tokens into the shielded pool in a single transaction.
		///
		/// **OPT-1.2:** Batch optimization that processes multiple shields together,
		/// amortizing tree traversal costs and reducing overhead per operation.
		///
		/// This is more efficient than calling `shield()` multiple times separately:
		/// - Shares tree state across operations
		/// - Reduces transaction overhead (~20% faster per shield)
		/// - Optimal for 5-20 shields per batch
		///
		/// # Arguments
		/// * `origin` - The account depositing tokens
		/// * `operations` - Vec of (asset_id, amount, commitment, encrypted_memo) tuples
		///
		/// # Errors
		/// * Same as `shield()` for any individual operation
		/// * `EmptyBatch` - Batch submitted with no operations
		/// * `TooManyOperations` - Batch exceeds maximum size (20)
		///
		/// # Events
		/// * `Shielded` - Emitted for each successful shield in the batch
		///
		/// # Weight
		/// Benchmarked per operation count via `shield_batch(n)`.
		#[pallet::call_index(12)]
		#[pallet::weight(T::WeightInfo::shield_batch(operations.len() as u32))]
		pub fn shield_batch(
			origin: OriginFor<T>,
			operations: BoundedVec<
				(u32, BalanceOf<T>, Commitment, FrameEncryptedMemo),
				ConstU32<20>,
			>,
		) -> DispatchResult {
			let who = ensure_signed(origin)?;
			ensure!(!operations.is_empty(), Error::<T>::EmptyBatch);

			// Process each shield operation
			for (asset_id, amount, commitment, encrypted_memo) in operations.into_iter() {
				crate::operations::shield::ShieldOperation::execute::<T>(
					who.clone(),
					asset_id,
					amount,
					commitment,
					encrypted_memo,
				)?;
			}

			Ok(())
		}

		/// Execute a private transfer within the shielded pool.
		///
		/// This spends existing notes (via nullifiers) and creates new notes
		/// (via commitments). A ZK proof verifies the transfer is valid without
		/// revealing amounts or participants. The fee is embedded in the ZK proof
		/// (input_sum == output_sum + fee) and paid to the fee collector without
		/// a transaction signer, preserving full sender privacy.
		///
		/// # Arguments
		/// * `origin` - Unsigned, signed, or the precompile's relayed origin; it
		///   determines who is credited the relay fee (see `ensure_relayed`)
		/// * `proof` - The ZK proof of valid transfer
		/// * `merkle_root` - The Merkle root the proof was computed against
		/// * `nullifiers` - Nullifiers for notes being spent
		/// * `commitments` - Commitments for new notes being created
		/// * `encrypted_memos` - Encrypted metadata for each new note
		/// * `asset_id` - Asset being transferred (public input of the proof)
		/// * `fee` - Gasless fee (must match proof's fee public input)
		///
		/// # Errors
		/// * `UnknownMerkleRoot` - Root is not in historic roots
		/// * `NullifierAlreadyUsed` - Double-spend attempt
		/// * `InvalidProof` - ZK proof verification failed
		/// * `FeeTooLow` - Fee is below `T::Relayer::min_relay_fee()`
		/// * `InvalidMemoSize` - Any encrypted memo is not exactly 180 bytes
		/// * `MemoCommitmentMismatch` - Number of memos does not match number of commitments
		#[pallet::call_index(1)]
		#[pallet::weight(T::WeightInfo::private_transfer(commitments.len() as u32))]
		#[allow(clippy::too_many_arguments)]
		pub fn private_transfer(
			origin: OriginFor<T>,
			#[allow(unused_variables)] proof: BoundedVec<u8, ConstU32<512>>,
			merkle_root: Hash,
			nullifiers: BoundedVec<Nullifier, ConstU32<2>>,
			commitments: BoundedVec<Commitment, ConstU32<2>>,
			encrypted_memos: BoundedVec<FrameEncryptedMemo, ConstU32<2>>,
			asset_id: u32,
			fee: BalanceOf<T>,
			circuit_version: u32,
		) -> DispatchResult {
			// The relayer is established by HOW the call arrived, never by what it
			// carries: an argument would be an unauthenticated claim.
			let relayer = ensure_relayed::<T, _>(origin)?;

			// Delegate to business operation
			crate::operations::private_transfer::PrivateTransferOperation::execute::<T>(
				proof,
				merkle_root,
				nullifiers,
				commitments,
				encrypted_memos,
				asset_id,
				fee,
				relayer,
				circuit_version,
			)
		}

		/// Withdraw tokens from the shielded pool to a public account.
		///
		/// This spends a private note and transfers the tokens to a public recipient.
		/// A ZK proof verifies ownership of the note without revealing which note.
		/// The fee is embedded in the ZK proof (note_value == amount + fee) and
		/// paid to the fee collector without a transaction signer.
		///
		/// # Arguments
		/// * `origin` - Unsigned, signed, or the precompile's relayed origin; it
		///   determines who is credited the relay fee (see `ensure_relayed`)
		/// * `proof` - The ZK proof of valid withdrawal
		/// * `merkle_root` - The Merkle root the proof was computed against
		/// * `nullifier` - Nullifier for the note being spent
		/// * `asset_id` - Asset being unshielded
		/// * `amount` - Net amount to withdraw (recipient receives this)
		/// * `recipient` - Public account to receive tokens
		/// * `fee` - Gasless fee (must match proof's fee public input)
		/// * `change_commitment` - Commitment of the change note (empty [0u8; 32] for total unshield)
		/// * `change_encrypted_memo` - Encrypted memo for the change note (None for total unshield)
		///
		/// # Errors
		/// * `UnknownMerkleRoot` - Root is not in historic roots
		/// * `NullifierAlreadyUsed` - Double-spend attempt
		/// * `InvalidProof` - ZK proof verification failed
		/// * `InsufficientPoolBalance` - Pool doesn't have enough tokens
		/// * `FeeTooLow` - Fee is below `T::Relayer::min_relay_fee()`
		/// * `InvalidMemoSize` - Change encrypted memo is invalid size
		#[pallet::call_index(2)]
		#[pallet::weight(T::WeightInfo::unshield())]
		#[allow(clippy::too_many_arguments)]
		pub fn unshield(
			origin: OriginFor<T>,
			#[allow(unused_variables)] proof: BoundedVec<u8, ConstU32<512>>,
			merkle_root: Hash,
			nullifier: Nullifier,
			asset_id: u32,
			amount: BalanceOf<T>,
			recipient: T::AccountId,
			fee: BalanceOf<T>,
			// Commitment of the change note. Must be [0u8; 32] for total unshield.
			// For partial unshield, must equal NoteCommitment(change_value, asset_id, change_owner_pk, change_blinding).
			change_commitment: Hash,
			// Encrypted memo for the change note. Must be [0u8; 0] for total unshield.
			// For partial unshield, contains encrypted plaintext: [value_lo(8), value_hi(8), owner_pk(32), blinding(32), asset_id(4), counterparty_pk(32)].
			change_encrypted_memo: FrameEncryptedMemo,
			// Circuit version the spent notes were created under; the proof is
			// verified against this version's VK (not merely the active one).
			circuit_version: u32,
		) -> DispatchResult {
			// The relayer is established by HOW the call arrived, never by what it
			// carries: an argument would be an unauthenticated claim.
			let relayer = ensure_relayed::<T, _>(origin)?;

			// Delegate to business operation
			crate::operations::unshield::UnshieldOperation::execute::<T>(
				&proof,
				merkle_root,
				nullifier,
				asset_id,
				amount,
				recipient,
				fee,
				change_commitment,
				change_encrypted_memo,
				relayer,
				circuit_version,
			)
		}

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

		/// Claim accumulated validator fees as a private shielded note.
		///
		/// Converts pending relay fee credits into a Merkle tree commitment.
		/// A value_proof ZK proof must be supplied, proving that `commitment`
		/// encodes exactly `amount` and `asset_id`.
		///
		/// The caller can only spend its own pending fees (keyed by the signed
		/// origin), but the resulting note's owner is chosen by the caller — the
		/// note need not belong to the validator. This is intentional: a relayer
		/// may direct its own earned fees to any shielded recipient.
		///
		/// # Errors
		/// * `InvalidProof` - ZK proof verification failed or wrong length (expected 128 bytes)
		/// * `InvalidPublicSignals` - Signals mismatch commitment/amount/asset_id, or wrong length (expected 76 bytes)
		/// * `InvalidAmount` - Amount exceeds u64::MAX (circuit signal size)
		/// * `InsufficientPendingFees` - Caller has fewer pending fees than `amount`
		/// * `InvalidAssetId` - No such asset registered
		/// * `MerkleTreeFull` - Merkle tree cannot accept more leaves
		#[pallet::call_index(16)]
		#[pallet::weight(T::WeightInfo::claim_shielded_fees())]
		pub fn claim_shielded_fees(
			origin: OriginFor<T>,
			commitment: Commitment,
			amount: BalanceOf<T>,
			asset_id: u32,
			memo: FrameEncryptedMemo,
			proof: BoundedVec<u8, ConstU32<512>>,
			public_signals: BoundedVec<u8, ConstU32<128>>,
			// Circuit version the spent notes were created under; the proof is
			// verified against this version's VK (not merely the active one).
			circuit_version: u32,
		) -> DispatchResult {
			let validator = ensure_signed(origin)?;
			crate::operations::fees::FeeOperation::claim_shielded::<T>(
				validator,
				commitment,
				amount,
				asset_id,
				memo,
				proof.into_inner(),
				public_signals.into_inner(),
				circuit_version,
			)
		}
	}

	// ========================================================================
	// Unsigned Transaction Validation (Gasless Privacy)
	// ========================================================================
	//
	// Lightweight anti-spam checks only — full ZK verification happens in each
	// extrinsic body.  Logic lives in `crate::validate_unsigned` for testability.

	/// Validate unsigned private_transfer and unshield transactions before
	/// they enter the transaction pool.  Full ZK proof verification happens
	/// inside the extrinsic; here we do lightweight anti-spam checks only.
	#[pallet::validate_unsigned]
	impl<T: Config> sp_runtime::traits::ValidateUnsigned for Pallet<T> {
		type Call = Call<T>;

		fn validate_unsigned(
			_source: sp_runtime::transaction_validity::TransactionSource,
			call: &Self::Call,
		) -> sp_runtime::transaction_validity::TransactionValidity {
			use sp_runtime::transaction_validity::InvalidTransaction;

			match call {
				Call::private_transfer {
					merkle_root,
					nullifiers,
					fee,
					circuit_version,
					..
				} => crate::validate_unsigned::validate_private_transfer::<T>(
					merkle_root,
					nullifiers,
					fee,
					*circuit_version,
				),

				Call::unshield {
					merkle_root,
					nullifier,
					asset_id,
					amount,
					fee,
					circuit_version,
					..
				} => crate::validate_unsigned::validate_unshield::<T>(
					merkle_root,
					nullifier,
					asset_id,
					amount,
					fee,
					*circuit_version,
				),

				_ => InvalidTransaction::Call.into(),
			}
		}
	}
}

// ─── Origin-based relay attribution ──────────────────────────────────────────

#[cfg(test)]
mod origin_tests {
	use super::pallet::ensure_relayed;
	use crate::{
		RawOrigin,
		mock::{RuntimeOrigin, Test, acc, mock_register_relayer, new_test_ext},
	};
	use sp_core::H160;

	fn evm(byte: u8) -> H160 {
		H160::repeat_byte(byte)
	}

	/// The precompile path: whatever the EVM executor put in `caller` is the
	/// relayer, verbatim and unresolved — the registry lookup happens later, in
	/// `credit_relay_fee`.
	#[test]
	fn a_relayed_origin_yields_its_address() {
		new_test_ext().execute_with(|| {
			let origin: RuntimeOrigin = RawOrigin::Relayed(evm(0xAA)).into();
			assert_eq!(ensure_relayed::<Test, _>(origin).unwrap(), Some(evm(0xAA)));
		});
	}

	/// Unsigned submissions name nobody. Not an error: the fee falls back to the
	/// block author, which is the pre-existing behaviour for an unnamed relayer.
	#[test]
	fn an_unsigned_origin_names_nobody() {
		new_test_ext().execute_with(|| {
			assert_eq!(ensure_relayed::<Test, _>(RuntimeOrigin::none()).unwrap(), None);
		});
	}

	/// The signed path resolves through the reverse index, so a signer is paid
	/// only for an address it actually registered.
	#[test]
	fn a_signed_origin_resolves_the_signers_registered_address() {
		new_test_ext().execute_with(|| {
			mock_register_relayer(acc(7), evm(0xBB));
			let origin: RuntimeOrigin = frame_system::RawOrigin::Signed(acc(7)).into();
			assert_eq!(ensure_relayed::<Test, _>(origin).unwrap(), Some(evm(0xBB)));
		});
	}

	/// An unregistered signer is not rejected — relaying is not gated on
	/// registration — it simply names nobody, exactly like an unsigned call.
	#[test]
	fn an_unregistered_signer_names_nobody() {
		new_test_ext().execute_with(|| {
			let origin: RuntimeOrigin = frame_system::RawOrigin::Signed(acc(9)).into();
			assert_eq!(ensure_relayed::<Test, _>(origin).unwrap(), None);
		});
	}

	/// Root must not be able to attribute a fee. Sudo dispatches with Root, so
	/// accepting it here would make `sudo.sudo(unshield { .. })` a way to pay an
	/// arbitrary party — the very thing removing the call argument prevents.
	#[test]
	fn root_cannot_relay() {
		new_test_ext().execute_with(|| {
			assert!(
				ensure_relayed::<Test, _>(RuntimeOrigin::root()).is_err(),
				"root must not be able to attribute a relay fee"
			);
		});
	}

	/// One signer, one address: registering a second account must not let the
	/// first claim it.
	#[test]
	fn a_signer_cannot_claim_another_accounts_address() {
		new_test_ext().execute_with(|| {
			mock_register_relayer(acc(1), evm(0xC1));
			mock_register_relayer(acc(2), evm(0xC2));

			let one: RuntimeOrigin = frame_system::RawOrigin::Signed(acc(1)).into();
			assert_eq!(ensure_relayed::<Test, _>(one).unwrap(), Some(evm(0xC1)));

			let two: RuntimeOrigin = frame_system::RawOrigin::Signed(acc(2)).into();
			assert_eq!(ensure_relayed::<Test, _>(two).unwrap(), Some(evm(0xC2)));
		});
	}
}
