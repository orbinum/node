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
	AssetId, AssetMetadata, AuditPolicy, AuditTrail, Auditor, Commitment, DEFAULT_TREE_DEPTH,
	DefaultMerklePath, DisclosureCondition, DisclosureRecord, DisclosureRequest,
	EncryptedMemo as FrameEncryptedMemo, Hash, MAX_ENCRYPTED_MEMO_SIZE, MAX_TREE_DEPTH, MerklePath,
	Note, Nullifier,
};

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
	use parity_scale_codec::{Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};

	/// The balance type for this pallet
	pub type BalanceOf<T> =
		<<T as Config>::Currency as Currency<<T as frame_system::Config>::AccountId>>::Balance;

	#[pallet::pallet]
	pub struct Pallet<T>(_);

	/// Input data for a batch disclosure submission
	#[derive(
		Clone,
		Encode,
		Decode,
		DecodeWithMemTracking,
		TypeInfo,
		PartialEq,
		RuntimeDebug,
		MaxEncodedLen
	)]
	pub struct BatchDisclosureSubmission<AccountId> {
		/// The commitment being disclosed
		pub commitment: Commitment,
		/// ZK proof (Groth16, max 256 bytes)
		pub proof: BoundedVec<u8, ConstU32<256>>,
		/// Public signals (76 bytes): [commitment(32)][value(8)][asset_id(4)][owner_hash(32)]
		pub public_signals: BoundedVec<u8, ConstU32<76>>,
		/// Optional auditor. `Some` → Flujo B (requires active DisclosureRequest).
		/// `None` → Flujo A (self-disclosure).
		pub auditor: Option<AccountId>,
	}

	/// Configuration trait for the pallet
	#[pallet::config]
	pub trait Config: frame_system::Config<RuntimeEvent: From<Event<Self>>> {
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

		/// Maximum number of historic roots to keep
		#[pallet::constant]
		type MaxHistoricRoots: Get<u32>;

		/// Minimum amount that can be shielded
		#[pallet::constant]
		type MinShieldAmount: Get<BalanceOf<Self>>;
		/// Weight information for extrinsics in this pallet
		type WeightInfo: WeightInfo;

		/// Number of blocks after which a disclosure request expires
		#[pallet::constant]
		type RequestExpiration: Get<BlockNumberFor<Self>>;
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

	/// Set of used nullifiers (nullifier -> block number when used)
	#[pallet::storage]
	pub type NullifierSet<T: Config> =
		StorageMap<_, Blake2_128Concat, Nullifier, BlockNumberFor<T>, OptionQuery>;

	/// Historic Poseidon Merkle roots (for proving against recent states)
	#[pallet::storage]
	pub type HistoricPoseidonRoots<T> = StorageMap<_, Blake2_128Concat, Hash, bool, ValueQuery>;

	/// Order of historic roots (FIFO queue for pruning)
	/// Stores roots in insertion order, oldest first
	#[pallet::storage]
	pub type HistoricRootsOrder<T: Config> =
		StorageValue<_, BoundedVec<Hash, T::MaxHistoricRoots>, ValueQuery>;

	/// Encrypted memos for commitments
	///
	/// Maps each commitment to its associated encrypted memo.
	/// Memos enable:
	/// - Note recovery by scanning blockchain
	/// - Selective disclosure to authorized auditors
	/// - FATF Travel Rule compliance
	///
	/// Only the note owner (with the correct decryption key) can decrypt the memo.
	#[pallet::storage]
	pub type CommitmentMemos<T> =
		StorageMap<_, Blake2_128Concat, Commitment, FrameEncryptedMemo, OptionQuery>;

	// ========================================================================
	// Audit Policies Storage
	// ========================================================================

	/// Audit policies defined by users
	///
	/// Maps account to their audit policy defining disclosure rules
	#[pallet::storage]
	pub type AuditPolicies<T: Config> = StorageMap<
		_,
		Blake2_128Concat,
		T::AccountId,
		AuditPolicy<T::AccountId, BalanceOf<T>, BlockNumberFor<T>>,
		OptionQuery,
	>;

	/// Pending disclosure requests
	///
	/// Maps (target_account, auditor, request_id) to disclosure request
	#[pallet::storage]
	pub type DisclosureRequests<T: Config> = StorageDoubleMap<
		_,
		Blake2_128Concat,
		T::AccountId, // target account
		Blake2_128Concat,
		T::AccountId, // auditor
		DisclosureRequest<T::AccountId, BlockNumberFor<T>>,
		OptionQuery,
	>;

	/// Disclosure records (parsed results of verified ZK disclosures)
	///
	/// Double-map: (commitment, key) → DisclosureRecord
	/// - Flujo A (self): key = note owner
	/// - Flujo B (audited): key = auditor, record.requester = target
	#[pallet::storage]
	pub type DisclosureRecords<T: Config> = StorageDoubleMap<
		_,
		Blake2_128Concat,
		Commitment,
		Blake2_128Concat,
		T::AccountId,
		DisclosureRecord<T::AccountId, BlockNumberFor<T>>,
		OptionQuery,
	>;

	/// Audit trail for compliance
	///
	/// Stores all disclosure events for regulatory compliance
	#[pallet::storage]
	pub type AuditTrailStorage<T: Config> = StorageMap<
		_,
		Blake2_128Concat,
		Hash, // audit trail hash
		AuditTrail<T::AccountId, BlockNumberFor<T>>,
		OptionQuery,
	>;

	/// Next audit trail ID for generating unique hashes
	#[pallet::storage]
	pub type NextAuditTrailId<T: Config> = StorageValue<_, u64, ValueQuery>;

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

	/// Last disclosure timestamp for rate limiting
	///
	/// Maps (account, commitment) to block number of last disclosure
	/// Used to enforce max_frequency from AuditPolicy
	#[pallet::storage]
	pub type LastDisclosureTimestamp<T: Config> = StorageDoubleMap<
		_,
		Blake2_128Concat,
		T::AccountId, // account owner
		Blake2_128Concat,
		Commitment,
		BlockNumberFor<T>,
		OptionQuery,
	>;

	/// Disclosure counters for O(1) rate limiting
	///
	/// Maps (target_account, auditor) to the total number of completed disclosures.
	/// Incremented on approve_disclosure and submit_disclosure (with auditor).
	/// Replaces the O(n) AuditTrailStorage::iter() scan in request_disclosure.
	#[pallet::storage]
	pub type DisclosureCounters<T: Config> = StorageDoubleMap<
		_,
		Blake2_128Concat,
		T::AccountId, // target account
		Blake2_128Concat,
		T::AccountId, // auditor
		u32,
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
			/// New tree size
			tree_size: u32,
		},

		/// Audit policy was set or updated
		AuditPolicySet {
			/// Account that set the policy
			account: T::AccountId,
			/// Policy version
			version: u32,
		},

		/// A selective disclosure was successfully verified and recorded
		Disclosed {
			/// Account that submitted the disclosure (note owner)
			who: T::AccountId,
			/// Commitment whose note was disclosed
			commitment: Commitment,
			/// Auditor when Flujo B; `None` for self-disclosure (Flujo A)
			auditor: Option<T::AccountId>,
		},

		/// Disclosure request was submitted by auditor
		DisclosureRequested {
			/// Target account to audit
			target: T::AccountId,
			/// Auditor making the request
			auditor: T::AccountId,
			/// Request reason
			reason: BoundedVec<u8, ConstU32<256>>,
		},

		/// Disclosure request was rejected
		DisclosureRejected {
			/// Target account
			target: T::AccountId,
			/// Auditor
			auditor: T::AccountId,
			/// Reason for rejection
			reason: BoundedVec<u8, ConstU32<256>>,
		},

		/// An expired disclosure request was pruned
		DisclosureRequestExpired {
			/// Target account (the account that received the request)
			target: T::AccountId,
			/// Auditor that submitted the request
			auditor: T::AccountId,
		},

		/// A disclosure record was revoked by its creator (Flujo A only)
		DisclosureRecordRevoked {
			/// Account that revoked the record
			who: T::AccountId,
			/// Commitment whose record was revoked
			commitment: Commitment,
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

		/// Relay fees were claimed and sent directly to the relayer's EVM account
		RelayFeesClaimedToEvm {
			/// The validator substrate account that claimed
			validator: T::AccountId,
			/// The EVM address that received the funds
			evm_address: sp_core::H160,
			/// Asset ID of the fees claimed
			asset_id: u32,
			/// Amount transferred to the EVM mirror account
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
		/// The Merkle tree is full
		MerkleTreeFull,
		/// The ZK proof is invalid
		InvalidProof,
		/// Insufficient balance in the pool
		InsufficientPoolBalance,
		/// The amount is below the minimum
		AmountTooSmall,
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
		/// Audit policy not found
		AuditPolicyNotFound,
		/// Auditor not authorized
		AuditorNotAuthorized,
		/// Disclosure conditions not met
		DisclosureConditionsNotMet,
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
		/// Disclosure request already exists
		DisclosureRequestAlreadyExists,
		/// Disclosure request not found
		DisclosureRequestNotFound,
		/// Invalid disclosure record (ZK proof failed or data inconsistent)
		InvalidDisclosureRecord,
		/// Audit policy version mismatch
		AuditPolicyVersionMismatch,
		/// Invalid public signals (length or consistency)
		InvalidPublicSignals,
		/// Invalid disclosure mask (blinding revealed or no fields disclosed)
		InvalidDisclosureMask,
		/// Commitment not found on-chain
		CommitmentNotFound,
		/// Auditor not authorized in policy
		UnauthorizedAuditor,
		/// Disclosure frequency limit exceeded
		DisclosureFrequencyExceeded,
		/// Too many auditors in policy
		TooManyAuditors,
		/// Too many conditions in policy
		TooManyConditions,
		/// Too many disclosure requests
		TooManyDisclosureRequests,
		/// No auditors provided (at least one required)
		NoAuditorsProvided,
		/// Disclosure record already exists for this (commitment, key) pair
		DisclosureRecordAlreadyExists,
		/// Duplicate auditor entry in policy (each auditor must appear at most once)
		DuplicateAuditor,
		/// Disclosure request has expired and can no longer be fulfilled
		DisclosureRequestExpired,
		/// Disclosure request has not yet expired and cannot be pruned
		DisclosureRequestNotExpired,
		/// Audit policy has expired (valid_until block has passed)
		AuditPolicyExpired,
		/// Disclosure record not found for the given commitment
		DisclosureRecordNotFound,
		/// Caller is not the owner of the disclosure record
		NotRecordOwner,
		/// Pending validator fees are less than the requested claim amount
		InsufficientPendingFees,
		/// Caller has no EVM address registered in the relayer registry
		RelayerNotRegistered,
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
		/// for note recovery and selective disclosure.
		///
		/// # Arguments
		/// * `origin` - The account depositing tokens
		/// * `amount` - Amount of tokens to shield
		/// * `commitment` - The commitment for the new note (computed off-chain)
		/// * `encrypted_memo` - Encrypted metadata for note recovery and audit
		///
		/// # Errors
		/// * `AmountTooSmall` - Amount is below minimum
		/// * `MerkleTreeFull` - No more space in the tree
		/// * `CommitmentAlreadyExists` - Duplicate commitment
		/// * `InvalidMemoSize` - Encrypted memo is not exactly 168 bytes
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
		/// * `TooManyOperations` - Batch exceeds maximum size (20)
		///
		/// # Events
		/// * `Shielded` - Emitted for each successful shield in the batch
		///
		/// # Weight
		/// Approximately `N * shield_weight * 0.8` (20% batch discount)
		#[pallet::call_index(12)]
		#[pallet::weight(T::WeightInfo::shield().saturating_mul(operations.len() as u64).saturating_mul(4) / 5)]
		pub fn shield_batch(
			origin: OriginFor<T>,
			operations: BoundedVec<
				(u32, BalanceOf<T>, Commitment, FrameEncryptedMemo),
				ConstU32<20>,
			>,
		) -> DispatchResult {
			let who = ensure_signed(origin)?;

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
		/// * `origin` - Must be none (unsigned transaction)
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
		/// * `InvalidMemoSize` - Any encrypted memo is not exactly 168 bytes
		/// * `MemoCommitmentMismatch` - Number of memos does not match number of commitments
		#[pallet::call_index(1)]
		#[pallet::weight(T::WeightInfo::private_transfer())]
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
			// EVM address of the relay node that signed the tx (from precompile caller); None for direct Substrate.
			relayer: Option<sp_core::H160>,
		) -> DispatchResult {
			ensure_none(origin)?;

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
		/// * `origin` - Must be none (unsigned transaction)
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
			// EVM address of the relay node that signed the tx (from precompile caller); None for direct Substrate.
			relayer: Option<sp_core::H160>,
		) -> DispatchResult {
			ensure_none(origin)?;

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
			)
		}

		/// Set or update audit policy for selective disclosure
		#[pallet::call_index(4)]
		#[pallet::weight(T::WeightInfo::set_audit_policy())]
		pub fn set_audit_policy(
			origin: OriginFor<T>,
			auditors: BoundedVec<Auditor<T::AccountId>, ConstU32<10>>,
			conditions: BoundedVec<
				DisclosureCondition<BalanceOf<T>, BlockNumberFor<T>>,
				ConstU32<10>,
			>,
			max_frequency: Option<BlockNumberFor<T>>,
			valid_until: Option<BlockNumberFor<T>>,
		) -> DispatchResult {
			let who = ensure_signed(origin)?;

			crate::operations::disclosure::DisclosureOperation::set_audit_policy::<T>(
				&who,
				auditors,
				conditions,
				max_frequency,
				valid_until,
			)
		}

		/// Request disclosure from a target account
		#[pallet::call_index(5)]
		#[pallet::weight(T::WeightInfo::request_disclosure())]
		pub fn request_disclosure(
			origin: OriginFor<T>,
			target: T::AccountId,
			reason: BoundedVec<u8, ConstU32<256>>,
		) -> DispatchResult {
			let auditor = ensure_signed(origin)?;

			crate::operations::disclosure::DisclosureOperation::request_disclosure::<T>(
				&auditor, &target, reason,
			)
		}

		/// Submit a selective disclosure proof for a specific commitment.
		///
		/// Unifies Flujo A (self-disclosure) and Flujo B (audited) into a single
		/// extrinsic. The `auditor` parameter selects the flow:
		///
		/// - `None`  → **Flujo A**: self-disclosure. Optional AuditPolicy is checked.
		///   Record stored at `(commitment, who)` and revocable by the owner.
		/// - `Some(auditor)` → **Flujo B**: audited disclosure. Requires an active
		///   `DisclosureRequest` and matching `AuditPolicy`. Record stored at
		///   `(commitment, auditor)` and permanent (not revocable).
		///
		/// # SAFETY
		/// Commitment ownership is enforced by the ZK proof: the Groth16 circuit
		/// reconstructs `commitment` from private inputs, so a passing proof can only
		/// have been generated by the note owner.
		#[pallet::call_index(6)]
		#[pallet::weight(T::WeightInfo::disclose())]
		pub fn disclose(
			origin: OriginFor<T>,
			commitment: Commitment,
			proof_bytes: BoundedVec<u8, ConstU32<256>>,
			// public_signals (76 bytes): [commitment(32)][value(8)][asset_id(4)][owner_hash(32)]
			public_signals: BoundedVec<u8, ConstU32<76>>,
			auditor: Option<T::AccountId>,
		) -> DispatchResult {
			let who = ensure_signed(origin)?;

			crate::operations::disclosure::DisclosureOperation::disclose::<T>(
				&who,
				commitment,
				proof_bytes,
				public_signals,
				auditor.as_ref(),
			)
		}

		/// Reject disclosure request
		#[pallet::call_index(7)]
		#[pallet::weight(T::WeightInfo::reject_disclosure())]
		pub fn reject_disclosure(
			origin: OriginFor<T>,
			auditor: T::AccountId,
			reason: BoundedVec<u8, ConstU32<256>>,
		) -> DispatchResult {
			let target = ensure_signed(origin)?;

			crate::operations::disclosure::DisclosureOperation::reject_disclosure::<T>(
				&target, &auditor, reason,
			)
		}

		#[pallet::call_index(13)]
		#[pallet::weight(T::WeightInfo::batch_submit_disclosure_proofs(submissions.len() as u32))]
		pub fn batch_submit_disclosure_proofs(
			origin: OriginFor<T>,
			submissions: BoundedVec<BatchDisclosureSubmission<T::AccountId>, ConstU32<10>>,
		) -> DispatchResult {
			let who = ensure_signed(origin)?;

			crate::operations::disclosure::DisclosureOperation::batch_submit_proofs::<T>(
				&who,
				submissions,
			)
		}

		/// Register a new asset for use in the shielded pool
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

		/// Unverify an asset, preventing its use in new transactions
		///
		/// Marks an asset as unverified. Existing private notes with this asset
		/// can still be spent, but new shield operations are prevented.
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

		/// Remove an expired disclosure request from storage.
		///
		/// Permissionless cleanup: any account can prune a request whose `expires_at`
		/// block has passed. This prevents storage bloat without requiring an
		/// O(n) on_initialize hook.
		///
		/// # Errors
		/// * `DisclosureRequestNotFound` - No request for (target, auditor)
		/// * `DisclosureRequestNotExpired` - `expires_at` has not passed yet
		#[pallet::call_index(14)]
		#[pallet::weight(T::WeightInfo::prune_expired_request())]
		pub fn prune_expired_request(
			origin: OriginFor<T>,
			target: T::AccountId,
			auditor: T::AccountId,
		) -> DispatchResult {
			let _ = ensure_signed(origin)?;

			let request = DisclosureRequests::<T>::get(&target, &auditor)
				.ok_or(Error::<T>::DisclosureRequestNotFound)?;
			let current_block = frame_system::Pallet::<T>::block_number();
			ensure!(
				current_block > request.expires_at,
				Error::<T>::DisclosureRequestNotExpired
			);
			DisclosureRequests::<T>::remove(&target, &auditor);
			Self::deposit_event(Event::DisclosureRequestExpired { target, auditor });
			Ok(())
		}

		/// Revoke a Flujo A (self-disclosure) record created by the caller.
		///
		/// Removes the `DisclosureRecord` stored at `(commitment, caller)`. Only
		/// applies to self-disclosures — Flujo B records (stored under the auditor
		/// key) are permanent once approved.
		///
		/// # Errors
		/// * `DisclosureRecordNotFound` - No self-disclosure record for `commitment`
		#[pallet::call_index(15)]
		#[pallet::weight(T::WeightInfo::revoke_disclosure_record())]
		pub fn revoke_disclosure_record(
			origin: OriginFor<T>,
			commitment: Commitment,
		) -> DispatchResult {
			let who = ensure_signed(origin)?;

			ensure!(
				DisclosureRecords::<T>::contains_key(commitment, &who),
				Error::<T>::DisclosureRecordNotFound
			);
			DisclosureRecords::<T>::remove(commitment, &who);
			Self::deposit_event(Event::DisclosureRecordRevoked { who, commitment });
			Ok(())
		}

		/// Claim accumulated validator fees as a private shielded note.
		///
		/// Converts pending relay fee credits into a Merkle tree commitment.
		/// A selective-disclosure ZK proof (disclosure circuit) must be supplied
		/// proving that `commitment` encodes exactly `amount` and `asset_id`.
		/// This closes the KNOWN LIMITATION that existed in the previous design.
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
			proof: sp_std::vec::Vec<u8>,
			public_signals: sp_std::vec::Vec<u8>,
		) -> DispatchResult {
			let validator = ensure_signed(origin)?;
			crate::operations::fees::FeeOperation::claim_shielded::<T>(
				validator,
				commitment,
				amount,
				asset_id,
				memo,
				proof,
				public_signals,
			)
		}

		/// Claim accumulated relay fees and transfer them directly to the
		/// relayer's EVM account.
		///
		/// Converts the pending relay-fee balance for (`origin`, `asset_id`) into
		/// real tokens sent to the H160 EVM mirror account
		/// (`H160[0..20] ++ [0x00; 12]`).  The EVM sees the balance immediately —
		/// no ZK proof or `unshield` step required.
		///
		/// This is the preferred path for gasless relayers: the H160 that pays
		/// EVM gas fees is automatically refunded without any manual token bridging.
		///
		/// # Arguments
		/// * `origin` - Signed validator/relayer (sr25519 / Aura key)
		/// * `asset_id` - Asset whose pending fees to claim
		/// * `amount` - Amount to transfer (must be ≤ pending balance)
		///
		/// # Errors
		/// * `InvalidAssetId` - Asset is not registered
		/// * `RelayerNotRegistered` - Caller has no H160 in the relayer registry
		/// * `InsufficientPendingFees` - Pending balance < `amount`
		/// * `InsufficientPoolBalance` - Pool lacks tokens (invariant violation)
		#[pallet::call_index(17)]
		#[pallet::weight(T::WeightInfo::claim_shielded_fees())]
		pub fn claim_relay_fees_to_evm(
			origin: OriginFor<T>,
			asset_id: u32,
			amount: BalanceOf<T>,
		) -> DispatchResult {
			let validator = ensure_signed(origin)?;
			crate::operations::fees::FeeOperation::claim_to_evm::<T>(validator, asset_id, amount)
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
					..
				} => crate::validate_unsigned::validate_private_transfer::<T>(
					merkle_root,
					nullifiers,
					fee,
				),

				Call::unshield {
					merkle_root,
					nullifier,
					asset_id,
					amount,
					fee,
					..
				} => crate::validate_unsigned::validate_unshield::<T>(
					merkle_root,
					nullifier,
					asset_id,
					amount,
					fee,
				),

				_ => InvalidTransaction::Call.into(),
			}
		}
	}
}
