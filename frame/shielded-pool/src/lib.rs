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

#[cfg(test)]
mod tests;

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;

// Clean Architecture layers
pub mod application;
pub mod domain;
pub mod infrastructure;

// Pallet weights
pub mod weights;

pub use weights::WeightInfo;

// Runtime API implementation
mod runtime_api_impl;

// Re-export domain types for external use
pub use application::DepositInfo;
pub use domain::entities::AssetMetadata;
pub use domain::entities::audit::{AuditPolicy, AuditTrail, DisclosureProof, DisclosureRequest};
pub use domain::value_objects::audit::{Auditor, DisclosureCondition};
pub use domain::value_objects::{
	DEFAULT_TREE_DEPTH, DefaultMerklePath, Hash, MAX_TREE_DEPTH, MerklePath,
};
pub use domain::value_objects::{MAX_MEMO_SIZE, StandardEncryptedMemo};
pub use domain::{Commitment, Note, Nullifier, value_objects::AssetId};
// Re-export FRAME-specific EncryptedMemo for storage compatibility
pub use infrastructure::frame_types::EncryptedMemo as FrameEncryptedMemo;

#[frame_support::pallet]
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
	use sp_runtime::traits::AccountIdConversion;

	/// The balance type for this pallet
	pub type BalanceOf<T> =
		<<T as Config>::Currency as Currency<<T as frame_system::Config>::AccountId>>::Balance;

	#[pallet::pallet]
	pub struct Pallet<T>(_);

	/// Input data for a batch disclosure proof submission
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
	pub struct BatchDisclosureSubmission {
		/// The commitment being disclosed
		pub commitment: Commitment,
		/// ZK proof (Groth16)
		pub proof: BoundedVec<u8, ConstU32<2048>>,
		/// Public signals for the proof (76 bytes)
		pub public_signals: BoundedVec<u8, ConstU32<128>>,
		/// Disclosed data (encrypted for auditor)
		pub disclosed_data: BoundedVec<u8, ConstU32<512>>,
	}

	/// Configuration trait for the pallet
	#[pallet::config]
	pub trait Config: frame_system::Config<RuntimeEvent: From<Event<Self>>> {
		/// The currency mechanism
		type Currency: Currency<Self::AccountId> + ReservableCurrency<Self::AccountId>;

		/// ZK proof verifier (domain port)
		type ZkVerifier: ZkVerifierPort;

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

	/// Merkle tree leaves (index -> commitment)
	#[pallet::storage]
	pub type MerkleLeaves<T> = StorageMap<_, Blake2_128Concat, u32, Commitment, OptionQuery>;

	/// Set of used nullifiers (nullifier -> block number when used)
	#[pallet::storage]
	pub type NullifierSet<T: Config> =
		StorageMap<_, Blake2_128Concat, Nullifier, BlockNumberFor<T>, OptionQuery>;

	/// Total balance held in the shielded pool
	#[pallet::storage]
	#[pallet::getter(fn pool_balance)]
	pub type PoolBalance<T: Config> = StorageValue<_, BalanceOf<T>, ValueQuery>;

	/// Historic Poseidon Merkle roots (for proving against recent states)
	#[pallet::storage]
	pub type HistoricPoseidonRoots<T> = StorageMap<_, Blake2_128Concat, Hash, bool, ValueQuery>;

	/// Order of historic roots (FIFO queue for pruning)
	/// Stores roots in insertion order, oldest first
	#[pallet::storage]
	pub type HistoricRootsOrder<T: Config> =
		StorageValue<_, BoundedVec<Hash, T::MaxHistoricRoots>, ValueQuery>;

	/// Deposit information for tracking
	#[pallet::storage]
	pub type Deposits<T: Config> = StorageMap<
		_,
		Blake2_128Concat,
		Commitment,
		DepositInfo<T::AccountId, BalanceOf<T>, BlockNumberFor<T>>,
		OptionQuery,
	>;

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
	// Audit Policies Storage (Phase 4)
	// ========================================================================

	/// Disclosure verifying key
	///
	/// Stores the verifying key for disclosure ZK proofs.
	/// Only governance (root) can update this key.
	/// Format: Raw bytes of ark-groth16 VerifyingKey serialized
	#[pallet::storage]
	pub type DisclosureVerifyingKey<T> =
		StorageValue<_, BoundedVec<u8, ConstU32<4096>>, OptionQuery>;

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

	/// Approved disclosures
	///
	/// Maps commitment to disclosure proof
	#[pallet::storage]
	pub type DisclosureProofs<T: Config> =
		StorageMap<_, Blake2_128Concat, Commitment, DisclosureProof, OptionQuery>;

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
			// Delegate to infrastructure layer for genesis initialization
			crate::infrastructure::genesis::initialize_genesis::<T>(self.initial_root);
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

		/// A private transfer was executed
		PrivateTransfer {
			/// Nullifiers of spent notes
			nullifiers: BoundedVec<Nullifier, ConstU32<2>>,
			/// New commitments created
			commitments: BoundedVec<Commitment, ConstU32<2>>,
			/// Encrypted memos for new notes
			encrypted_memos: BoundedVec<FrameEncryptedMemo, ConstU32<2>>,
			/// Indices of new leaves
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

		/// Disclosure verifying key was updated
		DisclosureVerifyingKeyUpdated {
			/// Size of the new VK in bytes
			vk_size: u32,
		},

		/// Disclosure proof was submitted on-chain
		DisclosureSubmitted {
			/// Account that submitted the proof
			who: T::AccountId,
			/// Commitment being disclosed
			commitment: Commitment,
			/// Size of the proof in bytes
			proof_size: u32,
		},

		/// Disclosure proof was verified successfully
		DisclosureVerified {
			/// Account that submitted the proof
			who: T::AccountId,
			/// Commitment that was verified
			commitment: Commitment,
			/// Whether verification succeeded
			verified: bool,
		},

		/// Audit trail was recorded for compliance
		AuditTrailRecorded {
			/// Account being audited
			account: T::AccountId,
			/// Auditor performing audit
			auditor: T::AccountId,
			/// Commitment disclosed
			commitment: Commitment,
			/// Audit trail hash
			trail_hash: Hash,
		},

		/// Disclosure request was submitted
		DisclosureRequested {
			/// Target account to audit
			target: T::AccountId,
			/// Auditor making the request
			auditor: T::AccountId,
			/// Request reason
			reason: BoundedVec<u8, ConstU32<256>>,
		},

		/// Disclosure was approved and proof submitted
		DisclosureApproved {
			/// Target account
			target: T::AccountId,
			/// Auditor
			auditor: T::AccountId,
			/// Commitment disclosed
			commitment: Commitment,
			/// Audit trail hash
			trail_hash: Hash,
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
		/// Asset ID does not exist in the registry
		InvalidAssetId,
		/// Asset is not verified for use
		AssetNotVerified,
		/// Asset ID mismatch between parameters
		AssetIdMismatch,
		/// Recipient address is zero (burn address)
		InvalidRecipient,
		DisclosureConditionsNotMet,
		/// Disclosure request already exists
		DisclosureRequestAlreadyExists,
		/// Disclosure request not found
		DisclosureRequestNotFound,
		/// Invalid disclosure proof
		InvalidDisclosureProof,
		/// Audit policy version mismatch
		AuditPolicyVersionMismatch,
		/// Invalid verifying key format
		InvalidVerifyingKey,
		/// Verifying key not set
		VerifyingKeyNotSet,
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
		/// Disclosure frequency limit exceeded
		DisclosureFrequencyLimitExceeded,
		/// Too many disclosure requests
		TooManyDisclosureRequests,
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
		/// * `InvalidMemoSize` - Encrypted memo is not exactly 104 bytes
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

			// Delegate to application service
			crate::application::services::shield_service::ShieldService::execute::<T>(
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
				crate::application::services::shield_service::ShieldService::execute::<T>(
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
		/// revealing amounts or participants. Encrypted memos enable note recovery
		/// and selective disclosure.
		///
		/// # Arguments
		/// * `origin` - Any signed account (sender identity is hidden)
		/// * `proof` - The ZK proof of valid transfer
		/// * `merkle_root` - The Merkle root the proof was computed against
		/// * `nullifiers` - Nullifiers for notes being spent
		/// * `commitments` - Commitments for new notes being created
		/// * `encrypted_memos` - Encrypted metadata for each new note
		///
		/// # Errors
		/// * `UnknownMerkleRoot` - Root is not in historic roots
		/// * `NullifierAlreadyUsed` - Double-spend attempt
		/// * `InvalidProof` - ZK proof verification failed
		/// * `InvalidMemoSize` - Encrypted memo is not exactly 104 bytes
		/// * `MemoCommitmentMismatch` - Number of memos doesn't match commitments
		#[pallet::call_index(1)]
		#[pallet::weight(T::WeightInfo::private_transfer())]
		pub fn private_transfer(
			origin: OriginFor<T>,
			#[allow(unused_variables)] proof: BoundedVec<u8, ConstU32<512>>,
			merkle_root: Hash,
			nullifiers: BoundedVec<Nullifier, ConstU32<2>>,
			commitments: BoundedVec<Commitment, ConstU32<2>>,
			encrypted_memos: BoundedVec<FrameEncryptedMemo, ConstU32<2>>,
		) -> DispatchResult {
			ensure_signed(origin)?;

			// Delegate to application service
			crate::application::services::transfer_service::TransferService::execute::<T>(
				proof,
				merkle_root,
				nullifiers,
				commitments,
				encrypted_memos,
			)
		}

		/// Withdraw tokens from the shielded pool to a public account.
		///
		/// This spends a private note and transfers the tokens to a public recipient.
		/// A ZK proof verifies ownership of the note without revealing which note.
		///
		/// # Arguments
		/// * `origin` - Any signed account
		/// * `proof` - The ZK proof of valid withdrawal
		/// * `merkle_root` - The Merkle root the proof was computed against
		/// * `nullifier` - Nullifier for the note being spent
		/// * `amount` - Amount to withdraw
		/// * `recipient` - Public account to receive tokens
		///
		/// # Errors
		/// * `UnknownMerkleRoot` - Root is not in historic roots
		/// * `NullifierAlreadyUsed` - Double-spend attempt
		/// * `InvalidProof` - ZK proof verification failed
		/// * `InsufficientPoolBalance` - Pool doesn't have enough tokens
		#[pallet::call_index(2)]
		#[pallet::weight(T::WeightInfo::unshield())]
		pub fn unshield(
			origin: OriginFor<T>,
			#[allow(unused_variables)] proof: BoundedVec<u8, ConstU32<512>>,
			merkle_root: Hash,
			nullifier: Nullifier,
			asset_id: u32,
			amount: BalanceOf<T>,
			recipient: T::AccountId,
		) -> DispatchResult {
			ensure_signed(origin)?;

			// Delegate to application service
			crate::application::services::unshield_service::UnshieldService::execute::<T>(
				&proof,
				merkle_root,
				nullifier,
				asset_id,
				amount,
				recipient,
			)
		}

		/// Set disclosure verifying key (governance only)
		///
		/// Configures the verifying key used to verify disclosure ZK proofs.
		/// This should be the disclosure_vk.json generated from the disclosure circuit.
		/// Only root/governance can call this extrinsic.
		///
		/// # Arguments
		/// * `origin` - Must be root
		/// * `vk_bytes` - Serialized verifying key (ark-groth16 format)
		///
		/// # Errors
		/// * `BadOrigin` - Caller is not root
		/// * `InvalidVerifyingKey` - VK format is invalid (size < 100 bytes)
		#[pallet::call_index(3)]
		#[pallet::weight(T::WeightInfo::set_disclosure_verifying_key())]
		pub fn set_disclosure_verifying_key(
			origin: OriginFor<T>,
			vk_bytes: BoundedVec<u8, ConstU32<4096>>,
		) -> DispatchResult {
			ensure_root(origin)?;

			crate::application::services::disclosure_service::DisclosureService::set_verifying_key::<
				T,
			>(vk_bytes)
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
		) -> DispatchResult {
			let who = ensure_signed(origin)?;

			crate::application::services::disclosure_service::DisclosureService::set_audit_policy::<T>(
				&who,
				auditors,
				conditions,
				max_frequency,
			)
		}

		/// Request disclosure from a target account
		#[pallet::call_index(5)]
		#[pallet::weight(T::WeightInfo::request_disclosure())]
		pub fn request_disclosure(
			origin: OriginFor<T>,
			target: T::AccountId,
			reason: BoundedVec<u8, ConstU32<256>>,
			evidence: Option<BoundedVec<u8, ConstU32<1024>>>,
		) -> DispatchResult {
			let auditor = ensure_signed(origin)?;

			crate::application::services::disclosure_service::DisclosureService::request_disclosure::<
				T,
			>(&auditor, &target, reason, evidence)
		}

		/// Approve disclosure request and submit proof
		#[pallet::call_index(6)]
		#[pallet::weight(T::WeightInfo::approve_disclosure())]
		pub fn approve_disclosure(
			origin: OriginFor<T>,
			auditor: T::AccountId,
			commitment: Commitment,
			zk_proof: BoundedVec<u8, ConstU32<2048>>,
			disclosed_data: BoundedVec<u8, ConstU32<512>>,
		) -> DispatchResult {
			let target = ensure_signed(origin)?;

			crate::application::services::disclosure_service::DisclosureService::approve_disclosure::<
				T,
			>(&target, &auditor, commitment, zk_proof, disclosed_data)
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

			crate::application::services::disclosure_service::DisclosureService::reject_disclosure::<
				T,
			>(&target, &auditor, reason)
		}

		/// Submit disclosure proof on-chain for verification
		///
		/// Permite al usuario submeter una prueba de selective disclosure para un memo
		/// específico. La prueba es verificada on-chain usando el ZK verifier.
		///
		/// # Arguments
		/// * `origin` - Cuenta del usuario que posee el memo
		/// * `commitment` - Commitment del memo a divulgar
		/// * `proof_bytes` - Groth16 proof serializado (256 bytes)
		/// * `public_signals` - Public signals (97 bytes):
		///   - commitment (32)
		///   - viewing_key_hash (32)
		///   - mask_bitmap (1)
		///   - revealed_owner_hash (32)
		/// * `partial_data` - Datos revelados según máscara
		/// * `auditor` - Optional auditor account requesting disclosure
		///
		/// # Errors
		/// * `InvalidProof` - Prueba no pasa verificación ZK
		/// * `VerifyingKeyNotSet` - VK del circuit no configurado
		/// * `CommitmentNotFound` - Commitment no existe on-chain
		/// * `InvalidPublicSignals` - Public signals inconsistentes con commitment
		/// * `UnauthorizedAuditor` - Auditor no autorizado en policy
		/// * `DisclosureFrequencyExceeded` - Disclosure demasiado frecuente
		#[pallet::call_index(8)]
		#[pallet::weight(T::WeightInfo::submit_disclosure())]
		pub fn submit_disclosure(
			origin: OriginFor<T>,
			commitment: Commitment,
			proof_bytes: BoundedVec<u8, ConstU32<256>>,
			public_signals: BoundedVec<u8, ConstU32<97>>,
			partial_data: BoundedVec<u8, ConstU32<256>>,
			auditor: Option<T::AccountId>,
		) -> DispatchResult {
			let who = ensure_signed(origin)?;

			crate::application::services::disclosure_service::DisclosureService::submit_disclosure::<
				T,
			>(
				&who,
				commitment,
				proof_bytes,
				public_signals,
				partial_data,
				auditor.as_ref(),
			)?;

			// Also emit DisclosureSubmitted for backwards compatibility
			Self::deposit_event(Event::DisclosureSubmitted {
				who: who.clone(),
				commitment,
				proof_size: 256, // Fixed size for Groth16
			});

			Ok(())
		}

		/// Submit multiple disclosure proofs in a single transaction (batch optimization).
		///
		/// **OPT-2.1:** Native Batching that verifies up to 10 disclosure proofs simultaneously.
		#[pallet::call_index(13)]
		#[pallet::weight(T::WeightInfo::batch_submit_disclosure_proofs(submissions.len() as u32))]
		pub fn batch_submit_disclosure_proofs(
			origin: OriginFor<T>,
			submissions: BoundedVec<BatchDisclosureSubmission, ConstU32<10>>,
		) -> DispatchResult {
			let who = ensure_signed(origin)?;

			crate::application::services::disclosure_service::DisclosureService::batch_submit_proofs::<
				T,
			>(&who, submissions)
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
		#[pallet::weight(Weight::from_parts(100_000, 0) + T::DbWeight::get().reads_writes(1, 2))]
		pub fn register_asset(
			origin: OriginFor<T>,
			name: BoundedVec<u8, ConstU32<64>>,
			symbol: BoundedVec<u8, ConstU32<16>>,
			decimals: u8,
			contract_address: Option<[u8; 20]>,
		) -> DispatchResult {
			ensure_root(origin)?;

			let _asset_id = crate::application::services::asset_service::AssetService::register::<T>(
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
		#[pallet::weight(Weight::from_parts(50_000, 0) + T::DbWeight::get().reads_writes(1, 1))]
		pub fn verify_asset(origin: OriginFor<T>, asset_id: u32) -> DispatchResult {
			ensure_root(origin)?;

			crate::application::services::asset_service::AssetService::verify::<T>(asset_id)
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
		#[pallet::weight(Weight::from_parts(50_000, 0) + T::DbWeight::get().reads_writes(1, 1))]
		pub fn unverify_asset(origin: OriginFor<T>, asset_id: u32) -> DispatchResult {
			ensure_root(origin)?;

			crate::application::services::asset_service::AssetService::unverify::<T>(asset_id)
		}
	}

	// ========================================================================
	// Helper Functions
	// ========================================================================

	impl<T: Config> Pallet<T> {
		/// Get the pool's account ID (derived from PalletId)
		pub fn pool_account_id() -> T::AccountId {
			T::PalletId::get().into_account_truncating()
		}

		/// Verify disclosure proof using ZK verifier
		///
		/// Valida una prueba de selective disclosure usando el verifier trait.
		/// La prueba debe ser Groth16 con 256 bytes.
		///
		/// # Arguments
		/// * `proof_bytes` - Groth16 proof serializado
		/// * `public_signals` - 97 bytes de public signals
		///
		/// # Returns
		/// * `Ok(())` si la prueba es válida
		/// * `Err` si la prueba falla o hay error de verificación
		pub fn verify_disclosure_proof_internal(
			proof_bytes: &[u8],
			public_signals: &[u8],
		) -> DispatchResult {
			crate::infrastructure::services::disclosure_validation_service::DisclosureValidationService::verify_proof_internal::<T>(
				proof_bytes,
				public_signals,
			)
		}

		/// Validate public signals consistency
		///
		/// Verifica que los public signals sean consistentes con el commitment on-chain:
		/// 1. commitment en signals coincide con el argumento
		/// 2. viewing_key_hash es válido (no zero)
		/// 3. mask_bitmap es válido (no revela blinding, revela al menos 1 campo)
		/// 4. revealed_owner_hash coherente con mask
		///
		/// # Arguments
		/// * `commitment` - Commitment del memo
		/// * `public_signals` - 97 bytes: [commitment(32)][vk_hash(32)][mask(1)][owner_hash(32)]
		pub fn validate_public_signals(
			commitment: &Commitment,
			public_signals: &[u8],
		) -> DispatchResult {
			crate::infrastructure::services::disclosure_validation_service::DisclosureValidationService::validate_public_signals::<T>(
				commitment,
				public_signals,
			)
		}

		/// Validate disclosure access control and rate limiting
		///
		/// Verifica que el disclosure sea autorizado:
		/// 1. Si hay AuditPolicy configurada, validar auditor autorizado
		/// 2. Validar rate limiting (max_frequency)
		/// 3. Si hay DisclosureRequest, verificar que auditor coincida
		///
		/// # Arguments
		/// * `who` - Account que genera el disclosure (owner del memo)
		/// * `commitment` - Commitment del memo
		/// * `auditor` - Optional auditor account
		///
		/// # Returns
		/// * `Ok(())` si el disclosure está autorizado
		/// * `Err` si no autorizado o excede rate limit
		pub fn validate_disclosure_access(
			who: &T::AccountId,
			commitment: &Commitment,
			auditor: Option<&T::AccountId>,
		) -> DispatchResult {
			crate::infrastructure::services::disclosure_validation_service::DisclosureValidationService::validate_disclosure_access::<T>(
				who,
				commitment,
				auditor,
			)
		}

		/// Insert a new leaf into the Merkle tree
		pub fn insert_leaf(commitment: Commitment) -> Result<u32, DispatchError> {
			crate::infrastructure::services::merkle_tree_service::MerkleTreeService::insert_leaf::<T>(
				commitment,
			)
		}

		/// Get the Merkle path for a leaf (for generating proofs off-chain)
		///
		/// Returns the sibling hashes and path indices needed to prove
		/// membership in the Merkle tree.
		pub fn get_merkle_path(leaf_index: u32) -> Option<DefaultMerklePath> {
			crate::infrastructure::services::merkle_tree_service::MerkleTreeService::get_merkle_path::<
				T,
			>(leaf_index)
		}

		/// Verify a Merkle proof for a given leaf
		pub fn verify_merkle_proof(root: &Hash, leaf: &Hash, path: &DefaultMerklePath) -> bool {
			crate::infrastructure::services::merkle_tree_service::MerkleTreeService::verify_merkle_proof(
				root,
				leaf,
				path,
			)
		}

		/// Get leaf index for a commitment (Linear scan - expensive, only for RPC)
		pub fn get_leaf_index(commitment: &Commitment) -> Option<u32> {
			crate::infrastructure::services::merkle_tree_service::MerkleTreeService::find_leaf_index::<
				T,
			>(commitment)
		}

		/// Verify disclosure proof (cryptographic verification)
		///
		/// Realiza verificación criptográfica completa del ZK proof de disclosure.
		/// Usa el verifying key almacenado en chain para verificar el Groth16 proof.
		pub fn verify_disclosure_proof(
			proof: &BoundedVec<u8, ConstU32<2048>>,
			commitment: &Commitment,
			disclosed_data: &BoundedVec<u8, ConstU32<512>>,
		) -> Result<(), DispatchError> {
			crate::infrastructure::services::disclosure_validation_service::DisclosureValidationService::verify_disclosure_proof::<T>(
				proof,
				commitment,
				disclosed_data,
			)
		}
	}
}
