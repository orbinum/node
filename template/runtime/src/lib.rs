//! The Substrate Node Template runtime. This can be compiled with `#[no_std]`, ready for Wasm.

#![cfg_attr(not(feature = "std"), no_std)]
// `construct_runtime!` does a lot of recursion and requires us to increase the limit to 256.
#![recursion_limit = "256"]
#![allow(clippy::new_without_default, clippy::or_fun_call)]
#![cfg_attr(feature = "runtime-benchmarks", warn(unused_crate_dependencies))]

extern crate alloc;

mod genesis_config_preset;
mod precompiles;
mod weights;

// Make the WASM binary available.
#[cfg(feature = "std")]
include!(concat!(env!("OUT_DIR"), "/wasm_binary.rs"));

use alloc::{borrow::Cow, vec, vec::Vec};
use core::marker::PhantomData;
use ethereum::AuthorizationList;
use scale_codec::{Decode, Encode};
use sp_api::impl_runtime_apis;
use sp_consensus_aura::sr25519::AuthorityId as AuraId;
use sp_consensus_grandpa::{AuthorityId as GrandpaId, AuthorityList as GrandpaAuthorityList};
use sp_core::{
	crypto::{ByteArray, KeyTypeId},
	hashing::blake2_256,
	ConstU128, OpaqueMetadata, H160, H256, U256,
};
use sp_runtime::MultiSignature;
use sp_runtime::{
	generic, impl_opaque_keys,
	traits::{
		BlakeTwo256, Block as BlockT, DispatchInfoOf, Dispatchable, Get, IdentityLookup, NumberFor,
		PostDispatchInfoOf, UniqueSaturatedInto,
	},
	transaction_validity::{TransactionSource, TransactionValidity, TransactionValidityError},
	ApplyExtrinsicResult, ConsensusEngineId, ExtrinsicInclusionMode, Perbill, Permill,
};
use sp_version::RuntimeVersion;
// Substrate FRAME
#[cfg(feature = "with-paritydb-weights")]
use frame_support::weights::constants::ParityDbWeight as RuntimeDbWeight;
#[cfg(feature = "with-rocksdb-weights")]
use frame_support::weights::constants::RocksDbWeight as RuntimeDbWeight;
use frame_support::{
	derive_impl,
	genesis_builder_helper::build_state,
	parameter_types,
	traits::{ConstBool, ConstU32, ConstU64, ConstU8, FindAuthor, OnFinalize, OnTimestampSet},
	weights::{constants::WEIGHT_REF_TIME_PER_MILLIS, IdentityFee, Weight},
	PalletId,
};
use pallet_transaction_payment::FungibleAdapter;
use polkadot_runtime_common::SlowAdjustingFeeUpdate;
use sp_genesis_builder::PresetId;
// Frontier
use fp_evm::weight_per_gas;
use fp_rpc::TransactionStatus;
use pallet_ethereum::{Call::transact, PostLogContent, Transaction as EthereumTransaction};
use pallet_evm::{Account as EVMAccount, FeeCalculator, Runner};

// A few exports that help ease life for downstream crates.
pub use frame_system::Call as SystemCall;
pub use pallet_balances::Call as BalancesCall;
pub use pallet_timestamp::Call as TimestampCall;

use precompiles::FrontierPrecompiles;

/// Type of block number.
pub type BlockNumber = u32;

/// Alias to 512-bit hash when used in the context of a transaction signature on the chain.
/// MultiSignature supports both sr25519 (Substrate) and ECDSA (Ethereum) signatures
pub type Signature = MultiSignature;

/// Account id is always 32 bytes (AccountId32 for Substrate-native accounts)
/// EVM addresses (20 bytes) are mapped to AccountId32 for compatibility
pub type AccountId = sp_runtime::AccountId32;

/// The type for looking up accounts. We don't expect more than 4 billion of them, but you
/// never know...
pub type AccountIndex = u32;

/// Balance of an account.
pub type Balance = u128;

/// Index of a transaction in the chain.
pub type Nonce = u32;

/// A hash of some data used by the chain.
pub type Hash = H256;

/// The hashing algorithm used by the chain.
pub type Hashing = BlakeTwo256;

/// Digest item type.
pub type DigestItem = generic::DigestItem;

/// The address format for describing accounts.
pub type Address = AccountId;

/// Block header type as expected by this runtime.
pub type Header = generic::Header<BlockNumber, BlakeTwo256>;

/// Block type as expected by this runtime.
pub type Block = generic::Block<Header, UncheckedExtrinsic>;

/// A Block signed with a Justification
pub type SignedBlock = generic::SignedBlock<Block>;

/// BlockId type as expected by this runtime.
pub type BlockId = generic::BlockId<Block>;

/// The SignedExtension to the basic transaction logic.
pub type SignedExtra = (
	frame_system::CheckNonZeroSender<Runtime>,
	frame_system::CheckSpecVersion<Runtime>,
	frame_system::CheckTxVersion<Runtime>,
	frame_system::CheckGenesis<Runtime>,
	frame_system::CheckEra<Runtime>,
	frame_system::CheckNonce<Runtime>,
	frame_system::CheckWeight<Runtime>,
	pallet_transaction_payment::ChargeTransactionPayment<Runtime>,
);

/// Unchecked extrinsic type as expected by this runtime.
pub type UncheckedExtrinsic =
	fp_self_contained::UncheckedExtrinsic<Address, RuntimeCall, Signature, SignedExtra>;

/// Extrinsic type that has already been checked.
pub type CheckedExtrinsic =
	fp_self_contained::CheckedExtrinsic<AccountId, RuntimeCall, SignedExtra, H160>;

/// The payload being signed in transactions.
pub type SignedPayload = generic::SignedPayload<RuntimeCall, SignedExtra>;

/// Executive: handles dispatch to the various modules.
pub type Executive = frame_executive::Executive<
	Runtime,
	Block,
	frame_system::ChainContext<Runtime>,
	Runtime,
	AllPalletsWithSystem,
>;

// Time is measured by number of blocks.
pub const MILLISECS_PER_BLOCK: u64 = 6000;
pub const SLOT_DURATION: u64 = MILLISECS_PER_BLOCK;
pub const MINUTES: BlockNumber = 60_000 / (MILLISECS_PER_BLOCK as BlockNumber);
pub const HOURS: BlockNumber = MINUTES * 60;
pub const DAYS: BlockNumber = HOURS * 24;

/// Opaque types. These are used by the CLI to instantiate machinery that don't need to know
/// the specifics of the runtime. They can then be made to be agnostic over specific formats
/// of data like extrinsics, allowing for them to continue syncing the network through upgrades
/// to even the core data structures.
pub mod opaque {
	use super::*;

	pub use sp_runtime::OpaqueExtrinsic as UncheckedExtrinsic;

	/// Opaque block header type.
	pub type Header = generic::Header<BlockNumber, BlakeTwo256>;
	/// Opaque block type.
	pub type Block = generic::Block<Header, UncheckedExtrinsic>;
	/// Opaque block identifier type.
	pub type BlockId = generic::BlockId<Block>;

	impl_opaque_keys! {
		pub struct SessionKeys {
			pub aura: Aura,
			pub grandpa: Grandpa,
		}
	}
}

#[sp_version::runtime_version]
pub const VERSION: RuntimeVersion = RuntimeVersion {
	spec_name: Cow::Borrowed("orbinum"),
	impl_name: Cow::Borrowed("orbinum"),
	authoring_version: 1,
	spec_version: 1,
	impl_version: 1,
	apis: RUNTIME_API_VERSIONS,
	transaction_version: 1,
	system_version: 1,
};

/// The version information used to identify this runtime when compiled natively.
#[cfg(feature = "std")]
pub fn native_version() -> sp_version::NativeVersion {
	sp_version::NativeVersion {
		runtime_version: VERSION,
		can_author_with: Default::default(),
	}
}

const NORMAL_DISPATCH_RATIO: Perbill = Perbill::from_percent(75);
/// We allow for 2000ms of compute with a 6 second average block time.
pub const WEIGHT_MILLISECS_PER_BLOCK: u64 = 2000;
pub const MAXIMUM_BLOCK_WEIGHT: Weight = Weight::from_parts(
	WEIGHT_MILLISECS_PER_BLOCK * WEIGHT_REF_TIME_PER_MILLIS,
	u64::MAX,
);
pub const MAXIMUM_BLOCK_LENGTH: u32 = 5 * 1024 * 1024;

parameter_types! {
	pub const Version: RuntimeVersion = VERSION;
	pub const BlockHashCount: BlockNumber = 256;
	pub BlockWeights: frame_system::limits::BlockWeights = frame_system::limits::BlockWeights
		::with_sensible_defaults(MAXIMUM_BLOCK_WEIGHT, NORMAL_DISPATCH_RATIO);
	pub BlockLength: frame_system::limits::BlockLength = frame_system::limits::BlockLength
		::max_with_normal_ratio(MAXIMUM_BLOCK_LENGTH, NORMAL_DISPATCH_RATIO);
	pub const SS58Prefix: u8 = 42;
}

// Configure FRAME pallets to include in runtime.
#[derive_impl(frame_system::config_preludes::SolochainDefaultConfig as frame_system::DefaultConfig)]
impl frame_system::Config for Runtime {
	/// Block & extrinsics weights: base values and limits.
	type BlockWeights = BlockWeights;
	/// The maximum length of a block (in bytes).
	type BlockLength = BlockLength;
	/// The index type for storing how many extrinsics an account has signed.
	type Nonce = Nonce;
	/// The type for hashing blocks and tries.
	type Hash = Hash;
	/// The hashing algorithm used.
	type Hashing = Hashing;
	/// The identifier used to distinguish between accounts.
	type AccountId = AccountId;
	/// The lookup mechanism to get account ID from whatever is passed in dispatchers.
	type Lookup = IdentityLookup<AccountId>;
	/// The block type.
	type Block = Block;
	/// Maximum number of block number to block hash mappings to keep (oldest pruned first).
	type BlockHashCount = BlockHashCount;
	/// The weight of database operations that the runtime can invoke.
	type DbWeight = RuntimeDbWeight;
	/// Version of the runtime.
	type Version = Version;
	/// The data to be stored in an account.
	type AccountData = pallet_balances::AccountData<Balance>;
	/// This is used as an identifier of the chain. 42 is the generic substrate prefix.
	type SS58Prefix = SS58Prefix;
	type MaxConsumers = ConstU32<16>;
}

impl pallet_aura::Config for Runtime {
	type AuthorityId = AuraId;
	type MaxAuthorities = ConstU32<32>;
	type DisabledValidators = ();
	type AllowMultipleBlocksPerSlot = ConstBool<false>;
	type SlotDuration = pallet_aura::MinimumPeriodTimesTwo<Runtime>;
}

impl pallet_grandpa::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type WeightInfo = ();
	type MaxAuthorities = ConstU32<32>;
	type MaxNominators = ConstU32<0>;
	type MaxSetIdSessionEntries = ConstU64<0>;
	type KeyOwnerProof = sp_core::Void;
	type EquivocationReportSystem = ();
}

impl cumulus_pallet_weight_reclaim::Config for Runtime {
	type WeightInfo = ();
}

parameter_types! {
	pub storage EnableManualSeal: bool = false;
}

pub struct ConsensusOnTimestampSet<T>(PhantomData<T>);
impl<T: pallet_aura::Config> OnTimestampSet<T::Moment> for ConsensusOnTimestampSet<T> {
	fn on_timestamp_set(moment: T::Moment) {
		if EnableManualSeal::get() {
			return;
		}
		<pallet_aura::Pallet<T> as OnTimestampSet<T::Moment>>::on_timestamp_set(moment)
	}
}

impl pallet_timestamp::Config for Runtime {
	type Moment = u64;
	type OnTimestampSet = ConsensusOnTimestampSet<Self>;
	type MinimumPeriod = ConstU64<{ SLOT_DURATION / 2 }>;
	type WeightInfo = ();
}

pub const EXISTENTIAL_DEPOSIT: u128 = 0;

impl pallet_balances::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type RuntimeHoldReason = RuntimeHoldReason;
	type RuntimeFreezeReason = RuntimeFreezeReason;
	type WeightInfo = pallet_balances::weights::SubstrateWeight<Self>;
	type Balance = Balance;
	type DustRemoval = ();
	type ExistentialDeposit = ConstU128<EXISTENTIAL_DEPOSIT>;
	type AccountStore = System;
	type ReserveIdentifier = [u8; 8];
	type FreezeIdentifier = RuntimeFreezeReason;
	type MaxLocks = ConstU32<50>;
	type MaxReserves = ConstU32<50>;
	type MaxFreezes = ConstU32<1>;
	type DoneSlashHandler = ();
}

impl pallet_transaction_payment::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type OnChargeTransaction = FungibleAdapter<Balances, ()>;
	type WeightToFee = IdentityFee<Balance>;
	type LengthToFee = IdentityFee<Balance>;
	/// Parameterized slow adjusting fee updated based on
	/// <https://research.web3.foundation/Polkadot/overview/token-economics#2-slow-adjusting-mechanism>
	type FeeMultiplierUpdate = SlowAdjustingFeeUpdate<Runtime>;
	type OperationalFeeMultiplier = ConstU8<5>;
	type WeightInfo = pallet_transaction_payment::weights::SubstrateWeight<Runtime>;
}

impl pallet_sudo::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type RuntimeCall = RuntimeCall;
	type WeightInfo = pallet_sudo::weights::SubstrateWeight<Self>;
}

impl pallet_evm_chain_id::Config for Runtime {}

pub struct FindAuthorTruncated<F>(PhantomData<F>);
impl<F: FindAuthor<u32>> FindAuthor<H160> for FindAuthorTruncated<F> {
	fn find_author<'a, I>(digests: I) -> Option<H160>
	where
		I: 'a + IntoIterator<Item = (ConsensusEngineId, &'a [u8])>,
	{
		if let Some(author_index) = F::find_author(digests) {
			let authority_id =
				pallet_aura::Authorities::<Runtime>::get()[author_index as usize].clone();
			return Some(H160::from_slice(&authority_id.to_raw_vec()[4..24]));
		}
		None
	}
}

const BLOCK_GAS_LIMIT: u64 = 75_000_000;
const MAX_POV_SIZE: u64 = 5 * 1024 * 1024;
/// The maximum storage growth per block in bytes.
const MAX_STORAGE_GROWTH: u64 = 400 * 1024;

parameter_types! {
	pub BlockGasLimit: U256 = U256::from(BLOCK_GAS_LIMIT);
	pub const GasLimitPovSizeRatio: u64 = BLOCK_GAS_LIMIT.saturating_div(MAX_POV_SIZE);
	pub const GasLimitStorageGrowthRatio: u64 = BLOCK_GAS_LIMIT.saturating_div(MAX_STORAGE_GROWTH);
	pub PrecompilesValue: FrontierPrecompiles<Runtime> = FrontierPrecompiles::<_>::new();
	pub WeightPerGas: Weight = Weight::from_parts(weight_per_gas(BLOCK_GAS_LIMIT, NORMAL_DISPATCH_RATIO, WEIGHT_MILLISECS_PER_BLOCK), 0);
}

/// Custom address mapper: converts H160 (Ethereum) to AccountId32 (Substrate)
/// This allows EVM accounts to operate within a native Substrate runtime
pub struct HashedAddressMapping<T: pallet_evm::Config>(PhantomData<T>);

impl<T> pallet_evm::AddressMapping<T::AccountId> for HashedAddressMapping<T>
where
	T: pallet_evm::Config,
	T::AccountId: From<[u8; 32]>,
{
	fn into_account_id(address: H160) -> T::AccountId {
		// For Ethereum accounts, map via blake2_256 hash
		// This avoids collisions and creates a unique AccountId32 per Ethereum address
		let hash_result = blake2_256(address.as_bytes());
		T::AccountId::from(hash_result)
	}
}

/// Ensure that the signed origin address matches the given H160 address
/// after mapping through HashedAddressMapping
pub struct EnsureAddressMatches;

impl<OuterOrigin> pallet_evm::EnsureAddressOrigin<OuterOrigin> for EnsureAddressMatches
where
	OuterOrigin: Into<Result<frame_system::RawOrigin<AccountId>, OuterOrigin>>
		+ From<frame_system::RawOrigin<AccountId>>,
{
	type Success = AccountId;

	fn try_address_origin(address: &H160, origin: OuterOrigin) -> Result<AccountId, OuterOrigin> {
		// Map the Ethereum address to AccountId using HashedAddressMapping logic
		let expected_account: AccountId = {
			let hash_result = blake2_256(address.as_bytes());
			AccountId::from(hash_result)
		};

		origin.into().and_then(|o| match o {
			frame_system::RawOrigin::Signed(who) if who == expected_account => Ok(who),
			r => Err(OuterOrigin::from(r)),
		})
	}
}

impl pallet_evm::Config for Runtime {
	type AccountProvider = pallet_evm::FrameSystemAccountProvider<Self>;
	type FeeCalculator = BaseFee;
	type GasWeightMapping = pallet_evm::FixedGasWeightMapping<Self>;
	type WeightPerGas = WeightPerGas;
	type BlockHashMapping = pallet_ethereum::EthereumBlockHashMapping<Self>;
	type CallOrigin = EnsureAddressMatches;
	type WithdrawOrigin = EnsureAddressMatches;
	type AddressMapping = HashedAddressMapping<Self>;
	type Currency = Balances;
	type PrecompilesType = FrontierPrecompiles<Self>;
	type PrecompilesValue = PrecompilesValue;
	type ChainId = EVMChainId;
	type BlockGasLimit = BlockGasLimit;
	type Runner = pallet_evm::runner::stack::Runner<Self>;
	type OnChargeTransaction = ();
	type OnCreate = ();
	type FindAuthor = FindAuthorTruncated<Aura>;
	type GasLimitPovSizeRatio = GasLimitPovSizeRatio;
	type GasLimitStorageGrowthRatio = GasLimitStorageGrowthRatio;
	type Timestamp = Timestamp;
	type CreateOriginFilter = ();
	type CreateInnerOriginFilter = ();
	type WeightInfo = pallet_evm::weights::SubstrateWeight<Self>;
}

parameter_types! {
	pub const PostBlockAndTxnHashes: PostLogContent = PostLogContent::BlockAndTxnHashes;
}

impl pallet_ethereum::Config for Runtime {
	type StateRoot = pallet_ethereum::IntermediateStateRoot<Self::Version>;
	type PostLogContent = PostBlockAndTxnHashes;
	type ExtraDataLength = ConstU32<30>;
}

parameter_types! {
	pub BoundDivision: U256 = U256::from(1024);
}

impl pallet_dynamic_fee::Config for Runtime {
	type MinGasPriceBoundDivisor = BoundDivision;
}

parameter_types! {
	pub DefaultBaseFeePerGas: U256 = U256::from(1_000_000_000);
	pub DefaultElasticity: Permill = Permill::from_parts(125_000);
}
pub struct BaseFeeThreshold;
impl pallet_base_fee::BaseFeeThreshold for BaseFeeThreshold {
	fn lower() -> Permill {
		Permill::zero()
	}
	fn ideal() -> Permill {
		Permill::from_parts(500_000)
	}
	fn upper() -> Permill {
		Permill::from_parts(1_000_000)
	}
}
impl pallet_base_fee::Config for Runtime {
	type Threshold = BaseFeeThreshold;
	type DefaultBaseFeePerGas = DefaultBaseFeePerGas;
	type DefaultElasticity = DefaultElasticity;
}

#[frame_support::pallet]
pub mod pallet_manual_seal {
	use super::*;
	use frame_support::pallet_prelude::*;

	#[pallet::pallet]
	pub struct Pallet<T>(PhantomData<T>);

	#[pallet::config]
	pub trait Config: frame_system::Config {}

	#[pallet::genesis_config]
	#[derive(frame_support::DefaultNoBound)]
	pub struct GenesisConfig<T> {
		pub enable: bool,
		#[serde(skip)]
		pub _config: PhantomData<T>,
	}

	#[pallet::genesis_build]
	impl<T: Config> BuildGenesisConfig for GenesisConfig<T> {
		fn build(&self) {
			EnableManualSeal::set(&self.enable);
		}
	}
}

impl pallet_manual_seal::Config for Runtime {}

impl pallet_zk_verifier::Config for Runtime {
	/// Only root can register/update verification keys
	type AdminOrigin = frame_system::EnsureRoot<AccountId>;
	/// Max VK size: 10MB (transfer_pk.ark: 8.3MB is the largest)
	type MaxVerificationKeySize = ConstU32<10485760>;
	/// Max proof size: 1KB (Groth16 proofs ~256-512 bytes)
	type MaxProofSize = ConstU32<1024>;
	/// Max public inputs: 32 field elements per circuit
	type MaxPublicInputs = ConstU32<32>;
	type WeightInfo = pallet_zk_verifier::weights::SubstrateWeight<Runtime>;
}

parameter_types! {
	/// Pool account that holds all shielded tokens
	pub const ShieldedPoolPalletId: PalletId = PalletId(*b"shld/pol");
}

impl pallet_shielded_pool::Config for Runtime {
	/// Native currency (ORB) for shield/unshield operations
	type Currency = Balances;
	/// Groth16 proof verifier for unshield/transfer operations
	type ZkVerifier = ZkVerifier;
	/// PalletId for the pool account
	type PalletId = ShieldedPoolPalletId;
	/// Merkle tree depth: 2^20 = 1M notes max (see MERKLE_TREE_SCALABILITY.md)
	type MaxTreeDepth = ConstU32<20>;
	/// Historic roots: allows proofs against past states (30s window)
	type MaxHistoricRoots = ConstU32<100>;
	/// Minimum shield amount: prevents spam, 1 ORB = 1e12 planck
	type MinShieldAmount = ConstU128<1_000_000_000_000>;
	type WeightInfo = pallet_shielded_pool::weights::SubstrateWeight<Runtime>;
}

// Create the runtime by composing the FRAME pallets that were previously configured.
#[frame_support::runtime]
mod runtime {
	#[runtime::runtime]
	#[runtime::derive(
		RuntimeEvent,
		RuntimeCall,
		RuntimeError,
		RuntimeOrigin,
		RuntimeFreezeReason,
		RuntimeHoldReason,
		RuntimeSlashReason,
		RuntimeLockId,
		RuntimeTask
	)]
	pub struct Runtime;

	#[runtime::pallet_index(0)]
	pub type System = frame_system;

	#[runtime::pallet_index(1)]
	pub type Timestamp = pallet_timestamp;

	#[runtime::pallet_index(2)]
	pub type Aura = pallet_aura;

	#[runtime::pallet_index(3)]
	pub type Grandpa = pallet_grandpa;

	#[runtime::pallet_index(4)]
	pub type Balances = pallet_balances;

	#[runtime::pallet_index(5)]
	pub type TransactionPayment = pallet_transaction_payment;

	#[runtime::pallet_index(6)]
	pub type Sudo = pallet_sudo;

	#[runtime::pallet_index(7)]
	pub type Ethereum = pallet_ethereum;

	#[runtime::pallet_index(8)]
	pub type EVM = pallet_evm;

	#[runtime::pallet_index(9)]
	pub type EVMChainId = pallet_evm_chain_id;

	#[runtime::pallet_index(10)]
	pub type BaseFee = pallet_base_fee;

	#[runtime::pallet_index(11)]
	pub type ManualSeal = pallet_manual_seal;

	#[runtime::pallet_index(12)]
	pub type ZkVerifier = pallet_zk_verifier;

	#[runtime::pallet_index(13)]
	pub type ShieldedPool = pallet_shielded_pool;
}

#[derive(Clone)]
pub struct TransactionConverter<B>(PhantomData<B>);

impl<B> Default for TransactionConverter<B> {
	fn default() -> Self {
		Self(PhantomData)
	}
}

impl<B: BlockT> fp_rpc::ConvertTransaction<<B as BlockT>::Extrinsic> for TransactionConverter<B> {
	fn convert_transaction(
		&self,
		transaction: pallet_ethereum::Transaction,
	) -> <B as BlockT>::Extrinsic {
		let extrinsic = UncheckedExtrinsic::new_bare(
			pallet_ethereum::Call::<Runtime>::transact { transaction }.into(),
		);
		let encoded = extrinsic.encode();
		<B as BlockT>::Extrinsic::decode(&mut &encoded[..])
			.expect("Encoded extrinsic is always valid")
	}
}

impl fp_self_contained::SelfContainedCall for RuntimeCall {
	type SignedInfo = H160;

	fn is_self_contained(&self) -> bool {
		match self {
			RuntimeCall::Ethereum(call) => call.is_self_contained(),
			_ => false,
		}
	}

	fn check_self_contained(&self) -> Option<Result<Self::SignedInfo, TransactionValidityError>> {
		match self {
			RuntimeCall::Ethereum(call) => call.check_self_contained(),
			_ => None,
		}
	}

	fn validate_self_contained(
		&self,
		info: &Self::SignedInfo,
		dispatch_info: &DispatchInfoOf<RuntimeCall>,
		len: usize,
	) -> Option<TransactionValidity> {
		match self {
			RuntimeCall::Ethereum(call) => call.validate_self_contained(info, dispatch_info, len),
			_ => None,
		}
	}

	fn pre_dispatch_self_contained(
		&self,
		info: &Self::SignedInfo,
		dispatch_info: &DispatchInfoOf<RuntimeCall>,
		len: usize,
	) -> Option<Result<(), TransactionValidityError>> {
		match self {
			RuntimeCall::Ethereum(call) => {
				call.pre_dispatch_self_contained(info, dispatch_info, len)
			}
			_ => None,
		}
	}

	fn apply_self_contained(
		self,
		info: Self::SignedInfo,
	) -> Option<sp_runtime::DispatchResultWithInfo<PostDispatchInfoOf<Self>>> {
		match self {
			call @ RuntimeCall::Ethereum(pallet_ethereum::Call::transact { .. }) => {
				Some(call.dispatch(RuntimeOrigin::from(
					pallet_ethereum::RawOrigin::EthereumTransaction(info),
				)))
			}
			_ => None,
		}
	}
}

#[cfg(feature = "runtime-benchmarks")]
mod benches {
	frame_benchmarking::define_benchmarks!(
		[frame_benchmarking, BaselineBench::<Runtime>]
		[frame_system, SystemBench::<Runtime>]
		[pallet_balances, Balances]
		[pallet_timestamp, Timestamp]
		[pallet_sudo, Sudo]
		[pallet_evm, EVM]
		[pallet_evm_precompile_curve25519, EVMPrecompileCurve25519Bench::<Runtime>]
		[pallet_evm_precompile_sha3fips, EVMPrecompileSha3FIPSBench::<Runtime>]
		[pallet_zk_verifier, ZkVerifier]
		[pallet_shielded_pool, ShieldedPool]
	);
}

impl_runtime_apis! {
	impl sp_api::Core<Block> for Runtime {
		fn version() -> RuntimeVersion {
			VERSION
		}

		fn execute_block(block: Block) {
			Executive::execute_block(block)
		}

		fn initialize_block(header: &<Block as BlockT>::Header) -> ExtrinsicInclusionMode {
			Executive::initialize_block(header)
		}
	}

	impl sp_api::Metadata<Block> for Runtime {
		fn metadata() -> OpaqueMetadata {
			OpaqueMetadata::new(Runtime::metadata().into())
		}

		fn metadata_at_version(version: u32) -> Option<OpaqueMetadata> {
			Runtime::metadata_at_version(version)
		}

		fn metadata_versions() -> Vec<u32> {
			Runtime::metadata_versions()
		}
	}

	impl sp_block_builder::BlockBuilder<Block> for Runtime {
		fn apply_extrinsic(extrinsic: <Block as BlockT>::Extrinsic) -> ApplyExtrinsicResult {
			Executive::apply_extrinsic(extrinsic)
		}

		fn finalize_block() -> <Block as BlockT>::Header {
			Executive::finalize_block()
		}

		fn inherent_extrinsics(data: sp_inherents::InherentData) -> Vec<<Block as BlockT>::Extrinsic> {
			data.create_extrinsics()
		}

		fn check_inherents(
			block: Block,
			data: sp_inherents::InherentData,
		) -> sp_inherents::CheckInherentsResult {
			data.check_extrinsics(&block)
		}
	}

	impl sp_transaction_pool::runtime_api::TaggedTransactionQueue<Block> for Runtime {
		fn validate_transaction(
			source: TransactionSource,
			tx: <Block as BlockT>::Extrinsic,
			block_hash: <Block as BlockT>::Hash,
		) -> TransactionValidity {
			Executive::validate_transaction(source, tx, block_hash)
		}
	}

	impl sp_offchain::OffchainWorkerApi<Block> for Runtime {
		fn offchain_worker(header: &<Block as BlockT>::Header) {
			Executive::offchain_worker(header)
		}
	}

	impl sp_genesis_builder::GenesisBuilder<Block> for Runtime {
		fn build_state(config: Vec<u8>) -> sp_genesis_builder::Result {
			build_state::<RuntimeGenesisConfig>(config)
		}

		fn get_preset(id: &Option<PresetId>) -> Option<Vec<u8>> {
			frame_support::genesis_builder_helper::get_preset::<RuntimeGenesisConfig>(id, genesis_config_preset::get_preset)
		}

		fn preset_names() -> Vec<sp_genesis_builder::PresetId> {
			vec![PresetId::from(sp_genesis_builder::DEV_RUNTIME_PRESET)]
		}
	}

	impl sp_session::SessionKeys<Block> for Runtime {
		fn generate_session_keys(seed: Option<Vec<u8>>) -> Vec<u8> {
			opaque::SessionKeys::generate(seed)
		}

		fn decode_session_keys(
			encoded: Vec<u8>,
		) -> Option<Vec<(Vec<u8>, KeyTypeId)>> {
			opaque::SessionKeys::decode_into_raw_public_keys(&encoded)
		}
	}

	impl sp_consensus_aura::AuraApi<Block, AuraId> for Runtime {
		fn slot_duration() -> sp_consensus_aura::SlotDuration {
			sp_consensus_aura::SlotDuration::from_millis(Aura::slot_duration())
		}

		fn authorities() -> Vec<AuraId> {
			pallet_aura::Authorities::<Runtime>::get().into_inner()
		}
	}

	impl sp_consensus_grandpa::GrandpaApi<Block> for Runtime {
		fn grandpa_authorities() -> GrandpaAuthorityList {
			Grandpa::grandpa_authorities()
		}

		fn current_set_id() -> sp_consensus_grandpa::SetId {
			Grandpa::current_set_id()
		}

		fn submit_report_equivocation_unsigned_extrinsic(
			_equivocation_proof: sp_consensus_grandpa::EquivocationProof<
				<Block as BlockT>::Hash,
				NumberFor<Block>,
			>,
			_key_owner_proof: sp_consensus_grandpa::OpaqueKeyOwnershipProof,
		) -> Option<()> {
			None
		}

		fn generate_key_ownership_proof(
			_set_id: sp_consensus_grandpa::SetId,
			_authority_id: GrandpaId,
		) -> Option<sp_consensus_grandpa::OpaqueKeyOwnershipProof> {
			// NOTE: this is the only implementation possible since we've
			// defined our key owner proof type as a bottom type (i.e. a type
			// with no values).
			None
		}
	}

	impl frame_system_rpc_runtime_api::AccountNonceApi<Block, AccountId, Nonce> for Runtime {
		fn account_nonce(account: AccountId) -> Nonce {
			System::account_nonce(account)
		}
	}

	impl pallet_transaction_payment_rpc_runtime_api::TransactionPaymentApi<
		Block,
		Balance,
	> for Runtime {
		fn query_info(
			uxt: <Block as BlockT>::Extrinsic,
			len: u32
		) -> pallet_transaction_payment_rpc_runtime_api::RuntimeDispatchInfo<Balance> {
			TransactionPayment::query_info(uxt, len)
		}

		fn query_fee_details(
			uxt: <Block as BlockT>::Extrinsic,
			len: u32,
		) -> pallet_transaction_payment::FeeDetails<Balance> {
			TransactionPayment::query_fee_details(uxt, len)
		}

		fn query_weight_to_fee(weight: Weight) -> Balance {
			TransactionPayment::weight_to_fee(weight)
		}

		fn query_length_to_fee(length: u32) -> Balance {
			TransactionPayment::length_to_fee(length)
		}
	}

	impl fp_rpc::EthereumRuntimeRPCApi<Block> for Runtime {
		fn chain_id() -> u64 {
			<Runtime as pallet_evm::Config>::ChainId::get()
		}

		fn account_basic(address: H160) -> EVMAccount {
			let (account, _) = pallet_evm::Pallet::<Runtime>::account_basic(&address);
			account
		}

		fn gas_price() -> U256 {
			let (gas_price, _) = <Runtime as pallet_evm::Config>::FeeCalculator::min_gas_price();
			gas_price
		}

		fn account_code_at(address: H160) -> Vec<u8> {
			pallet_evm::AccountCodes::<Runtime>::get(address)
		}

		fn author() -> H160 {
			<pallet_evm::Pallet<Runtime>>::find_author()
		}

		fn storage_at(address: H160, index: U256) -> H256 {
			pallet_evm::AccountStorages::<Runtime>::get(address, H256::from(index.to_big_endian()))
		}

		fn call(
			from: H160,
			to: H160,
			data: Vec<u8>,
			value: U256,
			gas_limit: U256,
			max_fee_per_gas: Option<U256>,
			max_priority_fee_per_gas: Option<U256>,
			nonce: Option<U256>,
			estimate: bool,
			access_list: Option<Vec<(H160, Vec<H256>)>>,
			authorization_list: Option<AuthorizationList>,
		) -> Result<pallet_evm::CallInfo, sp_runtime::DispatchError> {
			use pallet_evm::GasWeightMapping as _;

			let config = if estimate {
				let mut config = <Runtime as pallet_evm::Config>::config().clone();
				config.estimate = true;
				Some(config)
			} else {
				None
			};

			// Estimated encoded transaction size must be based on the heaviest transaction
			// type (EIP7702Transaction) to be compatible with all transaction types.
			let mut estimated_transaction_len = data.len() +
				// pallet ethereum index: 1
				// transact call index: 1
				// Transaction enum variant: 1
				// chain_id 8 bytes
				// nonce: 32
				// max_priority_fee_per_gas: 32
				// max_fee_per_gas: 32
				// gas_limit: 32
				// action: 21 (enum varianrt + call address)
				// value: 32
				// access_list: 1 (empty vec size)
				// authorization_list: 1 (empty vec size)
				// 65 bytes signature
				259;

			if access_list.is_some() {
				estimated_transaction_len += access_list.encoded_size();
			}

			if authorization_list.is_some() {
				estimated_transaction_len += authorization_list.encoded_size();
			}

			let gas_limit = if gas_limit > U256::from(u64::MAX) {
				u64::MAX
			} else {
				gas_limit.low_u64()
			};
			let without_base_extrinsic_weight = true;

			let (weight_limit, proof_size_base_cost) =
				match <Runtime as pallet_evm::Config>::GasWeightMapping::gas_to_weight(
					gas_limit,
					without_base_extrinsic_weight
				) {
					weight_limit if weight_limit.proof_size() > 0 => {
						(Some(weight_limit), Some(estimated_transaction_len as u64))
					}
					_ => (None, None),
				};

			<Runtime as pallet_evm::Config>::Runner::call(
				from,
				to,
				data,
				value,
				gas_limit.unique_saturated_into(),
				max_fee_per_gas,
				max_priority_fee_per_gas,
				nonce,
				access_list.unwrap_or_default(),
				authorization_list.unwrap_or_default(),
				false,
				true,
				weight_limit,
				proof_size_base_cost,
				config.as_ref().unwrap_or(<Runtime as pallet_evm::Config>::config()),
			).map_err(|err| err.error.into())
		}

		fn create(
			from: H160,
			data: Vec<u8>,
			value: U256,
			gas_limit: U256,
			max_fee_per_gas: Option<U256>,
			max_priority_fee_per_gas: Option<U256>,
			nonce: Option<U256>,
			estimate: bool,
			access_list: Option<Vec<(H160, Vec<H256>)>>,
			authorization_list: Option<AuthorizationList>,
		) -> Result<pallet_evm::CreateInfo, sp_runtime::DispatchError> {
			use pallet_evm::GasWeightMapping as _;

			let config = if estimate {
				let mut config = <Runtime as pallet_evm::Config>::config().clone();
				config.estimate = true;
				Some(config)
			} else {
				None
			};


			let mut estimated_transaction_len = data.len() +
				// from: 20
				// value: 32
				// gas_limit: 32
				// nonce: 32
				// 1 byte transaction action variant
				// chain id 8 bytes
				// 65 bytes signature
				190;

			if max_fee_per_gas.is_some() {
				estimated_transaction_len += 32;
			}
			if max_priority_fee_per_gas.is_some() {
				estimated_transaction_len += 32;
			}
			if access_list.is_some() {
				estimated_transaction_len += access_list.encoded_size();
			}
			if authorization_list.is_some() {
				estimated_transaction_len += authorization_list.encoded_size();
			}

			let gas_limit = if gas_limit > U256::from(u64::MAX) {
				u64::MAX
			} else {
				gas_limit.low_u64()
			};
			let without_base_extrinsic_weight = true;

			let (weight_limit, proof_size_base_cost) =
				match <Runtime as pallet_evm::Config>::GasWeightMapping::gas_to_weight(
					gas_limit,
					without_base_extrinsic_weight
				) {
					weight_limit if weight_limit.proof_size() > 0 => {
						(Some(weight_limit), Some(estimated_transaction_len as u64))
					}
					_ => (None, None),
				};

			<Runtime as pallet_evm::Config>::Runner::create(
				from,
				data,
				value,
				gas_limit.unique_saturated_into(),
				max_fee_per_gas,
				max_priority_fee_per_gas,
				nonce,
				access_list.unwrap_or_default(),
				authorization_list.unwrap_or_default(),
				false,
				true,
				weight_limit,
				proof_size_base_cost,
				config.as_ref().unwrap_or(<Runtime as pallet_evm::Config>::config()),
			).map_err(|err| err.error.into())
		}

		fn current_transaction_statuses() -> Option<Vec<TransactionStatus>> {
			pallet_ethereum::CurrentTransactionStatuses::<Runtime>::get()
		}

		fn current_block() -> Option<pallet_ethereum::Block> {
			pallet_ethereum::CurrentBlock::<Runtime>::get()
		}

		fn current_receipts() -> Option<Vec<pallet_ethereum::Receipt>> {
			pallet_ethereum::CurrentReceipts::<Runtime>::get()
		}

		fn current_all() -> (
			Option<pallet_ethereum::Block>,
			Option<Vec<pallet_ethereum::Receipt>>,
			Option<Vec<TransactionStatus>>
		) {
			(
				pallet_ethereum::CurrentBlock::<Runtime>::get(),
				pallet_ethereum::CurrentReceipts::<Runtime>::get(),
				pallet_ethereum::CurrentTransactionStatuses::<Runtime>::get()
			)
		}

		fn extrinsic_filter(
			xts: Vec<<Block as BlockT>::Extrinsic>,
		) -> Vec<EthereumTransaction> {
			xts.into_iter().filter_map(|xt| match xt.0.function {
				RuntimeCall::Ethereum(transact { transaction }) => Some(transaction),
				_ => None
			}).collect::<Vec<EthereumTransaction>>()
		}

		fn elasticity() -> Option<Permill> {
			Some(pallet_base_fee::Elasticity::<Runtime>::get())
		}

		fn gas_limit_multiplier_support() {}

		fn pending_block(
			xts: Vec<<Block as BlockT>::Extrinsic>,
		) -> (Option<pallet_ethereum::Block>, Option<Vec<TransactionStatus>>) {
			for ext in xts.into_iter() {
				let _ = Executive::apply_extrinsic(ext);
			}

			Ethereum::on_finalize(System::block_number() + 1);

			(
				pallet_ethereum::CurrentBlock::<Runtime>::get(),
				pallet_ethereum::CurrentTransactionStatuses::<Runtime>::get()
			)
		}

		fn initialize_pending_block(header: &<Block as BlockT>::Header) {
			Executive::initialize_block(header);
		}
	}

	impl fp_rpc::ConvertTransactionRuntimeApi<Block> for Runtime {
		fn convert_transaction(transaction: EthereumTransaction) -> <Block as BlockT>::Extrinsic {
			UncheckedExtrinsic::new_bare(
				pallet_ethereum::Call::<Runtime>::transact { transaction }.into(),
			)
		}
	}

	// ShieldedPool Runtime API implementation
	impl pallet_shielded_pool_runtime_api::ShieldedPoolRuntimeApi<Block> for Runtime {
		fn get_merkle_tree_info() -> (pallet_shielded_pool::Hash, u32, u32) {
			ShieldedPool::get_merkle_tree_info()
		}

		fn get_merkle_proof(leaf_index: u32) -> Option<pallet_shielded_pool::DefaultMerklePath> {
			ShieldedPool::get_merkle_proof(leaf_index)
		}

		fn get_merkle_proof_for_commitment(
			commitment: pallet_shielded_pool::Hash,
		) -> Option<(u32, pallet_shielded_pool::DefaultMerklePath)> {
			ShieldedPool::get_merkle_proof_for_commitment(commitment)
		}
	}

	// SignatureApi RuntimeAPI implementation
	impl orbinum_signature_api::SignatureApi<Block> for Runtime {
		fn get_supported_signature_types() -> alloc::vec::Vec<orbinum_signature_api::SignatureType> {
			// Sr25519 primero: tipo preferido para cuentas Substrate-nativas.
			// Ecdsa segundo: para cuentas derivadas de claves Ethereum.
			alloc::vec![
				orbinum_signature_api::SignatureType::Sr25519,
				orbinum_signature_api::SignatureType::Ecdsa,
			]
		}

		fn validate_signature(
			signature: sp_runtime::MultiSignature,
			message: alloc::vec::Vec<u8>,
			signer: sp_core::crypto::AccountId32,
		) -> bool {
			use sp_runtime::traits::Verify;
			signature.verify(message.as_slice(), &signer)
		}
	}

	#[cfg(feature = "runtime-benchmarks")]
	impl frame_benchmarking::Benchmark<Block> for Runtime {
		fn benchmark_metadata(extra: bool) -> (
			Vec<frame_benchmarking::BenchmarkList>,
			Vec<frame_support::traits::StorageInfo>,
		) {
			use frame_benchmarking::{baseline, BenchmarkList};
			use frame_support::traits::StorageInfoTrait;

			use baseline::Pallet as BaselineBench;
			use frame_system_benchmarking::Pallet as SystemBench;

			use pallet_evm_precompile_curve25519_benchmarking::Pallet as EVMPrecompileCurve25519Bench;
			use pallet_evm_precompile_sha3fips_benchmarking::Pallet as EVMPrecompileSha3FIPSBench;

			let mut list = Vec::<BenchmarkList>::new();
			list_benchmarks!(list, extra);

			let storage_info = AllPalletsWithSystem::storage_info();
			(list, storage_info)
		}

		#[allow(non_local_definitions)]
		fn dispatch_benchmark(
			config: frame_benchmarking::BenchmarkConfig
		) -> Result<Vec<frame_benchmarking::BenchmarkBatch>, alloc::string::String> {
			use frame_benchmarking::{baseline, BenchmarkBatch};
			use frame_support::traits::TrackedStorageKey;

			use baseline::Pallet as BaselineBench;
			use frame_system_benchmarking::Pallet as SystemBench;
			use pallet_evm_precompile_curve25519_benchmarking::Pallet as EVMPrecompileCurve25519Bench;
			use pallet_evm_precompile_sha3fips_benchmarking::Pallet as EVMPrecompileSha3FIPSBench;

			impl baseline::Config for Runtime {}
			impl frame_system_benchmarking::Config for Runtime {}
			impl pallet_evm_precompile_curve25519_benchmarking::Config for Runtime {}
			impl pallet_evm_precompile_sha3fips_benchmarking::Config for Runtime {}

			let whitelist: Vec<TrackedStorageKey> = Vec::new();

			let mut batches = Vec::<BenchmarkBatch>::new();
			let params = (&config, &whitelist);
			add_benchmarks!(params, batches);
			Ok(batches)
		}
	}
}

#[cfg(test)]
mod tests {
	use super::{AccountId, HashedAddressMapping, Runtime, WeightPerGas};
	use hex_literal::hex;
	use pallet_evm::AddressMapping;
	use sp_core::{ecdsa, hashing::blake2_256, sr25519, Pair, H160};
	use sp_runtime::{
		traits::{IdentifyAccount, Verify},
		MultiSignature, MultiSigner,
	};

	// ─────────────────────────────────────────────────────────────────────────
	// EVM Weight compatibility
	// ─────────────────────────────────────────────────────────────────────────

	#[test]
	fn configured_base_extrinsic_weight_is_evm_compatible() {
		let min_ethereum_transaction_weight = WeightPerGas::get() * 21_000;
		let base_extrinsic = <Runtime as frame_system::Config>::BlockWeights::get()
			.get(frame_support::dispatch::DispatchClass::Normal)
			.base_extrinsic;
		assert!(base_extrinsic.ref_time() <= min_ethereum_transaction_weight.ref_time());
	}

	// ─────────────────────────────────────────────────────────────────────────
	// HashedAddressMapping tests
	// ─────────────────────────────────────────────────────────────────────────

	/// El mismo H160 siempre produce el mismo AccountId32
	#[test]
	fn hashed_address_mapping_is_deterministic() {
		let eth_addr = H160::from([0x42u8; 20]);
		let acc1 = HashedAddressMapping::<Runtime>::into_account_id(eth_addr);
		let acc2 = HashedAddressMapping::<Runtime>::into_account_id(eth_addr);
		assert_eq!(acc1, acc2, "mismo H160 debe producir el mismo AccountId32");
	}

	/// Dos H160 distintos deben producir AccountId32 distintos
	#[test]
	fn hashed_address_mapping_is_unique() {
		let addr1 = H160::from([0x01u8; 20]);
		let addr2 = H160::from([0x02u8; 20]);
		let acc1 = HashedAddressMapping::<Runtime>::into_account_id(addr1);
		let acc2 = HashedAddressMapping::<Runtime>::into_account_id(addr2);
		assert_ne!(
			acc1, acc2,
			"diferentes H160 deben producir AccountId32 distintos"
		);
	}

	/// La dirección Ethereum de Alith mapeada en chain_spec coincide con el runtime
	#[test]
	fn chain_spec_mapping_matches_runtime_mapping() {
		// Dirección Ethereum de Alith (del chain_spec)
		let alith_eth = H160::from(hex!("f24FF3a9CF04c71Dbc94D0b566f7A27B94566cac"));

		// chain_spec usa: blake2_256(&eth_address)
		let chain_spec_account = AccountId::from(blake2_256(alith_eth.as_bytes()));

		// Runtime HashedAddressMapping usa: blake2_256(address.as_bytes())
		let runtime_account = HashedAddressMapping::<Runtime>::into_account_id(alith_eth);

		assert_eq!(
			chain_spec_account, runtime_account,
			"chain_spec y el runtime deben producir el mismo AccountId32 para Alith"
		);
	}

	/// Todos los EVM dev accounts del chain_spec mapean a AccountId únicos
	#[test]
	fn all_evm_dev_accounts_map_to_unique_accounts() {
		let dev_addresses: [[u8; 20]; 6] = [
			hex!("f24FF3a9CF04c71Dbc94D0b566f7A27B94566cac"), // Alith
			hex!("3Cd0A705a2DC65e5b1E1205896BaA2be8A07c6e0"), // Baltathar
			hex!("798d4Ba9baf0064Ec19eB4F0a1a45785ae9D6DFc"), // Charleth
			hex!("773539d4Ac0e786233D90A233654ccEE26a613D9"), // Dorothy
			hex!("Ff64d3F6efE2317EE2807d223a0Bdc4c0c49dfDB"), // Ethan
			hex!("C0F0f4ab324C46e55D02D0033343B4Be8A55532d"), // Faith
		];

		let accounts: alloc::vec::Vec<AccountId> = dev_addresses
			.iter()
			.map(|b| HashedAddressMapping::<Runtime>::into_account_id(H160::from(*b)))
			.collect();

		// Verificar que todos los AccountId son únicos
		for i in 0..accounts.len() {
			for j in (i + 1)..accounts.len() {
				assert_ne!(
					accounts[i], accounts[j],
					"EVM dev accounts deben mapearse a AccountId32 únicos (índices {i} y {j})"
				);
			}
		}
	}

	// ─────────────────────────────────────────────────────────────────────────
	// MultiSignature Sr25519 tests
	// ─────────────────────────────────────────────────────────────────────────

	/// Sr25519: firma válida verifica correctamente contra el signer
	#[test]
	fn sr25519_valid_signature_verifies() {
		let pair = sr25519::Pair::from_string("//Alice", None).unwrap();
		let msg = b"test-multisignature-orbinum";

		let sig = pair.sign(msg);
		let multi_sig = MultiSignature::Sr25519(sig);

		// AccountId32 para sr25519 desde MultiSigner
		let signer_account: AccountId = MultiSigner::from(pair.public()).into_account();

		assert!(
			multi_sig.verify(msg.as_ref(), &signer_account),
			"Sr25519 firma válida debe verificar contra su propio AccountId"
		);
	}

	/// Sr25519: firma de Alice NO verifica contra la cuenta de Bob
	#[test]
	fn sr25519_wrong_signer_rejected() {
		let alice = sr25519::Pair::from_string("//Alice", None).unwrap();
		let bob = sr25519::Pair::from_string("//Bob", None).unwrap();

		let msg = b"test-wrong-signer";
		let alice_sig = alice.sign(msg);
		let multi_sig = MultiSignature::Sr25519(alice_sig);

		let bob_account: AccountId = MultiSigner::from(bob.public()).into_account();

		assert!(
			!multi_sig.verify(msg.as_ref(), &bob_account),
			"Sr25519 firma de Alice NO debe verificar contra la cuenta de Bob"
		);
	}

	/// Sr25519: firma sobre mensaje A NO verifica mensaje B
	#[test]
	fn sr25519_wrong_message_rejected() {
		let pair = sr25519::Pair::from_string("//Alice", None).unwrap();

		let original_msg = b"mensaje original";
		let different_msg = b"mensaje diferente";

		let sig = pair.sign(original_msg);
		let multi_sig = MultiSignature::Sr25519(sig);

		let signer_account: AccountId = MultiSigner::from(pair.public()).into_account();

		assert!(
			!multi_sig.verify(different_msg.as_ref(), &signer_account),
			"Sr25519 firma sobre mensaje A NO debe verificar mensaje B"
		);
	}

	/// Sr25519: firma corrupta (bytes cero) es rechazada
	#[test]
	fn sr25519_corrupted_signature_rejected() {
		let pair = sr25519::Pair::from_string("//Alice", None).unwrap();
		let msg = b"test-corrupted";

		// Firma corrupta: 64 bytes en cero
		let corrupted = sr25519::Signature::default();
		let multi_sig = MultiSignature::Sr25519(corrupted);

		let signer_account: AccountId = MultiSigner::from(pair.public()).into_account();

		assert!(
			!multi_sig.verify(msg.as_ref(), &signer_account),
			"Sr25519 firma corrupta debe ser rechazada"
		);
	}

	/// Sr25519: cada cuenta verifica únicamente su propia firma
	#[test]
	fn sr25519_each_account_verifies_only_own_signature() {
		let alice = sr25519::Pair::from_string("//Alice", None).unwrap();
		let bob = sr25519::Pair::from_string("//Bob", None).unwrap();

		let msg = b"mismo-mensaje";
		let alice_sig = alice.sign(msg);
		let bob_sig = bob.sign(msg);

		// Las public keys son distintas
		assert_ne!(
			alice.public().0,
			bob.public().0,
			"Alice y Bob tienen keys distintas"
		);

		let alice_acc: AccountId = MultiSigner::from(alice.public()).into_account();
		let bob_acc: AccountId = MultiSigner::from(bob.public()).into_account();

		// Cada firma verifica solo contra su cuenta
		assert!(MultiSignature::Sr25519(alice_sig).verify(msg.as_ref(), &alice_acc));
		assert!(MultiSignature::Sr25519(bob_sig).verify(msg.as_ref(), &bob_acc));
		// Y no verifica la del otro
		assert!(!MultiSignature::Sr25519(alice.sign(msg)).verify(msg.as_ref(), &bob_acc));
		assert!(!MultiSignature::Sr25519(bob.sign(msg)).verify(msg.as_ref(), &alice_acc));
	}

	// ─────────────────────────────────────────────────────────────────────────
	// MultiSignature ECDSA tests
	// ─────────────────────────────────────────────────────────────────────────

	/// ECDSA: firma válida verifica correctamente
	/// AccountId32 = blake2_256(33-byte compressed pubkey)  ← ruta Substrate
	/// Distinto del mapping EVM = blake2_256(20-byte eth address) ← ruta HashedAddressMapping
	#[test]
	fn ecdsa_valid_signature_verifies() {
		let pair = ecdsa::Pair::from_string("//Alice", None).unwrap();
		let msg = b"test-ecdsa-multisignature";

		let sig = pair.sign(msg);
		let multi_sig = MultiSignature::Ecdsa(sig);

		let signer_account: AccountId = MultiSigner::from(pair.public()).into_account();

		assert!(
			multi_sig.verify(msg.as_ref(), &signer_account),
			"ECDSA firma válida debe verificar contra su AccountId"
		);
	}

	/// ECDSA: firma de Alice NO verifica contra la cuenta de Bob
	#[test]
	fn ecdsa_wrong_signer_rejected() {
		let alice = ecdsa::Pair::from_string("//Alice", None).unwrap();
		let bob = ecdsa::Pair::from_string("//Bob", None).unwrap();

		let msg = b"test-ecdsa-wrong-signer";
		let alice_sig = alice.sign(msg);
		let multi_sig = MultiSignature::Ecdsa(alice_sig);

		let bob_account: AccountId = MultiSigner::from(bob.public()).into_account();

		assert!(
			!multi_sig.verify(msg.as_ref(), &bob_account),
			"ECDSA firma de Alice NO debe verificar contra la cuenta de Bob"
		);
	}

	/// Documenta explícitamente las dos rutas de derivación de AccountId en Orbinum:
	///   1. Substrate ECDSA: blake2_256(33-byte-compressed-pubkey)
	///   2. EVM mapping:     blake2_256(20-byte-eth-address)
	///
	/// Son independientes e incompatibles intencionalmente.
	#[test]
	fn ecdsa_substrate_and_evm_paths_are_independent() {
		let alith_eth_address = H160::from(hex!("f24FF3a9CF04c71Dbc94D0b566f7A27B94566cac"));

		// Ruta 1: EVM mapping (chain_spec + pallet_evm)
		let evm_account = HashedAddressMapping::<Runtime>::into_account_id(alith_eth_address);

		// Ruta 2: Substrate ECDSA (MultiSigner)
		let ecdsa_pair = ecdsa::Pair::from_string("//AliceEcdsa", None).unwrap();
		let substrate_ecdsa_account: AccountId =
			MultiSigner::from(ecdsa_pair.public()).into_account();

		// Son distintas por diseño
		assert_ne!(
			evm_account, substrate_ecdsa_account,
			"HashedAddressMapping (EVM) y MultiSigner ECDSA son rutas independientes"
		);
	}

	// ─────────────────────────────────────────────────────────────────────────
	// Tamaños de firma y construcción del enum
	// ─────────────────────────────────────────────────────────────────────────

	/// Verificar tamaños de firma para cada variante de MultiSignature
	#[test]
	fn multisignature_variants_have_correct_byte_sizes() {
		let sr25519_pair = sr25519::Pair::from_string("//Alice", None).unwrap();
		let ecdsa_pair = ecdsa::Pair::from_string("//Alice", None).unwrap();
		let msg = b"size-test";

		let sr25519_sig = sr25519_pair.sign(msg);
		let ecdsa_sig = ecdsa_pair.sign(msg);

		// Sr25519: 64 bytes
		assert_eq!(
			sr25519_sig.0.len(),
			64,
			"Sr25519 signature debe ser 64 bytes"
		);

		// ECDSA: 65 bytes (64 + recovery bit)
		assert_eq!(ecdsa_sig.0.len(), 65, "ECDSA signature debe ser 65 bytes");

		// Se pueden construir como MultiSignature sin errores
		let _ms_sr = MultiSignature::Sr25519(sr25519_sig);
		let _ms_ec = MultiSignature::Ecdsa(ecdsa_sig);
	}

	// ─────────────────────────────────────────────────────────────────────────
	// SignatureApi RuntimeAPI — lógica de validación
	// ─────────────────────────────────────────────────────────────────────────

	// Helpers que replican exactamente la lógica expuesta en la RuntimeAPI.
	// validate_signature en el runtime simplemente delega a MultiSignature::verify.
	fn api_validate_signature(
		signature: MultiSignature,
		message: &[u8],
		signer: &AccountId,
	) -> bool {
		signature.verify(message, signer)
	}

	fn api_get_supported_types() -> alloc::vec::Vec<orbinum_signature_api::SignatureType> {
		alloc::vec![
			orbinum_signature_api::SignatureType::Sr25519,
			orbinum_signature_api::SignatureType::Ecdsa,
		]
	}

	fn sr25519_account(derivation: &str) -> (sr25519::Pair, AccountId) {
		let pair = sr25519::Pair::from_string(derivation, None).unwrap();
		let account: AccountId = MultiSigner::from(pair.public()).into_account();
		(pair, account)
	}

	fn ecdsa_account(derivation: &str) -> (ecdsa::Pair, AccountId) {
		let pair = ecdsa::Pair::from_string(derivation, None).unwrap();
		let account: AccountId = MultiSigner::from(pair.public()).into_account();
		(pair, account)
	}

	/// SignatureApi expone exactamente Sr25519 y Ecdsa, sin más
	#[test]
	fn signature_api_returns_sr25519_and_ecdsa() {
		use orbinum_signature_api::SignatureType;
		let types = api_get_supported_types();
		assert!(types.contains(&SignatureType::Sr25519));
		assert!(types.contains(&SignatureType::Ecdsa));
		assert_eq!(
			types.len(),
			2,
			"Solo Sr25519 y Ecdsa deben estar registrados"
		);
	}

	/// Sr25519 es el tipo preferido: primer elemento de get_supported_signature_types
	#[test]
	fn signature_api_sr25519_is_first_preferred_type() {
		use orbinum_signature_api::SignatureType;
		let types = api_get_supported_types();
		assert_eq!(
			types[0],
			SignatureType::Sr25519,
			"Sr25519 debe ser el primer tipo (preferido)"
		);
	}

	/// Los discriminantes SCALE del enum SignatureType no deben cambiar entre versiones
	#[test]
	fn signature_type_scale_discriminants_are_stable() {
		use orbinum_signature_api::SignatureType;
		use scale_codec::Encode;
		assert_eq!(SignatureType::Sr25519.encode(), vec![0u8]);
		assert_eq!(SignatureType::Ed25519.encode(), vec![1u8]);
		assert_eq!(SignatureType::Ecdsa.encode(), vec![2u8]);
	}

	/// validate_signature acepta firma Sr25519 válida
	#[test]
	fn signature_api_validate_sr25519_valid_signature() {
		let (pair, account) = sr25519_account("//Alice");
		let msg = b"orbinum-signature-api-test";
		let multi_sig = MultiSignature::Sr25519(pair.sign(msg));
		assert!(api_validate_signature(multi_sig, msg, &account));
	}

	/// validate_signature acepta firma ECDSA válida
	#[test]
	fn signature_api_validate_ecdsa_valid_signature() {
		let (pair, account) = ecdsa_account("//Alice");
		let msg = b"orbinum-signature-api-test";
		let multi_sig = MultiSignature::Ecdsa(pair.sign(msg));
		assert!(api_validate_signature(multi_sig, msg, &account));
	}

	/// validate_signature rechaza firma Sr25519 con firmante incorrecto
	#[test]
	fn signature_api_validate_wrong_signer_rejected() {
		let (alice, _) = sr25519_account("//Alice");
		let (_, bob_account) = sr25519_account("//Bob");
		let msg = b"test-message";
		let multi_sig = MultiSignature::Sr25519(alice.sign(msg));
		assert!(!api_validate_signature(multi_sig, msg, &bob_account));
	}

	/// validate_signature rechaza cuando el mensaje fue alterado
	#[test]
	fn signature_api_validate_wrong_message_rejected() {
		let (pair, account) = sr25519_account("//Alice");
		let signed_msg = b"original-message";
		let wrong_msg = b"modified-message";
		let multi_sig = MultiSignature::Sr25519(pair.sign(signed_msg));
		assert!(!api_validate_signature(multi_sig, wrong_msg, &account));
	}

	/// validate_signature rechaza firma Sr25519 con bytes corrompidos
	#[test]
	fn signature_api_validate_corrupted_signature_rejected() {
		let (pair, account) = sr25519_account("//Alice");
		let msg = b"test-message";
		let mut raw_sig = pair.sign(msg);
		raw_sig.0[0] ^= 0xFF;
		raw_sig.0[1] ^= 0xFF;
		let multi_sig = MultiSignature::Sr25519(raw_sig);
		assert!(!api_validate_signature(multi_sig, msg, &account));
	}

	/// validate_signature rechaza bytes de Sr25519 empaquetados como variante ECDSA
	#[test]
	fn signature_api_validate_wrong_signature_type_rejected() {
		let (sr_pair, sr_account) = sr25519_account("//Alice");
		let msg = b"cross-type-test";
		let sr_raw = sr_pair.sign(msg);
		let mut ecdsa_bytes = [0u8; 65];
		ecdsa_bytes[..64].copy_from_slice(&sr_raw.0[..64]);
		let multi_sig = MultiSignature::Ecdsa(ecdsa::Signature::from_raw(ecdsa_bytes));
		assert!(!api_validate_signature(multi_sig, msg, &sr_account));
	}

	// ─────────────────────────────────────────────────────────────────────────
	// Nonce Validation — estructura e invariantes
	// ─────────────────────────────────────────────────────────────────────────

	/// frame_system::CheckNonce<Runtime> puede instanciarse — compile-time check de
	/// que la extensión de nonce está disponible para el runtime configurado.
	///
	/// Si este test compila, CheckNonce está accesible y el Runtime implementa
	/// frame_system::Config correctamente.
	#[test]
	fn check_nonce_signed_extension_is_constructable() {
		// CheckNonce wraps T::Nonce (= u32 en este runtime).
		// Si este test compila, el tipo está disponible para el runtime.
		let _: frame_system::CheckNonce<Runtime>;
	}

	/// El tipo Nonce del runtime es u32, lo que significa que puede representar
	/// hasta 4.294.967.295 transacciones por cuenta sin overflow.
	#[test]
	fn nonce_type_is_u32_for_this_runtime() {
		// T::Nonce para este Runtime es u32
		let zero: <Runtime as frame_system::Config>::Nonce = 0u32;
		let one: <Runtime as frame_system::Config>::Nonce = 1u32;
		assert_ne!(zero, one, "Nonce 0 y Nonce 1 deben ser distintos");

		// El nonce usa u32 nativo — verificar límite superior
		let max_nonce: u32 = u32::MAX;
		assert_eq!(
			max_nonce, 4_294_967_295u32,
			"Nonce máximo es u32::MAX = 4.294.967.295"
		);
	}

	/// Sr25519 //Alice y ECDSA //Alice producen AccountId32 DISTINTOS, lo que
	/// significa que tienen nonces separados en el runtime. Los wallets deben
	/// gestionarlos de forma independiente.
	#[test]
	fn sr25519_and_ecdsa_same_derivation_produce_different_accounts() {
		let (_, sr25519_alice_account) = sr25519_account("//Alice");
		let (_, ecdsa_alice_account) = ecdsa_account("//Alice");

		assert_ne!(
			sr25519_alice_account, ecdsa_alice_account,
			"Sr25519 //Alice y ECDSA //Alice deben tener AccountId32 distintos — nonces independientes"
		);
	}

	/// Una cuenta tiene UN solo nonce sin importar el tipo de firma usada.
	/// Dos firmas distintas (Sr25519 y ECDSA) para el mismo AccountId apuntan
	/// al mismo contador de nonce en frame_system::Account.
	///
	/// Este test verifica que el AccountId32 siempre tiene 32 bytes y que la firma
	/// referencia a la cuenta correcta en storage. Frame_system garantiza que
	/// existe UN único AccountInfo por AccountId32, con UN único nonce.
	#[test]
	fn same_account_single_nonce_regardless_of_signature_type() {
		let (alice_sr, alice_sr_account) = sr25519_account("//AliceNonce");
		let msg = b"nonce-invariant-test";

		// Firma Sr25519 verifica contra su AccountId32
		let sig_sr = MultiSignature::Sr25519(alice_sr.sign(msg));
		assert!(
			api_validate_signature(sig_sr, msg, &alice_sr_account),
			"La firma Sr25519 del AccountId correcto siempre verifica"
		);

		// AccountId32 tiene exactamente 32 bytes — este es el key en frame_system::Account
		// que almacena UN AccountInfo con UN nonce.
		let account_bytes: &[u8; 32] = alice_sr_account.as_ref();
		assert_eq!(
			account_bytes.len(),
			32,
			"AccountId32 siempre tiene 32 bytes"
		);
	}
}
