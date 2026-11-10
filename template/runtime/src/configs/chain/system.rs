//! Core FRAME configuration: system, timestamp, balances, fees, sudo.
//!
//! `BlockWeights` is the one to read first — it caps what a block may execute,
//! which is what bounds every other pallet's per-block work.

use crate::{
	configs::{
		consensus::ConsensusOnTimestampSet,
		evm::{DefaultBaseFeePerGas, WeightPerGas},
	},
	economy::DealWithFees,
	primitives::constants::{
		BLOCK_LENGTH_NORMAL_RATIO, MAXIMUM_BLOCK_LENGTH, MAXIMUM_BLOCK_WEIGHT,
		NORMAL_DISPATCH_RATIO, SLOT_DURATION,
	},
	staking::{
		live::KickKeepsNominations, local_relay::LocalRelayFilter, payouts::NoControllerPayee,
	},
	AccountId, Balance, Balances, Block, BlockNumber, Hash, Hashing, Nonce, PalletInfo, Runtime,
	RuntimeCall, RuntimeEvent, RuntimeFreezeReason, RuntimeHoldReason, RuntimeOrigin, RuntimeTask,
	System, UncheckedExtrinsic, VERSION,
};
#[cfg(feature = "with-paritydb-weights")]
use frame_support::weights::constants::ParityDbWeight as RuntimeDbWeight;
#[cfg(feature = "with-rocksdb-weights")]
use frame_support::weights::constants::RocksDbWeight as RuntimeDbWeight;
use frame_support::{
	derive_impl, parameter_types,
	traits::{ConstU128, ConstU32, ConstU64, ConstU8, InsideBoth},
	weights::ConstantMultiplier,
};
use pallet_transaction_payment::FungibleAdapter;
use polkadot_runtime_common::SlowAdjustingFeeUpdate;
use sp_core::U256;
use sp_runtime::traits::IdentityLookup;
use sp_version::RuntimeVersion;

parameter_types! {
	pub const Version: RuntimeVersion = VERSION;
	pub const BlockHashCount: BlockNumber = 256;
	pub BlockWeights: frame_system::limits::BlockWeights = frame_system::limits::BlockWeights
		::with_sensible_defaults(MAXIMUM_BLOCK_WEIGHT, NORMAL_DISPATCH_RATIO);
	// Builder form: `max_with_normal_ratio` is deprecated, and the `normal_ratio` its
	// note suggests does not exist in this release.
	/// Normal transactions get 85% of the length (`BLOCK_LENGTH_NORMAL_RATIO`), above the
	/// 75% weight ratio: ISMP's GRANDPA proofs need the room.
	pub BlockLength: frame_system::limits::BlockLength = frame_system::limits::BlockLength
		::builder()
		.max_length(MAXIMUM_BLOCK_LENGTH)
		.modify_max_length_for_class(frame_support::dispatch::DispatchClass::Normal, |len| {
			*len = BLOCK_LENGTH_NORMAL_RATIO * MAXIMUM_BLOCK_LENGTH;
		})
		.build();
	pub const SS58Prefix: u8 = 42;
}

#[derive_impl(frame_system::config_preludes::SolochainDefaultConfig as frame_system::DefaultConfig)]
impl frame_system::Config for Runtime {
	/// Everything but the staking clients' calls, a `staking.kick` that would
	/// empty a nomination and a `staking.bond` paying the deprecated
	/// `Controller` destination.
	type BaseCallFilter =
		InsideBoth<LocalRelayFilter, InsideBoth<KickKeepsNominations, NoControllerPayee>>;
	type BlockWeights = BlockWeights;
	type BlockLength = BlockLength;
	type Nonce = Nonce;
	type Hash = Hash;
	type Hashing = Hashing;
	type AccountId = AccountId;
	type Lookup = IdentityLookup<AccountId>;
	type Block = Block;
	type BlockHashCount = BlockHashCount;
	type DbWeight = RuntimeDbWeight;
	type Version = Version;
	type AccountData = pallet_balances::AccountData<Balance>;
	/// 42 is the generic Substrate prefix.
	type SS58Prefix = SS58Prefix;
	type MaxConsumers = ConstU32<16>;
}

/// Lets pallets build the unsigned transactions they submit from offchain code:
/// GRANDPA equivocation reports.
impl<C> frame_system::offchain::CreateTransactionBase<C> for Runtime
where
	RuntimeCall: From<C>,
{
	type Extrinsic = UncheckedExtrinsic;
	type RuntimeCall = RuntimeCall;
}

impl<C> frame_system::offchain::CreateBare<C> for Runtime
where
	RuntimeCall: From<C>,
{
	fn create_bare(call: RuntimeCall) -> UncheckedExtrinsic {
		UncheckedExtrinsic::new_bare(call)
	}
}

impl pallet_timestamp::Config for Runtime {
	type Moment = u64;
	type OnTimestampSet = ConsensusOnTimestampSet<Self>;
	type MinimumPeriod = ConstU64<{ SLOT_DURATION / 2 }>;
	type WeightInfo = pallet_timestamp::weights::SubstrateWeight<Runtime>;
}

/// No existential deposit: an account is never reaped for a low balance. Upstream's
/// staking and pool benchmarks size stakes as multiples of it, so they run with one
/// planck.
#[cfg(not(feature = "runtime-benchmarks"))]
pub const EXISTENTIAL_DEPOSIT: u128 = 0;
#[cfg(feature = "runtime-benchmarks")]
pub const EXISTENTIAL_DEPOSIT: u128 = 1;

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

parameter_types! {
	/// Fee per unit of `ref_time`, priced as EVM gas at the default base fee
	/// (1 gwei / 20_000 weight per gas = 50_000 wei): a Substrate extrinsic costs what
	/// the equivalent EVM transaction does.
	pub WeightFee: Balance = (DefaultBaseFeePerGas::get()
		/ U256::from(WeightPerGas::get().ref_time())).low_u128();
	/// Fee per encoded byte: EVM calldata's 16 gas per non-zero byte.
	pub LengthFee: Balance = (DefaultBaseFeePerGas::get() * U256::from(16)).low_u128();
}

impl pallet_transaction_payment::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	/// Fee to the era's reward pool, tip to the block author (`economy`).
	type OnChargeTransaction = FungibleAdapter<Balances, DealWithFees>;
	type WeightToFee = ConstantMultiplier<Balance, WeightFee>;
	type LengthToFee = ConstantMultiplier<Balance, LengthFee>;
	/// Polkadot's slow-adjusting fee multiplier:
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
