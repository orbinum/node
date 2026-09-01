//! Core FRAME configuration: system, timestamp, balances, fees, sudo.
//!
//! `BlockWeights` is the one to read first — it caps what a block may execute,
//! which is what bounds every other pallet's per-block work.

use crate::*;
use frame_support::{derive_impl, parameter_types};

parameter_types! {
	pub const Version: RuntimeVersion = VERSION;
	pub const BlockHashCount: BlockNumber = 256;
	pub BlockWeights: frame_system::limits::BlockWeights = frame_system::limits::BlockWeights
		::with_sensible_defaults(MAXIMUM_BLOCK_WEIGHT, NORMAL_DISPATCH_RATIO);
	/// Block LENGTH uses 85% (`BLOCK_LENGTH_NORMAL_RATIO`), not the 75%
	/// `NORMAL_DISPATCH_RATIO` that bounds weights: ISMP needs the headroom for GRANDPA
	/// proofs, weights stay where they were.
	// Spelled with the builder because `max_with_normal_ratio` is deprecated, and the
	// `normal_ratio` builder method its note names does not exist on this release.
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
