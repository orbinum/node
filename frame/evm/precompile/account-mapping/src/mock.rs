//! Test mock for `pallet-evm-precompile-account-mapping`.
//!
//! Uses `AccountId = H160` so that `IdentityAddressMapping` works directly
//! (EVM caller H160 → substrate AccountId H160 without any conversion).
//! Uses `Balance = u128` so that `BalanceOf<T>: TryFrom<u128>` is trivially
//! satisfied.

use frame_support::{parameter_types, weights::Weight};
use pallet_account_mapping::PrivateLinkVerifierPort;
use pallet_evm::{
	Context, EnsureAddressNever, EnsureAddressRoot, FeeCalculator, IdentityAddressMapping,
	PrecompileHandle,
};
use sp_core::{H160, H256, U256};
use sp_runtime::{
	traits::{BlakeTwo256, Convert, IdentityLookup},
	BuildStorage,
};

use fp_evm::{ExitError, ExitReason, Transfer};

pub(crate) type Balance = u128;

type Block = frame_system::mocking::MockBlock<Test>;

frame_support::construct_runtime!(
	pub enum Test {
		System: frame_system,
		Balances: pallet_balances,
		Timestamp: pallet_timestamp,
		EVM: pallet_evm,
		AccountMapping: pallet_account_mapping,
	}
);

parameter_types! {
	pub const BlockHashCount: u64 = 250;
}

impl frame_system::Config for Test {
	type BaseCallFilter = frame_support::traits::Everything;
	type BlockWeights = ();
	type BlockLength = ();
	type RuntimeOrigin = RuntimeOrigin;
	type RuntimeCall = RuntimeCall;
	type RuntimeTask = RuntimeTask;
	type Nonce = u64;
	type Hash = H256;
	type Hashing = BlakeTwo256;
	type AccountId = H160;
	type Lookup = IdentityLookup<Self::AccountId>;
	type Block = Block;
	type RuntimeEvent = RuntimeEvent;
	type BlockHashCount = BlockHashCount;
	type DbWeight = ();
	type Version = ();
	type PalletInfo = PalletInfo;
	type AccountData = pallet_balances::AccountData<Balance>;
	type OnNewAccount = ();
	type OnKilledAccount = ();
	type SystemWeightInfo = ();
	type SS58Prefix = ();
	type OnSetCode = ();
	type MaxConsumers = frame_support::traits::ConstU32<16>;
	type ExtensionsWeightInfo = ();
	type SingleBlockMigrations = ();
	type MultiBlockMigrator = ();
	type PreInherents = ();
	type PostInherents = ();
	type PostTransactions = ();
}

parameter_types! {
	pub const ExistentialDeposit: Balance = 1;
}

impl pallet_balances::Config for Test {
	type RuntimeEvent = RuntimeEvent;
	type RuntimeHoldReason = RuntimeHoldReason;
	type RuntimeFreezeReason = RuntimeFreezeReason;
	type WeightInfo = ();
	type Balance = Balance;
	type DustRemoval = ();
	type ExistentialDeposit = ExistentialDeposit;
	type AccountStore = System;
	type ReserveIdentifier = [u8; 8];
	type FreezeIdentifier = RuntimeFreezeReason;
	type MaxLocks = ();
	type MaxReserves = ();
	type MaxFreezes = ();
	type DoneSlashHandler = ();
}

parameter_types! {
	pub const MinimumPeriod: u64 = 1000;
}

impl pallet_timestamp::Config for Test {
	type Moment = u64;
	type OnTimestampSet = ();
	type MinimumPeriod = MinimumPeriod;
	type WeightInfo = ();
}

pub struct FixedGasPrice;
impl FeeCalculator for FixedGasPrice {
	fn min_gas_price() -> (U256, Weight) {
		(1_000_000_000u128.into(), Weight::from_parts(7u64, 0))
	}
}

parameter_types! {
	pub BlockGasLimit: U256 = U256::max_value();
	pub WeightPerGas: Weight = Weight::from_parts(20_000, 0);
}

impl pallet_evm::Config for Test {
	type AccountProvider = pallet_evm::FrameSystemAccountProvider<Self>;
	type FeeCalculator = FixedGasPrice;
	type GasWeightMapping = pallet_evm::FixedGasWeightMapping<Self>;
	type WeightPerGas = WeightPerGas;
	type BlockHashMapping = pallet_evm::SubstrateBlockHashMapping<Self>;
	type CallOrigin = EnsureAddressRoot<Self::AccountId>;
	type WithdrawOrigin = EnsureAddressNever<Self::AccountId>;
	type AddressMapping = IdentityAddressMapping;
	type Currency = Balances;
	type PrecompilesType = ();
	type PrecompilesValue = ();
	type ChainId = ();
	type BlockGasLimit = BlockGasLimit;
	type Runner = pallet_evm::runner::stack::Runner<Self>;
	type OnChargeTransaction = ();
	type OnCreate = ();
	type FindAuthor = ();
	type GasLimitPovSizeRatio = ();
	type GasLimitStorageGrowthRatio = ();
	type Timestamp = Timestamp;
	type CreateInnerOriginFilter = ();
	type CreateOriginFilter = ();
	type WeightInfo = ();
}

/// Identity converter: each substrate H160 account maps to itself as EVM address.
pub struct IdentityEvmAddress;
impl Convert<H160, Option<H160>> for IdentityEvmAddress {
	fn convert(account: H160) -> Option<H160> {
		Some(account)
	}
}

parameter_types! {
	pub const TestAliasDeposit: Balance = 100;
	pub const TestMaxAliasLength: u32 = 32;
}

/// Accepts a proof if its first byte is `0x01`.
pub struct MockPrivateLinkVerifier;
impl PrivateLinkVerifierPort for MockPrivateLinkVerifier {
	fn verify(_commitment: &[u8; 32], _call_hash: &[u8; 32], proof: &[u8]) -> bool {
		proof.first().copied() == Some(0x01)
	}
}

impl pallet_account_mapping::Config for Test {
	type RuntimeCall = RuntimeCall;
	type Currency = Balances;
	type AccountIdToEvmAddress = IdentityEvmAddress;
	type AliasDeposit = TestAliasDeposit;
	type MaxAliasLength = TestMaxAliasLength;
	type WeightInfo = pallet_account_mapping::weights::SubstrateWeight<Test>;
	type PrivateLinkVerifier = MockPrivateLinkVerifier;
}

/// Caller address used in tests: `0x0000…0001`.
pub fn caller() -> H160 {
	H160::from_low_u64_be(1)
}

/// Builds test externalities and funds `caller()` with 1 000 000 units.
pub fn new_test_ext() -> sp_io::TestExternalities {
	let mut t = frame_system::GenesisConfig::<Test>::default()
		.build_storage()
		.unwrap();

	pallet_balances::GenesisConfig::<Test> {
		balances: vec![(caller(), 1_000_000)],
		dev_accounts: None,
	}
	.assimilate_storage(&mut t)
	.unwrap();

	let mut ext = sp_io::TestExternalities::new(t);
	ext.execute_with(|| System::set_block_number(1));
	ext
}

// ─────────────────────────────────────────────────────────────────────────────
// MockHandle
// ─────────────────────────────────────────────────────────────────────────────

pub(crate) struct MockHandle {
	pub input: Vec<u8>,
	pub context: Context,
}

impl MockHandle {
	pub fn new(input: Vec<u8>) -> Self {
		Self {
			input,
			context: Context {
				address: H160::zero(),
				caller: caller(),
				apparent_value: U256::zero(),
			},
		}
	}
}

impl PrecompileHandle for MockHandle {
	fn call(
		&mut self,
		_: H160,
		_: Option<Transfer>,
		_: Vec<u8>,
		_: Option<u64>,
		_: bool,
		_: &Context,
	) -> (ExitReason, Vec<u8>) {
		unimplemented!()
	}

	fn record_cost(&mut self, _: u64) -> Result<(), ExitError> {
		Ok(())
	}

	fn record_external_cost(
		&mut self,
		_ref_time: Option<u64>,
		_proof_size: Option<u64>,
		_storage_growth: Option<u64>,
	) -> Result<(), ExitError> {
		Ok(())
	}

	fn refund_external_cost(&mut self, _ref_time: Option<u64>, _proof_size: Option<u64>) {}

	fn remaining_gas(&self) -> u64 {
		u64::MAX
	}

	fn log(&mut self, _: H160, _: Vec<H256>, _: Vec<u8>) -> Result<(), ExitError> {
		Ok(())
	}

	fn code_address(&self) -> H160 {
		H160::zero()
	}

	fn input(&self) -> &[u8] {
		&self.input
	}

	fn context(&self) -> &Context {
		&self.context
	}

	fn origin(&self) -> H160 {
		self.context.caller
	}

	fn is_static(&self) -> bool {
		false
	}

	fn gas_limit(&self) -> Option<u64> {
		None
	}

	fn is_contract_being_constructed(&self, _address: H160) -> bool {
		false
	}
}
