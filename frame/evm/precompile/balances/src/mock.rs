//! Test mock for `pallet-evm-precompile-balances`.

use frame_support::{derive_impl, parameter_types, weights::Weight};
use pallet_evm::{
	AddressMapping, Context, EnsureAddressNever, EnsureAddressRoot, FeeCalculator, PrecompileHandle,
};
use sp_core::{H160, H256, U256};
use sp_runtime::{
	traits::{BlakeTwo256, IdentityLookup},
	AccountId32, BuildStorage,
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
	}
);

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
	type Block = Block;
	type Hash = H256;
	type Hashing = BlakeTwo256;
	type AccountId = AccountId32;
	type Lookup = IdentityLookup<Self::AccountId>;
	type AccountData = pallet_balances::AccountData<Balance>;
}

parameter_types! {
	/// Set ED to 1 so `transfer_keep_alive` semantics can be meaningfully tested:
	/// a keep-alive transfer that would drain the sender below 1 unit must fail,
	/// while `transfer_allow_death` may kill the account.
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

/// Maps an H160 EVM address to an AccountId32 by zero-padding on the right:
/// `[addr_20_bytes | 0x00 × 12]`.
///
/// This mirrors the `EeSuffixAddressMapping` used in the Orbinum runtime.
pub struct H160ToAccountId32Mapping;
impl AddressMapping<AccountId32> for H160ToAccountId32Mapping {
	fn into_account_id(address: H160) -> AccountId32 {
		let mut bytes = [0u8; 32];
		bytes[..20].copy_from_slice(address.as_bytes());
		AccountId32::from(bytes)
	}
}

impl pallet_evm::Config for Test {
	type AccountProvider = pallet_evm::FrameSystemAccountProvider<Self>;
	type FeeCalculator = FixedGasPrice;
	type GasWeightMapping = pallet_evm::FixedGasWeightMapping<Self>;
	type WeightPerGas = WeightPerGas;
	type BlockHashMapping = pallet_evm::SubstrateBlockHashMapping<Self>;
	type CallOrigin = EnsureAddressRoot<Self::AccountId>;
	type WithdrawOrigin = EnsureAddressNever<Self::AccountId>;
	type AddressMapping = H160ToAccountId32Mapping;
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

// ─────────────────────────────────────────────────────────────────────────────
// Test Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// EVM caller address used in tests: `0x0000…0001`.
pub fn caller() -> H160 {
	H160::from_low_u64_be(1)
}

/// Substrate `AccountId32` corresponding to `caller()`.
pub fn caller_account() -> AccountId32 {
	H160ToAccountId32Mapping::into_account_id(caller())
}

/// A pure-substrate (Sr25519-style) recipient: 32 bytes of `0x02`.
pub fn bob_account() -> AccountId32 {
	AccountId32::from([0x02u8; 32])
}

/// An EVM-suffix recipient: `[H160::from_low_u64_be(0xAB) | 12×0x00]`.
pub fn eve_evm_account() -> AccountId32 {
	H160ToAccountId32Mapping::into_account_id(H160::from_low_u64_be(0xAB))
}

/// Builds test externalities and funds `caller_account()` with 1_000_000 units.
pub fn new_test_ext() -> sp_io::TestExternalities {
	let mut t = frame_system::GenesisConfig::<Test>::default()
		.build_storage()
		.unwrap();

	pallet_balances::GenesisConfig::<Test> {
		balances: vec![(caller_account(), 1_000_000)],
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
