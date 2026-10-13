//! Test mock for `pallet-evm-precompile-shielded-pool`.

use fp_evm::{ExitError, ExitReason, Transfer};
use frame_support::{derive_impl, parameter_types, weights::Weight, PalletId};
use pallet_evm::{
	AddressMapping, Context, EnsureAddressNever, EnsureAddressRoot, FeeCalculator, PrecompileHandle,
};
use pallet_zk_verifier::{ShieldStatement, TransferStatement, UnshieldStatement, ZkVerifierPort};
use sp_core::{H160, H256, U256};
use sp_runtime::{
	traits::{BlakeTwo256, IdentityLookup},
	AccountId32, BuildStorage,
};

pub(crate) type Balance = u128;

type Block = frame_system::mocking::MockBlock<Test>;

frame_support::construct_runtime!(
	pub enum Test {
		System: frame_system,
		Balances: pallet_balances,
		Timestamp: pallet_timestamp,
		EVM: pallet_evm,
		ShieldedPool: pallet_shielded_pool,
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

/// `H160 ++ [0u8; 12]`, the runtime's EVM address mapping.
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

parameter_types! {
	pub const ShieldedPoolPalletId: PalletId = PalletId(*b"shldpool");
	pub const MaxTreeDepth: u32 = 20;
	pub const MaxHistoricRoots: u32 = 100;
	pub const RootRetentionBlocks: u64 = 128;
	/// Matches the pallet's own mock so both exercise the same cut.
	pub const SealedTreePrunedBelowLevel: u8 = 2;
	pub const MaxLeavesPerTree: u32 = 8;
}

pub struct MockZkVerifier;

impl ZkVerifierPort for MockZkVerifier {
	fn verify_transfer_proof(
		proof: &[u8],
		_statement: &TransferStatement,
		_version: Option<u32>,
	) -> Result<bool, sp_runtime::DispatchError> {
		non_empty(proof)
	}

	fn verify_unshield_proof(
		proof: &[u8],
		_statement: &UnshieldStatement,
		_version: Option<u32>,
	) -> Result<bool, sp_runtime::DispatchError> {
		non_empty(proof)
	}

	fn verify_shield_proof(
		proof: &[u8],
		_statement: &ShieldStatement,
		_version: Option<u32>,
	) -> Result<bool, sp_runtime::DispatchError> {
		non_empty(proof)
	}

	fn is_supported_version(_circuit_id: u32, version: u32) -> bool {
		version != 0
	}

	fn verification_weight() -> frame_support::weights::Weight {
		frame_support::weights::Weight::from_parts(11_700_000_000, 0)
	}
}

fn non_empty(proof: &[u8]) -> Result<bool, sp_runtime::DispatchError> {
	if proof.is_empty() {
		return Err(sp_runtime::DispatchError::Other("Empty proof"));
	}
	Ok(true)
}

parameter_types! {
	pub BlockAuthor: Option<AccountId32> = Some(AccountId32::from([1u8; 32]));
}

impl pallet_shielded_pool::Config for Test {
	type Currency = Balances;
	type ZkVerifier = MockZkVerifier;
	type PalletId = ShieldedPoolPalletId;
	type MaxTreeDepth = MaxTreeDepth;
	type MaxHistoricRoots = MaxHistoricRoots;
	type RootRetentionBlocks = RootRetentionBlocks;
	type SealedTreePrunedBelowLevel = SealedTreePrunedBelowLevel;
	type MaxLeavesPerTree = MaxLeavesPerTree;
	type WeightInfo = ();
	type BlockAuthor = BlockAuthor;
	type MinSpendFee = frame_support::traits::ConstU128<0>;
}

/// The EVM caller of every `MockHandle`.
pub fn caller() -> H160 {
	H160::from_low_u64_be(1)
}

pub fn caller_account() -> AccountId32 {
	H160ToAccountId32Mapping::into_account_id(caller())
}

/// Account mapped from `H160::zero()` — used as the precompile's own address in
/// `MockHandle` (`context.address = H160::zero()`).
///
/// In real EVM execution the EVM transfers `msg.value` from the caller to the
/// precompile's account before `execute` is called. The mock doesn't run the EVM
/// machinery, so `new_test_ext` funds this account directly to replicate that effect.
pub fn precompile_account() -> AccountId32 {
	H160ToAccountId32Mapping::into_account_id(H160::zero())
}

pub fn new_test_ext() -> sp_io::TestExternalities {
	let mut t = frame_system::GenesisConfig::<Test>::default()
		.build_storage()
		.unwrap();

	pallet_balances::GenesisConfig::<Test> {
		// Fund both the EVM caller and the precompile's own account. `dispatch::from_self`
		// dispatches `shield` with the precompile as origin, and the pallet transfers
		// from that account to the pool. The real EVM moves `msg.value` there before
		// `execute`; here genesis funds it instead.
		balances: vec![
			(caller_account(), 1_000_000_000_000_000u128),
			(precompile_account(), 1_000_000_000_000_000u128),
		],
		dev_accounts: None,
	}
	.assimilate_storage(&mut t)
	.unwrap();

	pallet_shielded_pool::GenesisConfig::<Test> {
		initial_root: [0u8; 32],
		_phantom: Default::default(),
	}
	.assimilate_storage(&mut t)
	.unwrap();

	let mut ext = sp_io::TestExternalities::new(t);
	ext.execute_with(|| System::set_block_number(1));
	ext
}

/// A precompile call from [`caller`] to the precompile at `H160::zero()`.
pub(crate) struct MockHandle {
	pub input: Vec<u8>,
	pub context: Context,
	/// Differs from `context.address` under DELEGATECALL.
	pub code_address: H160,
	pub is_static: bool,
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
			code_address: H160::zero(),
			is_static: false,
		}
	}

	/// A handle carrying `value` as `apparent_value` (`msg.value`), for payable
	/// calls such as `shield`.
	pub fn with_value(input: Vec<u8>, value: u128) -> Self {
		let mut handle = Self::new(input);
		handle.context.apparent_value = U256::from(value);
		handle
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
		self.code_address
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
		self.is_static
	}

	fn gas_limit(&self) -> Option<u64> {
		None
	}

	fn is_contract_being_constructed(&self, _address: H160) -> bool {
		false
	}
}
