//! Frontier EVM layer: EVM, Ethereum, fee models, and dev-only manual seal.
//!
//! A transaction's priority tip goes to the validator that authored the block
//! (`TipToValidator`). `block.coinbase` is the zero address: no H160 maps onto a
//! validator's sr25519 account, so any other value would name an account nobody
//! controls.

use crate::*;
use frame_support::{
	parameter_types,
	traits::fungible::{Balanced, Credit},
};

impl pallet_evm_chain_id::Config for Runtime {}

/// Pays an EVM transaction's priority tip to the validator that authored the
/// block; the base fee is burned. Without an author (an RPC simulation) the tip
/// is burned too.
pub struct TipToValidator;

impl pallet_evm::OnChargeEVMTransaction<Runtime> for TipToValidator {
	type LiquidityInfo = Option<Credit<AccountId, Balances>>;

	fn withdraw_fee(
		who: &H160,
		fee: U256,
	) -> Result<Self::LiquidityInfo, pallet_evm::Error<Runtime>> {
		<pallet_evm::EVMFungibleAdapter<Balances, ()> as pallet_evm::OnChargeEVMTransaction<
			Runtime,
		>>::withdraw_fee(who, fee)
	}

	fn correct_and_deposit_fee(
		who: &H160,
		corrected_fee: U256,
		base_fee: U256,
		already_withdrawn: Self::LiquidityInfo,
	) -> Self::LiquidityInfo {
		<pallet_evm::EVMFungibleAdapter<Balances, ()> as pallet_evm::OnChargeEVMTransaction<
			Runtime,
		>>::correct_and_deposit_fee(who, corrected_fee, base_fee, already_withdrawn)
	}

	fn pay_priority_fee(tip: Self::LiquidityInfo) {
		if let (Some(tip), Some(author)) = (tip, pallet_authorship::Pallet::<Runtime>::author()) {
			// A refused deposit drops the credit, which burns it.
			let _ = <Balances as Balanced<AccountId>>::resolve(&author, tip);
		}
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

impl pallet_evm::Config for Runtime {
	type AccountProvider = pallet_evm::FrameSystemAccountProvider<Self>;
	type FeeCalculator = BaseFee;
	type GasWeightMapping = pallet_evm::FixedGasWeightMapping<Self>;
	type WeightPerGas = WeightPerGas;
	type BlockHashMapping = pallet_ethereum::EthereumBlockHashMapping<Self>;
	type CallOrigin = EnsureAddressMatches;
	type WithdrawOrigin = EnsureAddressMatches;
	type AddressMapping = EeSuffixAddressMapping<Self>;
	type Currency = Balances;
	type PrecompilesType = FrontierPrecompiles<Self>;
	type PrecompilesValue = PrecompilesValue;
	type ChainId = EVMChainId;
	type BlockGasLimit = BlockGasLimit;
	type Runner = pallet_evm::runner::stack::Runner<Self>;
	type OnChargeTransaction = TipToValidator;
	type OnCreate = ();
	type FindAuthor = ();
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
	// ORB uses 18 decimals (1 ORB = 1e18 wei), aligned with Ethereum tooling.
	// DefaultBaseFeePerGas is used as the runtime-level fallback (e.g. storage migration).
	// Actual genesis values are set per-chain-spec in genesis_config_preset/:
	//   all networks → 1_000_000_000 wei/gas (1 gwei → ~0.00001 ORB / transfer)
	// The floor (empty blocks) = DefaultBaseFeePerGas / 2 = 0.5 gwei.
	// EIP-1559 adjusts the fee upward automatically as the network gains traffic.
	pub DefaultBaseFeePerGas: U256 = U256::from(1_000_000_000u64); // 1 gwei

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

impl pallet_manual_seal::Config for Runtime {}
