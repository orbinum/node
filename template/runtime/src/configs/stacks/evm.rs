//! Frontier EVM layer: EVM, Ethereum and the base fee.
//!
//! A transaction's base fee goes to the era's reward pool and its priority tip to
//! the validator that authored the block (`EvmFeeRouter`, same destinations as
//! Substrate fees, see `economy`). `block.coinbase` is the zero address: no H160
//! maps onto a validator's sr25519 account, so any other value would name an
//! account nobody controls.

use crate::{
	economy::{FeeDestination, TipDestination},
	evm::{
		account::{EeSuffixAddressMapping, EnsureAddressMatches},
		precompiles::FrontierPrecompiles,
	},
	primitives::constants::{NORMAL_DISPATCH_RATIO, WEIGHT_MILLISECS_PER_BLOCK},
	AccountId, Balances, BaseFee, EVMChainId, Runtime, Timestamp,
};
use fp_evm::weight_per_gas;
use frame_support::{
	parameter_types,
	traits::{fungible::Credit, ConstU32, OnUnbalanced},
	weights::Weight,
};
use pallet_ethereum::PostLogContent;
use sp_core::{H160, U256};
use sp_runtime::Permill;

impl pallet_evm_chain_id::Config for Runtime {}

/// Routes an EVM transaction's base fee to [`FeeDestination`] and its priority tip
/// to [`TipDestination`]. Nothing is burned.
pub struct EvmFeeRouter;

type EvmFeeAdapter = pallet_evm::EVMFungibleAdapter<Balances, FeeDestination>;

impl pallet_evm::OnChargeEVMTransaction<Runtime> for EvmFeeRouter {
	type LiquidityInfo = Option<Credit<AccountId, Balances>>;

	fn withdraw_fee(
		who: &H160,
		fee: U256,
	) -> Result<Self::LiquidityInfo, pallet_evm::Error<Runtime>> {
		<EvmFeeAdapter as pallet_evm::OnChargeEVMTransaction<Runtime>>::withdraw_fee(who, fee)
	}

	fn correct_and_deposit_fee(
		who: &H160,
		corrected_fee: U256,
		base_fee: U256,
		already_withdrawn: Self::LiquidityInfo,
	) -> Self::LiquidityInfo {
		<EvmFeeAdapter as pallet_evm::OnChargeEVMTransaction<Runtime>>::correct_and_deposit_fee(
			who,
			corrected_fee,
			base_fee,
			already_withdrawn,
		)
	}

	fn pay_priority_fee(tip: Self::LiquidityInfo) {
		if let Some(tip) = tip {
			<TipDestination as OnUnbalanced<_>>::on_unbalanced(tip);
		}
	}
}

const BLOCK_GAS_LIMIT: u64 = 75_000_000;
const MAX_POV_SIZE: u64 = 5 * 1024 * 1024;
/// Per block, in bytes.
const MAX_STORAGE_GROWTH: u64 = 400 * 1024;

parameter_types! {
	pub BlockGasLimit: U256 = U256::from(BLOCK_GAS_LIMIT);
	pub const GasLimitPovSizeRatio: u64 = BLOCK_GAS_LIMIT.saturating_div(MAX_POV_SIZE);
	pub const GasLimitStorageGrowthRatio: u64 = BLOCK_GAS_LIMIT.saturating_div(MAX_STORAGE_GROWTH);
	pub PrecompilesValue: FrontierPrecompiles<Runtime> = FrontierPrecompiles::<_>::new();
	pub WeightPerGas: Weight = Weight::from_parts(weight_per_gas(BLOCK_GAS_LIMIT, NORMAL_DISPATCH_RATIO, WEIGHT_MILLISECS_PER_BLOCK), 0);
	// EIP-7825 (Osaka) per-transaction cap of 2^24 gas.
	pub TransactionGasLimit: Option<U256> = Some(fp_evm::MAX_TRANSACTION_GAS_LIMIT);
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
	type OnChargeTransaction = EvmFeeRouter;
	type OnCreate = ();
	type FindAuthor = ();
	type GasLimitPovSizeRatio = GasLimitPovSizeRatio;
	type GasLimitStorageGrowthRatio = GasLimitStorageGrowthRatio;
	type TransactionGasLimit = TransactionGasLimit;
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
	// Pre-EIP-155 legacy transactions carry no chain id and replay across chains.
	type AllowUnprotectedTxs = frame_support::traits::ConstBool<false>;
}

parameter_types! {
	/// 1 gwei (ORB has 18 decimals, like ETH): the storage default and, scaled by
	/// `BaseFeeThreshold::ideal`, the floor the fee decays to (0.5 gwei). Each chain's
	/// starting value is set in `genesis/`.
	pub DefaultBaseFeePerGas: U256 = U256::from(1_000_000_000u64);

	/// 12.5%: the most the base fee moves in one block (EIP-1559).
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
