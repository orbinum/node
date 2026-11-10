//! Upkeep with no transactions: paying each era (`pallet-auto-payout`) and pruning
//! old ones (`EraPruning`).

use super::staking::MaxActiveValidators;
use crate::{
	configs::governance::PayoutAdmin,
	economy,
	staking::{
		params::{HISTORY_DEPTH, PAYMENT_WINDOW, PAYOUT_EXPIRY_MARGIN, SESSION_PERIOD},
		payouts::StakingPayouts,
		pruning, HeavyBlocks, HEAVY_BLOCK_READS,
	},
	BlockNumber, Runtime, RuntimeCall,
};
use frame_support::{
	parameter_types,
	traits::{ConstU32, ConstU64},
};
use sp_runtime::Perbill;

// Automatic payouts

parameter_types! {
	pub const PaymentWindow: BlockNumber = PAYMENT_WINDOW;
	/// 8% fits four full pages (64 nominators, ~39 ms each at staking's reference
	/// weights): the worst era (100 000 voters backing 16 validators each) is paid in
	/// some 6 300 of the window's 7 200 blocks without `on_idle`. 10% pays two such eras
	/// within one era after a stall. Mandatory weight, taken from the 25% operational
	/// headroom; transactions keep their 75%.
	pub DefaultPayoutLimits: pallet_auto_payout::PayoutLimits = pallet_auto_payout::PayoutLimits {
		floor: Perbill::from_percent(8),
		catch_up: Perbill::from_percent(10),
		idle: Perbill::from_percent(10),
	};
}

impl pallet_auto_payout::Config for Runtime {
	type Payouts = StakingPayouts;
	type AdminOrigin = PayoutAdmin;
	type MaxValidators = MaxActiveValidators;
	type MaxQueuedEras = ConstU32<HISTORY_DEPTH>;
	type PaymentWindow = PaymentWindow;
	type ExpiryMargin = ConstU32<PAYOUT_EXPIRY_MARGIN>;
	type DefaultLimits = DefaultPayoutLimits;
	type WeightInfo = pallet_auto_payout::weights::SubstrateWeight<Runtime>;
}

// Era pruning

parameter_types! {
	/// 20 ms of a block: some 30 steps at staking's reference weights (under a
	/// millisecond each), several thousand items.
	pub const EraPruningBlockShare: Perbill = Perbill::from_percent(1);
}

impl pruning::Config for Runtime {
	type RuntimeCall = RuntimeCall;
	type HeavyBlocks = HeavyBlocks;
	type HeavyBlockReads = ConstU64<HEAVY_BLOCK_READS>;
	type Signer = economy::EraPruningAccount;
	type MaxBlockShare = EraPruningBlockShare;
	/// A failed era is tried again once a session.
	type RetryAfter = ConstU32<SESSION_PERIOD>;
}
