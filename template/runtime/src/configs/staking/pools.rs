// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

//! Nomination pools and the delegations that hold their members' funds.

use crate::{
	configs::governance::StakingAdmin,
	economy,
	staking::{
		params::{BONDING_DURATION, POOL_SLASH_REWARD_FRACTION, POOL_UNBONDING_WINDOW},
		pools::{BalanceToU256, U256ToBalance},
	},
	Balances, DelegatedStaking, Runtime, RuntimeEvent, RuntimeFreezeReason, RuntimeHoldReason,
	Staking,
};
use frame_support::{
	parameter_types,
	traits::{ConstU32, Get},
	PalletId,
};
use sp_runtime::{FixedU128, Perbill};
use sp_staking::StakingInterface;

// Nomination pools

parameter_types! {
	/// Seed of every pool's bonded and reward accounts.
	pub const PoolsPalletId: PalletId = PalletId(*b"orb/pool");
	pub const MaxPointsToBalance: u8 = 10;
	pub const DelegatedStakingPalletId: PalletId = PalletId(*b"orb/dlst");
	pub const PoolSlashRewardFraction: Perbill = POOL_SLASH_REWARD_FRACTION;
}

/// Eras a pool keeps each era's unbonding funds apart after they unlock: as many
/// as keep `bonding duration + window` fixed at `BONDING_DURATION +
/// POOL_UNBONDING_WINDOW`, whichever unbonding time nominators have. That sum
/// bounds every pool's stored unbonding records; were it to shrink when
/// governance turns nominator slashing off, records kept under the larger
/// bound would no longer decode.
pub struct UnbondingWindow;

impl Get<u32> for UnbondingWindow {
	fn get() -> u32 {
		(BONDING_DURATION + POOL_UNBONDING_WINDOW)
			.saturating_sub(<Staking as StakingInterface>::nominator_bonding_duration())
	}
}

impl pallet_nomination_pools::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type WeightInfo = crate::weights::pallet_nomination_pools::SubstrateWeight<Runtime>;
	type Currency = Balances;
	type RuntimeFreezeReason = RuntimeFreezeReason;
	type RewardCounter = FixedU128;
	type BalanceToU256 = BalanceToU256;
	type U256ToBalance = U256ToBalance;
	/// Members' funds stay in their accounts, held as delegations to the pool.
	type StakeAdapter =
		pallet_nomination_pools::adapter::DelegateStake<Self, Staking, DelegatedStaking>;
	type PostUnbondingPoolsWindow = UnbondingWindow;
	type MaxMetadataLen = ConstU32<256>;
	/// As many unbonding chunks as a staker has.
	type MaxUnbonding = <Self as pallet_staking_async::Config>::MaxUnlockingChunks;
	type PalletId = PoolsPalletId;
	/// A pool whose points exceed ten times its balance (slashed nearly to
	/// nothing) takes no new members.
	type MaxPointsToBalance = MaxPointsToBalance;
	/// Pool limits (`set_configs`), as staking's parameters.
	type AdminOrigin = StakingAdmin;
	#[cfg(not(feature = "runtime-benchmarks"))]
	type BlockNumberProvider = crate::System;
	/// Upstream's benchmarks expect commission changes stamped at block 0.
	#[cfg(feature = "runtime-benchmarks")]
	type BlockNumberProvider = BlockZero;
	/// A direct staker cannot join or create a pool: one way of staking per account.
	type Filter = pallet_staking_async::AllStakers<Runtime>;
}

/// Block 0, always: what upstream's pool benchmarks read as the current block.
#[cfg(feature = "runtime-benchmarks")]
pub struct BlockZero;

#[cfg(feature = "runtime-benchmarks")]
impl sp_runtime::traits::BlockNumberProvider for BlockZero {
	type BlockNumber = crate::BlockNumber;
	fn current_block_number() -> crate::BlockNumber {
		0
	}
}

impl pallet_delegated_staking::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type PalletId = DelegatedStakingPalletId;
	type Currency = Balances;
	/// Members' slashes go where every slash goes.
	type OnSlash = economy::SlashDestination;
	/// Paid to whoever applies a member's pending slash.
	type SlashRewardFraction = PoolSlashRewardFraction;
	type RuntimeHoldReason = RuntimeHoldReason;
	type CoreStaking = Staking;
}
