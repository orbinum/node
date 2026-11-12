// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

//! The two clients that join staking and sessions in one runtime: rc-client on the
//! staking side, ah-client on the session side (`staking::local_relay`).

use crate::{
	configs::governance::StakingAdmin,
	opaque,
	staking::{
		local_relay::{DirectToAssetHub, DirectToRelay, EnsureLocalRelay, NoFallback},
		params::{minimum_validator_count, MAX_VALIDATOR_CANDIDATES, SESSIONS_PER_ERA},
	},
	Balance, Balances, Runtime, Session, Staking, Timestamp,
};
use frame_support::{
	parameter_types,
	traits::{ConstU128, ConstU32, Get},
};
use sp_staking::SessionIndex;

// Staking side's client

parameter_types! {
	/// The elected set is handed over this many sessions into the era, so the
	/// rotation at the end of the next-to-last session applies it.
	pub const ValidatorSetExportSession: SessionIndex = SESSIONS_PER_ERA - 2;
}

impl pallet_staking_async_rc_client::Config for Runtime {
	/// The session side's messages arrive as direct calls from the adapters
	/// (`staking::local_relay`).
	type RelayChainOrigin = EnsureLocalRelay;
	type AHStakingInterface = Staking;
	type SendToRelayChain = DirectToRelay;
	type MaxValidatorSetRetries = ConstU32<5>;
	type ValidatorSetExportSession = ValidatorSetExportSession;
	type RelayChainSessionKeys = opaque::SessionKeys;
	type Currency = Balances;
	/// Unused: its key calls are filtered, keys go through `session.set_keys`.
	type KeyDeposit = ConstU128<0>;
	type WeightInfo = pallet_staking_async_rc_client::weights::SubstrateWeight<Runtime>;
}

// Session side's client

/// The fewest validators an elected set needs for the session side to apply
/// it: two thirds of staking's seats. A smaller set is dropped, the current one
/// stays, and the era plan is reset (`staking::recovery`).
pub struct MinimumValidatorSetSize;
impl Get<u32> for MinimumValidatorSetSize {
	fn get() -> u32 {
		minimum_validator_count(pallet_staking_async::ValidatorCount::<Runtime>::get()).max(1)
	}
}

impl pallet_staking_async_ah_client::Config for Runtime {
	type CurrencyBalance = Balance;
	/// The staking side's messages arrive as direct calls from the adapters
	/// (`staking::local_relay`).
	type AssetHubOrigin = EnsureLocalRelay;
	type AdminOrigin = StakingAdmin;
	type SendToAssetHub = DirectToAssetHub;
	type MinimumValidatorSetSize = MinimumValidatorSetSize;
	/// Every candidate may hold points within one session report.
	type MaximumValidatorsWithPoints = ConstU32<MAX_VALIDATOR_CANDIDATES>;
	type UnixTime = Timestamp;
	/// Era points per authored block.
	type PointsPerBlock = ConstU32<20>;
	type MaxOffenceBatchSize = ConstU32<50>;
	type SessionInterface = Session;
	/// Never used: ah-client starts `Active` and stays so.
	type Fallback = NoFallback;
	type MaxSessionReportRetries = ConstU32<5>;
}
