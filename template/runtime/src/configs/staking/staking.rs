//! `pallet-staking-async`: bonds, nominations, eras, rewards and slashes.

use crate::{
	configs::{consensus::Period, governance::StakingAdmin},
	economy,
	staking::params::*,
	Balance, Balances, DelegatedStaking, NominationPools, PagedElection, RcClient, Runtime,
	RuntimeHoldReason, VoterList,
};
use frame_support::{
	parameter_types,
	traits::{ConstBool, ConstU32, Get},
	PalletId,
};
use sp_staking::{EraIndex, SessionIndex};

parameter_types! {
	pub const SessionsPerEra: SessionIndex = SESSIONS_PER_ERA;
	pub const BondingDuration: EraIndex = BONDING_DURATION;
	pub const NominatorUnbondDuration: EraIndex = NOMINATOR_UNBOND_DURATION;
	pub const SlashDeferDuration: EraIndex = SLASH_DEFER_DURATION;
	pub const MaxActiveValidators: u32 = MAX_ACTIVE_VALIDATORS;
	pub const MaxElectingVoters: u32 = MAX_ELECTING_VOTERS;
	/// Seed of staking's reward pot accounts, used only if minting is disabled.
	pub const StakingPotId: PalletId = PalletId(*b"orb/stpt");
	/// Storage items `prune_era_step` removes per call.
	pub const MaxPruningItems: u32 = 100;
}

/// Sessions into an era at which staking plans the next one: as late as the
/// election, the hand-over and the session that applies the set allow.
pub struct PlanningEraOffset;
impl Get<SessionIndex> for PlanningEraOffset {
	fn get() -> SessionIndex {
		pallet_staking_async::PlanningEraOffsetOf::<Runtime, Period, ConstU32<0>>::get()
	}
}

impl pallet_staking_async::Config for Runtime {
	type OldCurrency = Balances;
	/// Bonds are holds on the stash's balance.
	type Currency = Balances;
	type RuntimeHoldReason = RuntimeHoldReason;
	type CurrencyBalance = Balance;
	/// Vote weight is stake divided by a constant 10^9.
	type CurrencyToVote = crate::staking::vote::DecimalCurrencyToVote;
	type ElectionProvider = PagedElection;
	type NominationsQuota = pallet_staking_async::FixedNominationsQuota<MAX_NOMINATIONS>;
	type HistoryDepth = ConstU32<HISTORY_DEPTH>;
	/// The era payout keeps nothing back (`economy::EraPayout` returns no
	/// remainder); if it ever did, it would go to governance.
	type RewardRemainder = economy::ToGovernance;
	type Slash = economy::SlashDestination;
	/// Rewards are minted; nothing else to do with them.
	type Reward = ();
	type SessionsPerEra = SessionsPerEra;
	type PlanningEraOffset = PlanningEraOffset;
	type BondingDuration = BondingDuration;
	/// Nominators and pool members are not slashed (`staking::eras::pruning`): they leave sooner.
	type NominatorFastUnbondDuration = NominatorUnbondDuration;
	type SlashDeferDuration = SlashDeferDuration;
	type AdminOrigin = StakingAdmin;
	/// Each era's reward is minted on claim, as `EraPayout` prices it.
	type EraPayout = economy::EraPayout;
	type DisableMinting = ConstBool<false>;
	type UnclaimedRewardHandler = ();
	type RewardPots = pallet_staking_async::Seed<StakingPotId>;
	type StakerRewardCalculator = pallet_staking_async::reward::DefaultStakerRewardCalculator<Self>;
	type MaxExposurePageSize = ConstU32<MAX_EXPOSURE_PAGE_SIZE>;
	type MaxValidatorSet = MaxActiveValidators;
	/// The bags list, with accounts that no longer vote hidden from the snapshot's
	/// walk (`staking::live`).
	type VoterList = crate::staking::live::LiveVoters<VoterList>;
	/// Every candidate that called `validate`, filtered by admission at each
	/// snapshot.
	#[cfg(not(feature = "runtime-benchmarks"))]
	type TargetList = crate::staking::admission::AdmissionFilteredTargets<
		pallet_staking_async::UseValidatorsMap<Self>,
	>;
	/// Unfiltered: upstream's benchmark validators have no keys and no approval.
	/// The filter's cost is counted by hand (`staking::admission`).
	#[cfg(feature = "runtime-benchmarks")]
	type TargetList = pallet_staking_async::UseValidatorsMap<Self>;
	type MaxUnlockingChunks = ConstU32<32>;
	/// Controllers are deprecated; stash and controller are the same account.
	type MaxControllersInDeprecationBatch = ConstU32<100>;
	/// Pools and their delegations follow the pool's bond: unbonding and slashes.
	type EventListeners = (NominationPools, DelegatedStaking);
	/// `economy::EraPayout` caps the duration it pays for itself.
	type MaxEraDuration = ();
	type MaxPruningItems = MaxPruningItems;
	type RcClientInterface = RcClient;
	/// A pool member cannot also bond directly: one way of staking per account.
	/// Validating is gated by admission.
	type Filter = pallet_nomination_pools::AllPoolMembers<Runtime>;
	type WeightInfo = crate::weights::pallet_staking_async::SubstrateWeight<Runtime>;
}
