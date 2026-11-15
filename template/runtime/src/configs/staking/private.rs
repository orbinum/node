// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

//! Private staking: nomination pools joined with shielded notes (`staking::private`).

use crate::RuntimeCall;
use crate::{
	configs::{governance::StakingAdmin, system::BlockWeights},
	primitives::constants::ORB,
	staking::private,
	Runtime,
};
use frame_support::{
	parameter_types,
	traits::{ConstU32, Contains},
	weights::Weight,
	PalletId,
};
use sp_runtime::Perbill;

parameter_types! {
	/// Derives each pool's private member and tags the share assets.
	pub const PrivateStakingId: PalletId = PalletId(*b"orb/pstk");
	/// 1 ORB of virtual value and shares: inflating the first shares costs more
	/// than it could take.
	pub const PrivateStakingVirtualOffset: u128 = ORB;
	/// The smallest private entry: 10 ORB until governance sets another.
	pub const DefaultMinPrivateEntry: u128 = 10 * ORB;
	/// A tenth of a block for compounding, minting and paying in `on_idle`.
	pub PrivateStakingIdleWeight: Weight = Perbill::from_percent(10) * BlockWeights::get().max_block;
}

impl private::Config for Runtime {
	type PrivateStakingId = PrivateStakingId;
	/// Entries, or exits, per page of a pool's queue for one era.
	type MaxQueue = ConstU32<256>;
	/// Pages per pool and era: 8 192 entries or exits, each paying a spend fee.
	type MaxPages = ConstU32<32>;
	type VirtualOffset = PrivateStakingVirtualOffset;
	type DefaultMinEntry = DefaultMinPrivateEntry;
	type MinEntryOrigin = StakingAdmin;
	type MaxIdleWeight = PrivateStakingIdleWeight;
}

/// Nobody but the private staking pallet unbonds or withdraws a pool's private
/// member: its stake backs the shares, and only the pallet keeps their price.
/// (Pool roles may kick public members of a blocked pool, and anyone may unbond
/// members of a destroying pool; the pallet winds its member down itself.)
pub struct PrivateMembersStay;

impl Contains<RuntimeCall> for PrivateMembersStay {
	fn contains(call: &RuntimeCall) -> bool {
		use pallet_nomination_pools::Call;
		match call {
			RuntimeCall::NominationPools(
				Call::unbond { member_account, .. }
				| Call::withdraw_unbonded { member_account, .. },
			) => !private::Members::<Runtime>::contains_key(member_account),
			_ => true,
		}
	}
}
