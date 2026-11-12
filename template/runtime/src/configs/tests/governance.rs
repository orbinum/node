// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

//! Each privileged role's origin: every pallet's admin origin is its role's alias in
//! `configs::governance`, and only root passes it.

use crate::{
	configs::governance::{
		AdmissionAdmin, CircuitAdmin, CrossChainAdmin, PayoutAdmin, ShieldedAssetAdmin,
		StakingAdmin,
	},
	AccountId, Runtime, RuntimeOrigin,
};
use core::any::TypeId;
use frame_support::traits::EnsureOrigin;

/// `Origin` is the `Role` alias, refuses accounts and unsigned origins, and admits root.
fn assert_role<Origin, Role>(wiring: &str)
where
	Origin: EnsureOrigin<RuntimeOrigin> + 'static,
	Role: 'static,
{
	assert_eq!(TypeId::of::<Origin>(), TypeId::of::<Role>(), "{wiring}");
	let account = RuntimeOrigin::signed(AccountId::from([0x01; 32]));
	assert!(Origin::try_origin(account).is_err(), "{wiring}: an account");
	assert!(
		Origin::try_origin(RuntimeOrigin::none()).is_err(),
		"{wiring}: none"
	);
	assert!(
		Origin::try_origin(RuntimeOrigin::root()).is_ok(),
		"{wiring}: root"
	);
}

#[test]
fn staking_parameters_need_the_staking_admin() {
	assert_role::<<Runtime as pallet_staking_async::Config>::AdminOrigin, StakingAdmin>("staking");
	assert_role::<<Runtime as pallet_nomination_pools::Config>::AdminOrigin, StakingAdmin>(
		"nomination pools",
	);
	assert_role::<<Runtime as pallet_paged_election::Config>::AdminOrigin, StakingAdmin>(
		"paged election",
	);
	assert_role::<<Runtime as pallet_staking_async_ah_client::Config>::AdminOrigin, StakingAdmin>(
		"ah-client",
	);
}

#[test]
fn admission_needs_the_admission_admin() {
	assert_role::<<Runtime as pallet_validator_set::Config>::AddRemoveOrigin, AdmissionAdmin>(
		"validator set",
	);
}

#[test]
fn payouts_need_the_payout_admin() {
	assert_role::<<Runtime as pallet_auto_payout::Config>::AdminOrigin, PayoutAdmin>("auto-payout");
}

#[test]
fn cross_chain_trust_needs_the_cross_chain_admin() {
	assert_role::<<Runtime as pallet_ismp::Config>::AdminOrigin, CrossChainAdmin>("ismp");
	assert_role::<<Runtime as ismp_grandpa::Config>::RootOrigin, CrossChainAdmin>("ismp-grandpa");
	assert_role::<<Runtime as pallet_ismp_messaging::Config>::AdminOrigin, CrossChainAdmin>(
		"ismp-messaging",
	);
}

#[test]
fn privacy_admins_need_their_roles() {
	assert_role::<<Runtime as pallet_zk_verifier::Config>::AdminOrigin, CircuitAdmin>(
		"zk-verifier",
	);
	assert_role::<<Runtime as pallet_shielded_pool::Config>::AdminOrigin, ShieldedAssetAdmin>(
		"shielded pool",
	);
}

/// Staking calls upstream checks with `ensure_root` instead of its admin origin:
/// moving `StakingAdmin` off root leaves them with root. A signed origin stands for
/// whatever `StakingAdmin` may admit besides root.
#[test]
fn root_only_staking_calls() {
	use frame_support::{assert_noop, traits::UnfilteredDispatchable};
	use pallet_staking_async::{Call, ConfigOp};
	use sp_runtime::{DispatchError, Percent};

	let calls: Vec<Call<Runtime>> = vec![
		Call::set_validator_count { new: 1 },
		Call::increase_validator_count { additional: 1 },
		Call::scale_validator_count {
			factor: Percent::from_percent(10),
		},
		Call::force_no_eras {},
		Call::force_new_era {},
		Call::force_new_era_always {},
		Call::force_unstake {
			stash: AccountId::from([0x02; 32]),
			num_slashing_spans: 0,
		},
		Call::set_staking_configs {
			min_nominator_bond: ConfigOp::Noop,
			min_validator_bond: ConfigOp::Noop,
			max_nominator_count: ConfigOp::Noop,
			max_validator_count: ConfigOp::Noop,
			chill_threshold: ConfigOp::Noop,
			min_commission: ConfigOp::Noop,
			max_staked_rewards: ConfigOp::Noop,
			are_nominators_slashable: ConfigOp::Noop,
		},
	];
	crate::test_utils::with_ext(|| {
		for call in calls {
			let name = format!("{call:?}");
			assert_noop!(
				call.clone()
					.dispatch_bypass_filter(RuntimeOrigin::signed(AccountId::from([0x01; 32]))),
				DispatchError::BadOrigin
			);
			if !matches!(call, Call::force_unstake { .. }) {
				assert!(
					call.dispatch_bypass_filter(RuntimeOrigin::root()).is_ok(),
					"{name}"
				);
			}
		}
	});
}
