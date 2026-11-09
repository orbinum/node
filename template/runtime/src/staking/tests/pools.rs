//! Nomination pools as the runtime wires them: a pool nominates like any
//! nominator, the election counts it once, automatic payouts pay it, members
//! claim their share, leave after the bonding duration, take their share of a
//! slash, and the pool can be destroyed.
//!
//! Three validators (Alice, Bob, Charlie) from `test_utils::network::with_validators`.

use crate::test_utils::{
	blocks::{active_era, run_block, run_to_era, settle},
	network::{charlie, report_charlie, with_validators},
};
use crate::{
	economy::GovernanceAccount,
	staking::{
		candidacy::check_candidacy,
		params::{BONDING_DURATION, POOL_MIN_JOIN_BOND, TEST_POOL_MIN_CREATE_BOND},
	},
	test_utils::{account, ORB},
	AccountId, AutoPayout, Balance, Balances, NominationPools, Runtime, RuntimeEvent,
	RuntimeOrigin, Staking, System,
};
use frame_support::{
	assert_noop, assert_ok,
	traits::fungible::{Inspect, InspectHold, Mutate},
};
use pallet_nomination_pools::{
	BondExtra, BondedPools, ClaimPermission, PoolId, PoolMembers, PoolState,
};
use sp_keyring::Sr25519Keyring;
use sp_staking::StakingInterface;

const POOL: PoolId = 1;

fn alice() -> AccountId {
	account(Sr25519Keyring::Alice)
}

fn depositor() -> AccountId {
	AccountId::from([0x51; 32])
}

fn member(n: u8) -> AccountId {
	AccountId::from([0x60 + n; 32])
}

/// Anyone else: neither a member nor a pool role.
fn stranger() -> AccountId {
	AccountId::from([0x5f; 32])
}

fn signed(who: &AccountId) -> RuntimeOrigin {
	RuntimeOrigin::signed(who.clone())
}

fn bonded() -> AccountId {
	NominationPools::api_pool_accounts(POOL).0
}

fn reward_account() -> AccountId {
	NominationPools::api_pool_accounts(POOL).1
}

/// Pool 1, created by the depositor with the minimum bond, its roles all the
/// depositor's, joined by `members` and nominating `targets`.
fn create_pool(members: &[(AccountId, Balance)], targets: Vec<AccountId>) {
	Balances::set_balance(&depositor(), 1_000 * ORB);
	assert_ok!(NominationPools::create(
		signed(&depositor()),
		TEST_POOL_MIN_CREATE_BOND,
		depositor(),
		depositor(),
		depositor()
	));
	for (who, bond) in members {
		Balances::set_balance(who, 1_000 * ORB);
		assert_ok!(NominationPools::join(signed(who), *bond, POOL));
	}
	assert_ok!(NominationPools::nominate(
		signed(&depositor()),
		POOL,
		targets
	));
}

fn run_blocks(count: u32) {
	let start = System::block_number() + 1;
	for n in start..start + count {
		run_block(n);
	}
}

fn pending(who: &AccountId) -> Balance {
	NominationPools::api_pending_rewards(who.clone()).unwrap_or_default()
}

fn points(who: &AccountId) -> Balance {
	PoolMembers::<Runtime>::get(who).map_or(0, |m| m.points)
}

/// What `who` holds for its pool.
fn held(who: &AccountId) -> Balance {
	Balances::total_balance_on_hold(who)
}

/// Whether `a` is `b` up to `tolerance` parts in a million.
fn close(a: Balance, b: Balance, tolerance: Balance) -> bool {
	a.abs_diff(b) <= b / 1_000_000 * tolerance + 1
}

// Limits

#[test]
fn genesis_sets_the_pool_bonds_and_no_caps() {
	with_validators(|| {
		use pallet_nomination_pools as pools;
		assert_eq!(pools::MinJoinBond::<Runtime>::get(), POOL_MIN_JOIN_BOND);
		assert_eq!(
			pools::MinCreateBond::<Runtime>::get(),
			TEST_POOL_MIN_CREATE_BOND
		);
		assert_eq!(pools::MaxPools::<Runtime>::get(), None);
		assert_eq!(pools::MaxPoolMembers::<Runtime>::get(), None);
		assert_eq!(pools::MaxPoolMembersPerPool::<Runtime>::get(), None);
		assert_eq!(pools::GlobalMaxCommission::<Runtime>::get(), None);
		// The depositor's bond is the larger of the create bond and a nominator's.
		assert_eq!(
			NominationPools::depositor_min_bond(),
			TEST_POOL_MIN_CREATE_BOND
		);
		assert_eq!(
			pallet_staking_async::MaxNominatorsCount::<Runtime>::get(),
			None
		);
	});
}

#[test]
fn joining_below_the_minimum_fails() {
	with_validators(|| {
		create_pool(&[], vec![alice()]);
		Balances::set_balance(&member(1), 10 * ORB);
		assert_noop!(
			NominationPools::join(signed(&member(1)), POOL_MIN_JOIN_BOND - 1, POOL),
			pallet_nomination_pools::Error::<Runtime>::MinimumBondNotMet
		);
	});
}

/// One way of staking per account: a direct staker cannot join or create a pool,
/// and a pool member cannot bond directly.
#[test]
fn an_account_stakes_directly_or_through_a_pool_not_both() {
	with_validators(|| {
		create_pool(&[(member(1), 10 * ORB)], vec![alice()]);
		assert_noop!(
			Staking::bond(
				signed(&member(1)),
				10 * ORB,
				pallet_staking_async::RewardDestination::Staked
			),
			pallet_staking_async::Error::<Runtime>::Restricted
		);

		let staker = member(2);
		Balances::set_balance(&staker, 1_000 * ORB);
		assert_ok!(Staking::bond(
			signed(&staker),
			10 * ORB,
			pallet_staking_async::RewardDestination::Staked
		));
		assert_noop!(
			NominationPools::join(signed(&staker), 10 * ORB, POOL),
			pallet_nomination_pools::Error::<Runtime>::Restricted
		);
		assert_noop!(
			NominationPools::create(
				signed(&staker),
				TEST_POOL_MIN_CREATE_BOND,
				staker.clone(),
				staker.clone(),
				staker.clone()
			),
			pallet_nomination_pools::Error::<Runtime>::Restricted
		);
	});
}

/// A staker whose whole bond is unbonding still has a ledger, so it still
/// stakes directly: no pool.
#[test]
fn a_staker_with_only_unlocking_funds_cannot_join_or_create_a_pool() {
	with_validators(|| {
		create_pool(&[], vec![alice()]);
		let staker = member(3);
		Balances::set_balance(&staker, 1_000 * ORB);
		assert_ok!(Staking::bond(
			signed(&staker),
			10 * ORB,
			pallet_staking_async::RewardDestination::Staked
		));
		assert_ok!(Staking::unbond(signed(&staker), 10 * ORB));
		let ledger = pallet_staking_async::Ledger::<Runtime>::get(&staker).unwrap();
		assert_eq!(ledger.active, 0);
		assert!(!ledger.unlocking.is_empty());
		assert_noop!(
			NominationPools::join(signed(&staker), 10 * ORB, POOL),
			pallet_nomination_pools::Error::<Runtime>::Restricted
		);
		assert_noop!(
			NominationPools::create(
				signed(&staker),
				TEST_POOL_MIN_CREATE_BOND,
				staker.clone(),
				staker.clone(),
				staker.clone()
			),
			pallet_nomination_pools::Error::<Runtime>::Restricted
		);
	});
}

/// A pool member has no direct stake to add to or rebond; staking's filter
/// refuses it even with a ledger under its name.
#[test]
fn a_pool_member_cannot_bond_extra_or_rebond_directly() {
	use pallet_staking_async::{Bonded, Error, Ledger, StakingLedger, UnlockChunk};
	with_validators(|| {
		let who = member(1);
		create_pool(&[(who.clone(), 10 * ORB)], vec![alice()]);
		assert_noop!(
			Staking::bond_extra(signed(&who), ORB),
			Error::<Runtime>::Restricted
		);
		assert_noop!(
			Staking::rebond(signed(&who), ORB),
			Error::<Runtime>::NotController
		);

		let mut ledger = StakingLedger::<Runtime>::new(who.clone(), ORB);
		ledger.active = 0;
		ledger
			.unlocking
			.try_push(UnlockChunk {
				value: ORB,
				era: active_era() + 1,
			})
			.unwrap();
		Bonded::<Runtime>::insert(&who, &who);
		Ledger::<Runtime>::insert(&who, ledger);
		assert_noop!(
			Staking::rebond(signed(&who), ORB),
			Error::<Runtime>::Restricted
		);
		assert_noop!(
			Staking::bond_extra(signed(&who), ORB),
			Error::<Runtime>::Restricted
		);
	});
}

/// Governance caps pools and members on-chain and lifts the caps again; only
/// root may.
#[test]
fn governance_caps_pools_and_members_on_chain() {
	use pallet_nomination_pools::{ConfigOp::*, Error};
	let set_caps = |origin: RuntimeOrigin, pools, members, per_pool| {
		NominationPools::set_configs(origin, Noop, Noop, pools, members, per_pool, Noop)
	};
	let create = |who: &AccountId| {
		NominationPools::create(
			signed(who),
			TEST_POOL_MIN_CREATE_BOND,
			who.clone(),
			who.clone(),
			who.clone(),
		)
	};
	let join = |who: &AccountId| NominationPools::join(signed(who), 10 * ORB, POOL);
	with_validators(|| {
		for who in [depositor(), member(1), member(2), member(3), member(9)] {
			Balances::set_balance(&who, 1_000 * ORB);
		}
		assert!(set_caps(signed(&stranger()), Set(1), Noop, Noop).is_err());

		// One pool, two members in it (the depositor counts), three in all.
		assert_ok!(set_caps(RuntimeOrigin::root(), Set(1), Set(3), Set(2)));
		assert_ok!(create(&depositor()));
		assert_noop!(create(&member(9)), Error::<Runtime>::MaxPools);
		assert_ok!(join(&member(1)));
		assert_noop!(join(&member(2)), Error::<Runtime>::MaxPoolMembers);

		assert_ok!(set_caps(RuntimeOrigin::root(), Remove, Noop, Remove));
		assert_ok!(join(&member(2)));
		// Three members in all: a new pool's depositor would be a fourth.
		assert_noop!(create(&member(9)), Error::<Runtime>::MaxPoolMembers);

		assert_ok!(set_caps(RuntimeOrigin::root(), Noop, Remove, Noop));
		assert_ok!(create(&member(9)));
		assert_ok!(join(&member(3)));
		assert_eq!(pallet_nomination_pools::MaxPools::<Runtime>::get(), None);
		assert_eq!(
			pallet_nomination_pools::MaxPoolMembers::<Runtime>::get(),
			None
		);
		assert_eq!(
			pallet_nomination_pools::MaxPoolMembersPerPool::<Runtime>::get(),
			None
		);
	});
}

/// Pool commission has no ceiling until governance sets `GlobalMaxCommission`;
/// lowering it caps what a pool above it takes from the next payout on.
#[test]
fn a_lowered_global_ceiling_caps_pool_commission_at_once() {
	use pallet_nomination_pools::{ConfigOp::*, Error};
	with_validators(|| {
		create_pool(
			&[(member(1), 100 * ORB), (member(2), 300 * ORB)],
			vec![alice()],
		);
		assert_ok!(NominationPools::set_commission(
			signed(&depositor()),
			POOL,
			Some((sp_runtime::Perbill::from_percent(50), stranger()))
		));
		let ceiling = sp_runtime::Perbill::from_percent(10);
		assert!(NominationPools::set_configs(
			signed(&stranger()),
			Noop,
			Noop,
			Noop,
			Noop,
			Noop,
			Set(ceiling)
		)
		.is_err());
		assert_ok!(NominationPools::set_configs(
			RuntimeOrigin::root(),
			Noop,
			Noop,
			Noop,
			Noop,
			Noop,
			Set(ceiling)
		));
		assert_noop!(
			NominationPools::set_commission(
				signed(&depositor()),
				POOL,
				Some((sp_runtime::Perbill::from_percent(11), stranger()))
			),
			Error::<Runtime>::CommissionExceedsGlobalMaximum
		);

		let before = Balances::balance(&reward_account());
		run_to_era(3);
		run_blocks(50);
		let paid = Balances::balance(&reward_account()) - before;
		assert!(paid > 0, "the pool was paid");
		let members = pending(&member(1)) + pending(&member(2)) + pending(&depositor());
		assert!(
			close(members, paid - ceiling * paid, 1),
			"{members} of {paid}"
		);

		assert_ok!(NominationPools::claim_commission(
			signed(&depositor()),
			POOL
		));
		assert!(close(Balances::balance(&stranger()), ceiling * paid, 1));
	});
}

// A pool is one nominator

#[test]
fn members_funds_stay_in_their_accounts_and_the_pool_bonds_them() {
	with_validators(|| {
		create_pool(
			&[(member(1), 100 * ORB), (member(2), 300 * ORB)],
			vec![alice()],
		);
		assert_eq!(held(&member(1)), 100 * ORB);
		assert_eq!(Balances::total_balance(&member(1)), 1_000 * ORB);
		let total = TEST_POOL_MIN_CREATE_BOND + 400 * ORB;
		assert_eq!(
			<Staking as StakingInterface>::stake(&bonded())
				.unwrap()
				.active,
			total
		);
		assert!(pallet_staking_async::VirtualStakers::<Runtime>::contains_key(bonded()));
		// One nominator, whatever the members.
		assert_eq!(
			pallet_staking_async::Nominators::<Runtime>::get(bonded())
				.unwrap()
				.targets
				.into_inner(),
			vec![alice()]
		);
	});
}

#[test]
fn a_pool_cannot_become_a_validator_candidate() {
	with_validators(|| {
		create_pool(&[(member(1), 500 * ORB)], vec![alice()]);
		assert!(check_candidacy(&bonded(), &Default::default()).is_err());
	});
}

// Rewards

/// Pool 1 with members 1 (100 ORB) and 2 (300 ORB) besides the depositor
/// (100 ORB), backing Alice from era 2, and era 2 paid.
fn with_paid_pool<R>(run: impl FnOnce() -> R) -> R {
	with_validators(|| {
		create_pool(
			&[(member(1), 100 * ORB), (member(2), 300 * ORB)],
			vec![alice()],
		);
		run_to_era(3);
		let exposed =
			pallet_staking_async::ErasStakersPaged::<Runtime>::iter_prefix_values((2, alice()))
				.any(|page| page.others.iter().any(|e| e.who == bonded()));
		assert!(exposed, "the pool backs Alice in era 2");
		run_blocks(50);
		assert!(!Staking::api_pending_rewards(2, alice()));
		run()
	})
}

#[test]
fn automatic_payouts_pay_the_pool_and_members_claim_their_share() {
	with_paid_pool(|| {
		let paid = Balances::balance(&reward_account());
		assert!(paid > 0, "the pool was paid");
		let (one, two, dep) = (
			pending(&member(1)),
			pending(&member(2)),
			pending(&depositor()),
		);
		assert!(one > 0);
		// Shares follow points: 1 : 3 : 1.
		assert!(close(two, 3 * one, 1), "{two} vs 3 × {one}");
		assert!(close(dep, one, 1), "{dep} vs {one}");
		assert!(one + two + dep <= paid);

		let before = Balances::balance(&member(1));
		assert_ok!(NominationPools::claim_payout(signed(&member(1))));
		assert_eq!(Balances::balance(&member(1)), before + one);
		assert_eq!(pending(&member(1)), 0);
		// Points are untouched: claiming pays out, it does not restake.
		assert_eq!(points(&member(1)), 100 * ORB);
	});
}

#[test]
fn anyone_claims_for_a_member_unless_it_opts_out() {
	with_paid_pool(|| {
		// The default lets anyone pay a member its own rewards.
		assert_eq!(
			pallet_nomination_pools::ClaimPermissions::<Runtime>::get(member(2)),
			ClaimPermission::PermissionlessWithdraw
		);
		let (owed, before) = (pending(&member(2)), Balances::balance(&member(2)));
		assert_ok!(NominationPools::claim_payout_other(
			signed(&stranger()),
			member(2)
		));
		assert_eq!(Balances::balance(&member(2)), before + owed);
		assert_eq!(Balances::balance(&stranger()), 0);

		assert_ok!(NominationPools::set_claim_permission(
			signed(&member(1)),
			ClaimPermission::Permissioned
		));
		assert_noop!(
			NominationPools::claim_payout_other(signed(&stranger()), member(1)),
			pallet_nomination_pools::Error::<Runtime>::DoesNotHavePermission
		);
	});
}

#[test]
fn a_member_can_let_anyone_compound_its_rewards() {
	with_paid_pool(|| {
		let owed = pending(&member(1));
		assert_noop!(
			NominationPools::bond_extra_other(signed(&stranger()), member(1), BondExtra::Rewards),
			pallet_nomination_pools::Error::<Runtime>::DoesNotHavePermission
		);
		assert_ok!(NominationPools::set_claim_permission(
			signed(&member(1)),
			ClaimPermission::PermissionlessCompound
		));
		assert_ok!(NominationPools::bond_extra_other(
			signed(&stranger()),
			member(1),
			BondExtra::Rewards
		));
		// Restaked at par: the pool is unslashed.
		assert_eq!(points(&member(1)), 100 * ORB + owed);
		assert_eq!(held(&member(1)), 100 * ORB + owed);
		assert_eq!(pending(&member(1)), 0);
		// Compound only: claiming to the member's balance stays its own call.
		assert_noop!(
			NominationPools::claim_payout_other(signed(&stranger()), member(1)),
			pallet_nomination_pools::Error::<Runtime>::DoesNotHavePermission
		);
	});
}

// Leaving

/// A member unbonds and withdraws after the bonding duration; then the pool is
/// destroyed: the depositor leaves last and the pool's accounts are freed.
#[test]
fn members_leave_after_the_bonding_duration_and_the_pool_is_destroyed() {
	with_validators(|| {
		assert_ok!(AutoPayout::pause(RuntimeOrigin::root()));
		create_pool(&[(member(1), 100 * ORB)], vec![alice()]);
		run_to_era(2);

		assert_ok!(NominationPools::unbond(
			signed(&member(1)),
			member(1),
			100 * ORB
		));
		let unbonded_at = active_era();
		// Still held, and slashable, until the bonding duration has passed.
		assert_eq!(held(&member(1)), 100 * ORB);
		assert!(NominationPools::withdraw_unbonded(signed(&member(1)), member(1), 0).is_err());

		run_to_era(unbonded_at + BONDING_DURATION);
		assert_ok!(NominationPools::withdraw_unbonded(
			signed(&member(1)),
			member(1),
			0
		));
		assert!(PoolMembers::<Runtime>::get(member(1)).is_none());
		assert_eq!(held(&member(1)), 0);
		assert_eq!(Balances::balance(&member(1)), 1_000 * ORB);

		// The bouncer destroys the pool; the depositor, now alone, leaves.
		assert_ok!(NominationPools::set_state(
			signed(&depositor()),
			POOL,
			PoolState::Destroying
		));
		assert_ok!(NominationPools::unbond(
			signed(&depositor()),
			depositor(),
			TEST_POOL_MIN_CREATE_BOND
		));
		let unbonded_at = active_era();
		run_to_era(unbonded_at + BONDING_DURATION);
		assert_ok!(NominationPools::withdraw_unbonded(
			signed(&depositor()),
			depositor(),
			0
		));
		assert!(BondedPools::<Runtime>::get(POOL).is_none());
		assert!(<Staking as StakingInterface>::stake(&bonded()).is_err());
		assert_eq!(held(&depositor()), 0);
		assert_eq!(Balances::balance(&depositor()), 1_000 * ORB);
		assert!(System::events().iter().any(|r| matches!(
			r.event,
			RuntimeEvent::NominationPools(pallet_nomination_pools::Event::Destroyed {
				pool_id: POOL
			})
		)));
	});
}

#[test]
fn a_destroying_pool_lets_anyone_remove_its_members() {
	with_validators(|| {
		create_pool(&[(member(1), 100 * ORB)], vec![alice()]);
		assert_noop!(
			NominationPools::unbond(signed(&stranger()), member(1), 100 * ORB),
			pallet_nomination_pools::Error::<Runtime>::NotKickerOrDestroying
		);
		assert_ok!(NominationPools::set_state(
			signed(&depositor()),
			POOL,
			PoolState::Destroying
		));
		assert_ok!(NominationPools::unbond(
			signed(&stranger()),
			member(1),
			100 * ORB
		));
		assert_eq!(points(&member(1)), 0);
	});
}

// Slashes

/// The pool backs Alice and Charlie; Charlie equivocates in era 2. The slash
/// takes the pool's exposure behind Charlie, and each member loses its share of
/// it, by points.
#[test]
fn a_slash_on_a_backed_validator_reduces_every_member_in_proportion() {
	with_validators(|| {
		// Rewards would change the balances checked below.
		assert_ok!(AutoPayout::pause(RuntimeOrigin::root()));
		create_pool(
			&[(member(1), 100 * ORB), (member(2), 300 * ORB)],
			vec![alice(), charlie()],
		);
		run_to_era(2);
		let total = TEST_POOL_MIN_CREATE_BOND + 400 * ORB;
		let exposed: Balance =
			pallet_staking_async::ErasStakersPaged::<Runtime>::iter_prefix_values((2, charlie()))
				.flat_map(|page| page.0.others)
				.filter(|e| e.who == bonded())
				.map(|e| e.value)
				.sum();
		assert!(
			exposed > 0 && exposed < total,
			"pool exposure behind Charlie {exposed}"
		);

		assert_ok!(report_charlie());
		settle();
		let apply_at = pallet_staking_async::UnappliedSlashes::<Runtime>::iter_keys()
			.map(|(era, _)| era)
			.next()
			.expect("a deferred slash");
		run_to_era(apply_at);
		settle();

		// One offender of three: its whole exposure, capped at `MAX_SLASH_FRACTION`.
		let left = <Staking as StakingInterface>::total_stake(&bonded()).unwrap();
		let capped = crate::staking::params::MAX_SLASH_FRACTION * exposed;
		assert!(close(total - left, capped, 1), "slashed {}", total - left);
		let slashed = total - left;
		let (one, two) = (
			NominationPools::api_member_pending_slash(member(1)),
			NominationPools::api_member_pending_slash(member(2)),
		);
		assert!(close(one, slashed / 5, 1), "member 1 owes {one}");
		assert!(close(two, 3 * slashed / 5, 1), "member 2 owes {two}");

		// A member applying its own slash earns nothing from it: the whole slash
		// goes where every slash goes.
		let governance = Balances::balance(&GovernanceAccount::get());
		let free = Balances::balance(&member(1));
		assert_ok!(NominationPools::apply_slash(signed(&member(1)), member(1)));
		assert_eq!(Balances::balance(&member(1)), free);
		assert_eq!(held(&member(1)), 100 * ORB - one);
		assert_eq!(
			Balances::balance(&GovernanceAccount::get()) - governance,
			one
		);
		assert_eq!(NominationPools::api_member_pending_slash(member(1)), 0);

		// Member 2's share stays owed until it withdraws; what it unbonds is
		// already net of the slash.
		assert_ok!(NominationPools::unbond(
			signed(&member(2)),
			member(2),
			points(&member(2))
		));
		assert_eq!(NominationPools::api_member_pending_slash(member(2)), two);
		assert!(close(
			NominationPools::api_member_total_balance(member(2)),
			300 * ORB - two,
			1
		));
	});
}

/// Applying a member's slash when it owes none fails and pays its fee, so it
/// cannot be spammed.
#[test]
fn apply_slash_with_nothing_owed_is_refused() {
	use frame_support::dispatch::Pays;
	with_validators(|| {
		create_pool(&[(member(1), 100 * ORB)], vec![alice(), charlie()]);
		let refused = NominationPools::apply_slash(signed(&stranger()), member(1))
			.expect_err("nothing to slash");
		assert_eq!(
			refused.error,
			pallet_nomination_pools::Error::<Runtime>::NothingToSlash.into()
		);
		assert_eq!(refused.post_info.pays_fee, Pays::Yes);
	});
}

/// A validator reported for several eras slashes a pool behind it at most 99 %
/// in all: the pool keeps a sliver, so it can still wind up.
#[test]
fn a_pool_behind_an_offender_reported_in_two_eras_keeps_a_sliver() {
	use crate::test_utils::network::equivocation_now;
	use sp_keyring::Ed25519Keyring;
	with_validators(|| {
		assert_ok!(AutoPayout::pause(RuntimeOrigin::root()));
		create_pool(&[(member(1), 100 * ORB)], vec![charlie()]);
		run_to_era(2);
		let era_2 = equivocation_now(Ed25519Keyring::Charlie, 1);
		run_to_era(3);
		let era_3 = equivocation_now(Ed25519Keyring::Charlie, 2);
		for (proof, key_owner) in [era_2, era_3] {
			assert_ok!(crate::Grandpa::report_equivocation_unsigned(
				RuntimeOrigin::none(),
				Box::new(proof),
				key_owner
			));
		}
		settle();
		run_to_era(3 + crate::staking::params::SLASH_DEFER_DURATION);
		settle();
		assert!(pallet_staking_async::UnappliedSlashes::<Runtime>::iter()
			.next()
			.is_none());
		let total = TEST_POOL_MIN_CREATE_BOND + 100 * ORB;
		let left = <Staking as StakingInterface>::total_stake(&bonded()).unwrap_or_default();
		assert!(
			left > 0 && left <= total / 50,
			"pool left with {left} of {total}"
		);
	});
}

/// A pool slashed to nothing still winds up: its members can leave, and once
/// out they may stake again.
#[test]
fn a_pool_slashed_to_nothing_lets_its_members_leave() {
	with_validators(|| {
		assert_ok!(AutoPayout::pause(RuntimeOrigin::root()));
		create_pool(&[(member(1), 100 * ORB)], vec![charlie()]);
		run_to_era(2);
		assert_ok!(report_charlie());
		settle();
		let apply_at = pallet_staking_async::UnappliedSlashes::<Runtime>::iter_keys()
			.map(|(era, _)| era)
			.next()
			.expect("a deferred slash");
		run_to_era(apply_at);
		settle();
		let total = TEST_POOL_MIN_CREATE_BOND + 100 * ORB;
		let left = <Staking as StakingInterface>::total_stake(&bonded()).unwrap_or_default();
		assert!(
			left > 0 && left <= total / 50,
			"pool left with {left} of {total}"
		);

		// What is left is below the nominator minimum: anyone chills the pool and
		// sets it destroying.
		assert_ok!(NominationPools::chill(signed(&stranger()), POOL));
		assert_ok!(NominationPools::set_state(
			signed(&stranger()),
			POOL,
			PoolState::Destroying
		));
		let all = |who: &AccountId| PoolMembers::<Runtime>::get(who).map_or(0, |m| m.points);
		assert_ok!(NominationPools::unbond(
			signed(&stranger()),
			member(1),
			all(&member(1))
		));
		run_to_era(active_era() + BONDING_DURATION + 1);
		settle();
		assert_ok!(NominationPools::withdraw_unbonded(
			signed(&member(1)),
			member(1),
			0
		));
		assert!(
			!PoolMembers::<Runtime>::contains_key(member(1)),
			"member 1 left"
		);
		Balances::set_balance(&member(1), 1_000 * ORB);
		assert_ok!(<Staking as StakingInterface>::bond(
			&member(1),
			100 * ORB,
			&member(1)
		));
	});
}

/// Funds sent to a pool's accounts mint no points and move no member's stake:
/// to the bonded account they stay idle (delegations, not its balance, back
/// the pool), to the reward account they become rewards.
#[test]
fn donations_do_not_move_the_points_price() {
	with_validators(|| {
		create_pool(&[(member(1), 100 * ORB)], vec![alice()]);
		let price = NominationPools::api_points_to_balance(POOL, ORB);
		let stake = <Staking as StakingInterface>::total_stake(&bonded()).unwrap();
		Balances::set_balance(&stranger(), 1_000 * ORB);
		for to in [bonded(), reward_account()] {
			assert_ok!(Balances::transfer_keep_alive(
				signed(&stranger()),
				to,
				50 * ORB
			));
		}
		assert_eq!(NominationPools::api_points_to_balance(POOL, ORB), price);
		assert_eq!(
			<Staking as StakingInterface>::total_stake(&bonded()).unwrap(),
			stake
		);
		assert_eq!(
			PoolMembers::<Runtime>::get(member(1)).unwrap().points,
			100 * ORB,
			"no points minted"
		);
	});
}
