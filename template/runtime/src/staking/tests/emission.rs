//! Era rewards through the runtime: a year of eras run a day long, forced (still
//! a day) and stretched by missed slots and halts (two past the two-day cap), each
//! closed era's reward checked against the schedule, paid, and the supply grown by
//! what was paid; the second year's rate from era 366; and how one paid era
//! reaches each validator, nominator and pool member.

use super::auto_payout::pay_everything;
use crate::test_utils::{
	account,
	blocks::{active_era, run_to_era, stall},
	network::{genesis_of, with_validators},
	ORB,
};
use crate::{
	economy::schedule::{era_issuance, TokenomicsSchedule, ERAS_PER_YEAR, MAX_PAID_ERA_MS},
	primitives::constants::{DAY_MS, SLOT_DURATION},
	staking::params::TEST_POOL_MIN_CREATE_BOND,
	AccountId, AutoPayout, Balance, Balances, NominationPools, Runtime, RuntimeOrigin, Staking,
};
use alloc::collections::BTreeMap;
use frame_support::{
	assert_ok,
	traits::{fungible::Inspect, fungible::Mutate},
};
use pallet_staking_async::{
	ActiveEra, ErasRewardPoints, ErasStakersOverview, ErasStakersPaged, ErasValidatorPrefs,
	ErasValidatorReward, RewardDestination, ValidatorPrefs,
};
use sp_keyring::Sr25519Keyring;
use sp_runtime::Perbill;
use sp_staking::{EraIndex, StakingInterface};

const HOUR_MS: u64 = DAY_MS / 24;
const HOUR_SLOTS: u64 = HOUR_MS / SLOT_DURATION;
const YEAR_ONE_RATE: Balance = 45_000_000 * ORB;

/// When the era that is active now started, as staking recorded it.
fn era_start() -> u64 {
	ActiveEra::<Runtime>::get()
		.and_then(|era| era.start)
		.expect("the active era has started")
}

fn issuance() -> Balance {
	Balances::total_issuance()
}

/// How an era is run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Pace {
	/// 24 sessions of an hour.
	Day,
	/// `forceNewEra` as it starts: the next era is planned at once, but its set is
	/// still handed over at the same session, so the era still lasts a day.
	Forced,
	/// That many hours with no block inside it: a halt, or the slots of offline
	/// validators.
	Halt(u64),
}

/// The year's script: 20 forced eras; 30 eras of 32 hours, as with a third of the
/// slots missed; a 5-day halt (paid as two days); 5 forced eras; a 30-hour halt
/// (paid as two days) and a 24-hour one (exactly two days); the rest a day.
fn pace(era: EraIndex) -> Pace {
	match era {
		60..=79 | 250..=254 => Pace::Forced,
		100..=129 => Pace::Halt(8),
		200 => Pace::Halt(5 * 24),
		300 => Pace::Halt(30),
		301 => Pace::Halt(24),
		_ => Pace::Day,
	}
}

/// Each era's reward is the schedule's share for the time it lasted: a day (forced
/// or not), a stretched era's day and halt, at most two days. Era 0 pays nothing;
/// eras 1 to 365 are year 1 (45M ORB a year) and era 366 year 2 (40M). Each era
/// is paid before the next closes, and the supply grows by what was paid: the
/// reward, less at most the rounding of its shares.
///
/// Each era runs in its own `execute_with` and the changes are committed after
/// it: left in the overlay, every read walks a year of writes and each era runs
/// slower than the last. Prints its progress every 25 eras.
#[test]
#[ignore = "runs 366 eras (about 10 minutes): cargo test -p orbinum-runtime --lib a_year_of_eras -- --ignored --nocapture"]
fn a_year_of_eras_pays_the_schedule() {
	// The pace script needs day-long eras; `fast-runtime` eras last minutes.
	if cfg!(feature = "fast-runtime") {
		return;
	}
	let clock = std::time::Instant::now();
	let mut ext = genesis_of(3);
	let first_issuance = ext.execute_with(|| {
		run_to_era(1);
		assert_eq!(
			ErasValidatorReward::<Runtime>::get(0),
			Some(0),
			"era 0 pays nothing"
		);
		issuance()
	});
	let (mut rewarded, mut minted) = (0, 0);
	let (mut year_one, mut year_one_paid_ms) = (0, 0);
	let mut lasted_by_pace: BTreeMap<&str, (u32, u64)> = BTreeMap::new();

	for era in 1..=ERAS_PER_YEAR + 1 {
		ext.execute_with(|| {
			assert_eq!(active_era(), era);
			let start = era_start();
			match pace(era) {
				Pace::Day => {}
				Pace::Forced => {
					assert_ok!(Staking::force_new_era(RuntimeOrigin::root()));
				}
				Pace::Halt(hours) => stall(hours * HOUR_SLOTS),
			}
			run_to_era(era + 1);
			let lasted = era_start() - start;
			match pace(era) {
				Pace::Day | Pace::Forced => assert_eq!(lasted, DAY_MS, "era {era}"),
				Pace::Halt(hours) => assert_eq!(lasted, DAY_MS + hours * HOUR_MS, "era {era}"),
			}

			let year = (era - 1) / ERAS_PER_YEAR;
			let due = era_issuance::<TokenomicsSchedule>(year, lasted);
			assert_eq!(
				ErasValidatorReward::<Runtime>::get(era),
				Some(due),
				"era {era}: {:?}, lasted {lasted} ms, year {}",
				pace(era),
				year + 1
			);
			if era <= ERAS_PER_YEAR {
				year_one += due;
				year_one_paid_ms += lasted.min(MAX_PAID_ERA_MS);
			}
			let key = match pace(era) {
				Pace::Day => "day",
				Pace::Forced => "forced",
				Pace::Halt(hours) if DAY_MS + hours * HOUR_MS > MAX_PAID_ERA_MS => "halt, capped",
				Pace::Halt(_) => "halt",
			};
			let entry = lasted_by_pace.entry(key).or_default();
			*entry = (entry.0 + 1, entry.1 + lasted);

			let before = issuance();
			pay_everything(5_000);
			let paid = issuance() - before;
			// Three validators, each paid its commission and own share, on one page.
			let shares: Balance = 3 * 2;
			assert!(
				paid <= due,
				"era {era}: minted {paid} over its reward {due}"
			);
			assert!(
				due - paid <= shares * (due / 1_000_000_000 + 1),
				"era {era}: {} of {due} never minted",
				due - paid
			);
			rewarded += due;
			minted += paid;
		});
		ext.commit_all().expect("commit");
		if era % 25 == 0 {
			let elapsed = clock.elapsed().as_secs();
			let left = elapsed * u64::from(ERAS_PER_YEAR + 1 - era) / u64::from(era);
			std::println!(
				"era {era}/{}: {elapsed}s elapsed, about {left}s left",
				ERAS_PER_YEAR + 1
			);
		}
	}

	ext.execute_with(|| {
		// Year 1 issued its rate for the time its eras were paid for, to rounding.
		let year_one_due =
			YEAR_ONE_RATE * Balance::from(year_one_paid_ms) / Balance::from(365 * DAY_MS);
		assert!(year_one <= year_one_due);
		assert!(year_one_due - year_one < Balance::from(ERAS_PER_YEAR));
		// Era 366 is year 2: 40M ORB a year.
		assert_eq!(
			ErasValidatorReward::<Runtime>::get(ERAS_PER_YEAR + 1),
			Some(40_000_000 * ORB / 365)
		);
		// The supply grew by exactly what was paid.
		assert_eq!(issuance() - first_issuance, minted);
	});

	std::println!("eras by pace (count, total ms): {lasted_by_pace:?}");
	std::println!(
		"year 1: {} eras paid for {:.2} days, issued {} ORB of {} for a full year",
		ERAS_PER_YEAR,
		year_one_paid_ms as f64 / DAY_MS as f64,
		year_one / ORB,
		YEAR_ONE_RATE / ORB
	);
	std::println!(
		"eras 1-{}: rewards {} ORB, minted {} ORB, never minted {} planck",
		ERAS_PER_YEAR + 1,
		rewarded / ORB,
		minted / ORB,
		rewarded - minted
	);
}

fn validator(key: Sr25519Keyring) -> AccountId {
	account(key)
}

/// The reward account of pool `id`, where the pool's share is paid.
fn pool_reward_account(id: u32) -> AccountId {
	NominationPools::api_pool_accounts(id).1
}

fn pool_bonded_account(id: u32) -> AccountId {
	NominationPools::api_pool_accounts(id).0
}

/// What staking pays each staker for `era`: the validator's part of the reward
/// by era points; its commission off the top; the rest by stake, its own
/// included. Keyed by where the payment lands (a pool's goes to its reward
/// account).
fn shares_of(era: EraIndex) -> BTreeMap<AccountId, Balance> {
	let reward = ErasValidatorReward::<Runtime>::get(era).expect("era closed");
	let points = ErasRewardPoints::<Runtime>::get(era);
	let mut shares = BTreeMap::<AccountId, Balance>::new();
	let mut add = |who: &AccountId, amount: Balance| {
		let to = if *who == pool_bonded_account(1) {
			pool_reward_account(1)
		} else {
			who.clone()
		};
		*shares.entry(to).or_default() += amount;
	};
	for (stash, earned) in points.individual.iter() {
		let total = Perbill::from_rational(*earned, points.total) * reward;
		let commission = ErasValidatorPrefs::<Runtime>::get(era, stash).commission * total;
		let rest = total - commission;
		let exposure = ErasStakersOverview::<Runtime>::get(era, stash).expect("exposed");
		add(
			stash,
			commission + Perbill::from_rational(exposure.own, exposure.total) * rest,
		);
		for page in 0..exposure.page_count {
			let paged = ErasStakersPaged::<Runtime>::get((era, stash, page)).expect("page");
			for nominator in paged.others.iter() {
				add(
					&nominator.who,
					Perbill::from_rational(nominator.value, exposure.total) * rest,
				);
			}
		}
	}
	shares
}

/// A paid era reaches each validator, nominator and pool member as staking's
/// rules say: by era points among validators, the commission to the validator,
/// the rest by stake; a pool's share split among its members by their points.
/// Everything paid was minted; nothing else was.
#[test]
fn each_staker_is_paid_its_share_of_the_era() {
	with_validators(|| {
		let [alice, bob, charlie] = [
			Sr25519Keyring::Alice,
			Sr25519Keyring::Bob,
			Sr25519Keyring::Charlie,
		]
		.map(validator);
		for (who, commission) in [(&alice, 10), (&bob, 0), (&charlie, 25)] {
			let signed = RuntimeOrigin::signed(who.clone());
			assert_ok!(Staking::validate(
				signed.clone(),
				ValidatorPrefs {
					commission: Perbill::from_percent(commission),
					blocked: false,
				}
			));
			assert_ok!(Staking::set_payee(signed, RewardDestination::Stash));
		}
		let nominators = [
			(
				AccountId::from([0x71; 32]),
				1_000 * ORB,
				vec![alice.clone()],
			),
			(
				AccountId::from([0x72; 32]),
				3_000 * ORB,
				vec![alice.clone(), bob.clone()],
			),
		];
		for (who, bond, targets) in &nominators {
			Balances::set_balance(who, 10_000 * ORB);
			assert_ok!(<Staking as StakingInterface>::bond(who, *bond, who));
			assert_ok!(<Staking as StakingInterface>::nominate(
				who,
				targets.clone()
			));
		}
		let depositor = AccountId::from([0x51; 32]);
		let members = [
			(AccountId::from([0x61; 32]), 100 * ORB),
			(AccountId::from([0x62; 32]), 300 * ORB),
		];
		Balances::set_balance(&depositor, 1_000 * ORB);
		assert_ok!(NominationPools::create(
			RuntimeOrigin::signed(depositor.clone()),
			TEST_POOL_MIN_CREATE_BOND,
			depositor.clone(),
			depositor.clone(),
			depositor.clone()
		));
		for (who, bond) in &members {
			Balances::set_balance(who, 1_000 * ORB);
			assert_ok!(NominationPools::join(
				RuntimeOrigin::signed(who.clone()),
				*bond,
				1
			));
		}
		assert_ok!(NominationPools::nominate(
			RuntimeOrigin::signed(depositor.clone()),
			1,
			vec![charlie.clone()]
		));

		// Era 3 is the first with every nomination exposed: pay what came before, then
		// close it unpaid.
		run_to_era(3);
		pay_everything(5_000);
		assert_ok!(AutoPayout::pause(RuntimeOrigin::root()));
		run_to_era(4);
		let era = 3;
		let shares = shares_of(era);
		for who in [&alice, &bob, &charlie, &nominators[0].0, &nominators[1].0] {
			assert!(
				shares.get(who).is_some_and(|s| *s > 0),
				"{who:?} has a share"
			);
		}
		assert!(shares.get(&pool_reward_account(1)).is_some_and(|s| *s > 0));

		let balance = |who: &AccountId| Balances::balance(who);
		let before: BTreeMap<_, _> = shares
			.keys()
			.map(|who| (who.clone(), balance(who)))
			.collect();
		let pending =
			|who: &AccountId| NominationPools::api_pending_rewards(who.clone()).unwrap_or_default();
		let pool = [
			(depositor.clone(), TEST_POOL_MIN_CREATE_BOND),
			members[0].clone(),
			members[1].clone(),
		];
		let pending_before: BTreeMap<_, _> = pool
			.iter()
			.map(|(who, _)| (who.clone(), pending(who)))
			.collect();
		let issuance_before = issuance();
		assert_ok!(AutoPayout::resume(RuntimeOrigin::root()));
		pay_everything(5_000);

		let reward = ErasValidatorReward::<Runtime>::get(era).unwrap();
		// Each payment carries up to two `Perbill` roundings of the era's reward.
		let tolerance = 2 * (reward / 1_000_000_000 + 1);
		let mut paid_total = 0;
		for (who, share) in &shares {
			let paid = balance(who) - before[who];
			assert!(
				paid.abs_diff(*share) <= tolerance,
				"{who:?} paid {paid}, its share is {share}"
			);
			paid_total += paid;
		}
		assert_eq!(
			issuance() - issuance_before,
			paid_total,
			"only the shares were minted"
		);
		assert!(paid_total <= reward);

		// The pool's share is split among its members by points (100 : 100 : 300).
		let pool_paid = balance(&pool_reward_account(1)) - before[&pool_reward_account(1)];
		let total_points: Balance = pool.iter().map(|(_, points)| points).sum();
		for (who, points) in &pool {
			let earned = pending(who) - pending_before[who];
			let expected = Perbill::from_rational(*points, total_points) * pool_paid;
			assert!(
				earned.abs_diff(expected) <= pool_paid / 1_000_000_000 + 2,
				"{who:?} earned {earned}, expected {expected}"
			);
		}
	});
}
