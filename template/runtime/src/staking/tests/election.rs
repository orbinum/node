// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

//! The era election end to end: computed on-chain by `pallet-paged-election`
//! over a paged snapshot, fetched by staking page by page, handed to the session
//! side, applied at a session boundary. And what happens when an era plan can no
//! longer start: the current set stays and the era is planned again.

use crate::test_utils::{
	blocks::{active_era, next_session, run_block, run_to_era},
	network::{genesis, with_validators},
};
use crate::{
	staking::{
		params::{SESSIONS_PER_ERA, TEST_MIN_VALIDATOR_BOND},
		recovery::{plan_is_stalled, reset_stalled_plan},
	},
	test_utils::{account, with_ext},
	AccountId, Balance, Balances, PagedElection, Runtime, RuntimeEvent, RuntimeOrigin, Session,
	Staking, System,
};
use frame_election_provider_support::ElectionProvider;
use frame_support::{
	assert_noop, assert_ok,
	traits::{fungible::Mutate, Get},
};
use pallet_paged_election::{Event as Paged, Phase};
use pallet_staking_async as staking;
use pallet_staking_async_ah_client as ah_client;
use pallet_staking_async_rc_client as rc_client;
use sp_keyring::{Ed25519Keyring, Sr25519Keyring};
use sp_staking::StakingInterface;

fn sorted(mut set: Vec<AccountId>) -> Vec<AccountId> {
	set.sort();
	set
}

fn paged_events() -> Vec<Paged<Runtime>> {
	System::events()
		.into_iter()
		.filter_map(|r| match r.event {
			RuntimeEvent::PagedElection(e) => Some(e),
			_ => None,
		})
		.collect()
}

/// Staking's page fetches: `(page, result)`.
fn fetched_pages() -> Vec<(u32, Result<u32, u32>)> {
	System::events()
		.into_iter()
		.filter_map(|r| match r.event {
			RuntimeEvent::Staking(staking::Event::PagedElectionProceeded { page, result }) => {
				Some((page, result))
			}
			_ => None,
		})
		.collect()
}

fn count(event: impl Fn(&Paged<Runtime>) -> bool) -> usize {
	paged_events().iter().filter(|e| event(e)).count()
}

/// Sessions until staking plans `era`: its election has just started.
fn to_planning_of(era: u32) {
	for _ in 0..2 * SESSIONS_PER_ERA {
		if staking::CurrentEra::<Runtime>::get() == Some(era) {
			return;
		}
		next_session();
	}
	panic!("era {era} never planned");
}

/// Blocks until staking has fetched the first page of `era`'s election.
fn to_fetching_of(era: u32) {
	to_planning_of(era);
	for _ in 0..1_000 {
		if staking::NextElectionPage::<Runtime>::exists() {
			return;
		}
		run_block(System::block_number() + 1);
	}
	panic!("era {era}'s election never fetched");
}

/// The last snapshot's voter count.
fn last_snapshot_voters() -> u32 {
	paged_events()
		.iter()
		.rev()
		.find_map(|e| match e {
			Paged::SnapshotTaken { voters, .. } => Some(*voters),
			_ => None,
		})
		.expect("a snapshot")
}

fn until_reset() {
	for _ in 0..2 * SESSIONS_PER_ERA {
		if count(|e| matches!(e, Paged::EraPlanReset { .. })) > 0 {
			return;
		}
		next_session();
	}
	panic!("the plan was never reset");
}

// Happy path

#[test]
fn each_era_is_elected_on_chain_and_fetched_page_by_page() {
	with_validators(|| {
		let validators = sorted(
			[
				Sr25519Keyring::Alice,
				Sr25519Keyring::Bob,
				Sr25519Keyring::Charlie,
			]
			.into_iter()
			.map(account)
			.collect(),
		);
		assert_eq!(sorted(Session::validators()), validators);
		assert!(paged_events().contains(&Paged::ElectionStarted));
		assert!(paged_events().iter().any(|e| matches!(
			e,
			Paged::SnapshotTaken {
				targets: 3,
				voters: 3,
				to_elect: 3,
				..
			}
		)));
		assert_eq!(
			count(|e| matches!(e, Paged::ElectionDone { winners: 3, .. })),
			1
		);
		// Every page fetched, the most significant first, none failing.
		let pages: Vec<u32> = fetched_pages().iter().map(|(page, _)| *page).collect();
		assert_eq!(
			pages,
			(0..crate::configs::staking::ElectionPages::get())
				.rev()
				.collect::<Vec<_>>()
		);
		assert!(fetched_pages().iter().all(|(_, result)| result.is_ok()));
		for v in &validators {
			assert!(staking::ErasStakersOverview::<Runtime>::get(1, v).is_some());
		}
		// Cleared once fetched, unless the next era's election already started
		// (`fast-runtime` plans an era as the previous one starts).
		assert!(
			pallet_paged_election::CurrentPhase::<Runtime>::get() == Phase::Off
				|| staking::CurrentEra::<Runtime>::get() == Some(2)
		);
	});
}

/// A candidate backed by a large nominator takes the seat of the least backed
/// validator: the session runs what the election chose.
#[test]
fn the_election_seats_the_most_backed_candidates() {
	genesis().execute_with(|| {
		let (alice, bob, charlie) = (
			account(Sr25519Keyring::Alice),
			account(Sr25519Keyring::Bob),
			account(Sr25519Keyring::Charlie),
		);
		let dave = account(Sr25519Keyring::Dave);
		let keys = crate::opaque::SessionKeys {
			aura: Sr25519Keyring::Dave.public().into(),
			grandpa: Ed25519Keyring::Dave.public().into(),
		};
		assert_ok!(<Session as pallet_session::SessionInterface>::set_keys(
			&dave, keys
		));
		pallet_validator_set::ApprovedValidators::<Runtime>::mutate(|v| {
			v.try_push(dave.clone()).unwrap()
		});
		Balances::set_balance(&dave, 2 * TEST_MIN_VALIDATOR_BOND);
		assert_ok!(<Staking as StakingInterface>::bond(
			&dave,
			TEST_MIN_VALIDATOR_BOND,
			&dave
		));
		assert_ok!(Staking::validate(
			RuntimeOrigin::signed(dave.clone()),
			Default::default()
		));
		let whale = AccountId::from([0x77; 32]);
		let stake: Balance = 10 * TEST_MIN_VALIDATOR_BOND;
		Balances::set_balance(&whale, 2 * stake);
		assert_ok!(<Staking as StakingInterface>::bond(&whale, stake, &whale));
		assert_ok!(<Staking as StakingInterface>::nominate(
			&whale,
			vec![alice.clone(), bob.clone(), dave.clone()]
		));

		run_to_era(1);
		assert_eq!(
			sorted(Session::validators()),
			sorted(vec![alice, bob, dave.clone()])
		);
		assert!(staking::ErasStakersOverview::<Runtime>::get(1, &charlie).is_none());
		let dave_backing = staking::ErasStakersOverview::<Runtime>::get(1, &dave).unwrap();
		assert_eq!(dave_backing.nominator_count, 1);
	});
}

/// Exposures are the bonds rounded down to a vote unit (10^-9 ORB), and a
/// stake below one unit weighs nothing, so the snapshot leaves it out.
#[test]
fn exposures_equal_bonds_within_one_vote_unit() {
	use crate::staking::{params::TEST_MIN_NOMINATOR_BOND, vote::VOTE_FACTOR};
	genesis().execute_with(|| {
		let alice = account(Sr25519Keyring::Alice);
		let nominate = |who: &AccountId, stake: Balance| {
			Balances::set_balance(who, 2 * stake + 1);
			assert_ok!(<Staking as StakingInterface>::bond(who, stake, who));
			assert_ok!(<Staking as StakingInterface>::nominate(
				who,
				vec![alice.clone()]
			));
		};
		let (nominator, dust) = (AccountId::from([0x78; 32]), AccountId::from([0x79; 32]));
		let stake = 3 * TEST_MIN_NOMINATOR_BOND + 987_654_321;
		nominate(&nominator, stake);
		staking::MinNominatorBond::<Runtime>::put(0);
		nominate(&dust, VOTE_FACTOR - 1);

		run_to_era(1);
		assert_eq!(
			last_snapshot_voters(),
			4,
			"three validators and the nominator"
		);
		let overview = staking::ErasStakersOverview::<Runtime>::get(1, &alice).unwrap();
		assert_eq!(overview.own, TEST_MIN_VALIDATOR_BOND);
		assert_eq!(
			overview.total,
			TEST_MIN_VALIDATOR_BOND + stake - stake % VOTE_FACTOR
		);
		assert_eq!(overview.nominator_count, 1);
	});
}

// Recovery

/// The election for era 2 fails (governance aborts it): staking fetches failed
/// pages, hands over an empty set, which the session side drops. The next
/// session report resets the plan and plans era 2 again; the current set keeps
/// validating meanwhile, and era 2 starts once the new election lands.
#[test]
fn a_failed_election_keeps_the_set_and_plans_the_era_again() {
	with_validators(|| {
		let set = sorted(Session::validators());
		to_planning_of(2);
		assert!(pallet_paged_election::CurrentPhase::<Runtime>::get().is_computing());
		assert_ok!(PagedElection::abort(RuntimeOrigin::root()));

		for _ in 0..2 * SESSIONS_PER_ERA {
			if count(|e| matches!(e, Paged::EraPlanReset { .. })) > 0 {
				break;
			}
			next_session();
			assert_eq!(
				sorted(Session::validators()),
				set,
				"the set keeps its seats"
			);
			assert_eq!(active_era(), 1);
		}
		assert_eq!(count(|e| *e == Paged::EraPlanReset { era: 2 }), 1);
		let failed: Vec<_> = fetched_pages()
			.into_iter()
			.filter(|(_, result)| result.is_err())
			.collect();
		assert_eq!(
			failed.len() as u32,
			crate::configs::staking::ElectionPages::get()
		);
		assert!(System::events().iter().any(|r| matches!(
			r.event,
			RuntimeEvent::AhClient(ah_client::Event::SetTooSmallAndDropped)
		)));
		// Planned again in the same report, with a new election.
		assert_eq!(staking::CurrentEra::<Runtime>::get(), Some(2));
		assert_eq!(
			count(|e| *e == Paged::ElectionStarted),
			3,
			"era 1, era 2, and era 2 again"
		);

		run_to_era(2);
		assert_eq!(sorted(Session::validators()), set);
		// Nothing of the failed attempt is counted twice.
		assert_eq!(
			staking::ErasStakersOverview::<Runtime>::iter_prefix(2).count(),
			3
		);
		let total = staking::ErasTotalStake::<Runtime>::get(2);
		assert!(
			total <= 3 * TEST_MIN_VALIDATOR_BOND,
			"era 2 total stake {total}"
		);
		assert!(total > 3 * TEST_MIN_VALIDATOR_BOND * 999 / 1000);
	});
}

/// Bob and Charlie stop validating: the election seats Alice alone, under two
/// thirds of the three seats. The session side drops that set and the current
/// one stays; staking plans again every session until enough candidates are
/// back.
#[test]
fn a_set_below_two_thirds_of_the_seats_is_not_applied() {
	with_validators(|| {
		let set = sorted(Session::validators());
		let (bob, charlie) = (
			account(Sr25519Keyring::Bob),
			account(Sr25519Keyring::Charlie),
		);
		assert_ok!(Staking::chill(RuntimeOrigin::signed(bob.clone())));
		assert_ok!(Staking::chill(RuntimeOrigin::signed(charlie)));

		for _ in 0..2 * SESSIONS_PER_ERA {
			next_session();
		}
		assert_eq!(active_era(), 1, "no era starts with too small a set");
		assert_eq!(sorted(Session::validators()), set);
		assert!(count(|e| *e == Paged::EraPlanReset { era: 2 }) >= 1);

		assert_ok!(Staking::validate(
			RuntimeOrigin::signed(bob.clone()),
			Default::default()
		));
		run_to_era(2);
		assert_eq!(
			sorted(Session::validators()),
			sorted(vec![account(Sr25519Keyring::Alice), bob])
		);
	});
}

/// Bans that leave fewer admitted candidates than two thirds of the seats freeze
/// the set: every election seats too few and is dropped, so the current set,
/// the banned included, keeps validating and no era starts. Root lowering the
/// seats (`staking.setValidatorCount`) is the way out.
#[test]
fn bans_leaving_fewer_than_two_thirds_freeze_the_set() {
	use pallet_validator_set::BanTerm;
	with_validators(|| {
		let set = sorted(Session::validators());
		let alice = account(Sr25519Keyring::Alice);
		for who in [Sr25519Keyring::Bob, Sr25519Keyring::Charlie] {
			assert_ok!(crate::ValidatorSet::ban_validator(
				RuntimeOrigin::root(),
				account(who),
				BanTerm::Permanent
			));
		}

		for _ in 0..2 * SESSIONS_PER_ERA {
			next_session();
		}
		assert_eq!(active_era(), 1, "no era starts");
		assert_eq!(
			sorted(Session::validators()),
			set,
			"the banned keep their seats"
		);

		assert_ok!(Staking::set_validator_count(RuntimeOrigin::root(), 1));
		run_to_era(2);
		assert_eq!(Session::validators(), vec![alice]);
	});
}

/// Once staking fetched a page, the election cannot be aborted: staking would
/// seat the winners of the pages it already took. The whole set takes over.
#[test]
fn aborting_during_the_fetch_never_seats_a_partial_set() {
	with_validators(|| {
		let set = sorted(Session::validators());
		to_fetching_of(2);
		assert_noop!(
			PagedElection::abort(RuntimeOrigin::root()),
			pallet_paged_election::Error::<Runtime>::AlreadyFetching
		);
		run_to_era(2);
		assert_eq!(sorted(Session::validators()), set);
		assert!(fetched_pages().iter().all(|(_, result)| result.is_ok()));
		for v in &set {
			assert!(staking::ErasStakersOverview::<Runtime>::get(2, v).is_some());
		}
	});
}

/// An election cleared while staking fetches it leaves staking waiting for a
/// page an idle election never serves; the next report resets the plan and the
/// era starts with a new election.
#[test]
fn a_cleared_election_mid_fetch_still_resets_the_plan() {
	with_validators(|| {
		let set = sorted(Session::validators());
		to_fetching_of(2);
		// Page 0 clears the election, as the old `abort` of a failed one did.
		let _ = <PagedElection as ElectionProvider>::elect(0);
		assert_eq!(<PagedElection as ElectionProvider>::status(), Err(()));
		assert!(staking::NextElectionPage::<Runtime>::exists());

		until_reset();
		assert_eq!(count(|e| *e == Paged::EraPlanReset { era: 2 }), 1);
		assert!(!staking::NextElectionPage::<Runtime>::exists());
		run_to_era(2);
		assert_eq!(sorted(Session::validators()), set);
	});
}

/// An election aborted mid-snapshot leaves staking's voter cursor and the voter
/// list locked; the reset releases both, so the next snapshot reads every voter
/// from the top.
#[test]
fn an_aborted_snapshot_unlocks_the_voter_list_and_restarts_from_the_top() {
	use pallet_bags_list::{Instance1, Lock};
	with_validators(|| {
		to_planning_of(2);
		assert!(pallet_paged_election::CurrentPhase::<Runtime>::get().is_computing());
		// A snapshot cut short, as with more voters than a page.
		Lock::<Runtime, Instance1>::put(());
		staking::VoterSnapshotStatus::<Runtime>::put(staking::SnapshotStatus::Ongoing(account(
			Sr25519Keyring::Alice,
		)));
		assert_ok!(PagedElection::abort(RuntimeOrigin::root()));

		until_reset();
		assert!(Lock::<Runtime, Instance1>::get().is_none());
		run_to_era(2);
		assert_eq!(last_snapshot_voters(), 3);
	});
}

fn report(activation: Option<(u64, u32)>) -> rc_client::SessionReport<AccountId> {
	rc_client::SessionReport {
		end_index: 1,
		validator_points: vec![],
		activation_timestamp: activation,
		leftover: false,
	}
}

fn planned_era_two() {
	System::set_block_number(1);
	staking::ActiveEra::<Runtime>::put(staking::ActiveEraInfo {
		index: 1,
		start: Some(0),
	});
	staking::CurrentEra::<Runtime>::put(2);
}

/// Each place a planned era's set can be on its way keeps the plan alive.
#[test]
fn a_plan_is_stalled_only_when_nothing_holds_its_set() {
	with_ext(|| {
		planned_era_two();
		assert!(plan_is_stalled(&report(None)));
		assert!(!plan_is_stalled(&report(Some((1, 2)))), "activated now");

		type Hold = (&'static str, fn(), fn());
		let holds: [Hold; 6] = [
			(
				"election running",
				|| pallet_paged_election::CurrentPhase::<Runtime>::put(Phase::Select),
				|| pallet_paged_election::CurrentPhase::<Runtime>::kill(),
			),
			(
				"staking fetching",
				|| {
					pallet_paged_election::CurrentPhase::<Runtime>::put(Phase::Done);
					staking::NextElectionPage::<Runtime>::put(3);
				},
				|| {
					pallet_paged_election::CurrentPhase::<Runtime>::kill();
					staking::NextElectionPage::<Runtime>::kill();
				},
			),
			(
				"rc-client holding",
				|| {
					rc_client::OutgoingValidatorSet::<Runtime>::put((
						rc_client::ValidatorSetReport::new_terminal(vec![], 2, None),
						1,
					))
				},
				|| rc_client::OutgoingValidatorSet::<Runtime>::kill(),
			),
			(
				"ah-client holding",
				|| ah_client::ValidatorSet::<Runtime>::put((2, Vec::<AccountId>::new())),
				|| ah_client::ValidatorSet::<Runtime>::kill(),
			),
			(
				"ah-client merging",
				|| {
					ah_client::IncompleteValidatorSetReport::<Runtime>::put(
						rc_client::ValidatorSetReport::new_terminal(vec![], 2, None),
					)
				},
				|| ah_client::IncompleteValidatorSetReport::<Runtime>::kill(),
			),
			(
				"session about to activate",
				|| ah_client::NextSessionChangesValidators::<Runtime>::put(2),
				|| ah_client::NextSessionChangesValidators::<Runtime>::kill(),
			),
		];
		for (what, hold, release) in holds {
			hold();
			assert!(!plan_is_stalled(&report(None)), "{what}");
			release();
		}
		assert!(plan_is_stalled(&report(None)));
		// A page left to fetch from an idle election is never served.
		staking::NextElectionPage::<Runtime>::put(3);
		assert!(plan_is_stalled(&report(None)), "staking fetching nothing");
		staking::NextElectionPage::<Runtime>::kill();

		staking::CurrentEra::<Runtime>::put(1);
		assert!(!plan_is_stalled(&report(None)), "nothing planned");
	});
}

/// A reset clears what a partly fetched election stored for the planned era,
/// and staking's snapshot cursor, so the next election starts clean.
#[test]
fn a_reset_clears_the_failed_plan() {
	with_ext(|| {
		planned_era_two();
		let who = AccountId::from([1; 32]);
		let overview = sp_staking::PagedExposureMetadata::<Balance>::default();
		staking::ErasStakersOverview::<Runtime>::insert(2, &who, overview);
		staking::ErasStakersPaged::<Runtime>::insert(
			(2, &who, 0),
			staking::BoundedExposurePage::<Runtime>::default(),
		);
		staking::ErasValidatorPrefs::<Runtime>::insert(2, &who, staking::ValidatorPrefs::default());
		staking::ErasTotalStake::<Runtime>::insert(2, 5);
		staking::VoterSnapshotStatus::<Runtime>::put(staking::SnapshotStatus::Ongoing(who.clone()));
		pallet_bags_list::Lock::<Runtime, pallet_bags_list::Instance1>::put(());
		staking::NextElectionPage::<Runtime>::put(3);
		staking::ElectableStashes::<Runtime>::put(
			frame_support::BoundedBTreeSet::try_from(std::collections::BTreeSet::from([
				who.clone()
			]))
			.unwrap(),
		);
		// The active era's data stays.
		staking::ErasStakersOverview::<Runtime>::insert(1, &who, overview);

		reset_stalled_plan(&report(None));

		assert_eq!(staking::CurrentEra::<Runtime>::get(), Some(1));
		assert!(staking::ErasStakersOverview::<Runtime>::get(2, &who).is_none());
		assert!(staking::ErasStakersPaged::<Runtime>::get((2, &who, 0)).is_none());
		assert_eq!(
			staking::ErasValidatorPrefs::<Runtime>::iter_prefix(2).count(),
			0
		);
		assert_eq!(staking::ErasTotalStake::<Runtime>::get(2), 0);
		assert_eq!(
			staking::VoterSnapshotStatus::<Runtime>::get(),
			staking::SnapshotStatus::Waiting
		);
		assert!(pallet_bags_list::Lock::<Runtime, pallet_bags_list::Instance1>::get().is_none());
		assert!(!staking::NextElectionPage::<Runtime>::exists());
		assert!(staking::ElectableStashes::<Runtime>::get().is_empty());
		assert!(staking::ErasStakersOverview::<Runtime>::get(1, &who).is_some());
		assert_eq!(paged_events(), vec![Paged::EraPlanReset { era: 2 }]);

		// Nothing more to reset.
		reset_stalled_plan(&report(None));
		assert_eq!(paged_events().len(), 1);
	});
}

/// A dropped set can leave an era's worth of exposures, more than a block can
/// remove: each report removes a bounded share, `on_idle` the rest over the
/// next blocks, and the report after that resets the plan.
#[test]
fn a_large_failed_plan_is_removed_within_each_block_before_the_reset() {
	use crate::{
		configs::system::BlockWeights,
		staking::{pruning::StalledPlan, recovery::CLEAR_PER_REPORT},
		EraPruning,
	};
	use frame_support::traits::OnIdle;
	const PAGES: u32 = 2_500;
	let mut ext = sp_io::TestExternalities::default();
	let who = AccountId::from([1; 32]);
	ext.execute_with(|| {
		planned_era_two();
		staking::ErasStakersOverview::<Runtime>::insert(
			2,
			&who,
			sp_staking::PagedExposureMetadata::<Balance>::default(),
		);
		for page in 0..PAGES {
			staking::ErasStakersPaged::<Runtime>::insert(
				(2, &who, page),
				staking::BoundedExposurePage::<Runtime>::default(),
			);
		}
	});
	ext.commit_all().unwrap();
	let left = || staking::ErasStakersPaged::<Runtime>::iter_prefix((2,)).count() as u32;
	let max = BlockWeights::get().max_block;

	ext.execute_with(|| {
		let weight = reset_stalled_plan(&report(None));
		assert!(
			weight.all_lte(sp_runtime::Perbill::from_percent(10) * max),
			"{weight:?}"
		);
		assert_eq!(
			staking::CurrentEra::<Runtime>::get(),
			Some(2),
			"not reset yet"
		);
		assert_eq!(StalledPlan::<Runtime>::get(), Some(2));
		assert_eq!(left(), PAGES + 1 - CLEAR_PER_REPORT);
		assert!(paged_events().is_empty());
	});
	ext.commit_all().unwrap();

	let mut blocks = 0;
	while ext.execute_with(|| StalledPlan::<Runtime>::get().is_some()) {
		blocks += 1;
		assert!(blocks < 100, "the plan's data is never removed");
		ext.execute_with(|| {
			let used = EraPruning::on_idle(5, max);
			assert!(used.all_lte(EraPruning::share()), "{used:?}");
		});
		ext.commit_all().unwrap();
	}
	ext.execute_with(|| {
		assert_eq!(left(), 0);
		assert!(staking::ErasStakersOverview::<Runtime>::get(2, &who).is_none());
		reset_stalled_plan(&report(None));
		assert_eq!(staking::CurrentEra::<Runtime>::get(), Some(1));
		assert_eq!(paged_events(), vec![Paged::EraPlanReset { era: 2 }]);
	});
}

/// Removal stops if staking no longer has the stalled era planned.
#[test]
fn a_stalled_plan_staking_moved_past_is_left_alone() {
	use crate::{configs::system::BlockWeights, staking::pruning::StalledPlan, EraPruning};
	use frame_support::traits::OnIdle;
	with_ext(|| {
		planned_era_two();
		let who = AccountId::from([1; 32]);
		staking::ErasValidatorPrefs::<Runtime>::insert(2, &who, staking::ValidatorPrefs::default());
		StalledPlan::<Runtime>::put(2);
		staking::ActiveEra::<Runtime>::put(staking::ActiveEraInfo {
			index: 2,
			start: Some(0),
		});
		EraPruning::on_idle(5, BlockWeights::get().max_block);
		assert_eq!(StalledPlan::<Runtime>::get(), None);
		assert!(staking::ErasValidatorPrefs::<Runtime>::contains_key(
			2, &who
		));
	});
}

#[test]
fn the_election_is_planned_with_time_to_hand_the_set_over() {
	use crate::staking::params::SESSION_PERIOD;
	let offset = <crate::configs::staking::PlanningEraOffset as Get<u32>>::get();
	assert!(offset <= SESSIONS_PER_ERA);
	// The sessions left after planning cover the election and its export, one
	// session for the session side to queue the set and one to activate it.
	let election = <PagedElection as ElectionProvider>::duration_with_export();
	assert!(election < offset.saturating_sub(1) * SESSION_PERIOD);
}

/// 100 000 voters in production; `fast-runtime` keeps 25 000, since 32 pages
/// would not fit its 60-block era.
#[test]
fn the_snapshot_reads_the_most_staked_voters() {
	use crate::staking::params::{ELECTION_PAGES, MAX_ELECTING_VOTERS};
	#[cfg(not(feature = "fast-runtime"))]
	assert_eq!((ELECTION_PAGES, MAX_ELECTING_VOTERS), (32, 100_000));
	#[cfg(feature = "fast-runtime")]
	assert_eq!((ELECTION_PAGES, MAX_ELECTING_VOTERS), (8, 25_000));
}

/// A full production election (100 000 voters), with its export, takes under
/// half the blocks between planning and the hand-over, and a sliver of the era:
/// a slow block or a reset still leaves time to elect again.
#[cfg(not(feature = "fast-runtime"))]
#[test]
fn the_production_election_fits_its_era_with_room_to_spare() {
	use crate::staking::params::SESSION_PERIOD;
	let offset = <crate::configs::staking::PlanningEraOffset as Get<u32>>::get();
	let election = <PagedElection as ElectionProvider>::duration_with_export();
	let era = SESSIONS_PER_ERA * SESSION_PERIOD;
	assert!(
		2 * election <= offset.saturating_sub(1) * SESSION_PERIOD,
		"{election} blocks, {offset} sessions of {SESSION_PERIOD} to hand over"
	);
	assert!(
		100 * election <= era,
		"{election} blocks of a {era}-block era"
	);
}

#[test]
fn minimum_validator_count_is_two_thirds_rounded_up() {
	assert_eq!(crate::staking::params::minimum_validator_count(1), 1);
	assert_eq!(crate::staking::params::minimum_validator_count(3), 2);
	assert_eq!(crate::staking::params::minimum_validator_count(4), 3);
	assert_eq!(crate::staking::params::minimum_validator_count(14), 10);
}

#[test]
fn the_snapshot_reads_every_page() {
	assert_eq!(
		crate::staking::params::MAX_ELECTING_VOTERS,
		crate::staking::params::ELECTION_PAGES * crate::staking::params::VOTER_SNAPSHOT_PER_BLOCK
	);
	assert_eq!(
		<crate::PagedElection as frame_election_provider_support::ElectionProvider>::Pages::get(),
		crate::staking::params::ELECTION_PAGES
	);
}
