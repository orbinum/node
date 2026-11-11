//! Automatic payouts as the runtime wires them: the budget against the block and
//! the worst-case era, the staking adapter, and eras paid end to end.

use crate::test_utils::{
	blocks::{run_block, run_to_era},
	network::with_validators,
};
use crate::{
	configs::{staking::DefaultPayoutLimits, system::BlockWeights},
	staking::{params::*, payouts::StakingPayouts},
	test_utils::{account, with_ext, ORB},
	AccountId, AutoPayout, Balances, Runtime, RuntimeEvent, RuntimeOrigin, Staking, System,
};
use frame_support::{
	assert_ok,
	dispatch::DispatchClass,
	traits::{fungible::Inspect, fungible::Mutate},
	weights::Weight,
};
use pallet_auto_payout::{EraPayouts, PayoutOutcome};
use pallet_staking_async::RewardDestination;
use sp_keyring::Sr25519Keyring;
use sp_staking::StakingInterface;

fn max_block() -> Weight {
	BlockWeights::get().max_block
}

// Budget

#[test]
fn every_elected_validator_fits_the_era_being_paid() {
	// Fewer would leave the rest of an era's validators unpaid, without a word.
	assert!(
		<Runtime as pallet_auto_payout::Config>::MaxValidators::get()
			>= <Runtime as pallet_staking_async::Config>::MaxValidatorSet::get()
	);
}

#[test]
fn the_default_limits_fit_a_full_page() {
	let limits = DefaultPayoutLimits::get();
	assert_eq!(AutoPayout::check_limits(&limits), Ok(()));
	let page = StakingPayouts::page_weight(MAX_EXPOSURE_PAGE_SIZE);
	assert!(
		(limits.floor * max_block()).all_gte(page),
		"a full page {page:?} must fit the floor"
	);
}

/// Normal transactions keep their whole class limit: the guaranteed share is
/// mandatory weight and comes out of the operational headroom.
#[test]
fn transactions_keep_their_share_of_the_block() {
	let weights = BlockWeights::get();
	let limits = DefaultPayoutLimits::get();
	let normal = weights
		.get(DispatchClass::Normal)
		.max_total
		.expect("normal class is capped");
	let guaranteed = limits.catch_up.max(limits.floor) * weights.max_block;
	let total = normal
		.saturating_add(guaranteed)
		.saturating_add(weights.base_block);
	assert!(
		total.all_lte(weights.max_block),
		"normal {normal:?} + payouts {guaranteed:?} exceed the block"
	);
}

/// The worst era — every electing voter backing the most validators it may — is
/// paid within the window by the floor alone, on a chain whose transactions
/// leave `on_idle` nothing.
#[cfg(not(feature = "fast-runtime"))]
#[test]
fn the_worst_era_is_paid_within_the_window_on_a_full_chain() {
	let limits = DefaultPayoutLimits::get();
	let entries = MAX_ELECTING_VOTERS * MAX_NOMINATIONS;
	let pages = u64::from(MAX_ACTIVE_VALIDATORS + entries.div_ceil(MAX_EXPOSURE_PAGE_SIZE));
	let page = StakingPayouts::page_weight(MAX_EXPOSURE_PAGE_SIZE).ref_time();
	let budget = (limits.floor * max_block())
		.saturating_sub(AutoPayout::largest_step().saturating_sub(Weight::from_parts(page, 0)))
		.ref_time();
	let per_block = (budget / page).max(1);
	let blocks = pages.div_ceil(per_block);
	// No share on heavy blocks: each session's rotation, and the election's
	// blocks (at most one election per window).
	let heavy = u64::from(PAYMENT_WINDOW / SESSION_PERIOD)
		+ u64::from(<crate::PagedElection as frame_election_provider_support::ElectionProvider>::duration_with_export());
	assert!(
		blocks + heavy <= u64::from(PAYMENT_WINDOW),
		"{pages} pages at {per_block}/block take {blocks} blocks; window {PAYMENT_WINDOW}"
	);
}

/// After a stall, two worst-case eras are paid within one era by the catch-up
/// share alone.
#[cfg(not(feature = "fast-runtime"))]
#[test]
fn two_worst_eras_catch_up_within_an_era() {
	let limits = DefaultPayoutLimits::get();
	let entries = MAX_ELECTING_VOTERS * MAX_NOMINATIONS;
	let pages = 2 * u64::from(MAX_ACTIVE_VALIDATORS + entries.div_ceil(MAX_EXPOSURE_PAGE_SIZE));
	let page = StakingPayouts::page_weight(MAX_EXPOSURE_PAGE_SIZE).ref_time();
	let per_block = ((limits.catch_up * max_block()).ref_time() / page).max(1);
	let era = u64::from(SESSIONS_PER_ERA * SESSION_PERIOD);
	assert!(pages.div_ceil(per_block) <= era);
}

// Adapter

#[test]
fn heavy_blocks_are_the_session_end_and_the_election() {
	with_ext(|| {
		let boundary = 3 * SESSION_PERIOD;
		assert!(StakingPayouts::is_heavy_block(boundary));
		assert!(!StakingPayouts::is_heavy_block(boundary - 1));
		assert!(!StakingPayouts::is_heavy_block(boundary + 1));
		for phase in [
			pallet_paged_election::Phase::Targets,
			pallet_paged_election::Phase::Voters(3),
			pallet_paged_election::Phase::Select,
			pallet_paged_election::Phase::Done,
		] {
			pallet_paged_election::CurrentPhase::<Runtime>::put(phase);
			assert!(StakingPayouts::is_heavy_block(boundary + 1), "{phase:?}");
		}
	});
}

fn nominator(n: u32) -> AccountId {
	let mut raw = [0x7au8; 32];
	raw[..4].copy_from_slice(&n.to_le_bytes());
	AccountId::from(raw)
}

/// `count` nominators backing `target`, each bonding 100 ORB.
fn nominate(count: u32, target: &AccountId) {
	for n in 0..count {
		let who = nominator(n);
		Balances::set_balance(&who, 1_000 * ORB);
		assert_ok!(<Staking as StakingInterface>::bond(&who, 100 * ORB, &who));
		assert_ok!(<Staking as StakingInterface>::nominate(
			&who,
			vec![target.clone()]
		));
	}
}

/// Runs `blocks` more blocks; transactions leave them empty, so `on_idle`
/// pays from most of each.
fn run_payout_blocks(blocks: u32) {
	let start = System::block_number() + 1;
	for n in start..start + blocks {
		run_block(n);
	}
}

fn payout_events() -> Vec<pallet_auto_payout::Event<Runtime>> {
	System::events()
		.into_iter()
		.filter_map(|r| match r.event {
			RuntimeEvent::AutoPayout(e) => Some(e),
			_ => None,
		})
		.collect()
}

/// Era 2 with Alice backed by 70 nominators (two pages), closed; the pallet
/// has seen eras 1 to 3. Era points come from the blocks each validator
/// authored, durations from their timestamps.
fn with_closed_era<R>(run: impl FnOnce(&[AccountId]) -> R) -> R {
	with_validators(|| {
		let validators: Vec<_> = [
			Sr25519Keyring::Alice,
			Sr25519Keyring::Bob,
			Sr25519Keyring::Charlie,
		]
		.into_iter()
		.map(account)
		.collect();
		nominate(70, &validators[0]);
		run_to_era(3);
		run(&validators)
	})
}

#[test]
fn a_page_already_claimed_is_reported_and_leaves_no_state() {
	with_closed_era(|validators| {
		let alice = &validators[0];
		assert_ok!(Staking::payout_stakers_by_page(
			RuntimeOrigin::signed(nominator(0)),
			alice.clone(),
			2,
			0
		));
		let root = sp_io::storage::root(sp_runtime::StateVersion::V1);
		let (outcome, weight) = StakingPayouts::pay(2, alice, 0);
		assert_eq!(outcome, PayoutOutcome::AlreadyPaid);
		assert!(weight.all_lte(StakingPayouts::page_weight(MAX_EXPOSURE_PAGE_SIZE)));
		assert_eq!(
			sp_io::storage::root(sp_runtime::StateVersion::V1),
			root,
			"a refused payout must not write"
		);
	});
}

#[test]
fn refusals_are_classified_by_how_far_they_reach() {
	with_closed_era(|validators| {
		let alice = &validators[0];
		let root = sp_io::storage::root(sp_runtime::StateVersion::V1);
		// An era staking does not pay (not closed yet): the whole era is unpayable.
		let (outcome, _) = StakingPayouts::pay(50, alice, 0);
		assert!(
			matches!(outcome, PayoutOutcome::EraUnpayable(_)),
			"{outcome:?}"
		);
		// A page past the validator's exposure: so is every later page.
		let (outcome, _) = StakingPayouts::pay(2, alice, 1_000);
		assert!(
			matches!(outcome, PayoutOutcome::ValidatorUnpayable(_)),
			"{outcome:?}"
		);
		assert_eq!(
			sp_io::storage::root(sp_runtime::StateVersion::V1),
			root,
			"a refused payout must not write"
		);
	});
	// A call the runtime filters waits: neither skipped nor dropped.
	assert_eq!(
		crate::staking::payouts::classify(2, frame_system::Error::<Runtime>::CallFiltered.into()).0,
		PayoutOutcome::Blocked
	);
}

#[test]
fn the_adapter_pages_exposures_as_staking_does() {
	with_closed_era(|validators| {
		let pages = StakingPayouts::era_validators(2, MAX_ACTIVE_VALIDATORS);
		assert_eq!(pages.len(), validators.len());
		let alice = pages
			.iter()
			.find(|v| v.stash == validators[0])
			.expect("Alice");
		assert_eq!((alice.pages, alice.nominators), (2, 70));
		assert!(pages
			.iter()
			.filter(|v| v.stash != validators[0])
			.all(|v| v.pages == 1 && v.nominators == 0));
	});
}

// End to end

#[test]
fn closed_eras_are_paid_to_every_destination_without_claims() {
	with_closed_era(|validators| {
		// Three nominators, three destinations.
		let staked = nominator(1);
		let stash = nominator(2);
		let (elsewhere, receiver) = (nominator(3), AccountId::from([0x99; 32]));
		assert_ok!(Staking::set_payee(
			RuntimeOrigin::signed(staked.clone()),
			RewardDestination::Staked
		));
		assert_ok!(Staking::set_payee(
			RuntimeOrigin::signed(stash.clone()),
			RewardDestination::Stash
		));
		assert_ok!(Staking::set_payee(
			RuntimeOrigin::signed(elsewhere.clone()),
			RewardDestination::Account(receiver.clone())
		));
		let active_before = <Staking as StakingInterface>::stake(&staked)
			.unwrap()
			.active;
		let free_before = Balances::balance(&stash);
		// One page claimed by hand first: the pallet must skip it quietly.
		assert_ok!(Staking::payout_stakers_by_page(
			RuntimeOrigin::signed(nominator(0)),
			validators[1].clone(),
			2,
			0
		));

		run_payout_blocks(50);

		for era in [1, 2] {
			for v in validators {
				assert!(
					!Staking::api_pending_rewards(era, v.clone()),
					"era {era} still pending for {v:?}"
				);
			}
		}
		assert!(
			<Staking as StakingInterface>::stake(&staked)
				.unwrap()
				.active > active_before
		);
		assert!(Balances::balance(&stash) > free_before);
		assert!(Balances::balance(&receiver) > 0);
		assert!(pallet_auto_payout::Current::<Runtime>::get().is_none());
		assert!(pallet_auto_payout::Queue::<Runtime>::get().is_empty());
		let events = payout_events();
		assert!(events.contains(&pallet_auto_payout::Event::EraPaid {
			era: 2,
			blocks: events
				.iter()
				.find_map(|e| match e {
					pallet_auto_payout::Event::EraPaid { era: 2, blocks } => Some(*blocks),
					_ => None,
				})
				.unwrap()
		}));
		assert!(
			!events
				.iter()
				.any(|e| matches!(e, pallet_auto_payout::Event::PayoutSkipped { .. })),
			"nothing refused: {events:?}"
		);
	});
}

#[test]
fn paused_payouts_leave_manual_claims_working() {
	with_closed_era(|validators| {
		assert_ok!(AutoPayout::pause(RuntimeOrigin::root()));
		run_payout_blocks(20);
		assert!(Staking::api_pending_rewards(2, validators[0].clone()));
		for page in 0..2 {
			assert_ok!(Staking::payout_stakers_by_page(
				RuntimeOrigin::signed(nominator(0)),
				validators[0].clone(),
				2,
				page
			));
		}
		assert!(!Staking::api_pending_rewards(2, validators[0].clone()));
	});
}

#[test]
fn only_root_changes_the_limits() {
	with_validators(|| {
		assert!(AutoPayout::pause(RuntimeOrigin::signed(nominator(0))).is_err());
		assert!(AutoPayout::set_limits(
			RuntimeOrigin::signed(nominator(0)),
			DefaultPayoutLimits::get()
		)
		.is_err());
		assert_ok!(AutoPayout::set_limits(
			RuntimeOrigin::root(),
			DefaultPayoutLimits::get()
		));
	});
}

#[test]
fn the_payout_account_never_needs_funds() {
	with_closed_era(|_| {
		run_payout_blocks(50);
		assert_eq!(
			Balances::total_balance(&crate::economy::AutoPayoutAccount::get()),
			0
		);
	});
}

/// Staking refuses a validator without an exposure with the same error as an
/// era it no longer pays: only that validator is skipped.
#[test]
fn missing_overview_skips_only_that_validator() {
	with_closed_era(|validators| {
		let (alice, bob, charlie) = (&validators[0], &validators[1], &validators[2]);
		pallet_staking_async::ErasStakersOverview::<Runtime>::remove(2, alice);
		let root = sp_io::storage::root(sp_runtime::StateVersion::V1);
		let (outcome, _) = StakingPayouts::pay(2, alice, 0);
		assert!(
			matches!(outcome, PayoutOutcome::ValidatorUnpayable(_)),
			"{outcome:?}"
		);
		assert_eq!(sp_io::storage::root(sp_runtime::StateVersion::V1), root);
		assert_eq!(StakingPayouts::pay(2, bob, 0).0, PayoutOutcome::Paid);
		// Without the era's reward, the era itself is unpayable.
		pallet_staking_async::ErasValidatorReward::<Runtime>::remove(2);
		let (outcome, _) = StakingPayouts::pay(2, charlie, 0);
		assert!(
			matches!(outcome, PayoutOutcome::EraUnpayable(_)),
			"{outcome:?}"
		);
	});
}

fn skipped(era: u32) -> Vec<AccountId> {
	payout_events()
		.into_iter()
		.filter_map(|e| match e {
			pallet_auto_payout::Event::PayoutSkipped {
				era: e, validator, ..
			} if e == era => Some(validator),
			_ => None,
		})
		.collect()
}

fn era_paid(era: u32) -> bool {
	payout_events()
		.iter()
		.any(|e| matches!(e, pallet_auto_payout::Event::EraPaid { era: e, .. } if *e == era))
}

/// Whether every page of `who` in `era` was claimed. Unlike staking's
/// `api_pending_rewards`, counts the page of a validator without nominators.
fn paid_out(era: u32, who: &AccountId) -> bool {
	let pages = StakingPayouts::era_validators(era, MAX_ACTIVE_VALIDATORS)
		.into_iter()
		.find(|v| v.stash == *who)
		.map_or(0, |v| v.pages);
	pages > 0
		&& pallet_staking_async::ClaimedRewards::<Runtime>::get(era, who).len() as u32 == pages
}

/// Runs blocks until nothing waits to be paid, at most `max`.
pub(super) fn pay_everything(max: u32) {
	for _ in 0..max {
		if pallet_auto_payout::Current::<Runtime>::get().is_none()
			&& pallet_auto_payout::Queue::<Runtime>::get().is_empty()
		{
			return;
		}
		run_block(System::block_number() + 1);
	}
	panic!("eras still waiting after {max} blocks");
}

/// A validator that leaves staking between its era's close and the payment is
/// skipped with one event; the rest of the era is paid.
#[test]
fn a_reaped_validator_is_skipped_once_and_the_others_are_paid() {
	with_closed_era(|validators| {
		let bob = &validators[1];
		assert_ok!(Staking::force_unstake(
			RuntimeOrigin::root(),
			bob.clone(),
			0
		));
		pay_everything(50);
		assert_eq!(skipped(2), vec![bob.clone()]);
		for v in [&validators[0], &validators[2]] {
			assert!(paid_out(2, v), "{v:?}");
		}
		assert!(!paid_out(2, bob));
		assert!(era_paid(2));
	});
}

/// A validator with no era points is paid nothing, and the era goes on.
#[test]
fn a_validator_without_points_gets_nothing_and_the_run_goes_on() {
	with_closed_era(|validators| {
		let charlie = &validators[2];
		for era in [1, 2] {
			pallet_staking_async::ErasRewardPoints::<Runtime>::mutate(era, |points| {
				let lost = points.individual.remove(charlie).unwrap_or(0);
				points.total -= lost;
			});
		}
		let before = Balances::total_balance(charlie);
		pay_everything(50);
		assert_eq!(Balances::total_balance(charlie), before);
		for v in validators {
			assert!(paid_out(2, v), "{v:?}");
		}
		assert!(skipped(2).is_empty());
		assert!(era_paid(2));
	});
}

/// An election that fails keeps the election's blocks heavy, so nothing is
/// paid or pruned; both resume once the plan is reset and the era starts.
#[test]
fn payouts_resume_after_a_failed_election() {
	use pallet_staking_async::{EraPruningState, PruningStep};
	with_validators(|| {
		let alice = account(Sr25519Keyring::Alice);
		assert_ok!(AutoPayout::pause(RuntimeOrigin::root()));
		run_to_era(2);
		// Era 0 is past the history from the start: prunable.
		EraPruningState::<Runtime>::insert(0, PruningStep::ErasStakersPaged);
		for _ in 0..2 * SESSIONS_PER_ERA {
			if pallet_staking_async::CurrentEra::<Runtime>::get() == Some(3) {
				break;
			}
			crate::test_utils::blocks::next_session();
		}
		let phase = pallet_paged_election::CurrentPhase::<Runtime>::get;
		assert!(phase().is_computing());
		assert_ok!(AutoPayout::resume(RuntimeOrigin::root()));
		assert_ok!(crate::PagedElection::abort(RuntimeOrigin::root()));

		run_block(System::block_number() + 1);
		assert_ne!(phase(), pallet_paged_election::Phase::Off);
		assert!(!paid_out(1, &alice));
		assert!(EraPruningState::<Runtime>::contains_key(0));

		run_to_era(3);
		assert!(System::events().iter().any(|r| r.event
			== RuntimeEvent::PagedElection(pallet_paged_election::Event::EraPlanReset { era: 3 })));
		pay_everything(50);
		for era in [1, 2] {
			assert!(paid_out(era, &alice), "era {era}");
		}
		for _ in 0..20 {
			if !EraPruningState::<Runtime>::contains_key(0) {
				break;
			}
			run_block(System::block_number() + 1);
		}
		assert!(!EraPruningState::<Runtime>::contains_key(0));
		assert!(!payout_events()
			.iter()
			.any(|e| matches!(e, pallet_auto_payout::Event::EraExpired { .. })));
	});
}

/// Fees are burned when their era closes and minted again only as its pages
/// are paid. Paying every era mints at most their rewards; what is never minted
/// is rounding, which staking does with `Perbill` shares (of the era's reward
/// per validator, then of the validator's per page and per nominator). Each
/// share can lose up to a billionth of what it divides, plus one unit, so the
/// bound is a billionth of the rewards per share rather than one unit per page.
#[test]
fn issuance_is_conserved_across_a_paid_era() {
	use pallet_staking_async::ErasValidatorReward;
	with_validators(|| {
		let alice = account(Sr25519Keyring::Alice);
		nominate(70, &alice);
		assert_ok!(AutoPayout::pause(RuntimeOrigin::root()));
		run_to_era(2);
		let fees = 1_000 * ORB;
		assert_ok!(Balances::mint_into(
			&crate::economy::EraFeePoolAccount::get(),
			fees
		));
		let before = Balances::total_issuance();
		run_to_era(3);
		let closed = Balances::total_issuance();
		assert_eq!(before - closed, fees, "the pool is burned at the close");
		let rewards = ErasValidatorReward::<Runtime>::get(1).unwrap_or(0)
			+ ErasValidatorReward::<Runtime>::get(2).expect("era 2 has a reward");
		assert!(ErasValidatorReward::<Runtime>::get(2).unwrap() >= fees);

		assert_ok!(AutoPayout::resume(RuntimeOrigin::root()));
		pay_everything(50);
		assert_eq!(crate::test_utils::blocks::active_era(), 3);
		let minted = Balances::total_issuance() - closed;
		assert!(
			minted <= rewards,
			"minted {minted} over the rewards {rewards}"
		);
		// Two eras of three validators (validator and commission splits), four
		// pages and seventy nominators.
		let shares: u128 = 2 * (2 * 3 + 4 + 70);
		let dust = rewards - minted;
		assert!(
			dust <= shares * (rewards / 1_000_000_000 + 1),
			"{dust} never minted of {rewards}"
		);
	});
}

/// A closed era's reward is its share of the yearly schedule for the time it
/// lasted, plus its fees: one day in year 1 is 45M ORB / 365.
#[test]
fn an_era_reward_is_its_share_of_the_schedule() {
	use crate::economy::{
		schedule::{era_issuance, TokenomicsSchedule},
		EraFeePoolAccount,
	};
	use crate::primitives::constants::DAY_MS;
	use pallet_staking_async::{ActiveEra, ErasValidatorReward};
	let start = || {
		ActiveEra::<Runtime>::get()
			.and_then(|era| era.start)
			.unwrap()
	};
	with_validators(|| {
		assert_ok!(AutoPayout::pause(RuntimeOrigin::root()));
		run_to_era(2);
		let began = start();
		let fees = 1_000 * ORB;
		assert_ok!(Balances::mint_into(&EraFeePoolAccount::get(), fees));
		run_to_era(3);

		let lasted = start() - began;
		#[cfg(not(feature = "fast-runtime"))]
		assert_eq!(lasted, DAY_MS);
		let scheduled = era_issuance::<TokenomicsSchedule>(0, lasted);
		assert_eq!(
			scheduled,
			45_000_000 * ORB * u128::from(lasted) / u128::from(365 * DAY_MS)
		);
		assert_eq!(
			ErasValidatorReward::<Runtime>::get(2),
			Some(scheduled + fees)
		);
	});
}

/// A block's own weight never makes it heavy: what automatic payment spent in
/// `on_initialize` must not keep `on_idle` from paying more.
#[test]
fn weight_already_spent_does_not_make_a_block_heavy() {
	use crate::staking::HeavyBlocks;
	use frame_support::{dispatch::DispatchClass, traits::Contains};
	crate::test_utils::with_ext(|| {
		let n = 5;
		frame_system::Pallet::<Runtime>::set_block_number(n);
		let max = <Runtime as frame_system::Config>::BlockWeights::get().max_block;
		frame_system::Pallet::<Runtime>::register_extra_weight_unchecked(
			sp_runtime::Perbill::from_percent(10) * max,
			DispatchClass::Mandatory,
		);
		assert!(!HeavyBlocks::contains(&n));
	});
}
