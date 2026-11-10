//! Walking an era's pages.

use crate::{
	EraState, ValidatorPages,
	tests::mock::{AccountId, page_weight},
};
use core::cell::Cell;
use frame_support::{BoundedVec, traits::ConstU32};

type State = EraState<AccountId, u64, ConstU32<8>>;

fn validator(stash: AccountId, pages: u32, nominators: u32) -> ValidatorPages<AccountId> {
	ValidatorPages {
		stash,
		pages,
		nominators,
	}
}

fn state(validators: Vec<ValidatorPages<AccountId>>) -> State {
	EraState::new(7, BoundedVec::truncate_from(validators), 1, 4, page_weight)
}

#[test]
fn full_pages_first_then_the_remainder() {
	let v = validator(1, 3, 10);
	assert_eq!(
		(0..4).map(|p| v.nominators_on(p, 4)).collect::<Vec<_>>(),
		[4, 4, 2, 0]
	);
	assert_eq!(validator(1, 1, 0).nominators_on(0, 4), 0);
	assert_eq!(
		validator(1, 1, 3).nominators_on(u32::MAX, 4),
		0,
		"no overflow"
	);
}

#[test]
fn new_prices_every_page_and_drops_validators_without_pages() {
	let s = state(vec![
		validator(1, 3, 10),
		validator(2, 0, 0),
		validator(3, 1, 0),
	]);
	assert_eq!(s.validators.len(), 2);
	let expect = [4, 4, 2, 0].iter().take(3).chain([0].iter());
	let work: u64 = expect.map(|&n| page_weight(n).ref_time()).sum();
	assert_eq!(s.work, work);
	assert_eq!(s.pages(), 4);
	assert_eq!((s.done, s.validator, s.page), (0, 0, 0));
}

#[test]
fn advance_walks_pages_then_validators() {
	let mut s = state(vec![validator(1, 2, 5), validator(2, 1, 0)]);
	let mut seen = vec![];
	while let Some((v, page)) = s.next() {
		seen.push((v.stash, page));
		s.advance(1);
	}
	assert_eq!(seen, [(1, 0), (1, 1), (2, 0)]);
	assert!(s.is_done());
	assert_eq!(s.done, 3);
}

#[test]
fn progress_never_exceeds_the_work() {
	let mut s = state(vec![validator(1, 1, 0)]);
	s.advance(u64::MAX);
	assert_eq!(s.done, s.work);
	s.advance(1);
	assert!(s.is_done(), "advancing past the end stays done");
}

#[test]
fn an_era_without_validators_is_done_at_once() {
	let s = state(vec![]);
	assert!(s.is_done());
	assert_eq!(s.work, 0);
}

#[test]
fn work_matches_pricing_page_by_page() {
	for page_size in [0, 1, 4] {
		for nominators in 0..30 {
			for pages in 0..10 {
				let v = validator(1, pages, nominators);
				for from in 0..=pages + 1 {
					let by_page: u64 = (from..pages)
						.map(|p| page_weight(v.nominators_on(p, page_size)).ref_time())
						.sum();
					assert_eq!(
						v.work(from, page_size, page_weight),
						by_page,
						"size {page_size}, {nominators} nominators, pages {from}..{pages}"
					);
				}
			}
		}
	}
}

/// Starting or skipping a validator prices its pages with a few calls, however
/// many pages it has: the CPU of starting an era is bounded by its validators.
#[test]
fn pricing_an_era_does_not_walk_its_pages() {
	let calls = Cell::new(0u32);
	let counted = |n| {
		calls.set(calls.get() + 1);
		page_weight(n)
	};
	let pages = 25_000;
	let mut s = State::new(
		7,
		BoundedVec::truncate_from(vec![validator(1, pages, pages * 4 - 1), validator(2, 1, 0)]),
		1,
		4,
		counted,
	);
	assert!(calls.get() <= 2 * 3, "{} calls", calls.get());
	let expect = page_weight(4).ref_time() * u64::from(pages - 1)
		+ page_weight(3).ref_time()
		+ page_weight(0).ref_time();
	assert_eq!(s.work, expect);

	s.advance(page_weight(4).ref_time());
	calls.set(0);
	s.skip_validator(4, counted);
	assert!(calls.get() <= 3, "{} calls", calls.get());
	assert_eq!(s.done, expect - page_weight(0).ref_time());
	assert_eq!(s.next().map(|(v, p)| (v.stash, p)), Some((2, 0)));
}

#[test]
fn start_weight_covers_pricing_every_validator() {
	use crate::{Config, engine::START_CPU_PER_VALIDATOR, tests::mock::*};
	use frame_support::traits::Get;
	new_test_ext().execute_with(|| {
		let validators: u64 = <<Test as Config>::MaxValidators as Get<u32>>::get().into();
		let reads = TestDbWeight::get().reads(validators + 3);
		let cpu = START_CPU_PER_VALIDATOR.saturating_mul(validators);
		let start = AutoPayout::start_weight();
		assert!(start.all_gte(reads + cpu), "{start:?}");
		assert!(AutoPayout::largest_step().all_gte(start));
	});
}
