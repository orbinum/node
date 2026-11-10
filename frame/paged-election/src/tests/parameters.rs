//! `integrity_test`: each parameter the election cannot work with panics.

use crate::tests::mock::*;
use sp_runtime::Perbill;

fn check(set: impl FnOnce()) {
	set();
	PagedElection::check_parameters();
}

#[test]
fn the_mock_parameters_pass() {
	check(|| {});
}

#[test]
#[should_panic(expected = "Pages must be positive")]
fn no_pages() {
	check(|| Pages::set(0));
}

#[test]
#[should_panic(expected = "VoterSnapshotPerBlock must be positive")]
fn empty_voter_pages() {
	check(|| VoterSnapshotPerBlock::set(0));
}

#[test]
#[should_panic(expected = "MaxVotesPerVoter must be positive")]
fn no_votes() {
	check(|| MaxVotesPerVoter::set(0));
}

#[test]
#[should_panic(expected = "MaxTargets must be positive and fit a target index")]
fn no_targets() {
	check(|| MaxTargets::set(0));
}

#[test]
#[should_panic(expected = "MaxTargets must be positive and fit a target index")]
fn more_targets_than_an_index_holds() {
	check(|| MaxTargets::set(65_537));
}

#[test]
#[should_panic(expected = "MaxWinnersPerPage must be positive")]
fn no_winners() {
	check(|| MaxWinners::set(0));
}

#[test]
#[should_panic(expected = "MaxBackersPerWinner must hold a full voter page")]
fn backers_below_a_page() {
	check(|| MaxBackers::set(Some(VoterSnapshotPerBlock::get() - 1)));
}

#[test]
#[should_panic(expected = "MaxBackersPerWinnerFinal must hold every voter")]
fn final_backers_below_every_voter() {
	check(|| MaxBackersFinal::set(Some(Pages::get() * VoterSnapshotPerBlock::get() - 1)));
}

#[test]
#[should_panic(expected = "RoundBudget must fit the heaviest step")]
fn a_budget_below_the_heaviest_step() {
	check(|| RoundBudget::set(Perbill::from_parts(1)));
}

/// Clearing writes two keys per page: 20 000 pages do not fit a block.
#[test]
#[should_panic(expected = "a page export must fit a block")]
fn an_export_bigger_than_a_block() {
	check(|| Pages::set(20_000));
}
