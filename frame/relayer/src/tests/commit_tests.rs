//! Tests for relay commits.
//!
//! Covers:
//! - `record_relay_commits`   — registration gate, per-relayer quota, first write
//!   wins, all-or-nothing batches
//! - `take_committed_relayer` — earlier-block rule, earliest wins, ties, copied commits
//! - `on_initialize`          — expiry after `CommitTtl`, also across a TTL change
//! - `integrity_test`         — the `CommitTtl` lower bound

use crate::traits::RelayerInterface;
use crate::{
	CommitsByRelayer, Error, Event, RelayCommit, RelayCommits, mock::*, relay_commit_hash,
};
use frame_support::{assert_noop, assert_ok, traits::Hooks};
use sp_core::{H160, H256};

const OP: [u8; 32] = [0x11; 32];
const OTHER_OP: [u8; 32] = [0x22; 32];

/// Register accounts 1 and 2 as relayers; returns their EVM addresses.
fn two_relayers() -> (H160, H160) {
	set_mock_validator(1);
	set_mock_validator(2);
	let (a, ra) = register_with_proof(1, seeds::ALICE);
	let (b, rb) = register_with_proof(2, seeds::BOB);
	assert_ok!(ra);
	assert_ok!(rb);
	(a, b)
}

/// Records `commits` for `relayer` through the interface other pallets use.
fn record(relayer: &H160, commits: &[H256]) -> frame_support::dispatch::DispatchResult {
	crate::Pallet::<Test>::record_relay_commits(relayer, commits)
}

/// The account credited for the spend `op`, consuming its commits.
fn take(op: &[u8; 32]) -> Option<u64> {
	crate::Pallet::<Test>::take_committed_relayer(op)
}

/// The block `commit` was recorded in, if it is stored.
fn recorded(commit: H256) -> Option<u64> {
	RelayCommits::<Test>::get(commit).map(|c: RelayCommit<u64>| c.recorded_at)
}

/// Distinct placeholder commits, one per value in `range`.
fn commits(range: core::ops::Range<u64>) -> Vec<H256> {
	range.map(H256::from_low_u64_be).collect()
}

/// Moves to block `n` and runs its `on_initialize`.
fn run_to(n: u64) {
	System::set_block_number(n);
	crate::Pallet::<Test>::on_initialize(n);
}

// ─── record_relay_commits ────────────────────────────────────────────────────

#[test]
fn unregistered_address_cannot_commit() {
	new_test_ext().execute_with(|| {
		let stranger = H160::repeat_byte(0x99);
		assert_noop!(
			record(&stranger, &[relay_commit_hash(&OP, &stranger)]),
			Error::<Test>::NotRegistered
		);
	});
}

#[test]
fn commit_is_recorded_with_its_block_and_event() {
	new_test_ext().execute_with(|| {
		let (a, _) = two_relayers();
		let commit = relay_commit_hash(&OP, &a);
		assert_ok!(record(&a, &[commit]));
		assert_eq!(recorded(commit), Some(1));
		assert_eq!(
			CommitsByRelayer::<Test>::get(1 + CommitTtl::get(), 1).into_inner(),
			vec![commit]
		);
		System::assert_last_event(
			Event::RelayCommitted {
				relayer: a,
				count: 1,
			}
			.into(),
		);
	});
}

#[test]
fn existing_commit_keeps_its_earlier_block() {
	new_test_ext().execute_with(|| {
		let (a, _) = two_relayers();
		let commit = relay_commit_hash(&OP, &a);
		assert_ok!(record(&a, &[commit]));
		run_to(2);
		assert_ok!(record(&a, &[commit]));
		assert_eq!(recorded(commit), Some(1));
		assert!(CommitsByRelayer::<Test>::get(2 + CommitTtl::get(), 1).is_empty());
	});
}

#[test]
fn quota_is_per_relayer() {
	new_test_ext().execute_with(|| {
		let (a, b) = two_relayers();
		assert_ok!(record(&a, &commits(0..4)));
		assert_noop!(
			record(&a, &[H256::from_low_u64_be(100)]),
			Error::<Test>::TooManyCommits
		);
		// A full quota for one relayer does not lock the other out.
		assert_ok!(record(&b, &[H256::from_low_u64_be(200)]));
	});
}

#[test]
fn a_batch_with_nothing_new_writes_no_index_entry_and_no_event() {
	new_test_ext().execute_with(|| {
		let (a, _) = two_relayers();
		assert_ok!(record(&a, &commits(0..2)));
		run_to(2);
		System::reset_events();
		assert_ok!(record(&a, &commits(0..2)));
		assert_ok!(record(&a, &[]));
		assert!(!CommitsByRelayer::<Test>::contains_key(
			2 + CommitTtl::get(),
			1
		));
		assert!(System::events().is_empty());
	});
}

/// The quota belongs to the validator: rotating its relay address in the same
/// block does not reset it.
#[test]
fn rotating_the_relay_address_keeps_the_quota() {
	new_test_ext().execute_with(|| {
		let (a, _) = two_relayers();
		assert_ok!(record(&a, &commits(0..4)));
		assert_ok!(crate::Pallet::<Test>::unregister_relayer(
			RuntimeOrigin::signed(1)
		));
		let (c, registered) = register_with_proof(1, seeds::CAROL);
		assert_ok!(registered);
		assert_noop!(record(&c, &commits(10..11)), Error::<Test>::TooManyCommits);
	});
}

#[test]
fn a_batch_past_the_quota_writes_nothing() {
	new_test_ext().execute_with(|| {
		let (a, _) = two_relayers();
		assert_noop!(record(&a, &commits(0..5)), Error::<Test>::TooManyCommits);
		assert!(commits(0..5).iter().all(|c| recorded(*c).is_none()));
	});
}

#[test]
fn duplicates_and_present_commits_take_no_quota_and_are_not_counted() {
	new_test_ext().execute_with(|| {
		let (a, _) = two_relayers();
		assert_ok!(record(&a, &commits(0..2)));
		// Two present, one repeated: only 2 and 3 are new, within the quota of 4.
		let batch = [commits(0..4), commits(2..3)].concat();
		assert_ok!(record(&a, &batch));
		System::assert_last_event(
			Event::RelayCommitted {
				relayer: a,
				count: 2,
			}
			.into(),
		);
		assert_eq!(
			CommitsByRelayer::<Test>::get(1 + CommitTtl::get(), 1).len(),
			4
		);
	});
}

// ─── take_committed_relayer ──────────────────────────────────────────────────

#[test]
fn commit_from_earlier_block_credits_the_relayer_and_is_consumed() {
	new_test_ext().execute_with(|| {
		let (a, _) = two_relayers();
		let commit = relay_commit_hash(&OP, &a);
		assert_ok!(record(&a, &[commit]));
		run_to(2);
		assert_eq!(take(&OP), Some(1));
		assert!(!RelayCommits::<Test>::contains_key(commit));
		assert_eq!(take(&OP), None);
	});
}

#[test]
fn commit_from_the_same_block_is_ignored() {
	new_test_ext().execute_with(|| {
		let (a, _) = two_relayers();
		assert_ok!(record(&a, &[relay_commit_hash(&OP, &a)]));
		// Written in the block that spends: could have been placed after seeing it.
		assert_eq!(take(&OP), None);
	});
}

#[test]
fn copied_commit_credits_the_relayer_inside_the_hash() {
	new_test_ext().execute_with(|| {
		let (a, b) = two_relayers();
		// B front-runs A by writing A's commit first: it still names A.
		assert_ok!(record(&b, &[relay_commit_hash(&OP, &a)]));
		run_to(2);
		assert_eq!(take(&OP), Some(1));
	});
}

#[test]
fn earliest_commit_wins() {
	new_test_ext().execute_with(|| {
		let (a, b) = two_relayers();
		assert_ok!(record(&a, &[relay_commit_hash(&OP, &a)]));
		run_to(2);
		assert_ok!(record(&b, &[relay_commit_hash(&OP, &b)]));
		run_to(3);
		assert_eq!(take(&OP), Some(1));
		// The loser's commit is consumed too: the spend runs only once.
		assert!(!RelayCommits::<Test>::contains_key(relay_commit_hash(
			&OP, &b
		)));
	});
}

#[test]
fn commit_is_bound_to_its_operation() {
	new_test_ext().execute_with(|| {
		let (a, _) = two_relayers();
		assert_ok!(record(&a, &[relay_commit_hash(&OP, &a)]));
		run_to(2);
		assert_eq!(take(&OTHER_OP), None);
	});
}

#[test]
fn unregistered_relayer_is_not_credited() {
	new_test_ext().execute_with(|| {
		let (a, _) = two_relayers();
		assert_ok!(record(&a, &[relay_commit_hash(&OP, &a)]));
		assert!(crate::Pallet::<Test>::clear_relayer(&1).is_some());
		run_to(2);
		assert_eq!(take(&OP), None);
	});
}

#[test]
fn a_same_block_tie_credits_one_of_them_and_consumes_both() {
	new_test_ext().execute_with(|| {
		let (a, b) = two_relayers();
		assert_ok!(record(&a, &[relay_commit_hash(&OP, &a)]));
		assert_ok!(record(&b, &[relay_commit_hash(&OP, &b)]));
		run_to(2);
		// The lowest commit hash wins, whatever the registry's storage order.
		let (ha, hb) = (relay_commit_hash(&OP, &a), relay_commit_hash(&OP, &b));
		let expected = if ha < hb { 1 } else { 2 };
		assert_eq!(take(&OP), Some(expected));
		assert_eq!(recorded(relay_commit_hash(&OP, &a)), None);
		assert_eq!(recorded(relay_commit_hash(&OP, &b)), None);
	});
}

#[test]
fn the_tie_break_changes_with_the_spend() {
	new_test_ext().execute_with(|| {
		let (a, b) = two_relayers();
		// Across many spends each relayer wins some ties: no address wins them all.
		// The quota is 4 per relayer per block: 8 spends over two blocks.
		let mut wins = [0u32; 2];
		for i in 0..8u8 {
			if i == 4 {
				run_to(2);
			}
			let op = [i; 32];
			assert_ok!(record(&a, &[relay_commit_hash(&op, &a)]));
			assert_ok!(record(&b, &[relay_commit_hash(&op, &b)]));
		}
		run_to(3);
		for i in 0..8u8 {
			match take(&[i; 32]) {
				Some(1) => wins[0] += 1,
				Some(2) => wins[1] += 1,
				other => panic!("unexpected winner {other:?}"),
			}
		}
		assert!(wins[0] > 0 && wins[1] > 0, "{wins:?}");
	});
}

// ─── on_initialize (expiry) ──────────────────────────────────────────────────

#[test]
fn an_idle_block_is_weighed_as_pruning_nothing() {
	use crate::weights::WeightInfo;
	new_test_ext().execute_with(|| {
		two_relayers();
		assert_eq!(
			crate::Pallet::<Test>::on_initialize(1),
			<Test as crate::Config>::WeightInfo::prune_relay_commits(0, 0)
		);
	});
}

#[test]
fn commit_expires_after_ttl() {
	new_test_ext().execute_with(|| {
		let (a, _) = two_relayers();
		let commit = relay_commit_hash(&OP, &a);
		assert_ok!(record(&a, &[commit]));
		// Still usable in the last block before expiry (1 + CommitTtl - 1).
		run_to(1 + CommitTtl::get() - 1);
		assert!(RelayCommits::<Test>::contains_key(commit));
		run_to(1 + CommitTtl::get());
		assert!(!RelayCommits::<Test>::contains_key(commit));
		assert!(CommitsByRelayer::<Test>::get(1 + CommitTtl::get(), 1).is_empty());
		assert_eq!(take(&OP), None);
	});
}

#[test]
fn pruning_skips_commits_already_consumed() {
	new_test_ext().execute_with(|| {
		let (a, _) = two_relayers();
		let commit = relay_commit_hash(&OP, &a);
		assert_ok!(record(&a, &[commit]));
		run_to(2);
		assert_eq!(take(&OP), Some(1));
		// Re-recorded later: the old index entry must not delete the new commit.
		assert_ok!(record(&a, &[commit]));
		run_to(1 + CommitTtl::get());
		assert_eq!(recorded(commit), Some(2));
	});
}

#[test]
fn nothing_is_pruned_before_the_first_expiry() {
	new_test_ext().execute_with(|| {
		let (a, _) = two_relayers();
		assert_ok!(record(&a, &commits(0..2)));
		for n in 2..(1 + CommitTtl::get()) {
			run_to(n);
		}
		assert!(commits(0..2).iter().all(|c| recorded(*c) == Some(1)));
	});
}

#[test]
fn one_pass_prunes_every_relayer_that_expires() {
	new_test_ext().execute_with(|| {
		let (a, b) = two_relayers();
		assert_ok!(record(&a, &commits(0..3)));
		assert_ok!(record(&b, &commits(10..14)));
		let weight = crate::Pallet::<Test>::on_initialize(1 + CommitTtl::get());
		assert_eq!(weight, <() as crate::WeightInfo>::prune_relay_commits(2, 7));
		assert!(
			commits(0..3)
				.iter()
				.chain(&commits(10..14))
				.all(|c| recorded(*c).is_none())
		);
	});
}

#[test]
fn a_ttl_change_leaves_no_orphans() {
	new_test_ext().execute_with(|| {
		let (a, _) = two_relayers();
		assert_ok!(record(&a, &commits(0..1))); // expires at 1 + 5
		CommitTtl::set(&2);
		run_to(2);
		assert_ok!(record(&a, &commits(1..2))); // expires at 2 + 2

		run_to(4);
		assert_eq!(
			recorded(H256::from_low_u64_be(1)),
			None,
			"shorter TTL applies to new commits"
		);
		assert_eq!(
			recorded(H256::from_low_u64_be(0)),
			Some(1),
			"old commit keeps its expiry"
		);
		run_to(6);
		assert_eq!(recorded(H256::from_low_u64_be(0)), None);
		assert_eq!(CommitsByRelayer::<Test>::iter().count(), 0);
	});
}

// ─── integrity_test ──────────────────────────────────────────────────────────

#[test]
#[should_panic(expected = "CommitTtl must be at least 2 blocks")]
fn integrity_test_refuses_a_ttl_below_two() {
	new_test_ext().execute_with(|| {
		CommitTtl::set(&1);
		<crate::Pallet<Test> as Hooks<u64>>::integrity_test();
	});
}
