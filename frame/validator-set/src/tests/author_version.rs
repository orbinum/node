//! Minimum author version: declarations, the block check and the quorum.

use super::*;
use crate::{
	AuthorVersionNoted, LastAuthorVersion, MinAuthorVersion, NodeVersion,
	author_version::INHERENT_IDENTIFIER,
};
use frame_support::{
	inherent::{InherentData, ProvideInherent},
	traits::Hooks,
};

const V: fn(u16, u16, u16) -> NodeVersion = NodeVersion::new;

/// `who` authors the current block declaring `version`, as its node's inherent would.
fn author_declares(
	who: AccountId,
	version: NodeVersion,
) -> frame_support::dispatch::DispatchResult {
	set_block_author(Some(who));
	ValidatorSet::note_author_version(RuntimeOrigin::none(), version)
}

fn finalize() {
	ValidatorSet::on_finalize(System::block_number());
}

fn next_block() {
	System::set_block_number(System::block_number() + 1);
}

/// Each of `who` authors a block declaring `version`.
fn all_declare(who: &[AccountId], version: NodeVersion) {
	for &v in who {
		assert_ok!(author_declares(v, version));
		finalize();
		next_block();
	}
}

// ── note_author_version ──────────────────────────────────────────────────

#[test]
fn records_the_authors_version_and_block() {
	ExtBuilder::default().build().execute_with(|| {
		assert_ok!(author_declares(1, V(0, 4, 0)));
		assert_eq!(LastAuthorVersion::<Test>::get(1), Some((V(0, 4, 0), 1)));
		assert!(AuthorVersionNoted::<Test>::get());
	});
}

#[test]
fn a_non_approved_author_is_not_recorded() {
	ExtBuilder::default().build().execute_with(|| {
		assert_ok!(author_declares(99, V(0, 4, 0)));
		assert!(AuthorVersionNoted::<Test>::get());
		assert_eq!(LastAuthorVersion::<Test>::get(99), None);
	});
}

#[test]
fn leaving_the_set_drops_the_declaration() {
	ExtBuilder::default().build().execute_with(|| {
		all_declare(&[1, 2], V(0, 4, 0));
		assert_ok!(ValidatorSet::remove_validator(RuntimeOrigin::root(), 1));
		assert_ok!(ValidatorSet::deregister_validator(RuntimeOrigin::signed(2)));
		assert_eq!(LastAuthorVersion::<Test>::get(1), None);
		assert_eq!(LastAuthorVersion::<Test>::get(2), None);
	});
}

#[test]
fn an_author_that_stops_declaring_no_longer_counts() {
	ExtBuilder::default()
		.validators(vec![10, 20, 30, 40])
		.build()
		.execute_with(|| {
			all_declare(&[10, 20, 30], V(0, 4, 0));
			// 30 rolls back to a binary that declares nothing.
			set_block_author(Some(30));
			finalize();
			next_block();
			assert_eq!(LastAuthorVersion::<Test>::get(30), None);
			assert_noop!(
				ValidatorSet::set_min_author_version(RuntimeOrigin::root(), Some(V(0, 4, 0))),
				Error::<Test>::VersionQuorumNotMet
			);
		});
}

#[test]
fn is_an_inherent_not_a_signed_call() {
	ExtBuilder::default().build().execute_with(|| {
		assert!(ValidatorSet::note_author_version(RuntimeOrigin::signed(1), V(0, 4, 0)).is_err());
		assert!(ValidatorSet::note_author_version(RuntimeOrigin::root(), V(0, 4, 0)).is_err());
	});
}

#[test]
fn is_declared_at_most_once_per_block() {
	ExtBuilder::default().build().execute_with(|| {
		assert_ok!(author_declares(1, V(0, 4, 0)));
		assert_noop!(
			author_declares(1, V(0, 4, 0)),
			Error::<Test>::AuthorVersionAlreadyNoted
		);
		finalize();
		next_block();
		assert_ok!(author_declares(1, V(0, 4, 0)));
	});
}

#[test]
fn a_version_below_the_minimum_is_refused_equal_or_newer_accepted() {
	ExtBuilder::default().build().execute_with(|| {
		MinAuthorVersion::<Test>::put(V(0, 4, 0));
		for older in [V(0, 3, 9), V(0, 3, 0), V(0, 0, 9)] {
			assert_noop!(
				author_declares(1, older),
				Error::<Test>::AuthorVersionTooOld
			);
		}
		for ok in [V(0, 4, 0), V(0, 4, 1), V(0, 5, 0), V(1, 0, 0)] {
			assert_ok!(author_declares(1, ok));
			AuthorVersionNoted::<Test>::kill();
		}
	});
}

// ── on_finalize ──────────────────────────────────────────────────────────

#[test]
fn without_a_minimum_a_block_needs_no_declaration() {
	ExtBuilder::default().build().execute_with(|| {
		finalize(); // no panic: an old binary may author
	});
}

#[test]
#[should_panic(expected = "block author declared no node version")]
fn with_a_minimum_a_block_without_declaration_is_invalid() {
	ExtBuilder::default().build().execute_with(|| {
		MinAuthorVersion::<Test>::put(V(0, 4, 0));
		finalize();
	});
}

#[test]
fn with_a_minimum_a_declared_block_finalises_and_the_flag_clears() {
	ExtBuilder::default().build().execute_with(|| {
		MinAuthorVersion::<Test>::put(V(0, 4, 0));
		assert_ok!(author_declares(1, V(0, 4, 0)));
		finalize();
		assert!(!AuthorVersionNoted::<Test>::get());
	});
}

// ── set_min_author_version ───────────────────────────────────────────────

#[test]
fn only_the_add_remove_origin_sets_it() {
	ExtBuilder::default()
		.validators(vec![])
		.build()
		.execute_with(|| {
			assert!(
				ValidatorSet::set_min_author_version(RuntimeOrigin::signed(1), Some(V(0, 4, 0)))
					.is_err()
			);
		});
}

#[test]
fn sets_with_two_thirds_of_the_set_ready_and_emits_the_event() {
	ExtBuilder::default()
		.validators(vec![10, 20, 30, 40])
		.build()
		.execute_with(|| {
			all_declare(&[10, 20, 30], V(0, 4, 0));
			assert_ok!(ValidatorSet::set_min_author_version(
				RuntimeOrigin::root(),
				Some(V(0, 4, 0))
			));
			assert_eq!(MinAuthorVersion::<Test>::get(), Some(V(0, 4, 0)));
			System::assert_last_event(
				Event::MinAuthorVersionSet {
					version: Some(V(0, 4, 0)),
				}
				.into(),
			);
		});
}

#[test]
fn is_refused_without_quorum() {
	ExtBuilder::default()
		.validators(vec![10, 20, 30, 40])
		.build()
		.execute_with(|| {
			all_declare(&[10, 20], V(0, 4, 0));
			assert_noop!(
				ValidatorSet::set_min_author_version(RuntimeOrigin::root(), Some(V(0, 4, 0))),
				Error::<Test>::VersionQuorumNotMet
			);
		});
}

#[test]
fn older_declarations_do_not_count_toward_quorum() {
	ExtBuilder::default()
		.validators(vec![10, 20, 30, 40])
		.build()
		.execute_with(|| {
			all_declare(&[10, 20], V(0, 4, 0));
			all_declare(&[30], V(0, 3, 0));
			assert_noop!(
				ValidatorSet::set_min_author_version(RuntimeOrigin::root(), Some(V(0, 4, 0))),
				Error::<Test>::VersionQuorumNotMet
			);
		});
}

#[test]
fn stale_declarations_do_not_count_toward_quorum() {
	ExtBuilder::default()
		.validators(vec![10, 20, 30, 40])
		.build()
		.execute_with(|| {
			all_declare(&[10, 20, 30], V(0, 4, 0));
			// 30 declared at block 3; QuorumWindow is 100 in the mock.
			System::set_block_number(3 + QuorumWindow::get() + 1);
			all_declare(&[10, 20], V(0, 4, 0));
			assert_noop!(
				ValidatorSet::set_min_author_version(RuntimeOrigin::root(), Some(V(0, 4, 0))),
				Error::<Test>::VersionQuorumNotMet
			);
		});
}

#[test]
fn lifting_it_needs_no_quorum() {
	ExtBuilder::default()
		.validators(vec![10, 20, 30, 40])
		.build()
		.execute_with(|| {
			MinAuthorVersion::<Test>::put(V(9, 9, 9));
			assert_ok!(ValidatorSet::set_min_author_version(
				RuntimeOrigin::root(),
				None
			));
			assert_eq!(MinAuthorVersion::<Test>::get(), None);
			System::assert_last_event(Event::MinAuthorVersionSet { version: None }.into());
		});
}

#[test]
fn is_refused_for_an_empty_set() {
	ExtBuilder::default()
		.validators(vec![])
		.build()
		.execute_with(|| {
			assert_noop!(
				ValidatorSet::set_min_author_version(RuntimeOrigin::root(), Some(V(0, 4, 0))),
				Error::<Test>::VersionQuorumNotMet
			);
		});
}

// ── ProvideInherent ──────────────────────────────────────────────────────

#[test]
fn the_inherent_is_built_only_when_the_node_provides_a_version() {
	ExtBuilder::default().build().execute_with(|| {
		let mut data = InherentData::new();
		assert_eq!(ValidatorSet::create_inherent(&data), None);

		data.put_data(INHERENT_IDENTIFIER, &V(0, 4, 0)).unwrap();
		let call = ValidatorSet::create_inherent(&data).expect("version provided");
		assert!(ValidatorSet::is_inherent(&call));
		assert_eq!(
			call,
			crate::Call::note_author_version {
				version: V(0, 4, 0)
			}
		);
	});
}

#[test]
fn a_version_below_the_minimum_yields_no_inherent() {
	ExtBuilder::default().build().execute_with(|| {
		MinAuthorVersion::<Test>::put(V(0, 4, 0));
		let inherent_for = |version: NodeVersion| {
			let mut data = InherentData::new();
			data.put_data(INHERENT_IDENTIFIER, &version).unwrap();
			ValidatorSet::create_inherent(&data)
		};
		assert_eq!(inherent_for(V(0, 3, 9)), None);
		assert!(inherent_for(V(0, 4, 0)).is_some());
		assert!(inherent_for(V(1, 0, 0)).is_some());
	});
}
