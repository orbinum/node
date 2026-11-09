//! Noticing closed eras: queueing, expiring and the first sight.

use crate::{Current, Event, LastActiveEra, Paused, Queue, tests::mock::*};

#[test]
fn first_sight_records_the_era_and_queues_nothing() {
	new_test_ext().execute_with(|| {
		set_active_era(5);
		run_block(1, full());
		assert_eq!(LastActiveEra::<Test>::get(), Some(5));
		assert!(
			Queue::<Test>::get().is_empty(),
			"earlier eras are not known unpaid"
		);
	});
}

#[test]
fn no_active_era_does_nothing() {
	new_test_ext().execute_with(|| {
		run_block(1, quiet());
		assert_eq!(LastActiveEra::<Test>::get(), None);
		assert!(events().is_empty());
	});
}

#[test]
fn a_new_era_queues_the_one_that_closed() {
	new_test_ext().execute_with(|| {
		set_active_era(0);
		run_block(1, full());
		AutoPayout::pause(frame_system::RawOrigin::Root.into()).unwrap();
		set_active_era(1);
		run_block(2, full());
		assert_eq!(Queue::<Test>::get().into_inner(), vec![0]);
		assert!(events().contains(&Event::EraQueued { era: 0 }));
		run_block(3, full());
		assert_eq!(
			Queue::<Test>::get().len(),
			1,
			"the same era is not queued twice"
		);
	});
}

#[test]
fn skipped_eras_are_all_queued_in_order() {
	new_test_ext().execute_with(|| {
		set_active_era(2);
		run_block(1, full());
		AutoPayout::pause(frame_system::RawOrigin::Root.into()).unwrap();
		set_active_era(5);
		run_block(2, full());
		assert_eq!(Queue::<Test>::get().into_inner(), vec![2, 3, 4]);
	});
}

#[test]
fn eras_that_leave_history_unpaid_expire() {
	new_test_ext().execute_with(|| {
		set_active_era(0);
		run_block(1, full());
		// Paused, so nothing is paid while history moves on.
		AutoPayout::pause(frame_system::RawOrigin::Root.into()).unwrap();
		set_active_era(3);
		run_block(2, full());
		assert_eq!(Queue::<Test>::get().into_inner(), vec![0, 1, 2]);
		set_active_era(4 + HISTORY_DEPTH);
		run_block(3, full());
		assert!(
			Queue::<Test>::get().iter().all(|&era| era >= 4),
			"only eras within history"
		);
		// 0–2 were queued, 3 closed already out of history.
		for era in 0..4 {
			assert!(events().contains(&Event::EraExpired { era }), "era {era}");
		}
		// Era 4 is now the last one history keeps: the pause lifts so it is paid.
		assert!(events().contains(&Event::ResumedToAvoidExpiry { era: 4 }));
		assert!(!Paused::<Test>::get());
	});
}

#[test]
fn the_era_being_paid_expires_too() {
	new_test_ext().execute_with(|| {
		elect(0, &[(1, 40)]);
		set_active_era(0);
		run_block(1, full());
		set_active_era(1);
		run_block(2, Weight::from_parts(12_000_000, u64::MAX));
		assert_eq!(
			Current::<Test>::get().map(|s| s.era),
			Some(0),
			"started, not finished"
		);
		set_active_era(1 + HISTORY_DEPTH + 1);
		// Held, as only a call filter can hold it this close to expiry.
		Paused::<Test>::put(true);
		run_block(3, full());
		assert!(Current::<Test>::get().is_none());
		assert!(events().contains(&Event::EraExpired { era: 0 }));
	});
}

use frame_support::weights::Weight;
