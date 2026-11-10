//! The expiry watchdog: warning before an unpaid era leaves history, and a
//! pause that cannot outlast it.

use crate::{Current, Event, Paused, Queue, tests::mock::*};

#[test]
fn a_forgotten_pause_lifts_before_an_era_expires() {
	new_test_ext().execute_with(|| {
		elect(0, &[(1, 4)]);
		set_active_era(0);
		run_block(1, full());
		AutoPayout::pause(frame_system::RawOrigin::Root.into()).unwrap();
		let mut n = 2;
		// Era 0 waits, paused, era after era, until it is `EXPIRY_MARGIN` from the end.
		for active in 1..HISTORY_DEPTH - EXPIRY_MARGIN {
			set_active_era(active);
			run_block(n, full());
			n += 1;
		}
		assert!(Paused::<Test>::get(), "still paused before the margin");
		assert!(
			!events()
				.iter()
				.any(|e| matches!(e, Event::ExpiryAtRisk { .. }))
		);
		set_active_era(HISTORY_DEPTH - EXPIRY_MARGIN);
		run_block(n, full());
		assert!(!Paused::<Test>::get());
		assert!(events().contains(&Event::ExpiryAtRisk {
			era: 0,
			eras_left: EXPIRY_MARGIN
		}));
		assert!(events().contains(&Event::ResumedToAvoidExpiry { era: 0 }));
		for b in n + 1..n + 1 + WINDOW {
			run_block(b, quiet());
			if Current::<Test>::get().is_none() && Queue::<Test>::get().is_empty() {
				break;
			}
		}
		// Paid before leaving history.
		assert_eq!(paid(), [(0, 1, 0)]);
		assert!(
			!events()
				.iter()
				.any(|e| matches!(e, Event::EraExpired { .. }))
		);
	});
}

#[test]
fn only_a_call_filter_can_hold_an_era_and_it_is_warned_each_era() {
	new_test_ext().execute_with(|| {
		elect(0, &[(1, 4)]);
		set_active_era(0);
		run_block(1, full());
		set_blocked(true);
		for active in 1..=HISTORY_DEPTH + 1 {
			set_active_era(active);
			run_block(u64::from(active) + 1, quiet());
		}
		let warnings: Vec<_> = events()
			.into_iter()
			.filter_map(|e| match e {
				Event::ExpiryAtRisk { era: 0, eras_left } => Some(eras_left),
				_ => None,
			})
			.collect();
		// Days of warning before the loss, one per era.
		assert_eq!(warnings, (0..=EXPIRY_MARGIN).rev().collect::<Vec<_>>());
		assert!(events().contains(&Event::EraExpired { era: 0 }));
		assert!(paid().is_empty());
	});
}

#[test]
fn a_healthy_chain_raises_no_expiry_warning() {
	new_test_ext().execute_with(|| {
		elect(0, &[(1, 4)]);
		set_active_era(0);
		run_block(1, full());
		for active in 1..=HISTORY_DEPTH * 2 {
			elect(active, &[(1, 4)]);
			set_active_era(active);
			for k in 0..5 {
				run_block(u64::from(active) * 10 + k, quiet());
			}
		}
		assert!(
			!events()
				.iter()
				.any(|e| matches!(e, Event::ExpiryAtRisk { .. }))
		);
	});
}

/// Planning the next era takes the oldest one out of staking's history before
/// the active era moves: it is dropped from the queue, not paid into a refusal.
#[test]
fn oldest_era_expires_when_next_era_is_planned() {
	new_test_ext().execute_with(|| {
		for era in 0..=HISTORY_DEPTH {
			elect(era, &[(1, 4)]);
		}
		set_active_era(0);
		run_block(1, full());
		// A heavy block: history moves on with nothing paid.
		set_heavy(2);
		set_active_era(HISTORY_DEPTH);
		run_block(2, full());
		assert_eq!(Queue::<Test>::get().first(), Some(&0));
		plan_era(HISTORY_DEPTH + 1);
		run_block(3, quiet());
		assert!(events().contains(&Event::EraExpired { era: 0 }));
		assert!(!tried(0), "era 0 cost a refused call");
		assert!(tried(1), "the next era is paid");
	});
}

/// With the next era planned, the oldest unpaid era has one era less in
/// staking's history than the active era alone would give it.
#[test]
fn expiry_counts_from_the_planned_era() {
	new_test_ext().execute_with(|| {
		elect(0, &[(1, 4)]);
		set_active_era(0);
		run_block(1, full());
		set_blocked(true);
		let active = HISTORY_DEPTH - EXPIRY_MARGIN - 1;
		set_active_era(active);
		plan_era(active + 1);
		run_block(2, full());
		assert!(events().contains(&Event::ExpiryAtRisk {
			era: 0,
			eras_left: EXPIRY_MARGIN
		}));
	});
}
