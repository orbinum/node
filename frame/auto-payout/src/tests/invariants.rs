// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: GPL-3.0-or-later

//! The invariants `try_state` checks.

use crate::{Current, EraIndex, Queue, tests::mock::*};
use frame_support::storage::unhashed;

/// A value that no longer decodes reads as the default (an empty queue, no era
/// being paid): `try_state` must catch it instead of eras vanishing.
#[test]
fn auto_payout_state_decodes() {
	new_test_ext().execute_with(|| {
		assert!(AutoPayout::do_try_state().is_ok());
		// A queue longer than its bound, as after lowering `MaxQueuedEras`.
		let long: Vec<EraIndex> = (0..=HISTORY_DEPTH).collect();
		unhashed::put(&Queue::<Test>::hashed_key(), &long);
		assert!(Queue::<Test>::get().is_empty(), "reads as empty");
		assert!(AutoPayout::do_try_state().is_err());
	});
	new_test_ext().execute_with(|| {
		unhashed::put_raw(&Current::<Test>::hashed_key(), &[0xff; 3]);
		assert!(Current::<Test>::get().is_none(), "reads as nothing");
		assert!(AutoPayout::do_try_state().is_err());
	});
}
