// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

//! `NominatorsUnslashable`: a chain from before spec 22 stops slashing nominators,
//! once.

use crate::{migrations::NominatorsUnslashable, test_utils::with_ext, Runtime};
use frame_support::traits::OnRuntimeUpgrade;
use pallet_staking_async::AreNominatorsSlashable;

#[test]
fn turns_nominator_slashing_off_once() {
	with_ext(|| {
		// A spec 21 chain: staking's default, nominators slashable.
		AreNominatorsSlashable::<Runtime>::put(true);
		NominatorsUnslashable::on_runtime_upgrade();
		assert!(!AreNominatorsSlashable::<Runtime>::get());

		// Governance turns it back on; a later upgrade leaves that alone.
		AreNominatorsSlashable::<Runtime>::put(true);
		NominatorsUnslashable::on_runtime_upgrade();
		assert!(AreNominatorsSlashable::<Runtime>::get());
	});
}
