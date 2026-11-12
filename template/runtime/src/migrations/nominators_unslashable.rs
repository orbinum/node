// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

//! Only validators are slashed (spec 22): a chain started before it turns
//! staking's `AreNominatorsSlashable` off, as genesis does for a new chain
//! (`staking::eras::pruning`).
//!
//! Nominators and pool members then unbond in `NOMINATOR_UNBOND_DURATION` eras
//! instead of `BONDING_DURATION`; an account that validated within the last
//! `BONDING_DURATION` eras still waits the full time. Staking copies the flag
//! into each era as it starts, so the eras already started keep their own: an
//! offence in one of them still slashes its nominators. Chunks already unbonding
//! keep their unlock era.
//!
//! Runs once per chain: governance may turn the flag back on afterwards
//! (`staking.set_staking_configs`), and a later upgrade must not undo that.

use super::db_weight;
use crate::Runtime;
use frame_support::{traits::OnRuntimeUpgrade, weights::Weight};

#[cfg(feature = "try-runtime")]
use alloc::vec::Vec;

/// Whether this migration has run on this chain.
#[frame_support::storage_alias]
pub type Done =
	StorageValue<OrbinumNominatorsUnslashable, bool, frame_support::storage::types::ValueQuery>;

/// See the module docs.
pub struct NominatorsUnslashable;

impl OnRuntimeUpgrade for NominatorsUnslashable {
	fn on_runtime_upgrade() -> Weight {
		if Done::get() {
			return db_weight(1, 0);
		}
		Done::put(true);
		pallet_staking_async::AreNominatorsSlashable::<Runtime>::put(false);
		db_weight(1, 2)
	}

	#[cfg(feature = "try-runtime")]
	fn post_upgrade(_: Vec<u8>) -> Result<(), sp_runtime::TryRuntimeError> {
		frame_support::ensure!(Done::get(), "the migration did not run");
		Ok(())
	}
}
