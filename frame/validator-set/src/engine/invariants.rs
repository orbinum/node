// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: GPL-3.0-or-later

//! What must hold between blocks: checked by `try_state` and by the tests.

use crate::{ApprovedValidators, AuthorVersionNoted, Config, Pallet};
use alloc::collections::BTreeSet;
use frame_support::ensure;

impl<T: Config> Pallet<T> {
	pub(crate) fn do_try_state() -> Result<(), sp_runtime::TryRuntimeError> {
		let approved = ApprovedValidators::<T>::get();
		let unique: BTreeSet<_> = approved.iter().collect();
		ensure!(
			unique.len() == approved.len(),
			"the allowlist holds an account twice"
		);
		ensure!(
			!AuthorVersionNoted::<T>::get(),
			"a block's version declaration outlived its block"
		);
		Ok(())
	}
}
