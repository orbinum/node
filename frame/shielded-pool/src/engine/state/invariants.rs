// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: GPL-3.0-or-later

//! What must hold after every block: checked by `try_state`.

use crate::{
	Config, Pallet, PendingFees, PoolBalancePerAsset, SealedRootIndex, SealedTreeRoots,
	storage::MerkleRepository,
};
use frame_support::traits::{Currency, Get};

impl<T: Config> Pallet<T> {
	/// Ledger-solvency invariant: the pool account's physical free balance
	/// covers the tracked native-asset pool balance. Fees stay physical in the
	/// pool until `claim_fees` pays them out, so both move together, and the
	/// pending fees never exceed the ledger that backs them. Anyone can send
	/// the pool account funds (a transfer, an EVM value transfer), so the
	/// physical balance may exceed the ledger; that surplus is a donation no
	/// note can spend.
	/// Only the native asset (0) is backed by `Currency`; other assets live in
	/// external backends — TODO: extend when a per-asset balance reader exists.
	pub(crate) fn do_try_state() -> Result<(), sp_runtime::TryRuntimeError> {
		let pool = Self::pool_account_id();
		let physical = T::Currency::free_balance(&pool);
		let tracked = PoolBalancePerAsset::<T>::get(0u32);
		frame_support::ensure!(
			tracked <= physical,
			sp_runtime::TryRuntimeError::Other(
				"shielded-pool native ledger exceeds the physical pool balance"
			)
		);
		let pending = PendingFees::<T>::iter()
			.filter(|(_, asset_id, _)| *asset_id == 0)
			.fold(0u128, |sum, (_, _, amount)| sum.saturating_add(amount));
		frame_support::ensure!(
			pending <= sp_runtime::SaturatedConversion::saturated_into::<u128>(tracked),
			sp_runtime::TryRuntimeError::Other(
				"shielded-pool pending fees exceed the native pool ledger"
			)
		);

		// Forest invariants: the active root must always be provable
		// against; one sealed root per completed tree; the sealed maps
		// are a bijection.
		frame_support::ensure!(
			MerkleRepository::is_known_root::<T>(&MerkleRepository::get_poseidon_root::<T>()),
			sp_runtime::TryRuntimeError::Other("PoseidonRoot not in known-roots set")
		);
		let sealed = SealedTreeRoots::<T>::iter().count() as u32;
		frame_support::ensure!(
			sealed == MerkleRepository::get_tree_size::<T>() / T::MaxLeavesPerTree::get(),
			sp_runtime::TryRuntimeError::Other("sealed-tree count != tree_size / cap")
		);
		for (tree_id, root) in SealedTreeRoots::<T>::iter() {
			frame_support::ensure!(
				SealedRootIndex::<T>::get(root) == Some(tree_id),
				sp_runtime::TryRuntimeError::Other("SealedRootIndex out of sync")
			);
		}
		Ok(())
	}
}
