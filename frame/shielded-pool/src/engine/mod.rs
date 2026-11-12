// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: GPL-3.0-or-later

//! The pallet's logic, one concern per module:
//!
//! - [`operations`]: the calls' workflows (shield, transfer, unshield, fees,
//!   the asset registry) and the public values a proof binds.
//! - [`unsigned`]: pool admission of the unsigned spends.
//! - [`merkle`]: the Poseidon tree, the forest of sealed trees, the
//!   historic-root window and the sealed-node sweep.
//! - [`storage`]: typed repositories over the storage items.
//! - [`state`]: the initial state and the invariants `try_state` checks.
//! - [`queries`]: the `Pallet` queries wallets and RPC use.
//!
//! This module holds the parameter checks of `integrity_test`.

pub mod merkle;
pub mod operations;
pub mod queries;
pub mod state;
pub mod storage;
pub mod unsigned;

use crate::{Config, Pallet};
use frame_support::traits::Get;

impl<T: Config> Pallet<T> {
	/// Panics on parameters the pallet cannot work with.
	pub(crate) fn check_parameters() {
		assert_eq!(
			T::MaxTreeDepth::get(),
			crate::types::MAX_TREE_DEPTH,
			"MaxTreeDepth config must equal the fixed tree depth (MAX_TREE_DEPTH)"
		);

		assert!(
			T::MaxHistoricRoots::get() > 0,
			"MaxHistoricRoots must be non-zero, otherwise no root can ever be stored"
		);

		// The retention window must outlive the mempool longevity an unsigned
		// transaction is admitted with, or a spend can pass validation, get
		// gossiped, and only revert once included.
		let retention: u64 = sp_runtime::traits::UniqueSaturatedInto::<u64>::unique_saturated_into(
			T::RootRetentionBlocks::get(),
		);
		assert!(
			retention > unsigned::TX_LONGEVITY,
			"RootRetentionBlocks must exceed TX_LONGEVITY, otherwise a root can \
			 expire while a transaction admitted against it is still valid in the pool"
		);

		// Level 0 is `MerkleLeaves` and never prunable; the top level is the
		// root itself. A cut outside that range would either prune nothing or
		// leave `get_merkle_path` with no stored node to start from.
		let cut = T::SealedTreePrunedBelowLevel::get();
		assert!(
			cut > 0 && (cut as usize) < crate::types::DEFAULT_TREE_DEPTH,
			"SealedTreePrunedBelowLevel must be in 1..DEFAULT_TREE_DEPTH"
		);
		// `get_subtree_roots` reads stored level-SUBTREE_LEVEL nodes; pruned under a
		// higher cut, every call would rebuild each from 64 leaves.
		assert!(
			cut <= crate::types::SUBTREE_LEVEL,
			"SealedTreePrunedBelowLevel must not exceed SUBTREE_LEVEL"
		);

		let cap = T::MaxLeavesPerTree::get();
		assert!(
			cap.is_power_of_two() && cap <= (1u32 << crate::types::MAX_TREE_DEPTH),
			"MaxLeavesPerTree must be a power of two <= 2^MAX_TREE_DEPTH; \
			 clients derive tree_id from the global leaf index using this \
			 constant, so it must never change on a live chain"
		);
	}
}
