// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

//! What a block may hold: normal transactions get 75 % of the weight and 85 % of the
//! length; operational and mandatory work may use the whole block.

use crate::{
	configs::system::{BlockLength, BlockWeights},
	primitives::constants::{
		BLOCK_LENGTH_NORMAL_RATIO, MAXIMUM_BLOCK_LENGTH, MAXIMUM_BLOCK_WEIGHT,
		NORMAL_DISPATCH_RATIO,
	},
};
use frame_support::dispatch::DispatchClass;
use sp_runtime::Perbill;

#[test]
fn normal_transactions_get_85_percent_of_the_length() {
	assert_eq!(BLOCK_LENGTH_NORMAL_RATIO, Perbill::from_percent(85));
	let length = BlockLength::get().max;
	assert_eq!(
		*length.get(DispatchClass::Normal),
		BLOCK_LENGTH_NORMAL_RATIO * MAXIMUM_BLOCK_LENGTH
	);
	for class in [DispatchClass::Operational, DispatchClass::Mandatory] {
		assert_eq!(*length.get(class), MAXIMUM_BLOCK_LENGTH, "{class:?}");
	}
}

#[test]
fn normal_transactions_get_75_percent_of_the_weight() {
	let weights = BlockWeights::get();
	assert_eq!(weights.max_block, MAXIMUM_BLOCK_WEIGHT);
	let normal = weights
		.get(DispatchClass::Normal)
		.max_total
		.expect("normal is capped");
	assert_eq!(
		normal.ref_time(),
		(NORMAL_DISPATCH_RATIO * MAXIMUM_BLOCK_WEIGHT).ref_time()
	);
}
