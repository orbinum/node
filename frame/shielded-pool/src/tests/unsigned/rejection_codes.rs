// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: GPL-3.0-or-later

//! The rejection codes are part of the pool's interface: their values never change.

use super::*;

/// Rejection codes reach wallets as bare `Custom(N)`, so they are
/// part of the observable interface: pin them here, and retire a number rather
/// than reuse it for a new meaning.
#[test]
fn rejection_codes_are_stable() {
	assert_eq!(codes::UNKNOWN_ROOT, 1);
	assert_eq!(codes::ALL_INPUTS_DUMMY, 2);
	assert_eq!(codes::INSUFFICIENT_POOL_BALANCE, 3);
	assert_eq!(codes::AMOUNT_OVERFLOW, 4);
	assert_eq!(codes::UNSUPPORTED_CIRCUIT_VERSION, 10);
	assert_eq!(codes::INVALID_MEMO, 11);
	assert_eq!(codes::INVALID_PROOF, 12);
	assert_eq!(codes::INVALID_SPEND, 13);
	assert_eq!(codes::INVALID_ACTION, 14);
	assert_eq!(codes::MEMO_FORMAT_OUTDATED, 15);
}

/// No two codes share a number: a wallet that branches on one must never act on
/// another's meaning.
#[test]
fn rejection_codes_are_unique() {
	let all = [
		codes::UNKNOWN_ROOT,
		codes::ALL_INPUTS_DUMMY,
		codes::INSUFFICIENT_POOL_BALANCE,
		codes::AMOUNT_OVERFLOW,
		codes::UNSUPPORTED_CIRCUIT_VERSION,
		codes::INVALID_MEMO,
		codes::INVALID_PROOF,
		codes::INVALID_SPEND,
		codes::INVALID_ACTION,
		codes::MEMO_FORMAT_OUTDATED,
	];
	let mut sorted = all.to_vec();
	sorted.sort_unstable();
	sorted.dedup();
	assert_eq!(
		sorted.len(),
		all.len(),
		"duplicate rejection code in {all:?}"
	);
}
