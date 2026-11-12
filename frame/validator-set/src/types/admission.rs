// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: GPL-3.0-or-later

//! The admission vocabulary: the mode, how long a ban lasts and why an account
//! may not validate.

use frame_support::pallet_prelude::*;

/// Whether the allowlist gates candidacy. Both modes still require a ban-free
/// account with session keys; the runtime adds the self-bond.
#[derive(
	Encode,
	Decode,
	DecodeWithMemTracking,
	MaxEncodedLen,
	TypeInfo,
	Clone,
	Copy,
	PartialEq,
	Eq,
	Debug,
	Default
)]
pub enum AdmissionMode {
	/// Only accounts in `ApprovedValidators` may validate.
	#[default]
	Permissioned,
	/// Any account may validate.
	Open,
}

/// How long a ban lasts.
#[derive(
	Encode,
	Decode,
	DecodeWithMemTracking,
	MaxEncodedLen,
	TypeInfo,
	Clone,
	Copy,
	PartialEq,
	Eq,
	Debug
)]
pub enum BanTerm<BlockNumber> {
	/// Banned until this block, exclusive.
	Until(BlockNumber),
	/// Banned until governance lifts it.
	Permanent,
}

impl<BlockNumber: PartialOrd + Copy> BanTerm<BlockNumber> {
	/// Whether the ban still holds at block `now`.
	pub fn active_at(&self, now: BlockNumber) -> bool {
		match self {
			Self::Until(end) => now < *end,
			Self::Permanent => true,
		}
	}

	/// The longer of two terms, so a new ban never shortens one in force.
	pub fn longest(self, other: Self) -> Self {
		match (self, other) {
			(Self::Permanent, _) | (_, Self::Permanent) => Self::Permanent,
			(Self::Until(a), Self::Until(b)) => Self::Until(if a >= b { a } else { b }),
		}
	}
}

/// Why an account may not validate, as far as this pallet can tell.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Inadmissible {
	/// Under a ban that has not expired.
	Banned,
	/// Not in `ApprovedValidators` while the mode is `Permissioned`.
	NotApproved,
	/// No session keys registered, so it could not author.
	NoSessionKeys,
}
