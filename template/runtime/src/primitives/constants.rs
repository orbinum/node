// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

//! Time, token and block-size constants.

use crate::{Balance, BlockNumber};
use frame_support::weights::{constants::WEIGHT_REF_TIME_PER_MILLIS, Weight};
use sp_runtime::Perbill;

/// 1 ORB: 18 decimals, as ether.
pub const ORB: Balance = 1_000_000_000_000_000_000;

pub const MILLISECS_PER_BLOCK: u64 = 6000;
pub const SLOT_DURATION: u64 = MILLISECS_PER_BLOCK;
pub const MINUTES: BlockNumber = 60_000 / (MILLISECS_PER_BLOCK as BlockNumber);
pub const HOURS: BlockNumber = MINUTES * 60;
pub const DAYS: BlockNumber = HOURS * 24;

/// A day of wall-clock time, in milliseconds.
pub const DAY_MS: u64 = 24 * 60 * 60 * 1000;
/// A 365-day year, in milliseconds.
pub const YEAR_MS: u64 = 365 * DAY_MS;

pub const NORMAL_DISPATCH_RATIO: Perbill = Perbill::from_percent(75);
/// 2 s of compute per 6 s block.
pub const WEIGHT_MILLISECS_PER_BLOCK: u64 = 2000;
pub const MAXIMUM_BLOCK_WEIGHT: Weight = Weight::from_parts(
	WEIGHT_MILLISECS_PER_BLOCK * WEIGHT_REF_TIME_PER_MILLIS,
	u64::MAX,
);
/// 8 MiB: ISMP's GRANDPA consensus proofs do not fit in 5 MiB.
///
/// Bigger blocks widen the DoS surface: confirm validators keep up under load before
/// mainnet.
pub const MAXIMUM_BLOCK_LENGTH: u32 = 8 * 1024 * 1024;

/// Applies to block length only; weights stay at `NORMAL_DISPATCH_RATIO`.
pub const BLOCK_LENGTH_NORMAL_RATIO: Perbill = Perbill::from_percent(85);
