// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

//! Staking's fixed parameters. Bonds, counts and commission limits live on-chain
//! instead (`staking.set_staking_configs`, `staking.set_max_commission`,
//! `nomination_pools.set_configs`), so governance can tune them without an
//! upgrade; their genesis values are here too. Nominators and pools start
//! uncapped; the minimum bonds keep them from being spammed, and governance may
//! set a cap on-chain at any time. Commission starts with no ceiling, for
//! validators and pools alike.
//!
//! `fast-runtime` shortens time (sessions, eras, bonding and slash deferral,
//! keeping their ratios) and, to fit its short era, the election's pages.

use crate::{primitives::constants::ORB, Balance, BlockNumber};
use sp_runtime::Perbill;
use sp_staking::{EraIndex, SessionIndex};

/// Session length: validator set changes, if any, apply at session boundaries.
#[cfg(not(feature = "fast-runtime"))]
pub const SESSION_PERIOD: BlockNumber = crate::HOURS;
#[cfg(feature = "fast-runtime")]
pub const SESSION_PERIOD: BlockNumber = 2 * crate::MINUTES;

/// Sessions per era: 24 one-hour sessions, one era a day.
#[cfg(not(feature = "fast-runtime"))]
pub const SESSIONS_PER_ERA: SessionIndex = 24;
#[cfg(feature = "fast-runtime")]
pub const SESSIONS_PER_ERA: SessionIndex = 3;

/// Eras a validator's stake stays locked after `unbond`, and so slashable. It
/// applies too to an account that validated within the last `BONDING_DURATION`
/// eras, whatever it does now: switching to nominating does not shorten it.
#[cfg(not(feature = "fast-runtime"))]
pub const BONDING_DURATION: EraIndex = 28;
#[cfg(feature = "fast-runtime")]
pub const BONDING_DURATION: EraIndex = 3;

/// Eras a nominator's or a pool member's stake stays locked after `unbond`.
/// Only validators are slashed (`AreNominatorsSlashable` is off, see
/// `staking::eras::pruning`), so backers need not wait out the slash window:
/// two eras cover the active one and the next, whose election already counts
/// the stake.
#[cfg(not(feature = "fast-runtime"))]
pub const NOMINATOR_UNBOND_DURATION: EraIndex = 2;
#[cfg(feature = "fast-runtime")]
pub const NOMINATOR_UNBOND_DURATION: EraIndex = 1;

/// Eras before a reported slash applies; governance may cancel it meanwhile. Only
/// validators' own stake is slashed, and it stays locked the full
/// [`BONDING_DURATION`], so the window can be long while backers leave fast.
///
/// Two below [`BONDING_DURATION`], so no stake exposed in the offence's era can
/// be withdrawn before the slash lands. An era's exposures are stored while the
/// era before it runs, so stake unbonded then unlocks `BONDING_DURATION - 1`
/// eras after the offence's era; the slash is due an era earlier, and staking
/// refuses every withdrawal while the previous era's slashes are unapplied.
#[cfg(not(feature = "fast-runtime"))]
pub const SLASH_DEFER_DURATION: EraIndex = 26;
#[cfg(feature = "fast-runtime")]
pub const SLASH_DEFER_DURATION: EraIndex = 1;

/// The most an offence slashes of what it exposes. GRANDPA's fraction reaches
/// 100 % once a third of the set offends together (one validator of three);
/// a stake slashed to exactly nothing has its ledger removed, and a pool whose
/// ledger staking removed refuses its members' withdrawals for good (upstream),
/// leaving them unable to leave it or stake again. A sliver stays instead.
pub const MAX_SLASH_FRACTION: Perbill = Perbill::from_percent(99);

/// Eras whose rewards stay claimable.
pub const HISTORY_DEPTH: u32 = 84;

/// Validators a nominator may back.
pub const MAX_NOMINATIONS: u32 = 16;

/// Most validators in a session: Aura and GRANDPA's authority bound and the
/// election's winner count.
pub const MAX_ACTIVE_VALIDATORS: u32 = 100;

/// Most accounts that may offer themselves as validators at once, and most
/// accounts in the validator-set allowlist.
pub const MAX_VALIDATOR_CANDIDATES: u32 = 256;

/// Nominators rewarded per payout page. Small, so automatic payment can spread
/// an era over many blocks in steps of a few milliseconds.
pub const MAX_EXPOSURE_PAGE_SIZE: u32 = 64;

/// Blocks over which an era's rewards are paid automatically: half an era.
pub const PAYMENT_WINDOW: BlockNumber = SESSIONS_PER_ERA * SESSION_PERIOD / 2;

/// Eras before an unpaid era leaves [`HISTORY_DEPTH`] at which automatic payment
/// warns and lifts a pause: two weeks of notice on 24-hour eras.
pub const PAYOUT_EXPIRY_MARGIN: EraIndex = 14;

/// Voter pages in an election snapshot, taken by stake from the bags list, and
/// voters per page. The election (`pallet-paged-election`) reads, computes and
/// exports one page at a time, so no block carries the whole snapshot.
///
/// `fast-runtime` uses 8 pages: a 32-page election takes more blocks than its
/// 60-block era has.
#[cfg(not(feature = "fast-runtime"))]
pub const ELECTION_PAGES: u32 = 32;
#[cfg(feature = "fast-runtime")]
pub const ELECTION_PAGES: u32 = 8;
pub const VOTER_SNAPSHOT_PER_BLOCK: u32 = 3_125;

/// Voters an election reads, every page full: 100 000 (25 000 under
/// `fast-runtime`). Nominators and pools are not capped; past this many, the
/// most staked vote and the rest neither vote nor earn that era.
pub const MAX_ELECTING_VOTERS: u32 = ELECTION_PAGES * VOTER_SNAPSHOT_PER_BLOCK;

/// Share of a block the election may use per block while it computes.
pub const ELECTION_ROUND_BUDGET: Perbill = Perbill::from_percent(40);

/// Lowest self-bond while admission is open, whatever `MinValidatorBond` says,
/// so sybil candidates stay expensive.
#[cfg(not(feature = "fast-runtime"))]
pub const OPEN_MODE_MIN_SELF_BOND: Balance = 100_000 * ORB;
#[cfg(feature = "fast-runtime")]
pub const OPEN_MODE_MIN_SELF_BOND: Balance = 1_000 * ORB;

/// Genesis bonds for test networks (dev, local, testnet). Governance raises them
/// on-chain; mainnet's genesis uses the tokenomics values below.
pub const TEST_MIN_VALIDATOR_BOND: Balance = 1_000 * ORB;
pub const TEST_MIN_NOMINATOR_BOND: Balance = 100 * ORB;
pub const MAINNET_MIN_VALIDATOR_BOND: Balance = 100_000 * ORB;
pub const MAINNET_MIN_NOMINATOR_BOND: Balance = 100 * ORB;

/// Share of a slash paid to whoever reported the offence. Staking computes it on
/// the whole slash, nominators' included, and the reporter may be the offender
/// itself (a signed report, or the unsigned one in a block it authors): at 1 %,
/// reporting itself pays only while its nominators stake over 99 times its own.
pub const SLASH_REWARD_FRACTION: Perbill = Perbill::from_percent(1);

/// Least a member bonds when joining a nomination pool, on every network: pools
/// are how holders below `MinNominatorBond` stake.
pub const POOL_MIN_JOIN_BOND: Balance = ORB;

/// Least a depositor bonds to create a pool, since every pool is a nominator that
/// each election snapshot reads: one nominator bond on test networks, ten on
/// mainnet. With the nominator bond, it is what keeps the uncapped voter list
/// from being flooded.
pub const TEST_POOL_MIN_CREATE_BOND: Balance = TEST_MIN_NOMINATOR_BOND;
pub const MAINNET_POOL_MIN_CREATE_BOND: Balance = 10 * MAINNET_MIN_NOMINATOR_BOND;

/// Eras past [`BONDING_DURATION`] that a pool keeps each era's unbonding funds
/// apart before merging them into one (`PostUnbondingPoolsWindow`).
pub const POOL_UNBONDING_WINDOW: u32 = 4;

/// Share of a pool member's pending slash paid to whoever applies it
/// (`nomination_pools.apply_slash`): none. The applier may be the member
/// itself, and the call is free when it succeeds, so any share would be a
/// discount on the slash. A withdrawal applies the slash anyway, and until then
/// the slashed funds stay held.
pub const POOL_SLASH_REWARD_FRACTION: Perbill = Perbill::zero();

/// The fewest validators an elected set may have before the session side drops
/// it and the previous set stays: two thirds of `validators`, rounded up, the
/// share GRANDPA needs to finalise.
pub const fn minimum_validator_count(validators: u32) -> u32 {
	validators.saturating_mul(2).div_ceil(3)
}

const _: () = assert!(SLASH_DEFER_DURATION + 2 <= BONDING_DURATION);
const _: () =
	assert!(NOMINATOR_UNBOND_DURATION >= 1 && NOMINATOR_UNBOND_DURATION <= BONDING_DURATION);
const _: () = assert!(MAX_ACTIVE_VALIDATORS <= MAX_VALIDATOR_CANDIDATES);
const _: () = assert!(TEST_POOL_MIN_CREATE_BOND >= TEST_MIN_NOMINATOR_BOND);
const _: () = assert!(MAINNET_POOL_MIN_CREATE_BOND >= MAINNET_MIN_NOMINATOR_BOND);
// The elected set is handed to the session side `SESSIONS_PER_ERA - 2` sessions
// into the era (`ValidatorSetExportSession` in `configs/staking/clients.rs`).
const _: () = assert!(SESSIONS_PER_ERA > 2);
const _: () = assert!(PAYMENT_WINDOW > 0);
const _: () = assert!(PAYOUT_EXPIRY_MARGIN > 0 && PAYOUT_EXPIRY_MARGIN < HISTORY_DEPTH);
