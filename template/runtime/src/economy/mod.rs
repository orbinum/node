// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

//! Where value moves: transaction fees, tips, slashed funds and era rewards.
//!
//! Nothing is burned on purpose. Fees fund the era's rewards (burned when the
//! era closes, minted again as its pages are paid: shares nobody can be paid,
//! and rounding, stay burned), tips pay the block author and slashed funds go
//! to governance. Each policy is one alias below: change the
//! type, ship a runtime upgrade.
//!
//! - [`accounts`]: the keyless accounts the policies pay into.
//! - [`fees`]: splitting a transaction's fee from its tip.
//! - [`rewards`]: what an era pays and where it comes from.
//! - [`schedule`]: the yearly inflation schedule.

pub mod accounts;
pub mod fees;
pub mod rewards;
pub mod schedule;
#[cfg(test)]
mod tests;

pub use accounts::{AutoPayoutAccount, EraFeePoolAccount, EraPruningAccount, GovernanceAccount};

use crate::{configs::consensus::ValidatorAccountAuthor, Balances};
use frame_support::traits::tokens::imbalance::ResolveTo;

/// Transaction fees (Substrate and EVM base fee): into the era's reward pool, so
/// they are shared by era points instead of going to whoever authored the block.
/// A validator filling its own blocks gets back only its share.
pub type FeeDestination = ResolveTo<EraFeePoolAccount, Balances>;

/// Tips (Substrate and EVM priority fee): to the block author, which is what a
/// tip buys. Without an author, to governance.
pub type TipDestination = fees::ToAuthor<Balances, ValidatorAccountAuthor, GovernanceAccount>;

/// Governance's account, as a destination.
pub type ToGovernance = ResolveTo<GovernanceAccount, Balances>;

/// Slashed stake: to governance, which can return it if a slash is overturned.
pub type SlashDestination = ToGovernance;

/// Substrate transaction payment: fee and tip routed separately.
pub type DealWithFees = fees::DealWithFees<Balances, FeeDestination, TipDestination>;

/// What each era pays stakers: inflation on the tokenomics schedule plus the
/// fees collected during the era. To pay from a pre-funded pot instead of
/// inflation, swap `Inflation` for a capped drain of the pot.
pub type EraPayout = rewards::RewardSources<
	(
		rewards::Inflation<schedule::TokenomicsSchedule>,
		rewards::DrainAccount<EraFeePoolAccount, Balances>,
	),
	crate::staking::ActiveEraIndex,
>;
