//! Nomination pools: holders below `MinNominatorBond` stake together. Each pool
//! is one nominator to staking; its members never appear in an election.
//!
//! | What | How |
//! |---|---|
//! | Funds | Stay in each member's account, held for the pool (`pallet-delegated-staking`). The pool's bonded account is a virtual staker: staking bonds it without moving funds. |
//! | Rewards | `pallet-auto-payout` pays the pool like any nominator, into its reward account. Each member claims its share with `claim_payout`; anyone may claim it for the member (`claim_payout_other`) or restake it (`bond_extra_other`) if the member allows it (`set_claim_permission`). Nothing iterates members. |
//! | Slashes | Staking slashes the pool's bond when the slash applies. Each member's share comes out of its held funds when it withdraws, or when anyone calls `apply_slash` for it; until then the member owes it and what it unbonds is already reduced. |
//! | Validating | Never: a pool's accounts are keyless, so they cannot sign `staking.validate`. A pool only nominates. |
//!
//! Pool configs are in `configs/staking/pools.rs`, their genesis values in `params`.

use crate::Balance;
use sp_core::U256;
use sp_runtime::traits::Convert;

/// Widens a balance for the pools' reward arithmetic.
pub struct BalanceToU256;

impl Convert<Balance, U256> for BalanceToU256 {
	fn convert(balance: Balance) -> U256 {
		U256::from(balance)
	}
}

/// Narrows the pools' reward arithmetic back to a balance, saturating.
pub struct U256ToBalance;

impl Convert<U256, Balance> for U256ToBalance {
	fn convert(n: U256) -> Balance {
		n.try_into().unwrap_or(Balance::MAX)
	}
}
