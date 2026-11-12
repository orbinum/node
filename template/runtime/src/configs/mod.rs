// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

//! Per-pallet `Config` implementations, grouped by domain.
//!
//! - `chain`: system, timestamp, balances, transaction fees and sudo (`system`); Aura,
//!   GRANDPA, sessions, the validator set, authorship and manual seal (`consensus`);
//!   the origin each privileged role requires (`governance`).
//! - [`staking`]: staking, its election, pools, payouts and the clients joining them.
//! - `stacks`: the EVM, Ethereum transactions and the base fee (`evm`); the ZK
//!   verifier and the shielded pool (`privacy`); ISMP / Hyperbridge (`ismp`).

mod chain;
mod stacks;
pub mod staking;
#[cfg(test)]
mod tests;

pub use chain::{consensus, governance, system};
#[cfg(test)]
pub use stacks::privacy;
pub use stacks::{evm, ismp};
