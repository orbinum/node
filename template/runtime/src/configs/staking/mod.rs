//! Nominated proof of stake: staking, its election, and the glue that joins them
//! to sessions.
//!
//! Upstream's asynchronous staking, built to span a relay chain and a staking chain
//! over XCM; here both sides run in this runtime:
//!
//! | Side | Pallets | Role |
//! |---|---|---|
//! | staking | `Staking` (`pallet-staking-async`), `RcClient`, `VoterList`, `PagedElection` | bonds, nominations, eras, the election, rewards and slashes |
//! | session | `Session`, `Historical`, `Offences`, `AhClient` | the active set, era points, offence reports |
//! | pools | `NominationPools`, `DelegatedStaking` | stake from many members as one nominator (`staking::pools`) |
//! | upkeep | `AutoPayout`, `EraPruning` | paying each era and pruning old ones, with no transactions |
//!
//! Each side's client hands messages to the other by direct calls
//! (`staking::local_relay`).
//!
//! Each era, staking plans the next one by starting an election among the
//! candidates the validator set admits (`staking::admission`). The election
//! (`pallet-paged-election`) is computed on-chain over a paged snapshot, a few
//! steps per block in `on_poll`, within [`ElectionRoundBudget`] of the block; no
//! off-chain miner is involved. Staking fetches the result page by page and
//! hands the elected set to the session side, which applies it at a session
//! boundary and reports back when it is active, starting the era.
//!
//! An era plan that can no longer start (a failed election, or a set too small
//! to apply) is reset and planned again (`staking::recovery`); the current set
//! keeps validating meanwhile.

mod clients;
mod election;
mod payouts;
mod pools;
mod session;
#[allow(clippy::module_inception)]
mod staking;

pub use self::staking::*;
#[cfg(test)]
pub use self::{clients::*, election::*, payouts::*, pools::*};
