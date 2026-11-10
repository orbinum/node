//! Nominated proof of stake: who validates, chosen by stake among the candidates
//! the validator set admits, and how misbehaviour is punished.
//!
//! - [`params`]: eras, bonding, election bounds and self-bond limits.
//! - `validators`: the admission rule ([`admission`]), the transaction extension that
//!   rejects inadmissible `staking.validate` calls ([`candidacy`]), clamping
//!   commissions above a lowered ceiling ([`commission`]), and banning offenders
//!   ([`offences`]).
//! - `voting`: the voter list's stake thresholds ([`bags`]), keeping its walk to
//!   accounts that vote ([`live`]), stake to vote weight, exact to 10^-9 ORB
//!   ([`vote`]), and nomination pools, whose members stake through a delegation
//!   ([`pools`]).
//! - `eras`: the direct calls between the staking and session sides, which upstream
//!   joins over XCM ([`local_relay`]); resetting an era plan a failed election left
//!   unable to start ([`recovery`]); paying each era ([`payouts`]); and removing eras
//!   past the history from `on_idle` ([`pruning`]).
//!
//! Pallet configs are in `configs::staking`; where rewards and slashes go is in
//! `economy`.

mod eras;
pub mod params;
#[cfg(test)]
mod tests;
mod validators;
mod voting;

#[cfg(test)]
pub(crate) use eras::recovery;
pub(crate) use eras::{local_relay, payouts, pruning};
pub use validators::candidacy;
pub(crate) use validators::{admission, commission, offences};
pub(crate) use voting::{bags, live, pools, vote};

use crate::{BlockNumber, Runtime};
use frame_support::{
	dispatch::DispatchClass,
	traits::{Contains, Get},
};
use pallet_session::ShouldEndSession;
use sp_staking::EraIndex;

/// The era staking is in: the one whose payout is being computed when an era
/// closes.
pub struct ActiveEraIndex;

impl Get<EraIndex> for ActiveEraIndex {
	fn get() -> EraIndex {
		pallet_staking_async::ActiveEra::<Runtime>::get()
			.map(|era| era.index)
			.unwrap_or_default()
	}
}

/// Blocks that already carry staking's heavy work: a session's last block, where
/// it rotates and staking processes the session report (and, at an era's end,
/// starts the era), and every block the election works in (its snapshot and
/// rounds, and staking's fetch of its pages, all in `on_poll`). Work that can
/// wait (automatic payouts, pruning) stays out of them. Other hooks' declared
/// weight needs no check: `on_idle` only spends what they left.
pub struct HeavyBlocks;

/// Storage reads [`HeavyBlocks`] makes: the election's phase.
pub const HEAVY_BLOCK_READS: u64 = 1;

impl Contains<BlockNumber> for HeavyBlocks {
	fn contains(now: &BlockNumber) -> bool {
		<Runtime as pallet_session::Config>::ShouldEndSession::should_end_session(*now)
			|| pallet_paged_election::CurrentPhase::<Runtime>::get()
				!= pallet_paged_election::Phase::Off
	}
}

/// Charges `reads` to the block as mandatory weight: work a hook or a provider
/// does beyond what its caller priced.
pub(crate) fn register_reads(reads: u64) {
	let weight = <Runtime as frame_system::Config>::DbWeight::get().reads(reads);
	frame_system::Pallet::<Runtime>::register_extra_weight_unchecked(
		weight,
		DispatchClass::Mandatory,
	);
}
