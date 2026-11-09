//! The election's progress, its bookkeeping and the ways it can end.

use super::TargetIndex;
use frame_election_provider_support::PageIndex;
use scale_codec::{Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};
use scale_info::TypeInfo;

/// What the next `on_poll` step does.
#[derive(
	Encode,
	Decode,
	MaxEncodedLen,
	TypeInfo,
	Clone,
	Copy,
	Default,
	PartialEq,
	Eq,
	Debug
)]
pub enum Phase {
	/// No election.
	#[default]
	Off,
	/// Take the target snapshot and the number of seats.
	Targets,
	/// Take voter page `p`, from the most significant down to 0.
	Voters(PageIndex),
	/// Elect the next winner.
	Select,
	/// Apply the last winner's score as its voters' load in voter `page`,
	/// down to 0.
	Apply {
		page: PageIndex,
		winner: TargetIndex,
	},
	/// Winners are elected; staking may fetch the pages.
	Done,
	/// The election failed; every page fetch errors until page 0 clears it.
	Failed(FailReason),
}

impl Phase {
	/// Still computing: not ready for `elect`.
	pub fn is_computing(&self) -> bool {
		matches!(
			self,
			Self::Targets | Self::Voters(_) | Self::Select | Self::Apply { .. }
		)
	}
}

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
pub enum FailReason {
	/// Staking failed to provide targets, voters or the number of seats.
	DataProvider,
	/// Staking asked for more seats than `MaxWinnersPerPage`.
	TooManySeats,
	/// The pallet's own storage broke an invariant.
	Inconsistent,
	/// Governance aborted the election.
	Aborted,
}

/// The running election's bookkeeping.
#[derive(
	Encode,
	Decode,
	MaxEncodedLen,
	TypeInfo,
	Clone,
	Copy,
	Default,
	PartialEq,
	Eq,
	Debug
)]
pub struct ElectionMeta<BlockNumber> {
	/// Block in which the election started.
	pub started: BlockNumber,
	/// Targets in the snapshot.
	pub targets: u32,
	/// Seats staking asked for.
	pub desired: u32,
	/// Winners to elect: the seats, or every candidate if fewer.
	pub to_elect: u32,
	/// Voter pages stored, voters and votes in the snapshot so far.
	pub pages: u32,
	pub voters: u32,
	pub edges: u32,
	/// A score saturated at `u128::MAX`; reported once.
	pub saturated: bool,
	/// Pages staking fetched, page 0 excluded: once one is, the election can
	/// no longer be aborted or cleared.
	pub fetched: u32,
}

/// Why `elect` refused a page.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ElectionError {
	/// No election is running.
	NotOngoing,
	/// An election is already running or waits to be fetched.
	Ongoing,
	/// The election has not finished.
	NotReady,
	/// The page is not below `Pages`.
	InvalidPage,
	/// The election failed.
	Failed(FailReason),
	/// A page exceeded the supports' bounds; `integrity_test` rules this out.
	BoundsExceeded,
}
