//! The shares of a block automatic payment may spend, and their hard caps.

use frame_support::{pallet_prelude::*, weights::Weight};
use scale_info::TypeInfo;
use sp_runtime::Perbill;

/// Hard caps on [`PayoutLimits`], whatever governance sets.
pub const MAX_FLOOR: Perbill = Perbill::from_percent(10);
pub const MAX_CATCH_UP: Perbill = Perbill::from_percent(10);
pub const MAX_IDLE: Perbill = Perbill::from_percent(25);

/// Shares of the block's maximum weight the pallet may spend.
#[derive(
	Clone,
	Copy,
	PartialEq,
	Eq,
	Encode,
	Decode,
	DecodeWithMemTracking,
	MaxEncodedLen,
	TypeInfo,
	Debug
)]
pub struct PayoutLimits {
	/// Paid from `on_initialize` while the era is behind its schedule.
	pub floor: Perbill,
	/// Paid from `on_initialize` while more than one era waits.
	pub catch_up: Perbill,
	/// Most of a block's leftover weight `on_idle` spends.
	pub idle: Perbill,
}

/// Why a [`PayoutLimits`] is refused.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LimitsError {
	/// A share is above its hard cap.
	AboveCap,
	/// `catch_up` is below `floor`.
	CatchUpBelowFloor,
	/// `floor` cannot fit the largest step, so a behind era could stall.
	FloorBelowStep,
}

impl PayoutLimits {
	/// Checks the caps and that `floor` of `block` fits `largest_step`, the
	/// heaviest single thing the pallet does in a block.
	pub fn check(&self, block: Weight, largest_step: Weight) -> Result<(), LimitsError> {
		if self.floor > MAX_FLOOR || self.catch_up > MAX_CATCH_UP || self.idle > MAX_IDLE {
			return Err(LimitsError::AboveCap);
		}
		if self.catch_up < self.floor {
			return Err(LimitsError::CatchUpBelowFloor);
		}
		if (self.floor * block).any_lt(largest_step) {
			return Err(LimitsError::FloorBelowStep);
		}
		Ok(())
	}
}
