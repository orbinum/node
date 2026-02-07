//! DisclosureCondition value object
//!
//! Defines the conditions under which disclosure of encrypted notes is allowed.

use frame_support::{BoundedVec, pallet_prelude::*};
use parity_scale_codec::{Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};
use scale_info::TypeInfo;
use sp_runtime::RuntimeDebug;

use crate::domain::value_objects::Hash;

/// Conditions that must be met for disclosure
///
/// # Variants
/// - `Always`: Disclosure always allowed
/// - `TimeDelay`: Allowed after specific block number
/// - `AmountThreshold`: Allowed for transactions above threshold
/// - `JudicialOrder`: Requires on-chain proof of court order
/// - `Custom`: Programmable custom condition
#[derive(
	Clone,
	PartialEq,
	Eq,
	Encode,
	Decode,
	DecodeWithMemTracking,
	TypeInfo,
	RuntimeDebug,
	MaxEncodedLen
)]
pub enum DisclosureCondition<Balance, BlockNumber> {
	/// Always allow disclosure
	Always,
	/// Allow after a time delay
	TimeDelay {
		/// Block number after which disclosure is allowed
		after_block: BlockNumber,
	},
	/// Allow for transactions above a threshold
	AmountThreshold {
		/// Minimum amount for disclosure
		min_amount: Balance,
	},
	/// Allow with judicial order (requires on-chain proof)
	JudicialOrder {
		/// Court identifier
		court_id: Hash,
		/// Case identifier
		case_id: Hash,
	},
	/// Custom condition (programmable)
	Custom {
		/// Custom condition identifier
		condition_id: Hash,
		/// Additional parameters
		params: BoundedVec<u8, ConstU32<1024>>,
	},
}

impl<Balance, BlockNumber> DisclosureCondition<Balance, BlockNumber>
where
	Balance: PartialOrd,
	BlockNumber: PartialOrd,
{
	/// Check if time delay condition is met
	pub fn is_time_delay_met(&self, current_block: BlockNumber) -> bool {
		match self {
			Self::TimeDelay { after_block } => current_block >= *after_block,
			Self::Always => true,
			_ => false,
		}
	}

	/// Check if amount threshold condition is met
	pub fn is_amount_threshold_met(&self, amount: Balance) -> bool {
		match self {
			Self::AmountThreshold { min_amount } => amount >= *min_amount,
			Self::Always => true,
			_ => false,
		}
	}

	/// Check if this is a judicial order condition
	pub fn is_judicial_order(&self) -> bool {
		matches!(self, Self::JudicialOrder { .. })
	}
}
