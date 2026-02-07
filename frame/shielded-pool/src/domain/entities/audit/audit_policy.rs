//! AuditPolicy entity
//!
//! Defines the rules for disclosure of encrypted notes in the shielded pool.

use frame_support::{BoundedVec, pallet_prelude::*};
use parity_scale_codec::{Decode, Encode, MaxEncodedLen};
use scale_info::TypeInfo;
use sp_runtime::RuntimeDebug;

use crate::domain::value_objects::audit::{Auditor, DisclosureCondition};

/// Audit policy defining disclosure rules
///
/// # Domain Rules
/// - At least one auditor must be defined
/// - At least one condition must be defined
/// - Version must increment on updates
/// - Max frequency prevents DoS attacks
#[derive(
	Clone,
	PartialEq,
	Eq,
	Encode,
	Decode,
	TypeInfo,
	RuntimeDebug,
	MaxEncodedLen
)]
pub struct AuditPolicy<AccountId, Balance, BlockNumber> {
	/// Who can request disclosure
	pub auditors: BoundedVec<Auditor<AccountId>, ConstU32<10>>,
	/// Conditions for disclosure
	pub conditions: BoundedVec<DisclosureCondition<Balance, BlockNumber>, ConstU32<10>>,
	/// Maximum disclosure frequency (blocks between disclosures)
	pub max_frequency: Option<BlockNumber>,
	/// Policy version for upgrades
	pub version: u32,
}

impl<AccountId, Balance, BlockNumber> AuditPolicy<AccountId, Balance, BlockNumber> {
	/// Create new audit policy
	pub fn new(
		auditors: BoundedVec<Auditor<AccountId>, ConstU32<10>>,
		conditions: BoundedVec<DisclosureCondition<Balance, BlockNumber>, ConstU32<10>>,
	) -> Self {
		Self {
			auditors,
			conditions,
			max_frequency: None,
			version: 1,
		}
	}

	/// Check if policy has auditors
	pub fn has_auditors(&self) -> bool {
		!self.auditors.is_empty()
	}

	/// Check if policy has conditions
	pub fn has_conditions(&self) -> bool {
		!self.conditions.is_empty()
	}

	/// Set max frequency
	pub fn with_max_frequency(mut self, blocks: BlockNumber) -> Self {
		self.max_frequency = Some(blocks);
		self
	}

	/// Increment version
	pub fn increment_version(&mut self) {
		self.version = self.version.saturating_add(1);
	}

	/// Get version
	pub fn version(&self) -> u32 {
		self.version
	}
}
