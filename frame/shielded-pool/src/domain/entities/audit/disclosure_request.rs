//! DisclosureRequest entity
//!
//! Represents a request from an auditor to disclose information about a transaction.

use frame_support::{BoundedVec, pallet_prelude::*};
use parity_scale_codec::{Decode, Encode, MaxEncodedLen};
use scale_info::TypeInfo;
use sp_runtime::RuntimeDebug;

/// Disclosure request from an auditor
///
/// # Domain Rules
/// - Auditor must be authorized in the AuditPolicy
/// - Reason must be provided
/// - Evidence is optional but recommended for judicial orders
/// - Request timestamp used for rate limiting
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
pub struct DisclosureRequest<AccountId, BlockNumber> {
	/// The auditor making the request
	pub auditor: AccountId,
	/// The target account to audit
	pub target: AccountId,
	/// Request timestamp
	pub requested_at: BlockNumber,
	/// Reason for the request
	pub reason: BoundedVec<u8, ConstU32<256>>,
	/// Evidence supporting the request (court order, etc.)
	pub evidence: Option<BoundedVec<u8, ConstU32<1024>>>,
}

impl<AccountId, BlockNumber> DisclosureRequest<AccountId, BlockNumber>
where
	AccountId: Clone,
{
	/// Create new disclosure request
	pub fn new(
		auditor: AccountId,
		target: AccountId,
		requested_at: BlockNumber,
		reason: BoundedVec<u8, ConstU32<256>>,
	) -> Self {
		Self {
			auditor,
			target,
			requested_at,
			reason,
			evidence: None,
		}
	}

	/// Add evidence to the request
	pub fn with_evidence(mut self, evidence: BoundedVec<u8, ConstU32<1024>>) -> Self {
		self.evidence = Some(evidence);
		self
	}

	/// Check if request has evidence
	pub fn has_evidence(&self) -> bool {
		self.evidence.is_some()
	}

	/// Get auditor
	pub fn auditor(&self) -> &AccountId {
		&self.auditor
	}

	/// Get target
	pub fn target(&self) -> &AccountId {
		&self.target
	}

	/// Get timestamp
	pub fn timestamp(&self) -> &BlockNumber {
		&self.requested_at
	}
}
