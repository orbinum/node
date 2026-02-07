//! AuditTrail entity
//!
//! Represents an entry in the immutable audit log of all disclosure operations.

use frame_support::{BoundedVec, pallet_prelude::*};
use parity_scale_codec::{Decode, Encode, MaxEncodedLen};
use scale_info::TypeInfo;
use sp_runtime::RuntimeDebug;

use crate::domain::value_objects::Hash;

/// Audit trail entry
///
/// # Domain Rules
/// - Audit trails are immutable once created
/// - Trail hash ensures integrity
/// - Used for compliance and forensic analysis
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
pub struct AuditTrail<AccountId, BlockNumber> {
	/// The audited account
	pub account: AccountId,
	/// The auditor
	pub auditor: AccountId,
	/// Disclosure timestamp
	pub timestamp: BlockNumber,
	/// What was disclosed (summary)
	pub disclosure_type: BoundedVec<u8, ConstU32<64>>,
	/// Audit trail hash for verification
	pub trail_hash: Hash,
}

impl<AccountId, BlockNumber> AuditTrail<AccountId, BlockNumber>
where
	AccountId: Clone,
{
	/// Create new audit trail entry
	pub fn new(
		account: AccountId,
		auditor: AccountId,
		timestamp: BlockNumber,
		disclosure_type: BoundedVec<u8, ConstU32<64>>,
		trail_hash: Hash,
	) -> Self {
		Self {
			account,
			auditor,
			timestamp,
			disclosure_type,
			trail_hash,
		}
	}

	/// Get account
	pub fn account(&self) -> &AccountId {
		&self.account
	}

	/// Get auditor
	pub fn auditor(&self) -> &AccountId {
		&self.auditor
	}

	/// Get timestamp
	pub fn timestamp(&self) -> &BlockNumber {
		&self.timestamp
	}

	/// Get trail hash
	pub fn trail_hash(&self) -> &Hash {
		&self.trail_hash
	}

	/// Verify trail hash (basic check)
	pub fn verify_hash(&self, expected: &Hash) -> bool {
		&self.trail_hash == expected
	}
}
