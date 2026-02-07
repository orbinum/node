//! Auditor value object
//!
//! Defines who can request disclosure of encrypted notes in the shielded pool.

use parity_scale_codec::{Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};
use scale_info::TypeInfo;
use sp_runtime::RuntimeDebug;

use crate::domain::value_objects::Hash;

/// Who can request disclosure of encrypted notes
///
/// # Variants
/// - `Account`: A specific account authorized to audit
/// - `Role`: Any account holding a specific role
/// - `CredentialHolder`: Holder of a specific credential/NFT
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
pub enum Auditor<AccountId> {
	/// A specific account
	Account(AccountId),
	/// Any account with a specific role
	Role {
		/// Role identifier
		role: Hash,
	},
	/// Holder of a specific credential
	CredentialHolder {
		/// Credential identifier
		credential: Hash,
	},
}

impl<AccountId> Auditor<AccountId> {
	/// Create an account auditor
	pub fn account(account: AccountId) -> Self {
		Self::Account(account)
	}

	/// Create a role-based auditor
	pub fn role(role: Hash) -> Self {
		Self::Role { role }
	}

	/// Create a credential-based auditor
	pub fn credential(credential: Hash) -> Self {
		Self::CredentialHolder { credential }
	}
}
