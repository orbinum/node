//! DepositInfo DTO
//!
//! Data transfer object for deposit information in the shielded pool.

use parity_scale_codec::{Decode, Encode, MaxEncodedLen};
use scale_info::TypeInfo;
use sp_runtime::RuntimeDebug;

/// Information about a deposit into the shielded pool
///
/// This is a DTO used to transfer deposit information between layers.
/// It contains the depositor account, amount, and block number.
#[derive(
	Clone,
	PartialEq,
	Eq,
	Encode,
	Decode,
	MaxEncodedLen,
	TypeInfo,
	RuntimeDebug
)]
pub struct DepositInfo<AccountId, Balance, BlockNumber> {
	/// The account that made the deposit
	pub depositor: AccountId,
	/// The amount deposited
	pub amount: Balance,
	/// The block number when the deposit was made
	pub block_number: BlockNumber,
}

impl<AccountId, Balance, BlockNumber> DepositInfo<AccountId, Balance, BlockNumber> {
	/// Create new deposit info
	pub fn new(depositor: AccountId, amount: Balance, block_number: BlockNumber) -> Self {
		Self {
			depositor,
			amount,
			block_number,
		}
	}

	/// Get depositor
	pub fn depositor(&self) -> &AccountId {
		&self.depositor
	}

	/// Get amount
	pub fn amount(&self) -> &Balance {
		&self.amount
	}

	/// Get block number
	pub fn block_number(&self) -> &BlockNumber {
		&self.block_number
	}
}
