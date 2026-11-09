//! Keyless accounts that hold value on the chain's behalf. Nobody holds their
//! keys: only the runtime and root (`balances.force_transfer`) can move funds out.

use crate::AccountId;
use frame_support::{parameter_types, PalletId};
use sp_runtime::traits::AccountIdConversion;

parameter_types! {
	/// Governance funds: slashed stake and anything without a better recipient.
	/// Same id as `pallet-treasury`'s default, so adding that pallet later takes
	/// over these funds without moving them.
	pub GovernanceAccount: AccountId = PalletId(*b"py/trsry").into_account_truncating();
	/// Fees collected during the current era, paid out with its rewards.
	pub EraFeePoolAccount: AccountId = PalletId(*b"orb/feep").into_account_truncating();
	/// Signs the payouts `pallet-auto-payout` makes. Holds nothing: a payout pays
	/// the stakers, never the caller.
	pub AutoPayoutAccount: AccountId = PalletId(*b"orb/apay").into_account_truncating();
	/// Signs the era pruning `staking::pruning` does. Holds nothing: the call is
	/// free.
	pub EraPruningAccount: AccountId = PalletId(*b"orb/prun").into_account_truncating();
}
