//! Origin gates for the pallet's calls.
//!
//! | Calls | Accepted origins | Refused |
//! |---|---|---|
//! | spends (`private_transfer`, `unshield`) | unsigned, signed, `Relayed` | Root |
//! | relayer calls (`commit_relay`, `claim_relay_fees`) | signed, `Relayed` | unsigned, Root |
//!
//! Who submits a spend never decides who earns its fee; the relay commit does.

use crate::{
	RawOrigin,
	pallet::{Config, Origin},
};
use sp_runtime::traits::BadOrigin;

/// Gate a spend's origin: unsigned, signed, or the precompile's `Relayed`.
/// Root is refused, so `sudo` cannot submit spends.
pub fn ensure_spend_origin<T: Config, OuterOrigin>(o: OuterOrigin) -> Result<(), BadOrigin>
where
	OuterOrigin: Into<Result<Origin, OuterOrigin>>
		+ Into<Result<frame_system::RawOrigin<T::AccountId>, OuterOrigin>>,
{
	match Into::<Result<Origin, OuterOrigin>>::into(o) {
		Ok(RawOrigin::Relayed(_)) => Ok(()),
		Err(other) => match other.into() {
			Ok(frame_system::RawOrigin::None | frame_system::RawOrigin::Signed(_)) => Ok(()),
			_ => Err(BadOrigin),
		},
	}
}

/// An authenticated caller of the relayer calls (`commit_relay`,
/// `claim_relay_fees`).
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum RelayCaller<AccountId> {
	/// The precompile's origin: this EVM address signed the transaction.
	Evm(sp_core::H160),
	/// A signed Substrate extrinsic.
	Signed(AccountId),
}

/// The relayer calls' caller. Unsigned and Root are refused.
pub fn ensure_relay_caller<T: Config, OuterOrigin>(
	o: OuterOrigin,
) -> Result<RelayCaller<T::AccountId>, BadOrigin>
where
	OuterOrigin: Into<Result<Origin, OuterOrigin>>
		+ Into<Result<frame_system::RawOrigin<T::AccountId>, OuterOrigin>>,
{
	match Into::<Result<Origin, OuterOrigin>>::into(o) {
		Ok(RawOrigin::Relayed(address)) => Ok(RelayCaller::Evm(address)),
		Err(other) => match other.into() {
			Ok(frame_system::RawOrigin::Signed(who)) => Ok(RelayCaller::Signed(who)),
			_ => Err(BadOrigin),
		},
	}
}
