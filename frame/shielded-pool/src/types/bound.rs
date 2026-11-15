// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: GPL-3.0-or-later

//! What a bound spend hands its value to, and the router the runtime plugs in.
//!
//! A bound spend is an unshield proof whose `memo_hash` commits to an action as
//! well as the change memo. The proof is valid for that action alone: a copier
//! can neither swap the action (nor the output it mints) nor replay the proof as
//! a plain unshield, which hashes the memo alone and refuses executor accounts as
//! recipients.

use frame_support::{dispatch::DispatchResult, pallet_prelude::*, weights::Weight};
use parity_scale_codec::{Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};
use scale_info::TypeInfo;

/// The runtime's bound actions.
pub trait BoundActions<AccountId> {
	/// The actions, SCALE-encoded into the proof's `memo_hash`.
	type Action: Parameter + Member + MaxEncodedLen;

	/// The account the spend pays, which the proof names as its recipient;
	/// `None` for an action this runtime does not run.
	fn executor(action: &Self::Action) -> Option<AccountId>;

	/// Whether `who` executes bound actions. Plain `unshield` refuses to pay it.
	fn is_executor(who: &AccountId) -> bool;

	/// The smallest fee, in units of `asset_id`, a spend of this pallet-backed
	/// asset pays; `None` if no action handles the asset.
	fn min_fee(asset_id: u32) -> Option<u128>;

	/// Every check `execute` makes, writing nothing: run at pool admission and
	/// before the spend settles, so nothing admitted fails after its proof.
	/// `fee` is the spend's fee in the same asset, credited after `execute`.
	fn validate(action: &Self::Action, asset_id: u32, amount: u128, fee: u128) -> DispatchResult;

	/// Runs `action` once the spend has settled: `amount` of the native asset is
	/// in the executor's account, or `amount` of a pallet-backed asset is burned.
	/// The `fee` is not credited yet: a pallet-backed one is still in the supply.
	fn execute(action: Self::Action, asset_id: u32, amount: u128, fee: u128) -> DispatchResult;

	/// The weight of `execute` for `action`.
	fn weight(action: &Self::Action) -> Weight;

	/// Pays `validator` the value of `amount` of the pallet-backed `asset_id` it
	/// earned as spend fees. The pool burns the units once this succeeds.
	fn redeem_fees(validator: &AccountId, asset_id: u32, amount: u128) -> DispatchResult;

	/// The most `redeem_fees` costs, charged by `claim_fees` on top of its own.
	fn redeem_fees_weight() -> Weight;
}

/// Who pays for a note `mint_note` inserts: an account moves native funds in, or the
/// pallet that issues a pallet-backed asset issues it.
pub enum Funding<'a, AccountId> {
	From(&'a AccountId),
	Issued(frame_support::PalletId),
}

/// A note `mint_note` inserted: its commitment and the value it holds.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MintedNote {
	pub commitment: crate::Commitment,
	/// The value asked for, or up to [`MINT_ATTEMPTS`] − 1 units less when a note with
	/// that value and key already existed. `NoteMinted` carries it, so the owner finds
	/// the note either way.
	pub value: u128,
}

/// How many values `mint_note` tries, one unit apart, before refusing a note whose
/// commitment already exists.
pub const MINT_ATTEMPTS: u128 = 3;

/// The action of a runtime with none: every bound spend is refused.
#[derive(
	Clone,
	PartialEq,
	Eq,
	Encode,
	Decode,
	DecodeWithMemTracking,
	MaxEncodedLen,
	TypeInfo,
	Debug
)]
pub struct NoAction;

const NO_ACTIONS: DispatchError = DispatchError::Other("no bound actions");

impl<AccountId> BoundActions<AccountId> for () {
	type Action = NoAction;

	fn executor(_: &NoAction) -> Option<AccountId> {
		None
	}

	fn is_executor(_: &AccountId) -> bool {
		false
	}

	fn min_fee(_: u32) -> Option<u128> {
		None
	}

	fn validate(_: &NoAction, _: u32, _: u128, _: u128) -> DispatchResult {
		Err(NO_ACTIONS)
	}

	fn execute(_: NoAction, _: u32, _: u128, _: u128) -> DispatchResult {
		Err(NO_ACTIONS)
	}

	fn weight(_: &NoAction) -> Weight {
		Weight::zero()
	}

	fn redeem_fees(_: &AccountId, _: u32, _: u128) -> DispatchResult {
		Err(NO_ACTIONS)
	}

	fn redeem_fees_weight() -> Weight {
		Weight::zero()
	}
}
