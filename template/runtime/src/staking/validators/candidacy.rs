// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

//! `CheckValidatorCandidacy`: rejects a `staking.validate` that the admission
//! rule would ignore, and a `session.set_keys` or `session.purge_keys` from a
//! validator of the current or the queued session, before it reaches a block
//! and before it costs a fee.
//!
//! Session keys must stay put while they are in use: an equivocation is proven
//! against the keys pallet-session holds for its session, and those are the
//! account's `NextKeys`, both in the current session's trie and in each stored
//! session root. A validator that changed them mid-era could equivocate with keys
//! no proof can name. A validator rotates keys once out of the set; root's
//! `sudo_as` can still do it in an emergency.
//!
//! It encodes to nothing (no explicit or implicit data), so it adds no byte to
//! an extrinsic or its signed payload; clients that build transactions from
//! metadata skip it as an empty extension.
//!
//! It sees only the outer call. The runtime has no call-wrapping pallet
//! (utility, proxy, multisig), which a test pins; root's `sudo_as` bypasses
//! it by design, and the election filter still covers that path.

use super::admission::{check, Inadmissible};
use crate::{AccountId, Runtime, RuntimeCall, ValidatorSet};
use frame_support::pallet_prelude::*;
use pallet_staking_async::ValidatorPrefs;
use scale_info::TypeInfo;
use sp_runtime::{
	impl_tx_ext_default,
	traits::{
		AsSystemOriginSigner, DispatchInfoOf, DispatchOriginOf, Implication, TransactionExtension,
		ValidateResult,
	},
	transaction_validity::{InvalidTransaction, TransactionSource, ValidTransaction},
};
use sp_staking::StakingAccount;

/// Why `controller` may not offer itself as a validator with `prefs`: the
/// admission rule for its stash, staking's commission ceiling
/// (`MaxCommission`), then room among the candidates.
///
/// The election reads at most `MaxTargets` candidates and staking cuts the rest
/// in storage order, so a new candidate needs fewer than that already. Staking's
/// own cap, `MaxValidatorsCount`, is governance's to raise; this one is not.
pub fn check_candidacy(controller: &AccountId, prefs: &ValidatorPrefs) -> Result<(), Inadmissible> {
	let stash = pallet_staking_async::Pallet::<Runtime>::ledger(StakingAccount::Controller(
		controller.clone(),
	))
	.map_err(|_| Inadmissible::NotBonded)?
	.stash;
	check(&ValidatorSet::admission(), &stash)?;
	if prefs.commission > pallet_staking_async::MaxCommission::<Runtime>::get() {
		return Err(Inadmissible::CommissionTooHigh);
	}
	let max = <Runtime as pallet_paged_election::Config>::MaxTargets::get();
	if !pallet_staking_async::Validators::<Runtime>::contains_key(&stash)
		&& pallet_staking_async::Validators::<Runtime>::count() >= max
	{
		return Err(Inadmissible::TooManyCandidates);
	}
	Ok(())
}

/// `InvalidTransaction::Custom` code for session keys changed while in use.
pub const KEYS_IN_USE: u8 = 8;

/// Whether `who` validates in the current session or is queued for the next:
/// its session keys are in use.
pub fn keys_in_use(who: &AccountId) -> bool {
	pallet_session::Validators::<Runtime>::get().contains(who)
		|| pallet_session::QueuedKeys::<Runtime>::get()
			.iter()
			.any(|(validator, _)| validator == who)
}

/// Reads [`keys_in_use`] makes: the session's validators and the queued keys.
const KEYS_IN_USE_READS: u64 = 2;

/// The transaction extension. See the module docs.
#[derive(
	Encode,
	Decode,
	DecodeWithMemTracking,
	Clone,
	Copy,
	Eq,
	PartialEq,
	Default,
	TypeInfo
)]
pub struct CheckValidatorCandidacy;

impl core::fmt::Debug for CheckValidatorCandidacy {
	fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
		write!(f, "CheckValidatorCandidacy")
	}
}

/// Reads `check_candidacy` makes: bonded controller and ledger, the admission
/// snapshot (mode, allowlist, block number), ban, session keys, the stash's
/// ledger again, the minimum bond, the commission ceiling, and the stash's
/// candidacy and the candidate count. Counted by hand until a benchmark
/// replaces it.
const CANDIDACY_READS: u64 = 13;

fn is_validate(call: &RuntimeCall) -> bool {
	matches!(
		call,
		RuntimeCall::Staking(pallet_staking_async::Call::validate { .. })
	)
}

fn changes_session_keys(call: &RuntimeCall) -> bool {
	matches!(
		call,
		RuntimeCall::Session(
			pallet_session::Call::set_keys { .. } | pallet_session::Call::purge_keys {}
		)
	)
}

impl TransactionExtension<RuntimeCall> for CheckValidatorCandidacy {
	const IDENTIFIER: &'static str = "CheckValidatorCandidacy";
	type Implicit = ();
	type Val = ();
	type Pre = ();

	fn weight(&self, call: &RuntimeCall) -> Weight {
		let db = <Runtime as frame_system::Config>::DbWeight::get();
		if is_validate(call) {
			db.reads(CANDIDACY_READS)
		} else if changes_session_keys(call) {
			db.reads(KEYS_IN_USE_READS)
		} else {
			Weight::zero()
		}
	}

	fn validate(
		&self,
		origin: DispatchOriginOf<RuntimeCall>,
		call: &RuntimeCall,
		_info: &DispatchInfoOf<RuntimeCall>,
		_len: usize,
		_self_implicit: Self::Implicit,
		_inherited_implication: &impl Implication,
		_source: TransactionSource,
	) -> ValidateResult<Self::Val, RuntimeCall> {
		if let RuntimeCall::Staking(pallet_staking_async::Call::validate { prefs }) = call {
			// Only a signed `validate` can make a candidate.
			if let Some(who) = origin.as_system_origin_signer() {
				check_candidacy(who, prefs)
					.map_err(|reason| InvalidTransaction::Custom(reason as u8))?;
			}
		}
		if changes_session_keys(call) {
			if let Some(who) = origin.as_system_origin_signer() {
				if keys_in_use(who) {
					return Err(InvalidTransaction::Custom(KEYS_IN_USE).into());
				}
			}
		}
		Ok((ValidTransaction::default(), (), origin))
	}

	impl_tx_ext_default!(RuntimeCall; prepare);
}
