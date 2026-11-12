// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

//! The block author is the session validator the Aura pre-digest names, whoever
//! registered its key, and it earns what an author earns.

use crate::{
	configs::consensus::{ValidatorAccountAuthor, ValidatorAuthor},
	test_utils::authorship::{as_account, aura_key, digest, validator_set},
	test_utils::with_ext,
	Runtime, RuntimeCall, RuntimeOrigin,
};
use frame_support::traits::{FindAuthor, Get, Hooks, PalletInfoAccess};
use pallet_validator_set::NodeVersion;
use sp_runtime::traits::Dispatchable;

#[test]
fn the_author_is_the_session_validator_not_its_aura_key() {
	with_ext(|| {
		let set = validator_set();
		let logs = digest(1);
		let found =
			ValidatorAuthor::find_author(logs.logs.iter().filter_map(|d| d.as_pre_runtime()));
		assert_eq!(found, Some(set.bob.clone()));
		assert_ne!(found, Some(as_account(&set.bob_aura)));
		let logs = digest(0);
		let found =
			ValidatorAuthor::find_author(logs.logs.iter().filter_map(|d| d.as_pre_runtime()));
		assert_eq!(found, Some(set.alice));
	});
}

#[test]
fn a_setkeys_validator_has_its_version_recorded() {
	with_ext(|| {
		let set = validator_set();
		start_block(1);
		let version = NodeVersion::new(0, 4, 0);
		RuntimeCall::ValidatorSet(pallet_validator_set::Call::note_author_version { version })
			.dispatch(RuntimeOrigin::none())
			.expect("the declaration is accepted");
		assert_eq!(
			pallet_validator_set::LastAuthorVersion::<Runtime>::get(&set.bob),
			Some((version, 1))
		);
	});
}

fn start_block(slot: u64) {
	frame_system::Pallet::<Runtime>::initialize(&1, &Default::default(), &digest(slot));
	<crate::ValidatorSet as Hooks<u32>>::on_initialize(1);
}

/// A session rotation in the block's hooks replaces the session's validators and
/// Aura's authorities after the validator set noted the author: the declaration
/// is credited to the validator that authored, not to the one of the new set
/// its slot names now.
#[test]
fn a_rotation_block_credits_the_validator_that_authored_it() {
	with_ext(|| {
		let set = validator_set();
		start_block(1);
		// What `Session::on_initialize` does at a boundary.
		let (carol_aura, dave_aura) = (aura_key("//CarolAura"), aura_key("//DaveAura"));
		let (carol, dave) = (as_account(&carol_aura), as_account(&dave_aura));
		pallet_session::Validators::<Runtime>::put(vec![carol.clone(), dave.clone()]);
		pallet_aura::Authorities::<Runtime>::put(
			frame_support::BoundedVec::try_from(vec![carol_aura, dave_aura]).unwrap(),
		);
		let version = NodeVersion::new(0, 4, 0);
		RuntimeCall::ValidatorSet(pallet_validator_set::Call::note_author_version { version })
			.dispatch(RuntimeOrigin::none())
			.expect("the declaration is accepted");
		assert_eq!(
			pallet_validator_set::LastAuthorVersion::<Runtime>::get(&set.bob),
			Some((version, 1))
		);
		assert_eq!(
			pallet_validator_set::LastAuthorVersion::<Runtime>::get(&dave),
			None
		);
		assert_eq!(
			pallet_validator_set::LastAuthorVersion::<Runtime>::get(&carol),
			None
		);
	});
}

/// The validator set resolves its author before the session can rotate: its
/// hooks run first.
#[test]
fn the_validator_set_runs_before_the_session() {
	assert!(crate::ValidatorSet::index() < crate::Session::index());
}

#[test]
fn spend_fees_go_to_the_validator_account() {
	with_ext(|| {
		let set = validator_set();
		frame_system::Pallet::<Runtime>::initialize(&1, &Default::default(), &digest(1));
		assert_eq!(
			pallet_authorship::Pallet::<Runtime>::author(),
			Some(set.bob.clone())
		);
		assert_eq!(ValidatorAccountAuthor::get(), Some(set.bob));
	});
}
