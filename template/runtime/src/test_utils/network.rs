// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

//! A network of dev validators (Alice, Bob, Charlie, and up to Ferdie), as the
//! local chain spec builds it, and their GRANDPA equivocations.

use super::blocks::run_to_era;
use crate::{
	genesis::DEV_PRESET_ID,
	staking::params::TEST_MIN_VALIDATOR_BOND,
	test_utils::{account, preset_json},
	AccountId, Grandpa, Historical, Runtime, RuntimeGenesisConfig, RuntimeOrigin,
};
use frame_support::traits::KeyOwnerProofSystem;
use sp_consensus_grandpa::{AuthorityId as GrandpaId, EquivocationProof, KEY_TYPE};
use sp_core::{crypto::UncheckedFrom, Pair, H256};
use sp_keyring::{Ed25519Keyring, Sr25519Keyring};

const VALIDATORS: [(Sr25519Keyring, Ed25519Keyring); 6] = [
	(Sr25519Keyring::Alice, Ed25519Keyring::Alice),
	(Sr25519Keyring::Bob, Ed25519Keyring::Bob),
	(Sr25519Keyring::Charlie, Ed25519Keyring::Charlie),
	(Sr25519Keyring::Dave, Ed25519Keyring::Dave),
	(Sr25519Keyring::Eve, Ed25519Keyring::Eve),
	(Sr25519Keyring::Ferdie, Ed25519Keyring::Ferdie),
];

pub(crate) fn charlie() -> AccountId {
	account(Sr25519Keyring::Charlie)
}

/// The dev preset with Alice, Bob and Charlie bonded and keyed, as the local
/// chain spec does.
pub(crate) fn genesis() -> sp_io::TestExternalities {
	genesis_of(3)
}

/// The dev preset with the first `n` dev validators bonded and keyed.
pub(crate) fn genesis_of(n: usize) -> sp_io::TestExternalities {
	let validators = &VALIDATORS[..n];
	let mut config: RuntimeGenesisConfig =
		serde_json::from_slice(&preset_json(DEV_PRESET_ID)).expect("full config");
	let accounts: Vec<_> = validators.iter().map(|(sr, _)| account(*sr)).collect();
	config.session.keys = validators
		.iter()
		.map(|(sr, ed)| {
			let who = account(*sr);
			(
				who.clone(),
				who,
				crate::opaque::SessionKeys {
					aura: sp_consensus_aura::sr25519::AuthorityId::unchecked_from(sr.public().0),
					grandpa: GrandpaId::unchecked_from(ed.public().0),
				},
			)
		})
		.collect();
	// The dev preset funds Alice, Bob and Charlie; the rest get their bond here.
	for who in &accounts {
		if !config
			.balances
			.balances
			.iter()
			.any(|(funded, _)| funded == who)
		{
			config
				.balances
				.balances
				.push((who.clone(), 10 * TEST_MIN_VALIDATOR_BOND));
		}
	}
	config.staking.validator_count = n as u32;
	config.staking.stakers = accounts
		.iter()
		.map(|who| {
			(
				who.clone(),
				TEST_MIN_VALIDATOR_BOND,
				pallet_staking_async::StakerStatus::Validator,
			)
		})
		.collect();
	config.validator_set.initial_validators = accounts;
	let mut ext = sp_io::TestExternalities::default();
	ext.execute_with(|| {
		crate::genesis::build_state(serde_json::to_vec(&config).unwrap()).expect("genesis")
	});
	ext
}

/// [`genesis`], run to era 1 so the election has given the validators real
/// exposures.
pub(crate) fn with_validators<R>(run: impl FnOnce() -> R) -> R {
	with_validators_of(3, run)
}

/// [`genesis_of`] `n`, run to era 1 so the election has given the validators
/// real exposures.
pub(crate) fn with_validators_of<R>(n: usize, run: impl FnOnce() -> R) -> R {
	genesis_of(n).execute_with(|| {
		// Era 0 runs on the genesis keys without exposures; the first election
		// gives era 1 real ones for an offence to slash.
		run_to_era(1);
		// Vote weight round-trips through `u64`, so the total is a hair under n bonds.
		let total = pallet_staking_async::ErasTotalStake::<Runtime>::get(1);
		assert!(
			total > n as u128 * TEST_MIN_VALIDATOR_BOND * 999 / 1000,
			"era 1 total stake {total}"
		);
		run()
	})
}

/// Two conflicting prevotes from `key` in round 1 of set `set_id`.
pub(crate) fn prevote_equivocation(
	key: Ed25519Keyring,
	set_id: u64,
) -> EquivocationProof<H256, u32> {
	prevote_equivocation_in_round(key, set_id, 1)
}

/// Two conflicting prevotes from `key` in `round` of set `set_id`.
pub(crate) fn prevote_equivocation_in_round(
	key: Ed25519Keyring,
	set_id: u64,
	round: u64,
) -> EquivocationProof<H256, u32> {
	let sign = |target: H256| {
		let prevote = finality_grandpa::Prevote {
			target_hash: target,
			target_number: 1,
		};
		let payload = sp_consensus_grandpa::localized_payload(
			round,
			set_id,
			&finality_grandpa::Message::Prevote(prevote.clone()),
		);
		(prevote, key.pair().sign(&payload).into())
	};
	EquivocationProof::new(
		set_id,
		sp_consensus_grandpa::Equivocation::Prevote(finality_grandpa::Equivocation {
			round_number: round,
			identity: GrandpaId::unchecked_from(key.public().0),
			first: sign(H256::repeat_byte(1)),
			second: sign(H256::repeat_byte(2)),
		}),
	)
}

pub(crate) fn report_charlie() -> frame_support::dispatch::DispatchResultWithPostInfo {
	report_in_round(Ed25519Keyring::Charlie, 1)
}

/// `key`'s equivocation in `round` of the current set, with its key-owner proof
/// for the current session.
pub(crate) fn equivocation_now(
	key: Ed25519Keyring,
	round: u64,
) -> (EquivocationProof<H256, u32>, sp_session::MembershipProof) {
	let proof = prevote_equivocation_in_round(key, Grandpa::current_set_id(), round);
	let key_owner = Historical::prove((KEY_TYPE, GrandpaId::unchecked_from(key.public().0)))
		.expect("a session validator");
	(proof, key_owner)
}

/// A signed report, by `reporter`, of `key`'s equivocation in `round` of the
/// current set.
pub(crate) fn report_signed_in_round(
	reporter: &AccountId,
	key: Ed25519Keyring,
	round: u64,
) -> frame_support::dispatch::DispatchResultWithPostInfo {
	let (proof, key_owner) = equivocation_now(key, round);
	Grandpa::report_equivocation(
		RuntimeOrigin::signed(reporter.clone()),
		Box::new(proof),
		key_owner,
	)
}

/// An unsigned report of `key`'s equivocation in `round` of the current set.
pub(crate) fn report_in_round(
	key: Ed25519Keyring,
	round: u64,
) -> frame_support::dispatch::DispatchResultWithPostInfo {
	let proof = prevote_equivocation_in_round(key, Grandpa::current_set_id(), round);
	let key_owner = Historical::prove((KEY_TYPE, GrandpaId::unchecked_from(key.public().0)))
		.expect("a session validator");
	Grandpa::report_equivocation_unsigned(RuntimeOrigin::none(), Box::new(proof), key_owner)
}
