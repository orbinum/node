// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

//! Every staking role's call — a nominator's, a validator's, a pool member's and a pool
//! owner's — is signed as text by an EVM wallet (`EcdsaText`), a Solana wallet
//! (`Ed25519Text`) and a Substrate extension (`Ed25519WrappedText`), just as a
//! Substrate key signs it. Each has a shared vector, so clients render the same text.

use super::{ecdsa::sign_eip191, *};
use crate::{signature::OrbinumSigner, test_utils::ALITH_KEY};
use alloc::collections::BTreeSet;
use frame_support::traits::GetCallMetadata;
use sp_runtime::traits::IdentifyAccount;

/// The pallets whose calls the staking roles make.
const ROLE_PALLETS: &[&str] = &[
	"Staking",
	"NominationPools",
	"PrivateStaking",
	"Session",
	"ValidatorSet",
];

/// Whether a shared vector is a staking role's call (by its name).
pub(super) fn is_role_vector(name: &str) -> bool {
	[
		"staking_",
		"pools_",
		"private_staking_",
		"session_",
		"validator_set_",
	]
	.iter()
	.any(|prefix| name.starts_with(prefix))
}

fn call_name(call: &RuntimeCall) -> String {
	let meta = call.get_call_metadata();
	format!("{}.{}", meta.pallet_name, meta.function_name)
}

#[test]
fn every_staking_role_call_signs_as_text_from_evm_solana_and_extensions() {
	with_ext(|| {
		set_genesis(TESTNET_GENESIS);
		let (ed, ed_account) = keypair();
		let evm = sp_core::ecdsa::Pair::from_seed(&ALITH_KEY);
		let evm_account = OrbinumSigner::Ecdsa(evm.public()).into_account();

		let mut covered = BTreeSet::new();
		for (name, payload) in super::vectors::vector_messages() {
			if !is_role_vector(name) || !crate::signature::text_signable(&payload) {
				continue;
			}
			let call = RuntimeCall::decode(&mut &payload[..]).expect("a call");
			covered.insert(call_name(&call));
			assert_eq!(
				check(call.clone(), &ed_account, sign_text(&ed, &call, 0), 0),
				Ok(()),
				"{name}: Solana (Ed25519Text)"
			);
			assert_eq!(
				check(
					call.clone(),
					&ed_account,
					sign_wrapped_text(&ed, &call, 0),
					0
				),
				Ok(()),
				"{name}: extension (Ed25519WrappedText)"
			);
			let evm_sig = OrbinumSignature::EcdsaText(sign_eip191(&evm, &raw_payload(&call, 0)));
			assert_eq!(
				check(call, &evm_account, evm_sig, 0),
				Ok(()),
				"{name}: EVM (EcdsaText)"
			);
		}

		// Every text-signable call of these pallets has a vector: none is left to
		// Substrate keys alone.
		let expected: BTreeSet<String> = crate::signature::text::summary::tests::SIGNABLE_CALLS
			.iter()
			.filter(|call| {
				ROLE_PALLETS
					.iter()
					.any(|p| call.starts_with(&format!("{p}.")))
			})
			.map(|call| call.to_string())
			.collect();
		let missing: Vec<_> = expected.difference(&covered).collect();
		assert!(missing.is_empty(), "no shared vector for {missing:?}");
	});
}
