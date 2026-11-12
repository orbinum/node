// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

//! The benchmark extrinsics pass the runtime's validation on the dev genesis.

use super::*;
use scale_codec::Decode;
use sp_runtime::{transaction_validity::TransactionSource, BuildStorage};

/// Validates `call`, signed by [`signer`], against the dev genesis.
fn validate(call: runtime::RuntimeCall) {
	let storage = crate::chain_spec::development_config(false)
		.expect("dev spec")
		.build_storage()
		.expect("dev genesis builds");
	let genesis_hash = H256::repeat_byte(7);
	let xt = signed_extrinsic(signer(), call, 0, genesis_hash, genesis_hash, 0);
	let xt = runtime::UncheckedExtrinsic::decode(&mut &xt.encode()[..])
		.expect("decodes as the runtime's extrinsic");

	sp_io::TestExternalities::new(storage).execute_with(|| {
		// Block 1 is being validated; block 0's hash is `genesis_hash`.
		let validity =
			runtime::Executive::validate_transaction(TransactionSource::External, xt, genesis_hash);
		assert!(validity.is_ok(), "{validity:?}");
	});
}

#[test]
fn remark_is_accepted_by_the_runtime() {
	validate(SystemCall::remark { remark: vec![] }.into());
}

#[test]
fn transfer_keep_alive_is_accepted_by_the_runtime() {
	validate(
		BalancesCall::transfer_keep_alive {
			dest: dev_ecdsa_account("Alice"),
			value: runtime::EXISTENTIAL_DEPOSIT,
		}
		.into(),
	);
}
