// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

//! Extrinsic builders and inherent data for `benchmark overhead` and
//! `benchmark extrinsic`. Benchmarking only.

use std::{sync::Arc, time::Duration};

use sc_cli::Result;
use scale_codec::Encode;
use sp_core::{ecdsa, sr25519, Pair, H256};
use sp_inherents::{InherentData, InherentDataProvider};
use sp_runtime::{
	generic::Era,
	traits::{IdentifyAccount, Verify},
	OpaqueExtrinsic, SaturatedConversion,
};

use crate::client::Client;
use orbinum_runtime::{self as runtime, AccountId, Balance, BalancesCall, BlockNumber, SystemCall};

#[cfg(test)]
mod tests;

/// The account every benchmark extrinsic is signed by: `//Bob`, funded in the dev genesis.
fn signer() -> sr25519::Pair {
	sr25519::Pair::from_string("//Bob", None).expect("static seed is valid")
}

/// The account of the ECDSA key derived from a well-known dev seed (e.g. `"Alice"`).
pub fn dev_ecdsa_account(seed: &str) -> AccountId {
	let public = ecdsa::Pair::from_string(&format!("//{seed}"), None)
		.expect("static seed is valid")
		.public();
	<runtime::Signature as Verify>::Signer::from(public).into_account()
}

/// Generates `System::remark` extrinsics for `benchmark overhead`.
pub struct RemarkBuilder {
	client: Arc<Client>,
}

impl RemarkBuilder {
	/// Creates a new [`Self`] from the given client.
	pub fn new(client: Arc<Client>) -> Self {
		Self { client }
	}
}

impl frame_benchmarking_cli::ExtrinsicBuilder for RemarkBuilder {
	fn pallet(&self) -> &str {
		"system"
	}

	fn extrinsic(&self) -> &str {
		"remark"
	}

	fn build(&self, nonce: u32) -> std::result::Result<OpaqueExtrinsic, &'static str> {
		let call = SystemCall::remark { remark: vec![] }.into();
		Ok(create_benchmark_extrinsic(&self.client, signer(), call, nonce).into())
	}
}

/// Generates `Balances::transfer_keep_alive` extrinsics for `benchmark extrinsic`.
pub struct TransferKeepAliveBuilder {
	client: Arc<Client>,
	dest: AccountId,
	value: Balance,
}

impl TransferKeepAliveBuilder {
	/// Creates a new [`Self`] from the given client.
	pub fn new(client: Arc<Client>, dest: AccountId, value: Balance) -> Self {
		Self {
			client,
			dest,
			value,
		}
	}
}

impl frame_benchmarking_cli::ExtrinsicBuilder for TransferKeepAliveBuilder {
	fn pallet(&self) -> &str {
		"balances"
	}

	fn extrinsic(&self) -> &str {
		"transfer_keep_alive"
	}

	fn build(&self, nonce: u32) -> std::result::Result<OpaqueExtrinsic, &'static str> {
		let call = BalancesCall::transfer_keep_alive {
			dest: self.dest.clone(),
			value: self.value,
		}
		.into();
		Ok(create_benchmark_extrinsic(&self.client, signer(), call, nonce).into())
	}
}

/// Signs `call` as `sender`, valid from the client's best block.
pub fn create_benchmark_extrinsic(
	client: &Client,
	sender: sr25519::Pair,
	call: runtime::RuntimeCall,
	nonce: u32,
) -> runtime::UncheckedExtrinsic {
	let info = client.chain_info();
	signed_extrinsic(
		sender,
		call,
		nonce,
		info.genesis_hash,
		info.best_hash,
		info.best_number,
	)
}

/// Signs `call` as `sender` against the runtime's `SignedExtra`, mortal from
/// `best_number` (whose hash is `best_hash`).
fn signed_extrinsic(
	sender: sr25519::Pair,
	call: runtime::RuntimeCall,
	nonce: u32,
	genesis_hash: H256,
	best_hash: H256,
	best_number: BlockNumber,
) -> runtime::UncheckedExtrinsic {
	let period = runtime::BlockHashCount::get()
		.checked_next_power_of_two()
		.map(|c| c / 2)
		.unwrap_or(2) as u64;
	let extra: runtime::SignedExtra = (
		frame_system::CheckNonZeroSender::<runtime::Runtime>::new(),
		frame_system::CheckSpecVersion::<runtime::Runtime>::new(),
		frame_system::CheckTxVersion::<runtime::Runtime>::new(),
		frame_system::CheckGenesis::<runtime::Runtime>::new(),
		frame_system::CheckMortality::<runtime::Runtime>::from(Era::mortal(
			period,
			best_number.saturated_into(),
		)),
		frame_system::CheckNonce::<runtime::Runtime>::from(nonce),
		frame_system::CheckWeight::<runtime::Runtime>::new(),
		pallet_transaction_payment::ChargeTransactionPayment::<runtime::Runtime>::from(0),
		frame_metadata_hash_extension::CheckMetadataHash::<runtime::Runtime>::new(false),
		runtime::staking::candidacy::CheckValidatorCandidacy,
	);

	let raw_payload = runtime::SignedPayload::from_raw(
		call.clone(),
		extra.clone(),
		(
			(),
			runtime::VERSION.spec_version,
			runtime::VERSION.transaction_version,
			genesis_hash,
			best_hash,
			(),
			(),
			(),
			None::<[u8; 32]>,
			(),
		),
	);
	let signature = raw_payload.using_encoded(|e| sender.sign(e));

	runtime::UncheckedExtrinsic::new_signed(
		call,
		<runtime::Signature as Verify>::Signer::from(sender.public()).into_account(),
		runtime::Signature::Sr25519(signature),
		extra,
	)
}

/// Generates inherent data for the `benchmark overhead` command.
pub fn inherent_benchmark_data() -> Result<InherentData> {
	let mut inherent_data = InherentData::new();
	let d = Duration::from_millis(0);
	let timestamp = sp_timestamp::InherentDataProvider::new(d.into());

	futures::executor::block_on(timestamp.provide_inherent_data(&mut inherent_data))
		.map_err(|e| format!("creating inherent data: {e:?}"))?;
	Ok(inherent_data)
}
