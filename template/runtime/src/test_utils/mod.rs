// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

//! Helpers the runtime's tests share: accounts, extensions, calls and genesis, and
//! running the whole runtime.
//!
//! - `blocks`: running blocks, sessions and eras.
//! - `network`: a network of validators with dev keys.
//! - `authorship`: block authors.

pub(crate) mod authorship;
pub(crate) mod blocks;
pub(crate) mod network;

use crate::{
	genesis::{get_preset, mainnet, DEV_PRESET_ID, MAINNET_PRESET_ID},
	AccountId, BalancesCall, Runtime, RuntimeCall, SignedExtra,
};
use hex_literal::hex;
use sp_core::H256;
use sp_io::TestExternalities;
use sp_keyring::Sr25519Keyring;
use sp_runtime::generic::Era;

pub(crate) use crate::primitives::constants::ORB;

/// Alith, the dev EVM account: its secp256k1 key and EVM address are well known.
pub(crate) const ALITH_KEY: [u8; 32] =
	hex!("5fb92d6e98884f76de468fa3f6278f8807c48bebc13595d45af5bdc4da702133");
pub(crate) const ALITH_ADDRESS: [u8; 20] = hex!("f24ff3a9cf04c71dbc94d0b566f7a27b94566cac");

/// The recipient of the test transfers.
pub(crate) const BOB: [u8; 32] = [0xb0; 32];

/// A keyring account, as its sr25519 key's bytes.
pub(crate) fn account(key: Sr25519Keyring) -> AccountId {
	AccountId::from(key.public().0)
}

pub(crate) fn with_ext<R>(run: impl FnOnce() -> R) -> R {
	TestExternalities::default().execute_with(run)
}

/// A preset's genesis JSON, mainnet's included although `get_preset` does not
/// offer it until it is configured.
pub(crate) fn preset_json(id: &str) -> Vec<u8> {
	if id == MAINNET_PRESET_ID {
		return serde_json::to_vec(&mainnet::mainnet()).unwrap();
	}
	get_preset(&id.into()).expect("preset exists")
}

/// Runs `run` on the genesis the preset `id` builds, as the node builds it.
pub(crate) fn with_preset<R>(id: &str, run: impl FnOnce() -> R) -> R {
	let json = preset_json(id);
	TestExternalities::default().execute_with(|| {
		crate::genesis::build_state(json).expect("preset builds");
		run()
	})
}

/// The development chain id: transactions name it.
pub(crate) const CHAIN_ID: u64 = 42;

/// Runs `run` on the development preset, where Alith holds the supply, at block 1.
pub(crate) fn with_dev_chain<R>(run: impl FnOnce() -> R) -> R {
	with_preset(DEV_PRESET_ID, || {
		frame_system::Pallet::<Runtime>::set_block_number(1);
		frame_system::BlockHash::<Runtime>::insert(0u32, H256::repeat_byte(1));
		run()
	})
}

/// Every extension at its default, with this nonce, tip and mortality, and
/// `CheckMetadataHash` disabled.
pub(crate) fn signed_extra_with_era(nonce: u32, tip: u128, era: Era) -> SignedExtra {
	(
		frame_system::CheckNonZeroSender::new(),
		frame_system::CheckSpecVersion::new(),
		frame_system::CheckTxVersion::new(),
		frame_system::CheckGenesis::new(),
		frame_system::CheckEra::from(era),
		frame_system::CheckNonce::from(nonce),
		frame_system::CheckWeight::new(),
		pallet_transaction_payment::ChargeTransactionPayment::from(tip),
		frame_metadata_hash_extension::CheckMetadataHash::new(false),
		crate::staking::candidacy::CheckValidatorCandidacy,
	)
}

/// [`signed_extra_with_era`], immortal.
pub(crate) fn signed_extra(nonce: u32, tip: u128) -> SignedExtra {
	signed_extra_with_era(nonce, tip, Era::Immortal)
}

/// `transfer_keep_alive` of `value` to [`BOB`].
pub(crate) fn transfer(value: u128) -> RuntimeCall {
	RuntimeCall::Balances(BalancesCall::transfer_keep_alive {
		dest: AccountId::from(BOB),
		value,
	})
}

/// A shield of `amount` of `asset_id`, with fixed commitment, memo and proof.
pub(crate) fn shield(asset_id: u32, amount: u128) -> RuntimeCall {
	RuntimeCall::ShieldedPool(pallet_shielded_pool::Call::<Runtime>::shield {
		asset_id,
		amount,
		commitment: pallet_shielded_pool::Commitment::new([0x1c; 32]),
		encrypted_memo: pallet_shielded_pool::FrameEncryptedMemo::new(vec![0x3e; 180]).unwrap(),
		proof: vec![0x9f; 128].try_into().unwrap(),
		circuit_version: 1,
	})
}
