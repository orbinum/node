// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

//! The runtime's primitive types and its extrinsic format.

use crate::{signature::OrbinumSignature, staking, Runtime, RuntimeCall};
use sp_core::{H160, H256};
use sp_runtime::{
	generic::{self, Era},
	traits::BlakeTwo256,
};

pub type BlockNumber = u32;
pub type Signature = OrbinumSignature;
pub type AccountId = sp_runtime::AccountId32;
pub type AccountIndex = u32;
pub type Balance = u128;
pub type Nonce = u32;
pub type Hash = H256;
pub type Hashing = BlakeTwo256;
pub type DigestItem = generic::DigestItem;
pub type Address = AccountId;
pub type Header = generic::Header<BlockNumber, BlakeTwo256>;
pub type Block = generic::Block<Header, UncheckedExtrinsic>;
pub type SignedBlock = generic::SignedBlock<Block>;
pub type BlockId = generic::BlockId<Block>;

/// Order is wire format, not style: clients and Tesseract sign payloads built from
/// these extensions in this order. Reordering, or inserting one that encodes any
/// data, invalidates every signature they produce.
///
/// `CheckValidatorCandidacy` encodes to nothing, explicit or implicit, so it changes no
/// extrinsic or payload; clients that build from metadata (subxt, PAPI, polkadot.js)
/// skip an empty extension they do not know.
pub type SignedExtra = (
	frame_system::CheckNonZeroSender<Runtime>,
	frame_system::CheckSpecVersion<Runtime>,
	frame_system::CheckTxVersion<Runtime>,
	frame_system::CheckGenesis<Runtime>,
	frame_system::CheckEra<Runtime>,
	frame_system::CheckNonce<Runtime>,
	frame_system::CheckWeight<Runtime>,
	pallet_transaction_payment::ChargeTransactionPayment<Runtime>,
	frame_metadata_hash_extension::CheckMetadataHash<Runtime>,
	staking::candidacy::CheckValidatorCandidacy,
);

/// Named access to the [`SignedExtra`] fields read outside their extension.
pub trait SignedExtraFields {
	/// The mortality `CheckEra` carries.
	fn era(&self) -> Era;
	/// The account nonce `CheckNonce` carries.
	fn nonce(&self) -> Nonce;
	/// The tip `ChargeTransactionPayment` carries.
	fn tip(&self) -> Balance;
}

impl SignedExtraFields for SignedExtra {
	fn era(&self) -> Era {
		self.4 .0
	}

	fn nonce(&self) -> Nonce {
		self.5 .0
	}

	fn tip(&self) -> Balance {
		self.7.tip()
	}
}

pub type UncheckedExtrinsic =
	fp_self_contained::UncheckedExtrinsic<Address, RuntimeCall, Signature, SignedExtra>;

pub type CheckedExtrinsic =
	fp_self_contained::CheckedExtrinsic<AccountId, RuntimeCall, SignedExtra, H160>;

pub type SignedPayload = generic::SignedPayload<RuntimeCall, SignedExtra>;
