// This file is part of Frontier.

// Copyright (C) Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Signatures checked over the whole signing payload.
//!
//! `generic::UncheckedExtrinsic::check` hands `Verify::verify` the payload's blake2_256
//! once it is over 256 bytes. A signature over a text rendered from the payload, which a
//! person reads before signing, needs the payload itself at any size: it implements
//! [`VerifyFullPayload`], and [`check`] verifies it as Substrate's check does, except for
//! that hash.

use scale_codec::Encode;
use sp_runtime::{
	generic::{self, ExtrinsicFormat, Preamble},
	traits::{Lookup, TransactionExtension},
	transaction_validity::{InvalidTransaction, TransactionValidityError},
};

use crate::{CheckedExtrinsic, CheckedSignature, SelfContainedCall};

/// A signature checked over the whole signing payload.
pub trait VerifyFullPayload<AccountId> {
	/// Whether [`Self::verify_full_payload`] checks this signature, instead of
	/// `Verify::verify` over what Substrate's check would pass it.
	fn covers_full_payload(&self) -> bool;

	/// Checks the signature over `payload`: the call, the extension and its implicit
	/// data, as encoded, never hashed.
	fn verify_full_payload(&self, payload: &[u8], signer: &AccountId) -> bool;
}

/// `generic::UncheckedExtrinsic::check` for a signed extrinsic whose signature covers
/// the whole payload. Anything else is `BadProof`: the caller routes only those here.
pub(crate) fn check<Address, AccountId, Call, Signature, Extension, L>(
	xt: generic::UncheckedExtrinsic<Address, Call, Signature, Extension>,
	lookup: &L,
) -> Result<
	CheckedExtrinsic<AccountId, Call, Extension, <Call as SelfContainedCall>::SignedInfo>,
	TransactionValidityError,
>
where
	Call: Encode + SelfContainedCall,
	Extension: Encode + TransactionExtension<Call>,
	Signature: VerifyFullPayload<AccountId>,
	L: Lookup<Source = Address, Target = AccountId>,
{
	let Preamble::Signed(address, signature, tx_ext) = xt.preamble else {
		return Err(InvalidTransaction::BadProof.into());
	};
	let signed = lookup.lookup(address)?;
	let (function, tx_ext, implicit) =
		generic::SignedPayload::new(xt.function, tx_ext)?.deconstruct();
	// The bytes `SignedPayload` encodes, before its hashing above 256 bytes.
	let payload = (&function, &tx_ext, &implicit).encode();
	if !signature.verify_full_payload(&payload, &signed) {
		return Err(InvalidTransaction::BadProof.into());
	}
	Ok(CheckedExtrinsic {
		signed: CheckedSignature::GenericDelegated(ExtrinsicFormat::Signed(signed, tx_ext)),
		function,
	})
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::UncheckedExtrinsic;
	use scale_codec::{Decode, DecodeWithMemTracking};
	use scale_info::TypeInfo;
	use sp_runtime::{
		testing::UintAuthorityId,
		traits::{BlakeTwo256, Checkable, DispatchInfoOf, Dispatchable, Hash, IdentityLookup},
		transaction_validity::TransactionValidity,
		DispatchResultWithInfo,
	};

	/// A call whose encoding has any length.
	#[derive(
		Clone,
		PartialEq,
		Eq,
		Debug,
		Encode,
		Decode,
		DecodeWithMemTracking,
		TypeInfo
	)]
	struct TestCall(Vec<u8>);

	impl Dispatchable for TestCall {
		type RuntimeOrigin = ();
		type Config = ();
		type Info = ();
		type PostInfo = ();
		fn dispatch(self, _: ()) -> DispatchResultWithInfo<()> {
			Ok(())
		}
	}

	impl SelfContainedCall for TestCall {
		type SignedInfo = ();
		fn is_self_contained(&self) -> bool {
			false
		}
		fn check_self_contained(&self) -> Option<Result<(), TransactionValidityError>> {
			None
		}
		fn validate_self_contained(
			&self,
			_: &(),
			_: &DispatchInfoOf<Self>,
			_: usize,
		) -> Option<TransactionValidity> {
			None
		}
		fn apply_self_contained(self, _: ()) -> Option<DispatchResultWithInfo<()>> {
			None
		}
	}

	/// Valid over exactly `accepts`, through whichever path `full` selects.
	#[derive(
		Clone,
		PartialEq,
		Eq,
		Debug,
		Encode,
		Decode,
		DecodeWithMemTracking,
		TypeInfo
	)]
	struct TestSignature {
		full: bool,
		accepts: Vec<u8>,
	}

	impl sp_runtime::traits::Verify for TestSignature {
		type Signer = UintAuthorityId;
		fn verify<M: sp_runtime::traits::Lazy<[u8]>>(&self, mut msg: M, _: &u64) -> bool {
			!self.full && msg.get() == &self.accepts[..]
		}
	}

	impl VerifyFullPayload<u64> for TestSignature {
		fn covers_full_payload(&self) -> bool {
			self.full
		}
		fn verify_full_payload(&self, payload: &[u8], _: &u64) -> bool {
			self.full && payload == &self.accepts[..]
		}
	}

	const SIGNER: u64 = 7;

	/// A call whose payload (the call alone, with a `()` extension) is over 256 bytes.
	fn long_call() -> TestCall {
		TestCall(vec![0xab; 400])
	}

	fn check_signed(
		call: TestCall,
		signature: TestSignature,
	) -> Result<(), TransactionValidityError> {
		let xt = UncheckedExtrinsic::<u64, TestCall, TestSignature, ()>::new_signed(
			call.clone(),
			SIGNER,
			signature,
			(),
		);
		let checked = xt.check(&IdentityLookup::<u64>::default())?;
		assert_eq!(
			checked.signed,
			CheckedSignature::GenericDelegated(ExtrinsicFormat::Signed(SIGNER, ()))
		);
		assert_eq!(checked.function, call);
		Ok(())
	}

	#[test]
	fn a_full_payload_signature_is_checked_over_the_whole_payload() {
		let call = long_call();
		let payload = call.encode();
		assert!(payload.len() > 256);
		let sig = TestSignature {
			full: true,
			accepts: payload,
		};
		assert_eq!(check_signed(call, sig), Ok(()));
	}

	#[test]
	fn a_full_payload_signature_over_the_hash_is_refused() {
		let call = long_call();
		let hash = BlakeTwo256::hash(&call.encode()).0.to_vec();
		let sig = TestSignature {
			full: true,
			accepts: hash,
		};
		assert_eq!(
			check_signed(call, sig),
			Err(InvalidTransaction::BadProof.into())
		);
	}

	#[test]
	fn other_signatures_keep_substrates_check() {
		let call = long_call();
		let hash = BlakeTwo256::hash(&call.encode()).0.to_vec();
		let hashed = TestSignature {
			full: false,
			accepts: hash,
		};
		assert_eq!(check_signed(call.clone(), hashed), Ok(()));

		let whole = TestSignature {
			full: false,
			accepts: call.encode(),
		};
		assert_eq!(
			check_signed(call, whole),
			Err(InvalidTransaction::BadProof.into())
		);
	}

	#[test]
	fn a_short_payload_is_the_same_bytes_on_both_paths() {
		let call = TestCall(vec![1, 2, 3]);
		for full in [true, false] {
			let sig = TestSignature {
				full,
				accepts: call.encode(),
			};
			assert_eq!(check_signed(call.clone(), sig), Ok(()), "full = {full}");
		}
	}
}
