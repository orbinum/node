//! The whole extrinsic check: text signatures over payloads of any size pass, and a
//! change to the call, the extension or the chain fails; other signatures keep
//! Substrate's check.

use super::*;
use sp_runtime::transaction_validity::InvalidTransaction;

#[test]
fn signed_extrinsic_with_short_payload_passes_check() {
	with_ext(|| {
		set_genesis(TESTNET_GENESIS);
		let (pair, account) = keypair();
		let call = remark(20);
		assert!(raw_payload(&call, 0).len() <= 256);
		let sig = sign_text(&pair, &call, 0);
		assert_eq!(check(call, &account, sig, 0), Ok(()));
	});
}

#[test]
fn signed_extrinsic_with_long_payload_passes_check() {
	with_ext(|| {
		set_genesis(TESTNET_GENESIS);
		let (pair, account) = keypair();
		let call = remark(300);
		assert!(raw_payload(&call, 0).len() > 256);
		let sig = sign_text(&pair, &call, 0);
		assert_eq!(check(call, &account, sig, 0), Ok(()));
	});
}

#[test]
fn wrapped_text_extrinsics_pass_check_short_and_long() {
	with_ext(|| {
		set_genesis(TESTNET_GENESIS);
		let (pair, account) = keypair();
		for len in [20, 300] {
			let call = remark(len);
			let sig = sign_wrapped_text(&pair, &call, 0);
			assert_eq!(
				check(call, &account, sig, 0),
				Ok(()),
				"remark of {len} bytes"
			);
		}
	});
}

#[test]
fn signed_extrinsic_with_changed_extension_fails_check() {
	with_ext(|| {
		set_genesis(TESTNET_GENESIS);
		let (pair, account) = keypair();
		let sig = sign_text(&pair, &remark(20), 0);
		assert_eq!(
			check(remark(20), &account, sig, 1),
			Err(InvalidTransaction::BadProof.into())
		);
	});
}

#[test]
fn signed_extrinsic_with_changed_call_fails_check() {
	with_ext(|| {
		set_genesis(TESTNET_GENESIS);
		let (pair, account) = keypair();
		let sig = sign_text(&pair, &remark(20), 0);
		assert_eq!(
			check(remark(21), &account, sig, 0),
			Err(InvalidTransaction::BadProof.into())
		);
	});
}

#[test]
fn signed_extrinsic_signed_for_another_chain_fails_check() {
	with_ext(|| {
		set_genesis([0x22; 32]);
		let (pair, account) = keypair();
		let sig = sign_text(&pair, &remark(20), 0);
		set_genesis(TESTNET_GENESIS);
		assert_eq!(
			check(remark(20), &account, sig, 0),
			Err(InvalidTransaction::BadProof.into())
		);
	});
}

/// Only `0x03`/`0x04` take the whole-payload path: sr25519 still signs what
/// `Verify::verify` receives, the payload's blake2_256 above 256 bytes.
#[test]
fn sr25519_extrinsics_keep_the_generic_check() {
	with_ext(|| {
		set_genesis(TESTNET_GENESIS);
		let pair = sp_core::sr25519::Pair::from_seed(&[9u8; 32]);
		let account = AccountId::from(pair.public().0);
		for len in [20, 300] {
			let call = remark(len);
			let payload = SignedPayload::new(call.clone(), signed_extra(0)).unwrap();
			let sig = OrbinumSignature::Sr25519(payload.using_encoded(|m| pair.sign(m)));
			assert_eq!(check(call, &account, sig, 0), Ok(()), "{len} bytes");
		}
		let call = remark(300);
		let whole = OrbinumSignature::Sr25519(pair.sign(&raw_payload(&call, 0)));
		assert_eq!(
			check(call, &account, whole, 0),
			Err(InvalidTransaction::BadProof.into())
		);
	});
}
