// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

//! Keys and encodings `OrbinumSignature` refuses although the host primitive accepts them.

use crate::test_utils::with_ext;
use crate::{
	signature::{
		eip191_text_message, text_message, wrapped_text_message, OrbinumSignature, OrbinumSigner,
	},
	AccountId, Runtime,
};
use fp_self_contained::VerifyFullPayload;
use hex_literal::hex;
use sp_core::{ecdsa, ed25519, sr25519, Pair, H256};
use sp_runtime::traits::{IdentifyAccount, Verify};

/// `System.remark("any message")`: a call text signatures may authorise (bytes that
/// decode to no call never verify as text).
const MSG: &[u8] = b"\x00\x00\x2cany message";
const GENESIS: [u8; 32] = [0x5a; 32];

// Ed25519 text variants

/// Every small-order edwards25519 encoding, sign bit cleared.
const SMALL_ORDER: [[u8; 32]; 7] = [
	hex!("0000000000000000000000000000000000000000000000000000000000000000"),
	hex!("0100000000000000000000000000000000000000000000000000000000000000"),
	hex!("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"),
	hex!("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"),
	hex!("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
	hex!("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
	hex!("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
];

/// R = identity, s = 0: under ZIP-215, valid for a small-order key and any message.
const ED25519_FORGERY: [u8; 64] = {
	let mut sig = [0u8; 64];
	sig[0] = 0x01;
	sig
};

#[test]
fn ed25519_small_order_keys_are_refused() {
	with_ext(|| {
		frame_system::BlockHash::<Runtime>::insert(0u32, H256(GENESIS));
		let forged = ed25519::Signature::from_raw(ED25519_FORGERY);
		let text = text_message(&GENESIS, MSG);
		let wrapped = wrapped_text_message(&GENESIS, MSG);
		for key in SMALL_ORDER {
			let public = ed25519::Public::from_raw(key);
			// The host accepts the forgery, so each refusal below comes from the key check.
			assert!(sp_io::crypto::ed25519_verify(&forged, &text, &public));
			assert!(sp_io::crypto::ed25519_verify(&forged, &wrapped, &public));

			let mut negated = key;
			negated[31] |= 0x80;
			for k in [key, negated] {
				let account = AccountId::from(k);
				assert!(
					!OrbinumSignature::Ed25519Text(forged).verify_full_payload(MSG, &account),
					"Ed25519Text accepted {k:02x?}"
				);
				assert!(
					!OrbinumSignature::Ed25519WrappedText(forged)
						.verify_full_payload(MSG, &account),
					"Ed25519WrappedText accepted {k:02x?}"
				);
			}
		}
	});
}

/// The EVM address `0x01 00…00` maps to the identity point's encoding.
#[test]
fn ed25519_forgery_cannot_spend_from_the_evm_identity_account() {
	with_ext(|| {
		let account = crate::evm_h160_to_account_id(sp_core::H160::from(hex!(
			"0100000000000000000000000000000000000000"
		)));
		assert_eq!(
			<AccountId as AsRef<[u8; 32]>>::as_ref(&account),
			&SMALL_ORDER[1]
		);
		frame_system::BlockHash::<Runtime>::insert(0u32, H256(GENESIS));
		let forged = ed25519::Signature::from_raw(ED25519_FORGERY);
		assert!(!OrbinumSignature::Ed25519Text(forged).verify_full_payload(MSG, &account));
		assert!(!OrbinumSignature::Ed25519WrappedText(forged).verify_full_payload(MSG, &account));
	});
}

#[test]
fn ed25519_ordinary_key_still_verifies() {
	with_ext(|| {
		frame_system::BlockHash::<Runtime>::insert(0u32, H256(GENESIS));
		let pair = ed25519::Pair::from_seed(&[3u8; 32]);
		let account = OrbinumSigner::from(pair.public()).into_account();
		let text = pair.sign(&text_message(&GENESIS, MSG));
		let wrapped = pair.sign(&wrapped_text_message(&GENESIS, MSG));
		assert!(OrbinumSignature::Ed25519Text(text).verify_full_payload(MSG, &account));
		assert!(OrbinumSignature::Ed25519WrappedText(wrapped).verify_full_payload(MSG, &account));
		assert!(!OrbinumSignature::Ed25519Text(text).verify_full_payload(&b"other"[..], &account));
	});
}

/// edwards25519 group order `L`, little-endian.
const ED25519_ORDER: [u8; 32] =
	hex!("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010");

/// `S + L` verifies the same equation as `S`; only the reduced scalar is accepted.
#[test]
fn ed25519_text_with_s_plus_l_is_refused() {
	with_ext(|| {
		frame_system::BlockHash::<Runtime>::insert(0u32, H256(GENESIS));
		let pair = ed25519::Pair::from_seed(&[3u8; 32]);
		let account = OrbinumSigner::from(pair.public()).into_account();
		let sig = pair.sign(&text_message(&GENESIS, MSG));
		assert!(OrbinumSignature::Ed25519Text(sig).verify_full_payload(MSG, &account));
		let mut malleated = sig.0;
		let mut carry = 0u16;
		for i in 0..32 {
			let sum = malleated[32 + i] as u16 + ED25519_ORDER[i] as u16 + carry;
			malleated[32 + i] = sum as u8;
			carry = sum >> 8;
		}
		assert_eq!(carry, 0);
		assert_ne!(malleated, sig.0);
		let malleated = ed25519::Signature::from_raw(malleated);
		assert!(!OrbinumSignature::Ed25519Text(malleated).verify_full_payload(MSG, &account));
	});
}

/// Text signatures are checked over the whole payload only: through `Verify`, whose
/// message may be a blake2_256, even a valid one is refused.
#[test]
fn text_signatures_never_verify_through_verify() {
	with_ext(|| {
		frame_system::BlockHash::<Runtime>::insert(0u32, H256(GENESIS));
		let pair = ed25519::Pair::from_seed(&[3u8; 32]);
		let account = OrbinumSigner::from(pair.public()).into_account();
		let text = pair.sign(&text_message(&GENESIS, MSG));
		let wrapped = pair.sign(&wrapped_text_message(&GENESIS, MSG));
		assert!(OrbinumSignature::Ed25519Text(text).verify_full_payload(MSG, &account));
		assert!(!OrbinumSignature::Ed25519Text(text).verify(MSG, &account));
		assert!(!OrbinumSignature::Ed25519WrappedText(wrapped).verify(MSG, &account));
	});
}

/// A raw ed25519 signature over a payload's blake2_256 verifies on the host but under no
/// variant.
#[test]
fn a_blind_signature_over_the_payload_hash_authorizes_nothing() {
	with_ext(|| {
		frame_system::BlockHash::<Runtime>::insert(0u32, H256(GENESIS));
		let pair = ed25519::Pair::from_seed(&[4u8; 32]);
		let account = OrbinumSigner::from(pair.public()).into_account();
		let payload_hash = sp_io::hashing::blake2_256(b"a payload longer than 256 bytes");
		let blind = pair.sign(&payload_hash);
		assert!(sp_io::crypto::ed25519_verify(
			&blind,
			&payload_hash,
			&pair.public()
		));
		assert!(
			!OrbinumSignature::Ed25519Text(blind).verify_full_payload(&payload_hash[..], &account)
		);
		assert!(!OrbinumSignature::Ed25519WrappedText(blind)
			.verify_full_payload(&payload_hash[..], &account));
		assert!(!OrbinumSignature::Ed25519(blind).verify(&payload_hash[..], &account));
	});
}

// Sr25519

#[test]
fn sr25519_identity_key_is_refused() {
	with_ext(|| {
		// R = 0, s = 0, with schnorrkel's marker bit.
		let mut raw = [0u8; 64];
		raw[63] = 0x80;
		let forged = sr25519::Signature::from_raw(raw);
		let identity = [0u8; 32];
		assert!(sp_io::crypto::sr25519_verify(
			&forged,
			MSG,
			&sr25519::Public::from_raw(identity)
		));
		assert!(!OrbinumSignature::Sr25519(forged).verify(MSG, &AccountId::from(identity)));
	});
}

#[test]
fn sr25519_ordinary_key_still_verifies() {
	let pair = sr25519::Pair::from_string("//Alice", None).unwrap();
	let account = OrbinumSigner::from(pair.public()).into_account();
	assert!(OrbinumSignature::Sr25519(pair.sign(MSG)).verify(MSG, &account));
}

// ECDSA

/// A raw ECDSA signature over the payload's blake2_256 recovers the key on the host but
/// verifies under no variant: secp256k1 keys sign only text (`EcdsaText`).
#[test]
fn raw_ecdsa_never_verifies() {
	with_ext(|| {
		frame_system::BlockHash::<Runtime>::insert(0u32, H256(GENESIS));
		let pair = ecdsa::Pair::from_string("//Alice", None).unwrap();
		let account = OrbinumSigner::from(pair.public()).into_account();
		let hash = sp_io::hashing::blake2_256(MSG);
		let blind = pair.sign_prehashed(&hash);
		assert_eq!(blind.recover_prehashed(&hash), Some(pair.public()));
		assert!(!OrbinumSignature::Ecdsa(blind).verify(MSG, &account));
		assert!(!OrbinumSignature::EcdsaText(blind).verify_full_payload(MSG, &account));
		let text = pair.sign_prehashed(&sp_io::hashing::keccak_256(&eip191_text_message(
			&GENESIS, MSG,
		)));
		assert!(OrbinumSignature::EcdsaText(text).verify_full_payload(MSG, &account));
		assert!(!OrbinumSignature::Ecdsa(text).verify(MSG, &account));
	});
}
