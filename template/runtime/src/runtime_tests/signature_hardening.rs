//! Keys and encodings `OrbinumSignature` refuses although the host primitive accepts them.

use super::with_ext;
use crate::{
	orbinum_signature::{text_message, wrapped_text_message, OrbinumSignature, OrbinumSigner},
	AccountId, Runtime,
};
use fp_self_contained::VerifyFullPayload;
use hex_literal::hex;
use sp_core::{ecdsa, ed25519, sr25519, Pair, H256};
use sp_runtime::traits::{IdentifyAccount, Verify};

const MSG: &[u8] = b"any message";
const GENESIS: [u8; 32] = [0x5a; 32];

/// secp256k1 group order, big-endian.
const SECP256K1_ORDER: [u8; 32] =
	hex!("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");

/// `n − s` for a big-endian scalar.
fn order_minus(s: &[u8]) -> [u8; 32] {
	let mut out = [0u8; 32];
	let mut borrow = 0i16;
	for i in (0..32).rev() {
		let d = SECP256K1_ORDER[i] as i16 - s[i] as i16 - borrow;
		borrow = (d < 0) as i16;
		out[i] = (d + 256 * borrow) as u8;
	}
	out
}

// ─── Ed25519 / Ed25519Text ────────────────────────────────────────────────────

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

/// A Solana wallet signs any bytes through `signMessage`, e.g. a payload's blake2_256
/// shown as a login nonce. That signature verifies as raw ed25519 but under no variant.
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

// ─── Sr25519 ──────────────────────────────────────────────────────────────────

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

// ─── Ecdsa ────────────────────────────────────────────────────────────────────

fn ecdsa_alice() -> (ecdsa::Signature, AccountId) {
	let pair = ecdsa::Pair::from_string("//Alice", None).unwrap();
	(
		pair.sign(MSG),
		OrbinumSigner::from(pair.public()).into_account(),
	)
}

fn recovers_same_key(a: &[u8; 65], b: &[u8; 65]) -> bool {
	let hash = sp_io::hashing::blake2_256(MSG);
	match (
		sp_io::crypto::secp256k1_ecdsa_recover(a, &hash),
		sp_io::crypto::secp256k1_ecdsa_recover(b, &hash),
	) {
		(Ok(ka), Ok(kb)) => ka == kb,
		_ => false,
	}
}

#[test]
fn ecdsa_canonical_signature_verifies() {
	let (sig, account) = ecdsa_alice();
	assert!(
		sig.0[32..64] <= order_minus(&sig.0[32..64])[..],
		"sp_core signs with a low s"
	);
	assert!(sig.0[64] < 2);
	assert!(OrbinumSignature::Ecdsa(sig).verify(MSG, &account));
}

#[test]
fn ecdsa_high_s_alias_is_refused() {
	let (sig, account) = ecdsa_alice();
	let mut alias = sig.0;
	alias[32..64].copy_from_slice(&order_minus(&sig.0[32..64]));
	alias[64] ^= 1;
	assert!(recovers_same_key(&sig.0, &alias));
	assert!(!OrbinumSignature::Ecdsa(ecdsa::Signature::from_raw(alias)).verify(MSG, &account));
}

#[test]
fn ecdsa_offset_recovery_id_is_refused() {
	let (sig, account) = ecdsa_alice();
	let mut alias = sig.0;
	alias[64] += 27;
	assert!(recovers_same_key(&sig.0, &alias));
	assert!(!OrbinumSignature::Ecdsa(ecdsa::Signature::from_raw(alias)).verify(MSG, &account));
}
