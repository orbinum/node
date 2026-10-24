//! Signatures that must authorize nothing: a text that misstates the transaction, a text
//! over the payload hash (the first format), raw ed25519, and one framing passed off as
//! the other.

use super::*;
use fp_self_contained::VerifyFullPayload;
use sp_runtime::transaction_validity::InvalidTransaction;

/// blake2_256 of the 381-byte `system.remark("x" × 300)` payload: what `verify` receives.
const LONG_PAYLOAD_HASH: [u8; 32] =
	hex!("eaf7d84f0f7506f11bfc84c0eecbdfc8de11c799069005f3128c1130dbd43abd");

/// Signatures produced by the browser wallets through `solana:signMessage` over the
/// first text format (no `action:` line, `scripts/solana/lib/payload.mjs`), on 2026-10-19.
struct WalletVector {
	key: [u8; 32],
	short: [u8; 64],
	long: [u8; 64],
}

const PHANTOM: WalletVector = WalletVector {
	key: hex!("64c602b56868980acc7d978f3e6564079b9d1323b3578660986d9561cbf39ff5"),
	short: hex!(
		"ec3a49751ef729e15d8cd227a49f696799c0b763d6601d0fd19cc3246010f2ac
		 07405822f2b7cefb999f5d3d15e1bd8dd18c7c7da980d07852d8f8d4fb0f0b04"
	),
	long: hex!(
		"f951cf2f7d5b32cbd8d966fca779a1f94e884af0745cbc0f7197a0f33405b5d9
		 7ef6e405df389646c908c46e148720bf7b8ddb82ccb49dab2905c6921d21d609"
	),
};

const METAMASK: WalletVector = WalletVector {
	key: hex!("8a5c9983fd2b7cce2eaedb7ac261f9072de8f08879f6efb0d563d68167badb63"),
	short: hex!(
		"830d09e131b63721bcde6bdc6fa4e4a96df2a9c9bc6d53064a64b76fe33637cf
		 572d4c927a2980447655d848f8ef3da6243b5418b590109164d537fbcd0c0d07"
	),
	long: hex!(
		"a3d4b9f4d8729fb25892b903d2f0e2294062f022fc5b38f5a190d8903a8b1016
		 fd35192abd652cb1385b650995fff2439f64899a27025216c39adf5bb4c4710d"
	),
};

fn text_sig(sig: [u8; 64]) -> OrbinumSignature {
	OrbinumSignature::Ed25519Text(ed25519::Signature::from_raw(sig))
}

/// The text for `msg`, written out independently of the runtime's encoder.
fn expected_text(genesis: &[u8; 32], lines: &str, msg: &[u8]) -> String {
	format!(
		"Orbinum transaction\nchain: 0x{}\naction: {lines}\npayload: 0x{}",
		to_hex(genesis),
		to_hex(&sp_io::hashing::blake2_256(msg)),
	)
}

/// Signs `text` for `call` (tip 0) and checks the extrinsic the way the pool does.
fn check_signed_text(text: &str, call: RuntimeCall) -> Result<(), TransactionValidityError> {
	let (pair, account) = keypair();
	let sig = OrbinumSignature::Ed25519Text(pair.sign(text.as_bytes()));
	check(call, &account, sig, 0)
}

// ─── A text that misstates the payload ────────────────────────────────────────

#[test]
fn a_text_with_another_amount_is_refused() {
	with_ext(|| {
		set_genesis(TESTNET_GENESIS);
		let call = transfer(100 * ORB);
		let msg = raw_payload(&call, 0);
		let lines = format!(
			"Balances.transfer_keep_alive\nto: 0x{}\namount: 1 ORB",
			to_hex(&BOB)
		);
		assert_eq!(
			check_signed_text(&expected_text(&TESTNET_GENESIS, &lines, &msg), call),
			Err(InvalidTransaction::BadProof.into())
		);
	});
}

#[test]
fn a_text_with_another_recipient_is_refused() {
	with_ext(|| {
		set_genesis(TESTNET_GENESIS);
		let call = transfer(ORB);
		let msg = raw_payload(&call, 0);
		let lines = format!(
			"Balances.transfer_keep_alive\nto: 0x{}\namount: 1 ORB",
			to_hex(&[0xa1; 32])
		);
		assert_eq!(
			check_signed_text(&expected_text(&TESTNET_GENESIS, &lines, &msg), call),
			Err(InvalidTransaction::BadProof.into())
		);
	});
}

#[test]
fn a_shield_text_with_another_amount_is_refused() {
	with_ext(|| {
		set_genesis(TESTNET_GENESIS);
		let call = shield(100 * ORB);
		let msg = raw_payload(&call, 0);
		let lie = expected_text(&TESTNET_GENESIS, "ShieldedPool.shield\namount: 1 ORB", &msg);
		assert_eq!(
			check_signed_text(&lie, call),
			Err(InvalidTransaction::BadProof.into())
		);
	});
}

#[test]
fn a_text_hiding_the_tip_is_refused() {
	with_ext(|| {
		set_genesis(TESTNET_GENESIS);
		let (pair, account) = keypair();
		let call = transfer(ORB);
		let msg = payload_with_tip(&call, ORB);
		let lines = format!(
			"Balances.transfer_keep_alive\nto: 0x{}\namount: 1 ORB",
			to_hex(&BOB)
		);
		let text = expected_text(&TESTNET_GENESIS, &lines, &msg);
		let sig = OrbinumSignature::Ed25519Text(pair.sign(text.as_bytes()));
		let xt = UncheckedExtrinsic::new_signed(call, account, sig, signed_extra_with_tip(0, ORB));
		assert_eq!(
			xt.check(&frame_system::ChainContext::<Runtime>::default())
				.map(|_| ()),
			Err(InvalidTransaction::BadProof.into())
		);
	});
}

/// The first format signed the text of what `Verify` receives, a blake2_256 above 256
/// bytes. Such a signature no longer authorizes anything.
#[test]
fn a_text_over_the_payload_hash_fails_check() {
	with_ext(|| {
		set_genesis(TESTNET_GENESIS);
		let (pair, account) = keypair();
		let call = remark(300);
		let hash = sp_io::hashing::blake2_256(&raw_payload(&call, 0));
		let sig = OrbinumSignature::Ed25519Text(pair.sign(&text_message(&TESTNET_GENESIS, &hash)));
		assert_eq!(
			check(call, &account, sig, 0),
			Err(InvalidTransaction::BadProof.into())
		);
	});
}

// ─── Other ed25519 signatures ─────────────────────────────────────────────────

#[test]
fn hash_only_wallet_signatures_no_longer_verify() {
	with_ext(|| {
		set_genesis(TESTNET_GENESIS);
		for (name, w) in [("phantom", PHANTOM), ("metamask", METAMASK)] {
			let account = AccountId::from(w.key);
			assert!(
				!text_sig(w.short).verify_full_payload(&SHORT_PAYLOAD[..], &account),
				"{name}: short payload"
			);
			assert!(
				!text_sig(w.long).verify_full_payload(&LONG_PAYLOAD_HASH[..], &account),
				"{name}: hashed long payload"
			);
		}
	});
}

#[test]
fn a_raw_ed25519_signature_verifies_under_no_variant() {
	with_ext(|| {
		set_genesis(TESTNET_GENESIS);
		let (pair, account) = keypair();
		let sig = pair.sign(&SHORT_PAYLOAD);
		assert!(
			!OrbinumSignature::Ed25519Text(sig).verify_full_payload(&SHORT_PAYLOAD[..], &account)
		);
		assert!(!OrbinumSignature::Ed25519WrappedText(sig)
			.verify_full_payload(&SHORT_PAYLOAD[..], &account));
	});
}

#[test]
fn text_and_wrapped_text_signatures_do_not_cross() {
	with_ext(|| {
		set_genesis(TESTNET_GENESIS);
		let (pair, account) = keypair();
		let text = pair.sign(&text_message(&TESTNET_GENESIS, &SHORT_PAYLOAD));
		assert!(
			OrbinumSignature::Ed25519Text(text).verify_full_payload(&SHORT_PAYLOAD[..], &account)
		);
		assert!(!OrbinumSignature::Ed25519WrappedText(text)
			.verify_full_payload(&SHORT_PAYLOAD[..], &account));

		let wrapped = pair.sign(&wrapped_text_message(&TESTNET_GENESIS, &SHORT_PAYLOAD));
		assert!(OrbinumSignature::Ed25519WrappedText(wrapped)
			.verify_full_payload(&SHORT_PAYLOAD[..], &account));
		assert!(!OrbinumSignature::Ed25519Text(wrapped)
			.verify_full_payload(&SHORT_PAYLOAD[..], &account));
	});
}
