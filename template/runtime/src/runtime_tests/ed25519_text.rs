//! `OrbinumSignature::Ed25519Text`: ed25519 over the text rendering of the payload.

use super::with_ext;
use crate::{
	orbinum_signature::{
		text_message, wrapped_text_message, OrbinumSignature, TEXT_MESSAGE_LEN,
		WRAPPED_TEXT_MESSAGE_LEN,
	},
	AccountId, Runtime, RuntimeCall, SignedExtra, SignedPayload, UncheckedExtrinsic,
};
use hex_literal::hex;
use scale_codec::{Decode, Encode, MaxEncodedLen};
use sp_core::{ed25519, Pair, H256};
use sp_runtime::{
	traits::{Checkable, Verify},
	transaction_validity::{InvalidTransaction, TransactionValidityError},
	MultiSignature,
};

/// Public testnet genesis; the wallet vectors below were signed against it.
const TESTNET_GENESIS: [u8; 32] =
	hex!("58e2de05e550e64bb73bb2aeb706431dae70dcd1b589d477033c6e3aef3680ae");

/// `system.remark("orbinum solana probe")` signing payload (spec 19, tx 7, nonce 0, immortal).
const SHORT_PAYLOAD: [u8; 100] = hex!(
	"0000506f7262696e756d20736f6c616e612070726f626500000000130000000700000058e2de05e550e64b
	 b73bb2aeb706431dae70dcd1b589d477033c6e3aef3680ae58e2de05e550e64bb73bb2aeb706431dae70dc
	 d1b589d477033c6e3aef3680ae00"
);

/// blake2_256 of the 381-byte `system.remark("x" × 300)` payload: what `verify` receives.
const LONG_PAYLOAD_HASH: [u8; 32] =
	hex!("eaf7d84f0f7506f11bfc84c0eecbdfc8de11c799069005f3128c1130dbd43abd");

/// Signatures produced by the browser wallets through `solana:signMessage` over
/// `textMessage` (`scripts/solana/lib/payload.mjs`), on 2026-10-19.
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

/// Independent of the runtime's own encoder.
fn to_hex(bytes: &[u8]) -> String {
	bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn set_genesis(genesis: [u8; 32]) {
	frame_system::BlockHash::<Runtime>::insert(0u32, H256(genesis));
}

fn text_sig(sig: [u8; 64]) -> OrbinumSignature {
	OrbinumSignature::Ed25519Text(ed25519::Signature::from_raw(sig))
}

fn keypair() -> (ed25519::Pair, AccountId) {
	let pair = ed25519::Pair::from_seed(&[7u8; 32]);
	let account = AccountId::from(pair.public().0);
	(pair, account)
}

fn signed_extra(nonce: u32) -> SignedExtra {
	(
		frame_system::CheckNonZeroSender::new(),
		frame_system::CheckSpecVersion::new(),
		frame_system::CheckTxVersion::new(),
		frame_system::CheckGenesis::new(),
		frame_system::CheckEra::from(sp_runtime::generic::Era::Immortal),
		frame_system::CheckNonce::from(nonce),
		frame_system::CheckWeight::new(),
		pallet_transaction_payment::ChargeTransactionPayment::from(0u128),
		frame_metadata_hash_extension::CheckMetadataHash::new(false),
	)
}

/// The signing payload before the >256-byte hashing that `SignedPayload::encode` applies.
fn raw_payload(call: &RuntimeCall, nonce: u32) -> Vec<u8> {
	SignedPayload::new(call.clone(), signed_extra(nonce))
		.unwrap()
		.deconstruct()
		.encode()
}

fn remark(len: usize) -> RuntimeCall {
	RuntimeCall::System(frame_system::Call::remark {
		remark: vec![b'x'; len],
	})
}

/// Signs `call` the way a text-only wallet does: over `text_message` of the bytes
/// `verify` will receive.
fn sign_text(pair: &ed25519::Pair, call: &RuntimeCall, nonce: u32) -> OrbinumSignature {
	let payload = SignedPayload::new(call.clone(), signed_extra(nonce)).unwrap();
	let genesis = frame_system::Pallet::<Runtime>::block_hash(0u32);
	let text = payload.using_encoded(|msg| text_message(genesis.as_fixed_bytes(), msg));
	OrbinumSignature::Ed25519Text(pair.sign(&text))
}

/// Signs `call` the way a Substrate extension's `signRaw` does over the same text.
fn sign_wrapped_text(pair: &ed25519::Pair, call: &RuntimeCall, nonce: u32) -> OrbinumSignature {
	let payload = SignedPayload::new(call.clone(), signed_extra(nonce)).unwrap();
	let genesis = frame_system::Pallet::<Runtime>::block_hash(0u32);
	let text = payload.using_encoded(|msg| wrapped_text_message(genesis.as_fixed_bytes(), msg));
	OrbinumSignature::Ed25519WrappedText(pair.sign(&text))
}

fn check(
	call: RuntimeCall,
	account: &AccountId,
	signature: OrbinumSignature,
	nonce: u32,
) -> Result<(), TransactionValidityError> {
	let xt = UncheckedExtrinsic::new_signed(call, account.clone(), signature, signed_extra(nonce));
	// Round-trip the wire format, as the pool does.
	let xt = UncheckedExtrinsic::decode(&mut &xt.encode()[..]).unwrap();
	xt.check(&frame_system::ChainContext::<Runtime>::default())
		.map(|_| ())
}

// ─── Message format ───────────────────────────────────────────────────────────

#[test]
fn text_message_matches_the_documented_format() {
	let genesis = [0xabu8; 32];
	let msg = b"payload bytes";
	let expected = format!(
		"Orbinum transaction\nchain: 0x{}\npayload: 0x{}",
		to_hex(&genesis),
		to_hex(&sp_io::hashing::blake2_256(msg)),
	);
	assert_eq!(&text_message(&genesis, msg)[..], expected.as_bytes());
	assert_eq!(TEXT_MESSAGE_LEN, 169);
}

#[test]
fn text_message_hashes_a_32_byte_message_again() {
	let genesis = [1u8; 32];
	let text = text_message(&genesis, &LONG_PAYLOAD_HASH);
	let tail = format!(
		"payload: 0x{}",
		to_hex(&sp_io::hashing::blake2_256(&LONG_PAYLOAD_HASH))
	);
	assert!(text.ends_with(tail.as_bytes()));
}

// ─── Real wallet signatures ───────────────────────────────────────────────────

#[test]
fn wallet_signatures_verify() {
	with_ext(|| {
		set_genesis(TESTNET_GENESIS);
		for (name, w) in [("phantom", PHANTOM), ("metamask", METAMASK)] {
			let account = AccountId::from(w.key);
			assert!(
				text_sig(w.short).verify(&SHORT_PAYLOAD[..], &account),
				"{name}: short payload"
			);
			assert!(
				text_sig(w.long).verify(&LONG_PAYLOAD_HASH[..], &account),
				"{name}: hashed long payload"
			);
		}
	});
}

#[test]
fn wallet_signature_rejected_on_another_chain() {
	with_ext(|| {
		set_genesis([0x11; 32]);
		let account = AccountId::from(PHANTOM.key);
		assert!(!text_sig(PHANTOM.short).verify(&SHORT_PAYLOAD[..], &account));
	});
}

#[test]
fn wallet_signature_rejected_for_altered_payload() {
	with_ext(|| {
		set_genesis(TESTNET_GENESIS);
		let account = AccountId::from(PHANTOM.key);
		let mut altered = SHORT_PAYLOAD;
		altered[3] ^= 0x01;
		assert!(!text_sig(PHANTOM.short).verify(&altered[..], &account));
	});
}

#[test]
fn wallet_signature_rejected_for_another_account() {
	with_ext(|| {
		set_genesis(TESTNET_GENESIS);
		let other = AccountId::from(METAMASK.key);
		assert!(!text_sig(PHANTOM.short).verify(&SHORT_PAYLOAD[..], &other));
	});
}

#[test]
fn wallet_signature_rejected_for_swapped_payload() {
	with_ext(|| {
		set_genesis(TESTNET_GENESIS);
		let account = AccountId::from(PHANTOM.key);
		assert!(!text_sig(PHANTOM.short).verify(&LONG_PAYLOAD_HASH[..], &account));
		assert!(!text_sig(PHANTOM.long).verify(&SHORT_PAYLOAD[..], &account));
	});
}

// ─── Separation between the ed25519 framings ──────────────────────────────────

#[test]
fn a_raw_ed25519_signature_verifies_under_no_variant() {
	with_ext(|| {
		set_genesis(TESTNET_GENESIS);
		let (pair, account) = keypair();
		let sig = pair.sign(&SHORT_PAYLOAD);
		assert!(!OrbinumSignature::Ed25519Text(sig).verify(&SHORT_PAYLOAD[..], &account));
		assert!(!OrbinumSignature::Ed25519WrappedText(sig).verify(&SHORT_PAYLOAD[..], &account));
	});
}

#[test]
fn text_and_wrapped_text_signatures_do_not_cross() {
	with_ext(|| {
		set_genesis(TESTNET_GENESIS);
		let account = AccountId::from(PHANTOM.key);
		let sig = ed25519::Signature::from_raw(PHANTOM.short);
		assert!(OrbinumSignature::Ed25519Text(sig).verify(&SHORT_PAYLOAD[..], &account));
		assert!(!OrbinumSignature::Ed25519WrappedText(sig).verify(&SHORT_PAYLOAD[..], &account));

		let (pair, account) = keypair();
		let wrapped = pair.sign(&wrapped_text_message(&TESTNET_GENESIS, &SHORT_PAYLOAD));
		assert!(OrbinumSignature::Ed25519WrappedText(wrapped).verify(&SHORT_PAYLOAD[..], &account));
		assert!(!OrbinumSignature::Ed25519Text(wrapped).verify(&SHORT_PAYLOAD[..], &account));
	});
}

/// The bytes polkadot-js `signRaw` signs for the text: `u8aWrapBytes`.
#[test]
fn wrapped_text_message_is_the_text_inside_bytes_tags() {
	let text = text_message(&TESTNET_GENESIS, &SHORT_PAYLOAD);
	let expected = [b"<Bytes>".as_slice(), &text, b"</Bytes>"].concat();
	assert_eq!(
		&wrapped_text_message(&TESTNET_GENESIS, &SHORT_PAYLOAD)[..],
		&expected[..]
	);
	assert_eq!(WRAPPED_TEXT_MESSAGE_LEN, 184);
}

// ─── Full extrinsic check ─────────────────────────────────────────────────────

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
fn signed_extrinsic_with_hashed_long_payload_passes_check() {
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
fn signed_extrinsic_with_unhashed_long_payload_fails_check() {
	with_ext(|| {
		set_genesis(TESTNET_GENESIS);
		let (pair, account) = keypair();
		let call = remark(300);
		let text = text_message(&TESTNET_GENESIS, &raw_payload(&call, 0));
		let sig = OrbinumSignature::Ed25519Text(pair.sign(&text));
		assert_eq!(
			check(call, &account, sig, 0),
			Err(InvalidTransaction::BadProof.into())
		);
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

// ─── Wire format ──────────────────────────────────────────────────────────────

#[test]
fn discriminants_and_lengths_are_stable() {
	use sp_core::{ecdsa, sr25519};

	let (pair, _) = keypair();
	let sig = pair.sign(b"wire");

	// 0x00 decodes as `Ed25519`, kept for the metadata; it never verifies.
	let raw = OrbinumSignature::Ed25519(sig).encode();
	assert_eq!(raw, MultiSignature::Ed25519(sig).encode());

	let sr = sr25519::Signature::from_raw([1u8; 64]);
	assert_eq!(
		OrbinumSignature::Sr25519(sr).encode(),
		MultiSignature::Sr25519(sr).encode()
	);
	let ec = ecdsa::Signature::from_raw([2u8; 65]);
	assert_eq!(
		OrbinumSignature::Ecdsa(ec).encode(),
		MultiSignature::Ecdsa(ec).encode()
	);

	for (tag, variant) in [
		(0x03u8, OrbinumSignature::Ed25519Text(sig)),
		(0x04u8, OrbinumSignature::Ed25519WrappedText(sig)),
	] {
		let encoded = variant.encode();
		assert_eq!(encoded[0], tag);
		assert_eq!(&encoded[1..], &sig.0[..]);
		assert_eq!(
			OrbinumSignature::decode(&mut &encoded[..]).unwrap(),
			variant
		);
	}

	let unknown = [&[0x05u8][..], &sig.0[..]].concat();
	assert!(OrbinumSignature::decode(&mut &unknown[..]).is_err());

	assert_eq!(OrbinumSignature::max_encoded_len(), 66);
}

/// polkadot-api builds no extrinsic for a signature enum lacking `Ed25519`, `Sr25519` or
/// `Ecdsa`, and tags them with the fixed indices 0, 1 and 2.
#[test]
fn signature_metadata_keeps_the_shape_polkadot_api_requires() {
	use scale_info::{TypeDef, TypeInfo};

	let TypeDef::Variant(def) = OrbinumSignature::type_info().type_def else {
		panic!("OrbinumSignature is not an enum in the metadata");
	};
	let index_of = |name: &str| {
		def.variants
			.iter()
			.find(|v| v.name == name)
			.map(|v| v.index)
	};
	assert_eq!(index_of("Ed25519"), Some(0));
	assert_eq!(index_of("Sr25519"), Some(1));
	assert_eq!(index_of("Ecdsa"), Some(2));
	assert_eq!(index_of("Ed25519Text"), Some(3));
	assert_eq!(index_of("Ed25519WrappedText"), Some(4));
}

#[test]
fn a_valid_raw_ed25519_signature_never_verifies() {
	with_ext(|| {
		set_genesis(TESTNET_GENESIS);
		let (pair, account) = keypair();
		let sig = pair.sign(&SHORT_PAYLOAD);
		assert!(sp_io::crypto::ed25519_verify(
			&sig,
			&SHORT_PAYLOAD,
			&pair.public()
		));
		assert!(!OrbinumSignature::Ed25519(sig).verify(&SHORT_PAYLOAD[..], &account));
	});
}
