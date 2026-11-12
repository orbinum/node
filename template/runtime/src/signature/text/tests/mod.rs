// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

//! `Ed25519Text`, `Ed25519WrappedText` and `EcdsaText`: the text's frame (here), and
//! through the runtime the extrinsic check, the texts that must authorize nothing, the
//! wire format and the vectors shared with clients. How a call is summarised is tested
//! in `summary`, how values are written in `format`.

mod check;
mod ecdsa;
mod pool_commission;
mod refusals;
mod vectors;
mod wire;

use super::{eip191_text_message, format};
use crate::{
	signature::{text_message, wrapped_text_message, OrbinumSignature},
	test_utils::{shield, signed_extra, signed_extra_with_era, transfer, with_ext, BOB, ORB},
	AccountId, BalancesCall, Runtime, RuntimeCall, SignedExtra, SignedPayload, UncheckedExtrinsic,
};
use hex_literal::hex;
use scale_codec::{Decode, Encode};
use sp_core::{ed25519, Pair, H256};
use sp_runtime::{traits::Checkable, transaction_validity::TransactionValidityError};

/// Public testnet genesis; the wallet vectors below were signed against it.
const TESTNET_GENESIS: [u8; 32] =
	hex!("58e2de05e550e64bb73bb2aeb706431dae70dcd1b589d477033c6e3aef3680ae");

/// `system.remark("orbinum solana probe")` signing payload (spec 19, tx 7, nonce 0, immortal).
const SHORT_PAYLOAD: [u8; 100] = hex!(
	"0000506f7262696e756d20736f6c616e612070726f626500000000130000000700000058e2de05e550e64b
	 b73bb2aeb706431dae70dcd1b589d477033c6e3aef3680ae58e2de05e550e64bb73bb2aeb706431dae70dc
	 d1b589d477033c6e3aef3680ae00"
);

/// Independent of the runtime's own encoder.
fn to_hex(bytes: &[u8]) -> String {
	bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn set_genesis(genesis: [u8; 32]) {
	frame_system::BlockHash::<Runtime>::insert(0u32, H256(genesis));
}

fn keypair() -> (ed25519::Pair, AccountId) {
	let pair = ed25519::Pair::from_seed(&[7u8; 32]);
	let account = AccountId::from(pair.public().0);
	(pair, account)
}

/// The whole signing payload: what the text renders and its `payload:` line hashes.
fn payload_with_tip(call: &RuntimeCall, tip: u128) -> Vec<u8> {
	SignedPayload::new(call.clone(), signed_extra(0, tip))
		.unwrap()
		.deconstruct()
		.encode()
}

/// [`payload_with_tip`] of a transaction signed at block 1 000 (hash `0xbb…bb`), valid
/// for 64 blocks.
fn mortal_payload(call: &RuntimeCall, tip: u128) -> Vec<u8> {
	frame_system::Pallet::<Runtime>::set_block_number(1_000);
	frame_system::BlockHash::<Runtime>::insert(1_000u32, H256([0xbb; 32]));
	let era = sp_runtime::generic::Era::mortal(64, 1_000);
	SignedPayload::new(call.clone(), signed_extra_with_era(0, tip, era))
		.unwrap()
		.deconstruct()
		.encode()
}

fn raw_payload(call: &RuntimeCall, nonce: u32) -> Vec<u8> {
	SignedPayload::new(call.clone(), signed_extra(nonce, 0))
		.unwrap()
		.deconstruct()
		.encode()
}

fn remark(len: usize) -> RuntimeCall {
	RuntimeCall::System(frame_system::Call::remark {
		remark: vec![b'x'; len],
	})
}

/// Signs `call` the way a text-only wallet does: over `text_message` of the whole
/// payload, at any size.
fn sign_text(pair: &ed25519::Pair, call: &RuntimeCall, nonce: u32) -> OrbinumSignature {
	let genesis = frame_system::Pallet::<Runtime>::block_hash(0u32);
	let text = text_message(genesis.as_fixed_bytes(), &raw_payload(call, nonce));
	OrbinumSignature::Ed25519Text(pair.sign(&text))
}

/// Signs `call` the way a Substrate extension's `signRaw` does over the same text.
fn sign_wrapped_text(pair: &ed25519::Pair, call: &RuntimeCall, nonce: u32) -> OrbinumSignature {
	let genesis = frame_system::Pallet::<Runtime>::block_hash(0u32);
	let text = wrapped_text_message(genesis.as_fixed_bytes(), &raw_payload(call, nonce));
	OrbinumSignature::Ed25519WrappedText(pair.sign(&text))
}

fn check(
	call: RuntimeCall,
	account: &AccountId,
	signature: OrbinumSignature,
	nonce: u32,
) -> Result<(), TransactionValidityError> {
	let xt =
		UncheckedExtrinsic::new_signed(call, account.clone(), signature, signed_extra(nonce, 0));
	// Round-trip the wire format, as the transaction pool does.
	let xt = UncheckedExtrinsic::decode(&mut &xt.encode()[..]).unwrap();
	xt.check(&frame_system::ChainContext::<Runtime>::default())
		.map(|_| ())
}

#[test]
fn the_eip191_message_prefixes_the_text_with_its_length() {
	let payload = [0xffu8; 40];
	let text = text_message(&[0xab; 32], &payload);
	let message = eip191_text_message(&[0xab; 32], &payload);
	let prefix = format!("\x19Ethereum Signed Message:\n{}", text.len());
	assert_eq!(message, [prefix.as_bytes(), &text].concat());
}

#[test]
fn the_text_frames_the_summary_with_chain_and_payload() {
	let payload = [0xffu8; 40];
	let text = String::from_utf8(text_message(&[0xab; 32], &payload)).unwrap();
	let hash = String::from_utf8(format::hex(&sp_io::hashing::blake2_256(&payload))).unwrap();
	assert_eq!(
		text,
		format!(
			"Orbinum transaction\nchain: 0x{}\naction: unknown\npayload: {hash}",
			"ab".repeat(32)
		)
	);
}

#[test]
fn the_wrapped_text_is_the_text_inside_bytes_tags() {
	let payload = [0x01u8; 40];
	let text = text_message(&[0; 32], &payload);
	assert_eq!(
		wrapped_text_message(&[0; 32], &payload),
		[b"<Bytes>".as_slice(), &text, b"</Bytes>"].concat()
	);
}

#[test]
fn the_payload_line_hashes_the_whole_payload_at_any_size() {
	let payload = vec![0x07u8; 1000];
	let text = String::from_utf8(text_message(&[0; 32], &payload)).unwrap();
	let hash = String::from_utf8(format::hex(&sp_io::hashing::blake2_256(&payload))).unwrap();
	assert!(text.ends_with(&format!("\npayload: {hash}")));
}

/// The nonce is shown, not only hashed: a person tells two transactions of the same call
/// apart before the `payload:` line.
#[test]
fn texts_of_payloads_differing_only_in_nonce_differ_above_the_payload_line() {
	with_ext(|| {
		set_genesis(TESTNET_GENESIS);
		let above_payload = |nonce| {
			let text =
				String::from_utf8(text_message(&[0; 32], &raw_payload(&transfer(ORB), nonce)))
					.unwrap();
			let (head, _) = text.rsplit_once("\npayload: ").unwrap();
			head.to_string()
		};
		assert_ne!(above_payload(0), above_payload(1));
		assert!(above_payload(1).ends_with("\nexpires: never\nnonce: 1"));
	});
}
