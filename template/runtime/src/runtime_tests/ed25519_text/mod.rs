//! `OrbinumSignature::Ed25519Text` and `Ed25519WrappedText` through the runtime: the
//! extrinsic check, the texts that must authorize nothing, the wire format and the
//! vectors shared with clients. How the text is rendered is unit-tested in
//! `orbinum_signature::text`.

mod check;
mod refusals;
mod vectors;
mod wire;

use super::with_ext;
use crate::{
	orbinum_signature::{text_message, wrapped_text_message, OrbinumSignature},
	AccountId, BalancesCall, Runtime, RuntimeCall, SignedExtra, SignedPayload, UncheckedExtrinsic,
};
use hex_literal::hex;
use scale_codec::{Decode, Encode};
use sp_core::{ed25519, Pair, H256};
use sp_runtime::{traits::Checkable, transaction_validity::TransactionValidityError};

const ORB: u128 = 1_000_000_000_000_000_000;
const BOB: [u8; 32] = [0xb0; 32];

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

fn signed_extra(nonce: u32) -> SignedExtra {
	signed_extra_with_tip(nonce, 0)
}

fn signed_extra_with_tip(nonce: u32, tip: u128) -> SignedExtra {
	(
		frame_system::CheckNonZeroSender::new(),
		frame_system::CheckSpecVersion::new(),
		frame_system::CheckTxVersion::new(),
		frame_system::CheckGenesis::new(),
		frame_system::CheckEra::from(sp_runtime::generic::Era::Immortal),
		frame_system::CheckNonce::from(nonce),
		frame_system::CheckWeight::new(),
		pallet_transaction_payment::ChargeTransactionPayment::from(tip),
		frame_metadata_hash_extension::CheckMetadataHash::new(false),
	)
}

/// The whole signing payload: what the text renders and its `payload:` line hashes.
fn payload_with_tip(call: &RuntimeCall, tip: u128) -> Vec<u8> {
	SignedPayload::new(call.clone(), signed_extra_with_tip(0, tip))
		.unwrap()
		.deconstruct()
		.encode()
}

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

fn transfer(value: u128) -> RuntimeCall {
	RuntimeCall::Balances(BalancesCall::transfer_keep_alive {
		dest: AccountId::from(BOB),
		value,
	})
}

fn shield(amount: u128) -> RuntimeCall {
	RuntimeCall::ShieldedPool(pallet_shielded_pool::Call::shield {
		asset_id: 0,
		amount,
		commitment: pallet_shielded_pool::Commitment::new([0x1c; 32]),
		encrypted_memo: pallet_shielded_pool::FrameEncryptedMemo::new(vec![0x3e; 180]).unwrap(),
		proof: vec![0x9f; 128].try_into().unwrap(),
		circuit_version: 1,
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
	let xt = UncheckedExtrinsic::new_signed(call, account.clone(), signature, signed_extra(nonce));
	// Round-trip the wire format, as the pool does.
	let xt = UncheckedExtrinsic::decode(&mut &xt.encode()[..]).unwrap();
	xt.check(&frame_system::ChainContext::<Runtime>::default())
		.map(|_| ())
}
