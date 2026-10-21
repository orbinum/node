//! `Ed25519Text` and `Ed25519WrappedText`: ed25519 over a UTF-8 rendering of the payload.

use sp_core::ed25519::Signature;

const HEAD: &[u8] = b"Orbinum transaction\nchain: 0x";
const PAYLOAD: &[u8] = b"\npayload: 0x";
const OPEN: &[u8] = b"<Bytes>";
const CLOSE: &[u8] = b"</Bytes>";

/// Length of every [`text_message`]: both hashes render as 64 hex characters.
pub const TEXT_MESSAGE_LEN: usize = HEAD.len() + 64 + PAYLOAD.len() + 64;

/// Length of every [`wrapped_text_message`].
pub const WRAPPED_TEXT_MESSAGE_LEN: usize = OPEN.len() + TEXT_MESSAGE_LEN + CLOSE.len();

/// The text an `Ed25519Text` signature covers, with lowercase hex:
///
/// ```text
/// Orbinum transaction
/// chain: 0x{genesis}
/// payload: 0x{blake2_256(msg)}
/// ```
///
/// `msg` may already be a blake2_256 (payloads over 256 bytes); `verify` cannot tell, so
/// it is always hashed again.
pub fn text_message(genesis: &[u8; 32], msg: &[u8]) -> [u8; TEXT_MESSAGE_LEN] {
	let mut out = [0u8; TEXT_MESSAGE_LEN];
	concat_into(
		&mut out,
		[
			HEAD,
			&hex32(genesis),
			PAYLOAD,
			&hex32(&sp_io::hashing::blake2_256(msg)),
		],
	);
	out
}

/// [`text_message`] inside `<Bytes>…</Bytes>`: what a Substrate extension's `signRaw`
/// signs for that text (polkadot-js `u8aWrapBytes`).
pub fn wrapped_text_message(genesis: &[u8; 32], msg: &[u8]) -> [u8; WRAPPED_TEXT_MESSAGE_LEN] {
	let mut out = [0u8; WRAPPED_TEXT_MESSAGE_LEN];
	concat_into(&mut out, [OPEN, &text_message(genesis, msg), CLOSE]);
	out
}

fn concat_into<const N: usize>(out: &mut [u8], parts: [&[u8]; N]) {
	let mut at = 0;
	for part in parts {
		out[at..at + part.len()].copy_from_slice(part);
		at += part.len();
	}
}

fn hex32(bytes: &[u8; 32]) -> [u8; 64] {
	const DIGITS: &[u8; 16] = b"0123456789abcdef";
	let mut out = [0u8; 64];
	for (i, b) in bytes.iter().enumerate() {
		out[2 * i] = DIGITS[(b >> 4) as usize];
		out[2 * i + 1] = DIGITS[(b & 0x0f) as usize];
	}
	out
}

/// Same source as `CheckGenesis`, which already read it to build the payload.
fn genesis() -> [u8; 32] {
	frame_system::Pallet::<crate::Runtime>::block_hash(0).to_fixed_bytes()
}

pub(super) fn verify(sig: &Signature, msg: &[u8], key: &[u8; 32]) -> bool {
	super::ed25519::verify(sig, &text_message(&genesis(), msg), key)
}

pub(super) fn verify_wrapped(sig: &Signature, msg: &[u8], key: &[u8; 32]) -> bool {
	super::ed25519::verify(sig, &wrapped_text_message(&genesis(), msg), key)
}
