//! `Ed25519Text` and `Ed25519WrappedText`: ed25519 over a UTF-8 text the runtime renders
//! from the whole signing payload, so a person reads what they sign.
//!
//! ```text
//! Orbinum transaction
//! chain: 0x{genesis}
//! action: {Pallet}.{call}
//! to: 0x{account}          (balance transfers)
//! amount: {n} ORB          (balance transfers, ORB shields and fee claims)
//! tip: {n} ORB             (a non-zero tip)
//! payload: 0x{blake2_256(payload)}
//! ```
//!
//! - [`summary`]: the `action:` value and the lines under it.
//! - [`format`]: how hex, amounts and lines are written.
//!
//! The payload is the whole signing payload at any size, never its blake2_256:
//! `fp_self_contained::VerifyFullPayload` hands it over. The `payload:` line binds the
//! signature to every byte, the summary to what the person sees.

mod format;
mod summary;

use alloc::vec::Vec;
use sp_core::ed25519::Signature;

const HEAD: &[u8] = b"Orbinum transaction\nchain: ";
const OPEN: &[u8] = b"<Bytes>";
const CLOSE: &[u8] = b"</Bytes>";

/// The text an `Ed25519Text` signature covers (see the module doc).
pub fn text_message(genesis: &[u8; 32], payload: &[u8]) -> Vec<u8> {
	let mut out = Vec::with_capacity(320);
	out.extend_from_slice(HEAD);
	out.extend_from_slice(&format::hex(genesis));
	out.extend_from_slice(b"\naction: ");
	summary::render(&mut out, payload);
	format::line(
		&mut out,
		b"payload",
		&format::hex(&sp_io::hashing::blake2_256(payload)),
	);
	out
}

/// [`text_message`] inside `<Bytes>…</Bytes>`: what a Substrate extension's `signRaw`
/// signs for that text (polkadot-js `u8aWrapBytes`).
pub fn wrapped_text_message(genesis: &[u8; 32], payload: &[u8]) -> Vec<u8> {
	[OPEN, &text_message(genesis, payload), CLOSE].concat()
}

pub(super) fn verify(sig: &Signature, payload: &[u8], key: &[u8; 32]) -> bool {
	super::ed25519::verify(sig, &text_message(&genesis(), payload), key)
}

pub(super) fn verify_wrapped(sig: &Signature, payload: &[u8], key: &[u8; 32]) -> bool {
	super::ed25519::verify(sig, &wrapped_text_message(&genesis(), payload), key)
}

/// Same source as `CheckGenesis`, which already read it to build the payload.
fn genesis() -> [u8; 32] {
	frame_system::Pallet::<crate::Runtime>::block_hash(0).to_fixed_bytes()
}

#[cfg(test)]
mod tests {
	use super::*;

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
}
