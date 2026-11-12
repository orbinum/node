// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

//! `Ed25519Text`, `Ed25519WrappedText` and `EcdsaText`: a signature over a UTF-8 text the
//! runtime renders from the whole signing payload, so a person reads what they sign.
//! ed25519 signs the text (or its `<Bytes>` wrapping); ECDSA signs its EIP-191
//! `personal_sign` hash, as EVM wallets do.
//!
//! ```text
//! Orbinum transaction
//! chain: 0x{genesis}
//! action: {Pallet}.{call}
//! {key}: {value}           (the call's lines, see `summary`)
//! expires: within {n} blocks | never
//! nonce: {n}
//! tip: {n} ORB             (a non-zero tip)
//! payload: 0x{blake2_256(payload)}
//! ```
//!
//! A fingerprint is `0x{first 8 bytes}…{last 8 bytes}` in lowercase hex around U+2026:
//! of the raw value for a shield's `commitment:`, of its blake2_256 for `memo:` and a
//! remark's `remark:`.
//!
//! - [`summary`]: the `action:` value and the lines under it.
//! - [`format`](mod@format): how hex, amounts and lines are written.
//!
//! The payload is the whole signing payload at any size, never its blake2_256:
//! `fp_self_contained::VerifyFullPayload` hands it over. The `payload:` line binds the
//! signature to every byte, the summary to what the person sees.

mod format;
mod summary;
#[cfg(test)]
mod tests;

use crate::AccountId;
use alloc::vec::Vec;
use sp_core::{ecdsa, ed25519::Signature};

const HEAD: &[u8] = b"Orbinum transaction\nchain: ";
const OPEN: &[u8] = b"<Bytes>";
const CLOSE: &[u8] = b"</Bytes>";
const EIP191: &[u8] = b"\x19Ethereum Signed Message:\n";

/// The text `Ed25519Text` signs and `EcdsaText` signs through EIP-191 (see the module doc).
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

/// Whether a text signature may authorise the call `payload` signs (see [`summary`]).
#[cfg(test)]
pub fn text_signable(payload: &[u8]) -> bool {
	summary::signable(payload)
}

/// What an EVM wallet's `personal_sign` hashes for [`text_message`]: the EIP-191 prefix,
/// the text's UTF-8 byte length in decimal, then the text.
pub fn eip191_text_message(genesis: &[u8; 32], payload: &[u8]) -> Vec<u8> {
	let text = text_message(genesis, payload);
	[EIP191, &format::decimal(text.len() as u128), &text].concat()
}

pub(super) fn verify(sig: &Signature, payload: &[u8], key: &[u8; 32]) -> bool {
	summary::signable(payload)
		&& super::keys::ed25519::verify(sig, &text_message(&genesis(), payload), key)
}

pub(super) fn verify_wrapped(sig: &Signature, payload: &[u8], key: &[u8; 32]) -> bool {
	summary::signable(payload)
		&& super::keys::ed25519::verify(sig, &wrapped_text_message(&genesis(), payload), key)
}

pub(super) fn verify_ecdsa(sig: &ecdsa::Signature, payload: &[u8], signer: &AccountId) -> bool {
	if !summary::signable(payload) {
		return false;
	}
	let message = eip191_text_message(&genesis(), payload);
	super::keys::ecdsa::verify_hash(sig, &sp_io::hashing::keccak_256(&message), signer)
}

/// Same source as `CheckGenesis`, which already read it to build the payload.
fn genesis() -> [u8; 32] {
	frame_system::Pallet::<crate::Runtime>::block_hash(0).to_fixed_bytes()
}
