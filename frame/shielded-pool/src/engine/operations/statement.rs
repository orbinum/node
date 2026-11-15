// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: GPL-3.0-or-later

//! The pool-side values a spend proof commits to, in the form the verifier port
//! takes them. Field encoding is `pallet_zk_verifier::encoding`'s job; this module
//! only turns pool types into bytes.

use crate::{
	pallet::{Config, Error},
	types::EncryptedMemo,
};
use parity_scale_codec::Encode;

/// `blake2_256` of the SCALE-encoded memos: what a memo-bound proof commits to
/// (reduced mod r, as `memo_hash`).
///
/// A memo carries a note's secrets but is not otherwise part of the proven
/// statement; without this a copier could swap it and leave the note
/// unrecoverable. Transfer passes its output memos in order; unshield passes
/// its single change memo, empty for a total unshield.
pub fn memo_digest(memos: &[EncryptedMemo]) -> [u8; 32] {
	sp_io::hashing::blake2_256(&memos.encode())
}

/// Domain of a bound spend's `memo_hash`.
pub const BOUND_SPEND_DOMAIN: &[u8] = b"orbinum:bound-spend:v1";

/// What a bound spend's proof commits to as `memo_hash` (reduced mod r):
/// `blake2_256(BOUND_SPEND_DOMAIN ‖ genesis_hash ‖ blake2_256(SCALE(action)) ‖ memo_digest([change_memo]))`.
///
/// The genesis hash keeps a proof from one chain valid on no other; the action
/// hash binds everything the action decides, its outputs included. A plain
/// unshield commits to `memo_digest` alone, so neither proof passes as the other.
pub fn bound_digest<T: Config>(action: &[u8], change_memo: &EncryptedMemo) -> [u8; 32] {
	use sp_runtime::traits::Zero;
	let genesis = frame_system::Pallet::<T>::block_hash(
		frame_system::pallet_prelude::BlockNumberFor::<T>::zero(),
	);
	let mut preimage = sp_std::vec::Vec::with_capacity(BOUND_SPEND_DOMAIN.len() + 96);
	preimage.extend_from_slice(BOUND_SPEND_DOMAIN);
	preimage.extend_from_slice(genesis.as_ref());
	preimage.extend_from_slice(&sp_io::hashing::blake2_256(action));
	preimage.extend_from_slice(&memo_digest(core::slice::from_ref(change_memo)));
	sp_io::hashing::blake2_256(&preimage)
}

/// The recipient's raw account bytes. Orbinum accounts are `AccountId32` for
/// every signature scheme; any other width is rejected rather than bound as a
/// truncated or zero-padded value.
pub fn recipient_bytes<T: Config>(recipient: &T::AccountId) -> Result<[u8; 32], Error<T>> {
	<[u8; 32]>::try_from(recipient.encode().as_slice()).map_err(|_| Error::<T>::InvalidRecipient)
}
