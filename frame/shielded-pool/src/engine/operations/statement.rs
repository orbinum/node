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

/// The recipient's raw account bytes. Orbinum accounts are `AccountId32` for
/// every signature scheme; any other width is rejected rather than bound as a
/// truncated or zero-padded value.
pub fn recipient_bytes<T: Config>(recipient: &T::AccountId) -> Result<[u8; 32], Error<T>> {
	<[u8; 32]>::try_from(recipient.encode().as_slice()).map_err(|_| Error::<T>::InvalidRecipient)
}
