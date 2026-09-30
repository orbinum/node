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

#[cfg(test)]
mod tests {
	use super::*;
	use crate::{
		mock::{Test, acc},
		tests::memo,
	};
	use orbinum_zk_verifier::to_field_le;

	fn hex(bytes: [u8; 32]) -> String {
		bytes.iter().map(|b| format!("{b:02x}")).collect()
	}

	/// `memo_hash` as clients compute it. Shared with `@orbinum/protocol` and
	/// `@orbinum/wallet-sdk`: a client that disagrees binds a hash the chain rejects.
	#[test]
	fn memo_hash_matches_the_cross_repo_vectors() {
		assert_eq!(
			hex(to_field_le(&memo_digest(&[memo(1), memo(2)]))),
			"978a2292588866b11afe6c88da581146b3c18d08932f6aeccf0ca27704871819"
		);
		// A total unshield: one empty change memo.
		assert_eq!(
			hex(to_field_le(&memo_digest(&[EncryptedMemo::default()]))),
			"505e8bdcf453a9a8503ed771c10ed7dfe65cfad2a858ef471023a64084ba7223"
		);
	}

	#[test]
	fn memo_digest_changes_with_any_byte_order_or_count() {
		let base = memo_digest(&[memo(1), memo(2)]);
		let mut tampered = [0x01u8; 180];
		tampered[179] = 0x00;
		assert_ne!(
			base,
			memo_digest(&[EncryptedMemo::from_bytes(&tampered).unwrap(), memo(2)])
		);
		assert_ne!(base, memo_digest(&[memo(2), memo(1)]));
		assert_ne!(base, memo_digest(&[memo(1)]));
		assert_ne!(memo_digest(&[]), memo_digest(&[EncryptedMemo::default()]));
	}

	#[test]
	fn recipient_bytes_are_the_raw_account() {
		let who = acc(7);
		let raw: [u8; 32] = who.clone().into();
		assert_eq!(recipient_bytes::<Test>(&who).unwrap(), raw);
	}
}
