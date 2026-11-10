//! The public values a spend's proof binds: the memo digest and the recipient.

use crate::{
	operations::statement::*,
	tests::{
		mock::{Test, acc},
		util::memo,
	},
	types::EncryptedMemo,
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
